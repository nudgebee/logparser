package logparser

import (
	"context"
	_ "embed"
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed sensitive_patterns.json
var sensitivePatternsJSON []byte

var (
	unclassifiedPatternLabel = "unclassified pattern (pattern limit reached)"
	unclassifiedPatternHash  = "00000000000000000000000000000000"
)

// Shared pattern caches: compiled once, shared across all parsers.
// Key is the minConfidence level.
var (
	patternCacheMu sync.Mutex
	patternCache   = map[string][]PrecompiledPattern{}
)

type LogEntry struct {
	Timestamp time.Time
	Content   string
	Level     Level
}

type LogCounter struct {
	Level    Level
	Hash     string
	Sample   string
	Messages int
}

type SensitiveLogCounter struct {
	Sample   string
	Messages int
	Pattern  string
	Regex    string
	Name     string
	Hash     string
}

type PrecompiledPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Anchors    []string // lowercased literal strings for pre-filtering
	Confidence string   // "high", "medium", "low"
}

// SensitiveConfig controls sensitive data detection behavior.
type SensitiveConfig struct {
	// Enabled turns on sensitive data detection in log lines.
	Enabled bool
	// SampleRate controls how many lines are checked: 1-in-N.
	// 0 or 1 means every line is checked.
	SampleRate int
	// MinConfidence filters patterns by confidence level.
	// "high" = only distinctive-prefix patterns (lowest FP rate)
	// "medium" = high + service-keyword patterns (default)
	// "low" = all patterns including generic ones (highest FP rate)
	MinConfidence string
	// MaxDetections caps unique sensitive patterns tracked per parser.
	// 0 means no limit.
	MaxDetections int
}

type Parser struct {
	decoder Decoder

	patterns              map[patternKey]*patternStat
	patternsPerLevel      map[Level]int
	patternsPerLevelLimit int
	lock                  sync.RWMutex

	multilineCollector *MultilineCollector

	stop func()

	onMsgCb                     OnMsgCallbackF
	sensitivePatternDefinitions []PrecompiledPattern

	sensitivePatterns map[sensitivePatternKey]*sensitivePatternStat
	sensitiveConfig   SensitiveConfig
	sensitiveCounter  uint64
}

type OnMsgCallbackF func(ts time.Time, level Level, patternHash string, msg string)

func NewParser(ch <-chan LogEntry, decoder Decoder, onMsgCallback OnMsgCallbackF, multilineCollectorTimeout time.Duration, patternsPerLevelLimit int, sensitiveCfg SensitiveConfig) *Parser {
	p := &Parser{
		decoder:               decoder,
		patterns:              map[patternKey]*patternStat{},
		patternsPerLevel:      map[Level]int{},
		patternsPerLevelLimit: patternsPerLevelLimit,
		onMsgCb:               onMsgCallback,
		sensitivePatterns:     map[sensitivePatternKey]*sensitivePatternStat{},
		sensitiveConfig:       sensitiveCfg,
	}
	if sensitiveCfg.Enabled {
		patterns, err := getOrLoadPatterns(sensitiveCfg.MinConfidence)
		if err != nil {
			log.Printf("Error loading sensitive patterns: %v", err)
		}
		p.sensitivePatternDefinitions = patterns
	}
	ctx, stop := context.WithCancel(context.Background())
	p.stop = stop
	p.multilineCollector = NewMultilineCollector(ctx, multilineCollectorTimeout, multilineCollectorLimit)
	go func() {
		var err error
		for {
			select {
			case <-ctx.Done():
				return
			case entry := <-ch:
				if p.decoder != nil {
					if entry.Content, err = p.decoder.Decode(entry.Content); err != nil {
						continue
					}
				}
				p.multilineCollector.Add(entry)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-p.multilineCollector.Messages:
				p.inc(msg)
			}
		}
	}()

	return p
}

func (p *Parser) Stop() {
	p.stop()
}

func (p *Parser) inc(msg Message) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if msg.Level == LevelUnknown || msg.Level == LevelDebug || msg.Level == LevelInfo {
		key := patternKey{level: msg.Level, hash: ""}
		if stat := p.patterns[key]; stat == nil {
			p.patterns[key] = &patternStat{}
		}
		p.patterns[key].messages++
		if p.onMsgCb != nil {
			p.onMsgCb(msg.Timestamp, msg.Level, "", msg.Content)
		}
		pattern := NewPattern(msg.Content)
		p.processSensitivePattern(msg, pattern)
		return
	}

	pattern := NewPattern(msg.Content)
	stat, key := p.getPatternStat(msg.Level, pattern, msg.Content)
	if p.onMsgCb != nil {
		p.onMsgCb(msg.Timestamp, msg.Level, key.hash, msg.Content)
	}
	stat.messages++
	p.processSensitivePattern(msg, pattern)
}

func (p *Parser) processSensitivePattern(msg Message, pattern *Pattern) {
	if !p.sensitiveConfig.Enabled {
		return
	}

	// Sampling: only check 1-in-N lines.
	p.sensitiveCounter++
	if p.sensitiveConfig.SampleRate > 1 && p.sensitiveCounter%uint64(p.sensitiveConfig.SampleRate) != 0 {
		return
	}

	// Detection cap: stop scanning once we've tracked enough unique patterns.
	if p.sensitiveConfig.MaxDetections > 0 && len(p.sensitivePatterns) >= p.sensitiveConfig.MaxDetections {
		return
	}

	matches := DetectSensitiveData(msg.Content, pattern.Hash(), p.sensitivePatternDefinitions)
	for _, match := range matches {
		sKey := match.sensitivePatternKey
		stat := p.sensitivePatterns[sKey]
		if stat == nil {
			for k, ps := range p.sensitivePatterns {
				if k.pattern == sKey.pattern && ps.pattern.WeakEqual(pattern) {
					stat = ps
					break
				}
			}
			if stat == nil {
				stat = &sensitivePatternStat{pattern: pattern, sample: msg.Content, sensitiveKey: sKey.pattern, regex: match.regex, name: match.name, hash: sKey.hash}
				p.sensitivePatterns[sKey] = stat
			}
		}
		stat.messages++
	}
}

func (p *Parser) getPatternStat(level Level, pattern *Pattern, sample string) (*patternStat, patternKey) {
	key := patternKey{level: level, hash: pattern.Hash()}
	if stat := p.patterns[key]; stat != nil {
		return stat, key
	}
	for k, ps := range p.patterns {
		if k.level != level || ps.pattern == nil {
			continue
		}
		if ps.pattern.WeakEqual(pattern) {
			return ps, k
		}
	}

	if p.patternsPerLevel[level] >= p.patternsPerLevelLimit {
		fallbackKey := patternKey{level: level, hash: unclassifiedPatternHash}
		stat := p.patterns[fallbackKey]
		if stat == nil {
			stat = &patternStat{sample: unclassifiedPatternLabel}
			p.patterns[fallbackKey] = stat
		}
		return stat, fallbackKey
	}

	stat := &patternStat{pattern: pattern, sample: sample}
	p.patterns[key] = stat
	p.patternsPerLevel[level]++
	return stat, key
}

func (p *Parser) GetCounters() []LogCounter {
	p.lock.RLock()
	defer p.lock.RUnlock()
	res := make([]LogCounter, 0, len(p.patterns))
	for k, ps := range p.patterns {
		res = append(res, LogCounter{Level: k.level, Hash: k.hash, Sample: ps.sample, Messages: ps.messages})
	}
	return res
}

func (p *Parser) GetSensitiveCounters() []SensitiveLogCounter {
	p.lock.RLock()
	defer p.lock.RUnlock()
	res := make([]SensitiveLogCounter, 0, len(p.sensitivePatterns))
	for k, ps := range p.sensitivePatterns {
		res = append(res, SensitiveLogCounter{Pattern: k.pattern, Messages: ps.messages, Sample: ps.sample, Regex: ps.regex, Name: ps.name, Hash: ps.hash})
	}
	return res
}

type patternKey struct {
	level Level
	hash  string
}

type patternStat struct {
	pattern  *Pattern
	sample   string
	messages int
}

type sensitivePatternStat struct {
	pattern      *Pattern
	sample       string
	messages     int
	sensitiveKey string
	regex        string
	name         string
	hash         string
}

type sensitivePatternKey struct {
	pattern string
	hash    string
}

type SensitivePattern struct {
	Name       string `json:"name"`
	Pattern    string `json:"pattern"`
	Confidence string `json:"confidence,omitempty"`
}

type SensitivePatternMatch struct {
	sensitivePatternKey sensitivePatternKey
	regex               string
	name                string
	hash                string
}

// confidenceLevel returns a numeric level for sorting: high=3, medium=2, low=1.
func confidenceLevel(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 2 // default to medium
	}
}

// DetectSensitiveData scans a log line against precompiled patterns using
// anchor-based pre-filtering to skip patterns that can't possibly match.
func DetectSensitiveData(line string, hash string, precompiledPatterns []PrecompiledPattern) []SensitivePatternMatch {
	var matches []SensitivePatternMatch
	lowerLine := strings.ToLower(line)

	for i := range precompiledPatterns {
		p := &precompiledPatterns[i]

		// Pre-filter: if the pattern has anchors, at least one must appear in the line.
		if len(p.Anchors) > 0 && !anchorMatchesLine(lowerLine, p.Anchors) {
			continue
		}

		if p.Pattern.MatchString(line) {
			sensitivePart := p.Pattern.FindString(line)

			// Post-match validation for low-confidence patterns:
			// reject matches where the captured value doesn't look like a real secret
			// (e.g., SQL table names, cache keys, enum values).
			if p.Confidence == "low" && !looksLikeSecret(sensitivePart) {
				continue
			}

			key := sensitivePatternKey{
				pattern: sensitivePart,
				hash:    hash,
			}
			matches = append(matches, SensitivePatternMatch{name: p.Name, sensitivePatternKey: key, regex: p.Pattern.String(), hash: hash})
			break
		}
	}
	return matches
}

// getOrLoadPatterns returns a shared, cached pattern set for the given
// confidence level. Compiled regexes are loaded once and reused across all
// parsers — avoids duplicating ~2 MB of compiled regex state per container.
func getOrLoadPatterns(minConfidence string) ([]PrecompiledPattern, error) {
	patternCacheMu.Lock()
	defer patternCacheMu.Unlock()

	if cached, ok := patternCache[minConfidence]; ok {
		return cached, nil
	}
	patterns, err := LoadPatterns(minConfidence)
	if err != nil {
		return nil, err
	}
	patternCache[minConfidence] = patterns
	return patterns, nil
}

// LoadPatterns loads and compiles sensitive data patterns, filtering by
// minimum confidence level. Patterns below minConfidence are excluded.
func LoadPatterns(minConfidence string) ([]PrecompiledPattern, error) {
	var patterns []SensitivePattern
	err := json.Unmarshal(sensitivePatternsJSON, &patterns)
	if err != nil {
		return nil, err
	}

	minLevel := confidenceLevel(minConfidence)
	if minLevel == 0 {
		minLevel = 2 // default: medium
	}

	precompiled := make([]PrecompiledPattern, 0, len(patterns))
	for _, pattern := range patterns {
		confidence := pattern.Confidence
		if confidence == "" {
			confidence = "medium"
		}
		if confidenceLevel(confidence) < minLevel {
			continue
		}

		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			log.Printf("Error compiling pattern '%s': %v", pattern.Name, err)
			continue
		}
		precompiled = append(precompiled, PrecompiledPattern{
			Name:       pattern.Name,
			Pattern:    re,
			Anchors:    extractAnchors(pattern.Pattern),
			Confidence: confidence,
		})
	}
	return precompiled, nil
}
