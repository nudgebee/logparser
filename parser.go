package logparser

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sync"
	"time"
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
}

type Parser struct {
	decoder Decoder

	patterns map[patternKey]*patternStat
	lock     sync.RWMutex

	multilineCollector *MultilineCollector

	stop func()

	onMsgCb                      OnMsgCallbackF
	sensitivePatternsDefinations []SensitivePattern

	sensitivePatterns map[sensitivePatternKey]*sensitivePatternStat

	disableSensitivePatternDetection bool
}

type OnMsgCallbackF func(ts time.Time, level Level, patternHash string, msg string)

func NewParser(ch <-chan LogEntry, decoder Decoder, onMsgCallback OnMsgCallbackF, disableSensitiveDataDetection bool) *Parser {
	p := &Parser{
		decoder:                          decoder,
		patterns:                         map[patternKey]*patternStat{},
		onMsgCb:                          onMsgCallback,
		sensitivePatterns:                map[sensitivePatternKey]*sensitivePatternStat{},
		disableSensitivePatternDetection: disableSensitiveDataDetection,
	}
	ctx, stop := context.WithCancel(context.Background())
	p.stop = stop
	p.multilineCollector = NewMultilineCollector(ctx, multilineCollectorTimeout, multilineCollectorLimit)
	p.sensitivePatternsDefinations, _ = LoadPatterns("sensitive_patterns.json")
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
		processSensitivePattern(msg, p, pattern)
		return
	}

	pattern := NewPattern(msg.Content)
	key := patternKey{level: msg.Level, hash: pattern.Hash()}
	stat := p.patterns[key]
	if stat == nil {
		for k, ps := range p.patterns {
			if k.level == msg.Level && ps.pattern.WeakEqual(pattern) {
				stat = ps
				break
			}
		}
		if stat == nil {
			stat = &patternStat{pattern: pattern, sample: msg.Content}
			p.patterns[key] = stat
		}
	}
	if p.onMsgCb != nil {
		p.onMsgCb(msg.Timestamp, msg.Level, key.hash, msg.Content)
	}
	stat.messages++
	processSensitivePattern(msg, p, pattern)

}

func processSensitivePattern(msg Message, p *Parser, pattern *Pattern) {
	log.Printf("Processing sensitive pattern: %s, flag %v", pattern.Hash(), p.disableSensitivePatternDetection)
	if p.disableSensitivePatternDetection {
		return
	}
	matchs := DetectSensitiveData(msg.Content, pattern.Hash(), p.sensitivePatternsDefinations)
	for _, sKey := range matchs {
		log.Printf("Sensitive data detected: %s", sKey.pattern)
		stat := p.sensitivePatterns[sKey]
		if stat == nil {
			for k, ps := range p.sensitivePatterns {
				if k.pattern == sKey.pattern && ps.pattern.WeakEqual(pattern) {
					stat = ps
					break
				}
			}
			if stat == nil {
				stat = &sensitivePatternStat{pattern: pattern, sample: msg.Content, sensitiveKey: sKey.pattern}
				p.sensitivePatterns[sKey] = stat
			}
		}
		stat.messages++
	}
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
		res = append(res, SensitiveLogCounter{Pattern: k.pattern, Messages: ps.messages, Sample: ps.sample})
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
}

type sensitivePatternKey struct {
	pattern string
	hash    string
}

type SensitivePattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

func LoadPatterns(configFile string) ([]SensitivePattern, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var patterns []SensitivePattern
	err = json.Unmarshal(data, &patterns)
	if err != nil {
		return nil, err
	}

	return patterns, nil
}

func DetectSensitiveData(line string, hash string, patterns []SensitivePattern) []sensitivePatternKey {
	matches := []sensitivePatternKey{}
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			log.Printf("Error compiling pattern '%s': %v", pattern.Name, err)
			continue
		}

		if re.MatchString(line) {
			// extract only the sensitive part of the line
			sensitivePart := re.FindString(line)

			matches = append(matches, sensitivePatternKey{
				pattern: sensitivePart,
				hash:    hash,
			})
		}
	}
	return matches
}
