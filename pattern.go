package logparser

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	patternMaxWords  = 100
	patterMinWordLen = 2
	patternMaxDiff   = 1
)

var (
	buffers = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

var (
	squote  = '\''
	dquote  = '"'
	bslash  = '\\'
	lsbrack = '['
	rsbrack = ']'
	lpar    = '('
	rpar    = ')'
	lcur    = '{'
	rcur    = '}'

	hexWithPrefix = regexp.MustCompile(`^0x[a-fA-F0-9]+$`)
	hex           = regexp.MustCompile(`^[a-fA-F0-9]{4,}$`)
	uuid          = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
)

type Pattern struct {
	words []string
	str   *string
	hash  *string
}

func (p *Pattern) String() string {
	if p.str == nil {
		buf := buffers.Get().(*bytes.Buffer)
		buf.Reset()
		for _, w := range p.words {
			if buf.Len() > 0 {
				buf.WriteByte(' ')
			}
			buf.WriteString(w)
		}
		s := buf.String()
		p.str = &s
		buffers.Put(buf)
	}
	return *p.str
}

func (p *Pattern) Hash() string {
	if p.hash == nil {
		h := fmt.Sprintf("%x", md5.Sum([]byte(p.String())))
		p.hash = &h
	}
	return *p.hash
}

func (p *Pattern) WeakEqual(other *Pattern) bool {
	if len(p.words) != len(other.words) {
		return false
	}
	var diffs int
	for i := range other.words {
		if p.words[i] != other.words[i] {
			diffs++
			if diffs > patternMaxDiff {
				return false
			}
		}
	}
	return true
}

func NewPattern(input string) *Pattern {
	if strings.HasPrefix(strings.TrimSpace(input), "{") {
		if msg, _, ok := parseJSONLog(input); ok {
			input = msg
		}
	}
	return newPatternFromNormalized(input)
}

// NewPatternFromNormalized creates a Pattern from already-normalized content
// (e.g., the message output of ParseStructuredLog). Skips JSON/logfmt detection.
func NewPatternFromNormalized(input string) *Pattern {
	return newPatternFromNormalized(input)
}

func newPatternFromNormalized(input string) *Pattern {
	pattern := &Pattern{}
	buf := buffers.Get().(*bytes.Buffer)

	buf.Reset()
	for _, p := range strings.Fields(removeQuotedAndBrackets(input, buf)) {
		p = strings.TrimRight(p, "=:],;")

		if len(p) < patterMinWordLen {
			continue
		}
		if hexWithPrefix.MatchString(p) || hex.MatchString(p) || uuid.MatchString(p) {
			continue
		}
		p = removeDigits(p, buf)
		if !isWord(p) {
			continue
		}
		pattern.words = append(pattern.words, p)
		if len(pattern.words) >= patternMaxWords {
			break
		}
	}

	buffers.Put(buf)
	return pattern
}

func NewPatternFromWords(input string) *Pattern {
	return &Pattern{words: strings.Split(input, " ")}
}

// like regexp match to `^[a-zA-Z][a-zA-Z._-]*[a-zA-Z]$`, but much faster
func isWord(s string) bool {
	l := len(s) - 1
	var firstLast int
	for i, r := range s {
		switch i {
		case 0, l:
			switch {
			case r >= 'A' && r <= 'Z':
				firstLast++
			case r >= 'a' && r <= 'z':
				firstLast++
			default:
				return false
			}
		default:
			switch {
			case r >= 'A' && r <= 'Z':
			case r >= 'a' && r <= 'z':
			case r == '.':
			case r == '_':
			case r == '-':
			default:
				return false
			}
		}
	}
	return firstLast == 2
}

func removeDigits(s string, buf *bytes.Buffer) string {
	buf.Reset()
	for _, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		buf.WriteRune(r)
	}
	return buf.String()
}

func removeQuotedAndBrackets(s string, buf *bytes.Buffer) string {
	buf.Reset()
	var quote, prev rune
	var seenBrackets []rune
	var l int
	for i, r := range s {
		switch r {
		case lsbrack, lpar, lcur:
			if quote == 0 {
				seenBrackets = append(seenBrackets, r)
			}
		case rsbrack:
			if l = len(seenBrackets); l > 0 && seenBrackets[l-1] == lsbrack {
				seenBrackets = seenBrackets[:l-1]
				continue
			}
		case rpar:
			if l = len(seenBrackets); l > 0 && seenBrackets[l-1] == lpar {
				seenBrackets = seenBrackets[:l-1]
				continue
			}
		case rcur:
			if l = len(seenBrackets); l > 0 && seenBrackets[l-1] == lcur {
				seenBrackets = seenBrackets[:l-1]
				continue
			}
		case dquote, squote:
			prev = 0
			if i > 0 {
				prev = rune(s[i-1])
			}
			if prev != bslash && len(seenBrackets) == 0 {
				if quote == 0 {
					quote = r
				} else if quote == r {
					quote = 0
					continue
				}
			}
		}
		if quote != 0 || len(seenBrackets) > 0 {
			continue
		}
		buf.WriteRune(r)
	}
	return buf.String()
}

// patternMessageKeys lists the JSON field names (lowercase) used for pattern extraction.
// Following industry standard (Datadog, New Relic, Elastic, Better Stack), pattern
// hashing uses only the message/error content, not metadata fields like timestamps,
// file paths, line numbers, IDs, or data blobs which produce unstable hashes.
var patternMessageKeys = []string{"msg", "message", "error", "err", "reason", "log", "text"}

// patternLevelKeys lists the JSON field names (lowercase) checked for log level.
// Covers: slog/zerolog/zap (level), GCP/Stackdriver (severity), Bunyan (lvl),
// Python logging (levelname), and common variants.
var patternLevelKeys = []string{"level", "severity", "lvl", "log.level", "loglevel", "log_level", "levelname", "log_type"}

// maxFallbackFieldLen caps individual field values in the fallback path to prevent
// large data blobs (HTML, XML, stack traces) from overwhelming the pattern.
const maxFallbackFieldLen = 200

// parseJSONLog parses a JSON log line, extracting the normalized message content
// and the structured log level. Returns ok=false if the line is not valid JSON.
func parseJSONLog(line string) (message string, level Level, ok bool) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return line, LevelUnknown, false
	}
	message, level = structuredFromJSON(m)
	return message, level, true
}

// structuredFromJSON extracts the pattern content and the level from a
// decoded JSON log line. Numbers may be float64 (json.Unmarshal) or
// json.Number (decoding with UseNumber): both render the same, so pattern
// hashes do not depend on how the line was decoded.
func structuredFromJSON(m map[string]interface{}) (message string, level Level) {
	// Build a lowercase-key lookup for case-insensitive matching.
	lowerMap := make(map[string]interface{}, len(m))
	for k, v := range m {
		lowerMap[strings.ToLower(k)] = v
	}

	// Extract level from structured field.
	level = LevelUnknown
	for _, k := range patternLevelKeys {
		if v, found := lowerMap[k]; found {
			if s, isStr := v.(string); isStr {
				level = parseLevelValue(s)
			}
			break
		}
	}

	// Extract only message-relevant fields for stable pattern hashing.
	var buf strings.Builder
	for _, k := range patternMessageKeys {
		if v, found := lowerMap[k]; found {
			s := fmt.Sprintf("%v", float64Numbers(v))
			if s != "" {
				buf.WriteString(s)
				buf.WriteByte(' ')
			}
		}
	}
	if buf.Len() > 0 {
		return strings.TrimSpace(buf.String()), level
	}

	// Fallback: no known message fields found, use all values sorted by key
	// with a per-field length cap to prevent data blobs from dominating.
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := fmt.Sprintf("%v", float64Numbers(m[k]))
		if len(s) > maxFallbackFieldLen {
			s = s[:maxFallbackFieldLen]
		}
		buf.WriteString(s)
		buf.WriteByte(' ')
	}
	return strings.TrimSpace(buf.String()), level
}

// float64Numbers converts json.Number values, including nested ones, to the
// float64 that json.Unmarshal produces, so both decodings render alike.
func float64Numbers(v interface{}) interface{} {
	switch t := v.(type) {
	case json.Number:
		if f, err := strconv.ParseFloat(string(t), 64); err == nil {
			return f
		}
		return string(t)
	case map[string]interface{}:
		res := make(map[string]interface{}, len(t))
		for k, vv := range t {
			res[k] = float64Numbers(vv)
		}
		return res
	case []interface{}:
		res := make([]interface{}, len(t))
		for i, vv := range t {
			res[i] = float64Numbers(vv)
		}
		return res
	}
	return v
}

// ParseStructuredLog attempts to parse a log line as a structured format
// (JSON or logfmt), extracting the normalized message content and level.
// For unstructured logs, returns the original content and GuessLevel result.
func ParseStructuredLog(line string) (message string, level Level) {
	trimmed := strings.TrimSpace(line)

	// JSON logs
	if strings.HasPrefix(trimmed, "{") {
		if msg, lvl, ok := parseJSONLog(line); ok {
			return msg, lvl
		}
	}

	// logfmt logs
	if lvl, ok := parseLogfmtLevel(line); ok {
		return line, lvl
	}

	// Unstructured: fall back to text heuristic
	return line, GuessLevel(line)
}
