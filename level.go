package logparser

import (
	"strings"
	"unicode"
)

type Level int

const (
	LevelUnknown Level = iota
	LevelCritical
	LevelError
	LevelWarning
	LevelInfo
	LevelDebug

	maxLineLenForGuessingLevel = 255
	guessLevelInFields         = 7
)

func (l Level) String() string {
	switch l {
	case LevelCritical:
		return "critical"
	case LevelError:
		return "error"
	case LevelWarning:
		return "warning"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	}
	return "unknown"
}

var (
	glogLevelsMapping = map[byte]Level{
		'I': LevelInfo,
		'W': LevelWarning,
		'E': LevelError,
		'F': LevelCritical,
	}
	priority2Levels = map[string]Level{
		"0": LevelCritical,
		"1": LevelCritical,
		"2": LevelCritical,
		"3": LevelError,
		"4": LevelWarning,
		"5": LevelInfo,
		"6": LevelInfo,
		"7": LevelDebug,
	}
)

func LevelByPriority(priority string) Level {
	if level, ok := priority2Levels[priority]; ok {
		return level
	}
	return LevelUnknown
}

func GuessLevel(line string) Level {
	if len(line) > maxLineLenForGuessingLevel {
		line = line[:maxLineLenForGuessingLevel]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return LevelUnknown
	}
	limit := len(fields)
	if limit > guessLevelInFields {
		limit = guessLevelInFields
	}

	if l := tryGlog(fields); l != LevelUnknown {
		return l
	}

	for _, f := range fields[:limit] {
		start := 0
		for i := 0; i <= len(f); i++ {
			if i < len(f) && !isLevelFieldSeparator(f[i]) {
				continue
			}
			sf := f[start:i]
			start = i + 1
			if sf == "" {
				continue
			}
			// A key names a field, it is not a level: "error" in {"error":""}
			// or in error="" says nothing about the line's severity.
			if i < len(f) && f[i] == ':' && isQuotedWord(strings.TrimLeft(sf, "{")) {
				continue
			}
			sf = strings.TrimLeft(strings.ToLower(sf), "\"[(<'")
			if strings.HasPrefix(sf, "level=") {
				sf = sf[len("level="):]
			} else if startsWithKey(sf) {
				continue
			}

			if l := len(sf); l == 3 {
				switch sf {
				case "dbg", "trc":
					return LevelDebug
				case "inf":
					return LevelInfo
				case "wrn":
					return LevelWarning
				case "err":
					return LevelError
				case "ftl":
					return LevelCritical
				}
			} else if l >= 4 {
				switch sf[:4] {
				case "debu":
					return LevelDebug
				case "info", "noti", "note", "syst":
					return LevelInfo
				case "warn":
					return LevelWarning
				case "erro":
					return LevelError
				case "crit":
					return LevelCritical
				case "emer", "fata", "aler":
					if l >= 5 {
						switch sf[:5] {
						case "emerg", "fatal", "alert":
							return LevelCritical
						}
					}
				}
			}
		}
	}
	if l := guessRedisLevel(fields); l != LevelUnknown {
		return l
	}
	return LevelUnknown
}

func isLevelFieldSeparator(c byte) bool {
	return c == ']' || c == ')' || c == ';' || c == '|' || c == ':' || c == ',' || c == '.'
}

// isQuotedWord reports whether s is a single quoted word, such as "error".
func isQuotedWord(s string) bool {
	return len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' && strings.IndexByte(s[1:len(s)-1], '"') < 0
}

// startsWithKey reports whether s starts with a key=value pair, such as
// error="", rather than holding a = further in, as in error[req=abc.
func startsWithKey(s string) bool {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func tryGlog(fields []string) Level {
	firstField := fields[0]
	if len(firstField) != 5 {
		return LevelUnknown
	}
	level, ok := glogLevelsMapping[firstField[0]]
	if !ok {
		return LevelUnknown
	}
	for _, r := range firstField[1:] {
		if !unicode.IsDigit(r) {
			return LevelUnknown
		}
	}
	return level
}

// redis 2.x
// [pid] date loglevel message
// [4018] 14 Nov 07:01:22.119 * Background saving terminated with success

// redis 3.x+
// pid:role timestamp loglevel message
// 1:S 12 Nov 07:52:11.999 * FAIL message received from X about Y

// redis 5.x: the year was added
// 1:S 12 Nov 2019 07:52:11.999 * FAIL message received from X about Y
func guessRedisLevel(fields []string) Level {
	if len(fields) < 6 {
		return LevelUnknown
	}
	if strings.HasPrefix(fields[0], "[") && strings.HasSuffix(fields[0], "]") {
		return redisCharToLevel(fields[4])
	}
	if len(strings.Split(fields[0], ":")) == 2 {
		if len(fields[3]) == 4 { //redis 5.x+
			return redisCharToLevel(fields[5])
		} else {
			return redisCharToLevel(fields[4])
		}
	}
	return LevelUnknown
}

func redisCharToLevel(level string) Level {
	switch level {
	case ".":
		return LevelDebug
	case "-":
		return LevelInfo
	case "*", "#":
		return LevelWarning
	}
	return LevelUnknown
}

// parseLevelValue maps a structured log level field value (from JSON "level",
// logfmt level=, etc.) to a Level. Case-insensitive.
func parseLevelValue(val string) Level {
	val = strings.ToLower(strings.TrimSpace(val))
	switch val {
	case "debug", "dbg":
		return LevelDebug
	case "trace", "trc":
		return LevelDebug
	case "info", "inf", "notice", "informational", "log":
		return LevelInfo
	case "warn", "warning", "wrn":
		return LevelWarning
	case "error", "err":
		return LevelError
	case "fatal", "critical", "crit", "panic", "dpanic", "alert", "emerg", "emergency":
		return LevelCritical
	}
	return LevelUnknown
}
