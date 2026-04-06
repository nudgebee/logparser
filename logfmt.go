package logparser

import "strings"

// logfmtLevelKeys are the key names checked for level in logfmt-style logs.
var logfmtLevelKeys = []string{"level=", "lvl=", "severity="}

// parseLogfmtLevel extracts the log level from a logfmt-style line.
// It scans for level=/lvl=/severity= and parses the value.
// Returns (level, true) if a recognized level field is found.
func parseLogfmtLevel(line string) (Level, bool) {
	lower := strings.ToLower(line)
	for _, key := range logfmtLevelKeys {
		idx := strings.Index(lower, key)
		if idx < 0 {
			continue
		}
		// Ensure it's at a word boundary (start of line or preceded by space/tab).
		if idx > 0 {
			prev := line[idx-1]
			if prev != ' ' && prev != '\t' {
				continue
			}
		}
		valStart := idx + len(key)
		if valStart >= len(line) {
			continue
		}
		val := extractLogfmtValue(line[valStart:])
		if lvl := parseLevelValue(val); lvl != LevelUnknown {
			return lvl, true
		}
	}
	return LevelUnknown, false
}

// extractLogfmtValue extracts a logfmt value starting at the given position.
// Handles both quoted ("error") and unquoted (error) values.
func extractLogfmtValue(s string) string {
	if len(s) == 0 {
		return ""
	}
	if s[0] == '"' {
		// Quoted value: find closing quote.
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			return ""
		}
		return s[1 : 1+end]
	}
	// Unquoted value: ends at space or end of string.
	end := strings.IndexAny(s, " \t")
	if end < 0 {
		return s
	}
	return s[:end]
}
