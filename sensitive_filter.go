package logparser

import (
	"math"
	"regexp"
	"strings"
)

// nonCapGroupRE matches (?:...), (?i:...), (?-i:...) groups without nested parentheses.
var nonCapGroupRE = regexp.MustCompile(`\(\?(?:-?i)?:([^()]+)\)`)

// extractAnchors extracts case-insensitive literal substrings from a regex
// that must appear in any matching string. These serve as cheap pre-filters:
// if none of the anchors appear in a log line, the full regex can be skipped.
// Returns nil if no reliable anchors can be extracted.
func extractAnchors(regexStr string) []string {
	var anchors []string

	// Find non-capturing groups and extract literal alternatives.
	// Handles patterns like (?:adafruit), (?:AKIA|ASIA|ABIA), (?-i:Okta|OKTA).
	for _, m := range nonCapGroupRE.FindAllStringSubmatch(regexStr, -1) {
		content := m[1]
		for _, alt := range strings.Split(content, "|") {
			lit := leadingLiteral(alt)
			if len(lit) >= 3 {
				anchors = append(anchors, strings.ToLower(lit))
			}
		}
	}

	if len(anchors) > 0 {
		return dedupStrings(anchors)
	}

	// Fallback: extract literal prefix from the regex itself.
	// Handles patterns like ops_eyJ..., AGE-SECRET-KEY-..., shpat_...
	cleaned := regexStr
	for {
		n := len(cleaned)
		for _, pfx := range []string{`\b`, `(?i)`, `^`, `(?:`, `(`} {
			cleaned = strings.TrimPrefix(cleaned, pfx)
		}
		if len(cleaned) == n {
			break
		}
	}
	lit := leadingLiteral(cleaned)
	if len(lit) >= 3 {
		return []string{strings.ToLower(lit)}
	}

	return nil
}

// leadingLiteral extracts leading literal characters from a string,
// stopping at the first regex metacharacter.
func leadingLiteral(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			b.WriteRune(c)
		} else {
			break
		}
	}
	return b.String()
}

// anchorMatchesLine checks if any anchor substring appears in the lowercased line.
func anchorMatchesLine(lowerLine string, anchors []string) bool {
	for _, a := range anchors {
		if strings.Contains(lowerLine, a) {
			return true
		}
	}
	return false
}

// shannonEntropy calculates the Shannon entropy of a string in bits per character.
// Real secrets (API keys, tokens) have high entropy (~4-6 bits).
// Normal strings (English words, table names) have low entropy (~2-3 bits).
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// looksLikeSecret checks whether a matched value has the characteristics of
// a real secret rather than a normal application string. This is applied as
// a post-match filter for low-confidence patterns to reduce false positives.
//
// Real secrets (API keys, tokens, webhook URLs) tend to have:
//   - High character entropy (random-looking)
//   - Mix of character classes (upper, lower, digits)
//
// False positives (SQL tables, cache keys, enum values) tend to have:
//   - Low entropy (English words, underscores)
//   - Single character class (all lowercase + underscores)
func looksLikeSecret(s string) bool {
	if len(s) < 10 {
		return false
	}

	// Count character classes
	var hasUpper, hasLower, hasDigit bool
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}

	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}

	// Require at least 2 character classes (e.g., lower+digit, or upper+lower)
	if classes < 2 {
		return false
	}

	// Require minimum entropy to filter out structured-but-predictable strings.
	// Real tokens/keys: ~4.0+ bits (e.g., hex string = 4.0, base64 = ~5.2)
	// English words with separators: ~2.5-3.5 bits
	return shannonEntropy(s) >= 3.5
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
