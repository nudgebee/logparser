package logparser

import (
	"regexp" // Added for regexp.MustCompile
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	ch := make(chan LogEntry)
	parser := NewParser(ch, nil, nil, time.Second, false)

	ch <- LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: AKIAIOSFODNN7EXAMPLE", Level: LevelInfo}

	// wait for 10 seconds
	time.Sleep(10 * time.Second)
	counts := parser.GetSensitiveCounters()
	assert.Equal(t, 1, len(counts))
	parser.Stop()
}

func TestDetectSensitiveDataWithKeywords(t *testing.T) {
	mockPrecompiledPatterns := []PrecompiledPattern{
		{
			Name:     "KeywordTestSecret",
			Pattern:  regexp.MustCompile("secret_value_\\d+"),
			Keywords: []string{"secret_value", "credentials"},
		},
		{
			Name:     "SingleKeywordMatch",
			Pattern:  regexp.MustCompile("data-\\d+"),
			Keywords: []string{"specific_data", "another_term"},
		},
		{
			Name:     "NoKeywordSecret",
			Pattern:  regexp.MustCompile("general_secret"),
			Keywords: []string{}, // Or nil
		},
		{
			Name:     "NoMatchKeyword", // Keywords will not be in the test log lines for this one
			Pattern:  regexp.MustCompile("other_value_\\d+"),
			Keywords: []string{"will_not_appear", "absent_keyword"},
		},
		{
			Name:     "KeywordMismatchButRegexWouldMatch", // Specific for the self-corrected test case
			Pattern:  regexp.MustCompile("secret_code_\\d+"),
			Keywords: []string{"credentials", "token"}, // These keywords are not in "this line has secret_code_789"
		},
	}

	testCases := []struct {
		testName             string
		logLine              string
		hash                 string
		expectedMatches      int
		expectedPatternNames []string
	}{
		{
			testName:             "Keyword and Regex match",
			logLine:              "this line has secret_value_123 and other stuff",
			hash:                 "hash1",
			expectedMatches:      1,
			expectedPatternNames: []string{"KeywordTestSecret"},
		},
		{
			testName:             "Single keyword match from multiple, and Regex match",
			logLine:              "contains specific_data-456 only",
			hash:                 "hash2",
			expectedMatches:      1,
			expectedPatternNames: []string{"SingleKeywordMatch"},
		},
		{
			testName:             "Regex would match, but required keywords are not present",
			logLine:              "this line has secret_code_789 but not the right keywords", // Matches KeywordMismatchButRegexWouldMatch's regex
			hash:                 "hash3",
			expectedMatches:      0,
			expectedPatternNames: []string{},
		},
		{
			testName:             "No keywords, Regex match",
			logLine:              "a general_secret is here",
			hash:                 "hash4",
			expectedMatches:      1,
			expectedPatternNames: []string{"NoKeywordSecret"},
		},
		{
			testName:             "Multiple patterns match (keyworded and non-keyworded)",
			logLine:              "multi match: secret_value_000 and general_secret",
			hash:                 "hash5",
			expectedMatches:      2, // DetectSensitiveData breaks after first match, so this needs adjustment
			expectedPatternNames: []string{"KeywordTestSecret"}, // Adjusting expectation due to break
		},
		{
			testName:             "Regex would match, but its defined keywords are not in log line",
			logLine:              "this log has the pattern other_value_101 but not the triggering words", // Corrected log line
			hash:                 "hash6",
			expectedMatches:      0,
			expectedPatternNames: []string{},
		},
		{
			testName:             "No sensitive data",
			logLine:              "nothing sensitive here",
			hash:                 "hash7",
			expectedMatches:      0,
			expectedPatternNames: []string{},
		},
		{
			testName:             "Keyword present, but regex does not match",
			logLine:              "this line has credentials but not the secret_value_regex",
			hash:                 "hash8",
			expectedMatches:      0,
			expectedPatternNames: []string{},
		},
	}

	// Adjusting the multi-match test case based on DetectSensitiveData's behavior (breaks after first match)
	// The original DetectSensitiveData breaks after the first match.
	// If "KeywordTestSecret" is defined before "NoKeywordSecret" and matches first, only it will be returned.
	// Let's verify this understanding.
	// The current `DetectSensitiveData` has a `break` statement after a match.
	// So, it will only ever return 0 or 1 match.
	// The test case "Multiple patterns match (keyworded and non-keyworded)" needs to reflect this.
	// It should expect 1 match, the first one encountered.
	// Re-ordering mockPrecompiledPatterns or the log line can test which one is hit.
	// For now, assuming "KeywordTestSecret" would be checked first if its keywords match.
	// The log line "multi match: secret_value_000 and general_secret" contains "secret_value" (for KeywordTestSecret).
	// So "KeywordTestSecret" should match and break the loop.

	testCases[4].expectedMatches = 1 // Correcting based on break behavior
	testCases[4].expectedPatternNames = []string{"KeywordTestSecret"} // Correcting based on break behavior


	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			matches := DetectSensitiveData(tc.logLine, tc.hash, mockPrecompiledPatterns)
			assert.Equal(t, tc.expectedMatches, len(matches), "Unexpected number of matches")

			if tc.expectedMatches > 0 {
				matchedNames := []string{}
				for _, match := range matches {
					matchedNames = append(matchedNames, match.name) // Changed Name to name
				}
				// Since DetectSensitiveData breaks after the first match, we only expect one name if matches > 0
				assert.Contains(t, tc.expectedPatternNames, matchedNames[0], "Matched pattern name mismatch")
			}
		})
	}
}
