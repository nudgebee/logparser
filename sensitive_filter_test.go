package logparser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractAnchors(t *testing.T) {
	tests := []struct {
		name     string
		regex    string
		expected []string
	}{
		{
			name:     "AWS key pattern with alternation",
			regex:    `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`,
			expected: []string{"a3t", "akia", "asia", "abia", "acca"},
		},
		{
			name:     "keyword pattern - adafruit",
			regex:    `(?i)[\w.-]{0,50}?(?:adafruit)(?:[ \t\w.-]{0,20})`,
			expected: []string{"adafruit"},
		},
		{
			name:     "keyword pattern - discord",
			regex:    `(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})`,
			expected: []string{"discord"},
		},
		{
			name:     "literal prefix - age secret key",
			regex:    `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`,
			expected: []string{"age-secret-key-1"},
		},
		{
			name:     "literal prefix - shopify",
			regex:    `shpat_[a-fA-F0-9]{32}`,
			expected: []string{"shpat_"},
		},
		{
			name:     "literal prefix with \b - github pat",
			regex:    `ghp_[0-9a-zA-Z]{36}`,
			expected: []string{"ghp_"},
		},
		{
			name:     "case insensitive group - okta",
			regex:    `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:Okta|OKTA))(?:[ \t\w.-]{0,20}))`,
			expected: []string{"okta"},
		},
		{
			name:     "no extractable anchors - short prefix",
			regex:    `\b(ey[a-zA-Z0-9]{17,}\.)`,
			expected: nil,
		},
		{
			name:     "multiple service keywords",
			regex:    `(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)`,
			expected: []string{"jfrog", "artifactory", "bintray", "xray"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAnchors(tt.regex)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAnchorMatchesLine(t *testing.T) {
	assert.True(t, anchorMatchesLine("aws key is akiaiosfodnn7example", []string{"akia"}))
	assert.True(t, anchorMatchesLine("github token ghp_abc123", []string{"ghp_"}))
	assert.False(t, anchorMatchesLine("normal log line with no secrets", []string{"akia", "ghp_"}))
	assert.True(t, anchorMatchesLine("using adafruit library", []string{"adafruit"}))
}

func TestPrefilterEffectiveness(t *testing.T) {
	// Load all patterns and verify anchor extraction coverage
	patterns, err := LoadPatterns("low")
	require.NoError(t, err)

	withAnchors := 0
	for _, p := range patterns {
		if len(p.Anchors) > 0 {
			withAnchors++
		}
	}

	coverage := float64(withAnchors) / float64(len(patterns)) * 100
	t.Logf("Anchor coverage: %d/%d patterns (%.1f%%)", withAnchors, len(patterns), coverage)

	// At least 80% of patterns should have extractable anchors
	assert.True(t, coverage >= 80, "anchor coverage should be >= 80%%, got %.1f%%", coverage)
}

func TestPrefilterSkipsNonMatching(t *testing.T) {
	patterns, err := LoadPatterns("high")
	require.NoError(t, err)

	// A normal log line should not trigger any anchor matches for most patterns
	normalLine := "2024-01-15 INFO Processing request for user 12345 completed in 45ms"
	lowerLine := strings.ToLower(normalLine)

	candidateCount := 0
	for _, p := range patterns {
		if len(p.Anchors) == 0 || anchorMatchesLine(lowerLine, p.Anchors) {
			candidateCount++
		}
	}

	// Vast majority of high-confidence patterns should be skipped
	skipRate := float64(len(patterns)-candidateCount) / float64(len(patterns)) * 100
	t.Logf("Pre-filter skip rate: %.1f%% (%d/%d patterns skipped)", skipRate, len(patterns)-candidateCount, len(patterns))
	assert.True(t, skipRate >= 90, "pre-filter should skip >= 90%% of patterns for normal lines, got %.1f%%", skipRate)
}

func TestLooksLikeSecret(t *testing.T) {
	// Real secrets — should pass
	assert.True(t, looksLikeSecret("cdd6190b063b4da02e8beb855b65e55428055c491a48b2bdf1c85660391506882e1feb13"))
	assert.True(t, looksLikeSecret("AKIAIOSFODNN7EXAMPLE"))
	assert.True(t, looksLikeSecret("ghp_AAAAAAAAAAAA1234567890abcdefghijkl"))
	assert.True(t, looksLikeSecret("xK9mPq2wF7vL0aB3nR5tY8uJ1dG4hS6"))

	// False positives — should fail
	assert.False(t, looksLikeSecret("auth_group_permissions"))  // SQL table name
	assert.False(t, looksLikeSecret("throttle_user_1011"))      // too short after check
	assert.False(t, looksLikeSecret("application_json"))        // English words
	assert.False(t, looksLikeSecret("password_hash_algorithm")) // English words
	assert.False(t, looksLikeSecret("POST"))                    // too short

	// Edge cases
	assert.False(t, looksLikeSecret(""))
	assert.False(t, looksLikeSecret("short"))
	assert.False(t, looksLikeSecret("alllowercase")) // single class
}

func TestShannonEntropy(t *testing.T) {
	// Hex string — high entropy (~3.6 bits)
	hexEntropy := shannonEntropy("cdd6190b063b4da02e8beb855b65e55428055c49")
	assert.True(t, hexEntropy >= 3.5, "hex entropy should be >= 3.5, got %.2f", hexEntropy)

	// Mixed-case alphanumeric — very high entropy (~4.0+ bits)
	randomEntropy := shannonEntropy("aB3xK9mPq2wF7vL0")
	assert.True(t, randomEntropy >= 3.5, "random entropy should be >= 3.5, got %.2f", randomEntropy)

	// Repeated chars — low entropy
	repeatEntropy := shannonEntropy("aaaaaaaaaa")
	assert.True(t, repeatEntropy < 1.0, "repeated chars should have low entropy, got %.2f", repeatEntropy)

	// Empty string
	assert.Equal(t, 0.0, shannonEntropy(""))

	// Note: English words like "auth_group_permissions" can have entropy ~3.7,
	// overlapping with real secrets. That's why looksLikeSecret uses character-class
	// diversity as the primary filter, with entropy as a secondary check.
}

func TestDetectSensitiveData_LowConfidence_EntropyFilter(t *testing.T) {
	patterns, err := LoadPatterns("low")
	require.NoError(t, err)

	// Real webhook token in URL — should be detected
	matches := DetectSensitiveData(
		`GET /api/webhooks/pagerduty?token=cdd6190b063b4da02e8beb855b65e55428055c491a48b2bdf1c85660391506882e1feb13`,
		"hash1", patterns)
	assert.True(t, len(matches) > 0, "real webhook token should be detected")

	// SQL table name containing keyword — should NOT be detected
	matches = DetectSensitiveData(
		`SELECT * FROM auth_group_permissions WHERE id = 1`,
		"hash2", patterns)
	assert.Equal(t, 0, len(matches), "SQL table name should not trigger detection")

	// Redis cache key — should NOT be detected
	matches = DetectSensitiveData(
		`cache.key: throttle_user_1011_ratelimit`,
		"hash3", patterns)
	assert.Equal(t, 0, len(matches), "cache key should not trigger detection")
}

func TestDetectSensitiveDataWithPrefilter(t *testing.T) {
	patterns, err := LoadPatterns("high")
	require.NoError(t, err)

	// Should detect AWS key
	matches := DetectSensitiveData("AWS access key: AKIAIOSFODNN7EXAMPLE", "testhash", patterns)
	require.Len(t, matches, 1)
	assert.Contains(t, matches[0].name, "AWS")

	// Should detect GitHub PAT (ghp_ + exactly 36 alphanumeric chars)
	matches = DetectSensitiveData("token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "testhash", patterns)
	require.Len(t, matches, 1)
	assert.Equal(t, "github-pat", matches[0].name)

	// Normal log line should not match
	matches = DetectSensitiveData("INFO: request completed successfully in 200ms", "testhash", patterns)
	assert.Len(t, matches, 0)
}
