package logparser

import (
	"strings"
	"testing"
)

// BenchmarkDetectSensitiveData_NoMatch benchmarks detection on a normal log line
// that doesn't contain any sensitive data (worst case: all patterns checked).
func BenchmarkDetectSensitiveData_NoMatch(b *testing.B) {
	patterns, err := LoadPatterns("medium")
	if err != nil {
		b.Fatal(err)
	}
	line := `2024-01-15T10:30:45.123Z INFO  [http-handler] Request processed: method=GET path=/api/v1/users status=200 latency=45ms bytes=1234 user_agent="Mozilla/5.0"`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectSensitiveData(line, "abc123", patterns)
	}
}

// BenchmarkDetectSensitiveData_NoMatch_HighOnly benchmarks with only high-confidence patterns.
func BenchmarkDetectSensitiveData_NoMatch_HighOnly(b *testing.B) {
	patterns, err := LoadPatterns("high")
	if err != nil {
		b.Fatal(err)
	}
	line := `2024-01-15T10:30:45.123Z INFO  [http-handler] Request processed: method=GET path=/api/v1/users status=200 latency=45ms bytes=1234 user_agent="Mozilla/5.0"`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectSensitiveData(line, "abc123", patterns)
	}
}

// BenchmarkDetectSensitiveData_WithMatch benchmarks detection when a secret is present.
func BenchmarkDetectSensitiveData_WithMatch(b *testing.B) {
	patterns, err := LoadPatterns("medium")
	if err != nil {
		b.Fatal(err)
	}
	line := `ERROR: Failed to authenticate with AWS key AKIAIOSFODNN7EXAMPLE in region us-east-1`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectSensitiveData(line, "abc123", patterns)
	}
}

// BenchmarkDetectSensitiveData_LongLine benchmarks detection on a verbose log line.
func BenchmarkDetectSensitiveData_LongLine(b *testing.B) {
	patterns, err := LoadPatterns("medium")
	if err != nil {
		b.Fatal(err)
	}
	line := strings.Repeat(`level=info ts=2024-01-15T10:30:45.123Z caller=handler.go:45 msg="Processing batch request" `, 5)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DetectSensitiveData(line, "abc123", patterns)
	}
}

// BenchmarkPrefilterOnly benchmarks just the anchor pre-filter step (no regex).
func BenchmarkPrefilterOnly(b *testing.B) {
	patterns, err := LoadPatterns("medium")
	if err != nil {
		b.Fatal(err)
	}
	line := `2024-01-15T10:30:45.123Z INFO request processed successfully`
	lowerLine := strings.ToLower(line)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := range patterns {
			if len(patterns[j].Anchors) > 0 {
				anchorMatchesLine(lowerLine, patterns[j].Anchors)
			}
		}
	}
}

// BenchmarkOldStyle_NoPrefilter simulates the old approach: run all regexes without pre-filtering.
func BenchmarkOldStyle_NoPrefilter(b *testing.B) {
	patterns, err := LoadPatterns("medium")
	if err != nil {
		b.Fatal(err)
	}
	line := `2024-01-15T10:30:45.123Z INFO  [http-handler] Request processed: method=GET path=/api/v1/users status=200 latency=45ms bytes=1234`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Simulate old approach: no anchor check, run every regex
		for j := range patterns {
			if patterns[j].Pattern.MatchString(line) {
				_ = patterns[j].Pattern.FindString(line)
				break
			}
		}
	}
}
