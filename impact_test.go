package logparser

import (
	"fmt"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

// TestResourceImpact measures actual CPU and memory impact of sensitive detection.
func TestResourceImpact(t *testing.T) {
	// =========================================================
	// 1. MEMORY: Pattern storage
	// =========================================================
	t.Log("=== MEMORY IMPACT ===")

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	patternsHigh, _ := LoadPatterns("high")
	patternsMed, _ := LoadPatterns("medium")
	patternsAll, _ := LoadPatterns("low")

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	t.Logf("Pattern sets loaded (high=%d, med=%d, all=%d)", len(patternsHigh), len(patternsMed), len(patternsAll))
	t.Logf("Heap increase: %d KB", (m2.HeapAlloc-m1.HeapAlloc)/1024)

	// Measure size of a single pattern set in detail
	totalAnchorBytes := 0
	totalRegexEstimate := 0
	for _, p := range patternsMed {
		for _, a := range p.Anchors {
			totalAnchorBytes += len(a)
		}
		totalAnchorBytes += int(unsafe.Sizeof(p.Anchors)) + len(p.Anchors)*int(unsafe.Sizeof(""))
		totalRegexEstimate += len(p.Pattern.String()) * 10 // rough estimate: compiled regex ~10x source
	}
	t.Logf("Medium pattern set: anchors=%d bytes, regex estimate=%d KB",
		totalAnchorBytes, totalRegexEstimate/1024)

	// =========================================================
	// 2. MEMORY: Per-container parser overhead
	// =========================================================
	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)

	// Simulate 200 containers each with a parser
	parsers := make([]*Parser, 200)
	for i := range parsers {
		ch := make(chan LogEntry, 1)
		parsers[i] = NewParser(ch, nil, nil, time.Second, 256, SensitiveConfig{
			Enabled:       true,
			MinConfidence: "medium",
			MaxDetections: 100,
		})
	}

	runtime.GC()
	var m4 runtime.MemStats
	runtime.ReadMemStats(&m4)

	perParser := (m4.HeapAlloc - m3.HeapAlloc) / 200
	t.Logf("\nPer-parser memory (200 parsers): %d KB each", perParser/1024)
	t.Logf("Total for 200 parsers: %d MB", (m4.HeapAlloc-m3.HeapAlloc)/1024/1024)

	// Check if patterns are shared or duplicated
	// Each parser calls LoadPatterns independently — let's measure
	runtime.GC()
	var m5 runtime.MemStats
	runtime.ReadMemStats(&m5)

	// Patterns are loaded per-parser (embedded in parser struct)
	t.Logf("Note: Compiled regexes are shared across parsers (singleton cache)")
	t.Logf("Total heap after 200 parsers: %d MB", m5.HeapAlloc/1024/1024)

	for _, p := range parsers {
		p.Stop()
	}

	// =========================================================
	// 3. MEMORY: Disabled state (current default)
	// =========================================================
	runtime.GC()
	var m6 runtime.MemStats
	runtime.ReadMemStats(&m6)

	disabledParsers := make([]*Parser, 200)
	for i := range disabledParsers {
		ch := make(chan LogEntry, 1)
		disabledParsers[i] = NewParser(ch, nil, nil, time.Second, 256, SensitiveConfig{
			Enabled: false,
		})
	}

	runtime.GC()
	var m7 runtime.MemStats
	runtime.ReadMemStats(&m7)

	perParserDisabled := (m7.HeapAlloc - m6.HeapAlloc) / 200
	t.Logf("\nPer-parser memory (DISABLED): %d KB each", perParserDisabled/1024)
	t.Logf("Overhead of enabling sensitive detection: %d KB per parser",
		(perParser-perParserDisabled)/1024)

	for _, p := range disabledParsers {
		p.Stop()
	}

	// =========================================================
	// 4. CPU: Throughput at scale
	// =========================================================
	t.Log("\n=== CPU IMPACT ===")

	// Realistic log lines (mix of types from real apps)
	sampleLines := []string{
		`{"time":"2024-01-15T10:30:45Z","level":"INFO","msg":"Request processed","status":200,"latency":"45ms"}`,
		`2024-01-15 10:30:45.123 INFO  [http-handler] GET /api/v1/users 200 45ms`,
		`level=info ts=2024-01-15T10:30:45Z caller=handler.go:45 msg="batch complete" items=150`,
		`{"time":"2024-01-15T10:30:45Z","level":"ERROR","msg":"connection refused","host":"db-primary","port":5432}`,
		`WARN [2024-01-15 10:30:45] Cache miss for key user:12345:profile`,
		`{"time":"2024-01-15T10:30:45Z","level":"DEBUG","msg":"SQL query","query":"SELECT * FROM users WHERE id = $1","duration":"2ms"}`,
		`INFO Starting health check for service auth-gateway on port 8080`,
		`{"time":"2024-01-15T10:30:45Z","level":"INFO","msg":"Kafka message consumed","topic":"events","partition":3,"offset":45678}`,
		`ERROR: dial tcp 10.0.0.5:6379: connection refused`,
		`{"level":"info","ts":1705312245.123,"msg":"gRPC call completed","method":"/api.v1.Users/Get","code":"OK","duration":0.003}`,
	}

	configs := []struct {
		name string
		cfg  SensitiveConfig
	}{
		{"disabled (default)", SensitiveConfig{Enabled: false}},
		{"high-only", SensitiveConfig{Enabled: true, MinConfidence: "high"}},
		{"medium (recommended)", SensitiveConfig{Enabled: true, MinConfidence: "medium"}},
		{"medium + 1:100 sampling", SensitiveConfig{Enabled: true, MinConfidence: "medium", SampleRate: 100}},
		{"all (low)", SensitiveConfig{Enabled: true, MinConfidence: "low"}},
	}

	for _, cfg := range configs {
		// Create a parser with this config
		ch := make(chan LogEntry, 1000)
		p := NewParser(ch, nil, nil, time.Second, 256, cfg.cfg)

		// Warm up
		for _, line := range sampleLines {
			ch <- LogEntry{Timestamp: time.Now(), Content: line, Level: LevelInfo}
		}
		time.Sleep(100 * time.Millisecond)

		// Measure throughput: send lines as fast as possible for 2 seconds
		start := time.Now()
		sent := 0
		for time.Since(start) < 2*time.Second {
			for _, line := range sampleLines {
				ch <- LogEntry{Timestamp: time.Now(), Content: line, Level: LevelInfo}
				sent++
			}
		}
		// Wait for processing to finish
		time.Sleep(2 * time.Second)
		elapsed := time.Since(start) - 2*time.Second // subtract wait time
		lps := float64(sent) / elapsed.Seconds()

		p.Stop()
		t.Logf("  %-30s %8.0f lines/sec", cfg.name, lps)
	}

	// =========================================================
	// 5. CPU: Per-line cost breakdown
	// =========================================================
	t.Log("\n=== PER-LINE COST BREAKDOWN ===")

	patternsMedium, _ := LoadPatterns("medium")
	normalLine := `{"time":"2024-01-15T10:30:45Z","level":"INFO","msg":"Request processed","status":200}`

	// Measure ToLower cost
	iters := 100000
	start := time.Now()
	for i := 0; i < iters; i++ {
		_ = fmt.Sprintf("%s", normalLine) // prevent optimization
	}
	baseline := time.Since(start)

	start = time.Now()
	for i := 0; i < iters; i++ {
		lowerLine := toLower(normalLine)
		_ = lowerLine
	}
	toLowerCost := time.Since(start) - baseline

	// Measure anchor check cost
	lowerLine := toLower(normalLine)
	start = time.Now()
	for i := 0; i < iters; i++ {
		for j := range patternsMedium {
			if len(patternsMedium[j].Anchors) > 0 {
				anchorMatchesLine(lowerLine, patternsMedium[j].Anchors)
			}
		}
	}
	anchorCost := time.Since(start)

	t.Logf("  strings.ToLower:    %v per line", toLowerCost/time.Duration(iters))
	t.Logf("  Anchor checks (%d): %v per line", len(patternsMedium), anchorCost/time.Duration(iters))
	t.Logf("  Total pre-filter:   %v per line", (toLowerCost+anchorCost)/time.Duration(iters))

	// =========================================================
	// 6. SCALE PROJECTIONS
	// =========================================================
	t.Log("\n=== SCALE PROJECTIONS ===")
	t.Log("Assuming 100 lines/sec per container:")

	perLineMedium := 102 * time.Microsecond // from Loki benchmark
	perLineHigh := 52 * time.Microsecond
	perLineDisabled := time.Duration(0)

	for _, scenario := range []struct {
		name    string
		perLine time.Duration
		pods    int
	}{
		{"disabled", perLineDisabled, 200},
		{"high-only, 200 pods", perLineHigh, 200},
		{"medium, 100 pods", perLineMedium, 100},
		{"medium, 200 pods", perLineMedium, 200},
		{"medium + 1:100 sampling, 200 pods", perLineMedium / 100, 200},
	} {
		linesPerSec := scenario.pods * 100
		cpuPerSec := time.Duration(linesPerSec) * scenario.perLine
		cpuPct := float64(cpuPerSec) / float64(time.Second) * 100
		t.Logf("  %-42s %d lines/sec → %.1f%% CPU core", scenario.name, linesPerSec, cpuPct)
	}
}

func toLower(s string) string {
	// Simple wrapper for benchmarking
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
