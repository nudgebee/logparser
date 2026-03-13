package logparser

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type lokiQueryResponse struct {
	Data struct {
		Result []struct {
			Values [][]string `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// fetchLokiLogs queries Loki for recent logs from a pod.
func fetchLokiLogs(lokiURL, podName string, limit int) ([]string, error) {
	query := fmt.Sprintf(`{pod=~"%s.*"}`, podName)
	params := url.Values{
		"query": {query},
		"limit": {fmt.Sprintf("%d", limit)},
	}
	reqURL := fmt.Sprintf("%s/loki/api/v1/query_range?%s&start=%d&end=%d",
		lokiURL, params.Encode(),
		time.Now().Add(-1*time.Hour).UnixNano(),
		time.Now().UnixNano(),
	)

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("loki request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("loki returned %d: %s", resp.StatusCode, string(body[:minInt(len(body), 200)]))
	}

	var result lokiQueryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	var lines []string
	for _, stream := range result.Data.Result {
		for _, entry := range stream.Values {
			if len(entry) >= 2 {
				lines = append(lines, entry[1])
			}
		}
	}
	return lines, nil
}

// TestLokiBenchmark fetches real logs from Loki and benchmarks sensitive data detection.
// Run with: go test -v -run TestLokiBenchmark -timeout 60s -count=1
// Requires Loki at localhost:3100 with services-server pod logs.
func TestLokiBenchmark(t *testing.T) {
	lokiURL := "http://localhost:3100"
	podName := "services-server"
	logLimit := 5000

	t.Logf("Fetching up to %d logs from Loki for pod %s...", logLimit, podName)
	lines, err := fetchLokiLogs(lokiURL, podName, logLimit)
	if err != nil {
		t.Skipf("Skipping Loki benchmark (Loki not available): %v", err)
		return
	}

	if len(lines) == 0 {
		t.Skipf("No logs found for pod %s", podName)
		return
	}
	t.Logf("Fetched %d log lines", len(lines))

	// Show sample lines
	for i, line := range lines {
		if i >= 3 {
			break
		}
		if len(line) > 120 {
			line = line[:120] + "..."
		}
		t.Logf("  Sample[%d]: %s", i, line)
	}

	// Load patterns at each confidence level
	configs := []struct {
		name       string
		confidence string
	}{
		{"high-only", "high"},
		{"medium+high", "medium"},
		{"all (low+medium+high)", "low"},
	}

	for _, cfg := range configs {
		patterns, err := LoadPatterns(cfg.confidence)
		if err != nil {
			t.Fatalf("LoadPatterns(%s): %v", cfg.confidence, err)
		}

		t.Logf("\n=== %s (%d patterns) ===", cfg.name, len(patterns))

		// Benchmark: time all lines
		start := time.Now()
		totalMatches := 0
		matchNames := map[string]int{}
		for _, line := range lines {
			matches := DetectSensitiveData(line, "bench", patterns)
			totalMatches += len(matches)
			for _, m := range matches {
				matchNames[m.name]++
			}
		}
		elapsed := time.Since(start)

		perLine := elapsed / time.Duration(len(lines))
		linesPerSec := float64(len(lines)) / elapsed.Seconds()

		t.Logf("  Lines:       %d", len(lines))
		t.Logf("  Total time:  %v", elapsed)
		t.Logf("  Per line:    %v", perLine)
		t.Logf("  Lines/sec:   %.0f", linesPerSec)
		t.Logf("  Matches:     %d", totalMatches)

		if totalMatches > 0 {
			t.Logf("  Match breakdown:")
			for name, count := range matchNames {
				t.Logf("    %s: %d", name, count)
			}

			// Show sample matched lines
			t.Logf("  Sample matches:")
			shown := 0
			for _, line := range lines {
				matches := DetectSensitiveData(line, "bench", patterns)
				if len(matches) > 0 {
					sample := line
					if len(sample) > 150 {
						sample = sample[:150] + "..."
					}
					t.Logf("    [%s] %s", matches[0].name, sample)
					shown++
					if shown >= 5 {
						break
					}
				}
			}
		}

		// Compare with old-style (no pre-filter)
		startOld := time.Now()
		for _, line := range lines {
			for j := range patterns {
				if patterns[j].Pattern.MatchString(line) {
					_ = patterns[j].Pattern.FindString(line)
					break
				}
			}
		}
		elapsedOld := time.Since(startOld)

		speedup := float64(elapsedOld) / float64(elapsed)
		t.Logf("  Old style:   %v (%.1fx slower)", elapsedOld, speedup)
	}

	// Test with sampling
	t.Logf("\n=== Sampling benchmark (medium confidence, 1-in-100) ===")
	patterns, _ := LoadPatterns("medium")
	start := time.Now()
	sampled := 0
	for i, line := range lines {
		if i%100 != 0 {
			continue
		}
		sampled++
		DetectSensitiveData(line, "bench", patterns)
	}
	elapsed := time.Since(start)
	t.Logf("  Sampled:     %d/%d lines", sampled, len(lines))
	t.Logf("  Total time:  %v", elapsed)
	if sampled > 0 {
		t.Logf("  Per sampled: %v", elapsed/time.Duration(sampled))
	}

	// Estimate throughput at scale
	t.Logf("\n=== Throughput estimates ===")
	patternsHigh, _ := LoadPatterns("high")
	patternsMed, _ := LoadPatterns("medium")

	for _, scenario := range []struct {
		name     string
		patterns []PrecompiledPattern
	}{
		{"high-only", patternsHigh},
		{"medium+high", patternsMed},
	} {
		benchStart := time.Now()
		iterations := 0
		for time.Since(benchStart) < 2*time.Second {
			for _, line := range lines {
				DetectSensitiveData(line, "bench", scenario.patterns)
				iterations++
			}
		}
		benchElapsed := time.Since(benchStart)
		lps := float64(iterations) / benchElapsed.Seconds()
		t.Logf("  %s: %.0f lines/sec (%.0f pods @ 100 lines/sec)", scenario.name, lps, lps/100)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
