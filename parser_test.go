package logparser

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser(t *testing.T) {
	ch := make(chan LogEntry)
	parser := NewParser(ch, nil, nil, time.Second, 256, SensitiveConfig{
		Enabled:       true,
		MinConfidence: "high",
	})

	ch <- LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: AKIAIOSFODNN7EXAMPLE", Level: LevelInfo}

	// Wait for multiline collector flush (1s timeout) + processing.
	time.Sleep(3 * time.Second)
	counts := parser.GetSensitiveCounters()
	assert.Equal(t, 1, len(counts))
	parser.Stop()
}

func TestParserSensitiveDisabled(t *testing.T) {
	ch := make(chan LogEntry)
	parser := NewParser(ch, nil, nil, time.Second, 256, SensitiveConfig{
		Enabled: false,
	})

	ch <- LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: AKIAIOSFODNN7EXAMPLE", Level: LevelInfo}
	time.Sleep(3 * time.Second)
	counts := parser.GetSensitiveCounters()
	assert.Equal(t, 0, len(counts))
	parser.Stop()
}

func TestParserSensitiveSampling(t *testing.T) {
	ch := make(chan LogEntry)
	// Sample 1 in 10 lines
	parser := NewParser(ch, nil, nil, time.Second, 256, SensitiveConfig{
		Enabled:       true,
		SampleRate:    10,
		MinConfidence: "high",
	})

	// Send 20 lines, only ~2 should be checked (lines 10 and 20).
	for i := 0; i < 20; i++ {
		ch <- LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: AKIAIOSFODNN7EXAMPLE", Level: LevelInfo}
	}
	time.Sleep(3 * time.Second)
	counts := parser.GetSensitiveCounters()
	// Should detect the pattern, but with fewer messages than 20
	if len(counts) > 0 {
		total := 0
		for _, c := range counts {
			total += c.Messages
		}
		assert.True(t, total < 20, "sampling should reduce detections, got %d", total)
		assert.True(t, total > 0, "should still detect some")
	}
	parser.Stop()
}

func TestParserSensitiveMaxDetections(t *testing.T) {
	ch := make(chan LogEntry)
	parser := NewParser(ch, nil, nil, time.Second, 256, SensitiveConfig{
		Enabled:       true,
		MinConfidence: "high",
		MaxDetections: 1,
	})

	ch <- LogEntry{Timestamp: time.Now(), Content: "AWS key: AKIAIOSFODNN7EXAMPLE", Level: LevelError}
	ch <- LogEntry{Timestamp: time.Now(), Content: "GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", Level: LevelError}
	time.Sleep(3 * time.Second)
	counts := parser.GetSensitiveCounters()
	// Should stop after first unique detection
	assert.LessOrEqual(t, len(counts), 1)
	parser.Stop()
}

func TestParserMinConfidence(t *testing.T) {
	// Load only high-confidence patterns
	high, err := LoadPatterns("high")
	require.NoError(t, err)
	// Load all patterns (low = include everything)
	all, err := LoadPatterns("low")
	require.NoError(t, err)

	assert.True(t, len(high) < len(all), "high-confidence set should be smaller than full set")
	assert.True(t, len(high) > 0, "should have some high-confidence patterns")

	// Verify all high-confidence patterns are actually marked high
	for _, p := range high {
		assert.Equal(t, "high", p.Confidence, "pattern %s should be high confidence", p.Name)
	}
}

func TestParserJSONLevelOverride(t *testing.T) {
	// Verify that JSON structured level overrides GuessLevel in the full pipeline.
	// An INFO log with "error" in the message must NOT be pattern-grouped as error.
	p := &Parser{
		patterns:              map[patternKey]*patternStat{},
		patternsPerLevel:      map[Level]int{},
		patternsPerLevelLimit: 256,
		sensitivePatterns:     map[sensitivePatternKey]*sensitivePatternStat{},
	}

	// This JSON log has level=INFO but "error" in the msg and "ErrorRate" in type.
	// Old GuessLevel would misclassify based on text scanning.
	p.inc(Message{
		Timestamp: time.Now(),
		Content:   `{"time":"2026-04-05T06:02:13Z","level":"INFO","msg":"anomaly: processing anomaly","type":"ErrorRate"}`,
		Level:     LevelUnknown, // as set by multiline collector's GuessLevel
	})

	// Should be counted as INFO with empty hash (no pattern grouping)
	counters := p.GetCounters()
	require.Equal(t, 1, len(counters))
	assert.Equal(t, LevelInfo, counters[0].Level)
	assert.Equal(t, "", counters[0].Hash, "INFO logs should have empty pattern hash")

	// Verify no error-level patterns were created
	assert.Equal(t, 0, p.patternsPerLevel[LevelError])

	// Now send an actual ERROR JSON log
	p.inc(Message{
		Timestamp: time.Now(),
		Content:   `{"time":"2026-04-05T06:02:14Z","level":"ERROR","msg":"connection timeout","err":"dial tcp: timeout"}`,
		Level:     LevelUnknown,
	})

	counters = p.GetCounters()
	var errorCounters []LogCounter
	for _, c := range counters {
		if c.Level == LevelError {
			errorCounters = append(errorCounters, c)
		}
	}
	require.Equal(t, 1, len(errorCounters))
	assert.NotEmpty(t, errorCounters[0].Hash, "ERROR logs should have a pattern hash")
}

func TestParserCardinalityLimit(t *testing.T) {
	p := &Parser{
		patterns:              map[patternKey]*patternStat{},
		patternsPerLevel:      map[Level]int{},
		patternsPerLevelLimit: 2,
		sensitivePatterns:     map[sensitivePatternKey]*sensitivePatternStat{},
	}

	msgs := []string{
		"error alpha beta gamma",
		"error delta epsilon zeta",
		"error eta theta iota",
		"error kappa lambda mu",
	}
	for _, m := range msgs {
		p.inc(Message{Timestamp: time.Now(), Content: m, Level: LevelError})
	}
	assert.Equal(t, 2, p.patternsPerLevel[LevelError])

	fallbackKey := patternKey{level: LevelError, hash: unclassifiedPatternHash}
	stat, ok := p.patterns[fallbackKey]
	require.True(t, ok)
	assert.Equal(t, 2, stat.messages)
	assert.Equal(t, unclassifiedPatternLabel, stat.sample)

	counters := p.GetCounters()
	sort.Slice(counters, func(i, j int) bool { return counters[i].Sample < counters[j].Sample })

	assert.Equal(t, 3, len(counters))
	assert.Equal(t, msgs[0], counters[0].Sample)
	assert.Equal(t, msgs[1], counters[1].Sample)
	assert.Equal(t, unclassifiedPatternLabel, counters[2].Sample)
	assert.Equal(t, unclassifiedPatternHash, counters[2].Hash)
}
