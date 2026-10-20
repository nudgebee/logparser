package logparser

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestCriDecoder(t *testing.T) {
	d := CriDecoder{}

	line, err := d.DecodeEntry("2026-10-19T10:00:00.123456789Z stderr F connection refused: retrying")
	require.NoError(t, err)
	assert.Equal(t, DecodedLine{
		Content:   "connection refused: retrying",
		Timestamp: time.Date(2026, 10, 19, 10, 0, 0, 123456789, time.UTC),
		Stream:    "stderr",
	}, line)

	line, err = d.DecodeEntry("2026-10-19T10:00:00.5+05:30 stdout P first part of a long line ")
	require.NoError(t, err)
	assert.True(t, line.Partial)
	assert.Equal(t, "first part of a long line ", line.Content)
	assert.Equal(t, "stdout", line.Stream)

	line, err = d.DecodeEntry("2026-10-19T10:00:00Z stdout F ")
	require.NoError(t, err)
	assert.Equal(t, "", line.Content)

	_, err = d.DecodeEntry("2026-10-19T10:00:00Z stdout F")
	assert.Error(t, err, "no content field")

	// Decode keeps its old answer.
	content, err := d.Decode("2026-10-19T10:00:00Z stdout F a b c")
	require.NoError(t, err)
	assert.Equal(t, "a b c", content)
}

func TestDockerJsonDecoder(t *testing.T) {
	d := DockerJsonDecoder{}

	line, err := d.DecodeEntry(`{"log":"started on :8080\n","stream":"stdout","time":"2026-10-19T10:00:00.25Z"}`)
	require.NoError(t, err)
	assert.Equal(t, DecodedLine{
		Content:   "started on :8080",
		Timestamp: time.Date(2026, 10, 19, 10, 0, 0, 250000000, time.UTC),
		Stream:    "stdout",
	}, line)

	// The json-file driver splits lines over 16KB; only the last part ends in a newline.
	line, err = d.DecodeEntry(`{"log":"part of a long line","stream":"stderr","time":"2026-10-19T10:00:00Z"}`)
	require.NoError(t, err)
	assert.True(t, line.Partial)

	_, err = d.DecodeEntry("not json")
	assert.Error(t, err)

	// A malformed or missing time leaves the time unknown, not the line undecoded.
	for _, src := range []string{`{"log":"x\n","time":""}`, `{"log":"x\n","time":"2026-10-19 10:00:00"}`, `{"log":"x\n"}`} {
		line, err = d.DecodeEntry(src)
		require.NoError(t, err, src)
		assert.Equal(t, DecodedLine{Content: "x"}, line, src)
		content, err := d.Decode(src)
		require.NoError(t, err, src)
		assert.Equal(t, "x\n", content, src)
	}

	content, err := d.Decode(`{"log":"x\n","stream":"stdout","time":"2026-10-19T10:00:00Z"}`)
	require.NoError(t, err)
	assert.Equal(t, "x\n", content, "Decode keeps its old answer")
}

func TestPartialLines(t *testing.T) {
	p := partialLines{}
	t0 := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

	_, whole := p.add(LogEntry{Timestamp: t0, Content: "hello ", Stream: "stdout"}, true, t0)
	assert.False(t, whole)
	// A stderr line between the parts is whole on its own.
	e, whole := p.add(LogEntry{Timestamp: t0.Add(time.Millisecond), Content: "oops", Stream: "stderr"}, false, t0)
	require.True(t, whole)
	assert.Equal(t, "oops", e.Content)
	_, whole = p.add(LogEntry{Timestamp: t0.Add(2 * time.Millisecond), Content: "big ", Stream: "stdout"}, true, t0)
	assert.False(t, whole)
	e, whole = p.add(LogEntry{Timestamp: t0.Add(3 * time.Millisecond), Content: "world", Stream: "stdout"}, false, t0)
	require.True(t, whole)
	assert.Equal(t, LogEntry{Timestamp: t0, Content: "hello big world", Stream: "stdout"}, e, "the first part's time")
	assert.Empty(t, p)

	// A runaway line stops growing at the multiline limit, on a character boundary.
	p.add(LogEntry{Content: strings.Repeat("a", multilineCollectorLimit-1), Stream: "stdout"}, true, t0)
	e, _ = p.add(LogEntry{Content: "éé", Stream: "stdout"}, false, t0)
	assert.Len(t, e.Content, multilineCollectorLimit-1, "é is two bytes; half of one is dropped")

	// A line whose next part is overdue comes out as it is; one still growing stays.
	p.add(LogEntry{Content: "Enter password: ", Stream: "stdout"}, true, t0)
	p.add(LogEntry{Content: "still ", Stream: "stderr"}, true, t0)
	p.add(LogEntry{Content: "growing ", Stream: "stderr"}, true, t0.Add(time.Second))
	assert.Equal(t, []LogEntry{{Content: "Enter password: ", Stream: "stdout"}}, p.expired(t0.Add(time.Millisecond)))
	assert.Len(t, p, 1)
	assert.Empty(t, p.expired(t0.Add(time.Millisecond)))
}

// Lines read from a CRI log file reach the callback with the runtime's time and
// stream, split lines joined, and stdout and stderr never mixed in one message.
func TestParserRuntimeLines(t *testing.T) {
	type got struct {
		ts      time.Time
		stream  string
		content string
	}
	var mu sync.Mutex
	var msgs []got
	ch := make(chan LogEntry)
	p := NewParser(ch, CriDecoder{}, func(ts time.Time, _ Level, _ string, msg string, _ map[string]string, stream string) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, got{ts, stream, msg})
	}, 20*time.Millisecond, 10, true, rate.NewLimiter(rate.Inf, 1), SensitiveConfig{})
	defer p.Stop()

	read := time.Now()
	for _, l := range []string{
		"2026-10-19T10:00:00Z stdout P Exception in thread \"main\" java.lang.",
		"2026-10-19T10:00:00.001Z stderr F a stderr line",
		"2026-10-19T10:00:00.002Z stdout F IllegalStateException: boom",
		"2026-10-19T10:00:00.003Z stdout F \tat com.example.Main.main(Main.java:10)",
	} {
		ch <- LogEntry{Timestamp: read, Content: l, Level: LevelUnknown}
	}
	assert.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(msgs) == 2 }, time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, got{time.Date(2026, 10, 19, 10, 0, 0, 1000000, time.UTC), "stderr", "a stderr line"}, msgs[0])
	assert.Equal(t, got{
		time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC), "stdout",
		"Exception in thread \"main\" java.lang.IllegalStateException: boom\n\tat com.example.Main.main(Main.java:10)",
	}, msgs[1])
}

// A part whose line never ends (a prompt, an unterminated last line) is passed on
// after the multiline timeout instead of joining the stream's next line.
func TestParserFlushesDanglingPart(t *testing.T) {
	var mu sync.Mutex
	var msgs []string
	ch := make(chan LogEntry)
	p := NewParser(ch, CriDecoder{}, func(_ time.Time, _ Level, _ string, msg string, _ map[string]string, _ string) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, msg)
	}, 20*time.Millisecond, 10, true, rate.NewLimiter(rate.Inf, 1), SensitiveConfig{})
	defer p.Stop()
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(msgs) }

	ch <- LogEntry{Timestamp: time.Now(), Content: "2026-10-19T10:00:00Z stdout P Enter password: "}
	assert.Eventually(t, func() bool { return count() == 1 }, time.Second, 10*time.Millisecond)
	ch <- LogEntry{Timestamp: time.Now(), Content: "2026-10-19T10:05:00Z stdout F next unrelated line"}
	assert.Eventually(t, func() bool { return count() == 2 }, time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "next unrelated line", msgs[1])
	assert.Equal(t, "Enter password:", strings.TrimSpace(msgs[0]))
}

func TestMultilineCollectorKeepsStreamsApart(t *testing.T) {
	m := NewMultilineCollector(t.Context(), 20*time.Millisecond, multilineCollectorLimit)
	ts := time.Now()
	m.Add(LogEntry{Timestamp: ts, Content: "panic: boom", Stream: "stderr"})
	// An indented line would continue the message, but it comes from stdout.
	m.Add(LogEntry{Timestamp: ts, Content: "  ready", Stream: "stdout"})

	first := <-m.Messages
	second := <-m.Messages
	assert.Equal(t, "stderr", first.Stream)
	assert.Equal(t, "panic: boom", first.Content)
	assert.Equal(t, "stdout", second.Stream)
	assert.Equal(t, "ready", second.Content)
}
