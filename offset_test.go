package logparser

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

type offsetMsg struct {
	content string
	offset  int64
}

func offsetParser(t *testing.T, decoder Decoder) (chan<- LogEntry, func() []offsetMsg) {
	var mu sync.Mutex
	var msgs []offsetMsg
	ch := make(chan LogEntry)
	p := NewParser(ch, decoder, func(_ time.Time, _ Level, _ string, msg string, _ map[string]string, _ string, offset int64) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, offsetMsg{msg, offset})
	}, 20*time.Millisecond, 10, true, rate.NewLimiter(rate.Inf, 1), SensitiveConfig{})
	t.Cleanup(p.Stop)
	return ch, func() []offsetMsg {
		mu.Lock()
		defer mu.Unlock()
		return append([]offsetMsg(nil), msgs...)
	}
}

// A message carries the offset of the last line it consumed, so a reader that
// records it resumes after the whole message and never inside it.
func TestMessageCarriesLastLineOffset(t *testing.T) {
	ch, msgs := offsetParser(t, nil)
	for i, l := range []string{
		"first message",
		"java.lang.IllegalStateException: boom",
		"\tat com.example.Main.main(Main.java:10)",
		"\tat com.example.Main.run(Main.java:20)",
		"third message",
	} {
		ch <- LogEntry{Timestamp: time.Now(), Content: l, Offset: int64(100 * (i + 1))}
	}
	assert.Eventually(t, func() bool { return len(msgs()) == 3 }, time.Second, 5*time.Millisecond)
	got := msgs()
	assert.Equal(t, int64(100), got[0].offset)
	assert.Equal(t, int64(400), got[1].offset)
	assert.Equal(t, int64(500), got[2].offset)
}

// A message still collecting continuation lines has not been emitted, so nothing
// past its first line can be acknowledged yet; once it is emitted, its offset covers
// every line, including lines dropped over the size limit.
func TestOpenMessageOffsetCoversDroppedLines(t *testing.T) {
	ch, msgs := offsetParser(t, nil)
	ch <- LogEntry{Timestamp: time.Now(), Content: "panic: boom", Offset: 10}
	big := "\t" + strings.Repeat("x", multilineCollectorLimit)
	ch <- LogEntry{Timestamp: time.Now(), Content: big, Offset: 20}
	ch <- LogEntry{Timestamp: time.Now(), Content: "\tdropped over the limit", Offset: 30}
	assert.Eventually(t, func() bool { return len(msgs()) == 1 }, time.Second, 5*time.Millisecond)
	assert.Equal(t, int64(30), msgs()[0].offset)
}

// While one stream's line is split and only partly read, the other stream's
// messages must not acknowledge past the split line's first part: their offset is
// 0 (nothing new to acknowledge). The joined line then carries its last part's.
func TestNoOffsetPastAPendingPartialLine(t *testing.T) {
	ch, msgs := offsetParser(t, CriDecoder{})
	for _, e := range []LogEntry{
		{Content: "2026-10-19T10:00:00Z stdout F before", Offset: 10},
		{Content: "2026-10-19T10:00:00Z stdout P split ", Offset: 20},
		{Content: "2026-10-19T10:00:00.001Z stderr F other stream", Offset: 30},
		{Content: "2026-10-19T10:00:00.002Z stdout F line", Offset: 40},
	} {
		e.Timestamp = time.Now()
		ch <- e
	}
	assert.Eventually(t, func() bool { return len(msgs()) == 3 }, time.Second, 5*time.Millisecond)
	got := msgs()
	assert.Equal(t, offsetMsg{"before", 10}, got[0])
	assert.Equal(t, offsetMsg{"other stream", 0}, got[1])
	assert.Equal(t, offsetMsg{"split line", 40}, got[2])
}

// Two streams' split lines interleave and the later-started one finishes first:
// its message carries 0, since the other is still pending. When the other is then
// passed on (here after the timeout), everything read so far has been, so its
// message acknowledges the furthest line read, not its own last part. Its own
// would land inside the joined line already passed on, and a restart there would
// re-read that line's last part as a line of its own.
func TestPendingPartialAcknowledgesLinesPassedOnMeanwhile(t *testing.T) {
	ch, msgs := offsetParser(t, CriDecoder{})
	for _, e := range []LogEntry{
		{Content: "2026-10-19T10:00:00Z stdout P first ", Offset: 15},
		{Content: "2026-10-19T10:00:00.001Z stderr P never finished", Offset: 20},
		{Content: "2026-10-19T10:00:00.002Z stdout F half", Offset: 25},
	} {
		e.Timestamp = time.Now()
		ch <- e
	}
	assert.Eventually(t, func() bool { return len(msgs()) == 2 }, time.Second, 5*time.Millisecond)
	got := msgs()
	assert.Equal(t, offsetMsg{"first half", 0}, got[0])
	assert.Equal(t, offsetMsg{"never finished", 25}, got[1])
}

// A split line that never ends but keeps growing (a progress bar written without a
// newline, split by the runtime) must not hold acknowledgements back for the whole
// source: once its first part is old enough it is passed on, and its message
// acknowledges the other stream's lines held back meanwhile.
func TestEndlessSplitLineDoesNotBlockAcknowledgements(t *testing.T) {
	ch, msgs := offsetParser(t, CriDecoder{})
	send := func(content string, offset int64) {
		ch <- LogEntry{Timestamp: time.Now(), Content: content, Offset: offset}
	}
	send("2026-10-19T10:00:00Z stdout P progress 1% ", 10)
	send("2026-10-19T10:00:00Z stderr F an error meanwhile", 20)
	offset := int64(20)
	deadline := time.Now().Add(2 * time.Second)
	acked := func() bool {
		for _, m := range msgs() {
			if m.offset >= 20 {
				return true
			}
		}
		return false
	}
	// Parts keep arriving well within the multiline timeout (20ms).
	for !acked() && time.Now().Before(deadline) {
		offset += 10
		send("2026-10-19T10:00:00Z stdout P # ", offset)
		time.Sleep(5 * time.Millisecond)
	}
	got := msgs()
	assert.True(t, acked(), "no message acknowledged the stderr line while stdout kept growing: %v", got)
	assert.Equal(t, offsetMsg{"an error meanwhile", 0}, got[0], "held while the stdout line is pending")
}

// A split line whose last part never comes is passed on after the timeout with the
// offset of the last part read.
func TestDanglingPartialCarriesItsOffset(t *testing.T) {
	ch, msgs := offsetParser(t, CriDecoder{})
	ch <- LogEntry{Timestamp: time.Now(), Content: "2026-10-19T10:00:00Z stdout P Enter password: ", Offset: 50}
	assert.Eventually(t, func() bool { return len(msgs()) == 1 }, time.Second, 5*time.Millisecond)
	assert.Equal(t, int64(50), msgs()[0].offset)
}
