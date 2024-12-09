package logparser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	ch := make(chan LogEntry)
	parser := NewParser(ch, nil, nil, true)
	ch <- LogEntry{Timestamp: time.Now(), Content: "package.name [DEBUG] got 10 things in 3.1s", Level: LevelUnknown}

	ch <- LogEntry{Timestamp: time.Now(), Content: "hello this is key AKIAUCTZOIG66SPQV67B", Level: LevelUnknown}

	ch <- LogEntry{Timestamp: time.Now(), Content: "hello key AKIAUCTZOIG66SPQV67B", Level: LevelUnknown}

	ch <- LogEntry{Timestamp: time.Now(), Content: "hello this is key AKIAUCTZOIG66SPQV67B", Level: LevelUnknown}

	ch <- LogEntry{Timestamp: time.Now(), Content: "hello this is key AKIAUZTZOIG66SPQV67B", Level: LevelUnknown}

	ch <- LogEntry{Timestamp: time.Now(), Content: "hello this is key AKIAUDTZOIG66SPQV67B", Level: LevelUnknown}

	ch <- LogEntry{Timestamp: time.Now(), Content: "hello this is key AKIAURTZOIG66SPQV67B", Level: LevelUnknown}

	// wait for 10 seconds
	time.Sleep(10 * time.Second)
	counts := parser.GetSensitiveCounters()
	assert.Equal(t, 5, len(counts))
	parser.Stop()
}
