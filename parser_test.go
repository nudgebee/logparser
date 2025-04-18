package logparser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParser(t *testing.T) {
	ch := make(chan LogEntry)
	parser := NewParser(ch, nil, nil, time.Second, false)

	ch <- LogEntry{Timestamp: time.Now(), Content: "INFO:root:AWS access key: Key", Level: LevelInfo}

	// wait for 10 seconds
	time.Sleep(10 * time.Second)
	counts := parser.GetSensitiveCounters()
	assert.Equal(t, 1, len(counts))
	parser.Stop()
}
