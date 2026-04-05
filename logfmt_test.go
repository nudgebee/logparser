package logparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLogfmtLevel(t *testing.T) {
	// Basic unquoted values
	lvl, ok := parseLogfmtLevel(`ts=2024-01-15 level=error msg="failed"`)
	assert.True(t, ok)
	assert.Equal(t, LevelError, lvl)

	lvl, ok = parseLogfmtLevel(`level=info msg="started"`)
	assert.True(t, ok)
	assert.Equal(t, LevelInfo, lvl)

	lvl, ok = parseLogfmtLevel(`ts=2024-01-15 level=warn msg="slow"`)
	assert.True(t, ok)
	assert.Equal(t, LevelWarning, lvl)

	// Quoted values
	lvl, ok = parseLogfmtLevel(`ts=2024 level="error" msg="timeout"`)
	assert.True(t, ok)
	assert.Equal(t, LevelError, lvl)

	lvl, ok = parseLogfmtLevel(`level="WARNING" msg="deprecated"`)
	assert.True(t, ok)
	assert.Equal(t, LevelWarning, lvl)

	// Alternative key names
	lvl, ok = parseLogfmtLevel(`ts=2024 lvl=error msg="fail"`)
	assert.True(t, ok)
	assert.Equal(t, LevelError, lvl)

	lvl, ok = parseLogfmtLevel(`severity=fatal msg="crash"`)
	assert.True(t, ok)
	assert.Equal(t, LevelCritical, lvl)

	// No level field
	_, ok = parseLogfmtLevel(`ts=2024 msg="no level here"`)
	assert.False(t, ok)

	// Not logfmt at all
	_, ok = parseLogfmtLevel(`just a plain text log line`)
	assert.False(t, ok)

	// level= not at word boundary (should not match)
	_, ok = parseLogfmtLevel(`mylevel=error msg="fail"`)
	assert.False(t, ok)

	// level at start of line (valid)
	lvl, ok = parseLogfmtLevel(`level=debug msg="trace"`)
	assert.True(t, ok)
	assert.Equal(t, LevelDebug, lvl)
}

func TestExtractLogfmtValue(t *testing.T) {
	assert.Equal(t, "error", extractLogfmtValue(`error msg="test"`))
	assert.Equal(t, "error", extractLogfmtValue(`"error" msg="test"`))
	assert.Equal(t, "warn", extractLogfmtValue("warn"))
	assert.Equal(t, "", extractLogfmtValue(""))
	assert.Equal(t, "info", extractLogfmtValue(`"info"`))
}
