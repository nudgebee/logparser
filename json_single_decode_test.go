package logparser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Decoding a JSON line once (UseNumber) must give the same pattern content and
// level as the json.Unmarshal path, or pattern hashes would change.
func TestStructuredFromJSONMatchesUnmarshal(t *testing.T) {
	lines := []string{
		`{"level":"error","msg":"payment failed","order_id":"ord-1"}`,
		`{"severity":"WARNING","message":"retry 3 of 5","attempt":3}`,
		`{"lvl":"info","error":500,"reason":"upstream returned 1234567890123"}`,
		`{"level":"debug","err":12.5e3}`,
		`{"ts":1700000000.123,"code":1234567,"nested":{"a":1,"b":[1,2.5,"x"],"c":{"d":1e21}},"ok":true,"none":null}`,
		`{"log_type":"error","data":[{"id":9007199254740993},{"id":-0.000001}]}`,
		`  {"msg":"padded line","n":42}  `,
	}
	for _, line := range lines {
		m1, l1, ok := parseJSONLog(line)
		require.True(t, ok, line)
		fields := decodeJsonObject(line)
		require.NotNil(t, fields, line)
		m2, l2 := structuredFromJSON(fields)
		assert.Equal(t, m1, m2, line)
		assert.Equal(t, l1, l2, line)
	}
}

func TestJsonLogCRLF(t *testing.T) {
	jl := ParseJsonLog("{\"level\":\"error\",\"msg\":\"payment failed\"}\r")
	require.NotNil(t, jl)
	assert.Equal(t, "payment failed", jl.Message)
	assert.Equal(t, LevelError, jl.Level)

	m := &MultilineCollector{}
	assert.True(t, m.isNextMessage("{\"msg\":\"a\"}\r"))
	assert.True(t, m.isNextMessage("{\"msg\":\"a\"} "))
}

// The same JSON line gets the same pattern hash whether or not JSON parsing
// (message and attributes) is enabled.
func TestPatternHashIndependentOfParseJson(t *testing.T) {
	line := `{"level":"error","msg":"payment failed for order 42","order_id":"ord-1","duration_ms":138.5}`
	hash := func(parseJson bool) (h string, attrs map[string]string) {
		p := &Parser{
			patterns:              map[patternKey]*patternStat{},
			patternsPerLevel:      map[Level]int{},
			patternsPerLevelLimit: 256,
			parseJson:             parseJson,
			onMsgCb: func(ts time.Time, level Level, patternHash string, msg string, a map[string]string) {
				h, attrs = patternHash, a
			},
		}
		p.inc(Message{Timestamp: time.Now(), Content: line, Level: LevelUnknown})
		return
	}
	h1, a1 := hash(false)
	h2, a2 := hash(true)
	assert.NotEmpty(t, h1)
	assert.Equal(t, h1, h2)
	assert.Nil(t, a1)
	assert.Equal(t, "ord-1", a2["order_id"])
}
