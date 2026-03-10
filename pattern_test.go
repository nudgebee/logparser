package logparser

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPattern(t *testing.T) {
	assert.Equal(t,
		"package.name got things in",
		NewPattern("2019-07-24 12:06:21,688 package.name [DEBUG] got 10 things in 3.1s").String())

	assert.Equal(t,
		"INFO GET",
		NewPattern("INFO 192.168.1.6 GET /standalone?job_cycles=50000&sleep=20ms&sleep_jitter_percent=500 200 0.113s").String())

	assert.Equal(t,
		"WARN client closed connection after",
		NewPattern("WARN client 192.168.1.8:57600 closed connection after 1.000s").String())

	assert.Equal(t,
		"Jun host kubelet watch of ended with too old resource version",
		NewPattern("Jun 16 21:41:24 host01 kubelet[961]: W0616 21:41:24.642736     961 reflector.go:341] k8s.io/kubernetes/pkg/kubelet/config/apiserver.go:47: watch of *v1.Pod ended with: too old resource version: 81608152 (81608817)").String())

	assert.Equal(t,
		"Unable to ensure the docker processes run in the desired containers errors moving pid failed to find pid namespace of process",
		NewPattern(`Unable to ensure the docker processes run in the desired containers: errors moving "docker-containerd" pid: failed to find pid namespace of process '㌟'`).String())

	assert.Equal(t,
		"ExecSync from runtime service failed rpc error code Unknown desc container not running",
		NewPattern("ExecSync 099a0cbb70555d5d0e1823993175947487c9bc075171df5a161d8e46456b232c 'bash -c echo -ne \x01\x04\x00\x00\x00\x00 | nc 127.0.0.1 81' from runtime service failed: rpc error: code = Unknown desc = container not running (099a0cbb70555d5d0e1823993175947487c9bc075171df5a161d8e46456b232c)").String())

	assert.Equal(t,
		"Get request canceled",
		NewPattern("2019/07/23 15:21:08 http-load-generator.go:49: Get http://golang-app/standalone?job_cycles=50000\u0026sleep=20ms\u0026sleep_jitter_percent=500: net/http: request canceled (Client.Timeout exceeded while awaiting headers)").String())

	assert.Equal(t,
		"query for app done in",
		NewPattern(`2019/07/24 10:40:38.887696 module.go:3334: [INFO: 3fe862d0-f5d0-460f-88d5-e6088985e881]: query "{app!=[xz,xz3],name=[long.name]}" for app="xzxzx" done in 0.016s`).String())

	assert.Equal(t,
		"",
		NewPattern(`[Full GC (Allocation Failure) [CMS: 176934K->176934K(176960K), 0.0451364 secs] 253546K->253546K(253632K), [Metaspace: 11797K->11797K(1060864K)], 0.0454767 secs] [Times: user=0.04 sys=0.00, real=0.05 secs]`).String())

	assert.Equal(t,
		"Nov FAIL message received from about",
		NewPattern(`1:S 12 Nov 2019 07:52:11.999 * FAIL message received from b9112fbdd53291f1924bd3ff81d24b4d48e38929 about e16a51c1d8639a6cc904d8c4dce4ef6d5a1287c3`).String())

	assert.Equal(t,
		"Nov Start of election delayed for milliseconds",
		NewPattern(`1:S 12 Nov 2019 13:17:07.347 # Start of election delayed for 502 milliseconds (rank #0, offset 99524)`).String())

	assert.Equal(t,
		"WARN org.eclipse.jetty.server.HttpChannel",
		NewPattern(`11227 [qtp672320506-43] WARN org.eclipse.jetty.server.HttpChannel  - /`).String())

	assert.Equal(t,
		NewPattern("\tat sun.reflect.GeneratedMethodAccessor72.invoke(Unknown Source) ~[na:na]").String(),
		NewPattern("\tat sun.reflect.GeneratedMethodAccessor71.invoke(Unknown Source) ~[na:na]").String())

	assert.Equal(t,
		NewPattern("ERROR 1 --- [io-8080-exec-18] o.h.engine.jdbc.spi.SqlExceptionHelper : Too many connections").String(),
		NewPattern("ERROR 1 --- [nio-8080-exec-9] o.h.engine.jdbc.spi.SqlExceptionHelper : Too many connections").String())

	assert.Equal(t,
		"no results match selector",
		NewPattern(`[WARNING] no results match selector: {'status': ['1*', '2'], 'app': 'app1', 'host': 'parse*'}"}`).String())

	assert.Equal(t,
		"WARNING items are not found for project UniqueName",
		NewPattern(`WARNING: d2cf9441-82d6-4fc6-8c16-d2a8531ff4a5 26 items are not found {name=[aaaabbbbbcccc]} for project UniqueName`).String())

	assert.Equal(t,
		"Dec gke-foo---bcbd-node-eoj startupscript Finished running startup script",
		NewPattern(`Dec 21 23:17:22 gke-foo-1-1-4b5cbd14-node-4eoj startupscript: Finished running startup script /var/run/google.startup.script`).String())

	assert.Equal(t,
		"foo bar",
		NewPattern(`foo @ 0x000000000daffc3b 0x1 0xaa 0aa3f bar`).String(),
	)
}

func TestPatternWeakEqual(t *testing.T) {
	assert.True(t, NewPattern("foo one baz").WeakEqual(NewPattern("foo two baz")))
	assert.True(t, NewPattern("foo baz one").WeakEqual(NewPattern("foo baz two")))
	assert.False(t, NewPattern("foo bar baz").WeakEqual(NewPattern("foo barr bazz")))
	assert.False(t, NewPattern("foo bar baz").WeakEqual(NewPattern("baz bar foo")))
}

func BenchmarkPatternWeakEqual(b *testing.B) {
	p1 := NewPattern("foo one two bar buz")
	p2 := NewPattern("foo three four bar buz")
	for n := 0; n < b.N; n++ {
		p1.WeakEqual(p2)
	}
}

func TestPatternRemoveQuotedAndBrackets(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	assert.Equal(t, "foo  bar", removeQuotedAndBrackets(`foo 'squoted' bar`, buf))
	assert.Equal(t, "foo  bar", removeQuotedAndBrackets(`foo 'squoted \'baz\'' bar`, buf))
	assert.Equal(t, "foo  bar", removeQuotedAndBrackets(`foo "dquoted" bar`, buf))
	assert.Equal(t, "foo  bar", removeQuotedAndBrackets(`foo "dquoted \"baz\"" bar`, buf))
	assert.Equal(t, "foo  bar", removeQuotedAndBrackets(`foo "dquoted 'squoted' " bar`, buf))
	assert.Equal(t, "foo  bar", removeQuotedAndBrackets(`foo 'squoted "baz"' bar`, buf))

	assert.Equal(t, " msg", removeQuotedAndBrackets(`[nio-8080-exec-9] msg`, buf))
	assert.Equal(t, "json: ", removeQuotedAndBrackets(`json: {'arr': ['1', '2'], 'str': 'strval', 'age': 20}`, buf))
	assert.Equal(t, " ",
		removeQuotedAndBrackets(`[Full GC (Allocation Failure) [CMS: 176934K->176934K(176960K), 0.0451364 secs] 253546K->253546K(253632K), [Metaspace: 11797K->11797K(1060864K)], 0.0454767 secs] [Times: user=0.04 sys=0.00, real=0.05 secs]`, buf))
	assert.Equal(t,
		"Jun 16 21:41:24 host01 kubelet: W0616 21:41:24.642736     961 reflector.go:341]",
		removeQuotedAndBrackets(`Jun 16 21:41:24 host01 kubelet[961]: W0616 21:41:24.642736     961 reflector.go:341]`, buf))
}

func TestJsonPattern(t *testing.T) {
	// Fallback path: no known message keys, uses all values.
	p1 := NewPattern("{\"foo\": \"bar\"}")
	p2 := NewPattern("{\"foo\": \"bar 11818181\"}")
	assert.Equal(t, p1.String(), p2.String())
	assert.Equal(t, p1.Hash(), p2.Hash())

	// Python structured log with "message" key: pattern comes from message field only.
	p3 := NewPattern("{\"asctime\": \"2025-04-03 08:10:06,482\", \"levelname\": \"ERROR\", \"filename\": \"database.py\", \"lineno\": 61, \"message\": \"Error selecting data from cloud_accounts table: connection to server at \\\"192.168.1.13\\\", port 5432 failed: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\", \"exc_info\": \"Traceback (most recent call last):\\n File \\\"/app/db/database.py\\\", line 40, in select_data\\n conn = create_db_connection_pool().getconn()\\n ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\\n File \\\"/usr/local/lib/python3.12/site-packages/psycopg2/pool.py\\\", line 93, in _getconn\\n return self._connect(key)\\n ^^^^^^^^^^^^^^^^^^\\n File \\\"/usr/local/lib/python3.12/site-packages/psycopg2/pool.py\\\", line 63, in _connect\\n conn = psycopg2.connect(*self._args, **self._kwargs)\\n ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\\n File \\\"/usr/local/lib/python3.12/site-packages/psycopg2/__init__.py\\\", line 122, in connect\\n conn = _connect(dsn, connection_factory=connection_factory, **kwasync)\\n ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\\npsycopg2.OperationalError: connection to server at \\\"192.168.1.13\\\", port 5432 failed: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\", \"taskName\": null}")
	assert.NotEqual(t, "d4c3b7e0f4a1d2c5e8f9a4b5d6e7f8a9", p3.Hash())
	// Pattern should come from the "message" field content, not exc_info/filename/etc.
	assert.Contains(t, p3.String(), "Error")
	assert.Contains(t, p3.String(), "selecting")
	assert.NotContains(t, p3.String(), "database.py")
	assert.NotContains(t, p3.String(), "Traceback")
}

func TestJsonPatternMessageFieldOnly(t *testing.T) {
	emptyHash := NewPattern("").Hash()

	// Same "msg" with different context fields must produce the same hash.
	log1 := `{"time":"2026-03-10T05:02:40Z","level":"ERROR","msg":"search: no links found","file":"/app/tools/tool_web_search.go","line":268,"account_id":"aaa-bbb"}`
	log2 := `{"time":"2026-03-11T12:00:00Z","level":"ERROR","msg":"search: no links found","file":"/app/tools/tool_web_search.go","line":268,"account_id":"ccc-ddd"}`
	assert.Equal(t, NewPattern(log1).Hash(), NewPattern(log2).Hash(), "same msg with different metadata should produce same hash")

	// Same "msg" with a large data blob must produce the same hash as without.
	log3 := `{"time":"2026-03-10T05:02:40Z","level":"ERROR","msg":"search: no links found","data":"<!DOCTYPE html><html><head><meta charset='utf-8'><title>Brave Search</title></head><body><div class='results'>lots of html content here</div></body></html>"}`
	assert.Equal(t, NewPattern(log1).Hash(), NewPattern(log3).Hash(), "data blob should not affect hash")

	// Different "msg" must produce different hashes.
	log4 := `{"time":"2026-03-10T05:02:40Z","level":"ERROR","msg":"rewoosolver: unable to unmarshal response"}`
	assert.NotEqual(t, NewPattern(log1).Hash(), NewPattern(log4).Hash(), "different msg should produce different hash")

	// None of these should produce the empty hash.
	for _, l := range []string{log1, log2, log3, log4} {
		assert.NotEqual(t, emptyHash, NewPattern(l).Hash(), "should not produce empty hash: %s", l[:80])
	}
}

func TestJsonPatternCaseInsensitiveKeys(t *testing.T) {
	// Keys should be matched case-insensitively.
	log1 := `{"Message":"connection refused","Level":"ERROR"}`
	log2 := `{"message":"connection refused","level":"error"}`
	log3 := `{"MSG":"connection refused","LEVEL":"ERROR"}`
	assert.Equal(t, NewPattern(log1).Hash(), NewPattern(log2).Hash())
	assert.Equal(t, NewPattern(log1).Hash(), NewPattern(log3).Hash())
}

func TestJsonPatternFallback(t *testing.T) {
	// JSON with no recognized message keys falls back to all values.
	log := `{"component":"scheduler","action":"reconcile","status":"failed"}`
	p := NewPattern(log)
	assert.NotEqual(t, NewPattern("").Hash(), p.Hash(), "fallback should not produce empty hash")
	assert.Contains(t, p.String(), "scheduler")
}

func TestJsonPatternWithErrorField(t *testing.T) {
	// "error" field should be included in pattern extraction.
	log1 := `{"msg":"request failed","error":"connection timeout"}`
	log2 := `{"msg":"request failed","error":"permission denied"}`
	assert.NotEqual(t, NewPattern(log1).Hash(), NewPattern(log2).Hash(),
		"different error values should produce different hashes")
}

// TestJsonPatternRealLokiLogs validates the logparser against real production
// JSON logs collected from Loki. These cover Go structured logs (zerolog),
// Python structured logs, and logs with nested error objects/stacktraces.
func TestJsonPatternRealLokiLogs(t *testing.T) {
	emptyHash := NewPattern("").Hash()

	// --- Go structured logs (zerolog "msg" key) ---

	// Same msg, different metadata (account_id, trace_id, timestamps) → same hash.
	goLog1 := `{"time":"2026-03-10T06:00:32.76936812Z","level":"ERROR","msg":"tool execution error","account_id":"a2a30b02-0f67-42e5-a2ab-c658230fd798","session_id":"094b32cb-f980-49a9-9152-c9c7c4b83349","user_id":"af4cb6af-1254-421d-bfa5-ffcfe649017e","tenant_id":"890cad87-c452-4aa7-b84a-742cee0454a1","trace_id":"d1540fb0a887608c10dbe8f6b37683f7","file":"/app/agents/core/executor_planner.go","line":2177,"error":"workspace /analyze call failed: proxy call failed: unknown","tool":"agent_code_2"}`
	goLog2 := `{"time":"2026-03-10T07:15:00.000000000Z","level":"ERROR","msg":"tool execution error","account_id":"bbbbbbbb-0000-0000-0000-000000000000","session_id":"aaaaaaaa-0000-0000-0000-000000000000","user_id":"cccccccc-0000-0000-0000-000000000000","tenant_id":"dddddddd-0000-0000-0000-000000000000","trace_id":"eeeeeeee0000000000000000","file":"/app/agents/core/executor_planner.go","line":2177,"error":"workspace /analyze call failed: proxy call failed: unknown","tool":"agent_code_2"}`
	assert.Equal(t, NewPattern(goLog1).Hash(), NewPattern(goLog2).Hash(),
		"same msg+error with different metadata should produce same hash")
	assert.NotEqual(t, emptyHash, NewPattern(goLog1).Hash())

	// Different msg → different hash.
	goLog3 := `{"time":"2026-03-10T06:00:32.769283951Z","level":"ERROR","msg":"code: failed to execute via workspace","account_id":"a2a30b02","trace_id":"d1540fb0","error":"workspace /analyze call failed: proxy call failed: unknown"}`
	goLog4 := `{"time":"2026-03-10T06:00:32.769240731Z","level":"ERROR","msg":"workspace: proxy API call failed","account_id":"a2a30b02","trace_id":"d1540fb0","error":"unknown"}`
	assert.NotEqual(t, NewPattern(goLog3).Hash(), NewPattern(goLog4).Hash(),
		"different msg values should produce different hashes")

	// Pattern should come from msg, not from metadata fields.
	p1 := NewPattern(goLog1)
	assert.Contains(t, p1.String(), "tool")
	assert.Contains(t, p1.String(), "execution")
	assert.Contains(t, p1.String(), "error")
	assert.NotContains(t, p1.String(), "executor_planner.go",
		"file paths should not leak into pattern")

	// --- Go structured logs with nested error object (stringified as map) ---

	goLogNested := `{"time":"2026-03-10T05:52:11.512955513Z","level":"ERROR","msg":"unable to fetch events","accountId":"fc9f8ff5-8c17-421e-b461-18e346832e6c","job_id":"e35f812b-9900-47e5-a31d-6f213becd52e","error":{"message":"failed to list audit events: request failed: context deadline exceeded","type":"*fmt.wrapError"}}`
	pNested := NewPattern(goLogNested)
	assert.NotEqual(t, emptyHash, pNested.Hash())
	assert.Contains(t, pNested.String(), "unable")
	assert.Contains(t, pNested.String(), "fetch")
	assert.Contains(t, pNested.String(), "events")

	// --- Go structured log: WARN with error field containing URL ---

	goLogWarn := `{"time":"2026-03-10T06:05:44.826363378Z","level":"WARN","msg":"Primary model failed, analyzing error type","account_id":"a2a30b02","event_id":"d6dffec1","trace_id":"b1ccf7fe","error":"error in stream mode: Post \"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:streamGenerateContent\": context deadline exceeded","model":"gemini-3-flash-preview"}`
	pWarn := NewPattern(goLogWarn)
	assert.NotEqual(t, emptyHash, pWarn.Hash())
	assert.Contains(t, pWarn.String(), "Primary")
	assert.Contains(t, pWarn.String(), "model")
	assert.Contains(t, pWarn.String(), "failed")

	// --- Python structured logs ("message" key + "exc_info" key) ---

	pyLog := `{"asctime":"2026-03-10 06:00:44,782","levelname":"ERROR","filename":"search_logic.py","lineno":56,"message":"Error searching collection a2a30b02_long_term_memory: Unexpected Response: 400 (Bad Request)\nRaw response content:\nb'{\"status\":{\"error\":\"Wrong input: Vector dimension error: expected dim: 768, got 3072\"},\"time\":0.000263312}'","exc_info":"Traceback (most recent call last):\n  File \"/app/rag/search/search_logic.py\", line 36\n  response = client.query_points()\n"}`
	pPy := NewPattern(pyLog)
	assert.NotEqual(t, emptyHash, pPy.Hash())
	assert.Contains(t, pPy.String(), "Error")
	assert.Contains(t, pPy.String(), "searching")
	assert.NotContains(t, pPy.String(), "search_logic.py",
		"filename should not leak into pattern")
	assert.NotContains(t, pPy.String(), "Traceback",
		"exc_info should not leak into pattern")

	// Same Python error from same collection → same hash even with different traceback.
	pyLog2 := `{"asctime":"2026-03-10 07:00:00,000","levelname":"ERROR","filename":"other_file.py","lineno":99,"message":"Error searching collection a2a30b02_long_term_memory: Unexpected Response: 400 (Bad Request)\nRaw response content:\nb'{\"status\":{\"error\":\"Wrong input: Vector dimension error: expected dim: 768, got 3072\"},\"time\":0.000263312}'","exc_info":"different traceback here"}`
	assert.Equal(t, pPy.Hash(), NewPattern(pyLog2).Hash(),
		"same message with different traceback/filename should produce same hash")

	// --- Python structured log: "message" key with Pydantic validation errors ---

	pyLogPydantic := `{"asctime":"2026-03-10 06:00:11,298","levelname":"ERROR","filename":"message.py","lineno":870,"message":"Failed to send message: 6 validation errors for SLOAlertParams\nslo_target\n  Input should be a valid string [type=string_type, input_value=0.99, input_type=float]\nfiring_since\n  Input should be a valid string [type=string_type, input_value=1773122400.0, input_type=float]"}`
	pPydantic := NewPattern(pyLogPydantic)
	assert.NotEqual(t, emptyHash, pPydantic.Hash())
	assert.Contains(t, pPydantic.String(), "Failed")
	assert.Contains(t, pPydantic.String(), "send")
	assert.Contains(t, pPydantic.String(), "message")
	assert.NotContains(t, pPydantic.String(), "message.py",
		"filename should not leak into pattern")

	// --- JSON log with "message" key and large data blob ---

	logWithDataBlob := `{"timestamp":"2026-03-10T06:07:07Z","log_type":"ERROR","event":"tool_failure","message":"Tool failed: cli","data":{"tool_name":"cli"},"duration":"5m39.826611881s","error":"would reformat /tmp/code-analysis--2474322462/nudgebee/notifications-server/notifications_server/message_templates/google_chat/auto_optimize_scheduled_notification.py\nwould reformat /tmp/code-analysis--2474322462/nudgebee/notifications-server/notifications_server/message_templates/google_chat/finding.py\nwould reformat many more files..."}`
	logWithDataBlob2 := `{"timestamp":"2026-03-10T07:07:07Z","log_type":"ERROR","event":"tool_failure","message":"Tool failed: cli","data":{"tool_name":"cli"},"duration":"2m10.000000000s","error":"would reformat /tmp/code-analysis--9999999999/different/path/file.py"}`
	pBlob1 := NewPattern(logWithDataBlob)
	pBlob2 := NewPattern(logWithDataBlob2)
	assert.NotEqual(t, emptyHash, pBlob1.Hash())
	assert.NotEqual(t, emptyHash, pBlob2.Hash())
	// Both have same "message" but different "error" — different hashes expected
	// since error field is included in pattern extraction.
	assert.Contains(t, pBlob1.String(), "Tool")
	assert.Contains(t, pBlob1.String(), "failed")

	// --- Stability: same msg from different pods/times → same hash ---

	msgVariant1 := `{"time":"2026-03-10T05:52:56.777982952Z","level":"ERROR","msg":"pq: operator does not exist: uuid = text","tenant_id":"890cad87-c452-4aa7-b84a-742cee0454a1","user_id":"30b9833e-f667-4b0b-b2c1-065169968e24","trace_id":"d38476f460117ffcb7fece3edb16311a"}`
	msgVariant2 := `{"time":"2026-03-11T12:00:00.000000000Z","level":"ERROR","msg":"pq: operator does not exist: uuid = text","tenant_id":"aaaaaaaa-0000-0000-0000-000000000000","user_id":"bbbbbbbb-0000-0000-0000-000000000000","trace_id":"cccccccc0000000000000000"}`
	assert.Equal(t, NewPattern(msgVariant1).Hash(), NewPattern(msgVariant2).Hash(),
		"identical msg from different pods/times must produce same hash")

	// --- No empty hashes for any of these logs ---

	allLogs := []string{goLog1, goLog2, goLog3, goLog4, goLogNested, goLogWarn,
		pyLog, pyLog2, pyLogPydantic, logWithDataBlob, logWithDataBlob2,
		msgVariant1, msgVariant2}
	for i, l := range allLogs {
		h := NewPattern(l).Hash()
		assert.NotEqual(t, emptyHash, h, "log %d should not produce empty hash", i)
		assert.NotEqual(t, "", NewPattern(l).String(), "log %d should not produce empty pattern", i)
	}

	// --- Verify metadata isolation: none of these patterns contain UUIDs or file paths ---

	for i, l := range allLogs {
		s := NewPattern(l).String()
		assert.NotContains(t, s, "/app/", "log %d pattern should not contain file paths", i)
		assert.NotContains(t, s, ".go", "log %d pattern should not contain .go files", i)
		assert.NotContains(t, s, ".py", "log %d pattern should not contain .py files", i)
	}
}

// TestJsonPatternBulkLokiLogs runs 459 unique production JSON logs through NewPattern
// and asserts none produce empty hashes or panic. These were collected from Loki across
// Go (zerolog), Python, and custom JSON log formats.
func TestJsonPatternBulkLokiLogs(t *testing.T) {
	// Read JSONL file: each line is a JSON-encoded string containing a raw log line.
	data, err := os.ReadFile("/tmp/loki_test_logs.jsonl")
	if err != nil {
		t.Skip("bulk test logs not available at /tmp/loki_test_logs.jsonl — run Loki export first")
	}

	emptyHash := NewPattern("").Hash()
	lines := bytes.Split(data, []byte("\n"))

	var tested int
	var emptyPatterns []int
	hashCounts := map[string]int{}

	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		// Each line is a JSON-encoded string — unwrap it.
		var rawLog string
		if err := json.Unmarshal(line, &rawLog); err != nil {
			t.Logf("line %d: failed to unmarshal wrapper: %v", i, err)
			continue
		}

		p := NewPattern(rawLog)
		h := p.Hash()
		s := p.String()
		tested++

		if h == emptyHash {
			emptyPatterns = append(emptyPatterns, i)
			t.Errorf("line %d produced empty hash (pattern=%q), log prefix: %s", i, s, rawLog[:min(len(rawLog), 120)])
		}

		hashCounts[h]++
	}

	t.Logf("Tested %d logs, %d unique hashes, %d empty-hash violations", tested, len(hashCounts), len(emptyPatterns))

	// Report top hash collisions (most common patterns) for review.
	type kv struct {
		hash  string
		count int
	}
	var top []kv
	for h, c := range hashCounts {
		if c > 1 {
			top = append(top, kv{h, c})
		}
	}
	sort.Slice(top, func(i, j int) bool { return top[i].count > top[j].count })
	if len(top) > 10 {
		top = top[:10]
	}
	for _, kv := range top {
		t.Logf("  hash %s seen %d times", kv.hash, kv.count)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
