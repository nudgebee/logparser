package logparser

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type DockerLogJson struct {
	Log    string
	Stream string
	// Time is RFC3339Nano. A string, so a malformed one fails only its parse in
	// DecodeEntry, not the line's decoding.
	Time string
}

type Decoder interface {
	Decode(string) (string, error)
}

// EntryDecoder is a Decoder that also reads what the container runtime recorded
// about the line: its time, its stream, and whether it is only part of a longer
// line the runtime split. The parser prefers it to Decode.
type EntryDecoder interface {
	Decoder
	DecodeEntry(string) (DecodedLine, error)
}

// DecodedLine is one line of a container runtime's log file.
type DecodedLine struct {
	Content string
	// Timestamp is when the runtime received the line; zero if it is not recorded.
	Timestamp time.Time
	// Stream is "stdout" or "stderr", or "" if it is not recorded.
	Stream string
	// Partial: the runtime split a long line, and this is not its last part.
	Partial bool
}

type DockerJsonDecoder struct{}

func (d DockerJsonDecoder) Decode(src string) (string, error) {
	obj := DockerLogJson{}
	if err := json.Unmarshal([]byte(src), &obj); err != nil {
		return "", fmt.Errorf(`failed to unmarshal docker log entry "%s": %s`, src, err)
	}
	return obj.Log, nil
}

// DecodeEntry reads a json-file driver line. The driver splits lines longer than
// 16KB; every part but the last lacks the trailing newline.
func (d DockerJsonDecoder) DecodeEntry(src string) (DecodedLine, error) {
	obj := DockerLogJson{}
	if err := json.Unmarshal([]byte(src), &obj); err != nil {
		return DecodedLine{}, fmt.Errorf(`failed to unmarshal docker log entry "%s": %s`, src, err)
	}
	ts, _ := time.Parse(time.RFC3339Nano, obj.Time)
	return DecodedLine{
		Content:   strings.TrimSuffix(obj.Log, "\n"),
		Timestamp: ts,
		Stream:    obj.Stream,
		Partial:   !strings.HasSuffix(obj.Log, "\n"),
	}, nil
}

type CriDecoder struct{}

func (d CriDecoder) Decode(src string) (string, error) {
	line, err := d.DecodeEntry(src)
	return line.Content, err
}

// DecodeEntry reads a CRI log line: "<RFC3339Nano time> <stream> <P|F> <content>",
// where P marks a part of a line the runtime split and F its last part.
func (d CriDecoder) DecodeEntry(src string) (DecodedLine, error) {
	parts := strings.SplitN(src, " ", 4)
	if len(parts) < 4 {
		return DecodedLine{}, fmt.Errorf("unexpected entry format: %s", src)
	}
	ts, _ := time.Parse(time.RFC3339Nano, parts[0])
	return DecodedLine{Content: parts[3], Timestamp: ts, Stream: parts[1], Partial: parts[2] == "P"}, nil
}
