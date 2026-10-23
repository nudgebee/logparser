package logparser

import (
	"sort"
	"time"
	"unicode/utf8"
)

// partialLines joins the parts of a line the container runtime split (CRI "P",
// Docker json-file lines without a trailing newline), one line per stream, since
// stdout and stderr parts can interleave. A joined line keeps its first part's
// time and its last part's Offset, and stops growing at multilineCollectorLimit.
type partialLines map[string]*pendingLine

// partialLineMaxAge is how many multiline timeouts a split line may keep growing
// before it is passed on as it is (see expired).
const partialLineMaxAge = 10

type pendingLine struct {
	entry LogEntry
	first time.Time // when its first part arrived
	at    time.Time // when its latest part arrived
}

// add takes the next part of a stream's line, arriving at now, and returns the
// whole line once its last part arrives (whole=true).
func (p partialLines) add(e LogEntry, partial bool, now time.Time) (LogEntry, bool) {
	pending := p[e.Stream]
	if pending == nil {
		if partial {
			p[e.Stream] = &pendingLine{entry: e, first: now, at: now}
		}
		return e, !partial
	}
	if room := multilineCollectorLimit - len(pending.entry.Content); room > 0 {
		pending.entry.Content += truncateUTF8(e.Content, room)
	}
	pending.entry.Offset = e.Offset
	if partial {
		pending.at = now
		return LogEntry{}, false
	}
	delete(p, e.Stream)
	return pending.entry, true
}

// expired removes and returns, oldest first, the lines whose latest part arrived
// before cutoff. Such a line's last part may never come (an unterminated last line,
// a prompt), and it must not wait forever or glue onto the stream's next line.
//
// It also removes the lines whose first part arrived before firstCutoff, though
// parts still arrive: a line that never ends (a progress bar written without a
// newline) would otherwise stay pending for good, and while any line is pending no
// offset of its source can be acknowledged. Its later parts start a new line.
func (p partialLines) expired(cutoff, firstCutoff time.Time) []LogEntry {
	var lines []*pendingLine
	for stream, pending := range p {
		if pending.at.Before(cutoff) || pending.first.Before(firstCutoff) {
			lines = append(lines, pending)
			delete(p, stream)
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].at.Before(lines[j].at) })
	entries := make([]LogEntry, len(lines))
	for i, l := range lines {
		entries[i] = l.entry
	}
	return entries
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
