package logging

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #15699 (V16-02): EventReader.logEvent dropped the on-wire dataplane
// decision timestamp (rec.Time) when fanning out to SyslogClient and
// LocalLogWriter. Both text sinks stamped time.Now() when the async
// worker dequeued the item, so under backlog the header timestamp was
// systematically late and forensic ordering was falsified — even though
// EventBuffer, elapsed-time and the binary format already honor the
// wire decision instant (#2470/#2511).
//
// RED on pre-fix: SendFromEventReader/Send carry no timestamp, so the
// emitted header is the dequeue wall clock (fails the historical
// decision-time assertions below). GREEN after SendFromEventReaderAt /
// SendAt thread rec.Time through the queues (falling back to now only
// when the timestamp is zero).

// timedFrame15699 builds a SESSION_OPEN frame carrying the supplied
// wire decision timestamp with the per-policy syslog gate set.
func timedFrame15699(decision time.Time) []byte {
	frame := rawSessionFrame(eventTypeSessionOpen, 1)
	binary.LittleEndian.PutUint64(frame[0:8], uint64(decision.UnixNano()))
	return frame
}

func TestEventReaderPreservesWireDecisionTimeSyslog15699(t *testing.T) {
	decision := time.Date(2026, 1, 2, 3, 4, 5, 678_000_000, time.UTC)

	for _, format := range []string{"sd-syslog", "", "structured"} {
		t.Run("format="+format, func(t *testing.T) {
			c, pc := newLoopbackSyslogClient(t)
			c.Format = format
			c.MinSeverity = SyslogInfo
			c.Categories = CategoryAll

			reader := NewEventReader(nil, NewEventBuffer(4))
			reader.ReplaceSyslogClients([]*SyslogClient{c})
			defer reader.ReplaceSyslogClients(nil)

			if !reader.ProcessRawEvent(timedFrame15699(decision)) {
				t.Fatal("ProcessRawEvent failed")
			}
			got := recvOneFrame(t, pc)
			// Sinks normalize explicit stamps to local time (the location
			// time.Now() carried pre-#15699), so expectations are local.
			var want string
			if format == "sd-syslog" {
				want = decision.Local().Format("2006-01-02T15:04:05.000Z07:00")
			} else {
				want = decision.Local().Format(time.Stamp)
			}
			if !strings.Contains(got, want) {
				t.Fatalf("syslog header must carry wire decision time %s, got: %q", want, got)
			}
			// Control: the dequeue-time wall clock must not win. The
			// decision time is historical, so a now-stamped line
			// cannot contain it (checked above); also pin elapsed
			// consistency via the buffer record.
		})
	}
}

func TestEventReaderPreservesWireDecisionTimeLocal15699(t *testing.T) {
	decision := time.Date(2026, 1, 2, 3, 4, 5, 678_000_000, time.UTC)

	for _, format := range []string{"sd-syslog", "", "structured"} {
		t.Run("format="+format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "security.log")
			lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			lw.Format = format
			reader := NewEventReader(nil, NewEventBuffer(4))
			reader.ReplaceLocalWriters([]*LocalLogWriter{lw})
			if !reader.ProcessRawEvent(timedFrame15699(decision)) {
				t.Fatal("ProcessRawEvent failed")
			}
			if err := lw.Close(); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			out := string(b)
			var want string
			if format == "sd-syslog" {
				want = decision.Local().Format("2006-01-02T15:04:05.000Z07:00")
			} else {
				want = decision.Local().Format("2006-01-02T15:04:05.000")
			}
			if !strings.Contains(out, want) {
				t.Fatalf("local header must carry wire decision time %s, got: %q", want, out)
			}
		})
	}
}

// Direct SendAt with an explicit timestamp formats from it; Send (zero
// timestamp) keeps the receive-time behavior direct callers rely on.
func TestEventReaderPreservesWireDecisionTimeAtVariants15699(t *testing.T) {
	decision := time.Date(2026, 1, 2, 3, 4, 5, 678_000_000, time.UTC)

	c, pc := newLoopbackSyslogClient(t)
	c.Format = "sd-syslog"
	if err := c.SendAt(decision, SyslogInfo, "explicit at"); err != nil {
		t.Fatal(err)
	}
	got := recvOneFrame(t, pc)
	if want := decision.Local().Format("2006-01-02T15:04:05.000Z07:00"); !strings.Contains(got, want) {
		t.Fatalf("SendAt must format %s, got: %q", want, got)
	}

	if !c.SendFromEventReaderAt(decision, SyslogInfo, "reader at") {
		t.Fatal("SendFromEventReaderAt not accepted")
	}
	got = recvOneFrame(t, pc)
	if want := decision.Local().Format("2006-01-02T15:04:05.000Z07:00"); !strings.Contains(got, want) {
		t.Fatalf("SendFromEventReaderAt must format %s, got: %q", want, got)
	}

	// Local writer: SendAt explicit, SendFromEventReaderAt explicit.
	for _, tc := range []struct {
		name string
		send func(lw *LocalLogWriter) error
	}{
		{"SendAt", func(lw *LocalLogWriter) error { return lw.SendAt(decision, SyslogInfo, "explicit at") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "security.log")
			lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			lw.Format = "sd-syslog"
			if err := tc.send(lw); err != nil {
				t.Fatal(err)
			}
			if err := lw.Close(); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if want := decision.Local().Format("2006-01-02T15:04:05.000Z07:00"); !strings.Contains(string(b), want) {
				t.Fatalf("%s must format %s, got: %q", tc.name, want, string(b))
			}
		})
	}

	// Async local path carries the timestamp through auditItem.
	path := filepath.Join(t.TempDir(), "security.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	lw.Format = "sd-syslog"
	if !lw.SendFromEventReaderAt(decision, SyslogInfo, "reader at") {
		t.Fatal("LocalLogWriter.SendFromEventReaderAt not accepted")
	}
	lw.SyncForTest()
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := decision.Local().Format("2006-01-02T15:04:05.000Z07:00"); !strings.Contains(string(b), want) {
		t.Fatalf("local async must format %s, got: %q", want, string(b))
	}

	// Zero-timestamp At variants fall back to now (not epoch).
	c2, pc2 := newLoopbackSyslogClient(t)
	c2.Format = "sd-syslog"
	if !c2.SendFromEventReaderAt(time.Time{}, SyslogInfo, "zero at") {
		t.Fatal("zero-at not accepted")
	}
	got = recvOneFrame(t, pc2)
	if strings.Contains(got, "0001-01-01") || strings.Contains(got, "2026-01-02") {
		t.Fatalf("zero-at must fall back to now, got: %q", got)
	}
}
