package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalLogWriter_EventModeFormats_3409 pins #3409: the event-mode local
// writer fanout (EventReader.ProcessRawEvent -> local-writer loop) now honors
// `structured` (Junos RT_FLOW body) and `sd-syslog` (RFC 5424 envelope) in
// addition to `binary` and the standard default. Before #3409 the fanout
// branched ONLY on `binary` and wrote standard RFC 3164 text for every other
// format, so structured / sd-syslog silently no-op'd to standard text.
//
// RED-on-revert: restore the single `formatSyslogMsg` body + `ts [TAG] msg`
// framing for all non-binary formats and the structured sub-test loses its
// RT_FLOW_SESSION_CREATE / source-address tokens and the sd-syslog sub-test
// loses its <PRI>1 RFC 5424 envelope — both assertions fail.
func TestLocalLogWriter_EventModeFormats_3409(t *testing.T) {
	// One SESSION_OPEN frame with the per-policy syslog gate set so the event
	// reaches the human-facing local-writer fanout (rawSessionFrame lives in
	// per_policy_log_test.go, same package).
	feed := func(t *testing.T, format string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "security.log")
		lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		lw.Format = format
		reader := NewEventReader(nil, NewEventBuffer(8))
		reader.ReplaceLocalWriters([]*LocalLogWriter{lw})
		if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionOpen, 1)); !ok {
			t.Fatalf("ProcessRawEvent returned false")
		}
		if err := lw.Close(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("structured", func(t *testing.T) {
		out := feed(t, "structured")
		// The Junos RT_FLOW structured body (formatStructuredMsg) is emitted,
		// not the terse standard line.
		if !strings.Contains(out, "RT_FLOW_SESSION_CREATE") {
			t.Fatalf("structured event-mode output missing RT_FLOW_SESSION_CREATE: %q", out)
		}
		if !strings.Contains(out, "source-address=") {
			t.Fatalf("structured event-mode output missing structured-data fields: %q", out)
		}
		// Structured uses the local-file timestamp+tag prefix, not an RFC 5424
		// envelope.
		if strings.HasPrefix(out, "<") {
			t.Fatalf("structured output should not carry a syslog <PRI> envelope: %q", out)
		}
	})

	t.Run("sd-syslog", func(t *testing.T) {
		out := feed(t, "sd-syslog")
		// Junos sd-syslog (#14611): <PRI>1 TS HOST RT_FLOW - MSGID [junos SD].
		if !strings.HasPrefix(out, "<") {
			t.Fatalf("sd-syslog output missing <PRI> prefix: %q", out)
		}
		if !strings.Contains(out, ">1 ") {
			t.Fatalf("sd-syslog output missing RFC 5424 VERSION (>1 ): %q", out)
		}
		if !strings.Contains(out, " RT_FLOW - RT_FLOW_SESSION_CREATE [junos@") {
			t.Fatalf("sd-syslog output missing Junos APP-NAME/MSGID/SD: %q", out)
		}
		if !strings.Contains(out, `source-address="`) {
			t.Fatalf("sd-syslog output missing source-address SD param: %q", out)
		}
	})

	t.Run("standard-unchanged", func(t *testing.T) {
		out := feed(t, "")
		// The standard default keeps the terse RT_FLOW line with the local
		// timestamp+tag prefix; no structured-data fields, no <PRI> envelope.
		if strings.HasPrefix(out, "<") {
			t.Fatalf("standard output should not carry a syslog <PRI> envelope: %q", out)
		}
		if strings.Contains(out, "RT_FLOW_SESSION_CREATE") || strings.Contains(out, "source-address=") {
			t.Fatalf("standard output unexpectedly carries structured fields: %q", out)
		}
		if !strings.Contains(out, "RT_FLOW SESSION_OPEN") {
			t.Fatalf("standard output missing the terse RT_FLOW line: %q", out)
		}
	})
}
