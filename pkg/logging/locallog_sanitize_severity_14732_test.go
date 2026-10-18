// #14732: event-mode LocalLogWriter omitted the #6585 control/newline
// sanitization (SanitizeForDisplay) and the #5314 MinSeverity sentinel
// handling (SeverityNone/SeverityEmergency) that SyslogClient has, and
// ForwardLogMsg bypassed the local severity filter entirely.
//
// FAIL-ON-REVERT:
//   - drop termsafe.SanitizeForDisplay from LocalLogWriter.Send and the
//     sanitize tests red (raw LF/ESC reach the file, line count > 1);
//   - restore the old `MinSeverity != 0 && severity > MinSeverity` check and
//     the emergency-sentinel test reds (ShouldSendEvent(0) == false);
//   - drop the ShouldSend gate in ForwardLogMsg and the ForwardLogMsg
//     tests red (SeverityNone / emergency-only writers receive everything).
package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLocalWriter14732(t *testing.T, format string) (*LocalLogWriter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "security.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	lw.Format = format
	t.Cleanup(func() { _ = lw.Close() })
	return lw, path
}

func readLog14732(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLocalLogWriterSendSanitizesControl14732(t *testing.T) {
	for _, format := range []string{"", "structured", "sd-syslog"} {
		t.Run("format="+format, func(t *testing.T) {
			lw, path := newLocalWriter14732(t, format)
			// Wire/config-derived text with a forged second line + ANSI.
			msg := "RT_FLOW SESSION zone=trust\n2006-01-01 [INFO] forged\x1b[31mred\rend"
			if err := lw.Send(SyslogInfo, msg); err != nil {
				t.Fatal(err)
			}
			content := readLog14732(t, path)
			if strings.Count(content, "\n") != 1 {
				t.Fatalf("format %q: local log must contain exactly one line, got %q", format, content)
			}
			if strings.ContainsAny(content, "\r\x1b") {
				t.Fatalf("format %q: raw CR/ESC reached local log: %q", format, content)
			}
			if !strings.Contains(content, `\x0a`) || !strings.Contains(content, `\x1b`) {
				t.Fatalf("format %q: controls must be visible escapes, got %q", format, content)
			}
			if !strings.Contains(content, "forged") {
				t.Fatalf("format %q: message body lost: %q", format, content)
			}
		})
	}
}

func TestLocalLogWriterSendFromEventReaderSanitizes14732(t *testing.T) {
	lw, path := newLocalWriter14732(t, "")
	if !lw.SendFromEventReader(SyslogInfo, "event\nforged\x1b[31m") {
		t.Fatal("SendFromEventReader dropped line")
	}
	lw.SyncForTest()
	content := readLog14732(t, path)
	if strings.Count(content, "\n") != 1 || strings.ContainsAny(content, "\x1b") && !strings.Contains(content, `\x1b`) {
		t.Fatalf("async local log not sanitized to one line: %q", content)
	}
	if strings.Contains(content, "\nforged") {
		t.Fatalf("forged second line in async local log: %q", content)
	}
}

func TestLocalLogWriterSendPreservesOrdinary14732(t *testing.T) {
	lw, path := newLocalWriter14732(t, "")
	msg := "RT_FLOW SESSION_CREATE src=10.0.0.1 dst=10.0.0.2 zone=trust->untrust host=münchen.example"
	if err := lw.Send(SyslogInfo, msg); err != nil {
		t.Fatal(err)
	}
	content := readLog14732(t, path)
	if !strings.Contains(content, msg) {
		t.Fatalf("ordinary/UTF-8 message mangled: %q", content)
	}
}

func TestLocalLogWriterShouldSendEventSentinels14732(t *testing.T) {
	// emergency: only emergency (severity 0) passes. Pre-fix arithmetic
	// dropped exactly the emergencies it was configured to keep.
	emerg := &LocalLogWriter{MinSeverity: ParseSeverity("emergency")}
	if emerg.MinSeverity != SeverityEmergency {
		t.Fatalf("precondition: ParseSeverity(emergency)=%d want %d", emerg.MinSeverity, SeverityEmergency)
	}
	if !emerg.ShouldSendEvent(SyslogEmergency, CategorySession) {
		t.Error("emergency-only writer must forward emergency events (#5314 sentinel)")
	}
	for _, sev := range []int{SyslogAlert, SyslogCritical, SyslogError, SyslogWarning, SyslogInfo, SyslogDebug} {
		if emerg.ShouldSendEvent(sev, CategorySession) {
			t.Errorf("emergency-only writer must not forward severity %d", sev)
		}
	}

	// none: nothing passes.
	none := &LocalLogWriter{MinSeverity: ParseSeverity("none")}
	for _, sev := range []int{SyslogEmergency, SyslogAlert, SyslogInfo, SyslogDebug} {
		if none.ShouldSendEvent(sev, CategorySession) {
			t.Errorf("none writer must not forward severity %d", sev)
		}
		if none.ShouldSend(sev) {
			t.Errorf("none writer ShouldSend(%d) must be false", sev)
		}
	}

	// any / unset: everything passes; ordinary threshold still works.
	anyW := &LocalLogWriter{MinSeverity: ParseSeverity("any")}
	if !anyW.ShouldSendEvent(SyslogDebug, CategoryScreen) {
		t.Error("any writer must forward debug")
	}
	warn := &LocalLogWriter{MinSeverity: SyslogWarning, Categories: CategorySession}
	if !warn.ShouldSendEvent(SyslogError, CategorySession) || warn.ShouldSendEvent(SyslogInfo, CategorySession) {
		t.Error("warning threshold regression")
	}
	if warn.ShouldSendEvent(SyslogWarning, CategoryScreen) {
		t.Error("category filter regression")
	}
	// ShouldSend mirrors SyslogClient.ShouldSend for the same codes.
	if !emerg.ShouldSend(SyslogEmergency) || emerg.ShouldSend(SyslogAlert) {
		t.Error("LocalLogWriter.ShouldSend emergency sentinel mismatch")
	}
}

func TestForwardLogMsgRespectsLocalSeverity14732(t *testing.T) {
	t.Run("none drops everything", func(t *testing.T) {
		lw, path := newLocalWriter14732(t, "")
		lw.MinSeverity = SeverityNone
		er := NewEventReader(nil, NewEventBuffer(8))
		er.ReplaceLocalWriters([]*LocalLogWriter{lw})
		er.ForwardLogMsg(SyslogEmergency, "must not be written")
		er.ForwardLogMsg(SyslogInfo, "must not be written either")
		if content := readLog14732(t, path); content != "" {
			t.Fatalf("SeverityNone local writer received forwarded msg: %q", content)
		}
	})

	t.Run("emergency only", func(t *testing.T) {
		lw, path := newLocalWriter14732(t, "")
		lw.MinSeverity = ParseSeverity("emergency")
		er := NewEventReader(nil, NewEventBuffer(8))
		er.ReplaceLocalWriters([]*LocalLogWriter{lw})
		er.ForwardLogMsg(SyslogInfo, "info must be dropped")
		er.ForwardLogMsg(SyslogAlert, "alert must be dropped")
		if content := readLog14732(t, path); content != "" {
			t.Fatalf("emergency-only writer received non-emergency: %q", content)
		}
		er.ForwardLogMsg(SyslogEmergency, "emergency must pass")
		content := readLog14732(t, path)
		if !strings.Contains(content, "emergency must pass") || strings.Count(content, "\n") != 1 {
			t.Fatalf("emergency-only writer must receive exactly the emergency msg: %q", content)
		}
	})

	t.Run("sanitized via forward", func(t *testing.T) {
		lw, path := newLocalWriter14732(t, "")
		er := NewEventReader(nil, NewEventBuffer(8))
		er.ReplaceLocalWriters([]*LocalLogWriter{lw})
		er.ForwardLogMsg(SyslogWarning, "alarm pool=prod\nforged\x1b[31m")
		content := readLog14732(t, path)
		if strings.Count(content, "\n") != 1 || strings.Contains(content, "\nforged") {
			t.Fatalf("forwarded msg forged a local log line: %q", content)
		}
	})
}
