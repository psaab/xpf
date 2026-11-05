package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

func TestBootAlarmReplay16016(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system.log")
	writer, err := logging.NewLocalLogWriter(logging.LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	d := &Daemon{}
	expiry := time.Date(2026, time.November, 5, 12, 0, 0, 0, time.UTC)
	d.unkeyedAuthorityGraceAlarmSyslog("stamped", true, expiry)
	d.unkeyedAuthorityGraceAlarmSyslog("expired", true, expiry)

	if got, err := os.ReadFile(path); err != nil {
		t.Fatalf("read pre-readiness sink: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("boot notices were delivered before the event reader was ready: %q", got)
	}

	er := logging.NewEventReader(nil, nil)
	er.SetLocalWriters([]*logging.LocalLogWriter{writer})
	d.setEventReader(er)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replayed notices: %v", err)
	}
	stamped := "RT_SYSTEM - UNKEYED_AUTHORITY_GRACE_STAMPED"
	expired := "RT_SYSTEM - UNKEYED_AUTHORITY_GRACE_EXPIRED"
	if strings.Count(string(got), stamped) != 1 || strings.Count(string(got), expired) != 1 {
		t.Fatalf("sink must receive exactly one RT_SYSTEM STAMPED and EXPIRED notice, got %q", got)
	}
	if strings.Index(string(got), stamped) > strings.Index(string(got), expired) {
		t.Fatalf("boot notices were not replayed in order (STAMPED before EXPIRED): %q", got)
	}
}
