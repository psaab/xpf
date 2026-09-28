package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestShowSystemAlarmsIncludesPeerSnapshotDeferral10782(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	c.SetPeerSnapshotProtocolAlarmFn(func() string {
		return "Config sync deferred: peer snapshot protocol is below v4"
	})
	var runErr error
	out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"alarms"}) })
	if runErr != nil {
		t.Fatalf("show system alarms: %v", runErr)
	}
	if !strings.Contains(out, "1 active alarm(s):") ||
		!strings.Contains(out, "CRITICAL: Config sync deferred: peer snapshot protocol is below v4") {
		t.Fatalf("local system alarms omitted the peer snapshot deferral:\n%s", out)
	}
}
