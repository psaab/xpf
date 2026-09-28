package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestShowSystemAlarmsIncludesPeerSnapshotDeferral10782(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{
		store: store,
		peerSnapshotProtocolAlarmFn: func() string {
			return "Config sync deferred: peer snapshot protocol is below v4"
		},
	}
	var out strings.Builder
	s.showAlarms(&out)
	if !strings.Contains(out.String(), "1 active alarm(s):") ||
		!strings.Contains(out.String(), "CRITICAL: Config sync deferred: peer snapshot protocol is below v4") {
		t.Fatalf("remote system alarms omitted the peer snapshot deferral:\n%s", out.String())
	}
}
