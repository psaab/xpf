package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

func TestShowSystemAlarmsIncludesPeerLossTakeover16024(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.SetPeerUnconfirmedTakeoverForTesting("peer fencing is disabled")
	c := &CLI{
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		cluster: m,
	}
	var runErr error
	out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"alarms"}) })
	if runErr != nil {
		t.Fatalf("show system alarms: %v", runErr)
	}
	for _, want := range []string{
		"1 active alarm(s):",
		"CRITICAL: dual-primary risk: Peer-loss takeover: DEGRADED",
		"peer fencing is disabled",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("local system alarms omitted %q:\n%s", want, out)
		}
	}
}
