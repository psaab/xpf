package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

func TestShowSystemAlarmsIncludesPeerLossTakeover16024(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.SetPeerUnconfirmedTakeoverForTesting("peer fencing is disabled")
	s := &Server{
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		cluster: m,
	}
	var out strings.Builder
	s.showAlarms(&out)
	for _, want := range []string{
		"1 active alarm(s):",
		"CRITICAL: dual-primary risk: Peer-loss takeover: DEGRADED",
		"peer fencing is disabled",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("remote system alarms omitted %q:\n%s", want, out.String())
		}
	}
}
