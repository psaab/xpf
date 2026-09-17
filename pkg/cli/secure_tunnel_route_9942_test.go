package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/internal/testfixture"
	"github.com/psaab/xpf/pkg/frr"
)

// TestApplyToDataplaneSecureTunnelRoute9942 exercises the standalone CLI
// production path with the same fixture used by daemon assembly. The explicit
// and bare secure-tunnel bindings plus ordinary unit-zero route all remain
// visible in the managed FRR output.
func TestApplyToDataplaneSecureTunnelRoute9942(t *testing.T) {
	cfg := testfixture.SecureTunnelRouteConfig9942("st0.0")
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0640); err != nil {
		t.Fatal(err)
	}
	rec := &frr.RecordingExecutor{}
	m := frr.NewForTest(confPath, rec)
	defer m.Stop()
	if err := (&CLI{frr: m}).applyToDataplane(cfg); err != nil {
		t.Fatalf("applyToDataplane: %v", err)
	}
	if rec.ReloadCalls != 1 || rec.LastConf != confPath {
		t.Fatalf("ApplyFull reload calls = %d path=%q, want one call for %q",
			rec.ReloadCalls, rec.LastConf, confPath)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip route 10.99.0.0/16 st0.0\n",
		"ip route 10.100.0.0/16 st1\n",
		"ip route 10.101.0.0/16 wan0\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("standalone CLI did not install %q in frr.conf:\n%s", want, data)
		}
	}
}
