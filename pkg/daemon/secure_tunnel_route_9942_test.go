package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/internal/testfixture"
	"github.com/psaab/xpf/pkg/frr"
)

// TestAssembleAndApplyFRRSecureTunnelRoute9942 is the production wiring cell:
// assembleFRRConfig builds the FullConfig, and ApplyFull writes its managed
// section. Reverting the assembler's SecureTunnelUnitNetdev call leaves the
// route on the nonexistent st0 device and makes this test RED.
func TestAssembleAndApplyFRRSecureTunnelRoute9942(t *testing.T) {
	cfg := testfixture.SecureTunnelRouteConfig9942("st0.0")
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)

	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0640); err != nil {
		t.Fatal(err)
	}
	rec := &frr.RecordingExecutor{}
	m := frr.NewForTest(confPath, rec)
	defer m.Stop()
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
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
			t.Fatalf("assembled route did not install %q in frr.conf:\n%s", want, data)
		}
	}
}

// TestAssembleFRRConfigSecureTunnelBareBindControl9942 pins the historical
// bare bind spelling: st0 remains the route device and is not changed by the
// explicit-unit resolver arm.
func TestAssembleFRRConfigSecureTunnelBareBindControl9942(t *testing.T) {
	cfg := testfixture.SecureTunnelRouteConfig9942("st0")
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
	if got := fc.DeclaredNetdevs["st0.0"]; got != "st0" {
		t.Fatalf("bare bind route ref = %q, want st0 via SecureTunnelUnitNetdev", got)
	}
}

// TestAssembleFRRConfigUsesSharedDeclaredNetdevBuilder9942 proves daemon
// assembly wires the resolver-aware constructor into FullConfig.
func TestAssembleFRRConfigUsesSharedDeclaredNetdevBuilder9942(t *testing.T) {
	cfg := testfixture.SecureTunnelRouteConfig9942("st0.0")
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
	want := frr.DeclaredNetdevsForConfig(cfg, fc.IPv6NextHopInterfaces)
	if len(fc.DeclaredNetdevs) != len(want) {
		t.Fatalf("daemon declared map has %d entries, shared builder has %d: daemon=%v shared=%v",
			len(fc.DeclaredNetdevs), len(want), fc.DeclaredNetdevs, want)
	}
	for name, wantDev := range want {
		if got := fc.DeclaredNetdevs[name]; got != wantDev {
			t.Errorf("daemon declared[%q] = %q, shared builder = %q", name, got, wantDev)
		}
	}
}
