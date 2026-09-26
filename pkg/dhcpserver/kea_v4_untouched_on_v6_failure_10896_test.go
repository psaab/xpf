package dhcpserver

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// jointFilteredV6Config10896 builds the deterministic trigger from the issue:
// a healthy active v4 pool plus a v6 group SPANNING two RGs with only one
// mastered, i.e. narrowed by filterDHCPConfigForMasterRGs (MembersFiltered).
// The v4 renders and restarts fine; the v6 render hard-fails (#9122); the
// joined error marks the whole apply failed and the #6535 converger re-drives
// the COMPLETE apply every 30s.
func jointFilteredV6Config10896() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer:   v4Config("eth0").DHCPLocalServer,
		DHCPv6LocalServer: filteredGroupV6Config(true).DHCPv6LocalServer,
	}
}

func countCalls10896(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if c == want {
			n++
		}
	}
	return n
}

func assertFilteredV6Error10896(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("apply must report the filtered-v6 render failure")
	}
	msg := err.Error()
	if strings.Count(msg, "generate kea6 config") != 1 ||
		strings.Count(msg, "narrowed") != 1 ||
		strings.Contains(msg, "generate kea4 config") {
		t.Fatalf("apply must report only the single v6 render failure, got: %v", err)
	}
}

// Before the fix, every joint retry restarted the healthy v4 again: the first
// apply plus three converger retries produced FOUR "restart kea-dhcp4-server"
// calls. After the fix the v4 restart happens exactly once; retries leave v4
// untouched while the v6 error keeps surfacing.
func TestV4UntouchedAcrossFilteredV6Retries10896(t *testing.T) {
	cfg := jointFilteredV6Config10896()
	m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")

	assertFilteredV6Error10896(t, m.Apply(cfg))
	if n := countCalls10896(*calls, "restart "+kea4Svc); n != 1 {
		t.Fatalf("first apply must restart healthy v4 exactly once, got %d (calls %v)", n, *calls)
	}
	if n := countCalls10896(*calls, "restart "+kea6Svc); n != 0 {
		t.Fatalf("v6 must never restart when its render fails, got %d (calls %v)", n, *calls)
	}

	now := time.Now()
	for i := 0; i < 3; i++ {
		if !m.ClaimApplyRetry(now.Add(time.Duration(i) * time.Minute)) {
			t.Fatalf("converger retry %d was not claimable — the v6 debt vanished while v6 still fails", i)
		}
		assertFilteredV6Error10896(t, m.Apply(cfg))
	}
	if n := countCalls10896(*calls, "restart "+kea4Svc); n != 1 {
		t.Fatalf("#10896: healthy v4 was restarted by joint retries: %d restarts, calls %v", n, *calls)
	}
}

// The skip must not swallow a REAL v4 change: differing rendered bytes restart
// the unit again.
func TestV4RestartsWhenConfigChanges10896(t *testing.T) {
	cfg := jointFilteredV6Config10896()
	m, calls := testManager(t, map[string]bool{kea4Svc: true}, "")
	assertFilteredV6Error10896(t, m.Apply(cfg))
	cfg.DHCPLocalServer.Groups["g0"].Pools[0].RangeHigh = "10.0.1.201"
	assertFilteredV6Error10896(t, m.Apply(cfg))
	if n := countCalls10896(*calls, "restart "+kea4Svc); n != 2 {
		t.Fatalf("changed v4 config must restart v4 again, got %d restarts (calls %v)", n, *calls)
	}
}

// The skip requires a verifiably ACTIVE unit: an inactive v4 restarts on
// every apply (a restart that never lands must keep being attempted).
func TestV4RestartsWhenUnitInactive10896(t *testing.T) {
	cfg := jointFilteredV6Config10896()
	m, calls := testManager(t, map[string]bool{}, "")
	for i := 0; i < 2; i++ {
		assertFilteredV6Error10896(t, m.Apply(cfg))
	}
	if n := countCalls10896(*calls, "restart "+kea4Svc); n != 2 {
		t.Fatalf("inactive v4 must restart on every apply, got %d restarts (calls %v)", n, *calls)
	}
}
