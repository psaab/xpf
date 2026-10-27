package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// leaseRebindConfig builds a config with one IPsec gateway bound to the
// wan0.0 external interface. dhcp marks the unit DHCP-managed (so the
// #2884 scoping gate fires) and addr (CIDR) gives a deterministic
// configured address that PrepareConfig resolves into local_addrs in CI
// without a real lease.
func leaseRebindConfig(dhcp bool, addr string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: dhcp, PrimaryAddress: addr, Addresses: []string{addr}},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {Name: "gw", Address: "203.0.113.1", ExternalIface: "wan0.0"},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {PSK: config.NewSecret("fixture-secret"), Gateway: "gw"},
				},
			},
		},
	}
}

func readSwanctl(t *testing.T, dir string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ipsec.BPFRXConfFile))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read swanctl conf: %v", err)
	}
	return string(b), true
}

// driveReapplyIPsecLocked drives reapplyIPsecLocked under a test-held
// applySem, as managementOnlyLeaseRefresh does in production (#17071).
func driveReapplyIPsecLocked(t *testing.T, d *Daemon, cfg *config.Config) {
	t.Helper()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire applySem: %v", err)
	}
	defer d.applySem.Release(1)
	d.reapplyIPsecLocked(cfg)
}

// TestReapplyIPsecLocked_RebindsLocalAddr proves the #2884 fix:
// a DHCP lease change on an IPsec-bound interface re-renders swanctl with
// the NEW local_addrs. Fail-on-revert anchor — deleting the
// ipsec.Apply call (or the HasDHCPBoundGateway-gated branch) in
// reapplyIPsecLocked makes the second assertion go RED because the
// stale address is retained / the file is never written. The swanctl seam
// reports reload success so the assertions inspect a successfully applied
// config rather than the transient file from a failed reload.
func TestReapplyIPsecLocked_RebindsLocalAddr(t *testing.T) {
	dir := t.TempDir()
	m := ipsec.NewWithConfigDir(dir)
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) { return nil, nil })
	d := &Daemon{
		ipsec:    m,
		applySem: semaphore.NewWeighted(1),
	}
	driveReapplyIPsecLocked(t, d, leaseRebindConfig(true, "198.51.100.7/24"))
	got, ok := readSwanctl(t, dir)
	if !ok {
		t.Fatal("swanctl config not written on first lease change")
	}
	if !strings.Contains(got, "local_addrs = 198.51.100.7") {
		t.Fatalf("first render missing local_addrs:\n%s", got)
	}

	// DHCP renew to a new lease address.
	driveReapplyIPsecLocked(t, d, leaseRebindConfig(true, "203.0.113.42/24"))
	got, _ = readSwanctl(t, dir)
	if !strings.Contains(got, "local_addrs = 203.0.113.42") {
		t.Fatalf("re-render did not pick up the new lease address:\n%s", got)
	}
	if strings.Contains(got, "local_addrs = 198.51.100.7") {
		t.Fatalf("re-render retained the stale local_addrs:\n%s", got)
	}
}

// TestManagementOnlyLeaseRefresh_NoBoundGatewayIsNoOp proves the scoping
// guard through the live production path: a lease change on an interface
// NO IPsec gateway dynamically binds to does not touch swanctl (no reload
// storm, no SA churn). The non-DHCP-bound config is the store's active
// config, so managementOnlyLeaseRefresh reads it under applySem and
// reapplyIPsecLocked's gate — not a dead wrapper's pre-gate — decides.
func TestManagementOnlyLeaseRefresh_NoBoundGatewayIsNoOp(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set interfaces wan0 unit 0 family inet address 198.51.100.7/24\n" +
		"set security ike gateway gw address 203.0.113.1\n" +
		"set security ike gateway gw external-interface wan0.0\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	prevRoute := mgmtRouteRefreshFn
	t.Cleanup(func() { mgmtRouteRefreshFn = prevRoute })
	mgmtRouteRefreshFn = func(*Daemon) error { return nil }
	var applies atomic.Int32
	d := &Daemon{
		ipsec:    ipsec.NewWithConfigDir(dir),
		applySem: semaphore.NewWeighted(1),
		store:    store,
	}
	d.ipsecApply = func(*config.Config) error { applies.Add(1); return nil }
	d.mgmt.Store(&managementReconciler{})
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }

	// Gateway exists but its interface is not DHCP-managed, so the lease
	// change is irrelevant to its local bind.
	d.managementOnlyLeaseRefresh()
	if got := applies.Load(); got != 0 {
		t.Fatalf("IPsec rebind applied %d time(s) for a lease change on a non-IPsec-bound interface; the gate in reapplyIPsecLocked must suppress it", got)
	}
	if _, ok := readSwanctl(t, dir); ok {
		t.Fatal("swanctl config written for a lease change on a non-IPsec-bound interface")
	}
}
