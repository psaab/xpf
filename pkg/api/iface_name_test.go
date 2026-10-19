package api

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// TestInterfacesHandler_ResolvesRethToLoopback pins the #1565 fix: when
// a Junos config name doesn't directly map to a kernel ifname (RETH
// alias, slash-containing name, etc.), the handler must translate via
// (*Config).ResolveKernelIfName before calling net.InterfaceByName.
//
// We synthesize a cfg where reth0's RETH member is literally named
// "lo" — the loopback netdev is the only one guaranteed to exist on
// any Linux test runner. Pre-fix, the raw lookup of "reth0" returns
// no kernel ifindex (RETH names are virtual). Post-fix,
// ResolveKernelIfName("reth0") returns "lo" and the row's ifindex
// matches net.InterfaceByName("lo").Index.
func TestInterfacesHandler_ResolvesRethToLoopback(t *testing.T) {
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("test runner has no lo netdev: %v", err)
	}

	// Build a Junos config via configstore.LoadSet so we exercise the
	// real compiler path. `lo { gigether-options { redundant-parent reth0; } }`
	// plus `reth0` registers lo as reth0's physical member.
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	sets := []string{
		"set chassis cluster reth-count 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set security zones security-zone trust interfaces reth0",
	}
	for _, s := range sets {
		if _, err := store.LoadSet(s); err != nil {
			t.Fatalf("LoadSet(%q): %v", s, err)
		}
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Sanity: cfg.ResolveReth must resolve reth0 to lo. If not, the
	// test setup is wrong and we should fail loudly rather than
	// silently observing ifindex=0.
	if got := cfg.ResolveReth("reth0"); got != "lo" {
		t.Fatalf("ResolveReth(reth0) = %q, want lo (test cfg setup wrong)", got)
	}
	if got := cfg.ResolveKernelIfName("reth0"); got != "lo" {
		t.Fatalf("ResolveKernelIfName(reth0) = %q, want lo", got)
	}

	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/interfaces", nil)
	s.interfacesHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rows, ok := resp.Data.([]any)
	if !ok {
		t.Fatalf("data = %T, want []any", resp.Data)
	}

	var rethRow map[string]any
	for _, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name == "reth0" {
			rethRow = m
			break
		}
	}
	if rethRow == nil {
		t.Fatalf("no row for reth0 in /interfaces response: %s", rr.Body.String())
	}
	idx, _ := rethRow["ifindex"].(float64)
	if int(idx) != loIface.Index {
		t.Errorf("reth0 ifindex = %v, want %d (loopback) — translation broken",
			rethRow["ifindex"], loIface.Index)
	}
}

// TestWriteInterfacesDetail_DHCPLeasePath pins the #1565 fix on the
// detail handler: DHCP lease annotation must route through
// (*Config).DHCPLeaseKey (which produces the daemon's actual lease
// key shape), not call LeaseFor with the raw Junos config name.
//
// The unit-0 / no-VLAN config below produces a DHCP key equal to
// "reth0" (LinuxIfName("reth0") + no .VlanID suffix). The unit
// test TestDHCPLeaseKey_Mappings in pkg/config covers the
// vlan-id != unit case ("reth0", 80, vlan-id 180) → "reth0.180" —
// proving DHCPLeaseKey returns the daemon's actual key shape.
// This handler test additionally proves the handler ROUTES THROUGH
// DHCPLeaseKey at all (a regression to raw LeaseFor(ifName, ...)
// would still fail this test for the unit-0 case where
// ifName==key, since the handler then would not invoke
// DHCPLeaseKey and the test would skip the lease print path if
// the call wiring regressed — see the route trace in the
// production code at pkg/api/interfaces.go:223).
//
// We bind reth0 to lo (the only netdev guaranteed to exist) so the
// kernel-link lookup succeeds and the detail handler reaches the
// lease-print branch.
func TestWriteInterfacesDetail_DHCPLeasePath(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("test runner has no lo netdev: %v", err)
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Zone references reth0.0 (unit-suffixed Junos ref) — this is the
	// asymmetric case: handler-visible ifName is "reth0.0" but the
	// daemon's DHCP key is "reth0" (no .VlanID since unit 0 vlan-id 0).
	// A regression to raw LeaseFor(ifName, ...) would call
	// LeaseFor("reth0.0", ...) which hits the decoy.
	sets := []string{
		"set chassis cluster reth-count 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet dhcp",
		"set security zones security-zone trust interfaces reth0.0",
	}
	for _, s := range sets {
		if _, err := store.LoadSet(s); err != nil {
			t.Fatalf("LoadSet(%q): %v", s, err)
		}
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Expected daemon DHCP key for unit 0 with no vlan-id: "reth0".
	wantKey, ok := cfg.DHCPLeaseKey("reth0", 0)
	if !ok || wantKey != "reth0" {
		t.Fatalf("DHCPLeaseKey(reth0, 0) = (%q, %v), want (reth0, true)", wantKey, ok)
	}

	// Seed a lease at the correct DHCPLeaseKey shape. Also seed a
	// DECOY lease under a wrong-but-plausible regression key shape
	// — the raw Junos ref with a unit suffix ("reth0.0"). A
	// regression that keys LeaseFor by the raw ifName would print
	// the decoy address; the correct DHCPLeaseKey-routed handler
	// prints the correct one.
	dm, err := dhcp.New(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	correctLease := &dhcp.Lease{
		Address: netip.MustParsePrefix("192.0.2.5/24"),
		Gateway: netip.MustParseAddr("192.0.2.1"),
	}
	decoyLease := &dhcp.Lease{
		Address: netip.MustParsePrefix("203.0.113.99/24"),
		Gateway: netip.MustParseAddr("203.0.113.1"),
	}
	dm.SeedLeaseForTesting(wantKey, dhcp.AFInet, correctLease)
	dm.SeedLeaseForTesting("reth0.0", dhcp.AFInet, decoyLease)

	s := &Server{store: store, dhcp: dm}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/interfaces-detail", nil)
	s.interfacesDetailHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tr, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data = %T, want map", resp.Data)
	}
	out, _ := tr["output"].(string)
	if !strings.Contains(out, "DHCPv4: 192.0.2.5/24 (gw 192.0.2.1)") {
		t.Errorf("output missing correct DHCPv4 lease annotation; got:\n%s", out)
	}
	if strings.Contains(out, "203.0.113") {
		t.Errorf("output contains decoy lease — handler keyed LeaseFor wrongly; got:\n%s", out)
	}
}
