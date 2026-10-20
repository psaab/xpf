package grpcapi

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15724 (V48-01): ShowInterfacesDetail looked up DHCP leases by the raw
// Junos physical name (LeaseFor(physName, ...)). The daemon keys leases by
// cfg.DHCPLeaseKey — LinuxIfName + ".VlanID" when > 0 — so slash-named
// interfaces (ge-0/0/0) and VLAN-tagged units never matched. This pins the
// issue's acceptance shape (unit 100 with vlan-id 100), adapted to the
// renderer's fixture constraints: the detail renderer prints
// "Not present" and skips logical units for a non-reth interface with no
// kernel netdev, and ShowInterfacesDetail only walks zone-bound
// interfaces, so the VLAN unit is carried on a bondless reth0 whose
// member is lo (the only netdev guaranteed to exist, as in
// TestWriteInterfacesDetail_DHCPLeasePath). setupTestServer /
// loadAndCommitSet from the issue text do not exist in this package and
// are replaced by newConfigStore + LoadSet/Commit. The daemon key here
// is "reth0.100"; the CLI twin covers the slash-name (ge-0/0/0-style)
// key "ge-0-0-0.100" on a real host interface.
//
// Pre-fix this fails: the raw lookup LeaseFor("reth0") misses the
// ".100"-suffixed key and prints the decoy seeded under that raw key
// instead of the correct lease.
func TestShowInterfacesDetail_DHCPLeaseKey(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, s := range []string{
		"set chassis cluster reth-count 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 100 vlan-id 100",
		"set interfaces reth0 unit 100 family inet dhcp",
		"set interfaces reth0 unit 100 family inet6 dhcpv6",
		"set security zones security-zone untrust interfaces reth0.100",
	} {
		if _, err := store.LoadSet(s); err != nil {
			t.Fatalf("LoadSet(%q): %v", s, err)
		}
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wantKey, ok := cfg.DHCPLeaseKey("reth0", 100)
	if !ok || wantKey != "reth0.100" {
		t.Fatalf("DHCPLeaseKey(reth0, 100) = (%q, %v), want (reth0.100, true)", wantKey, ok)
	}

	dm, err := dhcp.New(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	dm.SeedLeaseForTesting(wantKey, dhcp.AFInet, &dhcp.Lease{
		Address: netip.MustParsePrefix("198.51.100.10/24"),
		Gateway: netip.MustParseAddr("198.51.100.1"),
	})
	dm.SeedLeaseForTesting(wantKey, dhcp.AFInet6, &dhcp.Lease{
		Address: netip.MustParsePrefix("2001:db8:100::10/64"),
		Gateway: netip.MustParseAddr("2001:db8:100::1"),
	})
	// Decoy: the raw pre-fix key (no VLAN suffix). Pre-fix both families
	// looked up exactly this key and would print the decoy.
	dm.SeedLeaseForTesting("reth0", dhcp.AFInet, &dhcp.Lease{
		Address: netip.MustParsePrefix("203.0.113.99/24"),
		Gateway: netip.MustParseAddr("203.0.113.1"),
	})
	dm.SeedLeaseForTesting("reth0", dhcp.AFInet6, &dhcp.Lease{
		Address: netip.MustParsePrefix("2001:db8:dead::99/64"),
		Gateway: netip.MustParseAddr("2001:db8:dead::1"),
	})

	srv := &Server{store: store, dhcp: dm}
	resp, err := srv.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{
		Filter: "reth0",
	})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	if !strings.Contains(resp.Output, "Address: 198.51.100.10/24, Gateway: 198.51.100.1") {
		t.Fatalf("missing DHCPv4 lease line for reth0.100 in output:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, "Address: 2001:db8:100::10/64, Gateway: 2001:db8:100::1") {
		t.Fatalf("missing DHCPv6 lease line for reth0.100 in output:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "203.0.113") || strings.Contains(resp.Output, "2001:db8:dead") {
		t.Fatalf("output contains decoy lease — lookup not keyed by DHCPLeaseKey:\n%s", resp.Output)
	}
}
