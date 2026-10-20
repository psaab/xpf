package cli

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// #15724 (V48-01): local `show interfaces [<name>]` looked up DHCP leases
// by the raw Junos physical name (dhcpLease -> LeaseFor(physName, ...)).
// The daemon keys leases by cfg.DHCPLeaseKey — LinuxIfName + ".VlanID"
// when > 0 — so slash-named interfaces (ge-0/0/0) and VLAN-tagged units
// never matched. This is the CLI twin of the gRPC acceptance test: it
// drives the real host interface (dash-named kernel device round-tripped
// to its Junos slash form) with unit 100 / vlan-id 100, so the daemon key
// is "<kernel>.100", not the raw Junos name.
//
// Pre-fix this fails: the raw lookup misses and no Address line is
// printed. Decoy leases under the raw Junos name and the unit-number
// (non-VLAN) key prove the lookup is neither still raw nor keyed by
// unit number.
func TestShowInterfacesDHCPLeaseKey15724(t *testing.T) {
	junos, kernel, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available to exercise slash->kernel resolution")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ` + junos + ` {
        vlan-tagging;
        unit 100 {
            vlan-id 100;
            family inet { dhcp; }
            family inet6 { dhcpv6; }
        }
    }
}
security { zones { security-zone untrust { interfaces { ` + junos + `.100; } } } }
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wantKey, ok := cfg.DHCPLeaseKey(junos, 100)
	if !ok || wantKey != kernel+".100" {
		t.Fatalf("DHCPLeaseKey(%s, 100) = (%q, %v), want (%s.100, true)", junos, wantKey, ok, kernel)
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
	// Decoys: raw Junos name (pre-fix key) and unit-number key.
	dm.SeedLeaseForTesting(junos, dhcp.AFInet, &dhcp.Lease{
		Address: netip.MustParsePrefix("203.0.113.99/24"),
		Gateway: netip.MustParseAddr("203.0.113.1"),
	})
	dm.SeedLeaseForTesting(kernel, dhcp.AFInet6, &dhcp.Lease{
		Address: netip.MustParsePrefix("2001:db8:dead::99/64"),
		Gateway: netip.MustParseAddr("2001:db8:dead::1"),
	})

	c := &CLI{store: store, dhcp: dm}
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{junos}); err != nil {
			t.Fatalf("showInterfaces(%q): %v", junos, err)
		}
	})
	if !strings.Contains(out, "Address: 198.51.100.10/24, Gateway: 198.51.100.1") {
		t.Fatalf("missing DHCPv4 lease line for %s.100 in output:\n%s", junos, out)
	}
	if !strings.Contains(out, "Address: 2001:db8:100::10/64, Gateway: 2001:db8:100::1") {
		t.Fatalf("missing DHCPv6 lease line for %s.100 in output:\n%s", junos, out)
	}
	if strings.Contains(out, "203.0.113") || strings.Contains(out, "2001:db8:dead") {
		t.Fatalf("output contains decoy lease — lookup not keyed by DHCPLeaseKey:\n%s", out)
	}
}
