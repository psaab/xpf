package userspace

import (
	"net"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vipstamp"
)

// #18573 SNAT-source cell. Measured on udp: after a commit renumbered
// reth0.50 .11 -> .43, the kernel still held the stamped .11, the commit's
// snapshot listed .11/24 before .43/24, and interface-mode SNAT translated
// every new LAN flow to the deleted .11. The row the helper SNATs from must
// carry the configured .43 and never the leftover.
//
// The kernel half is faked through the two seams the builder reads
// (buildLinkSnapshot for the live listing, directVIPStampDumpFn for the
// ownership stamp); the config, the row builder, the merge and the SNAT
// pick (pickInterfaceSnapshotV4, which feeds the interface-NAT address map)
// are production. FAIL-ON-REVERT: drop either filterLive call in
// buildInterfaceSnapshotsFrom and the row lists .11 and the pick returns it.

func renumberCfg18573(t *testing.T, v4 string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces reth0 unit 50 family inet address " + v4,
		// RG2, not RG1: the base/unit rows of a SECOND group must keep its
		// stamped VIP (a configured set that only knew one group would
		// filter it as a leftover — review Z2 on #18579).
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set security zones security-zone wan interfaces reth0.50",
		"set security zones security-zone lan interfaces reth1.0",
	} {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func liveRows18573(t *testing.T, stamp uint8) {
	t.Helper()
	origLink, origDump := buildLinkSnapshot, directVIPStampDumpFn
	t.Cleanup(func() { buildLinkSnapshot, directVIPStampDumpFn = origLink, origDump })
	live := map[string]struct {
		idx   int
		addrs []string
	}{
		"ge-0-0-2.50": {9, []string{"169.254.1.1/32", "172.16.50.11/24", "172.16.50.43/24"}},
		// Untagged reth1.0 collapses onto the member: the BASE row (kernel
		// listing only) and the unit row share ifindex 4, and the helper's
		// shared-ifindex merge takes the first row's pick — so the base row
		// must not carry the leftover either.
		"ge-0-0-1": {4, []string{"10.0.61.1/24", "10.0.0.9/24"}},
	}
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		l, ok := live[linuxName]
		if !ok {
			return 0, 0, "", nil
		}
		var out []InterfaceAddressSnapshot
		for _, a := range l.addrs {
			out = append(out, InterfaceAddressSnapshot{Family: "inet", Address: a})
		}
		return l.idx, 1500, "02:bf:72:01:01:00", out
	}
	directVIPStampDumpFn = func() ([]vipstamp.Row, error) {
		return []vipstamp.Row{
			{LinkIndex: 9, Prefix: netip.MustParsePrefix("169.254.1.1/32")},
			{LinkIndex: 9, Prefix: netip.MustParsePrefix("172.16.50.11/24"), Proto: stamp},
			{LinkIndex: 9, Prefix: netip.MustParsePrefix("172.16.50.43/24"), Proto: vipstamp.Proto},
			{LinkIndex: 4, Prefix: netip.MustParsePrefix("10.0.61.1/24"), Proto: vipstamp.Proto},
			{LinkIndex: 4, Prefix: netip.MustParsePrefix("10.0.0.9/24"), Proto: stamp},
		}, nil
	}
}

func rowByName18573(t *testing.T, rows []InterfaceSnapshot, name string) InterfaceSnapshot {
	t.Helper()
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no %s row in %d rows", name, len(rows))
	return InterfaceSnapshot{}
}

func addrSet18573(r InterfaceSnapshot) map[string]bool {
	out := make(map[string]bool)
	for _, a := range r.Addresses {
		out[a.Address] = true
	}
	return out
}

func TestSnapshotSNATSourceAfterRenumberIsTheConfiguredAddress18573(t *testing.T) {
	liveRows18573(t, vipstamp.Proto)
	rows := buildInterfaceSnapshotsFrom(renumberCfg18573(t, "172.16.50.43/24"), nil)

	unit := rowByName18573(t, rows, "reth0.50")
	got := addrSet18573(unit)
	if got["172.16.50.11/24"] {
		t.Fatalf("reth0.50 row publishes the renumbered-away leftover: %v", unit.Addresses)
	}
	if !got["172.16.50.43/24"] || !got["169.254.1.1/32"] {
		t.Fatalf("reth0.50 row lost a configured or foreign address: %v", unit.Addresses)
	}
	if ip := pickInterfaceSnapshotV4(unit); !ip.Equal(net.ParseIP("172.16.50.43")) {
		t.Fatalf("interface-SNAT source after renumber = %v, want 172.16.50.43 (row %v)", ip, unit.Addresses)
	}

	for _, name := range []string{"reth1", "reth1.0"} {
		r := rowByName18573(t, rows, name)
		if addrSet18573(r)["10.0.0.9/24"] {
			t.Fatalf("%s row publishes the leftover 10.0.0.9: %v", name, r.Addresses)
		}
		if ip := pickInterfaceSnapshotV4(r); !ip.Equal(net.ParseIP("10.0.61.1")) {
			t.Fatalf("%s SNAT source = %v, want 10.0.61.1 (row %v)", name, ip, r.Addresses)
		}
	}
}

// The TRUE twin: the same kernel listing with the old address UNSTAMPED (an
// address xpf cannot prove it installed — a pre-#18573 VIP, or a foreign one)
// is published exactly as before. This pins that the filter is keyed on the
// stamp, not on "not configured" — which would also strip DHCP leases and
// standalone VRRP VIPs.
func TestSnapshotKeepsUnstampedUnconfiguredAddress18573(t *testing.T) {
	liveRows18573(t, 0)
	rows := buildInterfaceSnapshotsFrom(renumberCfg18573(t, "172.16.50.43/24"), nil)
	if !addrSet18573(rowByName18573(t, rows, "reth0.50"))["172.16.50.11/24"] {
		t.Fatal("an unstamped kernel address was dropped from the snapshot")
	}
	if !addrSet18573(rowByName18573(t, rows, "reth1"))["10.0.0.9/24"] {
		t.Fatal("an unstamped kernel address was dropped from the base row")
	}
}

// A failed ownership dump filters nothing (the pre-#18573 listing is the
// floor), and a stamped address the config still names is never dropped.
func TestSnapshotLeftoverFilterFloor18573(t *testing.T) {
	liveRows18573(t, vipstamp.Proto)
	directVIPStampDumpFn = func() ([]vipstamp.Row, error) { return nil, net.ErrClosed }
	rows := buildInterfaceSnapshotsFrom(renumberCfg18573(t, "172.16.50.43/24"), nil)
	if !addrSet18573(rowByName18573(t, rows, "reth0.50"))["172.16.50.11/24"] {
		t.Fatal("dump failure must leave the kernel listing unfiltered")
	}

	liveRows18573(t, vipstamp.Proto)
	rows = buildInterfaceSnapshotsFrom(renumberCfg18573(t, "172.16.50.11/24"), nil)
	if !addrSet18573(rowByName18573(t, rows, "reth0.50"))["172.16.50.11/24"] {
		t.Fatal("a stamped address the config still names was dropped")
	}
}
