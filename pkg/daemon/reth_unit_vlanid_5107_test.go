package daemon

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildRAConfigsRethUnitVlanIDMismatch is the #5107 bug-1 guard: RA
// interface resolution must map a RETH logical unit to its configured vlan-id
// for the kernel VLAN sub-interface suffix, not preserve the unit number.
//
// reth0 unit 80 carries `vlan-id 180`, so the kernel sub-interface is
// member.180. The old resolution (LinuxIfName(ResolveReth(...))) kept the unit
// suffix and bound RA to member.80, a netdev that does not exist. This also
// desynced buildRAConfigs from rethInterfacesForRG (which already suffixes by
// unit.VlanID), silently dropping the sender from the cluster RA owned set.
//
// Fail-on-revert: restoring `config.LinuxIfName(cfg.ResolveReth(ra.Interface))`
// in buildRAConfigs resolves reth0.80 to "ge-0-0-0.80" — the expected
// "ge-0-0-0.180" is absent and the forbidden "ge-0-0-0.80" appears, failing
// both assertions.
func TestBuildRAConfigsRethUnitVlanIDMismatch(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0, ClusterID: 1}},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						// unit == vlan-id (common case, must still work).
						50: {Number: 50, VlanID: 50, Addresses: []string{
							"172.16.50.8/24", "2001:db8:50::8/64"}},
						// unit != vlan-id (the #5107 failure case).
						80: {Number: 80, VlanID: 180, Addresses: []string{
							"172.16.80.8/24", "2001:db8:80::8/64"}},
					},
				},
				// Node 0's local member is ge-0/0/0 (slot 0 -> node 0).
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-7/0/0": {Name: "ge-7/0/0", RedundantParent: "reth0"},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "reth0.80"},
				{Interface: "reth0.50"},
			},
		},
	}

	resolved := make(map[string]bool)
	for _, ra := range d.buildRAConfigs(cfg) {
		resolved[ra.Interface] = true
	}

	if !resolved["ge-0-0-0.180"] {
		t.Errorf("RA on reth0.80 (vlan-id 180) resolved to %v; want the set to "+
			"include ge-0-0-0.180 (vlan-id), not the unit suffix", keys(resolved))
	}
	if resolved["ge-0-0-0.80"] {
		t.Errorf("RA resolved to ge-0-0-0.80 (unit number) — unit# was used as "+
			"the kernel VLAN suffix instead of vlan-id 180 (#5107); got %v", keys(resolved))
	}
	// Same-value unit (50 == vlan-id 50): no regression.
	if !resolved["ge-0-0-0.50"] {
		t.Errorf("RA on reth0.50 (vlan-id 50) resolved to %v; want ge-0-0-0.50",
			keys(resolved))
	}
}

// TestRethUnitForVlanID exercises the vlan-id -> unit reverse lookup that the
// post-MAC IPv6 link-local repair uses to translate a kernel VLAN suffix back
// to the logical unit rethCfg.Units is keyed by (#5107 bug 2).
func TestRethUnitForVlanID(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0, VlanID: 0, Addresses: []string{"fe80::aaaa/64"}},
			50: {Number: 50, VlanID: 50},
			80: {Number: 80, VlanID: 180}, // unit != vlan-id
			90: {Number: 90, VlanID: 190},
		},
	}

	tests := []struct {
		name     string
		vid      int
		wantUnit int
		wantOK   bool
	}{
		{"mismatch: vlan-id 180 -> unit 80", 180, 80, true},
		{"same-value: vlan-id 50 -> unit 50", 50, 50, true},
		{"another mismatch: vlan-id 190 -> unit 90", 190, 90, true},
		// 80 is a UNIT number, not any unit's vlan-id: must NOT resolve.
		// The old direct Units[80] index would have matched here.
		{"unit-number-not-vlan-id: 80 -> miss", 80, 0, false},
		{"unknown vlan-id: miss", 999, 0, false},
		// vlan-id 0 is the untagged parent, not a VLAN sub-interface: miss.
		{"untagged vlan-id 0: miss", 0, 0, false},
	}
	for _, tt := range tests {
		gotUnit, gotOK := rethUnitForVlanID(cfg, tt.vid)
		if gotUnit != tt.wantUnit || gotOK != tt.wantOK {
			t.Errorf("%s: rethUnitForVlanID(vid=%d) = (%d, %v), want (%d, %v)",
				tt.name, tt.vid, gotUnit, gotOK, tt.wantUnit, tt.wantOK)
		}
	}
}

// dupVIDWarn is the collision warning rethUnitForVlanID emits when several
// units share a vlan-id (an invalid config). Kept in one place so the test
// asserting it stays in lockstep with the production string.
const dupVIDWarn = "reth: multiple units share a vlan-id; using lowest unit for the netdev name (all matching units scanned for IPv6 link-local repair)"

// TestRethUnitForVlanIDDuplicateDeterministic proves a duplicate vlan-id (an
// invalid config) resolves deterministically to the lowest unit number
// regardless of map iteration order, AND that the collision is logged (an
// invalid duplicate vlan-id must not pass silently).
func TestRethUnitForVlanIDDuplicateDeterministic(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name: "reth1",
		Units: map[int]*config.InterfaceUnit{
			70: {Number: 70, VlanID: 200, Addresses: []string{"2001:db8:70::1/64"}},
			90: {Number: 90, VlanID: 200, Addresses: []string{"2001:db8:90::1/64"}},
		},
	}
	// Capture WARN records so we can assert the deterministic-lowest collision
	// warning fires exactly once per call.
	rec := &recordingSlogHandler{level: slog.LevelWarn}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(prev)

	// Repeat to defeat Go's randomized map iteration order.
	const iters = 64
	for i := 0; i < iters; i++ {
		gotUnit, gotOK := rethUnitForVlanID(cfg, 200)
		if !gotOK || gotUnit != 70 {
			t.Fatalf("duplicate vlan-id 200: rethUnitForVlanID = (%d, %v), "+
				"want (70, true) deterministically (lowest unit)", gotUnit, gotOK)
		}
	}
	if n := rec.count(dupVIDWarn); n != iters {
		t.Errorf("duplicate-vlan-id warning fired %d times, want %d (once per call)",
			n, iters)
	}
}

// TestRethSubIfaceNeedsLinkLocal is the #5107 bug-2 fail-on-revert guard for
// the post-MAC IPv6 repair decision. The kernel VLAN suffix (vlan-id) must be
// translated to its logical unit before checking Units for IPv6.
//
// Fail-on-revert: replacing rethSubIfaceNeedsLinkLocal's body with the old
// `return rethUnitHasIPv6(rethCfg, vid)` indexes Units[180], which is absent
// (Units is keyed by unit 80), so the IPv6-bearing sub-interface is skipped and
// the vlan-id-180 assertion flips to false.
func TestRethSubIfaceNeedsLinkLocal(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 0, Addresses: []string{"fe80::aaaa/64"}},
			// unit == vlan-id, has IPv6.
			50: {Number: 50, VlanID: 50, Addresses: []string{
				"172.16.50.8/24", "2001:db8:50::8/64"}},
			// unit != vlan-id, has IPv6 (the #5107 failure case).
			80: {Number: 80, VlanID: 180, Addresses: []string{
				"172.16.80.8/24", "2001:db8:80::8/64"}},
			// VLAN sub-interface present but IPv4-only: no link-local needed.
			90: {Number: 90, VlanID: 190, Addresses: []string{"172.16.90.8/24"}},
			// DHCPv6 counts as IPv6.
			100: {Number: 100, VlanID: 200, DHCPv6: true},
		},
	}

	tests := []struct {
		name string
		vid  int
		want bool
	}{
		{"mismatch unit 80 vlan-id 180 with IPv6", 180, true},
		{"same-value unit 50 vlan-id 50 with IPv6", 50, true},
		{"IPv4-only sub-interface vlan-id 190", 190, false},
		{"DHCPv6 sub-interface vlan-id 200", 200, true},
		// vid 80 is a unit number, not a vlan-id: no matching sub-interface.
		{"unit-number 80 is not a vlan-id", 80, false},
		{"unknown vlan-id", 999, false},
	}
	for _, tt := range tests {
		if got := rethSubIfaceNeedsLinkLocal(cfg, tt.vid); got != tt.want {
			t.Errorf("%s: rethSubIfaceNeedsLinkLocal(vid=%d) = %v, want %v",
				tt.name, tt.vid, got, tt.want)
		}
	}
}

// TestRethSubIfaceNeedsLinkLocalDuplicateVIDAnyIPv6 is the #5107-fold guard: a
// duplicate vlan-id may split addressing so the LOWEST unit is IPv4-only while a
// higher unit carries IPv6. The single shared kernel netdev (member.<vid>) still
// needs a link-local, so rethSubIfaceNeedsLinkLocal must scan ALL units mapped
// to the vlan-id, not just the deterministic-lowest one.
//
// Fail-on-revert: restoring the lowest-only predicate
// (`u, _ := rethUnitForVlanID(...); return rethUnitHasIPv6(rethCfg, u)`) checks
// only unit 70 (IPv4-only) for the first config and returns false.
func TestRethSubIfaceNeedsLinkLocalDuplicateVIDAnyIPv6(t *testing.T) {
	silenceLogs(t) // duplicate vlan-id emits the expected collision warning

	// Lowest unit IPv4-only, higher unit IPv6 → true.
	cfgHigh := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			70: {Number: 70, VlanID: 200, Addresses: []string{"172.16.70.8/24"}},
			90: {Number: 90, VlanID: 200, Addresses: []string{"2001:db8:90::8/64"}},
		},
	}
	if !rethSubIfaceNeedsLinkLocal(cfgHigh, 200) {
		t.Errorf("duplicate vlan-id 200, IPv6 on the higher unit: got false, want " +
			"true (any mapped unit with IPv6 needs the shared netdev's link-local)")
	}

	// Reversed roles (lowest unit IPv6) → true.
	cfgLow := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			70: {Number: 70, VlanID: 200, Addresses: []string{"2001:db8:70::8/64"}},
			90: {Number: 90, VlanID: 200, Addresses: []string{"172.16.90.8/24"}},
		},
	}
	if !rethSubIfaceNeedsLinkLocal(cfgLow, 200) {
		t.Errorf("duplicate vlan-id 200, IPv6 on the lower unit: got false, want true")
	}

	// Neither unit has IPv6 → false.
	cfgNone := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			70: {Number: 70, VlanID: 200, Addresses: []string{"172.16.70.8/24"}},
			90: {Number: 90, VlanID: 200, Addresses: []string{"172.16.90.8/24"}},
		},
	}
	if rethSubIfaceNeedsLinkLocal(cfgNone, 200) {
		t.Errorf("duplicate vlan-id 200, IPv4-only on both units: got true, want false")
	}
}

// TestRethSubIfaceNameNeedsLinkLocal binds the post-MAC IPv6 repair PRODUCTION
// path in applyDataplaneAndHACore, which routes the whole decision through
// rethSubIfaceNameNeedsLinkLocal(rethCfg, subName) — parse the vlan-id out of the
// kernel VLAN sub-interface name and resolve it to the IPv6-bearing unit(s).
//
// Fail-on-revert: reverting the vlan-id -> unit resolution (making the seam index
// Units[vid] directly, e.g. `return rethUnitHasIPv6(rethCfg, vid)`) misses
// Units[180] and flips the ".180" cases to false.
func TestRethSubIfaceNameNeedsLinkLocal(t *testing.T) {
	cfg := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			// unit != vlan-id, has IPv6.
			80: {Number: 80, VlanID: 180, Addresses: []string{
				"172.16.80.8/24", "2001:db8:80::8/64"}},
			// unit != vlan-id, IPv4-only.
			90: {Number: 90, VlanID: 190, Addresses: []string{"172.16.90.8/24"}},
		},
	}
	tests := []struct {
		subName string
		want    bool
	}{
		// Real kernel VLAN sub-interface names are parent.<vlan-id>.
		{"ge-7-0-1.180", true},  // node-1 name, vlan-id 180 -> unit 80 (IPv6)
		{"ge-0-0-2.180", true},  // node-0 name, same result
		{"ge-7-0-1.190", false}, // vlan-id 190 -> unit 90 (IPv4-only)
		// A unit-number suffix is NOT a vlan-id — the whole #5107 bug.
		{"ge-7-0-1.80", false},
		// No vlan-id suffix: the parent netdev is repaired elsewhere.
		{"ge-7-0-1", false},
		// Non-numeric suffix: false, no panic.
		{"ge-7-0-1.foo", false},
	}
	for _, tt := range tests {
		if got := rethSubIfaceNameNeedsLinkLocal(cfg, tt.subName); got != tt.want {
			t.Errorf("rethSubIfaceNameNeedsLinkLocal(%q) = %v, want %v",
				tt.subName, got, tt.want)
		}
	}
}

// TestRethSubIfaceLinkLocalRepairDrivesEnsureByVlanID binds the per-sub-interface
// repair ACTION that the post-MAC loop in applyDataplaneAndHACore delegates to:
// removeAutoLinkLocalExcluding runs for every child (stale-LL strip) and
// ensureRethLinkLocalExcluding runs ONLY when the resolved vlan-id carries IPv6. The two
// netlink side-effects are swapped for spies so the decision path (parse +
// vlan-id->unit resolve + all-units scan + repair ordering) is driven without
// real netlink. The remaining unbound surface is just the netlink LinkList/
// ParentIndex enumeration, which the loop delegates to this function in one line.
//
// Fail-on-revert: reverting rethSubIfaceNameNeedsLinkLocal's resolution to index
// Units[vid] directly (`return rethUnitHasIPv6(rethCfg, vid)`) drops the ".180"
// ensure (Units[180] is absent), so `ensured` no longer equals ["ge-7-0-1.180"].
func TestRethSubIfaceLinkLocalRepairDrivesEnsureByVlanID(t *testing.T) {
	var removed, ensured []string
	origRemove := removeAutoLinkLocalFn
	origEnsure := ensureRethLinkLocalFn
	removeAutoLinkLocalFn = func(n string, _ []net.IP) { removed = append(removed, n) }
	ensureRethLinkLocalFn = func(n string, _ []net.IP) { ensured = append(ensured, n) }
	t.Cleanup(func() {
		removeAutoLinkLocalFn = origRemove
		ensureRethLinkLocalFn = origEnsure
	})

	cfg := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			// vlan-id 180 (!= unit 80), has IPv6.
			80: {Number: 80, VlanID: 180, Addresses: []string{
				"172.16.80.8/24", "2001:db8:80::8/64"}},
			// vlan-id 190 (!= unit 90), IPv4-only.
			90: {Number: 90, VlanID: 190, Addresses: []string{"172.16.90.8/24"}},
		},
	}

	// Kernel VLAN sub-interface names the enumeration loop would hand us.
	for _, sub := range []string{"ge-7-0-1.180", "ge-7-0-1.190", "ge-7-0-1.80"} {
		rethSubIfaceLinkLocalRepair(cfg, sub)
	}

	// Stale-LL strip is unconditional: every child.
	wantRemoved := []string{"ge-7-0-1.180", "ge-7-0-1.190", "ge-7-0-1.80"}
	if !equalStrs(removed, wantRemoved) {
		t.Errorf("removeAutoLinkLocalFn calls = %v, want %v (every child)",
			removed, wantRemoved)
	}
	// ensure only for the IPv6-bearing vlan-id 180 -> unit 80. Not .190
	// (IPv4-only) and not .80 (a unit number, not a vlan-id).
	wantEnsured := []string{"ge-7-0-1.180"}
	if !equalStrs(ensured, wantEnsured) {
		t.Errorf("ensureRethLinkLocalFn calls = %v, want %v (only the IPv6 vlan-id)",
			ensured, wantEnsured)
	}
}

// TestDesiredClusterRAResolvesByVlanID binds the cluster RA ownership gate in
// desiredClusterRA (daemon_ra_reconcile.go). An owned RG's RETH interfaces are
// enumerated by rethInterfacesForRG, which suffixes by unit.VlanID (member.180);
// buildRAConfigs must resolve the RA interface to the SAME member.180 or the
// `ownedIfaces[ra.Interface]` match drops the sender. reth0 unit 80 vlan-id 180
// exercises unit# != vlan-id.
//
// Fail-on-revert: reverting buildRAConfigs to
// `config.LinuxIfName(cfg.ResolveReth(ra.Interface))` resolves reth0.80 to
// member.80, which misses ownedIfaces[member.180], so desiredClusterRA returns
// an EMPTY set and the len(desired)==1 assertion fails — binding the bonus
// cluster-RA-ownership fix, not just buildRAConfigs in isolation.
func TestDesiredClusterRAResolvesByVlanID(t *testing.T) {
	cfg := &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0, ClusterID: 1}},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						80: {Number: 80, VlanID: 180, Addresses: []string{
							"172.16.80.8/24", "2001:db8:80::8/64"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-7/0/0": {Name: "ge-7/0/0", RedundantParent: "reth0"},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{
				{Interface: "reth0.80"},
			},
		},
	}
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	// Own RG1: the node is VRRP master for reth0.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)

	desired := d.desiredClusterRA(cfg)
	if len(desired) != 1 {
		t.Fatalf("desiredClusterRA returned %d RAs, want 1 — the owned reth0.80 "+
			"sender must survive the ownership match (member.80 misses "+
			"ownedIfaces[member.180] and drops it)", len(desired))
	}
	if desired[0].Interface != "ge-0-0-0.180" {
		t.Fatalf("owned RA Interface = %q, want ge-0-0-0.180 (vlan-id)",
			desired[0].Interface)
	}
}

// silenceLogs swaps the default slog logger for a discard handler for the
// duration of the test (restored via Cleanup). Used where a test intentionally
// drives a duplicate-vlan-id path that logs an expected collision warning.
func silenceLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// equalStrs reports whether two string slices are equal in order and contents.
func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// keys returns the set's members for error messages.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
