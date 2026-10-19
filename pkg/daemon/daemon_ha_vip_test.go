package daemon

import (
	"net"
	"path/filepath"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// #15684 (V35-02): addStableRethLinkLocal and the direct-mode router
// link-local NA in directSendGARPs hardcoded unit-0 link-local predicates.
//
//   - addStable checked rethUnitHasConfiguredLinkLocal(ifc, 0) for the whole
//     interface: a configured LL on unit 0 suppressed the stable LL on every
//     VLAN unit, and a configured LL on a VLAN unit did not suppress the
//     stable LL on that unit (both addresses were installed).
//   - directSendGARPs read the router LL only from Units[0] and announced
//     that same address on every VLAN sub-interface, including IPv4-only
//     units.
//
// TestAddStableRethLinkLocalPerUnitVLAN pins the per-unit behaviour:
//
//  1. unit 0 explicit fe80::10:1/64 + unit 50 (vlan-id 50) global only ->
//     stableLL added to ge-0-0-0.50, not ge-0-0-0.
//  2. unit 0 global only + unit 60 (vlan-id 60) explicit fe80::60:1/64 ->
//     stableLL added to ge-0-0-0, skipped on ge-0-0-0.60.
//  3. directSendGARPs announces fe80::10:1 on ge-0-0-0, stableLL on
//     ge-0-0-0.50, fe80::60:1 on ge-0-0-0.60, and no IPv6 NA on the
//     IPv4-only ge-0-0-0.70.
//
// The fixture combines (1) and (2) on one interface so both directions are
// covered by one config: unit 0 carries fe80::10:1, unit 50 carries only a
// global address, unit 60 carries fe80::60:1, unit 70 is IPv4-only. The
// stable-LL adds then want exactly {ge-0-0-0.50} and the router NAs want
// exactly {ge-0-0-0: fe80::10:1, ge-0-0-0.50: stableLL,
// ge-0-0-0.60: fe80::60:1} with nothing on ge-0-0-0.70.
//
// Fail-on-revert: restoring the unit-0-only predicate (skip whole iface /
// announce unit-0 LL everywhere) yields adds {} (or a duplicate on .60)
// and NAs all carrying fe80::10:1 plus one on .70 -> RED.

// perUnitVLANStore builds the combined fixture: cluster-id 1, RG 1 on reth0
// (members ge-0/0/0 + ge-7/0/0), vlan-tagging, and the units above.
func perUnitVLANStore(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-6611\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
			"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
			"set interfaces reth0 vlan-tagging\n" +
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0\n" +
			"set interfaces reth0 unit 0 family inet6 address fe80::10:1/64\n" +
			"set interfaces reth0 unit 0 family inet6 address 2001:db8:0::1/64\n" +
			"set interfaces reth0 unit 50 vlan-id 50\n" +
			"set interfaces reth0 unit 50 family inet6 address 2001:db8:50::1/64\n" +
			"set interfaces reth0 unit 60 vlan-id 60\n" +
			"set interfaces reth0 unit 60 family inet6 address fe80::60:1/64\n" +
			"set interfaces reth0 unit 60 family inet6 address 2001:db8:60::1/64\n" +
			"set interfaces reth0 unit 70 vlan-id 70\n" +
			"set interfaces reth0 unit 70 family inet address 10.0.70.1/24\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigure()
	return s
}

func TestAddStableRethLinkLocalPerUnitVLAN(t *testing.T) {
	s := perUnitVLANStore(t)
	stableLL := cluster.StableRethLinkLocal(1, 1)

	var added []string
	origAdd := addStableLLToInterfaceFn
	addStableLLToInterfaceFn = func(ifName string, ll net.IP) {
		if !ll.Equal(stableLL) {
			t.Errorf("addStableLL(%s) ll = %v, want stable %v", ifName, ll, stableLL)
		}
		added = append(added, ifName)
	}
	t.Cleanup(func() { addStableLLToInterfaceFn = origAdd })

	d := &Daemon{store: s}
	d.addStableRethLinkLocal(1)

	sort.Strings(added)
	// Unit 0 (fe80::10:1) and unit 60 (fe80::60:1) suppress their own stable
	// LL; only the global-only unit 50 gets it. Pre-fix the unit-0 check
	// skipped the whole interface, so added was empty.
	want := []string{"ge-0-0-0.50"}
	if len(added) != len(want) {
		t.Fatalf("stable LL added to %v, want %v", added, want)
	}
	for i := range want {
		if added[i] != want[i] {
			t.Fatalf("stable LL added to %v, want %v", added, want)
		}
	}
}

func TestDirectSendGARPsPerUnitRouterLinkLocal15684(t *testing.T) {
	s := perUnitVLANStore(t)
	stableLL := cluster.StableRethLinkLocal(1, 1)

	type naCall struct {
		iface string
		ip    string
	}
	var nas []naCall
	installBurstSeams(t,
		func(string, net.IP, int, cluster.BurstStillValid) error { return nil },
		func(iface string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
			nas = append(nas, naCall{iface, ip.String()})
			return nil
		})
	prevProbe := directARPProbeFn
	directARPProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { directARPProbeFn = prevProbe })

	d := &Daemon{
		store:             s,
		rgStates:          make(map[int]*rgStateMachine),
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 1},
	}
	d.directSendGARPs(1)

	// Router-LL NAs are the link-local targets. Configured link-locals also
	// appear as VIP NAs (the same address announced once as a VIP and once
	// as the router identity); the stable LL appears only as a router NA.
	// Deduplicate to the (iface, addr) set before comparing.
	seenNA := make(map[naCall]bool)
	var routerNAs []naCall
	for _, n := range nas {
		if ip := net.ParseIP(n.ip); ip != nil && ip.IsLinkLocalUnicast() && !seenNA[n] {
			seenNA[n] = true
			routerNAs = append(routerNAs, n)
		}
	}
	sort.Slice(routerNAs, func(i, j int) bool { return routerNAs[i].iface < routerNAs[j].iface })

	want := []naCall{
		{"ge-0-0-0", "fe80::10:1"},
		{"ge-0-0-0.50", stableLL.String()},
		{"ge-0-0-0.60", "fe80::60:1"},
	}
	if len(routerNAs) != len(want) {
		t.Fatalf("router link-local NAs = %v, want %v (no NA on IPv4-only ge-0-0-0.70)", routerNAs, want)
	}
	for i := range want {
		if routerNAs[i] != want[i] {
			t.Fatalf("router link-local NAs = %v, want %v", routerNAs, want)
		}
	}
}
