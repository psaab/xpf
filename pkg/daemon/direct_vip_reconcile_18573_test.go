package daemon

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/vipstamp"
)

// #18573 cells: a commit that renumbers or removes a RETH address must delete
// the old address on the RG owner, a non-owner must never install it and must
// drop any stale copy it carries, and an RG move after the commit must not
// resurrect it. These drive the REAL reconcileDirectVIPAddrs through a fake
// kernel address table (the vipstamp seams) and a real committed config.

// rethStore18573 commits a direct-mode (private-RG election, the compiler
// default) cluster config with reth0 unit 50 on VLAN 50 carrying v4 and v6.
func rethStore18573(t *testing.T, v4, v6 string) *configstore.Store {
	t.Helper()
	return testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-18573",
		"set chassis cluster node 0",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces reth0 unit 50 family inet address " + v4,
		"set interfaces reth0 unit 50 family inet6 address " + v6,
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
	})
}

// fakeKernel18573 is a per-test address table behind the vipstamp seams.
type fakeKernel18573 struct {
	t       *testing.T
	links   map[string]int // netdev -> ifindex
	rows    []vipstamp.Row
	adds    []string // "netdev addr replace?" in call order
	dels    []string
	dumpErr error
}

func (k *fakeKernel18573) name(idx int) string {
	for n, i := range k.links {
		if i == idx {
			return n
		}
	}
	return ""
}

func (k *fakeKernel18573) find(idx int, p netip.Prefix) int {
	for i, r := range k.rows {
		if r.LinkIndex == idx && r.Prefix == p {
			return i
		}
	}
	return -1
}

// has reports whether netdev carries addr, and whether it is stamped.
func (k *fakeKernel18573) has(netdev, addr string) (present, stamped bool) {
	p := netip.MustParsePrefix(addr)
	if i := k.find(k.links[netdev], p); i >= 0 {
		return true, k.rows[i].Stamped()
	}
	return false, false
}

func (k *fakeKernel18573) put(netdev, addr string, proto uint8) {
	k.rows = append(k.rows, vipstamp.Row{LinkIndex: k.links[netdev], Prefix: netip.MustParsePrefix(addr), Proto: proto})
}

func (k *fakeKernel18573) install(t *testing.T, d *Daemon) {
	t.Helper()
	origDump, origAdd, origDel, origIdx := directVIPAddrDumpFn, directVIPAddrAddFn, directVIPAddrDelFn, directVIPLinkByIndexFn
	t.Cleanup(func() {
		directVIPAddrDumpFn, directVIPAddrAddFn, directVIPAddrDelFn, directVIPLinkByIndexFn = origDump, origAdd, origDel, origIdx
	})
	directVIPAddrDumpFn = func() ([]vipstamp.Row, error) {
		if k.dumpErr != nil {
			return nil, k.dumpErr
		}
		return append([]vipstamp.Row(nil), k.rows...), nil
	}
	directVIPAddrAddFn = func(idx int, p netip.Prefix, replace bool) error {
		k.adds = append(k.adds, fmt.Sprintf("%s %s replace=%v", k.name(idx), p, replace))
		if i := k.find(idx, p); i >= 0 {
			if !replace {
				return syscall.EEXIST
			}
			k.rows[i].Proto = vipstamp.Proto
			return nil
		}
		k.rows = append(k.rows, vipstamp.Row{LinkIndex: idx, Prefix: p, Proto: vipstamp.Proto})
		return nil
	}
	directVIPAddrDelFn = func(r vipstamp.Row) error {
		k.dels = append(k.dels, fmt.Sprintf("%s %s", k.name(r.LinkIndex), r.Prefix))
		i := k.find(r.LinkIndex, r.Prefix)
		if i < 0 {
			return syscall.EADDRNOTAVAIL
		}
		k.rows = append(k.rows[:i], k.rows[i+1:]...)
		return nil
	}
	directVIPLinkByIndexFn = func(idx int) (netlink.Link, error) {
		if n := k.name(idx); n != "" {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: n, Index: idx}}, nil
		}
		return nil, fmt.Errorf("no link %d", idx)
	}
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		if idx, ok := k.links[name]; ok {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
}

func newFakeKernel18573(t *testing.T) *fakeKernel18573 {
	return &fakeKernel18573{t: t, links: map[string]int{"ge-0-0-2": 5, "ge-0-0-2.50": 9, "ge-0-0-1": 4}}
}

func mustHave18573(t *testing.T, k *fakeKernel18573, netdev, addr string, wantPresent, wantStamped bool) {
	t.Helper()
	present, stamped := k.has(netdev, addr)
	if present != wantPresent || (present && stamped != wantStamped) {
		t.Fatalf("%s %s: present=%v stamped=%v, want present=%v stamped=%v (table %v; adds %v; dels %v)",
			netdev, addr, present, stamped, wantPresent, wantStamped, k.rows, k.adds, k.dels)
	}
}

// The issue's reproduction, both families: the owner held .10 (stamped by
// its own earlier install); a commit renumbers to .42. FAIL-ON-REVERT:
// restoring the config-only add pass leaves .10 / ::10 on the owner.
func TestDirectVIPRenumberRemovesOldAddressOnOwner18573(t *testing.T) {
	k := newFakeKernel18573(t)
	d := &Daemon{store: rethStore18573(t, "172.16.50.10/24", "2001:db8:50::10/64")}
	k.install(t, d)

	if added := d.directAddVIPs(1); added != 2 {
		t.Fatalf("first owner pass added %d, want 2", added)
	}
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", true, true)
	mustHave18573(t, k, "ge-0-0-2.50", "2001:db8:50::10/64", true, true)

	// Commit: renumber .10 -> .42 (v4) and ::10 -> ::42 (v6).
	d.store = rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")
	if added := d.directAddVIPs(1); added != 2 {
		t.Fatalf("post-commit owner pass added %d, want 2", added)
	}
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.42/24", true, true)
	mustHave18573(t, k, "ge-0-0-2.50", "2001:db8:50::42/64", true, true)
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", false, false)
	mustHave18573(t, k, "ge-0-0-2.50", "2001:db8:50::10/64", false, false)

	// Converged: a steady-state tick changes nothing.
	k.adds, k.dels = nil, nil
	if added := d.directAddVIPs(1); added != 0 || len(k.adds) != 0 || len(k.dels) != 0 {
		t.Fatalf("steady-state tick mutated the kernel: added=%d adds=%v dels=%v", added, k.adds, k.dels)
	}
}

// Ownership is tracked, not guessed: an unstamped address the config does not
// name is never touched, on the owner or the non-owner — a DHCP lease, a
// kernel/stable link-local, another daemon's address. Its twin with the stamp
// IS removed, so the cell distinguishes the predicate from "never delete".
func TestDirectVIPLeavesForeignAddressesAlone18573(t *testing.T) {
	for _, want := range []bool{true, false} {
		t.Run(fmt.Sprintf("want=%v", want), func(t *testing.T) {
			k := newFakeKernel18573(t)
			d := &Daemon{store: rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")}
			k.install(t, d)
			k.put("ge-0-0-2.50", "169.254.1.1/32", 0)
			k.put("ge-0-0-2.50", "fe80::5:1/64", 3)                 // IFAPROT_KERNEL_LL
			k.put("ge-0-0-2.50", "172.16.50.99/24", 0)              // foreign, unstamped
			k.put("ge-0-0-2.50", "172.16.50.98/24", vipstamp.Proto) // xpf leftover
			k.put("ge-0-0-1", "10.0.61.200/24", 0)                  // another netdev, foreign
			if want {
				d.directAddVIPs(1)
			} else {
				d.directRemoveVIPs(1)
			}
			mustHave18573(t, k, "ge-0-0-2.50", "169.254.1.1/32", true, false)
			mustHave18573(t, k, "ge-0-0-2.50", "fe80::5:1/64", true, false)
			mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.99/24", true, false)
			mustHave18573(t, k, "ge-0-0-1", "10.0.61.200/24", true, false)
			mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.98/24", false, false)
		})
	}
}

// The non-owner never installs, and drops both the configured VIP (stamped or
// not — the pre-#18573 contract, which a VIP from an older xpf relies on) and
// any stamped leftover. Then the RG moves to it after the commit: it installs
// ONLY the new address, from its own (synced) active config — nothing in the
// old address set is resurrected — and the former owner, now demoted, drops
// what it held.
func TestDirectVIPNonOwnerAndRGMoveAfterRenumber18573(t *testing.T) {
	newCfg := rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")

	// Node 1 (non-owner) carries a stale stamped .10 from a former tenure and
	// an unstamped .42 (e.g. installed by a pre-#18573 xpf).
	n1 := newFakeKernel18573(t)
	d1 := &Daemon{store: newCfg}
	n1.install(t, d1)
	n1.put("ge-0-0-2.50", "172.16.50.10/24", vipstamp.Proto)
	n1.put("ge-0-0-2.50", "172.16.50.42/24", 0)
	// removed counts the RG's configured VIP only: the leftover belongs to
	// no RG and must not drive the RG's service edge (prev || removed > 0).
	if removed := d1.directRemoveVIPs(1); removed != 1 || len(n1.dels) != 2 {
		t.Fatalf("non-owner removed %d (want 1) with dels %v (want 2)", removed, n1.dels)
	}
	if len(n1.adds) != 0 {
		t.Fatalf("non-owner installed addresses: %v", n1.adds)
	}
	mustHave18573(t, n1, "ge-0-0-2.50", "172.16.50.10/24", false, false)
	mustHave18573(t, n1, "ge-0-0-2.50", "172.16.50.42/24", false, false)

	// RG move: node 1 becomes the owner.
	if added := d1.directAddVIPs(1); added != 2 {
		t.Fatalf("new owner added %d, want 2", added)
	}
	for _, a := range n1.adds {
		if a == "ge-0-0-2.50 172.16.50.10/24 replace=false" || a == "ge-0-0-2.50 2001:db8:50::10/64 replace=false" {
			t.Fatalf("new owner resurrected the renumbered address: %v", n1.adds)
		}
	}
	mustHave18573(t, n1, "ge-0-0-2.50", "172.16.50.42/24", true, true)
	mustHave18573(t, n1, "ge-0-0-2.50", "172.16.50.10/24", false, false)

	// Node 0, the former owner, demoted while still carrying a leftover it
	// never got to prune (e.g. the move raced the post-commit tick).
	n0 := newFakeKernel18573(t)
	d0 := &Daemon{store: newCfg}
	n0.install(t, d0)
	n0.put("ge-0-0-2.50", "172.16.50.10/24", vipstamp.Proto)
	n0.put("ge-0-0-2.50", "172.16.50.42/24", vipstamp.Proto)
	n0.put("ge-0-0-2.50", "2001:db8:50::42/64", vipstamp.Proto)
	d0.directRemoveVIPs(1)
	if len(n0.rows) != 0 {
		t.Fatalf("demoted former owner kept %v", n0.rows)
	}
}

// A VIP installed by a pre-#18573 xpf is unstamped; the owner adopts it (a
// replace that writes the stamp) so a LATER renumber of it is caught too.
// FAIL-ON-REVERT: dropping the adopt pass leaves the renumbered address.
func TestDirectVIPAdoptsUnstampedConfiguredVIP18573(t *testing.T) {
	k := newFakeKernel18573(t)
	d := &Daemon{store: rethStore18573(t, "172.16.50.10/24", "2001:db8:50::10/64")}
	k.install(t, d)
	k.put("ge-0-0-2.50", "172.16.50.10/24", 0)
	k.put("ge-0-0-2.50", "2001:db8:50::10/64", 0)
	if added := d.directAddVIPs(1); added != 0 {
		t.Fatalf("adoption must not count as an add (announce edge), got %d", added)
	}
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", true, true)
	mustHave18573(t, k, "ge-0-0-2.50", "2001:db8:50::10/64", true, true)

	d.store = rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")
	d.directAddVIPs(1)
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", false, false)
	mustHave18573(t, k, "ge-0-0-2.50", "2001:db8:50::10/64", false, false)
}

// A commit that removes the whole unit, or moves it to another VLAN, leaves
// the stamped address on a netdev the config no longer names at all; it is
// still a leftover and still goes.
func TestDirectVIPRemovesLeftoverOnUnattributedNetdev18573(t *testing.T) {
	k := newFakeKernel18573(t)
	k.links["ge-0-0-2.60"] = 11
	d := &Daemon{store: rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")}
	k.install(t, d)
	k.put("ge-0-0-2.60", "172.16.60.42/24", vipstamp.Proto)
	k.put("ge-0-0-2.60", "172.16.60.7/24", 0)
	d.directAddVIPs(1)
	mustHave18573(t, k, "ge-0-0-2.60", "172.16.60.42/24", false, false)
	mustHave18573(t, k, "ge-0-0-2.60", "172.16.60.7/24", true, false)
}

// Without a readback the reconcile must not delete on a guess, and must not do
// less than the pre-#18573 code: it adds (stamped) / removes the configured set.
func TestDirectVIPDumpFailureDegradesToConfiguredSet18573(t *testing.T) {
	k := newFakeKernel18573(t)
	d := &Daemon{store: rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")}
	k.install(t, d)
	k.put("ge-0-0-2.50", "172.16.50.10/24", vipstamp.Proto)
	k.dumpErr = syscall.EBUSY
	if added := d.directAddVIPs(1); added != 2 {
		t.Fatalf("blind owner pass added %d, want 2", added)
	}
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", true, true) // not judged without a readback
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.42/24", true, true)
	if removed := d.directRemoveVIPs(1); removed != 2 {
		t.Fatalf("blind non-owner pass removed %d, want 2", removed)
	}
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.42/24", false, false)
	k.dumpErr = nil
	d.directAddVIPs(1)
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", false, false)
}

// Deleting an IPv4 primary without promote_secondaries also deletes its
// subnet's secondaries; the reconcile re-asserts every configured VIP after
// any delete, so the surviving address comes back in the same pass.
func TestDirectVIPReassertsAfterDeleteCascade18573(t *testing.T) {
	k := newFakeKernel18573(t)
	d := &Daemon{store: rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")}
	k.install(t, d)
	k.put("ge-0-0-2.50", "172.16.50.10/24", vipstamp.Proto) // primary, leftover
	k.put("ge-0-0-2.50", "172.16.50.42/24", vipstamp.Proto) // secondary, wanted
	k.put("ge-0-0-2.50", "2001:db8:50::42/64", vipstamp.Proto)
	delFn := directVIPAddrDelFn
	directVIPAddrDelFn = func(r vipstamp.Row) error {
		err := delFn(r)
		if r.Prefix == netip.MustParsePrefix("172.16.50.10/24") {
			// the kernel takes the secondary down with it
			if i := k.find(r.LinkIndex, netip.MustParsePrefix("172.16.50.42/24")); i >= 0 {
				k.rows = append(k.rows[:i], k.rows[i+1:]...)
			}
		}
		return err
	}
	if added := d.directAddVIPs(1); added != 1 {
		t.Fatalf("re-assert added %d, want 1 (adds %v)", added, k.adds)
	}
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.42/24", true, true)
	mustHave18573(t, k, "ge-0-0-2.50", "172.16.50.10/24", false, false)
}

// A reconcile-path change republishes the userspace snapshot: every changed
// netdev is queued to the interface-link refresher (#18573 addendum).
func TestDirectVIPChangeQueuesSnapshotRefresh18573(t *testing.T) {
	k := newFakeKernel18573(t)
	d := &Daemon{store: rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")}
	k.install(t, d)
	k.put("ge-0-0-2.50", "172.16.50.10/24", vipstamp.Proto)
	k.put("ge-0-0-2.50", "172.16.50.42/24", vipstamp.Proto)
	k.put("ge-0-0-2.50", "2001:db8:50::42/64", vipstamp.Proto)
	var queued []string
	orig := wakeInterfaceLinkSnapshotFn
	t.Cleanup(func() { wakeInterfaceLinkSnapshotFn = orig })
	wakeInterfaceLinkSnapshotFn = func(_ chan string, netdev string) {
		queued = append(queued, netdev)
	}
	wake := make(chan string, 1)
	d.interfaceLinkRefreshWake.Store(&wake)
	d.directAddVIPs(1)
	sort.Strings(queued)
	if len(queued) != 1 || queued[0] != "ge-0-0-2.50" {
		t.Fatalf("removal queued refreshes %v, want [ge-0-0-2.50]", queued)
	}
	queued = nil
	d.directAddVIPs(1)
	if len(queued) != 0 {
		t.Fatalf("a converged tick must not queue a refresh, got %v", queued)
	}
	// A demotion removes configured VIPs only: they are merged into the row
	// regardless of the kernel, so the rows cannot change — no rebuild.
	d.directRemoveVIPs(1)
	if len(queued) != 0 {
		t.Fatalf("a not-owner removal must not queue a refresh, got %v", queued)
	}
}

// Pure planner: the per-row verdicts, including the cross-RG shared-netdev
// protection (another group's configured VIP on the same netdev is not a
// leftover) and the non-owner deletion of an unstamped configured VIP.
func TestPlanDirectVIPAddrsVerdicts18573(t *testing.T) {
	stamped := func(a string) resolvedAddrRow {
		return resolvedAddrRow{Row: vipstamp.Row{LinkIndex: 9, Prefix: netip.MustParsePrefix(a), Proto: vipstamp.Proto}, Netdev: "n"}
	}
	plain := func(a string) resolvedAddrRow {
		return resolvedAddrRow{Row: vipstamp.Row{LinkIndex: 9, Prefix: netip.MustParsePrefix(a)}, Netdev: "n"}
	}
	configured := map[string]map[string]bool{"n": {
		config.PrefixIdentity(netip.MustParsePrefix("10.0.0.1/24")): true,
		config.PrefixIdentity(netip.MustParsePrefix("10.0.0.2/24")): true, // other RG's
	}}
	in := directVIPPlanInput{
		Want:       true,
		Desired:    map[string][]string{"n": {"10.0.0.1/24"}},
		Configured: configured,
		Rows: []resolvedAddrRow{
			plain("10.0.0.1/24"),   // desired, unstamped -> adopt
			stamped("10.0.0.2/24"), // other RG's configured -> keep
			stamped("10.0.0.3/24"), // leftover -> delete
			plain("10.0.0.4/24"),   // foreign -> keep
			stamped("10.0.0.1/25"), // same host, other prefix: a different address -> delete
		},
	}
	plan := planDirectVIPAddrs(in)
	if len(plan.Add) != 0 || len(plan.Adopt) != 1 || plan.Adopt[0].CIDR != "10.0.0.1/24" {
		t.Fatalf("owner plan add=%v adopt=%v", plan.Add, plan.Adopt)
	}
	var dels []string
	for _, d := range plan.Del {
		dels = append(dels, d.Row.Prefix.String()+" "+d.Reason)
	}
	want := []string{"10.0.0.3/24 " + directVIPDelLeftover, "10.0.0.1/25 " + directVIPDelLeftover}
	if fmt.Sprint(dels) != fmt.Sprint(want) {
		t.Fatalf("owner deletes %v, want %v", dels, want)
	}

	in.Want = false
	plan = planDirectVIPAddrs(in)
	dels = nil
	for _, d := range plan.Del {
		dels = append(dels, d.Row.Prefix.String()+" "+d.Reason)
	}
	want = []string{"10.0.0.1/24 " + directVIPDelNotOwner, "10.0.0.3/24 " + directVIPDelLeftover, "10.0.0.1/25 " + directVIPDelLeftover}
	if fmt.Sprint(dels) != fmt.Sprint(want) || len(plan.Add)+len(plan.Adopt) != 0 {
		t.Fatalf("non-owner deletes %v (add %v adopt %v), want %v", dels, plan.Add, plan.Adopt, want)
	}
}

// rethStore2RG18573 is a two-RG direct-mode cluster: reth0 (RG1) unit 50 on
// VLAN 50 of ge-0/0/2, reth1 (RG2) untagged on ge-0/0/1.
func rethStore2RG18573(t *testing.T) *configstore.Store {
	t.Helper()
	return testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-18573",
		"set chassis cluster node 0",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces reth0 unit 50 family inet address 172.16.50.42/24",
		"set interfaces reth0 unit 50 family inet6 address 2001:db8:50::42/64",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.62.1/24",
		"set interfaces reth1 unit 0 family inet6 address 2001:db8:62::1/64",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
	})
}

// Review (Z2) on #18579: the leftover sweep is global — every RG's pass,
// RG0's included, judges every stamped address on every netdev — so the
// configured set must span EVERY group. A set that only knew the passing RG
// would make the RG0 and RG1 passes delete RG2's live VIPs, and RG2's pass
// would re-add them: a delete/re-add (and GARP) every 2 s on any two-RG
// cluster. FAIL-ON-REVERT: restrict AddressIdentitiesByNetdev to one RG and
// RG2's stamped VIPs vanish here. The RG2 leftover is the control: it IS
// deleted by a foreign RG's pass, so the cell cannot pass by deleting nothing.
func TestDirectVIPOtherRGsStampedVIPsSurviveEveryPass18573(t *testing.T) {
	type pass struct {
		rg   int
		want bool
	}
	for _, p := range []pass{{0, true}, {0, false}, {1, true}, {1, false}} {
		t.Run(fmt.Sprintf("rg%d-want=%v", p.rg, p.want), func(t *testing.T) {
			k := newFakeKernel18573(t)
			d := &Daemon{store: rethStore2RG18573(t)}
			k.install(t, d)
			k.put("ge-0-0-1", "10.0.62.1/24", vipstamp.Proto)
			k.put("ge-0-0-1", "2001:db8:62::1/64", vipstamp.Proto)
			k.put("ge-0-0-1", "10.0.62.9/24", vipstamp.Proto) // RG2 leftover
			if p.want {
				d.directAddVIPs(p.rg)
			} else {
				d.directRemoveVIPs(p.rg)
			}
			mustHave18573(t, k, "ge-0-0-1", "10.0.62.1/24", true, true)
			mustHave18573(t, k, "ge-0-0-1", "2001:db8:62::1/64", true, true)
			mustHave18573(t, k, "ge-0-0-1", "10.0.62.9/24", false, false)
			for _, del := range k.dels {
				if del == "ge-0-0-1 10.0.62.1/24" || del == "ge-0-0-1 2001:db8:62::1/64" {
					t.Fatalf("RG%d pass deleted RG2's configured VIP: %v", p.rg, k.dels)
				}
			}
		})
	}
}

// Review (Z2) on #18579: per-(netdev, VIP) diagnostics are latched, not
// per-tick. A kernel that accepts REPLACE without recording IFA_PROTO would
// re-adopt (and log) on every 2 s pass; a REPLACE that keeps failing would
// Warn every pass. Each logs once until the next commit (resetVIPWarnings).
func TestDirectVIPAdoptDiagnosticsAreLatched18573(t *testing.T) {
	var buf strings.Builder
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	k := newFakeKernel18573(t)
	d := &Daemon{store: rethStore18573(t, "172.16.50.42/24", "2001:db8:50::42/64")}
	k.install(t, d)
	k.put("ge-0-0-2.50", "172.16.50.42/24", 0)
	k.put("ge-0-0-2.50", "2001:db8:50::42/64", vipstamp.Proto)
	addFn := directVIPAddrAddFn
	replaceErr := error(nil)
	directVIPAddrAddFn = func(idx int, p netip.Prefix, replace bool) error {
		if replace {
			k.adds = append(k.adds, "replace "+p.String())
			return replaceErr // accepted (or refused) without recording the stamp
		}
		return addFn(idx, p, replace)
	}
	count := func(msg string) int { return strings.Count(buf.String(), msg) }

	for i := 0; i < 3; i++ {
		d.directAddVIPs(1)
	}
	if n := count("stamped pre-existing VIP"); n != 1 {
		t.Fatalf("adoption Info logged %d times over 3 ticks, want 1:\n%s", n, buf.String())
	}
	if n := strings.Count(fmt.Sprint(k.adds), "replace 172.16.50.42/24"); n != 3 {
		t.Fatalf("adoption must still be retried every tick (got %d REPLACEs)", n)
	}

	replaceErr = syscall.EPERM
	for i := 0; i < 3; i++ {
		d.directAddVIPs(1)
	}
	if n := count("failed to stamp pre-existing VIP"); n != 1 {
		t.Fatalf("adopt-failure Warn logged %d times over 3 ticks, want 1:\n%s", n, buf.String())
	}
	// A commit re-arms the diagnostics.
	d.resetVIPWarnings()
	d.directAddVIPs(1)
	if n := count("failed to stamp pre-existing VIP"); n != 2 {
		t.Fatalf("after a commit the Warn must fire again once, got %d total", n)
	}
}
