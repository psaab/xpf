package nftables

import (
	"bytes"
	"net"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
)

// netlink_kernel_test.go exercises the netlink installer against the REAL kernel
// nf_tables subsystem in a private network namespace (no `nft` binary needed —
// google/nftables talks netlink directly). It proves:
//   - every construct in the §5.1 matrix LOADS (the kernel validates each expr
//     on Flush; a malformed offset/mask/set is rejected), including the
//     no-prior-table cold-boot install (§12.2) and the day-2 atomic replace;
//   - the named CounterObjs read back UNCHANGED through the existing
//     pkg/nftables counter readers (the observability contract, §4).
//
// These tests need CAP_NET_ADMIN to create a netns; they SKIP with an explicit
// reason otherwise (memory rule: no silent caps). Run locally with
//   unshare -rn env GOFLAGS=-mod=mod go test ./pkg/nftables/...
// and in CI as root; the parent runs the `nft`-text parity T1 where `nft` exists.

// enterPrivateNetns locks the goroutine to its OS thread and moves it into a
// fresh network namespace so the default-netns installer + counter readers all
// operate on an isolated, empty ruleset. It SKIPs when netns creation is denied.
func enterPrivateNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns (%v)", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns — needs CAP_NET_ADMIN (run under `unshare -rn` or as root): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

// TestNetlinkInstallLoadsInKernel installs every ruleset variant and asserts the
// kernel accepts each Flush (validating all exprs), covering the no-prior-table
// cold-boot install and the day-2 atomic replace.
func TestNetlinkInstallLoadsInKernel(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()

	// Cold-boot: no table exists yet — the fence install must NOT abort (§12.2).
	if err := in.InstallColdBootFence(fenceScenario()); err != nil {
		t.Fatalf("cold-boot fence install (no prior table) failed: %v", err)
	}
	// Day-2 atomic replace: the real host-inbound table over the fence.
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound install (atomic replace) failed: %v", err)
	}
	// Re-install (idempotent replace) must also succeed.
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound re-install failed: %v", err)
	}
	if err := in.InstallGapFence(gapFenceScenario()); err != nil {
		t.Fatalf("gap fence install failed: %v", err)
	}
	if _, err := in.InstallLo0(lo0Scenario()); err != nil {
		t.Fatalf("lo0 install failed: %v", err)
	}

	// Every expected table is present with a non-empty input chain.
	assertChainNonEmpty(t, HostInboundTableName)
	assertChainNonEmpty(t, HostInboundGapTableName)
	assertChainNonEmpty(t, Lo0TableName)

	// Teardown: delete is idempotent (present -> removed, absent -> nil).
	for _, name := range []string{HostInboundTableName, HostInboundGapTableName, Lo0TableName} {
		if err := in.DeleteTable(name); err != nil {
			t.Fatalf("DeleteTable(%s) failed: %v", name, err)
		}
		if err := in.DeleteTable(name); err != nil {
			t.Fatalf("DeleteTable(%s) second call (absent) should be nil: %v", name, err)
		}
	}
}

// TestCounterReadbackThroughExistingReaders installs the host-inbound table and
// verifies the named CounterObjs round-trip through the EXISTING pkg/nftables
// readers unchanged (deny, accept, and junos-host deny counters).
func TestCounterReadbackThroughExistingReaders(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound install failed: %v", err)
	}

	// Coarse per-zone/family deny counters.
	deny, state, err := ReadHostInboundDenyCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundDenyCounters: %v", err)
	}
	// #5719: a REAL host-inbound generation always carries named counter objects,
	// so the read must report Counted — the state that makes an aggregate zero
	// AUTHORITATIVE. (The fence/absent states are proved below and, without a
	// kernel, by TestClassifyHostInboundDenyObjects.)
	if state != HostInboundTableCounted {
		t.Errorf("table state = %d, want HostInboundTableCounted (%d) for a real install",
			state, HostInboundTableCounted)
	}
	denySet := map[string]bool{}
	for _, d := range deny {
		denySet[d.Zone+"/"+d.Family] = true
	}
	// #3226: `mgmt` (system-services all) is in this list because `all` is now
	// the named-service UNION, not a full admit — the zone falls through to the
	// per-match path and so re-arms its catch-all drop + deny counter. Before
	// #3226 `all` short-circuited to a bare accept with NO drop and NO counter,
	// and this test asserted mgmt's ABSENCE; that assertion would have failed
	// under CAP_NET_ADMIN (it passed only because the private-netns tests skip
	// without the capability), so the flip below is a real privileged-CI gate on
	// the new behaviour, not a bookkeeping edit.
	for _, want := range []string{"trust/ip", "trust/ip6", "core/ip", "edge/ip", "quarantine/ip", "quarantine/ip6", "mgmt/ip", "junos-host/ip", "junos-host/ip6"} {
		if !denySet[want] {
			t.Errorf("deny counter %q not read back; got %v", want, denySet)
		}
	}
	// `any-service` remains the lone full-admit token: a bare accept with no
	// catch-all drop, and therefore no deny counter on either family.
	for _, notWant := range []string{"admin/ip", "admin/ip6"} {
		if denySet[notWant] {
			t.Errorf("admin zone (system-services any-service) must NOT have a deny counter; got %v", denySet)
		}
	}

	// Global ICMP-accept counters (aggregate).
	acc, err := ReadHostInboundAcceptCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundAcceptCounters: %v", err)
	}
	accSet := map[string]bool{}
	for _, a := range acc {
		accSet[a.Type] = true
	}
	for _, want := range HostInboundAcceptCounterTypes {
		if !accSet[want] {
			t.Errorf("accept counter %q not read back; got %v", want, accSet)
		}
	}

	// junos-host DENY counters.
	jh, err := ReadHostInboundJunosHostDenyCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundJunosHostDenyCounters: %v", err)
	}
	jhSet := map[string]bool{}
	for _, j := range jh {
		jhSet[j.Scope+"/"+j.Family] = true
	}
	for _, want := range []string{"untrust/ip", "untrust/ip6"} {
		if !jhSet[want] {
			t.Errorf("junos-host deny counter %q not read back; got %v", want, jhSet)
		}
	}
}

// TestLo0CounterReadback installs the lo0 filter and verifies the `then count`
// counters read back through ReadLo0Counters unchanged.
func TestLo0CounterReadback(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if _, err := in.InstallLo0(lo0Scenario()); err != nil {
		t.Fatalf("lo0 install failed: %v", err)
	}
	counts, err := ReadLo0Counters()
	if err != nil {
		t.Fatalf("ReadLo0Counters: %v", err)
	}
	got := map[string]bool{}
	for _, c := range counts {
		got[c.Counter] = true
	}
	for _, want := range []string{"ssh_hits", "audit"} {
		if !got[want] {
			t.Errorf("lo0 counter %q not read back; got %v", want, got)
		}
	}
}

// assertChainNonEmpty checks the inet table's `input` chain has >= 1 rule.
func assertChainNonEmpty(t *testing.T, table string) {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	rules, err := c.GetRules(
		&nftables.Table{Family: nftables.TableFamilyINet, Name: table},
		&nftables.Chain{Name: "input"},
	)
	if err != nil {
		t.Fatalf("GetRules(%s): %v", table, err)
	}
	if len(rules) == 0 {
		t.Errorf("table %s input chain has no rules", table)
	}
}

// TestFenceTableReadsCounterless is the #5719 discrimination proved END-TO-END
// against the real kernel: the #5644 M37 cold-boot fail-closed fence installs
// xpf_hostinbound with catch-all DROPs and deliberately NO named counters, so it
// must read back as HostInboundTableCounterless — an empty deny slice whose zero
// is NOT authoritative — and be distinguishable from a torn-down table, which
// reads HostInboundTableAbsent (no enforcement, so zero denies really is true).
// Before #5719 both answered (nil, nil) and the REST/Prometheus surfaces
// published an authoritative 0 while the appliance was fenced and dropping.
//
// Like every test in this file it needs CAP_NET_ADMIN and SKIPs otherwise;
// TestClassifyHostInboundDenyObjects covers the same present-table
// discrimination with no privilege at all.
func TestFenceTableReadsCounterless(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()

	// (1) Nothing installed in the fresh netns -> ABSENT.
	counts, state, err := ReadHostInboundDenyCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundDenyCounters (no table): %v", err)
	}
	if state != HostInboundTableAbsent {
		t.Errorf("state with no table = %d, want HostInboundTableAbsent (%d)",
			state, HostInboundTableAbsent)
	}
	if len(counts) != 0 {
		t.Errorf("deny counters with no table = %v, want none", counts)
	}

	// (2) Fence installed -> PRESENT, but carrying no named counters.
	if err := in.InstallColdBootFence(fenceScenario()); err != nil {
		t.Fatalf("InstallColdBootFence failed: %v", err)
	}
	counts, state, err = ReadHostInboundDenyCounters()
	if err != nil {
		t.Fatalf("ReadHostInboundDenyCounters (fence): %v", err)
	}
	if state != HostInboundTableCounterless {
		t.Errorf("state under the cold-boot fence = %d, want HostInboundTableCounterless (%d) "+
			"— an enforcing but uncounted table must not look like an absent one",
			state, HostInboundTableCounterless)
	}
	if len(counts) != 0 {
		t.Errorf("deny counters under the fence = %v, want none (the fence declares none)", counts)
	}

	// (3) Torn down -> ABSENT again.
	if err := in.DeleteTable(HostInboundTableName); err != nil {
		t.Fatalf("DeleteTable(%s): %v", HostInboundTableName, err)
	}
	if _, state, err = ReadHostInboundDenyCounters(); err != nil {
		t.Fatalf("ReadHostInboundDenyCounters (after delete): %v", err)
	}
	if state != HostInboundTableAbsent {
		t.Errorf("state after teardown = %d, want HostInboundTableAbsent (%d)",
			state, HostInboundTableAbsent)
	}
}

// TestTableEnforcingDistinguishesShellTables10751: a fully installed table
// reads enforcing; a shell (table + bare input chain, no rules) and an
// absent table read non-enforcing. Needs CAP_NET_ADMIN (skips otherwise).
func TestTableEnforcingDistinguishesShellTables10751(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if ok, err := in.TableEnforcing(HostInboundTableName); err != nil || ok {
		t.Fatalf("absent table enforcing = %v, %v; want false, nil", ok, err)
	}
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound install: %v", err)
	}
	if ok, err := in.TableEnforcing(HostInboundTableName); err != nil || !ok {
		t.Fatalf("installed table enforcing = %v, %v; want true, nil", ok, err)
	}
	if err := in.DeleteTable(HostInboundTableName); err != nil {
		t.Fatalf("delete table: %v", err)
	}
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("open netlink: %v", err)
	}
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: HostInboundTableName})
	prio := nftables.ChainPriority(hostInboundPriority)
	pol := nftables.ChainPolicyAccept
	c.AddChain(&nftables.Chain{Name: "input", Table: tbl, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: &prio, Policy: &pol})
	if err := c.Flush(); err != nil {
		t.Fatalf("create shell table: %v", err)
	}
	if ok, err := in.TableEnforcing(HostInboundTableName); err != nil || ok {
		t.Fatalf("shell table enforcing = %v, %v; want false, nil", ok, err)
	}
}

// TestTableDropsInputRequiresDropVerdict10751: a real install (catch-all
// DROPs) reads dropping; an admits-only zero-drop fence shell (mandatory
// admits, policy accept, zero DROP — still "enforcing" by shape) reads
// non-dropping, as do bare shells and absent tables. Needs CAP_NET_ADMIN
// (skips otherwise).
func TestTableDropsInputRequiresDropVerdict10751(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	if ok, err := in.TableDropsInput(HostInboundTableName); err != nil || ok {
		t.Fatalf("absent table drops = %v, %v; want false, nil", ok, err)
	}
	if err := in.InstallHostInbound(hostInboundScenario()); err != nil {
		t.Fatalf("host-inbound install: %v", err)
	}
	if ok, err := in.TableDropsInput(HostInboundTableName); err != nil || !ok {
		t.Fatalf("real table drops = %v, %v; want true, nil", ok, err)
	}
	// Zero-drop fence shell: admits-only, policy accept — enforcing shape
	// without any DROP verdict.
	if err := in.InstallColdBootFence(FenceSpec{}); err != nil {
		t.Fatalf("zero-drop fence install: %v", err)
	}
	if ok, err := in.TableEnforcing(HostInboundTableName); err != nil || !ok {
		t.Fatalf("admits-only shell enforcing = %v, %v; want true, nil (shape holds rules)", ok, err)
	}
	if ok, err := in.TableDropsInput(HostInboundTableName); err != nil || ok {
		t.Fatalf("admits-only shell drops = %v, %v; want false, nil", ok, err)
	}
}

// TestGapFenceWithholdsSharedNetns10751: a gap spec carrying only X (W
// withheld daemon-side, #10751 R7-C) installs an X DROP with no W match
// anywhere; mandatory admits present (positive control). Needs
// CAP_NET_ADMIN (skips otherwise).
func TestGapFenceWithholdsSharedNetns10751(t *testing.T) {
	enterPrivateNetns(t)
	in := NewNetlinkInstaller()
	x, w := "10.0.0.9", "10.0.0.5"
	if err := in.InstallGapFence(GapFenceSpec{UncoveredV4: []string{x}}); err != nil {
		t.Fatalf("gap install: %v", err)
	}
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("open netlink: %v", err)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: HostInboundGapTableName}
	chain, err := c.ListChain(tbl, "input")
	if err != nil {
		t.Fatalf("read gap chain: %v", err)
	}
	rules, err := c.GetRules(tbl, chain)
	if err != nil {
		t.Fatalf("read gap rules: %v", err)
	}
	xb, wb := net.ParseIP(x).To4(), net.ParseIP(w).To4()
	var xDrop, wSeen, acceptSeen bool
	for _, r := range rules {
		var cmpX, cmpW, drop bool
		for _, e := range r.Exprs {
			switch v := e.(type) {
			case *expr.Verdict:
				if v.Kind == expr.VerdictDrop {
					drop = true
				}
				if v.Kind == expr.VerdictAccept {
					acceptSeen = true
				}
			case *expr.Cmp:
				if bytes.Equal(v.Data, xb) {
					cmpX = true
				}
				if bytes.Equal(v.Data, wb) {
					cmpW = true
				}
			}
		}
		xDrop = xDrop || (cmpX && drop)
		wSeen = wSeen || cmpW
	}
	if !xDrop {
		t.Error("gap table has no DROP matching X")
	}
	if wSeen {
		t.Error("gap table matches withheld W")
	}
	if !acceptSeen {
		t.Error("gap table lost its mandatory admits (positive control)")
	}
}
