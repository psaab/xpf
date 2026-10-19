package daemon

import (
	"net/netip"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// lifelineOnlyPDConfig is the supported composition from #9239: standalone, the
// only DHCPv6 client is the true management lifeline fxp0, and it maps a
// delegated prefix to a downstream RA interface.
//
// The lifeline is what makes this dangerous: every DHCP client here is a
// lifeline, so the classifier picks the management-only branch, which refreshes
// routes, DNS and IPsec and NEVER touches RA.
func lifelineOnlyPDConfig() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name:  "fxp0",
					Units: map[int]*config.InterfaceUnit{0: {DHCP: true, DHCPv6: true}},
				},
			},
		},
	}
}

func TestPDWithdrawalRequiresRecompile9239(t *testing.T) {
	cfg := lifelineOnlyPDConfig()

	// REFERENCE ARM. Establish that a PRESENT delegated prefix forces the
	// recompile, using a real dhcp.Manager rather than the bare bool. Without
	// this the withdrawal assertion below could pass against a world in which
	// PD never mattered at all, and would be measuring nothing.
	withPD := &Daemon{dhcp: dhcp.NewManagerForTesting(nil)}
	withPD.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	withPD.dhcp.SeedDelegatedPrefixesForRATesting("fxp0", "ge-0/0/1",
		[]dhcp.DelegatedPrefix{{Interface: "fxp0", Prefix: netip.MustParsePrefix("2001:db8::/56")}})
	if !withPD.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("reference arm: a PRESENT delegated prefix must force the recompile; " +
			"if this fails the withdrawal row below proves nothing")
	}

	// THE DEFECT. commitLease has already deleted the withdrawn prefix by the
	// time the callback runs, so the post-state is empty -- identical to a box
	// that never had PD. Only the PRIOR distinguishes them.
	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	if !d.dhcpLeaseChangeRequiresRecompile(cfg, true) {
		t.Error("withdrawing the LAST delegated prefix must force the full apply: " +
			"standalone has no other RA applier, so the sender keeps refreshing a " +
			"prefix upstream has withdrawn")
	}

	// NARROWNESS. A box that never had PD must still take the cheap
	// management-only path. If this reds, the fix has turned every lifeline
	// lease refresh into a full dataplane recompile.
	if d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Error("a lease refresh with no PD, past or present, must not force a recompile")
	}
}

// TestPDWithdrawalTransitionIsRecordedOnce9239 pins the memo's own behaviour:
// the withdrawal forces exactly ONE full apply, not a permanent one. A latch
// that never clears would turn every subsequent lease refresh on this box into
// a dataplane recompile, which is the opposite failure.
func TestPDWithdrawalTransitionIsRecordedOnce9239(t *testing.T) {
	d := &Daemon{}
	// Present -> the swap records true and reports no prior.
	if prior := d.pdForRAPresent.Swap(true); prior {
		t.Fatal("a fresh daemon must report no prior delegated prefix")
	}
	// Withdrawn -> the swap reports the prior true (forcing the apply) and
	// records false.
	if prior := d.pdForRAPresent.Swap(false); !prior {
		t.Error("the withdrawal pass must observe the prior prefix")
	}
	// Steady state -> no prior, so no further forced applies.
	if prior := d.pdForRAPresent.Swap(false); prior {
		t.Error("the transition must clear after one pass, not latch")
	}
}

// TestPDWithdrawalDrivesTheRealCallback9239 is the cell that binds the WIRING.
//
// The two cells above call the predicate directly, which binds only the
// FUNCTION: replacing `hadPDForRA` with a literal `false` at the one production
// call site leaves both of them green. Verified by mutation — that edit killed
// zero cells in the whole package before this one existed, which is precisely
// how a fix can land, look tested, and do nothing.
//
// So this drives onDHCPAddressChange, the callback the daemon actually
// registers, and observes WHICH BRANCH it took. preApplyHookForTest fires only
// inside the recompile arm; the management-only arm never reaches it.
func TestPDWithdrawalDrivesTheRealCallback9239(t *testing.T) {
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Lifeline-only DHCPv6: fxp0 is a TRUE host-inbound lifeline, so without a
	// PD signal the classifier takes the cheap management-only path -- the arm
	// that never applies RA. That is what makes the withdrawal invisible.
	if _, err := s.LoadSet("set interfaces fxp0 unit 0 family inet dhcp\n" +
		"set interfaces fxp0 unit 0 family inet6 dhcpv6-client client-type stateful\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		opts:     Options{NoDataplane: true},
		dhcp:     dhcp.NewManagerForTesting(nil),
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	d.dhcp.SeedDelegatedPrefixesForRATesting("fxp0", "ge-0/0/1",
		[]dhcp.DelegatedPrefix{{Interface: "fxp0", Prefix: netip.MustParsePrefix("2001:db8::/56")}})

	var applied int
	d.preApplyHookForTest = func() { applied++ }

	// applyActiveConfig CLEARS the published management-VRF set under
	// NoDataplane, and an empty set makes the predicate return true
	// conservatively -- via a branch that has nothing to do with prefix
	// delegation. Left unrestored, passes 2 and 3 would both be answered by
	// that branch and this cell would be VACUOUS for the fix it exists to
	// guard: it stayed green with the wiring cut. Re-establish the
	// precondition before every pass so each verdict is attributable.
	pass := func() {
		d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
		d.onDHCPAddressChange()
	}

	// Pass 1: the prefix is present. Recompile expected -- and this is also
	// what records the prior for pass 2.
	pass()
	if applied != 1 {
		t.Fatalf("reference arm: a lease change WITH a delegated prefix must recompile; applied=%d", applied)
	}

	// Pass 2: the upstream withdrew the last IA-PD while keeping IA-NA.
	// commitLease has already removed it, so the manager now reports none --
	// an empty manager is exactly that post-state.
	d.dhcp = dhcp.NewManagerForTesting(nil)
	pass()
	if applied != 2 {
		t.Errorf("withdrawing the LAST delegated prefix must still recompile, so RA is "+
			"re-applied and the sender stops refreshing a withdrawn prefix; applied=%d", applied)
	}

	// Pass 3: steady state with no PD on either side. The transition must have
	// cleared, or every later lease refresh on this box is a full recompile.
	pass()
	if applied != 2 {
		t.Errorf("the withdrawal must force ONE apply, not latch; applied=%d", applied)
	}
}
