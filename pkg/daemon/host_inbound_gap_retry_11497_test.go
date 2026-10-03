package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

// TestDoubleNftFailAutoConverges11497 is the #11497 acceptance cell: a day-2
// double failure (real install AND gap install both fail in the same apply)
// must latch a bounded retry debt, and the retry owner must converge the
// newcomer with NO new external event once the fault heals — no lease change,
// no commit, no feed/poll/sync apply.
//
// Shape mirrors TestVRFLeaseWindowBoundedByGapAfterFailedRerender10751 (the
// single-failure bound): a VRF-enslaved unzoned DHCP lease is the sharpest
// newcomer because no backstop covers it. Phase 1 installs enforcement, phase
// 2 lands the lease with nft down (double-fail), phase 3 heals nft and fires
// ONLY the wall-clock retry tick with snapshots and config unchanged.
func TestDoubleNftFailAutoConverges11497(t *testing.T) {
	origInstaller := nftInstaller
	t.Cleanup(func() { nftInstaller = origInstaller })
	origSample := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = origSample })
	origReassert := hostInboundGapReassertFn
	t.Cleanup(func() { hostInboundGapReassertFn = origReassert })

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "data", Interfaces: []string{"ge-0/0/9.0"}}}

	uni := int(netlink.SCOPE_UNIVERSE)
	sib := scriptedSnap10751("ge-0/0/0.0", "trust", scriptedAddr10751("inet", "10.0.0.1/24", uni))
	vrfDown := scriptedSnap10751("ge-0/0/9.0", "")
	vrfDown.RoutingInstance = "data"
	s1 := []dpuserspace.InterfaceSnapshot{sib, vrfDown}
	vrfUp := scriptedSnap10751("ge-0/0/9.0", "",
		scriptedAddr10751("inet", "203.0.113.9/24", uni),
		scriptedAddr10751("inet6", "2001:db8:9::9/64", uni))
	vrfUp.RoutingInstance = "data"
	s2 := []dpuserspace.InterfaceSnapshot{sib, vrfUp}

	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	// Phase 1: enforcement installs cleanly; nothing is owed (control against
	// an unconditional latch).
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return s1 }
	nftInstaller = &fakeNftInstaller{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("phase 1 (install): %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("phase 1: hostInboundEnforced must be true after a successful real install")
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("phase 1: first apply must hand off (phase 2 runs day-2)")
	}
	if owed, _, _ := d.HostInboundGapDebt(); owed {
		t.Fatal("phase 1: a successful install must owe no gap retry (unconditional latch)")
	}

	// Phase 2: the VRF lease lands while nft is down — real AND gap fail.
	realErr := errors.New("nftables: real host-inbound load failed")
	gapErr := errors.New("nftables: gap fence load failed")
	var realCalls, gapCalls int
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return s2 }
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { realCalls++; return realErr },
		gapFence:    func(xnft.GapFenceSpec) error { gapCalls++; return gapErr },
	}
	err = d.applyHostInboundFilter(cfg)
	if err == nil || !errors.Is(err, realErr) || !errors.Is(err, gapErr) {
		t.Fatalf("phase 2: double failure must surface the joined real+gap error, got %v", err)
	}
	if realCalls != 1 || gapCalls != 1 {
		t.Fatalf("phase 2: real=%d gap=%d attempts, want exactly 1+1 (no retry storm)", realCalls, gapCalls)
	}
	owed, failures, lastErr := d.HostInboundGapDebt()
	if !owed {
		t.Fatal("phase 2: double nft failure owes nothing; the newcomer stays reachable with no retry owner (#11497)")
	}
	if failures != 1 {
		t.Fatalf("phase 2: failure count = %d, want 1", failures)
	}
	if lastErr == "" {
		t.Fatal("phase 2: debt must record the last error for the operator")
	}
	if d.hostInboundGapFenceActive.Load() {
		t.Fatal("phase 2: no gap fence stands (its install failed)")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "203.0.113.9")]; ok {
		t.Fatal("phase 2: covered set must not include the still-unenforced VRF lease")
	}

	// Phase 3: nft heals; the ONLY trigger is the owner's wall-clock retry
	// tick — snapshots and config are unchanged (no new external event). The
	// retry re-drives the host-inbound apply and must converge + discharge.
	origInterval := hostInboundGapReassertInterval
	t.Cleanup(func() { hostInboundGapReassertInterval = origInterval })
	hostInboundGapReassertInterval = 10 * time.Millisecond
	nftInstaller = &fakeNftInstaller{}
	applies := 0
	converged := make(chan struct{}, 1)
	hostInboundGapReassertFn = func(d *Daemon) error {
		applies++
		err := d.applyHostInboundFilter(cfg)
		if err == nil {
			converged <- struct{}{}
		}
		return err
	}
	retryCtx, cancelRetry := context.WithCancel(context.Background())
	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		d.hostInboundGapReassertLoop(retryCtx)
	}()
	select {
	case <-converged:
		cancelRetry()
	case <-time.After(2 * time.Second):
		cancelRetry()
		<-retryDone
		t.Fatal("phase 3: retry owner did not converge after nft healed; no external event was sent")
	}
	<-retryDone
	if applies != 1 {
		t.Fatalf("phase 3: retry owner performed %d applies, want exactly 1 (debt must converge by APPLY)", applies)
	}
	if owed, _, _ := d.HostInboundGapDebt(); owed {
		t.Fatal("phase 3: debt still owed after the converging retry; the owner must discharge on success")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "203.0.113.9")]; !ok {
		t.Fatalf("phase 3: covered set must include the converged VRF lease, got %v", d.hostInboundCoveredAddrs)
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('6', "2001:db8:9::9")]; !ok {
		t.Fatalf("phase 3: covered set must include the converged VRF lease (v6), got %v", d.hostInboundCoveredAddrs)
	}
	if d.hostInboundGapFenceActive.Load() {
		t.Fatal("phase 3: gap marker must clear once the real table covers the lease")
	}
}

// TestHostInboundGapReassertDoesNothingWhenNothingOwed11497 is the narrowness
// control on the retry owner: it ticks for the life of the daemon, so a
// version that re-applied unconditionally would re-render every 30s on a
// healthy node.
func TestHostInboundGapReassertDoesNothingWhenNothingOwed11497(t *testing.T) {
	origReassert := hostInboundGapReassertFn
	t.Cleanup(func() { hostInboundGapReassertFn = origReassert })
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	applies := 0
	hostInboundGapReassertFn = func(*Daemon) error { applies++; return nil }
	for range 3 {
		d.reassertHostInboundGapOnce(context.Background())
	}
	if applies != 0 {
		t.Fatalf("reassert applied %d time(s) with nothing owed; the owner must be debt-gated", applies)
	}
	if owed, failures, _ := d.HostInboundGapDebt(); owed || failures != 0 {
		t.Fatalf("idle reassert latched debt (owed=%v failures=%d); it must be a no-op", owed, failures)
	}
}

// TestUnchangedDHCPRenewalReassertsOnlyOwedGapDebt11497 proves the daemon-side
// T1/T2 exception: an unchanged lease event drives a full active-config apply
// while the exact gap debt is owed, then is silent again after convergence.
func TestUnchangedDHCPRenewalReassertsOnlyOwedGapDebt11497(t *testing.T) {
	store, _ := newRollbackTestStore(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
	applies := 0
	d.applyBodyForTest = func(*config.Config) { applies++ }
	d.noteHostInboundGapApplyResult(errors.New("real host-inbound and gap nft failures"))
	if owed, _, _ := d.HostInboundGapDebt(); !owed {
		t.Fatal("failure injection did not latch host-inbound gap debt")
	}

	d.onDHCPUnchangedLease()
	if applies != 1 {
		t.Fatalf("unchanged-lease retry performed %d applies, want exactly one", applies)
	}
	if owed, _, _ := d.HostInboundGapDebt(); owed {
		t.Fatal("successful active-config apply did not discharge gap debt")
	}
	d.onDHCPUnchangedLease()
	if applies != 1 {
		t.Fatalf("unchanged lease with no debt performed another apply: total=%d", applies)
	}
}
