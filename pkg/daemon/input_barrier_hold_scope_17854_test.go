package daemon

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// withBound17854 swaps the nft installer and shrinks the pending-handoff
// bound, restoring both on cleanup.
func withBound17854(t *testing.T, fake *fakeNftInstaller, bound time.Duration) {
	t.Helper()
	origInstaller, origBound := nftInstaller, earlyInputPendingHandoffBound
	t.Cleanup(func() {
		nftInstaller = origInstaller
		earlyInputPendingHandoffBound = origBound
	})
	nftInstaller = fake
	earlyInputPendingHandoffBound = bound
}

// withClock17854 pins the daemon's barrier wall clock to a mutable instant.
func withClock17854(t *testing.T, d *Daemon) *time.Time {
	t.Helper()
	now := time.Unix(1700000000, 0)
	d.earlyInputBarrierRetainedNowFn = func() time.Time { return now }
	return &now
}

// lo0OnlyTeardownConfig17885: an lo0 filter with no zoned host-inbound scope,
// so applyHostInboundFilter takes the no-enforcement teardown path.
func lo0OnlyTeardownConfig17854() *config.Config {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest", Action: config.FilterActionDiscard},
		}},
	}
	return cfg
}

// TestEarlyInputLo0HoldOutlivesPendingBound17854 pins the #17854 defect on
// the real-install handoff site: the #16785 bound exists for a never-leasing
// zoned DHCP unit only. A FAILED lo0 install has no substitute backstop once
// the early barrier is gone, so its hold must never be timed out.
// FAIL-ON-REVERT: restoring `effectiveLo0 := lo0RetainsBarrier &&
// !pendingExpired` (plus the forced holdsBarrier=false at expiry) removes the
// barrier on the past-bound apply and marks the handoff done.
func TestEarlyInputLo0HoldOutlivesPendingBound17854(t *testing.T) {
	fake := &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { return errors.New("lo0 load failed") },
	}
	withBound17854(t, fake, time.Minute)
	cfg := lo0FenceTestConfig()
	d := &Daemon{}
	now := withClock17854(t, d)

	// Tail order: lo0 fails first, then host-inbound on the same Daemon.
	if err := d.applyLo0Filter(cfg); err == nil {
		t.Fatal("lo0 apply unexpectedly succeeded")
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("first apply with failed lo0: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("first apply barrier calls = %v, want no remove", fake.earlyInputBarrierCalls)
	}

	// Far past the pending bound: the lo0 hold must STILL retain the barrier.
	*now = now.Add(10 * time.Minute)
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("past-bound apply with failed lo0: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, a failed lo0 must retain the barrier past the pending bound", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("a failed lo0 must not mark the handoff done past the pending bound")
	}
	if st := d.HostInboundApplied(); !st.BarrierRetained {
		t.Fatalf("applied state = %+v, want the lo0 hold surfaced as retained", st)
	}

	// Control (#17854 acceptance): a successful lo0 recovery permits the
	// ordinary handoff on the next apply.
	fake.lo0 = nil
	if err := d.applyLo0Filter(cfg); err != nil {
		t.Fatalf("recovered lo0 apply: %v", err)
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("recovery apply: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 1 {
		t.Fatalf("barrier calls = %v, want exactly one handoff remove after lo0 recovery", fake.earlyInputBarrierCalls)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("lo0 recovery must permit the ordinary handoff")
	}
	if st := d.HostInboundApplied(); st.BarrierRetained {
		t.Fatalf("applied state = %+v, want the hold cleared after handoff", st)
	}
}

// TestEarlyInputMixedPendingLo0HoldOutlivesBound17854 pins the #17854
// regression acceptance: expire a genuine never-leasing DHCP hold WHILE the
// lo0 install still fails — no handoff may occur. The pending bound alone
// cannot drop the lo0 backstop. Recovery then hands off without restarting
// a fresh bound.
func TestEarlyInputMixedPendingLo0HoldOutlivesBound17854(t *testing.T) {
	fake := &fakeNftInstaller{}
	withBound17854(t, fake, time.Minute)
	withLANRow16785(t)
	cfg := neverLeasingZonedConfig16785(t)
	d := &Daemon{}
	now := withClock17854(t, d)
	d.lo0LastFailed.Store(true)

	// Within bound: both holds retain the barrier.
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("within-bound apply: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("within-bound barrier calls = %v, want no remove", fake.earlyInputBarrierCalls)
	}

	// Past bound: the pending hold expired, but lo0 still fails — the
	// barrier must stay.
	*now = now.Add(10 * time.Minute)
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("past-bound mixed apply: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, an expired pending bound must not drop a failed-lo0 hold", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("no handoff may occur while lo0 enforcement keeps failing")
	}
	if st := d.HostInboundApplied(); !st.BarrierRetained || st.BarrierPendingDetail == "" {
		t.Fatalf("applied state = %+v, want the retained hold surfaced with detail", st)
	}

	// lo0 recovers; the never-leasing pending hold is the only remainder and
	// its bound already expired — the very next apply hands off (no fresh
	// five-minute restart).
	d.lo0LastFailed.Store(false)
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("post-recovery apply: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 1 {
		t.Fatalf("barrier calls = %v, want exactly one handoff remove after lo0 recovery", fake.earlyInputBarrierCalls)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("recovery with an expired pending bound must hand off")
	}
}

// TestEarlyInputChangedHoldOutlivesPendingBound17854 pins the sibling half of
// #17854: an addresses-changed hold (a desired destination the just-installed
// ruleset does not cover) is a coverage gap, not a DHCP wait — the pending
// bound must not hand the barrier off over an uncovered destination.
// FAIL-ON-REVERT: the expired shared-clock path skips the retry error and
// removes the barrier, returning nil.
func TestEarlyInputChangedHoldOutlivesPendingBound17854(t *testing.T) {
	fake := &fakeNftInstaller{}
	withBound17854(t, fake, time.Minute)
	cfg := hostInboundTestConfig()
	d := &Daemon{}
	now := withClock17854(t, d)

	// Odd samples (install) see the static WAN set; even samples (handoff
	// re-sample) add an uncovered newcomer address, so every apply observes
	// changed addresses.
	orig := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = orig })
	calls := 0
	sampleHostInboundSnapshots = func(cfg *config.Config) []dpuserspace.InterfaceSnapshot {
		calls++
		snaps := []dpuserspace.InterfaceSnapshot{
			{
				Name: "reth0.50", Zone: "wan", IsUnit: true, LinuxName: "reth0",
				Addresses: []dpuserspace.InterfaceAddressSnapshot{
					{Family: "inet", Address: "172.16.50.8/24"},
					{Family: "inet6", Address: "2001:db8:50::8/64"},
				},
			},
		}
		if calls%2 == 0 {
			snaps[0].Addresses = append(snaps[0].Addresses,
				dpuserspace.InterfaceAddressSnapshot{Family: "inet", Address: "172.16.50.99/24"})
		}
		return snaps
	}

	// First apply: newcomer retained within the bound, apply fails to retry.
	if err := d.applyHostInboundFilter(cfg); err == nil {
		t.Fatal("first apply with an uncovered newcomer must fail the commit")
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("first apply barrier calls = %v, want no remove", fake.earlyInputBarrierCalls)
	}

	// Past the pending bound: still a coverage gap — retain and retry, never
	// a silent handoff.
	*now = now.Add(10 * time.Minute)
	err := d.applyHostInboundFilter(cfg)
	if err == nil {
		t.Fatal("past-bound apply must keep failing the commit over an uncovered destination")
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, an uncovered destination must retain the barrier past the pending bound", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("an uncovered destination must not mark the handoff done")
	}
	if st := d.HostInboundApplied(); !st.BarrierRetained {
		t.Fatalf("applied state = %+v, want the changed-address hold surfaced as retained", st)
	}
}

// TestEarlyInputTeardownLo0HoldOutlivesBound17854 pins #17854 on the
// no-enforcement teardown handoff site: a cold-start lo0 failure (including a
// failed cold-boot fence) must keep its last guard no matter how old the
// pending hold clock is.
func TestEarlyInputTeardownLo0HoldOutlivesBound17854(t *testing.T) {
	fake := &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { return errors.New("lo0 load failed") },
	}
	withBound17854(t, fake, time.Minute)
	cfg := lo0OnlyTeardownConfig17854()
	d := &Daemon{}
	now := withClock17854(t, d)

	if err := d.applyLo0Filter(cfg); err == nil {
		t.Fatal("lo0 apply unexpectedly succeeded")
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("teardown with failed lo0: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, want no remove within the bound", fake.earlyInputBarrierCalls)
	}

	*now = now.Add(10 * time.Minute)
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("past-bound teardown with failed lo0: %v", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, a failed lo0 must retain the barrier on teardown past the bound", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("teardown must not hand off while lo0 enforcement keeps failing")
	}
	st := d.HostInboundApplied()
	if !st.BarrierRetained || st.BarrierPendingDetail != "lo0" {
		t.Fatalf("applied state = %+v, want the lo0 hold surfaced with detail", st)
	}
}

// TestEarlyInputFencedFallbackLo0HoldOutlivesBound17854 pins #17854 on the
// fenced-fallback handoff site: the cold-boot fence covers host-inbound only,
// so a failed lo0 keeps the barrier past the pending bound.
func TestEarlyInputFencedFallbackLo0HoldOutlivesBound17854(t *testing.T) {
	installErr := errors.New("real host-inbound load failed")
	fake := &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { return errors.New("lo0 load failed") },
		hostInbound: func(xnft.HostInboundSpec) error {
			return installErr
		},
		coldBootFence: func(xnft.FenceSpec) error { return nil },
	}
	withBound17854(t, fake, time.Minute)
	cfg := lo0FenceTestConfig()
	d := &Daemon{}
	now := withClock17854(t, d)

	if err := d.applyLo0Filter(cfg); err == nil {
		t.Fatal("lo0 apply unexpectedly succeeded")
	}
	if err := d.applyHostInboundFilter(cfg); !errors.Is(err, installErr) {
		t.Fatalf("fallback apply error = %v, want real install error", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, want no remove within the bound", fake.earlyInputBarrierCalls)
	}

	*now = now.Add(10 * time.Minute)
	if err := d.applyHostInboundFilter(cfg); !errors.Is(err, installErr) {
		t.Fatalf("past-bound fallback error = %v, want real install error only", err)
	}
	if got := barrierRemoves16785(fake); got != 0 {
		t.Fatalf("barrier calls = %v, a failed lo0 must retain the barrier past the pending bound on fallback", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("fenced fallback must not hand off while lo0 enforcement keeps failing")
	}
}

// TestEarlyInputPendingStateConcurrentReads17854 pins the #17854
// synchronization finding: the 30s gap-retry loop and the HostInboundApplied
// projection read the retained-hold state without applySem, so the state
// itself must be safe to read concurrently with retention writes. Run under
// -race this trips on unsynchronized plain time.Time/string fields.
func TestEarlyInputPendingStateConcurrentReads17854(t *testing.T) {
	fake := &fakeNftInstaller{}
	withBound17854(t, fake, time.Minute)
	cfg := neverLeasingZonedConfig16785(t)
	withLANRow16785(t)
	d := &Daemon{}
	now := withClock17854(t, d)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = d.HostInboundApplied()
					_ = d.earlyInputPendingExpired()
				}
			}
		}()
	}
	for i := range 50 {
		*now = now.Add(time.Duration(i) * time.Second)
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Errorf("apply %d: %v", i, err)
			break
		}
		// Cycle the unbounded note path alongside the pending one so both
		// field sets churn under the readers.
		d.noteEarlyInputBarrierRetained(fmt.Sprintf("cycle-%d", i))
	}
	close(stop)
	wg.Wait()
}
