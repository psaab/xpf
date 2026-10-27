package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #15264 (B06-02): the host-inbound applied state is a latch — after `nft flush
// ruleset` (accepted operator action, xpf-input-closed.service:22-26) the
// kernel tables are gone but HostInboundApplied still reports Current.
// The low-rate kernel-truth recheck must mark it stale (and Warn once).

func hostDriftDaemon15264() *Daemon {
	// #17861: the recheck serializes its observe+clear pass with applies
	// via applySem, so every daemon handed to it needs a live semaphore.
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.hostInboundEnforced.Store(true)
	d.noteHostInboundApplySucceeded()
	d.lo0Enforced.Store(true)
	return d
}

func TestKernelTruthDriftMarksHostInboundStale15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	if !d.HostInboundApplied().Current() {
		t.Fatalf("precondition: want Current, got %+v", d.HostInboundApplied())
	}
	// Out-of-band flush: kernel reports no DROP on either table.
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return false, nil },
	}
	buf, restore := captureSlog(t)
	defer restore()
	d.recheckHostKernelTruth15264(time.Now())
	st := d.HostInboundApplied()
	if st.Current() {
		t.Fatalf("after flush, probe still Current: %+v (B06-02 stale status)", st)
	}
	// #16823: Established stays sticky (renders Stale, not NotEstablished)
	// while the day-2 retention latch and coverage sets are cleared, so a
	// failed re-apply takes the cold-boot fence path.
	if !st.Established {
		t.Fatalf("after flush, Established must stay sticky-true (Stale): %+v (#16823)", st)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatalf("after flush, hostInboundEnforced must clear so a failed re-apply fences: %+v (#16823)", st)
	}
	if d.hostInboundCoveredAddrs != nil || d.hostInboundDHCPRetainedAddrs != nil {
		t.Fatalf("after flush, coverage sets must clear: covered=%v dhcp=%v (#16823)", d.hostInboundCoveredAddrs, d.hostInboundDHCPRetainedAddrs)
	}
	if !st.LastApplyFailed {
		t.Fatalf("after flush, LastApplyFailed must be true: %+v", st)
	}
	if d.lo0Enforced.Load() {
		t.Fatalf("after flush, lo0Enforced must clear (table gone): %+v", st)
	}
	if !d.lo0LastFailed.Load() {
		t.Fatal("after flush, lo0LastFailed must be true")
	}
	if !strings.Contains(buf.String(), "15264") {
		t.Fatalf("expected Warn log naming #15264 on drift, got: %q", buf.String())
	}
	// Idempotent: second check stays stale, no panic. The probe gate is the
	// sticky established bit, so the recheck still probes after the latch
	// clear above.
	d.recheckHostKernelTruth15264(time.Now())
	if d.HostInboundApplied().Current() {
		t.Fatal("second check resurrected Current")
	}
}

func TestKernelTruthPresentKeepsCurrent15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	nftInstaller = &fakeNftInstaller{} // defaults: drops=true, enforcing=true
	d.recheckHostKernelTruth15264(time.Now())
	if !d.HostInboundApplied().Current() {
		t.Fatalf("control: tables present must stay Current: %+v", d.HostInboundApplied())
	}
}

// Program-only host-inbound generation: DROPs live in junos-host subchains,
// so TableDropsInput reads false but the table IS enforcing by shape. Must
// stay Current — a false stale here would lie in the opposite direction.
func TestKernelTruthProgramOnlyStaysCurrent15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return true, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if !d.HostInboundApplied().Current() {
		t.Fatalf("program-only (enforcing, subchain DROPs) must stay Current: %+v", d.HostInboundApplied())
	}
}

// lo0-only drift: never-established host-inbound is untouched, while an
// established lo0 table that vanished clears its latch.
func TestKernelTruthLo0DriftOnly15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := &Daemon{applySem: semaphore.NewWeighted(1)} // #17861: recheck takes applySem
	d.lo0Enforced.Store(true)
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(name string) (bool, error) { return name != xnft.Lo0TableName, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if d.lo0Enforced.Load() {
		t.Fatal("lo0Enforced must clear when xpf_lo0 vanished")
	}
	if d.HostInboundApplied().LastApplyFailed {
		t.Fatal("never-established host-inbound must not be marked stale")
	}
}

func TestKernelTruthNotEstablishedIsNoop15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := &Daemon{applySem: semaphore.NewWeighted(1)} // nothing established, nothing configured
	calls := 0
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { calls++; return false, nil },
		tableEnforcing:  func(string) (bool, error) { calls++; return false, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if calls != 0 {
		t.Fatalf("no established/configured surface must not probe kernel, calls=%d", calls)
	}
	if d.HostInboundApplied().LastApplyFailed {
		t.Fatal("cold daemon must not be marked stale")
	}
}

func TestKernelTruthReadErrorKeepsCurrent15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, errors.New("netlink boom") },
		tableEnforcing:  func(string) (bool, error) { return false, errors.New("netlink boom") },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if !d.HostInboundApplied().Current() {
		t.Fatalf("read error must not mark stale (unreadable proves nothing): %+v", d.HostInboundApplied())
	}
	_ = xnft.HostInboundTableName
}

// #16823 (R3-F09-02) DEFECT arm: after the recheck proves the established
// host-inbound table gone (`nft flush ruleset`), a re-apply whose real
// install FAILS must install the cold-boot fence for the previously
// covered addresses. Pre-fix the recheck left hostInboundEnforced and the
// covered set set, so the re-apply took the day-2 retention branch,
// computed an empty uncovered set, and installed NEITHER fence — this
// cell is RED pre-fix (fenceCalls==0, gapCalls==0) and GREEN post-fix.
func TestKernelTruthFlushThenFailedReapplyInstallsColdBootFence16823(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	cfg := hostInboundTestConfig()

	// Step 1: real install succeeds → covered={172.16.50.8, 2001:db8:50::8}.
	nftInstaller = &fakeNftInstaller{}
	d := &Daemon{applySem: semaphore.NewWeighted(1)} // #17861: recheck takes applySem
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("step 1 (install): %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 1: hostInboundEnforced must be true after a successful real install")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "172.16.50.8")]; !ok {
		t.Fatalf("step 1: covered set must include 172.16.50.8, got %v", d.hostInboundCoveredAddrs)
	}

	// Step 2: out-of-band `nft flush ruleset` → recheck proves both tables
	// (and the gap table) gone.
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return false, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	st := d.HostInboundApplied()
	if !st.Established || !st.LastApplyFailed || st.Current() {
		t.Fatalf("step 2: after flush the state must stay established-but-stale, got %+v", st)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatalf("step 2 (#16823): recheck must clear hostInboundEnforced on kernel-proven drift")
	}
	if d.hostInboundCoveredAddrs != nil || d.hostInboundDHCPRetainedAddrs != nil {
		t.Fatalf("step 2 (#16823): recheck must clear coverage sets, covered=%v dhcp=%v",
			d.hostInboundCoveredAddrs, d.hostInboundDHCPRetainedAddrs)
	}

	// Step 3: operator re-applies (the documented convergence step); the
	// real install FAILS. The cold-boot fence must stand for the
	// previously covered addresses.
	injected := errors.New("nftables: re-apply install failed")
	var fenceCalls, gapCalls int
	var fenceSpec xnft.FenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return injected },
		coldBootFence: func(spec xnft.FenceSpec) error {
			fenceCalls++
			fenceSpec = spec
			return nil
		},
		gapFence: func(xnft.GapFenceSpec) error { gapCalls++; return nil },
	}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("step 3: failed re-apply must surface the install error, got %v", err)
	}
	if fenceCalls != 1 {
		t.Fatalf("step 3 (#16823 FAIL-OPEN): after flush + failed re-apply, cold-boot fence installs=%d gap installs=%d; "+
			"want exactly one cold-boot fence denying the previously covered addresses", fenceCalls, gapCalls)
	}
	if gapCalls != 0 {
		t.Fatalf("step 3: cold-boot path must not also install a gap fence, got %d", gapCalls)
	}
	if !sliceContains(fenceViewAddrs(fenceSpec, false), "172.16.50.8") {
		t.Errorf("step 3: fence must deny previously covered 172.16.50.8:\n%+v", fenceSpec)
	}
	if !sliceContains(fenceViewAddrs(fenceSpec, true), "2001:db8:50::8") {
		t.Errorf("step 3: fence must deny previously covered 2001:db8:50::8:\n%+v", fenceSpec)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 3: the standing fence must re-establish hostInboundEnforced")
	}
	if st := d.HostInboundApplied(); !st.Established || !st.LastApplyFailed || st.Current() {
		t.Fatalf("step 3: fence fallback after a failed real install must read established-but-stale, got %+v", st)
	}
}

// #16823 positive control: a flushed box whose re-apply SUCCEEDS converges
// to Current with the real coverage restored and no fence installed. This
// is the documented recovery path and must stay green on both sides of
// the fix.
func TestKernelTruthFlushThenSuccessfulReapplyConverges16823(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	cfg := hostInboundTestConfig()

	nftInstaller = &fakeNftInstaller{}
	d := &Daemon{applySem: semaphore.NewWeighted(1)} // #17861: recheck takes applySem
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("step 1 (install): %v", err)
	}
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return false, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if st := d.HostInboundApplied(); st.Current() {
		t.Fatalf("step 2: flushed box must not read Current: %+v", st)
	}

	var fenceCalls int
	nftInstaller = &fakeNftInstaller{
		coldBootFence: func(xnft.FenceSpec) error { fenceCalls++; return nil },
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("step 3 (successful re-apply): %v", err)
	}
	if fenceCalls != 0 {
		t.Fatalf("step 3: successful re-apply must not install a fence, got %d", fenceCalls)
	}
	st := d.HostInboundApplied()
	if !st.Current() || st.Generation != 2 {
		t.Fatalf("step 3: converged state must be Current at generation 2, got %+v", st)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 3: successful re-apply must re-establish hostInboundEnforced")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "172.16.50.8")]; !ok {
		t.Fatalf("step 3: covered set must be restored, got %v", d.hostInboundCoveredAddrs)
	}
}

// #16823 gap arm: drift also clears the gap marker/spec when the gap table
// is gone, and retains both when the gap table still stands (partial
// flush) or cannot be read.
func TestKernelTruthDriftClearsGapMarkerWhenGapTableGone16823(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	newDriftGapDaemon := func() *Daemon {
		d := hostDriftDaemon15264()
		d.hostInboundGapFenceActive.Store(true)
		d.hostInboundGapFenceSpec = &xnft.GapFenceSpec{UncoveredV4: []string{"203.0.113.9"}}
		d.hostInboundPreActivationFence = &xnft.GapFenceSpec{PreActivation: true, UncoveredV4: []string{"203.0.113.10"}}
		return d
	}

	t.Run("gap gone clears marker and specs", func(t *testing.T) {
		d := newDriftGapDaemon()
		nftInstaller = &fakeNftInstaller{
			tableDropsInput: func(string) (bool, error) { return false, nil },
			tableEnforcing:  func(string) (bool, error) { return false, nil },
		}
		d.recheckHostKernelTruth15264(time.Now())
		if d.HostInboundApplied().GapFenceActive {
			t.Fatal("gap table gone: GapFenceActive must clear (#16823)")
		}
		if d.hostInboundGapFenceSpec != nil || d.hostInboundPreActivationFence != nil {
			t.Fatalf("gap table gone: specs must clear, gap=%v pre=%v", d.hostInboundGapFenceSpec, d.hostInboundPreActivationFence)
		}
	})

	t.Run("gap standing retains marker and specs", func(t *testing.T) {
		d := newDriftGapDaemon()
		nftInstaller = &fakeNftInstaller{
			tableDropsInput: func(string) (bool, error) { return false, nil },
			tableEnforcing: func(name string) (bool, error) {
				return name == xnft.HostInboundGapTableName, nil
			},
		}
		d.recheckHostKernelTruth15264(time.Now())
		if !d.HostInboundApplied().GapFenceActive {
			t.Fatal("gap table still enforcing: GapFenceActive must stay (#16823)")
		}
		if d.hostInboundGapFenceSpec == nil {
			t.Fatal("gap table still enforcing: gap spec must stay for the next merge")
		}
		// The main-table drift arm still fired.
		if d.hostInboundEnforced.Load() {
			t.Fatal("main table gone: hostInboundEnforced must clear even when the gap stands")
		}
	})

	t.Run("gap read error retains marker", func(t *testing.T) {
		d := newDriftGapDaemon()
		nftInstaller = &fakeNftInstaller{
			tableDropsInput: func(string) (bool, error) { return false, nil },
			tableEnforcing: func(name string) (bool, error) {
				if name == xnft.HostInboundGapTableName {
					return false, errors.New("netlink boom")
				}
				return false, nil
			},
		}
		d.recheckHostKernelTruth15264(time.Now())
		if !d.HostInboundApplied().GapFenceActive {
			t.Fatal("gap read error proves nothing: GapFenceActive must stay")
		}
	})
}

// #16823 warn de-dupe: after a drift episode the probe gate survives the
// latch clear, a heal re-arms the one-shot Warn, and a second flush warns
// again (exactly once).
func TestKernelTruthDriftWarnRearmsAfterHeal16823(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	flushed := &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return false, nil },
	}
	present := &fakeNftInstaller{} // drops=true, enforcing=true

	buf, restore := captureSlog(t)
	defer restore()

	nftInstaller = flushed
	d.recheckHostKernelTruth15264(time.Now())
	d.recheckHostKernelTruth15264(time.Now())
	if got := strings.Count(buf.String(), "marking applied state stale"); got != 1 {
		t.Fatalf("first episode must warn exactly once, got %d warns:\n%s", got, buf.String())
	}

	// Heal: a successful real install clears staleness; the next clean
	// pass re-arms the de-dupe.
	d.noteHostInboundApplySucceeded()
	nftInstaller = present
	d.recheckHostKernelTruth15264(time.Now())
	if d.hostDriftNoticed15264.Load() {
		t.Fatal("clean pass after heal must re-arm the drift warn")
	}

	nftInstaller = flushed
	d.recheckHostKernelTruth15264(time.Now())
	if got := strings.Count(buf.String(), "marking applied state stale"); got != 2 {
		t.Fatalf("second flush must warn again (total 2), got %d:\n%s", got, buf.String())
	}
}

// #17861 DEFECT cell: the drift probe and its retention clears must be ONE
// critical section relative to applies. Pre-fix the recheck observed the
// kernel and cleared apply-owned state (hostInboundEnforced, the covered /
// DHCP-retained sets, the gap + pre-activation fence pointers, lo0Enforced)
// WITHOUT applySem: a probe that had already observed the flushed table
// could be preempted before its clears while a concurrent apply installed
// and published a fresh real generation; resuming, the stale observation
// wiped the FRESH generation's retention state, so the next failed apply
// replaced the valid retained table and its service accepts with the
// cold-boot deny-only fence and lost the retained fence bookkeeping. This
// cell parks the recheck between its kernel reads and the clears, then
// publishes a fresh generation under applySem exactly as a successful
// apply does: RED pre-fix (fresh state wiped by the resumed probe), GREEN
// post-fix (the probe holds applySem across its whole pass, so the clears
// complete before the publication, which supersedes them).
func TestKernelTruthDriftClearSparesConcurrentFreshApply17861(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	// Retention state of the FLUSHED generation — what the recheck may clear.
	d.hostInboundCoveredAddrs = map[string]struct{}{hostInboundDropAddrKey('4', "198.51.100.7"): {}}
	d.hostInboundDHCPRetainedAddrs = map[string]struct{}{hostInboundDropAddrKey('4', "198.51.100.7"): {}}
	d.hostInboundGapFenceActive.Store(true)
	d.hostInboundGapFenceSpec = &xnft.GapFenceSpec{UncoveredV4: []string{"198.51.100.7"}}
	d.hostInboundPreActivationFence = &xnft.GapFenceSpec{PreActivation: true, UncoveredV4: []string{"198.51.100.8"}}

	// Park point: TableEnforcing(xpf_hostinbound) is the LAST kernel read
	// before the clears, so parking inside it puts the recheck exactly in
	// the issue's window — observation complete, clears not yet run.
	inProbe := make(chan struct{})
	resume := make(chan struct{})
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing: func(name string) (bool, error) {
			if name == xnft.HostInboundTableName {
				close(inProbe)
				<-resume
			}
			return false, nil
		},
	}
	recheckDone := make(chan struct{})
	go func() {
		d.recheckHostKernelTruth15264(time.Now())
		close(recheckDone)
	}()
	<-inProbe

	// Concurrent successful apply, modeled on the production success sites
	// (applyHostInboundFilter real-load success with retained fences at
	// daemon_nft.go, applyLo0Filter success): the whole publication happens
	// under applySem, like every real apply.
	acquired := make(chan struct{})
	applied := make(chan struct{})
	freshGap := &xnft.GapFenceSpec{UncoveredV4: []string{"203.0.113.10"}}
	freshPre := &xnft.GapFenceSpec{PreActivation: true, UncoveredV4: []string{"203.0.113.11"}}
	go func() {
		defer close(applied)
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			return
		}
		defer d.applySem.Release(1)
		close(acquired)
		d.hostInboundEnforced.Store(true)
		d.noteHostInboundApplySucceeded()
		d.hostInboundGapFenceActive.Store(true) // fresh generation retained its fences
		d.hostInboundGapFenceSpec = freshGap
		d.hostInboundPreActivationFence = freshPre
		d.hostInboundCoveredAddrs = map[string]struct{}{hostInboundDropAddrKey('4', "203.0.113.10"): {}}
		d.hostInboundDHCPRetainedAddrs = map[string]struct{}{hostInboundDropAddrKey('4', "203.0.113.10"): {}}
		d.lo0Enforced.Store(true)
	}()

	// Pre-fix the recheck holds no semaphore, so the apply acquires
	// immediately and its publication lands INSIDE the stale probe's
	// window: wait for it, then resume the probe straight into the bug.
	// Post-fix the probe holds applySem for its whole observe+clear pass,
	// so the apply stays parked on the acquire: time out, resume the
	// probe, and let its clears complete before the publication lands.
	select {
	case <-acquired:
		<-applied
	case <-time.After(2 * time.Second):
	}
	close(resume)
	<-recheckDone
	<-applied

	// The fresh generation's retention state must survive the drift clear.
	if !d.hostInboundEnforced.Load() {
		t.Fatal("#17861: the stale drift clear wiped the fresh generation's hostInboundEnforced latch; " +
			"the next failed apply would fence over the valid retained table and its service accepts")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "203.0.113.10")]; !ok {
		t.Fatalf("#17861: the stale drift clear wiped the fresh covered set, got %v", d.hostInboundCoveredAddrs)
	}
	if _, ok := d.hostInboundDHCPRetainedAddrs[hostInboundDropAddrKey('4', "203.0.113.10")]; !ok {
		t.Fatalf("#17861: the stale drift clear wiped the fresh DHCP-retained set, got %v", d.hostInboundDHCPRetainedAddrs)
	}
	if d.hostInboundGapFenceSpec != freshGap || d.hostInboundPreActivationFence != freshPre {
		t.Fatalf("#17861: the stale drift clear wiped the fresh fence bookkeeping, gap=%v pre=%v",
			d.hostInboundGapFenceSpec, d.hostInboundPreActivationFence)
	}
	if !d.hostInboundGapFenceActive.Load() {
		t.Fatal("#17861: the stale drift clear wiped the fresh gap-fence marker")
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("#17861: the stale drift clear wiped the fresh lo0Enforced latch")
	}
	if st := d.HostInboundApplied(); !st.Current() {
		t.Fatalf("#17861: the fresh generation must read Current after superseding the drift clear, got %+v", st)
	}
}
