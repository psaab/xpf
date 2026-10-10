package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func rpmTestConfig(target string) *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: target, TestInterval: 3600},
		}},
	}}
	return cfg
}

// TestReconcileRPMConfigHashGating is the #1827 PR-1a gating test: the
// probe set is re-applied only when the rendered RPM stanza actually
// changed — unrelated re-applies of the same config are skipped so
// probe state is never wiped.
func TestReconcileRPMConfigHashGating(t *testing.T) {
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
	defer d.rpm.StopAll()

	cfg := rpmTestConfig("192.0.2.1")
	if !d.reconcileRPM(cfg) {
		t.Fatal("first reconcile must apply")
	}
	if d.reconcileRPM(cfg) {
		t.Fatal("identical config must be hash-gated (no re-apply)")
	}
	// A semantically identical but freshly-built config object must
	// also be gated (hash is content-based, not pointer-based).
	if d.reconcileRPM(rpmTestConfig("192.0.2.1")) {
		t.Fatal("equal-content config must be hash-gated")
	}
	// A real change re-applies.
	if !d.reconcileRPM(rpmTestConfig("192.0.2.2")) {
		t.Fatal("changed RPM stanza must re-apply")
	}
	// Removing the stanza re-applies (stops probes) once, then gates.
	empty := &config.Config{}
	if !d.reconcileRPM(empty) {
		t.Fatal("RPM removal must re-apply (stop probes)")
	}
	if d.reconcileRPM(empty) {
		t.Fatal("steady-state empty config must be gated")
	}
	if got := d.rpm.Results(); len(got) != 0 {
		t.Fatalf("probes still running after removal: %+v", got)
	}
}

func TestRPMConfigHashSensitivity(t *testing.T) {
	base := rpmTestConfig("192.0.2.1").Services.RPM
	h1 := rpmConfigHash(base, nil)
	h2 := rpmConfigHash(base, nil)
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
	if h1 == rpmConfigHash(nil, nil) {
		t.Fatal("nil config must hash differently from configured probes")
	}
	// RETH map participates (it changes destination-interface resolution).
	if h1 == rpmConfigHash(base, map[string]string{"reth0": "ge-0/0/2"}) {
		t.Fatal("reth map must participate in the hash")
	}
	withPin := rpmTestConfig("192.0.2.1").Services.RPM
	withPin.Probes["WAN"].Tests["t"].NextHop = "10.0.0.1"
	if h1 == rpmConfigHash(withPin, nil) {
		t.Fatal("next-hop change must change the hash")
	}
}

// rpmPinnedTestConfig returns a config whose single test carries a
// next-hop pin (so BuildProbePins yields one pin).
func rpmPinnedTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "192.0.2.1", NextHop: "10.0.0.1",
				DestinationInterface: "ge-0/0/2", TestInterval: 3600},
		}},
	}}
	return cfg
}

// TestReconcileRPMPinFailureRetry is the #1895 daemon-side contract:
// pin install failures are threaded into the RPM manager, hash-gated
// reconciles retry ONLY the pin install (no probe restart), and the
// retry stops once the install recovers.
func TestReconcileRPMPinFailureRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	retFailed := map[string]error{"WAN/t": fmt.Errorf("egress interface missing")}
	d := &Daemon{rpm: rpm.New(), daemonCtx: ctx, probePinEgressStateFn: func(string) probePinEgressState { return probePinEgressUp }}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		calls++
		if len(pins) != 1 || pins[0].TestKey != "WAN/t" {
			t.Fatalf("unexpected pins: %+v", pins)
		}
		// Codex PR #1899 r1 MAJOR-1: while the band is being
		// cleared-and-reprogrammed, every pin must already be held
		// (pre-marked) so a live probe cannot race the reprogram and
		// false-PASS through the main table.
		if got := d.rpm.PinInstallFailureCount(); got != len(pins) {
			t.Fatalf("pins not pre-held during reprogram: count = %d, want %d", got, len(pins))
		}
		return retFailed
	}
	defer d.rpm.StopAll()

	cfg := rpmPinnedTestConfig()
	if !d.reconcileRPM(cfg) {
		t.Fatal("first reconcile must apply")
	}
	if calls != 1 {
		t.Fatalf("pin apply calls = %d, want 1", calls)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("failure not threaded into rpm manager: count = %d, want 1", got)
	}

	// Hash-gated call: no probe re-apply, but the failed pin install
	// is retried.
	if d.reconcileRPM(cfg) {
		t.Fatal("identical config must stay hash-gated while pins retry")
	}
	if calls != 2 {
		t.Fatalf("pin apply calls = %d, want 2 (retry under unchanged hash)", calls)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("still-failed retry must keep the failure: count = %d", got)
	}

	// Recovery: the next gated call retries, succeeds, clears the
	// manager state, and stops retrying afterwards.
	retFailed = nil
	if d.reconcileRPM(cfg) {
		t.Fatal("recovery retry must not count as a probe re-apply")
	}
	if calls != 3 {
		t.Fatalf("pin apply calls = %d, want 3", calls)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("recovered pins must clear the failure: count = %d", got)
	}
	if d.reconcileRPM(cfg); calls != 3 {
		t.Fatalf("pin apply calls = %d, want 3 (no retry once recovered)", calls)
	}
}

// TestReconcileRPMNoInstallerHoldsPinnedTests: next-hop pins configured but
// no routing manager to install them; with the egress admin-down, every pin
// must still be marked failed and held. Marks alone would otherwise send
// marked-but-unbacked probes through the main table after a later link-up
// (Codex PR #1899 r1 MAJOR-2).
func TestReconcileRPMNoInstallerHoldsPinnedTests(t *testing.T) {
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background(),
		probePinEgressStateFn: func(string) probePinEgressState { return probePinEgressDown }}
	defer d.rpm.StopAll()

	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("first reconcile must apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("pinned test without installer must be held: count = %d, want 1", got)
	}
	// Unpinned configs never report installer failures.
	if !d.reconcileRPM(rpmTestConfig("192.0.2.9")) {
		t.Fatal("config change must re-apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("unpinned config must clear held pins: count = %d", got)
	}
	// Removing RPM entirely releases everything (Codex r3: the
	// no-installer path shares the hold-then-publish-after-Apply
	// ordering, so removal cannot leave stale holds — or release an
	// old hold before the old goroutines are drained).
	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("pinned config must re-apply")
	}
	if !d.reconcileRPM(&config.Config{}) {
		t.Fatal("RPM removal must re-apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("RPM removal must clear held pins: count = %d", got)
	}
}

// rpmTwoPinConfig returns a config with two pinned tests.
func rpmTwoPinConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"a": {Name: "a", Target: "192.0.2.1", NextHop: "10.0.0.1",
				DestinationInterface: "ge-0/0/1", TestInterval: 3600},
			"b": {Name: "b", Target: "192.0.2.2", NextHop: "10.0.1.1",
				DestinationInterface: "ge-0/0/2", TestInterval: 3600},
		}},
	}}
	return cfg
}

// TestReconcileRPMFullApplyHoldsUnionOfOldAndNewPins: on a config
// change, the band reprogram must run with BOTH the old (live) pinned
// tests and the new pin set held — a removed/reordered old pin's live
// goroutine must not send against the band in flux (Codex PR #1899
// r2) — and the real results must only be published after rpm.Apply.
func TestReconcileRPMFullApplyHoldsUnionOfOldAndNewPins(t *testing.T) {
	var heldAtInstall []int
	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		heldAtInstall = append(heldAtInstall, d.rpm.PinInstallFailureCount())
		return nil
	}
	defer d.rpm.StopAll()

	// First apply: no live marks yet — hold covers the 2 new pins.
	if !d.reconcileRPM(rpmTwoPinConfig()) {
		t.Fatal("first reconcile must apply")
	}
	// Config change drops WAN/a: the hold must cover the union of the
	// 2 live old pins and the 1 surviving new pin = 2 keys.
	one := rpmTwoPinConfig()
	delete(one.Services.RPM.Probes["WAN"].Tests, "a")
	if !d.reconcileRPM(one) {
		t.Fatal("changed config must re-apply")
	}
	want := []int{2, 2} // first apply: 2 new; second: union{a,b}∪{b} = 2
	if len(heldAtInstall) != 2 || heldAtInstall[0] != want[0] || heldAtInstall[1] != want[1] {
		t.Fatalf("held counts at install time = %v, want %v", heldAtInstall, want)
	}
	// All installs succeeded: published results clear every hold.
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("holds not released after publish: count = %d", got)
	}
}

// TestProbePinPeriodicRetryRecoversWithoutCommit is the #1895 AGY-fold
// contract: a pin that fails at apply time (boot ordering — egress
// link not yet up) recovers via the slow periodic retry loop with NO
// commit and NO RG transition, and the loop stops once every pin is
// installed.
func TestProbePinPeriodicRetryRecoversWithoutCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	linkUp := false
	calls := 0
	d := &Daemon{rpm: rpm.New(), daemonCtx: ctx, probePinRetryEvery: 5 * time.Millisecond,
		probePinEgressStateFn: func(string) probePinEgressState { return probePinEgressUp }}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if !linkUp {
			return map[string]error{pins[0].TestKey: fmt.Errorf("egress interface missing")}
		}
		return nil
	}
	defer d.rpm.StopAll()

	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("first reconcile must apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("pin must be held after failed apply: count = %d", got)
	}

	// The "link appears" with no further reconcileRPM calls: the
	// periodic loop must recover the pin on its own.
	mu.Lock()
	linkUp = true
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && d.rpm.PinInstallFailureCount() != 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("periodic retry did not recover the pin without a commit: count = %d", got)
	}

	// The loop stops once recovered: no further installer calls.
	mu.Lock()
	settled := calls
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	final := calls
	mu.Unlock()
	if final != settled {
		t.Fatalf("retry loop kept running after recovery: %d -> %d installer calls", settled, final)
	}
	d.rpmMu.Lock()
	active := d.rpmPinRetryActive
	d.rpmMu.Unlock()
	if active {
		t.Fatal("rpmPinRetryActive still set after recovery")
	}
}

// TestReconcileRPMDetectsMissingKernelPinWithoutHashChange12088 pins the
// reported kernel drift: a successful initial install followed by route loss
// must be held on an unchanged config hash, before the periodic reinstall.
func TestReconcileRPMDetectsMissingKernelPinWithoutHashChange12088(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Daemon{
		rpm:                   rpm.New(),
		daemonCtx:             ctx,
		probePinRetryEvery:    time.Hour,
		probePinEgressStateFn: func(string) probePinEgressState { return probePinEgressUp },
	}
	defer d.rpm.StopAll()
	defer d.stopPinRetryLoop()

	var mu sync.Mutex
	routePresent := false
	var applyCalls int
	d.probePinApply = func([]routing.ProbePin) map[string]error {
		mu.Lock()
		defer mu.Unlock()
		applyCalls++
		routePresent = true
		return nil
	}
	d.probePinVerify = func(pins []routing.ProbePin) map[string]error {
		if len(pins) != 1 || pins[0].TestKey != "WAN/t" {
			t.Fatalf("unexpected pins: %+v", pins)
		}
		mu.Lock()
		defer mu.Unlock()
		if routePresent {
			return nil
		}
		return map[string]error{"WAN/t": fmt.Errorf("pinned route missing")}
	}

	cfg := rpmPinnedTestConfig()
	if !d.reconcileRPM(cfg) {
		t.Fatal("first reconcile must apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("initially installed pin is held: failures=%d", got)
	}
	mu.Lock()
	routePresent = false // emulate the kernel deleting the table route
	mu.Unlock()
	if d.reconcileRPM(cfg) {
		t.Fatal("unchanged RPM hash must not restart probes")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("missing route was not held after unchanged-hash reconcile: failures=%d", got)
	}
	mu.Lock()
	gotApplyCalls := applyCalls
	mu.Unlock()
	if gotApplyCalls != 1 {
		t.Fatalf("drift detection reinstalled before retry interval: apply calls=%d, want 1", gotApplyCalls)
	}
}

func TestProbePinFailuresReleaseOnlyOnAdminDownEgress12088(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var stateMu sync.Mutex
	egressState := probePinEgressUp
	egressLookup := func(string) probePinEgressState {
		stateMu.Lock()
		defer stateMu.Unlock()
		return egressState
	}
	setEgressUp := func(up bool) {
		stateMu.Lock()
		if up {
			egressState = probePinEgressUp
		} else {
			egressState = probePinEgressDown
		}
		stateMu.Unlock()
	}
	d := &Daemon{
		rpm:                   rpm.New(),
		daemonCtx:             ctx,
		probePinRetryEvery:    time.Hour,
		probePinEgressStateFn: egressLookup,
	}
	d.probePinApply = func([]routing.ProbePin) map[string]error {
		return nil // Apply succeeds; this test isolates the verify-path filter.
	}
	d.probePinVerify = func(pins []routing.ProbePin) map[string]error {
		return map[string]error{pins[0].TestKey: fmt.Errorf("pinned route missing")}
	}
	defer func() {
		cancel()
		d.stopPinRetryLoop()
		d.rpm.StopAll()
	}()

	cfg := rpmPinnedTestConfig()
	if !d.reconcileRPM(cfg) {
		t.Fatal("initial reconcile must apply")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("missing pin on admin-up egress must hold: failures=%d", got)
	}
	setEgressUp(false)
	if d.reconcileRPM(cfg) {
		t.Fatal("unchanged RPM hash must not restart probes")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("admin-down egress must not hold the test: failures=%d", got)
	}
	setEgressUp(true)
	if d.reconcileRPM(cfg) {
		t.Fatal("unchanged RPM hash must not restart probes")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 1 {
		t.Fatalf("missing pin after admin-up must hold again: failures=%d", got)
	}
}

func TestProbePinFailuresHoldMissingEgress12088(t *testing.T) {
	missingName := fmt.Sprintf("xpf%d", os.Getpid())
	if _, err := netlink.LinkByName(missingName); err == nil {
		t.Skipf("test egress %q unexpectedly exists", missingName)
	}
	manager := rpm.New()
	defer manager.StopAll()
	d := &Daemon{rpm: manager}
	if state := d.probePinEgressStateForName(missingName); state != probePinEgressUnknown {
		t.Fatalf("missing egress state = %v, want unknown", state)
	}
	pins := routing.BuildProbePins(rpmPinnedTestConfig().Services.RPM, nil)
	if len(pins) != 1 {
		t.Fatalf("built pins = %d, want 1", len(pins))
	}
	pins[0].Interface = missingName
	failed := map[string]error{pins[0].TestKey: fmt.Errorf("pinned route missing")}
	held := d.probePinFailuresExceptAdminDownEgress(pins, failed)
	manager.SetPinInstallResults(held)
	if got := manager.PinInstallFailureCount(); got != 1 {
		t.Fatalf("missing-egress pin failure gauge count = %d, want 1", got)
	}

	// A transient LinkByName error is the same unknown state and also
	// must not release the pin hold.
	d.probePinEgressStateFn = func(string) probePinEgressState { return probePinEgressUnknown }
	held = d.probePinFailuresExceptAdminDownEgress(pins, failed)
	manager.SetPinInstallResults(held)
	if got := manager.PinInstallFailureCount(); got != 1 {
		t.Fatalf("unreadable-egress pin failure gauge count = %d, want 1", got)
	}

	// A confirmed existing-but-admin-down egress is the only state that
	// releases the hold, because its bound probes can report ENETUNREACH.
	d.probePinEgressStateFn = func(string) probePinEgressState { return probePinEgressDown }
	held = d.probePinFailuresExceptAdminDownEgress(pins, failed)
	manager.SetPinInstallResults(held)
	if got := manager.PinInstallFailureCount(); got != 0 {
		t.Fatalf("admin-down egress pin failure gauge count = %d, want 0", got)
	}
}

// TestProbePinRetryLoopResubscribesAndResyncsOnClosedSubscriptions12088
// protects the close-channel recovery path: the loop must not panic or spin,
// must establish fresh link and address subscriptions, and must verify all
// pins after the subscription gap.
func TestProbePinRetryLoopResubscribesAndResyncsOnClosedSubscriptions12088(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := rpmPinnedTestConfig()
	var linkSubscriptions, addrSubscriptions, verifyCalls atomic.Int32
	d := &Daemon{
		rpm:                   rpm.New(),
		daemonCtx:             ctx,
		rpmEffective:          cfg.Services.RPM,
		probePinRetryEvery:    time.Hour,
		probePinResubBackoff:  time.Millisecond,
		probePinEgressStateFn: func(string) probePinEgressState { return probePinEgressUp },
		probePinVerify: func([]routing.ProbePin) map[string]error {
			verifyCalls.Add(1)
			return nil
		},
		probePinLinkSubscribe: func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}, _ func(error)) error {
			if linkSubscriptions.Add(1) == 1 {
				close(ch)
			}
			return nil
		},
		probePinAddrSubscribe: func(ch chan<- netlink.AddrUpdate, _ <-chan struct{}, _ func(error)) error {
			if addrSubscriptions.Add(1) == 1 {
				close(ch)
			}
			return nil
		},
	}
	defer d.rpm.StopAll()

	loopDone := make(chan any, 1)
	go func() {
		defer func() { loopDone <- recover() }()
		d.probePinRetryLoop(ctx)
	}()

	var completedEarly bool
	var panicValue any
	if !waitUntil(t, 2*time.Second, func() bool {
		if linkSubscriptions.Load() >= 2 &&
			addrSubscriptions.Load() >= 2 &&
			verifyCalls.Load() >= 2 {
			return true
		}
		select {
		case panicValue = <-loopDone:
			completedEarly = true
			return true
		default:
			return false
		}
	}) {
		cancel()
		select {
		case panicValue = <-loopDone:
		case <-time.After(2 * time.Second):
			t.Fatal("probe pin retry loop did not exit after cancellation")
		}
		t.Fatalf("closed subscriptions did not each resubscribe and resync: link=%d addr=%d verify=%d",
			linkSubscriptions.Load(), addrSubscriptions.Load(), verifyCalls.Load())
	}
	if completedEarly {
		t.Fatalf("probe pin retry loop exited before recovery (panic=%v)", panicValue)
	}

	cancel()
	select {
	case panicValue = <-loopDone:
		if panicValue != nil {
			t.Fatalf("probe pin retry loop panicked after subscription close: %v", panicValue)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe pin retry loop did not exit after cancellation")
	}
	if got := linkSubscriptions.Load(); got < 2 {
		t.Fatalf("link subscription count = %d, want resubscription", got)
	}
	if got := addrSubscriptions.Load(); got < 2 {
		t.Fatalf("address subscription count = %d, want resubscription", got)
	}
	if got := verifyCalls.Load(); got < 2 {
		t.Fatalf("verify calls = %d, want a resync after each subscription is restored", got)
	}
}

const probePin12088InnerEnv = "XPF_12088_PROBE_PIN_INNER"

// TestProbePinKernelDriftReconcilesInPrivateNetns12088 exercises the real
// netlink manager and the daemon's unchanged-hash path against kernel link and
// address cleanup. The outer invocation isolates the whole test process so no
// host routes, addresses, or links are touched.
func TestProbePinKernelDriftReconcilesInPrivateNetns12088(t *testing.T) {
	if os.Getenv(probePin12088InnerEnv) == "1" {
		runProbePinKernelDriftInPrivateNetns12088(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("netns acceptance skipped: unshare is not available")
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run",
		"^TestProbePinKernelDriftReconcilesInPrivateNetns12088$", "-test.v")
	cmd.Env = append(os.Environ(), probePin12088InnerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("private-netns acceptance output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") ||
			strings.Contains(string(out), "unshare:") {
			t.Skipf("netns acceptance skipped: cannot create private namespace: %v", err)
		}
		t.Fatalf("private-netns probe pin acceptance failed: %v", err)
	}
}

func runProbePinKernelDriftInPrivateNetns12088(t *testing.T) {
	const (
		iface = "xpf12088"
		next  = "198.51.100.1"
	)
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("loopback lookup: %v", err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("loopback up: %v", err)
	}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: iface}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Skipf("netns acceptance skipped: cannot create dummy interface: %v", err)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		t.Fatalf("created probe interface lookup: %v", err)
	}
	addr, err := netlink.ParseAddr("198.51.100.2/24")
	if err != nil {
		t.Fatalf("parse probe interface address: %v", err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("probe interface address add: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("probe interface up: %v", err)
	}

	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		rpm:                rpm.New(),
		daemonCtx:          ctx,
		routing:            rt,
		probePinRetryEvery: 1500 * time.Millisecond,
	}
	defer func() {
		cancel()
		d.stopPinRetryLoop()
		d.rpm.StopAll()
		_ = rt.Close()
	}()

	cfg := rpmPinnedTestConfig()
	test := cfg.Services.RPM.Probes["WAN"].Tests["t"]
	test.Target = "127.0.0.1"
	test.NextHop = next
	test.DestinationInterface = iface
	test.TestInterval = 3600
	if !d.reconcileRPM(cfg) {
		t.Fatal("initial pin reconcile did not apply")
	}
	pins := routing.BuildProbePins(cfg.Services.RPM, nil)
	if len(pins) != 1 {
		t.Fatalf("configured pins = %d, want 1", len(pins))
	}
	if failed := rt.VerifyProbePins(pins); len(failed) != 0 {
		t.Fatalf("initial kernel pin did not verify: %v", failed)
	}
	rulePresent := func() bool {
		rules, err := netlink.RuleList(unix.AF_INET)
		if err != nil {
			t.Fatalf("read kernel rules: %v", err)
		}
		for _, rule := range rules {
			if rule.Priority == pins[0].Priority && rule.Mark == pins[0].Mark &&
				rule.Table == pins[0].Table {
				return true
			}
		}
		return false
	}
	routePresent := func() bool {
		routes, err := netlink.RouteListFiltered(unix.AF_INET,
			&netlink.Route{Table: pins[0].Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("read pinned table: %v", err)
		}
		return len(routes) > 0
	}
	sent := func() int64 {
		for _, result := range d.rpm.Results() {
			if result.ProbeName == "WAN" && result.TestName == "t" {
				return result.TotalSent
			}
		}
		return 0
	}
	waitForProbe := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && sent() == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		if sent() == 0 {
			t.Fatal("initial pinned loopback probe did not complete")
		}
	}

	waitForEventHold := func(what string) {
		t.Helper()
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) && d.rpm.PinInstallFailureCount() == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		if got := d.rpm.PinInstallFailureCount(); got != 1 {
			t.Fatalf("%s event did not hold the drifted pin: failures=%d", what, got)
		}
	}
	waitForProbe()
	// Let a healthy monitor tick pass so each following kernel event has a
	// full retry interval in which the held state can be observed.
	time.Sleep(1600 * time.Millisecond)

	assertHeldWithoutProbe := func(what string) int64 {
		t.Helper()
		before := sent()
		if got := d.rpm.PinInstallFailureCount(); got != 1 {
			t.Fatalf("%s: missing kernel route was not held: pin failures=%d", what, got)
		}
		// Restart one immediate RPM cycle while the route is absent. Apply
		// retains SetPinInstallResults; ErrProbeSetup must prevent a send.
		d.rpm.Apply(ctx, cfg.Services.RPM)
		time.Sleep(100 * time.Millisecond)
		if got := sent(); got != before {
			t.Fatalf("%s: probe sent while table-7000 route was absent: %d -> %d",
				what, before, got)
		}
		if routePresent() {
			t.Fatalf("%s: route reinstalled before the retry interval", what)
		}
		return before
	}
	waitForRepair := func(what string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if routePresent() && d.rpm.PinInstallFailureCount() == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !routePresent() {
			t.Fatalf("%s: table-%d route was not restored by one retry interval",
				what, pins[0].Table)
		}
		if got := d.rpm.PinInstallFailureCount(); got != 0 {
			t.Fatalf("%s: pin remained held after route restoration: failures=%d", what, got)
		}
		if failed := rt.VerifyProbePins(pins); len(failed) != 0 {
			t.Fatalf("%s: repaired pin failed readback: %v", what, failed)
		}
	}

	if err := netlink.LinkSetDown(link); err != nil {
		t.Fatalf("egress link down: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("egress link up: %v", err)
	}
	if !rulePresent() || routePresent() {
		t.Fatal("link bounce did not reproduce rule-survives / table-route-disappears")
	}
	waitForEventHold("link down/up")
	if d.reconcileRPM(cfg) {
		t.Fatal("unchanged-hash link-flap reconcile restarted the probe set")
	}
	assertHeldWithoutProbe("link down/up")
	waitForRepair("link down/up")

	if err := netlink.AddrDel(link, addr); err != nil {
		t.Fatalf("last address removal: %v", err)
	}
	if !rulePresent() || routePresent() {
		t.Fatal("last-address removal did not reproduce rule-survives / table-route-disappears")
	}
	waitForEventHold("address removal")
	if d.reconcileRPM(cfg) {
		t.Fatal("unchanged-hash address-loss reconcile restarted the probe set")
	}
	assertHeldWithoutProbe("last-address removal")
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("last address re-add: %v", err)
	}
	waitForRepair("last-address removal and re-add")
	// An IPv6 pin must read back with the kernel's user-route default metric
	// (IP6_RT_PRIO_USER, 1024), not the IPv4 zero metric.
	const v6Iface = "xpf12088v6"
	v6Dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: v6Iface}}
	if err := netlink.LinkAdd(v6Dummy); err != nil {
		t.Fatalf("create IPv6 probe interface: %v", err)
	}
	v6Link, err := netlink.LinkByName(v6Iface)
	if err != nil {
		t.Fatalf("lookup IPv6 probe interface: %v", err)
	}
	v6Addr, err := netlink.ParseAddr("2001:db8:1::2/64")
	if err != nil {
		t.Fatalf("parse IPv6 probe interface address: %v", err)
	}
	v6Addr.Flags |= unix.IFA_F_NODAD
	if err := netlink.AddrAdd(v6Link, v6Addr); err != nil {
		t.Fatalf("add IPv6 probe interface address: %v", err)
	}
	if err := netlink.LinkSetUp(v6Link); err != nil {
		t.Fatalf("raise IPv6 probe interface: %v", err)
	}
	v6Cfg := rpmPinnedTestConfig()
	v6Test := v6Cfg.Services.RPM.Probes["WAN"].Tests["t"]
	v6Test.Target = "2001:db8:ffff::1"
	v6Test.NextHop = "2001:db8:1::1"
	v6Test.DestinationInterface = v6Iface
	v6Pins := routing.BuildProbePins(v6Cfg.Services.RPM, nil)
	if failed := rt.ApplyProbePins(v6Pins); len(failed) != 0 {
		t.Fatalf("IPv6 kernel probe pin install failed: %v", failed)
	}
	if failed := rt.VerifyProbePins(v6Pins); len(failed) != 0 {
		t.Fatalf("freshly installed IPv6 kernel probe pin did not verify: %v", failed)
	}
	v6Routes, err := netlink.RouteListFiltered(unix.AF_INET6,
		&netlink.Route{Table: v6Pins[0].Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("read IPv6 probe table: %v", err)
	}
	if len(v6Routes) != 1 || v6Routes[0].Priority != 1024 {
		t.Fatalf("IPv6 probe route = %+v, want one route with kernel metric 1024", v6Routes)
	}
}

const probePinCarrierLoss12088InnerEnv = "XPF_12088_PROBE_PIN_CARRIER_INNER"

// TestProbePinCarrierLossTriggersIPMonFailover12088 proves that an installed
// LINKDOWN pin remains probeable when ignore_routes_with_linkdown=1 adds DEAD:
// actual ICMP loss crosses RPM's successive-loss threshold and reaches the
// ip-monitoring route-overlay actuator instead of holding the test at ErrProbeSetup.
func TestProbePinCarrierLossTriggersIPMonFailover12088(t *testing.T) {
	if os.Getenv(probePinCarrierLoss12088InnerEnv) == "1" {
		runProbePinCarrierLossInPrivateNetns12088(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("carrier-loss acceptance skipped: unshare is not available")
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run",
		"^TestProbePinCarrierLossTriggersIPMonFailover12088$", "-test.v")
	cmd.Env = append(os.Environ(), probePinCarrierLoss12088InnerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("private-netns carrier-loss output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") ||
			strings.Contains(string(out), "unshare:") {
			t.Skipf("carrier-loss acceptance skipped: cannot create private namespace: %v", err)
		}
		t.Fatalf("private-netns carrier-loss acceptance failed: %v", err)
	}
}

func runProbePinCarrierLossInPrivateNetns12088(t *testing.T) {
	const (
		localName = "xpf12088ca"
		peerName  = "xpf12088cb"
		target    = "198.51.100.3"
		peerAddr  = "198.51.100.2"
		nextHop   = "198.51.100.254"
	)
	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/all/ignore_routes_with_linkdown",
		"/proc/sys/net/ipv4/conf/default/ignore_routes_with_linkdown",
	} {
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
			t.Fatalf("enable ignore_routes_with_linkdown: %v", err)
		}
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: localName}, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("carrier-loss acceptance skipped: cannot create veth pair: %v", err)
		}
		t.Fatalf("create veth pair: %v", err)
	}
	local, err := netlink.LinkByName(localName)
	if err != nil {
		t.Fatalf("lookup local veth: %v", err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("lookup peer veth: %v", err)
	}
	if err := netlink.AddrAdd(local, mustProbeAddr12088(t, "198.51.100.1/24")); err != nil {
		t.Fatalf("address local veth: %v", err)
	}
	if err := netlink.AddrAdd(peer, mustProbeAddr12088(t, peerAddr+"/24")); err != nil {
		t.Fatalf("address peer veth: %v", err)
	}
	if err := netlink.LinkSetUp(local); err != nil {
		t.Fatalf("raise local veth: %v", err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatalf("raise peer veth: %v", err)
	}

	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	cfg := rpmPinnedTestConfig()
	test := cfg.Services.RPM.Probes["WAN"].Tests["t"]
	test.Target = target
	test.NextHop = nextHop
	test.DestinationInterface = localName
	test.ProbeType = "icmp-ping"
	test.ProbeCount = 1
	test.ProbeInterval = 1
	test.TestInterval = 1
	test.ThresholdSuccessive = 2
	pins := routing.BuildProbePins(cfg.Services.RPM, nil)
	if len(pins) != 1 {
		t.Fatalf("configured pins = %d, want one", len(pins))
	}
	if failed := rt.ApplyProbePins(pins); len(failed) != 0 {
		t.Fatalf("initial probe pin install failed: %v", failed)
	}
	if failed := rt.VerifyProbePins(pins); len(failed) != 0 {
		t.Fatalf("initial probe pin did not verify: %v", failed)
	}

	if err := netlink.LinkSetDown(peer); err != nil {
		t.Fatalf("drop peer carrier: %v", err)
	}
	linkdown := func() bool {
		routes, err := netlink.RouteListFiltered(unix.AF_INET,
			&netlink.Route{Table: pins[0].Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("read pinned route after carrier loss: %v", err)
		}
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == target+"/32" &&
				route.Flags&int(unix.RTNH_F_LINKDOWN) != 0 &&
				route.Flags&int(unix.RTNH_F_DEAD) != 0 {
				return true
			}
		}
		return false
	}
	linkdownDeadline := time.Now().Add(time.Second)
	for time.Now().Before(linkdownDeadline) && !linkdown() {
		time.Sleep(10 * time.Millisecond)
	}
	if !linkdown() {
		t.Fatal("kernel did not retain the pinned host route with DEAD|LINKDOWN after carrier loss and ignore_routes_with_linkdown=1")
	}
	if failed := rt.VerifyProbePins(pins); len(failed) != 0 {
		t.Fatalf("carrier-down pin failed shape verification: %v", failed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{
		rpm:                rpm.New(),
		daemonCtx:          ctx,
		routing:            rt,
		probePinRetryEvery: time.Hour,
		// Keep the already-installed route intact; the real kernel readback
		// below is the verification under test.
		probePinApply: func([]routing.ProbePin) map[string]error { return nil },
	}
	actuated := make(chan []config.RouteOverlayEntry, 1)
	var monitor *ipmon.Engine
	monitor = ipmon.New(func(context.Context) bool {
		overlay := monitor.ActiveOverlay()
		if len(overlay) != 0 {
			select {
			case actuated <- overlay:
			default:
			}
		}
		return true
	})
	monitor.Apply(&config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "203.0.113.1"},
			},
		},
	}}, []*rpm.ProbeResult{{ProbeName: "WAN", TestName: "t", LastStatus: "pass"}})
	monitor.Start()
	transitions := make(chan rpm.Transition, 1)
	d.rpm.SetTransitionCallback(func(tr rpm.Transition) {
		transitions <- tr
		monitor.HandleTransition(tr)
	})
	defer func() {
		cancel()
		d.stopPinRetryLoop()
		d.rpm.StopAll()
		monitor.Stop()
		_ = rt.Close()
		_ = netlink.LinkDel(local)
	}()

	if !d.reconcileRPM(cfg) {
		t.Fatal("initial RPM reconcile did not start the pinned probe")
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("LINKDOWN pin entered ErrProbeSetup hold: pin failures=%d", got)
	}

	deadline := time.Now().Add(20 * time.Second)
	var result *rpm.ProbeResult
	for time.Now().Before(deadline) {
		for _, current := range d.rpm.Results() {
			if current.ProbeName == "WAN" && current.TestName == "t" {
				result = current
				break
			}
		}
		if result != nil && result.LastStatus == "fail" && result.SuccFail >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if result == nil || result.LastStatus != "fail" || result.SuccFail < 2 || result.TotalSent < 2 {
		t.Fatalf("carrier loss did not become thresholded probe failure: result=%+v", result)
	}
	if got := d.rpm.PinInstallFailureCount(); got != 0 {
		t.Fatalf("genuine probe loss was held as setup failure: pin failures=%d", got)
	}
	select {
	case tr := <-transitions:
		if tr.Status != "fail" || tr.ProbeName != "WAN" || tr.TestName != "t" {
			t.Fatalf("unexpected failover sensor transition: %+v", tr)
		}
	case <-time.After(time.Second):
		t.Fatal("thresholded carrier loss did not publish an RPM fail transition")
	}
	select {
	case overlay := <-actuated:
		if len(overlay) != 1 || overlay[0].Destination != "0.0.0.0/0" ||
			overlay[0].NextHop != "203.0.113.1" {
			t.Fatalf("ip-monitoring actuator received overlay %+v, want failover default route via 203.0.113.1", overlay)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ip-monitoring failover overlay was not actuated after thresholded probe loss")
	}
}

func mustProbeAddr12088(t *testing.T, value string) *netlink.Addr {
	t.Helper()
	addr, err := netlink.ParseAddr(value)
	if err != nil {
		t.Fatalf("parse address %q: %v", value, err)
	}
	return addr
}
