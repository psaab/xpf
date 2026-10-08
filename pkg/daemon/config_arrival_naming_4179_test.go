package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

type namingCall struct {
	nodeID      int
	clusterMode bool
}

// namingStub records positional naming invocations and can inject an error on
// the first N calls (to exercise the #4179 retry-on-failure path).
type namingStub struct {
	calls    []namingCall
	failNext int   // fail the next N calls, then succeed
	failErr  error // error returned while failNext > 0
}

// withNamingStub installs a configurable stub over the positional/device-map
// naming dispatch. The returned *namingStub can be inspected (calls) and armed
// (failNext) by the test.
func withNamingStub(t *testing.T) *namingStub {
	t.Helper()
	savedPos := enumerateAndRenameInterfacesFn
	savedMapped := enumerateAndRenameMappedFn
	st := &namingStub{}
	enumerateAndRenameInterfacesFn = func(nodeID int, clusterMode bool, _ int, _ bool, _ []string) error {
		st.calls = append(st.calls, namingCall{nodeID: nodeID, clusterMode: clusterMode})
		if st.failNext > 0 {
			st.failNext--
			return st.failErr
		}
		return nil
	}
	enumerateAndRenameMappedFn = func(*config.DeviceMapConfig, *config.Config, map[string]bool) error {
		t.Fatal("device-map branch must not fire for a plain positional test config")
		return nil
	}
	t.Cleanup(func() {
		enumerateAndRenameInterfacesFn = savedPos
		enumerateAndRenameMappedFn = savedMapped
	})
	return st
}

func newStoreDaemon(t *testing.T) *Daemon {
	t.Helper()
	// Pin the #1922 lifeline record and networkd directory to scratch paths so
	// naming/bootstrap-exit tests never read or mutate the host's management state.
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })
	oldLinkDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = oldLinkDir })

	if err := os.WriteFile(filepath.Join(linkDir, linkPrefix+"fxp0.network"),
		[]byte(bootstrapLifelineNetworkMarker+" (DHCP)\n[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n"),
		0o644); err != nil {
		t.Fatalf("seed bootstrap lifeline network: %v", err)
	}

	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	return &Daemon{store: store}
}

func clusterConfigNode1() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 1}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-7/0/1": {Name: "ge-7/0/1"},
	}
	return cfg
}

func standaloneConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1"},
	}
	return cfg
}

// TestConfigArrivalRenamingHANode covers the live config-arrival case: a
// config-less HA node can accept a standalone config, but a clustered config
// is rejected by the topology preflight because no HA runtime was built at
// boot. Re-applying the accepted config's naming settings before reconcile
// keeps its interface map from being ignored.
func TestConfigArrivalRenamingHANode(t *testing.T) {
	st := withNamingStub(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := standaloneConfig()
	if ran, err := d.maybeReapplyConfigArrivalNaming(cfg); err != nil || !ran {
		t.Fatalf("expected config-arrival re-naming for the first accepted standalone config: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 1 {
		t.Fatalf("expected exactly one naming re-run, got %d", len(st.calls))
	}
	if st.calls[0].clusterMode || st.calls[0].nodeID != 0 {
		t.Fatalf("standalone re-naming must use standalone mode + node 0, got clusterMode=%v nodeID=%d",
			st.calls[0].clusterMode, st.calls[0].nodeID)
	}

	// One-shot: a second apply of the same config must NOT re-name.
	if ran, err := d.maybeReapplyConfigArrivalNaming(cfg); err != nil || ran {
		t.Fatalf("config-arrival re-naming must be one-shot; second apply re-ran it: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 1 {
		t.Fatalf("second apply re-ran naming (%d calls); must be one-shot", len(st.calls))
	}
}

// TestConfigArrivalRenamingRejectsClusterConfig pins the runtime boundary at
// the naming hook too: a cluster config must not be applied as if config arrival
// could construct the HA runtime and rename interfaces live.
func TestConfigArrivalRenamingRejectsClusterConfig(t *testing.T) {
	st := withNamingStub(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	if ran, err := d.maybeReapplyConfigArrivalNaming(clusterConfigNode1()); err != nil || ran {
		t.Fatalf("cluster config cannot trigger config-arrival naming on a node without an HA runtime: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 0 {
		t.Fatalf("cluster config must not re-run naming, got %d calls", len(st.calls))
	}
	if !d.emptyHANamingPending.Load() {
		t.Fatal("rejected cluster config must not consume the standalone config-arrival marker")
	}
}

// TestConfigArrivalRenamingRetriesOnFailure is the Copilot-caught robustness
// bug (#4182 review): the flag must be consumed only on SUCCESS. A transient
// naming failure (NIC enumeration / netlink error) on the first config apply
// must LEAVE the flag set so the NEXT apply retries — otherwise a config-less
// HA node is stranded on standalone names forever after one blip. Reverting to
// consume-the-flag-first (CompareAndSwap before applyStartupNamingForConfig)
// makes this RED: the second apply never re-runs naming.
func TestConfigArrivalRenamingRetriesOnFailure(t *testing.T) {
	st := withNamingStub(t)
	st.failNext = 1
	st.failErr = errors.New("transient NIC enumeration failure")

	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := standaloneConfig()

	// First apply: naming is attempted but errors → returns false, flag STAYS.
	if ran, err := d.maybeReapplyConfigArrivalNaming(cfg); err != nil || ran {
		t.Fatalf("a failed naming attempt must not report success: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 1 {
		t.Fatalf("first apply should have attempted naming once, got %d", len(st.calls))
	}
	if !d.emptyHANamingPending.Load() {
		t.Fatal("the flag must STAY SET after a failed naming attempt so the next apply retries")
	}

	// Second apply: the stub now succeeds → naming re-runs and the flag is
	// consumed.
	if ran, err := d.maybeReapplyConfigArrivalNaming(cfg); err != nil || !ran {
		t.Fatalf("the second apply must retry naming after the first failed: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 2 {
		t.Fatalf("second apply should have retried naming, got %d total calls", len(st.calls))
	}
	if d.emptyHANamingPending.Load() {
		t.Fatal("the flag must be consumed after the retry succeeded")
	}

	// Third apply: one-shot — no further re-naming.
	if ran, err := d.maybeReapplyConfigArrivalNaming(cfg); err != nil || ran {
		t.Fatalf("naming must not re-run after a successful retry consumed the flag: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 2 {
		t.Fatalf("no further naming expected after success, got %d calls", len(st.calls))
	}
}

// TestConfigArrivalRenamingEmptyConfigDoesNotConsumeFlag proves an empty
// config (no interfaces) does not consume the one-shot flag — naming waits for
// the first accepted standalone config, mirroring the bootstrap-exit "empty
// config is not a takeover" rule.
func TestConfigArrivalRenamingEmptyConfigDoesNotConsumeFlag(t *testing.T) {
	st := withNamingStub(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	empty := &config.Config{}
	if ran, err := d.maybeReapplyConfigArrivalNaming(empty); err != nil || ran {
		t.Fatalf("an empty config must not trigger config-arrival re-naming: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 0 {
		t.Fatalf("empty config must not re-run naming, got %d calls", len(st.calls))
	}

	// The flag survived: a non-empty accepted standalone config still triggers naming.
	if ran, err := d.maybeReapplyConfigArrivalNaming(standaloneConfig()); err != nil || !ran {
		t.Fatalf("the flag must survive an empty config so a later standalone config re-runs naming: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 1 {
		t.Fatalf("standalone config must re-run naming after the empty one, got %d calls", len(st.calls))
	}
}

// TestConfigArrivalRenamingSkippedWhenNotPending proves a normal node (flag
// never set — it booted WITH a config) never re-runs naming on a day-2 commit.
func TestConfigArrivalRenamingSkippedWhenNotPending(t *testing.T) {
	st := withNamingStub(t)
	d := newStoreDaemon(t) // emptyHANamingPending defaults false

	if ran, err := d.maybeReapplyConfigArrivalNaming(standaloneConfig()); err != nil || ran {
		t.Fatalf("a node that did not boot config-less must not re-run naming: ran=%v err=%v", ran, err)
	}
	if len(st.calls) != 0 {
		t.Fatalf("no naming re-run expected on a normal node, got %d calls", len(st.calls))
	}
}

// refuseBarrierForNamingTest10751 scripts a REAL barrier-gate refusal through
// applyStartupNamingPolicy: the barrier reads absent and the guard reinstall
// fails while nftables is usable, so the policy returns
// errEarlyInputProtectionRefused before any rename is attempted.
func refuseBarrierForNamingTest10751(t *testing.T) {
	t.Helper()
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	nftInstaller = &fakeNftInstaller{
		earlyInputBarrierPresent:         func() (bool, error) { return false, nil },
		earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("guard reinstall failed") },
	}
}

// TestConfigArrivalNamingPropagatesBarrierRefusal10751: a barrier-gate
// refusal (concurrent flush between the pre-apply check and this
// re-attestation) returns the sentinel so the caller aborts the apply —
// while the one-shot flag STAYS SET for retry and no rename runs.
// RED on revert: swallowing the refusal returns (false, nil).
func TestConfigArrivalNamingPropagatesBarrierRefusal10751(t *testing.T) {
	st := withNamingStub(t)
	refuseBarrierForNamingTest10751(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	ran, err := d.maybeReapplyConfigArrivalNaming(standaloneConfig())
	if ran {
		t.Fatal("refused naming must not report success")
	}
	if !errors.Is(err, errEarlyInputProtectionRefused) {
		t.Fatalf("refused naming err = %v, want errEarlyInputProtectionRefused", err)
	}
	if !d.emptyHANamingPending.Load() {
		t.Fatal("the flag must STAY SET after a refusal so the next apply retries")
	}
	if len(st.calls) != 0 {
		t.Fatalf("refusal must fire pre-mutation, got %d rename calls", len(st.calls))
	}
}

// TestBootstrapExitAbortsTakeoverOnBarrierRefusal10751: the first-apply
// bootstrap exit aborts with bootstrap mode RE-SUPPRESSED (nothing
// mutated), so a retry re-attempts takeover instead of reconciling onto
// untaken interfaces. Healing the barrier then lets the retry converge.
func TestBootstrapExitAbortsTakeoverOnBarrierRefusal10751(t *testing.T) {
	st := withNamingStub(t)
	refuseBarrierForNamingTest10751(t)
	d := newStoreDaemon(t)
	d.bootstrapMode.Store(true)

	if err := d.maybeExitBootstrapOnFirstConfig(standaloneConfig()); !errors.Is(err, errEarlyInputProtectionRefused) {
		t.Fatalf("bootstrap exit err = %v, want errEarlyInputProtectionRefused", err)
	}
	if !d.inBootstrap() {
		t.Fatal("a refused bootstrap exit must stay in bootstrap mode for retry")
	}
	if len(st.calls) != 0 {
		t.Fatalf("refusal must fire before any rename, got %d rename calls", len(st.calls))
	}

	// Heal: the barrier is present again, so the retry takes over.
	nftInstaller = &fakeNftInstaller{}
	if err := d.maybeExitBootstrapOnFirstConfig(standaloneConfig()); err != nil {
		t.Fatalf("retry after healing err = %v, want nil", err)
	}
	if d.inBootstrap() {
		t.Fatal("the retry must exit bootstrap mode")
	}
	if len(st.calls) != 1 {
		t.Fatalf("retry should have run naming once, got %d calls", len(st.calls))
	}
}

// TestBootstrapExitContinuesOnTransientNamingError10751 pins that ONLY the
// barrier refusal aborts: a transient rename failure keeps the historical
// warn-and-continue (exit proceeds, nil error).
func TestBootstrapExitContinuesOnTransientNamingError10751(t *testing.T) {
	st := withNamingStub(t)
	st.failNext = 1
	st.failErr = errors.New("transient NIC enumeration failure")
	d := newStoreDaemon(t)
	d.bootstrapMode.Store(true)

	if err := d.maybeExitBootstrapOnFirstConfig(standaloneConfig()); err != nil {
		t.Fatalf("transient naming failure err = %v, want nil (historical warn-and-continue)", err)
	}
	if d.inBootstrap() {
		t.Fatal("a transient naming failure must not hold the daemon in bootstrap")
	}
	if len(st.calls) != 1 {
		t.Fatalf("expected one attempted rename, got %d calls", len(st.calls))
	}
}
