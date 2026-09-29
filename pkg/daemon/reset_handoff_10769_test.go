package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sync/semaphore"
)

func isolateHandoffFlag(t *testing.T) {
	t.Helper()
	orig := configstore.ResetHandoffPath
	configstore.ResetHandoffPath = filepath.Join(t.TempDir(), ".reset-handoff")
	t.Cleanup(func() { configstore.ResetHandoffPath = orig })
}

// recoveryHostSeams bundles every host-path redirect + recorder the
// recovery e2es need so the authoring apply cannot touch the test host
// even as root. The authoring config is minimal (host-name + userspace
// dataplane), but several apply steps write unconditionally or sweep
// live host state: transit sysctls (managed once EverCommitted),
// sudoers/known-hosts/rsyslog sweeps, chrony renders + reload, DNS
// reconcile, and the hostname rename (installed separately at each
// test top since phase-1 restore needs it too).
type recoveryHostSeams struct {
	v4, v6          string
	barrier         *fakeNftInstaller
	sudoersStale    string
	knownHosts      string
	rsyslogStale    string
	chronySources   string
	chronyThreshold string
	chronyReloaded  *bool
	rsyslogRestarts *int
	dnsCalls        *int
	linkDir         string
	ghostMarker     string
	provDir         string
	provOrig        string
}

// provisionedRedirectActive reports whether the account-ownership
// inventory redirect is in effect: the live value must equal the
// expected throwaway path and differ from the entry value. Checked
// BEFORE planting any marker so a redirect regression fails without
// touching host state.
func provisionedRedirectActive(got, expected, orig string) bool {
	return got == expected && got != orig
}

func TestProvisionedRedirectGuard10769(t *testing.T) {
	const orig = "/var/lib/xpf/provisioned-users"
	redir := filepath.Join(t.TempDir(), "prov", "provisioned-users")
	if !provisionedRedirectActive(redir, redir, orig) {
		t.Fatal("active redirect must be accepted")
	}
	if provisionedRedirectActive(orig, redir, orig) {
		t.Fatal("unredirected entry value must be rejected")
	}
	if provisionedRedirectActive(filepath.Join(t.TempDir(), "elsewhere"), redir, orig) {
		t.Fatal("unexpected path must be rejected")
	}
}

func isolateRecoveryApplyHost(t *testing.T) *recoveryHostSeams {
	t.Helper()
	s := &recoveryHostSeams{}
	dir := t.TempDir()
	// Transit sysctls + appliance marker. Pre-seed "1" so the gated
	// close ("0") proves the write routed here.
	origV4, origV6 := ipv4ForwardSysctlPath, ipv6ForwardSysctlPath
	origMarker := applianceMarkerFile
	s.v4, s.v6 = filepath.Join(dir, "ip_forward"), filepath.Join(dir, "forwarding")
	if err := os.WriteFile(s.v4, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.v6, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = s.v4, s.v6
	applianceMarkerFile = filepath.Join(dir, "appliance")
	t.Cleanup(func() {
		ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = origV4, origV6
		applianceMarkerFile = origMarker
	})
	// nft barrier installer.
	s.barrier = withBarrierRecorder(t)
	// Sudoers sweep: plant a stale grant the reconcile must remove.
	origSudoers := sudoersDir
	sudoersTmp := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(sudoersTmp, 0o755); err != nil {
		t.Fatal(err)
	}
	s.sudoersStale = filepath.Join(sudoersTmp, "xpf-stale-evil")
	if err := os.WriteFile(s.sudoersStale, []byte("# stale\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	sudoersDir = sudoersTmp
	t.Cleanup(func() { sudoersDir = origSudoers })
	// Account-ownership inventory: one seam relocates all three roots.
	// Plant a ghost marker (account registry only, no password/key
	// markers) for a name absent from the passwd fixture: the
	// reconcile must enumerate it through the redirect, find no such
	// account, and drop the stale marker — success without touching
	// any credential. Benign by construction: the name exists
	// nowhere (fixture passwd has only root), and even a same-named
	// host account would mismatch the planted UID and stay untouched
	// (UID-keyed provenance).
	origProv := provisionedUsersDir
	expectedProv := filepath.Join(dir, "prov", "provisioned-users")
	provisionedUsersDir = expectedProv
	t.Cleanup(func() { provisionedUsersDir = origProv })
	s.provDir, s.provOrig = provisionedUsersDir, origProv
	// Guard BEFORE any marker operation: a removed redirect must stop
	// here, never plant into or enumerate the live host inventory.
	if !provisionedRedirectActive(provisionedUsersDir, expectedProv, origProv) {
		t.Fatalf("provisioned-users redirect inactive: got %q want %q (orig %q); refusing to plant ghost marker", provisionedUsersDir, expectedProv, origProv)
	}
	const ghostUser = "xpf-test-ghost-10769"
	if err := markProvisioned(ghostUser, 59999); err != nil {
		t.Fatal(err)
	}
	s.ghostMarker = markerPathIn(provisionedUsersDir, ghostUser)
	origPasswd := passwdPath
	passwdFixture := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwdFixture, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	passwdPath = passwdFixture
	t.Cleanup(func() { passwdPath = origPasswd })
	// Managed SSH known-hosts: plant a file the empty-config branch
	// must remove.
	origKH := sshKnownHostsPath
	s.knownHosts = filepath.Join(dir, "ssh_known_hosts")
	// Managed header: the remover only deletes files xpfd owns.
	if err := os.WriteFile(s.knownHosts, []byte("# Managed by xpfd — do not edit\nstale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sshKnownHostsPath = s.knownHosts
	t.Cleanup(func() { sshKnownHostsPath = origKH })
	// Rsyslog drop-ins + restart.
	origRsyslog := rsyslogConfDir
	rsysTmp := filepath.Join(dir, "rsyslog.d")
	if err := os.MkdirAll(rsysTmp, 0o755); err != nil {
		t.Fatal(err)
	}
	s.rsyslogStale = filepath.Join(rsysTmp, "10-xpf-stale.conf")
	if err := os.WriteFile(s.rsyslogStale, []byte("# stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rsyslogConfDir = rsysTmp
	origRsRestart := rsyslogRestartFn
	restarts := 0
	rsyslogRestartFn = func() ([]byte, error) { restarts++; return nil, nil }
	s.rsyslogRestarts = &restarts
	t.Cleanup(func() { rsyslogConfDir = origRsyslog; rsyslogRestartFn = origRsRestart })
	// Chrony renders + runtime reload. The minimal config renders empty,
	// so plant stale content the reconcile must remove (proving the
	// redirect is live) and the reload stub must observe.
	origCS, origCT := chronySourcesPath, chronyThresholdPath
	s.chronySources = filepath.Join(dir, "xpf.sources")
	s.chronyThreshold = filepath.Join(dir, "xpf-threshold.conf")
	for _, p := range []string{s.chronySources, s.chronyThreshold} {
		if err := os.WriteFile(p, []byte("# stale\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	chronySourcesPath, chronyThresholdPath = s.chronySources, s.chronyThreshold
	origChReload := chronyReloadFn
	reloaded := false
	chronyReloadFn = func(sourcesChanged, thresholdChanged bool) chronyReloadOutcome {
		reloaded = true
		return chronyReloadOutcome{}
	}
	s.chronyReloaded = &reloaded
	t.Cleanup(func() { chronySourcesPath, chronyThresholdPath = origCS, origCT; chronyReloadFn = origChReload })
	s.dnsCalls = new(int)
	// Interface link dir: nothing in these applies configures
	// interfaces; the redirect + emptiness assertion trip if that
	// ever changes.
	origLink := linkDir
	s.linkDir = filepath.Join(dir, "network")
	if err := os.MkdirAll(s.linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	linkDir = s.linkDir
	t.Cleanup(func() { linkDir = origLink })
	return s
}

// assertRecoveryHostIsolated proves the authoring apply wrote only
// through the redirected seams: every plant swept or written in the
// throwaway tree, every external command stubbed, every sysctl
// flipped in the redirect. Call after the authoring commit.
func assertRecoveryHostIsolated(t *testing.T, d *Daemon, s *recoveryHostSeams) {
	t.Helper()
	for _, p := range []string{s.v4, s.v6} {
		if body, err := os.ReadFile(p); err != nil || strings.TrimSpace(string(body)) != "0" {
			t.Fatalf("transit sysctl redirect %s = %q err=%v, want gated 0", p, body, err)
		}
	}
	if lastBarrierCall(s.barrier) == "" {
		t.Fatal("transit barrier must route to the fake installer")
	}
	for _, p := range []string{s.sudoersStale, s.knownHosts, s.rsyslogStale} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("stale plant %s must be swept from the redirect: %v", p, err)
		}
	}
	for _, p := range []string{s.chronySources, s.chronyThreshold} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("stale chrony plant %s must be removed from the redirect: %v", p, err)
		}
	}
	if !*s.chronyReloaded {
		t.Fatal("chrony reload must route to the stub")
	}
	if *s.rsyslogRestarts == 0 {
		t.Fatal("rsyslog restart must route to the stub")
	}
	if *s.dnsCalls == 0 {
		t.Fatal("DNS reconcile must route to the field seam")
	}
	// The ghost marker's absence proves the absent-user reconcile
	// enumerated through the redirected roots (a host inventory read
	// would never have seen it) and converged without error. The var
	// check proves the redirect itself is active (catches removal of
	// the redirect, under which the plant would land on the host).
	if provisionedUsersDir != s.provDir || s.provDir == s.provOrig {
		t.Fatal("provisioned-users redirect must be active during the apply")
	}
	if _, err := os.Lstat(s.ghostMarker); !os.IsNotExist(err) {
		t.Fatalf("ghost marker %s must be dropped from the redirect: %v", s.ghostMarker, err)
	}
	// Drift tripwire, NOT interception evidence: this fixture
	// configures no interfaces, so nothing should write here. It
	// trips if a future fixture change starts writing link files,
	// forcing that path to be isolated deliberately.
	if entries, _ := os.ReadDir(s.linkDir); len(entries) != 0 {
		t.Fatalf("link dir must stay empty, got %v", entries)
	}
}

// fakePendingWipe returns a factoryReset wipe closure honoring the pending
// protocol a real gated wipe follows: record PENDING, then succeed. The
// daemon flips pending→clean only after post-verification passes, so a
// fake success without pending fails closed like a bypassed wipe.
func fakePendingWipe(t *testing.T) func() error {
	t.Helper()
	return func() error {
		boot, err := configstore.CurrentBootID()
		if err != nil {
			return err
		}
		return configstore.WriteResetHandoff(boot, configstore.ResetHandoffPending, "")
	}
}

func handoffTestStore(t *testing.T) *configstore.Store {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCommitRefusedWhileHandoffDirty10769(t *testing.T) {
	isolateHandoffFlag(t)
	store := handoffTestStore(t)
	if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed", ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("commit with dirty handoff = %v, want incomplete", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 1, peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("commit-confirmed with dirty handoff = %v, want incomplete", err)
	}
	if _, err := d.syncAndApply(context.Background(), "system { host-name peer; }", nil); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("sync with dirty handoff = %v, want incomplete", err)
	}
	if cfg := store.ActiveConfig(); cfg != nil {
		t.Fatalf("refused provisioning must persist nothing, active = %+v", cfg.System.HostName)
	}
}

func TestCommitRefusedPreReboot10769(t *testing.T) {
	isolateHandoffFlag(t)
	store := handoffTestStore(t)
	boot, err := configstore.CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	if err := configstore.WriteResetHandoff(boot, "", ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffRebootRequired) {
		t.Fatalf("pre-reboot commit = %v, want reboot-required", err)
	}
}

func TestCommitOpensPostReboot10769(t *testing.T) {
	isolateHandoffFlag(t)
	store := handoffTestStore(t)
	if err := configstore.WriteResetHandoff("other-boot", "", ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	_, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
	if errors.Is(err, configstore.ErrResetHandoffDirty) || errors.Is(err, configstore.ErrResetHandoffRebootRequired) {
		t.Fatalf("post-reboot commit must pass the handoff gate, got %v", err)
	}
	if _, serr := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(serr) {
		t.Fatalf("converged flag must be cleared, stat err = %v", serr)
	}
}

func commitUserspaceStateFile(t *testing.T, store *configstore.Store, stateFile string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	set := "set system dataplane-type userspace\n" +
		"set system dataplane state-file " + stateFile + "\n"
	if _, err := store.LoadSet(set); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func TestReconcileHandoffAtBoot10769(t *testing.T) {
	t.Run("absent flag is a no-op", func(t *testing.T) {
		isolateHandoffFlag(t)
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
	})
	t.Run("clean post-reboot clears", func(t *testing.T) {
		isolateHandoffFlag(t)
		custom := filepath.Join(t.TempDir(), "custom", "userspace-dp.json")
		if err := configstore.WriteResetHandoff("other-boot", "", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
			t.Fatalf("converged flag must be cleared: %v", err)
		}
	})
	t.Run("clean same-boot is kept", func(t *testing.T) {
		isolateHandoffFlag(t)
		boot, err := configstore.CurrentBootID()
		if err != nil {
			t.Fatal(err)
		}
		custom := filepath.Join(t.TempDir(), "custom", "userspace-dp.json")
		if err := configstore.WriteResetHandoff(boot, "", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(configstore.ResetHandoffPath); err != nil {
			t.Fatalf("same-boot flag must be kept: %v", err)
		}
	})
	t.Run("dirty post-reboot repairs and clears", func(t *testing.T) {
		isolateHandoffFlag(t)
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		stateFile := filepath.Join(t.TempDir(), "run", "xpf", "userspace-dp.json")
		if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stateFile, []byte("stale snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		store := handoffTestStore(t)
		commitUserspaceStateFile(t, store, stateFile)
		if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed", stateFile); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: store}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(stateFile); !os.IsNotExist(err) {
			t.Fatalf("dirty residue must be repaired at boot: %v", err)
		}
		if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
			t.Fatalf("repaired flag must be cleared: %v", err)
		}
	})
	t.Run("dirty repair failure keeps the flag", func(t *testing.T) {
		isolateHandoffFlag(t)
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
			t.Fatal(err)
		}
		store := handoffTestStore(t)
		commitUserspaceStateFile(t, store, filepath.Join(blocker, "userspace-dp.json"))
		if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed", filepath.Join(blocker, "userspace-dp.json")); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: store}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(configstore.ResetHandoffPath); err != nil {
			t.Fatalf("unrepaired dirty flag must be kept: %v", err)
		}
	})
}

// resetHelperDP simulates a userspace dataplane whose helper writes its
// final state (plus an orphan temp sibling, exact writer shape) when
// stopped — the write the post-wipe sweep must catch and verify.
type resetHelperDP struct {
	dataplane.RuntimeDataPlane

	stateFile string
	stops     int
}

func (d *resetHelperDP) Start(context.Context) error { return nil }
func (d *resetHelperDP) Close() error                { return nil }
func (d *resetHelperDP) Teardown() error             { return nil }
func (d *resetHelperDP) StopHelperForReset() {
	d.stops++
	if d.stateFile == "" {
		return
	}
	// Best-effort final write: sweep-failure cells point stateFile at an
	// unwritable path on purpose, and the helper's own write error is not
	// what they assert.
	_ = os.MkdirAll(filepath.Dir(d.stateFile), 0o700)
	_ = os.WriteFile(d.stateFile, []byte("final snapshot"), 0o600)
	base := filepath.Base(d.stateFile)
	_ = os.WriteFile(filepath.Join(filepath.Dir(d.stateFile), base+".1_1.1.tmp"), []byte("orphan temp"), 0o600)
}

// The reset stop must keep matching the concrete userspace manager: a
// signature drift that silently disables the optional-interface assertion
// fails the build here instead of skipping the helper stop.
var _ helperResetStopper = (*dpuserspace.Manager)(nil)

func TestFactoryResetStopsSweepsAndDisarmsHelper10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, true)
	fence := withBarrierRecorder(t)
	root := t.TempDir()
	stateFile := filepath.Join(root, "run", "xpf", "userspace-dp.json")
	store := handoffTestStore(t)
	commitUserspaceStateFile(t, store, stateFile)
	stub := &resetHelperDP{stateFile: stateFile}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.setDataplane(stub)
	d.dataplaneArmed.Store(true)
	if err := d.factoryReset(context.Background(), fakePendingWipe(t)); err != nil {
		t.Fatalf("factoryReset: %v", err)
	}
	if stub.stops != 1 {
		t.Fatalf("helper stops = %d, want exactly one pre-success stop", stub.stops)
	}
	if _, err := os.Lstat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("helper state survived post-stop sweep: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(stateFile)); len(entries) != 0 {
		t.Fatalf("helper temp siblings survived: %v", entries)
	}
	if d.dataplaneArmed.Load() {
		t.Fatal("dataplane must be disarmed after a successful wipe")
	}
	if got := lastBarrierCall(fence); got != "install" {
		t.Fatalf("barrier call = %q, want install", got)
	}
	assertTransitForwarding(t, v4, v6, "0", "after a successful wipe")
	if _, dirty, _, present, _ := configstore.ReadResetHandoff(); !present || dirty != "" {
		t.Fatalf("successful reset must flip the handoff clean: present=%v dirty=%q", present, dirty)
	}
}

func TestFactoryResetSkipsHelperStopOnWipeFailure10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, true)
	fence := withBarrierRecorder(t)
	stub := &resetHelperDP{}
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.setDataplane(stub)
	d.dataplaneArmed.Store(true)
	wipeErr := errors.New("wipe failed")
	if err := d.factoryReset(context.Background(), func() error { return wipeErr }); !errors.Is(err, wipeErr) {
		t.Fatalf("factoryReset error = %v, want %v", err, wipeErr)
	}
	if stub.stops != 0 {
		t.Fatal("failed wipe must not stop the helper (box stays serving)")
	}
	if !d.dataplaneArmed.Load() {
		t.Fatal("failed wipe must not disarm transit")
	}
	if got := lastBarrierCall(fence); got != "" {
		t.Fatalf("barrier call = %q, want none on wipe failure", got)
	}
	assertTransitForwarding(t, v4, v6, "1", "after a failed wipe")
}

func TestFactoryResetMarksHandoffDirtyOnSweepFailure10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := handoffTestStore(t)
	commitUserspaceStateFile(t, store, filepath.Join(blocker, "userspace-dp.json"))
	stub := &resetHelperDP{}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.setDataplane(stub)
	if err := d.factoryReset(context.Background(), func() error { return nil }); err == nil {
		t.Fatal("sweep failure must fail the reset")
	}
	if _, dirty, _, present, _ := configstore.ReadResetHandoff(); !present || dirty == "" {
		t.Fatalf("sweep failure must mark the handoff dirty: present=%v dirty=%q", present, dirty)
	}
	if stub.stops != 1 {
		t.Fatal("helper stop precedes the sweep and must still have run")
	}
}

// RED on revert: routing the reset sweep through the legacy-blind matcher
// reports success while the pre-#2957 orphan survives beside the erased
// destination.
func TestSweepHelperStateVerifiedRemovesLegacyTemps10769(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "userspace-dp.json")
	if err := os.WriteFile(dest, []byte(`{"flows":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "userspace-dp.json.4250000000.1.tmp")
	if err := os.WriteFile(legacy, []byte(`{"flows":["prior"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sweepHelperStateVerified(dest); err != nil {
		t.Fatalf("verified sweep: %v", err)
	}
	for _, path := range []string{dest, legacy} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived the verified sweep: %v", path, err)
		}
	}
}

// handoffResiduePaths is the isolated residue inventory boot-repair tests
// seed and assert on: a custom helper path, the Kea wipe set, and the
// DDNS/IPsec canonicals plus crash temps.
type handoffResiduePaths struct {
	customHelper string
	customTemp   string
	kea          []string
	ddnsLease    string
	ddnsSurface  string
	ipsec        string
	ddnsTemps    []string
	ipsecTemps   []string
}

// isolateHandoffRepairPaths redirects the Kea/DDNS/IPsec verify sets into a
// disposable tree and returns the residue inventory plus the custom helper
// path tests record in the flag.
func isolateHandoffRepairPaths(t *testing.T) (custom string, rp handoffResiduePaths) {
	t.Helper()
	isolateHandoffFlag(t)
	oldLease, oldSurfaceA, oldIPsec := resetDDNSLeaseStatePath, resetDDNSSurfaceAPath, resetIPsecStatePath
	oldKea := resetKeaLeaseCurrents
	root := t.TempDir()
	resetDDNSLeaseStatePath = filepath.Join(root, "ddns", "dhcp-ddns-state.json")
	resetDDNSSurfaceAPath = filepath.Join(root, "ddns", "interface-ddns-state.json")
	resetIPsecStatePath = filepath.Join(root, "ipsec", "ipsec-conn-state.json")
	resetKeaLeaseCurrents = []string{
		filepath.Join(root, "kea", "kea-leases4.csv"),
		filepath.Join(root, "kea", "kea-leases6.csv"),
	}
	t.Cleanup(func() {
		resetDDNSLeaseStatePath, resetDDNSSurfaceAPath, resetIPsecStatePath = oldLease, oldSurfaceA, oldIPsec
		resetKeaLeaseCurrents = oldKea
	})
	custom = filepath.Join(root, "custom", "userspace-dp.json")
	rp.customHelper = custom
	rp.customTemp = filepath.Join(root, "custom", "userspace-dp.json.4250000000.1.tmp")
	for _, current := range resetKeaLeaseCurrents {
		rp.kea = append(rp.kea, dhcpserver.KeaLeaseWipePaths(current)...)
	}
	rp.ddnsLease, rp.ddnsSurface, rp.ipsec = resetDDNSLeaseStatePath, resetDDNSSurfaceAPath, resetIPsecStatePath
	rp.ddnsTemps = []string{
		filepath.Join(root, "ddns", ".dhcp-ddns-state.json.tmp-1"),
		filepath.Join(root, "ddns", ".interface-ddns-state.json.tmp-2"),
	}
	rp.ipsecTemps = []string{filepath.Join(root, "ipsec", ".ipsec-conn-state.json.tmp-3")}
	return custom, rp
}

func writeHandoffResidue(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func seedHandoffHelper(t *testing.T, rp handoffResiduePaths) {
	t.Helper()
	writeHandoffResidue(t, rp.customHelper, `{"flows":["prior"]}`)
	writeHandoffResidue(t, rp.customTemp, `{"flows":["prior-temp"]}`)
}

func seedHandoffKea(t *testing.T, rp handoffResiduePaths) {
	t.Helper()
	for _, p := range rp.kea {
		writeHandoffResidue(t, p, "address,hwaddr\n")
	}
}

func seedHandoffTemps(t *testing.T, rp handoffResiduePaths) {
	t.Helper()
	writeHandoffResidue(t, rp.ddnsLease, `{"version":1,"records":[]}`)
	writeHandoffResidue(t, rp.ddnsSurface, `{"version":1,"records":[]}`)
	writeHandoffResidue(t, rp.ipsec, `{"loaded":[],"pending_terminate":[]}`)
	for _, p := range append(append([]string{}, rp.ddnsTemps...), rp.ipsecTemps...) {
		writeHandoffResidue(t, p, `{"orphan":true}`)
	}
}

func assertHandoffGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("residue %s survived boot repair: %v", p, err)
		}
	}
}

// RED on revert: repairing every dirty flag with a helper-only sweep at a
// re-derived path leaves Kea/temps residue and sweeps the default instead
// of the recorded custom path. Each dirty reason is crossed with a custom
// recorded path and an ERASED config (no active config: re-derivation
// yields the compiled default), and must repair its class without
// prematurely clearing.
func TestReconcileRepairsRecordedClassWithConfigErased10769(t *testing.T) {
	setup := func(t *testing.T) (store *configstore.Store, custom string, rp handoffResiduePaths) {
		t.Helper()
		custom, rp = isolateHandoffRepairPaths(t)
		// Config erased: a fresh store with no active config, so path
		// re-derivation yields the compiled default, not custom.
		return handoffTestStore(t), custom, rp
	}
	seedHelper := seedHandoffHelper
	seedKea := seedHandoffKea
	seedTemps := seedHandoffTemps
	assertGone := assertHandoffGone
	cases := []struct {
		name   string
		reason string
		seed   func(t *testing.T, rp handoffResiduePaths)
		check  func(t *testing.T, rp handoffResiduePaths)
	}{
		{"helper", configstore.ResetHandoffReasonHelper + ": helper state sweep failed: boom",
			seedHelper,
			func(t *testing.T, rp handoffResiduePaths) { assertGone(t, rp.customHelper, rp.customTemp) }},
		{"kea", configstore.ResetHandoffReasonKea + ": kea leases reappeared after re-erase: boom",
			seedKea,
			func(t *testing.T, rp handoffResiduePaths) { assertGone(t, rp.kea...) }},
		{"temps", configstore.ResetHandoffReasonTemps + ": state temps reappeared after re-erase: boom",
			seedTemps,
			func(t *testing.T, rp handoffResiduePaths) {
				assertGone(t, rp.ddnsLease, rp.ddnsSurface, rp.ipsec)
				assertGone(t, rp.ddnsTemps...)
				assertGone(t, rp.ipsecTemps...)
			}},
		{"unprefixed stop", "xpfd still active after reset stop",
			func(t *testing.T, rp handoffResiduePaths) { seedHelper(t, rp); seedKea(t, rp); seedTemps(t, rp) },
			func(t *testing.T, rp handoffResiduePaths) {
				assertGone(t, rp.customHelper, rp.customTemp)
				assertGone(t, rp.kea...)
				assertGone(t, rp.ddnsLease, rp.ddnsSurface, rp.ipsec)
				assertGone(t, rp.ddnsTemps...)
				assertGone(t, rp.ipsecTemps...)
			}},
		{"pending", configstore.ResetHandoffPending,
			func(t *testing.T, rp handoffResiduePaths) { seedHelper(t, rp); seedKea(t, rp); seedTemps(t, rp) },
			func(t *testing.T, rp handoffResiduePaths) {
				assertGone(t, rp.customHelper, rp.customTemp)
				assertGone(t, rp.kea...)
				assertGone(t, rp.ddnsLease, rp.ddnsSurface, rp.ipsec)
				assertGone(t, rp.ddnsTemps...)
				assertGone(t, rp.ipsecTemps...)
			}},
	}
	boots := []struct {
		name      string
		bootID    func(t *testing.T) string
		assertCon func(t *testing.T, custom string)
	}{
		{"post-reboot clears", func(t *testing.T) string { return "other-boot" },
			func(t *testing.T, custom string) {
				if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
					t.Fatalf("repaired post-reboot flag must be cleared: %v", err)
				}
			}},
		{"same-boot downgrades", func(t *testing.T) string {
			boot, err := configstore.CurrentBootID()
			if err != nil {
				t.Fatal(err)
			}
			return boot
		},
			func(t *testing.T, custom string) {
				_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
				if err != nil || !present || dirty != "" || gotPath != custom {
					t.Fatalf("same-boot repair must downgrade to clean with path preserved: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
				}
			}},
	}
	for _, tc := range cases {
		for _, bc := range boots {
			t.Run(tc.name+"/"+bc.name, func(t *testing.T) {
				store, custom, rp := setup(t)
				tc.seed(t, rp)
				if err := configstore.WriteResetHandoff(bc.bootID(t), tc.reason, custom); err != nil {
					t.Fatal(err)
				}
				d := &Daemon{store: store}
				d.reconcileResetHandoffAtBoot()
				tc.check(t, rp)
				bc.assertCon(t, custom)
			})
		}
	}
}

func TestHandoffFailureReasonTagsClasses(t *testing.T) {
	if got := handoffFailureReason(errors.New("boom"), nil, nil); !strings.HasPrefix(got, configstore.ResetHandoffReasonHelper+":") {
		t.Fatalf("single-class reason = %q, want helper prefix", got)
	}
	if got := handoffFailureReason(nil, errors.New("a"), errors.New("b")); strings.HasPrefix(got, configstore.ResetHandoffReasonKea+":") || !strings.Contains(got, "kea:") || !strings.Contains(got, "temps:") {
		t.Fatalf("multi-class reason = %q, want unprefixed aggregate naming both", got)
	}
}

// Unrepairable residue must keep the flag dirty and the provisioning gate
// refused — never downgrade or clear over it.
func TestReconcileKeepsDirtyWhenRepairFails10769(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions; erase would not fail")
	}
	isolateHandoffFlag(t)
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	custom := filepath.Join(t.TempDir(), "custom", "userspace-dp.json")
	if err := os.MkdirAll(filepath.Dir(custom), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte(`{"flows":["prior"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(custom), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Dir(custom), 0o755) })
	if err := configstore.WriteResetHandoff("other-boot", configstore.ResetHandoffReasonHelper+": sweep failed", custom); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: handoffTestStore(t)}
	d.reconcileResetHandoffAtBoot()
	_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
	if err != nil || !present || dirty == "" {
		t.Fatalf("failed repair must keep the flag dirty: dirty=%q present=%v err=%v", dirty, present, err)
	}
	if gotPath != custom {
		t.Fatalf("re-marked flag must preserve the recorded path, got %q", gotPath)
	}
	if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("gate over unrepaired residue = %v, want incomplete", err)
	}
	if _, err := os.Lstat(custom); err != nil {
		t.Fatalf("unrepaired residue must still be present: %v", err)
	}
}

// RED on revert: clearing a clean post-reboot flag without re-verifying
// opens N+1 provisioning over residue stranded by a crash between
// verification and the reboot (the shutdown helper's final write, a
// fence escaper). Clean + residue must repair-and-converge when
// repairable, and re-mark dirty + refuse when not.
func TestReconcileReverifiesCleanFlag10769(t *testing.T) {
	t.Run("repairable residue converges", func(t *testing.T) {
		custom, rp := isolateHandoffRepairPaths(t)
		seedHandoffHelper(t, rp)
		seedHandoffKea(t, rp)
		seedHandoffTemps(t, rp)
		if err := configstore.WriteResetHandoff("other-boot", "", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		assertHandoffGone(t, rp.customHelper, rp.customTemp)
		assertHandoffGone(t, rp.kea...)
		assertHandoffGone(t, rp.ddnsLease, rp.ddnsSurface, rp.ipsec)
		assertHandoffGone(t, rp.ddnsTemps...)
		assertHandoffGone(t, rp.ipsecTemps...)
		if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
			t.Fatalf("repaired clean flag must be cleared post-reboot: %v", err)
		}
	})
	t.Run("unrepairable residue re-marks dirty", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions; erase would not fail")
		}
		custom, rp := isolateHandoffRepairPaths(t)
		seedHandoffHelper(t, rp)
		if err := os.Chmod(filepath.Dir(custom), 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Dir(custom), 0o755) })
		if err := configstore.WriteResetHandoff("other-boot", "", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" {
			t.Fatalf("unrepaired clean flag must re-mark dirty: dirty=%q present=%v err=%v", dirty, present, err)
		}
		if gotPath != custom {
			t.Fatalf("re-marked flag must preserve the recorded path, got %q", gotPath)
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate over unrepaired residue = %v, want incomplete", err)
		}
	})
	t.Run("clean same-boot with residue repairs and stays clean", func(t *testing.T) {
		custom, rp := isolateHandoffRepairPaths(t)
		seedHandoffKea(t, rp)
		boot, err := configstore.CurrentBootID()
		if err != nil {
			t.Fatal(err)
		}
		if err := configstore.WriteResetHandoff(boot, "", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		assertHandoffGone(t, rp.kea...)
		_, dirty, _, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty != "" {
			t.Fatalf("repaired same-boot flag must stay clean: dirty=%q present=%v err=%v", dirty, present, err)
		}
	})
}

// Boot repair must see canonical-only reappearances too: empty canonicals
// converge, record-bearing ones refuse.
func TestReconcileRepairsCanonicalOnlyReappearance10769(t *testing.T) {
	t.Run("empty canonicals converge", func(t *testing.T) {
		custom, rp := isolateHandoffRepairPaths(t)
		writeHandoffResidue(t, rp.ddnsLease, `{"version":1,"records":[]}`)
		writeHandoffResidue(t, rp.ddnsSurface, `{"version":1,"records":[]}`)
		writeHandoffResidue(t, rp.ipsec, `{"loaded":[],"pending_terminate":[]}`)
		if err := configstore.WriteResetHandoff("other-boot", configstore.ResetHandoffReasonTemps+": recheck", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		assertHandoffGone(t, rp.ddnsLease, rp.ddnsSurface, rp.ipsec)
		if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
			t.Fatalf("repaired flag must be cleared post-reboot: %v", err)
		}
	})
	t.Run("record canonical refuses", func(t *testing.T) {
		custom, rp := isolateHandoffRepairPaths(t)
		writeHandoffResidue(t, rp.ddnsLease, `{"version":1,"records":[{"family":4,"identity":"mac:aa","address":"203.0.113.5","fqdn":"host.example.net","forward_type":"A","ptr_name":"5.113.0.203.in-addr.arpa","ttl":300}]}`)
		if err := configstore.WriteResetHandoff("other-boot", configstore.ResetHandoffReasonTemps+": recheck", custom); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		_, dirty, _, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" {
			t.Fatalf("record residue must keep the flag dirty: dirty=%q present=%v err=%v", dirty, present, err)
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate over record residue = %v, want incomplete", err)
		}
	})
}

func TestStartupPhasesReconcileBeforeBootstrap(t *testing.T) {
	// Source-shape pin (same mechanism as the #6739 order cell): the
	// phase list is a literal in Run, so assert the reconcile entry
	// precedes the bootstrap entry textually.
	runSrc := readSource6739(t, "daemon_run.go")
	reconcile := strings.Index(runSrc, `"reset-handoff-reconcile"`)
	bootstrap := strings.Index(runSrc, `"config-load-bootstrap"`)
	if reconcile < 0 || bootstrap < 0 {
		t.Fatalf("startup phases lack reconcile (%d) or bootstrap (%d) entries", reconcile, bootstrap)
	}
	if reconcile > bootstrap {
		t.Fatal("reset-handoff-reconcile must precede config-load-bootstrap: dirty-handoff repair runs before any bootstrap promotion can import N+1")
	}
}

// RED on revert: without the bootstrap gate, a new medium promotes N+1
// over a dirty post-reset box (the pending marker is gone; only the
// handoff flag remains).
func TestBootstrapFromFileRefusesWhileHandoffDirty10769(t *testing.T) {
	conf := "system { host-name fw; }\n"
	t.Run("dirty refuses", func(t *testing.T) {
		isolateHandoffFlag(t)
		d, hasActive := bootstrapDaemon(t, conf, -1)
		if err := configstore.WriteResetHandoff("other-boot", configstore.ResetHandoffReasonTemps+": residue", ""); err != nil {
			t.Fatal(err)
		}
		if err := d.bootstrapFromFile(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("dirty bootstrap = %v, want incomplete", err)
		}
		if hasActive() {
			t.Fatal("refused bootstrap must leave NO active config")
		}
	})
	t.Run("clean same-boot refuses", func(t *testing.T) {
		isolateHandoffFlag(t)
		d, hasActive := bootstrapDaemon(t, conf, -1)
		boot, err := configstore.CurrentBootID()
		if err != nil {
			t.Fatal(err)
		}
		if err := configstore.WriteResetHandoff(boot, "", ""); err != nil {
			t.Fatal(err)
		}
		if err := d.bootstrapFromFile(); !errors.Is(err, configstore.ErrResetHandoffRebootRequired) {
			t.Fatalf("same-boot bootstrap = %v, want reboot-required", err)
		}
		if hasActive() {
			t.Fatal("refused bootstrap must leave NO active config")
		}
	})
	t.Run("absent flag promotes", func(t *testing.T) {
		isolateHandoffFlag(t)
		d, hasActive := bootstrapDaemon(t, conf, -1)
		if err := d.bootstrapFromFile(); err != nil {
			t.Fatalf("ungated bootstrap must promote: %v", err)
		}
		if !hasActive() {
			t.Fatal("ungated bootstrap must install an active config")
		}
	})
}

// Opus5 R1 exact shape: a successful-reset handoff marked dirty, no active
// config, and an importable new-medium file. Startup through bootstrap
// cannot promote or apply N+1 until residue is verified clean and the
// gate permits; repair failure with real seeded residue keeps it closed.
func TestStartupRepairsBeforeBootstrap10769(t *testing.T) {
	newMediumDaemon := func(t *testing.T) (*Daemon, string) {
		t.Helper()
		dir := t.TempDir()
		medium := filepath.Join(dir, "xpf.conf")
		if err := os.WriteFile(medium, []byte("system { host-name n-plus-one; }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := configstore.New(filepath.Join(dir, "config.db"))
		if err != nil {
			t.Fatal(err)
		}
		return &Daemon{store: store, opts: Options{ConfigFile: medium}}, medium
	}
	t.Run("load alone refuses, reconcile then load converges", func(t *testing.T) {
		custom, rp := isolateHandoffRepairPaths(t)
		seedHandoffTemps(t, rp)
		if err := configstore.WriteResetHandoff("other-boot", configstore.ResetHandoffReasonTemps+": residue", custom); err != nil {
			t.Fatal(err)
		}
		d, _ := newMediumDaemon(t)
		if _, err := d.loadAndBootstrapConfig(); err != nil {
			t.Fatalf("load must not fail fatally on a gated bootstrap: %v", err)
		}
		if d.store.ActiveConfig() != nil {
			t.Fatal("bootstrap before repair must NOT promote N+1 over a dirty handoff")
		}
		d.reconcileResetHandoffAtBoot()
		if _, err := d.loadAndBootstrapConfig(); err != nil {
			t.Fatalf("load after repair: %v", err)
		}
		if d.store.ActiveConfig() == nil {
			t.Fatal("bootstrap after verified repair must promote N+1")
		}
	})
	t.Run("repair failure keeps the gate closed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions; erase would not fail")
		}
		custom, rp := isolateHandoffRepairPaths(t)
		seedHandoffHelper(t, rp)
		if err := os.Chmod(filepath.Dir(custom), 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Dir(custom), 0o755) })
		if err := configstore.WriteResetHandoff("other-boot", configstore.ResetHandoffReasonHelper+": residue", custom); err != nil {
			t.Fatal(err)
		}
		d, _ := newMediumDaemon(t)
		d.reconcileResetHandoffAtBoot()
		if _, err := d.loadAndBootstrapConfig(); err != nil {
			t.Fatalf("load must not fail fatally on a gated bootstrap: %v", err)
		}
		if d.store.ActiveConfig() != nil {
			t.Fatal("bootstrap must NOT promote while residue repair fails")
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate after failed repair = %v, want incomplete", err)
		}
	})
}

// RED on revert: a helper sweep that unlinks a reserved alias deletes a
// reset gate or identity file instead of helper state — but a sweep that
// skips the unlink AND reports clean lets the handoff clear with helper
// residue unproven (fail-open). The canonical must survive byte-identical
// while exact-shape temps beside it are still swept, AND the sweep must
// fail naming the reserved alias, even with temps already clean. Gate
// basenames exercise the predicate hermetically (exact literals are
// pinned in the config validator table); the skip path is shared for
// every reserved shape.
func TestSweepHelperStateVerifiedRefusesReserved10769(t *testing.T) {
	for _, base := range []string{".reset-handoff", ".day0-config-applied"} {
		t.Run(base, func(t *testing.T) {
			dir := t.TempDir()
			canonical := filepath.Join(dir, base)
			body := []byte("gate bytes must survive")
			if err := os.WriteFile(canonical, body, 0o600); err != nil {
				t.Fatal(err)
			}
			temp := canonical + ".4250000000.1.tmp"
			if err := os.WriteFile(temp, []byte(`{"orphan":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			err := sweepHelperStateVerified(canonical)
			if err == nil {
				t.Fatal("reserved-alias sweep must fail closed, got nil")
			}
			if !strings.Contains(err.Error(), "aliases reserved") || !strings.Contains(err.Error(), canonical) {
				t.Fatalf("sweep error must name the reserved alias, got %v", err)
			}
			if !strings.Contains(err.Error(), "delete /etc/xpf/.reset-handoff") || !strings.Contains(err.Error(), "restart xpfd") || !strings.Contains(err.Error(), "commit-confirmed") {
				t.Fatalf("sweep error must document the verify/delete/restart/commit-confirmed/rerun recovery, got %v", err)
			}
			if got, err := os.ReadFile(canonical); err != nil || string(got) != string(body) {
				t.Fatalf("reserved canonical must survive byte-identical: %q err=%v", got, err)
			}
			if _, err := os.Lstat(temp); !os.IsNotExist(err) {
				t.Fatalf("temps beside reserved canonical must still be swept: %v", err)
			}
		})
	}
	t.Run("clean temps still fail", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, ".reset-handoff")
		if err := os.WriteFile(canonical, []byte("gate bytes must survive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := sweepHelperStateVerified(canonical); err == nil {
			t.Fatal("reserved alias with clean temps must fail the sweep, got nil")
		} else if !strings.Contains(err.Error(), "aliases reserved") {
			t.Fatalf("sweep error must name the reserved alias, got %v", err)
		}
	})
	t.Run("missing parent still fails", func(t *testing.T) {
		dir := t.TempDir()
		parent := filepath.Join(dir, "no-such-dir")
		canonical := filepath.Join(parent, ".reset-handoff")
		if err := sweepHelperStateVerified(canonical); err == nil {
			t.Fatal("reserved alias with a missing parent must fail the sweep, got nil")
		} else if !strings.Contains(err.Error(), "aliases reserved") {
			t.Fatalf("sweep error must name the reserved alias, got %v", err)
		}
		if _, serr := os.Lstat(parent); !os.IsNotExist(serr) {
			t.Fatalf("failed sweep must create nothing: %v", serr)
		}
	})
	t.Run("missing parent non-reserved succeeds", func(t *testing.T) {
		dir := t.TempDir()
		parent := filepath.Join(dir, "no-such-dir")
		canonical := filepath.Join(parent, "userspace-dp.json")
		if err := sweepHelperStateVerified(canonical); err != nil {
			t.Fatalf("missing parent with a non-reserved path must sweep nil, got %v", err)
		}
		if _, serr := os.Lstat(parent); !os.IsNotExist(serr) {
			t.Fatalf("nil sweep must create nothing: %v", serr)
		}
	})
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-state.json")
		if err := os.WriteFile(target, []byte(`{"flows":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "state-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := sweepHelperStateVerified(link); err == nil {
			t.Fatal("symlinked helper state must fail closed")
		}
		for _, path := range []string{link, target} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("refusal must remove nothing, %s stat err=%v", path, err)
			}
		}
	})
}

// RED on revert: a boot-repair verifier that treats a reserved canonical
// as expected-present clears the handoff with helper residue unproven.
// Verification must fail naming the alias, even with temps clean.
func TestVerifyHelperStateErasedRefusesReserved10769(t *testing.T) {
	dir := t.TempDir()
	canonical := filepath.Join(dir, ".reset-handoff")
	if err := os.WriteFile(canonical, []byte("gate bytes must survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyHelperStateErased(canonical); err == nil {
		t.Fatal("reserved alias with clean temps must fail boot-repair verification, got nil")
	} else if !strings.Contains(err.Error(), "cannot be verified") || !strings.Contains(err.Error(), canonical) {
		t.Fatalf("verify error must name the unverifiable alias, got %v", err)
	}
	if got, err := os.ReadFile(canonical); err != nil || string(got) != "gate bytes must survive" {
		t.Fatalf("verification must remove nothing: %q err=%v", got, err)
	}
}

// RED on revert: reconcile over a flag recording a reserved helper path
// must keep the handoff dirty — a dirty flag stays dirty and a clean
// flag re-marks dirty — until the operator completes the manual
// recovery (verify, delete the flag, restart xpfd, author clean via
// commit-confirmed) and reruns. The reserved file itself is never
// unlinked by the repair.
func TestReconcileKeepsReservedHelperPathDirty10769(t *testing.T) {
	setup := func(t *testing.T, dirty string) (string, string) {
		t.Helper()
		isolateHandoffFlag(t)
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		dir := t.TempDir()
		canonical := filepath.Join(dir, ".reset-handoff")
		if err := os.WriteFile(canonical, []byte("gate bytes must survive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := configstore.WriteResetHandoff("other-boot", dirty, canonical); err != nil {
			t.Fatal(err)
		}
		return canonical, dir
	}
	assertStillGated := func(t *testing.T, canonical string) {
		t.Helper()
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" || gotPath != canonical {
			t.Fatalf("flag must stay dirty recording the reserved path: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		if !strings.Contains(dirty, "aliases reserved") && !strings.Contains(dirty, "cannot be verified") {
			t.Fatalf("re-marked reason must name the reserved alias failure, got %q", dirty)
		}
		if got, err := os.ReadFile(canonical); err != nil || string(got) != "gate bytes must survive" {
			t.Fatalf("repair must never unlink the reserved file: %q err=%v", got, err)
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate = %v, want incomplete", err)
		}
	}
	t.Run("dirty stays dirty", func(t *testing.T) {
		canonical, _ := setup(t, configstore.ResetHandoffReasonHelper+": residue")
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		assertStillGated(t, canonical)
	})
	t.Run("clean re-marks dirty", func(t *testing.T) {
		canonical, _ := setup(t, "")
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		assertStillGated(t, canonical)
	})
}

// RED on revert: unlinking a hardlinked helper canonical before the
// census destroys the nlink evidence, so a retry succeeds while the
// sibling retains tenant state. Both attempts must fail with the
// inode-scan error and remove nothing.
func TestSweepHelperStateVerifiedRefusesHardlinkedCanonical10769(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "userspace-dp.json")
	if err := os.WriteFile(dest, []byte(`{"flows":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "sibling.json")
	if err := os.Link(dest, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		var linkErr *configstore.FactoryResetHardlinkError
		if err := sweepHelperStateVerified(dest); !errors.As(err, &linkErr) {
			t.Fatalf("attempt %d: expected FactoryResetHardlinkError, got %v", attempt, err)
		}
		for _, path := range []string{dest, sibling} {
			if _, serr := os.Lstat(path); serr != nil {
				t.Fatalf("attempt %d: refusal must remove nothing, %s stat err=%v", attempt, path, serr)
			}
		}
	}
}

func TestEraseKeaLeasesForResetRefusesHardlinkedLease10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	lease := resetKeaLeaseCurrents[0]
	if err := os.MkdirAll(filepath.Dir(lease), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lease, []byte("address,hwaddr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(filepath.Dir(lease), "sibling.csv")
	if err := os.Link(lease, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	var linkErr *configstore.FactoryResetHardlinkError
	if err := eraseKeaLeasesForReset(); !errors.As(err, &linkErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	for _, path := range []string{lease, sibling} {
		if _, serr := os.Lstat(path); serr != nil {
			t.Fatalf("refusal must remove nothing, %s stat err=%v", path, serr)
		}
	}
}

// The Kea re-erase must refuse a symlink like the primary seal leg:
// unlinking the link would pass verification while the target rows
// survive for the next tenant's Kea.
func TestEraseKeaLeasesForResetRefusesSymlinkedLease10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	lease := resetKeaLeaseCurrents[0]
	if err := os.MkdirAll(filepath.Dir(lease), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(lease), "real-leases.csv")
	if err := os.WriteFile(target, []byte("address,hwaddr\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lease); err != nil {
		t.Fatal(err)
	}
	if err := eraseKeaLeasesForReset(); err == nil {
		t.Fatal("symlinked Kea lease must fail the re-erase, got nil")
	} else if !strings.Contains(err.Error(), "symlinked Kea lease") {
		t.Fatalf("re-erase error must name the symlinked lease, got %v", err)
	}
	for _, path := range []string{lease, target} {
		if _, serr := os.Lstat(path); serr != nil {
			t.Fatalf("refusal must remove nothing, %s stat err=%v", path, serr)
		}
	}
}

// Pathless flags come only from the concurrent-shutdown race (a
// shutdown-branch mark landing before completion records PENDING) or
// from hand-crafted/corrupt input: every normal-path writer records a
// path (the flag file is new in this PR). Boot repair must fail closed
// — never infer from the default path or the new-tenant config —
// keeping the gate shut with recovery instructions. Production ordering
// throughout (reconcile before load): the new medium carries the custom
// path the residue sits at, and neither clearing nor promotion may happen.
func TestReconcileRefusesPathlessFlag10769(t *testing.T) {
	setup := func(t *testing.T, dirty string) (*Daemon, string, handoffResiduePaths) {
		t.Helper()
		custom, rp := isolateHandoffRepairPaths(t)
		seedHandoffHelper(t, rp)
		if err := configstore.WriteResetHandoff("other-boot", dirty, ""); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		medium := filepath.Join(dir, "xpf.conf")
		conf := "system {\n    host-name n-plus-one;\n    dataplane-type userspace;\n" +
			"    dataplane {\n        state-file " + custom + ";\n    }\n}\n"
		if err := os.WriteFile(medium, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := configstore.New(filepath.Join(dir, "config.db"))
		if err != nil {
			t.Fatal(err)
		}
		return &Daemon{store: store, opts: Options{ConfigFile: medium}}, custom, rp
	}
	t.Run("dirty pathless stays shut", func(t *testing.T) {
		d, _, rp := setup(t, configstore.ResetHandoffReasonHelper+": residue")
		d.reconcileResetHandoffAtBoot()
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" || gotPath != "" {
			t.Fatalf("pathless flag must stay dirty and pathless: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		for _, p := range []string{rp.customHelper, rp.customTemp} {
			if _, serr := os.Lstat(p); serr != nil {
				t.Fatalf("unverifiable residue must not be swept or cleared over: %s stat err=%v", p, serr)
			}
		}
		if _, err := d.loadAndBootstrapConfig(); err != nil {
			t.Fatalf("load must not fail fatally on a gated bootstrap: %v", err)
		}
		if d.store.ActiveConfig() != nil {
			t.Fatal("bootstrap must NOT promote N+1 over an unverifiable handoff")
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate = %v, want incomplete", err)
		}
	})
	t.Run("clean pathless re-marks dirty", func(t *testing.T) {
		d, _, _ := setup(t, "")
		d.reconcileResetHandoffAtBoot()
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" || gotPath != "" {
			t.Fatalf("pathless clean flag must re-mark dirty: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate = %v, want incomplete", err)
		}
	})
}

// Race-transition pin (round-7 origin, round-8 wiring): the shutdown
// branch can persist a PATHLESS dirty flag when a wipe is in flight but
// has not recorded PENDING yet. Trigger chain: factoryReset marks
// resetting before the wipe, the wipe holds applySem, a concurrent
// shutdown times out its 5s apply drain (applyCloseoutDrainTimeout) and
// proceeds anyway, the isResetting gate takes the shutdown sweep branch,
// and a helper-sweep failure marks the handoff dirty while no flag
// exists yet - MarkResetHandoffDirty preserves the recorded path, which
// is empty then. The real runShutdownSequence branch (including the
// held-semaphore drain timeout) is pinned in
// TestRunShutdownSequenceMarksPathlessOnHelperFailure10769; here the
// origin runs through the sweep method (consequence pin), the
// completion runs through the REAL factoryReset pending-write /
// post-verify / flip transition after the plant is removed, and the
// manual leg verifies + removes residue before deleting the flag.
func TestShutdownRacePathlessFlagStaysGated10769(t *testing.T) {
	setup := func(t *testing.T) (*Daemon, *configstore.Store, string, string) {
		t.Helper()
		isolateHandoffFlag(t)
		isolateFactoryResetOwnershipPaths(t)
		isolateFactoryResetIdentityPaths(t)
		dir := t.TempDir()
		target := filepath.Join(dir, "real-state.json")
		if err := os.WriteFile(target, []byte(`{"flows":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "state-link.json")
		store := handoffTestStore(t)
		commitUserspaceStateFile(t, store, link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
		d.enterResetGeneration()
		if !d.isResetting() {
			t.Fatal("reset generation must be marked: the shutdown sweep branch is gated on it")
		}
		return d, store, link, target
	}
	markPathless := func(t *testing.T, d *Daemon, store *configstore.Store, link, target string) {
		t.Helper()
		// No flag present: the wipe is in flight but pre-completion.
		d.removeResetHelperStateAfterStop(store.ActiveConfig())
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" || gotPath != "" {
			t.Fatalf("shutdown-branch mark with no flag must persist pathless dirty: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		if !strings.Contains(dirty, "helper state sweep failed") {
			t.Fatalf("pathless reason must name the sweep failure, got %q", dirty)
		}
		for _, path := range []string{link, target} {
			if _, serr := os.Lstat(path); serr != nil {
				t.Fatalf("symlink refusal must remove nothing, %s stat err=%v", path, serr)
			}
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate = %v, want incomplete", err)
		}
	}
	t.Run("origin stays gated through reconcile", func(t *testing.T) {
		d, store, link, target := setup(t)
		markPathless(t, d, store, link, target)
		d.reconcileResetHandoffAtBoot()
		if _, dirty, gotPath, present, err := configstore.ReadResetHandoff(); err != nil || !present || dirty == "" || gotPath != "" {
			t.Fatalf("reconcile must never clear the pathless flag: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate after reconcile = %v, want incomplete", err)
		}
	})
	t.Run("completion converges after plant removal", func(t *testing.T) {
		d, store, link, target := setup(t)
		markPathless(t, d, store, link, target)
		// The operator removed the symlink plant; the path the reset
		// records is now plant-free. The retry's wipe performs the
		// exact write completeZeroize performs for gated completions
		// (PENDING + completion helper path), overwriting the
		// pathless-dirty mark; factoryReset's real post-verify and
		// flip observe the overwrite ordering.
		for _, path := range []string{link, target} {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove plant %s: %v", path, err)
			}
		}
		wipe := func() error {
			boot, err := configstore.CurrentBootID()
			if err != nil {
				return err
			}
			return configstore.WriteResetHandoff(boot, configstore.ResetHandoffPending, dpuserspace.StateFilePathForConfig(store.ActiveConfig()))
		}
		if err := d.factoryReset(context.Background(), wipe); err != nil {
			t.Fatalf("retry after plant removal must converge: %v", err)
		}
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty != "" || gotPath != link {
			t.Fatalf("completion must flip clean recording the retried path: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffRebootRequired) {
			t.Fatalf("gate after completion = %v, want reboot-required (clean, not dirty)", err)
		}
	})
	t.Run("manual recovery removes residue before delete", func(t *testing.T) {
		d, store, link, target := setup(t)
		markPathless(t, d, store, link, target)
		// The documented recovery (legacyHelperPathRecovery): verify
		// the residue, remove it, THEN delete the flag file. A bare
		// delete over present residue would reopen provisioning over
		// unswept state.
		for _, path := range []string{link, target} {
			if _, serr := os.Lstat(path); serr != nil {
				t.Fatalf("residue to recover must be present, %s stat err=%v", path, serr)
			}
		}
		for _, path := range []string{link, target} {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove residue %s: %v", path, err)
			}
		}
		for _, path := range []string{link, target} {
			if _, serr := os.Lstat(path); !os.IsNotExist(serr) {
				t.Fatalf("residue must be gone before flag deletion, %s stat err=%v", path, serr)
			}
		}
		if err := os.Remove(configstore.ResetHandoffPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("delete flag file: %v", err)
		}
		if err := configstore.CheckResetHandoff(); err != nil {
			t.Fatalf("gate after manual recovery = %v, want open", err)
		}
	})
}

// End-to-end proof for the SUPPORTED reserved-alias recovery (round-8,
// corrected round-9): the wipe is DESTRUCTIVE (.configdb + live config
// removed) and the failed daemon keeps serving its stale in-memory
// Store, so no commit on the still-running daemon can converge -
// in-band paths are gate-refused, and a direct store commit fails
// persistence (ENOENT: NewDB is the sole .configdb creator) or would
// resurrect the whole stale tree. The supported sequence is: verify the
// reserved file + remove temp residue, delete the flag file, RESTART
// xpfd (fresh Store/DB), author a clean non-reserved config via the
// bootstrap-supported commit-confirmed path (plain commit refuses in
// bootstrap), rerun the reset. Phases below model a real wipe and drive
// the actual startup path + rerun (no synthetic flag ops except the
// standard reboot-id simulation).
func TestReservedAliasManualRecoveryConverges10769(t *testing.T) {
	isolateHandoffFlag(t)
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	// Host-mutation isolation: the authoring apply renames the host
	// (phase 5) and the failed-reset restore touches the kernel name
	// (phase 1). Stub the kernel/disk seams so the suite cannot rename
	// the test host or rewrite /etc/hostname even as root; phase 5
	// asserts the stubs intercepted a genuine rename attempt.
	origSethostname, origHostnamePath, origOsHostname := sethostname, hostnamePath, osHostname
	t.Cleanup(func() { sethostname, hostnamePath, osHostname = origSethostname, origHostnamePath, origOsHostname })
	hostnamePath = filepath.Join(t.TempDir(), "hostname")
	kernelName := "test-host-before"
	osHostname = func() (string, error) { return kernelName, nil }
	var hostRenames []string
	sethostname = func(b []byte) error {
		hostRenames = append(hostRenames, string(b))
		kernelName = string(b)
		return nil
	}
	// Bootstrap input pin: the boot predicate branches on node-id
	// presence (present forces normal via the HA guard), so pin absent
	// for environment independence. The present shape has dedicated
	// coverage (cluster_topology_preflight_5840_test).
	origNodeID := hasNodeIDFileFn
	t.Cleanup(func() { hasNodeIDFileFn = origNodeID })
	hasNodeIDFileFn = func() bool { return false }
	hostSeams := isolateRecoveryApplyHost(t)
	root := t.TempDir()
	gateRoot := t.TempDir()
	fixedRoot := t.TempDir()
	reserved := filepath.Join(gateRoot, ".reset-handoff")
	gateBytes := []byte("gate bytes must survive")
	if err := os.WriteFile(reserved, gateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(fixedRoot, "run", "xpf", "userspace-dp.json")
	dbPath := filepath.Join(root, "xpf.conf")
	store, err := configstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Phase 0: legacy ingress. A strict commit of the reserved value
	// fails (new configs cannot create this state); the tolerant HA-sync
	// ingress keeps it with a warning (the stranded population).
	legacy := "system {\n    host-name legacy-reserved;\n    dataplane-type userspace;\n" +
		"    dataplane {\n        state-file " + reserved + ";\n    }\n}\n"
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system dataplane-type userspace\nset system dataplane state-file " + reserved + "\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err == nil {
		t.Fatal("strict commit of a reserved state-file must fail")
	} else if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("strict rejection must name the reserved alias, got %v", err)
	}
	store.ExitConfigure()
	synced, err := store.SyncApply(legacy, nil)
	if err != nil {
		t.Fatalf("tolerant ingress must keep the legacy value: %v", err)
	}
	if got := synced.System.UserspaceDataplane.StateFile; got != reserved {
		t.Fatalf("tolerated StateFile = %q, want the legacy reserved path %q", got, reserved)
	}
	if joined := strings.Join(synced.Warnings, "\n"); !strings.Contains(joined, "state-file") {
		t.Fatalf("tolerant ingress must warn about the state-file, got %q", joined)
	}
	// Phase 1: the first wipe is destructive and fails recording reserved.
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	straggler := reserved + ".4250000000.1.tmp"
	if err := os.WriteFile(straggler, []byte(`{"orphan":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	firstWipe := func() error {
		// Model production's destructive wipe: every entry under the
		// config root goes (.configdb SSOT, live config, rollback
		// slots, journal). Helper paths live outside the config root
		// in production, so they are untouched here; PENDING is
		// recorded after.
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
				return err
			}
		}
		boot, err := configstore.CurrentBootID()
		if err != nil {
			return err
		}
		return configstore.WriteResetHandoff(boot, configstore.ResetHandoffPending, dpuserspace.StateFilePathForConfig(store.ActiveConfig()))
	}
	if err := d.factoryReset(context.Background(), firstWipe); err == nil {
		t.Fatal("first wipe over a reserved alias must fail, got nil")
	} else if !strings.Contains(err.Error(), "aliases reserved") {
		t.Fatalf("wipe error must name the reserved alias, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".configdb")); !os.IsNotExist(err) {
		t.Fatalf("real wipe must remove the config DB: %v", err)
	}
	if got := store.ActiveConfig().System.UserspaceDataplane.StateFile; got != reserved {
		t.Fatalf("failed daemon keeps its stale in-memory Store, active = %q", got)
	}
	if _, dirty, gotPath, present, err := configstore.ReadResetHandoff(); err != nil || !present || dirty == "" || gotPath != reserved {
		t.Fatalf("failed wipe must leave dirty recording reserved: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
	}
	if got, err := os.ReadFile(reserved); err != nil || string(got) != string(gateBytes) {
		t.Fatalf("reserved file must survive byte-identical: %q err=%v", got, err)
	}
	if _, err := os.Lstat(straggler); !os.IsNotExist(err) {
		t.Fatalf("failed wipe must still sweep temps beside the alias: %v", err)
	}
	// Phase 2: no commit on the still-running daemon can converge. The
	// in-band fix is gate-refused; a direct store commit fails
	// persistence against the wiped DB (and would resurrect the whole
	// stale tree if it could persist).
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system dataplane state-file " + fixed + "\n"); err != nil {
		t.Fatalf("LoadSet fix: %v", err)
	}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("in-band fix while dirty = %v, want incomplete", err)
	}
	if _, err := store.Commit(); err == nil {
		t.Fatal("direct commit against the wiped DB must fail, got nil")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("direct commit must fail with the ENOENT cause (temp create in the missing .configdb), got %v", err)
	}
	if got := store.ActiveConfig().System.UserspaceDataplane.StateFile; got != reserved {
		t.Fatalf("failed fix attempts must promote nothing, active = %q", got)
	}
	store.ExitConfigure()
	// Phase 3: manual recovery - verify, remove residue, delete the flag.
	if got, err := os.ReadFile(reserved); err != nil || string(got) != string(gateBytes) {
		t.Fatalf("operator must verify correct reserved contents first: %q err=%v", got, err)
	}
	fresh := reserved + ".4250000001.1.tmp"
	if err := os.WriteFile(fresh, []byte(`{"orphan":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fresh); err != nil {
		t.Fatalf("operator removes temp residue before deleting the flag: %v", err)
	}
	if _, err := os.Lstat(fresh); !os.IsNotExist(err) {
		t.Fatalf("residue must be gone before flag deletion: %v", err)
	}
	if err := os.Remove(configstore.ResetHandoffPath); err != nil {
		t.Fatalf("delete flag file: %v", err)
	}
	if err := configstore.CheckResetHandoff(); err != nil {
		t.Fatalf("gate after manual flag deletion = %v, want open", err)
	}
	// Phase 4: restart into a fresh Store via the actual startup path.
	// NewDB recreates the wiped .configdb; Load must take the genuine
	// fresh branch (any surviving marker would fail loudly here, not
	// silently import stale state).
	freshStore, err := configstore.New(dbPath)
	if err != nil {
		t.Fatalf("restart must reconstruct the DB: %v", err)
	}
	if err := freshStore.Load(); err != nil {
		t.Fatalf("restart must load fresh (no surviving markers): %v", err)
	}
	if freshStore.ActiveConfig() != nil || freshStore.EverCommitted() {
		t.Fatal("restarted store must have no active config and no history")
	}
	// Production-shaped apply fixture (applyMarkerDaemon9175's seams):
	// the authoring commit must drive a REAL successful apply, so a
	// green run cannot mean promotion over a failed apply. The test
	// drives phase-1 startup directly while operator commits arrive
	// post-phase-3 in production, so phase-3 wiring is done by hand:
	// vrrpMgr is constructed eagerly at bringup before any apply can
	// run (daemon_run_bringup.go) — the only production nil window is
	// the phase-1-armed rollback timer firing before phase 3 (#6739),
	// which serves the rollback executor, never operator commits. A
	// bare daemon without vrrpMgr therefore cannot arise on this
	// path; removing the fixture fails with the VRRP apply error.
	installFakeNetworkctl(t)
	installSSHDSeam(t, &sshdSeamRecorder{})
	d2 := &Daemon{store: freshStore, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: dbPath, NoDataplane: true}, vrrpMgr: vrrp.NewManager()}
	d2.setDataplane(&runtimeOnlyApplyTestDP{})
	d2.reconcileDNSFn = func(*config.Config, bool) error { *hostSeams.dnsCalls++; return nil }
	failClosed, err := d2.loadAndBootstrapConfig()
	if err != nil || failClosed {
		t.Fatalf("startup path must take fresh boot, failClosed=%v err=%v", failClosed, err)
	}
	if !d2.inBootstrap() {
		t.Fatal("restarted daemon with no config must enter bootstrap mode")
	}
	// Phase 5: author the clean config via commit-confirmed (plain
	// commit refuses in bootstrap).
	if err := freshStore.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	clean := "set system host-name recovered\nset system dataplane-type userspace\nset system dataplane state-file " + fixed + "\n"
	if _, err := freshStore.LoadSet(clean); err != nil {
		t.Fatalf("LoadSet clean: %v", err)
	}
	if _, err := d2.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("plain commit in bootstrap = %v, want bootstrap-mode refusal", err)
	}
	if _, err := d2.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("commit-confirmed authoring must succeed (apply included): %v", err)
	}
	if got := freshStore.ActiveConfig().System.UserspaceDataplane.StateFile; got != fixed {
		t.Fatalf("authored StateFile = %q, want the fixed path %q", got, fixed)
	}
	if err := freshStore.ConfirmCommit(); err != nil {
		t.Fatalf("confirm the authored window: %v", err)
	}
	assertRecoveryHostIsolated(t, d2, hostSeams)
	// Host-write isolation proof. NoDataplane skips the tunable block
	// (daemon_apply_tail.go) so the apply captures no sysctl state; a
	// capture here would mean a live /proc write path ran. The
	// hostname rename genuinely attempted and was intercepted by the
	// stub (kernel name + redirected file), never the live host.
	d2.priorTunablesMu.Lock()
	tunableCaptures := d2.priorTunables != nil && (len(d2.priorTunables.neighRetrans) != 0 || len(d2.priorTunables.governors) != 0 || d2.priorTunables.budget != "" || len(d2.priorTunables.mlx5Adaptive) != 0)
	d2.priorTunablesMu.Unlock()
	if tunableCaptures {
		t.Fatal("authoring apply must capture no host tunables (no live sysctl writes even as root)")
	}
	renamed := false
	for _, name := range hostRenames {
		if name == "recovered" {
			renamed = true
		}
	}
	if !renamed {
		t.Fatalf("hostname stub must intercept the authoring rename, got %q", hostRenames)
	}
	if body, err := os.ReadFile(hostnamePath); err != nil || string(body) != "recovered\n" {
		t.Fatalf("redirected hostname file = %q err=%v, want the authored name", body, err)
	}
	// The authored config must be durable, not just in-memory: a fresh
	// handle loads it back before the rerun wipes the root again.
	durableStore, err := configstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := durableStore.Load(); err != nil {
		t.Fatalf("authored config must load back: %v", err)
	}
	if got := durableStore.ActiveConfig().System.UserspaceDataplane.StateFile; got != fixed {
		t.Fatalf("authored StateFile durable = %q, want %q", got, fixed)
	}
	// Phase 6: rerun converges clean recording the fixed path.
	if err := os.MkdirAll(filepath.Dir(fixed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`{"flows":["prior"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rerunWipe := func() error {
		// Like production, the rerun wipes the config root again
		// (including the freshly authored DB): a successful reset
		// leaves no config behind. The fixed helper residue sits
		// outside the config root, so only the post-verify sweep
		// removes it.
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
				return err
			}
		}
		boot, err := configstore.CurrentBootID()
		if err != nil {
			return err
		}
		return configstore.WriteResetHandoff(boot, configstore.ResetHandoffPending, dpuserspace.StateFilePathForConfig(freshStore.ActiveConfig()))
	}
	if err := d2.factoryReset(context.Background(), rerunWipe); err != nil {
		t.Fatalf("rerun after the fix must converge: %v", err)
	}
	if _, dirty, gotPath, present, err := configstore.ReadResetHandoff(); err != nil || !present || dirty != "" || gotPath != fixed {
		t.Fatalf("rerun must flip clean recording fixed: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
	}
	if _, err := os.Lstat(fixed); !os.IsNotExist(err) {
		t.Fatalf("rerun must sweep the recorded fixed path: %v", err)
	}
	if got, err := os.ReadFile(reserved); err != nil || string(got) != string(gateBytes) {
		t.Fatalf("reserved file must survive the rerun byte-identical: %q err=%v", got, err)
	}
	// Phase 7: reboot simulation converges the gate on a third handle.
	// The successful reset left no config: the box is fresh, awaiting
	// N+1 provisioning. Reconcile verifies the recorded fixed path is
	// clean (residue would re-mark dirty) and clears the flag.
	if err := configstore.WriteResetHandoff("other-boot", "", fixed); err != nil {
		t.Fatal(err)
	}
	thirdStore, err := configstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := thirdStore.Load(); err != nil {
		t.Fatalf("third handle must load: %v", err)
	}
	if thirdStore.ActiveConfig() != nil || thirdStore.EverCommitted() {
		t.Fatal("post-reset box must be fresh (no active, no history)")
	}
	d3 := &Daemon{store: thirdStore, applySem: semaphore.NewWeighted(1)}
	d3.reconcileResetHandoffAtBoot()
	if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
		t.Fatalf("converged flag must be cleared: %v", err)
	}
	if err := configstore.CheckResetHandoff(); err != nil {
		t.Fatalf("gate after convergence = %v, want open", err)
	}
}

// Composed ungated recovery (round-11): a REAL PerformZeroizeWipeUngated
// failure over a reserved alias (hermetic via the grpcapi test seam)
// leaves REAL pending markers with no handoff flag; restart takes
// fail-closed bootstrap; the operator authors clean via commit-confirmed;
// the REAL ungated retry clears those markers and converges. No
// synthetic marker, no synthetic wipe closure: every destructive step
// runs production code. The pure-offline direct-rerun shape (no daemon
// at all) is proven grpcapi-side.
func TestUngatedComposedRecoveryConverges10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	origNodeID := hasNodeIDFileFn
	t.Cleanup(func() { hasNodeIDFileFn = origNodeID })
	hasNodeIDFileFn = func() bool { return false }
	origSethostname, origHostnamePath, origOsHostname := sethostname, hostnamePath, osHostname
	t.Cleanup(func() { sethostname, hostnamePath, osHostname = origSethostname, origHostnamePath, origOsHostname })
	hostnamePath = filepath.Join(t.TempDir(), "hostname")
	kernelName := "test-host-before"
	osHostname = func() (string, error) { return kernelName, nil }
	var hostRenames []string
	sethostname = func(b []byte) error {
		hostRenames = append(hostRenames, string(b))
		kernelName = string(b)
		return nil
	}
	hostSeams := isolateRecoveryApplyHost(t)
	root := t.TempDir()
	restoreWipe := grpcapi.RedirectZeroizeWipePathsForTesting(root)
	t.Cleanup(restoreWipe)
	configDir := filepath.Join(root, "etc-xpf")
	if err := os.MkdirAll(filepath.Join(configDir, ".configdb"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".configdb", "master.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(configDir, "xpf.conf")
	reserved := filepath.Join(root, "gates", ".reset-handoff")
	gateBytes := []byte("gate bytes must survive")
	if err := os.MkdirAll(filepath.Dir(reserved), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reserved, gateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reserved+".4250000000.1.tmp", []byte(`{"orphan":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Phase 1: the REAL ungated wipe fails on the reserved alias.
	err := grpcapi.PerformZeroizeWipeUngated(configDir, "xpf.conf", "", grpcapi.ZeroizeLogInventory{}, reserved)
	if err == nil {
		t.Fatal("ungated wipe over a reserved alias must fail, got nil")
	}
	if !strings.Contains(err.Error(), "aliases reserved") {
		t.Fatalf("wipe error must name the reserved alias, got %v", err)
	}
	if !strings.Contains(err.Error(), "pending markers") || !strings.Contains(err.Error(), "no handoff flag") {
		t.Fatalf("wipe error must give the ungated markers/no-flag guidance, got %v", err)
	}
	// The surviving marker is a VALID production record: prefix plus a
	// JSON body whose fields match the wiped root (the private retry
	// reader gates on exactly this shape; grpcapi pins the reader).
	markerData, err := os.ReadFile(configstore.FactoryResetPendingPath)
	if err != nil || !strings.HasPrefix(string(markerData), configstore.FactoryResetPendingPrefix) {
		t.Fatalf("loader pending marker must survive the failed wipe: %q err=%v", markerData, err)
	}
	var record struct {
		Version      int                         `json:"version"`
		ConfigDir    string                      `json:"config_dir"`
		ConfigBase   string                      `json:"config_base"`
		ArchiveDir   string                      `json:"archive_dir"`
		LogInventory grpcapi.ZeroizeLogInventory `json:"log_inventory"`
	}
	body := strings.TrimPrefix(string(markerData), configstore.FactoryResetPendingPrefix)
	if err := json.Unmarshal([]byte(body), &record); err != nil {
		t.Fatalf("pending marker body must be a valid record: %v", err)
	}
	if record.Version != 1 || filepath.Clean(record.ConfigDir) != configDir || record.ConfigBase != "xpf.conf" {
		t.Fatalf("pending record fields = %+v, want Version 1 matching the wiped root", record)
	}
	if record.ArchiveDir != "" || !reflect.DeepEqual(record.LogInventory, grpcapi.ZeroizeLogInventory{}) {
		t.Fatalf("pending record must carry the empty archive/inventory of this fixture: %+v", record)
	}
	if _, _, _, present, err := configstore.ReadResetHandoff(); err != nil || present {
		t.Fatalf("failed ungated wipe must write no handoff flag: present=%v err=%v", present, err)
	}
	for _, path := range []string{filepath.Join(configDir, "xpf.conf"), filepath.Join(configDir, ".configdb")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed wipe must still erase config %s: %v", path, err)
		}
	}
	if got, err := os.ReadFile(reserved); err != nil || string(got) != string(gateBytes) {
		t.Fatalf("reserved file must survive byte-identical: %q err=%v", got, err)
	}
	if _, err := os.Lstat(reserved + ".4250000000.1.tmp"); !os.IsNotExist(err) {
		t.Fatalf("failed wipe must still sweep temps beside the alias: %v", err)
	}
	// Phase 2: restart refuses on the surviving markers and takes
	// fail-closed bootstrap (distinct from the fresh-boot shape).
	freshStore, err := configstore.New(dbPath)
	if err != nil {
		t.Fatalf("restart must reconstruct the DB: %v", err)
	}
	if err := freshStore.Load(); !errors.Is(err, configstore.ErrFactoryResetPending) {
		t.Fatalf("Load with surviving markers = %v, want the pending refusal", err)
	} else if !errors.Is(err, configstore.ErrConfigAbsentWithHistory) {
		t.Fatalf("pending refusal must classify absent-with-history, got %v", err)
	}
	installFakeNetworkctl(t)
	installSSHDSeam(t, &sshdSeamRecorder{})
	d := &Daemon{store: freshStore, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: dbPath, NoDataplane: true}, vrrpMgr: vrrp.NewManager()}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	d.reconcileDNSFn = func(*config.Config, bool) error { *hostSeams.dnsCalls++; return nil }
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || !failClosed {
		t.Fatalf("startup path must take fail-closed bootstrap, failClosed=%v err=%v", failClosed, err)
	}
	if !d.inBootstrap() {
		t.Fatal("restart with surviving markers must enter bootstrap mode")
	}
	// Phase 3: author the clean config via commit-confirmed (plain
	// refuses in bootstrap).
	fixed := filepath.Join(root, "custom", "userspace-dp.json")
	if err := freshStore.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	clean := "set system host-name recovered\nset system dataplane-type userspace\nset system dataplane state-file " + fixed + "\n"
	if _, err := freshStore.LoadSet(clean); err != nil {
		t.Fatalf("LoadSet clean: %v", err)
	}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("plain commit in bootstrap = %v, want bootstrap-mode refusal", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("commit-confirmed authoring must succeed (apply included): %v", err)
	}
	if got := freshStore.ActiveConfig().System.UserspaceDataplane.StateFile; got != fixed {
		t.Fatalf("authored StateFile = %q, want the fixed path %q", got, fixed)
	}
	if err := freshStore.ConfirmCommit(); err != nil {
		t.Fatalf("confirm the authored window: %v", err)
	}
	assertRecoveryHostIsolated(t, d, hostSeams)
	renamed := false
	for _, name := range hostRenames {
		if name == "recovered" {
			renamed = true
		}
	}
	if !renamed {
		t.Fatalf("hostname stub must intercept the authoring rename, got %q", hostRenames)
	}
	if body, err := os.ReadFile(hostnamePath); err != nil || string(body) != "recovered\n" {
		t.Fatalf("redirected hostname file = %q err=%v, want the authored name", body, err)
	}
	// Phase 4: the REAL ungated retry clears those markers and flips
	// clean. Production resolves the compiled default (pinned
	// non-reserved grpcapi-side); the test uses the hermetic
	// equivalent since the destructive mechanics are
	// path-independent and the live default is forbidden.
	if err := os.MkdirAll(filepath.Dir(fixed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`{"flows":["prior"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := grpcapi.PerformZeroizeWipeUngated(configDir, "xpf.conf", "", grpcapi.ZeroizeLogInventory{}, fixed); err != nil {
		t.Fatalf("real retry must converge: %v", err)
	}
	if _, err := os.Lstat(configstore.FactoryResetPendingPath); !os.IsNotExist(err) {
		t.Fatalf("converged retry must clear the loader marker: %v", err)
	}
	_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
	if err != nil || !present || dirty != "" || gotPath != fixed {
		t.Fatalf("retry must flip clean recording the retried path: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
	}
	if _, err := os.Lstat(fixed); !os.IsNotExist(err) {
		t.Fatalf("retry must sweep the recorded helper path: %v", err)
	}
	if got, err := os.ReadFile(reserved); err != nil || string(got) != string(gateBytes) {
		t.Fatalf("reserved file must survive the retry byte-identical: %q err=%v", got, err)
	}
	// Phase 5: reboot simulation converges the gate on a fresh handle
	// over the wiped root: no config, no markers, no flag.
	if err := configstore.WriteResetHandoff("other-boot", "", fixed); err != nil {
		t.Fatal(err)
	}
	thirdStore, err := configstore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := thirdStore.Load(); err != nil {
		t.Fatalf("third handle must load fresh: %v", err)
	}
	if thirdStore.ActiveConfig() != nil || thirdStore.EverCommitted() {
		t.Fatal("post-reset box must be fresh (no active, no history)")
	}
	d3 := &Daemon{store: thirdStore, applySem: semaphore.NewWeighted(1)}
	d3.reconcileResetHandoffAtBoot()
	if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
		t.Fatalf("converged flag must be cleared: %v", err)
	}
	if err := configstore.CheckResetHandoff(); err != nil {
		t.Fatalf("gate after convergence = %v, want open", err)
	}
}
