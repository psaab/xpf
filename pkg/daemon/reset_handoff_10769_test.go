package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

func isolateHandoffFlag(t *testing.T) {
	t.Helper()
	orig := configstore.ResetHandoffPath
	configstore.ResetHandoffPath = filepath.Join(t.TempDir(), ".reset-handoff")
	t.Cleanup(func() { configstore.ResetHandoffPath = orig })
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
		if err := configstore.WriteResetHandoff("other-boot", "", ""); err != nil {
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
		if err := configstore.WriteResetHandoff(boot, "", ""); err != nil {
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
		if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed", ""); err != nil {
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
		if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed", ""); err != nil {
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
