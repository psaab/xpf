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
			if !strings.Contains(err.Error(), "rerun the reset") {
				t.Fatalf("sweep error must document the fix-and-rerun recovery, got %v", err)
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
// flag re-marks dirty — until the operator fixes state-file and reruns.
// The reserved file itself is never unlinked by the repair.
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

// Race-transition pin (round-7): the shutdown branch can persist a
// PATHLESS dirty flag when a wipe is in flight but has not recorded
// PENDING yet. Trigger chain: factoryReset marks resetting before the
// wipe, the wipe holds applySem, a concurrent shutdown times out its 5s
// apply drain (applyCloseoutDrainTimeout) and proceeds anyway, the
// isResetting gate takes the shutdown sweep branch, and a helper-sweep
// failure marks the handoff dirty while no flag exists yet -
// MarkResetHandoffDirty preserves the recorded path, which is empty
// then. The drain timeout is a const (no seam for a real 5s hold), so
// this pins the production consequence instead: the shutdown-branch
// mark with an absent flag through the real functions, then the
// fail-closed aftermath (gated, reconcile never clears, manual
// recovery only) and the competing-overwrite convergence (a later
// PENDING completion overwrites pathless-dirty with pending+path,
// still gated).
func TestShutdownRacePathlessFlagStaysGated10769(t *testing.T) {
	isolateHandoffFlag(t)
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
	d.reconcileResetHandoffAtBoot()
	if _, dirty, gotPath, present, err := configstore.ReadResetHandoff(); err != nil || !present || dirty == "" || gotPath != "" {
		t.Fatalf("reconcile must never clear the pathless flag: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
	}
	if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("gate after reconcile = %v, want incomplete", err)
	}
	// Documented manual recovery is the only way out.
	if err := configstore.ClearResetHandoff(); err != nil {
		t.Fatal(err)
	}
	if err := configstore.CheckResetHandoff(); err != nil {
		t.Fatalf("gate after manual flag deletion = %v, want open", err)
	}
	// Competing overwrite converges fail-closed: a completion landing
	// after the shutdown mark replaces pathless-dirty with pending+path.
	boot, err := configstore.CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(dir, "userspace-dp.json")
	if err := configstore.WriteResetHandoff(boot, "helper state sweep failed", ""); err != nil {
		t.Fatal(err)
	}
	if err := configstore.WriteResetHandoff(boot, configstore.ResetHandoffPending, helperPath); err != nil {
		t.Fatal(err)
	}
	_, dirty, gotPath, present, err = configstore.ReadResetHandoff()
	if err != nil || !present || dirty != configstore.ResetHandoffPending || gotPath != helperPath {
		t.Fatalf("completion must overwrite with pending+path: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
	}
	if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("gate after overwrite = %v, want incomplete", err)
	}
}
