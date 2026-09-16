package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #5309: teardownUnmappedManaged was VOID and deleted the durable
// 10-xpf-<name>.link marker AND the matching .network "regardless of the rename
// outcome"; a rename-back failure only slog.Warn'd, a standalone networkctl
// reload failure only warned, and the caller (daemon_apply) invoked it with no
// result check. Scenario: an operator removes a mapped data NIC, the rename-back
// FAILS (EBUSY/collision) -> the teardown warned, DELETED both durable files,
// and the commit returned SUCCESS while the live interface kept the wrong name
// (stale host routing ownership) AND the retry debt was destroyed (the durable
// markers — the only record that the next commit must retry — were gone).
//
// The fix makes teardownUnmappedManaged RETURN an aggregated error, RETAIN the
// durable markers on a genuine failure, and thread the error into networkdErr so
// the commit fails closed (mirroring the #4956 startup aggregation, the #4901
// retain-on-failed-delete, and the #5310/#5354 swallowed-apply-error fixes).

// unmappedTeardownConfig builds a leave-alone device-map whose ONLY mapped
// logical name is ge-0/0/3 (LinuxIfName ge-0-0-3), so any on-disk .link for a
// DIFFERENT name (e.g. ge-0-0-9) is an unmapped previously-managed NIC the
// teardown must reconcile.
func unmappedTeardownConfig() *config.DeviceMapConfig {
	return &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyLeaveAlone,
	}
}

// seedUnmappedMarkers writes BOTH durable markers (10-xpf-<name>.link and
// 10-xpf-<name>.network) for an unmapped name, returning their paths.
func seedUnmappedMarkers(t *testing.T, dir, name string) (linkPath, netPath string) {
	t.Helper()
	if wrote, err := writeLinkFile(name, "enp99s0"); err != nil || !wrote {
		t.Fatalf("seed: writeLinkFile(%q) = (%v, %v), want (true, nil)", name, wrote, err)
	}
	linkPath = filepath.Join(dir, linkPrefix+name+".link")
	netPath = filepath.Join(dir, linkPrefix+name+".network")
	if err := os.WriteFile(netPath, []byte("[Match]\nName="+name+"\n"), 0o644); err != nil {
		t.Fatalf("seed .network: %v", err)
	}
	return linkPath, netPath
}

// stubTeardownSeams points the teardown's injectable seams at test doubles:
//   - teardownRestoreTargetFn reports a LIVE device (live=true) wearing every
//     unmapped xpf name, resolving to predictable name `predictable`;
//   - renameInterfaceFn returns renameErr;
//   - networkctlReloadFn returns reloadErr.
//
// It restores all three on cleanup and returns call counters.
func stubTeardownSeams(t *testing.T, live bool, predictable string, renameErr, reloadErr error) (renameCalls, reloadCalls *int) {
	t.Helper()

	savedRestore := teardownRestoreTargetFn
	teardownRestoreTargetFn = func(target string) (string, bool) {
		return predictable, live
	}
	t.Cleanup(func() { teardownRestoreTargetFn = savedRestore })

	var rc, lc int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		rc++
		return renameErr
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error {
		lc++
		return reloadErr
	}
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	return &rc, &lc
}

// TestTeardownUnmappedManaged_RenameBackFailureRetainsAndErrors_5309 is the
// #5309 fail-on-revert. A rename-back failure (EBUSY/collision) on a live device
// still wearing an xpf name must (a) RETURN an error and (b) RETAIN both durable
// markers so the retry debt survives to the next commit.
//
// FAIL-ON-REVERT: restore the pre-fix body (void signature + delete both files
// "regardless of the rename outcome" + warn-only) and this test goes RED on BOTH
// counts — the returned error disappears (void) and the .link/.network markers
// are gone (deleted regardless), destroying the retry debt.
func TestTeardownUnmappedManaged_RenameBackFailureRetainsAndErrors_5309(t *testing.T) {
	dir := withTempLinkDir(t)
	linkPath, netPath := seedUnmappedMarkers(t, dir, "ge-0-0-9")

	ebusy := errors.New("simulated rename-back EBUSY/collision")
	renameCalls, _ := stubTeardownSeams(t, true, "enp99s0", ebusy, nil)

	err := teardownUnmappedManaged(unmappedTeardownConfig(), nil)
	if err == nil {
		t.Fatal("teardownUnmappedManaged must return an error when the rename-back " +
			"fails (fail-closed); got nil — the void warn-only #5309 describes")
	}
	if !errors.Is(err, ebusy) {
		t.Fatalf("returned error must wrap the injected rename-back failure, got %v", err)
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename-back attempt for the unmapped live NIC")
	}
	// Both durable markers MUST be retained so the next commit can retry.
	if _, statErr := os.Stat(linkPath); statErr != nil {
		t.Fatalf("rename-back failed but the durable .link was deleted (retry debt "+
			"destroyed): %v", statErr)
	}
	if _, statErr := os.Stat(netPath); statErr != nil {
		t.Fatalf("rename-back failed but the durable .network was deleted (retry debt "+
			"destroyed): %v", statErr)
	}
}

// TestTeardownUnmappedManaged_RenameBackSuccessDeletesMarkers_5309 proves the
// fix does NOT over-retain: when the rename-back SUCCEEDS, both durable markers
// are reclaimed and no error is returned (normal convergence — no regression of
// the original teardown intent).
func TestTeardownUnmappedManaged_RenameBackSuccessDeletesMarkers_5309(t *testing.T) {
	dir := withTempLinkDir(t)
	linkPath, netPath := seedUnmappedMarkers(t, dir, "ge-0-0-9")

	renameCalls, reloadCalls := stubTeardownSeams(t, true, "enp99s0", nil, nil)

	if err := teardownUnmappedManaged(unmappedTeardownConfig(), nil); err != nil {
		t.Fatalf("teardownUnmappedManaged must succeed when the rename-back succeeds: %v", err)
	}
	if *renameCalls == 0 {
		t.Fatal("expected a rename-back attempt for the unmapped live NIC")
	}
	if *reloadCalls == 0 {
		t.Fatal("a successful teardown that changed files must networkctl reload")
	}
	if _, statErr := os.Stat(linkPath); !os.IsNotExist(statErr) {
		t.Fatalf("rename-back succeeded but the stale .link was not reclaimed: %v", statErr)
	}
	if _, statErr := os.Stat(netPath); !os.IsNotExist(statErr) {
		t.Fatalf("rename-back succeeded but the stale .network was not reclaimed: %v", statErr)
	}
}

// TestTeardownUnmappedManaged_ReloadFailureRetainsAndErrors_5309 covers the
// standalone networkctl-reload failure: the rename-back succeeded (markers
// reclaimed) but activating the change fails. That must surface as an error
// (fail-closed) rather than the pre-fix warn-and-swallow.
func TestTeardownUnmappedManaged_ReloadFailureRetainsAndErrors_5309(t *testing.T) {
	withTempLinkDir(t)
	seedUnmappedMarkers(t, linkDir, "ge-0-0-9")

	reloadFail := errors.New("simulated networkctl reload failure")
	_, reloadCalls := stubTeardownSeams(t, true, "enp99s0", nil, reloadFail)

	err := teardownUnmappedManaged(unmappedTeardownConfig(), nil)
	if err == nil {
		t.Fatal("teardownUnmappedManaged must return an error when networkctl reload " +
			"fails (fail-closed); got nil")
	}
	if !errors.Is(err, reloadFail) {
		t.Fatalf("returned error must wrap the reload failure, got %v", err)
	}
	if *reloadCalls == 0 {
		t.Fatal("expected a networkctl reload attempt after a file change")
	}
}

// TestTeardownUnmappedManaged_IdempotentAlreadyTornDown_5309 proves idempotency:
// a NIC that was already renamed back (no live device wears the xpf name) is a
// no-op success — the leftover marker is reclaimed and NO error is returned, and
// a benign reload is NOT a spurious failure. Only a GENUINE rename-back / reload
// failure retains + errors.
func TestTeardownUnmappedManaged_IdempotentAlreadyTornDown_5309(t *testing.T) {
	dir := withTempLinkDir(t)
	linkPath, _ := seedUnmappedMarkers(t, dir, "ge-0-0-9")

	// live=false: teardownRestoreTargetFn reports no live device wears the xpf
	// name (already renamed back by a prior run). renameInterfaceFn must NOT be
	// called; the leftover marker is reclaimed; the teardown returns nil.
	renameCalls, _ := stubTeardownSeams(t, false, "", nil, nil)

	if err := teardownUnmappedManaged(unmappedTeardownConfig(), nil); err != nil {
		t.Fatalf("an already-torn-down NIC must be an idempotent no-op success, got %v", err)
	}
	if *renameCalls != 0 {
		t.Fatalf("no live device wears the xpf name — no rename-back must be attempted, got %d", *renameCalls)
	}
	if _, statErr := os.Stat(linkPath); !os.IsNotExist(statErr) {
		t.Fatalf("idempotent teardown must reclaim the orphaned .link, still present: %v", statErr)
	}
}

// TestTeardownUnmappedManaged_PureNoOpNoReload_5309 proves the zero-churn
// contract (operator priority #1): when every on-disk .link is still a desired
// binding, the teardown touches nothing, never calls networkctl reload, and
// returns nil (a benign no-op is never a spurious fail-closed error).
func TestTeardownUnmappedManaged_PureNoOpNoReload_5309(t *testing.T) {
	dir := withTempLinkDir(t)
	_, _ = writeLinkFile("ge-0-0-3", "enp9s0") // still mapped (desired)

	_, reloadCalls := stubTeardownSeams(t, true, "enp99s0", nil, nil)

	if err := teardownUnmappedManaged(unmappedTeardownConfig(), nil); err != nil {
		t.Fatalf("no-op teardown (all names desired) must return nil, got %v", err)
	}
	if *reloadCalls != 0 {
		t.Fatalf("no file changed — networkctl reload must not be called, got %d", *reloadCalls)
	}
	if _, statErr := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-3.link")); statErr != nil {
		t.Fatalf("no-op teardown removed a still-mapped .link: %v", statErr)
	}
}

// TestApplyTailReconcilesSurfacesDeviceMapTeardownError_5309 is the commit-level
// wiring proof. The device-map teardown failure is folded into networkdErr at
// its call site in applyDataplaneAndHACore, and networkdErr is the FIRST operand
// of the tail commit-error join in applyTailReconciles. This drives the REAL
// applyTailReconciles with a teardown-shaped error in the networkdErr slot and
// asserts the returned commit error includes it — pinning that a device-map
// teardown failure fails the commit CLOSED (mirrors #5310's
// TestApplyTailReconcilesSurfacesInterfaceReconcileError). The nft seams are
// stubbed to succeed so the injected networkdErr is the only operand that can
// surface.
//
// FAIL-ON-REVERT: drop networkdErr from the tail errors.Join and this goes RED —
// the commit would report nil despite the teardown having failed (the swallowed
// fail-open #5309/#5310 describe).
func TestApplyTailReconcilesSurfacesDeviceMapTeardownError_5309(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	teardownErr := fmt.Errorf("device-map teardown: %w",
		errors.New("rename-back ge-0-0-9 -> enp99s0: EBUSY"))
	err := d.applyTailReconciles(cfg, teardownErr, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("applyTailReconciles must surface a device-map teardown failure carried " +
			"in networkdErr (fail-closed); got nil")
	}
	if !errors.Is(err, teardownErr) {
		t.Fatalf("returned commit error must include the teardown failure via the tail "+
			"errors.Join wiring, got %v", err)
	}
}
