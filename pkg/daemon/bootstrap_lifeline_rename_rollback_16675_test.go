package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #16675: bootstrap exit renames a non-index-0 foreign-host lifeline
// positionally (enp6s0 -> ge-0-0-0), and the first-commit rollback kept
// both the rename and its 10-xpf-ge-0-0-0.link, so the host's own
// kernel-name-keyed config ([Match] Name=enp6s0) never matched again —
// console-only lockout persisting across reboots, reported as a clean
// rollback. These cells pin the fix: the exit captures the pre-takeover
// (kernel, logical) pair, and the first-commit teardown removes the
// takeover .link and renames back.
//
// Production resolveLifelineCurrentName reads /sys/class/net, so the
// cells drive the resolveLifelineCurrentNameFn seam with a fake fabric:
// the "live name" is a mutable string the fake rename moves, exactly
// like the kernel does.

// lifelineRenameFabric16675 models the lifeline NIC's live name.
type lifelineRenameFabric16675 struct {
	live      string
	renames   [][2]string
	renameErr error
}

func stubLifelineRename16675(t *testing.T, live string) *lifelineRenameFabric16675 {
	t.Helper()
	fab := &lifelineRenameFabric16675{live: live}
	oldResolve := resolveLifelineCurrentNameFn
	resolveLifelineCurrentNameFn = func() (string, bool) {
		if fab.live == "" {
			return "", false
		}
		return fab.live, true
	}
	oldRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		if fab.renameErr != nil {
			return fab.renameErr
		}
		if fab.live != from {
			return errors.New("ENODEV: " + from)
		}
		fab.renames = append(fab.renames, [2]string{from, to})
		fab.live = to
		return nil
	}
	t.Cleanup(func() {
		resolveLifelineCurrentNameFn = oldResolve
		renameInterfaceFn = oldRename
	})
	return fab
}

func writeTakeoverLink16675(t *testing.T, dir, logical, original string) {
	t.Helper()
	content := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=" + original + "\n\n[Link]\nName=" + logical + "\n"
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+logical+".link"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// The abandoned config's .network for the renamed NIC: teardown
	// already removes these pre-fix; the witness is the .link + rename.
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+logical+".network"),
		[]byte("[Match]\nName="+logical+"\n\n[Network]\nAddress=198.51.100.2/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestBootstrapRollbackRestoresNonFxp0LifelineRename16675 is the witness
// flip: pre-fix the rollback kept 10-xpf-ge-0-0-0.link and issued no
// rename; post-fix the .link is gone and ge-0-0-0 -> enp6s0 was issued.
// The index-0 fxp0 lifeline .network restore rides along unchanged.
func TestBootstrapRollbackRestoresNonFxp0LifelineRename16675(t *testing.T) {
	dir := withTempLinkDir(t)
	installFakeNetworkctl(t)
	fab := stubLifelineRename16675(t, "ge-0-0-0")
	writeTakeoverLink16675(t, dir, "ge-0-0-0", "enp6s0")

	// Index-0 fxp0 lifeline fixture (the control that must stay green):
	// a captured snapshot the rollback restores byte-for-byte.
	lifeline := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
	fxp0Path := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.WriteFile(fxp0Path, []byte("[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		bootstrapLifelineCaptured:    true,
		bootstrapLifelinePresent:     true,
		bootstrapLifelineNetwork:     lifeline,
		bootstrapLifelineKernelName:  "enp6s0",
		bootstrapLifelineLogicalName: "ge-0-0-0",
	}
	steps := d.runBootstrapTeardownSteps(true)
	if err, degraded := summarizeBootstrapTeardown(steps); degraded {
		t.Fatalf("rollback must report clean, got degraded err=%v steps=%+v", err, steps)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
		t.Fatalf("rollback kept the takeover .link (the #16675 lockout); stat err=%v", err)
	}
	if len(fab.renames) != 1 || fab.renames[0] != [2]string{"ge-0-0-0", "enp6s0"} {
		t.Fatalf("rollback renames = %v, want exactly [ge-0-0-0 -> enp6s0]", fab.renames)
	}
	if fab.live != "enp6s0" {
		t.Fatalf("lifeline live name = %q, want enp6s0 (host config matches again)", fab.live)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.network")); !os.IsNotExist(err) {
		t.Fatalf("rollback kept the takeover .network; stat err=%v", err)
	}
	got, err := os.ReadFile(fxp0Path)
	if err != nil || string(got) != string(lifeline) {
		t.Fatalf("index-0 fxp0 lifeline restore regressed: got %q err=%v", got, err)
	}
}

// TestBootstrapRollbackRenameFailureRetainsLink16675 pins the ordering:
// a failed rename-back retains BOTH the .link and the live name and
// reports DEGRADED — never file-first-then-fail (that is the lockout
// minus the evidence).
func TestBootstrapRollbackRenameFailureRetainsLink16675(t *testing.T) {
	dir := withTempLinkDir(t)
	installFakeNetworkctl(t)
	fab := stubLifelineRename16675(t, "ge-0-0-0")
	fab.renameErr = errors.New("simulated EBUSY")
	writeTakeoverLink16675(t, dir, "ge-0-0-0", "enp6s0")

	d := &Daemon{
		bootstrapLifelineKernelName:  "enp6s0",
		bootstrapLifelineLogicalName: "ge-0-0-0",
	}
	steps := d.runBootstrapTeardownSteps(true)
	err, degraded := summarizeBootstrapTeardown(steps)
	// The fxp0 restore also fails here (no captured snapshot), so assert
	// on the rename step specifically.
	found := false
	for _, s := range steps {
		if s.name == "restore lifeline kernel name" && s.err != nil {
			found = true
		}
	}
	if !degraded || !found {
		t.Fatalf("rename-back failure must surface as a DEGRADED rename step, got err=%v steps=%+v", err, steps)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); err != nil {
		t.Fatalf("failed rename-back deleted the takeover .link (retry debt destroyed): %v", err)
	}
	if fab.live != "ge-0-0-0" {
		t.Fatalf("failed rename-back moved the live name to %q", fab.live)
	}
}

// TestBootstrapRollbackLinkMismatchRetains16675: a takeover .link whose
// OriginalName disagrees with the captured kernel name is not the rename
// we recorded — retain file + name, report DEGRADED, rename nothing.
func TestBootstrapRollbackLinkMismatchRetains16675(t *testing.T) {
	dir := withTempLinkDir(t)
	installFakeNetworkctl(t)
	fab := stubLifelineRename16675(t, "ge-0-0-0")
	writeTakeoverLink16675(t, dir, "ge-0-0-0", "enp9s0") // not the captured enp6s0

	d := &Daemon{
		bootstrapLifelineKernelName:  "enp6s0",
		bootstrapLifelineLogicalName: "ge-0-0-0",
	}
	steps := d.runBootstrapTeardownSteps(true)
	found := false
	for _, s := range steps {
		if s.name == "restore lifeline kernel name" && s.err != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("mismatched .link must fail the rename step, steps=%+v", steps)
	}
	if len(fab.renames) != 0 {
		t.Fatalf("mismatched .link must not be renamed, got %v", fab.renames)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); err != nil {
		t.Fatalf("mismatched .link must be retained: %v", err)
	}
}

// TestBootstrapRollbackUnprovenancedLinkFailsClosed16675: a lifeline
// wearing a logical name claimed by a .link, with NO captured pair, must
// not silently keep the rename — the rollback reports it instead of
// logging success over a stranded management NIC.
func TestBootstrapRollbackUnprovenancedLinkFailsClosed16675(t *testing.T) {
	dir := withTempLinkDir(t)
	installFakeNetworkctl(t)
	fab := stubLifelineRename16675(t, "ge-0-0-0")
	writeTakeoverLink16675(t, dir, "ge-0-0-0", "enp6s0")

	d := &Daemon{} // no captured pair, no snapshot
	steps := d.runBootstrapTeardownSteps(true)
	found := false
	for _, s := range steps {
		if s.name == "restore lifeline kernel name" && s.err != nil &&
			strings.Contains(s.err.Error(), "no captured pre-takeover rename provenance") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unprovenanced lifeline .link must fail closed, steps=%+v", steps)
	}
	if len(fab.renames) != 0 {
		t.Fatalf("unprovenanced shape must not guess a rename, got %v", fab.renames)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); err != nil {
		t.Fatalf("unprovenanced .link must be retained: %v", err)
	}
}

// TestCaptureBootstrapLifelineRenamePreExit16675 pins the capture: a
// non-index-0 lifeline in positional mode records (kernel, logical);
// index-0, device-map, and already-logical shapes record nothing.
func TestCaptureBootstrapLifelineRenamePreExit16675(t *testing.T) {
	tests := []struct {
		name        string
		live        string
		nics        []pciNIC
		deviceMap   bool
		wantKernel  string
		wantLogical string
	}{
		{
			name:       "non-index-0 positional",
			live:       "enp6s0",
			nics:       []pciNIC{{name: "enp5s0"}, {name: "enp6s0"}},
			wantKernel: "enp6s0", wantLogical: "ge-0-0-0",
		},
		{
			name: "index-0 is fxp0-covered",
			live: "enp5s0",
			nics: []pciNIC{{name: "enp5s0"}, {name: "enp6s0"}},
		},
		{
			name:      "device-map never claims the lifeline",
			live:      "enp6s0",
			nics:      []pciNIC{{name: "enp5s0"}, {name: "enp6s0"}},
			deviceMap: true,
		},
		{
			name: "already logical",
			live: "ge-0-0-0",
			nics: []pciNIC{{name: "enp5s0"}, {name: "ge-0-0-0"}},
		},
		{
			name: "not enumerated",
			live: "enp6s0",
			nics: []pciNIC{{name: "enp5s0"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTempLinkDir(t)
			_ = stubLifelineRename16675(t, tt.live)
			oldEnum := enumeratePCINICsFn
			enumeratePCINICsFn = func() ([]pciNIC, error) { return tt.nics, nil }
			t.Cleanup(func() { enumeratePCINICsFn = oldEnum })

			cfg := &config.Config{}
			if tt.deviceMap {
				cfg.Chassis.DeviceMap = &config.DeviceMapConfig{
					Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/0", PCIAddr: "0000:06:00.0"}},
				}
			}
			d := &Daemon{}
			d.captureBootstrapLifelineRenamePreExit(cfg)
			k, l := d.bootstrapLifelineRenamePair()
			if k != tt.wantKernel || l != tt.wantLogical {
				t.Fatalf("captured pair = (%q,%q), want (%q,%q)", k, l, tt.wantKernel, tt.wantLogical)
			}
		})
	}
}

// lifelineRenameStoreWithDebt16675 builds an expired-FIRST store (via
// the shared 12155 fixture) and writes a durable lifeline record that
// carries the #16675 rename pair under the teardown generation. The
// record deliberately has Present=false and no network bytes: the
// foreign-host lifeline had no xpf fxp0 file, which is exactly the
// captured-absence shape.
func lifelineRenameStoreWithDebt16675(t *testing.T, dir, kernel, logical string) (*configstore.Store, string) {
	t.Helper()
	_ = firstCommit12155FilesAndCommands(t)
	fullStore, _ := firstCommit12155ExpiredStore(t)
	oldDir := linkDir
	linkDir = dir
	t.Cleanup(func() { linkDir = oldDir })
	gen := fullStore.FirstCommitTeardownGeneration()
	data, err := json.Marshal(bootstrapLifelineSnapshotRecord{
		Generation:          gen,
		Present:             false,
		LifelineKernelName:  kernel,
		LifelineLogicalName: logical,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, bootstrapLifelineSnapshotBase), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return fullStore, gen
}

// TestBootstrapRollbackRestoresRenameFromDurableRecord16675 covers the
// across-restart path: a fresh daemon (no in-memory pair) with teardown
// debt owed adopts the generation-bound pair from the durable record
// and still renames back. The .network restore is DEGRADED here (the
// record carries no marker bytes) — that pre-existing gate is not this
// test's subject; the rename step must still run and succeed.
func TestBootstrapRollbackRestoresRenameFromDurableRecord16675(t *testing.T) {
	dir := withTempLinkDir(t)
	installFakeNetworkctl(t)
	fab := stubLifelineRename16675(t, "ge-0-0-0")
	writeTakeoverLink16675(t, dir, "ge-0-0-0", "enp6s0")

	store, gen := lifelineRenameStoreWithDebt16675(t, dir, "enp6s0", "ge-0-0-0")
	d := &Daemon{store: store}
	steps := d.runBootstrapTeardownSteps(true)
	for _, s := range steps {
		if s.name == "restore lifeline kernel name" && s.err != nil {
			t.Fatalf("durable rename restore failed: %v (steps=%+v)", s.err, steps)
		}
	}
	_ = gen
	if len(fab.renames) != 1 || fab.renames[0] != [2]string{"ge-0-0-0", "enp6s0"} {
		t.Fatalf("durable rollback renames = %v, want [ge-0-0-0 -> enp6s0]", fab.renames)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
		t.Fatalf("durable rollback kept the takeover .link; stat err=%v", err)
	}
}

// TestBootstrapRollbackDurableGenerationMismatch16675: a durable pair
// bound to a DIFFERENT generation is not provenance for this teardown —
// no rename is issued from it (the scoped unprovenanced check then
// reports the stranded .link instead of silently keeping it).
func TestBootstrapRollbackDurableGenerationMismatch16675(t *testing.T) {
	dir := withTempLinkDir(t)
	installFakeNetworkctl(t)
	fab := stubLifelineRename16675(t, "ge-0-0-0")
	writeTakeoverLink16675(t, dir, "ge-0-0-0", "enp6s0")

	store, _ := lifelineRenameStoreWithDebt16675(t, dir, "enp6s0", "ge-0-0-0")
	// Rewrite the durable record under a stale generation.
	d0 := &Daemon{store: store}
	_ = d0
	data, err := os.ReadFile(filepath.Join(dir, bootstrapLifelineSnapshotBase))
	if err != nil {
		t.Fatal(err)
	}
	stale := strings.Replace(string(data), store.FirstCommitTeardownGeneration(), "stale-generation", 1)
	if stale == string(data) {
		t.Fatal("premise: durable record does not carry the teardown generation")
	}
	if err := os.WriteFile(filepath.Join(dir, bootstrapLifelineSnapshotBase), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store}
	steps := d.runBootstrapTeardownSteps(true)
	if len(fab.renames) != 0 {
		t.Fatalf("generation-mismatched pair must not drive a rename, got %v", fab.renames)
	}
	found := false
	for _, s := range steps {
		if s.name == "restore lifeline kernel name" && s.err != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("mismatched-generation shape must fail closed, steps=%+v", steps)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); err != nil {
		t.Fatalf("mismatched-generation .link must be retained: %v", err)
	}
}
