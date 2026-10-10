package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
)

// F1 (fold-2 confirmation): the realistic #6538 shape — a committed box that booted NORMAL (no
// bootstrap exit, so no in-process snapshot), whose committed config manages
// fxp0 (unmarked xpfd file), and whose NON-first window has a nil compiled
// target. The safe-state entry must not attempt the first-commit lifeline
// restore: no "restore management lifeline network" step, no DEGRADED. This
// is the no-DEGRADED half of the M1b fix the fold-1 reviewer requested.
func TestFirstCommitGate6538ShapeNoRestoreNoDegraded12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	fxp0 := "interfaces { fxp0 { unit 0 { family inet { address 10.1.1.5/24; } } } }\n"
	commitConfirmedText12154(t, store, fxp0)
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	managed := []networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"10.1.1.5/24"}}}
	d := lifelineDaemon12154(t, store, dir, managed)
	// Committed box: boots NORMAL, never runs the bootstrap-exit capture.
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("apply committed: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil || isBootstrapLifelineNetwork(before) || !strings.Contains(string(before), "10.1.1.5/24") {
		t.Fatalf("premise: committed unmarked fxp0 file = %q err=%v", before, err)
	}
	d.bootstrapLifelineMu.Lock()
	captured := d.bootstrapLifelineCaptured
	d.bootstrapLifelineMu.Unlock()
	if captured {
		t.Fatal("premise: normal-boot daemon must hold no snapshot")
	}
	commitConfirmedText12154(t, store, "system { host-name fw-6538; }\n"+fxp0)
	gen := store.ConfirmGenForTesting()
	store.SetConfirmPrevCfgForTesting(nil)
	if target, first, pending := store.PendingRollbackTarget(gen); !pending || first || target != nil {
		t.Fatalf("premise: pending=%v first=%v target!=nil=%v", pending, first, target != nil)
	}
	buf, restore := captureSlog(t)
	store.InvokeRollbackTimerForTesting(gen)
	restore()
	logs := buf.String()
	if strings.Contains(logs, "restore management lifeline network") || strings.Contains(logs, "DEGRADED") {
		t.Fatalf("#6538-shape safe-state entry ran the first-commit lifeline restore / reported DEGRADED:\n%s", logs)
	}
	t.Logf("no first-commit restore, no DEGRADED on the #6538 shape")
}

// F1 (fold-2 confirmation): the #1960-repair shape — a committed box that booted
// fail-closed into BOOTSTRAP (committed config uncompilable), so the
// operator's repaired `commit confirmed` exits bootstrap and CAPTURES the
// day-0 lifeline, yet the window is NON-first with a nil compiled target.
// The documented invariant: a snapshot captured during bootstrap exit must
// never be used by a later safe-state entry on a committed box. fxp0 must
// NOT be rewritten from the day-0 snapshot.
func TestFirstCommitGate1960RepairNeverRestoresDay012154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	day0 := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
	if err := os.WriteFile(path, day0, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	// Make the box committed (everCommitted=true) without touching fxp0.
	commitConfirmedText12154(t, store, "system { host-name committed; }\n")
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if !store.EverCommitted() {
		t.Fatal("premise: not committed")
	}
	managed := []networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"10.9.9.9/24"}}}
	d := lifelineDaemon12154(t, store, dir, managed)
	d.bootstrapMode.Store(true) // #1960 fail-closed boot on a committed box
	commitConfirmedText12154(t, store, "interfaces { fxp0 { unit 0 { family inet { address 10.9.9.9/24; } } } }\n")
	gen := store.ConfirmGenForTesting()
	store.SetConfirmPrevCfgForTesting(nil) // compiled was nil at arm time (#1960)
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("apply repaired: %v", err)
	}
	d.bootstrapLifelineMu.Lock()
	snap := append([]byte(nil), d.bootstrapLifelineNetwork...)
	d.bootstrapLifelineMu.Unlock()
	if string(snap) != string(day0) {
		t.Fatalf("premise: bootstrap exit did not capture day-0: %q", snap)
	}
	applied, _ := os.ReadFile(path)
	if target, first, pending := store.PendingRollbackTarget(gen); !pending || first || target != nil {
		t.Fatalf("premise: pending=%v first=%v target!=nil=%v", pending, first, target != nil)
	}
	store.InvokeRollbackTimerForTesting(gen)
	after, _ := os.ReadFile(path)
	if string(after) == string(day0) && string(applied) != string(day0) {
		t.Fatalf("committed-box safe-state entry rewrote fxp0 from the day-0 snapshot:\napplied=%q\nafter=%q", applied, after)
	}
	t.Logf("fxp0 after nil-target non-first rollback = %q (applied=%q)", after, applied)
}
