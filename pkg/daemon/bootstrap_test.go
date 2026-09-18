package daemon

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestClassifyLoadError pins the #1917 D1 / #1960 boot-path classification of
// a Store.Load error. This is the seam the daemon's Run uses to decide
// fatal-exit (unreadable) vs fail-closed-bootstrap (compile failure) vs
// warn-and-proceed (other) vs normal (nil).
func TestClassifyLoadError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want loadErrorClass
	}{
		{"nil", nil, loadOK},
		// #1917 D1: present-but-unreadable bytes => fatal exit.
		{"unreadable", fmt.Errorf("read config: %w: boom", configstore.ErrConfigDBUnreadable), loadFatalUnreadable},
		// #1960: present, valid bytes, previously committed, no longer compiles
		// => fail-closed bootstrap, NOT a fatal exit (which would strand mgmt).
		{"compile-failed", fmt.Errorf("compile config: %w: undefined group", configstore.ErrConfigCompile), loadCompileFailed},
		// A plain wrapped compile error (the Load wrap chains both sentinels in
		// other paths; ensure the compile tag is still detected through %w).
		{"compile-failed-wrapped", fmt.Errorf("outer: %w", fmt.Errorf("compile config: %w: x", configstore.ErrConfigCompile)), loadCompileFailed},
		{"other", fmt.Errorf("some unrelated failure"), loadOtherError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyLoadError(tt.err); got != tt.want {
				t.Fatalf("classifyLoadError(%v) = %v; want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestCompileFailureForcesBootstrapNotClaimAll ties the two halves together:
// when classifyLoadError reports loadCompileFailed, the boot predicate (fed
// configCompileFailed=true) MUST resolve to bootClassBootstrap — i.e. the
// daemon enters the lifeline safe state and does NOT run the positional
// claim-all interface rename. This mirrors the exact inputs daemon_run.go
// computes after an ErrConfigCompile Load: ActiveConfig()==nil
// (hasActive=false), EverCommitted()==true, and the compile-failed flag set.
// It is checked for both standalone and HA-node (node-id present) boxes,
// since the compile-failure override must beat the HA-node guard.
func TestCompileFailureForcesBootstrapNotClaimAll(t *testing.T) {
	compileFailErr := fmt.Errorf("compile config: %w: undefined group", configstore.ErrConfigCompile)
	if classifyLoadError(compileFailErr) != loadCompileFailed {
		t.Fatal("precondition: compile error not classified as loadCompileFailed")
	}

	for _, nodeID := range []bool{false, true} {
		t.Run(fmt.Sprintf("nodeID=%v", nodeID), func(t *testing.T) {
			// hasActive=false (compile failed → compiled stayed nil),
			// everCommitted=true (committed DB), configCompileFailed=true.
			got := computeBootClass(false, true, nodeID, true)
			if got != bootClassBootstrap {
				t.Fatalf("compile-failed committed config (nodeID=%v) classified %v; "+
					"want bootClassBootstrap (no positional claim-all)", nodeID, got)
			}
		})
	}
}

// TestShouldBootstrapFromFile pins the daemon's import gate (the Run branch at
// daemon_run.go that imports the text xpf.conf after Load). It exists because
// the helper-level computeBootClass test cannot catch a regression in the
// SEPARATE Run-level decision to skip bootstrapFromFile on compile failure
// (Codex #1991 r2): removing the `!configCompileFailed` guard would still pass
// every computeBootClass case yet would silently import a different config over
// a broken committed DB. The (no-active, compile-failed) cell below is the one
// that flips false→true if the guard is dropped, failing this test.
func TestShouldBootstrapFromFile(t *testing.T) {
	tests := []struct {
		name          string
		hasActive     bool
		compileFailed bool
		want          bool
	}{
		// No active config and no compile failure: fresh / never-committed
		// boot imports the text xpf.conf (the long-standing behavior).
		{"no-active-no-compile-failure", false, false, true},
		// A valid active config is loaded: never import over it.
		{"active-loaded", true, false, false},
		// #1960 the load-bearing cell: no active config (compiled stayed nil)
		// but the committed DB failed to compile. The import MUST be skipped —
		// importing xpf.conf here swaps in a different config and then takes
		// over interfaces, defeating the fail-closed intent. Dropping the
		// `!configCompileFailed` guard flips this to true and fails the test.
		{"no-active-compile-failed", false, true, false},
		// Defensive: even if a compiled config were somehow present, a
		// compile-failed load never imports.
		{"active-and-compile-failed", true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBootstrapFromFile(tt.hasActive, tt.compileFailed); got != tt.want {
				t.Fatalf("shouldBootstrapFromFile(hasActive=%v, compileFailed=%v) = %v; want %v",
					tt.hasActive, tt.compileFailed, got, tt.want)
			}
		})
	}
}

// TestComputeBootClass covers the #1922 five-case boot predicate table.
// Case 4 (corrupt/too-new) is fatal via #1917 D1 before the predicate runs,
// so it is not represented as a predicate input.
func TestComputeBootClass(t *testing.T) {
	tests := []struct {
		name          string
		hasActive     bool
		everCommitted bool
		nodeID        bool
		compileFailed bool
		want          bootClass
	}{
		// Case 1: fresh / no config, no node-id => bootstrap.
		{"fresh-no-config", false, false, false, false, bootClassBootstrap},
		// Case 2/3: a valid active config is loaded => normal.
		{"valid-active", true, true, false, false, bootClassNormal},
		// Case 2: day-0 import-clean (compiled present, committed via Commit).
		{"day0-import", true, true, false, false, bootClassNormal},
		// Case 5 committed-empty: no active config, but everCommitted => normal.
		{"committed-empty", false, true, false, false, bootClassNormal},
		// Case 5 never-committed: no active config, never committed => bootstrap.
		{"never-committed", false, false, false, false, bootClassBootstrap},
		// AGY r1 CRITICAL: post-first-commit-rollback restart. The empty tree
		// on disk (committed=0) compiles to a NON-nil config, so
		// hasActiveConfig is TRUE — but everCommitted is FALSE, so the box
		// must stay in bootstrap, NOT misclassify as normal.
		{"post-rollback-restart-empty-compiled", true, false, false, false, bootClassBootstrap},
		// HA-node guard (C2/C8): node-id present always resolves NOT-bootstrap,
		// even with no active config and never committed.
		{"ha-node-no-config", false, false, true, false, bootClassNormal},
		{"ha-node-with-config", true, true, true, false, bootClassNormal},
		// node-id present + never committed still NOT bootstrap (loud-error
		// handled at call site, but predicate must not enter bootstrap).
		{"ha-node-never-committed", false, false, true, false, bootClassNormal},

		// #1960 fail-closed: a previously-committed config that no longer
		// compiles must enter bootstrap, NOT positional claim-all. Store.Load
		// sets everCommitted=true but leaves compiled nil (hasActive=false),
		// which without the override resolves to NORMAL.
		{"compile-failed-committed", false, true, false, true, bootClassBootstrap},
		// The compile-failure override beats EVEN the HA-node guard: claiming
		// all NICs on a broken config is the exact lockout this fixes.
		{"compile-failed-ha-node", false, true, true, true, bootClassBootstrap},
		// Compile failure also overrides a (defensively) non-nil active config
		// — the daemon only sets this flag when compiled stayed nil, but the
		// predicate must be safe regardless.
		{"compile-failed-has-active", true, true, false, true, bootClassBootstrap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeBootClass(tt.hasActive, tt.everCommitted, tt.nodeID, tt.compileFailed)
			if got != tt.want {
				t.Fatalf("computeBootClass(active=%v, committed=%v, nodeID=%v, compileFailed=%v) = %v; want %v",
					tt.hasActive, tt.everCommitted, tt.nodeID, tt.compileFailed, got, tt.want)
			}
		})
	}
}

// TestProtectedInterfaces proves the Item 4 protected set:
//   - default => fxp0 protected.
//   - explicit fxp0 leaf => fxp0 protected.
//   - explicit non-fxp0 leaf => that NIC protected AND fxp0 NARROWED off
//     (OQ-D escape valve).
//
// The lifeline-record contribution is exercised separately (it reads sysfs).
func TestProtectedInterfaces(t *testing.T) {
	// No lifeline record present in the test env, so the set is just the
	// leaf/default contribution.
	t.Run("default-fxp0", func(t *testing.T) {
		set := protectedInterfaces("")
		if !set["fxp0"] {
			t.Fatal("default protected set must contain fxp0")
		}
	})
	t.Run("explicit-fxp0", func(t *testing.T) {
		set := protectedInterfaces("fxp0")
		if !set["fxp0"] {
			t.Fatal("explicit fxp0 leaf must protect fxp0")
		}
	})
	t.Run("explicit-non-fxp0-narrows-fxp0-off", func(t *testing.T) {
		set := protectedInterfaces("ge-0-0-3")
		if !set["ge-0-0-3"] {
			t.Fatal("explicit non-fxp0 leaf must protect that interface")
		}
		if set["fxp0"] {
			t.Fatal("explicit non-fxp0 leaf must NARROW fxp0 out of the auto-protection (OQ-D)")
		}
	})

	// OQ-D BLOCKER (Codex r3): the lifeline-record union must NOT silently
	// re-add fxp0 when an explicit non-fxp0 leaf narrowed it off. Exercised
	// via the pure core with an injected lifeline name.
	t.Run("lifeline-fxp0-does-not-defeat-narrowing", func(t *testing.T) {
		set := protectedInterfacesWith("ge-0-0-3", "fxp0")
		if !set["ge-0-0-3"] {
			t.Fatal("explicit non-fxp0 leaf must protect that interface")
		}
		if set["fxp0"] {
			t.Fatal("lifeline resolving to fxp0 must NOT re-add fxp0 when narrowed off (OQ-D)")
		}
	})
	t.Run("lifeline-protected-when-no-leaf", func(t *testing.T) {
		set := protectedInterfacesWith("", "ge-0-0-5")
		if !set["fxp0"] || !set["ge-0-0-5"] {
			t.Fatalf("no leaf: fxp0 + lifeline both protected; got %v", set)
		}
	})
	t.Run("lifeline-added-when-leaf-is-fxp0", func(t *testing.T) {
		set := protectedInterfacesWith("fxp0", "ge-0-0-5")
		if !set["fxp0"] || !set["ge-0-0-5"] {
			t.Fatalf("explicit fxp0 leaf: fxp0 + lifeline both protected; got %v", set)
		}
	})
}

// TestReadLifelineRecord proves the persisted record round-trips and an
// absent/blank record reports not-found.
func TestReadLifelineRecord(t *testing.T) {
	// Redirect the record path into a temp file for the test.
	t.Cleanup(func() { lifelineRecordFileForTest = "" })
	tmp := t.TempDir() + "/lifeline-interface"
	lifelineRecordFileForTest = tmp

	if _, ok := readLifelineRecordAt(tmp); ok {
		t.Fatal("absent record reported found")
	}

	want := lifelineRecord{PCIAddr: "0000:05:00.0", MAC: "52:54:00:ab:cd:ef"}
	if err := writeLifelineRecordAt(tmp, want); err != nil {
		t.Fatal(err)
	}
	got, ok := readLifelineRecordAt(tmp)
	if !ok {
		t.Fatal("record reported not-found after write")
	}
	if got.PCIAddr != want.PCIAddr || got.MAC != want.MAC {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
