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
		// #10297: active.json absent but rollback markers survive => fail
		// closed bootstrap, not a fresh text-config import.
		{"absent-active-with-history", fmt.Errorf("load config: %w", configstore.ErrConfigAbsentWithHistory), loadAbsentWithHistory},
		// #11802: valid rescue fallback requires the safe bootstrap path too.
		{"rescue-fallback", fmt.Errorf("load: %w", configstore.ErrConfigRescueFallback), loadRescueFallback},
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
// computes after an ErrConfigCompile Load: EverCommitted()==true and the
// compile-failed flag set.
// It is checked for both standalone and HA-node (node-id present) boxes,
// since the compile-failure override must beat the HA-node guard.
func TestCompileFailureForcesBootstrapNotClaimAll(t *testing.T) {
	compileFailErr := fmt.Errorf("compile config: %w: undefined group", configstore.ErrConfigCompile)
	if classifyLoadError(compileFailErr) != loadCompileFailed {
		t.Fatal("precondition: compile error not classified as loadCompileFailed")
	}

	for _, nodeID := range []bool{false, true} {
		t.Run(fmt.Sprintf("nodeID=%v", nodeID), func(t *testing.T) {
			// everCommitted=true (committed DB), configCompileFailed=true.
			got := computeBootClass(true, nodeID, true)
			if got != bootClassBootstrap {
				t.Fatalf("compile-failed committed config (nodeID=%v) classified %v; "+
					"want bootClassBootstrap (no positional claim-all)", nodeID, got)
			}
		})
	}
}

// TestAbsentActiveHistoryForcesBootstrapNotClaimAll_10297 pins the second
// fail-closed half of #10297: the Store error is distinct from a corrupt
// present DB, but an absent active config with surviving history still forces
// lifeline bootstrap and skips stale text-config import.
func TestAbsentActiveHistoryForcesBootstrapNotClaimAll_10297(t *testing.T) {
	err := fmt.Errorf("load config: %w", configstore.ErrConfigAbsentWithHistory)
	if got := classifyLoadError(err); got != loadAbsentWithHistory {
		t.Fatalf("classifyLoadError(%v) = %v; want loadAbsentWithHistory", err, got)
	}
	if got := computeBootClass(true, false, true); got != bootClassBootstrap {
		t.Fatalf("absent active with history classified %v; want bootClassBootstrap", got)
	}
	if shouldBootstrapFromFile(false, true, true) {
		t.Fatal("absent active with history must not import stale xpf.conf")
	}
}

// TestShouldBootstrapFromFile pins the daemon's import gate (the Run branch at
// daemon_run.go that imports text xpf.conf after Load). A first-commit rollback
// leaves a compiled empty config with EverCommitted=false; this is still an
// unconfigured box and must retry the file import. A compiled active config
// with EverCommitted=true remains protected, and fail-closed loads never import.
func TestShouldBootstrapFromFile(t *testing.T) {
	tests := []struct {
		name          string
		hasActive     bool
		everCommitted bool
		failClosed    bool
		want          bool
	}{
		{"fresh-store", false, false, false, true},
		{"first-commit-rollback-compiled-empty", true, false, false, true},
		{"committed-active-config", true, true, false, false},
		{"no-active-existing-behavior", false, true, false, true},
		{"valid-rescue-fallback", false, true, true, false},
		{"no-active-fail-closed", false, true, true, false},
		{"active-fail-closed", true, false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBootstrapFromFile(tt.hasActive, tt.everCommitted, tt.failClosed); got != tt.want {
				t.Fatalf("shouldBootstrapFromFile(active=%v, everCommitted=%v, failClosed=%v) = %v; want %v",
					tt.hasActive, tt.everCommitted, tt.failClosed, got, tt.want)
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
		everCommitted bool
		nodeID        bool
		compileFailed bool
		want          bootClass
	}{
		{"fresh-no-config", false, false, false, bootClassBootstrap},
		{"valid-active", true, false, false, bootClassNormal},
		{"committed-empty", true, false, false, bootClassNormal},
		{"never-committed", false, false, false, bootClassBootstrap},
		// A compiled empty tree after first-commit rollback still has
		// everCommitted=false and must remain in bootstrap.
		{"post-rollback-restart-empty-compiled", false, false, false, bootClassBootstrap},
		{"ha-node-no-config", false, true, false, bootClassNormal},
		{"ha-node-with-config", true, true, false, bootClassNormal},
		{"ha-node-never-committed", false, true, false, bootClassNormal},
		{"compile-failed-committed", true, false, true, bootClassBootstrap},
		{"compile-failed-ha-node", true, true, true, bootClassBootstrap},
		{"compile-failed", true, false, true, bootClassBootstrap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeBootClass(tt.everCommitted, tt.nodeID, tt.compileFailed)
			if got != tt.want {
				t.Fatalf("computeBootClass(committed=%v, nodeID=%v, compileFailed=%v) = %v; want %v",
					tt.everCommitted, tt.nodeID, tt.compileFailed, got, tt.want)
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
