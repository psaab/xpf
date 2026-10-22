package config_test

// Regression tests for #2524: `system dataplane ring-entries` had only a
// minimum bound (ValidateIntegerMin(1)). A large value committed and was
// passed to the Rust helper, which sizes per-binding UMEM preallocations
// directly from it (~3×ring_entries frames per binding, ~96 MB/binding at
// ring_entries=8192). An out-of-range value failed by OOM at bring-up
// instead of as a clean commit/startup error.
//
// The fix bounds the leaf at commit (pkg/config ValidateRingEntries):
//   - in range  [1..MaxRingEntries] (MaxRingEntries = 16384), AND
//   - a power of two (the helper rounds ring sizes up to a power of two,
//     so requiring it keeps the configured number honest).
// A matching helper-side backstop clamps/rejects in the Rust loader
// (afxdp MAX_RING_ENTRIES, server/lifecycle.rs --ring-entries parse).
//
// FAIL-ON-REVERT: flipping ValidateRingEntries back to ValidateIntegerMin(1)
// in schema_system.go makes TestSchema2524_RejectsOversized and
// TestSchema2524_RejectsNonPowerOfTwo go RED (the over-max / non-pow2
// values commit clean again), proving the gate is load-bearing.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ringEntriesCheck builds the leaf via flat-set (ParseSetCommand + SetPath),
// the canonical way to exercise set syntax (see CLAUDE.md — never NewParser
// for set lines).
func ringEntriesCheck(t *testing.T, val string) error {
	t.Helper()
	return flatSchemaCheck(t, "set system dataplane ring-entries "+val)
}

func TestSchema2524_AcceptsValidPowersOfTwo(t *testing.T) {
	for _, v := range []string{"1", "2", "1024", "2048", "8192", "16384"} {
		if err := ringEntriesCheck(t, v); err != nil {
			t.Errorf("ring-entries %s: expected accept, got %v", v, err)
		}
	}
}

func TestSchema2524_RejectsOversized(t *testing.T) {
	// 16385 is max+1; 32768/100000 are powers-of-two/round numbers above
	// the ceiling. All must be rejected (RED if the bound is reverted).
	for _, v := range []string{"16385", "32768", "100000"} {
		err := ringEntriesCheck(t, v)
		if err == nil {
			t.Fatalf("ring-entries %s: expected out-of-range error, got nil", v)
		}
		if !strings.Contains(err.Error(), "ring-entries") {
			t.Fatalf("ring-entries %s: error should reference ring-entries: %v", v, err)
		}
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("ring-entries %s: error should quote bad value: %v", v, err)
		}
	}
}

func TestSchema2524_RejectsNonPowerOfTwo(t *testing.T) {
	// In-range but not a power of two — accepted before the fix, rejected
	// after (RED on revert to ValidateIntegerMin(1)).
	for _, v := range []string{"3", "1000", "3000", "1023", "12345"} {
		err := ringEntriesCheck(t, v)
		if err == nil {
			t.Fatalf("ring-entries %s: expected power-of-two error, got nil", v)
		}
		if !strings.Contains(err.Error(), "power of two") {
			t.Fatalf("ring-entries %s: error should mention power of two: %v", v, err)
		}
	}
}

func TestSchema2524_RejectsZeroAndGarbage(t *testing.T) {
	for _, v := range []string{"0", "-1", "asd"} {
		if err := ringEntriesCheck(t, v); err == nil {
			t.Fatalf("ring-entries %s: expected error, got nil", v)
		}
	}
}

// TestSchema2524_ValidatorUnit exercises ValidateRingEntries directly so the
// boundary (MaxRingEntries) and the power-of-two predicate are pinned
// independent of the schema wiring.
func TestSchema2524_ValidatorUnit(t *testing.T) {
	if config.MaxRingEntries != 16384 {
		t.Fatalf("MaxRingEntries = %d, want 16384", config.MaxRingEntries)
	}
	good := []string{"1", "16384"}
	for _, v := range good {
		if err := config.ValidateRingEntries(v); err != nil {
			t.Errorf("ValidateRingEntries(%q): unexpected error: %v", v, err)
		}
	}
	bad := []string{"0", "16385", "24576", "asd", ""}
	for _, v := range bad {
		if err := config.ValidateRingEntries(v); err == nil {
			t.Errorf("ValidateRingEntries(%q): expected error, got nil", v)
		}
	}
}
