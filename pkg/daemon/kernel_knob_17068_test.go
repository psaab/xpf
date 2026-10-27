package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

// #17068 acceptance (2) at the daemon layer: a commit with
// load-balance consistent-hash asserts fib_multipath_hash_policy=1, and
// a following commit without it restores the pre-assert value. Driven
// through the production reconcile against a temp-file knob stand-in
// (class U hermetic; never touches real procfs).
func TestFibMultipathHashPolicyRestoresOnUnset17068(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fib_multipath_hash_policy")
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fibMultipathHashPolicyPath
	fibMultipathHashPolicyPath = p
	t.Cleanup(func() { fibMultipathHashPolicyPath = orig })

	d := &Daemon{}
	// Commit WITH consistent-hash: knob asserted.
	d.reconcileFibMultipathHashPolicy(true)
	if got := readKnob17068(t, p); got != "1" {
		t.Fatalf("with consistent-hash: knob=%q want 1", got)
	}
	// Re-assert (second commit still with it): capture must not be
	// overwritten by the asserted value.
	d.reconcileFibMultipathHashPolicy(true)
	// Commit WITHOUT consistent-hash: knob returns to pre-assert 0.
	d.reconcileFibMultipathHashPolicy(false)
	if got := readKnob17068(t, p); got != "0" {
		t.Fatalf("without consistent-hash: knob=%q want restored 0", got)
	}
}

// The operator's own pre-assert value (not a constant) is restored:
// seed 3, assert 1, release must return 3 — the #15710 constant-restore
// regression class.
func TestFibMultipathRestoresCapturedPrior17068(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fib_multipath_hash_policy")
	if err := os.WriteFile(p, []byte("3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fibMultipathHashPolicyPath
	fibMultipathHashPolicyPath = p
	t.Cleanup(func() { fibMultipathHashPolicyPath = orig })

	d := &Daemon{}
	d.reconcileFibMultipathHashPolicy(true)
	d.reconcileFibMultipathHashPolicy(false)
	if got := readKnob17068(t, p); got != "3" {
		t.Fatalf("knob=%q want captured prior 3 restored", got)
	}
}

// Control: applyFRRConfig with ConsistentHash=false on a daemon that
// never asserted leaves the knob untouched (no capture, no write).
func TestFibMultipathUnsetWithoutAssertIsNoop17068(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fib_multipath_hash_policy")
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fibMultipathHashPolicyPath
	fibMultipathHashPolicyPath = p
	t.Cleanup(func() { fibMultipathHashPolicyPath = orig })

	d := &Daemon{}
	if err := d.applyFRRConfig(&frr.FullConfig{ConsistentHash: false}); err != nil {
		t.Fatalf("applyFRRConfig: %v", err)
	}
	if got := readKnob17068(t, p); got != "0" {
		t.Fatalf("knob=%q want untouched 0", got)
	}
}

func readKnob17068(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read knob: %v", err)
	}
	return strings.TrimSpace(string(b))
}
