package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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

// Control, driven through the production applyFRRConfig path with a real
// (test-seamed) FRR manager: a FullConfig with no content at all goes
// through ApplyFull's Clear path, and with no consistent-hash policy the
// knob is left untouched. Pre-fix this cell was test-only-green: it used
// a nil-frr daemon, whose applyFRRConfig returns before the reconcile.
func TestFibMultipathUnsetWithoutAssertIsNoop17068(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fib_multipath_hash_policy")
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fibMultipathHashPolicyPath
	fibMultipathHashPolicyPath = p
	t.Cleanup(func() { fibMultipathHashPolicyPath = orig })

	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{frr: frr.NewForTest(conf, &frr.RecordingExecutor{})}
	t.Cleanup(d.frr.Stop)
	if err := d.applyFRRConfig(&frr.FullConfig{}); err != nil {
		t.Fatalf("applyFRRConfig: %v", err)
	}
	if got := readKnob17068(t, p); got != "0" {
		t.Fatalf("knob=%q want untouched 0", got)
	}
}

// Production-path cell: a FullConfig carrying ONLY a consistent-hash
// forwarding-table export (no routes, protocols, or cluster content —
// the shape ApplyFull's hasContent gate sends to Clear without ever
// running resolveECMP) must still assert the knob, and removing the
// policy must restore the pre-assert value. Pre-fix, fc.ConsistentHash
// was never set on this path, so the knob stayed 0.
func TestFibMultipathPolicyOnlyConfigAsserts17068(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fib_multipath_hash_policy")
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fibMultipathHashPolicyPath
	fibMultipathHashPolicyPath = p
	t.Cleanup(func() { fibMultipathHashPolicyPath = orig })

	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{frr: frr.NewForTest(conf, &frr.RecordingExecutor{})}
	t.Cleanup(d.frr.Stop)

	policyOnly := &frr.FullConfig{
		ForwardingTableExport: "lb-policy",
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"lb-policy": {
					Name: "lb-policy",
					Terms: []*config.PolicyTerm{
						{LoadBalance: "consistent-hash", Action: "accept"},
					},
				},
			},
		},
	}
	if err := d.applyFRRConfig(policyOnly); err != nil {
		t.Fatalf("applyFRRConfig(policy-only): %v", err)
	}
	if got := readKnob17068(t, p); got != "1" {
		t.Fatalf("policy-only consistent-hash: knob=%q want asserted 1", got)
	}
	// Removal through the same production path restores the prior.
	if err := d.applyFRRConfig(&frr.FullConfig{}); err != nil {
		t.Fatalf("applyFRRConfig(removed): %v", err)
	}
	if got := readKnob17068(t, p); got != "0" {
		t.Fatalf("after policy removal: knob=%q want restored 0", got)
	}
}

// Restart cell: a fresh daemon (empty registry) whose first apply finds
// the knob already at 1 — left there by a previous daemon that asserted
// it — must restore the operator default 0 on unset, not "restore" the
// asserted value it would otherwise capture as prior.
func TestFibMultipathRestartRestoresOperatorDefault17068(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fib_multipath_hash_policy")
	if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := fibMultipathHashPolicyPath
	fibMultipathHashPolicyPath = p
	t.Cleanup(func() { fibMultipathHashPolicyPath = orig })

	d := &Daemon{} // fresh process: no capture survives the restart
	d.reconcileFibMultipathHashPolicy(true)
	d.reconcileFibMultipathHashPolicy(false)
	if got := readKnob17068(t, p); got != "0" {
		t.Fatalf("after restart+unset: knob=%q want operator default 0, not the poisoned capture 1", got)
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
