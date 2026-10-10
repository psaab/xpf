package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #5682 (codex-review-182 M24): an UNREADABLE kernel-upgrade journal (I/O error,
// corruption, parse failure) must FAIL CLOSED — hold the candidate-election
// SECONDARY, exactly as a definitively-armed candidate would — instead of being
// treated as "not armed" and proceeding to a normal election. A clean ENOENT
// ("never armed") must STILL proceed so a node that never armed an upgrade is
// not bricked. These tests are the fail-on-revert gate: neutralizing the fix
// (unreadable -> return without holding) turns the unreadable cases RED.

// stubKernelSys satisfies upgrade.KernelSystem by embedding a nil interface: it
// is legal to construct a KernelRunner with it (NewKernelRunner only rejects a
// nil Sys), and IsArmed/loadKernelJournal never call any Sys method (they only
// os.ReadFile the JournalPath), so no method is ever invoked in the hold path.
type stubKernelSys struct{ upgrade.KernelSystem }

// fakeKernelSys overrides only the two methods reconcileKernelUpgradeHold's
// promotion-marker gate calls, so the self-heal/promotion tests can steer the
// release decision without a live host.
type fakeKernelSys struct {
	upgrade.KernelSystem
	running     string
	runningErr  error
	promoted    string
	promotedErr error
}

func (f fakeKernelSys) RunningKernel() (string, error)       { return f.running, f.runningErr }
func (f fakeKernelSys) ReadPromotionMarker() (string, error) { return f.promoted, f.promotedErr }

// runnerAt returns a kernelRunnerFn seam whose KernelRunner reads the journal at
// path (stub system; the journal read is pure filesystem).
func runnerAt(path string) func() (*upgrade.KernelRunner, error) {
	return func() (*upgrade.KernelRunner, error) {
		return upgrade.NewKernelRunner(upgrade.KernelConfig{
			JournalPath: path,
			Sys:         stubKernelSys{},
		})
	}
}

// writeJournal marshals a valid journal to path.
func writeJournal(t *testing.T, path string, j upgrade.KernelJournal) {
	t.Helper()
	data, err := json.Marshal(&j)
	if err != nil {
		t.Fatalf("marshal journal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
}

// TestHoldSecondaryIfKernelCandidateArmed_FailClosed is the merge gate: it
// covers all four journal states from the issue.
func TestHoldSecondaryIfKernelCandidateArmed_FailClosed(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string) string // returns the journal path to point the runner at
		wantHold   bool
		wantFailCl bool // expected d.kernelUpgradeHoldFailClosed after the call
	}{
		{
			// (3) UNREADABLE via parse failure (corrupt/malformed content on an
			// existing file). MUST hold (fail-closed).
			name: "unreadable_parse_failure_holds",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "kernel-upgrade.state")
				if err := os.WriteFile(p, []byte("{ this is not valid json"), 0o644); err != nil {
					t.Fatalf("write malformed journal: %v", err)
				}
				return p
			},
			wantHold:   true,
			wantFailCl: true,
		},
		{
			// (3b) UNREADABLE via genuine I/O read error (path is a directory ->
			// os.ReadFile returns EISDIR, which is NOT os.IsNotExist). MUST hold.
			name: "unreadable_io_error_holds",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "journal-is-a-dir")
				if err := os.Mkdir(p, 0o755); err != nil {
					t.Fatalf("mkdir journal path: %v", err)
				}
				return p
			},
			wantHold:   true,
			wantFailCl: true,
		},
		{
			// (2) MISSING journal (ENOENT) — a node that never armed an upgrade.
			// MUST NOT hold (regression guard: do not brick a never-armed node).
			name: "missing_enoent_no_hold",
			setup: func(t *testing.T, dir string) string {
				return filepath.Join(dir, "does-not-exist.state")
			},
			wantHold:   false,
			wantFailCl: false,
		},
		{
			// (1) Definitively ARMED — hold (unchanged behavior).
			name: "armed_holds",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "kernel-upgrade.state")
				writeJournal(t, p, upgrade.KernelJournal{
					State:            upgrade.KernelStateArmed,
					CandidateVersion: "6.18.5-test",
				})
				return p
			},
			wantHold:   true,
			wantFailCl: false,
		},
		{
			// (4) Definitively NOT ARMED (valid content, pre-armed state) — no hold.
			name: "not_armed_valid_no_hold",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "kernel-upgrade.state")
				writeJournal(t, p, upgrade.KernelJournal{
					State:            upgrade.KernelStateInstalled,
					CandidateVersion: "6.18.5-test",
				})
				return p
			},
			wantHold:   false,
			wantFailCl: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tt.setup(t, dir)
			m := cluster.NewManager(0, 1)
			d := &Daemon{
				cluster:        m,
				kernelRunnerFn: runnerAt(path),
				kernelSystemFn: func() upgrade.KernelSystem {
					return fakeKernelSys{running: "6.18.5-test"}
				},
			}

			d.holdSecondaryIfKernelCandidateArmed()

			if got := m.KernelUpgradeHeld(); got != tt.wantHold {
				t.Fatalf("KernelUpgradeHeld() = %v, want %v", got, tt.wantHold)
			}
			if got := d.kernelUpgradeHoldFailClosed; got != tt.wantFailCl {
				t.Fatalf("kernelUpgradeHoldFailClosed = %v, want %v", got, tt.wantFailCl)
			}
		})
	}
}

// TestReconcileKernelUpgradeHold_FailClosedSelfHeals proves a fail-closed hold
// set on a transient read error is RELEASABLE (not stranded SECONDARY forever):
// once the journal reads cleanly as NOT armed, the reconcile tick releases it.
func TestReconcileKernelUpgradeHold_FailClosedSelfHeals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel-upgrade.state")

	// Boot with an unreadable (corrupt) journal -> fail-closed hold.
	if err := os.WriteFile(path, []byte("{corrupt"), 0o644); err != nil {
		t.Fatalf("write corrupt journal: %v", err)
	}
	m := cluster.NewManager(0, 1)
	d := &Daemon{cluster: m, kernelRunnerFn: runnerAt(path)}
	d.holdSecondaryIfKernelCandidateArmed()
	if !m.KernelUpgradeHeld() || !d.kernelUpgradeHoldFailClosed {
		t.Fatalf("precondition: expected fail-closed hold set (held=%v failClosed=%v)",
			m.KernelUpgradeHeld(), d.kernelUpgradeHoldFailClosed)
	}

	// Reconcile while the journal is still unreadable: hold MUST persist.
	d.reconcileKernelUpgradeHold()
	if !m.KernelUpgradeHeld() {
		t.Fatal("hold released while journal still unreadable; must keep holding fail-closed")
	}

	// The transient error clears: journal now reads cleanly as NOT armed.
	writeJournal(t, path, upgrade.KernelJournal{State: upgrade.KernelStateInit})
	d.reconcileKernelUpgradeHold()
	if m.KernelUpgradeHeld() {
		t.Fatal("fail-closed hold not released after journal became readable and not-armed (node stranded SECONDARY)")
	}
	if d.kernelUpgradeHoldFailClosed {
		t.Fatal("kernelUpgradeHoldFailClosed still set after release")
	}
}

// TestReconcileKernelUpgradeHold_FailClosedBecomesArmed proves that when a
// fail-closed hold's journal later reads as genuinely ARMED and the running
// kernel matches the candidate, the hold is converted to a normal armed hold
// (fail-closed flag cleared) and remains under the strict marker gate.
func TestReconcileKernelUpgradeHold_FailClosedBecomesArmed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel-upgrade.state")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o644); err != nil {
		t.Fatalf("write corrupt journal: %v", err)
	}
	m := cluster.NewManager(0, 1)
	d := &Daemon{
		cluster:        m,
		kernelRunnerFn: runnerAt(path),
		// A genuine candidate boot converts to an ordinary candidate hold, then
		// the promotion-marker gate keeps holding until promotion is confirmed.
		kernelSystemFn: func() upgrade.KernelSystem {
			return fakeKernelSys{running: "6.18.5-test"}
		},
	}
	d.holdSecondaryIfKernelCandidateArmed()
	if !d.kernelUpgradeHoldFailClosed {
		t.Fatal("precondition: fail-closed flag must be set")
	}

	// Journal now reads as a genuine armed candidate.
	writeJournal(t, path, upgrade.KernelJournal{
		State:            upgrade.KernelStateArmed,
		CandidateVersion: "6.18.5-test",
	})
	d.reconcileKernelUpgradeHold()
	if !m.KernelUpgradeHeld() {
		t.Fatal("armed candidate must keep holding (not self-heal away)")
	}
	if d.kernelUpgradeHoldFailClosed {
		t.Fatal("fail-closed flag must clear once the journal reads armed (now a normal armed hold)")
	}
}

// TestReconcileKernelUpgradeHold_ArmedReleasesOnPromotion is a regression guard
// that the existing strict release path still works: a normal armed hold is
// released once the promotion marker names the running kernel.
func TestReconcileKernelUpgradeHold_ArmedReleasesOnPromotion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernel-upgrade.state")
	writeJournal(t, path, upgrade.KernelJournal{
		State:            upgrade.KernelStateArmed,
		CandidateVersion: "6.18.5-test",
	})
	m := cluster.NewManager(0, 1)
	d := &Daemon{
		cluster:        m,
		kernelRunnerFn: runnerAt(path),
		kernelSystemFn: func() upgrade.KernelSystem {
			return fakeKernelSys{running: "6.18.5-test", promoted: "6.18.5-test"}
		},
	}
	d.holdSecondaryIfKernelCandidateArmed()
	if !m.KernelUpgradeHeld() || d.kernelUpgradeHoldFailClosed {
		t.Fatalf("precondition: armed hold, not fail-closed (held=%v failClosed=%v)",
			m.KernelUpgradeHeld(), d.kernelUpgradeHoldFailClosed)
	}
	d.reconcileKernelUpgradeHold()
	if m.KernelUpgradeHeld() {
		t.Fatal("armed hold must release once the promotion marker matches the running kernel")
	}
}
