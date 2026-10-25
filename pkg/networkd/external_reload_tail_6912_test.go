package networkd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// #6912. Apply's activation tail does two things only Apply can do: the
// per-interface `networkctl reconfigure` that applies bond/VLAN addresses, and
// restoreSlowPathRPFilter, which re-disables rp_filter on the userspace
// dataplane's slow-path TUN after networkd resets it.
//
// pkg/daemon is a second `networkctl reload` owner and runs one BEFORE
// networkd.Apply on the live day-2 path. When that external reload SUCCEEDS,
// the kernel really does re-read the directory, so the reload obligation is
// genuinely discharged — but the tail was not run, and an external owner
// cannot run it.
//
// The pre-#6912 gate could not see this. With no failed Apply anywhere there
// is nothing for the debt mechanism to carry: changed is false, the reload
// debt was correctly cleared, no reconfigure failed, and this Manager never
// started a pass. Every term was false while the tail had never run, and Apply
// returned nil having left addresses unreconfigured and rp_filter at
// networkd's default — which silently drops locally-originated traffic via the
// TUN.
//
// This is distinct from #5718, which covers a FAILED Apply whose debt a later
// external success clears. Here nothing fails at any point.

// setSlowPathRPFilter models networkd resetting rp_filter on the slow-path TUN,
// which is what a reload does and what the tail exists to undo.
func setSlowPathRPFilter(t *testing.T, v string) {
	t.Helper()
	p := filepath.Join(procSysNetRoot, "conf", "xpf-usp0", "rp_filter")
	if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
		t.Fatalf("setting rp_filter: %v", err)
	}
}

// TestExternalReloadSuccessOwesTheTail_6912 is the fail-on-revert: drop the
// externalTailOutstanding() term from Apply's gate, or the arming in
// NoteReloadResult, and the unchanged Apply skips the tail again.
func TestExternalReloadSuccessOwesTheTail_6912(t *testing.T) {
	resetReloadDebtForTest(t)
	readRPFilter := rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reconfigureArgs [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := activationTailIfaces()

	// 1) A first Apply writes the files and runs its own tail. Nothing fails.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("setup: first Apply: %v", err)
	}
	if len(reconfigureArgs) != 2 {
		t.Fatalf("setup: want one tail (2 per-interface calls) on the first Apply, got %d", len(reconfigureArgs))
	}
	if got := readRPFilter(); got != "0" {
		t.Fatalf("setup: the first tail must restore rp_filter to 0, got %q", got)
	}

	// 2) An EXTERNAL owner (pkg/daemon's teardown/linksetup/bootstrap reload)
	//    reloads SUCCESSFULLY and reports it. networkd resets rp_filter as part
	//    of that reload.
	setSlowPathRPFilter(t, "2")
	epoch := BeginReload()
	NoteReloadResult(epoch, nil)

	// 3) An unchanged Apply. Files are byte-identical and nothing has failed,
	//    so this is the case with no debt to carry.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	if len(reconfigureArgs) != 4 {
		t.Fatalf("an unchanged Apply after a successful EXTERNAL reload must still run the tail; "+
			"want 4 reconfigure calls (2 tails x 2 interfaces), got %d (%v)", len(reconfigureArgs), reconfigureArgs)
	}
	// Assert WHICH interfaces, not merely that a call happened: a tail that
	// reconfigured the wrong set would leave the real ones unapplied while
	// making a call that looks correct.
	if !slices.EqualFunc(reconfigureArgs[2:], wantActivationTailArgv, func(a, b []string) bool { return slices.Equal(a, b) }) {
		t.Fatalf("the owed tail ran %v, want %v", reconfigureArgs[2:], wantActivationTailArgv)
	}
	// And assert what the value BECAME — the rp_filter half is the one that
	// silently drops traffic, and it is invisible in the argv.
	if got := readRPFilter(); got != "0" {
		t.Fatalf("the owed tail must restore rp_filter to 0, got %q — locally-originated "+
			"traffic via the slow-path TUN is silently dropped at networkd's default", got)
	}
}

// TestTailDebtIsClearedByTheTail_6912 pins the other half: the debt must be
// discharged once paid, or every subsequent unchanged Apply would reconfigure
// forever. A gate that never clears is as wrong as one that never fires — it
// just fails in the expensive direction instead of the silent one.
func TestTailDebtIsClearedByTheTail_6912(t *testing.T) {
	resetReloadDebtForTest(t)
	_ = rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reconfigureCalls int
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			reconfigureCalls++
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := activationTailIfaces()
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("setup: %v", err)
	}
	epoch := BeginReload()
	NoteReloadResult(epoch, nil)
	if !externalTailOutstanding() {
		t.Fatal("a successful external reload must arm the tail debt")
	}

	if err := m.Apply(ifaces); err != nil { // pays the debt
		t.Fatalf("second Apply: %v", err)
	}
	if externalTailOutstanding() {
		t.Fatal("a completed tail must discharge the external tail debt")
	}
	after := reconfigureCalls

	// A third unchanged Apply with no external reload in between owes nothing.
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("third Apply: %v", err)
	}
	if reconfigureCalls != after {
		t.Fatalf("an unchanged Apply with no outstanding debt must not reconfigure; "+
			"calls went %d -> %d", after, reconfigureCalls)
	}
}

// TestApplyLeavesNoTailDebtOutstanding_6912 asserts that a completed Apply
// leaves no tail debt behind, whatever armed it.
//
// It deliberately does NOT claim to pin the arming SITE. Moving the arming into
// the shared noteReloadSucceeded was measured to change nothing observable,
// because Apply's own tail clears the flag in the same pass — so a test named
// for the arming site would pass under that mutation and assert something it
// does not actually check. The invariant that IS real, and is what protects
// against an unchanged Apply reconfiguring forever, is this one: after a
// successful Apply the debt is discharged.
func TestApplyLeavesNoTailDebtOutstanding_6912(t *testing.T) {
	resetReloadDebtForTest(t)
	_ = rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	orig := runNetworkctl
	runNetworkctl = func(args ...string) error { return nil }
	t.Cleanup(func() { runNetworkctl = orig })

	if err := m.Apply(activationTailIfaces()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if externalTailOutstanding() {
		t.Fatal("a completed Apply must leave no tail debt outstanding")
	}
}
