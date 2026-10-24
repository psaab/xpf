package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/daemon"
)

// cleanupStepRecorder scripts every cleanup step and records the order
// in which the subcommand invoked them.
type cleanupStepRecorder struct {
	steps    []string
	guardErr error
	// heldDuringSteps records, per mutation step, whether the cleanup
	// lease was still held (the guard's release had not yet run).
	heldDuringSteps []bool
	released        bool
}

func installCleanupSteps16430(t *testing.T, rec *cleanupStepRecorder) {
	t.Helper()
	origGuard, origTransit := cleanupGuard, cleanupCloseTransit
	origDataplane, origFabric, origFRR := cleanupDataplane, cleanupFabric, cleanupClearFRR
	t.Cleanup(func() {
		cleanupGuard, cleanupCloseTransit = origGuard, origTransit
		cleanupDataplane, cleanupFabric, cleanupClearFRR = origDataplane, origFabric, origFRR
	})
	record := func(name string) {
		rec.steps = append(rec.steps, name)
		rec.heldDuringSteps = append(rec.heldDuringSteps, !rec.released)
	}
	cleanupGuard = func() (func(), error) {
		rec.steps = append(rec.steps, "guard")
		if rec.guardErr != nil {
			return nil, rec.guardErr
		}
		return func() { rec.released = true }, nil
	}
	cleanupCloseTransit = func() error { record("transit"); return nil }
	cleanupDataplane = func() error { record("dataplane"); return nil }
	cleanupFabric = func() { record("fabric") }
	cleanupClearFRR = func() error { record("frr"); return nil }
}

// TestCleanupRefusesBesideLiveDaemon16430 is the #16430 acceptance at the
// verb level: with a lease held (a live daemon), the cleanup entry
// refuses non-zero, naming `systemctl stop xpfd`, BEFORE any transit/
// pin/fabric/FRR mutation.
func TestCleanupRefusesBesideLiveDaemon16430(t *testing.T) {
	rec := &cleanupStepRecorder{
		guardErr: fmt.Errorf("cleanup refused: %w; stop the daemon first ('systemctl stop xpfd') and retry",
			daemon.ErrDaemonAlreadyRunning),
	}
	installCleanupSteps16430(t, rec)

	var stdout, stderr bytes.Buffer
	if code := runCleanupSubcommand(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("cleanup beside live daemon exit = %d, want 1 (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "systemctl stop xpfd") {
		t.Fatalf("stderr = %q, want it to name 'systemctl stop xpfd'", stderr.String())
	}
	if !errors.Is(rec.guardErr, daemon.ErrDaemonAlreadyRunning) {
		t.Fatalf("guard err = %v, want ErrDaemonAlreadyRunning chain", rec.guardErr)
	}
	// Only the guard ran: no transit, pin, fabric or FRR mutation.
	if len(rec.steps) != 1 || rec.steps[0] != "guard" {
		t.Fatalf("steps = %v, want only [guard] before refusal", rec.steps)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on refusal", stdout.String())
	}
}

// TestCleanupProceedsWithoutLiveDaemon16430 pins the unchanged no-holder
// path: every step runs in the established order, the singleton is held
// for the whole teardown and released only at the end, and the #10907
// success report is printed with exit 0.
func TestCleanupProceedsWithoutLiveDaemon16430(t *testing.T) {
	rec := &cleanupStepRecorder{}
	installCleanupSteps16430(t, rec)

	var stdout, stderr bytes.Buffer
	if code := runCleanupSubcommand(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("cleanup with no live daemon exit = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	want := []string{"guard", "transit", "dataplane", "fabric", "frr"}
	if len(rec.steps) != len(want) {
		t.Fatalf("steps = %v, want %v", rec.steps, want)
	}
	for i := range want {
		if rec.steps[i] != want[i] {
			t.Fatalf("steps = %v, want %v", rec.steps, want)
		}
	}
	for i, held := range rec.heldDuringSteps {
		if !held {
			t.Fatalf("step %q ran after the cleanup lease was released", rec.steps[i+1])
		}
	}
	if !rec.released {
		t.Fatal("cleanup lease must be released when cleanup finishes")
	}
	if got, want := stdout.String(), "all pinned BPF state and managed routes removed\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

// TestCleanupGuardRunsBeforeArgValidation16430 pins that a stray operand
// is still a usage error and never reaches the guard or any mutation.
func TestCleanupStrayOperandRefusesBeforeGuard16430(t *testing.T) {
	rec := &cleanupStepRecorder{}
	installCleanupSteps16430(t, rec)

	var stdout, stderr bytes.Buffer
	if code := runCleanupSubcommand([]string{"oops"}, &stdout, &stderr); code != 1 {
		t.Fatalf("cleanup with stray operand exit = %d, want 1", code)
	}
	if len(rec.steps) != 0 {
		t.Fatalf("steps = %v, want none for a usage error", rec.steps)
	}
	if !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("stderr = %q, want usage error", stderr.String())
	}
}
