package upgrade

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// #14165: pruning a running candidate kernel.
//
// The promotion gate positively confirms running == CandidateVersion (Gate 2),
// then verify / beacon / BootOrder failures route through revert ->
// restoreKnownGood -> PruneInactiveSlot. Before the fix that prune purged
// linux-image-<candidate> and swept /lib/modules/<candidate> +
// /boot/*-<candidate> from under the LIVE kernel; on the attempt-cap path the
// box then stayed up in that orphaned state (no modules for late loads, no
// boot files), because restoreKnownGood ran BEFORE the cap decision.
//
// The fix defers ONLY the destructive prune while the candidate is running
// (or running is unreadable): the non-destructive restore — BootOrder front,
// watchdog disarm, inactive-slot selector -> known-good — still runs so the
// NEXT boot lands on known-good. The real PruneInactiveSlot re-checks
// uname -r itself as an independent fail-closed layer, so a direct caller
// cannot prune the running kernel either.
//
// RED evidence is recorded in docs/log/14165.md: the fake-system tests below
// fail on origin/master (prune:<slot> recorded while running the candidate)
// and the real-system tests fail there (purge/sweep proceeds while
// runningKernelFn reports the candidate).

// --- Fake-system: verify REJECT while running the candidate must NOT prune,
// but MUST restore the selector for the next boot. ---
func TestKernelPromoteRevertRunningCandidateDefersPrune14165(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.running = "6.18.5-12-generic" // Gate 2: positively running candidate
	f.bootCurrent = "0004"
	f.verifyPass = false // REJECT -> verifyAndPromote -> revert
	f.beaconPass = true

	if _, err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("expected a controlled revert, got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#14165: pruned the RUNNING candidate on revert")
	}
	if !contains(f.calls, "restore-selector:"+SlotB) {
		t.Fatal("#14165: deferred prune must still restore the inactive slot selector to known-good")
	}
	if f.selectors[SlotB] != "6.18.5-10-generic" {
		t.Fatalf("inactive selector = %q, want known-good for the next boot", f.selectors[SlotB])
	}
	if f.order[0] != "0003" {
		t.Fatalf("BootOrder front = %q, want known-good slot 0003 restored", f.order[0])
	}
}

// --- Fake-system: beacon failure while running the candidate must NOT prune. ---
func TestKernelPromoteBeaconFailRunningCandidateDefersPrune14165(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = false // beacon FAILED -> revert

	if _, err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("expected a controlled revert, got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#14165: pruned the RUNNING candidate on beacon-failure revert")
	}
	if f.selectors[SlotB] != "6.18.5-10-generic" {
		t.Fatalf("inactive selector = %q, want known-good", f.selectors[SlotB])
	}
}

// --- Fake-system: BootOrder-promote failure while running the candidate must
// NOT prune (the third verifyAndPromote failure route into revert). ---
func TestKernelPromoteBootOrderFailRunningCandidateDefersPrune14165(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true
	f.bootOrderFrontErr = true // SetBootOrderFront(candID) fails -> revert

	if _, err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("expected a controlled revert, got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#14165: pruned the RUNNING candidate on BootOrder-failure revert")
	}
}

// --- Fake-system: at the attempt cap the box STAYS UP on the candidate; it
// must stay up with its kernel intact (this is the worst case in the issue:
// restoreKnownGood ran before the cap decision, so the stranded boot was the
// pruned one). ---
func TestKernelPromoteRevertCapExceededRunningCandidateDefersPrune14165(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// Seed the journal at the cap so the next revert exceeds it.
	jj, _ := r.loadKernelJournal()
	jj.PromoteAttempts = maxPromoteAttempts
	if err := r.saveKernelJournal(jj); err != nil {
		t.Fatalf("seed capped journal: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = false

	_, err := r.Promote()
	if err == nil {
		t.Fatal("expected the attempt-cap revert error (not rebooting)")
	}
	if errorsIsReverted(err) {
		t.Fatalf("cap-exceeded path must NOT request the exit-3 revert reboot, got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#14165: pruned the RUNNING candidate on the attempt-cap give-up path — the stranded boot keeps a deleted kernel")
	}
	if f.selectors[SlotB] != "6.18.5-10-generic" {
		t.Fatalf("inactive selector = %q, want known-good restored even at the cap", f.selectors[SlotB])
	}
	if f.order[0] != "0003" {
		t.Fatalf("BootOrder front = %q, want known-good 0003 even at the cap", f.order[0])
	}
}

// --- Fake-system: an unreadable running kernel on a revert path must defer
// the prune (cannot prove we are off the candidate — fail closed). BootEntries
// failure enters revert without any prior RunningKernel read. ---
func TestKernelPromoteRevertRunningUnreadableDefersPrune14165(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.entriesErr = fmt.Errorf("efibootmgr timed out")
	f.runningErr = fmt.Errorf("uname -r failure")

	if _, err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("expected a controlled revert, got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#14165: pruned while the running kernel was unreadable (cannot prove off candidate)")
	}
	if f.selectors[SlotB] != "6.18.5-10-generic" {
		t.Fatalf("inactive selector = %q, want known-good restored", f.selectors[SlotB])
	}
}

// --- Fake-system (control): positively OFF the candidate, the prune still
// runs in place. Firmware fell back to known-good, gate cleans up. ---
func TestKernelPromoteOffCandidateStillPrunes14165(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.bootCurrent = "0003" // firmware booted known-good slot
	f.running = "6.18.5-10-generic"

	if _, err := r.Promote(); err != nil {
		t.Fatalf("known-good cleanup should succeed, got %v", err)
	}
	if !contains(f.calls, "prune:"+SlotB) {
		t.Fatal("control: prune must still run when positively off the candidate")
	}
}

// --- Real-system: PruneInactiveSlot itself refuses while uname -r reports
// the candidate — no purge attempted, no files swept, selector untouched by
// the destructive path (the runner restores it via the separate method). ---
func TestPruneInactiveSlot_RunningCandidateRefused14165(t *testing.T) {
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purgeCalled := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return cand, nil },
		pkgInstalledFn:  func(string) (bool, error) { return true, nil },
		aptGetFn: func(args ...string) error {
			purgeCalled = true
			return nil
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("#14165: prune of the RUNNING candidate must be refused")
	}
	if !strings.Contains(err.Error(), "running kernel") {
		t.Errorf("error should name the running-kernel deferral: %v", err)
	}
	if purgeCalled {
		t.Error("#14165: apt purge attempted against the running kernel")
	}
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s deleted while running it (%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s deleted while running it (%v)", cand, statErr)
	}
	// The destructive path must not have rewritten the selector either: on
	// master the selector write is prune's first step, so a refusal AFTER it
	// would still prove the guard runs before any mutation. The selector file
	// must not point at known-good via THIS call (the runner does that via
	// RestoreInactiveSlotSelector).
	if sel, selErr := sys.ReadSlotSelector("xpf-B"); selErr == nil && sel == knownGood {
		t.Error("#14165: refused prune still rewrote the selector — guard must precede all mutation")
	}
}

// --- Real-system: an unreadable uname -r refuses the prune (fail closed). ---
func TestPruneInactiveSlot_RunningUnreadableRefused14165(t *testing.T) {
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purgeCalled := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return "", errors.New("uname -r boom") },
		pkgInstalledFn:  func(string) (bool, error) { return false, nil },
		aptGetFn: func(args ...string) error {
			purgeCalled = true
			return nil
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("#14165: prune with unreadable running kernel must be refused (fail closed)")
	}
	if purgeCalled {
		t.Error("#14165: purge attempted while running kernel unreadable")
	}
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s swept while running kernel unreadable (%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s swept while running kernel unreadable (%v)", cand, statErr)
	}
}

// --- Real-system (control): running a DIFFERENT kernel, the prune proceeds
// exactly as before (purge + confirmed-absent sweep + selector restore). ---
func TestPruneInactiveSlot_OffCandidatePrunes14165(t *testing.T) {
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purged := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		pkgInstalledFn:  func(string) (bool, error) { return !purged, nil },
		aptGetFn: func(args ...string) error {
			if len(args) > 0 && args[0] == "purge" {
				purged = true
			}
			return nil
		},
	}

	if err := sys.PruneInactiveSlot("xpf-B", knownGood, cand); err != nil {
		t.Fatalf("control: prune off the candidate should succeed, got %v", err)
	}
	if _, statErr := os.Stat(modulesDir); !os.IsNotExist(statErr) {
		t.Errorf("control: /lib/modules/%s should be swept off-candidate (stat err=%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); !os.IsNotExist(statErr) {
		t.Errorf("control: /boot/vmlinuz-%s should be swept off-candidate (stat err=%v)", cand, statErr)
	}
	if sel, selErr := sys.ReadSlotSelector("xpf-B"); selErr != nil || sel != knownGood {
		t.Errorf("control: selector = %q (err %v), want known-good %q", sel, selErr, knownGood)
	}
}

// --- Real-system: RestoreInactiveSlotSelector alone never purges or sweeps,
// even while running the candidate (it is the deferred path's only mutation). ---
func TestRestoreInactiveSlotSelector_NeverDestructive14165(t *testing.T) {
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return cand, nil },
	}

	if err := sys.RestoreInactiveSlotSelector("xpf-B", knownGood); err != nil {
		t.Fatalf("selector restore should succeed while running candidate, got %v", err)
	}
	if sel, selErr := sys.ReadSlotSelector("xpf-B"); selErr != nil || sel != knownGood {
		t.Fatalf("selector = %q (err %v), want known-good %q", sel, selErr, knownGood)
	}
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("selector restore deleted /lib/modules/%s (%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("selector restore deleted /boot/vmlinuz-%s (%v)", cand, statErr)
	}
}
