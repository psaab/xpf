package upgrade

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// fakeKernelSystem is a unit-test double for KernelSystem. It models the
// firmware/apt/boot surface as in-memory state and records the operations the
// state machine performs, so the Arm/Promote/revert logic is exercised without
// a live UEFI host.
type fakeKernelSystem struct {
	uefi        bool
	efibootmgr  bool
	entries     map[string]string // label -> Boot#### id
	order       []string          // BootOrder (front = default)
	submenuOK   bool
	wdPresent   bool
	wdPersist   bool
	freeBytes   map[string]uint64
	running     string
	held        bool
	installRet  string // uname -r returned by InstallCandidateKernel
	installErr  error
	moveDefault bool // if true, InstallCandidateKernel moves the default

	selectors map[string]string // slot -> uname -r
	bootNext  string
	wdArmed   bool

	entriesErr error

	bootCurrent       string
	bootCurrentErr    error
	getBootNextErr    error  // #5847: force a readback error (stay ARMING)
	clearBootNextErr  error  // #6758: force the un-undoable case (NVRAM stays armed)
	getBootNextRet    string // #5847: override readback (firmware "lied"); "" => mirror bootNext
	runningErr        error
	armWatchdogErr    error
	disarmWatchdogErr error
	bootOrderFrontErr bool
	verifyPass        bool
	verifyErr         error
	beaconPass        bool
	beaconErr         error

	rebooted        bool
	promotionMarker string
	lastRoll        KernelRollOutcome
	lastRollWrites  int
	lastRollErr     error
	calls           []string
	now             time.Time
}

func newFakeKernelSystem() *fakeKernelSystem {
	return &fakeKernelSystem{
		uefi:       true,
		efibootmgr: true,
		// active slot = xpf-A (Boot0003) first in BootOrder; xpf-B = Boot0004.
		entries:   map[string]string{SlotA: "0003", SlotB: "0004"},
		order:     []string{"0003", "0004", "0001"},
		submenuOK: true,
		wdPresent: true,
		wdPersist: true,
		freeBytes: map[string]uint64{"/boot": 512 << 20, "/boot/efi": 80 << 20},
		running:   "6.18.5-10-generic",
		held:      true,
		selectors: map[string]string{SlotA: "6.18.5-10-generic", SlotB: "6.18.5-10-generic"},
		now:       time.Unix(1_700_000_000, 0),
	}
}

func (f *fakeKernelSystem) log(s string) { f.calls = append(f.calls, s) }

func (f *fakeKernelSystem) IsUEFI() bool       { return f.uefi }
func (f *fakeKernelSystem) EfibootmgrOK() bool { return f.efibootmgr }
func (f *fakeKernelSystem) BootEntries() (map[string]string, error) {
	if f.entriesErr != nil {
		return nil, f.entriesErr
	}
	cp := map[string]string{}
	for k, v := range f.entries {
		cp[k] = v
	}
	return cp, nil
}
func (f *fakeKernelSystem) BootOrder() ([]string, error) {
	return append([]string(nil), f.order...), nil
}
func (f *fakeKernelSystem) GrubSubmenuDisabled() (bool, error) { return f.submenuOK, nil }
func (f *fakeKernelSystem) WatchdogStatus() (bool, bool)       { return f.wdPresent, f.wdPersist }
func (f *fakeKernelSystem) FreeBytes(p string) (uint64, error) {
	if v, ok := f.freeBytes[p]; ok {
		return v, nil
	}
	return 1 << 40, nil
}
func (f *fakeKernelSystem) RunningKernel() (string, error) { return f.running, f.runningErr }
func (f *fakeKernelSystem) KernelHeld() (bool, error)      { return f.held, nil }
func (f *fakeKernelSystem) InstallCandidateKernel(v string) (string, error) {
	f.log("install:" + v)
	if f.installErr != nil {
		return "", f.installErr
	}
	if f.moveDefault {
		// simulate dpkg postinst update-grub moving the default to a new id
		f.order = append([]string{"0099"}, f.order...)
	}
	if f.installRet != "" {
		return f.installRet, nil
	}
	return v, nil
}
func (f *fakeKernelSystem) DefaultBootEntry() (string, error) {
	if len(f.order) == 0 {
		return "", nil
	}
	return f.order[0], nil
}
func (f *fakeKernelSystem) WriteSlotSelector(slot, unameR string) error {
	f.log("write-selector:" + slot + "=" + unameR)
	f.selectors[slot] = unameR
	return nil
}
func (f *fakeKernelSystem) ReadSlotSelector(slot string) (string, error) {
	return f.selectors[slot], nil
}
func (f *fakeKernelSystem) SetBootNext(id string) error {
	f.log("bootnext:" + id)
	f.bootNext = id
	return nil
}

// ClearBootNext mirrors efibootmgr --delete-bootnext (#6758): it drops the
// one-shot unconditionally, so clearing an already-absent BootNext succeeds.
// clearBootNextErr injects the un-undoable case — NVRAM stays armed while the
// journal records ARMING, which is the divergence the arm must report loudly.
func (f *fakeKernelSystem) ClearBootNext() error {
	f.log("bootnext-clear")
	if f.clearBootNextErr != nil {
		return f.clearBootNextErr
	}
	f.bootNext = ""
	return nil
}

// GetBootNext mirrors what SetBootNext stored (firmware accepted the one-shot)
// unless a test injects getBootNextErr (readback error) or getBootNextRet
// (firmware silently dropped/partial-wrote the variable → readback disagrees).
func (f *fakeKernelSystem) GetBootNext() (string, error) {
	f.log("get-bootnext")
	if f.getBootNextErr != nil {
		return "", f.getBootNextErr
	}
	if f.getBootNextRet != "" {
		return f.getBootNextRet, nil
	}
	return f.bootNext, nil
}
func (f *fakeKernelSystem) ArmWatchdog() error {
	if f.armWatchdogErr != nil {
		return f.armWatchdogErr
	}
	f.wdArmed = true
	return nil
}
func (f *fakeKernelSystem) Reboot() error { f.log("reboot"); f.rebooted = true; return nil }
func (f *fakeKernelSystem) WritePromotionMarker(u string) error {
	f.promotionMarker = u
	return nil
}
func (f *fakeKernelSystem) ReadPromotionMarker() (string, error) { return f.promotionMarker, nil }
func (f *fakeKernelSystem) ClearPromotionMarker() error          { f.promotionMarker = ""; return nil }
func (f *fakeKernelSystem) ClearRollLease() error                { return nil }

// #6495 durable last-roll record. lastRollWrites counts writes so a test can
// assert the record is written EXACTLY once per completed roll — a second
// write on the same roll would overwrite a real outcome with a later one.
func (f *fakeKernelSystem) WriteLastRoll(rec KernelRollOutcome) error {
	if f.lastRollErr != nil {
		return f.lastRollErr
	}
	f.lastRoll = rec
	f.lastRollWrites++
	return nil
}
func (f *fakeKernelSystem) ReadLastRoll() (KernelRollOutcome, error) {
	return f.lastRoll, nil
}
func (f *fakeKernelSystem) BootCurrent() (string, error) {
	if f.bootCurrentErr != nil {
		return "", f.bootCurrentErr
	}
	if f.bootCurrent != "" {
		return f.bootCurrent, nil
	}
	return f.bootNext, nil // by default the firmware honored BootNext
}
func (f *fakeKernelSystem) VerifyDataplane() (bool, error) { return f.verifyPass, f.verifyErr }
func (f *fakeKernelSystem) ForwardBeacon(time.Duration) (bool, error) {
	return f.beaconPass, f.beaconErr
}
func (f *fakeKernelSystem) SetBootOrderFront(id string) error {
	if f.bootOrderFrontErr {
		return fmt.Errorf("simulated bootorder write failure")
	}
	f.log("bootorder-front:" + id)
	// non-destructive: move id to front, preserve the rest in order
	out := []string{id}
	for _, e := range f.order {
		if e != id {
			out = append(out, e)
		}
	}
	f.order = out
	return nil
}
func (f *fakeKernelSystem) DisarmWatchdog() error {
	if f.disarmWatchdogErr != nil {
		return f.disarmWatchdogErr
	}
	f.wdArmed = false
	return nil
}
func (f *fakeKernelSystem) PruneInactiveSlot(slot, kg, cand string) error {
	f.log("prune:" + slot)
	f.selectors[slot] = kg
	return nil
}
func (f *fakeKernelSystem) Now() time.Time { return f.now }

func newKernelRunner(t *testing.T, f *fakeKernelSystem) *KernelRunner {
	t.Helper()
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	withBootGateJournal(t, journal)
	r, err := NewKernelRunner(KernelConfig{
		JournalPath: journal,
		Sys:         f,
		Logf:        func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewKernelRunner: %v", err)
	}
	return r
}

// withBootGateJournal models a box whose boot-time promotion gate reads
// `path`, restoring the production value afterwards.
//
// Every test that arms needs this, because Arm refuses a journal the gate does
// not read (#6631) and every test journal is a t.TempDir(). Stating it that way
// round — "on this box the gate reads here" — is what keeps the fixtures
// truthful; a flag that merely switched the check off would let a test assert
// an arm that production would reject.
func withBootGateJournal(t *testing.T, path string) {
	t.Helper()
	orig := bootGateJournalPath
	t.Cleanup(func() { bootGateJournalPath = orig })
	bootGateJournalPath = path
}

func contains(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

func errorsIsReverted(err error) bool { return errors.Is(err, ErrKernelReverted) }

// --- Arm happy path: preflight -> install -> arm -> reboot, all journaled. ---
func TestKernelArmHappyPath(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !f.rebooted {
		t.Fatal("expected a reboot at the end of Arm")
	}
	// inactive slot (xpf-B, since A is active) selector points at the candidate
	if f.selectors[SlotB] != "6.18.5-12-generic" {
		t.Fatalf("inactive slot selector = %q, want candidate", f.selectors[SlotB])
	}
	// active slot selector untouched
	if f.selectors[SlotA] != "6.18.5-10-generic" {
		t.Fatalf("active slot selector moved to %q", f.selectors[SlotA])
	}
	// BootNext armed to the inactive slot id (0004)
	if f.bootNext != "0004" {
		t.Fatalf("BootNext = %q, want 0004 (xpf-B)", f.bootNext)
	}
	// journal reached ARMED
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateArmed {
		t.Fatalf("journal state = %s, want ARMED", j.State)
	}
	if j.InactiveSlot != SlotB || j.ActiveSlot != SlotA {
		t.Fatalf("slots active=%s inactive=%s, want A/B", j.ActiveSlot, j.InactiveSlot)
	}
}

// --- Promote happy path: gates pass -> BootOrder reorder + journal cleared. ---
func TestKernelPromoteHappyPath(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// candidate boot: firmware honored BootNext (BootCurrent=0004), kernel matches
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true

	if err := r.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	// candidate slot (0004) now front of BootOrder (non-destructive)
	if f.order[0] != "0004" {
		t.Fatalf("BootOrder front = %q, want 0004 (promoted candidate)", f.order[0])
	}
	if !contains(f.order, "0003") {
		t.Fatal("former active slot 0003 dropped from BootOrder (must be preserved as rollback)")
	}
	if f.wdArmed {
		t.Fatal("watchdog still armed after promote")
	}
	// journal cleared on terminal success
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateInit {
		t.Fatalf("journal not cleared after promote (state=%s)", j.State)
	}
}

// --- Revert: verify REJECT -> no promote, BootOrder unchanged, journal cleared. ---
func TestKernelPromoteRevertOnVerifyReject(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	origOrder := append([]string(nil), f.order...)
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = false // REJECT
	f.beaconPass = true

	err := r.Promote()
	if err == nil {
		t.Fatal("expected a revert error on verify REJECT")
	}
	if f.order[0] != origOrder[0] {
		t.Fatalf("BootOrder default changed on revert (%v -> %v)", origOrder, f.order)
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("promoted the candidate despite verify REJECT")
	}
	if !contains(f.calls, "prune:"+SlotB) {
		t.Fatal("did not prune the inactive slot on revert")
	}
	// inactive selector reset to known-good
	if f.selectors[SlotB] != "6.18.5-10-generic" {
		t.Fatalf("inactive selector not reset on revert: %q", f.selectors[SlotB])
	}
}

// --- Revert: forward beacon fail (structural verify passed but no forward). ---
func TestKernelPromoteRevertOnBeaconFail(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	_ = r.Arm("6.18.5-12-generic")
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = false // forwards-not

	if err := r.Promote(); err == nil {
		t.Fatal("expected revert on beacon fail")
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("promoted despite forward-beacon failure")
	}
}

// TestKernelPromoteCountsNVRAMReadTimeoutAsRevert10761 pins the caller side of
// the bounded efibootmgr command: a timed-out first BootEntries read must enter
// revert(), persist the attempt before cleanup, and request the controlled
// exit-3 reboot rather than surfacing an infra error for systemd's uncounted
// OnFailure reboot.
func TestKernelPromoteCountsNVRAMReadTimeoutAsRevert10761(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	attemptLogged := false
	r.cfg.Logf = func(_ string, args ...any) {
		if len(args) >= 3 && args[1] == 1 && args[2] == maxPromoteAttempts {
			attemptLogged = true
		}
	}

	f.entriesErr = fmt.Errorf("efibootmgr timed out: context deadline exceeded")

	err := r.Promote()
	if !errorsIsReverted(err) {
		t.Fatalf("Promote error = %v, want a controlled revert for the timed-out NVRAM read", err)
	}
	if !attemptLogged {
		t.Fatal("timed-out NVRAM read did not persist/count attempt 1 before cleanup")
	}

	if f.lastRoll.Outcome != RollOutcomeReverted {
		t.Fatalf("last-roll outcome = %q, want %q", f.lastRoll.Outcome, RollOutcomeReverted)
	}
	if !contains(f.calls, "prune:"+SlotB) {
		t.Fatal("timed-out NVRAM read did not enter revert cleanup")
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatalf("load journal after counted revert: %v", err)
	}
	if j.State != KernelStateInit {
		t.Fatalf("journal state after controlled reboot request = %s, want cleared INIT", j.State)
	}
}

// --- Firmware fell back (BootCurrent != candidate): ALREADY on known-good ->
// clean up in place, NO reboot (r1 AGY: rebooting here is redundant + loops on
// a read-only-root journal). Promote() returns nil (exit 0, continue boot). ---
func TestKernelPromoteAlreadyKnownGoodNoReboot(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	_ = r.Arm("6.18.5-12-generic")
	// firmware ignored/fell-back: BootCurrent is the ACTIVE slot, not candidate
	f.bootCurrent = "0003"
	f.running = "6.18.5-10-generic"
	f.verifyPass = true
	f.beaconPass = true

	// NO error (no reboot requested — we're already on known-good).
	if err := r.Promote(); err != nil {
		t.Fatalf("expected nil (already on known-good, no reboot), got %v", err)
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("promoted despite firmware not booting the candidate")
	}
	// the candidate slot was cleaned up
	if !contains(f.calls, "prune:"+SlotB) {
		t.Fatal("did not prune the un-promoted candidate on known-good cleanup")
	}
	// journal cleared (no terminal-state stuck ARMED that would re-run forever)
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateInit {
		t.Fatalf("journal not cleared on known-good cleanup (state=%s)", j.State)
	}
}

// --- Revert reboot is bounded: after maxPromoteAttempts the gate stops
// requesting reboots (r1 AGY catastrophic read-only-root loop guard). We
// simulate the candidate-booted-but-gate-fails path repeatedly with a journal
// that DOES persist; the attempt counter caps the reboots. ---
func TestKernelPromoteRevertAttemptsCapped(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	_ = r.Arm("6.18.5-12-generic")
	// candidate DID boot (BootCurrent==candidate) but the gate fails (verify
	// REJECT), so each Promote() is a real revert that requests a reboot.
	f.bootCurrent = "0004"
	f.running = "6.18.5-12-generic"
	f.verifyPass = false

	reverts := 0
	// Re-arm-free: simulate the journal surviving across "reboots" by NOT
	// clearing it between calls — but revert() clears on success, so to model
	// the read-only-root case we re-write ARMED before each call.
	for i := 0; i < maxPromoteAttempts+2; i++ {
		// restore ARMED (model: journal could not be cleared on a R/O root)
		jj, _ := r.loadKernelJournal()
		if jj.State == KernelStateInit {
			jj = &KernelJournal{
				CandidateVersion: "6.18.5-12-generic", KnownGoodVersion: "6.18.5-10-generic",
				ActiveSlot: SlotA, InactiveSlot: SlotB, State: KernelStateArmed,
				PromoteAttempts: i,
			}
			_ = r.saveKernelJournal(jj)
		}
		err := r.Promote()
		if errorsIsReverted(err) {
			reverts++
		}
	}
	if reverts > maxPromoteAttempts {
		t.Fatalf("revert reboots not capped: %d reverts > cap %d", reverts, maxPromoteAttempts)
	}
}

// --- Revert: candidate booted but wrong uname (selector/kernel mismatch). ---
func TestKernelPromoteRevertOnKernelMismatch(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	_ = r.Arm("6.18.5-12-generic")
	f.bootCurrent = "0004"
	f.running = "6.18.5-99-WRONG" // not the candidate
	f.verifyPass = true
	f.beaconPass = true

	if err := r.Promote(); err == nil {
		t.Fatal("expected revert on uname mismatch")
	}
}

// --- Preflight fail-closed: not UEFI. ---
func TestKernelArmAbortsNonUEFI(t *testing.T) {
	f := newFakeKernelSystem()
	f.uefi = false
	r := newKernelRunner(t, f)
	err := r.Arm("6.18.5-12-generic")
	if !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("want ErrKernelChannelUnavailable, got %v", err)
	}
	if f.rebooted {
		t.Fatal("must not reboot when preflight fails")
	}
}

// --- Preflight fail-closed: A/B slots not registered. ---
func TestKernelArmAbortsSlotsUnregistered(t *testing.T) {
	f := newFakeKernelSystem()
	delete(f.entries, SlotB)
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("want unavailable on missing slot, got %v", err)
	}
}

// --- Preflight: BootOrder front is neither A/B (non-xpf default). ---
func TestKernelArmAbortsForeignDefault(t *testing.T) {
	f := newFakeKernelSystem()
	f.order = []string{"0001", "0003", "0004"} // 0001 (firmware) is default
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("want unavailable on foreign default, got %v", err)
	}
}

// --- Preflight fail-closed: strict watchdog policy, no persistent watchdog. ---
func TestKernelArmStrictWatchdogAborts(t *testing.T) {
	f := newFakeKernelSystem()
	f.wdPersist = false
	journal := filepath.Join(t.TempDir(), "k.state")
	withBootGateJournal(t, journal)
	r, _ := NewKernelRunner(KernelConfig{
		JournalPath:    journal,
		Sys:            f,
		StrictWatchdog: true,
	})
	if err := r.Arm("6.18.5-12-generic"); !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("want unavailable under D1 without persistent watchdog, got %v", err)
	}
}

// --- D2: no persistent watchdog -> proceeds (BootNext closes the loop). ---
func TestKernelArmD2ProceedsWithoutPersistentWatchdog(t *testing.T) {
	f := newFakeKernelSystem()
	f.wdPersist = false        // present but not verified-persistent
	r := newKernelRunner(t, f) // StrictWatchdog defaults false (D2)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("D2 should proceed, got %v", err)
	}
	if !f.rebooted {
		t.Fatal("D2 should arm + reboot")
	}
}

// --- Preflight fail-closed: insufficient /boot space. ---
func TestKernelArmAbortsLowBootSpace(t *testing.T) {
	f := newFakeKernelSystem()
	f.freeBytes["/boot"] = 1 << 20 // 1 MiB, below the 64 MiB margin
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("want unavailable on low /boot space, got %v", err)
	}
}

// --- Install aborts if the dpkg postinst moves the permanent default. ---
func TestKernelInstallAbortsIfDefaultMoves(t *testing.T) {
	f := newFakeKernelSystem()
	f.moveDefault = true
	r := newKernelRunner(t, f)
	err := r.Arm("6.18.5-12-generic")
	if err == nil || errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("want a non-unavailable install error on moved default, got %v", err)
	}
	if f.rebooted {
		t.Fatal("must not reboot if the default moved")
	}
}

// --- Install aborts if the kernel set is not re-held after install. ---
func TestKernelInstallAbortsIfNotReheld(t *testing.T) {
	f := newFakeKernelSystem()
	f.held = false
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err == nil {
		t.Fatal("want error if kernel not re-held after install")
	}
	if f.rebooted {
		t.Fatal("must not reboot if rehold failed")
	}
}

// --- Idempotent resume: a second Arm after ARMED refuses (already armed). ---
func TestKernelArmRefusesWhenAlreadyArmed(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("first Arm: %v", err)
	}
	f.rebooted = false
	err := r.Arm("6.18.5-13-generic")
	if err == nil {
		t.Fatal("second Arm should refuse while a candidate is armed")
	}
	if f.rebooted {
		t.Fatal("second Arm must not reboot")
	}
}

// --- Promote on an ordinary boot (nothing armed) is a no-op. ---
func TestKernelPromoteNoOpWhenNotArmed(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Promote(); err != nil {
		t.Fatalf("Promote on ordinary boot should be a no-op, got %v", err)
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("ordinary boot must not touch BootOrder")
	}
}

// --- IsArmed reflects the journal state. ---
func TestKernelIsArmed(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	armed, _, _ := r.IsArmed()
	if armed {
		t.Fatal("not armed initially")
	}
	_ = r.Arm("6.18.5-12-generic")
	armed, j, _ := r.IsArmed()
	if !armed || j.CandidateVersion != "6.18.5-12-generic" {
		t.Fatalf("expected armed candidate, got armed=%v j=%+v", armed, j)
	}
}

// --- Arm refuses to resume with a DIFFERENT candidate than the journaled one
// (r1 Copilot: don't install version B against a version-A journal). ---
func TestKernelArmRefusesResumeWithDifferentCandidate(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	// Seed a journal already past PREFLIGHT targeting version A.
	j := &KernelJournal{
		CandidateVersion: "6.18.5-12-generic", KnownGoodVersion: "6.18.5-10-generic",
		ActiveSlot: SlotA, InactiveSlot: SlotB, State: KernelStatePreflight,
	}
	if err := r.saveKernelJournal(j); err != nil {
		t.Fatalf("seed journal: %v", err)
	}
	// Arm with a DIFFERENT version must refuse and not reboot.
	if err := r.Arm("6.18.5-13-generic"); err == nil {
		t.Fatal("expected refusal to resume with a different candidate")
	}
	if f.rebooted {
		t.Fatal("must not reboot on a candidate-mismatch resume")
	}
	// Arm with the SAME journaled version resumes (installs + arms + reboots).
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("resume with the journaled candidate should proceed: %v", err)
	}
	if !f.rebooted {
		t.Fatal("resume with the journaled candidate should reach reboot")
	}
}

// --- revert disarms the watchdog (r1 Copilot: an armed watchdog must not keep
// firing after the fallback reboot). ---
func TestKernelRevertDisarmsWatchdog(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	_ = r.Arm("6.18.5-12-generic")
	if !f.wdArmed {
		t.Fatal("Arm should have armed the watchdog")
	}
	// candidate boots but verify REJECTs -> revert.
	f.bootCurrent = "0004"
	f.running = "6.18.5-12-generic"
	f.verifyPass = false
	if err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("expected revert, got %v", err)
	}
	if f.wdArmed {
		t.Fatal("revert must disarm the watchdog")
	}
}

// --- promote with a BootOrder-reorder failure REVERTS (r1 Copilot: don't leave
// the candidate running un-promoted as a non-revert infra error). ---
func TestKernelPromoteRevertsOnBootOrderFailure(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	_ = r.Arm("6.18.5-12-generic")
	f.bootCurrent = "0004"
	f.running = "6.18.5-12-generic"
	f.verifyPass = true
	f.beaconPass = true
	f.bootOrderFrontErr = true // SetBootOrderFront fails

	err := r.Promote()
	if !errorsIsReverted(err) {
		t.Fatalf("expected a REVERT when promote BootOrder reorder fails, got %v", err)
	}
}

// --- #4872 A: a transient BootCurrent read error while ACTUALLY running the
// candidate must NOT prune the running candidate; it runs the verification gate
// (and a healthy candidate still promotes). ---
func TestKernelPromoteBootCurrentErrRunningCandidateDoesNotPrune(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// The candidate DID boot, but efibootmgr/NVRAM read of BootCurrent is flaky.
	f.bootCurrentErr = fmt.Errorf("simulated efibootmgr read failure")
	f.running = "6.18.5-12-generic" // we ARE running the candidate
	f.verifyPass = true
	f.beaconPass = true

	if err := r.Promote(); err != nil {
		t.Fatalf("healthy candidate must promote despite a BootCurrent read error, got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#4872 A: pruned the RUNNING candidate on a transient BootCurrent read error")
	}
	if !contains(f.calls, "bootorder-front:0004") {
		t.Fatal("#4872 A: candidate not promoted on the fail-closed verify path")
	}
}

// --- #4872 A: BootCurrent AND RunningKernel both unreadable -> indeterminate.
// Fail closed: NO prune, NO reboot, surface a NON-revert error, journal
// preserved so the next boot re-runs the gate. ---
func TestKernelPromoteIndeterminateFailsClosed(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.bootCurrentErr = fmt.Errorf("efibootmgr read failure")
	f.runningErr = fmt.Errorf("uname -r failure")

	err := r.Promote()
	if err == nil {
		t.Fatal("#4872 A: indeterminate boot state must surface an error, not proceed as healthy")
	}
	if errorsIsReverted(err) {
		t.Fatalf("#4872 A: indeterminate must NOT be a revert (exit-3 reboot-loop risk), got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#4872 A: pruned the candidate while unable to prove we are off it")
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateArmed {
		t.Fatalf("#4872 A: journal not preserved on indeterminate state (state=%s)", j.State)
	}
}

// --- #4872 A: BootCurrent unreadable but RunningKernel positively identifies a
// NON-candidate (known-good) kernel -> pruning the un-promoted candidate is
// safe; no reboot, no promote. ---
func TestKernelPromoteBootCurrentErrRunningKnownGoodCleansUp(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.bootCurrentErr = fmt.Errorf("efibootmgr read failure")
	f.running = "6.18.5-10-generic" // known-good, NOT the candidate

	if err := r.Promote(); err != nil {
		t.Fatalf("on positively-known-good boot, expect nil cleanup, got %v", err)
	}
	if !contains(f.calls, "prune:"+SlotB) {
		t.Fatal("expected the un-promoted candidate pruned when positively on known-good")
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("must not promote when not running the candidate")
	}
}

// --- #4872 B: under StrictWatchdog (D1) an ArmWatchdog failure ABORTS the arm
// (no BootNext, no reboot) rather than silently rebooting into a candidate with
// no functioning watchdog. ---
func TestKernelArmStrictWatchdogArmFailureAborts(t *testing.T) {
	f := newFakeKernelSystem()
	f.armWatchdogErr = fmt.Errorf("simulated /dev/watchdog I/O error")
	journal := filepath.Join(t.TempDir(), "k.state")
	withBootGateJournal(t, journal)
	r, _ := NewKernelRunner(KernelConfig{
		JournalPath:    journal,
		Sys:            f,
		StrictWatchdog: true,
	})
	err := r.Arm("6.18.5-12-generic")
	if !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("#4872 B: strict-watchdog arm failure must abort with ErrKernelChannelUnavailable, got %v", err)
	}
	if f.rebooted {
		t.Fatal("#4872 B: must NOT reboot into a candidate with no functioning watchdog under D1")
	}
	if f.bootNext != "" {
		t.Fatal("#4872 B: must NOT set BootNext when the strict arm failed")
	}
	j, _ := r.loadKernelJournal()
	if j.State.atLeast(KernelStateArmed) {
		t.Fatalf("#4872 B: journal advanced to %s despite the strict arm failure", j.State)
	}
}

// --- #4872 B: under D2 (best-effort) an ArmWatchdog failure is logged and the
// arm still proceeds (BootNext is the loop-safety). ---
func TestKernelArmD2WatchdogArmFailureProceeds(t *testing.T) {
	f := newFakeKernelSystem()
	f.armWatchdogErr = fmt.Errorf("simulated /dev/watchdog I/O error")
	r := newKernelRunner(t, f) // D2 (StrictWatchdog defaults false)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("D2 should proceed despite an arm failure, got %v", err)
	}
	if !f.rebooted {
		t.Fatal("D2 should still arm BootNext + reboot")
	}
}
