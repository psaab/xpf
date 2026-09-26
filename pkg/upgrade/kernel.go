// Package upgrade — LANE-1 verify-gated in-place kernel channel (#1930 INC-1).
//
// The embedded AF_XDP shim .o is kernel-space-verifier-gated (#1864): a kernel
// the .o has never been verified against can REJECT it at boot, leaving the box
// with no dataplane. verify-dataplane runs the KERNEL verifier, so a candidate
// kernel can only be validated from inside a boot of that kernel — the channel
// is therefore "boot the candidate once, verify from inside it, promote-or-
// revert", NOT "verify-then-set-default" (plan §2 invariant 1).
//
// Substrate A4 (plan §3.1, converged over 6 review rounds): two FIXED,
// permanently-registered UEFI boot slots (xpf-A / xpf-B), each an ESP dir with
// shim+grub + a GRUB-script "selector" file that sets xpf_slot_kernel /
// xpf_slot_initrd. The SHARED /boot/grub/grub.cfg branches on $cmdpath (the dir
// GRUB was launched from) via an /etc/grub.d/09_xpf drop-in that sources the
// slot selector — signed grub ignores a per-dir grub.cfg (its prefix is signed),
// so selection is by $cmdpath, never a per-slot grub.cfg or a GRUB env write
// (which Secure-Boot lockdown forbids). A candidate is armed by pointing the
// INACTIVE slot's selector at it (atomic ESP write) and `efibootmgr --bootnext
// <inactive-slot>`. The UEFI FIRMWARE clears BootNext before launch, so a
// candidate that hangs at ANY stage (incl. pre-Linux) + a reset falls through
// the permanent BootOrder to the known-good slot — the boot-LOOP is closed
// unconditionally, with no bootloader/OS write at the failing moment.
//
// HA orchestration (the cross-node "never both down" sequence) is EXTERNAL
// (INC-2, scripts/deploy) because the reboot kills any in-process driver; this
// file owns ONE node's local arm / verify / promote / revert state machine.
//
// Design invariants mirror runner.go:
//   - PRE-REBOOT phases (PREFLIGHT, INSTALL, ARM) are abortable: a failure
//     leaves the running kernel + active slot untouched (no BootNext armed, or
//     an armed-but-unbooted BootNext that the firmware will clear on the next
//     boot anyway).
//   - Every transition is journaled (temp+fsync+rename) so a crash/reboot is
//     recoverable and idempotent.
//   - The ACTIVE slot's kernel is NEVER pruned (the A/B rollback guarantee);
//     GC removes only the un-promoted candidate + its inactive-slot staging.
//   - Promotion is a NON-destructive BootOrder reorder (preserve PXE/recovery).
package upgrade

import (
	"errors"
	"time"
)

// KernelState is a phase of the kernel-channel state machine. Each value is the
// COMPLETED milestone; the journal records the last finished phase so a reboot
// resumes at the next one. The pre-reboot order is total; the post-reboot
// promotion/revert path is reached only after a real candidate boot.
type KernelState string

const (
	// KernelStateInit is the implicit pre-start phase (no journal yet).
	KernelStateInit KernelState = ""

	// KernelStatePreflight: all pre-asserts passed (UEFI+efibootmgr, both
	// A/B slots registered with the active slot first in BootOrder, GRUB
	// submenu disabled, watchdog present-or-overridden, free /boot and ESP
	// headroom). No mutation yet.
	KernelStatePreflight KernelState = "PREFLIGHT"

	// KernelStateInstalled: the candidate kernel package(s) were installed
	// into /boot (unhold -> install -> rehold), update-initramfs and
	// update-grub succeeded, and the permanent known-good default did NOT
	// move (re-asserted). The candidate is on disk but NOT armed.
	KernelStateInstalled KernelState = "INSTALLED"

	// KernelStateArming: PREPARED-INTENT to arm, durably recorded BEFORE any
	// NVRAM mutation (#5847). The INACTIVE slot's selector is (being) written,
	// but `efibootmgr --bootnext` has NOT been positively confirmed via a
	// readback. A journal stuck HERE — a crash between recording intent and the
	// verified ARMED transition — is NOT a genuine in-flight trial: the firmware
	// still boots the known-good default (no confirmed one-shot), so `Arm` may
	// RE-ARM from ARMING and self-recovery must NOT suppress expired-lease
	// failback on it (the drained node can rejoin). Only after a POSITIVE
	// BootNext readback does the runner transition ARMING -> ARMED.
	KernelStateArming KernelState = "ARMING"

	// KernelStateArmed: the INACTIVE slot's selector points at the candidate
	// (atomic ESP write) AND `efibootmgr --bootnext <inactive-slot>` is set AND
	// was POSITIVELY READ BACK (#5847), so the next boot is genuinely the
	// one-shot candidate trial. Only this VERIFIED state counts as an in-flight
	// trial (IsArmed true; self-recovery suppresses failback). The armed boot id
	// + a per-attempt nonce are recorded for provenance.
	KernelStateArmed KernelState = "ARMED"

	// KernelStatePromoted: on the candidate boot the promotion gate passed
	// (BootCurrent==candidate slot, uname -r==candidate, verify-dataplane
	// PASS, forward beacon PASS) and the BootOrder was reordered candidate-
	// first (non-destructive). Terminal success.
	KernelStatePromoted KernelState = "PROMOTED"

	// KernelStateReverted: the candidate did NOT pass the gate (REJECT /
	// wrong-kernel / beacon fail), so it was NOT promoted; the box is (or is
	// being) rebooted to the known-good slot. Terminal failure (recoverable —
	// the running kernel is unchanged from the operator's view).
	KernelStateReverted KernelState = "REVERTED"
)

func (s KernelState) order() int {
	switch s {
	case KernelStateInit:
		return 0
	case KernelStatePreflight:
		return 1
	case KernelStateInstalled:
		return 2
	case KernelStateArming:
		return 3
	case KernelStateArmed:
		return 4
	case KernelStatePromoted, KernelStateReverted:
		return 5
	default:
		return -1
	}
}

func (s KernelState) atLeast(t KernelState) bool { return s.order() >= t.order() }

// KernelJournal is the crash-safe persisted state of an in-progress kernel
// channel run. Written via temp+fsync+rename on every transition.
type KernelJournal struct {
	// CandidateVersion is the `uname -r` the candidate kernel will report
	// (e.g. "6.18.5-12-generic"). The promotion gate asserts the booted
	// kernel matches this exactly.
	CandidateVersion string `json:"candidate_version"`

	// KnownGoodVersion is the `uname -r` of the active (rollback) kernel at
	// arm time — the slot BootOrder falls back to.
	KnownGoodVersion string `json:"known_good_version"`

	// ActiveSlot / InactiveSlot are the A/B slot labels ("xpf-A"/"xpf-B").
	// The candidate is staged into InactiveSlot; promotion makes it active.
	ActiveSlot   string `json:"active_slot"`
	InactiveSlot string `json:"inactive_slot"`

	// State is the last COMPLETED phase.
	State KernelState `json:"state"`

	// StartedAt is when the run began (for stale-run detection).
	StartedAt time.Time `json:"started_at"`

	// PromoteAttempts counts revert-reboots for THIS armed candidate. Bounded
	// by maxPromoteAttempts so a read-only-root journal that cannot clear cannot
	// loop reboots forever (r1 AGY catastrophic).
	PromoteAttempts int `json:"promote_attempts,omitempty"`

	// BootID is the Boot#### id (the inactive slot) that was armed as the
	// one-shot BootNext AND POSITIVELY READ BACK before the ARMED transition
	// (#5847). Empty until the verified ARMED state. On the candidate boot the
	// promotion gate can tie BootCurrent to this id to confirm the firmware
	// booted the slot we actually armed (provenance for a genuine trial).
	BootID string `json:"boot_id,omitempty"`

	// ArmNonce is a per-attempt token generated when ENTERING ARMING (#5847) and
	// carried onto the verified ARMED journal. It distinguishes a fresh arm from
	// a stale journal left by a prior or crashed attempt, so provenance is not
	// confused across attempts.
	ArmNonce string `json:"arm_nonce,omitempty"`

	// ArmAttempts counts arm attempts (armCandidate entries) for THIS run so a
	// fresh ArmNonce is unique across attempts even under a stuck test clock
	// (#5847).
	ArmAttempts int `json:"arm_attempts,omitempty"`

	// PromoteBinary is the ABSOLUTE path of the xpfd the promotion gate must
	// run on the candidate boot, recorded BY THE ARMING (#6601 r6).
	//
	// Every prior design derived this from ambient state the system happened to
	// expose — $PATH, then compiled defaults, then inode identity, then a unit
	// name, then that unit's LoadState — and each one could be stale after a
	// relocation or a unit switch. The last of those is what broke: a disabled
	// unit still reports LoadState=loaded with MainPID=0 (verified firsthand),
	// so a leftover default unit whose drop-in still pointed at an OLD version
	// satisfied the arm-time check, and on the candidate boot its stale
	// ExecStart was accepted and the stale binary authorized the promotion.
	//
	// The arming does not have to infer anything: it IS an xpfd process, so
	// os.Executable() names the live binary by construction, and it knows that
	// at the moment it arms. Recording it converts the question from "which
	// xpfd is live?" (unanswerable from ambient state) into "which xpfd armed
	// this candidate?" (a fact). It is cleared with the journal on
	// promote/revert.
	//
	// EXACTLY TWO parties may write it, and both establish the value by
	// CONSTRUCTION rather than by inference: `arm`, which resolves the binary
	// executing it; and (#6639) an in-place binary cut, which re-stamps it
	// because the cut CREATED the new xpfd and repointed `current`, the sbin
	// link and the unit ExecStart at it. Before #6639 only the first existed,
	// so a cut while a candidate was armed left the record naming a binary the
	// unit no longer pointed at, and the outer hop refused the promotion on
	// every subsequent boot.
	//
	// The verifying binary may therefore be a different BUILD from the arming
	// one. That is deliberate: the property being protected is "the gate runs
	// the LIVE xpfd, never a stale leftover", not "the same build throughout".
	//
	// The gate REFUSES when this is present but unusable, and never falls back
	// to inference. See armRecordPath / the outer hop's sidecar.
	PromoteBinary string `json:"promote_binary,omitempty"`
}

// ErrKernelChannelUnavailable marks a pre-assert failure that means LANE 1
// cannot be safely armed on this platform (no UEFI, slots unregistered, no
// watchdog under the strict policy, insufficient space). The operator is told
// to use LANE 2 (image-replace). Distinct from a transient/IO error.
var ErrKernelChannelUnavailable = errors.New("kernel channel unavailable (use image-replace / LANE 2)")

// ErrKernelReverted marks the EXPECTED outcome of a failed promotion gate: the
// candidate did not pass (REJECT / wrong-kernel / beacon fail / firmware
// fell-back), so it was not promoted and the box must reboot to the known-good
// slot. The CLI maps this to exit 3 (the promotion oneshot reboots), distinct
// from a genuine infrastructure error (exit 1) — a unit must be able to tell
// "reverted" from "broken" (r1 Codex High).
var ErrKernelReverted = errors.New("kernel candidate reverted (reboot to known-good)")

// KernelSystem abstracts the OS / firmware / apt / boot surface so the kernel
// state machine is unit-testable without a live UEFI host. The production
// implementation is realKernelSystem (kernel_linux.go).
type KernelSystem interface {
	// ---- pre-assert surface ----

	// IsUEFI reports whether the system booted via UEFI (efivarfs present).
	IsUEFI() bool
	// EfibootmgrOK reports whether `efibootmgr` runs and can read NVRAM.
	EfibootmgrOK() bool
	// BootEntries returns the current UEFI boot entries keyed by label,
	// with the value being the Boot#### hex id (e.g. "xpf-A"->"0003").
	BootEntries() (map[string]string, error)
	// BootOrder returns the current BootOrder as an ordered slice of
	// Boot#### hex ids (front = default).
	BootOrder() ([]string, error)
	// GrubSubmenuDisabled reports whether GRUB_DISABLE_SUBMENU=y is set and
	// the /etc/grub.d/09_xpf $cmdpath fragment is present.
	GrubSubmenuDisabled() (bool, error)
	// WatchdogStatus reports (devicePresent, persistenceFlag): a watchdog
	// device exists, and the bake recorded that this platform's watchdog
	// survives a warm reset (Path Option D1). The caller's policy decides
	// whether a missing persistence flag aborts (D1) or warns (D2).
	WatchdogStatus() (present bool, persistent bool)
	// FreeBytes reports available bytes on the filesystem backing path
	// (used for both /boot and the ESP headroom asserts).
	FreeBytes(path string) (uint64, error)

	// ---- install surface ----

	// RunningKernel returns `uname -r`.
	RunningKernel() (string, error)
	// KernelHeld reports whether the linux-* package set is currently held.
	KernelHeld() (bool, error)
	// InstallCandidateKernel does unhold -> apt-get install <ver> -> rehold,
	// verifying update-initramfs/update-grub succeeded, and returns the
	// installed kernel's `uname -r` form. It MUST NOT move the permanent
	// default (the caller re-asserts that afterwards).
	InstallCandidateKernel(version string) (unameR string, err error)
	// DefaultBootEntry returns the Boot#### id that is currently the
	// permanent default (BootOrder front), for the no-move re-assert.
	DefaultBootEntry() (string, error)

	// ---- arm surface ----

	// WriteSlotSelector atomically writes the GRUB-script selector for the
	// given slot (kernel/initrd vars) — temp+rename+fsync on the ESP.
	WriteSlotSelector(slot, unameR string) error
	// ReadSlotSelector returns the uname -r the slot's selector points at.
	ReadSlotSelector(slot string) (string, error)
	// SetBootNext arms the one-shot boot of the given Boot#### id.
	SetBootNext(bootID string) error
	// GetBootNext returns the Boot#### id currently armed as the one-shot
	// BootNext, or "" if none is set (#5847). The two-phase arm reads this back
	// AFTER SetBootNext to POSITIVELY CONFIRM the firmware accepted the one-shot
	// before recording the verified ARMED journal — a firmware that silently
	// dropped or partial-wrote the variable must not yield a false-ARMED journal.
	GetBootNext() (string, error)
	// ClearBootNext removes the one-shot BootNext variable (#6758). The
	// two-phase arm calls it on EVERY failure that happens after SetBootNext
	// has already succeeded, so NVRAM never stays armed while the durable
	// journal records ARMING — a state the journal explicitly defines as "the
	// firmware still boots the known-good default (no confirmed one-shot)".
	// Clearing an already-absent BootNext is not an error.
	ClearBootNext() error
	// ArmWatchdog arms the persistent watchdog before the reboot (best
	// effort; the firmware BootNext clear is the loop-safety, the watchdog
	// only converts a hang into the reset that triggers the fallback).
	ArmWatchdog() error
	// Reboot reboots the host. Returns only on failure (a success does not
	// return — the process is gone). Tests inject a no-op + flag.
	Reboot() error

	// WritePromotionMarker durably records that <unameR> was promoted at the
	// given time (survives the journal clear), so the external HA orchestrator's
	// post-reboot version-check ("running kernel == target AND promotion
	// confirmed") has a durable signal to poll via `xpfd upgrade kernel status`.
	WritePromotionMarker(unameR string) error
	// ReadPromotionMarker returns the last promoted uname -r (or "" if none).
	ReadPromotionMarker() (string, error)
	// ClearPromotionMarker removes the durable promotion marker. Called at the
	// start of an Arm so a STALE marker from a PRIOR roll (e.g. a previous
	// successful roll to the SAME version) cannot false-satisfy the external
	// orchestrator's post-reboot version-check for THIS roll (r1 Codex High).
	ClearPromotionMarker() error
	// ClearRollLease removes the local kernel-roll lease. Called on a REVERT so
	// a stranded lease does not suppress this node's self-recovery for the full
	// TTL after a dead roll (r2 AGY).
	ClearRollLease() error

	// WriteLastRoll durably records the outcome of a COMPLETED roll — promoted,
	// reverted, or discarded on known-good — so it survives the journal clear
	// (#6495, #10772 x1-F6). Unlike the promotion marker this is written for
	// every outcome and is NOT cleared at arm time: it is history, overwritten
	// by the next roll. See kernel_lastroll.go for the deliberate asymmetry
	// with the marker.
	WriteLastRoll(rec KernelRollOutcome) error
	// ReadLastRoll returns the last recorded roll outcome (a zero record when
	// no roll has completed on this box).
	ReadLastRoll() (KernelRollOutcome, error)

	// ---- promotion-gate surface (runs on the candidate boot) ----

	// BootCurrent returns the Boot#### id the firmware actually booted.
	BootCurrent() (string, error)
	// VerifyDataplane runs `<xpfd> verify-dataplane` (0 PASS / 3 REJECT). The
	// production implementation execs an EXPLICIT, version-resolved xpfd path
	// and NEVER a PATH-resolved bare name (#6541); if no explicit path
	// resolves it returns an error rather than falling back to PATH, and the
	// caller reverts (see verifyAndPromote's Gate 3).
	VerifyDataplane() (bool, error)
	// ForwardBeacon runs a bounded forward health probe to a stable target
	// and reports whether the dataplane actually forwards.
	ForwardBeacon(deadline time.Duration) (bool, error)
	// SetBootOrderFront moves bootID to the front of BootOrder
	// NON-DESTRUCTIVELY (preserving all other entries), making it the
	// durable default. Used to promote the candidate slot.
	SetBootOrderFront(bootID string) error
	// DisarmWatchdog disarms the watchdog after a successful promote.
	DisarmWatchdog() error
	// PruneInactiveSlot resets the inactive slot's selector back to the
	// known-good kernel and purges the un-promoted candidate kernel pkg.
	PruneInactiveSlot(slot, knownGoodUnameR, candidateVersion string) error

	// Now returns the current time.
	Now() time.Time
}

// slotLabels are the two FIXED A/B UEFI slot labels (plan §3.1). They are
// permanently registered at first boot (INC-0 oneshot), never per-upgrade.
const (
	SlotA = "xpf-A"
	SlotB = "xpf-B"
)

// KernelConfig configures a KernelRunner.
type KernelConfig struct {
	// JournalPath is the crash-safe kernel-channel journal (distinct from
	// the binary-cut journal so the two channels never collide).
	JournalPath string

	// StrictWatchdog selects Path Option D: true = D1 (fail-closed if the
	// watchdog is not verified-persistent), false = D2 (warn-and-proceed —
	// BootNext still closes the loop; an early hang needs one external reset).
	StrictWatchdog bool

	// BootFreeMargin / ESPFreeMargin are the headroom required on /boot and
	// the ESP beyond the candidate kernel+initramfs / slot staging.
	BootFreeMargin uint64
	ESPFreeMargin  uint64

	// BeaconDeadline bounds the forward health beacon on the candidate boot.
	BeaconDeadline time.Duration

	// BootMountpoint / ESPMountpoint are the paths whose free space is
	// pre-asserted (defaults /boot and /boot/efi).
	BootMountpoint string
	ESPMountpoint  string

	// Sys is the OS/firmware/apt/boot surface. Required.
	Sys KernelSystem

	// Logf is an optional structured progress sink (defaults to no-op).
	Logf func(format string, args ...any)
}

func (c *KernelConfig) withDefaults() {
	if c.JournalPath == "" {
		c.JournalPath = DefaultKernelJournalPath
	}
	if c.BootFreeMargin == 0 {
		c.BootFreeMargin = 64 << 20 // candidate kernel+initramfs+headroom
	}
	if c.ESPFreeMargin == 0 {
		c.ESPFreeMargin = 16 << 20 // two slot dirs shim+grub+selector
	}
	if c.BeaconDeadline == 0 {
		c.BeaconDeadline = 20 * time.Second
	}
	if c.BootMountpoint == "" {
		c.BootMountpoint = "/boot"
	}
	if c.ESPMountpoint == "" {
		c.ESPMountpoint = "/boot/efi"
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// DefaultKernelJournalPath is the kernel-channel journal location.
const DefaultKernelJournalPath = "/var/lib/xpf/kernel-upgrade.state"

// KernelRunner drives the LANE-1 kernel-channel state machine for ONE node.
type KernelRunner struct {
	cfg KernelConfig
}

// NewKernelRunner builds a KernelRunner. Sys must be set.
func NewKernelRunner(cfg KernelConfig) (*KernelRunner, error) {
	if cfg.Sys == nil {
		return nil, errors.New("kernel upgrade: Sys is required")
	}
	cfg.withDefaults()
	return &KernelRunner{cfg: cfg}, nil
}

func (r *KernelRunner) logf(format string, args ...any) { r.cfg.Logf(format, args...) }

// otherSlot returns the slot label that is not s.
func otherSlot(s string) string {
	if s == SlotA {
		return SlotB
	}
	return SlotA
}
