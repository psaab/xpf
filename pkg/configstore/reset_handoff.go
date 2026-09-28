package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// ResetHandoffPath is the box-level factory-reset handoff flag. completeZeroize
// writes it on every successful wipe with the current boot ID; post-success
// failures (helper-state sweep, daemon stop verification) append a dirty
// reason instead of failing silently. N+1 provisioning (commits, peer sync)
// refuses while the flag demands a reboot or a retry. A package var so tests
// drive the gate against a disposable path; production is always /etc/xpf.
var ResetHandoffPath = "/etc/xpf/.reset-handoff"

// Reset handoff gate sentinels, matched with errors.Is by provisioning paths.
var (
	// ErrResetHandoffDirty refuses provisioning while a prior reset left
	// residue: only another factory reset clears it.
	ErrResetHandoffDirty = errors.New("factory reset incomplete: residue remains, retry factory reset")
	// ErrResetHandoffRebootRequired refuses pre-reboot N+1 provisioning after
	// a clean reset: volatile tenant state (shm, journal) clears on reboot.
	ErrResetHandoffRebootRequired = errors.New("factory reset requires a reboot before new configuration")
)

// Reset handoff dirty-reason classes. Boot repair dispatches on the class
// prefix ("helper: ..."); unknown or unprefixed reasons (stop failures,
// the pending sentinel, pre-path flags) repair every class — verification,
// not the reason, is the ground truth for clearing.
const (
	ResetHandoffReasonHelper = "helper"
	ResetHandoffReasonKea    = "kea"
	ResetHandoffReasonTemps  = "temps"
)

// ResetHandoffPending is the dirty reason a completed wipe records while
// daemon post-verification has not yet passed. A crash in that window
// leaves pending + no markers; boot repair treats it as unknown-cause and
// repairs every class before the flag may downgrade.
const ResetHandoffPending = "reset verification pending"

// maxResetHandoffBytes bounds handoff-flag and boot-id reads: both are tiny,
// and authoritative store reads must be bounded (#8597).
const maxResetHandoffBytes = 1 << 16

// CurrentBootID returns the kernel boot ID, stable for the running boot.
func CurrentBootID() (string, error) {
	data, err := ReadBoundedFile("/proc/sys/kernel/random/boot_id", maxResetHandoffBytes)
	if err != nil {
		return "", fmt.Errorf("read boot id: %w", err)
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", fmt.Errorf("read boot id: empty")
	}
	return id, nil
}

// WriteResetHandoff durably records a completed reset for boot ID with the
// given dirty reason ("" when clean) and the pre-wipe effective helper
// state path ("" when unknown). The reason is flattened to one line:
// joined errors carry newlines that would otherwise corrupt the line format
// and fail every later read closed. The helper path is recorded because
// post-wipe the config it derives from is erased: boot repair must sweep
// the recorded path, never re-derive the default. A path containing a line
// break fails closed rather than corrupting the format.
func WriteResetHandoff(bootID, dirty, helperPath string) error {
	var b strings.Builder
	b.WriteString("boot_id=" + strings.TrimSpace(bootID) + "\n")
	flat := strings.Join(strings.Fields(dirty), " ")
	b.WriteString("dirty=" + flat + "\n")
	if hp := strings.TrimSpace(helperPath); hp != "" {
		if strings.ContainsAny(hp, "\r\n") {
			return fmt.Errorf("write reset handoff flag: helper path %q contains a line break", hp)
		}
		b.WriteString("helper_path=" + hp + "\n")
	}
	if err := fsatomic.WriteFileDurable(ResetHandoffPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write reset handoff flag: %w", err)
	}
	return nil
}

// ReadResetHandoff parses the handoff flag. present is false when no flag
// exists. A corrupt flag is returned as an error (fail closed). helperPath
// is "" only on hand-crafted or corrupt flags: every in-tree writer
// records a path, and boot repair treats an empty path as unverifiable.
func ReadResetHandoff() (bootID, dirty, helperPath string, present bool, err error) {
	data, rerr := ReadBoundedFile(ResetHandoffPath, maxResetHandoffBytes)
	if errors.Is(rerr, os.ErrNotExist) {
		return "", "", "", false, nil
	}
	if rerr != nil {
		return "", "", "", false, fmt.Errorf("read reset handoff flag: %w", rerr)
	}
	seenBoot := false
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "boot_id="); ok {
			bootID, seenBoot = strings.TrimSpace(rest), true
		} else if rest, ok := strings.CutPrefix(line, "dirty="); ok {
			dirty = strings.TrimSpace(rest)
		} else if rest, ok := strings.CutPrefix(line, "helper_path="); ok {
			helperPath = strings.TrimSpace(rest)
		} else if strings.TrimSpace(line) != "" {
			return "", "", "", false, fmt.Errorf("reset handoff flag %s is corrupt", ResetHandoffPath)
		}
	}
	if !seenBoot || bootID == "" {
		return "", "", "", false, fmt.Errorf("reset handoff flag %s is corrupt", ResetHandoffPath)
	}
	return bootID, dirty, helperPath, true, nil
}

// ClearResetHandoff removes the flag (post-reboot convergence). Absence is clean.
func ClearResetHandoff() error {
	if err := os.Remove(ResetHandoffPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear reset handoff flag: %w", err)
	}
	if err := fsatomic.SyncDir(filepath.Dir(ResetHandoffPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sync reset handoff removal: %w", err)
	}
	return nil
}

// MarkResetHandoffDirty records a post-success residue reason, preserving the
// recorded boot ID (or the current one when no flag exists yet) and the
// recorded helper path.
func MarkResetHandoffDirty(reason string) error {
	bootID, _, helperPath, present, err := ReadResetHandoff()
	if err != nil {
		return err
	}
	if !present {
		bootID, err = CurrentBootID()
		if err != nil {
			return err
		}
	}
	return WriteResetHandoff(bootID, reason, helperPath)
}

// FlipResetHandoffClean rewrites a pending/dirty flag clean after daemon
// post-verification passed, preserving the recorded boot ID and helper
// path. An absent or unreadable flag fails closed: the wipe must have
// recorded pending first, so absence means the protocol was bypassed.
func FlipResetHandoffClean() error {
	bootID, _, helperPath, present, err := ReadResetHandoff()
	if err != nil {
		return fmt.Errorf("flip reset handoff clean: %w", err)
	}
	if !present {
		return fmt.Errorf("flip reset handoff clean: no flag recorded")
	}
	return WriteResetHandoff(bootID, "", helperPath)
}

// CheckResetHandoff enforces the N+1 provisioning gate. Dirty refuses until a
// clean reset overwrites the flag; clean-but-unrebooted refuses until a
// reboot (clearing the flag on first observation post-reboot). Absence opens.
func CheckResetHandoff() error {
	bootID, dirty, _, present, err := ReadResetHandoff()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrResetHandoffDirty, err)
	}
	if !present {
		return nil
	}
	if dirty != "" {
		return fmt.Errorf("%w: %s", ErrResetHandoffDirty, dirty)
	}
	current, err := CurrentBootID()
	if err != nil {
		return fmt.Errorf("%w: cannot verify reboot (%v)", ErrResetHandoffRebootRequired, err)
	}
	if bootID == current {
		return ErrResetHandoffRebootRequired
	}
	return ClearResetHandoff()
}
