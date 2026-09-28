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

// CurrentBootID returns the kernel boot ID, stable for the running boot.
func CurrentBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
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
// given dirty reason ("" when clean).
func WriteResetHandoff(bootID, dirty string) error {
	var b strings.Builder
	b.WriteString("boot_id=" + bootID + "\n")
	b.WriteString("dirty=" + dirty + "\n")
	if err := fsatomic.WriteFileDurable(ResetHandoffPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write reset handoff flag: %w", err)
	}
	return nil
}

// ReadResetHandoff parses the handoff flag. present is false when no flag
// exists. A corrupt flag is returned as an error (fail closed).
func ReadResetHandoff() (bootID, dirty string, present bool, err error) {
	data, rerr := os.ReadFile(ResetHandoffPath)
	if errors.Is(rerr, os.ErrNotExist) {
		return "", "", false, nil
	}
	if rerr != nil {
		return "", "", false, fmt.Errorf("read reset handoff flag: %w", rerr)
	}
	seenBoot := false
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "boot_id="); ok {
			bootID, seenBoot = strings.TrimSpace(rest), true
		} else if rest, ok := strings.CutPrefix(line, "dirty="); ok {
			dirty = strings.TrimSpace(rest)
		} else if strings.TrimSpace(line) != "" {
			return "", "", false, fmt.Errorf("reset handoff flag %s is corrupt", ResetHandoffPath)
		}
	}
	if !seenBoot || bootID == "" {
		return "", "", false, fmt.Errorf("reset handoff flag %s is corrupt", ResetHandoffPath)
	}
	return bootID, dirty, true, nil
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
// recorded boot ID (or the current one when no flag exists yet).
func MarkResetHandoffDirty(reason string) error {
	bootID, _, present, err := ReadResetHandoff()
	if err != nil {
		return err
	}
	if !present {
		bootID, err = CurrentBootID()
		if err != nil {
			return err
		}
	}
	return WriteResetHandoff(bootID, reason)
}

// CheckResetHandoff enforces the N+1 provisioning gate. Dirty refuses until a
// clean reset overwrites the flag; clean-but-unrebooted refuses until a
// reboot (clearing the flag on first observation post-reboot). Absence opens.
func CheckResetHandoff() error {
	bootID, dirty, present, err := ReadResetHandoff()
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
