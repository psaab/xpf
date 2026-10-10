package upgrade

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBinaryUpgradeStatusPath is the durable record written by the Debian
// postinst when publishing or cutting the staged binary generation fails. It
// deliberately lives under /var/lib/xpf rather than /run, which is tmpfs.
const DefaultBinaryUpgradeStatusPath = "/var/lib/xpf/upgrade-deferred"

// DefaultBinaryUpgradeStatusUnreadablePath is a durable fail-closed signal
// written under dpkg's package metadata directory when the primary status
// record cannot be persisted. Its presence prevents readers from reporting a
// clean state after postinst returned with an unresolved cut.
const DefaultBinaryUpgradeStatusUnreadablePath = "/var/lib/dpkg/info/xpf.upgrade-deferred-unreadable"

// BinaryUpgradeStatus is the operator-facing snapshot of a nonfatal postinst
// publish/cut failure. A zero value means no failure is pending.
type BinaryUpgradeStatus struct {
	Recorded       bool
	StagedVersion  string
	RunningVersion string
	Reason         string
	Recovery       string
	RecordedAt     time.Time
	ReadErr        error
}

// ReadBinaryUpgradeStatus reads the durable postinst failure record. A missing
// record is the ordinary state; malformed or unreadable records are reported
// rather than being mistaken for no pending upgrade.
func ReadBinaryUpgradeStatus(path string) BinaryUpgradeStatus {
	return readBinaryUpgradeStatus(path, DefaultBinaryUpgradeStatusUnreadablePath)
}

func readBinaryUpgradeStatus(path, unreadablePath string) BinaryUpgradeStatus {
	if path == "" {
		path = DefaultBinaryUpgradeStatusPath
	}
	if unreadablePath != "" {
		_, markerErr := os.Stat(unreadablePath)
		if markerErr == nil {
			return BinaryUpgradeStatus{ReadErr: fmt.Errorf(
				"postinst could not persist binary upgrade status (durable marker %s is present)",
				unreadablePath)}
		}
		if !errors.Is(markerErr, os.ErrNotExist) {
			return BinaryUpgradeStatus{ReadErr: fmt.Errorf(
				"check durable binary upgrade status marker %s: %w", unreadablePath, markerErr)}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BinaryUpgradeStatus{}
		}
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("read binary upgrade status %s: %w", path, err)}
	}
	defer f.Close()

	values := make(map[string]string, 6)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: malformed line", path)}
		}
		switch key {
		case "format", "staged_version", "running_version", "reason", "recovery", "recorded_at":
			if _, exists := values[key]; exists {
				return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: duplicate %s field", path, key)}
			}
			values[key] = value
		default:
			// Ignore unknown keys so a newer postinst can add metadata without
			// making an older status command hide the failure.
		}
	}
	if err := scanner.Err(); err != nil {
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("read binary upgrade status %s: %w", path, err)}
	}
	for _, key := range []string{"format", "staged_version", "running_version", "reason", "recovery", "recorded_at"} {
		if values[key] == "" {
			return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: missing %s field", path, key)}
		}
	}
	if values["format"] != "1" {
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: unsupported format %q", path, values["format"])}
	}
	for _, field := range []struct{ name, value string }{
		{name: "staged_version", value: values["staged_version"]},
		{name: "running_version", value: values["running_version"]},
	} {
		if field.value != "unknown" {
			if err := ValidateVersionSegment(field.value); err != nil {
				return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: invalid %s: %w", path, field.name, err)}
			}
		}
	}
	switch values["reason"] {
	case "publish-failed", "publish-deferred", "cut-failed", "cut-deferred":
	default:
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: unknown failure reason %q", path, values["reason"])}
	}
	switch values["recovery"] {
	case "xpfd publish-generation && xpfd upgrade", "xpfd publish-generation && xpfd upgrade --rolling", "xpfd upgrade", "xpfd upgrade --rolling":
	default:
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: invalid recovery command", path)}
	}
	recordedAt, err := time.Parse(time.RFC3339, values["recorded_at"])
	if err != nil {
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("binary upgrade status %s: invalid recorded_at: %w", path, err)}
	}
	return BinaryUpgradeStatus{
		Recorded:       true,
		StagedVersion:  values["staged_version"],
		RunningVersion: values["running_version"],
		Reason:         values["reason"],
		Recovery:       values["recovery"],
		RecordedAt:     recordedAt,
	}
}

// ClearBinaryUpgradeStatus removes a resolved postinst failure record and
// durably records the directory update. A missing record is already clear.
func ClearBinaryUpgradeStatus(path string) error {
	if path == "" {
		path = DefaultBinaryUpgradeStatusPath
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear binary upgrade status %s: %w", path, err)
	}
	markerRemoved := false
	if err := os.Remove(DefaultBinaryUpgradeStatusUnreadablePath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear durable binary upgrade status marker: %w", err)
		}
	} else {
		markerRemoved = true
	}
	if err := syncStatusDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if markerRemoved && filepath.Dir(path) != filepath.Dir(DefaultBinaryUpgradeStatusUnreadablePath) {
		if err := syncStatusDirectory(filepath.Dir(DefaultBinaryUpgradeStatusUnreadablePath)); err != nil {
			return err
		}
	}
	return nil
}

func syncStatusDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open binary upgrade status directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync binary upgrade status directory: %w", err)
	}
	return nil
}

// ClearBinaryUpgradeStatusIfCurrent removes a postinst failure record only
// when its staged version is the version currently committed by the cutover.
// The upgrade lock serializes the current-link check and clear against other
// cutovers. A missing, unreadable, or mismatched record is left untouched.
func (r *Runner) ClearBinaryUpgradeStatusIfCurrent(path string) (bool, error) {
	if r == nil {
		return false, fmt.Errorf("clear binary upgrade status: nil runner")
	}
	h, err := acquireUpgradeLock("upgrade status clear", "")
	if err != nil {
		return false, fmt.Errorf("clear binary upgrade status: %w", err)
	}
	defer func() { _ = h.Release() }()

	status := ReadBinaryUpgradeStatus(path)
	if status.ReadErr != nil {
		return false, status.ReadErr
	}
	if !status.Recorded {
		return false, nil
	}
	current, err := r.readCurrentVersion()
	if err != nil {
		return false, fmt.Errorf("read committed version before clearing binary upgrade status: %w", err)
	}
	if current == "" || status.StagedVersion != current {
		return false, nil
	}
	if err := ClearBinaryUpgradeStatus(path); err != nil {
		return false, err
	}
	return true, nil
}

// RenderBinaryUpgradeStatus writes the read-only operator status for deferred
// binary upgrades. The warning never changes command success: this is a status
// surface, and unreadable state must be shown rather than hidden behind a failed
// CLI invocation.
func RenderBinaryUpgradeStatus(w io.Writer, status BinaryUpgradeStatus) {
	fmt.Fprintln(w, "Binary upgrade status:")
	if status.ReadErr != nil {
		fmt.Fprintf(w, "  WARNING: could not read durable postinst status: %v\n", status.ReadErr)
		return
	}
	if !status.Recorded {
		fmt.Fprintln(w, "  No unresolved postinst publish/cut failure")
		return
	}
	fmt.Fprintf(w, "  Pending:        yes — staged %s, running %s\n",
		status.StagedVersion, status.RunningVersion)
	fmt.Fprintf(w, "  Failure:        %s\n", status.Reason)
	fmt.Fprintf(w, "  Recorded at:    %s\n", status.RecordedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  Recovery:       %s\n", status.Recovery)
}
