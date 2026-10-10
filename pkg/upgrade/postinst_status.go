package upgrade

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	identity       binaryUpgradeStatusIdentity
}

type binaryUpgradeStatusIdentity struct {
	device uint64
	inode  uint64
	size   int64
}

func statusFileIdentity(info os.FileInfo) (binaryUpgradeStatusIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return binaryUpgradeStatusIdentity{}, fmt.Errorf("unsupported binary upgrade status file identity")
	}
	return binaryUpgradeStatusIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		size:   info.Size(),
	}, nil
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
	info, err := f.Stat()
	if err != nil {
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("stat binary upgrade status %s: %w", path, err)}
	}
	identity, err := statusFileIdentity(info)
	if err != nil {
		return BinaryUpgradeStatus{ReadErr: fmt.Errorf("identify binary upgrade status %s: %w", path, err)}
	}

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
		identity:       identity,
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

func sameBinaryUpgradeStatusRecord(a, b BinaryUpgradeStatus) bool {
	return a.Recorded && b.Recorded &&
		a.identity == b.identity &&
		a.StagedVersion == b.StagedVersion &&
		a.RunningVersion == b.RunningVersion &&
		a.Reason == b.Reason &&
		a.Recovery == b.Recovery &&
		a.RecordedAt.Equal(b.RecordedAt)
}

// clearBinaryUpgradeStatusIfUnchanged re-reads the lockless postinst writer's
// record while the caller holds the upgrade lock. The final lstat checks that
// the path still names the compared regular file immediately before unlink.
// It does not remove the unreadable marker: a marker appearing concurrently is
// new failure evidence and must remain fail-closed.
func clearBinaryUpgradeStatusIfUnchanged(path string, expected BinaryUpgradeStatus) (bool, error) {
	current := ReadBinaryUpgradeStatus(path)
	if current.ReadErr != nil {
		return false, current.ReadErr
	}
	if !sameBinaryUpgradeStatusRecord(expected, current) {
		return false, nil
	}
	if path == "" {
		path = DefaultBinaryUpgradeStatusPath
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("recheck binary upgrade status %s before unlink: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	identity, err := statusFileIdentity(info)
	if err != nil {
		return false, fmt.Errorf("identify binary upgrade status %s before unlink: %w", path, err)
	}
	if identity != expected.identity {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("clear binary upgrade status %s: %w", path, err)
	}
	if err := syncStatusDirectory(filepath.Dir(path)); err != nil {
		return false, err
	}
	return true, nil
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

// ClearBinaryUpgradeStatusIfCurrent removes a resolved postinst failure record.
// It clears when the staged version is the known committed current version, or
// when this invocation supplies health-confirmed evidence from the current
// durable cut generation for a strictly newer Debian version. A later Runner
// operation advances that generation, invalidating saved evidence even when it
// rolls back to the same runtime version. The upgrade lock protects generation,
// journal, and current-version checks against cutovers; the final record
// re-read protects against the lockless postinst status writer.
func (r *Runner) ClearBinaryUpgradeStatusIfCurrent(path string, committed CommittedCut) (bool, error) {
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
	journal, err := r.loadJournal()
	if err != nil {
		return false, fmt.Errorf("read upgrade journal before clearing binary upgrade status: %w", err)
	}
	if journal.State != StateInit && journal.State != StateCommitted {
		return false, nil
	}
	current, err := r.readCurrentVersion()
	if err != nil {
		return false, fmt.Errorf("read committed version before clearing binary upgrade status: %w", err)
	}
	if status.StagedVersion != "unknown" && current != "" &&
		current != "unknown" && status.StagedVersion == current {
		return clearBinaryUpgradeStatusIfUnchanged(path, status)
	}
	if status.StagedVersion == "unknown" || !committed.healthConfirmed ||
		committed.version == "" || committed.version == "unknown" ||
		current != committed.version {
		return false, nil
	}
	generation, err := readStatusGeneration(r.statusGenerationPath())
	if err != nil {
		return false, err
	}
	if committed.generationValid {
		if committed.generation != generation {
			return false, nil
		}
	} else if committed.generation != 0 || generation != 0 {
		return false, nil
	}
	cmp, err := compareDebianVersions(committed.version, status.StagedVersion)
	if err != nil || cmp <= 0 {
		return false, nil
	}
	return clearBinaryUpgradeStatusIfUnchanged(path, status)
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
