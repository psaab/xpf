package upgrade

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
	return parseBinaryUpgradeStatusFile(f, path)
}

// parseBinaryUpgradeStatusFile parses an already-open status file. The clear
// path uses it on a held-open dirfd-relative fd so the inode stays pinned
// through the quarantine decision (ABA-proof); the plain reader opens by path.
func parseBinaryUpgradeStatusFile(f *os.File, path string) BinaryUpgradeStatus {
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
// record while the caller holds the upgrade lock, then removes it via an
// atomic quarantine rename: renameat2-NOREPLACE moves the name aside. The
// re-read fd stays OPEN through the decision (pinning the inode against
// number-reuse ABA); an fstat comparison between the quarantined file and
// that fd proves the moved file is the compared one. Then the live name must
// still be vacant: a writer rename landing after the quarantine move
// repopulates it, and the clear retains (dropping the quarantined copy)
// rather than reporting a clear it did not make. Check-then-unlink can never
// be atomic — the decision is made on the moved-away file plus a vacant
// live name, never on a live name. It does not remove the unreadable marker:
// a marker appearing concurrently is new failure evidence and must remain
// fail-closed.
//
// Package hook for the deterministic race test (statConfigDBDir pattern):
// when non-nil, runs between the quarantine move and the identity decision.
var clearStatusQuarantineHook func()

func clearBinaryUpgradeStatusIfUnchanged(path string, expected BinaryUpgradeStatus) (bool, error) {
	if path == "" {
		path = DefaultBinaryUpgradeStatusPath
	}
	dirFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return false, nil
		}
		return false, fmt.Errorf("open binary upgrade status directory before clear: %w", err)
	}
	defer unix.Close(dirFD)
	base := filepath.Base(path)
	// Open the live name via dirfd and hold the fd OPEN through the whole
	// decision: this pins the inode, killing inode-number-reuse ABA (a freed
	// inode cannot be recycled while open).
	fd, err := unix.Openat(dirFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return false, nil
		}
		return false, fmt.Errorf("open binary upgrade status %s: %w", path, err)
	}
	defer unix.Close(fd)
	var fdStat unix.Stat_t
	if err := unix.Fstat(fd, &fdStat); err != nil {
		return false, fmt.Errorf("stat binary upgrade status %s: %w", path, err)
	}
	if fdStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, nil
	}
	// Wrap a DUPLICATE for parsing: closing the *os.File must not close the
	// pinned fd (it stays open through the quarantine decision below).
	parseFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("duplicate binary upgrade status fd %s: %w", path, err)
	}
	parseFile := os.NewFile(uintptr(parseFD), path)
	if parseFile == nil {
		unix.Close(int(parseFD))
		return false, fmt.Errorf("wrap binary upgrade status fd %s", path)
	}
	current := parseBinaryUpgradeStatusFile(parseFile, path)
	parseFile.Close()
	if current.ReadErr != nil {
		return false, current.ReadErr
	}
	if !sameBinaryUpgradeStatusRecord(expected, current) {
		return false, nil
	}
	// Quarantine name: matches the writer `$status_name.*` 24h sweep pattern
	// (debian/xpf.postinst), so a crashed clear cannot strand the directory.
	quarantine := base + ".clear." + strconv.FormatInt(int64(os.Getpid()), 10)
	if err := unix.Renameat2(dirFD, base, dirFD, quarantine, unix.RENAME_NOREPLACE); err != nil {
		if err == unix.ENOENT || err == unix.EEXIST {
			return false, nil
		}
		return false, fmt.Errorf("quarantine binary upgrade status %s: %w", path, err)
	}
	if clearStatusQuarantineHook != nil {
		clearStatusQuarantineHook()
	}
	// The name now points elsewhere (or nowhere); compare the QUARANTINED
	// file against the still-open re-read fd. Match → the moved file is the
	// compared one: unlink it. Mismatch → a rename won a race we did not
	// see: move it back unless a newer record owns the name.
	var qStat unix.Stat_t
	if err := unix.Fstatat(dirFD, quarantine, &qStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, fmt.Errorf("stat quarantined binary upgrade status %s: %w", path, err)
	}
	if uint64(qStat.Dev) != uint64(fdStat.Dev) || qStat.Ino != fdStat.Ino {
		if err := unix.Renameat2(dirFD, quarantine, dirFD, base, unix.RENAME_NOREPLACE); err != nil {
			if err == unix.EEXIST {
				// A newer record owns the live name; drop the quarantined one.
				_ = unix.Unlinkat(dirFD, quarantine, 0)
				return false, nil
			}
			return false, fmt.Errorf("restore quarantined binary upgrade status %s: %w", path, err)
		}
		return false, nil
	}
	// The quarantined file IS the compared one — but only unlink it if the
	// live name is still vacant. A writer rename landing after the quarantine
	// move (the hook point) repopulates the name: that newer record must be
	// retained AND the clear must report not-cleared (a concurrent writer
	// invalidates this clear attempt). Restore-then-retain either way.
	var liveStat unix.Stat_t
	liveErr := unix.Fstatat(dirFD, base, &liveStat, unix.AT_SYMLINK_NOFOLLOW)
	if liveErr == nil {
		// Live name repopulated: move our file back only if possible, but
		// the name is taken — drop the quarantined copy and retain.
		_ = unix.Unlinkat(dirFD, quarantine, 0)
		return false, nil
	}
	if liveErr != unix.ENOENT {
		return false, fmt.Errorf("recheck live binary upgrade status %s: %w", path, liveErr)
	}
	if err := unix.Unlinkat(dirFD, quarantine, 0); err != nil {
		return false, fmt.Errorf("clear quarantined binary upgrade status %s: %w", path, err)
	}
	if err := unix.Fsync(dirFD); err != nil {
		return false, fmt.Errorf("sync binary upgrade status directory after clear: %w", err)
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
	// The only evidence constructor (recordCommittedCut) always carries begin
	// state: generation-invalid evidence cannot occur in production. Require
	// validity rather than honoring a legacy zero path (Opus MINOR-3).
	if !committed.generationValid || committed.generation != generation {
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
