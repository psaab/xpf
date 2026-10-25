package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// committedFile is the dotfile stamped INSIDE versions/<ver>/ at COMMIT,
// recording the journal-derived predecessor + commit time. It lives inside
// the version dir so GC removes it with the dir. A present non-committed
// record identifies a copied target that did not reach COMMIT (#10851).
const committedFile = ".committed"

// committedStamp is the journal-derived commit record persisted at COMMIT.
// Version is a self-check: a dir copied sideways (cp -a) carries a stamp
// naming another version and is treated as non-committed, never trusted.
type committedStamp struct {
	Version             string `json:"version"`
	Predecessor         string `json:"predecessor,omitempty"`
	Committed           bool   `json:"committed"`
	CommittedAtUnixNano int64  `json:"committed_at_unix_nano,omitempty"`
}

// committedStampPath returns the path of the commit record inside
// versions/<ver>/.
func (r *Runner) committedStampPath(ver string) string {
	return filepath.Join(r.versionDir(ver), committedFile)
}

// writeCommitStamp durably replaces versions/<ver>/.committed.
func (r *Runner) writeCommitStamp(stamp committedStamp) error {
	return r.writeCommitStampTo(r.versionDir(stamp.Version), stamp)
}

// writeCommitStampTo durably writes a record in a version tree, including a
// not-yet-renamed copy partial.
func (r *Runner) writeCommitStampTo(dir string, stamp committedStamp) error {
	data, err := json.Marshal(stamp)
	if err != nil {
		return fmt.Errorf("marshal commit record for %s: %w", stamp.Version, err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, committedFile)
	if err := fsatomic.WriteFileDurable(path, data, 0o644); err != nil {
		return fmt.Errorf("persist commit record for %s: %w", stamp.Version, err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync version dir after commit record for %s: %w", stamp.Version, err)
	}
	return nil
}

// stampCommittedVersion persists the journal-derived commit record for a
// cut that reached COMMIT (flipped + started + health-confirmed). It is
// idempotent: re-stamping a resumed COMMIT overwrites the same record.
// A write failure fails the COMMIT — the journal stays pre-COMMITTED so a
// re-run retries — because silently committing without the record would
// leave the next bare --rollback on the mtime fallback (#10851).
func (r *Runner) stampCommittedVersion(j *Journal) error {
	if j.TargetVersion == "" {
		return fmt.Errorf("cannot stamp a commit record without a target version")
	}
	// #15186 defence in depth: never write Predecessor == Version. A
	// same-version cut (PreviousVersion == TargetVersion) has no distinct
	// predecessor to record; the reader rejects a self-predecessor, which
	// would erase the real predecessor from rollback history. Omit it.
	predecessor := j.PreviousVersion
	if predecessor == j.TargetVersion {
		predecessor = ""
	}
	return r.writeCommitStamp(committedStamp{
		Version:             j.TargetVersion,
		Predecessor:         predecessor,
		Committed:           true,
		CommittedAtUnixNano: r.cfg.Sys.Now().UnixNano(),
	})
}

// committedPredecessorStamp returns target's committed stamp only when the
// current version's commit record names it as its predecessor. A same-tag
// downgrade may recopy that target before the pre-STOP envelope recheck; keep
// its history until the recheck passes so a refusal does not erase the known-
// good rollback target.
func (r *Runner) committedPredecessorStamp(j *Journal, target string) *committedStamp {
	if j == nil || j.PreviousVersion == "" || target == "" || target == j.PreviousVersion {
		return nil
	}
	currentStamp, present := r.readCommittedStamp(j.PreviousVersion)
	if !present || currentStamp == nil || !currentStamp.Committed ||
		currentStamp.Predecessor != target {
		return nil
	}
	targetStamp, present := r.readCommittedStamp(target)
	if !present || targetStamp == nil || !targetStamp.Committed {
		return nil
	}
	return targetStamp
}

// predecessorStampBackup captures a committed predecessor's stamp file and
// DB snapshot so a failed recopy can restore them. A nil field means the
// corresponding artifact did not exist when the backup was taken. The
// backup must be taken BEFORE PREFLIGHT (and before any resume or
// cut-boundary re-snapshot): each of those rewrites .<target>.dbsnap from
// the live DB, so a backup taken afterwards would preserve the wrong-era
// DB (#16765).
type predecessorStampBackup struct {
	version   string
	stampData []byte
	dbsnapDir string
	backupDir string
	// demotedByReplacement is set when COPY replaced the predecessor with
	// different (or unverifiable) bytes: the old committed history no
	// longer describes the bytes on disk, so a later failure must NOT
	// resurrect it (#12177 demotion survives; #14720 Case C).
	demotedByReplacement bool
	// stashImmune is set on a backup taken before PREFLIGHT: any
	// snapshotConfigDB call during the run may stash and adopt this backup
	// in place of the wrong-era .<target>.dbsnap it just wrote in
	// applySnapshotStash. A COPY-demoted backup is never stashed (#12177).
	stashImmune bool
}

// backupCommittedPredecessor preserves the committed stamp bytes and the
// .<ver>.dbsnap tree of a committed predecessor before a recopy demotes or
// replaces it (#14720). Returns nil when target is not a committed
// predecessor of the journal's live version.
func (r *Runner) backupCommittedPredecessor(j *Journal, target string) *predecessorStampBackup {
	if r.committedPredecessorStamp(j, target) == nil {
		return nil
	}
	b := &predecessorStampBackup{version: target}
	if data, err := os.ReadFile(r.committedStampPath(target)); err == nil {
		b.stampData = data
	}
	snap := filepath.Join(r.cfg.VersionsDir, "."+target+".dbsnap")
	if _, err := os.Stat(snap); err == nil {
		tmp, err := os.MkdirTemp(r.cfg.VersionsDir, ".predbak-*")
		if err != nil {
			r.logf("upgrade: WARN backup committed predecessor %s snapshot: %v", target, err)
			return b
		}
		b.backupDir = tmp
		b.dbsnapDir = filepath.Join(tmp, "dbsnap")
		if _, err := copyTree(snap, b.dbsnapDir); err != nil {
			r.logf("upgrade: WARN backup committed predecessor %s snapshot: %v", target, err)
			_ = os.RemoveAll(tmp)
			b.backupDir = ""
			b.dbsnapDir = ""
		}
	}
	return b
}

// discardPredecessorBackup removes the temporary backup copy without
// restoring it. Called on every Run exit that does not restore (COMMIT,
// copy-stage failures, pre-STOP refusals past the backup's scope) so a
// .predbak-* tree is never left behind in VersionsDir.
func (r *Runner) discardPredecessorBackup(b *predecessorStampBackup) {
	if b == nil || b.backupDir == "" {
		return
	}
	_ = os.RemoveAll(b.backupDir)
	b.backupDir = ""
	b.dbsnapDir = ""
}

// discardAdoptedSnapshotDir clears dbsnapDir WITHOUT touching backupDir:
// after applySnapshotStash installs the backup copy at .<ver>.dbsnap,
// dbsnapDir keeps aliasing that live path while backupDir still names the
// private copy. A later unconditional restore must first drop the alias
// (it would otherwise copyTree the live dir onto itself); the private
// copy in backupDir remains the source of truth.
func (b *predecessorStampBackup) discardAdoptedSnapshotDir() {
	b.dbsnapDir = ""
}

// applySnapshotStash replaces a just-written config-DB snapshot with the
// backed-up predecessor snapshot, so the journal's DBSnapshotPath keeps
// pointing at the canonical .<target>.dbsnap while its CONTENT stays the
// pre-cut (pre-PREFLIGHT) bytes. Called from snapshotConfigDB whenever this
// run is re-staging the committed predecessor. The backup's private copy
// is RETAINED (backupDir) so a later unconditional restore on a failure arm
// can still reinstall it; dbsnapDir is repointed at the canonical snapshot
// so the restore's copy source and the journal agree. A copy failure is
// logged and leaves the just-written snapshot in place — the failure-arm
// restore will overwrite it.
func (r *Runner) applySnapshotStash(b *predecessorStampBackup, snapDir string) {
	if b == nil || b.backupDir == "" || b.demotedByReplacement {
		return
	}
	src := filepath.Join(b.backupDir, "dbsnap")
	if _, err := os.Stat(src); err != nil {
		return
	}
	_ = os.RemoveAll(snapDir)
	if _, err := copyTree(src, snapDir); err != nil {
		r.logf("upgrade: WARN stash committed predecessor %s snapshot: %v", b.version, err)
		return
	}
	if serr := partialSweepSyncDir(r.cfg.VersionsDir); serr != nil {
		r.logf("upgrade: WARN fsync versions dir after predecessor snapshot stash: %v", serr)
	}
	b.dbsnapDir = snapDir
}

// restoreCommittedPredecessorBackup restores the backed-up committed stamp
// and DB snapshot after a failed recopy of the predecessor. The snapshot
// is restored UNCONDITIONALLY (#16765): PREFLIGHT/resume re-snapshots
// overwrite it with the live DB's content, so an existence-only check
// would keep the wrong-era copy. Restoring unconditionally replaces
// whatever this cut wrote with the pre-cut bytes; when the backup has no
// snapshot (none existed at backup time) a snapshot written by this cut
// for the predecessor's version is removed. A backup whose bytes were
// replaced (demotedByReplacement) is never restored in full: the old
// committed history does not describe the replacement bytes (#12177),
// but the snapshot is still restored unconditionally — demotion is about
// stamp candidacy, not DB-snapshot ownership, and the wrong-era snapshot
// was written by this cut, not by the replacement. Best-effort: failures
// are logged, never masking the cut error that triggered restore.
func (r *Runner) restoreCommittedPredecessorBackup(b *predecessorStampBackup) {
	if b == nil || b.version == "" {
		return
	}
	defer r.discardPredecessorBackup(b)
	if !b.demotedByReplacement && len(b.stampData) > 0 {
		if _, err := os.Stat(r.versionDir(b.version)); err == nil {
			var stamp committedStamp
			if err := json.Unmarshal(b.stampData, &stamp); err == nil {
				if err := r.writeCommitStamp(stamp); err != nil {
					r.logf("upgrade: WARN restore committed predecessor %s stamp: %v", b.version, err)
				}
			}
		}
	}
	snap := filepath.Join(r.cfg.VersionsDir, "."+b.version+".dbsnap")
	if b.dbsnapDir != "" || b.backupDir != "" {
		// The private copy under backupDir is the source of truth.
		// dbsnapDir may alias the live .<ver>.dbsnap after a stash, so it
		// must not be copied onto itself; discard that alias first.
		b.discardAdoptedSnapshotDir()
		src := filepath.Join(b.backupDir, "dbsnap")
		if _, err := os.Stat(src); err == nil {
			_ = os.RemoveAll(snap)
			if _, err := copyTree(src, snap); err != nil {
				r.logf("upgrade: WARN restore committed predecessor %s snapshot: %v", b.version, err)
			} else if serr := partialSweepSyncDir(r.cfg.VersionsDir); serr != nil {
				r.logf("upgrade: WARN fsync versions dir after predecessor snapshot restore: %v", serr)
			}
		}
	} else {
		// No snapshot existed when the backup was taken: drop any
		// wrong-era snapshot this cut's PREFLIGHT wrote for the
		// predecessor's version (#16765).
		_ = os.RemoveAll(snap)
	}
}

// stampInFlightVersion marks a copied target as non-committed until the cut
// reaches COMMIT. The durable marker survives an auto-rollback, excluding a
// complete but just-failed runtime from default rollback selection.
func (r *Runner) stampInFlightVersion(ver string) error {
	return r.writeCommitStamp(committedStamp{Version: ver})
}

// readCommittedStamp returns (record, present). An absent record is a legacy
// version and may use the loudly logged mtime fallback; a present uncommitted,
// unreadable, or invalid record is excluded from rollback selection. A
// committed record's self-check and predecessor are validated before trust.
func (r *Runner) readCommittedStamp(ver string) (*committedStamp, bool) {
	path := r.committedStampPath(ver)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false
		}
		r.logf("upgrade: WARN commit record %s unreadable (%v); excluding %s as uncommitted", path, err, ver)
		return nil, true
	}
	var stamp committedStamp
	if err := json.Unmarshal(data, &stamp); err != nil {
		r.logf("upgrade: WARN commit record %s is corrupt (%v); excluding %s as uncommitted", path, err, ver)
		return nil, true
	}
	if stamp.Version != ver {
		r.logf("upgrade: WARN commit record %s names version %q, not %q (copied dir?); excluding %s as uncommitted", path, stamp.Version, ver, ver)
		return nil, true
	}
	if stamp.Committed {
		if stamp.CommittedAtUnixNano <= 0 {
			r.logf("upgrade: WARN commit record %s has invalid commit time %d; excluding %s as uncommitted", path, stamp.CommittedAtUnixNano, ver)
			return nil, true
		}
		if stamp.Predecessor != "" && (ValidateVersionSegment(stamp.Predecessor) != nil || stamp.Predecessor == ver) {
			r.logf("upgrade: WARN commit record %s has invalid predecessor %q; excluding %s as uncommitted", path, stamp.Predecessor, ver)
			return nil, true
		}
	}
	return &stamp, true
}
