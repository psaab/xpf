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
// corresponding artifact did not exist when the backup was taken.
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

// restoreCommittedPredecessorBackup restores the backed-up committed stamp
// (and DB snapshot, when the live one is gone) after a failed recopy of the
// predecessor. A backup whose bytes were replaced (demotedByReplacement) is
// never restored: the old committed history does not describe the
// replacement bytes. Best-effort: failures are logged, never masking the
// cut error that triggered restore.
func (r *Runner) restoreCommittedPredecessorBackup(b *predecessorStampBackup) {
	if b == nil || b.version == "" {
		return
	}
	if b.demotedByReplacement {
		if b.backupDir != "" {
			_ = os.RemoveAll(b.backupDir)
		}
		return
	}
	defer func() {
		if b.backupDir != "" {
			_ = os.RemoveAll(b.backupDir)
		}
	}()
	if len(b.stampData) > 0 {
		if _, err := os.Stat(r.versionDir(b.version)); err == nil {
			var stamp committedStamp
			if err := json.Unmarshal(b.stampData, &stamp); err == nil {
				if err := r.writeCommitStamp(stamp); err != nil {
					r.logf("upgrade: WARN restore committed predecessor %s stamp: %v", b.version, err)
				}
			}
		}
	}
	if b.dbsnapDir != "" {
		snap := filepath.Join(r.cfg.VersionsDir, "."+b.version+".dbsnap")
		if _, err := os.Stat(snap); os.IsNotExist(err) {
			if _, err := copyTree(b.dbsnapDir, snap); err != nil {
				r.logf("upgrade: WARN restore committed predecessor %s snapshot: %v", b.version, err)
			} else if serr := partialSweepSyncDir(r.cfg.VersionsDir); serr != nil {
				r.logf("upgrade: WARN fsync versions dir after predecessor snapshot restore: %v", serr)
			}
		}
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
