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
	return r.writeCommitStamp(committedStamp{
		Version:             j.TargetVersion,
		Predecessor:         j.PreviousVersion,
		Committed:           true,
		CommittedAtUnixNano: r.cfg.Sys.Now().UnixNano(),
	})
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
