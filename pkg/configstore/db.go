// Package configstore provides atomic config persistence using JSON files.
package configstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// DB handles durable persistence of configuration trees to disk.
// Writes go through fsatomic.WriteFileDurable (#1894): temp + fsync +
// rename + dir fsync, so a persisted tree survives power loss.
type DB struct {
	dir string

	// writerVersion is the xpf build version stamped into the config
	// compatibility-envelope header on write (#1917 increment B, plan
	// §6.4 / D1). Empty => "unknown". Set via SetWriterVersion from the
	// daemon's ldflags version before the first write.
	writerVersion string
}

// SetWriterVersion sets the build version stamped into the config-DB
// compatibility envelope on write (#1917). Call once at startup before
// any WriteActive; the daemon's single init path is the only caller.
func (db *DB) SetWriterVersion(v string) {
	db.writerVersion = v
}

// NewDB creates a DB rooted at the given directory.
// The directory is created if it doesn't exist.
func NewDB(dir string) (*DB, error) {
	// Durable creation (#1894 code-r1): on first boot the .configdb
	// entry itself must survive power loss, or a commit that reported
	// success can vanish with the whole directory. WriteFileDurable
	// only fsyncs .configdb (the file's parent), not /etc/xpf.
	//
	// Owner-only 0700 (#4056): this directory holds master.key plus the
	// active/candidate/rollback config DB — every file that may carry a
	// cleartext IKE PSK / auth key when master-password is not set. It is
	// a dedicated, xpf-owned subdirectory, so 0700 leaks nothing an
	// operator needs. The FILES themselves are 0600 (writeTreeMarked); the
	// dir mode is defense-in-depth so a non-owner cannot even enumerate
	// the slot names.
	if err := fsatomic.MkdirAllDurable(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	// MkdirAllDurable does not chmod an already-existing directory, so an
	// upgrade from a pre-#4056 build inherits the old 0755. Enforce 0700
	// here — the daemon owns the dir, so this is idempotent and cheap.
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("restrict db dir perms: %w", err)
	}
	// Sweep temp files leaked by a crash mid-write (#1894). fsatomic
	// names its temps ".<base>.tmp-<random>", so a daemon killed between
	// CreateTemp and rename leaves one behind; they are dead weight and
	// would accumulate forever in a long-lived .configdb.
	if stale, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*")); err == nil {
		for _, p := range stale {
			_ = os.Remove(p)
		}
	}
	return &DB{dir: dir}, nil
}

// activePath returns the path to the active config file.
func (db *DB) activePath() string {
	return filepath.Join(db.dir, "active.json")
}

// candidatePath returns the path to the candidate config file.
func (db *DB) candidatePath() string {
	return filepath.Join(db.dir, "candidate.json")
}

// rollbackPath returns the path for rollback slot n (1-based).
func (db *DB) rollbackPath(n int) string {
	return filepath.Join(db.dir, fmt.Sprintf("rollback.%d.json", n))
}

// ReadActive loads the active configuration from disk.
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadActive() (*config.ConfigTree, error) {
	tree, _, err := db.readTreeMeta(db.activePath())
	return tree, err
}

// ReadActiveMeta loads the active configuration AND the #1922 step-0
// committed marker. committed is TRUE when the file is absent (no marker to
// honor — Load treats absent as start-fresh anyway), TRUE for a legacy
// (no-envelope) DB, and TRUE for any enveloped DB that omits or sets
// committed=1; it is FALSE only for an enveloped DB this build wrote with
// the explicit never-committed marker (committed=0).
func (db *DB) ReadActiveMeta() (tree *config.ConfigTree, committed bool, err error) {
	return db.readTreeMeta(db.activePath())
}

// WriteActive persists the active configuration to disk atomically. The
// on-disk envelope is stamped committed=1 (a real successful commit/sync).
func (db *DB) WriteActive(tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.activePath(), tree, true)
}

// WriteActiveMarker persists tree as the active config with an explicit
// #1922 step-0 committed marker. committed=false writes the never-committed
// marker used by the Item 1b first-commit rollback (enterBootstrapMode):
// the empty tree on disk must NOT later classify as operator-committed-empty.
func (db *DB) WriteActiveMarker(tree *config.ConfigTree, committed bool) error {
	return db.writeTreeMarked(db.activePath(), tree, committed)
}

// ReadCandidate loads the candidate configuration from disk.
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadCandidate() (*config.ConfigTree, error) {
	tree, _, err := db.readTreeMeta(db.candidatePath())
	return tree, err
}

// WriteCandidate persists the candidate configuration to disk atomically.
func (db *DB) WriteCandidate(tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.candidatePath(), tree, true)
}

// DeleteCandidate removes the candidate file from disk.
func (db *DB) DeleteCandidate() error {
	err := os.Remove(db.candidatePath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete candidate: %w", err)
	}
	return nil
}

// ReadRollback loads a rollback configuration from slot n (1-based).
// Returns nil (no error) if the file doesn't exist.
func (db *DB) ReadRollback(n int) (*config.ConfigTree, error) {
	tree, _, err := db.readTreeMeta(db.rollbackPath(n))
	return tree, err
}

// WriteRollback persists a rollback configuration to slot n (1-based).
func (db *DB) WriteRollback(n int, tree *config.ConfigTree) error {
	return db.writeTreeMarked(db.rollbackPath(n), tree, true)
}

// DeleteRollback removes rollback slot n from disk.
func (db *DB) DeleteRollback(n int) error {
	err := os.Remove(db.rollbackPath(n))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete rollback %d: %w", n, err)
	}
	return nil
}

// confirmRecord is the persisted pending commit-confirmed state (#4577). It
// survives a daemon crash/reboot INSIDE the confirm window so the
// auto-rollback safety hatch is not silently lost: the in-memory
// time.AfterFunc rollback timer does not outlive the process, so without this
// record a crash before the operator confirms would make an UNCONFIRMED config
// permanent (the classic management-stranding trap). Store.Load re-arms the
// timer when the deadline is still in the future, or rolls back to PrevTree
// when it already passed during downtime.
type confirmRecord struct {
	// Deadline is the absolute wall-clock time the confirm window expires.
	Deadline time.Time `json:"deadline"`
	// PrevTree is the rollback target — the config that was active BEFORE the
	// still-unconfirmed commit-confirmed. For a NESTED confirmed commit it
	// stays the ORIGINAL last-confirmed config (mirrors confirmPrevTree).
	PrevTree *config.ConfigTree `json:"prev_tree"`
	// FirstCommit records that PrevTree is the empty bootstrap tree (the
	// commit-confirmed was the first commit on a fresh store, confirmPrevCfg
	// was nil at arm time). The rollback must then re-enter never-committed
	// state (committed=0 marker), matching the in-memory PromoteRollback
	// #1922 Item 1b path — not persist an operator-committed-empty config.
	FirstCommit bool `json:"first_commit"`
	// GuardedHash binds this record to the still-UNCONFIRMED config it guards —
	// the sha256 of the active tree's Format() text at arm time (#5835). On boot
	// recovery, if the loaded active config's hash differs, a later commit /
	// confirm has advanced the active config but this record's durable removal
	// had failed: the record is STALE and must NOT resurrect a rollback of an
	// unrelated, already-confirmed generation. An empty GuardedHash marks a
	// legacy record (written before #5835); recovery then skips the binding
	// check and behaves exactly as #4577, preserving the cross-upgrade
	// auto-rollback hatch (confirmRecord evolves via additive JSON fields).
	GuardedHash string `json:"guarded_hash,omitempty"`
	// Resolved marks this record as a RESOLUTION TOMBSTONE (#8565): the window
	// it describes was already resolved — confirmed, superseded, or rolled back
	// — and only the DURABLE DELETION of this file was still owed. Recovery must
	// therefore neither re-arm its timer nor revert to its PrevTree; it must
	// finish the deletion.
	//
	// Without it, "window pending" and "window RESOLVED but the deletion failed"
	// are the same bytes on disk. #5835's GuardedHash check separates them only
	// when the resolution CHANGED the active config; a confirmation does not
	// change it at all (`ConfirmCommit` / `ConfirmPendingOnDemotion` replace no
	// tree), so the hash still matches and recovery reverts a config the
	// operator explicitly confirmed.
	//
	// Written durably BEFORE the delete it precedes, and only at the point the
	// removal is actually reached — which #5473 already defers until the
	// resolving write is durable — so a tombstone never marks a window whose
	// resolution did not take effect. A tombstone write that itself fails
	// degrades to exactly the pre-#8565 behaviour, never worse.
	//
	// Additive, per this file's own contract: an older reader ignores the
	// unknown field and behaves as it does today.
	Resolved bool `json:"resolved,omitempty"`
}

// confirmPath returns the path to the pending commit-confirmed state file.
func (db *DB) confirmPath() string {
	return filepath.Join(db.dir, "confirm.json")
}

// WriteConfirm persists the pending commit-confirmed state durably (#4577):
// temp + fsync + rename + dir fsync, so the deadline+rollback-target survive
// power loss. The embedded PrevTree may carry secret leaves (IKE PSK, auth
// keys), so it is encrypted with the same master-password machinery as
// active.json (keyed off the prev tree's master-password leaf) and written
// owner-only 0600. No #1917 compatibility envelope is used — the file is
// transient recovery state, not a committed config, and confirmRecord evolves
// via additive JSON fields.
func (db *DB) WriteConfirm(rec *confirmRecord) error {
	data, err := db.encodeConfirm(rec)
	if err != nil {
		return err
	}
	// #9014: through the rbWriteFileDurable seam, not fsatomic directly, so a
	// test can fail the ARM write. Until this issue there was no way to
	// exercise the failure path at all, which is part of why it was the one
	// confirm-durability leg with no health state — nothing could reach it.
	if err := rbWriteFileDurable(db.confirmPath(), data, 0600); err != nil {
		return fmt.Errorf("persist confirm state: %w", err)
	}
	return nil
}

// ReadConfirm loads the pending commit-confirmed state, or (nil, nil) if none
// is persisted (#4577). A GENUINELY ABSENT record is not an error — the
// no-confirm-pending path returns (nil, nil).
//
// A record that is PRESENT but structurally or semantically DEGENERATE is
// rejected with an error rather than returned as a valid pending confirm
// (#5637, codex-review-181 M29). This mirrors the #5474 readTreeMeta hardening:
// json.Unmarshal of a top-level `null` (or `{}`) into *confirmRecord SUCCEEDS
// and yields a ZERO-VALUE record — Deadline is the zero time and PrevTree is
// nil. recoverPendingConfirmLocked would then read time.Now().After(zeroTime)
// as TRUE (an "expired" window) and synthesize a rollback to an EMPTY prev
// tree, silently WIPING the just-loaded active config to policy-absent
// (fail-open) on boot; or, inside a live window, re-arm a timer off a bogus
// deadline. requireJSONObject alone is insufficient — `{}` is a valid object
// yet carries no usable deadline/target — so both the raw-shape gate AND a
// decoded field check are required.
//
// recoverPendingConfirmLocked already treats a read error as fail-closed (log
// + skip restore, keep the loaded active config, never panic), so a degenerate
// record can no longer drive a bogus empty rollback.
func (db *DB) ReadConfirm() (*confirmRecord, error) {
	// #8597 (muse-004 K70): BOUNDED. This module's own answer to an unbounded
	// authoritative read is ReadBoundedFile (#6753/#4909) — which also refuses a
	// non-regular file — and the most privileged reads on the boot path were the
	// ones still using os.ReadFile.
	data, err := ReadBoundedFile(db.confirmPath(), MaxConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read confirm state: %w", err)
	}
	data, _, err = db.maybeDecryptTreeJSON(data, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt confirm state: %w", err)
	}
	// Reject a null/array/scalar top-level body BEFORE decoding: a literal
	// `null` decodes into a zero-value confirmRecord with NO error (#5637). The
	// encrypted write path always inner-marshals a struct to an object, so this
	// only rejects genuinely malformed plaintext/decrypted state, never a
	// legitimately-written record.
	if err := requireJSONObject(data); err != nil {
		return nil, fmt.Errorf("parse confirm state: %w", err)
	}
	rec := &confirmRecord{}
	if err := json.Unmarshal(data, rec); err != nil {
		return nil, fmt.Errorf("parse confirm state: %w", err)
	}
	// A structurally-valid object can still be semantically degenerate — `{}`
	// decodes with a zero Deadline and a nil PrevTree. A pending confirm without
	// a deadline is meaningless (the zero time is always "already expired", so
	// recovery would immediately roll back), and one without a rollback target
	// would revert to an empty tree. A legitimately-written record ALWAYS has a
	// real future deadline (time.Now().Add(window)) and a non-nil PrevTree
	// (confirmPrevTree = s.active.Clone(), non-nil even for a first commit —
	// FirstCommit distinguishes the empty-bootstrap case), so rejecting these
	// degenerate shapes never touches a valid record.
	if rec.Deadline.IsZero() {
		return nil, fmt.Errorf("parse confirm state: pending commit-confirmed record has no deadline")
	}
	if rec.PrevTree == nil {
		return nil, fmt.Errorf("parse confirm state: pending commit-confirmed record has no rollback target")
	}
	return rec, nil
}

// DeleteConfirm removes the pending commit-confirmed state file (#4577).
// Absent is not an error.
//
// The removal is a DURABLE transition (#4864): after a successful unlink the
// parent directory is fsynced so the directory-entry removal survives a
// crash/power-loss. WriteConfirm persists confirm.json through
// fsatomic.WriteFileDurable (temp + fsync + rename + dir fsync); without a
// matching dir fsync here a *successful* unlink is not durable, so a crash in
// the window before the dirent flushes can replay the stale confirm.json on
// reboot — and recoverPendingConfirmLocked would then revert an
// already-confirmed config (re-diverging a confirmed HA standby). The unlink
// and dir fsync route through the package durability seams (rbRemove/rbSyncDir,
// #3441) so a downgrade that drops the dir sync fails a test RED.
func (db *DB) DeleteConfirm() error {
	if err := rbRemove(db.confirmPath()); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("delete confirm state: %w", err)
		}
		// Already absent. This is EITHER "never existed" OR "a prior call
		// unlinked it but its dir fsync failed" — the removal is then not yet
		// durable and a crash could replay the stale dirent (#5835). The DB
		// layer cannot tell the two apart across calls, so it does NOT short-
		// circuit here: it falls through to the dir fsync below so an absent-
		// file RETRY still reaches the #4864 durability sync. The caller's
		// confirmRemoveDegraded flag carries the cross-call "sync owed" state;
		// this method keeps returning an error until a dir fsync succeeds, so a
		// post-unlink sync failure can never be laundered into a false success
		// by a subsequent absent-file retry.
	}
	if err := rbSyncDir(filepath.Dir(db.confirmPath())); err != nil {
		return fmt.Errorf("sync dir after delete confirm state: %w", err)
	}
	return nil
}

// readTreeMeta reads and parses a config tree from a JSON file, returning
// the #1922 step-0 committed marker alongside it. Returns (nil, true, nil)
// if the file doesn't exist (absent => start-fresh; committed is irrelevant
// but defaults true so an absent-DB caller never sees a spurious
// never-committed signal). A legacy (no-envelope) DB also reads committed.
func (db *DB) readTreeMeta(path string) (*config.ConfigTree, bool, error) {
	// #8597 (muse-004 K70): BOUNDED — see ReadConfirm above. This is the SSOT
	// the daemon must load to take over, so it was the least bounded read of
	// the most important file.
	data, err := ReadBoundedFile(path, MaxConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, true, nil
		}
		return nil, true, fmt.Errorf("read %s: %w", path, err)
	}
	// Config compatibility envelope (#1917 increment B). The envelope is
	// the OUTERMOST framing — a magic header line prepended to the
	// (possibly-encrypted) body. Strip+validate it BEFORE decryption so a
	// too-new DB fails closed here, never silently empty-loads. A body
	// with no envelope is a pre-floor (legacy) DB and is read unchanged
	// (committed defaults true — migration rule C3).
	committed := true
	// #7176 (C179-053): the AAD for the body is the stored header line, but
	// ONLY for envelopes stamped at or above envelopeAADFormatVersion. Below
	// that the body was sealed with nil AAD and must be opened the same way.
	//
	// The gate reads the STORED v=, not this build's constant, and that is what
	// makes a forced downgrade fail closed: rewriting a v2 header to v=1 selects
	// the nil-AAD path against a ciphertext sealed with AAD, so the tag check
	// fails. Editing anything else in a v2 header — the committed= marker
	// included — changes the AAD and fails the same way.
	var aad []byte
	if hasEnvelope(data) {
		body, hdr, eerr := stripEnvelope(data)
		if eerr != nil {
			return nil, true, fmt.Errorf("read %s: %w", path, eerr)
		}
		if hdr.FormatVersion >= envelopeAADFormatVersion {
			aad = envelopeHeaderLineBytes(data)
		}
		data = body
		committed = hdr.Committed
	}

	data, decrypted, err := db.maybeDecryptTreeJSON(data, aad)
	if err != nil {
		return nil, true, fmt.Errorf("decrypt %s: %w", path, err)
	}

	// Reject a body whose top-level JSON is not an OBJECT (#5474 fail-open).
	// Go's json.Unmarshal([]byte("null"), &ConfigTree{}) returns NO error and
	// leaves the tree at its zero value — a semantically EMPTY config. A
	// legacy/plaintext (or enveloped-but-unencrypted) active body of literal
	// `null` would therefore decode to an empty tree and Store.Load would
	// compile+boot it normally, so the firewall comes up with policy ABSENT
	// (fail-open) instead of failing closed. Syntactically-invalid bodies and
	// top-level arrays/scalars already error against the struct target, but
	// `null` is syntactically valid and decodes to zero policy — this is the
	// specific gap. Authoritative persisted state must REJECT malformed/partial
	// top-level JSON, so require a JSON object here.
	//
	// data is the FINAL plaintext ConfigTree body: the #1917 envelope has been
	// stripped and any AES-GCM ciphertext decrypted, so this frames the check
	// exactly where a plaintext ConfigTree JSON is about to be decoded. The
	// encrypted-envelope path is unaffected (its inner body always marshals
	// from a struct to an object), the valid empty config `{}` still passes,
	// and well-formed populated objects decode byte-for-byte as before.
	// Store.Load tags the returned error with ErrConfigDBUnreadable, so a null/
	// array/scalar DB becomes a fatal fail-closed boot, not a blind bootstrap.
	if err := requireJSONObject(data); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", path, err)
	}

	tree := &config.ConfigTree{}
	if err := json.Unmarshal(data, tree); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", path, err)
	}

	// Unexpected-plaintext warning (#4579 A4-06). When master-password is
	// set, every write path encrypts the body (maybeEncryptTreeJSON keyed
	// off the tree's master-password leaf), so a config that DECLARES a
	// master-password should never be read back as plaintext. If it is,
	// the file was written without the AES-GCM envelope — a downgrade to
	// an older build, a restore from an unencrypted backup, or tampering.
	// Reaching this state needs write access to the 0600/0700 .configdb
	// (root/owner), so it is not a privilege-escalation vector; the warn
	// makes the silent at-rest exposure visible instead of loading the
	// cleartext secrets without a trace. Boot-time / commit-paced read, so
	// a one-time slog.Warn is safe (never in a per-packet/-session loop).
	if !decrypted && masterPasswordPRF(tree) != "" {
		slog.Warn("configuration declares a master-password but was read as "+
			"UNENCRYPTED plaintext (expected an AES-GCM envelope) — the config "+
			"may have been downgraded, restored from an unencrypted backup, or "+
			"tampered with; secrets are exposed at rest",
			"path", path, "issue", "#4579")
	}
	return tree, committed, nil
}

// requireJSONObject rejects a persisted config body whose top-level JSON is
// not an OBJECT ("{...}"). It closes the #5474 fail-open gap: a top-level
// `null` decodes into *ConfigTree without error (zero value = empty config),
// and a top-level array or scalar, while already rejected by the struct
// target's own decode, is caught here first with an intention-revealing error.
// The valid empty config `{}` passes. The check inspects only the leading
// non-whitespace byte (JSON insignificant whitespace is space/tab/CR/LF); the
// subsequent json.Unmarshal still fully validates object well-formedness.
func requireJSONObject(data []byte) error {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return fmt.Errorf("config body is empty, not a JSON object")
	}
	if trimmed[0] != '{' {
		// Surface a short prefix so a `null`/array/scalar body is identifiable
		// in the fail-closed boot log without dumping a large or secret-bearing
		// body.
		snippet := trimmed
		if len(snippet) > 16 {
			snippet = snippet[:16]
		}
		return fmt.Errorf("config body is not a JSON object (top-level starts with %q); "+
			"a null/array/scalar body decodes to an EMPTY config and would boot with "+
			"policy absent (fail-open) — refusing", string(snippet))
	}
	return nil
}

// writeTree persists a config tree to a JSON file durably (#1894,
// DurableState class): temp + fsync + rename + dir fsync, so a commit
// that reported success cannot be silently lost to a power cut — the
// guarantee the #1799 persist-before-promote contract is built on.
func (db *DB) writeTreeMarked(path string, tree *config.ConfigTree, committed bool) error {
	data, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// #7176 (C179-053): the header must exist BEFORE the seal, because it IS
	// the AAD. Encryption-ness is known here (the same predicate
	// maybeEncryptTreeJSON uses), which also lets min-reader be exact: only an
	// ENCRYPTED v2 envelope is unreadable by a pre-v2 build, so only that case
	// raises the floor. An unencrypted v2 envelope has no ciphertext to bind
	// and stays readable by an older reader — stamping min-reader=2 on it would
	// refuse a downgrade for no reason.
	//
	// The alternative — leaving min-reader at 1 always — is also fail-closed,
	// but an old build would report an opaque "decrypt config tree" failure
	// instead of the envelope layer's explicit "too new" message. A confusing
	// error during a rollback is the worst time for one.
	encrypted := masterPasswordPRF(tree) != ""
	minReader := EnvelopeMinReaderVersion
	if encrypted {
		minReader = envelopeAADFormatVersion
	}
	header := buildEnvelopeHeaderLine(db.writerVersion, committed, minReader)

	var aad []byte
	if encrypted {
		aad = header
	}
	data, err = db.maybeEncryptTreeJSON(data, tree, aad)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	// Wrap the (possibly-encrypted) body in the config compatibility
	// envelope (#1917 increment B). The magic header line makes a pre-floor
	// reader fail closed (its json.Unmarshal rejects a leading '#'), so a
	// future format bump can never silently empty-load on an old reader.
	// committed stamps the #1922 step-0 marker.
	out := make([]byte, 0, len(header)+len(data))
	out = append(out, header...)
	data = append(out, data...)

	// #9617: refuse bytes the reader will refuse. Load, rollback and candidate
	// reads all go through ReadBoundedFile(path, MaxConfigSize), and a JSON
	// tree can be many times its config text (18x for a run of small groups
	// stanzas), so a config that passes every INPUT bound (the parse budget,
	// checkConfigSize) can still serialize past the ceiling. Checked on the
	// envelope-wrapped, possibly-encrypted bytes, which are exactly what the
	// reader counts, and BEFORE the write: the file on disk stays the previous
	// readable generation, and a commit fails pre-promotion with its candidate
	// intact instead of succeeding into a DB the next Load refuses.
	if err := checkPersistSize(path, len(data)); err != nil {
		return err
	}

	// Owner-only 0600 (#4056): active.json / candidate.json /
	// rollback.N.json carry the full config, including secret leaves (IKE
	// PSK, WireGuard/auth keys, SNMP community). When master-password is
	// set the body is AES-GCM encrypted, but when it is not the secrets are
	// cleartext — either way the DB must not be world-readable. The daemon
	// runs as the owner, so 0600 does not affect read-back.
	if err := fsatomic.WriteFileDurable(path, data, 0600); err != nil {
		return fmt.Errorf("persist %s: %w", path, err)
	}
	return nil
}

// encodeConfirm produces the exact bytes WriteConfirm persists: the indented
// record, encrypted under the rollback target's master-password when it has
// one. It refuses a record ReadConfirm would refuse (#9617), so the
// commit-confirmed path can size-check the record BEFORE it promotes anything
// (commitConfirmedLocked) using the same function the write uses.
func (db *DB) encodeConfirm(rec *confirmRecord) ([]byte, error) {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal confirm state: %w", err)
	}
	data, err = db.maybeEncryptTreeJSON(data, rec.PrevTree, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt confirm state: %w", err)
	}
	if err := checkPersistSize(db.confirmPath(), len(data)); err != nil {
		return nil, err
	}
	return data, nil
}

// ErrPersistExceedsReadCeiling reports that an artifact the store is about to
// persist is larger than the ceiling its own reader enforces (#9617).
//
// Every tree and record this package writes is read back through
// ReadBoundedFile(path, MaxConfigSize): active.json at Load, rollback.N.json,
// candidate.json, and confirm.json at boot recovery. Before #9617 no writer
// checked the bytes it was about to persist against that ceiling, so an
// accepted commit could write an active DB the next Load refuses
// (ErrConfigDBUnreadable: the daemon does not come back), and a successful
// commit confirmed could write a confirm.json the next boot refuses (the
// rollback window is silently lost). A writer's domain must be a subset of its
// reader's; this is the writer half of that invariant.
var ErrPersistExceedsReadCeiling = errors.New("refusing to persist an artifact its reader would refuse")

// checkPersistSize applies the reader's exact boundary: ReadBounded refuses
// len > max and accepts len == max, so this refuses n > MaxConfigSize and
// nothing else. TestPersistSizeGateMatchesReaderBoundary_9617 pins the pair.
func checkPersistSize(path string, n int) error {
	if n > MaxConfigSize {
		return fmt.Errorf("%w: %s would be %d bytes, over the %d byte ceiling enforced when it is read back, so the next load would reject it",
			ErrPersistExceedsReadCeiling, filepath.Base(path), n, MaxConfigSize)
	}
	return nil
}
