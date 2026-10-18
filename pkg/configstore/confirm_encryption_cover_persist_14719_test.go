package configstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #14719 (D18-01): DB.writeConfirmCover is cleared on return from
// commitConfirmedLocked, so every later WriteConfirm of the SAME window
// strips the #14172 confirm encryption.
//
// The arm sets writeConfirmCover = masterPasswordPRF(committedTree) and
// clears it by defer (store_commit.go). encodeConfirm resolves
// confirmEncryptionPRF(rec.PrevTree, cover): PrevTree's own profile when
// it has one, else the cover, else plaintext. In the exact #14172
// scenario (PrevTree plaintext, guarded tree ADDs a master-password)
// PrevTree has no profile, so once the defer clears the cover every
// subsequent write of that record marshals the full PrevTree (all secret
// leaves) in CLEARTEXT and fsyncs it:
//
//   - resolution tombstone (markConfirmResolvedLocked) — fires on EVERY
//     confirm resolution in this configuration;
//   - phase-3 finalization retry (persistRetryLoop, confirmArmRec);
//   - boot rebind / migration rewrites (store_persist.go);
//   - FIRST sentinel (store_persist.go).
//
// Crash or delete-failure leaves the tombstone indefinitely, and even on
// success cleartext blocks were durably written. This defeats the
// operator's act of enabling master-password.
//
// Fix contract: the cover profile must be RE-DERIVABLE from durable
// state at any later write, not only carried in a transient DB field.
// The envelope is self-describing (env.PRF) and ReadConfirm already
// decrypts it, so a later writer that reads the on-disk record before
// rewriting it can recover the profile the window was armed under and
// re-seal under it. A tree-based alternative (later writers knowing the
// guarded/active tree's profile) satisfies the same contract provided
// every writer below ends encrypted.
//
// RED on revert: dropping the recovery (keying later writes off
// PrevTree + the transient cover alone) writes each record below in
// cleartext -> the raw-bytes assertions fail.
//
// Distinct cells per writer (issue scope: keep regression cells distinct
// per claim/writer):

const secret14719 = "s3cret-psk-14719"

func assertConfirmEncrypted14719(t *testing.T, db *DB, what string) {
	t.Helper()
	_, body, envelope := confirmRaw14172(t, db)
	if !envelope {
		t.Fatalf("%s: confirm.json is NOT an AES-GCM envelope although the window was armed "+
			"under a guarded master-password (#14719 plaintext strip): %s", what, body)
	}
	if bytes.Contains(body, []byte(secret14719)) {
		t.Fatalf("%s: confirm.json body carries the rollback secret in cleartext (#14719)", what)
	}
	if !bytes.Contains(body, []byte(encryptedTreeFormat)) {
		t.Fatalf("%s: confirm.json body lacks the %q envelope marker: %s", what, encryptedTreeFormat, body)
	}
	env, ok, err := unmarshalEnvelope(body)
	if err != nil || !ok {
		t.Fatalf("%s: unmarshalEnvelope: ok=%v err=%v", what, ok, err)
	}
	if env.PRF == "" {
		t.Fatalf("%s: confirm envelope carries no PRF profile", what)
	}
	if _, err := db.ReadConfirm(); err != nil {
		t.Fatalf("%s: ReadConfirm on the rewritten record: %v", what, err)
	}
}

// armEncryptedWindow14719 drives the real end-to-end #14172 scenario:
// plaintext base with a secret, then CommitConfirmed adding a
// master-password. Returns the store with the encrypted window armed.
func armEncryptedWindow14719(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("security ike policy p1 pre-shared-key ascii-text " + secret14719); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(base): %v", err)
	}
	if err := s.SetFromInput("system master-password pseudorandom-function sha256"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	// Fixture control: arm itself is encrypted (the #14172 fix).
	assertConfirmEncrypted14719(t, s.db, "arm (fixture control)")
	// The transient cover is gone after commitConfirmedLocked returns —
	// that is the exact precondition of #14719.
	if s.db.writeConfirmCover.profile != "" {
		t.Fatal("fixture broken: writeConfirmCover still set after arm returned, so the #14719 precondition does not hold")
	}
	return s
}

// Cell 1 — resolution tombstone. ConfirmCommit resolves the window;
// markConfirmResolvedLocked rewrites the SAME record with Resolved=true
// before deleting it. If the delete then fails/crashes, the tombstone
// is what survives on disk. It must stay encrypted.
func TestConfirmTombstoneStaysEncryptedAfterArm14719(t *testing.T) {
	s := armEncryptedWindow14719(t)

	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	// ConfirmCommit deletes confirm.json after tombstoning. Re-drive the
	// tombstone writer directly against the armed record shape to assert
	// the bytes it WOULD leave behind if the delete failed: read the
	// record back is impossible post-delete, so instead exercise the
	// writer path in isolation below. Here assert the delete landed.
	if _, err := os.Stat(s.db.confirmPath()); !os.IsNotExist(err) {
		t.Fatalf("confirm.json should be deleted after successful ConfirmCommit, stat err=%v", err)
	}
}

// Cell 1b — tombstone writer in isolation: arm, read the record (as
// resolveConfirmRemovalLocked does), then tombstone it with the cover
// already cleared (post-arm state). Raw bytes must stay encrypted.
func TestMarkConfirmResolvedKeepsEncryption14719(t *testing.T) {
	s := armEncryptedWindow14719(t)

	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm armed record: rec=%v err=%v", rec, err)
	}
	s.mu.Lock()
	s.markConfirmResolvedLocked(rec)
	s.mu.Unlock()

	assertConfirmEncrypted14719(t, s.db, "resolution tombstone")

	got, err := s.db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm tombstone: %v", err)
	}
	if !got.Resolved {
		t.Fatal("tombstone lost its Resolved marker")
	}
}

// Cell 2 — phase-3 finalization retry. When the final writeConfirmState
// in commitConfirmedLocked fails, noteConfirmArmFailureLocked stashes
// the record in confirmArmRec and persistRetryLoop re-drives
// db.WriteConfirm(confirmArmRec) long after the cover was cleared.
func TestConfirmArmRetryKeepsEncryption14719(t *testing.T) {
	s := armEncryptedWindow14719(t)

	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm armed record: rec=%v err=%v", rec, err)
	}
	// Direct WriteConfirm of the stashed record with no cover set — the
	// exact retry write persistRetryLoop performs.
	if err := s.db.WriteConfirm(rec); err != nil {
		t.Fatalf("retry WriteConfirm: %v", err)
	}
	assertConfirmEncrypted14719(t, s.db, "finalization retry (direct WriteConfirm, cover cleared)")
}

// Cell 3 — boot recovery rewrite. A restarted store that Loads the
// encrypted window and then rewrites the record (rebind/migration path
// via writeConfirmState) must keep it encrypted. Simulated by a plain
// WriteConfirm from a fresh DB over the same directory: the fresh DB
// never had a cover set, exactly like a post-restart writer.
func TestConfirmRewriteAfterRestartKeepsEncryption14719(t *testing.T) {
	s := armEncryptedWindow14719(t)
	dir := s.db.dir

	fresh, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB(fresh): %v", err)
	}
	rec, err := fresh.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("fresh ReadConfirm: rec=%v err=%v", rec, err)
	}
	if err := fresh.WriteConfirm(rec); err != nil {
		t.Fatalf("fresh WriteConfirm (boot rewrite): %v", err)
	}
	assertConfirmEncrypted14719(t, fresh, "boot rewrite from fresh DB (no cover ever set)")
}

// Cell 4 — FIRST sentinel shape: same record, deadline moved to the
// past sentinel, rewritten via WriteConfirm with no cover (the
// store_persist.go:1039 write). PrevTree is unchanged, so this is the
// same mechanism with a different record field delta.
func TestConfirmFirstSentinelRewriteKeepsEncryption14719(t *testing.T) {
	s := armEncryptedWindow14719(t)

	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm armed record: rec=%v err=%v", rec, err)
	}
	rec.Deadline = time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC)
	if err := s.db.WriteConfirm(rec); err != nil {
		t.Fatalf("FIRST sentinel WriteConfirm: %v", err)
	}
	assertConfirmEncrypted14719(t, s.db, "FIRST sentinel rewrite")
}

// Control — a record armed in plaintext (neither tree ever declared a
// master-password) must STAY plaintext on later writes: cover recovery
// must not invent encryption (or create master.key pressure) for
// windows that were never encrypted. Mirrors the #14172 control at the
// later-writer layer.
func TestConfirmPlaintextWindowStaysPlaintextOnRewrite14719(t *testing.T) {
	prev := tree14172(t, "", secret14719)
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	rec := &confirmRecord{Deadline: time.Now().Add(10 * time.Minute), PrevTree: prev}
	if err := db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm(arm): %v", err)
	}
	if _, _, envelope := confirmRaw14172(t, db); envelope {
		t.Fatal("fixture broken: plaintext window was encrypted at arm")
	}
	// Later writer: tombstone shape.
	tomb := *rec
	tomb.Resolved = true
	if err := db.WriteConfirm(&tomb); err != nil {
		t.Fatalf("WriteConfirm(tombstone): %v", err)
	}
	if _, _, envelope := confirmRaw14172(t, db); envelope {
		t.Fatal("plaintext window became encrypted on tombstone rewrite — cover recovery over-applied")
	}
	if _, err := db.ReadConfirm(); err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
}
