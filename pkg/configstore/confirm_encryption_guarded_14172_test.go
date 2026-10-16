package configstore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14172 (D8-05): `commit confirmed` ADDING a master-password over a
// previous PLAINTEXT config wrote confirm.json in cleartext. The record
// serializes the whole confirmRecord JSON — Deadline, the PrevTree
// rollback target with every secret leaf it carries, hashes and flags —
// but carries NO field for the guarded (newly committed) tree: that tree
// reaches the record only as GuardedHash. encodeConfirm keyed the
// encryption profile off rec.PrevTree alone (masterPasswordPRF(PrevTree)
// == "" → plaintext pass-through), so the guarded commit's active.json
// was AES-GCM encrypted while confirm.json from the same commit sat on
// disk readable by anyone with access to the 0600 file (backup scoped to
// the file, forensic reader, the operator's own `cat`) — and ReadConfirm
// accepted it with no signal, discarding the `decrypted` flag.
//
// The fix: encodeConfirm seals under confirmEncryptionPRF(PrevTree,
// cover) — the rollback target's own profile when it has one, else the
// guarded tree's. commitConfirmedLocked carries the guarded profile on
// the DB (writeConfirmCover) for the provisional/final writes of the
// arm, because the public WriteConfirm signature is the persistence
// boundary and cannot grow a tree parameter without threading it
// through every tombstone/migration/retry write. ReadConfirm keeps the
// decrypted flag and warns (#4579 A4-06 parity) when a plaintext record's
// PrevTree declares a master-password; recovery adds the guarded
// (active) tree as a second opinion. Legacy plaintext records stay
// READABLE — a global ban would strand pending windows across upgrade.
//
// Access model (documented, not asserted as a fix): confirm.json is
// 0600 inside the 0700 .configdb, and the AES-GCM key (master.key) sits
// in the same directory WITHOUT any TPM/HSM sealing. A reader who
// obtains the whole directory or root on the box can decrypt regardless;
// the cover defends the body-only reader (a backup or disclosure scoped
// to confirm.json / active.json), matching the #6856 threat table. A
// keyless body-sha256 or MAC alone would not have been a fix: a writer
// who can rewrite the root-owned file can recompute an unkeyed digest,
// and the encrypted form already gets AEAD integrity from AES-GCM.
//
// RED on revert, per mechanism: (a) dropping the cover (keying off
// PrevTree alone) writes the guarded record in cleartext → Test 1 and
// Test 5 fail on the raw-bytes assertions; (b) dropping ReadConfirm's
// retained-flag warn → Test 3 fails; (c) dropping recovery's guarded
// second-opinion warn → Test 4 fails; (d) re-keying the BOTH-master
// case off the guarded tree → Test 2's PRF assertion fails.

const secret14172 = "s3cret-psk-14172"

func tree14172(t *testing.T, masterPassword string, secret string) *config.ConfigTree {
	t.Helper()
	text := masterPassword + `
security {
	ike {
		policy p1 {
			pre-shared-key ascii-text "` + secret + `";
		}
	}
}`
	root, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse 14172 fixture: %v", perrs)
	}
	return &config.ConfigTree{Children: root.Children}
}

func confirmRaw14172(t *testing.T, db *DB) (raw []byte, body []byte, envelope bool) {
	t.Helper()
	raw, err := os.ReadFile(db.confirmPath())
	if err != nil {
		t.Fatalf("read confirm.json: %v", err)
	}
	body, err = stripConfirmEnvelope(raw)
	if err != nil {
		t.Fatalf("stripConfirmEnvelope: %v", err)
	}
	_, envelope, err = unmarshalEnvelope(body)
	if err != nil {
		t.Fatalf("unmarshalEnvelope: %v", err)
	}
	return raw, body, envelope
}

func TestConfirmEncryptedWhenGuardedTreeAddsMasterPassword14172(t *testing.T) {
	// Previous config: PLAINTEXT rollback target carrying a secret, no
	// master-password anywhere (so pre-fix encodeConfirm passed the
	// record through unencrypted).
	prev := tree14172(t, "", secret14172)
	guarded := tree14172(t, `system { master-password { pseudorandom-function sha256; } }`, secret14172)

	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	rec := &confirmRecord{
		Deadline:    time.Now().Add(10 * time.Minute),
		PrevTree:    prev,
		GuardedHash: guardedConfigHash(guarded),
	}
	// The arm sets the cover from the guarded tree; the fixture mirrors
	// commitConfirmedLocked. Without a cover the DB-default "" profile
	// keeps the legacy plaintext behaviour (Test 6 pins that control).
	db.writeConfirmCover = confirmEncryptionCover{profile: masterPasswordPRF(guarded)}
	if err := db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	_, body, envelope := confirmRaw14172(t, db)
	if !envelope {
		t.Fatalf("confirm.json is NOT an AES-GCM envelope although the guarded tree declares "+
			"a master-password — the #14172 plaintext exposure: %s", body)
	}
	if bytes.Contains(body, []byte(secret14172)) {
		t.Fatal("confirm.json body carries the rollback target's secret in cleartext")
	}
	if !bytes.Contains(body, []byte(encryptedTreeFormat)) {
		t.Fatalf("confirm.json body lacks the %q envelope marker: %s", encryptedTreeFormat, body)
	}
	env, ok, err := unmarshalEnvelope(body)
	if err != nil || !ok {
		t.Fatalf("unmarshalEnvelope: ok=%v err=%v", ok, err)
	}
	if env.PRF != masterPasswordPRF(guarded) {
		t.Fatalf("confirm envelope PRF = %q, want the guarded tree's %q", env.PRF, masterPasswordPRF(guarded))
	}

	// The encrypted record still round-trips and decrypts to the same
	// rollback target — encryption must not lose the window.
	got, err := db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
	if got == nil || got.PrevTree == nil {
		t.Fatalf("ReadConfirm lost the rollback target: %+v", got)
	}
	if !strings.Contains(got.PrevTree.Format(), secret14172) {
		t.Fatal("decrypted PrevTree lost its secret leaf")
	}
	if got.GuardedHash != rec.GuardedHash {
		t.Fatalf("GuardedHash round-trip mismatch: got %q want %q", got.GuardedHash, rec.GuardedHash)
	}
}

func TestConfirmKeepsPrevProfileWhenBothTreesDeclareMasterPassword14172(t *testing.T) {
	// Nested re-arm over an already-encrypted config: BOTH trees declare
	// a master-password (with different selectors). The record keeps the
	// PrevTree profile it was armed under — a pre-fix reader must still
	// open it — rather than silently re-keying to the guarded selector.
	prev := tree14172(t, `system { master-password { pseudorandom-function sha512; } }`, secret14172)
	guarded := tree14172(t, `system { master-password { pseudorandom-function sha256; } }`, secret14172)

	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	rec := &confirmRecord{
		Deadline:    time.Now().Add(10 * time.Minute),
		PrevTree:    prev,
		GuardedHash: guardedConfigHash(guarded),
	}
	db.writeConfirmCover = confirmEncryptionCover{profile: masterPasswordPRF(guarded)}
	if err := db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	_, body, envelope := confirmRaw14172(t, db)
	if !envelope {
		t.Fatalf("confirm.json is not encrypted although both trees declare a master-password: %s", body)
	}
	env, _, err := unmarshalEnvelope(body)
	if err != nil {
		t.Fatalf("unmarshalEnvelope: %v", err)
	}
	if env.PRF != masterPasswordPRF(prev) {
		t.Fatalf("confirm envelope PRF = %q, want the rollback target's %q (the profile the "+
			"window was armed under)", env.PRF, masterPasswordPRF(prev))
	}
	if bytes.Contains(body, []byte(secret14172)) {
		t.Fatal("confirm.json body carries the secret in cleartext")
	}
	if _, err := db.ReadConfirm(); err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
}

func TestReadConfirmWarnsOnPlaintextRecordWhosePrevDeclaresMasterPassword14172(t *testing.T) {
	buf := captureWarnLogs(t)

	// Hand-write a LEGACY plaintext record whose rollback target carries
	// a master-password (the pre-#14172 / downgrade shape): a raw JSON
	// body under the confirm envelope, no AES-GCM envelope.
	prev := tree14172(t, `system { master-password { pseudorandom-function sha256; } }`, secret14172)
	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	// Bypass encodeConfirm so the bytes stay plaintext, as an older build
	// (or a tampered restore) would have left them. Marshal the record the
	// same way encodeConfirm does — the confirmRecord JSON keys, not the
	// tree's FormatJSON (which uses different keys and would trip the
	// strict DisallowUnknownFields decode).
	plain := &confirmRecord{Deadline: time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC), PrevTree: prev}
	body, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("marshal legacy record: %v", err)
	}
	raw := append([]byte(confirmEnvelopeMagic+" v=1\n"), body...)
	if err := os.WriteFile(db.confirmPath(), raw, 0600); err != nil {
		t.Fatalf("write legacy plaintext confirm.json: %v", err)
	}

	rec, err := db.ReadConfirm()
	if err != nil {
		t.Fatalf("a legacy plaintext record must stay READABLE (stranding the window is worse): %v", err)
	}
	if rec == nil {
		t.Fatal("ReadConfirm returned nil for a readable legacy record")
	}
	if !strings.Contains(buf.String(), "UNENCRYPTED plaintext") {
		t.Fatalf("ReadConfirm did not warn on a plaintext record whose PrevTree declares a "+
			"master-password; logs: %q", buf.String())
	}
}

func TestRecoveryWarnsOnPlaintextRecordGuardedByMasterPasswordActive14172(t *testing.T) {
	buf := captureWarnLogs(t)
	path := filepath.Join(t.TempDir(), "config")

	// Active (guarded) config declares a master-password + secret.
	// Rollback target is plaintext (pre-#14172 shape).
	guarded := tree14172(t, `system { master-password { pseudorandom-function sha256; } }`, secret14172)
	prev := tree14172(t, "", "rollback-secret-14172")

	armed := newTestStoreAt(t, path)
	if err := armed.db.WriteActive(guarded); err != nil {
		t.Fatalf("WriteActive(guarded): %v", err)
	}
	rec := &confirmRecord{
		Deadline:    time.Now().Add(10 * time.Minute),
		PrevTree:    prev,
		GuardedHash: guardedConfigHash(guarded),
	}
	// Write WITHOUT setting the cover: the legacy plaintext bytes an older
	// build would have persisted for this exact window.
	if err := armed.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm(legacy): %v", err)
	}
	if _, _, envelope := confirmRaw14172(t, armed.db); envelope {
		t.Fatal("fixture broken: the legacy record was encrypted, so the recovery warn below proves nothing")
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(buf.String(), "UNENCRYPTED plaintext") {
		t.Fatalf("recovery did not warn that the plaintext confirm record is guarded by a "+
			"master-password active config; logs: %q", buf.String())
	}
	// The legacy window still recovers: the record was not rejected.
	if !restarted.IsConfirmPending() {
		t.Fatal("the legacy plaintext window must still re-arm on Load (readable, not stranded)")
	}
}

func TestCommitConfirmedEncryptsConfirmWhenAddingMasterPassword14172(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Base: plaintext config WITH a secret, no master-password.
	if err := s.SetFromInput("security ike policy p1 pre-shared-key ascii-text " + secret14172); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(base): %v", err)
	}
	// Guarded commit: ADDS the master-password (plus keeps the secret).
	if err := s.SetFromInput("system master-password pseudorandom-function sha256"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}

	// active.json from the same commit is encrypted (control).
	rawActive, err := os.ReadFile(s.db.activePath())
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	if !strings.Contains(string(rawActive), encryptedTreeFormat) {
		t.Fatal("fixture broken: active.json was not encrypted, so the confirm.json assertion proves nothing")
	}

	_, body, envelope := confirmRaw14172(t, s.db)
	if !envelope {
		t.Fatalf("confirm.json is NOT encrypted although CommitConfirmed added a master-password "+
			"over a plaintext rollback target (#14172): %s", body)
	}
	if bytes.Contains(body, []byte(secret14172)) {
		t.Fatal("confirm.json carries the secret in cleartext although the guarded commit declares a master-password")
	}
	env, _, err := unmarshalEnvelope(body)
	if err != nil {
		t.Fatalf("unmarshalEnvelope: %v", err)
	}
	if env.PRF == "" {
		t.Fatal("confirm envelope carries no PRF profile")
	}
	if _, err := s.db.ReadConfirm(); err != nil {
		t.Fatalf("ReadConfirm on the armed record: %v", err)
	}
}

func TestConfirmRecordWithoutCoverStaysPlaintextWhenNeitherTreeDeclares14172(t *testing.T) {
	// Control: no master-password in either tree (and no cover set, as on
	// every non-arm WriteConfirm path) → the record stays plaintext JSON
	// and round-trips. Over-encrypting here would create master.key files
	// on boxes that never opted into encryption and break pre-fix readers
	// for no gain.
	prev := tree14172(t, "", secret14172)

	db, err := NewDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	rec := &confirmRecord{Deadline: time.Now().Add(10 * time.Minute), PrevTree: prev}
	if err := db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}
	_, body, envelope := confirmRaw14172(t, db)
	if envelope {
		t.Fatalf("confirm.json was encrypted although no tree declares a master-password: %s", body)
	}
	if _, err := db.ReadConfirm(); err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
}

func TestTamperedPlaintextConfirmIsContainedNotRolledBack14172(t *testing.T) {
	// A plaintext confirm record rewritten by someone who can already
	// write the root-owned file: flip a GuardedHash nibble so the record
	// no longer binds the active config. Recovery must stale-drop it
	// (never roll back to its PrevTree), exactly as the existing #5835
	// binding requires — the plaintext form gets no NEW trust from
	// #14172, and an unkeyed hash/MAC alone would not change this (the
	// writer can recompute it). The encrypted form's integrity comes
	// from AES-GCM, not from an added checksum.
	path := filepath.Join(t.TempDir(), "config")
	guarded := tree14172(t, `system { master-password { pseudorandom-function sha256; } }`, secret14172)
	prev := tree14172(t, "", "rollback-secret-14172")

	armed := newTestStoreAt(t, path)
	if err := armed.db.WriteActive(guarded); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	rec := &confirmRecord{
		Deadline:    time.Now().Add(10 * time.Minute),
		PrevTree:    prev,
		GuardedHash: guardedConfigHash(guarded),
	}
	if err := armed.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	// Tamper: rewrite the file with a one-character hash change.
	raw, err := os.ReadFile(armed.db.confirmPath())
	if err != nil {
		t.Fatalf("read confirm.json: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(rec.GuardedHash[:8]),
		[]byte(strings.Repeat("0", 8)), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture broken: tamper did not change the record bytes")
	}
	if err := os.WriteFile(armed.db.confirmPath(), tampered, 0600); err != nil {
		t.Fatalf("write tampered confirm.json: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if restarted.IsConfirmPending() {
		t.Fatal("a tampered plaintext record whose hash no longer binds the active config must be stale-dropped, not re-armed")
	}
	if restarted.ActiveConfig() == nil {
		t.Fatal("ActiveConfig is nil after stale-drop")
	}
	activeTree, err := restarted.db.ReadActive()
	if err != nil || activeTree == nil {
		t.Fatalf("active config unreadable after stale-drop: %v", err)
	}
	if !strings.Contains(activeTree.Format(), secret14172) {
		t.Fatal("recovery rolled back away from the guarded config to the tampered record's PrevTree")
	}
}
