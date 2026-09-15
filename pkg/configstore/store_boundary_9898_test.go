package configstore

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore/journal"
)

var errInjected9898 = errors.New("injected 9898 failure")

func mkTree9898() *config.ConfigTree {
	return &config.ConfigTree{}
}

// TestDBRejectsUnknownTopLevelKeys_9898 (F-001) pins the key-set check on the
// final plaintext body. requireJSONObject tests only the leading byte and the
// plain json.Unmarshal into ConfigTree drops unknown keys, so on base ANY JSON
// object boots as a (possibly empty) policy with no signal. Post-fix the
// top-level key set must be exactly {"Children"} (case-folded, matching
// encoding/json); anything else fails closed. The valid empty config `{}` is
// deliberately ACCEPTED (the #5474 cell pins it), as are case variants of the
// one known key. Nested decode stays lenient (additive Node evolution must not
// brick a boot) — only the top level is gated.
//
// RED on base: every reject/ subtest reads back with nil error.
func TestDBRejectsUnknownTopLevelKeys_9898(t *testing.T) {
	reject := []struct {
		name string
		body string
	}{
		{"fully unknown object boots empty", `{"bogus":{}}`},
		{"unknown key beside valid null", `{"Children":null,"evil":1}`},
		{"unknown key beside valid array", `{"Children":[],"x":0}`},
		{"unknown key case-mangled valid plus junk", `{"children":null,"EVIL":null}`},
	}
	accept := []struct {
		name string
		body string
	}{
		{"empty object is the valid empty config", `{}`},
		{"empty object with whitespace", "\n  {}\n"},
		{"explicit null children", `{"Children":null}`},
		{"case-folded known key", `{"children":null}`},
		{"populated object", `{"Children":[{"Keys":["system"]}]}`},
	}

	frame := func(t *testing.T, enveloped bool, body string) *DB {
		t.Helper()
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatalf("NewDB: %v", err)
		}
		raw := []byte(body)
		if enveloped {
			raw = wrapEnvelope(raw, "9.9.9", true, EnvelopeMinReaderVersion)
		}
		if err := os.WriteFile(db.activePath(), raw, 0600); err != nil {
			t.Fatalf("write active.json: %v", err)
		}
		return db
	}

	for _, enveloped := range []bool{false, true} {
		framing := "plaintext"
		if enveloped {
			framing = "enveloped"
		}
		for _, tc := range reject {
			t.Run("reject/"+framing+"/"+tc.name, func(t *testing.T) {
				db := frame(t, enveloped, tc.body)
				tree, _, err := db.ReadActiveMeta()
				if err == nil {
					t.Fatalf("ReadActiveMeta(%q) = nil error (tree=%+v); want fail-closed on unknown top-level keys", tc.body, tree)
				}
			})
		}
		for _, tc := range accept {
			t.Run("accept/"+framing+"/"+tc.name, func(t *testing.T) {
				db := frame(t, enveloped, tc.body)
				tree, _, err := db.ReadActiveMeta()
				if err != nil {
					t.Fatalf("ReadActiveMeta(%q) errored: %v; want success", tc.body, err)
				}
				if tree == nil {
					t.Fatalf("ReadActiveMeta(%q) returned nil tree; want non-nil valid tree", tc.body)
				}
			})
		}
	}
}

// TestDBRejectsUnknownKeysInEncryptedBody_9898 (F-001, encrypted leg) pins
// that the key-set gate sits on the FINAL plaintext body — after envelope
// strip AND decrypt — so an unknown top-level key smuggled inside the
// AES-GCM envelope is also refused. The seal is produced by the production
// maybeEncryptTreeJSON (not re-implemented), and the control proves a valid
// encrypted tree still round-trips.
func TestDBRejectsUnknownKeysInEncryptedBody_9898(t *testing.T) {
	db := newEncDB(t)
	tree := encryptedTree(t)
	header := buildEnvelopeHeaderLine("test-1.0", true, envelopeAADFormatVersion)
	sealed, err := db.maybeEncryptTreeJSON([]byte(`{"Children":null,"evil":1}`), tree, header)
	if err != nil {
		t.Fatalf("seal bad body: %v", err)
	}
	out := make([]byte, 0, len(header)+len(sealed))
	out = append(out, header...)
	out = append(out, sealed...)
	if err := os.WriteFile(db.activePath(), out, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ReadActiveMeta(); err == nil {
		t.Fatalf("ReadActiveMeta(encrypted body with unknown key) = nil error; want fail-closed")
	} else if !strings.Contains(err.Error(), "unknown top-level key") {
		t.Fatalf("error %q does not name the key gate; want the F-001 refusal, not another layer", err)
	}

	// Control: a valid encrypted tree round-trips through the same gate.
	db2 := newEncDB(t)
	if err := db2.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive(valid encrypted): %v", err)
	}
	if _, _, err := db2.ReadActiveMeta(); err != nil {
		t.Fatalf("ReadActiveMeta(valid encrypted) errored: %v", err)
	}
}

// TestUnencryptedHeaderTamperFailsClosed_9898 (F-035) pins integrity over the
// unencrypted envelope header. On base the committed= marker is parsed with no
// binding on the DEFAULT (unencrypted) path, so a one-byte committed=0/1 edit
// silently changes the boot class. Post-fix the writer stamps a body-sha256
// over header+body and the reader verifies it when present: flipping the
// marker (or any header/body byte) without recomputing fails closed.
//
// The check is verify-when-present: legacy envelopes without the field (every
// file written before this fix, plus the hand-framed fixtures below) still
// read, so there is no flag day and downgrades keep working. A writer that
// recomputes the hash bypasses this — it is tamper-EVIDENCE against naive
// edits and corruption, not tamper-proofing against a file writer (who could
// rewrite the file wholesale); full authentication needs master-password
// (#7176 AAD on the encrypted path).
//
// RED on base: the tamper/ subtests read back with nil error and a flipped
// committed flag.
func TestUnencryptedHeaderTamperFailsClosed_9898(t *testing.T) {
	flip := func(t *testing.T, path, from, to string) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), from) {
			t.Fatalf("fixture broken: header lacks %q:\n%s", from, raw)
		}
		fixed := strings.Replace(string(raw), from, to, 1)
		if err := os.WriteFile(path, []byte(fixed), 0600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("tamper/committed-1-to-0", func(t *testing.T) {
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteActiveMarker(mkTree9898(), true); err != nil {
			t.Fatal(err)
		}
		flip(t, db.activePath(), "committed=1", "committed=0")
		_, committed, err := db.ReadActiveMeta()
		if err == nil {
			t.Fatalf("ReadActiveMeta after committed=1->0 edit = nil error (committed=%v); want fail-closed", committed)
		}
	})

	t.Run("tamper/committed-0-to-1", func(t *testing.T) {
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteActiveMarker(mkTree9898(), false); err != nil {
			t.Fatal(err)
		}
		if _, committed, err := db.ReadActiveMeta(); err != nil || committed {
			t.Fatalf("untampered marker read = (%v,%v); want (false,nil)", committed, err)
		}
		flip(t, db.activePath(), "committed=0", "committed=1")
		_, committed, err := db.ReadActiveMeta()
		if err == nil {
			t.Fatalf("ReadActiveMeta after committed=0->1 edit = nil error (committed=%v); want fail-closed", committed)
		}
	})

	t.Run("accept/untampered-round-trip", func(t *testing.T) {
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []bool{true, false} {
			if err := db.WriteActiveMarker(mkTree9898(), c); err != nil {
				t.Fatal(err)
			}
			_, got, err := db.ReadActiveMeta()
			if err != nil || got != c {
				t.Fatalf("round trip committed=%v read (%v,%v)", c, got, err)
			}
		}
	})

	t.Run("accept/legacy-envelope-without-hash", func(t *testing.T) {
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		// A pre-fix envelope has no body-sha256 field; it must keep reading
		// (migration, no flag day).
		raw := wrapEnvelope([]byte(`{"Children":null}`), "9.9.9", true, EnvelopeMinReaderVersion)
		if strings.Contains(string(raw), "body-sha256") {
			t.Fatalf("fixture broken: legacy framing unexpectedly carries a hash:\n%s", raw)
		}
		if err := os.WriteFile(db.activePath(), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, committed, err := db.ReadActiveMeta(); err != nil || !committed {
			t.Fatalf("legacy envelope read = (%v,%v); want (true,nil)", committed, err)
		}
	})
}

// TestBodySHA256Spec_9898 (F-035 field spec) pins the exact contract: the
// digest covers header AND body (a body flip fails as loudly as a marker
// flip); a flipped digest value fails; a malformed-present field (bad hex,
// short value, duplicates) is rejected rather than treated as absent; and
// encrypted writes carry NO field (keyed AAD already binds those headers —
// stamping one would break decryption).
func TestBodySHA256Spec_9898(t *testing.T) {
	stamped := func(t *testing.T) (*DB, []byte) {
		t.Helper()
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteActive(mkTree9898()); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(db.activePath())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "body-sha256=") {
			t.Fatalf("writer did not stamp the field:\n%s", raw)
		}
		return db, raw
	}
	rewrite := func(t *testing.T, db *DB, raw []byte) error {
		t.Helper()
		if err := os.WriteFile(db.activePath(), raw, 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := db.ReadActiveMeta()
		return err
	}
	fieldValue := func(t *testing.T, raw []byte) string {
		t.Helper()
		line := string(raw[:strings.IndexByte(string(raw), '\n')])
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "body-sha256="); ok {
				return v
			}
		}
		t.Fatalf("no body-sha256 field in %q", line)
		return ""
	}

	t.Run("reject/body flip", func(t *testing.T) {
		db, raw := stamped(t)
		bad := strings.Replace(string(raw), `"Children": null`, `"Children": []`, 1)
		if bad == string(raw) {
			t.Fatalf("fixture broken: body pattern not found:\n%s", raw)
		}
		if err := rewrite(t, db, []byte(bad)); err == nil {
			t.Fatalf("body edit with stale digest = nil error; want fail-closed")
		}
	})

	t.Run("reject/digest flip", func(t *testing.T) {
		db, raw := stamped(t)
		v := fieldValue(t, raw)
		flipped := "0"
		if v[0] == '0' {
			flipped = "1"
		}
		bad := strings.Replace(string(raw), "body-sha256="+v, "body-sha256="+flipped+v[1:], 1)
		if err := rewrite(t, db, []byte(bad)); err == nil {
			t.Fatalf("digest edit = nil error; want fail-closed")
		}
	})

	t.Run("reject/malformed present", func(t *testing.T) {
		db, raw := stamped(t)
		v := fieldValue(t, raw)
		line := string(raw[:strings.IndexByte(string(raw), '\n')])
		body := string(raw[strings.IndexByte(string(raw), '\n')+1:])
		cases := map[string]string{
			"bad hex":  strings.Replace(line, v, strings.Repeat("z", 64), 1) + "\n" + body,
			"short":    strings.Replace(line, v, v[:32], 1) + "\n" + body,
			"long":     strings.Replace(line, v, v+v, 1) + "\n" + body,
			"empty":    strings.Replace(line, "body-sha256="+v, "body-sha256=", 1) + "\n" + body,
			"dupe":     line + " body-sha256=" + v + "\n" + body,
			"looklike": strings.Replace(line, "body-sha256=", "xbody-sha256=", 1) + "\n" + body,
		}
		for name, bad := range cases {
			if name == "looklike" {
				// A boundary-invalid token is an unrelated unknown field:
				// tolerated (and the real field is gone, so legacy-accept).
				// This documents the accepted discriminator residual, not a
				// bypass to rely on — see the verifyBodySHA256 comment.
				if err := rewrite(t, db, []byte(bad)); err != nil {
					t.Fatalf("looklike token errored: %v; want tolerated-unknown-field accept", err)
				}
				continue
			}
			if err := rewrite(t, db, []byte(bad)); err == nil {
				t.Fatalf("%s field = nil error; want malformed-present rejection", name)
			}
		}
	})

	t.Run("accept/encrypted has no field", func(t *testing.T) {
		db := newEncDB(t)
		tree := encryptedTree(t)
		raw := writeRealActive(t, db, tree, true)
		if strings.Contains(string(raw), "body-sha256") {
			t.Fatalf("encrypted envelope carries the field (breaks AAD):\n%s", raw[:160])
		}
		if _, _, err := db.ReadActiveMeta(); err != nil {
			t.Fatalf("encrypted round trip errored: %v", err)
		}
	})
}

// TestDeleteCandidateDurableSeam_9898 (F-112) pins DeleteCandidate on the
// package durability seams with the #5835 retry semantics: the unlink and
// the dir sync both route through rbRemove/rbSyncDir, and an absent-file
// retry still reaches the dir sync (a retry after an unlinked-but-unsynced
// removal must not launder the owed sync into a false success).
//
// RED on base: the seam spies never fire (bare os.Remove, no sync).
func TestDeleteCandidateDurableSeam_9898(t *testing.T) {
	t.Run("retry sequence converges only on durable sync", func(t *testing.T) {
		restoreRollbackSeams(t)
		var removes, syncs int
		failSync := true
		rbRemove = func(p string) error {
			removes++
			return os.Remove(p)
		}
		rbSyncDir = func(d string) error {
			syncs++
			if failSync {
				return errInjected9898
			}
			return nil
		}
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteCandidate(mkTree9898()); err != nil {
			t.Fatal(err)
		}
		// Present unlink, sync EIO: error, file now absent.
		if err := db.DeleteCandidate(); err == nil {
			t.Fatalf("delete with failing sync = nil error; want propagation")
		}
		if _, serr := os.Stat(db.candidatePath()); !os.IsNotExist(serr) {
			t.Fatalf("candidate still present: %v", serr)
		}
		// Absent retry, sync EIO: STILL an error (no laundering).
		if err := db.DeleteCandidate(); err == nil {
			t.Fatalf("absent retry with failing sync = nil error; want the owed sync to keep failing")
		}
		// Absent retry, sync healed: success.
		failSync = false
		if err := db.DeleteCandidate(); err != nil {
			t.Fatalf("absent retry with healed sync errored: %v", err)
		}
		if removes != 3 || syncs != 3 {
			t.Fatalf("seams reached remove=%d sync=%d; want 3/3 (no short-circuit)", removes, syncs)
		}
	})

	t.Run("remove error propagates without sync", func(t *testing.T) {
		restoreRollbackSeams(t)
		var syncs int
		rbRemove = func(p string) error { return errInjected9898 }
		rbSyncDir = func(d string) error {
			syncs++
			return nil
		}
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteCandidate(mkTree9898()); err != nil {
			t.Fatal(err)
		}
		if err := db.DeleteCandidate(); err == nil {
			t.Fatalf("delete with failing remove = nil error; want propagation")
		}
		if syncs != 0 {
			t.Fatalf("failed remove still reached dir sync; want early return")
		}
		if _, serr := os.Stat(db.candidatePath()); serr != nil {
			t.Fatalf("failed remove lost the file: %v", serr)
		}
	})
}

// TestDeleteRollbackDurableSeam_9898 (F-112) is the DeleteCandidate twin for
// rollback slots: same seams, same retry sequence, same propagation.
//
// RED on base: the seam spies never fire.
func TestDeleteRollbackDurableSeam_9898(t *testing.T) {
	t.Run("retry sequence converges only on durable sync", func(t *testing.T) {
		restoreRollbackSeams(t)
		var removes, syncs int
		failSync := true
		rbRemove = func(p string) error {
			removes++
			return os.Remove(p)
		}
		rbSyncDir = func(d string) error {
			syncs++
			if failSync {
				return errInjected9898
			}
			return nil
		}
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteRollback(1, mkTree9898()); err != nil {
			t.Fatal(err)
		}
		if err := db.DeleteRollback(1); err == nil {
			t.Fatalf("delete with failing sync = nil error; want propagation")
		}
		if _, serr := os.Stat(db.rollbackPath(1)); !os.IsNotExist(serr) {
			t.Fatalf("slot still present: %v", serr)
		}
		if err := db.DeleteRollback(1); err == nil {
			t.Fatalf("absent retry with failing sync = nil error; want the owed sync to keep failing")
		}
		failSync = false
		if err := db.DeleteRollback(1); err != nil {
			t.Fatalf("absent retry with healed sync errored: %v", err)
		}
		if removes != 3 || syncs != 3 {
			t.Fatalf("seams reached remove=%d sync=%d; want 3/3 (no short-circuit)", removes, syncs)
		}
	})

	t.Run("remove error propagates without sync", func(t *testing.T) {
		restoreRollbackSeams(t)
		var syncs int
		rbRemove = func(p string) error { return errInjected9898 }
		rbSyncDir = func(d string) error {
			syncs++
			return nil
		}
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		db, err := NewDB(dbDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.WriteRollback(2, mkTree9898()); err != nil {
			t.Fatal(err)
		}
		if err := db.DeleteRollback(2); err == nil {
			t.Fatalf("delete with failing remove = nil error; want propagation")
		}
		if syncs != 0 {
			t.Fatalf("failed remove still reached dir sync; want early return")
		}
		if _, serr := os.Stat(db.rollbackPath(2)); serr != nil {
			t.Fatalf("failed remove lost the slot: %v", serr)
		}
	})
}

// restoreMasterKeySeams restores the Link publish and file-sync seams after a
// test mutates them.
func restoreMasterKeySeams(t *testing.T) {
	t.Helper()
	realLink, realSync := masterKeyLink, syncMasterKeyFile
	t.Cleanup(func() { masterKeyLink, syncMasterKeyFile = realLink, realSync })
}

// TestConcurrentMasterKeyCreateConverges_9898 (F-111) pins atomic master-key
// creation. On base readOrCreateMasterKey is check-then-act across processes:
// concurrent creators each generate a key and the last rename wins, so losers
// return (and seal ciphertext with) a key that is NOT on disk — permanently
// undecryptable. Post-fix exactly one key is published and every creator
// returns the key that is actually stored.
//
// Two-phase on purpose: every goroutine opens its own DB handle on the shared
// directory BEFORE the barrier (the multi-handle model is the closest
// in-process analogue of racing processes), and no NewDB runs mid-race, so
// no temp sweep can fire during creation — the sweep race itself is covered
// deterministically by TestMasterKeyPublishRetriesSweptTemp_9898, not by
// timing. The many-round loop makes a false GREEN (all rounds accidentally
// serial) vanish on base.
//
// RED on base: at least one round returns divergent keys.
func TestConcurrentMasterKeyCreateConverges_9898(t *testing.T) {
	const rounds = 50
	const creators = 16
	for r := 0; r < rounds; r++ {
		dir := filepath.Join(t.TempDir(), ".configdb")
		dbs := make([]*DB, creators)
		for i := range dbs {
			db, err := NewDB(dir)
			if err != nil {
				t.Fatal(err)
			}
			dbs[i] = db
		}
		start := make(chan struct{})
		keys := make([][]byte, creators)
		errs := make([]error, creators)
		var wg sync.WaitGroup
		for i := 0; i < creators; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				k, err := dbs[i].readOrCreateMasterKey()
				keys[i], errs[i] = k, err
			}(i)
		}
		close(start)
		wg.Wait()
		for i := 0; i < creators; i++ {
			if errs[i] != nil {
				t.Fatalf("round %d creator %d: %v", r, i, errs[i])
			}
			if string(keys[i]) != string(keys[0]) {
				t.Fatalf("round %d: creator %d returned a key that differs from creator 0's — "+
					"one of them seals ciphertext the stored key cannot open (F-111)", r, i)
			}
		}
		stored, err := os.ReadFile(filepath.Join(dir, "master.key"))
		if err != nil {
			t.Fatalf("round %d: read stored key: %v", r, err)
		}
		if string(stored) != string(keys[0]) {
			t.Fatalf("round %d: creators agree with each other but NOT with the stored key", r)
		}
	}
}

// TestMasterKeyCreateConvergesAcrossProcesses_9898 (F-111) is the true
// cross-process proof: N helper processes race creation on one directory and
// every one must report the stored key. Overlap is FORCED, not hoped for:
// children rendezvous on ready/go files and then all sleep inside the Link
// seam before publishing, so every child is inside the race window together
// (one winner, N-1 EEXIST adopters). Children open the pre-created directory
// with &DB{} directly — no per-child NewDB, so no sweep noise can fire
// mid-race (the sweep race is the seam test's job). Each child prints
// exactly 64 hex chars — it os.Exits before the test framework prints
// anything, and without -v the framework prints nothing before the test runs.
func TestMasterKeyCreateConvergesAcrossProcesses_9898(t *testing.T) {
	if dir := os.Getenv("XPF_9898_MASTERKEY_RACE_DIR"); dir != "" {
		id := os.Getenv("XPF_9898_CHILD_ID")
		// Rendezvous: signal ready, then wait for the parent's go-file.
		if err := os.WriteFile(filepath.Join(dir, "race-ready-"+id), []byte("r"), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		goFile := filepath.Join(dir, "race-go")
		for i := range 6000 {
			if _, err := os.Stat(goFile); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
			if i == 5999 {
				fmt.Fprintln(os.Stderr, "go-file never appeared")
				os.Exit(2)
			}
		}
		// Force the overlap: every child parks inside the publish seam
		// before the kernel decides the winner.
		masterKeyLink = func(old, new string) error {
			time.Sleep(300 * time.Millisecond)
			return os.Link(old, new)
		}
		db := &DB{dir: dir}
		key, err := db.readOrCreateMasterKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("%x", key)
		os.Exit(0)
	}
	dir := filepath.Join(t.TempDir(), ".configdb")
	if _, err := NewDB(dir); err != nil {
		t.Fatal(err)
	}
	const children = 8
	outs := make([]string, children)
	errs := make([]error, children)
	var wg sync.WaitGroup
	for i := range children {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestMasterKeyCreateConvergesAcrossProcesses_9898$")
			cmd.Env = append(os.Environ(),
				"XPF_9898_MASTERKEY_RACE_DIR="+dir,
				fmt.Sprintf("XPF_9898_CHILD_ID=%d", i))
			out, err := cmd.Output()
			outs[i], errs[i] = string(out), err
		}(i)
	}
	// Release only once every child is waiting at the barrier.
	deadline := time.Now().Add(30 * time.Second)
	for {
		ready := 0
		for i := 0; i < children; i++ {
			if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("race-ready-%d", i))); err == nil {
				ready++
			}
		}
		if ready == children {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d children reached the barrier; test broken", ready, children)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(dir, "race-go"), []byte("g"), 0600); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for i, out := range outs {
		if errs[i] != nil {
			t.Fatalf("child %d: %v", i, errs[i])
		}
		if len(out) != 64 {
			t.Fatalf("child %d reported %q; want exactly 64 hex chars", i, out)
		}
		if out != outs[0] {
			t.Fatalf("child %d disagrees with child 0 — divergent keys across processes (F-111)", i)
		}
	}
	stored, err := os.ReadFile(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", stored) != outs[0] {
		t.Fatalf("children agree with each other but NOT with the stored key")
	}
}

// TestMasterKeyPublishRetriesSweptTemp_9898 (F-111) pins convergence when a
// concurrent NewDB temp sweep deletes a live key temp between CreateTemp and
// Link. The stub removes the temp and falls through to the REAL Link, so the
// kernel returns a genuine ENOENT; the create path must recreate and
// converge instead of failing.
func TestMasterKeyPublishRetriesSweptTemp_9898(t *testing.T) {
	restoreMasterKeySeams(t)
	var calls int
	masterKeyLink = func(old, new string) error {
		calls++
		if calls == 1 {
			_ = os.Remove(old)
		}
		return os.Link(old, new)
	}
	dbDir := filepath.Join(t.TempDir(), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := db.readOrCreateMasterKey()
	if err != nil {
		t.Fatalf("create with one swept temp errored: %v; want recreate-and-converge", err)
	}
	if calls != 2 {
		t.Fatalf("Link called %d times; want 2 (ENOENT then publish)", calls)
	}
	stored, err := os.ReadFile(filepath.Join(dbDir, "master.key"))
	if err != nil || string(stored) != string(key) {
		t.Fatalf("stored key mismatch: %v", err)
	}
	stale, err := filepath.Glob(filepath.Join(dbDir, ".*.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Fatalf("leaked key temps: %v", stale)
	}
}

// TestMasterKeyWinnerDirSyncFailure_9898 (F-111) pins the winner-EIO path:
// the file is LEFT in place ("first key wins forever" stays unconditional)
// and the error is PLAIN — never *PostRenameSyncError, which Commit would
// misread as "the new active config is visible, converge" while the active
// write never ran. A retry then converges to the left-in-place key.
func TestMasterKeyWinnerDirSyncFailure_9898(t *testing.T) {
	restoreRollbackSeams(t)
	failSync := true
	rbSyncDir = func(d string) error {
		if failSync {
			return errInjected9898
		}
		return nil
	}
	dbDir := filepath.Join(t.TempDir(), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := db.readOrCreateMasterKey()
	if err == nil {
		t.Fatalf("create with failing dir sync = nil error; want propagation")
	}
	if key != nil {
		t.Fatalf("failed create returned a key; want nil")
	}
	if isPostRenameDurabilityFailure(err) {
		t.Fatalf("key dir-sync failure classified as post-rename: %v — Commit would "+
			"converge to an active config that was never written", err)
	}
	left, err := os.ReadFile(filepath.Join(dbDir, "master.key"))
	if err != nil || len(left) != 32 {
		t.Fatalf("winner-EIO file = %d bytes, %v; want the 32-byte key left in place", len(left), err)
	}
	failSync = false
	key2, err := db.readOrCreateMasterKey()
	if err != nil {
		t.Fatalf("retry after EIO errored: %v", err)
	}
	if string(key2) != string(left) {
		t.Fatalf("retry converged to a different key; want first-wins-forever")
	}
}

// TestMasterKeyAdoptSyncsBeforeUseWhileWinnerParked_9898 (F-111) pins the
// durability ORDERING on the actual encrypted write path: creator A links
// the key but parks before its dir sync, while creator B takes the
// fast-path hit on A's linked-but-undurable file and completes a full
// encrypted WriteActive. B must establish durability itself (file sync +
// dir sync) before sealing — otherwise its ciphertext is rename-published
// before any barrier covers the key entry, and a power cut with selective
// entry loss strands it with the key gone.
//
// The proof is the seam ordering: B's write completes while A is still
// parked (A's syncs cannot have run yet), so syncs observed during the
// park MUST be B's adopt barrier. A pre-fix fast path (return directly)
// records zero syncs during the park and fails.
func TestMasterKeyAdoptSyncsBeforeUseWhileWinnerParked_9898(t *testing.T) {
	restoreRollbackSeams(t)
	restoreMasterKeySeams(t)
	dbDir := filepath.Join(t.TempDir(), ".configdb")
	db, err := NewDB(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	linked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	masterKeyLink = func(old, new string) error {
		err := os.Link(old, new)
		if err == nil {
			once.Do(func() { close(linked) })
			<-release // winner parked: linked but not yet synced
		}
		return err
	}
	var dirSyncs, fileSyncs atomic.Int32
	rbSyncDir = func(d string) error {
		dirSyncs.Add(1)
		return nil
	}
	syncMasterKeyFile = func(f *os.File) error {
		fileSyncs.Add(1)
		return nil
	}
	type result struct {
		key []byte
		err error
	}
	aDone := make(chan result, 1)
	go func() {
		k, err := db.readOrCreateMasterKey()
		aDone <- result{k, err}
	}()
	select {
	case <-linked:
	case <-time.After(10 * time.Second):
		t.Fatalf("winner never linked; test broken")
	}
	// B: the real encrypted write path on the linked-but-undurable key.
	// (The active write's own dir sync routes through fsatomic directly,
	// not the rbSyncDir spy, so the counters below see key-path syncs only.)
	if err := db.WriteActive(encryptedTree(t)); err != nil {
		t.Fatalf("B's encrypted write while winner parked errored: %v", err)
	}
	if got := fileSyncs.Load(); got < 1 {
		t.Fatalf("B sealed with zero key file-syncs while the winner was parked; want the adopt barrier before use")
	}
	if got := dirSyncs.Load(); got < 1 {
		t.Fatalf("B sealed with zero key dir-syncs while the winner was parked; want the adopt barrier before use")
	}
	close(release)
	var ares result
	select {
	case ares = <-aDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("winner never returned after release; test broken")
	}
	if ares.err != nil {
		t.Fatalf("winner errored: %v", ares.err)
	}
	// Both creators converged AND the ciphertext opens with the stored key.
	stored, err := os.ReadFile(filepath.Join(dbDir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(ares.key) {
		t.Fatalf("winner disagrees with the stored key")
	}
	if _, _, err := db.ReadActiveMeta(); err != nil {
		t.Fatalf("B's ciphertext does not open with the stored key: %v", err)
	}
}

// TestAdoptPublishedMasterKey_9898 (F-111) unit-pins the loser path
// directly: a valid published file is adopted with a file-sync plus a
// dir-sync assist, and every degenerate input fails closed.
func TestAdoptPublishedMasterKey_9898(t *testing.T) {
	t.Run("adopt valid assists both syncs", func(t *testing.T) {
		restoreRollbackSeams(t)
		restoreMasterKeySeams(t)
		var dirSyncs, fileSyncs int
		rbSyncDir = func(d string) error {
			dirSyncs++
			return nil
		}
		syncMasterKeyFile = func(f *os.File) error {
			fileSyncs++
			return nil
		}
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		if _, err := NewDB(dbDir); err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 32)
		for i := range want {
			want[i] = byte(i)
		}
		if err := os.WriteFile(filepath.Join(dbDir, "master.key"), want, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := adoptPublishedMasterKey(filepath.Join(dbDir, "master.key"))
		if err != nil {
			t.Fatalf("adopt valid: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("adopted the wrong key")
		}
		if fileSyncs != 1 || dirSyncs != 1 {
			t.Fatalf("adopt reached file sync=%d dir sync=%d; want 1/1 (durability assist)", fileSyncs, dirSyncs)
		}
	})

	t.Run("dir assist failure fails closed", func(t *testing.T) {
		restoreRollbackSeams(t)
		rbSyncDir = func(d string) error { return errInjected9898 }
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		if _, err := NewDB(dbDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dbDir, "master.key"), make([]byte, 32), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := adoptPublishedMasterKey(filepath.Join(dbDir, "master.key")); err == nil {
			t.Fatalf("adopt with failing dir assist = nil error; want fail-closed")
		}
	})

	t.Run("file assist failure fails closed", func(t *testing.T) {
		restoreMasterKeySeams(t)
		syncMasterKeyFile = func(f *os.File) error { return errInjected9898 }
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		if _, err := NewDB(dbDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dbDir, "master.key"), make([]byte, 32), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := adoptPublishedMasterKey(filepath.Join(dbDir, "master.key")); err == nil {
			t.Fatalf("adopt with failing file assist = nil error; want fail-closed")
		}
	})

	t.Run("missing fails closed", func(t *testing.T) {
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		if _, err := NewDB(dbDir); err != nil {
			t.Fatal(err)
		}
		if _, err := adoptPublishedMasterKey(filepath.Join(dbDir, "master.key")); err == nil {
			t.Fatalf("adopt missing file = nil error; want fail-closed")
		}
	})

	t.Run("corrupt length fails closed", func(t *testing.T) {
		dbDir := filepath.Join(t.TempDir(), ".configdb")
		if _, err := NewDB(dbDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dbDir, "master.key"), []byte("short"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := adoptPublishedMasterKey(filepath.Join(dbDir, "master.key")); err == nil {
			t.Fatalf("adopt short file = nil error; want fail-closed")
		}
	})
}

// TestJournalPermsDegradedExposed_9898 (F-113 exposure) pins that the Store
// forwards the journal's repair state: a clean journal reads false. The
// latched-true state itself is pinned in the journal package, where the
// repair seams live; this cell pins the wiring between the two.
func TestJournalPermsDegradedExposed_9898(t *testing.T) {
	s := newTestStore(t)
	if s.JournalPermsDegraded() {
		t.Fatalf("fresh store reads JournalPermsDegraded true; want clean default")
	}
}

// TestJournalPermsDegradedEndToEnd_9898 (F-113 consumer) drives the full
// failure→visible→repair→clear cycle through the production Store getter —
// the exact function the daemon wires to /health and the gauge. No seams:
// the journal is pointed at a path whose parent is a regular FILE, so the
// repair lstat fails ENOTDIR (a non-NotExist error, deterministically, as
// any user including root); replacing the blocking file with a real
// directory lets the next use retry the full pass and clear.
func TestJournalPermsDegradedEndToEnd_9898(t *testing.T) {
	s := newTestStore(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	s.journal = journal.New(filepath.Join(blocker, ".config.journal"))
	if s.JournalPermsDegraded() {
		t.Fatalf("fresh journal reads degraded before first use; want clean")
	}
	if _, err := s.journal.Tail(0); err == nil {
		t.Fatalf("Tail on an ENOTDIR journal = nil error; fixture broken (want a repair failure)")
	}
	if !s.JournalPermsDegraded() {
		t.Fatalf("failed repair reads clean through the Store getter; want visible degradation")
	}
	// Repair: a real directory where the blocking file was.
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blocker, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.journal.Tail(0); err != nil {
		t.Fatalf("Tail after repair errored: %v", err)
	}
	if s.JournalPermsDegraded() {
		t.Fatalf("repaired journal still reads degraded through the Store getter; want clear")
	}
}
