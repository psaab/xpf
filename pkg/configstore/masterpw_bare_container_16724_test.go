package configstore

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// #16724: a bare `system master-password` (or the empty container left
// behind by deleting only its pseudorandom-function leaf) committed clean
// and wrote active.json / confirm.json in CLEARTEXT with no master.key, no
// commit warning and no #4579 read-back warning, while
// `show configuration` rendered `master-password;`.
//
// Root cause: masterPasswordConfigured (Q1, "is encryption required?") keyed
// on a non-empty pseudorandom-function VALUE instead of the presence of the
// master-password node. Zero children therefore answered "no encryption",
// and Q2's defaultMasterPasswordPRF fallback was never reached.
//
// Fix: Q1 answers presence — any master-password node at top-level system,
// under groups (recursive, <*> included), dormant/inactive, after the
// compact fold — and Q2 falls back to defaultMasterPasswordPRF. Every
// consumer keyed on masterPasswordPRF (writeTreeMarked, maybeEncryptTreeJSON,
// confirmEncryptionPRF / confirmNeedsEncryption, the #4579 / #14172
// read-back warnings, the commit-confirmed cover) inherits the fix.
//
// RED on revert: restoring the PRF-value Q1 makes the bare rows resolve
// prf="" (plaintext). The unit, active.json, confirm.json and #4579 cells
// below then fail on their envelope / secret / warning assertions; the PRF
// and absent controls keep passing, proving the cells are not
// "encrypt everything".

const secret16724 = "s3cret-psk-16724"

func tree16724(t *testing.T, stanza string) *config.ConfigTree {
	t.Helper()
	text := stanza + `
security {
	ike {
		policy p1 {
			pre-shared-key ascii-text "` + secret16724 + `";
		}
	}
}`
	root, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse 16724 fixture: %v", perrs)
	}
	return &config.ConfigTree{Children: root.Children}
}

func bareTree16724() *config.ConfigTree {
	return &config.ConfigTree{Children: []*config.Node{{
		Keys: []string{"system"},
		Children: []*config.Node{
			{Keys: []string{"host-name", "bare-fw"}, IsLeaf: true},
			{Keys: []string{"master-password"}},
		},
	}}}
}

// TestBareMasterPasswordEncrypts16724 is the acceptance matrix: bare and
// PRF-less containers encrypt under the default; a configured PRF keeps its
// own selector; absence stays plaintext.
func TestBareMasterPasswordEncrypts16724(t *testing.T) {
	cases := []struct {
		name    string
		stanza  string
		wantPRF string // "" means plaintext expected
	}{
		{"bare braced empty", `system { master-password { } }`, defaultMasterPasswordPRF},
		{"bare semicolon", `system { master-password; }`, defaultMasterPasswordPRF},
		{"bare inactive", `system { inactive: master-password; }`, defaultMasterPasswordPRF},
		{"bare in second system stanza", `system { host-name fw1; } system { master-password; }`, defaultMasterPasswordPRF},
		{"bare in unapplied group", "groups { enc { system { master-password; } } }\nsystem { host-name fw1; }", defaultMasterPasswordPRF},
		{"bare under groups wildcard", "groups { <*> { system { master-password; } } }\nsystem { host-name fw1; }", defaultMasterPasswordPRF},
		{"prf control unchanged", `system { master-password { pseudorandom-function juniper-prf1; } }`, "juniper-prf1"},
		{"absent control plaintext", `system { host-name fw1; }`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := tree16724(t, tc.stanza)
			if tc.wantPRF == "" {
				if masterPasswordConfigured(tree) {
					t.Fatalf("Q1 says encryption required for %q with no master-password", tc.stanza)
				}
				if got := masterPasswordPRF(tree); got != "" {
					t.Fatalf("masterPasswordPRF = %q, want \"\" (plaintext)", got)
				}
			} else {
				if !masterPasswordConfigured(tree) {
					t.Fatalf("Q1 (must we encrypt?) says NO for %q — the #16724 defect", tc.stanza)
				}
				if got := masterPasswordPRF(tree); got != tc.wantPRF {
					t.Fatalf("masterPasswordPRF = %q, want %q — empty means PLAINTEXT, "+
						"a non-default value means the PRF control regressed", got, tc.wantPRF)
				}
			}

			dir := t.TempDir()
			db, err := NewDB(dir)
			if err != nil {
				t.Fatalf("NewDB: %v", err)
			}
			if err := db.WriteActive(tree); err != nil {
				t.Fatalf("WriteActive: %v", err)
			}
			raw, err := os.ReadFile(db.activePath())
			if err != nil {
				t.Fatalf("ReadFile(active): %v", err)
			}
			if tc.wantPRF == "" {
				if strings.Contains(string(raw), encryptedTreeFormat) {
					t.Fatalf("absent control was encrypted; fix is encrypt-everything: %s", raw)
				}
				if _, err := os.Stat(db.masterKeyPath()); !os.IsNotExist(err) {
					t.Fatalf("absent control created master.key (stat err=%v)", err)
				}
				return
			}
			if strings.Contains(string(raw), secret16724) {
				t.Fatalf("IKE pre-shared key on disk IN CLEARTEXT under %q (#16724)", tc.stanza)
			}
			if !strings.Contains(string(raw), encryptedTreeFormat) {
				t.Fatalf("persisted config under %q carries no encryption envelope", tc.stanza)
			}
			if _, err := os.Stat(db.masterKeyPath()); err != nil {
				t.Fatalf("master.key not created under %q: %v", tc.stanza, err)
			}
			got, err := db.ReadActive()
			if err != nil {
				t.Fatalf("ReadActive: %v", err)
			}
			if got.FormatJSON() != tree.FormatJSON() {
				t.Fatalf("encrypted config under %q did not round-trip", tc.stanza)
			}
		})
	}
}

// TestBareMasterPasswordSetSyntax16724 pins the operator spelling from the
// issue: `set system master-password` with no PRF leaf.
func TestBareMasterPasswordSetSyntax16724(t *testing.T) {
	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand("set system master-password")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if !strings.Contains(tree.Format(), "master-password;") {
		t.Fatalf("fixture broken: bare set did not render master-password;: %s", tree.Format())
	}
	if !masterPasswordConfigured(tree) {
		t.Fatal("Q1 says NO for bare `set system master-password` — #16724")
	}
	if got := masterPasswordPRF(tree); got != defaultMasterPasswordPRF {
		t.Fatalf("masterPasswordPRF = %q, want default %q", got, defaultMasterPasswordPRF)
	}
}

// TestDeletePRFLeavesBareContainerEncrypts16724 pins the second acceptance
// row: deleting only the PRF leaf must not silently downgrade an encrypted
// DB to plaintext. It stays encrypted under the default selector.
func TestDeletePRFLeavesBareContainerEncrypts16724(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set system master-password pseudorandom-function sha256",
		"set security ike policy p1 pre-shared-key ascii-text " + secret16724,
	} {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	dir := t.TempDir()
	db, err := NewDB(dir)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive(before): %v", err)
	}
	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile(before): %v", err)
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) || strings.Contains(string(raw), secret16724) {
		t.Fatalf("control broken: PRF config not encrypted before delete: %s", raw)
	}

	if err := tree.DeletePath([]string{"system", "master-password", "pseudorandom-function"}); err != nil {
		t.Fatalf("DeletePath(PRF): %v", err)
	}
	if !strings.Contains(tree.Format(), "master-password") {
		t.Fatalf("fixture broken: delete removed the whole container: %s", tree.Format())
	}
	if !masterPasswordConfigured(tree) {
		t.Fatal("Q1 says NO after delete-PRF left the bare container — #16724 downgrade")
	}
	if got := masterPasswordPRF(tree); got != defaultMasterPasswordPRF {
		t.Fatalf("masterPasswordPRF after delete-PRF = %q, want default %q", got, defaultMasterPasswordPRF)
	}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive(after): %v", err)
	}
	raw, err = os.ReadFile(db.activePath())
	if err != nil {
		t.Fatalf("ReadFile(after): %v", err)
	}
	if strings.Contains(string(raw), secret16724) {
		t.Fatal("delete-PRF silently downgraded active.json to cleartext (#16724)")
	}
	if !strings.Contains(string(raw), encryptedTreeFormat) {
		t.Fatal("delete-PRF left active.json without an encryption envelope (#16724)")
	}
	if _, err := os.Stat(db.masterKeyPath()); err != nil {
		t.Fatalf("master.key missing after delete-PRF rewrite: %v", err)
	}
}

// TestBareMasterPasswordConfirmEncrypts16724 covers the commit-confirmed
// surface named in the issue: both the PrevTree profile and the guarded-tree
// cover must seal confirm.json when either tree carries only a bare
// container.
func TestBareMasterPasswordConfirmEncrypts16724(t *testing.T) {
	prevBare := tree16724(t, `system { master-password; }`)
	guardedBare := tree16724(t, `system { master-password; }`)
	plain := tree16724(t, `system { host-name fw1; }`)

	t.Run("prev bare seals confirm", func(t *testing.T) {
		db, err := NewDB(t.TempDir())
		if err != nil {
			t.Fatalf("NewDB: %v", err)
		}
		rec := &confirmRecord{
			Deadline:    time.Now().Add(10 * time.Minute),
			PrevTree:    prevBare,
			GuardedHash: guardedConfigHash(plain),
		}
		if err := db.WriteConfirm(rec); err != nil {
			t.Fatalf("WriteConfirm: %v", err)
		}
		_, body, envelope := confirmRaw14172(t, db)
		if !envelope {
			t.Fatalf("confirm.json NOT encrypted although PrevTree carries a bare master-password (#16724): %s", body)
		}
		if bytes.Contains(body, []byte(secret16724)) {
			t.Fatal("confirm.json carries the secret in cleartext under a bare PrevTree")
		}
		env, ok, err := unmarshalEnvelope(body)
		if err != nil || !ok {
			t.Fatalf("unmarshalEnvelope: ok=%v err=%v", ok, err)
		}
		if env.PRF != defaultMasterPasswordPRF {
			t.Fatalf("confirm envelope PRF = %q, want default %q", env.PRF, defaultMasterPasswordPRF)
		}
		if _, err := db.ReadConfirm(); err != nil {
			t.Fatalf("ReadConfirm: %v", err)
		}
	})

	t.Run("guarded bare cover seals confirm", func(t *testing.T) {
		db, err := NewDB(t.TempDir())
		if err != nil {
			t.Fatalf("NewDB: %v", err)
		}
		rec := &confirmRecord{
			Deadline:    time.Now().Add(10 * time.Minute),
			PrevTree:    plain,
			GuardedHash: guardedConfigHash(guardedBare),
		}
		// Mirror commitConfirmedLocked: cover is masterPasswordPRF(guarded).
		if got := masterPasswordPRF(guardedBare); got != defaultMasterPasswordPRF {
			t.Fatalf("guarded bare profile = %q, want default %q — cover would be empty pre-fix", got, defaultMasterPasswordPRF)
		}
		db.writeConfirmCover = confirmEncryptionCover{profile: masterPasswordPRF(guardedBare)}
		if err := db.WriteConfirm(rec); err != nil {
			t.Fatalf("WriteConfirm: %v", err)
		}
		_, body, envelope := confirmRaw14172(t, db)
		if !envelope {
			t.Fatalf("confirm.json NOT encrypted although guarded tree carries a bare master-password (#16724): %s", body)
		}
		if bytes.Contains(body, []byte(secret16724)) {
			t.Fatal("confirm.json carries the secret in cleartext under a bare guarded tree")
		}
	})
}

// TestBareMasterPasswordDowngradeWarn16724 pins the #4579 acceptance row: a
// plaintext body under a bare container must warn on read-back. Pre-fix the
// warning keyed on the PRF value and stayed silent.
func TestBareMasterPasswordDowngradeWarn16724(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)
	tree := bareTree16724()
	if got := masterPasswordPRF(tree); got != defaultMasterPasswordPRF {
		t.Fatalf("fixture broken: bare tree resolves %q, want default %q", got, defaultMasterPasswordPRF)
	}
	body, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	framed := wrapEnvelope(body, "", true, EnvelopeMinReaderVersion)
	if err := fsatomic.WriteFileDurable(s.db.activePath(), framed, 0600); err != nil {
		t.Fatalf("write plaintext active.json: %v", err)
	}
	got, err := s.db.ReadActive()
	if err != nil {
		t.Fatalf("ReadActive: %v", err)
	}
	if got == nil || !masterPasswordConfigured(got) {
		t.Fatalf("read-back tree lost the bare master-password: %+v", got)
	}
	logged := buf.String()
	if !strings.Contains(logged, "#4579") || !strings.Contains(logged, "UNENCRYPTED plaintext") {
		t.Fatalf("expected #4579 plaintext warning for bare master-password; got log:\n%s", logged)
	}
}

// TestBareMasterPasswordStoreCommitConfirmed16724 exercises the production
// Store path end to end: a bare guarded commit-confirmed must encrypt both
// active.json and confirm.json and create master.key.
func TestBareMasterPasswordStoreCommitConfirmed16724(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security ike policy p1 pre-shared-key ascii-text " + secret16724); err != nil {
		t.Fatalf("SetFromInput(secret): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(base): %v", err)
	}
	if err := s.SetFromInput("system master-password"); err != nil {
		t.Fatalf("SetFromInput(bare master-password): %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	rawActive, err := os.ReadFile(s.db.activePath())
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	if !strings.Contains(string(rawActive), encryptedTreeFormat) {
		t.Fatal("active.json not encrypted after bare commit-confirmed (#16724)")
	}
	if strings.Contains(string(rawActive), secret16724) {
		t.Fatal("active.json carries the secret in cleartext after bare commit-confirmed")
	}
	if _, err := os.Stat(s.db.masterKeyPath()); err != nil {
		t.Fatalf("master.key not created after bare commit-confirmed: %v", err)
	}
	_, body, envelope := confirmRaw14172(t, s.db)
	if !envelope {
		t.Fatalf("confirm.json not encrypted after bare commit-confirmed (#16724): %s", body)
	}
	if bytes.Contains(body, []byte(secret16724)) {
		t.Fatal("confirm.json carries the secret in cleartext after bare commit-confirmed")
	}
	if _, err := s.db.ReadConfirm(); err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
}
