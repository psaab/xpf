package configstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6856: pin the ACTUAL at-rest-encryption threat model, in both directions.
//
// `system master-password` is an encryption-POLICY knob, not a secret: the
// subtree is closed-world and carries exactly one leaf
// (`pseudorandom-function`), so no operator secret ever enters the config.
// The AES-GCM key is 32 random bytes in `.configdb/master.key`, written
// alongside the ciphertext it protects.
//
// That yields a guarantee much narrower than "the config is encrypted at
// rest", and the narrowness is the whole point of pkg/configstore/README.md's
// "What at-rest encryption does and does not protect" section. These cells
// bind the two facts that section asserts, so the documentation cannot drift
// away from the code silently:
//
//   - a COPY OF THE DIRECTORY decrypts, because the key travels with it; and
//   - a copy of the BODY ALONE does not.
//
// Deliberately a PAIRED cell. Either half alone proves only correlation: the
// body-only half would still pass if encryption were skipped entirely and the
// body were rejected for some unrelated reason, and the directory-copy half
// would still pass if nothing were ever encrypted. Together they show the key
// file is necessary AND sufficient — which is exactly the documented claim.
//
// If a future change binds the KDF to an operator secret, moves master.key
// outside the DB directory, or seals it to a TPM, the directory-copy half
// REDS. That is correct and intended: the security claim in the README would
// no longer be true, and it must be rewritten in the same change.
func TestAtRestKeyTravelsWithTheConfigDirectory6856(t *testing.T) {
	// A canary that no default, no empty tree, and no fallback path could
	// produce. If encryption were silently skipped, this string would appear
	// verbatim in the on-disk body and the ciphertext assertion below fires.
	plaintext := []byte(`{"canary":"XPF-6856-PRESHARED-KEY-CANARY","system":{}}`)

	originDir := t.TempDir()
	origin := &DB{dir: originDir}

	tree := &config.ConfigTree{}
	if path, err := config.ParseSetCommand(
		"set system master-password pseudorandom-function sha256",
	); err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	} else if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	// Precondition: encryption must actually have happened. Without this the
	// two cells below are vacuous — a plaintext body "decrypts" in any
	// directory and would make the directory-copy half pass for the wrong
	// reason.
	if prf := masterPasswordPRF(tree); prf == "" {
		t.Fatalf("fixture broken: masterPasswordPRF resolved empty, so nothing " +
			"would be encrypted and both cells below would prove nothing")
	}
	body, err := origin.maybeEncryptTreeJSON(plaintext, tree, nil)
	if err != nil {
		t.Fatalf("maybeEncryptTreeJSON: %v", err)
	}
	if _, ok, err := unmarshalEnvelope(body); err != nil || !ok {
		t.Fatalf("fixture broken: encrypted body is not an envelope (ok=%t err=%v) — "+
			"the cells below would be asserting over plaintext", ok, err)
	}
	if bytes.Contains(body, []byte("XPF-6856-PRESHARED-KEY-CANARY")) {
		t.Fatal("the canary survived into the on-disk body verbatim — the body is " +
			"not actually encrypted, so neither cell below means anything")
	}
	keyMaterial, err := os.ReadFile(origin.masterKeyPath())
	if err != nil {
		t.Fatalf("read master.key: %v", err)
	}
	if got := filepath.Dir(origin.masterKeyPath()); got != originDir {
		t.Fatalf("master.key path %q is not inside the DB directory %q — the "+
			"README's claim that a directory copy carries the key is no longer true",
			origin.masterKeyPath(), originDir)
	}

	t.Run("a copy of the whole .configdb directory DECRYPTS", func(t *testing.T) {
		// The stolen-appliance / disk-image / full-directory-backup case.
		// master.key rides along with the ciphertext, so the thief reads the
		// config. This is the documented NON-guarantee.
		stolenDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(stolenDir, "master.key"), keyMaterial, 0600); err != nil {
			t.Fatalf("copy master.key: %v", err)
		}
		stolen := &DB{dir: stolenDir}

		got, decrypted, err := stolen.maybeDecryptTreeJSON(body, nil)
		if err != nil {
			t.Fatalf("a copied .configdb directory failed to decrypt (%v) — if this "+
				"is an intentional hardening change, the README's threat-model "+
				"section must be rewritten in the same commit", err)
		}
		if !decrypted {
			t.Fatal("body was not treated as encrypted at all")
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decrypted body = %q, want %q", got, plaintext)
		}
	})

	t.Run("the body WITHOUT master.key stays opaque", func(t *testing.T) {
		// The documented guarantee: a reader who gets the DB body but not the
		// sibling key file learns nothing. This is the only case at-rest
		// encryption actually defends.
		bodyOnly := &DB{dir: t.TempDir()} // no master.key written

		got, decrypted, err := bodyOnly.maybeDecryptTreeJSON(body, nil)
		if err == nil {
			t.Fatalf("body decrypted without master.key (decrypted=%t, got=%q) — "+
				"at-rest encryption would then protect nothing at all", decrypted, got)
		}
		if bytes.Contains(got, []byte("XPF-6856-PRESHARED-KEY-CANARY")) {
			t.Fatal("plaintext canary leaked out of the failed-decrypt path")
		}
	})
}

// TestMasterPasswordCarriesNoSecret6856 pins the most surprising half of the
// #6856 threat model, which pkg/configstore/README.md now states outright: xpf's
// `system master-password` is a POLICY knob that carries no secret at all.
//
// A Junos operator reaches for `set system master-password plain-text-password
// <secret>` first. In xpf that is REJECTED at commit by the closed-world gate
// on the subtree — it is not accepted-and-ignored, which is the failure mode
// that would make the README's "no operator input reaches the KDF" sentence
// read as an accident rather than a contract.
//
// Both directions matter. The accept case alone would still pass if the
// subtree stopped being closed-world (everything would be accepted); the
// reject case alone would still pass if the whole subtree were rejected.
func TestMasterPasswordCarriesNoSecret6856(t *testing.T) {
	validate := func(t *testing.T, cmd string) error {
		t.Helper()
		tree := &config.ConfigTree{}
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
		return config.SchemaValidate(tree)
	}

	t.Run("a secret-bearing leaf is rejected at commit", func(t *testing.T) {
		// If this ever commits clean, an operator would believe they had set a
		// master password that keys the config DB. Nothing would key it, and
		// the README's threat-model table would be describing a different
		// product than the one shipping.
		if err := validate(t, "set system master-password plain-text-password hunter2"); err == nil {
			t.Fatal("`master-password plain-text-password` committed clean — an operator " +
				"would believe a secret keys the config DB when the KDF never sees it")
		}
	})

	t.Run("the PRF selector still commits", func(t *testing.T) {
		// The positive control: the reject above must come from the leaf being
		// unmodeled, not from the subtree being unusable.
		if err := validate(t, "set system master-password pseudorandom-function sha256"); err != nil {
			t.Fatalf("the one modeled leaf must still commit, got %v — without this the "+
				"reject above would pass even if the whole subtree were broken", err)
		}
	})
}
