package config

import (
	"strings"
	"testing"
)

// #4578 — master-password pseudorandom-function typo must FAIL COMMIT.
//
// configstore.masterPasswordPRF reads the raw AST for `system master-password
// pseudorandom-function <fn>` and, when it finds the leaf, uses the value to
// derive an at-rest encryption key for the persisted config trees. Because the
// `system` subtree is open-world (#4515/X-1), a typo previously committed
// clean:
//
//   - a typo in the KEYWORD (`pseudo-random-fnuction`) meant masterPasswordPRF
//     found no `pseudorandom-function` child and fell through to its empty
//     default → at-rest encryption silently OFF; or
//   - a typo in the VALUE (`bogus-prf`) fell through configstore.prfHash's
//     default and failed the persisted-tree write with an opaque error.
//
// The fix is scoped strictly to this subtree: master-password is now
// closed-world (rejects the keyword typo) and pseudorandom-function is
// enum-validated (rejects the value typo). Both fire on the strict commit path
// (SchemaValidate). These tests use the production ParseSetCommand + SetPath +
// SchemaValidate path (buildTree). Each rejection is RED on revert of the
// respective flag/validator.

// TestMasterPasswordPRF_RejectsKeywordTypo is the primary RED-on-revert
// discriminator: a misspelled KEYWORD under the closed-world master-password
// subtree is rejected at commit. On revert of closedWorld the same input is
// silently accepted (SchemaValidate returns nil) and encryption is silently
// disabled — the #4578 bug.
func TestMasterPasswordPRF_RejectsKeywordTypo(t *testing.T) {
	tree := buildTree(t, []string{
		"set system master-password pseudo-random-fnuction juniper-prf1",
	})
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("a typo'd master-password keyword must be rejected at commit " +
			"(RED on revert: silently accepted → at-rest encryption silently OFF)")
	}
	if !strings.Contains(err.Error(), "pseudo-random-fnuction") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the typo'd keyword and the closed-world subtree, got: %v", err)
	}
}

// TestMasterPasswordPRF_RejectsBadValue covers the value-slot gate: a
// pseudorandom-function selector configstore.prfHash does not understand is
// rejected at commit. RED on revert of the ValidateMasterPasswordPRF validator.
func TestMasterPasswordPRF_RejectsBadValue(t *testing.T) {
	for _, bad := range []string{"bogus-prf", "hmac-sha256", "sha255"} {
		tree := buildTree(t, []string{
			"set system master-password pseudorandom-function " + bad,
		})
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("an unknown pseudorandom-function %q must be rejected at commit "+
				"(RED on revert: silently accepted → wrong/absent encryption)", bad)
		}
		if !strings.Contains(err.Error(), bad) {
			t.Fatalf("error must name the bad value %q, got: %v", bad, err)
		}
	}
}

// TestMasterPasswordPRF_AcceptsValidSelectors proves no false-reject: every
// selector configstore.prfHash understands still commits clean AND compiles to
// the expected MasterPassword value. Case-insensitivity is exercised too
// (prfHash lower-cases before matching, so the commit gate must not reject a
// spelling the runtime accepts).
func TestMasterPasswordPRF_AcceptsValidSelectors(t *testing.T) {
	cases := append(append([]string(nil), MasterPasswordPRFNames...), "HMAC-SHA2-256", "Sha512")
	for _, sel := range cases {
		tree := buildTree(t, []string{
			"set system master-password pseudorandom-function " + sel,
		})
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valid pseudorandom-function %q must commit clean, got: %v", sel, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", sel, err)
		}
		if cfg.System.MasterPassword != sel {
			t.Fatalf("compiled MasterPassword = %q, want %q", cfg.System.MasterPassword, sel)
		}
	}
}

// TestMasterPasswordPRF_DefaultUnsetStillCommits guards the intentional
// default: a config with NO master-password stanza (encryption off by default)
// and a config that names master-password with a valid PRF must both commit —
// the closed-world flip must not turn "no master-password" into an error.
func TestMasterPasswordPRF_DefaultUnsetStillCommits(t *testing.T) {
	// No master-password at all.
	noStanza := buildTree(t, []string{
		"set system host-name fw0",
	})
	if err := SchemaValidate(noStanza); err != nil {
		t.Fatalf("a config with no master-password must commit clean (encryption off by default), got: %v", err)
	}

	// master-password present with a valid PRF.
	withPRF := buildTree(t, []string{
		"set system master-password pseudorandom-function juniper-prf1",
	})
	if err := SchemaValidate(withPRF); err != nil {
		t.Fatalf("a valid master-password config must commit clean, got: %v", err)
	}
}

// TestValidateMasterPasswordPRF_Unit locks the validator's accept/reject set at
// the unit level (independent of the schema wiring).
func TestValidateMasterPasswordPRF_Unit(t *testing.T) {
	for _, name := range MasterPasswordPRFNames {
		if err := ValidateMasterPasswordPRF(name); err != nil {
			t.Errorf("ValidateMasterPasswordPRF(%q) = %v, want nil", name, err)
		}
	}
	for _, bad := range []string{"", "hmac-sha256", "bogus", "prf1"} {
		if err := ValidateMasterPasswordPRF(bad); err == nil {
			t.Errorf("ValidateMasterPasswordPRF(%q) = nil, want error", bad)
		}
	}
}
