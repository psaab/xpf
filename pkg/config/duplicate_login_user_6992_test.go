package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #6992 — the same `system login user` name authored in two blocks left TWO
// entries in Login.Users, and two readers picked DIFFERENT ones.
//
//	pkg/cli configuredClass      -> the FIRST block with a non-empty class
//	pkg/daemon applySystemLogin  -> iterates every block in order, so the
//	                                account state that lands (password,
//	                                authorized_keys) comes from the LAST
//
// Measured on a config that commits CLEAN at strict, before this fix:
//
//	user alice { uid 2001; class admins; authentication { ssh-rsa "K1"; } }
//	user alice { uid 2002; class ops;    authentication { ssh-rsa "K2"; } }
//
// compiled to two entries. applySystemLogin rewrites authorized_keys per entry
// with WriteFileDurable, so K2 — the key the operator wrote under the VIEW-only
// block — is the one on disk, while configuredClass answered `admins`. The
// credential that authenticates and the class that authorizes it came from
// different blocks, in the permissive direction.
//
// THE FIX IS A FOLD, NOT A MATCHED TIE-BREAK. compileSystemLogin now collapses a
// duplicated name into ONE entry with per-leaf last-authored-wins, which is what
// the FLAT spelling already produces (SetPath merges `set system login user
// alice ...` written twice onto one node, replacing each leaf). That is the
// #5180 dual-AST-equivalence property, and it is stronger than teaching one
// reader the other's tie-break — the pattern #6838 warns is a proxy that rots
// the day the other reader changes. After the fold there is no tie to break.
//
// The duplicate is ALSO rejected at strict commit, in the #5180 gate, because a
// fold is still a silent drop of the earlier block's uid/class/keys. Flat merges
// it in; hierarchical is told to author it once.

const dupUserHier6992 = `
system {
    login {
        class ops { permissions [ view ]; }
        class admins { permissions [ all ]; }
        user alice {
            uid 2001;
            class admins;
            authentication { ssh-rsa "ssh-rsa AAAAB3FIRST alice@a"; }
        }
        user alice {
            uid 2002;
            class ops;
            authentication { ssh-rsa "ssh-rsa AAAAB3SECOND alice@b"; }
        }
    }
}
`

// dupUserFlat6992 is the SAME statements in the flat spelling. It is the oracle:
// SetPath already merges them onto one node, so whatever it compiles to is what
// the hierarchical shape must compile to.
var dupUserFlat6992 = []string{
	"set system login class ops permissions view",
	"set system login class admins permissions all",
	"set system login user alice uid 2001",
	"set system login user alice class admins",
	`set system login user alice authentication ssh-rsa "ssh-rsa AAAAB3FIRST alice@a"`,
	"set system login user alice uid 2002",
	"set system login user alice class ops",
	`set system login user alice authentication ssh-rsa "ssh-rsa AAAAB3SECOND alice@b"`,
}

func hierTree6992(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v", errs)
	}
	return tree
}

func flatTree6992(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, quoted, err := ParseSetCommandQuoted(line)
		if err != nil {
			t.Fatalf("ParseSetCommandQuoted(%q): %v", line, err)
		}
		if err := tree.SetPathQuoted(path, quoted); err != nil {
			t.Fatalf("SetPathQuoted(%q): %v", line, err)
		}
	}
	return tree
}

func renderUsers6992(users []*LoginUser) string {
	parts := make([]string, 0, len(users))
	for _, u := range users {
		parts = append(parts, fmt.Sprintf("{name=%s uid=%d class=%s pw=%q keys=%v}",
			u.Name, u.UID, u.Class, u.EncryptedPassword.Reveal(), u.SSHKeys))
	}
	return strings.Join(parts, " ")
}

// TestDuplicateUserFoldsToOneEntry_6992 is the core property: after the fold no
// two entries share a name, so no reader can pick a different one.
//
// It asserts the FIELD VALUES too, not just the count. A fold that produced one
// entry with the wrong uid or class would satisfy a count-only assertion while
// still provisioning an account the operator did not describe, and a count-based
// guard is exactly the kind that goes vacuous.
func TestDuplicateUserFoldsToOneEntry_6992(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree6992(t, dupUserHier6992))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	users := cfg.System.Login.Users
	if len(users) != 1 {
		t.Fatalf("duplicate `user alice` compiled to %d entries; two readers can then "+
			"pick different ones: %s", len(users), renderUsers6992(users))
	}
	u := users[0]
	if u.Name != "alice" {
		t.Errorf("folded entry name = %q, want alice", u.Name)
	}
	if u.UID != 2002 {
		t.Errorf("folded uid = %d, want 2002 (the LAST authored value, matching the flat spelling)", u.UID)
	}
	if u.Class != "ops" {
		t.Errorf("folded class = %q, want ops (the LAST authored value)", u.Class)
	}
	// #8863 CHANGED THIS EXPECTATION, and the reason is that it was DERIVED
	// rather than decided. This cell originally required only the LAST block's
	// key, because the flat spelling replaced on a repeated `set … ssh-rsa` and
	// the fold was written to match it.
	//
	// That flat behaviour was the #8863 defect: a second key REVOKED the first,
	// and applyRootAuth / applySystemLogin write the compiled set as the WHOLE
	// of authorized_keys, so the holder of the first key lost access at the next
	// apply. With the flat path corrected to accumulate, matching it means
	// accumulating here too.
	//
	// #6992's decision is intact: uid, class and password above still take the
	// LAST authored value. Keys are a SET and are unioned; scalars are scalars
	// and are replaced. Both keys are provisioned because the operator authored
	// both, in both spellings.
	//
	// The CONTENTS are asserted, not the count: a fold that produced two entries
	// of the same key, or the right count of the wrong keys, must not pass.
	if len(u.SSHKeys) != 2 {
		t.Errorf("folded SSH keys = %v, want BOTH authored keys — a key missing here is "+
			"REVOKED at the next apply, because the compiled set becomes the whole of "+
			"authorized_keys (#8863)", u.SSHKeys)
	} else {
		if !strings.Contains(u.SSHKeys[0], "FIRST") {
			t.Errorf("folded SSH keys[0] = %q, want the FIRST block's key — dropping it is the "+
				"#8863 revocation this fold used to perform", u.SSHKeys[0])
		}
		if !strings.Contains(u.SSHKeys[1], "SECOND") {
			t.Errorf("folded SSH keys[1] = %q, want the SECOND block's key", u.SSHKeys[1])
		}
	}
}

// TestDuplicateUserFoldMatchesTheFlatSpelling_6992 is the dual-AST-equivalence
// half, and it is what makes the fold's tie-break a derivation rather than a
// choice: the flat spelling already merges these statements, so the
// hierarchical one must land on the same config rather than on a third answer.
func TestDuplicateUserFoldMatchesTheFlatSpelling_6992(t *testing.T) {
	hierCfg, err := CompileConfigLenient(hierTree6992(t, dupUserHier6992))
	if err != nil {
		t.Fatalf("hierarchical compile: %v", err)
	}
	flatCfg, err := CompileConfigLenient(flatTree6992(t, dupUserFlat6992))
	if err != nil {
		t.Fatalf("flat compile: %v", err)
	}

	// Non-vacuity: the oracle must actually carry the values under test. A flat
	// fixture that compiled to an empty user list would make the comparison
	// below pass for the wrong reason.
	if len(flatCfg.System.Login.Users) != 1 || flatCfg.System.Login.Users[0].Class == "" {
		t.Fatalf("fixture bug: the flat oracle is not a single classed user: %s",
			renderUsers6992(flatCfg.System.Login.Users))
	}

	if got, want := renderUsers6992(hierCfg.System.Login.Users), renderUsers6992(flatCfg.System.Login.Users); got != want {
		t.Errorf("the two spellings of the same statements compile differently\n hier: %s\n flat: %s", got, want)
	}
}

// TestClassAndCredentialComeFromTheSameBlock_6992 states the security property
// directly rather than through the entry count, so it survives a refactor that
// changes how the fold is implemented.
//
// The class a reader resolves for a name and the SSH key the daemon provisions
// for that name must come from ONE entry. Pre-fix this failed: the first entry
// carried `admins` and the second carried the key that reaches authorized_keys.
func TestClassAndCredentialComeFromTheSameBlock_6992(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree6992(t, dupUserHier6992))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// firstClassed mirrors pkg/cli configuredClass: the first entry of this
	// name with a non-empty class.
	var firstClassed *LoginUser
	// lastProvisioned mirrors pkg/daemon applySystemLogin: it iterates every
	// entry in order and rewrites authorized_keys, so the last one wins.
	var lastProvisioned *LoginUser
	for _, u := range cfg.System.Login.Users {
		if u == nil || u.Name != "alice" {
			continue
		}
		if firstClassed == nil && u.Class != "" {
			firstClassed = u
		}
		if len(u.SSHKeys) > 0 {
			lastProvisioned = u
		}
	}
	if firstClassed == nil || lastProvisioned == nil {
		t.Fatalf("fixture bug: no classed entry (%v) or no key-bearing entry (%v)",
			firstClassed != nil, lastProvisioned != nil)
	}
	if firstClassed != lastProvisioned {
		t.Errorf("the class reader and the credential provisioner resolve DIFFERENT entries: "+
			"class %q from one block, key %v from another — the key authored under one "+
			"block authenticates into the other block's class",
			firstClassed.Class, lastProvisioned.SSHKeys)
	}
}

// TestDuplicateUserRejectedAtCommit_6992 pins the gate half. The fold makes the
// outcome deterministic; it does not make the earlier block's uid/class/keys
// stop disappearing, and a silent drop is what the #5180 gate exists to refuse.
//
// Both severities are asserted: strict rejects, tolerant warns and still boots
// (#1960 no-brick). A test that only checked the reject would pass on a change
// that made the tolerant load fail closed and brick an upgrading node.
func TestDuplicateUserRejectedAtCommit_6992(t *testing.T) {
	tree := hierTree6992(t, dupUserHier6992)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("a duplicated `system login user` name committed CLEAN; the earlier " +
			"block's uid, class and keys are silently dropped")
	}
	if !strings.Contains(err.Error(), "login user") || !strings.Contains(err.Error(), "alice") {
		t.Fatalf("rejected, but NOT by the duplicate-login-user gate: %v", err)
	}

	cfg, lenientErr := CompileConfigLenient(tree)
	if lenientErr != nil {
		t.Fatalf("the tolerant load / peer-sync path must still boot (#1960): %v", lenientErr)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "login user") && strings.Contains(w, "alice") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the tolerant path dropped a block with NO warning; warnings were:\n%s",
			strings.Join(cfg.Warnings, "\n"))
	}
}

// TestDuplicateUserAcrossTwoLoginBlocks_6992 pins the UNION half of the gate's
// walk. Both the compiler and the gate treat repeated `system` / `login`
// stanzas as one stanza, so a name split across two `login` blocks is the same
// duplicate — and it is the spelling an operator reaches by `load merge`-ing a
// second file rather than by writing the name twice in one block.
//
// Without this fixture the walk could consult only the FIRST `login` block and
// every other assertion in this file would still pass, because they all author
// one block.
func TestDuplicateUserAcrossTwoLoginBlocks_6992(t *testing.T) {
	tree := hierTree6992(t, `
system {
    login {
        class ops { permissions [ view ]; }
        user alice { uid 2001; class admins; }
    }
    login {
        user alice { uid 2002; class ops; }
    }
}
`)
	if _, err := CompileConfig(tree); err == nil {
		t.Errorf("a name duplicated ACROSS two `login` blocks committed clean")
	} else if !strings.Contains(err.Error(), "login user") || !strings.Contains(err.Error(), "alice") {
		t.Errorf("rejected by a different gate: %v", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if len(cfg.System.Login.Users) != 1 {
		t.Errorf("the fold did not span two `login` blocks: %s",
			renderUsers6992(cfg.System.Login.Users))
	}
}

// TestSingleUserBlockUnaffected_6992 is the green control. The fold and the gate
// must be invisible to every config that authors a name once — which is every
// real config — so a distinct-name fixture must compile unchanged and commit.
func TestSingleUserBlockUnaffected_6992(t *testing.T) {
	cfg, err := CompileConfig(hierTree6992(t, `
system {
    login {
        class ops { permissions [ view ]; }
        user alice { uid 2001; class ops; }
        user bob   { uid 2002; class ops; }
    }
}
`))
	if err != nil {
		t.Fatalf("distinct user names no longer commit: %v", err)
	}
	got := map[string]int{}
	for _, u := range cfg.System.Login.Users {
		got[u.Name] = u.UID
	}
	want := map[string]int{"alice": 2001, "bob": 2002}
	if len(got) != len(want) {
		t.Fatalf("compiled users = %s, want two distinct entries", renderUsers6992(cfg.System.Login.Users))
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("user %s uid = %d, want %d", n, got[n], want[n])
		}
	}
}

// TestPartialDuplicateInheritsUnauthoredLeaves_6992 pins the per-LEAF half of
// the fold, which a "keep only the last block" implementation would get wrong.
//
// The second block authors only a class. The uid from the first block must
// survive, because that is what the flat spelling gives — SetPath replaces the
// leaves a later statement authors and leaves the others in place. Folding to
// the last BLOCK instead of the last LEAF would silently zero the uid.
func TestPartialDuplicateInheritsUnauthoredLeaves_6992(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree6992(t, `
system {
    login {
        class ops { permissions [ view ]; }
        user alice { uid 2001; class admins; }
        user alice { class ops; }
    }
}
`))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("want one folded entry, got %s", renderUsers6992(cfg.System.Login.Users))
	}
	u := cfg.System.Login.Users[0]
	if u.UID != 2001 {
		t.Errorf("uid = %d, want 2001 — the second block authored no uid, so the first "+
			"block's value must survive (per-LEAF last-authored-wins, not last-block-wins)", u.UID)
	}
	if u.Class != "ops" {
		t.Errorf("class = %q, want ops (the second block authored it)", u.Class)
	}
}
