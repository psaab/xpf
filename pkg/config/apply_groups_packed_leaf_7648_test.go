package config

import "testing"

// apply_groups_packed_leaf_7648_test.go — #7648.
//
// When an applied group supplied a stanza in the COMPACT spelling and the local
// configuration already had a same-name node, the group's value was DROPPED.
// The BLOCK spelling of the same group merged correctly — two spellings of one
// intent, opposite outcomes.
//
// `ast_groups.go` classifies a node carrying its body on `Keys` as a LEAF, and
// the leaf path OVERRIDES when a peer exists (inline wins). A node whose body
// is in `Children` takes the container path and merges.
//
// WHY THE FIX EXPANDS RATHER THAN SPECIAL-CASES. Expanding the packed tail lets
// the SAME override logic run one level down:
//
//   - local `authentication-sha256 { }` — no peer for the expanded child, so
//     the group's value is adopted. This is the case that was dropped.
//   - local `authentication-sha256 { authentication-password "local"; }` — the
//     expanded child finds a peer, ordinary override applies, INLINE WINS.
//
// So the fix restores inheritance without weakening apply-groups precedence,
// and both are pinned below.
//
// INTERACTION WITH #7530, worth stating because it changes what this defect
// LOOKS like. Since that gate landed, the dropped-password case no longer
// compiles to a silent `AuthPassword=""` — it is REJECTED at commit, because a
// user naming an auth protocol with no key material now fails. The silent
// credential loss became a loud error, which is better; but it means a
// perfectly legitimate configuration (the group supplies the password
// compactly) could not be committed at all. That is what this fixes.

func compileGroups7648(t *testing.T, groupBody, localBody string) (*Config, error) {
	t.Helper()
	src := `groups { g1 { snmp { v3 { usm { local-engine { user ops {
    ` + groupBody + `
} } } } } } }
snmp { v3 { usm { local-engine { user ops {
    ` + localBody + `
} } } } }
apply-groups g1;`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

// THE DEFECT: the compact spelling must inherit exactly as the block one does.
func TestGroupCompactSpellingMergesIntoAnExistingPeer7648(t *testing.T) {
	cfg, err := compileGroups7648(t,
		`authentication-sha256 authentication-password "groupsecret";`,
		`authentication-sha256 { }`)
	if err != nil {
		t.Fatalf("the group supplies the password compactly and the local node is an "+
			"empty block — a legitimate configuration that must commit. Since #7530 the "+
			"dropped value is no longer a silent AuthPassword=\"\" but a commit "+
			"REJECTION, which is how this defect now surfaces: %v", err)
	}
	u := cfg.System.SNMP.V3Users["ops"]
	if u == nil {
		t.Fatal("no user compiled")
	}
	if u.AuthPassword.Reveal() != "groupsecret" {
		t.Errorf("AuthPassword = %q, want \"groupsecret\": the group's COMPACT value was "+
			"dropped against an existing same-name peer, while the BLOCK spelling of the "+
			"same group merges (#7648)", u.AuthPassword.Reveal())
	}
}

// EQUIVALENCE: the two spellings of one group must produce one outcome.
//
// Asserting them EQUAL rather than pinning a literal is the point — the defect
// was precisely that they disagreed, and a literal on one side would not have
// said which side was wrong.
func TestGroupCompactAndBlockSpellingsAgree7648(t *testing.T) {
	compact, errC := compileGroups7648(t,
		`authentication-sha256 authentication-password "groupsecret";`,
		`authentication-sha256 { }`)
	block, errB := compileGroups7648(t,
		`authentication-sha256 { authentication-password "groupsecret"; }`,
		`authentication-sha256 { }`)
	if errB != nil {
		t.Fatalf("the BLOCK spelling is the working control and must compile: %v", errB)
	}
	if errC != nil {
		t.Fatalf("the COMPACT spelling failed where the BLOCK spelling succeeded: %v", errC)
	}
	cu, bu := compact.System.SNMP.V3Users["ops"], block.System.SNMP.V3Users["ops"]
	if cu == nil || bu == nil {
		t.Fatal("a user failed to compile on one of the two spellings")
	}
	if cu.AuthPassword.Reveal() != bu.AuthPassword.Reveal() || cu.AuthProtocol != bu.AuthProtocol {
		t.Errorf("the two spellings of ONE group disagree: compact {%q,%q} vs block {%q,%q}",
			cu.AuthProtocol, cu.AuthPassword.Reveal(), bu.AuthProtocol, bu.AuthPassword.Reveal())
	}
}

// CONTROL — APPLY-GROUPS PRECEDENCE IS NOT WEAKENED. An inline value still
// beats the group's.
//
// This is the cell that stops the fix being "groups now win". Expanding the
// packed tail moves the override decision one level down; it must not remove
// it.
func TestInlineValueStillBeatsTheGroup7648(t *testing.T) {
	cfg, err := compileGroups7648(t,
		`authentication-sha256 authentication-password "groupsecret";`,
		`authentication-sha256 { authentication-password "localsecret"; }`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	u := cfg.System.SNMP.V3Users["ops"]
	if u == nil {
		t.Fatal("no user compiled")
	}
	if u.AuthPassword.Reveal() != "localsecret" {
		t.Errorf("AuthPassword = %q, want \"localsecret\": apply-groups precedence says "+
			"the INLINE value wins over the group's, and expanding the packed tail must "+
			"not change that (#7648)", u.AuthPassword.Reveal())
	}
}

// CONTROL — group-only inheritance with NO local peer was already clean and
// must stay clean. The issue measured this explicitly.
func TestGroupOnlyInheritanceStillWorks7648(t *testing.T) {
	src := `groups { g1 { snmp { v3 { usm { local-engine { user ops {
    authentication-sha256 authentication-password "groupsecret";
} } } } } } }
apply-groups g1;`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("group-only inheritance must compile: %v", err)
	}
	if u := cfg.System.SNMP.V3Users["ops"]; u == nil || u.AuthPassword.Reveal() != "groupsecret" {
		t.Errorf("group-only inheritance regressed: %+v", u)
	}
}

// CONTROL — when BOTH sides use the compact spelling, inline STILL wins.
//
// This cell exists because the mutation matrix found its absence. Applying the
// expansion regardless of whether the peer is a leaf (`if !peer.IsLeaf` →
// `if true`) passed every other test here. It is a real defect: a COMPACT local
// peer is IsLeaf with its value on `Keys` and an EMPTY `Children`, so merging
// the group's expanded child into it finds no peer and ADOPTS the group's
// value — silently inverting apply-groups precedence for the one shape where
// both sides spell it the same way.
//
// The expansion is therefore gated on the peer being a container: that is the
// shape where the group is supplying content the local node does not have,
// rather than competing with a value it does.
func TestBothCompactSpellingsStillLetInlineWin7648(t *testing.T) {
	cfg, err := compileGroups7648(t,
		`authentication-sha256 authentication-password "groupsecret";`,
		`authentication-sha256 authentication-password "localsecret";`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	u := cfg.System.SNMP.V3Users["ops"]
	if u == nil {
		t.Fatal("no user compiled")
	}
	if u.AuthPassword.Reveal() != "localsecret" {
		t.Errorf("AuthPassword = %q, want \"localsecret\": with BOTH sides compact the "+
			"local peer is a leaf carrying its value on Keys, so expanding the group's "+
			"tail into its empty Children would adopt the GROUP's value and invert "+
			"apply-groups precedence (#7648)", u.AuthPassword.Reveal())
	}
}
