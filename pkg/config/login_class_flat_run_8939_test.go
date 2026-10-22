package config

import (
	"reflect"
	"testing"
)

// #8939 on the RBAC surface. `system login class <name>` dropped every leaf
// after the first of a flat `set` command:
//
//	set system login class ops allow-commands "a" allow-configuration "c"
//	  -> allow-commands="a"  allow-configuration=""
//
// THE LOST VALUE IS NOT THE WHOLE LOSS. compiler_system.go also records leaf
// PRESENCE into LoginClass.AllowLeavesPresent, and #7172's loginRegexesFor
// keys enforcement on presence, not value:
//
//	if !allowSet && !denySet { return CompiledLoginRegexes{}, false, nil }
//
// with the caller contract stated in that file -- "callers MUST skip
// evaluation entirely". An allow regex is an ALLOWLIST. So dropping
// `allow-configuration` does not narrow the class to an empty allowlist, it
// removes the family's rule ALTOGETHER and the class keeps everything
// `permissions` grants. The loss direction is toward MORE authority.
//
// REACHABILITY IS A PROPERTY OF THE LEAF THE RUN STARTS AT, NOT OF THE
// CONTAINER -- measured on the FLAT-SET tree through the same pair
// compileTreeStrict runs (schemaValidateExpandedTree then CompileConfig), not
// on a hierarchical transcription, which is a DIFFERENT AST shape that #8437's
// fused-statement guard already catches and which `CheckText` cannot express.
//
//	login class:  allow-commands "x" idle-timeout 30  -> ACCEPTED
//	login class:  idle-timeout 30 allow-commands "x"  -> SCHEMA-REJECT
//	ike gateway:  address A external-interface E      -> ACCEPTED
//	ike gateway:  version v2-only address A           -> SCHEMA-REJECT
//
// Same container, same two statements, opposite verdicts by ORDER. A leaf that
// declares a type/validator (`idle-timeout` valueType 6, `version` valueType 8)
// routes to the typed-leaf branch, whose modifier-child check rejects the
// trailing tokens; an untyped args:1 leaf (`allow-commands`, `address`) falls
// through to the container branch, which by #3332's compiler-faithful contract
// DELIBERATELY ignores leftover Keys.
//
// So the earlier container-level reading -- "`class` is args:1 with children
// and no wildcard, therefore nothing under it is validated" -- is WRONG, and
// `idle-timeout` is the counterexample. What IS container-level is unknown-
// keyword blindness, a separate property:
//
//	set system login class ops bogus-token 5    -> ADMITTED
//	set system login user bob  bogus-token 5    -> ADMITTED
//	set security flow tcp-session bogus-token 5 -> rejected, closed world
func TestLoginClassFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *LoginClass {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil || cfg.System.Login == nil {
			t.Fatalf("compile: %v", err)
		}
		for _, lc := range cfg.System.Login.Classes {
			if lc != nil && lc.Name == "ops" {
				return lc
			}
		}
		t.Fatal("the command produced no `ops` class (#8939)")
		return nil
	}

	b := "set system login class ops "

	t.Run("two leaves", func(t *testing.T) {
		ref := build(t, b+`allow-commands "show interfaces"`, b+`allow-configuration "system services"`)
		if ref.AllowCommands == "" || ref.AllowConfiguration == "" ||
			len(ref.AllowLeavesPresent) != 2 {
			t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
				"below would pass against a class that carries nothing (#8939)", ref)
		}
		got := build(t, b+`allow-commands "show interfaces" allow-configuration "system services"`)
		if got.AllowConfiguration != ref.AllowConfiguration {
			t.Errorf("allow-configuration = %q, want %q (#8939)",
				got.AllowConfiguration, ref.AllowConfiguration)
		}
		// THE ONE THAT MATTERS. Presence is what #7172 gates enforcement on;
		// without it the configuration family has no rule at all.
		if !reflect.DeepEqual(got.AllowLeavesPresent, ref.AllowLeavesPresent) {
			t.Errorf("AllowLeavesPresent = %v, want %v -- a missing entry here does "+
				"not narrow the allowlist, it REMOVES the family's rule and the class "+
				"keeps everything `permissions` grants (#8939, #7172)",
				got.AllowLeavesPresent, ref.AllowLeavesPresent)
		}
	})

	// THE WIDTH A RECURSIVE DESCENT FAILS. At two leaves a flat run is
	// indistinguishable from ordinary nesting; the third packs onto ONE node's
	// Keys and only a keyword-delimited scan reaches it (#9079).
	t.Run("three leaves", func(t *testing.T) {
		ref := build(t, b+`allow-commands "show interfaces"`,
			b+`allow-configuration "system services"`, b+"idle-timeout 30")
		if ref.AllowCommands == "" || ref.AllowConfiguration == "" || ref.IdleTimeout == 0 {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		got := build(t, b+`allow-commands "show interfaces" `+
			`allow-configuration "system services" idle-timeout 30`)
		if got.AllowCommands != ref.AllowCommands ||
			got.AllowConfiguration != ref.AllowConfiguration ||
			got.IdleTimeout != ref.IdleTimeout {
			t.Errorf("packed class = {cmd:%q cfg:%q idle:%d}, want {cmd:%q cfg:%q idle:%d} (#8939)",
				got.AllowCommands, got.AllowConfiguration, got.IdleTimeout,
				ref.AllowCommands, ref.AllowConfiguration, ref.IdleTimeout)
		}
	})

	// MUTANTS THAT MUST SURVIVE. `permissions` is a MULTI leaf whose values are
	// permission names, not statements, and expandFlatRun cuts at any token
	// that resolves as a schema SIBLING. Both arms below already worked BEFORE
	// this change; they are here because a segmentation bug would break them
	// and the loser fixture cannot see either one.
	t.Run("multi leaf is not split", func(t *testing.T) {
		if got := build(t, b+`permissions all allow-configuration "system services"`); !reflect.DeepEqual(
			got.Permissions, []string{"all"}) || got.AllowConfiguration != "system services" {
			t.Errorf("permissions=%v allow-configuration=%q, want [all] / %q (#8939)",
				got.Permissions, got.AllowConfiguration, "system services")
		}
		if got := build(t, b+`permissions [ view configure ]`); !reflect.DeepEqual(
			got.Permissions, []string{"view", "configure"}) {
			t.Errorf("bracketed permissions = %v, want [view configure] -- the "+
				"multi leaf's VALUES must not be segmented (#8939, #2419)",
				got.Permissions)
		}
	})
}

// TestLoginClassRegexpsRefusalStillBypassed8939 records a defect this change
// does NOT fix, so the partial landing does not remove the reason to look.
//
// #7971 models `allow-commands-regexps` ONLY so it is REFUSED -- the family
// inverts allow/deny precedence, so accepting it under the plain family's
// semantics would silently weaken the restriction the operator wrote. That
// refusal is a keyValidator in the typed schema walk. Measured:
//
//	set … allow-commands "a"                      -> commits
//	set … allow-commands-regexps "b"              -> REFUSED (#7971)
//	set … allow-commands "a" allow-commands-regexps "b"  -> COMMITS
//
// The flat run nests the refused leaf under `allow-commands`, and because
// `class` is an args:1 instance container the walk never descends to it. The
// compiler-side fix above makes the leaf READ; it cannot make the walk REFUSE
// it, so a deliberate fail-closed refusal is still reachable-around by a
// spelling. Closing it means teaching the walk to descend into arg-modelled
// instance containers, which changes admission across every such container and
// is not smuggled into a compiler change.
//
// Asserted as the CURRENT state, deliberately: if someone closes the walk-side
// hole this cell goes red and points at itself, which is the correct outcome
// for a recorded gap.
func TestLoginClassRegexpsRefusalStillBypassed8939(t *testing.T) {
	mk := func(cmds ...string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		return tree
	}
	b := "set system login class ops "

	// The refusal exists and fires on its own line. If THIS stops rejecting,
	// #7971 has regressed and the comparison below means nothing.
	if err := SchemaValidateWithDefinitions(mk(b+`allow-commands-regexps "b"`), nil); err == nil {
		t.Fatal("#7971 no longer refuses a bare `allow-commands-regexps`; the " +
			"bypass measurement below has lost its reference arm")
	}

	if err := SchemaValidateWithDefinitions(mk(b+`allow-commands "a" allow-commands-regexps "b"`), nil); err != nil {
		t.Logf("the #7971 refusal now fires on the PACKED spelling too (%v). "+
			"That is a FIX: delete this cell and the note in docs/log/8939.md.", err)
	}
}

// TestFlatRunLeavesMultiValueBlocksAlone8939 is the regression cell for a
// defect this change INTRODUCED and a shipped instrument caught.
//
// expandFlatRun originally hoisted EVERY child of a terminating leaf, on the
// reasoning that a leaf declaring no schema children can have no body, so
// anything nested under it must be the next link of the chain. That is false
// for a `multi` leaf, and #2419 had already said so: in the BLOCK spelling
//
//	permissions { view; configure; }
//
// the children are VALUES, not statements. Hoisting them turned a leaf that
// was READ into one that was not read at all.
//
// THE LOSER FIXTURE COULD NOT SEE IT. `system login class` was ALREADY on the
// loser list, so the row leaving looks like the fix working; a container that
// starts walking and simultaneously stops reading another leaf produces the
// same fixture delta as a clean fix. TestSchemaSpellingDifferentialGate caught
// it because it sweeps SIX spellings per leaf and reports per-spelling
// verdicts -- `A=keep B=inert C=keep D=keep E=keep F=drop` -- so a leaf read in
// one spelling and inert in another is visible as a disagreement rather than
// as an aggregate.
//
// The fix is to hoist only a child that RESOLVES as another leaf of the
// container. Every chain link begins with a keyword, so none is lost; every
// value list stays attached to the leaf that owns it. expandFlatRun also stops
// CUTTING a multi leaf's Keys, per #2419.
//
// THIS CELL BINDS THE PAIR, NOT EITHER HALF, and that is measured rather than
// assumed: removing the hoist gate alone leaves it green, removing the multi
// guard alone leaves it green, removing BOTH reproduces the original
// per-spelling signature exactly. `permissions` is both multi and
// block-spelled, so either guard clears it; the two diverge on leaves this
// container does not have. The matrix is in flat_run_scan.go beside the code
// it describes.
func TestFlatRunLeavesMultiValueBlocksAlone8939(t *testing.T) {
	perms := func(t *testing.T, tree *ConfigTree) []string {
		t.Helper()
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil || cfg.System.Login == nil {
			t.Fatalf("compile: %v", err)
		}
		for _, lc := range cfg.System.Login.Classes {
			if lc != nil && lc.Name == "ops" {
				return lc.Permissions
			}
		}
		t.Fatal("no `ops` class")
		return nil
	}

	// The BLOCK spelling, which is the one the hoist broke. hierTree parses
	// real config text, so this is the shape a load / peer-sync carries.
	got := perms(t, hierTree(t, `system {
    login {
        class ops {
            permissions { view; configure; }
        }
    }
}`))
	if !reflect.DeepEqual(got, []string{"view", "configure"}) {
		t.Errorf("block-spelling permissions = %v, want [view configure] -- the "+
			"children of a multi leaf are VALUES and must not be hoisted into "+
			"sibling statements of the container (#8939, #2419)", got)
	}

	// And the run AFTER a multi leaf must still be reached, so the fix above is
	// not simply "stop expanding anything with children".
	tree := &ConfigTree{}
	for _, c := range []string{
		`set system login class ops permissions view deny-commands "request system reboot"`,
	} {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil || cfg.System.Login == nil {
		t.Fatalf("compile: %v", err)
	}
	for _, lc := range cfg.System.Login.Classes {
		if lc == nil || lc.Name != "ops" {
			continue
		}
		if lc.DenyCommands == "" || len(lc.DenyLeavesPresent) == 0 {
			t.Errorf("deny-commands after a multi leaf = %q present=%v, want the "+
				"authored value and its #5831 presence record (#8939)",
				lc.DenyCommands, lc.DenyLeavesPresent)
		}
	}
}
