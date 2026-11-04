package config

import (
	"strings"
	"testing"
)

// #18962: the valueless-statement trio — the generic #8597 walk gate
// (schema_walk.go), validateScalarValueLeaf's too-few half
// (schema_walk_leaf.go), and the #16571 screen missing-value gate
// (compiler_validate_strict_screen.go) — shared ONE commit-outcome tail:
// "the compiler drops a valueless statement, so this commits clean and the
// configuration silently does not carry it". That sentence is true only on
// the tolerant ingress, where the finding is downgraded to a warning and the
// booted config really lacks the statement. On the strict arm the very same
// text is the commit-refusing error, so the refusal asserted the commit
// succeeded (the #18951/#18958 wording class).
//
// The tails are now per-arm, and these cells pin them as LITERALS (never a
// reference to valuelessStatementTail18962), head unchanged, so a tail swap
// cannot satisfy them tautologically:
//
//   - strict: the drop is kept as the REASON ("would ... so"), the outcome
//     states the refusal;
//   - lenient: the original drop wording, verbatim, because the tolerant
//     caller logs-and-continues and the accepted config carries no statement.
const (
	strictTail18962  = "the compiler would silently drop a valueless statement, so the commit is refused"
	lenientTail18962 = "the compiler drops a valueless statement, so this commits clean and the " +
		"configuration silently does not carry it"
)

// assertArmTails18962 fails the cell when err's text does not carry the
// expected arm's tail, or when it leaks the OTHER arm's outcome claim — the
// half that catches a regression back to one shared wording.
func assertArmTails18962(t *testing.T, where, text string, strict bool) {
	t.Helper()
	want, other, otherClaim := strictTail18962, lenientTail18962, "commits clean"
	if !strict {
		want, other, otherClaim = lenientTail18962, strictTail18962, "commit is refused"
	}
	if !strings.Contains(text, want) {
		t.Errorf("%s: tail is not the %s arm's literal %q: %q",
			where, map[bool]string{true: "strict", false: "lenient"}[strict], want, text)
	}
	if strings.Contains(text, other) || strings.Contains(text, otherClaim) {
		t.Errorf("%s: %s-arm text carries the other arm's outcome claim: %q",
			where, map[bool]string{true: "strict", false: "lenient"}[strict], text)
	}
}

// Builder 1 — the generic #8597 walk gate (schema_walk.go). The strict
// entries (SchemaValidate, SchemaValidateWithDefinitions) refuse the commit;
// SchemaValidateWithDefinitionsLenient is the tolerant-ingress entry
// (compileTreeLenient) whose errors are logged-and-continued.
func TestValuelessWalkTailIsPerArm_18962(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-options rib inet6.0 static route 2001:db8::/64 next-hop fe80::1 interface",
	})
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("strict SchemaValidate accepted a valueless `interface` modifier")
	}
	if !strings.Contains(err.Error(), "`interface` declares a value and none was given — ") {
		t.Fatalf("head changed — the re-pin is against the unchanged head: %v", err)
	}
	assertArmTails18962(t, "strict walk", err.Error(), true)

	lerr := SchemaValidateWithDefinitionsLenient(tree, tree)
	if lerr == nil {
		t.Fatal("lenient walk went silent — tolerance is the caller's downgrade, not the walk's")
	}
	if !strings.Contains(lerr.Error(), "`interface` declares a value and none was given — ") {
		t.Fatalf("lenient head drifted: %v", lerr)
	}
	assertArmTails18962(t, "lenient walk", lerr.Error(), false)
}

// Builder 2 — validateScalarValueLeaf's too-few half (schema_walk_leaf.go),
// reached through the walk's fixed-arity scalar branch. The routing-instance
// #9736 caller threads its own lenient flag the same way; no RI schema leaf
// reaches that case today (every scalar RI leaf carries a dedicated #9736
// validator whose wording names the mechanism only), so this cell pins the
// builder through its live caller.
func TestScalarLeafTooFewTailIsPerArm_18962(t *testing.T) {
	tree := buildTree(t, []string{"set interfaces ge-0/0/0 description"})
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("strict SchemaValidate accepted a valueless `description`")
	}
	if !strings.Contains(err.Error(), "`description` declares a value and none was given (this leaf takes 1 value token(s)); ") {
		t.Fatalf("head changed — the re-pin is against the unchanged head: %v", err)
	}
	assertArmTails18962(t, "strict scalar leaf", err.Error(), true)

	lerr := SchemaValidateWithDefinitionsLenient(tree, tree)
	if lerr == nil {
		t.Fatal("lenient walk went silent for a valueless `description`")
	}
	assertArmTails18962(t, "lenient scalar leaf", lerr.Error(), false)
}

// Builder 3 — the #16571 screen missing-value gate
// (compiler_validate_strict_screen.go). Strict compile returns the error;
// the tolerant compile downgrades it to a warning whose text the booted
// config really lacks the leaf.
func TestScreenMissingValueTailIsPerArm_18962(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option s1 tcp syn-flood attack-threshold 300 source-threshold",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict CompileConfig accepted a valueless source-threshold")
	}
	if !strings.Contains(err.Error(), "`tcp syn-flood source-threshold` declares a value and none was given — ") {
		t.Fatalf("head changed — the re-pin is against the unchanged head: %v", err)
	}
	if !strings.HasSuffix(err.Error(), " (#16571)") {
		t.Fatalf("the #16571 tag must close the message on both arms: %v", err)
	}
	assertArmTails18962(t, "strict screen", err.Error(), true)

	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must boot (#1960 no-brick): %v", lerr)
	}
	var hit bool
	for _, w := range cfg.Warnings {
		if !strings.Contains(w, "source-threshold") {
			continue
		}
		hit = true
		if !strings.Contains(w, "downgraded to warning on tolerant path") {
			t.Fatalf("lenient screen finding must arrive as the caller's downgrade: %q", w)
		}
		assertArmTails18962(t, "lenient screen", w, false)
		if !strings.HasSuffix(w, " (#16571)") {
			t.Fatalf("the #16571 tag must close the message on both arms: %q", w)
		}
	}
	if !hit {
		t.Fatalf("lenient compile warned about nothing; the downgrade warning is missing: %v", cfg.Warnings)
	}
}
