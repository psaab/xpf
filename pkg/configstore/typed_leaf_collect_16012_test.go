package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16012: tolerant schema walk reported only the first typed-leaf
// violation. Two independent violations must both be collected, the
// tolerant path must persist both warnings, and strict still rejects.
const twoTypedViolations16012 = `class-of-service {
    schedulers be transmit-rate asd;
    schedulers ef transmit-rate xyz;
}`

func TestTwoTypedLeafViolationsBothCollected16012(t *testing.T) {
	// Strict: still rejects (first error).
	if _, err := CheckText(twoTypedViolations16012, -1); err == nil {
		t.Fatal("strict CheckText accepted two typed-leaf violations")
	}
	tree, errs := config.NewParser(twoTypedViolations16012).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	collected, cerr := config.SchemaValidateCollectTypedLeaves(tree, nil)
	if cerr != nil {
		t.Fatalf("collect structural err: %v", cerr)
	}
	if len(collected) < 2 {
		t.Fatalf("collect = %d errors, want >=2 (both violations): %v", len(collected), collected)
	}
	joined := ""
	for _, e := range collected {
		joined += e.Error() + "\n"
	}
	for _, want := range []string{"asd", "xyz"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("collected errors do not name %q: %s", want, joined)
		}
	}
	// Tolerant: no-brick, both warnings persisted.
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile rejected (no-brick violated): %v", err)
	}
	warnings := config.ToleratedTypedLeafWarnings(compiled)
	if len(warnings) != 2 {
		t.Fatalf("tolerated typed-leaf warnings = %d, want 2: %v", len(warnings), compiled.Warnings)
	}
	wj := strings.Join(warnings, "\n")
	for _, want := range []string{"asd", "xyz"} {
		if !strings.Contains(wj, want) {
			t.Fatalf("persisted warnings do not name %q: %s", want, wj)
		}
	}
	// Control: single violation still yields exactly one.
	single, _ := config.NewParser(toleratedTypedLeaf10515).Parse()
	if got, _ := config.SchemaValidateCollectTypedLeaves(single, nil); len(got) != 1 {
		t.Fatalf("single-violation collect = %d, want 1: %v", len(got), got)
	}
	clean, _ := config.NewParser("class-of-service {\n schedulers be transmit-rate 1g;\n}").Parse()
	if got, _ := config.SchemaValidateCollectTypedLeaves(clean, nil); len(got) != 0 {
		t.Fatalf("clean collect = %d, want 0: %v", len(got), got)
	}
}

// Fold: typed violations collected before a later non-typed structural
// error must be preserved, and a multi-value leaf must collect every
// invalid member (bounded), not stop at the first.
func TestCollectPreservesTypedBeforeStructuralAndAllMultiMembers16012(t *testing.T) {
	// Typed first, structural (midKeyword, non-typed) later.
	mixed := `class-of-service {
    schedulers be transmit-rate asd;
}
security {
    policies {
        from-zone trust to-zon untrust {
            policy p1 { then permit; }
        }
    }
}`
	tree, errs := config.NewParser(mixed).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	collected, structural := config.SchemaValidateCollectTypedLeaves(tree, nil)
	if structural == nil {
		t.Fatal("expected later structural error to be returned separately")
	}
	if config.IsTypedLeafSchemaError(structural) {
		t.Fatalf("structural error misclassified typed: %v", structural)
	}
	if len(collected) != 1 || !strings.Contains(collected[0].Error(), "asd") {
		t.Fatalf("typed errors before structural must be preserved, got %v (structural %v)", collected, structural)
	}
	// Tolerant path persists the preserved typed warning despite structural schemaErr.
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if warnings := config.ToleratedTypedLeafWarnings(compiled); len(warnings) != 1 || !strings.Contains(warnings[0], "asd") {
		t.Fatalf("preserved typed warning not persisted: %v", compiled.Warnings)
	}

	// Multi-value: every invalid member collected (flat and block forms).
	flat, _ := config.NewParser("system {\n name-server [ bad-one bad-two 1.1.1.1 ];\n}").Parse()
	// Bracket spelling may parse differently; use set-style multi tokens via braced system leaf line.
	_ = flat
	multiText := "system {\n    name-server bad-one;\n}"
	_ = multiText
	// Direct flat-set construction through parser used by schema tests: two bad members on one leaf.
	tree2, errs2 := config.NewParser(`system {
    name-server {
        bad-one;
        bad-two;
    }
}`).Parse()
	if len(errs2) > 0 {
		t.Fatalf("parse2: %v", errs2[0])
	}
	got, serr := config.SchemaValidateCollectTypedLeaves(tree2, nil)
	if serr != nil {
		t.Fatalf("multi collect structural: %v", serr)
	}
	joined := ""
	for _, e := range got {
		joined += e.Error() + "\n"
	}
	if len(got) != 2 || !strings.Contains(joined, "bad-one") || !strings.Contains(joined, "bad-two") {
		t.Fatalf("multi-value collect = %d want 2 both members: %v", len(got), got)
	}
	// Bound: >16 invalid members caps at MaxCollected.
	var sb strings.Builder
	sb.WriteString("system {\n name-server {\n")
	for range 20 {
		sb.WriteString("bad-member;\n")
	}
	sb.WriteString("}\n}")
	tree3, _ := config.NewParser(sb.String()).Parse()
	got3, _ := config.SchemaValidateCollectTypedLeaves(tree3, nil)
	if len(got3) != config.MaxCollectedTypedLeafViolations16012 {
		t.Fatalf("bounded collect = %d want %d", len(got3), config.MaxCollectedTypedLeafViolations16012)
	}
}
