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
	collected := config.SchemaValidateCollectTypedLeaves(tree, nil)
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
	if got := config.SchemaValidateCollectTypedLeaves(single, nil); len(got) != 1 {
		t.Fatalf("single-violation collect = %d, want 1: %v", len(got), got)
	}
	clean, _ := config.NewParser("class-of-service {\n schedulers be transmit-rate 1g;\n}").Parse()
	if got := config.SchemaValidateCollectTypedLeaves(clean, nil); len(got) != 0 {
		t.Fatalf("clean collect = %d, want 0: %v", len(got), got)
	}
}
