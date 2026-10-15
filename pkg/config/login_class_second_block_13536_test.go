package config

import (
	"strings"
	"testing"
)

// TestLoginClassInSecondLoginBlockValidates13536 is the RED-on-revert guard
// for #13536. Two sibling `login { … }` blocks under one `system` are legal
// and CompileConfig merges them (#6957), but collectSchemaRefs used the
// singular FindChild("login"), so a custom class defined only in the SECOND
// block was invisible to SchemaValidate and the commit was falsely rejected
// as referencing an undefined class.
func TestLoginClassInSecondLoginBlockValidates13536(t *testing.T) {
	src := "system {\n" +
		"  login { class noc-first { permissions view; } user alice { class noc-second; } }\n" +
		"  login { class noc-second { permissions view; } user bob { class noc-second; } }\n" +
		"}"

	// Premise: the parser really does produce two sibling `login` children,
	// so this fixture exercises the multi-block scan and cannot silently
	// collapse into the single-block case.
	sys := systemNode6956(t, src)
	logins := 0
	for _, ch := range sys.Children {
		if ch.Name() == "login" {
			logins++
		}
	}
	if logins != 2 {
		t.Fatalf("fixture produced %d `login` children, want 2", logins)
	}

	tree, parseErrs := NewParser(src).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var classNames []string
	for _, lc := range c.System.Login.Classes {
		classNames = append(classNames, lc.Name)
	}
	joined := strings.Join(classNames, ",")
	for _, want := range []string{"noc-first", "noc-second"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("compiled classes %v missing %q — premise broken, compiler no longer merges blocks", classNames, want)
		}
	}
	if err := SchemaValidate(tree, c); err != nil {
		t.Fatalf("SchemaValidate rejected a class defined in the second login block: %v", err)
	}
}

// TestLoginClassUndefinedAcrossLoginBlocksStillRejected13536 proves the fix
// did not go fail-open: a class defined in NEITHER login block is still
// rejected.
func TestLoginClassUndefinedAcrossLoginBlocksStillRejected13536(t *testing.T) {
	src := "system {\n" +
		"  login { class noc-first { permissions view; } }\n" +
		"  login { user bob { class ghost-class; } }\n" +
		"}"
	tree, parseErrs := NewParser(src).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	err = SchemaValidate(tree, c)
	if err == nil {
		t.Fatal("SchemaValidate accepted an undefined login class (fail-open regression)")
	}
	if !strings.Contains(err.Error(), "ghost-class") || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("rejection does not name the undefined class: %v", err)
	}
}
