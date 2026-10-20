package config

import (
	"strings"
	"testing"
)

// #15718: Node.Annotation must survive every format/load surface.

func annotatedTree15718(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser("system {\n    host-name fw1;\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.AnnotatePath([]string{"system"}, "sys note"); err != nil {
		t.Fatalf("AnnotatePath system: %v", err)
	}
	if err := tree.AnnotatePath([]string{"system", "host-name"}, "primary fw"); err != nil {
		t.Fatalf("AnnotatePath host-name: %v", err)
	}
	return tree
}

func TestAnnotationSurfaces15718(t *testing.T) {
	tree := annotatedTree15718(t)

	// FormatSet / FormatPathSet / FormatSetForLoadMerge emit annotate lines.
	for name, out := range map[string]string{
		"FormatSet":             tree.FormatSet(),
		"FormatSetForLoadMerge": tree.FormatSetForLoadMerge(),
		"FormatPathSet":         tree.FormatPathSet([]string{"system"}),
	} {
		if !strings.Contains(out, `annotate system "sys note"`) {
			t.Errorf("%s missing container annotate:\n%s", name, out)
		}
		if !strings.Contains(out, `annotate system host-name fw1 "primary fw"`) {
			t.Errorf("%s missing leaf annotate:\n%s", name, out)
		}
	}

	// FormatPath / FormatPathInheritance render matched root annotation.
	if out := tree.FormatPath([]string{"system"}); !strings.Contains(out, "/* sys note */") {
		t.Errorf("FormatPath missing root annotation:\n%s", out)
	}
	if out := tree.FormatPath([]string{"system", "host-name"}); !strings.Contains(out, "/* primary fw */") {
		t.Errorf("FormatPath leaf missing annotation:\n%s", out)
	}
	if out := tree.FormatPathInheritance([]string{"system"}); !strings.Contains(out, "/* sys note */") {
		t.Errorf("FormatPathInheritance missing root annotation:\n%s", out)
	}

	// FormatCompare: annotation-only change is visible.
	plain, errs := NewParser("system {\n    host-name fw1;\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse plain: %v", errs)
	}
	if diff := FormatCompare(plain, tree); !strings.Contains(diff, "/* primary fw */") && !strings.Contains(diff, "/* sys note */") {
		t.Errorf("FormatCompare hides annotation change:\n%q", diff)
	}
	if diff := FormatCompare(tree, plain); !strings.Contains(diff, "/* primary fw */") && !strings.Contains(diff, "/* sys note */") {
		t.Errorf("FormatCompare hides annotation removal:\n%q", diff)
	}
	if diff := FormatCompare(tree, tree.Clone()); diff != "" {
		t.Errorf("FormatCompare identical annotated trees = %q, want empty", diff)
	}

	// Parser: /* comment */ before a statement attaches as Annotation.
	parsed, errs := NewParser("system {\n    /* my comment */\n    host-name fw1;\n}\n/* top note */\ninterfaces {\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse annotated: %v", errs)
	}
	sys := parsed.Children[0]
	if len(sys.Children) == 0 || sys.Children[0].Annotation != "my comment" {
		t.Errorf("parser dropped preceding comment: %+v", sys.Children)
	}
	if len(parsed.Children) < 2 || parsed.Children[1].Annotation != "top note" {
		t.Errorf("parser dropped top-level comment")
	}
	// Format -> Parse round-trip preserves annotations.
	rt, errs := NewParser(tree.Format()).Parse()
	if len(errs) > 0 {
		t.Fatalf("reparse Format: %v", errs)
	}
	if rt.Children[0].Annotation != "sys note" || rt.Children[0].Children[0].Annotation != "primary fw" {
		t.Errorf("Format->Parse lost annotations: %+v", rt.Children[0])
	}
	// Plain prose comments are not annotations.
	prose, errs := NewParser("system {\n    /* just prose */\n    host-name fw1;\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse prose: %v", errs)
	}
	_ = prose // prose comment before statement DOES attach per Junos; covered above

	// IsFlatLoadLine recognizes annotate.
	if !IsFlatLoadLine(`annotate system host-name "primary fw"`) {
		t.Error("IsFlatLoadLine(annotate) = false")
	}
	flat, _, err := ClassifyLoadContent("annotate system host-name \"primary fw\"\n")
	if err != nil || !flat {
		t.Errorf("ClassifyLoadContent annotate-only = flat %v err %v", flat, err)
	}
}

func TestAnnotationChangedValue15718(t *testing.T) {
	a := annotatedTree15718(t)
	b := a.Clone()
	if err := b.AnnotatePath([]string{"system", "host-name"}, "secondary fw"); err != nil {
		t.Fatal(err)
	}
	diff := FormatCompare(a, b)
	if !strings.Contains(diff, "secondary fw") || !strings.Contains(diff, "primary fw") {
		t.Errorf("changed annotation diff missing old/new:\n%s", diff)
	}
}
