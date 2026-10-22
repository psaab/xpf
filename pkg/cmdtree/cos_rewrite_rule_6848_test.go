package cmdtree

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// #6848: `show class-of-service rewrite-rule` operational-tree wiring.

// cosRewriteRuleSchemaFamilies returns the rewrite-rule code-point families an
// operator can actually COMMIT, read from the config schema
// (schemaClassOfService["rewrite-rules"].children via the exported completer).
//
// This is the population every other copy of the list is measured against.
// pkg/config cannot import pkg/dataplane/userspace/format (format imports
// config), but CompleteSetPath crosses the boundary in the safe direction, so a
// test up here can hold the schema, the renderer and the operational tree in
// one place.
func cosRewriteRuleSchemaFamilies(t *testing.T) []string {
	t.Helper()
	got := config.CompleteSetPath([]string{"class-of-service", "rewrite-rules"})
	if len(got) == 0 {
		t.Fatal("config schema offers no `class-of-service rewrite-rules` children; " +
			"the derivation this file depends on has moved")
	}
	out := append([]string(nil), got...)
	sort.Strings(out)
	return out
}

// TestCoSRewriteRuleTypeChildrenMatchRenderer pins the THREE places the family
// list is written against the one place it is defined.
//
// The copies are: (a) the renderer's per-family branches in
// FormatCoSRewriteRules, (b) format.CoSRewriteRuleTypes, and (c) the cmdtree
// `type` completion children. Until #6858 this test compared (b) with (c) only
// — and NOTHING reads (b) except this test, so the pair was a closed loop.
// Deleting `appendNameOnly("exp", ...)` from the renderer left the package
// compiling and this test PASSING, which is precisely the drift its own doc
// comment said it existed to catch.
//
// (a) is behavioural and cannot be read as a list, so it is covered by
// TestCoSRewriteRuleRendererCoversEverySchemaFamily below; this test covers the
// two that are lists. Both directions matter: a value completion offers but the
// renderer ignores means the operator filters and gets everything back, and a
// family the renderer handles but completion omits means the operator cannot
// find it.
func TestCoSRewriteRuleTypeChildrenMatchRenderer(t *testing.T) {
	want := cosRewriteRuleSchemaFamilies(t)

	node := operationalNode(t, "show", "class-of-service", "rewrite-rule", "type")
	treeChildren := make([]string, 0, len(node.Children))
	for name := range node.Children {
		treeChildren = append(treeChildren, name)
	}
	sort.Strings(treeChildren)

	rendererTypes := append([]string(nil), dpformat.CoSRewriteRuleTypes...)
	sort.Strings(rendererTypes)

	for _, c := range []struct {
		what string
		got  []string
	}{
		{"cmdtree `type` completion children", treeChildren},
		{"format.CoSRewriteRuleTypes", rendererTypes},
	} {
		if !equalStrings(c.got, want) {
			t.Errorf("%s = %v, committable families (from the config schema) = %v; "+
				"a family an operator can commit must be completable AND filterable",
				c.what, c.got, want)
		}
	}
}

// TestCoSRewriteRuleRendererCoversEverySchemaFamily is the behavioural half:
// for every family the schema accepts, a rule authored in real `set` syntax
// must appear in the unfiltered render AND be selectable by `type <family>`.
//
// This is what makes the SSOT claim true rather than circular. The renderer's
// family handling is four hardcoded branches, not a list, so the only way to
// observe it is to render.
//
// FAIL-ON-REVERT: delete any one of the four branches in FormatCoSRewriteRules
// — `wantType("dscp")`, `wantType("ieee-802.1")`, `appendNameOnly("inet-
// precedence", ...)`, `appendNameOnly("exp", ...)` — and that family's rule
// stops rendering, so both the unfiltered and the filtered assertion go RED.
func TestCoSRewriteRuleRendererCoversEverySchemaFamily(t *testing.T) {
	families := cosRewriteRuleSchemaFamilies(t)

	cmds := []string{"set class-of-service forwarding-classes queue 0 best-effort"}
	for _, fam := range families {
		// Code point 0 is in range for all four families (dscp 0..63, the
		// others 0..7), so one command shape covers every family without a
		// hand-written per-family table that could itself drift.
		cmds = append(cmds, "set class-of-service rewrite-rules "+fam+" "+cosRuleNameFor(fam)+
			" forwarding-class best-effort loss-priority low code-point 0")
	}
	cfg := compileCoSSet6858(t, cmds...)

	all := dpformat.FormatCoSRewriteRules(cfg, "", "")
	for _, fam := range families {
		header := "Rewrite rule: " + cosRuleNameFor(fam) + ", Code point type: " + fam
		if !strings.Contains(all, header) {
			t.Errorf("unfiltered render omits committable family %q (expected header %q):\n%s",
				fam, header, all)
		}
	}

	for _, fam := range families {
		out := dpformat.FormatCoSRewriteRules(cfg, "", fam)
		want := "Rewrite rule: " + cosRuleNameFor(fam) + ", Code point type: " + fam
		if !strings.Contains(out, want) {
			t.Errorf("type=%q filter dropped its own family (expected %q):\n%s", fam, want, out)
		}
		for _, other := range families {
			if other == fam {
				continue
			}
			if leak := "Rewrite rule: " + cosRuleNameFor(other) + ","; strings.Contains(out, leak) {
				t.Errorf("type=%q filter leaked family %q (%q):\n%s", fam, other, leak, out)
			}
		}
	}
}

// cosRuleNameFor derives a distinct, plain rule name per family so the test
// needs no hand-maintained family->name table.
func cosRuleNameFor(family string) string {
	return "rw-" + strings.ReplaceAll(family, ".", "-")
}

// compileCoSSet6858 runs `set` lines through the real grammar gate
// (SchemaValidate) and the real compiler — the same two steps a commit
// performs — so a family that reaches the renderer here is one an operator can
// actually commit.
func compileCoSSet6858(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCoSRewriteRuleNameCompletionIncludesInertFamilies pins that completion
// offers rules from ALL four families.
//
// Completing only the enforced dscp rules would hide precisely the rules this
// command exists to surface: an operator who configured an inert ieee-802.1 /
// inet-precedence / exp rule could not tab to it, and so would never see that
// it is inert. The two name-only families are stored as slices rather than
// maps, which is exactly the shape a name-collection helper is most likely to
// forget.
func TestCoSRewriteRuleNameCompletionIncludesInertFamilies(t *testing.T) {
	cfg := &config.Config{ClassOfService: &config.ClassOfServiceConfig{
		DSCPRewriteRules:           map[string]*config.CoSDSCPRewriteRule{"rw-dscp": {Name: "rw-dscp"}},
		IEEE8021RewriteRules:       map[string]*config.CoSIEEE8021RewriteRule{"rw-pcp": {Name: "rw-pcp"}},
		INetPrecedenceRewriteRules: []string{"rw-prec"},
		EXPRewriteRules:            []string{"rw-exp"},
	}}

	node := operationalNode(t, "show", "class-of-service", "rewrite-rule")
	if node.DynamicFn == nil {
		t.Fatal("rewrite-rule node has no DynamicFn; rule names would not complete")
	}
	got := map[string]bool{}
	for _, n := range node.DynamicFn(cfg) {
		got[n] = true
	}
	for _, want := range []string{"rw-dscp", "rw-pcp", "rw-prec", "rw-exp"} {
		if !got[want] {
			t.Errorf("completion omitted rewrite rule %q (have %v); an inert rule the "+
				"operator cannot tab to is one they will never learn is inert", want, got)
		}
	}

	// The `name` filter child must offer the same set — a narrower list there
	// would make `... rewrite-rule name <TAB>` disagree with `... rewrite-rule <TAB>`.
	nameNode := operationalNode(t, "show", "class-of-service", "rewrite-rule", "name")
	if nameNode.DynamicFn == nil {
		t.Fatal("rewrite-rule name node has no DynamicFn")
	}
	if len(nameNode.DynamicFn(cfg)) != len(node.DynamicFn(cfg)) {
		t.Errorf("`rewrite-rule name` completion (%v) differs from `rewrite-rule` completion (%v)",
			nameNode.DynamicFn(cfg), node.DynamicFn(cfg))
	}
}

// TestCoSRewriteRuleNameCompletionNilSafe covers the pre-config / cold-boot
// call, where the completer runs before any config exists.
func TestCoSRewriteRuleNameCompletionNilSafe(t *testing.T) {
	node := operationalNode(t, "show", "class-of-service", "rewrite-rule")
	if got := node.DynamicFn(nil); len(got) != 0 {
		t.Errorf("nil config completion = %v, want empty", got)
	}
	if got := node.DynamicFn(&config.Config{}); len(got) != 0 {
		t.Errorf("config with no ClassOfService = %v, want empty", got)
	}
}

// operationalNode walks the operational tree to path, failing the test if any
// segment is missing.
func operationalNode(t *testing.T, path ...string) *Node {
	t.Helper()
	nodes := OperationalTree
	var node *Node
	for i, seg := range path {
		n, ok := nodes[seg]
		if !ok {
			t.Fatalf("operational tree has no node at %v (missing %q)", path[:i+1], seg)
		}
		node = n
		nodes = n.Children
	}
	return node
}
