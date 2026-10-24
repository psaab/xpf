package cmdtree

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// #8304 scope guard.
//
// AcceptsArgs is honoured in Canonicalize and NOWHERE ELSE. That is a
// deliberate asymmetry, not an oversight: "offers completions" and "accepts an
// argument" are different properties, and the completion walkers ask the first
// one. A walker that honoured AcceptsArgs would offer a bare value slot as if
// it were a completion source, and — worse — a reader who saw it honoured in
// two places would reasonably conclude it is a general "this node is permissive"
// flag and mark nodes whose dispatcher refuses the argument.
//
// Left as a comment, that scope is a claim that is true when written and false
// the moment someone honours it in another walker. This binds it.
//
// The check is AST-based, not grep-based, so a rename or a reflow cannot make
// it silently stop matching: it counts SELECTOR reads (`x.AcceptsArgs`), which
// excludes both the field declaration and the `AcceptsArgs: true` composite
// literal keys that mark nodes.

// acceptsArgsReadSites returns enclosing-function name -> read count for
// selector reads of the named field across the package's PRODUCTION files.
// Test files are excluded deliberately: this asserts where the SHIPPING code
// honours the flag, and a test is entitled to read it to make assertions.
func fieldReadSitesByFunc(t *testing.T, field string) map[string]int {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	sites := map[string]int{}
	scanned := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if ok && sel.Sel != nil && sel.Sel.Name == field {
					sites[fn.Name.Name]++
				}
				return true
			})
		}
	}

	if scanned == 0 {
		t.Fatalf("scanned 0 production files — the walker is broken, not the package empty")
	}
	return sites
}

func sortedFuncs(sites map[string]int) []string {
	out := make([]string, 0, len(sites))
	for k := range sites {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AcceptsArgs must be read by Canonicalize and the #16472 form walk, and by nothing else.
func TestAcceptsArgsIsHonouredOnlyInCanonicalize_8304(t *testing.T) {
	// POSITIVE CONTROL FIRST. If the detector cannot see a field that IS read
	// in many places, then a clean AcceptsArgs result proves nothing — it is
	// the vacuous green this whole cell exists to avoid. HasDynamic is the
	// right control precisely because it is the property AcceptsArgs was split
	// out of, and it IS read by the completion walkers.
	control := fieldReadSitesByFunc(t, "HasDynamic")
	if len(control) < 2 {
		t.Fatalf("positive control failed: the detector found reads of HasDynamic in %d function(s) (%v). "+
			"It must see reads spread across several functions, or its verdict on AcceptsArgs is vacuous — "+
			"the pattern is wrong, not the reads missing.",
			len(control), sortedFuncs(control))
	}
	outsideCanon := 0
	for fn := range control {
		if fn != "Canonicalize" {
			outsideCanon++
		}
	}
	if outsideCanon == 0 {
		t.Fatalf("positive control failed: every HasDynamic read the detector found was inside Canonicalize (%v). "+
			"It has never demonstrated it can SEE a read outside Canonicalize, which is the only thing "+
			"this test is trying to detect.", sortedFuncs(control))
	}

	// THE ASSERTION.
	sites := fieldReadSitesByFunc(t, "AcceptsArgs")

	total := 0
	for _, n := range sites {
		total += n
	}
	if total == 0 {
		t.Fatalf("no production code reads AcceptsArgs. Either the flag became dead — in which case the " +
			"nodes marked with it are silently unresolvable again — or this detector stopped matching.")
	}

	for _, fn := range sortedFuncs(sites) {
		// #16472: CanonicalForms / chargeTokens16472 are the shared
		// form walk (moved from pkg/cli) that ends a command form at
		// an AcceptsArgs node; they are deliberate second readers.
		if fn == "CanonicalForms" || fn == "chargeTokens16472" {
			continue
		}
		if fn != "Canonicalize" {
			t.Errorf("AcceptsArgs is read in %s(), but it is honoured ONLY in Canonicalize (plus the #16472 form walk).\n"+
				"  Read sites found: %v\n"+
				"  \"offers completions\" and \"accepts an argument\" are different properties; the completion\n"+
				"  walkers ask the first. If %s() genuinely needs this, that is a design change and the\n"+
				"  Node.AcceptsArgs doc comment plus pkg/cmdtree/README.md must change with it — do not\n"+
				"  simply widen this test.", fn, sites, fn)
		}
	}
}
