package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// #6598: the fabric peer-MAC validity predicate lives in exactly one place,
// dpuserspace.FabricNeighUsable. Two resolvers for "which MAC answers for the
// fabric peer" disagreeing about what a usable neighbour is IS the defect, so
// this is a case for one definition rather than two that happen to agree.
//
// Re-duplication is easy and silent: before this fix daemon_ha_fabric.go held
// the named const, two address-matched call sites at different indentation, and
// a FOURTH copy written as an inline mask expansion that no search for the
// const name would ever have found.
//
// The scan is over the AST, not the text, so a comment mentioning NUD_FAILED
// (this file's own explanation, or a future one in the source) cannot satisfy
// or trip it — identifiers are identifiers and comments are not in the tree.
const fabricSourceFile6598 = "daemon_ha_fabric.go"

func TestFabricNeighPredicateHasOneDefinition_6598(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fabricSourceFile6598, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", fabricSourceFile6598, err)
	}

	var nudIdents []string
	var usableCalls int
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if strings.HasPrefix(node.Name, "NUD_") {
				nudIdents = append(nudIdents,
					fset.Position(node.Pos()).String()+": "+node.Name)
			}
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok &&
				pkg.Name == "dpuserspace" && node.Sel.Name == "FabricNeighUsable" {
				usableCalls++
			}
		}
		return true
	})

	// Vacuity: a file that failed to yield declarations would pass both
	// assertions below for the wrong reason.
	if len(file.Decls) < 10 {
		t.Fatalf("%s yielded only %d declarations — the scan is not reading the real file",
			fabricSourceFile6598, len(file.Decls))
	}

	// Direction 1: no NUD state constant is named here any more. Every fabric
	// neighbour-validity decision delegates.
	if len(nudIdents) > 0 {
		t.Errorf("%s names NUD state constants directly, re-duplicating the fabric "+
			"validity predicate instead of calling dpuserspace.FabricNeighUsable (#6598):\n\t%s",
			fabricSourceFile6598, strings.Join(nudIdents, "\n\t"))
	}

	// Direction 2: it delegates at every site it still checks. Without this,
	// DELETING the validity checks outright would satisfy direction 1 — the
	// predicate would be gone rather than shared, which is the same fail-open
	// this issue exists to close.
	// After #17044 the daemon no longer resolves the peer itself: the live
	// resolver in pkg/dataplane/userspace does, and it gates through the same
	// predicate. The two remaining daemon sites are the ARP/NDP probe gate
	// and the address-matched identity scan that arms the resolver's
	// link-local constraint. Enumerated rather than lower-bounded so that
	// REMOVING a check fails here even though adding one also does — the
	// count is a census of the decisions this file makes, and it should
	// change only deliberately.
	const wantCalls = 2
	if usableCalls != wantCalls {
		t.Errorf("%s calls dpuserspace.FabricNeighUsable %d times, want %d "+
			"(probe gate, identity scan); "+
			"a dropped call is a neighbour-validity check that silently went away (#6598)",
			fabricSourceFile6598, usableCalls, wantCalls)
	}
}
