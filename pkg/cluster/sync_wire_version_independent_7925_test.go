package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #7925: SessionSyncWireVersion must be its OWN counter, not derived from
// CurrentHAProtocolVersion.
//
// WHY A SOURCE-LEVEL CHECK AND NOT A VALUE COMPARISON. Both constants are 1
// today, and they were equal before this change too — when SessionSyncWireVersion
// was literally `uint16(CurrentHAProtocolVersion)`. So `SessionSyncWireVersion ==
// 1` and `SessionSyncWireVersion == CurrentHAProtocolVersion` are BOTH true
// before and after the split. No comparison of values can tell the two states
// apart; the only observable difference is whether the declaration still names
// the HA constant. That is a fact about the source, so the source is what gets
// asserted.
//
// WHY go/parser AND NOT grep. The doc comment on the declaration deliberately
// quotes the old form — "no longer `uint16(CurrentHAProtocolVersion)`" — to
// record what changed. A textual scan is therefore satisfied by the very comment
// explaining the fix, and would report the constant as still derived. Parsing to
// an AST and inspecting only the VALUE EXPRESSION excludes comments by
// construction rather than by a strip step that could itself be wrong.
//
// Bump rule this guards, from the declaration's own doc: bump
// SessionSyncWireVersion when the `syncMsg*` set or `syncHeader` changes; bump
// CurrentHAProtocolVersion when heartbeat / failover / RG-handoff semantics
// change. Their equality today is a coincidence of history, not an invariant.

// haProtocolIdentsIn reports which HA-protocol constant names appear in an
// expression. Shared by the assertion and its positive control so the control
// exercises the same walker the assertion relies on.
func haProtocolIdentsIn(expr ast.Expr) []string {
	watched := map[string]bool{
		"CurrentHAProtocolVersion":   true,
		"LegacyHAProtocolVersion":    true,
		"MinCompatHAProtocolVersion": true,
	}
	var found []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && watched[id.Name] {
			found = append(found, id.Name)
		}
		return true
	})
	return found
}

func sessionSyncWireVersionExpr(t *testing.T) ast.Expr {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sync.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing sync.go: %v", err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != "SessionSyncWireVersion" || i >= len(vs.Values) {
					continue
				}
				return vs.Values[i]
			}
		}
	}
	// Not finding it is a failure, never a pass: a renamed or relocated constant
	// must not read as "no HA reference found".
	t.Fatal("SessionSyncWireVersion const declaration not found in sync.go — if it " +
		"moved, move this test with it; a missing declaration must not silently pass")
	return nil
}

func TestSessionSyncWireVersionIsNotDerivedFromHAProtocol7925(t *testing.T) {
	if found := haProtocolIdentsIn(sessionSyncWireVersionExpr(t)); len(found) > 0 {
		t.Errorf("SessionSyncWireVersion is declared in terms of %v, so a session-wire-only "+
			"change is forced to bump the HA protocol version as a side effect. That pushes "+
			"the HA version out from under MinCompatHAProtocolVersion and fails "+
			"GateProtocolCompat's [floor,current] window for peers that stayed compatible on "+
			"heartbeat/failover — the two are checked differently (HA: window; session-sync: "+
			"exact equality), which is why they must be able to move apart (#7925)", found)
	}
}

// Positive control. Without it, a walker that visited nothing — a wrong node
// type, an early return — would report "no HA reference" for the same reason a
// correctly split constant does, and the assertion above would pass whether or
// not the split ever happened.
func TestHAProtocolIdentWalkerDetectsADerivedExpression7925(t *testing.T) {
	derived, err := parser.ParseExpr("uint16(CurrentHAProtocolVersion)")
	if err != nil {
		t.Fatalf("parsing the control expression: %v", err)
	}
	found := haProtocolIdentsIn(derived)
	if len(found) != 1 || found[0] != "CurrentHAProtocolVersion" {
		t.Fatalf("the walker must find CurrentHAProtocolVersion in the pre-#7925 form "+
			"`uint16(CurrentHAProtocolVersion)`; got %v. Until it does, a clean result from "+
			"the assertion above means nothing", found)
	}
}
