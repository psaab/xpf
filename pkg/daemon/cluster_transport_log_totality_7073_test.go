package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"testing"
)

// #7073: step 20 decides whether to restart cluster comms with a WHOLE-struct
// comparison of clusterTransportKey, but the line that reported
// the decision was written out by hand and printed only four pairs. A commit
// that changed only fab1 therefore restarted comms correctly and then logged
//
//	cluster: transport config changed, restarting comms old_control=em0
//	new_control=em0 old_peer=... new_peer=... old_fabric=... new_fabric=...
//	old_fabric_peer=... new_fabric_peer=...
//
// with every pair identical — a line that asserts a change and then shows none,
// which reads to an operator as a spurious restart.
//
// The fix derives the pairs from the struct. These tests bind that.

// transportChangeLogArgs must yield one old_/new_ pair per field, carrying that
// field's value, for EVERY field of clusterTransportKey.
//
// The fixture differs in Fabric1Interface ONLY. That is deliberate and is the
// whole point: a fixture that differed in ControlInterface would have passed
// against the broken hand-written list too, because control was one of the four
// pairs it happened to print. fab1-only is the smallest shape in which the
// defect changes an outcome.
func TestTransportChangeLogArgsCoverEveryTransportField_7073(t *testing.T) {
	active := clusterTransportKey{
		ControlInterface:   "em0",
		PeerAddress:        "10.99.0.2",
		FabricInterface:    "fab0",
		FabricPeerAddress:  "10.99.1.2",
		Fabric1Interface:   "fab1-old",
		Fabric1PeerAddress: "10.99.2.2",
	}
	next := active
	next.Fabric1Interface = "fab1-new"

	rt := reflect.TypeOf(clusterTransportKey{})
	args := transportChangeLogArgs(active, next)

	if want := 4 * rt.NumField(); len(args) != want {
		t.Fatalf("transportChangeLogArgs returned %d args, want %d (one old_/new_ pair per field of %s)",
			len(args), want, rt.Name())
	}

	pairs := map[string]any{}
	for i := 0; i+1 < len(args); i += 2 {
		k, ok := args[i].(string)
		if !ok {
			t.Fatalf("arg %d is not a string key: %#v", i, args[i])
		}
		if _, dup := pairs[k]; dup {
			t.Fatalf("duplicate log key %q", k)
		}
		pairs[k] = args[i+1]
	}

	av := reflect.ValueOf(active)
	nv := reflect.ValueOf(next)
	differing := 0
	for i := range rt.NumField() {
		f := rt.Field(i)
		// The tag is not what makes a field appear — a tagless field is still
		// logged, under its Go name — but an untagged field means an unreadable
		// operator-facing key, so require one.
		tag := f.Tag.Get("log")
		if tag == "" {
			t.Errorf("clusterTransportKey.%s has no `log` tag; step 20 would log it as %q", f.Name, "old_"+f.Name)
			tag = f.Name
		}
		gotOld, ok := pairs["old_"+tag]
		if !ok {
			t.Errorf("no old_%s pair for clusterTransportKey.%s", tag, f.Name)
			continue
		}
		gotNew, ok := pairs["new_"+tag]
		if !ok {
			t.Errorf("no new_%s pair for clusterTransportKey.%s", tag, f.Name)
			continue
		}
		if want := av.Field(i).Interface(); gotOld != want {
			t.Errorf("old_%s = %v, want %v", tag, gotOld, want)
		}
		if want := nv.Field(i).Interface(); gotNew != want {
			t.Errorf("new_%s = %v, want %v", tag, gotNew, want)
		}
		if gotOld != gotNew {
			differing++
		}
	}

	// The reported symptom, stated directly: a line announcing a change must
	// show at least one. This is what reds if fab1 is dropped from the args.
	if differing != 1 {
		t.Errorf("fab1-only change produced %d differing old/new pairs, want exactly 1; "+
			"0 means the line asserts a change and shows none (#7073)", differing)
	}
}

// The helper is only worth anything if step 20 actually calls it. Bind the
// WIRING, not just the function: parse daemon_apply_tail.go and require that
// the "transport config changed" slog.Info call passes exactly one further
// argument, a spread of transportChangeLogArgs.
//
// This walks the AST rather than grepping the source text, so a comment that
// happens to quote the call — including the ones this change added — cannot
// satisfy it.
func TestStep20LogsTransportChangeThroughTheDerivedArgs_7073(t *testing.T) {
	const (
		file = "daemon_apply_tail.go"
		msg  = "cluster: transport config changed, restarting comms"
	)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if got, err := strconv.Unquote(lit.Value); err != nil || got != msg {
			return true
		}
		found++
		if len(call.Args) != 2 {
			t.Errorf("%s: the %q call takes %d args; want 2 (the message and one spread of transportChangeLogArgs). "+
				"A hand-written key/value list is what dropped the fab1 pairs (#7073).",
				fset.Position(call.Pos()), msg, len(call.Args))
			return true
		}
		if call.Ellipsis == token.NoPos {
			t.Errorf("%s: the %q call's second argument is not spread with ...", fset.Position(call.Pos()), msg)
		}
		inner, ok := call.Args[1].(*ast.CallExpr)
		if !ok {
			t.Errorf("%s: second argument is %T, want a call to transportChangeLogArgs", fset.Position(call.Pos()), call.Args[1])
			return true
		}
		id, ok := inner.Fun.(*ast.Ident)
		if !ok || id.Name != "transportChangeLogArgs" {
			t.Errorf("%s: second argument calls %s, want transportChangeLogArgs",
				fset.Position(call.Pos()), exprName(inner.Fun))
		}
		return true
	})

	if found != 1 {
		t.Fatalf("found %d %q log calls in %s, want exactly 1 — the test cannot bind a site it did not find",
			found, msg, file)
	}
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprName(v.X) + "." + v.Sel.Name
	default:
		return "<expr>"
	}
}
