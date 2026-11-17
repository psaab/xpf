package cluster

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"
)

// eventWait19161 bounds every wait for a cluster event in this package's
// tests (#19161). It is generous on purpose: a gate cell can pause the runner
// for minutes, and the guest clock runs on through a pause.
const eventWait19161 = 2 * time.Minute

// recvEvent19161 returns the next event from ch, or fails the test naming the
// event it waited for. A bare `<-m.Events()` that never fires used to hang the
// whole package until its -timeout panic (45 minutes on a root leg, naming a
// goroutine, not the cell or the missing event).
func recvEvent19161(t testing.TB, ch <-chan ClusterEvent, what string) ClusterEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(eventWait19161):
		t.Fatalf("no cluster event within %v: %s", eventWait19161, what)
		return ClusterEvent{}
	}
}

// TestNoUnboundedEventsReceive19161 keeps the package free of unbounded
// waits on an Events() channel: each must go through recvEvent19161, or be a
// case of a select that also has a default, a time.After/timer case, or a
// Done() case. A bare receive, a select with no such bound, a range over
// Events(), and an Events() channel bound to a variable (which this scan
// cannot follow) are each reported with their position.
func TestNoUnboundedEventsReceive19161(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, file)
	}
	problems, bounded := scanEventWaits19161(fset, parsed)
	// Anti-vacuity: the package has well over a hundred event waits; a scan
	// that saw few of them is not looking at this package.
	if bounded < 100 {
		t.Fatalf("only %d bounded event waits seen; the scan did not see the package", bounded)
	}
	for _, p := range problems {
		t.Errorf("%s; use recvEvent19161 so a missing event is a named FAIL, not a package hang", p)
	}
}

func isEventsCall19161(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Events" && len(call.Args) == 0
}

func isEventsRecv19161(n ast.Node) bool {
	u, ok := n.(*ast.UnaryExpr)
	return ok && u.Op == token.ARROW && isEventsCall19161(u.X)
}

// selectIsBounded19161: a default clause, or a case receiving from
// time.After(...)/time.Tick(...), a timer or ticker's .C, or a ...Done().
func selectIsBounded19161(sel *ast.SelectStmt) bool {
	for _, c := range sel.Body.List {
		cc := c.(*ast.CommClause)
		if cc.Comm == nil {
			return true // default
		}
		var x ast.Expr
		switch st := cc.Comm.(type) {
		case *ast.ExprStmt:
			x = st.X
		case *ast.AssignStmt:
			if len(st.Rhs) == 1 {
				x = st.Rhs[0]
			}
		}
		u, ok := x.(*ast.UnaryExpr)
		if !ok || u.Op != token.ARROW {
			continue
		}
		switch ch := u.X.(type) {
		case *ast.CallExpr:
			if f, ok := ch.Fun.(*ast.SelectorExpr); ok {
				if id, ok := f.X.(*ast.Ident); ok && id.Name == "time" && (f.Sel.Name == "After" || f.Sel.Name == "Tick") {
					return true
				}
				if f.Sel.Name == "Done" {
					return true
				}
			}
		case *ast.SelectorExpr:
			if ch.Sel.Name == "C" {
				return true
			}
		}
	}
	return false
}

// scanEventWaits19161 returns one problem per unbounded Events() wait, and
// the number of bounded ones.
func scanEventWaits19161(fset *token.FileSet, files []*ast.File) (problems []string, bounded int) {
	report := func(n ast.Node, what string) {
		problems = append(problems, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), what))
	}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectStmt:
			ok := selectIsBounded19161(x)
			for _, c := range x.Body.List {
				cc := c.(*ast.CommClause)
				if cc.Comm != nil {
					ast.Inspect(cc.Comm, func(m ast.Node) bool {
						if isEventsRecv19161(m) {
							if ok {
								bounded++
							} else {
								report(m, "Events() receive in a select with no default, timeout or Done() case")
							}
						}
						return true
					})
				}
				for _, s := range cc.Body {
					ast.Inspect(s, visit)
				}
			}
			return false
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "recvEvent19161" {
				bounded++
			}
		case *ast.RangeStmt:
			if isEventsCall19161(x.X) {
				report(x, "range over Events()")
			}
		case *ast.AssignStmt:
			for _, r := range x.Rhs {
				if isEventsCall19161(r) {
					report(r, "Events() bound to a variable (receive from X.Events() directly)")
				}
			}
		case *ast.ValueSpec:
			for _, v := range x.Values {
				if isEventsCall19161(v) {
					report(v, "Events() bound to a variable (receive from X.Events() directly)")
				}
			}
		case *ast.UnaryExpr:
			if isEventsRecv19161(x) {
				report(x, "bare <-...Events()")
			}
		}
		return true
	}
	for _, f := range files {
		ast.Inspect(f, visit)
	}
	return problems, bounded
}

// The scan itself, on fixtures: each unbounded shape is reported, each bound
// is accepted.
func TestEventWaitScanCells19161(t *testing.T) {
	const pre = "package c\n\nimport \"time\"\n\nvar _ = time.Second\n\nfunc f(m *M, ctx C, tm *T) {\n"
	cells := []struct {
		name, body string
		problems   int
		bounded    int
	}{
		{"recvEvent19161 is bounded", "recvEvent19161(nil, m.Events(), \"x\")\n", 0, 1},
		{"a bare receive is reported", "<-m.Events()\n", 1, 0},
		{"an assigned bare receive is reported", "ev := <-m.Events()\n_ = ev\n", 1, 0},
		{"a select with time.After is bounded", "select {\ncase <-m.Events():\ncase <-time.After(time.Second):\n}\n", 0, 1},
		{"a select with default is bounded", "select {\ncase ev := <-m.Events():\n_ = ev\ndefault:\n}\n", 0, 1},
		{"a select with a Done() case is bounded", "select {\ncase <-m.Events():\ncase <-ctx.Done():\n}\n", 0, 1},
		{"a select with a timer's C is bounded", "select {\ncase <-m.Events():\ncase <-tm.C:\n}\n", 0, 1},
		{"a select with no bound is reported", "select {\ncase <-m.Events():\ncase <-m.Other():\n}\n", 1, 0},
		{"a bare receive inside a bounded select's body is reported", "select {\ncase <-time.After(time.Second):\n<-m.Events()\n}\n", 1, 0},
		{"a range over Events() is reported", "for ev := range m.Events() {\n_ = ev\n}\n", 1, 0},
		{"Events() bound to a variable is reported", "ch := m.Events()\n<-ch\n", 1, 0},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "cell.go", pre+c.body+"}\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			problems, bounded := scanEventWaits19161(fset, []*ast.File{f})
			if len(problems) != c.problems || bounded != c.bounded {
				t.Errorf("got %d problem(s) %v and %d bounded; want %d and %d", len(problems), problems, bounded, c.problems, c.bounded)
			}
		})
	}
}
