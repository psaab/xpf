package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/denyaudit"
)

func collectAuthzDenials9042(t *testing.T) map[string]float64 {
	t.Helper()
	c := newCollector(nil)
	ch := make(chan prometheus.Metric, 32)
	c.emitAuthzDenials(ch)
	close(ch)
	out := map[string]float64{}
	for m := range ch {
		var pbm dto.Metric
		if err := m.Write(&pbm); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if !strings.Contains(m.Desc().String(), "xpf_authz_denials_total") {
			continue
		}
		label := ""
		for _, lp := range pbm.GetLabel() {
			if lp.GetName() == "surface" {
				label = lp.GetValue()
			}
		}
		out[label] = pbm.GetCounter().GetValue()
	}
	return out
}

// #9042: every surface must be emitted, INCLUDING AT ZERO. A counter that
// appears only once it fires cannot be alerted on and cannot distinguish
// "never denied" from "not scraped" — and zero is the normal state here, so it
// is the reading an operator most needs to be able to trust.
func TestAuthzDenialsEmittedForEverySurface9042(t *testing.T) {
	got := collectAuthzDenials9042(t)
	for _, s := range denyaudit.Surfaces() {
		if _, ok := got[string(s)]; !ok {
			t.Errorf("#9042: no sample for surface=%q. The log was demoted to Debug on the "+
				"strength of this counter existing; a surface that is not emitted has had "+
				"its only signal deleted rather than bounded.", s)
		}
	}
	if len(got) != len(denyaudit.Surfaces()) {
		t.Errorf("#9042: emitted %d samples for %d surfaces", len(got), len(denyaudit.Surfaces()))
	}
}

// THE BUG THIS GUARDS IS ONE I MADE, and it is invisible from the code.
//
// The descriptor was wired into describe() while the emit call was NOT, because
// the neighbouring call site reads `defer c.emitAdmissionRefusals(ch)` and a
// pattern written without `defer` silently matched nothing. A
// described-but-never-emitted metric scrapes as ABSENT — precisely the state
// this issue exists to end — and nothing about either file looks wrong.
//
// Asserted on the source rather than by calling Collect: Collect dereferences
// c.srv and panics on the nil-server collector these metric tests use. The
// production scrape path now enters through collectContext so the HTTP request
// context can reach long session-table walks; that method is shared by Collect
// and the request-bound metrics adapter.
func TestAuthzDenialsIsWiredIntoCollect9042(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("#9042: cannot read metrics.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "metrics.go", src, 0)
	if err != nil {
		t.Fatalf("#9042: parse metrics.go: %v", err)
	}
	var collect *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "collectContext" && fd.Body != nil {
			collect = fd
			break
		}
	}
	if collect == nil {
		t.Fatal("#9042: collectContext not found in metrics.go")
	}
	found := false
	ast.Inspect(collect.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "emitAuthzDenials" {
			found = true
		}
		return true
	})
	if !found {
		t.Error("#9042: collectContext never calls emitAuthzDenials, so xpf_authz_denials_total is " +
			"DESCRIBED but never emitted and scrapes as absent. The denial logs were demoted " +
			"to Debug on the strength of this counter existing.")
	}
}

// The counter the collector reads is the SAME one the recording sites advance.
func TestAuthzDenialsTracksTheRealCounter9042(t *testing.T) {
	before := collectAuthzDenials9042(t)[string(denyaudit.SurfaceRESTCrossSite)]
	for i := 0; i < 7; i++ {
		denyaudit.Note(denyaudit.SurfaceRESTCrossSite, "origin-mismatch")
	}
	after := collectAuthzDenials9042(t)[string(denyaudit.SurfaceRESTCrossSite)]
	if after-before != 7 {
		t.Errorf("#9042: metric advanced by %v after 7 denials, want 7 — the collector is "+
			"reading a different counter from the one the denial sites increment",
			after-before)
	}
}
