package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// #15253 (A80-02): the doc comment on emitDegradedPathCounters must not
// claim the RSS reshape is mlx5_core-only. That text predates the #9040
// capability probe (83acc21894) and is wrong in both directions: a probed
// i40e/ice box that was reshaped is described as dropping, and an mlx5 box
// whose reshape was skipped is implied safe. The comment is the operator
// guidance, so it is asserted here (comments stripped from code, comment
// itself inspected via the AST doc node -- not a substring of dead text).
func TestDegradedPathDocNotMlx5Only15253(t *testing.T) {
	src, err := os.ReadFile("metrics_degraded_path_9040.go")
	if err != nil {
		t.Fatalf("#15253: read metrics_degraded_path_9040.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "metrics_degraded_path_9040.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("#15253: parse: %v", err)
	}
	var doc string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "emitDegradedPathCounters" {
			doc = fd.Doc.Text()
			break
		}
	}
	if doc == "" {
		t.Fatal("#15253: emitDegradedPathCounters doc comment not found")
	}
	if strings.Contains(doc, "only reshaped to") && strings.Contains(doc, "mlx5_core") {
		t.Errorf("#15253: doc still claims RSS is only reshaped on mlx5_core:\n%s", doc)
	}
	if strings.Contains(doc, "every other driver is skipped") {
		t.Errorf("#15253: doc still claims an explicit driver guard skips other drivers:\n%s", doc)
	}
	if !strings.Contains(doc, "capability") {
		t.Errorf("#15253: doc must describe the #9040 capability-probed reshape:\n%s", doc)
	}
}
