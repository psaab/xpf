package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestEveryStrictCommitGateIsWired is a completeness canary for the commit-time
// strict-validation surface (#4422). The commit path enforces ~80 hand-wired
// `validate<X>Strict(cfg *Config) error` gates, each an `if err :=
// validate<X>Strict(cfg); err != nil { return ... }` line in
// runUniformGates / compiler.go. Every one of those gates turns a silent
// fail-open / fail-closed / split-brain misconfiguration into an operator-
// visible commit error (dangling policer / prefix-list / routing-instance /
// feed references, out-of-range NAT ports, never-match filter cross-fields,
// unknown host-inbound tokens, and so on — see compiler_validate_strict*.go).
//
// The per-issue tests each assert that THEIR gate fires. NONE of them asserts
// that the COMPLETE set is wired: if a new `validate<X>Strict(cfg *Config)
// error` is added to compiler_validate_strict*.go but the author forgets the
// one-line `if err := validate<X>Strict(cfg); err != nil { ... }` invocation in
// the gate runner, the gate is DEAD — it compiles, its own unit test still
// passes if that test calls the function directly, yet the commit path never
// runs it and the misconfiguration it guards silently ships. That is exactly
// the class of regression this canary catches. It mirrors the established
// completeness-canary idiom in this codebase (pkg/api
// TestCollectorDescriptorCoverage for Prometheus descriptors;
// TestStrictValidationSetMatchesCatalogNames for the app-catalog drift guard).
//
// FAIL-ON-REVERT: delete (or comment out) any single
// `if err := validate<X>Strict(cfg); err != nil { ... }` invocation in
// compiler_uniformgates.go / compiler.go and this test names that gate as
// UNWIRED and goes RED.
//
// Method: parse every non-test .go file in the package, collect the set of
// top-level functions whose name ends in "Strict" and whose signature is
// exactly `(cfg *Config) error` (the gate shape — helpers and parameterized
// gates with other signatures, e.g. validateHostInboundStanzaStrict(zone,
// ifName string, hib *HostInboundTraffic, lenient bool), are intentionally
// excluded and covered by their per-feature wiring tests), then collect every
// call expression to a same-named function. A defined gate that is never
// called anywhere in the production source is unwired.
func TestEveryStrictCommitGateIsWired(t *testing.T) {
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.): %v", err)
	}

	// defined: gate name -> "file:line" of its definition (for the error msg).
	defined := map[string]string{}
	// called: any function name that appears as a call target.
	called := map[string]bool{}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if node.Recv == nil && strings.HasSuffix(node.Name.Name, "Strict") &&
					isCfgConfigErrorGateSig(node.Type) {
					defined[node.Name.Name] = fset.Position(node.Name.Pos()).String()
				}
			case *ast.CallExpr:
				if id, ok := node.Fun.(*ast.Ident); ok {
					called[id.Name] = true
				}
			}
			return true
		})
	}

	// Sanity floor: if the parse walk found far fewer gates than the ~80 the
	// commit path wires today, the canary is silently mis-parsing (e.g. a build
	// change moved the source) and would vacuously pass — fail loudly instead.
	if len(defined) < 50 {
		t.Fatalf("found only %d `(cfg *Config) error` strict gates; expected ~80 — "+
			"the wiring canary is mis-parsing the package source and would give a "+
			"false all-clear", len(defined))
	}

	var unwired []string
	for gate, pos := range defined {
		if !called[gate] {
			unwired = append(unwired, gate+" (defined at "+pos+")")
		}
	}
	if len(unwired) > 0 {
		sort.Strings(unwired)
		t.Fatalf("%d strict commit gate(s) are DEFINED but never invoked in the "+
			"compile path — the gate is dead and the misconfiguration it guards "+
			"silently ships (wire it into runUniformGates / compiler.go with an "+
			"`if err := <gate>(cfg); err != nil { return ... }` line):\n  %s",
			len(unwired), strings.Join(unwired, "\n  "))
	}
}

// isCfgConfigErrorGateSig reports whether a function type is exactly the strict
// commit-gate shape `func(cfg *Config) error`: one parameter of type *Config
// and one result of the built-in type `error`. Anything else (extra params, a
// non-*Config param, a non-error or multi-value result) is not a top-level gate
// and is excluded from the defined set.
func isCfgConfigErrorGateSig(ft *ast.FuncType) bool {
	if ft.Params == nil || ft.Results == nil {
		return false
	}
	// Exactly one parameter, of type *Config.
	if len(ft.Params.List) != 1 {
		return false
	}
	p := ft.Params.List[0]
	if len(p.Names) != 1 {
		return false
	}
	star, ok := p.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if id, ok := star.X.(*ast.Ident); !ok || id.Name != "Config" {
		return false
	}
	// Exactly one result, of the built-in type error.
	if len(ft.Results.List) != 1 {
		return false
	}
	r := ft.Results.List[0]
	if len(r.Names) != 0 { // a named result would still be fine, but gates use none
		return false
	}
	id, ok := r.Type.(*ast.Ident)
	return ok && id.Name == "error"
}
