package config

import (
	"go/ast"
	"strings"
	"testing"
)

func TestCompilerPrewalkNamelessSkipCensus17257(t *testing.T) {
	files, _ := parseConfigPackage17153(t)
	file := files["compiler_prewalk.go"]
	if file == nil {
		t.Fatal("compiler_prewalk.go not parsed")
	}
	var prewalk *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "runPreWalkGates" {
			prewalk = fn
			break
		}
	}
	if prewalk == nil {
		t.Fatal("runPreWalkGates not found")
	}
	wantFlags := map[string]string{
		"validateFirewallNamelessTermsAST12526": "lenientFirewallRefs",
		"validatePolicyNamelessTermsAST12521":   "lenientPolicyNamelessTerm12521",
	}
	calls := make(map[string]int, len(wantFlags))
	ast.Inspect(prewalk.Body, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok {
			guarded := make(map[string]bool)
			ast.Inspect(ifStmt.Cond, func(cond ast.Node) bool {
				for _, flag := range wantFlags {
					if isOptsField17153(cond, flag) {
						guarded[flag] = true
					}
				}
				return true
			})
			ast.Inspect(ifStmt.Body, func(body ast.Node) bool {
				call, ok := body.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				flag, governed := wantFlags[ident.Name]
				if governed && guarded[flag] {
					t.Errorf("%s is again suppressed by opts.%s in runPreWalkGates", ident.Name, flag)
				}
				return true
			})
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		flag, governed := wantFlags[ident.Name]
		if !governed {
			return true
		}
		calls[ident.Name]++
		if len(call.Args) != 2 || !isOptsField17153(call.Args[1], flag) {
			t.Errorf("%s must receive opts.%s as its lenient argument", ident.Name, flag)
		}
		return true
	})
	for validator := range wantFlags {
		if calls[validator] != 1 {
			t.Errorf("runPreWalkGates calls %s %d times, want exactly once", validator, calls[validator])
		}
	}
}

func TestNamelessTermAlarmWarnings17257(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{
			name: "packed firewall",
			src:  `firewall { filter { F term { then discard; } } }`,
			want: `firewall family inet filter "F"`,
		},
		{
			name: "packed policy",
			src:  `policy-options { policy-statement { P term { then reject; } } }`,
			want: `policy-statement "P"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hierTree(t, tc.src))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			// Prove the standing signal comes from retained markers, not the
			// transient compile-warning slice.
			cfg.Warnings = nil
			warnings := NamelessTermAlarmWarnings17257(cfg)
			if len(warnings) != 1 || !strings.Contains(warnings[0], tc.want) ||
				!strings.Contains(warnings[0], "nameless") ||
				!strings.Contains(warnings[0], "tolerant compilation") {
				t.Fatalf("nameless alarm warnings = %q, want one marker-derived alarm naming %q", warnings, tc.want)
			}
		})
	}

	clean, err := CompileConfigLenient(hierTree(t, `system { host-name clean; }`))
	if err != nil {
		t.Fatalf("clean lenient compile: %v", err)
	}
	if warnings := NamelessTermAlarmWarnings17257(clean); len(warnings) != 0 {
		t.Fatalf("clean config alarm warnings = %q, want none", warnings)
	}
}
