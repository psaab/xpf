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

// #17153 guard (hardened by the fold): mode queries read the tolerant mode
// bit, flag docs name every governed validator, deferJunosHostWarnings has
// one definition whose body is exactly `return opts.tolerant`, and
// `opts.tolerant =` cannot be assigned outside lenientCompileOpts().
//
// RED-on-revert: restoring `tree, opts.sanitizeFreeTextControlChars)` at the
// tunnel gate, restoring either copy of the four-flag OR, pointing the
// RX-MTU/mgmt advisories back at suppressContestedTrunkZoneAdvisory,
// dropping a validator name from the lenientFirewallRefs doc, reading
// opts.tolerant at a scrub site, adding a dummy
// validateTunnelEndpointIDCollisionAST call that discards its result while
// the production call borrows another flag, changing
// deferJunosHostWarnings to anything but `return opts.tolerant`, or an
// `opts.tolerant =` assignment outside lenientCompileOpts() each turn a
// cell below RED.

func parseConfigPackage17153(t *testing.T) (map[string]*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = f
	}
	if len(files) == 0 {
		t.Fatal("no non-test Go files parsed in pkg/config")
	}
	return files, fset
}

func isOptsField17153(n ast.Node, field string) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "opts"
}

// validatorsGovernedBy17153 returns, for flag, the sorted validator names
// invoked in an `if err := validateX(...); err != nil { if opts.<flag> ... }`
// (or `if !opts.<flag> { if err := validateX ... }` pre-walk) pattern in
// non-test sources, plus the enclosing func name for helper-pattern sites.
func validatorsGovernedBy17153(files map[string]*ast.File, flag string) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			// Pattern A: if err := validateX(...); ... { if opts.flag }
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ifStmt, ok := n.(*ast.IfStmt)
				if !ok || ifStmt.Init == nil {
					return true
				}
				// find validate call in init
				var vname string
				ast.Inspect(ifStmt.Init, func(m ast.Node) bool {
					if c, ok := m.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && (strings.HasPrefix(id.Name, "validate") || strings.HasPrefix(id.Name, "Validate")) {
							vname = id.Name
						}
					}
					return true
				})
				if vname == "" {
					return true
				}
				found := false
				ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
					if isOptsField17153(m, flag) {
						found = true
					}
					return true
				})
				if found {
					out[vname] = true
				}
				return true
			})
			// Pattern B (pre-walk): if !opts.flag { if err := validateX }
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ifStmt, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				uses := false
				ast.Inspect(ifStmt.Cond, func(m ast.Node) bool {
					if isOptsField17153(m, flag) {
						uses = true
					}
					return true
				})
				if !uses {
					return true
				}
				ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
					if c, ok := m.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && (strings.HasPrefix(id.Name, "validate") || strings.HasPrefix(id.Name, "Validate")) {
							out[id.Name] = true
						}
					}
					return true
				})
				return true
			})
		}
	}
	return out
}

func fieldDoc17153(t *testing.T, files map[string]*ast.File, typeName, fieldName string) string {
	t.Helper()
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != typeName {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					for _, n := range field.Names {
						if n.Name == fieldName {
							if field.Doc == nil {
								t.Fatalf("field %s.%s has no doc comment", typeName, fieldName)
							}
							return field.Doc.Text()
						}
					}
				}
			}
		}
	}
	t.Fatalf("field %s.%s not found", typeName, fieldName)
	return ""
}

func TestTolerantModeBit17153(t *testing.T) {
	if !lenientCompileOpts().tolerant {
		t.Fatal("tolerant is not set by lenientCompileOpts() — the only constructor allowed to set it")
	}
	if (compileOpts{}).tolerant {
		t.Fatal("zero compileOpts must be strict (tolerant=false)")
	}
	// Only lenientCompileOpts() may set tolerant in non-test code, by
	// composite-literal key or by an `opts.tolerant =` assignment. The
	// literal leg is scoped to the lenientCompileOpts body inside
	// compiler_opts.go; the assignment leg scans every non-test file.
	files, _ := parseConfigPackage17153(t)
	for name, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			inLenient := name == "compiler_opts.go" && fd.Name.Name == "lenientCompileOpts"
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.KeyValueExpr:
					id, ok := e.Key.(*ast.Ident)
					if ok && id.Name == "tolerant" && !inLenient {
						t.Errorf("%s (%s) sets tolerant outside lenientCompileOpts()", name, fd.Name.Name)
					}
				case *ast.AssignStmt:
					for _, lhs := range e.Lhs {
						if isOptsField17153(lhs, "tolerant") && !inLenient {
							t.Errorf("%s (%s) assigns opts.tolerant outside lenientCompileOpts()", name, fd.Name.Name)
						}
					}
				}
				return true
			})
		}
	}
}

func TestSanitizeReadOnlyAtScrubSites17153(t *testing.T) {
	files, _ := parseConfigPackage17153(t)
	// Allowlisted scrub sites: the pre-walk scrub/validate branch only.
	allowedFile := "compiler_prewalk.go"
	count := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if isOptsField17153(n, "sanitizeFreeTextControlChars") {
				count++
				if name != allowedFile {
					t.Errorf("opts.sanitizeFreeTextControlChars read in %s: only scrub sites (%s) may read it (#17153)", name, allowedFile)
				}
			}
			return true
		})
	}
	if count == 0 {
		t.Fatal("no sanitizeFreeTextControlChars read found — guard is vacuous")
	}
	// Tunnel gate must read tolerant, not sanitize, at exactly one
	// non-test call site. An exact count defeats a dummy call that
	// passes opts.tolerant and discards its result while the real
	// gate borrows another flag.
	tunnelCalls := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := c.Fun.(*ast.Ident)
			if !ok || id.Name != "validateTunnelEndpointIDCollisionAST" {
				return true
			}
			tunnelCalls++
			if name != "compiler.go" {
				t.Errorf("validateTunnelEndpointIDCollisionAST called in %s, want only compiler.go", name)
			}
			sawTolerant := false
			for _, a := range c.Args {
				ast.Inspect(a, func(m ast.Node) bool {
					if isOptsField17153(m, "tolerant") {
						sawTolerant = true
					}
					if isOptsField17153(m, "sanitizeFreeTextControlChars") {
						t.Error("tunnel gate still borrows sanitizeFreeTextControlChars")
					}
					return true
				})
			}
			if !sawTolerant {
				t.Errorf("validateTunnelEndpointIDCollisionAST call in %s does not pass opts.tolerant", name)
			}
			return true
		})
	}
	if tunnelCalls != 1 {
		t.Fatalf("validateTunnelEndpointIDCollisionAST has %d non-test call sites, want exactly 1 (dummy-call bypass?)", tunnelCalls)
	}
}

func TestDeferJunosHostWarningsSingleDefinition17153(t *testing.T) {
	files, _ := parseConfigPackage17153(t)
	defs := 0
	calls := 0
	for name, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "deferJunosHostWarnings" {
				continue
			}
			defs++
			if name != "compiler_tailgates.go" {
				t.Errorf("deferJunosHostWarnings defined in %s, want compiler_tailgates.go", name)
			}
			// Body must be exactly `return opts.tolerant`: a single
			// return of that selector, nothing else (no wrapper logic).
			if fd.Body == nil || len(fd.Body.List) != 1 {
				t.Errorf("deferJunosHostWarnings body is not the single statement `return opts.tolerant`")
				continue
			}
			ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 || !isOptsField17153(ret.Results[0], "tolerant") {
				t.Errorf("deferJunosHostWarnings body is not `return opts.tolerant`")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "deferJunosHostWarnings" {
					calls++
				}
			}
			return true
		})
	}
	if defs != 1 {
		t.Fatalf("deferJunosHostWarnings has %d definitions, want exactly 1", defs)
	}
	if calls < 2 {
		t.Fatalf("deferJunosHostWarnings has %d call sites, want >=2 (tailgates + final pass)", calls)
	}
	// The former four-flag OR must not reappear as a mode query.
	orFlags := []string{"lenientTunnelRITarget12520", "lenientWireguardRoutingInstance", "lenientRIDualClaim11060", "lenientRIMgmtMember11392"}
	for name, f := range files {
		if name != "compiler.go" && name != "compiler_tailgates.go" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			be, ok := n.(*ast.BinaryExpr)
			if !ok || be.Op != token.OR {
				return true
			}
			hits := 0
			for _, fl := range orFlags {
				ast.Inspect(be, func(m ast.Node) bool {
					if isOptsField17153(m, fl) {
						hits++
					}
					return true
				})
			}
			if hits >= 2 {
				t.Errorf("%s: multi-flag OR over %v reintroduces the duplicated defer predicate", name, orFlags)
			}
			return true
		})
	}
	if !deferJunosHostWarnings(lenientCompileOpts()) || deferJunosHostWarnings(compileOpts{}) {
		t.Fatal("deferJunosHostWarnings must be true only on the tolerant path")
	}
}

func TestFlagDocsNameGovernedValidators17153(t *testing.T) {
	files, _ := parseConfigPackage17153(t)

	// lenientFirewallRefs: every governed validator must be named in its doc.
	governed := validatorsGovernedBy17153(files, "lenientFirewallRefs")
	if len(governed) < 14 {
		names := make([]string, 0, len(governed))
		for k := range governed {
			names = append(names, k)
		}
		sort.Strings(names)
		t.Fatalf("AST census found only %d validators governed by lenientFirewallRefs (%v); census is not reaching the gates", len(governed), names)
	}
	doc := fieldDoc17153(t, files, "compileOpts", "lenientFirewallRefs")
	for v := range governed {
		if !strings.Contains(doc, v) {
			t.Errorf("lenientFirewallRefs governs %s but its field doc does not name it", v)
		}
	}

	// tolerant: doc must name every function whose suppression/mode it
	// governs. appendContestedTrunkZoneAdvisoryLocked and
	// appendSharedDeviceUnzonedUnitAdvisoryLocked are NOT in this list:
	// they keep their co-set suppressor (see the suppressor census below)
	// and must not be claimed for tolerant.
	tdoc := fieldDoc17153(t, files, "compileOpts", "tolerant")
	for _, want := range []string{
		"validateTunnelEndpointIDCollisionAST", "deferJunosHostWarnings",
		"appendUserspaceRxMTUAdvisoryLocked", "appendUserspaceMgmtZoneAdvisoryLocked",
	} {
		if !strings.Contains(tdoc, want) {
			t.Errorf("tolerant doc does not name governed site %s", want)
		}
	}
	// tolerant's governed set is exactly the four sites above: an
	// additional opts.tolerant read elsewhere would be claimed by no doc.
	tolerantReads := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if isOptsField17153(n, "tolerant") {
				tolerantReads++
			}
			return true
		})
	}
	// Reads: tunnel arg (compiler.go), `return opts.tolerant`
	// (compiler_tailgates.go), RX-MTU guard, mgmt-zone guard. The
	// composite literal in lenientCompileOpts is a key, not a read.
	if tolerantReads != 4 {
		t.Errorf("opts.tolerant is read at %d non-test sites, want exactly 4 (tunnel gate, deferJunosHostWarnings body, RX-MTU guard, mgmt-zone guard); an extra read is governed by no doc claim", tolerantReads)
	}
	// Contested/shared advisories must read their co-set suppressor,
	// not tolerant (the other half of the F1 doc fix).
	for name, f := range files {
		if name != "contested_trunk_zone_advisory_7509.go" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if isOptsField17153(n, "tolerant") {
				t.Errorf("%s reads opts.tolerant: contested/shared advisories keep suppressContestedTrunkZoneAdvisory", name)
			}
			return true
		})
	}
	// RX-MTU and mgmt advisories must read tolerant, not the contested suppressor.
	for name, f := range files {
		if name != "userspace_rx_mtu_advisory_9727.go" && name != "userspace_mgmt_zone_advisory_10308.go" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if isOptsField17153(n, "suppressContestedTrunkZoneAdvisory") {
				t.Errorf("%s still reads suppressContestedTrunkZoneAdvisory", name)
			}
			return true
		})
	}
	// suppressor doc must name its real advisories.
	sdoc := fieldDoc17153(t, files, "compileOpts", "suppressContestedTrunkZoneAdvisory")
	for _, want := range []string{"appendContestedTrunkZoneAdvisoryLocked", "appendSharedDeviceUnzonedUnitAdvisoryLocked"} {
		if !strings.Contains(sdoc, want) {
			t.Errorf("suppressContestedTrunkZoneAdvisory doc does not name %s", want)
		}
	}
}
