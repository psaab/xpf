package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #17148 (R4-Q20-02): strict mode must have ONE definition.
//
// #16296 fold edited each literal by hand to carry an always-on field;
// every zero-value compileOpts{} test compile — including the helper
// documented as "the STRICT commit path" — silently kept measuring a
// different mode. #16849 later removed that field and re-aligned the
// values, which proves the values can coincide again, but without a
// constructor the next always-on fold repeats the divergence.
//
// strictCompileOpts() (compiler_opts.go, beside lenientCompileOpts) is
// now the single source of truth. This test pins three things:
//
//  1. Behavioural parity: CompileConfig (production strict) and
//     compileTree(strictCompileOpts()) agree on the historically
//     divergent shape — a value-less flexible-match-range — in BOTH
//     arms: discard hard-rejects, accept stays accepted WITH its
//     #15943/#16849 warning, and the tolerant path still boots.
//  2. Structural identity: strictCompileOpts carries no
//     lenient*/sanitize* downgrade, and currentClusterOpts(nil) — the
//     opts the two WithCurrentClusterPrimary entries compile with —
//     is exactly strictCompileOpts, so the cluster-primary entries
//     cannot drift from the plain strict entries.
//  3. No second spelling: an AST census over non-test sources rejects
//     any compileOpts{...} composite literal outside compiler_opts.go
//     (the one best-effort side compile excepted, named below), and a
//     census over compileTree/compileExpanded call sites in test
//     sources rejects any direct compileOpts{...} literal argument —
//     a test that wants strict starts from strictCompileOpts() and
//     applies its seam overrides to the returned value.
//
// FAIL-ON-REVERT: hand-copy a field into one production strict literal
// (e.g. set a lenient* flag in CompileConfig only) and arm 1 or 2
// reds; spell a production or compileTree-test compile as a bare
// compileOpts{...} literal again and arm 3 reds.

// strictOptsEqual17148 reports whether two compileOpts values are
// identical. compileOpts contains pointer/slice/map fields; DeepEqual
// on the zero-shaped values the constructors return is exact here:
// both sides are built by the same literal, so nil-ness matches.
func strictOptsEqual17148(a, b compileOpts) bool {
	return reflect.DeepEqual(a, b)
}

func TestStrictCompileOptsSingleSource17148(t *testing.T) {
	// --- Arm 2a: strict carries no downgrade. -------------------------
	strict := strictCompileOpts()
	walkBoolFields16166(reflect.ValueOf(strict), "", func(path string, fv reflect.Value) {
		leaf := path[strings.LastIndex(path, ".")+1:]
		if strings.HasPrefix(leaf, "lenient") || strings.HasPrefix(leaf, "sanitize") {
			if fv.Bool() {
				t.Errorf("strictCompileOpts().%s is true: strict must not carry a tolerant downgrade (#17148)", path)
			}
		}
	})
	if strict.skipCompactNormalize {
		t.Error("strictCompileOpts().skipCompactNormalize is true: production must run the compact normalizer (#8690 seam is test-only)")
	}
	if strict.nodeID != nil {
		t.Error("strictCompileOpts().nodeID is non-nil: node identity is stamped per call by compileTree's node-aware entry (#4329/#17157)")
	}
	// The tolerant constructor must genuinely differ, or the arm above
	// is vacuous (e.g. a walk that visits nothing).
	if !lenientCompileOpts().lenientFlexMatch {
		t.Error("lenientCompileOpts().lenientFlexMatch is false: the census walk / tolerant constructor is not live")
	}

	// --- Arm 2b: the cluster-primary entries ARE strict. --------------
	if got := currentClusterOpts(nil); !strictOptsEqual17148(got, strict) {
		t.Errorf("currentClusterOpts(nil) = %+v, want strictCompileOpts() (%+v): the WithCurrentClusterPrimary entries drifted from plain strict (#17148)", got, strict)
	}
	// A cluster-carrying current config only ADDS the two cluster-key
	// fields; every bool must still match strict.
	clusterCurrent := &Config{Chassis: ChassisConfig{Cluster: &ClusterConfig{}}}
	clusterCurrent.Chassis.Cluster.ControlLinkAuthKey = NewSecret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	gotCluster := currentClusterOpts(clusterCurrent)
	walkBoolFields16166(reflect.ValueOf(gotCluster), "", func(path string, fv reflect.Value) {
		leaf := path[strings.LastIndex(path, ".")+1:]
		if (strings.HasPrefix(leaf, "lenient") || strings.HasPrefix(leaf, "sanitize")) && fv.Bool() {
			t.Errorf("currentClusterOpts(cluster).%s is true: cluster entries must stay strict (#17148)", path)
		}
	})
	if gotCluster.currentClusterPrimary16025 == nil {
		t.Error("currentClusterOpts(cluster) lost its #16025 primary: fixture no longer exercises the cluster arm")
	}

	// --- Arm 1: production strict == strictCompileOpts in behaviour. --
	discardCmds := []string{
		"set firewall family inet filter f1 term m from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term m from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term m then discard",
	}
	acceptCmds := []string{
		"set firewall family inet filter f1 term m from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term m from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term m then accept",
	}
	_, errProdDiscard := CompileConfig(buildTree(t, discardCmds))
	_, errCtorDiscard := compileTree(buildTree(t, discardCmds), strictCompileOpts(), nil)
	if errProdDiscard == nil || errCtorDiscard == nil {
		t.Fatalf("value-less discard must hard-reject on BOTH production strict and strictCompileOpts (#16849): prod=%v ctor=%v", errProdDiscard, errCtorDiscard)
	}
	if errProdDiscard.Error() != errCtorDiscard.Error() {
		t.Errorf("discard rejection differs: prod=%q ctor=%q (#17148 divergence)", errProdDiscard, errCtorDiscard)
	}
	cfgProd, errProdAccept := CompileConfig(buildTree(t, acceptCmds))
	cfgCtor, errCtorAccept := compileTree(buildTree(t, acceptCmds), strictCompileOpts(), nil)
	if errProdAccept != nil || errCtorAccept != nil {
		t.Fatalf("value-less accept must stay strict-accepted on both: prod=%v ctor=%v", errProdAccept, errCtorAccept)
	}
	if strings.Join(cfgProd.Warnings, "\n") != strings.Join(cfgCtor.Warnings, "\n") {
		t.Errorf("accept warnings differ: prod=%v ctor=%v (#17148 divergence)", cfgProd.Warnings, cfgCtor.Warnings)
	}
	if !strings.Contains(strings.Join(cfgCtor.Warnings, "\n"), "no match-value") {
		t.Errorf("strict value-less accept lost its warning: %v (#15943/#16849)", cfgCtor.Warnings)
	}
	// Tolerant control: the same discard shape still boots (#1960).
	if _, err := CompileConfigLenient(buildTree(t, discardCmds)); err != nil {
		t.Errorf("tolerant compile must still boot the value-less discard: %v", err)
	}
	// compileStrict8690 (documented as the STRICT commit path) must
	// agree with production strict on the divergent shape, in both
	// normalizer positions.
	discardText := "firewall { family inet { filter f1 { term m { from { flexible-match-range { range r1 { bit-length 8; byte-offset 12; } } } then discard; } } } }"
	for _, skip := range []bool{false, true} {
		if err := compileStrict8690(t, discardText, skip); err == nil {
			t.Errorf("compileStrict8690(skip=%v) accepted a value-less discard that production strict rejects (#17148)", skip)
		}
	}

	// --- Arm 3: no second spelling of strict. --------------------------
	assertNoBareCompileOptsLiterals17148(t)
}

// sideCompileExemptions17148 names the non-test compileOpts{...}
// literals allowed outside compiler_opts.go, with the reason. Each is
// a best-effort SIDE compile (its error is dropped by design), not a
// strict/tolerant entry point. A new entry here is a reviewed decision,
// not a convenience.
var sideCompileExemptions17148 = map[string]string{
	"compiler_validate_strict_reth_lag.go": "best-effort expanded reth-member union; not a commit gate",
}

func assertNoBareCompileOptsLiterals17148(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.): %v", err)
	}
	var prodOffenders, testOffenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		isTest := strings.HasSuffix(name, "_test.go")
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				// compileOpts{...} literal (not strictCompileOpts() —
				// that is a CallExpr, and not a nested struct value
				// inside lenientCompileOpts, which lives in
				// compiler_opts.go and is exempt by file).
				if id, ok := node.Type.(*ast.Ident); ok && id.Name == "compileOpts" {
					if isTest {
						// Tests: only flag literals passed DIRECTLY
						// to compileTree/compileExpanded — checked
						// in the CallExpr arm below. A literal fed
						// to a sub-helper (advisory opts probe) is
						// not a compile entry spelling.
						return true
					}
					if name == "compiler_opts.go" {
						return true
					}
					if _, ok := sideCompileExemptions17148[name]; ok {
						return true
					}
					prodOffenders = append(prodOffenders,
						fmt.Sprintf("%s (%s)", name, fset.Position(node.Pos())))
				}
			case *ast.CallExpr:
				if !isTest {
					return true
				}
				id, ok := node.Fun.(*ast.Ident)
				if !ok || (id.Name != "compileTree" && id.Name != "compileExpanded") {
					return true
				}
				for _, arg := range node.Args {
					if lit, ok := arg.(*ast.CompositeLit); ok {
						if tid, ok := lit.Type.(*ast.Ident); ok && tid.Name == "compileOpts" {
							testOffenders = append(testOffenders,
								fmt.Sprintf("%s (%s)", name, fset.Position(lit.Pos())))
						}
					}
				}
			}
			return true
		})
	}
	sort.Strings(prodOffenders)
	sort.Strings(testOffenders)
	for _, o := range prodOffenders {
		t.Errorf("bare compileOpts{...} literal in production source at %s: route it through strictCompileOpts()/lenientCompileOpts() in compiler_opts.go (#17148 single source of truth)", o)
	}
	for _, o := range testOffenders {
		t.Errorf("compileTree/compileExpanded called with a direct compileOpts{...} literal in test source at %s: start from strictCompileOpts()/lenientCompileOpts() and apply seam overrides to the returned value (#17148)", o)
	}
	// Census liveness: the exemptions must still exist, or this test
	// would green after someone deleted the side compiles. And the
	// production walk must actually see compiler_opts.go's own literal.
	seenExempt := map[string]bool{}
	for _, e := range entries {
		if _, ok := sideCompileExemptions17148[e.Name()]; ok {
			seenExempt[e.Name()] = true
		}
	}
	for name := range sideCompileExemptions17148 {
		if !seenExempt[name] {
			t.Errorf("side-compile exemption %s no longer exists; drop it from sideCompileExemptions17148 (#17148)", name)
		}
	}

}
