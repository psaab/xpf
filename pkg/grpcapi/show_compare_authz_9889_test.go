package grpcapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9889: ShowCompare is priced PermView and diffs against the CANDIDATE on BOTH
// arms, so a view-only caller reads another session's uncommitted configuration.
//
// rollback_n == 0 renders active-vs-candidate (ShowCompareRedacted,
// store_format.go) and rollback_n > 0 renders rollback-slot-vs-candidate
// (ShowCompareRollbackRedacted) — the report's acceptance criterion priced only
// the first arm, but the second arm's own doc says it diffs "between rollback
// slot n and the candidate". The fix prices the WHOLE RPC at PermConfig via
// configTargetReadPermission, mirroring the REST twin, which #9324 priced the
// same way (candidateConfigReadPermission prices GET /api/v1/config/compare,
// both branches, at PermConfig while the route table still lists PermView).
//
// The last test in this file rewrites the completeness census the issue calls
// vacuous: TestEveryServiceMethodHasAPermission_5278 proves every method HAS a
// price, not that every candidate read is priced. The 9889 census enumerates
// candidate-READING RPCs from handler behaviour — which store methods touch
// the candidate field to render display output or derive diagnostics, and
// which served handlers reach them — and asserts each costs configure.

const (
	authzUIDReadOnly9889      = 4251
	authzUIDConfigure9889     = 4252
	authzUIDConfigureOnly9889 = 4253
)

// compareCanary9889 is staged in the candidate and never committed. Any RPC
// output containing it rendered another session's work-in-progress.
const compareCanary9889 = "uncommitted-canary-9889"

// authzConfig9889 is the active config the 9889 cases are evaluated against: a
// read-only user, a user in a custom class holding EXACTLY view+configure, and
// a user in a class holding configure WITHOUT view. The view+configure class
// (rather than super-user) proves the price is PermConfig and not PermAll — a
// fix typed at the super-user floor would fail the served cells below. The
// configure-only class pins the ADDITIVE shape of the gRPC price: the method
// table still requires PermView and the candidate gate additionally requires
// PermConfig, so a class holding only one half is denied.
const authzConfig9889 = `
system {
    host-name showcompare-9889-test;
    login {
        class configurator {
            permissions [ view configure ];
        }
        class configureonly {
            permissions [ configure ];
        }
        user rouser {
            class read-only;
        }
        user cfguser {
            class configurator;
        }
        user couser {
            class configureonly;
        }
    }
}
`

const authzPasswd9889 = `root:x:0:0:root:/root:/bin/bash
rouser:x:4251:4251::/home/rouser:/bin/bash
cfguser:x:4252:4252::/home/cfguser:/bin/bash
couser:x:4253:4253::/home/couser:/bin/bash
`

func usePasswdFixture9889(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(authzPasswd9889), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// compareAuthzStore9889 returns a store whose ACTIVE config carries the 9889
// login model, with rollback slot 1 populated by a seed commit and the canary
// staged in the candidate WITHOUT committing — the exact state in which
// ShowCompare discloses another session's work-in-progress.
func compareAuthzStore9889(t *testing.T) *configstore.Store {
	t.Helper()
	store := authzStore5278(t, authzConfig9889)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set system host-name rollback-seed-9889"); err != nil {
		t.Fatalf("LoadSet seed: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit seed: %v", err)
	}
	// Commit leaves the session in configure mode with a fresh candidate, so
	// the canary stages directly onto it and is never committed.
	if _, err := store.LoadSet("set system host-name " + compareCanary9889); err != nil {
		t.Fatalf("LoadSet canary: %v", err)
	}
	return store
}

// TestReadOnlyDeniedShowCompareBothArms_9889 is the end-to-end leak cell: with
// a staged candidate present, a view-only principal is denied on BOTH arms of
// ShowCompare through the production listener and interceptor chain. One
// subtest per arm: assertDenied is fatal, so a flat sequence would report only
// the first arm on revert and leave the second arm's RED unobserved.
//
// RED-on-revert: without the gate extension both calls succeed and return the
// staged canary, failing both subtests.
func TestReadOnlyDeniedShowCompareBothArms_9889(t *testing.T) {
	usePasswdFixture9889(t)
	client := runPrimaryListener(t, Config{
		Store:        compareAuthzStore9889(t),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly9889),
	})
	ctx := callCtx(t)

	for _, n := range []int32{0, 1} {
		t.Run(fmt.Sprintf("rollback_n=%d", n), func(t *testing.T) {
			resp, err := client.ShowCompare(ctx, &pb.ShowCompareRequest{RollbackN: n})
			assertDenied(t, fmt.Sprintf("ShowCompare{rollback_n:%d}", n), err)
			// The denial must carry no output: PermissionDenied with an empty
			// body is what closes the exfiltration loop, not the status alone.
			if resp.GetOutput() != "" {
				t.Errorf("denied ShowCompare{rollback_n:%d} returned output %q; "+
					"a refusal that still renders the candidate is the leak",
					n, resp.GetOutput())
			}
		})
	}
}

// TestConfigureClassServedShowCompareBothArms_9889 is the negative control:
// the fix must not cost a legitimate configure-class principal anything. The
// principal holds exactly view+configure, and each response must CONTAIN the
// canary — proving the admitted call reached the handler and rendered the
// candidate, not merely avoided a denial.
func TestConfigureClassServedShowCompareBothArms_9889(t *testing.T) {
	usePasswdFixture9889(t)
	client := runPrimaryListener(t, Config{
		Store:        compareAuthzStore9889(t),
		PeerLookupFn: fixedPeerUID5278(authzUIDConfigure9889),
	})
	ctx := callCtx(t)

	resp, err := client.ShowCompare(ctx, &pb.ShowCompareRequest{RollbackN: 0})
	assertNotDenied(t, "ShowCompare{rollback_n:0}", err)
	if err != nil {
		t.Fatalf("ShowCompare{rollback_n:0}: %v", err)
	}
	if !strings.Contains(resp.GetOutput(), compareCanary9889) {
		t.Errorf("rollback_n=0 output does not contain the staged canary; the "+
			"admitted call did not render the candidate: %q", resp.GetOutput())
	}

	resp, err = client.ShowCompare(ctx, &pb.ShowCompareRequest{RollbackN: 1})
	assertNotDenied(t, "ShowCompare{rollback_n:1}", err)
	if err != nil {
		t.Fatalf("ShowCompare{rollback_n:1}: %v", err)
	}
	if !strings.Contains(resp.GetOutput(), compareCanary9889) {
		t.Errorf("rollback_n=1 output does not contain the staged canary; the "+
			"admitted call did not render the candidate: %q", resp.GetOutput())
	}
}

// TestShowCompareCandidateReadCostsConfigure_9889 pins the gate price on both
// arms. Unlike ShowConfig there is no ACTIVE arm — no selector makes the
// answer right for a view-only caller — so the price is unconditional.
func TestShowCompareCandidateReadCostsConfigure_9889(t *testing.T) {
	method := "/" + serviceName + "/ShowCompare"

	got, ok := configTargetReadPermission(method, &pb.ShowCompareRequest{RollbackN: 0})
	if !ok || got != config.PermConfig {
		t.Fatalf("rollback_n=0 -> (%v, %v), want (PermConfig, true)", got, ok)
	}

	got, ok = configTargetReadPermission(method, &pb.ShowCompareRequest{RollbackN: 1})
	if !ok || got != config.PermConfig {
		t.Fatalf("rollback_n=1 -> (%v, %v), want (PermConfig, true)", got, ok)
	}

	if _, ok := configTargetReadPermission("/some.other.Service/ShowCompare", &pb.ShowCompareRequest{}); ok {
		t.Error("a foreign service's ShowCompare was priced as a config-target read")
	}
}

// TestUnreadableShowCompareRequestFailsClosed_9889 pins that the price does not
// depend on decoding the request at all: garbage on this method is refused at
// the stricter price rather than admitted at the looser one.
func TestUnreadableShowCompareRequestFailsClosed_9889(t *testing.T) {
	got, ok := configTargetReadPermission("/"+serviceName+"/ShowCompare", struct{}{})
	if !ok || got != config.PermConfig {
		t.Fatalf("an unreadable ShowCompare request -> (%v, %v), want (PermConfig, true)", got, ok)
	}
}

// TestShowComparePriceIsViewAndConfigure_9889 pins the ADDITIVE shape of the
// gRPC price, at the gate (no handler runs, so no fixture state is disturbed).
// authorizeRPC charges the table's PermView FIRST and the candidate gate's
// PermConfig SECOND, and the two permissions are independent bits — so a class
// holding only one half is denied. (REST instead REPLACES the route price with
// PermConfig, so a configure-only caller is admitted there; the #9324
// ShowConfig gate has this same additive shape on gRPC, and ShowCompare
// inherits it.)
func TestShowComparePriceIsViewAndConfigure_9889(t *testing.T) {
	usePasswdFixture9889(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig9889)})
	compare := "/" + serviceName + "/ShowCompare"

	// Configure WITHOUT view: denied on both arms — the coarse view gate
	// fires before the candidate gate is ever consulted.
	for _, n := range []int32{0, 1} {
		if err := s.authorizeRPC(ctxWithPeerUID(authzUIDConfigureOnly9889), compare, &pb.ShowCompareRequest{RollbackN: n}); err == nil {
			t.Errorf("configure-only ShowCompare{rollback_n:%d} was admitted at the gate; the gRPC price is view AND configure", n)
		}
	}

	// The same principal passes a pure-configure gate, proving the denial
	// above is the VIEW half of the additive price and not a broken class.
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDConfigureOnly9889), "/"+serviceName+"/EnterConfigure", &pb.EnterConfigureRequest{}); err != nil {
		t.Errorf("configure-only EnterConfigure denied at the gate: %v — the fixture class does not hold configure", err)
	}

	// View AND configure: admitted on both arms.
	for _, n := range []int32{0, 1} {
		if err := s.authorizeRPC(ctxWithPeerUID(authzUIDConfigure9889), compare, &pb.ShowCompareRequest{RollbackN: n}); err != nil {
			t.Errorf("view+configure ShowCompare{rollback_n:%d} denied at the gate: %v", n, err)
		}
	}
}

// candidateReadProbe9889 maps each RPC the census may find at a below-configure
// table price to the requests that prove the candidate-read gate covers it.
// The requests are the candidate-READING ones: an omitted ConfigTarget (proto3
// zero IS candidate, pinned by TestConfigTargetProto3ZeroIsStillCandidate9324)
// and an explicit CANDIDATE for ShowConfig; both rollback arms for ShowCompare
// (rollback_n=0 IS the candidate arm, pinned by
// TestShowCompareZeroRollbackComparesCandidate).
//
// A NEW candidate-reading RPC priced below PermConfig fails the census until
// its author extends the gate AND this map — that forcing function is the
// point: the price table alone cannot express "this RPC reads the candidate".
type gateProbe9889 struct {
	desc string
	req  any
}

var candidateReadProbe9889 = map[string][]gateProbe9889{
	"ShowConfig": {
		{"omitted target", &pb.ShowConfigRequest{}},
		{"explicit CANDIDATE", &pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE}},
	},
	"ShowCompare": {
		{"rollback_n=0", &pb.ShowCompareRequest{RollbackN: 0}},
		{"rollback_n=1", &pb.ShowCompareRequest{RollbackN: 1}},
	},
}

// TestCandidateReadingRPCsCostConfigure_9889 is the census #9889 demands:
// every RPC whose handler reads CANDIDATE content must cost configure,
// enumerated from handler behaviour rather than from the price table.
//
// Hop 0 (configstore): a candidate-content source is a *Store method that
// references the candidate FIELD and either redacts for display (forDisplay),
// belongs to the Show render family, or COMPILES the candidate (a compiled
// config — and the commit-check error/warning text derived from it — carries
// candidate identifiers, so diagnostic readers are candidate readers too).
// Hop 1 (grpcapi): a candidate-reading RPC is a served method whose handler
// reaches a source through same-package calls, transitively.
// Hop 2 (price): each such RPC costs PermConfig (or PermAll) in the method
// table, or the candidate-read gate prices every probe request at PermConfig.
//
// Deliberately OUT of the property, by construction: config MUTATIONS that
// touch the candidate without deriving a readable value (Set/Delete/Load —
// table-PermConfig anyway), CommitDiffSummary (candidate-derived COUNTS, no
// content, via a PermConfig RPC), and metadata (dirty flags). The property is
// disclosure of another session's uncommitted configuration — display or
// diagnostic — to a viewer: the #9324/#9889 shape.
// Documented boundary: the daemon commit closures. The commit implementations
// (commitWithDescriptionLocked/commitConfirmedLocked) enumerate in hop 0 (they
// compile the candidate) but hop 1 cannot reach them: the handlers invoke
// cross-package daemon closures through the s.commitFn / s.commitConfirmedFn
// func-field seams, which a same-package walk cannot follow. Both RPCs are
// table-PermConfig, pinned explicitly below so the seam never silently drops
// below configure. Every OTHER call shape is proven visible by
// TestEveryRendererCallIsCensusVisible_9889, which fails on any source reached
// through a parameter, a package-level store, or a captured method value
// instead of an s.store (or alias) call in a *Server method.
//
// RED-on-revert: dropping the ShowCompare gate case prices it PermView with no
// gate coverage, failing hop 2 with the sources named.
func TestCandidateReadingRPCsCostConfigure_9889(t *testing.T) {
	renderers := candidateReadingStoreMethods9889(t)
	rpcs := candidateReadingRPCs9889(t, renderers)

	// Guard the guard: the census must SEE the known members. If a
	// refactor moves the store calls behind a shape the walk does not follow,
	// this fails LOUDLY instead of certifying a shrunken set.
	for _, want := range []string{"ShowConfig", "ShowCompare", "CommitCheck"} {
		if _, ok := rpcs[want]; !ok {
			t.Fatalf("census enumerated %v — %s, a known candidate-reading "+
				"RPC, is missing: the enumeration rotted", sortedKeys9889(rpcs), want)
		}
	}
	for _, name := range sortedKeys9889(rpcs) {
		via := rpcs[name]
		if perm, priced := methodPermissions[name]; priced &&
			(perm == config.PermConfig || perm == config.PermAll) {
			continue
		}
		probes, ok := candidateReadProbe9889[name]
		if !ok || len(probes) == 0 {
			t.Errorf("RPC %s reads candidate content (via store.%s) but is "+
				"priced %s with no candidate-read gate probe — price it at "+
				"PermConfig, or extend configTargetReadPermission and "+
				"candidateReadProbe9889", name, strings.Join(via, ", "),
				permName(methodPermissions[name]))
			continue
		}
		for _, probe := range probes {
			got, covered := configTargetReadPermission("/"+serviceName+"/"+name, probe.req)
			if !covered || got != config.PermConfig {
				t.Errorf("RPC %s reads candidate content (via store.%s) but "+
					"its gate probe %q -> (%v, %v), want (PermConfig, true)",
					name, strings.Join(via, ", "), probe.desc, got, covered)
			}
		}
	}

	// Seam belt-and-braces (see the boundary note above): the commit RPCs
	// reach candidate-compiling store methods through the daemon func-field
	// seams, invisible to hop 1. Their table price is the entire coverage,
	// so pin it here rather than trust a table row nobody reads.
	for _, name := range []string{"Commit", "CommitConfirmed"} {
		if perm := methodPermissions[name]; perm != config.PermConfig && perm != config.PermAll {
			t.Errorf("RPC %s compiles the candidate through a daemon seam and "+
				"is priced %s — it must cost PermConfig or more",
				name, permName(perm))
		}
	}
}

// candidateReadingStoreMethods9889 is hop 0: the names of the *Store methods
// in ../configstore that disclose candidate CONTENT — they reference the
// candidate field on the receiver and either redact for display, belong to the
// Show render family, or COMPILE the candidate (a compiled config — and the
// commit-check error/warning text derived from it — carries candidate
// identifiers, so diagnostic readers are candidate readers too).
func candidateReadingStoreMethods9889(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "configstore", "*.go"))
	if err != nil {
		t.Fatalf("glob configstore: %v", err)
	}
	out := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			recv, ok := receiverNamed9889(fn.Recv, "Store")
			if !ok {
				continue
			}
			touchesCandidate := false
			callsForDisplay := false
			compilesCandidate := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.SelectorExpr:
					// The candidate FIELD, not any .candidate: the base must
					// be the receiver.
					if e.Sel.Name == "candidate" {
						if id, ok := e.X.(*ast.Ident); ok && id.Name == recv {
							touchesCandidate = true
						}
					}
				case *ast.CallExpr:
					if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "forDisplay" {
						callsForDisplay = true
					}
					// s.compileTree(s.candidate) and its lenient/strict
					// siblings: compiling the candidate derives a
					// candidate-content value (or identifier-carrying
					// diagnostics). The argument MUST be the candidate field
					// — compiling any other tree (a peer push, rescue text)
					// is not a candidate read.
					if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
						if base, ok := sel.X.(*ast.Ident); ok && base.Name == recv &&
							(sel.Sel.Name == "compileTree" || sel.Sel.Name == "compileTreeLenient" || sel.Sel.Name == "compileTreeStrict") {
							for _, arg := range e.Args {
								if isCandidateField9889(arg, recv) {
									compilesCandidate = true
								}
							}
						}
					}
				}
				return true
			})
			if touchesCandidate && (callsForDisplay || compilesCandidate || strings.HasPrefix(fn.Name.Name, "Show")) {
				out[fn.Name.Name] = true
			}
		}
	}
	// Guard the guard: one member per RPC arm family, plus the diagnostic and
	// accessor families. If the predicates stop matching the code they were
	// written against, this fails instead of certifying a shrunken renderer
	// set (which would make hop 1 vacuous for the missing family).
	for _, want := range []string{
		"ShowCandidateRedacted",
		"ShowCompareRedacted",
		"ShowCompareRollbackRedacted",
		"CommitCheck",
		"CompileCandidate",
	} {
		if !out[want] {
			t.Fatalf("renderer enumeration found %v — %s is missing: the "+
				"hop-0 predicates rotted", sortedKeys9889(storeSetKeys9889(out)), want)
		}
	}
	return out
}

func sortedKeys9889(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func storeSetKeys9889(set map[string]bool) map[string][]string {
	m := make(map[string][]string, len(set))
	for k := range set {
		m[k] = nil
	}
	return m
}

// receiverNamed9889 reports whether recv declares a method on the named type
// (pointer or value receiver) and returns the receiver identifier.
func receiverNamed9889(recv *ast.FieldList, want string) (string, bool) {
	if recv == nil || len(recv.List) != 1 {
		return "", false
	}
	name := ""
	if len(recv.List[0].Names) == 1 {
		name = recv.List[0].Names[0].Name
	}
	switch typ := recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := typ.X.(*ast.Ident); ok && id.Name == want {
			return name, true
		}
	case *ast.Ident:
		if typ.Name == want {
			return name, true
		}
	}
	return "", false
}

// isCandidateField9889 reports whether e is the candidate field on the
// receiver (recv.candidate).
func isCandidateField9889(e ast.Expr, recv string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "candidate" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == recv
}

// TestEveryRendererCallIsCensusVisible_9889 proves hop 1 sees every candidate
// read in production code. Hop 1 matches a renderer call ONLY inside a *Server
// method with an s.store (or alias) base, so any OTHER shape — a store (or
// server) received as a parameter, a package-level store, a renderer method
// VALUE captured instead of called — would be a read the census certifies
// without seeing. This test fails on exactly those shapes: every mention of an
// enumerated source in call or value position must resolve through hop 1's own
// rule, or the census is blind and must learn the shape first.
func TestEveryRendererCallIsCensusVisible_9889(t *testing.T) {
	renderers := candidateReadingStoreMethods9889(t)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob grpcapi: %v", err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			recv, onServer := receiverNamed9889(fn.Recv, "Server")
			var aliases map[string]bool
			if onServer {
				aliases = storeAliases9889(&grpcapiFunc9889{body: fn.Body, recvName: recv, onServer: true})
			}
			// Pass 1: the callee positions — a renderer named as a call's
			// function is judged by its base; anything else is a method
			// value escaping call-shape analysis.
			callees := map[*ast.SelectorExpr]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && renderers[sel.Sel.Name] {
						callees[sel] = true
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !renderers[sel.Sel.Name] {
					return true
				}
				if !callees[sel] {
					t.Errorf("%s: %s captures store.%s as a VALUE rather than calling it — hop 1 cannot follow method values; call it through s.store or teach the census the shape",
						path, fn.Name.Name, sel.Sel.Name)
					return true
				}
				if !onServer || !isStoreBase9889(sel.X, recv, aliases) {
					t.Errorf("%s: %s calls store.%s through a base hop 1 cannot see (not s.store or an alias in a *Server method) — the read is invisible to the census; route it through s.store or teach the census the shape",
						path, fn.Name.Name, sel.Sel.Name)
				}
				return true
			})
		}
	}
}

// grpcapiFunc9889 is one parsed production function in this package.
type grpcapiFunc9889 struct {
	body     *ast.BlockStmt
	recvName string // receiver identifier; "" for a plain function
	onServer bool   // method on *Server (or Server)
}

// candidateReadingRPCs9889 is hop 1: every served RPC whose handler reaches a
// candidate renderer, mapped to the sorted renderer names it reaches. Reach is
// transitive over same-package calls: s.helper() on the receiver, bare
// helper() calls, and `st := s.store` aliases followed to st.Renderer().
func candidateReadingRPCs9889(t *testing.T, renderers map[string]bool) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob grpcapi: %v", err)
	}
	funcs := map[string]*grpcapiFunc9889{}
	key := func(onServer bool, name string) string {
		if onServer {
			return "Server." + name
		}
		return name
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if fn.Recv == nil {
				funcs[key(false, fn.Name.Name)] = &grpcapiFunc9889{body: fn.Body}
				continue
			}
			if recv, ok := receiverNamed9889(fn.Recv, "Server"); ok {
				funcs[key(true, fn.Name.Name)] = &grpcapiFunc9889{
					body:     fn.Body,
					recvName: recv,
					onServer: true,
				}
			}
		}
	}

	// reaches memoizes the transitive renderer set per function. visiting
	// guards cycles (a recursive helper reaches what its body reaches).
	memo := map[string]map[string]bool{}
	var reaches func(k string, visiting map[string]bool) map[string]bool
	reaches = func(k string, visiting map[string]bool) map[string]bool {
		if done, ok := memo[k]; ok {
			return done
		}
		if visiting[k] {
			return map[string]bool{}
		}
		fn, ok := funcs[k]
		if !ok {
			return map[string]bool{}
		}
		visiting[k] = true
		found := map[string]bool{}
		aliases := storeAliases9889(fn)
		ast.Inspect(fn.body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				// s.store.Renderer() or alias.Renderer().
				if renderers[fun.Sel.Name] && isStoreBase9889(fun.X, fn.recvName, aliases) {
					found[fun.Sel.Name] = true
					return true
				}
				// s.helper(): a method call on the receiver stays
				// in-package on *Server.
				if id, ok := fun.X.(*ast.Ident); ok && fn.onServer && id.Name == fn.recvName {
					for r := range reaches(key(true, fun.Sel.Name), visiting) {
						found[r] = true
					}
				}
			case *ast.Ident:
				// helper(): a plain same-package call. Builtins and
				// qualified calls never resolve here, so a miss is just
				// "not ours" rather than an error.
				for r := range reaches(key(false, fun.Name), visiting) {
					found[r] = true
				}
			}
			return true
		})
		delete(visiting, k)
		memo[k] = found
		return found
	}

	out := map[string][]string{}
	for _, name := range serviceMethodNames(t) {
		reached := reaches(key(true, name), map[string]bool{})
		if len(reached) == 0 {
			continue
		}
		via := make([]string, 0, len(reached))
		for r := range reached {
			via = append(via, r)
		}
		sort.Strings(via)
		out[name] = via
	}
	return out
}

// storeAliases9889 collects the local identifiers assigned s.store within fn,
// so alias.Renderer() calls resolve to the store.
func storeAliases9889(fn *grpcapiFunc9889) map[string]bool {
	aliases := map[string]bool{}
	if fn.recvName == "" {
		return aliases
	}
	ast.Inspect(fn.body, func(n ast.Node) bool {
		assigns := func(lhs []ast.Expr, rhs []ast.Expr) {
			if len(lhs) != 1 || len(rhs) != 1 {
				return
			}
			id, ok := lhs[0].(*ast.Ident)
			if !ok || id.Name == "_" || id.Name == fn.recvName {
				return
			}
			if isStoreBase9889(rhs[0], fn.recvName, nil) {
				aliases[id.Name] = true
			}
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			assigns(stmt.Lhs, stmt.Rhs)
		case *ast.ValueSpec:
			if len(stmt.Names) == 1 && len(stmt.Values) == 1 {
				assigns([]ast.Expr{stmt.Names[0]}, stmt.Values)
			}
		}
		return true
	})
	return aliases
}

// isStoreBase9889 reports whether e is s.store (or one of its local aliases).
func isStoreBase9889(e ast.Expr, recv string, aliases map[string]bool) bool {
	switch base := e.(type) {
	case *ast.SelectorExpr:
		// s.store
		if base.Sel.Name != "store" || recv == "" {
			return false
		}
		id, ok := base.X.(*ast.Ident)
		return ok && id.Name == recv
	case *ast.Ident:
		return aliases[base.Name]
	}
	return false
}
