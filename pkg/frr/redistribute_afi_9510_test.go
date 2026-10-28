package frr

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9510: a source outside the enclosing router's address family must not
// render, because FRR rejects the line at parse and one rejected line fails the
// whole managed reload. The controls in the same table are what make the drops
// meaningful: a filter that dropped everything would pass the drop rows alone.
func TestResolveRedistributeBareTokenAddressFamily_9510(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		self, export, want string
	}{
		// FRR's per-daemon grammar does not list these sources.
		{"ospf", "ospf6", ""},
		{"ospf", "ripng", ""},
		{"ospf6", "ospf", ""},
		{"ospf6", "rip", ""},
		{"rip", "ospf6", ""},
		{"rip", "ripng", ""},
		// BGP_NODE carries only the IPv4 grammar (FRR_IP_REDIST_STR_BGPD).
		{"bgp", "ospf6", ""},
		{"bgp", "ripng", ""},
		// Controls: same routers, sources their grammar does list.
		{"ospf", "static", " redistribute static\n"},
		{"ospf", "rip", " redistribute rip\n"},
		{"ospf", "direct", " redistribute connected\n"},
		{"ospf6", "static", " redistribute static\n"},
		{"ospf6", "ripng", " redistribute ripng\n"},
		{"ospf6", "bgp", " redistribute bgp\n"},
		{"rip", "ospf", " redistribute ospf\n"},
		{"bgp", "ospf", " redistribute ospf\n"},
		{"bgp", "kernel", " redistribute kernel\n"},
	} {
		if got := m.resolveRedistribute(tc.export, nil, tc.self, nil); got != tc.want {
			t.Errorf("export %q under router %s: got %q, want %q", tc.export, tc.self, got, tc.want)
		}
	}
}

// The policy path filters per TERM at the use site. One policy carries
// sources from both families. Each router keeps the ones its grammar lists,
// which is the property a commit-time reject of the policy would have broken.
func TestResolveRedistributePolicyTermAddressFamily_9510(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"mixed": {Name: "mixed", Terms: []*config.PolicyTerm{
				{Name: "v6igp", FromProtocols: []string{"ospf6"}, Action: "accept"},
				{Name: "v6rip", FromProtocols: []string{"ripng"}, Action: "accept"},
				{Name: "v4rip", FromProtocols: []string{"rip"}, Action: "accept"},
				{Name: "both", FromProtocols: []string{"static"}, Action: "accept"},
			}},
			"v6only": {Name: "v6only", Terms: []*config.PolicyTerm{
				{Name: "t", FromProtocols: []string{"ripng"}, Action: "accept"},
			}},
		},
	}
	for _, tc := range []struct {
		policy, self, want string
	}{
		{"mixed", "ospf", " redistribute rip route-map mixed-rip-xpf-redist-ospf\n redistribute static route-map mixed-static-xpf-redist-ospf\n"},
		{"mixed", "ospf6", " redistribute ripng route-map mixed-ripng-xpf-redist-ospf6\n redistribute static route-map mixed-static-xpf-redist-ospf6\n"},
		{"mixed", "rip", " redistribute static route-map mixed-static-xpf-redist-rip\n"},
		// Control: no enclosing router, so nothing is filtered.
		{"mixed", "", " redistribute ospf6 route-map mixed-ospf6-xpf-redist\n redistribute rip route-map mixed-rip-xpf-redist\n" +
			" redistribute ripng route-map mixed-ripng-xpf-redist\n redistribute static route-map mixed-static-xpf-redist\n"},
		// Every term filtered: nothing renders.
		{"v6only", "ospf", ""},
		{"v6only", "rip", ""},
		// Control for the rows above: the same policy under a router whose
		// grammar lists the source. (No row pins a `router isis` literal: the
		// plain form is not IS-IS grammar at all: #9666.)
		{"v6only", "ospf6", " redistribute ripng route-map v6only-ripng-xpf-redist-ospf6\n"},
	} {
		if got := m.resolveRedistribute(tc.policy, po, tc.self, nil); got != tc.want {
			t.Errorf("policy %q under router %q: got %q, want %q", tc.policy, tc.self, got, tc.want)
		}
	}
}

// The filter passes a router it has no row for. So every call site's self
// must have a row, and no call site may pass a non-literal self that this
// scan would skip. #17032: the census keys on the AFI type, not on wrapper
// spelling. go/ast finds every call to a method whose parameter list
// carries the redistribution self, regardless of whether the method is a
// legacy wrapper (resolveRedistribute), a Cluster15158 production form,
// or a terminal sink (redistributeEntriesAt) — the shapes the old regex
// census keyed on literals and therefore could not see (an AFI-less
// router added through resolveRedistributeCluster15158 or
// redistributeEntriesAt stayed GREEN). A call is classified by the self
// argument AT ITS DECLARED POSITION: a string literal is read directly;
// an identifier must be the self parameter of its enclosing censused
// definition, which is itself proven (in that definition's body) to
// forward that parameter, or a pinned literal, into a censused callee.
// Any other shape — unknown identifier, composite expression, missing
// self argument, an enclosing definition outside the censused set —
// fails closed. Completeness is pinned by counting the self-carrying
// callee definitions themselves: adding a new wrapper or sink whose
// signature carries a redistribution self changes the pin and fails
// here until the callee set is extended.
func TestRedistNodeAFICoversEveryCallSite_9510(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// selfPos[callee] is the parameter index of the redistribution self,
	// or -1 for the ISIS/BGP-IPv6 forms whose self is a hard-coded
	// literal inside the body (proven from each definition below;
	// hardSelf maps them to the literal their sink call must carry).
	selfPos := map[string]int{
		"resolveRedistribute":                      2,
		"resolveRedistributeCluster15158":          2,
		"resolveRedistributeChainCluster15158":     2,
		"resolveISISRedistribute":                  -1,
		"resolveISISRedistributeCluster15158":      -1,
		"resolveISISRedistributeChain":             -1,
		"resolveISISRedistributeChainCluster15158": -1,
		"resolveBGPIPv6Redistribute":               -1,
		"resolveBGPIPv6RedistributeCluster15158":   -1,
		"redistributeEntries":                      2,
		"redistributeEntriesAt":                    2,
		"redistChainEntries15156":                  2,
		"redistBGPUnionEntries16868":               2,
		"bgpPolicyRedistEntriesAt14586":            2,
		"bgpChainRedistEntries16868":               2,
		"redistOrChains16868":                      2,
		"redistOrRouteMapName16868":                2,
		"addExport":                                1, // forwarder closure (daemon, self, ...)
		"addChain":                                 1, // forwarder closure (chain, self, node)
	}
	hardSelf := map[string]string{
		"resolveISISRedistribute":                  "isis",
		"resolveISISRedistributeCluster15158":      "isis",
		"resolveISISRedistributeChain":             "isis",
		"resolveISISRedistributeChainCluster15158": "isis",
		"resolveBGPIPv6Redistribute":               "bgp",
		"resolveBGPIPv6RedistributeCluster15158":   "bgp",
	}
	type defn struct {
		name   string
		params []string
		body   *ast.BlockStmt
		pos    token.Pos
	}
	defsByName := map[string][]*defn{}
	// enclosing maps each definition body to its defn, so a call's
	// identifier argument can be tied to the parameter of the function
	// that textually contains it.
	enclosing := map[*ast.BlockStmt]*defn{}
	var allBodies []*ast.BlockStmt
	seenLit := map[*ast.BlockStmt]bool{}
	paramsOf := func(ft *ast.FuncType) []string {
		var out []string
		if ft == nil || ft.Params == nil {
			return out
		}
		for _, field := range ft.Params.List {
			if len(field.Names) == 0 {
				out = append(out, "")
				continue
			}
			for _, nm := range field.Names {
				out = append(out, nm.Name)
			}
		}
		return out
	}
	record := func(name string, ft *ast.FuncType, body *ast.BlockStmt, pos token.Pos) {
		if body == nil {
			return
		}
		allBodies = append(allBodies, body)
		if _, ok := selfPos[name]; !ok {
			return
		}
		d := &defn{name: name, params: paramsOf(ft), body: body, pos: pos}
		defsByName[name] = append(defsByName[name], d)
		enclosing[body] = d
	}
	for _, fname := range files {
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, fname, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				record(fd.Name.Name, fd.Type, fd.Body, fd.Pos())
			}
		}
		// Every FuncLit body is a walk context; a FuncLit assigned to a
		// bare identifier (addExport/addChain) is also a censused
		// definition when its name is in the callee set.
		ast.Inspect(f, func(n ast.Node) bool {
			if fl, ok := n.(*ast.FuncLit); ok {
				if fl.Body != nil && !seenLit[fl.Body] {
					seenLit[fl.Body] = true
					allBodies = append(allBodies, fl.Body)
				}
				return true
			}
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			fl, ok := as.Rhs[0].(*ast.FuncLit)
			if !ok {
				return true
			}
			if _, censused := selfPos[id.Name]; censused {
				if _, dup := enclosing[fl.Body]; !dup {
					d := &defn{name: id.Name, params: paramsOf(fl.Type), body: fl.Body, pos: fl.Pos()}
					defsByName[id.Name] = append(defsByName[id.Name], d)
					enclosing[fl.Body] = d
				}
			}
			return true
		})
	}
	calleeName := func(ce *ast.CallExpr) string {
		if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
			return sel.Sel.Name
		}
		if id, ok := ce.Fun.(*ast.Ident); ok {
			return id.Name
		}
		return ""
	}
	// literalAt returns the string literal at args[idx], if present.
	literalAt := func(args []ast.Expr, idx int) (string, bool) {
		if idx < 0 || idx >= len(args) {
			return "", false
		}
		bl, ok := args[idx].(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		return s, err == nil
	}
	// Sinks apply the AFI filter themselves; they need no forwarding
	// proof. Their (self, node) callers are censused in Pass 2.
	sinks := map[string]bool{"redistributeEntries": true, "redistributeEntriesAt": true}
	// Pass 1 — definition proof: every non-sink censused definition must
	// reach a censused callee carrying (a) its own self parameter
	// unchanged, (b) the pinned literal for a hard-coded form, or (c)
	// any literal (a wrapper pinning its own router, e.g.
	// "bgp"/"bgp-ipv6"). A definition that reaches no censused callee,
	// or reaches one only through an unproven expression, cannot be
	// trusted as a forwarder.
	for name, ds := range defsByName {
		if sinks[name] {
			continue
		}
		want := selfPos[name]
		for _, d := range ds {
			proven := false
			ast.Inspect(d.body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				inner := calleeName(ce)
				ipos, ok := selfPos[inner]
				if !ok || inner == name {
					return true
				}
				if want < 0 {
					// Hard-coded form: forward into its twin or carry
					// the pinned literal into a sink.
					if strings.HasPrefix(inner, name) {
						proven = true
						return true
					}
					if s, ok := literalAt(ce.Args, ipos); ok && s == hardSelf[name] {
						proven = true
					}
					return true
				}
				if ipos < 0 {
					proven = true // delegates to a hard-coded form
					return true
				}
				if s, ok := literalAt(ce.Args, ipos); ok && s != "" {
					proven = true
					return true
				}
				if id, ok := ce.Args[ipos].(*ast.Ident); ok && want < len(d.params) && id.Name == d.params[want] {
					proven = true
				}
				return true
			})
			if !proven {
				p := fset.Position(d.pos)
				t.Fatalf("%s (%s:%d): definition does not forward its self parameter or a pinned literal into a censused callee; the census cannot prove its router", name, filepath.Base(p.Filename), p.Line)
			}
		}
	}
	// Pass 2 — call census: every call to a censused callee in every
	// non-test body. Bodies are walked with their enclosing defn (nil
	// for a non-censused function, where only literals may appear).
	lits := map[string]int{}
	type bodyCtx struct {
		body *ast.BlockStmt
		def  *defn
	}
	var ctxs []bodyCtx
	// Walk every top-level function body, censused or not, plus the
	// forwarder closure bodies recorded above.
	seenBody := map[*ast.BlockStmt]bool{}
	addCtx := func(b *ast.BlockStmt) {
		if b == nil || seenBody[b] {
			return
		}
		seenBody[b] = true
		ctxs = append(ctxs, bodyCtx{b, enclosing[b]})
	}
	for _, b := range allBodies {
		addCtx(b)
	}
	literalCalls := 0
	for _, ctx := range ctxs {
		ast.Inspect(ctx.body, func(n ast.Node) bool {
			// Do not descend into a nested closure: its calls are
			// visited under its own context (or, for an anonymous
			// non-censused closure, identifiers cannot be proven).
			if fl, ok := n.(*ast.FuncLit); ok && fl.Body != ctx.body {
				return false // visited under its own context
			}
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := calleeName(ce)
			ipos, ok := selfPos[name]
			if !ok {
				return true
			}
			p := fset.Position(ce.Pos())
			where := filepath.Base(p.Filename) + ":" + strconv.Itoa(p.Line)
			if ipos < 0 {
				lits[hardSelf[name]]++
				if hardSelf[name] == "bgp" {
					// The BGP-IPv6 node itself: its sink carries the
					// "bgp-ipv6" node literal (Pass 1 proved it).
					lits["bgp-ipv6"]++
				}
				literalCalls++
				return true
			}
			if name == "redistributeEntriesAt" {
				if node, ok := literalAt(ce.Args, 3); ok && node != "" {
					lits[node]++
				}
			}
			if s, ok := literalAt(ce.Args, ipos); ok {
				if s == "" {
					t.Errorf("%s: call to %s passes an empty self literal; frrRedistNodeAFI has no row for it", where, name)
					return true
				}
				lits[s]++
				literalCalls++
				return true
			}
			id, ok := ce.Args[ipos].(*ast.Ident)
			if !ok {
				t.Errorf("%s: call to %s passes a non-literal, non-identifier self; a call this census cannot read is a router the filter cannot see", where, name)
				return true
			}
			// Identifier: proven only as the self parameter of the
			// enclosing censused definition (Pass 1 proved that
			// definition forwards it). Its literal is counted at the
			// outermost literal call site, so nothing is added here.
			if ctx.def == nil || selfPos[ctx.def.name] < 0 || selfPos[ctx.def.name] >= len(ctx.def.params) || ctx.def.params[selfPos[ctx.def.name]] != id.Name {
				t.Errorf("%s: call to %s passes self via identifier %q, which is not the proven self parameter of its enclosing censused definition; a call this census cannot read is a router the filter cannot see", where, name, id.Name)
			}
			return true
		})
	}
	if literalCalls == 0 {
		t.Fatal("census found no literal-self calls; it is not reading the production call sites")
	}
	// Completeness pin: the censused callee definitions themselves,
	// counted over declarations. Adding a new self-carrying wrapper or
	// sink — or renaming one away — breaks the pin until this census
	// is extended to classify it.
	defCount := 0
	for _, ds := range defsByName {
		defCount += len(ds)
	}
	if defCount != 19 {
		t.Fatalf("census completeness pin: %d censused callee definitions, want 19 (%v); a self-carrying callee was added or removed without updating this census", defCount, defsByName)
	}
	// Positive control: the scan must see the routers known to render
	// redistribute today, or it is reading the wrong files.
	for _, want := range []string{"ospf", "ospf6", "bgp", "rip", "isis", "bgp-ipv6"} {
		if lits[want] == 0 {
			t.Errorf("scan did not find the %q call site; census is blind", want)
		}
	}
	for self := range lits {
		if _, ok := frrRedistNodeAFI[self]; !ok {
			t.Errorf("call site passes self=%q, which frrRedistNodeAFI has no row for, so its cross-family sources are not filtered", self)
		}
	}
}

// Every keyword the commit gate admits must have a source row, and every row
// must be reachable from the gate. The domain is read from the switch in
// config.FRRRoutingProtocolKeyword, not restated here.
func TestRedistSourceAFICoversKeywordDomain_9510(t *testing.T) {
	path := filepath.Join("..", "config", "routing_protocol_domain.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var tokens []string
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "FRRRoutingProtocolKeyword" {
			return true
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			if cc, ok := n.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						s, _ := strconv.Unquote(bl.Value)
						tokens = append(tokens, s)
					}
				}
			}
			return true
		})
		return false
	})
	sort.Strings(tokens)
	// Positive control: the parse must reach the switch.
	if len(tokens) < 9 || sort.SearchStrings(tokens, "direct") == len(tokens) || sort.SearchStrings(tokens, "ospf6") == len(tokens) {
		t.Fatalf("parsed case tokens %v; the census is not reading FRRRoutingProtocolKeyword", tokens)
	}
	reached := map[string]bool{}
	for _, tok := range tokens {
		kw, ok := config.FRRRoutingProtocolKeyword(tok)
		if !ok {
			t.Errorf("case token %q is not admitted by FRRRoutingProtocolKeyword", tok)
			continue
		}
		reached[kw] = true
		if _, ok := frrRedistSourceAFI[kw]; !ok {
			t.Errorf("keyword %q (from %q) has no frrRedistSourceAFI row, so it is never filtered by family", kw, tok)
		}
	}
	for kw := range frrRedistSourceAFI {
		if !reached[kw] {
			t.Errorf("frrRedistSourceAFI row %q is not produced by any admitted token; a dead row hides a renamed keyword", kw)
		}
	}
}

// A policy whose every `from protocol` was filtered must say that none APPLIES
// here. The pre-existing "has no `from protocol`" text would send the operator
// looking for a term the policy already has. Both branches return "", so only
// the diagnostic tells them apart.
func TestResolveRedistributeAllFilteredWarnsAccurately_9510(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"v6only": {Name: "v6only", Terms: []*config.PolicyTerm{
			{Name: "t", FromProtocols: []string{"ripng"}, Action: "accept"},
		}},
		"commonly": {Name: "commonly", Terms: []*config.PolicyTerm{
			{Name: "t", Action: "accept"},
		}},
	}}
	m := New()
	if got := m.resolveRedistribute("v6only", po, "ospf", nil); got != "" {
		t.Fatalf("all-filtered policy rendered %q", got)
	}
	if out := buf.String(); !strings.Contains(out, "applies under this router") || strings.Contains(out, "has no `from protocol`") {
		t.Errorf("all-filtered policy warned:\n%s\nwant the none-applies diagnostic, not has-no-from-protocol", out)
	}
	// #14380 control: a policy that really has no `from protocol`
	// now expands over every node-fitting source instead of warning.
	buf.Reset()
	got := m.resolveRedistribute("commonly", po, "ospf", nil)
	for _, proto := range []string{"bgp", "connected", "isis", "kernel", "rip", "static"} {
		want := " redistribute " + proto + " route-map commonly-" + proto + "-xpf-redist-ospf\n"
		if !strings.Contains(got, want) {
			t.Errorf("protocol-less policy missing %q, got %q", want, got)
		}
	}
}
