package frr

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
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
		{"mixed", "ospf", " redistribute rip route-map mixed\n redistribute static route-map mixed\n"},
		{"mixed", "ospf6", " redistribute ripng route-map mixed\n redistribute static route-map mixed\n"},
		{"mixed", "rip", " redistribute static route-map mixed\n"},
		// Control: no enclosing router, so nothing is filtered.
		{"mixed", "", " redistribute ospf6 route-map mixed\n redistribute rip route-map mixed\n" +
			" redistribute ripng route-map mixed\n redistribute static route-map mixed\n"},
		// Every term filtered: nothing renders.
		{"v6only", "ospf", ""},
		{"v6only", "rip", ""},
		// Control for the rows above: the same policy under a router whose
		// grammar lists the source. (No row pins a `router isis` literal: the
		// plain form is not IS-IS grammar at all: #9666.)
		{"v6only", "ospf6", " redistribute ripng route-map v6only\n"},
	} {
		if got := m.resolveRedistribute(tc.policy, po, tc.self, nil); got != tc.want {
			t.Errorf("policy %q under router %q: got %q, want %q", tc.policy, tc.self, got, tc.want)
		}
	}
}

// The filter passes a router it has no row for. So every call site's self
// literal must have a row, and no call site may pass a non-literal self that
// this scan would skip. The count check closes that gap.
func TestRedistNodeAFICoversEveryCallSite_9510(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	callRE := regexp.MustCompile(`\.resolveRedistribute\(`)
	litRE := regexp.MustCompile(`\.resolveRedistribute\([^,()]+,\s*[^,()]+,\s*"([a-z0-9]*)",`)
	// #9666: IS-IS renders through resolveISISRedistribute, which takes the
	// router's level rather than a self literal and hard-codes self "isis"
	// into redistributeEntries. Its call sites count as "isis" ONLY if that
	// hard-coding is proven below, and redistributeEntries may have no caller
	// but the two wrappers, so a third path cannot slip past this census.
	isisCallRE := regexp.MustCompile(`\.resolveISISRedistribute\(`)
	isisSelfRE := regexp.MustCompile(`func \(m \*Manager\) resolveISISRedistribute\([^)]*\) string \{\s*return isisRedistributeLines\(m\.redistributeEntries\([^,()]+,\s*[^,()]+,\s*"isis",`)
	entriesCallRE := regexp.MustCompile(`\.redistributeEntries\(`)
	calls, lits := 0, map[string]int{}
	isisCalls, isisSelfProven, entriesCalls := 0, false, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		calls += len(callRE.FindAllIndex(b, -1))
		for _, mm := range litRE.FindAllSubmatch(b, -1) {
			lits[string(mm[1])]++
		}
		isisCalls += len(isisCallRE.FindAllIndex(b, -1))
		isisSelfProven = isisSelfProven || isisSelfRE.Match(b)
		entriesCalls += len(entriesCallRE.FindAllIndex(b, -1))
	}
	if isisCalls > 0 {
		if !isisSelfProven {
			t.Fatalf("found %d resolveISISRedistribute calls but could not prove it passes self \"isis\" to redistributeEntries", isisCalls)
		}
		calls += isisCalls
		lits["isis"] += isisCalls
	}
	if entriesCalls != 2 {
		t.Fatalf("redistributeEntries has %d callers, want exactly the two wrappers (resolveRedistribute, resolveISISRedistribute); another caller would be a router this census cannot see", entriesCalls)
	}
	n := 0
	for _, c := range lits {
		n += c
	}
	if calls == 0 || n != calls {
		t.Fatalf("found %d resolveRedistribute calls but %d with a literal self %v; a call this scan cannot read is a router the filter cannot see", calls, n, lits)
	}
	// Positive control: the scan must see the five routers known to render
	// redistribute today, or it is reading the wrong files.
	for _, want := range []string{"ospf", "ospf6", "bgp", "rip", "isis"} {
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
	// Control: a policy that really has no `from protocol` keeps its own text.
	buf.Reset()
	if got := m.resolveRedistribute("commonly", po, "ospf", nil); got != "" {
		t.Fatalf("protocol-less policy rendered %q", got)
	}
	if out := buf.String(); !strings.Contains(out, "has no `from protocol`") {
		t.Errorf("protocol-less policy warned:\n%s\nwant has-no-from-protocol", out)
	}
}
