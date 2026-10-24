package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #16150: reachability audit for compactNormalizeInScope — the audit is
// the product; no table conversion is authorized by this issue.
//
// The predicate has three distinct ways a listed pair can fail to be the
// reason a fold happens, and each already has (or here gains) a guard:
//
//  1. SHADOWED BY THE PRE-EMPTION (this file). The guard at the top of
//     compactNormalizeInScope returns false for containers
//     `authentication` and `user` before any switch is consulted. Any
//     case naming one of those containers can never fire through the
//     predicate. Today exactly two such cases exist; the stale comment
//     above the guard claimed none did.
//  2. UNFIREABLE (no schema position) — pinned by
//     TestNoAdmittedPairIsUnfireable8690.
//  3. DUPLICATE across switches (a later copy never decides, and
//     removing the earlier copy silently leaves the pair admitted) —
//     pinned by TestNoPairIsAdmittedByTwoFamilySwitches8690.
//
// This file covers (1) and, because a shadowed/unfireable check that
// only reads case literals would miss it, the one non-switch admission
// (`policy proposal-set`) and the live-fire proof that every other
// admitted pair is actually consulted by the production fold.
//
// Incident prose is deliberately NOT touched: the pairs below stay in
// compact_normalize_scope.go with their family rationale. This audit
// proves which of them can fire; it does not convert the table.

// shadowedByPreemption16150 is the exact set of case pairs that the
// `authentication`/`user` pre-emption makes unreachable through
// compactNormalizeInScope. Pinned, not endorsed: each names an OSPF
// spelling whose compact form is handled by packedBodyChildren and
// the OSPF compiler readers (compiler_protocols.go), not by this
// fold, so the dead entry costs no coverage today — but it must not
// grow silently, and removing an entry requires re-deriving that
// handling rather than deleting a line here.
var shadowedByPreemption16150 = []string{
	"authentication md5",
	"authentication simple-password",
}

// parseScopeSource16150 parses compact_normalize_scope.go and returns
// the distinct case-literal pairs and the container of any top-level
// `if containerKeyword == "X" || ... { return false }` pre-emption.
// Parsing (not regex) is load-bearing: see the shape history in
// TestNoPairIsAdmittedByTwoFamilySwitches8690.
func parseScopeSource16150(t *testing.T) (pairs []string, preempted map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "compact_normalize_scope.go", nil, 0)
	if err != nil {
		t.Fatalf("parse predicate source: %v", err)
	}
	seen := map[string]bool{}
	preempted = map[string]bool{}
	// Find the predicate function first so case literals elsewhere in
	// the file (none today) cannot pollute the audit.
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "compactNormalizeInScope" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("compactNormalizeInScope not found in compact_normalize_scope.go")
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CaseClause:
			for _, e := range node.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.Contains(v, " ") {
					continue
				}
				if !seen[v] {
					seen[v] = true
					pairs = append(pairs, v)
				}
			}
		case *ast.IfStmt:
			// The pre-emption shape: `if containerKeyword == "a" ||
			// containerKeyword == "b" { return false }` as the first
			// statement. Collect every string compared against
			// containerKeyword in such a guard whose body returns false.
			if !ifReturnsFalse16150(node) {
				return true
			}
			ast.Inspect(node.Cond, func(c ast.Node) bool {
				be, ok := c.(*ast.BinaryExpr)
				if !ok || be.Op != token.EQL {
					return true
				}
				ident, lit := be.X, be.Y
				if id, ok := ident.(*ast.Ident); ok && id.Name == "containerKeyword" {
					if bl, ok := lit.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						if v, err := strconv.Unquote(bl.Value); err == nil {
							preempted[v] = true
						}
					}
				}
				return true
			})
		}
		return true
	})
	sort.Strings(pairs)
	return pairs, preempted
}

func ifReturnsFalse16150(ifStmt *ast.IfStmt) bool {
	for _, s := range ifStmt.Body.List {
		if ret, ok := s.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "false" {
				return true
			}
		}
	}
	return false
}

// TestCompactNormalizeShadowedPairs16150 pins mechanism (1): the set of
// listed pairs shadowed by the authentication/user pre-emption is
// exactly the known two. A new entry reds (it would read as coverage
// while never firing); a removed entry also reds (the pin must shrink
// with the fix, and the OSPF readers' handling must be re-derived
// first). The pre-emption containers themselves are re-derived from
// source, not restated, so widening the guard reds here too.
func TestCompactNormalizeShadowedPairs16150(t *testing.T) {
	pairs, preempted := parseScopeSource16150(t)
	if len(pairs) < 400 {
		t.Fatalf("only %d distinct pairs parsed from compactNormalizeInScope; "+
			"the walk has lost reach and this audit would report clean for that reason (#16150)", len(pairs))
	}
	// Reach control on the pre-emption derivation: the guard must be
	// found, with exactly the two containers the #6662 decision names.
	if len(preempted) != 2 || !preempted["authentication"] || !preempted["user"] {
		t.Fatalf("pre-emption containers derived from source = %v, want exactly {authentication, user}; "+
			"the audit cannot classify shadowing without the guard it audits (#16150)", preempted)
	}
	var shadowed []string
	for _, p := range pairs {
		container, _, _ := strings.Cut(p, " ")
		if preempted[container] {
			shadowed = append(shadowed, p)
		}
	}
	sort.Strings(shadowed)
	if strings.Join(shadowed, "\n") != strings.Join(shadowedByPreemption16150, "\n") {
		t.Errorf("pairs shadowed by the authentication/user pre-emption changed:\n got: %v\nwant: %v\n"+
			"A NEW entry can never fire through compactNormalizeInScope — it reads as coverage and "+
			"normalizes nothing. Either scope it under a container the guard does not pre-empt, or "+
			"re-derive the #6662 exclusion as pairs (see the guard comment). A REMOVED entry means "+
			"a shadowed pair was tidied; shrink this pin with it after re-deriving who handles that "+
			"spelling instead (#16150).", shadowed, shadowedByPreemption16150)
	}
	// Direct predicate evidence, not just source shape: both pinned
	// pairs must actually be refused by the live predicate today.
	for _, p := range shadowedByPreemption16150 {
		c, h, _ := strings.Cut(p, " ")
		if compactNormalizeInScope(c, h) {
			t.Errorf("compactNormalizeInScope(%q, %q) = true, but the pair is pinned as shadowed "+
				"by the pre-emption; either the guard moved or the pin is stale (#16150)", c, h)
		}
	}
	t.Logf("#16150: %d distinct pairs, %d shadowed by pre-emption %v", len(pairs), len(shadowed), shadowed)
}

// TestCompactNormalizeNonSwitchAdmission16150 proves the one admission
// that is not a case literal — `if containerKeyword == "policy" &&
// head == "proposal-set"` — is live, pair-scoped, and not shadowed.
// A case-literal-only audit (mechanisms 1–3 above) is structurally
// blind to it, so its reachability is asserted behaviourally.
func TestCompactNormalizeNonSwitchAdmission16150(t *testing.T) {
	if !compactNormalizeInScope("policy", "proposal-set") {
		t.Error("`policy proposal-set` must be admitted via the non-switch if; " +
			"the case-literal audits cannot see this admission, so its loss would be silent (#16150)")
	}
	if compactNormalizeInScope("xpf-no-such-container-16150", "proposal-set") {
		t.Error("`proposal-set` admitted under a sentinel container — the non-switch admission has become head-only (#16150)")
	}
	if compactNormalizeInScope("policy", "xpf-no-such-head-16150") {
		t.Error("`policy` admitted with a sentinel head — the non-switch admission has become container-only (#16150)")
	}
	if compactNormalizeInScope("authentication", "proposal-set") || compactNormalizeInScope("user", "proposal-set") {
		t.Error("`proposal-set` admitted under a pre-empted container — the guard no longer pre-empts (#16150)")
	}
}

// schemaChildrenByKeyword16150 maps every schema keyword to the set of
// child names declared at any position with that keyword. Wildcard
// children are recorded under the parent keyword, matching production:
// a wildcard is an argument of its parent, not a level of its own
// (same derivation as TestNoAdmittedPairIsUnfireable8690).
func schemaChildrenByKeyword16150() map[string]map[string]bool {
	kids := map[string]map[string]bool{}
	var walk func(n *schemaNode, name string, depth int)
	walk = func(n *schemaNode, name string, depth int) {
		if n == nil || depth > 12 {
			return
		}
		if kids[name] == nil {
			kids[name] = map[string]bool{}
		}
		for cn, ch := range n.children {
			kids[name][cn] = true
			walk(ch, cn, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, name, depth+1)
		}
	}
	walk(setSchema, "", 0)
	return kids
}

// TestCompactNormalizeEveryLivePairFires16150 is the decisive
// acceptance check: every admitted pair that is neither shadowed nor
// unfireable must be observed firing at the production seam. For each
// such pair it builds the minimal packed spelling at EVERY schema
// position where the pair occurs (keyword node with the head packed
// onto its Keys), runs the real normalizeCompactStanzas pass, and
// requires at least one position to fold. A pair the pass never
// consults — because the walk cannot reach its container, an outer
// link is missing, or the head is not a child there — reds.
//
// Seeded-unreachable control: the shadowed pair
// `authentication simple-password` is run through the same machinery
// and must fold NOWHERE, proving the harness can distinguish firing
// from non-firing rather than reporting every pair live.
func TestCompactNormalizeEveryLivePairFires16150(t *testing.T) {
	pairs, preempted := parseScopeSource16150(t)
	kids := schemaChildrenByKeyword16150()

	// Classify each pair exactly as the three mechanisms define.
	var live, shadowed, unfireable []string
	for _, p := range pairs {
		container, head, _ := strings.Cut(p, " ")
		switch {
		case preempted[container]:
			shadowed = append(shadowed, p)
		case !kids[container][head]:
			unfireable = append(unfireable, p)
		default:
			live = append(live, p)
		}
	}
	// Include the non-switch admission in the live set: it has a schema
	// position (policy -> proposal-set under ike/ipsec policy) and must
	// fire like any case pair.
	live = append(live, "policy proposal-set")
	sort.Strings(live)
	if len(unfireable) > 0 {
		t.Errorf("%d pair(s) have no schema position and can never fire: %v (#16150; also pinned by #8690)",
			len(unfireable), unfireable)
	}
	if strings.Join(shadowed, "\n") != strings.Join(shadowedByPreemption16150, "\n") {
		t.Errorf("shadowed set %v does not match the pin %v (#16150)", shadowed, shadowedByPreemption16150)
	}

	// foldCount builds, for one (container, head) pair, a tree whose
	// root-to-container path follows a real schema position, with the
	// head packed onto the container node's Keys, and returns how many
	// folds the production pass performs. Positions are enumerated by
	// walking setSchema and recording every path whose last keyword is
	// the container and which declares head as a child.
	fires := map[string]bool{}
	for _, pair := range append(append([]string{}, live...), shadowed...) {
		container, head, _ := strings.Cut(pair, " ")
		paths := schemaPathsToPair16150(container, head)
		if len(paths) == 0 {
			continue // unfireable; already reported above
		}
		for _, path := range paths {
			if len(path) == 0 {
				continue
			}
			if firesAt16150(t, path, container, head) {
				fires[pair] = true
				break
			}
		}
	}

	// Seeded-unreachable control must NOT fire.
	for _, p := range shadowed {
		if fires[p] {
			t.Errorf("seeded shadowed pair %q folded — the harness cannot distinguish firing from "+
				"non-firing, so the live verdicts below are meaningless (#16150)", p)
		}
	}
	var dead []string
	for _, p := range live {
		if !fires[p] {
			dead = append(dead, p)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("%d live pair(s) were never observed firing at any schema position: %v\n"+
			"Each is admitted, has a schema position, and is not shadowed — yet the production "+
			"pass folds nothing for it. The usual causes are a missing outer chain link or a "+
			"container the walk only reaches under a spelling this harness does not build; "+
			"either adjudicate the pair with a spelling that reaches it or remove it (#16150).",
			len(dead), dead)
	}
	t.Logf("#16150: %d live pairs all observed firing, %d shadowed (control: none fired), %d unfireable",
		len(live), len(shadowed), len(unfireable))
}

// schemaPathsToPair16150 returns every root-to-container TEXT path at
// which container occurs as the last keyword and declares head as a
// child. A path is a list of schema child NAMES from the root; tokens
// for args/wildcards are added when the fixture is rendered, not here.
// Wildcard positions contribute an `xpfname` path element, mirroring
// collectCompactSites, so a container that only exists under a named
// instance (tunnel under an interface, peer under wireguard) still
// gets a path — omitting it was the first harness's blind spot.
func schemaPathsToPair16150(container, head string) [][]string {
	var out [][]string
	var walk func(n *schemaNode, name string, path []string, depth int)
	walk = func(n *schemaNode, name string, path []string, depth int) {
		if n == nil || depth > 12 {
			return
		}
		if name == container && n.children[head] != nil {
			out = append(out, append([]string{}, path...))
		}
		names := make([]string, 0, len(n.children))
		for cn := range n.children {
			names = append(names, cn)
		}
		sort.Strings(names)
		for _, cn := range names {
			walk(n.children[cn], cn, append(append([]string{}, path...), cn), depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, name, append(append([]string{}, path...), "xpfname"), depth+1)
		}
	}
	walk(setSchema, "", nil, 0)
	return out
}

// renderPackedFixture16150 renders a braced text fixture following
// path, with the last element's node carrying the packed tail
// `head xpfarg;`. Every element is rendered with dummy args for its
// schema node (`xpfarg` per arg, `xpfname` for a wildcard element),
// and a compoundKey element carries its sub-key (the next path
// element) on its own line, exactly as an operator writes
// `family inet …;`. The text is parsed by the real parser, so
// Keys/args/compoundKey shapes are production's, not a reconstruction.
func renderPackedFixture16150(t *testing.T, path []string, head string) string {
	t.Helper()
	// Resolve schema nodes along the path, descending into the
	// compoundKey sub-node where the next element names it.
	nodes := make([]*schemaNode, len(path))
	cur := setSchema
	for i, elem := range path {
		if elem == "xpfname" {
			if cur.wildcard == nil {
				return ""
			}
			nodes[i] = cur.wildcard
			cur = cur.wildcard
			continue
		}
		child := schemaChildFor(cur, elem)
		// A sub-key element (the element after a compoundKey) is not a
		// child of the compoundKey's parent: schemaChildFor returns
		// nil (or a wildcard fallback) for it. Resolve it from the
		// compoundKey node's own children BEFORE the nil check.
		if i > 0 && nodes[i-1] != nil && nodes[i-1].compoundKey {
			if sub, ok := nodes[i-1].children[elem]; ok && sub != nil {
				child = sub
			}
		}
		if child == nil {
			return ""
		}
		nodes[i] = child
		cur = child
		if child.compoundKey && i+1 < len(path) {
			if sub, ok := child.children[path[i+1]]; ok && sub != nil {
				cur = sub
			}
		}
	}
	// Iterative rendering keeps brace balance obvious: each element
	// opens one level, except a compoundKey element, which carries its
	// sub-key (the next path element) on its own line and consumes it.
	var b strings.Builder
	type frame struct{ close bool }
	var frames []frame
	i := 0
	for i < len(path) {
		elem := path[i]
		sn := nodes[i]
		toks := []string{elem}
		for range sn.args {
			toks = append(toks, "xpfarg")
		}
		if sn.compoundKey && i+1 < len(path) {
			toks = append(toks, path[i+1])
			if i+1 == len(path)-1 {
				b.WriteString(strings.Join(toks, " ") + " " + head + " xpfarg; ")
				i = len(path)
				break
			}
			b.WriteString(strings.Join(toks, " ") + " { ")
			frames = append(frames, frame{close: true})
			i += 2 // sub-key consumed
			continue
		}
		if i == len(path)-1 {
			b.WriteString(strings.Join(toks, " ") + " " + head + " xpfarg; ")
			i++
			break
		}
		b.WriteString(strings.Join(toks, " ") + " { ")
		frames = append(frames, frame{close: true})
		i++
	}
	for range frames {
		b.WriteString("} ")
	}
	return b.String()
}

// firesAt16150 parses the rendered fixture and reports whether the
// production pass folds the packed head into a child of a node whose
// production container keyword (Keys[0], or the compoundKey sub-key)
// is container. The ckw derivation mirrors normalizeCompactNodes.
func firesAt16150(t *testing.T, path []string, container, head string) bool {
	t.Helper()
	text := renderPackedFixture16150(t, path, head)
	if text == "" {
		return false
	}
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		return false
	}
	if normalizeCompactStanzas(tree) == 0 {
		return false
	}
	// Walk with the schema exactly as the pass does, tracking the
	// production (ckw, head) question at each node, and check the
	// specific fold: some node that asked (container, head) now has a
	// child named head. Approximated structurally: any node whose
	// first key is container (or whose compound sub-key is container)
	// with a direct child named head.
	return treeHasChild16150(tree, container, head)
}

// treeHasChild16150 reports whether the fold produced a child named
// head under the pair's container. Two production shapes count:
// a plain node whose first key is container with a direct child
// named head, and a compoundKey node (Keys = [family, container, …])
// whose folded child is named head — for the latter the pass asks
// (sub-key, head), so the container lives at Keys[1], not Keys[0].
func treeHasChild16150(tree *ConfigTree, container, head string) bool {
	found := false
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			isContainer := len(n.Keys) > 0 && n.Keys[0] == container ||
				len(n.Keys) > 1 && n.Keys[1] == container
			if isContainer {
				for _, c := range n.Children {
					if c != nil && len(c.Keys) > 0 && c.Keys[0] == head {
						found = true
					}
				}
			}
			walk(n.Children)
		}
	}
	walk(tree.Children)
	return found
}

// TestCompactNormalizeSeededUnreachablePair16150 is the explicit
// seeded-pair control the issue requires: a pair that looks exactly
// like an ordinary admission but names a pre-empted container must be
// refused by the predicate and must fold nothing, while its
// non-pre-empted sibling fires. If a future change widens scope by
// adding such a case below the guard, the first assertion is the one
// that must be made to red in review — the pair itself is
// indistinguishable from coverage by reading the switch.
func TestCompactNormalizeSeededUnreachablePair16150(t *testing.T) {
	// Seeded: (user, ssh) would be the natural pair for a login-adjacent
	// fold; the pre-emption refuses it regardless of the head.
	if compactNormalizeInScope("user", "ssh") {
		t.Error("seeded pair (user, ssh) admitted despite the pre-emption — the guard no longer pre-empts (#16150)")
	}
	if compactNormalizeInScope("authentication", "md5") {
		t.Error("seeded pair (authentication, md5) admitted despite the pre-emption (#16150)")
	}
	// The same head under a live container is admitted, proving the
	// refusal above is the container pre-emption and not the head.
	if !compactNormalizeInScope("ssh", "protocol-version") {
		t.Error("(ssh, protocol-version) must stay admitted; the seeded refusal must be container-scoped (#16150)")
	}
	// Behavioural: a packed `authentication simple-password` tail inside
	// an OSPF interface stanza folds nothing through this pass (the OSPF
	// reader handles the spelling via packedBodyChildren instead).
	tree, perrs := NewParser(`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication simple-password "xpf-secret"; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	before := fmt.Sprintf("%v", tree.Children)
	if n := normalizeCompactStanzas(tree); n != 0 {
		t.Errorf("the compact pass folded %d node(s) inside the OSPF authentication stanza; "+
			"the shadowed pairs must stay inert through this predicate (got tree change from %s)", n, before)
	}
}
