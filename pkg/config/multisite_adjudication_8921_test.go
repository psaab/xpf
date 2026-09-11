package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #8921 items 1 and 2. `compactNormalizeInScope` is keyed on (container
// keyword, head), so an admission is live at every site where a container of
// that keyword declares that head -- and each was adjudicated by measuring ONE
// fixture at ONE site. The ratchet (multisite_admission_ratchet_8921_test.go,
// item 3) records WHERE. This file adjudicates every recorded (pair, site)
// cell, and docs/config-schema.md records why that settles item 1 without
// parent-qualifying the predicate.
//
// THE PROPERTY. An admission exists so that the elided spelling means the
// braced one. At a given site that holds exactly when normalizing
//
//	C <id> H <value>;       produces the tree the parser builds for
//	C <id> { H <value>; }
//
// and it is decidable per site WITHOUT a compiled fixture and without asking
// whether the value is observable in the typed config -- the question that
// leaves 91 of these cells unruled by the #2419 census. The reason is where the
// fold runs: both compile entries (compileConfigWithOpts and
// compileConfigForNodeWithOpts) prune inactive nodes and then normalize before
// anything else reads the tree, and SchemaValidateWithDefinitions normalizes
// before its walk. An identical tree therefore compiles and validates
// identically whether or not the value is observable in the typed config.
// The claim is about the RENDERED value: where a container splits a packed
// run into statements, a value that spells a sibling statement keyword can end
// a statement early, and that value-dependent case is outside this cell (it
// is issue 9635, with the #8437 gate).
//
// WHY STRUCTURE IS THE PER-SITE QUESTION. The pair decides only WHETHER the fold
// fires. Where the container's identity ends (its args, a compoundKey sub-key)
// and what the head's statement is are read from the schema node AT THAT SITE.
// Those are the inputs that can differ between two sites sharing a keyword, and
// they are exactly what this cell exercises.
//
// WHAT THIS CANNOT SEE, so a green here is not read as more:
//   - A site where the product deliberately REFUSES the elided spelling (#6662
//     packed login bodies, #3043 policy terminal actions). There the fold would
//     be structurally right and still wrong to admit; that is a policy decision,
//     not a structural one. Such pairs are excluded, and the rejection-vs-
//     acceptance arm of TestCompactNormalizeScopePreservesCompiledResult8690
//     measures a disarmed gate at every site the pass normalizes.
//   - `show configuration`, which renders the tree as authored and never sees
//     the fold.

// renderSite8921 turns a registry site path into the statement heads a
// production parse builds: an `args` slot is a placeholder token, a compoundKey
// takes its sub-key onto the same statement (`family inet`), and `*` is an
// instance name. Rendering the compound key as two nested blocks instead would
// be a DIFFERENT AST shape from the one hierarchical configs produce, and would
// skip the compoundKey branch of the fold.
func renderSite8921(path string) ([]string, *schemaNode, error) {
	parts := strings.Split(path, "/")
	cur := setSchema
	var stmts []string
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if p == "*" {
			if cur.wildcard == nil {
				return nil, nil, fmt.Errorf("%q has no instance slot", strings.Join(parts[:i], "/"))
			}
			stmts = append(stmts, "xpfname")
			cur = cur.wildcard
			continue
		}
		next := cur.children[p]
		if next == nil {
			return nil, nil, fmt.Errorf("%q does not declare %q", strings.Join(parts[:i], "/"), p)
		}
		stmt := p + strings.Repeat(" xpfarg", next.args)
		if next.compoundKey && i+1 < len(parts) {
			if sub := next.children[parts[i+1]]; sub != nil {
				i++
				stmt += " " + parts[i] + strings.Repeat(" xpfarg", sub.args)
				next = sub
			}
		}
		stmts = append(stmts, stmt)
		cur = next
	}
	return stmts, cur, nil
}

// headTail8921 renders a head statement that CARRIES the per-key provenance the
// fold has to preserve: an authored quote on the first value and, for a
// multi-value leaf, a bracketed list. A tail with neither would make the mask
// half of the comparison vacuous -- which is how the defect this file found
// stayed invisible: every census fixture value is an unquoted token.
func headTail8921(head string, h *schemaNode) string {
	switch {
	case h.multi && h.args > 0:
		return head + ` [ "xpf v0" xpfv1 ]`
	case h.args > 0:
		tail := head + ` "xpf v0"`
		for a := 1; a < h.args; a++ {
			tail += fmt.Sprintf(" xpfv%d", a)
		}
		return tail
	case h.wildcard != nil:
		return head + ` "xpf w"`
	}
	return head // a valueless flag, or a container head
}

// positionless8921 copies a tree with Line/Column cleared -- the parser records
// a source position and the fold cannot invent one. EVERY other field is
// compared, by reflection, so a field added to Node later is compared too
// rather than silently skipped.
func positionless8921(nodes []*Node) []*Node {
	if nodes == nil {
		return nil
	}
	out := make([]*Node, len(nodes))
	for i, n := range nodes {
		if n == nil {
			continue
		}
		c := *n
		c.Line, c.Column = 0, 0
		c.Children = positionless8921(n.Children)
		out[i] = &c
	}
	return out
}

func sameTree8921(a, b *ConfigTree) bool {
	return reflect.DeepEqual(positionless8921(a.Children), positionless8921(b.Children))
}

func dumpTree8921(b *strings.Builder, nodes []*Node, depth int) {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		fmt.Fprintf(b, "%s%q leaf=%t quoted=%v bracketed=%v\n",
			strings.Repeat("  ", depth), n.Keys, n.IsLeaf, n.KeysQuoted, n.KeysBracketed)
		dumpTree8921(b, n.Children, depth+1)
	}
}

func treeText8921(tree *ConfigTree) string {
	var b strings.Builder
	dumpTree8921(&b, tree.Children, 1)
	return b.String()
}

func anyKey8921(nodes []*Node, pred func(*Node, int) bool) bool {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		for i := range n.Keys {
			if pred(n, i) {
				return true
			}
		}
		if anyKey8921(n.Children, pred) {
			return true
		}
	}
	return false
}

func parse8921(t *testing.T, label, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 || tree == nil {
		t.Errorf("%s: %s does not parse: %v", label, text, errs)
		return nil
	}
	return tree
}

func TestMultisiteAdmissionsFoldToTheBracedTree8921(t *testing.T) {
	reg := multisiteRegistry8921(t)
	pairs := make([]string, 0, len(reg))
	for p := range reg {
		pairs = append(pairs, p)
	}
	sort.Strings(pairs)
	admitNothing := func(string, string) bool { return false }

	cells, identical, quoted, bracketed := 0, 0, 0, 0
	for _, pair := range pairs {
		f := strings.Fields(pair)
		if len(f) != 2 {
			t.Errorf("malformed registry pair %q", pair)
			continue
		}
		head := f[1]
		for _, site := range reg[pair] {
			cells++
			cell := pair + " @ " + site
			stmts, container, err := renderSite8921(site)
			if err != nil {
				t.Errorf("%s: cannot render the site (%v). A cell this walk cannot build "+
					"is UNADJUDICATED, not clean.", cell, err)
				continue
			}
			h := container.children[head]
			if h == nil {
				t.Errorf("%s: the container there does not declare %q, so the registry "+
					"row describes a site the admission cannot reach", cell, head)
				continue
			}
			parent, last := stmts[:len(stmts)-1], stmts[len(stmts)-1]
			tail := headTail8921(head, h)
			elidedText := nest(parent, last+" "+tail+";")
			bracedText := nest(parent, last+" { "+tail+"; }")
			elided := parse8921(t, cell, elidedText)
			braced := parse8921(t, cell, bracedText)
			unfolded := parse8921(t, cell, elidedText)
			if elided == nil || braced == nil || unfolded == nil {
				continue
			}
			fired := normalizeCompactStanzas(elided)
			normalizeCompactStanzasWithScope(unfolded, admitNothing)
			// THE ORACLE IS THE BRACED SPELLING AS PARSED. Normalizing it as well
			// would let a corruption both spellings share read as agreement --
			// which is how the packed-statement splitter's mis-split of a value
			// spelling a sibling keyword stayed invisible. Require instead that
			// the braced tree is already a fixed point of the pass.
			bracedNormal := parse8921(t, cell, bracedText)
			if bracedNormal == nil {
				continue
			}
			normalizeCompactStanzas(bracedNormal)
			if !sameTree8921(bracedNormal, braced) {
				t.Errorf("%s: normalizing the BRACED spelling changes it, so the oracle "+
					"is not a fixed point of the pass:\n  as parsed\n%s  normalized\n%s",
					cell, treeText8921(braced), treeText8921(bracedNormal))
				continue
			}

			if fired == 0 {
				t.Errorf("%s: the fold did not fire on %s. Production never consults this "+
					"pair at this site, so the registry records it as live somewhere it "+
					"is not -- the shape a wildcard slot produced before this walk stopped "+
					"recording pairs at one.", cell, elidedText)
				continue
			}
			// NEGATIVE CONTROL, per cell. With nothing admitted the elided spelling
			// stays packed; if that STILL matched the braced tree, this comparison
			// could not tell a folded site from an unfolded one and every verdict
			// below would be about nothing.
			if sameTree8921(unfolded, braced) {
				t.Errorf("%s: NEGATIVE CONTROL: with no pair admitted, the elided spelling "+
					"already equals the braced tree, so this cell cannot observe the fold",
					cell)
				continue
			}
			if !sameTree8921(elided, braced) {
				t.Errorf("%s: the fold does NOT produce the braced tree here.\n"+
					"  elided %s\n%s  braced %s\n%s"+
					"This admission was adjudicated at another site and is wrong at this "+
					"one: the elided spelling reaches every reader downstream of the "+
					"normalizer as something the operator did not write.",
					cell, elidedText, treeText8921(elided), bracedText, treeText8921(braced))
				continue
			}
			identical++
			if anyKey8921(braced.Children, func(n *Node, i int) bool { return n.KeyQuoted(i) }) {
				quoted++
			}
			if anyKey8921(braced.Children, func(n *Node, i int) bool { return n.KeyBracketed(i) }) {
				bracketed++
			}
		}
	}
	if cells == 0 {
		t.Fatal("NON-VACUITY: the registry yielded no (pair, site) cells")
	}
	// The mask half is only a measurement if the fixtures carry masks. Every
	// fixture value used to be an unquoted token, which is exactly why a fold
	// that dropped the quote bit passed every instrument in the tree.
	if quoted == 0 || bracketed == 0 {
		t.Errorf("NON-VACUITY: of %d identical cells, %d carried an authored quote and %d "+
			"a bracketed list; a zero means the comparison below never looked at that mask",
			identical, quoted, bracketed)
	}
	t.Logf("#8921: %d of %d recorded (pair, site) cells fold to exactly the braced tree "+
		"(%d carry an authored quote, %d a bracketed list)", identical, cells, quoted, bracketed)
}

// censusCell8921 maps a #2419 census site onto the registry's cell key. The
// census renders an args slot as `name xpfarg` inside one element and an
// instance slot as `xpfname`; the registry spells the path with `/` and `*`. A
// site directly under an instance slot has no container keyword production
// would ask about, so it maps to nothing.
func censusCell8921(s compactSite) (string, bool) {
	if len(s.container) == 0 || strings.HasPrefix(s.container[0], "groups") {
		return "", false
	}
	path := make([]string, 0, len(s.container))
	kw := ""
	for _, el := range s.container {
		if el == "xpfname" {
			path = append(path, "*")
			kw = ""
			continue
		}
		kw = strings.Fields(el)[0]
		path = append(path, kw)
	}
	if kw == "" {
		return "", false
	}
	return kw + " " + s.leaf + " @ " + strings.Join(path, "/"), true
}

// TestMultisiteCellsAgreeWithTheCompiledCensus8921 cross-checks the premise the
// structural cell rests on: that nothing reads the tree before the fold, so an
// identical tree compiles identically. If a reader ran BEFORE the normalizer, a
// cell found structurally identical could still compile differently, and the
// #2419 census -- which compiles both spellings through the real compiler --
// would rule it divergent. Wherever the census rules a recorded cell at all, it
// must not say divergent.
func TestMultisiteCellsAgreeWithTheCompiledCensus8921(t *testing.T) {
	want := map[string]bool{}
	for pair, sites := range multisiteRegistry8921(t) {
		for _, s := range sites {
			want[pair+" @ "+s] = true
		}
	}
	res := runCompactBlockCensus(t)
	matched, equivalent := 0, 0
	var divergent []string
	for _, s := range collectCompactSites() {
		cell, ok := censusCell8921(s)
		if !ok || !want[cell] {
			continue
		}
		matched++
		switch res.state[strings.Join(s.container, " ")+" "+s.leaf] {
		case "equivalent":
			equivalent++
		case "divergent":
			divergent = append(divergent, cell)
		}
	}
	// MATCHER CONTROL. The first attempt to intersect these two instruments
	// reported a clean zero because the key mapping matched nothing; an agreement
	// over no cells is not an agreement.
	if equivalent == 0 {
		t.Fatalf("MATCHER CONTROL: %d census sites mapped onto recorded cells and none was "+
			"ruled equivalent; the key mapping is broken and this agreement is about "+
			"nothing", matched)
	}
	// One matched cell satisfies the control above, so mapper drift that dropped
	// most of them would still pass it. When this cell was written the census
	// reached 487 of 531 recorded cells; require that it still reaches a clear
	// majority, or the agreement below is about a sample nobody chose.
	if matched*4 < len(want)*3 {
		t.Errorf("MATCHER FLOOR: the census reaches only %d of %d recorded cells; the "+
			"mapping between the two instruments has drifted", matched, len(want))
	}
	sort.Strings(divergent)
	if len(divergent) > 0 {
		t.Errorf("#8921: the #2419 census compiles %d recorded cell(s) DIFFERENTLY in the two "+
			"spellings, while TestMultisiteAdmissionsFoldToTheBracedTree8921 requires the "+
			"fold to produce the braced tree at every one:\n  %s\n"+
			"If the structural cell is green, something reads the tree BEFORE the "+
			"normalizer and the per-site adjudication in this file is unsound -- find that "+
			"reader before touching either list.",
			len(divergent), strings.Join(divergent, "\n  "))
	}
	t.Logf("#8921: the #2419 census reaches %d of %d recorded cells and rules %d equivalent, "+
		"0 divergent; the rest are cells it cannot observe, which the structural cell "+
		"adjudicates without needing to", matched, len(want), equivalent)
}

// strictCompile8921 compiles through the STRICT (commit) path.
func strictCompile8921(t *testing.T, text string) error {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse: %v\n%s", errs, text)
	}
	_, err := CompileConfig(tree)
	return err
}

// TestElidedQuotedValueKeepsItsQuote8921 is the consequence the structural cell
// found. The fold moved Keys and left the per-key quote mask behind, so an
// authored quote was gone by the time the #9027 self-repeat gate asked for it.
// That gate refuses a multi-value run that repeats its own keyword unless the
// repeat is QUOTED -- the quote is how an operator says "this is a value that
// happens to be named `export`", not two statements missing a semicolon.
//
// Measured before the fix, at two admitted sites: the braced spelling committed
// and the elided spelling was refused with the self-repeat error. The
// `api-auth api-key` row is a credential.
func TestElidedQuotedValueKeepsItsQuote8921(t *testing.T) {
	const bgpPre = `routing-options { autonomous-system 65000; } ` +
		`policy-options { policy-statement A { then accept; } policy-statement export { then accept; } } `
	cases := []struct {
		name                                               string
		bracedBare, bracedQuoted, elidedBare, elidedQuoted string
	}{
		{
			name:         "protocols bgp group <g> export, a policy named export",
			bracedBare:   bgpPre + `protocols { bgp { group g1 { export A export; } } }`,
			bracedQuoted: bgpPre + `protocols { bgp { group g1 { export A "export"; } } }`,
			elidedBare:   bgpPre + `protocols { bgp { group g1 export A export; } }`,
			elidedQuoted: bgpPre + `protocols { bgp { group g1 export A "export"; } }`,
		},
		{
			name:         "system services web-management api-auth api-key, a credential",
			bracedBare:   `system { services { web-management { api-auth { api-key AAA api-key; } } } }`,
			bracedQuoted: `system { services { web-management { api-auth { api-key AAA "api-key"; } } } }`,
			elidedBare:   `system { services { web-management { api-auth api-key AAA api-key; } } }`,
			elidedQuoted: `system { services { web-management { api-auth api-key AAA "api-key"; } } }`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// CONTROLS. The gate must be observable at this site in BOTH spellings,
			// or an accepted elided spelling below would mean nothing: a bare repeat
			// is refused braced, and refused elided (so the elided value does reach
			// the gate), and a quoted repeat is accepted braced.
			if err := strictCompile8921(t, c.bracedBare); err == nil ||
				!strings.Contains(err.Error(), "repeats its own keyword") {
				t.Fatalf("CONTROL: the braced bare repeat was not refused by the #9027 gate "+
					"(err=%v), so this site cannot observe a lost quote", err)
			}
			if err := strictCompile8921(t, c.elidedBare); err == nil ||
				!strings.Contains(err.Error(), "repeats its own keyword") {
				t.Fatalf("CONTROL: the elided bare repeat was not refused (err=%v) -- the "+
					"elided value is not reaching the gate at all", err)
			}
			if err := strictCompile8921(t, c.bracedQuoted); err != nil {
				t.Fatalf("CONTROL: the braced QUOTED repeat was refused: %v", err)
			}
			if err := strictCompile8921(t, c.elidedQuoted); err != nil {
				t.Errorf("the elided spelling lost its authored quote on the way through the "+
					"brace-elision fold and was refused at commit, while the braced "+
					"spelling of the same statement commits: %v", err)
			}
		})
	}
}

// TestInstanceNamedLikeAnAdmittedKeyword8921 is the one way a statement directly
// under an instance slot DOES reach the predicate: production asks it with
// Keys[0], which there is the operator's instance name, so an interface named
// `interfaces` asks ("interfaces", "unit") -- an admitted pair. The fold then
// builds the braced tree of that statement, which is why the multi-site ratchet
// records no site at a slot: the collision exists and is structurally harmless.
func TestInstanceNamedLikeAnAdmittedKeyword8921(t *testing.T) {
	elided := parse8921(t, "elided", `interfaces { interfaces unit 0; }`)
	braced := parse8921(t, "braced", `interfaces { interfaces { unit 0; } }`)
	if elided == nil || braced == nil {
		return
	}
	if normalizeCompactStanzas(elided) == 0 {
		t.Fatal("CONTROL: the fold did not fire for an interface named `interfaces`, so " +
			"this cell no longer reaches the collision it documents")
	}
	if !sameTree8921(elided, braced) {
		t.Errorf("an interface named like an admitted container keyword does not fold to "+
			"its braced tree:\n  elided\n%s  braced\n%s", treeText8921(elided), treeText8921(braced))
	}
}

// TestBracedPackedRunKeepsItsQuotes8921 covers the second place the
// normalization pass builds statements out of a slice of someone else's Keys:
// splitBracedPackedChildren8886, which splits a run of statements authored on
// one line INSIDE a braced packedStatements container. It had the same shape as
// the fold -- Keys sliced, masks dropped -- and the structural cell above never
// reaches it, because every fixture there is a single statement.
func TestBracedPackedRunKeepsItsQuotes8921(t *testing.T) {
	// Both statements quoted, so the SECOND statement's mask is sliced at a
	// non-zero offset; and a bracketed list in second position, so the bracket
	// mask is sliced there too. A splitter that reset its running offset, or
	// carried only one of the two masks, passes a first-statement-only fixture.
	for _, c := range []struct{ name, run, separate string }{
		{"tunnel, both statements quoted",
			`interfaces { gr-0/0/0 { unit 0 { tunnel { source "10.0.0.1" destination "10.0.0.2"; } } } }`,
			`interfaces { gr-0/0/0 { unit 0 { tunnel { source "10.0.0.1"; destination "10.0.0.2"; } } } }`},
		// The list has ONE member because a packed run declines to split through
		// a multi-member list: each statement is placed by its declared args, and
		// a second member names no statement (measured: `proposals p1 p2` in a run
		// comes back whole). One bracketed member still puts a bracket mask at a
		// non-zero offset, which is what this case exists to exercise.
		{"ike policy, bracketed list second",
			`security { ike { policy P1 { pre-shared-key ascii-text "k" proposals [ "p1" ]; } } }`,
			`security { ike { policy P1 { pre-shared-key ascii-text "k"; proposals [ "p1" ]; } } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := parse8921(t, "packed run", c.run)
			two := parse8921(t, "separate statements", c.separate)
			if run == nil || two == nil {
				return
			}
			if n := normalizeCompactStanzas(run); n == 0 {
				t.Fatal("the packed run was not split, so this cell no longer reaches " +
					"splitBracedPackedChildren8886")
			}
			normalizeCompactStanzas(two)
			if !anyKey8921(two.Children, func(n *Node, i int) bool { return n.KeyQuoted(i) }) {
				t.Fatal("NON-VACUITY: the reference spelling carries no authored quote")
			}
			if !sameTree8921(run, two) {
				t.Errorf("a packed run split inside a braced container is not the tree of the "+
					"same statements written separately:\n  run\n%s  separate\n%s",
					treeText8921(run), treeText8921(two))
			}
		})
	}
}
