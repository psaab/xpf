package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #8807 predicate A (arity): the compiler reads a constant Keys[i] inside a
// `case "K":` clause where the schema's declaration of K cannot supply index i.
//
// WHAT THIS PREDICATE CANNOT SEE, stated here and repeated in every failure
// message, because a landed census guard READS AS COVERAGE:
//
//   It is NAME-KEYED. It pairs a compiler `case` label with schema declarations
//   that share that NAME, at any path. It cannot tell you the compiler site and
//   the declaration are the same path, and it therefore cannot see a leaf that
//   is undeclared at its own position while declared somewhere else. That is
//   the #8800 shape: `address` was unread-at-path under `nat source pool` while
//   declared under `proxy-arp interface` and elsewhere, so no name-keyed
//   predicate could surface it.
//
//   It also mis-ATTRIBUTES in the other direction. `preempt` was reported
//   because the chassis declaration (`children: nil`) was paired with the
//   INTERFACES compiler site, which handles `preempt hold-time <n>` packed.
//   Two self-consistent paths sharing a name; no defect. Of 12 hits at the time
//   of writing, SEVEN were pairings of this kind.
//
// So a green here means "no NEW name-keyed arity contradiction", never "the
// class is covered". The positional predicate is the thing that would cover it
// and it is not built (#8807, and #8787's closing note before that).

type arityDecl8807 struct {
	path     string
	args     int
	children int
	wildcard bool
}

// schemaLeafIndex8807 walks the LIVE schema -- children AND wildcard. A
// children-only walk reports named-instance subtrees (`interfaces <name> ...`,
// which hang off wildcard) as empty and calls everything beneath them
// undeclared; on #8787 that produced 56% noise.
func schemaLeafIndex8807() map[string][]arityDecl8807 {
	out := map[string][]arityDecl8807{}
	seen := map[*schemaNode]bool{}
	var walk func(n *schemaNode, path string)
	walk = func(n *schemaNode, path string) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		for k, c := range n.children {
			if c == nil {
				continue
			}
			p := path + "/" + k
			out[k] = append(out[k], arityDecl8807{p, c.args, len(c.children), c.wildcard != nil})
			walk(c, p)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+"/<*>")
		}
	}
	walk(setSchema, "")
	return out
}

// compilerCaseIndices8807 returns, per `case "K":` label, the highest constant
// index read from a Keys-like slice inside that clause.
func compilerCaseIndices8807(t *testing.T) map[string][]aritySite8807 {
	t.Helper()
	res := map[string][]aritySite8807{}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no compiler sources found (glob err %v) -- this cell measures "+
			"NOTHING if it cannot read them, which is indistinguishable from a "+
			"clean census", err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || strings.HasPrefix(f, "schema") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			continue
		}
		scanned++
		ast.Inspect(af, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			var kws []string
			for _, e := range cc.List {
				bl, ok := e.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				if s, err := strconv.Unquote(bl.Value); err == nil && s != "" {
					kws = append(kws, s)
				}
			}
			if len(kws) == 0 {
				return true
			}
			max := -1
			for _, stmt := range cc.Body {
				ast.Inspect(stmt, func(m ast.Node) bool {
					ix, ok := m.(*ast.IndexExpr)
					if !ok {
						return true
					}
					sel, ok := ix.X.(*ast.SelectorExpr)
					if !ok || !strings.Contains(sel.Sel.Name, "Keys") {
						return true
					}
					lit, ok := ix.Index.(*ast.BasicLit)
					if !ok || lit.Kind != token.INT {
						return true
					}
					if v, err := strconv.Atoi(lit.Value); err == nil && v > max {
						max = v
					}
					return true
				})
			}
			if max < 0 {
				return true
			}
			cont := enclosingContainer8807(af, cc)
			for _, kw := range kws {
				res[kw] = append(res[kw], aritySite8807{container: cont, maxIdx: max})
			}
			return true
		})
	}
	if scanned < 50 {
		t.Fatalf("only %d compiler files parsed -- too few for this census to mean "+
			"anything; a shrinking corpus makes the predicate go quiet, which "+
			"looks identical to a clean result", scanned)
	}
	return res
}

// aritySite8807 is ONE compiler case clause: the container whose children it
// iterates, and the highest constant Keys[i] it reads.
//
// The container is the cheapest available LOCALISATION and it is exactly what a
// name-keyed predicate lacks. It is recovered lexically -- the innermost
// enclosing range over FindChildren("X") -- so it is PARTIAL: a loop over a
// variable bound earlier, or over node.Children directly, yields no container
// and that site stays name-keyed. Adding it took the census from 12 hits to 6,
// and every row it removed was one this file had adjudicated as a false pairing
// or an already-fixed row.
type aritySite8807 struct {
	container string // "" when it could not be recovered
	maxIdx    int
}

// enclosingContainer8807 returns X from the innermost `range ... FindChildren("X")`
// enclosing cc, or "" if there is none.
func enclosingContainer8807(af *ast.File, cc *ast.CaseClause) string {
	var best string
	var bestPos token.Pos
	ast.Inspect(af, func(n ast.Node) bool {
		rs, ok := n.(*ast.RangeStmt)
		if !ok || rs.Body == nil {
			return true
		}
		if rs.Body.Pos() > cc.Pos() || rs.Body.End() < cc.End() {
			return true
		}
		var found string
		ast.Inspect(rs.X, func(m ast.Node) bool {
			ce, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "FindChildren" || len(ce.Args) != 1 {
				return true
			}
			if bl, ok := ce.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if v, err := strconv.Unquote(bl.Value); err == nil {
					found = v
				}
			}
			return true
		})
		if found != "" && rs.Body.Pos() >= bestPos {
			best, bestPos = found, rs.Body.Pos()
		}
		return true
	})
	return best
}

type arityHit8807 struct {
	kw      string
	maxIdx  int
	minArgs int
	maxArgs int
	paths   []string
}

// arityCensusHits8807 runs the predicate. Both aggregations are computed
// because NEITHER IS CORRECT:
//
//	min-args reports a keyword when ANY declaration is narrower than the index
//	the compiler reads -- so a FIXED defect keeps firing forever whenever a
//	sibling path legitimately takes fewer tokens. `pre-shared-key` still
//	appears after #8777 fixed it, because `security ipsec vpn pre-shared-key`
//	is args:1 and CORRECT there. A control that still fires after its own fix
//	cannot distinguish fixed from broken, which is why #8787's
//	"control-validated" claim for this predicate was itself unsound.
//
//	max-args reports only when EVERY declaration is too narrow, so it cannot
//	see a per-path defect standing beside a correct sibling -- the #8800 shape.
//
// Reporting both bounds the honest answer instead of picking the aggregation
// that flatters the census.
func arityCensusHits8807(t *testing.T) []arityHit8807 {
	t.Helper()
	idx := schemaLeafIndex8807()
	cases := compilerCaseIndices8807(t)
	var hits []arityHit8807
	for kw, sites := range cases {
		decls, ok := idx[kw]
		if !ok {
			continue // predicate B (existence) territory, not A
		}
		// CONTAINER-KEYED FILTER. A site whose container is recoverable is
		// compared only against declarations under a node of that name. This is
		// what stops a compiler site at one path being paired with a schema leaf
		// at another, and it is what makes the control trustworthy again:
		// `pre-shared-key` kept firing after #8777 fixed it because a CORRECT
		// args:1 sibling at `security ipsec vpn` matched by name, and a control
		// that still fires after its own fix cannot distinguish fixed from
		// broken. Sites with no recoverable container stay name-keyed.
		maxIdx := 0
		conts := map[string]bool{}
		anyUnlocalised := false
		for _, st := range sites {
			if st.container == "" {
				anyUnlocalised = true
				if st.maxIdx > maxIdx {
					maxIdx = st.maxIdx
				}
				continue
			}
			conts[st.container] = true
			relevant := false
			for _, d := range decls {
				if strings.Contains(d.path, "/"+st.container+"/") && strings.HasSuffix(d.path, "/"+kw) {
					relevant = true
					break
				}
			}
			if relevant && st.maxIdx > maxIdx {
				maxIdx = st.maxIdx
			}
		}
		if maxIdx == 0 {
			continue
		}
		// TRUE LEAVES only. A container's next token is a child keyword, so
		// args:0 plus reading Keys[1] is legitimate packed handling, not a
		// defect (#8787: this filter took 21 -> 17 and its control survived it).
		minArgs, maxArgs, anyLeaf := 1<<30, -1, false
		var paths []string
		for _, d := range decls {
			if d.children != 0 || d.wildcard {
				continue
			}
			if !anyUnlocalised && len(conts) > 0 {
				match := false
				for c := range conts {
					if strings.Contains(d.path, "/"+c+"/") {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			anyLeaf = true
			paths = append(paths, d.path+" args="+strconv.Itoa(d.args))
			if d.args < minArgs {
				minArgs = d.args
			}
			if d.args > maxArgs {
				maxArgs = d.args
			}
		}
		if !anyLeaf || maxIdx <= minArgs {
			continue
		}
		sort.Strings(paths)
		hits = append(hits, arityHit8807{kw, maxIdx, minArgs, maxArgs, paths})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].kw < hits[j].kw })
	return hits
}

// arityVerdict8807 is the hand adjudication of each hit. The predicate cannot
// produce these: deciding whether a compiler site and a schema declaration are
// the SAME PATH requires reading both, which is exactly the localisation a
// name-keyed predicate lacks.
type arityVerdict8807 struct {
	state string // "false-pairing" | "already-fixed" | "genuine"
	why   string
}

// States, and why "genuine" is not "defect":
//
//	false-pairing  the compiler site and the matched schema leaf are DIFFERENT
//	               paths sharing a name. No defect at either.
//	already-fixed  correct at the path the compiler reads; a sibling path
//	               legitimately declares fewer tokens, which is what keeps the
//	               min-args aggregation firing.
//	genuine        the site and the declaration plausibly coincide and it has
//	               NOT been measured. A candidate, not a finding -- #8787's
//	               `tcp-mss` rows looked identical to drops and turned out to be
//	               LOUD rejections, so two of its first six would have been
//	               over-reported by trusting the predicate.
//
// Deliberately UNORDERED and carrying no confidence ranking. `preempt` was
// ranked the strongest candidate here because its compiler comment explicitly
// documents the packed `Keys[1:]` form -- and that is precisely the evidence a
// name-keyed predicate cannot attribute to a path. A rich, specific comment
// raises confidence and localises nothing, so the ranking was the least
// reliable output this census produced. Order candidates by what a measurement
// finds, not by how convincing their evidence reads.
var arityAdjudicated8807 = map[string]arityVerdict8807{
	// The three remaining false pairings are ALL sites whose container could not
	// be recovered lexically, so they are still name-keyed. That is the residual
	// blindness of the CONTAINER-keyed predicate and it belongs next to the
	// ratchet, not in someone's notes.
	//
	// WHAT MAKES THEM UNLOCALISABLE: enclosingContainer8807 recovers a container
	// only from an enclosing `range ... FindChildren("X")`. These four sites
	// iterate something else --
	//
	//   - a bare `range node.Children` / `range prop.Children`, where the
	//     container is whatever the caller passed and is not written at the site
	//     at all (`count`, `reject`, `then`);
	//   - a variable bound further up the function, so the literal container
	//     name is nowhere in the enclosing range expression (`from-zone`,
	//     `interface`, `pool`, `match`).
	//
	// Recovering those needs the call path, not a lexical walk -- which is
	// exactly the positional predicate this issue exists to build, and the
	"from-zone": {"false-pairing", "the site is the top-level `security policies from-zone <z> to-zone <z>` " +
		"container reading Keys[3]; the matched leaf is `global/policy/match/from-zone` args:1, correct there."},
	"interface": {"false-pairing", "compiler_protocols.go reads Keys[1] on a protocols interface; the args:0 leaf " +
		"matched is `nat source rule-set rule then source-nat interface`."},
	"pool": {"false-pairing", "compiler_services.go reads Keys[4] on the DHCP-server pool; the matched leaves are " +
		"NAT pools args:1. The NAT pools' real defect was existence, not arity (#8800)."},

	"description": {"false-pairing", "compiler_security_addressbook.go (packed address-book statements, #12831) reads " +
		"Keys[2:], Keys[4], Keys[5:], Keys[3:] inside `description` case clauses: those indices address the PACKED " +
		"member tail (address/address-set statements following the description value), never the description leaf's own " +
		"args:1 value. Unknown tail tokens are recorded as unknown members and fail closed (strict undefined-member, " +
		"lenient poison), so no description argument is dropped or widened by the higher reads."},

	"reject": {"measured-benign", "same path, real arity mismatch -- compiler_firewall.go:1337 reads an OPTIONAL " +
		"Keys[1] message-type on `then reject <type>` while the leaf is args:0. MEASURED by lane-8015 with an absent " +
		"baseline: every spelling delivers, and a bogus message-type is a LOUD commit rejection via the " +
		"UnknownActions path rather than a silent drop. No defect. The residue is that COMPLETION under-offers, " +
		"because the compiler is ahead of the schema -- the mirror of the #8773 rule."},
	// `then` WAS HERE AND IS GONE BECAUSE IT WAS FIXED, not because the
	// instrument stopped seeing it — which this cell rightly demands be
	// distinguished before the entry is deleted.
	//
	// The predicate flagged `/policy-options/policy-statement/then` as a bare
	// leaf whose compiler (compiler_routing.go:908) iterates children it did not
	// declare. The schema now declares those two children (accept, reject), so
	// the node is no longer a bare leaf and the predicate correctly stops
	// matching. The mismatch is resolved rather than hidden.
	//
	// THE CONTROL that separates those two readings: `reject` is STILL reported
	// by this census in the same run. If the compiler-file glob or the schema
	// walk had broken, both would have vanished together. One leaving while its
	// sibling stays is what a real fix looks like from here.
	//
	// The completion residue that made it worth fixing is recorded on `reject`
	// below, which keeps it: the compiler was AHEAD of the schema, so nothing
	// dropped and `?` help under-offered instead — the mirror of the #8773 rule.
	"preempt": {"measured-benign", "#15199: the combined `virtual-address, virtual-inet6-address` case in parseVRRPGroups reads Keys[i+2] while scanning a packed run, so the name-keyed predicate re-attributes that index to the sibling `preempt` case in the same switch. The preempt sites themselves read only the documented optional `hold-time <n>` pair (braced child or Keys[1:]/Keys[2] packed form, both declared under preempt in the schema); braced and packed spellings compile identically (vrrp tests). No argument is dropped."},
}

// arityGenuineFloor8807 is a RATCHET, not an equality. It fails in BOTH
// directions on purpose: a rise means a new unadjudicated candidate, and a DROP
// means candidates were resolved and this constant must be tightened so the
// next regression has no slack to hide in (the #7484 shape).
// Tightened 2 -> 0 the first time this ratchet fired for real: lane-8015
// measured `reject` and `then` and both are benign, so the census stands at
// 12 hits and ZERO defects. Do not read that as "the predicate found
// nothing useful" -- it found that a whole predicate produced no defects,
// which is a result, and it produced one real residue (completion
// under-offers for both leaves, because the compiler is AHEAD of the
// schema -- the mirror of the #8773 rule).
const arityGenuineFloor8807 = 0

func TestArityCensusIsRatcheted8807(t *testing.T) {
	hits := arityCensusHits8807(t)
	live := map[string]bool{}
	for _, h := range hits {
		live[h.kw] = true
	}

	const blindness = "\n\nWHAT THIS PREDICATE CANNOT SEE: it is NAME-KEYED. It pairs a " +
		"compiler `case` label with schema declarations that share that NAME, and it " +
		"localises a site ONLY when the enclosing FindChildren container can be " +
		"recovered lexically. Sites iterating a variable, or node.Children directly, " +
		"yield no container and stay fully name-keyed -- all four false pairings still " +
		"listed here are of that kind. And in EITHER mode it is blind to a leaf that is " +
		"undeclared at its OWN position while declared elsewhere, because it can only " +
		"pair with declarations that EXIST: that is the #8800 shape (`address` " +
		"unread-at-path under `nat source pool`, declared under `proxy-arp interface`), " +
		"and no arity predicate can see it because it is an EXISTENCE question. So " +
		"GREEN MEANS \"no new arity contradiction this predicate can localise\", NEVER " +
		"\"the class is covered\". The positional predicate is not built (#8807).\n\n" +
		"THIRD BLINDNESS, found by lane-8015 while checking a row here: it only sees a " +
		"CONSTANT Keys[i]. A site consuming a following token through a VARIABLE index " +
		"-- parsePolicyTermInlineKeys at compiler_routing.go:1269 does `i++; " +
		"term.Action = keys[i]` -- is invisible to it. So a keyword can have sites this " +
		"predicate reports AND sites it cannot see, and the evidence recorded for a row " +
		"may describe only the visible half."

	// 1. The hit SET must match the adjudication. A new hit is unadjudicated and
	//    nobody can tell from the number whether it is a defect.
	var added, removed []string
	for kw := range live {
		if _, ok := arityAdjudicated8807[kw]; !ok {
			added = append(added, kw)
		}
	}
	for kw := range arityAdjudicated8807 {
		if !live[kw] {
			removed = append(removed, kw)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		t.Errorf("UNADJUDICATED arity-census hit(s): %v\n"+
			"A hit is a CANDIDATE, not a defect. Read the compiler site and the "+
			"schema leaf and confirm THEY ARE THE SAME PATH before doing anything "+
			"else -- that one grep is what refuted `preempt`, the row previously "+
			"ranked strongest here. Then measure braced-vs-packed before assigning "+
			"a verdict: #8787's `tcp-mss` rows looked like drops and were LOUD "+
			"rejections. Add it to arityAdjudicated8807 with its evidence.%s",
			added, blindness)
	}
	if len(removed) > 0 {
		t.Errorf("arity-census hit(s) GONE: %v\n"+
			"If they were fixed, delete them here and TIGHTEN arityGenuineFloor8807. "+
			"If they vanished because the instrument stopped seeing them, that is a "+
			"broken instrument reading as progress -- check the compiler-file glob "+
			"and the schema walk before believing it.%s", removed, blindness)
	}

	// 2. The GENUINE count is ratcheted in both directions.
	genuine := []string{}
	for kw, v := range arityAdjudicated8807 {
		if v.state == "genuine" && live[kw] {
			genuine = append(genuine, kw)
		}
	}
	sort.Strings(genuine)
	if len(genuine) > arityGenuineFloor8807 {
		t.Errorf("genuine arity candidates ROSE to %d (%v), floor is %d.%s",
			len(genuine), genuine, arityGenuineFloor8807, blindness)
	}
	if len(genuine) < arityGenuineFloor8807 {
		t.Errorf("genuine arity candidates FELL to %d (%v) -- THIS IS A GOOD FAILURE.\n"+
			"Set arityGenuineFloor8807 = %d. Leaving it at %d gives the next "+
			"regression that much room to hide.%s",
			len(genuine), genuine, len(genuine), arityGenuineFloor8807, blindness)
	}
}

// schemaNodeAt8807 resolves a schema node by explicit path segments, so a
// mutation control names the PATH it breaks rather than a keyword. "<*>"
// selects the wildcard child.
func schemaNodeAt8807(t *testing.T, segs ...string) *schemaNode {
	t.Helper()
	n := setSchema
	for _, s := range segs {
		if n == nil {
			t.Fatalf("path %v does not resolve at %q", segs, s)
		}
		if s == "<*>" {
			n = n.wildcard
			continue
		}
		n = n.children[s]
	}
	if n == nil {
		t.Fatalf("path %v resolves to nil", segs)
	}
	return n
}

// TestArityCensusMutationControl8807 is what makes every number above
// falsifiable. The predicate's ORIGINAL control (`pre-shared-key`, #8787) is
// worse than useless today: it still fires after #8777 fixed it, because
// min-args aggregation picks up a CORRECT sibling at args:1. A control that
// still fires after its own fix cannot distinguish fixed from broken.
//
// So the control is a MUTATION: re-break #8796 by narrowing both `gateway
// local-identity` declarations, and require the row to change state.
//
// BOTH HALVES ARE ASSERTED IN ONE RUN, and either alone would be satisfiable by
// a dead instrument: "fires when broken" is satisfied by something that always
// fires, and "quiet when whole" by something that never does. The same shape as
// an advisory that must fire for one input and not for another, or an allowlist
// that must admit inside and deny outside.
func TestArityCensusMutationControl8807(t *testing.T) {
	paths := [][]string{
		{"security", "ike", "gateway", "local-identity"},
		{"security", "ipsec", "gateway", "local-identity"},
	}
	nodes := make([]*schemaNode, 0, len(paths))
	for _, p := range paths {
		nodes = append(nodes, schemaNodeAt8807(t, p...))
	}

	fires := func() bool {
		for _, h := range arityCensusHits8807(t) {
			// The DISCRIMINATING signal is the conservative aggregation: with
			// #8796 in place `local-identity` still appears under min-args
			// (the ipsec-vpn sibling is args:1 and correct), so only max-args
			// separates "fixed" from "broken" here.
			if h.kw == "local-identity" && h.maxIdx > h.maxArgs {
				return true
			}
		}
		return false
	}

	// DECLINE half: whole tree, the row must NOT fire under max-args.
	if fires() {
		t.Fatalf("`local-identity` fires under the conservative aggregation on an " +
			"UNMUTATED tree. Either #8796 has regressed -- both `security ike " +
			"gateway <g> local-identity` and `security ipsec gateway <g> " +
			"local-identity` should be args:2 -- or this control now measures " +
			"something else and every count in this file is unfalsifiable.")
	}

	// ACCEPT half: re-break it and require the row to appear.
	saved := make([]int, len(nodes))
	for i, n := range nodes {
		saved[i] = n.args
		if n.args != 2 {
			t.Fatalf("mutation control expected args:2 at %v, found %d -- the "+
				"control is anchored to a declaration that has changed shape and "+
				"must be re-derived, not adjusted", paths[i], n.args)
		}
		n.args = 1
	}
	broken := fires()
	for i, n := range nodes {
		n.args = saved[i]
	}
	if !broken {
		t.Errorf("MUTATION SURVIVED: narrowing both `gateway local-identity` " +
			"declarations to args:1 -- exactly the #8796 defect -- did not make " +
			"the census report it. The predicate is not detecting the thing it " +
			"claims to detect, so every count in this file is a number generator.")
	}

	// And the restore must actually restore, or the next cell inherits a
	// mutated schema and its green means nothing.
	if fires() {
		t.Fatalf("the mutation control did NOT restore the schema; subsequent " +
			"tests in this package are running against a broken tree")
	}
}
