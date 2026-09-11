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

// #8807, the POSITIONAL predicate: a head the compiler READS at container P
// that the schema does not declare AT P, while declaring it somewhere else.
//
// That last clause is the whole point. A head declared NOWHERE is #8787's
// predicate B and was already enumerated by it. A head declared somewhere but
// missing at the path the compiler reads it is what every keyword-anywhere
// check passes silently -- and it is the #8800 shape, where `address` was
// unread-at-path under `nat source pool` while declared under `proxy-arp
// interface` and others. #8825 was found by this predicate.
//
// WHAT IT CANNOT SEE, repeated in the failure text because a landed census
// guard reads as coverage:
//
//   CONTAINER RECOVERY IS PARTIAL. A site is localised only when its immediate
//   enclosing range iterates the DIRECT children of a FindChildren("X") loop
//   variable. Roughly a third of clauses qualify; the rest are invisible, not
//   clean.
//
//   CONTAINERS ARE MATCHED BY NAME, NOT PATH. Two schema nodes sharing a
//   container name are pooled, so a head declared under either satisfies both.
//   `pool` happens to be unambiguous; `family` and `group` are not.
//
//   IT IS AN EXISTENCE PREDICATE ONLY. It says nothing about arity, and
//   nothing about whether a declared-and-read head is actually HELD by a
//   struct field -- that is #8785's shape and it defeated predicate C five
//   times.

// rangeInfo8807 is one range statement: the FindChildren container it iterates
// (empty if none) and its value variable.
type rangeInfo8807 struct {
	node *ast.RangeStmt
	fc   string
	val  string
}

type posSite8807 struct {
	container string
	head      string
	file      string
}

// positionalSites8807 collects every case clause of every switch whose tag is a
// call to .Name() -- i.e. dispatching on a config node's keyword rather than on
// a value.
//
// It deliberately does NOT reuse the arity census's collector: that one records
// only clauses containing a constant Keys[i], which is the arity-shaped subset.
// The #8800 site reads `prop.Keys[1:]`, a SLICE, so the arity collector never
// saw it and the first version of this predicate FAILED its own #8800 control
// while looking like it worked.
func positionalSites8807(t *testing.T) []posSite8807 {
	t.Helper()
	var out []posSite8807
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no compiler sources found (glob err %v): this cell measures "+
			"nothing if it cannot read them, which is indistinguishable from a "+
			"clean result", err)
	}
	parsed := 0
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
		parsed++

		// Index every range statement with the FindChildren container it
		// iterates (if any) and its value variable.
		var ranges []rangeInfo8807
		ast.Inspect(af, func(nd ast.Node) bool {
			rs, ok := nd.(*ast.RangeStmt)
			if !ok {
				return true
			}
			var fc string
			ast.Inspect(rs.X, func(m ast.Node) bool {
				ce, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				se, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok || se.Sel.Name != "FindChildren" || len(ce.Args) != 1 {
					return true
				}
				if bl, ok := ce.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if v, err := strconv.Unquote(bl.Value); err == nil {
						fc = v
					}
				}
				return true
			})
			val := ""
			if id, ok := rs.Value.(*ast.Ident); ok {
				val = id.Name
			}
			ranges = append(ranges, rangeInfo8807{rs, fc, val})
			return true
		})

		ast.Inspect(af, func(nd ast.Node) bool {
			sw, ok := nd.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil {
				return true
			}
			ce, ok := sw.Tag.(*ast.CallExpr)
			if !ok {
				return true
			}
			if se, ok := ce.Fun.(*ast.SelectorExpr); !ok || se.Sel.Name != "Name" {
				return true
			}
			cont := containerForSwitch8807(ranges, sw)
			for _, st := range sw.Body.List {
				cc, ok := st.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, e := range cc.List {
					bl, ok := e.(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(bl.Value); err == nil && v != "" {
						out = append(out, posSite8807{cont, v, f})
					}
				}
			}
			return true
		})
	}
	if parsed < 50 {
		t.Fatalf("only %d compiler files parsed: too few for this census to mean "+
			"anything, and a shrinking corpus makes the predicate go quiet, which "+
			"looks identical to a clean result", parsed)
	}
	return out
}

// containerForSwitch8807 requires the switch's IMMEDIATE enclosing range to
// iterate the DIRECT children of a FindChildren loop variable. Accepting the
// nearest enclosing FindChildren instead names an ANCESTOR whenever the switch
// operates on a deeper node, which produced 104 hits with obvious noise
// (`ids-option / ping-death`) before this was tightened to 5.
func containerForSwitch8807(ranges []rangeInfo8807, sw *ast.SwitchStmt) string {
	var imm *rangeInfo8807
	for i := range ranges {
		r := &ranges[i]
		if r.node.Body == nil || r.node.Body.Pos() > sw.Pos() || r.node.Body.End() < sw.End() {
			continue
		}
		if imm == nil || r.node.Body.Pos() > imm.node.Body.Pos() {
			imm = r
		}
	}
	if imm == nil {
		return ""
	}
	// `range <v>.Children` or `range <v>.node.Children`, AND through a
	// wrapping call: `range expandFlatRun(<v>.Children, schema)`.
	//
	// #8939 THREADS EVERY CHILDREN LOOP IT FIXES THROUGH expandFlatRun, and
	// without the call case that rewrite silently DELETES this predicate's
	// coverage of the container -- the range expression stops being a
	// SelectorExpr, container recovery returns "", and every site in the
	// switch drops out. It is not hypothetical: it took `vpn`'s recovered
	// read set to empty, which pushed the container under
	// converseCoverage8807 and removed the pinned `vpn / traffic-selector`
	// row. The ratchet reported that as unmeasured rows FALLING -- a good
	// failure that reads exactly like progress. Tightening the constant would
	// have BANKED the loss.
	base := baseChildrenIdent8807(imm.node.X)
	if base == "" {
		return imm.fc // the range itself is the FindChildren loop
	}
	for i := range ranges {
		r := &ranges[i]
		if r.fc == "" || r.val != base {
			continue
		}
		if r.node.Body != nil && r.node.Body.Pos() <= sw.Pos() && r.node.Body.End() >= sw.End() {
			return r.fc
		}
	}
	return ""
}

// baseChildrenIdent8807 recovers the loop variable of a `<v>.Children` /
// `<v>.node.Children` range expression, looking THROUGH any wrapping call so a
// helper interposed between the loop and the node list does not blind the
// predicate. Returns "" when the range is not over some node's children.
func baseChildrenIdent8807(x ast.Expr) string {
	switch e := x.(type) {
	case *ast.SelectorExpr:
		if e.Sel.Name != "Children" {
			return ""
		}
		switch b := e.X.(type) {
		case *ast.Ident:
			return b.Name
		case *ast.SelectorExpr:
			if id, ok := b.X.(*ast.Ident); ok {
				return id.Name
			}
		}
	case *ast.CallExpr:
		// The node list is an ARGUMENT of the wrapper, not its result.
		for _, a := range e.Args {
			if v := baseChildrenIdent8807(a); v != "" {
				return v
			}
		}
	}
	return ""
}

// containerDeclares8807 maps a schema node NAME to the set of child keywords
// declared under any node of that name.
//
// seen is keyed by (node, NAME): a node reached under two different container
// names must record its children under BOTH. Keying on the node alone made
// `application-set` report zero children and produced three false hits.
func containerDeclares8807() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	type nk struct {
		n    *schemaNode
		name string
	}
	seen := map[nk]bool{}
	var walk func(n *schemaNode, name string)
	walk = func(n *schemaNode, name string) {
		if n == nil || seen[nk{n, name}] {
			return
		}
		seen[nk{n, name}] = true
		if out[name] == nil {
			out[name] = map[string]bool{}
		}
		for k, c := range n.children {
			out[name][k] = true
			walk(c, k)
		}
		if n.wildcard != nil {
			walk(n.wildcard, name)
		}
	}
	walk(setSchema, "<root>")
	return out
}

// positionalHits8807 returns "container / head" for every site read at a
// container that does not declare the head, where the head IS declared
// elsewhere.
func positionalHits8807(t *testing.T) []string {
	t.Helper()
	decl := containerDeclares8807()
	anywhere := map[string]bool{}
	for _, heads := range decl {
		for h := range heads {
			anywhere[h] = true
		}
	}
	set := map[string]bool{}
	for _, s := range positionalSites8807(t) {
		if s.container == "" {
			continue
		}
		if heads, ok := decl[s.container]; ok && heads[s.head] {
			continue
		}
		if !anywhere[s.head] {
			continue // declared nowhere: #8787 predicate B, already enumerated
		}
		set[s.container+" / "+s.head] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// posVerdict8807 is the hand adjudication. The predicate cannot produce these:
// deciding whether an undeclared-at-path head actually LOSES a value requires
// compiling both spellings, and #8787's `tcp-mss` rows proved the distinction
// matters -- two of its first six looked like drops and were LOUD rejections.
type posVerdict8807 struct {
	state string // "defect" | "benign" | "known"
	why   string
}

var posAdjudicated8807 = map[string]posVerdict8807{
	// `application-set / application` and `application-set / application-set`
	// were here as #8825 defects and are GONE because #8825 declared them.
	// The ratchet reported them as removed and demanded the floor be
	// tightened, which is the mechanism working: a fixed row must not leave
	// slack behind. `application-set / description` stays -- it is still
	// undeclared, and still benign, because the value lands nowhere by design.
	// MEASURED SEPARATELY, and it is NOT a defect -- which is why the three
	// heads under this one node had to be measured one at a time rather than
	// inherited from `application`. compileApplications accepts `description`
	// deliberately, "without adding a member and without flagging it", and
	// ApplicationSet has NO Description field: the value lands NOWHERE by
	// design. Both spellings compile to members=[] -- identical. Declaring it
	// would move completion and validation and change no compiled result.
	//
	// This is #8830's distinction applied to a fix rather than to an
	// instrument: "a clause exists" and "the value lands somewhere" are
	// different questions, and here the clause exists and the value lands
	// nowhere ON PURPOSE.
	"application-set / description": {"benign", "MEASURED: both spellings compile to members=[], identical. " +
		"compileApplications accepts `description` deliberately without recording it, and ApplicationSet has no " +
		"Description field -- the value lands nowhere by design, so no spelling can lose it."},

	"vpn / gateway": {"benign", "MEASURED: `security ipsec vpn <v> { gateway g; }` and the `ike { gateway g; }` " +
		"nesting compile IDENTICALLY (gateway=\"gw1\" both ways, strict accepts both). The compiler accepts the head " +
		"at vpn level as well as under `ike`, and the schema declares only the nested form. Nothing is lost, so this " +
		"is a declaration gap with no behavioural consequence."},
	"vpn / ipsec-policy": {"benign", "MEASURED alongside `vpn / gateway`, identical in both spellings."},
}

// posDefectFloor8807 is a RATCHET. It fails in BOTH directions: a rise means an
// unadjudicated positional hit, and a DROP means one was fixed and this must be
// tightened so the next regression has no slack to hide in (#7484's shape).
const posDefectFloor8807 = 0

const posBlindness8807 = "\n\nWHAT THIS PREDICATE CANNOT SEE:\n" +
	"  (1) CONTAINER RECOVERY IS PARTIAL. A site is localised only when its immediate " +
	"enclosing range iterates the DIRECT children of a FindChildren(\"X\") loop variable. " +
	"About a third of clauses qualify; the rest are INVISIBLE, not clean.\n" +
	"  (2) CONTAINERS ARE MATCHED BY NAME, NOT PATH. Two schema nodes sharing a container " +
	"name are pooled, so a head declared under either satisfies both. `pool` is " +
	"unambiguous; `family` and `group` are not.\n" +
	"  (3) EXISTENCE ONLY. It says nothing about arity (that is the #8807 arity census), " +
	"and nothing about whether a declared-and-read head is actually HELD by a struct " +
	"field -- #8785's shape, which defeated predicate C five times.\n" +
	"  (4) A head declared NOWHERE is excluded by design: that is #8787's predicate B, " +
	"already enumerated there.\n" +
	"  (5) FALSE NEGATIVE, and this is the serious one. The converse marks a head as " +
	"READ if any .Name() clause at that container names it. It never checks that the " +
	"clause does anything with the value, so a clause that reads into NOTHING is " +
	"scored as a read and the row goes quiet -- which is #8785's own defect with a " +
	"clause in front of it. `description` under `security ike proposal` is caught " +
	"ONLY because no clause exists. The #8785 control therefore proves SENSITIVITY, " +
	"not soundness: that the instrument fires when it should, never that it fires " +
	"ONLY when it should. Answering \"unread\" properly means comparing whole " +
	"compiled results with and without the statement, warnings included -- a " +
	"behavioural predicate, not an AST one.\n" +
	"So GREEN MEANS \"no new positional gap this predicate can localise\", NEVER \"the class " +
	"is covered\".\n\n" +
	"TWO INSTRUMENT BUGS THAT PRODUCED CONFIDENT WRONG ANSWERS HERE, so the next person " +
	"changing this cell is told rather than rediscovering:\n" +
	"  (a) DO NOT REUSE THE ARITY CENSUS SITE COLLECTOR. compilerCaseIndices8807 records " +
	"only clauses containing a CONSTANT Keys[i] -- the arity-shaped subset. The #8800 " +
	"site reads `prop.Keys[1:]`, a SLICE, so that collector never sees it and this " +
	"predicate FAILS its own #8800 control while otherwise looking like it works. An " +
	"existence predicate needs every clause of every .Name() switch. That is the same " +
	"shape as predicate A's `pre-shared-key` control, which kept firing after its fix: a " +
	"control that cannot discriminate reads as diligence.\n" +
	"  (b) KEY THE SCHEMA WALK ON (node, NAME), NOT node. A schema node reached under a " +
	"second container name must record its children under BOTH; keying on the node alone " +
	"made `application-set` report zero children and manufactured three false hits. A walk " +
	"with that bug is a false-positive generator, and its hits cannot be adjudicated."

func TestPositionalPredicateIsRatcheted8807(t *testing.T) {
	hits := positionalHits8807(t)
	live := map[string]bool{}
	for _, h := range hits {
		live[h] = true
	}
	var added, removed []string
	for h := range live {
		if _, ok := posAdjudicated8807[h]; !ok {
			added = append(added, h)
		}
	}
	for h := range posAdjudicated8807 {
		if !live[h] {
			removed = append(removed, h)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	if len(added) > 0 {
		t.Errorf("UNADJUDICATED positional hit(s): %v\n"+
			"A hit is a CANDIDATE, not a defect. COMPILE BOTH SPELLINGS before "+
			"assigning a verdict -- of the first five hits here, two were benign "+
			"(the compiler accepted the head at both nestings and nothing was "+
			"lost), so trusting the predicate would have over-reported by 40%%. "+
			"Add it to posAdjudicated8807 with the measurement.%s", added, posBlindness8807)
	}
	if len(removed) > 0 {
		t.Errorf("positional hit(s) GONE: %v\n"+
			"If the declaration was added, delete the row here and TIGHTEN "+
			"posDefectFloor8807. If they vanished because the instrument stopped "+
			"seeing them, that is a broken instrument reading as progress -- check "+
			"the compiler-file glob and the container recovery before believing "+
			"it.%s", removed, posBlindness8807)
	}

	defects := []string{}
	for h, v := range posAdjudicated8807 {
		if v.state == "defect" && live[h] {
			defects = append(defects, h)
		}
	}
	sort.Strings(defects)
	if len(defects) > posDefectFloor8807 {
		t.Errorf("positional DEFECTS rose to %d (%v), floor %d.%s",
			len(defects), defects, posDefectFloor8807, posBlindness8807)
	}
	if len(defects) < posDefectFloor8807 {
		t.Errorf("positional defects FELL to %d (%v) -- THIS IS A GOOD FAILURE.\n"+
			"Set posDefectFloor8807 = %d. Leaving it at %d gives the next "+
			"regression that much room to hide.%s",
			len(defects), defects, len(defects), posDefectFloor8807, posBlindness8807)
	}
}

// TestPositionalPredicateControl8807 is the acceptance criterion from #8807:
// the instrument must RE-FIND #8800, the case that distinguishes a positional
// predicate from a keyword-anywhere one. `address` is declared under
// `proxy-arp interface` and elsewhere, so a keyword-anywhere check passes it
// silently.
//
// BOTH HALVES RUN HERE, and either alone is satisfiable by a dead instrument:
// "reports it when broken" by something that always reports, "quiet when whole"
// by something that never does.
func TestPositionalPredicateControl8807(t *testing.T) {
	has := func(want string) bool {
		for _, h := range positionalHits8807(t) {
			if h == want {
				return true
			}
		}
		return false
	}

	// DECLINE half.
	if has("pool / address") {
		t.Fatalf("`pool / address` reported on an UNMUTATED tree: either #8800 has " +
			"regressed -- `address` should be declared under both `security nat " +
			"source pool` and `security nat destination pool` -- or this control " +
			"measures something else and every count in this file is unfalsifiable.")
	}

	// ACCEPT half: reproduce #8800 by removing the declarations.
	nat := setSchema.children["security"].children["nat"]
	if nat == nil {
		t.Fatal("security/nat not found: the control is anchored to a path that has moved")
	}
	src := nat.children["source"].children["pool"]
	dst := nat.children["destination"].children["pool"]
	if src == nil || dst == nil {
		t.Fatal("NAT pool nodes not found: re-derive this control, do not adjust it")
	}
	sa, da := src.children["address"], dst.children["address"]
	if sa == nil || da == nil {
		t.Fatalf("expected `address` declared under both NAT pools (source=%v destination=%v); "+
			"#8800 and its follow-up landed both and this control depends on them",
			sa != nil, da != nil)
	}
	delete(src.children, "address")
	delete(dst.children, "address")
	found := has("pool / address")
	src.children["address"], dst.children["address"] = sa, da

	if !found {
		t.Errorf("MUTATION SURVIVED: removing the `address` declaration from both NAT " +
			"pools -- exactly the #8800 defect -- did not make the predicate report " +
			"`pool / address`. It is not detecting the thing it claims to detect, so " +
			"every count in this file is a number generator.\n" +
			"The first version of this predicate failed here for a specific reason " +
			"worth checking first: it reused the ARITY census's site collector, which " +
			"records only clauses containing a constant Keys[i]. The #8800 site reads " +
			"`prop.Keys[1:]`, a SLICE, so that collector never saw it.")
	}
	// The restore must restore, or every later cell runs against a broken tree.
	if has("pool / address") {
		t.Fatal("the control did NOT restore the schema; subsequent tests in this package are compromised")
	}
}

// ---------------------------------------------------------------------------
// #8807 direction 2, the CONVERSE: declared at position P and UNREAD at P.
//
// This is the predicate that defeated #8787's predicate C five times, and the
// reason is #8785: `description` is DECLARED under `security ike proposal`, and
// the defect is that nothing holds it -- no compiler clause reads it there and
// IKEProposal has no field for it. So "unread" cannot be answered by asking
// whether the keyword appears anywhere; it has to be asked AT THE PATH.
//
// THE COVERAGE GATE, and why it is not tuned to save the control. Container
// recovery is partial, so a container whose clauses are mostly unlocalised has
// an under-populated read-set and every declared child looks unread. Containers
// are therefore only considered when the compiler is observed to read at least
// converseCoverage8807 of what is declared there -- evidence that the read-set
// is reasonably complete. The #8785 control passes at 50%, 60%, 70% AND 80%,
// so the threshold is not doing the work of the control; it was chosen for
// signal-to-noise (26 hits at 50%, 9 at 70%).
//
// An UNAMBIGUOUS-container filter was tried first and REJECTED: it cuts the set
// to 2, but `proposal` has two schema paths, so it excludes the #8785 control
// itself. A filter that kills its own control invalidates everything downstream
// of it -- #8787 recorded that lesson about predicate A and it applies here.
const converseCoverage8807 = 0.7

type converseVerdict8807 struct {
	state string // "known-defect" | "unmeasured" | "benign"
	why   string
}

// UNMEASURED IS A THIRD STATE, not a quiet pass. Every row below except #8785
// needs both spellings compiled before it can be called anything -- of the five
// hits in direction 1, two were benign, so assuming would over-report by 40%.
var converseAdjudicated8807 = map[string]converseVerdict8807{
	"proposal / description": {"known-defect", "#8785. Declared under `security ike proposal` (and `security " +
		"ipsec proposal`), no compiler clause reads it there, and IKEProposal has no Description field. The " +
		"three-part remedy is declare / add the field / read it, and only the first is visible to a schema test."},

	"policy / description":    {"unmeasured", "declared under a policy container; no localised read clause. NOT MEASURED."},
	"policy / scheduler-name": {"unmeasured", "NOT MEASURED."},
	"pool / dns-server":       {"unmeasured", "DHCP pool; NOT MEASURED."},
	"pool / static-binding":   {"unmeasured", "DHCP pool; NOT MEASURED."},
	"route / policy":          {"unmeasured", "NOT MEASURED."},
	"schedulers / scheduler":  {"unmeasured", "NOT MEASURED."},
	"vpn / traffic-selector":  {"unmeasured", "IPsec VPN; the compiler may read it through a helper rather than a .Name() clause. NOT MEASURED."},
}

// converseHits8807 returns "container / head" for every head declared at a
// container the compiler demonstrably reads, that has no read clause there.
func converseHits8807(t *testing.T) []string {
	t.Helper()
	read := map[string]map[string]bool{}
	for _, s := range positionalSites8807(t) {
		if s.container == "" {
			continue
		}
		if read[s.container] == nil {
			read[s.container] = map[string]bool{}
		}
		read[s.container][s.head] = true
	}
	decl := containerDeclares8807()
	var out []string
	for cont, heads := range decl {
		r, ok := read[cont]
		if !ok || len(heads) == 0 {
			continue
		}
		hit := 0
		for h := range heads {
			if r[h] {
				hit++
			}
		}
		if float64(hit)/float64(len(heads)) < converseCoverage8807 {
			continue
		}
		for h := range heads {
			if !r[h] {
				out = append(out, cont+" / "+h)
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestConversePredicateIsPinned8807(t *testing.T) {
	hits := converseHits8807(t)
	live := map[string]bool{}
	for _, h := range hits {
		live[h] = true
	}
	var added, removed []string
	for h := range live {
		if _, ok := converseAdjudicated8807[h]; !ok {
			added = append(added, h)
		}
	}
	for h := range converseAdjudicated8807 {
		if !live[h] {
			removed = append(removed, h)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(added) > 0 {
		t.Errorf("UNPINNED converse hit(s): %v\n"+
			"Declared at this container and no clause reads it there. That is a "+
			"CANDIDATE: it may be read through a helper rather than a .Name() "+
			"switch, which this predicate cannot see. Compile both spellings and "+
			"check the typed struct actually HOLDS the value -- #8785's defect was "+
			"a missing struct field behind a correct declaration.\n\n"+
			"AND ENUMERATE WHERE THE VALUE LANDS BEFORE CALLING ANYTHING UNREAD. "+
			"#8787 declared `then next` measured-clean by checking `Action`, which "+
			"is the wrong field -- `next term` sets `NextTerm`, and it IS read. That "+
			"was not an honest \"could not tell\"; it was a confident CLEAN produced "+
			"by reading a field the value never lands in. A value that lands in a "+
			"field you did not check is INDISTINGUISHABLE from a value that lands "+
			"nowhere, and \"unread\" is precisely the judgement this predicate makes. "+
			"Compare whole compiled results, and DO NOT discard cfg.Warnings while "+
			"doing it: a keyword whose only visible effect is an advisory is still "+
			"being read, and nulling warnings made a read keyword look like a silent "+
			"drop.%s", added, posBlindness8807)
	}
	if len(removed) > 0 {
		t.Errorf("converse hit(s) GONE: %v\n"+
			"If a read clause was added, delete the row. If they vanished because "+
			"container recovery or the coverage gate changed, the instrument moved "+
			"and not the code -- check before believing it.%s", removed, posBlindness8807)
	}

	unmeasured := 0
	for h, v := range converseAdjudicated8807 {
		if v.state == "unmeasured" && live[h] {
			unmeasured++
		}
	}
	if unmeasured > converseUnmeasured8807 {
		t.Errorf("unmeasured converse rows ROSE to %d (ceiling %d). "+
			"\"Not measured\" is a THIRD STATE, not a pass, and it must not "+
			"accumulate.%s", unmeasured, converseUnmeasured8807, posBlindness8807)
	}
	if unmeasured < converseUnmeasured8807 {
		t.Errorf("unmeasured converse rows FELL to %d -- GOOD FAILURE. Set "+
			"converseUnmeasured8807 = %d so the count cannot drift back up.%s",
			unmeasured, unmeasured, posBlindness8807)
	}
}

// converseUnmeasured8807 is a CEILING on rows whose consequence nobody has
// established. It ratchets down as they are measured; it must never rise.
//
// "NOT MEASURED" IS NOT A PASS. The justification is direction 1 of this same
// predicate: of its five hits, TWO were benign -- `vpn / gateway` and
// `vpn / ipsec-policy` compile identically in both nestings -- so treating hits
// as findings would have over-reported by 40%. A category that only accumulates
// stops being a measurement and becomes a registration, which is why this is a
// ratcheting ceiling and not a logged number.
const converseUnmeasured8807 = 7

// TestConversePredicateControl8807 is #8807's second acceptance control: the
// instrument must report #8785. Both halves run, because "reports it" alone is
// satisfiable by something that reports everything.
func TestConversePredicateControl8807(t *testing.T) {
	has := func(want string) bool {
		for _, h := range converseHits8807(t) {
			if h == want {
				return true
			}
		}
		return false
	}
	if !has("proposal / description") {
		t.Fatalf("#8785 CONTROL FAILED: `proposal / description` is not reported. " +
			"It is declared under `security ike proposal` with no clause reading it " +
			"there and no Description field on IKEProposal, so a working converse " +
			"predicate must surface it. Check container recovery for `proposal` and " +
			"the coverage gate before trusting any other row -- and note that an " +
			"unambiguous-container filter WILL break this control, because " +
			"`proposal` has two schema paths.")
	}
	// DECLINE half: a head that IS read at its container must not be reported.
	if has("proposal / dh-group") {
		t.Fatalf("`proposal / dh-group` reported, but the IKE proposal compiler " +
			"reads it -- the predicate is reporting reads as non-reads, so every " +
			"row is suspect.")
	}
}
