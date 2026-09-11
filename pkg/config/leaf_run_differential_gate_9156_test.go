package config

import (
	"sort"
	"strings"
	"testing"
)

// #9156: the (CONTAINER, LEAF-RUN) axis.
//
// A flat-set run whose FIRST leaf is untyped carries every later statement past
// the strict commit gate, and a reader that iterates `node.Children` without
// expanding the run then keeps only the head. `validateModifierChild` rejects a
// run whose head is TYPED, so a leaf declaring no valueType and no validator is
// an ADMISSION HEAD:
//
//	set … tunnel destination 10.0.0.2 keepalive-retry 5   -> STRICT REJECT
//	set … tunnel keepalive-retry 5 destination 10.0.0.2   -> err=<nil>, dst=""
//
// WHY THE EXISTING GATE CANNOT SEE THIS. schema_spelling_differential_gate_test.go
// is the #2419 gate and its unit is (ONE leaf, TWO values) across five
// spellings. This class is (ONE container, TWO DIFFERENT leaves) on one line.
// Different axis; its green says nothing here. This file is the missing axis.
//
// THE ORACLE IS THE SEPARATE-LINES FORM, always. Two spellings agreeing tells
// you nothing about which is right, and the separate-lines spelling is the one
// the operator can verify by reading `show configuration`.
//
// THE COMPARISON RUNS ON THE LENIENT PATH, DELIBERATELY. A census that compiles
// strictly loses a row exactly where a validator rejects its synthesized
// value — so it goes blind at the GATED sites, which are the ones a reader is
// most likely to have skipped. #1960's doctrine is that Load and SyncApply take
// the lenient path, so a strict rejection does not mean the loss cannot happen:
// it means it happens on boot and HA sync instead of at commit. Comparing
// leniently keeps those rows in the population.

// leafRunSite is one probe: a container, an untyped ADMISSION HEAD, and a
// second leaf the head's run would swallow.
type leafRunSite9156 struct {
	container []string
	head      string
	headNode  *schemaNode
	tail      string
	tailNode  *schemaNode
}

func (s leafRunSite9156) key() string {
	return strings.Join(s.container, " ") + " [" + s.head + " -> " + s.tail + "]"
}

// isAdmissionHead9156 is the property that makes a leaf carry a run past the
// strict gate: it declares no type and no validator, so validateModifierChild
// has nothing to reject the following token with.
func isAdmissionHead9156(n *schemaNode) bool {
	return n != nil &&
		len(n.children) == 0 && n.wildcard == nil &&
		!n.multi &&
		n.valueType == ValueAny &&
		n.validator == nil &&
		n.tailValidator == nil &&
		n.treeValidator == nil
}

// isSwallowableLeaf9156 is what a run can carry: any childless single-valued
// leaf of the same container. It may be typed — the head is what decides
// admission, not the tail.
func isSwallowableLeaf9156(n *schemaNode) bool {
	return n != nil && len(n.children) == 0 && n.wildcard == nil && !n.multi
}

// collectLeafRunSites9156 enumerates the population.
//
// It reuses collectCompactSites' container model rather than re-deriving one,
// so this gate and the #2419 census disagree about NOTHING except the axis. A
// second walk would be a second set of blind spots to reason about.
func collectLeafRunSites9156() []leafRunSite9156 {
	byContainer := map[string][]compactSite{}
	var order []string
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		// #9056: the VALUELESS-FLAG shape entered collectCompactSites' population
		// when the #2419 census learned to enumerate it. It is deliberately kept
		// OUT of this gate's population, and the exclusion is
		// population-preserving rather than a narrowing: every site this walk
		// could previously see declared `args >= 1` or a wildcard, because those
		// were the only shapes the census emitted. A flag satisfies
		// isAdmissionHead9156 (no children, no wildcard, no type, no validator)
		// and isSwallowableLeaf9156 alike, so admitting it silently re-picks
		// `heads[0]` / `tails[0]` for many containers -- measured: five recorded
		// containers changed verdict and 26 more were skipped for "no
		// synthesizable value", because a flag HAS no value slot and this gate's
		// mechanism is a head whose value slot swallows the next token.
		//
		// Whether an argless head can carry a flat run past validateModifierChild
		// is a real question on THIS gate's axis, and a different one from the
		// brace-elision drop #9056 measures. The flat-run spelling of the
		// `security flow` flags specifically is already covered by
		// security_flow_packed_run_8939_test.go.
		if s.flag {
			continue
		}
		k := strings.Join(s.container, "\x00")
		if _, ok := byContainer[k]; !ok {
			order = append(order, k)
		}
		byContainer[k] = append(byContainer[k], s)
	}
	sort.Strings(order)

	var out []leafRunSite9156
	for _, k := range order {
		sites := byContainer[k]
		var heads, tails []compactSite
		for _, s := range sites {
			if isAdmissionHead9156(s.node) {
				heads = append(heads, s)
			}
			if isSwallowableLeaf9156(s.node) {
				tails = append(tails, s)
			}
		}
		if len(heads) == 0 || len(tails) < 2 {
			continue
		}
		sort.Slice(heads, func(i, j int) bool { return heads[i].leaf < heads[j].leaf })
		sort.Slice(tails, func(i, j int) bool { return tails[i].leaf < tails[j].leaf })
		head := heads[0]
		for _, tail := range tails {
			if tail.leaf == head.leaf {
				continue
			}
			out = append(out, leafRunSite9156{
				container: head.container,
				head:      head.leaf,
				headNode:  head.node,
				tail:      tail.leaf,
				tailNode:  tail.node,
			})
			break // one probe per container: the axis is the container, not the pair
		}
	}
	return out
}

func leafValue9156(n *schemaNode) (string, bool) {
	v, _, ok := synthPair(n)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// statement9156 renders `<leaf> <value>` with the leaf's arity honoured: an
// args:0 flag takes no value at all, and appending one to it manufactures a
// different statement.
func statement9156(leaf string, n *schemaNode, val string) string {
	if n.args == 0 {
		return leaf
	}
	return leaf + " " + val
}

// TestLeafRunDifferentialGate9156 is the gate.
//
// For every mixed-shape container it compiles TWO configs that say the same
// thing — the leaves on ONE line, and the leaves on SEPARATE lines — and
// requires them to compile identically. The separate-lines form is the oracle.
//
// A site that does not compare is reported in a NAMED skip bucket rather than
// dropped. The buckets are the honest denominator: a census that silently
// enumerates fewer rows reports a smaller failure count and reads like progress.
func TestLeafRunDifferentialGate9156(t *testing.T) {
	sites := collectLeafRunSites9156()
	if len(sites) < 20 {
		t.Fatalf("VOID: enumerated only %d leaf-run sites. The walk is not reaching "+
			"the schema and every comparison below would be vacuous", len(sites))
	}

	var (
		agreed    []string
		differed  []string
		skipNoVal []string
		skipRunNC []string // the one-line form did not compile
		skipSepNC []string // the separate-lines ORACLE did not compile
		skipFlat  []string // the FLAT-SET arm could not be built or compiled
	)
	flatCompared := 0
	reachable := 0
	for _, s := range sites {
		hv, ok := leafValue9156(s.headNode)
		if !ok {
			skipNoVal = append(skipNoVal, s.key()+" (head)")
			continue
		}
		tv, ok := leafValue9156(s.tailNode)
		if !ok {
			skipNoVal = append(skipNoVal, s.key()+" (tail)")
			continue
		}
		ctx := contextFor(s.container)
		headStmt := statement9156(s.head, s.headNode, hv)
		tailStmt := statement9156(s.tail, s.tailNode, tv)

		// ONE LINE: the run. The braced rendering of a flat-set run is the
		// nested chain SetPath builds, which is what the reader sees.
		runText := nest(s.container, ctx+headStmt+" "+tailStmt+";")
		// SEPARATE LINES: the oracle.
		sepText := nest(s.container, ctx+headStmt+"; "+tailStmt+";")

		sep, sepErr := gateCompileBrace(sepText)
		if sepErr != nil {
			skipSepNC = append(skipSepNC, s.key())
			continue
		}
		run, runErr := gateCompileBrace(runText)
		if runErr != nil {
			skipRunNC = append(skipRunNC, s.key())
			continue
		}

		// THE SECOND AXIS. The braced and flat-set spellings of the SAME
		// statement build DIFFERENT ASTs, and a gate that drives one says
		// nothing about the other:
		//
		//	braced    tunnel { keepalive-retry 5 destination 10.0.0.2; }
		//	          -> [keepalive-retry 5 destination 10.0.0.2]      PACKED KEYS
		//	flat-set  set … tunnel keepalive-retry 5 destination 10.0.0.2
		//	          -> [keepalive-retry 5] > [destination 10.0.0.2]  NESTED CHAIN
		//
		// The remedies differ accordingly — `packedStatements` splits the first
		// and cannot see the second — so a container can be correct on one axis
		// and lose on the other. #9156's own defect is on the FLAT-SET axis, and
		// the braced-only version of this gate stayed GREEN when that fix was
		// reverted: it was blind to its own subject.
		flatSep, flatSepErr := gateCompileFlatSet9156(s.container, ctx, headStmt, tailStmt, false)
		flatRun, flatRunErr := gateCompileFlatSet9156(s.container, ctx, headStmt, tailStmt, true)
		flatDriven := flatSepErr == nil && flatRunErr == nil
		if !flatDriven {
			skipFlat = append(skipFlat, s.key())
		} else {
			flatCompared++
		}

		bracedDiffers := run != sep
		flatDiffers := flatDriven && flatRun != flatSep
		if !bracedDiffers && !flatDiffers {
			agreed = append(agreed, s.key())
			continue
		}
		axis := "{braced+flat}"
		switch {
		case bracedDiffers && !flatDiffers:
			axis = "{braced}"
		case flatDiffers && !bracedDiffers:
			axis = "{flat}"
		}
		// REACHABILITY, computed rather than hand-measured (#9391).
		//
		// A differing row is only OPERATOR-REACHABLE if the strict commit walk
		// ADMITS the one-line spelling. Where the strict gate rejects it, the
		// loss can still happen — Load and SyncApply take the lenient path per
		// #1960 — but it cannot be reached by committing, and that path logs a
		// warning naming the leaf. Those are different severities and the code
		// decides which, not a reading.
		//
		// The differentiator is the HEAD leaf's declaration, and the two
		// hand-measured rows proved the register is NOT homogeneous:
		//
		//	system login user <u> [uid -> class]
		//	  `uid` is untyped -> an ADMISSION HEAD -> strict ACCEPTS
		//	  -> operator-reachable, and it silently dropped a DEMOTION
		//	security zones security-zone <z> [description -> screen]
		//	  `description` is scalar: true -> #3332 rejects the trailing token
		//	  -> strict REJECTS both spellings -> lenient-only, and warned
		//
		// Hand-measuring 26 rows one at a time to learn that is the expensive
		// way to ask a question the walker can answer for every row at once.
		if strictAdmitsLeafRun9156(s.container, ctx, headStmt, tailStmt) {
			axis += " {strict-admits}"
			reachable++
		} else {
			axis += " {lenient-only}"
		}
		differed = append(differed, s.key()+" "+axis)
	}

	total := len(sites)
	compared := len(agreed) + len(differed)
	skipped := len(skipNoVal) + len(skipRunNC) + len(skipSepNC)
	t.Logf("#9156 leaf-run differential: %d containers enumerated; %d COMPARED "+
		"(%d agree, %d differ); %d skipped (%d no synthesizable value, %d one-line "+
		"form did not compile, %d ORACLE did not compile)",
		total, compared, len(agreed), len(differed), skipped,
		len(skipNoVal), len(skipRunNC), len(skipSepNC))
	if compared+skipped != total {
		t.Errorf("accounting hole: %d compared + %d skipped != %d enumerated",
			compared, skipped, total)
	}
	if compared == 0 {
		t.Fatalf("VOID: nothing was compared, so the verdict below is about the " +
			"fixture and not about the schema")
	}
	// THE FLAT-SET ARM MUST HAVE RUN. `gateCompileFlatSet9156` shipped once with
	// ZERO call sites — a restore from a mutation backup silently reverted the
	// wiring, the helper stayed in the file, Go does not flag an unused
	// function, and the gate went back to braced-only while its comment and its
	// PR both said otherwise. A helper that exists is not a helper that is
	// CALLED, and this is the assertion that tells the difference.
	if flatCompared == 0 {
		t.Fatalf("VOID: the FLAT-SET axis was never driven. Every verdict above is the "+
			"braced axis alone, which is blind to the nested-chain shape this gate "+
			"exists for (%d containers compared on the braced axis)", compared)
	}
	if flatCompared*2 < compared {
		t.Errorf("the flat-set axis was driven on only %d of %d compared containers; "+
			"below half, the axis is more absent than present and the totals read as "+
			"coverage it does not have", flatCompared, compared)
	}
	t.Logf("  flat-set axis driven on %d of %d compared containers", flatCompared, compared)
	t.Logf("  of the %d differing: %d are OPERATOR-REACHABLE (the strict commit walk "+
		"admits the one-line spelling) and %d are lenient-only (strict rejects it; the "+
		"loss needs a config FILE or an HA sync, and that path logs a warning naming "+
		"the leaf)", len(differed), reachable, len(differed)-reachable)

	// The skip buckets are DRAINED, not counted. A row leaves this population
	// precisely where a validator rejects the synthesized placeholder, so the
	// census is blindest exactly at the gated sites — which is where a reader
	// is most likely to have skipped the expansion. Naming them is what lets
	// the next person shrink the bucket instead of trusting the ratio.
	report := func(name string, rows []string) {
		if len(rows) == 0 {
			return
		}
		sort.Strings(rows)
		show := rows
		if len(show) > 25 {
			show = show[:25]
		}
		t.Logf("  SKIPPED / %s (%d):\n    %s", name, len(rows), strings.Join(show, "\n    "))
	}
	report("no synthesizable value", skipNoVal)
	report("one-line form did not compile", skipRunNC)
	report("ORACLE did not compile", skipSepNC)
	report("flat-set arm not compilable (braced arm still compared)", skipFlat)

	// RATCHET. The register below is a DEBT REGISTER, not an acceptance: the
	// gate fails on any container that starts differing AND on any recorded one
	// that starts agreeing, so the list cannot rot in either direction.
	unrecorded, fixed := ratchetLeafRunDiffers9156(differed)
	sort.Strings(fixed)
	if len(fixed) > 0 {
		t.Errorf("#9156: %d recorded container(s) no longer differ: %v.\n"+
			"That is the good direction — remove them from leafRunKnownDiffer9156 in "+
			"the same change. A register left above reality stops being a ratchet: it "+
			"silently re-admits every container it still lists.", len(fixed), fixed)
	}
	differed = unrecorded

	if len(differed) > 0 {
		sort.Strings(differed)
		t.Errorf("#9156: %d of %d compared containers compile DIFFERENTLY when their "+
			"leaves are written on ONE line instead of separate lines. The "+
			"separate-lines form is the oracle; a difference means the one-line "+
			"spelling LOST something the operator wrote, on a commit that reports "+
			"success.\n  %s\n\n"+
			"The remedy is one of the three this tree already carries — "+
			"hoistAndSplitRun8939/expandFlatRun at the reader, `packedStatements` "+
			"on the container, or a bespoke splitter — and which one depends on the "+
			"SHAPE SetPath built, not on the container's family. Add a row to "+
			"leafRunKnownDiffer9156 only with the measurement that says why it "+
			"cannot be fixed.",
			len(differed), compared, strings.Join(differed, "\n  "))
	}
}

// TestLeafRunDifferentialGateDiscriminates9156 is the control.
//
// A differential gate that reports agreement everywhere is indistinguishable
// from one whose two spellings are the SAME STRING. This drives the #9156
// fixture through the same machinery with the fix's expansion bypassed, and
// requires it to be caught — so the gate above cannot be green because it
// compares nothing.
func TestLeafRunDifferentialGateDiscriminates9156(t *testing.T) {
	// The two spellings must not render identically, or every row is vacuous.
	container := []string{"interfaces", "gr-0/0/0", "unit 0", "tunnel"}
	run := nest(container, "keepalive-retry 5 destination 10.0.0.2;")
	sep := nest(container, "keepalive-retry 5; destination 10.0.0.2;")
	if run == sep {
		t.Fatalf("VOID: the two spellings render to the same text")
	}
	runCfg, err := gateCompileBrace(run)
	if err != nil {
		t.Fatalf("one-line form did not compile: %v", err)
	}
	sepCfg, err := gateCompileBrace(sep)
	if err != nil {
		t.Fatalf("separate-lines form did not compile: %v", err)
	}
	if runCfg != sepCfg {
		t.Errorf("the #9156 fixture still differs between spellings — the tunnel "+
			"reader is not expanding the run:\n  one-line     %s\n  separate     %s",
			runCfg, sepCfg)
	}
	// And the comparison is not trivially true: a DIFFERENT destination must
	// compile differently, or the marshal is not observing the value at all.
	other, err := gateCompileBrace(nest(container, "keepalive-retry 5; destination 10.0.0.9;"))
	if err != nil {
		t.Fatalf("control compile: %v", err)
	}
	if other == sepCfg {
		t.Fatalf("VOID: changing the destination changed nothing in the compiled " +
			"output, so this gate's equality test cannot see a lost value")
	}
}

// TestFlatRunRemedyCensus9156 is the coverage half.
//
// The tree carries THREE unrelated remedies for the same AST shape, applied
// container by container, and only one of them had a coverage guard. This names
// what each covers, so a reader choosing a remedy can see the existing
// distribution instead of guessing, and so a remedy losing all its call sites
// is a failure rather than a silent regression.
func TestFlatRunRemedyCensus9156(t *testing.T) {
	files, err := goSourceFiles9156()
	if err != nil {
		t.Fatalf("enumerate sources: %v", err)
	}
	counts := map[string]int{}
	sites := map[string][]string{}
	for _, f := range files {
		src, err := readFile9156(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range strings.Split(src, "\n") {
			for _, remedy := range []string{"expandFlatRun(", "hoistAndSplitRun8939("} {
				if strings.Contains(line, remedy) && !strings.Contains(line, "func "+strings.TrimSuffix(remedy, "(")) {
					counts[remedy]++
					sites[remedy] = append(sites[remedy], f)
				}
			}
			if strings.Contains(line, "packedStatements:") && strings.Contains(line, "true") {
				counts["packedStatements: true"]++
				sites["packedStatements: true"] = append(sites["packedStatements: true"], f)
			}
		}
	}
	for _, remedy := range []string{"expandFlatRun(", "hoistAndSplitRun8939(", "packedStatements: true"} {
		if counts[remedy] == 0 {
			t.Errorf("remedy %q has ZERO call sites. Either it was removed — in which "+
				"case every container it covered silently regressed — or this census "+
				"stopped matching it, which is worse because it reads as absence.",
				remedy)
		}
		uniq := map[string]bool{}
		for _, f := range sites[remedy] {
			uniq[f] = true
		}
		var fl []string
		for f := range uniq {
			fl = append(fl, f)
		}
		sort.Strings(fl)
		t.Logf("remedy %-24s %3d call site(s) across %d file(s): %s",
			remedy, counts[remedy], len(fl), strings.Join(fl, ", "))
	}
	// The bespoke splitter is a single named file; its absence is the same
	// class of silent regression.
	if _, err := readFile9156("compiler_chassis_cluster_packed.go"); err != nil {
		t.Errorf("the bespoke chassis-cluster splitter (#6672) is gone: %v. It is the "+
			"third remedy and `chassis cluster` depends on it", err)
	}
	t.Logf("remedy %-24s 1 file: compiler_chassis_cluster_packed.go", "bespoke splitter")
}

func goSourceFiles9156() ([]string, error) {
	return filepathGlob9156("*.go")
}

func TestTunnelSchemaResolvesBothPositions9156(t *testing.T) {
	iface := resolveSchemaChild(setSchema, "interfaces")
	if iface == nil || iface.wildcard == nil {
		t.Fatalf("interfaces wildcard missing")
	}
	top := resolveSchemaChild(iface.wildcard, "tunnel")
	unit := resolveSchemaChild(resolveSchemaChild(iface.wildcard, "unit"), "tunnel")
	if top == nil {
		t.Fatalf("interface-level tunnel node missing")
	}
	if unit == nil {
		t.Fatalf("unit-level tunnel node missing")
	}
	if got := tunnelSchema9156(); got != top {
		t.Errorf("tunnelSchema9156 resolved %p, want the interface-level node %p", got, top)
	}
	// The two positions must declare the SAME leaves, or one resolver cannot
	// serve both readers and the unit-level expansion would be driven by the
	// wrong declaration.
	for name := range top.children {
		if unit.children[name] == nil {
			t.Errorf("interface-level tunnel declares %q and the unit-level one does not; "+
				"one resolver can no longer serve both readers", name)
		}
	}
	for name := range unit.children {
		if top.children[name] == nil {
			t.Errorf("unit-level tunnel declares %q and the interface-level one does not", name)
		}
	}
}

// leafRunKnownDiffer9156 is the population the gate found when it was built:
// 26 of 99 compared containers, tracked at issue #9391.
//
// IT IS A DEBT REGISTER, NOT AN ACCEPTANCE. Every row here is a container whose
// one-line spelling LOSES something the operator wrote, on a commit that
// reports success. They are listed rather than counted for the reason #8921
// records: a number that moves is not reviewable, and a list is.
//
// THREE WERE HAND-MEASURED before this file was written, because a gate row is
// a candidate until someone looks:
//
// EVERY REMAINING ROW IS {lenient-only}, and that is a MEASUREMENT the gate
// makes on each run rather than a claim in this comment. The strict commit walk
// REJECTS the one-line spelling at all 25, so none is reachable by an operator
// committing: the loss needs a config FILE or an HA sync, and
// Store.compileTreeLenient logs a warning naming the leaf and saying the token
// would be dropped (#1960's tolerate-and-warn doctrine, working).
//
// That reduces #9391 enormously and it was worth measuring rather than
// hand-checking: the register is NOT homogeneous, and the differentiator is the
// HEAD leaf's declaration. An untyped head is an ADMISSION HEAD and the gate has
// nothing to reject the next token with; a `scalar: true` head is refused by
// #3332's trailing-token gate. Two rows were hand-measured and they landed on
// opposite sides of exactly that line.
//
// The two OPERATOR-REACHABLE rows are both fixed:
//
//   - `security log stream <s> [port -> category]` — FIXED (#9391). The one
//     reachable row of the original 26, and it exists in this register ONLY
//     because the flat-set axis was restored — the braced-only gate found 26
//     rows of which ZERO were reachable, and missed the one that was.
//     `port` is untyped, so `set security log stream s1 port 5514 category
//     rt-flow` committed CLEAN with the category dropped, and Categories == 0
//     means ALL (pkg/logging/syslog.go) — so the operator's NARROWING was
//     silently inverted into "export every category" to a collector scoped for
//     one. Over-export, not a blind spot.
//   - `system login user <u> [uid -> class]` — FIXED (#9391). It was the
//     AUTHORIZATION one, and the severity was in the DOWNGRADE direction rather
//     than the empty-class one: a demotion written on one line was dropped, the
//     user kept `super-user`, and reconcileSudoers keeps the passwordless-root
//     grant for exactly that class. Its row is gone from this register and the
//     ratchet is what required removing it.
//   - `security zones security-zone <z> [description -> screen]` — SECURITY.
//     The zone's IDS/DoS screen profile is dropped, while `show configuration`
//     renders the operator's own line back.
//   - `security screen ids-option <s> tcp syn-flood [alarm-threshold ->
//     attack-threshold]` — the threshold is lost, but the screen compiler
//     RECORDS it in UnknownLeaves rather than dropping it silently, which makes
//     this row a lower severity than the two above.
//
// The remaining 23 are UNTRIAGED and #9391 says so. Adding a row here without
// measuring it records the debt instead of paying it.
//
// A row leaves this map by being FIXED, and the ratchet above fails if one
// starts agreeing while still listed — so the register cannot outlive the
// defect it describes.
var leafRunKnownDiffer9156 = map[string]bool{
	"bridge-domains xpfname [domain-type -> routing-interface] {braced+flat} {lenient-only}":                                                   true,
	"class-of-service interfaces xpfarg [output-traffic-control-profile -> priority-low-min-share] {braced+flat} {lenient-only}":               true,
	"forwarding-options sampling instance xpfarg family inet output flow-server xpfarg [source-address -> port] {braced+flat} {lenient-only}":  true,
	"forwarding-options sampling instance xpfarg family inet6 output flow-server xpfarg [source-address -> port] {braced+flat} {lenient-only}": true,
	"interfaces xpfname [bandwidth -> description] {braced+flat} {lenient-only}":                                                               true,
	"interfaces xpfname aggregated-ether-options [link-speed -> minimum-links] {braced+flat} {lenient-only}":                                   true,
	"interfaces xpfname gigether-options [802.3ad -> redundant-parent] {braced+flat} {lenient-only}":                                           true,
	"interfaces xpfname tunnel wireguard [private-key -> listen-port] {braced+flat} {lenient-only}":                                            true,
	"interfaces xpfname tunnel wireguard peer xpfarg [endpoint -> persistent-keepalive] {braced+flat} {lenient-only}":                          true,
	"protocols bgp group xpfarg neighbor xpfarg [authentication-key -> description] {braced+flat} {lenient-only}":                              true,
	"routing-instances xpfname [description -> instance-type] {braced+flat} {lenient-only}":                                                    true,
	"routing-instances xpfname protocols bgp group xpfarg neighbor xpfarg [authentication-key -> description] {braced+flat} {lenient-only}":    true,
	"security dynamic-address feed-server xpfarg [hostname -> hold-interval] {braced+flat} {lenient-only}":                                     true,
	"security flow traceoptions packet-filter xpfarg [destination-prefix -> protocol] {braced+flat} {lenient-only}":                            true,
	"security nat nat64 rule-set xpfarg [prefix -> source-pool] {braced+flat} {lenient-only}":                                                  true,
	"security screen ids-option xpfarg limit-session [destination-ip-based -> source-ip-based] {braced+flat} {lenient-only}":                   true,
	"security screen ids-option xpfarg tcp syn-flood [alarm-threshold -> attack-threshold] {braced+flat} {lenient-only}":                       true,
	"security zones security-zone xpfarg [description -> screen] {braced+flat} {lenient-only}":                                                 true,
	"system ntp server xpfarg [routing-instance -> key] {braced} {lenient-only}":                                                               true,
	// #9235 REMOVED the two `static-binding` rows that stood here:
	//
	//	system services dhcp-local-server   group <g> pool <p> static-binding <m>
	//	system services dhcpv6-local-server group <g> pool <p> static-binding <m>
	//	  both [host-name -> fixed-address] {braced+flat} {lenient-only}
	//
	// They no longer differ, which is the direction this register wants, and the
	// gate's own failure text prescribes removing them in the same change: "a
	// register left above reality stops being a ratchet — it silently re-admits
	// every container it still lists." One `closedWorld`-free schema node
	// (dhcpStaticBindingSchema) serves both positions, so one expansion cleared
	// both rows.
}

// TestLeafRunRegisterIsNotVacuous9156 pins that the register is a REGISTER and
// not a wildcard.
//
// A ratchet whose allowlist quietly grew to cover every enumerated container
// would be green forever and would read exactly like a clean board. This
// asserts the register is strictly smaller than the compared population, and
// that the container #9156 actually FIXED is not in it — a fix that left its
// own row behind would be indistinguishable from no fix at all.
func TestLeafRunRegisterIsNotVacuous9156(t *testing.T) {
	if n := len(leafRunKnownDiffer9156); n == 0 {
		t.Fatalf("the register is empty; either every container was fixed (remove " +
			"this cell's premise deliberately) or the gate stopped finding rows")
	}
	for k := range leafRunKnownDiffer9156 {
		if strings.HasPrefix(k, "interfaces xpfname tunnel [") {
			t.Errorf("%q is registered as a known difference, but it is the container "+
				"#9156 FIXED. A fix that leaves its own row in the register is "+
				"indistinguishable from no fix", k)
		}
	}
	// THE REGISTER MUST BE CONSULTED, not merely small. A mutation that made the
	// gate accept every difference as recorded left the whole suite green while
	// this cell still passed on size alone — so the decision is driven here with
	// a fabricated input instead of being inferred from the gate's colour.
	var anyRecorded string
	for k := range leafRunKnownDiffer9156 {
		anyRecorded = k
		break
	}
	const fabricated = "xpf-not-a-real-container [xpfhead -> xpftail] {flat}"
	unrec, _ := ratchetLeafRunDiffers9156([]string{fabricated, anyRecorded})
	if len(unrec) != 1 || unrec[0] != fabricated {
		t.Errorf("the ratchet returned %v for one UNREGISTERED and one REGISTERED "+
			"difference; it must return exactly the unregistered one. A ratchet that "+
			"admits an unregistered difference is disarmed, and the gate is green "+
			"either way", unrec)
	}
	_, stale := ratchetLeafRunDiffers9156(nil)
	if len(stale) != len(leafRunKnownDiffer9156) {
		t.Errorf("with NOTHING differing the ratchet reported %d stale entries, want "+
			"all %d — otherwise a fixed container can keep its row forever",
			len(stale), len(leafRunKnownDiffer9156))
	}

	sites := collectLeafRunSites9156()
	if len(leafRunKnownDiffer9156) >= len(sites) {
		t.Errorf("the register holds %d rows against %d enumerated containers. An "+
			"allowlist that covers the population is not a ratchet",
			len(leafRunKnownDiffer9156), len(sites))
	}
}
