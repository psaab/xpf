package config

// schema_slot_escape_gate_test.go — the SLOT-1 VALIDATION-ESCAPE gate.
//
// WHAT THIS GATE ASSERTS
//
// For every value-bearing MULTI leaf in setSchema: a value the commit check
// REJECTS in slot 0 must also be rejected in every later slot. If
//
//	set <path> <leaf> <bad>              -> rejected
//	set <path> <leaf> [ <good> <bad> ]   -> COMMITS CLEAN
//
// then the leaf's check only ever saw slot 0, and every value past the first
// entered the running configuration unchecked. That is a fail-OPEN: the
// operator sees a clean commit, `show configuration` renders the list back
// intact, and the invalid member is either silently dropped by the compiler or
// carried into the dataplane unvalidated.
//
// WHY THIS IS A SEPARATE GATE FROM THE #2419 SPELLING DIFFERENTIAL
//
// schema_spelling_differential_gate_test.go compares COMPILED OUTPUT across the
// five spellings a value list admits. Its primitive is
//
//	dropped(spelling) := compile(spelling, [v1]) == compile(spelling, [v1 v2])
//
// which detects a compiler DROPPING a value. It is structurally blind to this
// property: a leaf that drops NOTHING but validates only slot 0 compiles
// identically in every spelling, so the differential reports agreement. The two
// gates are complementary and neither subsumes the other — a leaf can read
// every value and check only the first (#6687 vlan-id-list, #6692 archive-sites,
// #6688 source-NAT port range), or read only the first and thereby never check
// the rest (#7126 import-rib).
//
// PROVENANCE — the four instances that motivated this gate were all found as a
// SIDE EFFECT of fixing a read defect, never by looking for them:
//
//	#7126  import-rib [ inet.0 does-not-exist.inet.0 ]   committed clean;
//	       the identical name in slot 0 was rejected "references an undefined rib"
//	#6687  vlan-id-list [ 10 99999 ] / [ 10 notanumber ] committed clean
//	#6692  archive-sites: the #4589 leading-dash gate (CWE-88) ran on one
//	       member only, so a `-oProxyCommand=` past the first was unchecked
//	#6688  source-NAT `port range 1000 2000`: the endpoints were validated but
//	       the consumed token count was not, so a pool sized for 1001 ports
//	       provided ONE and committed clean
//
// Four in one campaign, each discovered by accident. Nothing asserted the
// property, so the class had no floor.
//
// CALIBRATION — A SWEEP THAT CANNOT FIND THE BUG YOU ALREADY HAVE REPORTS ZERO
//
// Both harnesses below were run unchanged against 22e17c2de (the commit before
// any of the four fixes landed). Measured there, the table harness reports
// ESCAPED for all six instances that existed at that commit:
//
//	bridge-domain vlan-id-list              #6687
//	nat src pool port range                 #6688
//	system archival archive-sites           #6692
//	rib-group import-rib                    #7126
//	cos rewrite-rules dscp code-points      #6697 (fixed by #7138)
//	cos rewrite-rules ieee-802.1 code-points#6697 (fixed by #7138)
//
// and the same harnesses report zero at origin/master. That 6-of-6 recall on
// independently-confirmed defects, against zero at head, is this gate's
// non-vacuity argument. Re-run it by copying this file into a worktree at
// 22e17c2de.
//
// COVERAGE — HOW THE TWO HARNESSES SPLIT THE SCHEMA
//
// TestSlotEscapeCoverage re-derives these numbers on every run and logs them,
// so they cannot rot into a stale comment. Measured at the commit that
// introduced this file, over the 124 enumerable multi-value leaf SITES:
//
//	43  the sweep probes directly — a pool token commits clean (the control)
//	    and another is rejected (the value to move into slot 1)
//	36  no observable gate — every one of the 81 pool tokens commits clean, so
//	    there is no check to escape and neither harness can carry a verdict.
//	    TestSlotEscapeCoverage LOGS this list rather than asserting it.
//	45  no control under a synthetic parent path: `security policies from-zone
//	    xa20 ...` is rejected for reasons that have nothing to do with the leaf
//	    under test. This is a harness limitation, not a property of the leaf,
//	    and it is exactly the class the hand fixtures exist for. All 45 have a
//	    row; TestSlotEscapeCoverage FAILS if a schema addition lands one here
//	    without a row, which is the anti-rot property.
//
// A NOTE ON THE 36. That number is not a clean bill of health, and one of the
// four motivating defects would have been invisible to a harness that stopped
// at "the domain looks open": #6692's archive-sites gate is a leading-dash
// check, which only a token beginning with '-' can trip. The pool carries one
// for that reason. A leaf whose domain no pool token violates lands in the 36
// and is neither cleared nor accused.
//
// AN EARLIER VERSION OF THIS COMMENT SAID 79/45 INSTEAD OF 43/36/45, and the
// error is worth recording because it flatters: the pool at the time contained
// `scp://u@h:/p`, which ParseSetCommand REJECTS as a syntax error at every
// site. That gave every site a "rejected" token, so every site with any clean
// token looked probed. The inflated number was the sweep counting its own
// parse failure as a leaf's gate. A token that cannot parse is not a value the
// leaf refused; keep the pool to tokens the grammar accepts.
//
// WHAT THIS GATE DOES NOT SEE
//
//   - A leaf with NO check at all cannot escape one. Such leaves are recorded
//     in slotEscapeUngated with the probe value that was accepted in slot 0.
//     They are NOT assertions that the leaf is correct — only that this gate
//     has nothing to compare. Several are worth a separate look; see the notes
//     on individual rows.
//   - The sweep's verdict depends on the token pool containing both a value the
//     leaf accepts and one it rejects. A leaf whose domain no pool token
//     satisfies carries no verdict from the sweep; that is why the pool spans
//     several domains and why the hand table exists.
//   - Only the operator commit path is probed. The tolerant load / peer-sync
//     path (configstore Store.Load / SyncApply) deliberately downgrades these
//     rejections to warnings so a persisted config still boots (#1960), and
//     that asymmetry is correct, not a finding.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Shared commit-check primitive.
//
// This is the OPERATOR commit path: the schema walk followed by the strict
// compiler, in the order configstore runs them (schemaValidateExpandedTree then
// CompileConfig, pkg/configstore/store.go). Using CompileConfigLenient here
// would silently test the no-brick path instead and never observe a rejection.
// ---------------------------------------------------------------------------

func slotEscapeCommitSet(cmds []string) error {
	tree := &ConfigTree{}
	hasBGP, hasProcessAS := false, false
	for _, c := range cmds {
		if strings.Contains(c, "protocols bgp") {
			hasBGP = true
		}
		if strings.Contains(c, "routing-options autonomous-system") ||
			strings.Contains(c, "protocols bgp local-as") {
			hasProcessAS = true
		}
		p, quoted, grouped, err := ParseSetCommandGrouped(c)
		if err != nil {
			return fmt.Errorf("parse %q: %w", c, err)
		}
		if err := tree.SetPathQuotedGrouped(p, quoted, grouped); err != nil {
			return fmt.Errorf("setpath %q: %w", c, err)
		}
	}
	if hasBGP && !hasProcessAS {
		p, quoted, grouped, err := ParseSetCommandGrouped("set routing-options autonomous-system 65000")
		if err != nil {
			return err
		}
		if err := tree.SetPathQuotedGrouped(p, quoted, grouped); err != nil {
			return err
		}
	}
	if err := SchemaValidate(tree, nil); err != nil {
		return err
	}
	_, err := CompileConfig(tree)
	return err
}

func slotEscapeCommitBrace(body string) error {
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		return fmt.Errorf("parse: %v", errs)
	}
	formatted := tree.Format()
	if strings.Contains(formatted, "protocols") && strings.Contains(formatted, "bgp") &&
		!strings.Contains(formatted, "autonomous-system") && !strings.Contains(formatted, "local-as") {
		set, err := ParseSetCommand("set routing-options autonomous-system 65000")
		if err != nil {
			return err
		}
		if err := tree.SetPath(set); err != nil {
			return err
		}
	}
	if err := SchemaValidate(tree, nil); err != nil {
		return err
	}
	_, err := CompileConfig(tree)
	return err
}

// slotEscapeRender builds the tree from set commands and renders it as
// canonical hierarchical brace text. That is the spelling a candidate is
// PERSISTED and re-read in, so an escape reachable only through the flat-set
// grammar still has to be probed in the form the box reloads.
func slotEscapeRender(cmds []string) (string, error) {
	tree := &ConfigTree{}
	for _, c := range cmds {
		p, err := ParseSetCommand(c)
		if err != nil {
			return "", err
		}
		if err := tree.SetPath(p); err != nil {
			return "", err
		}
	}
	return tree.Format(), nil
}

// ---------------------------------------------------------------------------
// Harness 1 — automatic sweep over the sites a synthetic parent path reaches.
// ---------------------------------------------------------------------------

// slotEscapeTokens must span the value DOMAINS setSchema's leaves accept, not
// merely be distinctive strings: the sweep can only judge a leaf for which the
// pool holds BOTH an accepted and a rejected token. Adding a domain here widens
// coverage; it cannot manufacture a finding, because a finding still requires a
// clean control.
var slotEscapeTokens = []string{
	"zzqaaa1", "zzqbbb2",
	"0", "1", "3", "7", "10", "46", "63", "80", "101", "255", "443",
	"1000", "2000", "99999", "4294967296", "-1",
	"10.211.212.0/24", "10.211.212.0/32", "10.211.212.0/99", "999.1.1.1/24", "10.211.212.5",
	"2001:db8::1", "2001:db8::53", "2001:db8::zzz", "2001:db8::/64", "2001:db8::zzz/64",
	"ge-5/0/7", "ge-5/0/7/9/9",
	"ef", "af11", "notadscp",
	"tcp", "bgp", "notaproto", "ospf", "ospf3", "isis", "rip",
	"-oProxyCommand=id",
	"aes256-ctr", "hmac-sha2-256", "curve25519-sha256",
	"session-init", "session-close",
	"ssh", "ping", "http", "https", "telnet", "snmp",
	"any", "all", "low", "high", "medium-low",
	"best-effort", "expedited-forwarding", "assured-forwarding",
	"syn", "ack", "fin", "echo-request", "unreachable",
	"basic-datapath", "view", "link",
	"example.com", "8.8.8.8", "inet.0", "65000:1", "junos-http", "trust",
	"esp", "aes-256-cbc", "group14", "main", "virtual-router", "discard", "reject",
}

// slotEscapeForms are the spellings a two-element value list admits. All five
// are probed: #6687 escaped in the hierarchical bracket and block forms as well
// as the flat-set one, so restricting to the flat-set grammar would have missed
// two thirds of that defect's surface.
type slotEscapeForm struct {
	name string
	run  func(g gateLeaf, vals []string) error
}

func slotEscapeForms() []slotEscapeForm {
	flatPrefix := func(g gateLeaf) string {
		return "set " + strings.Join(append(append([]string{}, g.path...), g.leaf), " ")
	}
	return []slotEscapeForm{
		{"A-hier-bracket", func(g gateLeaf, vals []string) error {
			return slotEscapeCommitBrace(gateBraceConfig(g.path,
				fmt.Sprintf("%s [ %s ];", g.leaf, strings.Join(vals, " "))))
		}},
		{"B-hier-block", func(g gateLeaf, vals []string) error {
			var b strings.Builder
			for _, v := range vals {
				b.WriteString(v)
				b.WriteString("; ")
			}
			return slotEscapeCommitBrace(gateBraceConfig(g.path,
				fmt.Sprintf("%s { %s}", g.leaf, b.String())))
		}},
		{"C-hier-repeat", func(g gateLeaf, vals []string) error {
			var b strings.Builder
			for _, v := range vals {
				b.WriteString(g.leaf)
				b.WriteString(" ")
				b.WriteString(v)
				b.WriteString("; ")
			}
			return slotEscapeCommitBrace(gateBraceConfig(g.path, b.String()))
		}},
		{"D-set-bracket", func(g gateLeaf, vals []string) error {
			if len(vals) == 1 {
				return slotEscapeCommitSet([]string{flatPrefix(g) + " " + vals[0]})
			}
			return slotEscapeCommitSet([]string{flatPrefix(g) + " [ " + strings.Join(vals, " ") + " ]"})
		}},
		{"E-set-repeat", func(g gateLeaf, vals []string) error {
			var cmds []string
			for _, v := range vals {
				cmds = append(cmds, flatPrefix(g)+" "+v)
			}
			return slotEscapeCommitSet(cmds)
		}},
	}
}

// slotEscapeMultiSites returns every enumerable multi-value leaf site. It reuses
// the #2419 gate's enumerator so the two gates cannot disagree about what the
// schema contains.
func slotEscapeMultiSites() []gateLeaf {
	var out []gateLeaf
	for _, g := range enumerateGateLeaves() {
		if g.multi {
			out = append(out, g)
		}
	}
	return out
}

// slotEscapeSweepQualifies reports whether a site carries a verdict from the
// automatic sweep in the given form: at least one pool token commits CLEAN
// (the control) and at least one is rejected (the thing to move to slot 1).
func slotEscapeSweepOutcomes(g gateLeaf, form slotEscapeForm) (res []string, ok bool) {
	res = make([]string, len(slotEscapeTokens))
	clean, rejected := 0, 0
	for i, tok := range slotEscapeTokens {
		e := form.run(g, []string{tok})
		if e == nil {
			res[i] = ""
			clean++
		} else {
			res[i] = e.Error()
			rejected++
		}
	}
	return res, clean > 0 && rejected > 0
}

func TestSlotEscapeSweep(t *testing.T) {
	var failures []string
	for _, form := range slotEscapeForms() {
		for _, g := range slotEscapeMultiSites() {
			res, ok := slotEscapeSweepOutcomes(g, form)
			if !ok {
				continue
			}
			// One control is enough: the property is per-leaf, not per-value
			// pair, and every additional control multiplies the probe cost by
			// the pool size for no additional discrimination.
			good, ctrlIdx := "", -1
			for i, r := range res {
				if r == "" {
					good, ctrlIdx = slotEscapeTokens[i], i
					break
				}
			}
			_ = ctrlIdx
			for i, bad := range slotEscapeTokens {
				if res[i] == "" || bad == good {
					continue
				}
				if err := form.run(g, []string{good, bad}); err == nil {
					failures = append(failures, fmt.Sprintf(
						"%s [%s]: %q is REJECTED in slot 0 (%s) but the list [ %s %s ] commits clean",
						g.siteKey(), form.name, bad, firstLine(res[i]), good, bad))
				}
			}
		}
	}
	sort.Strings(failures)
	for _, f := range failures {
		t.Errorf("slot-1 validation escape: %s", f)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 140 {
		s = s[:140] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Harness 2 — hand-authored fixtures for the sites a synthetic parent cannot
// reach. Each row supplies a REAL prerequisite config, so the control commits
// clean and the comparison is meaningful.
// ---------------------------------------------------------------------------

type slotEscapeRow struct {
	name string   // human label, used in failure output
	site string   // the setSchema site this row covers (see TestSlotEscapeCoverage)
	base []string // prerequisite set commands; must commit clean with `good` alone
	leaf string   // the `set ...` prefix WITHOUT the value
	good string   // a value the leaf accepts
	bad  string   // a value the leaf must reject
}

func TestSlotEscapeTable(t *testing.T) {
	for _, r := range append(slotEscapeRows(), slotEscapeHistoricalRows()...) {
		r := r
		t.Run(strings.ReplaceAll(r.name, " ", "_"), func(t *testing.T) {
			with := func(vals ...string) []string {
				return append(append([]string{}, r.base...), r.leaf+" "+strings.Join(vals, " "))
			}
			if err := slotEscapeCommitSet(with(r.good)); err != nil {
				t.Fatalf("fixture broken: the control (%s %s) must commit clean, got: %v", r.leaf, r.good, err)
			}
			e0 := slotEscapeCommitSet(with(r.bad))
			if e0 == nil {
				if _, known := slotEscapeUngated[r.site]; known {
					t.Skipf("no gate on this leaf for %q (recorded in slotEscapeUngated); nothing to escape", r.bad)
				}
				t.Fatalf("fixture broken: %q must be REJECTED in slot 0 for this row to mean anything", r.bad)
			}
			if _, known := slotEscapeUngated[r.site]; known {
				t.Fatalf("slotEscapeUngated records this site as having no gate, but %q was rejected in slot 0 (%v) — the row now carries a real verdict, so remove the slotEscapeUngated entry", r.bad, e0)
			}

			// Slot 1, four ways: flat-set bracket, flat-set repeated, the
			// canonical hierarchical render the box reloads from, and a
			// three-element list with the bad value LAST (a check that stops
			// after two would pass the two-element probe).
			check := func(label string, err error) {
				if err == nil {
					t.Errorf("slot-1 validation escape [%s]: %q is rejected in slot 0 (%s) but the list with it in a later slot commits CLEAN",
						label, r.bad, firstLine(e0.Error()))
				}
			}
			check("D-set-bracket", slotEscapeCommitSet(with("[", r.good, r.bad, "]")))
			check("E-set-repeat", slotEscapeCommitSet(append(append([]string{}, r.base...),
				r.leaf+" "+r.good, r.leaf+" "+r.bad)))
			check("D-set-bracket-slot2", slotEscapeCommitSet(with("[", r.good, r.good, r.bad, "]")))
			body, err := slotEscapeRender(with("[", r.good, r.bad, "]"))
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			check("hier-render-roundtrip", slotEscapeCommitBrace(body))
		})
	}
}

// ---------------------------------------------------------------------------
// Coverage — every multi site must carry a verdict from one harness or the
// other, so growing the schema cannot silently grow a hole.
// ---------------------------------------------------------------------------

func TestSlotEscapeCoverage(t *testing.T) {
	covered := map[string]bool{}
	for _, r := range append(slotEscapeRows(), slotEscapeHistoricalRows()...) {
		if r.site != "" {
			covered[r.site] = true
		}
	}

	// Classify every multi site by what the automatic sweep can observe:
	//
	//	verdict     a pool token commits clean AND another is rejected -> the
	//	            sweep probes this site directly
	//	no-gate     every pool token commits clean; there is no check to
	//	            escape, so neither harness can carry a verdict
	//	no-control  no pool token commits clean, because the SYNTHETIC parent
	//	            path is rejected for reasons unrelated to the leaf. This is
	//	            a harness limitation, not a property of the leaf, and it is
	//	            the class a hand fixture exists to cover.
	var noGate, needFixture []string
	verdict := 0
	for _, g := range slotEscapeMultiSites() {
		anyVerdict, anyClean := false, false
		for _, form := range slotEscapeForms() {
			res, ok := slotEscapeSweepOutcomes(g, form)
			if ok {
				anyVerdict = true
				anyClean = true
				break
			}
			for _, r := range res {
				if r == "" {
					anyClean = true
				}
			}
		}
		switch {
		case anyVerdict:
			verdict++
		case anyClean:
			noGate = append(noGate, g.siteKey())
		default:
			if !covered[g.siteKey()] {
				needFixture = append(needFixture, g.siteKey())
			}
		}
	}

	sort.Strings(noGate)
	t.Logf("multi sites=%d  probed by the sweep=%d  no observable gate=%d  hand fixtures=%d",
		len(slotEscapeMultiSites()), verdict, len(noGate), len(covered))
	// Logged, not asserted. A leaf that rejects nothing has no gate to escape,
	// and pinning the list would fail every time a leaf legitimately GAINS a
	// check — the direction we want. It is printed because it is the honest
	// inventory of where this gate is silent, and because several entries are
	// worth a separate look on their own merits.
	for _, s := range noGate {
		t.Logf("no observable gate (nothing for this gate to compare): %s", s)
	}

	sort.Strings(needFixture)
	var refusedByDesign []string
	for _, s := range needFixture {
		// #9017: a site under `family any` may have NO value it accepts, so no
		// row can express it. `family any` compiles into BOTH pools (#4287),
		// and #4296 REFUSES every family-specific match there -- a v4/v6
		// address literal, a per-family icmp type/code -- because such a match
		// can never match the other family and would silently under-block it.
		//
		// The exclusion is MEASURED, not declared: the site is only excused if
		// a representative commit is actually refused, and refused by #4296
		// rather than by anything else. A register that could be satisfied by
		// writing a line here would be worth less than the hole it covers.
		if why := familyAnyRefusal9017(s); why != "" {
			refusedByDesign = append(refusedByDesign, s+"  ("+why+")")
			continue
		}
		t.Errorf("multi leaf %q carries NO slot-escape verdict: it does not commit clean under a "+
			"synthetic parent path, and it has no row in slotEscapeRows. Add one — a prerequisite "+
			"base config that commits clean, a value the leaf accepts, and one it must reject.", s)
	}
	for _, s := range refusedByDesign {
		t.Logf("refused by design, no value to probe: %s", s)
	}

	// A row whose site is no longer a leaf in setSchema silently stops covering
	// anything, exactly as a stale allowlist row does in the #2419 gate. Checked
	// against EVERY enumerated leaf, not only the multi ones: #7126's import-rib
	// is a multi:false leaf that escaped anyway, and its regression row must not
	// be deleted just because the coverage half does not reach it.
	live := map[string]bool{}
	for _, g := range enumerateGateLeaves() {
		live[g.siteKey()] = true
	}
	for site := range covered {
		if !live[site] {
			t.Errorf("a slot-escape row covers %q, which is no longer a leaf in setSchema — "+
				"update or delete the row", site)
		}
	}
	for site := range slotEscapeUngated {
		if !live[site] {
			t.Errorf("slotEscapeUngated records %q, which is no longer a leaf in setSchema", site)
		}
	}
}

// familyAnyRefusal9017 reports why a `firewall family any` match leaf has no
// probeable value, or "" if it actually has one.
//
// It COMMITS a representative value and requires the refusal to name #4296. A
// site that starts accepting a value -- because the gate was relaxed, or
// because the leaf stopped being family-specific -- stops being excused here
// and goes back to demanding a real row, which is the direction we want.
func familyAnyRefusal9017(site string) string {
	const prefix = "firewall family any filter <*> term <*> from "
	if !strings.HasPrefix(site, prefix) {
		return ""
	}
	leaf := strings.TrimPrefix(site, prefix)
	val, ok := map[string]string{
		"source-address":      "10.0.0.0/8",
		"destination-address": "10.0.0.0/8",
		"icmp-type":           "3",
		"icmp-code":           "1",
	}[leaf]
	if !ok {
		return ""
	}
	tr := &ConfigTree{}
	for _, l := range []string{
		"set firewall family any filter F term t1 then accept",
		"set firewall family any filter F term t1 from " + leaf + " " + val,
	} {
		pth, err := ParseSetCommand(l)
		if err != nil {
			return ""
		}
		tr.SetPath(pth)
	}
	_, err := CompileConfig(tr)
	if err == nil {
		return "" // it DOES accept a value — demand a real row
	}
	if !strings.Contains(err.Error(), "#4296") {
		return ""
	}
	return "#4296 refuses family-specific matches under family any"
}
