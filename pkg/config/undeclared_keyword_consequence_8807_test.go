package config

import (
	"encoding/json"
	"fmt"
	"testing"
)

// #8807 / #8787: the twelve predicate-B keywords that were recorded as
// UNDECLARED and never measured for consequence.
//
// #8787 established existence -- "the compiler names it and the schema never
// declares it" -- and stopped there. Existence is not a verdict: an undeclared
// keyword may be read anyway, refused on purpose, or silently dropped, and only
// the third is a defect. All 12 remaining rows are still undeclared today
// (checked by walking the live schema), so the recorded fact holds; what
// follows is what it COSTS.
//
// Measured, every one of them:
//
//	READ                8  compiled result changes; the value reaches a field
//	STRICT-REJECT       0  refused on purpose, with a specific message
//	ACCEPTED + ADVISORY 4  accepted, warned as unenforced, value not compiled
//	SILENTLY DROPPED    0
//
// ZERO silent drops and zero fail-opens, which is the answer #8787 did not have.
//
// WHY THIS IS PINNED RATHER THAN JUST REPORTED. These keywords are invisible to
// every other guard in the package: undeclared means SchemaValidate never sees
// them, completion never offers them, and no census keyed on declared children
// can reach them. If a refactor stopped reading one, the config would be
// silently dropped and NOTHING would fail -- the regression would present as
// "no test caught it". Measured-clean-but-unpinned is a coincidence with a good
// outcome, not coverage.
//
// ONE FIXTURE TRAP, which produced a WRONG verdict on the first pass and is
// recorded so the next reader does not re-hit it:
//
// WARNINGS ARE PART OF THE COMPILED RESULT. Nulling cfg.Warnings before
// comparing reported `member` as a silent drop -- it is read, and the proof
// is the "no members" advisory DISAPPEARING when a member is present.
type undeclCase8807 struct {
	kw    string
	base  string // the statement ABSENT
	with  string // identical, statement PRESENT
	class string
}

const (
	kwRead     = "READ"     // the compiled result changes
	kwRejected = "REJECTED" // strict commit refuses it, on purpose
	kwAdvisory = "ADVISORY" // accepted, warned as unenforced, not compiled
)

// signature8807 returns the compiled config AND its warning count, because a
// keyword whose only effect is an advisory is still being read.
func signature8807(t *testing.T, text string) (js string, warnings int, strictOK bool) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture does not parse: %v", perrs)
	}
	cfg, err := compileConfigWithOpts(tree, lenientCompileOpts())
	if err != nil || cfg == nil {
		t.Fatalf("fixture does not compile leniently: %v", err)
	}
	warnings = len(cfg.Warnings)
	cfg.Warnings = nil
	b, _ := json.Marshal(cfg)
	strictTree, _ := NewParser(text).Parse()
	_, serr := compileConfigWithOpts(strictTree, compileOpts{})
	return string(b), warnings, serr == nil
}

func TestTheTwelveUndeclaredKeywordsHaveNoSilentDrop8807(t *testing.T) {
	for _, c := range undeclCases8807() {
		c := c
		t.Run(c.kw, func(t *testing.T) {
			bj, bw, _ := signature8807(t, c.base)
			wj, ww, wStrict := signature8807(t, c.with)

			got := ""
			switch {
			case !wStrict:
				got = kwRejected
			case wj != bj:
				got = kwRead
			case ww != bw:
				got = kwAdvisory
			default:
				got = "SILENTLY-DROPPED"
			}
			if got != c.class {
				t.Errorf("#8807 keyword %q: measured %q, expected %q.\n"+
					"This keyword is UNDECLARED in the schema, so no other guard in this package "+
					"covers it -- SchemaValidate never sees it and completion never offers it. A "+
					"move from %s to SILENTLY-DROPPED means a configuration statement now compiles "+
					"to nothing with no diagnostic, which is the fail-open shape this family keeps "+
					"producing. Re-measure with the base and with legs differing ONLY by the "+
					"statement before changing this expectation.",
					c.kw, got, c.class, c.class)
			}
			if got == kwAdvisory && ww <= bw {
				t.Errorf("#8807 keyword %q is classed ADVISORY but the warning count did not rise "+
					"(%d -> %d); an unenforced knob that warns about nothing is indistinguishable "+
					"from a silent drop", c.kw, bw, ww)
			}
		})
	}
}

// The classification above is only meaningful while these keywords remain
// undeclared. If one gains a schema declaration its consequence changes -- it
// becomes completable, validated, and visible to the census machinery -- and the
// row above stops describing it.
func TestTheTwelveAreStillUndeclared8807(t *testing.T) {
	declared := map[string]bool{}
	seen := map[*schemaNode]bool{}
	var walk func(n *schemaNode, d int)
	walk = func(n *schemaNode, d int) {
		if n == nil || d > 14 || seen[n] {
			return
		}
		seen[n] = true
		for kw, c := range n.children {
			declared[kw] = true
			walk(c, d+1)
			if c != nil {
				walk(c.wildcard, d+1)
			}
		}
		walk(n.wildcard, d+1)
	}
	walk(setSchema, 0)
	if !declared["community"] {
		t.Fatal("the schema walk found no `community` under snmp, so it is not reaching the live " +
			"schema and the absence results below are vacuous")
	}
	for _, c := range undeclCases8807() {
		if declared[c.kw] {
			t.Errorf("#8807: %q is now DECLARED somewhere in the schema. That is progress, not a "+
				"regression -- but its row in TestTheTwelveUndeclaredKeywordsHaveNoSilentDrop8807 "+
				"describes an undeclared keyword and no longer applies. Re-measure it and move it "+
				"out of this list.", c.kw)
		}
	}
}

func undeclCases8807() []undeclCase8807 {
	dhcp := func(pool string) string {
		return "system {\n services {\n  dhcp-local-server {\n   group g1 {\n    interface ge-0-0-1;\n" + pool + "\n   }\n  }\n }\n}\n"
	}
	ir := func(b string) string {
		return "interfaces {\n interface-range r1 {\n  description d;\n" + b + "\n }\n}\n"
	}
	sn := func(b string) string { return "snmp {\n community public;\n" + b + "\n}\n" }
	fw := func(then string) string {
		return "firewall {\n family inet {\n  filter f1 {\n   term t1 {\n    from { protocol tcp; }\n" + then + "\n   }\n  }\n }\n}\n"
	}
	return []undeclCase8807{
		// system services dhcp-local-server group <g> pool <p> — the pool
		// container is itself undeclared, so these three sit under an
		// undeclared parent and are read anyway.
		{"address-range", dhcp("    pool p1 { }"), dhcp("    pool p1 { address-range low 10.0.0.10 high 10.0.0.20; }"), kwRead},
		{"subnet", dhcp("    pool p1 { }"), dhcp("    pool p1 { subnet 10.0.0.0/24; }"), kwRead},
		{"router", dhcp("    pool p1 { }"), dhcp("    pool p1 { router 10.0.0.1; }"), kwRead},
		{"commit", "system {\n host-name h1;\n}\n", "system {\n host-name h1;\n commit persist-groups-inheritance;\n}\n", kwRead},
		// interfaces interface-range — `member` being read is visible as the
		// "no members" advisory disappearing, not as a new field.
		{"member", ir(""), ir("  member ge-0-0-1;"), kwRead},
		{"member-range", ir(""), ir("  member-range ge-0-0-1 to ge-0-0-3;"), kwRead},
		// then next — #8787 recorded this as "measured clean, both spellings
		// leave Action empty". Action is the wrong field: `next term` sets
		// NextTerm, and the compiled result does change. The base leg is
		// `then { }` so the two differ ONLY by the keyword; comparing against
		// `then { accept; }` confounds it with the removed action.
		{"next", fw("    then { }"), fw("    then { next term; }"), kwRead},
		// snmp knobs: accepted and warned as unenforced, by design. The
		// compiler names each one precisely to emit that advisory.
		{"view", sn(""), sn(" view v1 { oid .1.3.6.1; }"), kwAdvisory},
		{"trap-options", sn(""), sn(" trap-options { source-address 10.0.0.1; }"), kwAdvisory},
		{"health-monitor", sn(""), sn(" health-monitor { interval 60; }"), kwAdvisory},
		{"rmon", sn(""), sn(" rmon { event 1 { description e; } }"), kwAdvisory},
		{"userspace", "system {\n dataplane-type userspace;\n dataplane { workers 4; }\n}\n",
			"system {\n dataplane-type userspace;\n dataplane { userspace { workers 4; } }\n}\n", kwRead},
	}
}

var _ = fmt.Sprintf
