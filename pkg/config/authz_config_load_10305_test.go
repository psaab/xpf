package config

import (
	"strings"
	"testing"
)

// #10305: the `load merge` gate and the config store classified a body as
// flat-vs-hierarchical with DIFFERENT predicates, and when they disagreed the
// hierarchical body was never adjudicated.
//
// The gate (LoadMutationLines) called a body flat iff ANY line's first field
// was in the 8-verb set — single-token lines counted. The store
// (LoadMergeAs/parseOverrideContent via hasFlatVerb) calls a body flat iff ANY
// line carries one of 4 verbs AND at least 2 fields. A body with a
// copy|rename|insert|annotate-led (or bare single-token) trigger line and no
// 4-verb line was gate-flat — only the verb-led lines adjudicated — but
// store-hierarchical: the whole tree merged unchecked.
//
// The fix unifies the predicate: the gate detects flat EXACTLY the way the
// store routes it (IsFlatLoadLine, the single source both sides call), so every
// body is adjudicated on the store-routed form. These cells fail while the
// gate uses its own wider predicate and pass once it matches the store.
//
// The denied subtree below is the trigger-terminated shape: the trigger line
// ends in `;`, so the hierarchical parser does not glue it to the following
// stanza (newlines are whitespace to the parser — an unterminated trigger
// would swallow the next stanza as its own arguments and the cell would be
// vacuous).

const deniedSubtree10305 = `system {
    root-authentication {
        plain-text-password hunter2;
    }
}
`

func divergentBodies10305() map[string]string {
	return map[string]string{
		// The issue's shape: an annotate-led trigger on an allowed path.
		"annotate trigger": "annotate system host-name \"ok10305\";\n" + deniedSubtree10305,
		"copy trigger":     "copy system host-name to licensing;\n" + deniedSubtree10305,
		"rename trigger":   "rename system host-name to licensing;\n" + deniedSubtree10305,
		"insert trigger":   "insert system host-name before licensing;\n" + deniedSubtree10305,
		// A bare single-token line: the gate's old predicate counted it as
		// flat (first field in the verb set), the store never does (it needs
		// a path token to replay). Placed where the parser terminates it
		// without gluing: after the stanza's closing brace.
		"bare single-token trigger": deniedSubtree10305 + "set\n",
	}
}

func TestLoadMergeDivergentBodyIsDenied10305(t *testing.T) {
	cfg := cfg9892(t)
	for name, body := range divergentBodies10305() {
		t.Run(name, func(t *testing.T) {
			// PREMISE: the same denied subtree WITHOUT the trigger is
			// refused. If it is not, the fixture is vacuous and this cell
			// cannot distinguish adjudicated from unadjudicated.
			if err := AuthorizeConfigLoad(cfg, "limited", "merge", deniedSubtree10305); err == nil {
				t.Fatal("premise failed: the bare denied subtree was allowed, " +
					"so this cell cannot measure the trigger")
			}
			err := AuthorizeConfigLoad(cfg, "limited", "merge", body)
			if err == nil {
				t.Fatalf("load merge of a body the store routes HIERARCHICAL was ALLOWED — "+
					"the gate called it flat on the %q line and adjudicated only that line, "+
					"so the denied subtree merged unchecked (#10305)", name)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the denial echoed the secret from the denied path: %v", err)
			}
			// The gate must adjudicate the STORE-ROUTED form: a hierarchical
			// rendering names the denied leaf, so its presence proves the
			// body was not taken as flat verb-led lines.
			rendered := strings.Join(LoadMutationLines(body), "\n")
			if !strings.Contains(rendered, "system root-authentication") {
				t.Errorf("the gate did not render the hierarchical form: %q — "+
					"the denied leaf was never adjudicated (#10305)", rendered)
			}
		})
	}
}

// `load override` of the divergent body stays REFUSED, not adjudicated: it
// replaces the whole candidate, so the paths it deletes cannot be enumerated.
// This holds before and after the fix (a pin, not a RED cell).
func TestLoadOverrideDivergentBodyStaysRefused10305(t *testing.T) {
	cfg := cfg9892(t)
	for name, body := range divergentBodies10305() {
		if err := AuthorizeConfigLoad(cfg, "limited", "override", body); err == nil {
			t.Errorf("%s: load override was allowed for a regex-restricted class (#10305)", name)
		}
	}
}

// The store-flat branch still adjudicates every verb-led line it collects,
// including a malformed copy WITHOUT `to`: the F-029 fallback adjudicates the
// whole remainder rather than declaring the line ungated. The `set` line is
// what makes this body store-flat; the bare copy line is collected but never
// replayed (the store's flat branch rejects it), so denying it cannot refuse
// working traffic. Pin: green before and after.
func TestLoadMergeStoreFlatBodyStillAdjudicatesBareCopy10305(t *testing.T) {
	cfg := cfg9892(t)
	body := "set system host-name ok10305\ncopy system root-authentication"
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", body); err == nil {
		t.Error("a store-flat body whose bare `copy` line names a denied path was allowed — " +
			"the malformed-copy fallback must adjudicate the whole remainder (#10305)")
	}
}

// NARROWNESS CONTROLS: unifying the predicate must not refuse what the store
// would legitimately merge. Pins: green before and after.
func TestLoadMergeAllowedBodiesStillPass10305(t *testing.T) {
	cfg := cfg9892(t)
	for name, body := range map[string]string{
		"flat allowed":         "set system host-name ok10305",
		"hierarchical allowed": "system {\n    host-name ok10305;\n}",
		// A trigger-led line on an allowed path and NOTHING denied: the
		// store merges a junk node, the gate adjudicates the same junk
		// rendering, and the deny does not match either. Allowed both ways.
		"trigger alone": "annotate system host-name \"ok10305\";\n",
	} {
		if err := AuthorizeConfigLoad(cfg, "limited", "merge", body); err != nil {
			t.Errorf("%s: an allowed load was refused: %v", name, err)
		}
	}
}

// `load set` remains a flat-script path. It must continue to adjudicate a
// denied line and admit an unrelated one; this control prevents a fix for
// merge/override classification from widening or removing the set gate.
func TestLoadSetStillAdjudicatesFlatLines10305(t *testing.T) {
	cfg := cfg9892(t)
	if err := AuthorizeConfigLoad(cfg, "limited", "set", "set system root-authentication hunter2"); err == nil {
		t.Error("load set allowed a denied path (#10305)")
	}
	if err := AuthorizeConfigLoad(cfg, "limited", "set", "set system host-name allowed10305"); err != nil {
		t.Errorf("load set refused an allowed path: %v", err)
	}
}
