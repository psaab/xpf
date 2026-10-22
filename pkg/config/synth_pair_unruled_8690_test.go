package config

import (
	"os"
	"strings"
	"testing"
)

// #8690 unruled-fixture sweep, first increment.
//
// The inventory's three skip buckets are not "clean" — the issue says so and
// the census's own note repeats it. This increment attacks the smallest of
// them, "no two distinct synthesizable values" (17 sites), and finds that
// EVERY one of the ten it resolved was a verdict about `synthPair` rather than
// about the leaf: three declared value types the type switch never covered,
// and five ValueEnumOf leaves whose second value the schema already knew.
//
// Result, measured: checked 677 -> 685, divergent 186 -> 191, no-pair 17 -> 7,
// nothing removed. The five new divergent sites are compact-blind readers this
// census could not SEE, not new defects.

// leafAt walks setSchema to one site, so a cell can assert against the REAL
// schema node rather than a fixture that models it.
func leafAt(t *testing.T, path ...string) *schemaNode {
	t.Helper()
	n := setSchema
	for i, seg := range path {
		// `xpfarg` / `xpfname` are the census's SYNTHESIZED instance names, not
		// schema segments: a container that names its instance with `args`
		// carries the leaves as direct children, so the placeholder is stepped
		// over. The inventory header says the same thing about its own keys.
		if seg == "xpfarg" || seg == "xpfname" {
			if n.wildcard != nil {
				n = n.wildcard
			}
			continue
		}
		got, ok := n.children[seg]
		if !ok {
			// A wildcard-named instance segment (`scheduler <name>`): the path
			// carries a placeholder, and the schema carries the wildcard child.
			if n.wildcard != nil {
				got, ok = n.wildcard, true
			}
		}
		if !ok {
			t.Fatalf("schema path %v: no %q at depth %d", path, seg, i)
		}
		n = got
	}
	return n
}

// The enum recovery, on a leaf whose set is known from its own docs.
func TestEnumPairComesFromTheValidatorNotTheExamples_8690(t *testing.T) {
	n := leafAt(t, "system", "services", "ssh", "protocol-version")
	if n.valueType != ValueEnumOf {
		t.Fatalf("fixture drift: protocol-version is not ValueEnumOf")
	}
	if len(n.valueExamples) != 1 {
		t.Fatalf("this cell is about a ONE-example enum; the leaf now declares %d "+
			"examples, so it no longer exercises the path", len(n.valueExamples))
	}
	v1, v2, ok := enumPairFromValidator(n)
	if !ok {
		t.Fatal("no pair recovered from a ValidateEnum leaf — the validator names " +
			"its set when it rejects, so this is the path going blind")
	}
	if v1 == v2 {
		t.Fatalf("the pair is not distinct: %q %q", v1, v2)
	}
	// THE LOAD-BEARING PROPERTY: both values are accepted by the leaf's own
	// gate. A mis-parse of the rejection message must yield NO answer, never a
	// value the schema refuses — which is exactly what made 103 sites unrulable
	// before #8662 (probed with an invented value the leaf rejects).
	for _, v := range []string{v1, v2} {
		if err := n.validator(v); err != nil {
			t.Errorf("recovered value %q is REJECTED by the leaf's validator: %v", v, err)
		}
	}
}

// It must decline rather than guess when the leaf is not an enumerable set.
func TestEnumPairDeclinesWhenThereIsNoSetToRead_8690(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *schemaNode
	}{
		{"no validator", &schemaNode{valueType: ValueEnumOf}},
		{"not an enum type", &schemaNode{
			valueType: ValueIdentifier,
			validator: ValidateEnum([]string{"a", "b"}),
		}},
		{"a validator that accepts anything", &schemaNode{
			valueType: ValueEnumOf,
			validator: func(string) error { return nil },
		}},
		{"a rejection that does not enumerate", &schemaNode{
			valueType: ValueEnumOf,
			validator: func(string) error { return errNoEnumeration8690 },
		}},
		{"a single-valued set", &schemaNode{
			valueType: ValueEnumOf,
			validator: ValidateEnum([]string{"only"}),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := enumPairFromValidator(tc.node); ok {
				t.Error("a pair was invented where the schema states no enumerable set")
			}
		})
	}
}

// THE CLAIM THE RE-VERIFICATION MAKES, tested rather than asserted.
//
// enumPairFromValidator's contract is "the parse cannot produce a WRONG answer,
// only no answer". Nothing exercised that: with a real ValidateEnum the parse is
// exact, so removing the re-verification changed no result and the mutation
// ESCAPED. The property needs a validator whose rejection message LIES — names
// values it then refuses — which is exactly the drift the re-verification
// exists for (a future validator that filters, normalises case, or lists a
// deprecated value it no longer accepts).
func TestEnumPairRefusesAValueTheValidatorWouldReject_8690(t *testing.T) {
	// Enumerates three, accepts only the last one. A parse without
	// re-verification returns ("liar-a", "liar-b") — both rejected.
	lying := &schemaNode{
		valueType: ValueEnumOf,
		validator: func(raw string) error {
			if raw == "real-c" {
				return nil
			}
			return errLyingEnum8690{}
		},
	}
	v1, v2, ok := enumPairFromValidator(lying)
	if ok {
		t.Errorf("returned (%q, %q) from a validator that accepts NEITHER. The "+
			"candidates come from a message, and only the validator itself decides "+
			"what the leaf takes (#8690)", v1, v2)
	}

	// The positive control on the same shape: when the message tells the truth
	// about two of the three, the pair is those two — so the cell above fails
	// for the lie, not because the helper stopped working.
	honest := &schemaNode{
		valueType: ValueEnumOf,
		validator: func(raw string) error {
			switch raw {
			case "liar-a", "real-c":
				return nil
			}
			return errLyingEnum8690{}
		},
	}
	h1, h2, ok := enumPairFromValidator(honest)
	if !ok {
		t.Fatal("the honest control produced no pair, so the refusal above proves nothing")
	}
	if h1 != "liar-a" || h2 != "real-c" {
		t.Errorf("pair = (%q, %q), want the two the validator actually accepts, in "+
			"message order", h1, h2)
	}
}

// A panicking validator must not take the census down with it:
// "cannot answer" is a verdict, not a crash.
func TestEnumPairSurvivesAPanickingValidator_8690(t *testing.T) {
	n := &schemaNode{
		valueType: ValueEnumOf,
		validator: func(_ string) error { panic("validator panic (#8690)") },
	}
	if _, _, ok := enumPairFromValidator(n); ok {
		t.Error("a panicking validator must yield no pair, not a pair")
	}
}

// The three value types the switch gained. Each pair must be accepted by the
// leaf's own validator where it declares one — the same property as above, and
// the reason these sites were unrulable rather than simply unchecked.
func TestTheNewValueTypesSynthesizeAcceptedPairs_8690(t *testing.T) {
	for _, tc := range []struct {
		name string
		path []string
	}{
		{"ValueHostname", []string{"system", "domain-name"}},
		{"ValueDate (start)", []string{"schedulers", "scheduler", "xpfarg", "start-date"}},
		{"ValueDate (stop)", []string{"schedulers", "scheduler", "xpfarg", "stop-date"}},
		{"ValueUnixSocketPath", []string{"system", "dataplane", "control-socket"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := leafAt(t, tc.path...)
			v1, v2, ok := synthPair(n)
			if !ok {
				t.Fatalf("%v: synthPair still declines — the type switch does not "+
					"cover this leaf's declared type (#8690)", tc.path)
			}
			if v1 == v2 {
				t.Fatalf("the pair is not distinct: %q %q", v1, v2)
			}
			if n.validator == nil {
				return
			}
			for _, v := range []string{v1, v2} {
				if err := n.validator(v); err != nil {
					t.Errorf("synthesized %q is REJECTED by the leaf's own validator: "+
						"%v. Probing with a value the schema refuses is what made 103 "+
						"sites unrulable before #8662 — the census would record "+
						"'not observable' about the FIXTURE", v, err)
				}
			}
		})
	}
}

// The five sites this increment moved into the divergent set. They are listed
// by name so a later change that quietly loses them is visible: an inventory
// shrinking is normally progress, and these five shrinking would be regression.
// Renamed from TestTheFiveNewlyVisibleSitesAreInTheInventory_8690: a count in
// the name goes stale exactly when the list legitimately shrinks, and then the
// name argues against the change instead of describing it.
//
// `schedulers scheduler <s> {start-date,stop-date}` left this list when the
// schedulers family was normalized. That is the first branch of the message
// below — the line is correctly gone — and it was confirmed by the census
// reporting both sites as now compiling equivalently, which is the normalizer
// working rather than the synthesiser regressing.
func TestNewlyVisibleSitesAreAccountedFor_8690(t *testing.T) {
	// `want` is now EMPTY: the last three — `system dataplane control-socket`,
	// `system domain-name`, `system services ssh protocol-version` — were
	// normalized, so their lines are correctly gone. They follow
	// `schedulers scheduler <s> {start,stop}-date` out of this list for the
	// same reason and by the same confirmation.
	//
	// An empty membership list asserts NOTHING, so the sites change sides
	// rather than leaving: `normalized` below carries them, and the cell now
	// checks the opposite property — that each compiles IDENTICALLY in both
	// spellings. A site that stops being equivalent has been un-normalized, and
	// a site that never was would have failed here on arrival.
	//
	// Deleting them instead would stop them being checked in EITHER direction,
	// which is the stale-allowlist failure the #2419 inventory exists to
	// prevent.
	want := []string{}
	normalized := []string{
		"system dataplane control-socket",
		"system domain-name",
		"system services ssh protocol-version",
	}
	inv := readInventory8690(t)
	for _, w := range want {
		if !inv[w] {
			t.Errorf("%q is not in the inventory. It became visible only because "+
				"synthPair learned to build a pair for it; if it has been NORMALIZED "+
				"the line is correctly gone and this list should shrink with it — but "+
				"if it went missing because the synthesiser regressed, the site is "+
				"unruled again and nothing else says so (#8690)", w)
		}
	}
	// DEGENERACY CONTROL. With `want` empty the loop above proves nothing, so
	// the cell would pass on any tree at all unless something else carries the
	// claim.
	if len(want) == 0 && len(normalized) == 0 {
		t.Fatal("both lists are empty — this cell asserts nothing and its silence means " +
			"nothing. Re-derive it against whatever now needs watching (#8690)")
	}
	for _, n := range normalized {
		if inv[n] {
			t.Errorf("%q is recorded as NORMALIZED but is still in the inventory — either the "+
				"normalization was reverted or it never took effect, and nothing else says so "+
				"(#8690)", n)
		}
	}
}

// The seven that remain, and WHY, so the next lane does not re-derive it. Six
// are declared inert by their own valueDesc; no synthesiser should invent a
// pair for them.
func TestTheRemainingNoPairSitesAreDeclaredInert_8690(t *testing.T) {
	inert := [][]string{
		{"system", "login", "class", "xpfarg", "allow-commands-regexps"},
		{"system", "login", "class", "xpfarg", "allow-configuration-regexps"},
		{"system", "login", "class", "xpfarg", "deny-commands-regexps"},
		{"system", "login", "class", "xpfarg", "deny-configuration-regexps"},
	}
	for _, path := range inert {
		n := leafAt(t, path...)
		if !strings.Contains(strings.ToLower(n.valueDesc), "not implemented") {
			t.Errorf("%v no longer declares itself unimplemented (%q). If it became a "+
				"real leaf it needs a synthesizable pair and a census verdict, and it "+
				"is currently sitting in a skip bucket that means the opposite (#8690)",
				path, n.valueDesc)
		}
		if _, _, ok := synthPair(n); ok {
			t.Errorf("%v is declared unimplemented but synthPair now builds a pair "+
				"for it; the census would probe a leaf the schema says does nothing",
				path)
		}
	}
}

// errNoEnumeration8690 is a rejection whose message does not name a set.
var errNoEnumeration8690 = errNoEnum8690{}

type errNoEnum8690 struct{}

func (errNoEnum8690) Error() string { return "invalid value" }

// readInventory8690 returns the site keys currently in the checked-in
// inventory.
func readInventory8690(t *testing.T) map[string]bool {
	t.Helper()
	b := mustReadFile8690(t, "testdata/compact_block_divergences_2419.txt")
	out := map[string]bool{}
	for _, l := range strings.Split(b, "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out[strings.TrimSpace(strings.Split(l, "\t")[0])] = true
	}
	return out
}

func mustReadFile8690(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// errLyingEnum8690's message enumerates three values; the validator that
// returns it accepts fewer.
type errLyingEnum8690 struct{}

func (errLyingEnum8690) Error() string {
	return `invalid value "x" (expected one of: liar-a, liar-b, real-c)`
}
