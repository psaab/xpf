package config

import (
	"strings"
	"testing"
)

// Round-10 guards for the #6673 quote-provenance fix.
//
// THE DEFECT THESE BIND. eventMultiWordLeafValues decides whether a token group
// is a bracketed LIST of authored values or the words of ONE unquoted statement.
// Before this round it answered "was the first member quoted?" by inspecting the
// member's TEXT — a space, or emptiness. That is an implication in one direction
// only: every space-bearing token was quoted, but a quoted token need not carry
// a space. A quoted ONE-WORD first member has neither marker, so
//
//	commands [ "set" "system host-name pwned" ]
//
// read as bare-first and JOINED into the single string
// `set system host-name pwned` — a syntactically perfect command that passes
// eventengine.classifyPlan's `set ` prefix check, parses, and is APPLIED. The
// authoring the operator wrote is a bare `set` member, which is exactly what the
// documented fail-closed path exists to reject.
//
// WHAT MAKES THESE TESTS BIND rather than restate the implementation: every case
// asserts the VALUE COUNT and the values, and the fused-string assertion is
// stated as an absence over the whole result — so a regression that re-fuses the
// members fails on the count AND on the forbidden value, in both AST shapes. The
// positive controls are the two authorings that must NOT change, and they are
// the reason a "just always split" fix cannot pass this table.

// quoteProvenanceCase is one authoring, expressed in both spellings an operator
// can use, with the values it must compile to.
type quoteProvenanceCase struct {
	name string
	// hier is the value list as written inside `commands { ... }` /
	// `attributes-match ...` in hierarchical syntax (the text after the leaf
	// keyword, without the trailing `;`).
	valueText string
	want      []string
	// forbidden is a value that must NEVER appear in the result — the fused
	// string for the ambiguous authorings.
	forbidden string
}

var quoteProvenanceCases = []quoteProvenanceCase{
	{
		// THE BUG. Two authored members, the first a quoted ONE-WORD token.
		name:      "quoted one-word member beside a quoted multi-word member",
		valueText: `[ "set" "system host-name pwned" ]`,
		want:      []string{"set", "system host-name pwned"},
		forbidden: "set system host-name pwned",
	},
	{
		// Same shape with `delete`, so the guard is not pinned to one verb.
		name:      "quoted one-word DELETE member beside a quoted remainder",
		valueText: `[ "delete" "system host-name" ]`,
		want:      []string{"delete", "system host-name"},
		forbidden: "delete system host-name",
	},
	{
		// A quoted one-word member that is not a verb at all: still two values.
		name:      "quoted one-word garbage member first",
		valueText: `[ "bogus" "set system host-name foo" ]`,
		want:      []string{"bogus", "set system host-name foo"},
		forbidden: "bogus set system host-name foo",
	},
	{
		// POSITIVE CONTROL 1 — the authoring that must still JOIN. A bare first
		// token with a quoted VALUE inside one command. An "always split" fix
		// fails here.
		name:      "bare first token with a quoted value inside ONE command",
		valueText: `set system host-name "foo bar"`,
		want:      []string{"set system host-name foo bar"},
	},
	{
		// POSITIVE CONTROL 2 — the authoring that must still SPLIT, and did
		// before this round (its first member carries a space).
		name:      "quoted multi-word member beside a bare garbage token",
		valueText: `[ "set a b" bogus ]`,
		want:      []string{"set a b", "bogus"},
		forbidden: "set a b bogus",
	},
	{
		// POSITIVE CONTROL 3 — the authored-empty first member pinned by
		// TestEventChangeConfigCommands6673EmptyCommandStaysInTheBatch.
		name:      "authored EMPTY first member",
		valueText: `[ "" "set a b" ]`,
		want:      []string{"", "set a b"},
		forbidden: " set a b",
	},
	{
		// POSITIVE CONTROL 4 — a single quoted command is one value under both
		// rules; nothing about provenance may change it.
		name:      "one quoted command",
		valueText: `"set system host-name foo"`,
		want:      []string{"set system host-name foo"},
	},
	{
		// DOCUMENTED RESIDUAL, pinned so a future change to it is deliberate:
		// an all-bare group carries no quoted token in either authoring, so
		// provenance cannot separate `[ seta setb ]` from `seta setb` and both
		// join. Asserted, not merely described in a comment.
		name:      "all-bare members still JOIN (documented residual)",
		valueText: `[ seta setb ]`,
		want:      []string{"seta setb"},
	},
}

func commandsNode6673(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	n := tree.FindChild("event-options")
	for _, k := range []string{"policy", "then", "change-configuration", "commands"} {
		if n == nil {
			t.Fatalf("config tree has no %q node", k)
		}
		n = n.FindChild(k)
	}
	if n == nil {
		t.Fatal("config tree has no commands node")
	}
	return n
}

// TestEventCommands6673QuoteProvenanceHierarchical drives the hierarchical
// parser, where a bracketed list lands on the leaf node's OWN Keys.
func TestEventCommands6673QuoteProvenanceHierarchical(t *testing.T) {
	for _, tc := range quoteProvenanceCases {
		t.Run(tc.name, func(t *testing.T) {
			src := "event-options { policy p { then { change-configuration { commands " +
				tc.valueText + "; } } } }"
			tree, perrs := NewParser(src).Parse()
			if len(perrs) != 0 {
				t.Fatalf("parse: %v", perrs)
			}
			got := eventChangeConfigCommands(commandsNode6673(t, tree))
			assertValues6673(t, "hierarchical", tc, got)
		})
	}
}

// TestEventCommands6673QuoteProvenanceFlatSet drives the flat-set path through
// the SAME entry points production uses (ParseSetCommandGrouped +
// SetPathQuotedGrouped, which is what configstore.Store.SetFromInputAs calls
// since #9881 unified the operator-set and replay pairs). There the bracketed
// list lands on a CHILD's Keys instead, so it exercises a different arm of the
// reader — and a fix applied to only one arm fails one of these two tests.
//
// Using the provenance-carrying entry points is the point: plain SetPath records
// no provenance, so a test written against it would be evaluated under the
// legacy text rule and would pass with the defect still present.
func TestEventCommands6673QuoteProvenanceFlatSet(t *testing.T) {
	for _, tc := range quoteProvenanceCases {
		t.Run(tc.name, func(t *testing.T) {
			line := "set event-options policy p then change-configuration commands " + tc.valueText
			path, quoted, grouped, err := ParseSetCommandGrouped(line)
			if err != nil {
				t.Fatalf("ParseSetCommandGrouped: %v", err)
			}
			tree := &ConfigTree{}
			if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
				t.Fatalf("SetPathQuotedGrouped: %v", err)
			}
			got := eventChangeConfigCommands(commandsNode6673(t, tree))
			assertValues6673(t, "flat-set", tc, got)
		})
	}
}

// TestEventCommands6673QuoteProvenanceSurvivesTextRoundTrip is the guard for the
// serialization half of the fix.
//
// Quote provenance lives on the Node, but three production paths carry a config
// as TEXT and re-parse it on the far side: HA config sync (Store.SyncApply takes
// a string), `show | display set` replay, and load merge / archive. If Format
// normalized `"set"` back to a bare `set` — which quoteKey alone does, since
// `set` is bare-safe — the peer would re-parse the list as one fused command and
// the fail-open would simply move across the wire. keyNeedsAuthoredQuote exists
// for this, and this test is what binds it: it asserts the values are IDENTICAL
// after a full render/re-parse cycle in BOTH renderings.
func TestEventCommands6673QuoteProvenanceSurvivesTextRoundTrip(t *testing.T) {
	for _, tc := range quoteProvenanceCases {
		t.Run(tc.name, func(t *testing.T) {
			src := "event-options { policy p { then { change-configuration { commands " +
				tc.valueText + "; } } } }"
			tree, perrs := NewParser(src).Parse()
			if len(perrs) != 0 {
				t.Fatalf("parse: %v", perrs)
			}
			direct := eventChangeConfigCommands(commandsNode6673(t, tree))

			// Leg 1: hierarchical render -> re-parse.
			hierText := tree.Format()
			rt, perrs := NewParser(hierText).Parse()
			if len(perrs) != 0 {
				t.Fatalf("re-parse of Format() output %q: %v", hierText, perrs)
			}
			if got := eventChangeConfigCommands(commandsNode6673(t, rt)); !equalStrings6673(got, direct) {
				t.Fatalf("hierarchical round trip changed the compiled commands:\n"+
					"  before: %q\n  after:  %q\n  rendered as: %s\n"+
					"a serialize/re-parse cycle (HA config sync, load merge, archive) "+
					"must not launder an authored quote away", direct, got, hierText)
			}

			// Leg 2: display-set render -> replay each line.
			setText := tree.FormatSet()
			replay := &ConfigTree{}
			for _, line := range strings.Split(strings.TrimSpace(setText), "\n") {
				if line == "" {
					continue
				}
				path, quoted, grouped, err := ParseSetCommandGrouped(line)
				if err != nil {
					t.Fatalf("replaying %q: %v", line, err)
				}
				if err := replay.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
					t.Fatalf("replaying %q: %v", line, err)
				}
			}
			if got := eventChangeConfigCommands(commandsNode6673(t, replay)); !equalStrings6673(got, direct) {
				t.Fatalf("display-set round trip changed the compiled commands:\n"+
					"  before: %q\n  after:  %q\n  rendered as: %s",
					direct, got, setText)
			}
		})
	}
}

// TestEventAttributesMatch6673QuoteProvenance binds the SECOND leaf that shares
// the reader. A fix applied to `commands` alone leaves this one fusing, and the
// fused expression reaches ValidateEventAttributesMatchStrict as a single
// plausible constraint instead of two, one of which is malformed.
func TestEventAttributesMatch6673QuoteProvenance(t *testing.T) {
	src := `event-options { policy p { attributes-match [ "e1.owner" "e2.owner matches X" ]; } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	am := tree.FindChild("event-options").FindChild("policy").FindChild("attributes-match")
	if am == nil {
		t.Fatal("no attributes-match node")
	}
	got := eventAttributesMatchExprs(am)
	want := []string{"e1.owner", "e2.owner matches X"}
	if !equalStrings6673(got, want) {
		t.Fatalf("eventAttributesMatchExprs = %q (n=%d), want %q (n=%d) — a quoted "+
			"one-word member must stay its own expression so the strict validator "+
			"sees the malformed constraint the operator authored",
			got, len(got), want, len(want))
	}
}

// TestNodeQuoteProvenance6673Invariants pins the accessor contract the reader
// relies on, including the deliberate "absent provenance is not a claim of
// bareness" distinction.
func TestNodeQuoteProvenance6673Invariants(t *testing.T) {
	// A hand-built node (compiler synthesis, or a config DB written before
	// this change) records nothing and must SAY so rather than answering
	// "every key was bare".
	synth := &Node{Keys: []string{"commands", "set", "system host-name x"}}
	if synth.KeysHaveQuoteProvenance() {
		t.Fatal("a hand-built node must not claim quote provenance")
	}
	if synth.KeyQuoted(0) || synth.KeyQuoted(99) || synth.KeyQuoted(-1) {
		t.Fatal("KeyQuoted must answer false, and never panic, without provenance")
	}
	// Such a node keeps the legacy text rule — the non-regression that stops an
	// upgrade from silently splitting a working remediation.
	if got, want := eventChangeConfigCommands(synth), []string{"set system host-name x"}; !equalStrings6673(got, want) {
		t.Fatalf("provenance-less node = %q, want %q (legacy text rule)", got, want)
	}

	// setKeysQuoted collapses an all-false mask to nil, which is what keeps the
	// persisted config byte-identical for the overwhelming majority of nodes.
	allBare := &Node{Keys: []string{"a", "b"}}
	allBare.setKeysQuoted([]bool{false, false})
	if allBare.KeysQuoted != nil {
		t.Fatalf("all-false mask stored as %v, want nil", allBare.KeysQuoted)
	}
	// A mismatched length is dropped rather than misattributed.
	skew := &Node{Keys: []string{"a", "b"}}
	skew.setKeysQuoted([]bool{true})
	if skew.KeysQuoted != nil {
		t.Fatalf("length-mismatched mask stored as %v, want nil", skew.KeysQuoted)
	}
}

func assertValues6673(t *testing.T, shape string, tc quoteProvenanceCase, got []string) {
	t.Helper()
	if len(got) != len(tc.want) {
		t.Fatalf("%s: %q compiled to %d values %q, want %d %q — the value COUNT is "+
			"the assertion: fusing two authored members into one valid command is "+
			"exactly the #6673 fail-open", shape, tc.valueText, len(got), got, len(tc.want), tc.want)
	}
	if !equalStrings6673(got, tc.want) {
		t.Fatalf("%s: %q compiled to %q, want %q", shape, tc.valueText, got, tc.want)
	}
	if tc.forbidden == "" {
		return
	}
	for _, v := range got {
		if v == tc.forbidden {
			t.Fatalf("%s: %q produced the FUSED value %q — the members must never "+
				"be joined into a single command the operator did not write",
				shape, tc.valueText, tc.forbidden)
		}
	}
}

func equalStrings6673(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSetPathQuotedRefreshesADuplicateLeafsProvenance_6673 binds the duplicate
// short-circuit (#6673 r11 B2).
//
// THE DEFECT. SetPath's dedup arms compare keys with keysEqual, which reads the
// key TEXT and nothing else, then return early. Two set commands with identical
// text but DIFFERENT quoting are not the same statement — they group opposite
// ways — so the early return left the FIRST command's mask describing the
// SECOND command's tokens. Both slices keep the same length, so the
// len(KeysQuoted)==len(Keys) invariant still holds and nothing downstream can
// detect it; the node simply carries a mask that was never authored for it.
//
// Measured before the fix: issuing the path with mask [false,true] and then
// re-issuing it with [true,false] left [false,true] in place, so the group
// JOINED where the operator's second command says it must SPLIT — the
// fail-open direction, since joining is what turns two members into one
// applicable command.
func TestSetPathQuotedRefreshesADuplicateLeafsProvenance_6673(t *testing.T) {
	base := []string{"event-options", "policy", "p", "then", "change-configuration", "commands"}
	withTail := func(a, b string) []string {
		return append(append([]string(nil), base...), a, b)
	}
	// mask helper: which of the two TAIL tokens were authored quoted.
	mask := func(firstQuoted, secondQuoted bool) []bool {
		m := make([]bool, len(base)+2)
		m[len(base)] = firstQuoted
		m[len(base)+1] = secondQuoted
		return m
	}

	tree := &ConfigTree{}
	// First command: `set` BARE, `system` quoted -> the group JOINS.
	if err := tree.SetPathQuoted(withTail("set", "system"), mask(false, true)); err != nil {
		t.Fatalf("first SetPathQuoted: %v", err)
	}
	if got := childMask6673(t, tree); !equalBools6673(got, []bool{false, true}) {
		t.Fatalf("after the first command the child mask is %v, want [false true] — the "+
			"fixture is not set up as this test describes", got)
	}

	// Second command: identical TEXT, opposite quoting -> the group must SPLIT.
	if err := tree.SetPathQuoted(withTail("set", "system"), mask(true, false)); err != nil {
		t.Fatalf("second SetPathQuoted: %v", err)
	}
	if got := childMask6673(t, tree); !equalBools6673(got, []bool{true, false}) {
		t.Fatalf("the duplicate short-circuit kept the FIRST command's mask %v, want "+
			"[true false]. keysEqual compares key TEXT only, so two commands that differ "+
			"solely in quoting look identical to it — and the retained mask then describes "+
			"tokens it was never authored for (#6673 r11 B2)", got)
	}

	got := eventChangeConfigCommands(commandsNode6673(t, tree))
	want := []string{"set", "system"}
	if !equalStrings6673(got, want) {
		t.Fatalf("compiled commands = %q, want %q — the second command authored a QUOTED "+
			"leading `set`, which splits the group; joining is the fail-open direction "+
			"because it is what turns two members into one applicable command", got, want)
	}
}

// TestInactiveStripPreservesQuoteProvenance_6673 binds the copy at
// inactive.go's stripInactiveNodes (#6673 r11 F1).
//
// The inner accessors were already bound, but the CALL SITE was not: deleting
// `KeysQuoted` from the clone left the ENTIRE suite green, because
// WithoutInactive returns the receiver unchanged when nothing is inactive — so
// every existing fixture skipped the clone entirely.
//
// This fixture carries an UNRELATED `inactive:` statement, which is what makes
// the strip actually run. That is the whole point: an operator parking one
// unrelated line with `inactive:` is enough to route the tree through the clone,
// and without the copy the remediation list silently changes meaning. Measured
// with the copy deleted:
//
//	ThenCommands ["set" "system host-name pwned"]  ->  ["set system host-name pwned"]
//
// i.e. a batch classifyPlan declines becomes one it applies. Fail-open, reached
// by a config change that has nothing to do with event-options.
func TestInactiveStripPreservesQuoteProvenance_6673(t *testing.T) {
	src := `system {
  inactive: host-name parked;
}
event-options {
  policy p {
    then {
      change-configuration {
        commands [ "set" "system host-name pwned" ];
      }
    }
  }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	// PRECONDITION: without an inactive node WithoutInactive short-circuits and
	// stripInactiveNodes never runs, so the fixture would bind nothing.
	if !tree.HasInactiveNodes() {
		t.Fatal("fixture precondition: the tree must carry an inactive node, or the " +
			"strip returns the receiver unchanged and this test exercises no copy")
	}

	stripped := tree.WithoutInactive()
	if stripped == tree {
		t.Fatal("fixture precondition: WithoutInactive returned the receiver, so no clone " +
			"happened and the copy under test never ran")
	}
	n := stripped.FindChild("event-options").FindChild("policy").FindChild("then").
		FindChild("change-configuration").FindChild("commands")
	if n == nil {
		t.Fatal("the stripped tree lost the commands node")
	}
	if !n.KeysHaveQuoteProvenance() {
		t.Fatalf("the inactive strip DROPPED quote provenance (Keys=%q KeysQuoted=%v). "+
			"WithoutInactive produces the tree the compiler reads, so a lost mask here "+
			"silently re-keys every multi-value leaf below it (#6673 r11 F1)",
			n.Keys, n.KeysQuoted)
	}

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled %d event policies, want 1", len(cfg.EventOptions))
	}
	got := cfg.EventOptions[0].ThenCommands
	want := []string{"set", "system host-name pwned"}
	if !equalStrings6673(got, want) {
		t.Fatalf("ThenCommands = %q (n=%d), want %q (n=%d). An unrelated `inactive:` "+
			"statement routes the tree through stripInactiveNodes; if that clone drops "+
			"KeysQuoted the two authored members FUSE into one applicable command",
			got, len(got), want, len(want))
	}
}

// childMask6673 returns the mask of the commands node's sole child, which is
// where the flat-set path puts the value list.
func childMask6673(t *testing.T, tree *ConfigTree) []bool {
	t.Helper()
	n := commandsNode6673(t, tree)
	if len(n.Children) != 1 {
		t.Fatalf("commands node has %d children, want 1", len(n.Children))
	}
	return n.Children[0].KeysQuoted
}

func equalBools6673(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
