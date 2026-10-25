package eventengine

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Round-9 differential guards for the two event-options arms #6659 widened.
//
// Both arms read Children EXCLUSIVELY before #6659 — unlike every other leaf in
// that change, which read nodeVal and therefore already preferred the node's own
// tail. That asymmetry is the whole bug class here: widening a Children-only
// reader to "tail AND children" PROMOTES tokens the previous reader discarded,
// and for these two arms the discarded token reaches a runtime consumer that
// rejects it. The result is a configuration BOTH trees accept where only the
// widened one makes the policy inert — which no compile-level assertion about
// the intermediate string can catch.
//
// Every case below therefore asserts the CONSUMER's verdict (does the constraint
// set admit the event / does the batch classify into an executable plan), and
// compares it against what origin/master's reader produces for the same AST
// rather than against a hand-written expectation.

// masterAttributesMatchExprs6673 is origin/master's `attributes-match` reader,
// verbatim (pkg/config/compiler_services.go before #6659):
//
//	for _, amChild := range child.Children {
//	    ep.AttributesMatch = append(ep.AttributesMatch, strings.Join(amChild.Keys, " "))
//	}
//
// It is the ORACLE for the shapes master compiled something from — the block,
// flat-set and mixed `bogus { … }` spellings. It is deliberately NOT an oracle
// for the packed/bracket spellings, where master compiled nothing at all (the
// #6659 fail-open); those are asserted against the constraint the operator
// authored instead.
func masterAttributesMatchExprs6673(n *config.Node) []string {
	var out []string
	for _, c := range n.Children {
		out = append(out, strings.Join(c.Keys, " "))
	}
	return out
}

// masterChangeConfigCommands6673 is origin/master's `then change-configuration
// commands` reader, verbatim:
//
//	for _, cmdChild := range cmdsNode.Children {
//	    ep.ThenCommands = append(ep.ThenCommands, cmdChild.Name())
//	}
//
// Name() is Keys[0], which truncated an UNQUOTED command to its first word —
// a real master bug #6659 fixed. Every command this oracle is used against is
// QUOTED (one token), so the two agree on these inputs and the oracle is sound
// here; do not reuse it for unquoted commands.
func masterChangeConfigCommands6673(n *config.Node) []string {
	var out []string
	for _, c := range n.Children {
		out = append(out, c.Name())
	}
	return out
}

func compilePolicy6673(t *testing.T, cfgText string) (*config.EventPolicy, *config.ConfigTree) {
	t.Helper()
	tree, perrs := config.NewParser(cfgText).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected a configuration origin/master accepts: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled %d event policies, want 1", len(cfg.EventOptions))
	}
	return cfg.EventOptions[0], tree
}

func policyNode6673(t *testing.T, tree *config.ConfigTree, path ...string) *config.Node {
	t.Helper()
	var cur *config.Node
	for _, n := range tree.Children {
		if n.Name() == "event-options" {
			cur = n
		}
	}
	if cur == nil {
		t.Fatal("no event-options node")
	}
	for _, seg := range path {
		next := cur.FindChild(seg)
		if next == nil {
			t.Fatalf("no %q under %q", seg, cur.Name())
		}
		cur = next
	}
	return cur
}

// TestEventAttributesMatch6673BracketListYieldsSeparateConstraints is the R1
// differential.
//
// `attributes-match [ "a" "b" ];` has NO children — the lexer strips the
// brackets and each quoted member lands as its own token on Keys[1:]. Joining
// that tail produces the single impossible expression
// `e.test-owner matches ^alice$ e.test-name matches ^wan$`.
// ValidateEventAttributesMatchStrict splits only the FIRST " matches " and
// accepts the remainder as a (compilable) regex, so commit succeeds — and then
// attributesMatch compares that composite pattern against ev.TestOwner alone and
// never matches. Master compiled no constraints from a packed tail at all, so
// the policy FIRED; the widened read makes the same config permanently inert.
//
// The assertion is the engine's verdict, not the compiler's string.
func TestEventAttributesMatch6673BracketListYieldsSeparateConstraints(t *testing.T) {
	pol, _ := compilePolicy6673(t, `event-options {
  policy p {
    events ping_test_failed;
    attributes-match [ "ping_test_failed.test-owner matches ^alice$" "ping_test_failed.test-name matches ^wan$" ];
    then { change-configuration { commands { "set system host-name fired"; } } }
  }
}`)

	e := &Engine{}
	authored := rpm.Event{Name: "ping_test_failed", TestOwner: "alice", TestName: "wan"}
	if !e.attributesMatch(pol, authored) {
		t.Fatalf("policy does not fire for the event it was written for "+
			"(TestOwner=%q TestName=%q); compiled constraints = %q.\n"+
			"A bracketed attributes-match list must compile to ONE CONSTRAINT "+
			"PER MEMBER. Joining the members yields a single expression whose "+
			"regex is everything after the FIRST \" matches \", which is "+
			"compared against ev.TestOwner alone and can never match — the "+
			"policy is accepted at commit and never fires, while origin/master "+
			"(which compiled no packed-tail constraint at all) fired.",
			authored.TestOwner, authored.TestName, pol.AttributesMatch)
	}
	if got := len(pol.AttributesMatch); got != 2 {
		t.Fatalf("compiled %d attributes-match constraints from a 2-member "+
			"bracket list, want 2: %q", got, pol.AttributesMatch)
	}

	// Both constraints must actually BIND, or "it fires" would be satisfied by
	// compiling nothing — which is exactly master's fail-open.
	for _, tc := range []struct {
		name string
		ev   rpm.Event
	}{
		{"first member must bind", rpm.Event{Name: "ping_test_failed", TestOwner: "bob", TestName: "wan"}},
		{"second member must bind", rpm.Event{Name: "ping_test_failed", TestOwner: "alice", TestName: "lan"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e.attributesMatch(pol, tc.ev) {
				t.Fatalf("policy fires for TestOwner=%q TestName=%q; the "+
					"constraint list %q must NARROW the policy, not just exist",
					tc.ev.TestOwner, tc.ev.TestName, pol.AttributesMatch)
			}
		})
	}
}

// TestEventChangeConfigCommands6673MixedShapeStaysExecutable is the R2
// differential.
//
// `commands bogus { "set system host-name fired"; }` parses as
// Keys=["commands","bogus"] with one child. Master read Children only, ignored
// `bogus`, and the remediation ran. Emitting BOTH hands classifyPlan a token
// matching neither the `set ` nor the `delete ` prefix, and classifyPlan rejects
// the WHOLE batch — HandleEvent then drops it. Both trees accept the config;
// only the widened read makes the remediation inert.
//
// The expectation is origin/master's own reader output run through the same
// classifyPlan, not a hardcoded (ok, ops) pair.
func TestEventChangeConfigCommands6673MixedShapeStaysExecutable(t *testing.T) {
	const cfgText = `event-options {
  policy p {
    events ping_test_failed;
    then { change-configuration { commands bogus { "set system host-name fired"; } } }
  }
}`
	pol, tree := compilePolicy6673(t, cfgText)
	cmdsNode := policyNode6673(t, tree, "policy", "then", "change-configuration", "commands")
	masterCmds := masterChangeConfigCommands6673(cmdsNode)
	if len(masterCmds) != 1 {
		t.Fatalf("oracle premise broken: origin/master's reader produced %q, "+
			"want exactly the one child command", masterCmds)
	}

	e := &Engine{}
	wantOps, wantOK := e.classifyPlan(&config.EventPolicy{Name: "p", ThenCommands: masterCmds})
	gotOps, gotOK := e.classifyPlan(pol)

	if gotOK != wantOK || len(gotOps) != len(wantOps) {
		t.Fatalf("classifyPlan(head ThenCommands=%q) = (%d ops, ok=%v); "+
			"classifyPlan(origin/master ThenCommands=%q) = (%d ops, ok=%v).\n"+
			"The node's own tail is the identifier slot master DISCARDED. "+
			"Promoting it into the command list makes classifyPlan reject the "+
			"whole batch (`return nil, false`), so a remediation that ran "+
			"before #6659 silently stops running while the configuration still "+
			"commits.", pol.ThenCommands, len(gotOps), gotOK,
			masterCmds, len(wantOps), wantOK)
	}
	if !gotOK || len(gotOps) != 1 {
		t.Fatalf("the remediation must classify into exactly one executable op, "+
			"got %d ops ok=%v from ThenCommands=%q", len(gotOps), gotOK, pol.ThenCommands)
	}
}

// TestEventChangeConfigCommands6673PackedFormStillWidens is the CONTROL that
// stops the R2 fix from degenerating into "restore master".
//
// A `commands` node with NO children is the shape master compiled NOTHING from
// (the #6659 fail-open). Its tail must still be read, one command per token.
func TestEventChangeConfigCommands6673PackedFormStillWidens(t *testing.T) {
	pol, tree := compilePolicy6673(t, `event-options {
  policy p {
    events ping_test_failed;
    then { change-configuration { commands [ "set system host-name a" "set system host-name b" ]; } }
  }
}`)
	cmdsNode := policyNode6673(t, tree, "policy", "then", "change-configuration", "commands")
	if got := masterChangeConfigCommands6673(cmdsNode); len(got) != 0 {
		t.Fatalf("oracle premise broken: origin/master compiled %q from a "+
			"packed `commands` list; it must compile nothing (that is the "+
			"#6659 fail-open)", got)
	}
	e := &Engine{}
	ops, ok := e.classifyPlan(pol)
	if !ok || len(ops) != 2 {
		t.Fatalf("packed `commands [ a b ]` classified into %d ops ok=%v from "+
			"ThenCommands=%q, want 2 executable ops — the #6659 widening must "+
			"survive the mixed-shape fix", len(ops), ok, pol.ThenCommands)
	}
}

// TestEventAttributesMatch6673PackedFormStillWidens is the matching CONTROL for
// the attributes-match arm: a packed single expression has no children, so the
// tail must still compile into the one constraint master dropped.
func TestEventAttributesMatch6673PackedFormStillWidens(t *testing.T) {
	pol, tree := compilePolicy6673(t, `event-options {
  policy p {
    events ping_test_failed;
    attributes-match "ping_test_failed.test-owner matches ^alice$";
  }
}`)
	amNode := policyNode6673(t, tree, "policy", "attributes-match")
	if got := masterAttributesMatchExprs6673(amNode); len(got) != 0 {
		t.Fatalf("oracle premise broken: origin/master compiled %q from a "+
			"packed attributes-match; it must compile nothing", got)
	}
	e := &Engine{}
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "alice"}) {
		t.Fatalf("packed attributes-match does not admit the event it names; "+
			"constraints = %q", pol.AttributesMatch)
	}
	if e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "bob"}) {
		t.Fatalf("packed attributes-match compiled to nothing (the #6659 "+
			"fail-open is back); constraints = %q", pol.AttributesMatch)
	}
}

// TestEventAttributesMatch6673UnquotedPackedStaysOneExpression pins the OTHER
// side of the bracket-vs-token discrimination: an UNQUOTED packed expression is
// split into bare tokens by the lexer and must be re-joined into ONE constraint,
// not turned into three malformed ones. Without this the R1 fix would break the
// spelling #6659 was written to support.
func TestEventAttributesMatch6673UnquotedPackedStaysOneExpression(t *testing.T) {
	pol, _ := compilePolicy6673(t, `event-options {
  policy p {
    events ping_test_failed;
    attributes-match ping_test_failed.test-owner matches alice;
  }
}`)
	if len(pol.AttributesMatch) != 1 {
		t.Fatalf("unquoted packed attributes-match compiled to %d constraints "+
			"(%q), want exactly 1 — its tokens are ONE expression, not a list",
			len(pol.AttributesMatch), pol.AttributesMatch)
	}
	e := &Engine{}
	if !e.attributesMatch(pol, rpm.Event{Name: "ping_test_failed", TestOwner: "alice"}) {
		t.Fatalf("unquoted packed constraint %q does not admit its own event",
			pol.AttributesMatch)
	}
}

// --- #6673 fold: the FLAT-SET parser shape, which this file had never driven --

// compileFlatSetPolicy6673 builds the candidate the way an operator using
// `set` / `load set` does — ParseSetCommand + SetPath, never NewParser (which
// merges every set line into one node, per CLAUDE.md).
//
// Every test above this line drives config text through NewParser. That is why
// none of them saw the regression below: a bracketed list lands on the node's
// own Keys under the hierarchical parser but on ONE CHILD's Keys under SetPath,
// and the two shapes were read by different branches of the same helper.
func compileFlatSetPolicy6673(t *testing.T, cmds ...string) *config.EventPolicy {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected a configuration origin/master accepts: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled %d event policies, want 1", len(cfg.EventOptions))
	}
	return cfg.EventOptions[0]
}

// TestEventChangeConfigCommands6673FlatSetBracketStaysExecutable is the F1
// differential, and it is a REGRESSION guard rather than a fail-open guard —
// the branch was strictly worse than origin/master at this shape.
//
// `set … commands [ "set system host-name foo" "delete system host-name" ]`
// puts both members on ONE CHILD's Keys. The children branch joined them, so
// the policy compiled to the single string
// "set system host-name foo delete system host-name".
//
// That string is not merely a lost command. It carries the `set ` prefix, so
// classifyPlan ACCEPTS it: ParseSetCommand parses the six remaining tokens into
// a path and the batch classifies ok with one op. The remediation therefore
// stops applying command #1 (what master did, dropping the rest) and starts
// applying a path the operator never wrote, which the candidate commit then
// rejects — the automation stops working entirely where it previously worked
// partially.
//
// The assertion is classifyPlan's verdict plus the op's own setInput, because
// "ok=true with one op" is exactly what the FUSED value also produces; only the
// path inside the op separates them.
func TestEventChangeConfigCommands6673FlatSetBracketStaysExecutable(t *testing.T) {
	pol := compileFlatSetPolicy6673(t,
		"set event-options policy p events ping_test_failed",
		`set event-options policy p then change-configuration commands [ "set system host-name foo" "delete system host-name" ]`,
	)

	e := &Engine{}
	ops, ok := e.classifyPlan(pol)
	if !ok {
		t.Fatalf("flat-set bracket `commands` classified as UNEXECUTABLE from "+
			"ThenCommands=%q", pol.ThenCommands)
	}
	if len(ops) != 2 {
		t.Fatalf("flat-set bracket `commands` classified into %d ops from "+
			"ThenCommands=%q, want 2 — the two bracket members fused into one "+
			"string, and because it still starts with `set ` classifyPlan "+
			"accepts it and the remediation applies a path the operator never "+
			"wrote", len(ops), pol.ThenCommands)
	}
	if ops[0].setInput != "system host-name foo" {
		t.Fatalf("first op setInput = %q, want %q — anything longer means the "+
			"second bracket member was fused onto the first command's path",
			ops[0].setInput, "system host-name foo")
	}
	if !ops[1].isDelete {
		t.Fatalf("second op is not a delete (raw = %q); the `delete …` member "+
			"of the bracket must survive as its own operation", ops[1].raw)
	}
}

// TestEventAttributesMatch6673FlatSetBracketYieldsSeparateConstraints is the F2
// differential — the same AST shape, on the other leaf.
//
// This one is NOT a regression against master: master fused it identically. It
// is the failure the branch's own docs declared fixed and located "there, and
// only there" — the branch widened the tail read but left the flat-set child
// shape fusing, so a two-member list committed clean and then matched nothing,
// because ParseEventAttributesMatch splits at the FIRST separator and treats
// everything after it as one regex.
//
// It fails CLOSED at runtime (attributesMatch rejects a non-matching pattern),
// so the cost is a policy that never fires rather than one that always does.
func TestEventAttributesMatch6673FlatSetBracketYieldsSeparateConstraints(t *testing.T) {
	pol := compileFlatSetPolicy6673(t,
		"set event-options policy p events ping_test_failed",
		`set event-options policy p attributes-match [ "ping_test_failed.test-owner matches ^alice$" "ping_test_failed.test-name matches ^wan$" ]`,
	)

	e := &Engine{}
	authored := rpm.Event{Name: "ping_test_failed", TestOwner: "alice", TestName: "wan"}
	if !e.attributesMatch(pol, authored) {
		t.Fatalf("policy does not fire for the event it was written for "+
			"(TestOwner=%q TestName=%q); compiled constraints = %q. A "+
			"flat-set bracketed attributes-match list must compile to ONE "+
			"CONSTRAINT PER MEMBER; fused, the regex is everything after the "+
			"first \" matches \" and is compared against ev.TestOwner alone, "+
			"so the policy commits clean and never matches anything.",
			authored.TestOwner, authored.TestName, pol.AttributesMatch)
	}
	if got := len(pol.AttributesMatch); got != 2 {
		t.Fatalf("compiled %d attributes-match constraints from a 2-member "+
			"flat-set bracket list, want 2: %q", got, pol.AttributesMatch)
	}
	// Both must BIND, or "it fires" is satisfied by compiling nothing.
	for _, tc := range []struct {
		name string
		ev   rpm.Event
	}{
		{"first member must bind", rpm.Event{Name: "ping_test_failed", TestOwner: "bob", TestName: "wan"}},
		{"second member must bind", rpm.Event{Name: "ping_test_failed", TestOwner: "alice", TestName: "lan"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e.attributesMatch(pol, tc.ev) {
				t.Fatalf("policy fires for TestOwner=%q TestName=%q; the "+
					"constraint list %q must NARROW the policy, not just exist",
					tc.ev.TestOwner, tc.ev.TestName, pol.AttributesMatch)
			}
		})
	}
}

// TestEventChangeConfigCommands6673FlatSetUnquotedStaysOneCommand is the
// OVER-REACH guard for the pair above, and it is what rules out the schema fix.
//
// Declaring these two leaves `multi: true` in setSchema makes SetPath absorb a
// bracket onto the node's own tail — which does fix the two tests above — but
// it absorbs an UNQUOTED command's bare words the same way, and the tail is
// read per token. `set … commands set system host-name foo` then compiles to
// four bare words, none of which carries a `set `/`delete ` prefix, so
// classifyPlan rejects the whole batch and the remediation never runs. Measured
// firsthand before choosing the reader fix instead.
func TestEventChangeConfigCommands6673FlatSetUnquotedStaysOneCommand(t *testing.T) {
	pol := compileFlatSetPolicy6673(t,
		"set event-options policy p events ping_test_failed",
		`set event-options policy p then change-configuration commands set system host-name foo`,
	)
	e := &Engine{}
	ops, ok := e.classifyPlan(pol)
	if !ok || len(ops) != 1 {
		t.Fatalf("unquoted flat-set `commands` classified into %d ops ok=%v "+
			"from ThenCommands=%q, want 1 executable op — its bare words are "+
			"ONE command, not a list", len(ops), ok, pol.ThenCommands)
	}
	if ops[0].setInput != "system host-name foo" {
		t.Fatalf("op setInput = %q, want %q", ops[0].setInput, "system host-name foo")
	}
}

// TestEventChangeConfigCommands6673FlatSetRepeatedStatementsAllSurvive is the
// second over-reach guard, and it pins the OTHER thing `multi: true` breaks.
//
// Under `multi`, repeated flat-set statements become distinct SIBLING
// `commands` nodes instead of merging into one node's children — and
// compileEventOptions reaches the leaf through ccNode.FindChild (SINGULAR), so
// every sibling after the first is silently dropped. That is worse than both
// master and the branch. Measured firsthand; this guard makes the loss visible
// if anyone declares the leaf `multi` without also making the reader
// sibling-aware.
func TestEventChangeConfigCommands6673FlatSetRepeatedStatementsAllSurvive(t *testing.T) {
	pol := compileFlatSetPolicy6673(t,
		"set event-options policy p events ping_test_failed",
		`set event-options policy p then change-configuration commands "set system host-name foo"`,
		`set event-options policy p then change-configuration commands "delete system host-name"`,
	)
	e := &Engine{}
	ops, ok := e.classifyPlan(pol)
	if !ok || len(ops) != 2 {
		t.Fatalf("two repeated flat-set `commands` statements classified into "+
			"%d ops ok=%v from ThenCommands=%q, want 2 — a dropped sibling is "+
			"a remediation step that silently never runs",
			len(ops), ok, pol.ThenCommands)
	}
}
