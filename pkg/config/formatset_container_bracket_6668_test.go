package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// #6668 — a bracket list authored at a CONTAINER position did not survive
// `show | display set`.
//
// THE DEFECT. The flat-set language re-splits a `set` line into nodes at each
// keyword's schema arity, so it can express a container carrying exactly
// `1 + args` keys and nothing wider. A bracket list authored at a container
// position is wider:
//
//	interfaces { [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { ... } } }
//	  -> ONE node, Keys=["ge-0/0/0","ge-0/0/1"], body as its children
//
// FormatSet flattened that to a bare token run. Replaying the run made
// `ge-0/0/0` the container and demoted `ge-0/0/1` from a zone MEMBER to the
// first key of a LEAF, with the whole host-inbound body re-parented under it.
//
// WHY IT IS NOT A DISPLAY BUG. configstore's LoadMergeAs renders a parsed
// hierarchical file with FormatSet and replays it through applyEditLine, so
// `load merge <file>` — reachable from the CLI, gRPC and REST — rewrote the
// operator's config INSIDE the daemon and reported the merge successful.
//
// WHY NOTHING CAUGHT IT. Every token survives the trip, so no token-count or
// idempotency check can see it: FormatSet of the damaged tree is BYTE-IDENTICAL
// to FormatSet of the original, a fixed point. TestDualASTDifferential does
// exactly the right round trip and its step-4 sanity gate compares FormatSet
// TEXT, which is blind here; its 29 bracket fixtures are all value LEAVES,
// which round-trip clean by construction (SetPath's trailing-value absorber
// re-collapses a leaf's tail — the #2419 contract). Hence the structural gate
// this file installs, and the container fixtures added to that harness.
//
// THE DISPOSITION IS NOT UNIFORMLY FAIL-CLOSED, which is the part worth naming.
// For the zone-interfaces case the replay is REJECTED at commit. But
// `system login user [ alice bob ] { class super-user; }` is REJECTED as
// authored and its round-tripped form COMMITTED CLEAN with the second member's
// body gone — a round trip that launders a config past a commit gate and hands
// the operator a different, narrower login model than the one they wrote.

// bracketedContainerStructureDiff compares two node forests and reports the
// first place where a CONTAINER whose keys were authored inside a `[ ... ]`
// list on the left has no counterpart with the SAME keys on the right.
//
// It is deliberately one-directional and scoped: it asks only about groups the
// operator actually bracketed. A blanket structural equality would also fail
// the packed-statement family, whose flat replay re-nests legitimately.
func bracketedContainerStructureDiff(want, got []*Node, path []string) string {
	byKeys := func(nodes []*Node) map[string]*Node {
		m := make(map[string]*Node, len(nodes))
		for _, n := range nodes {
			if n != nil {
				m[strings.Join(n.Keys, "\x00")] = n
			}
		}
		return m
	}
	gotByKeys := byKeys(got)
	for _, w := range want {
		if w == nil {
			continue
		}
		here := append(append([]string(nil), path...), w.Keys...)
		g := gotByKeys[strings.Join(w.Keys, "\x00")]
		if g == nil {
			if isBracketedContainer(w) {
				return fmt.Sprintf(
					"at %q: authored container Keys=%v is absent after the round trip; "+
						"the replay produced %v instead",
					strings.Join(path, " "), w.Keys, keySets(got))
			}
			continue
		}
		if d := bracketedContainerStructureDiff(w.Children, g.Children, here); d != "" {
			return d
		}
	}
	return ""
}

func isBracketedContainer(n *Node) bool {
	if n == nil || n.IsLeaf || len(n.KeysBracketed) != len(n.Keys) {
		return false
	}
	for _, b := range n.KeysBracketed {
		if b {
			return true
		}
	}
	return false
}

func keySets(nodes []*Node) [][]string {
	out := make([][]string, 0, len(nodes))
	for _, n := range nodes {
		if n != nil {
			out = append(out, n.Keys)
		}
	}
	return out
}

// replayDisplaySet6668 replays FormatSet output the way the service load paths
// do (configstore applyEditLine): ParseSetVerbGrouped + the grouped edit
// entries. Using the UNGROUPED entries here would measure a replay no
// production path performs.
func replayDisplaySet6668(t *testing.T, setText string) *ConfigTree {
	t.Helper()
	out := &ConfigTree{}
	for _, line := range strings.Split(setText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		verb, path, quoted, grouped, err := ParseSetVerbGrouped(line)
		if err != nil {
			t.Fatalf("ParseSetVerbGrouped(%q): %v", line, err)
		}
		switch verb {
		case verbDelete:
			err = out.DeletePathGrouped(path, grouped)
		case verbDeactivate:
			err = out.DeactivatePathGrouped(path, grouped)
		case verbActivate:
			err = out.ActivatePathGrouped(path, grouped)
		default:
			err = out.SetPathQuotedGrouped(path, quoted, grouped)
		}
		if err != nil {
			t.Fatalf("replay %q: %v", line, err)
		}
	}
	return out
}

func parseHier6668(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v", errs)
	}
	return tree
}

const zoneIfaceBracketBody6668 = `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.2.1/24; } } }
}
security {
    zones {
        security-zone trust {
            interfaces {
                [ ge-0/0/0 ge-0/0/1 ] {
                    host-inbound-traffic { system-services ssh; }
                }
            }
        }
    }
}
`

// TestBracketedContainerSurvivesDisplaySet_6668 is the issue's exact shape. It
// asserts the THREE things that were each independently broken: the flat line
// carries the boundary, the replayed tree has the same node, and the two
// compile to the same typed config.
func TestBracketedContainerSurvivesDisplaySet_6668(t *testing.T) {
	hier := parseHier6668(t, zoneIfaceBracketBody6668)

	setText := hier.FormatSet()
	if !strings.Contains(setText, "[ ge-0/0/0 ge-0/0/1 ]") {
		t.Fatalf("display-set output does not carry the authored bracket group:\n%s", setText)
	}

	flat := replayDisplaySet6668(t, setText)

	// The member must still be a MEMBER, not a leaf keyword. Assert the node
	// exists with BOTH keys — the pre-fix tree had Keys=["ge-0/0/0"] with a
	// leaf Keys=["ge-0/0/1","host-inbound-traffic","system-services","ssh"]
	// under it, which is a different config that still commits on some shapes.
	ifNode := findNode6668(flat.Children, []string{"security"}, []string{"zones"}, []string{"security-zone", "trust"}, []string{"interfaces"})
	if ifNode == nil {
		t.Fatalf("replayed tree has no security-zone trust interfaces node")
	}
	if len(ifNode.Children) != 1 {
		t.Fatalf("interfaces should hold ONE bracketed member node, got %v", keySets(ifNode.Children))
	}
	member := ifNode.Children[0]
	if len(member.Keys) != 2 || member.Keys[0] != "ge-0/0/0" || member.Keys[1] != "ge-0/0/1" {
		t.Errorf("member node Keys = %v, want [ge-0/0/0 ge-0/0/1] — the second member was demoted", member.Keys)
	}
	if member.IsLeaf {
		t.Errorf("member node became a leaf; the host-inbound body was re-parented")
	}

	if d := bracketedContainerStructureDiff(hier.Children, flat.Children, nil); d != "" {
		t.Errorf("structure diff: %s", d)
	}

	wantCfg, err := CompileConfig(hier)
	if err != nil {
		t.Fatalf("fixture bug: hierarchical CompileConfig: %v", err)
	}
	gotCfg, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("replayed tree failed to compile: %v", err)
	}
	wantZone := mustMarshal6668(t, wantCfg.Security.Zones)
	gotZone := mustMarshal6668(t, gotCfg.Security.Zones)
	if wantZone != gotZone {
		t.Errorf("compiled zones differ after the round trip\n want %s\n  got %s", wantZone, gotZone)
	}
}

// TestDisplaySetReplayKeepsTheCommitVerdict_6668 is the property that makes
// this a security-relevant defect rather than a formatting one: replaying a
// config's own `display set` output must not change whether it COMMITS.
//
// Both directions are pinned. `applications` and `screen` were Accept->Reject
// (lost work); `system login user` and `class-of-service scheduler-maps` were
// Reject->Accept — the round trip LAUNDERED a config past a commit gate with a
// member's body silently dropped. A test that only pinned "still rejected"
// would pass on a fix that rejected everything, so the accepted cases are
// asserted to still commit.
func TestDisplaySetReplayKeepsTheCommitVerdict_6668(t *testing.T) {
	cases := []struct {
		name       string
		hier       string
		wantCommit bool
		// why names the direction this row guards, so a future edit that
		// flips wantCommit has to argue with the reason rather than the value.
		why string
	}{
		{
			name:       "zone-interfaces-with-body",
			hier:       zoneIfaceBracketBody6668,
			wantCommit: true,
			why:        "authored form is valid and compiles; the replay was REJECTED (lost work)",
		},
		{
			name: "security-zone-list",
			hier: `security { zones { security-zone [ trust dmz ] {
			           host-inbound-traffic { system-services ssh; } } } }`,
			wantCommit: true,
			why:        "two zones sharing a body; the replay split the list",
		},
		{
			name:       "applications",
			hier:       `applications { application [ a1 a2 ] { protocol tcp; } }`,
			wantCommit: true,
			why:        `replay was rejected with 'unknown statement "a2" in the application body'`,
		},
		{
			name:       "screen-ids-option",
			hier:       `security { screen { ids-option [ s1 s2 ] { icmp { flood; } } } }`,
			wantCommit: true,
			why:        "replay was rejected with `s2` is not a supported screen option",
		},
		{
			name:       "login-user-list",
			hier:       `system { login { user [ alice bob ] { class super-user; } } } `,
			wantCommit: false,
			why: "REJECT->ACCEPT laundering: authored form is refused because a body " +
				"on the instance line is silently dropped, but the replayed form " +
				"COMMITTED with bob's body gone — a narrower login model than authored",
		},
		{
			name: "cos-scheduler-maps-list",
			hier: `class-of-service { scheduler-maps [ m1 m2 ] {
			           forwarding-class be { scheduler s1; } } }`,
			wantCommit: false,
			why: "REJECT->ACCEPT laundering: the undefined-scheduler binding was " +
				"dissolved into a leaf by the replay, so the reference gate stopped firing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hier := parseHier6668(t, tc.hier)
			_, hierErr := CompileConfig(hier)
			if (hierErr == nil) != tc.wantCommit {
				t.Fatalf("fixture bug (%s): authored form commit=%v, want %v (err=%v)",
					tc.why, hierErr == nil, tc.wantCommit, hierErr)
			}
			flat := replayDisplaySet6668(t, hier.FormatSet())
			_, flatErr := CompileConfig(flat)
			if (flatErr == nil) != tc.wantCommit {
				t.Fatalf("replay flipped the commit verdict (%s): commit=%v, want %v (err=%v)\nset text:\n%s",
					tc.why, flatErr == nil, tc.wantCommit, flatErr, hier.FormatSet())
			}
			if d := bracketedContainerStructureDiff(hier.Children, flat.Children, nil); d != "" {
				t.Errorf("structure diff: %s", d)
			}
		})
	}
}

// TestBracketedValueLeavesRenderUnchanged_6668 pins the ZERO-CHURN half. A
// bracketed VALUE list already round-trips clean — SetPath's absorber
// re-collapses a leaf's tail — so emitting a delimiter for it would rewrite
// every such line in every deployed `display set` transcript for no
// information. This fails if the render ever starts bracketing leaves.
func TestBracketedValueLeavesRenderUnchanged_6668(t *testing.T) {
	fixtures := map[string]string{
		"policy-match-source-address": `security { policies { from-zone trust to-zone untrust {
		    policy p1 { match { source-address [ a b c ]; destination-address any; application any; }
		                then { permit; } } } } }`,
		"host-inbound-system-services": `security { zones { security-zone trust {
		    host-inbound-traffic { system-services [ ssh ping ]; } } } }`,
		"system-name-server":   `system { name-server [ 1.1.1.1 8.8.8.8 ]; }`,
		"static-route-nexthop": `routing-options { static { route 0.0.0.0/0 { next-hop [ 10.0.0.1 10.0.0.2 ]; } } }`,
		"firewall-from-protocol": `firewall { family inet { filter f1 { term t1 {
		    from { protocol [ tcp udp icmp ]; } then { accept; } } } } }`,
	}
	for name, src := range fixtures {
		t.Run(name, func(t *testing.T) {
			hier := parseHier6668(t, src)
			setText := hier.FormatSet()
			if strings.Contains(setText, "[") || strings.Contains(setText, "]") {
				t.Errorf("value list acquired a bracket delimiter — this is churn, not a fix:\n%s", setText)
			}
			flat := replayDisplaySet6668(t, setText)
			if hier.FormatSet() != flat.FormatSet() {
				t.Errorf("value list stopped round-tripping:\n--- want ---\n%s--- got ---\n%s",
					hier.FormatSet(), flat.FormatSet())
			}
		})
	}
}

// TestPackedContainerIsNotBracketed_6668 pins that the render keys off authored
// PROVENANCE, not off "more keys than the schema arity".
//
// The arity rule also catches the packed-statement family — a class whose flat
// replay already reconstructs an equivalent config, and which is tracked
// separately (#6588/#6665/#6672). Bracketing it would rewrite four lines of the
// class-of-service dual-AST fixture and zero lines of the case this fix exists
// for. Measured, not assumed: this fixture carries containers with more keys
// than their arity and NO bracket, and must render bare.
func TestPackedContainerIsNotBracketed_6668(t *testing.T) {
	hier := parseHier6668(t, `
class-of-service {
    scheduler-maps edge-map { forwarding-class best-effort { scheduler be-sched; } }
    interfaces ge-0/0/1 { unit 0 shaping-rate 10g { burst-size 125m; } }
}
`)
	setText := hier.FormatSet()
	if strings.Contains(setText, "[") {
		t.Errorf("packed statement was bracketed — the render is keying off arity, not provenance:\n%s", setText)
	}
}

// TestDeactivatedBracketedContainerRoundTrips_6668 covers the second verb.
// `display set` emits a node's `set` line(s) and then its `deactivate` line
// over the SAME tokens, so the deactivate walk has to tokenize them the same
// way. Before the grouped delete/deactivate entries it did not, and the replay
// aborted — which on LoadMerge fails the whole file.
func TestDeactivatedBracketedContainerRoundTrips_6668(t *testing.T) {
	hier := parseHier6668(t, `
security { zones { security-zone trust { interfaces {
    inactive: [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { system-services ssh; } }
} } } }
`)
	setText := hier.FormatSet()
	if !strings.Contains(setText, "deactivate security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]") {
		t.Fatalf("deactivate line lost the bracket group:\n%s", setText)
	}
	flat := replayDisplaySet6668(t, setText)
	member := findNode6668(flat.Children, []string{"security"}, []string{"zones"}, []string{"security-zone", "trust"},
		[]string{"interfaces"}, []string{"ge-0/0/0", "ge-0/0/1"})
	if member == nil {
		t.Fatalf("replayed tree lost the bracketed member node")
	}
	if !member.Inactive {
		t.Errorf("node reloaded ACTIVE — the deactivate line did not find it")
	}
}

// TestBracketProvenanceSurvivesCloneAndJSON_6668 binds the two places the
// provenance has to travel or the fix is a one-shot: configstore deep-clones
// the candidate on every merge (LoadMergeAs works on a clone and swaps it in),
// and persists the tree as JSON. A provenance that does not survive either one
// means the very next render after a merge or a reboot flattens the group again.
func TestBracketProvenanceSurvivesCloneAndJSON_6668(t *testing.T) {
	hier := parseHier6668(t, zoneIfaceBracketBody6668)
	want := hier.FormatSet()

	if got := hier.Clone().FormatSet(); got != want {
		t.Errorf("Clone dropped the bracket provenance\n want %s\n  got %s", want, got)
	}

	blob, err := json.Marshal(hier)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ConfigTree
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := back.FormatSet(); got != want {
		t.Errorf("JSON round trip dropped the bracket provenance\n want %s\n  got %s", want, got)
	}

	// WithoutInactive returns the clone the compiler and the schema walker
	// actually read — but it is a NO-OP (no clone at all) when nothing is
	// deactivated, so a fixture with no inactive node cannot exercise the copy
	// and would pass with the provenance dropped. Give it something to strip.
	withInactive := parseHier6668(t, zoneIfaceBracketBody6668+`
system {
    inactive: host-name fw-standby;
}
`)
	stripped := withInactive.WithoutInactive()
	if stripped == withInactive {
		t.Fatalf("fixture bug: WithoutInactive did not clone, so this asserts nothing")
	}
	if got := stripped.FormatSet(); !strings.Contains(got, "[ ge-0/0/0 ge-0/0/1 ]") {
		t.Errorf("WithoutInactive dropped the bracket provenance:\n%s", got)
	}
}

// TestLexerPeekRestoresBracketState_6668 is the unit guard for the subtlest
// part of the plumbing. Peek runs Next and rewinds; the bracket depth is part
// of the position it must rewind, because Next CONSUMES the delimiters. A Peek
// that stepped over a '[' and did not restore the depth would mark every later
// token — including tokens outside the list — as bracketed, which turns a
// whole statement into one node.
func TestLexerPeekRestoresBracketState_6668(t *testing.T) {
	l := NewLexer("a [ b c ] d")

	if tok := l.Next(); tok.Value != "a" || l.InBracket() {
		t.Fatalf("token %q InBracket=%v, want a/false", tok.Value, l.InBracket())
	}
	// Peek steps over the '['. Its state must not leak.
	if tok := l.Peek(); tok.Value != "b" {
		t.Fatalf("peek = %q, want b", tok.Value)
	}
	if l.InBracket() {
		t.Errorf("Peek leaked the bracket depth: InBracket() true after a peek, before consuming 'b'")
	}
	if tok := l.Next(); tok.Value != "b" || !l.InBracket() {
		t.Fatalf("token %q InBracket=%v, want b/true", tok.Value, l.InBracket())
	}
	if tok := l.Next(); tok.Value != "c" || !l.InBracket() {
		t.Fatalf("token %q InBracket=%v, want c/true", tok.Value, l.InBracket())
	}
	if tok := l.Next(); tok.Value != "d" || l.InBracket() {
		t.Fatalf("token %q InBracket=%v, want d/false", tok.Value, l.InBracket())
	}
}

// TestStrayCloseBracketDoesNotUnderflow_6668 pins the floor. Without it a
// stray ']' drives the depth negative and every LATER '[' in the file opens at
// depth 0 or below, so real groups stop being recorded — a malformed line
// silently disarming the grouping for the rest of the input.
//
// Since #9881 the token FOLLOWING the stray reports bracketed: the stray
// vanishes with no trace (no depth change for any later token to observe),
// so the follower carries the delimiter loss instead. The floor itself is
// unchanged — depth stays floored, the later `[ c ]` group still records,
// and its balanced close still marks nothing.
func TestStrayCloseBracketDoesNotUnderflow_6668(t *testing.T) {
	l := NewLexer("a ] b [ c ] d")
	want := map[string]bool{"a": false, "b": true, "c": true, "d": false}
	for {
		tok := l.Next()
		if tok.Type == TokenEOF {
			break
		}
		if got, ok := want[tok.Value]; ok && got != l.InBracket() {
			t.Errorf("token %q InBracket=%v, want %v", tok.Value, l.InBracket(), got)
		}
	}
}

// TestShortBracketGroupNeverNarrowsANode_6668 pins the "widen only" rule. A
// group shorter than the schema arity must leave the node exactly as the arity
// rule built it; narrowing would truncate a keyed container's identity and
// split one node into two.
func TestShortBracketGroupNeverNarrowsANode_6668(t *testing.T) {
	tree := &ConfigTree{}
	// The group must END before the arity slice does, or narrowing is
	// unobservable: `security-zone` takes two tokens, so a one-token group ON
	// THE KEYWORD is the shape where "narrow to the group's end" would cut the
	// instance name off the node. A group on the NAME instead
	// (`security-zone [ trust ]`) ends exactly where the arity slice ends and
	// cannot discriminate — that fixture varies the axis but samples only the
	// passing point.
	path, quoted, grouped, err := ParseSetCommandGrouped(
		"set security zones [ security-zone ] trust host-inbound-traffic system-services ssh")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
		t.Fatalf("set: %v", err)
	}
	zone := findNode6668(tree.Children, []string{"security"}, []string{"zones"}, []string{"security-zone", "trust"})
	if zone == nil {
		zones := findNode6668(tree.Children, []string{"security"}, []string{"zones"})
		var got [][]string
		if zones != nil {
			got = keySets(zones.Children)
		}
		t.Fatalf("a one-element group narrowed the keyed container: "+
			"want a node Keys=[security-zone trust], got %v", got)
	}
}

// findNode6668 walks a forest following exact key groups.
func findNode6668(nodes []*Node, groups ...[]string) *Node {
	var cur *Node
	for _, g := range groups {
		cur = nil
		for _, n := range nodes {
			if keysEqual(n.Keys, g) {
				cur = n
				break
			}
		}
		if cur == nil {
			return nil
		}
		nodes = cur.Children
	}
	return cur
}

func mustMarshal6668(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
