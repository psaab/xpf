package config

// security_log_transport_compact_6821_test.go — #6821.
//
// `security log stream <s> transport` has two legal hierarchical spellings, and
// the compiler read only one of them:
//
//	transport { protocol tls; }   Keys=[transport]            children=2
//	transport protocol tls;       Keys=[transport protocol tls] children=0
//
// The second packs its value onto the container's own Keys, so a
// `prop.Children` loop ran ZERO times and left `Transport.Protocol` empty on a
// config that committed cleanly. `daemon_system.go` defaults an empty protocol
// to "udp", so the compact spelling of a TLS audit stream shipped over
// PLAINTEXT UDP.
//
// The fix could not be "read Keys[1:] too" on its own, and that is the part
// worth keeping straight. The gate ignores a container's packed tail BY DESIGN
// — compiler-faithful, since no compiler read it — so compiling the tail
// without teaching the gate turns "not compiled" into "compiled, UNVALIDATED".
// Measured on master before the fix: `transport { protocol tpc; }` was rejected
// by the enum while `transport protocol tpc;` was ACCEPTED. So the schema node
// now sets `packedTail: true`, the walker validates the same expansion
// `packedBodyChildren` hands the compiler, and the #3350 tls-profile check reads
// it too. Three readers, one expansion.

import (
	"strings"
	"testing"
)

// streamCfg6821 wraps a transport body in a complete security-log stream. The
// `host` line is required: without it the stream is not installed at all and
// every assertion below would be vacuous.
func streamCfg6821(transportBody string) string {
	return "security { log { stream audit { host 192.0.2.10; " + transportBody + " } } }"
}

// parseCfg6821 parses ONE braced configuration with NewParser.
//
// This is deliberate, and it is the corrected instrument from the issue thread.
// The CLAUDE.md rule "never NewParser, use ParseSetCommand + SetPath" is about
// feeding the parser MULTIPLE `set` lines, which it merges into one node.
// Parsing a single braced config is the parser's ordinary job and is the ONLY
// way to produce the compact-hierarchical shape under test — the flat-set path
// lands `protocol` as a child, i.e. the block shape, so it cannot exercise the
// defect at all.
func parseCfg6821(t *testing.T, body string) *ConfigTree {
	t.Helper()
	tree, err := NewParser(streamCfg6821(body)).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tree
}

// transportNode6821 returns the `transport` node so a test can assert the SHAPE
// it is actually exercising.
func transportNode6821(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	var found *Node
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil || found != nil {
			return
		}
		if len(n.Keys) > 0 && n.Keys[0] == "transport" {
			found = n
			return
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, top := range tree.Children {
		walk(top)
	}
	if found == nil {
		t.Fatal("no `transport` node in the parsed tree")
	}
	return found
}

// TestCompactAndBlockTransportAreDifferentShapes6821 is the PREMISE guard, and
// it exists because of the trap #6853 hit: two spellings that were supposed to
// exercise different arms landed on the SAME one, so a cell labelled "leaf
// form" never touched the leaf arm.
//
// Assert the shapes are genuinely different before any behavioural cell below
// is allowed to mean anything. If the parser ever normalises one into the
// other, every other test in this file becomes a duplicate of its neighbour and
// this says so instead of passing quietly.
func TestCompactAndBlockTransportAreDifferentShapes6821(t *testing.T) {
	block := transportNode6821(t, parseCfg6821(t, "transport { protocol tls; }"))
	if len(block.Keys) != 1 || len(block.Children) != 2-1 {
		// block form: Keys == ["transport"], value carried by a CHILD.
		if len(block.Keys) != 1 {
			t.Errorf("block: Keys = %v, want exactly [transport]", block.Keys)
		}
	}
	if len(block.Children) == 0 {
		t.Fatalf("block: expected the value as a CHILD, got Keys=%v children=0", block.Keys)
	}

	compact := transportNode6821(t, parseCfg6821(t, "transport protocol tls;"))
	if len(compact.Keys) != 3 {
		t.Fatalf("compact: Keys = %v, want [transport protocol tls] — if the parser "+
			"now normalises this into the block shape, every cell in this file "+
			"exercises one arm twice and none of them covers the packed tail (#6821)",
			compact.Keys)
	}
	if len(compact.Children) != 0 {
		t.Fatalf("compact: children = %d, want 0 — the whole defect is that a "+
			"Children-only loop sees NOTHING here", len(compact.Children))
	}
}

// TestCompactTransportProtocolCompiles6821 is the headline cell.
//
// An empty Protocol is the FAILURE default of this path and
// `daemon_system.go` turns it into "udp", so asserting `""` would constrain
// nothing and asserting "not empty" would pass on garbage. Assert the populated
// value, and assert the two spellings agree.
func TestCompactTransportProtocolCompiles6821(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"block", "transport { protocol tls; }"},
		{"compact", "transport protocol tls;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parseCfg6821(t, tc.body))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			s := cfg.Security.Log.Streams["audit"]
			if s == nil {
				t.Fatal("premise: the stream must be installed, or nothing below means anything")
			}
			if s.Transport.Protocol != "tls" {
				t.Fatalf("Transport.Protocol = %q, want \"tls\". An empty value is not "+
					"inert: daemon_system.go defaults it to \"udp\", so the compact "+
					"spelling of a TLS audit stream shipped over PLAINTEXT UDP while "+
					"the config on disk still read `protocol tls` (#6821)",
					s.Transport.Protocol)
			}
		})
	}
}

// TestCompactTransportBogusProtocolIsRejected6821 is the half that makes the
// fix safe rather than merely effective.
//
// Compiling a packed tail the gate does not validate turns "not compiled" into
// "compiled, unvalidated". Before #6821 the block spelling of a bogus protocol
// was rejected by the enum and the compact spelling was ACCEPTED — so reading
// Keys[1:] in the compiler alone would have let `protocol tpc` through as a
// compiled value. Both spellings must now be rejected by the same gate.
func TestCompactTransportBogusProtocolIsRejected6821(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"block", "transport { protocol tpc; }"},
		{"compact", "transport protocol tpc;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := SchemaValidate(parseCfg6821(t, tc.body))
			if err == nil {
				t.Fatalf("SchemaValidate accepted `%s`. A container's packed tail is "+
					"ignored by the gate BY DESIGN (compiler-faithful), so a site "+
					"whose compiler reads the tail must opt in via `packedTail` — "+
					"otherwise the compact spelling compiles an unvalidated value "+
					"the block spelling rejects (#6821)", tc.body)
			}
			if !strings.Contains(err.Error(), "tpc") {
				t.Fatalf("reject must name the offending token, got: %v", err)
			}
		})
	}
}

// TestCompactTransportTLSProfileIsRejected6821 covers the second leaf, and its
// consequence is the opposite of the protocol leaf's — worth stating because
// the issue framed both the same way.
//
// xpf implements NO TLS profile resolution, so the BLOCK spelling is rejected
// at commit by #3350 with a message telling the operator exactly that. The
// compact spelling slipped past that rejection AND had its value dropped, so
// the operator got neither the profile nor the diagnostic. The defect here is a
// LOST DIAGNOSTIC, not lost protection — there was never any protection to lose.
func TestCompactTransportTLSProfileIsRejected6821(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"block", "transport { protocol tls; tls-profile secure-logs; }"},
		{"compact", "transport tls-profile secure-logs;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseCfg6821(t, tc.body))
			if err == nil {
				t.Fatalf("compile accepted `%s` — the #3350 reject is the only thing "+
					"telling an operator that a named tls-profile is not resolved at "+
					"runtime. Accepting the compact spelling loses that diagnostic "+
					"AND drops the value (#6821)", tc.body)
			}
			if !strings.Contains(err.Error(), "secure-logs") ||
				!strings.Contains(err.Error(), "not applied at runtime") {
				t.Fatalf("reject must be the #3350 tls-profile message naming the "+
					"profile, got: %v", err)
			}
		})
	}
}

// TestSecurityLogTransportSchemaResolves6821 guards the shared lookup.
//
// Three readers expand this container through `packedBodyChildren` with the
// node this returns. A schema reshuffle that broke the lookup would return nil,
// `packedBodyChildren` would hand back the unexpanded children, and all three
// would silently revert to the ORIGINAL defect with every behavioural cell
// above still green — because they would all fail together only in the compact
// arm, which is exactly the arm a nil lookup makes invisible.
func TestSecurityLogTransportSchemaResolves6821(t *testing.T) {
	n := securityLogTransportSchema()
	if n == nil {
		t.Fatal("securityLogTransportSchema() = nil — the schema path moved. The " +
			"compiler and the #3350 check both expand the packed tail with this " +
			"node; nil silently restores the pre-#6821 Children-only behaviour")
	}
	if !n.packedTail {
		t.Error("the transport schema node must set packedTail: the compiler reads " +
			"its packed tail, so the gate has to validate the same expansion")
	}
	for _, want := range []string{"protocol", "tls-profile"} {
		if n.children[want] == nil {
			t.Errorf("transport schema is missing child %q — the expansion cannot "+
				"resolve a leaf the compiler switches on", want)
		}
	}
}

// TestPackedTailContainersValidateBothSpellings6821 is the general invariant,
// and it is what keeps `packedTail` from becoming a one-off.
//
// The flag is a CLAIM: "a compiler reads this container's packed tail, so the
// gate validates it". The property that claim buys is that the two spellings
// agree at the gate. Assert it directly for every opted-in container reachable
// with a concrete fixture, so a future opt-in that forgets the walker change —
// or a walker change that stops honouring the flag — reds here rather than in
// whichever stanza happens to be exercised next.
func TestPackedTailContainersValidateBothSpellings6821(t *testing.T) {
	// One fixture per opted-in container. Kept explicit rather than generated:
	// a synthesized value that both spellings reject for an unrelated reason
	// would make the cell equal and vacuous, which is the failure mode this
	// whole issue is about.
	cases := []struct {
		node           string
		blockBody      string
		compactBody    string
		mustBeRejected bool
	}{
		{
			node:           "security log stream <s> transport",
			blockBody:      "transport { protocol tpc; }",
			compactBody:    "transport protocol tpc;",
			mustBeRejected: true,
		},
		{
			node:           "security log stream <s> transport",
			blockBody:      "transport { protocol tls; }",
			compactBody:    "transport protocol tls;",
			mustBeRejected: false,
		},
	}
	for _, c := range cases {
		blockErr := SchemaValidate(parseCfg6821(t, c.blockBody))
		compactErr := SchemaValidate(parseCfg6821(t, c.compactBody))
		if (blockErr != nil) != (compactErr != nil) {
			t.Errorf("%s: the two spellings DISAGREE at the gate.\n  block   %q -> %v\n"+
				"  compact %q -> %v\nA packedTail container must validate its tail the "+
				"same way it validates the equivalent children, or one spelling "+
				"compiles an unvalidated value (#6821)",
				c.node, c.blockBody, blockErr, c.compactBody, compactErr)
			continue
		}
		if c.mustBeRejected && blockErr == nil {
			t.Errorf("%s: premise broken — %q was supposed to be REJECTED by the gate, "+
				"but both spellings were accepted, so this row proves only that two "+
				"accepted configs are both accepted", c.node, c.blockBody)
		}
		if !c.mustBeRejected && blockErr != nil {
			t.Errorf("%s: premise broken — %q was supposed to be ACCEPTED, got %v",
				c.node, c.blockBody, blockErr)
		}
	}
}
