package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Tests for #6735: a `security zones security-zone <z> interfaces` member whose
// Keys carry `host-inbound-traffic` with FURTHER TOKENS AFTER IT.
//
// The lexer strips brackets (#2419), so these two statements are structurally
// identical by the time the compiler sees them:
//
//	interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];   // member list
//	interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh;  // packed body
//
// and their readings DISAGREE about zone membership. zoneInterfaceKeysBeforeBody
// truncates at the keyword, so the first silently loses member `ge-0/0/1.0` —
// a valid, defined interface the operator put in this zone, left with Zone == ""
// so the dataplane never binds it and no policy naming the zone applies to its
// traffic — and the second silently loses the whole override. The #6525
// non-empty belt cannot see the first: one member survived, so the stanza is not
// empty.
//
// The resolution is refusal, not a guess: reject at commit, warn on the tolerant
// path, and point the operator at the block spelling, which is unambiguous.

// zonePackedTailConfig wraps a zone stanza in a config that DEFINES both
// interfaces the tests reference, so a rejection can only come from the gate
// under test and never from the zone-interface-DEFINED gate.
func zonePackedTailConfig(stanza string) string {
	return `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            ` + stanza + `
        }
    }
}`
}

// TestZoneInterfaces6735PackedTailRejectedAndPositiveControl holds BOTH tables
// in one function on purpose. A rejection test alone cannot distinguish
// "rejects the ambiguous statement" from "rejects everything" — the accept
// table is what makes the reject table mean something, and keeping them in one
// test means neither can be deleted or skipped without the other.
func TestZoneInterfaces6735PackedTailRejectedAndPositiveControl(t *testing.T) {
	t.Run("rejected", func(t *testing.T) {
		cases := []struct {
			name     string
			stanza   string
			wantLost string // the token(s) the truncator would have silently dropped
		}{
			{
				// The #6735 defect proper: a valid member AFTER the keyword.
				name:     "bracket list with a body keyword mid-list",
				stanza:   `interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];`,
				wantLost: "ge-0/0/1.0",
			},
			{
				// Same shape, read the other way: the override is what is lost.
				name:     "compact packed body on the stanza Keys",
				stanza:   `interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh;`,
				wantLost: "system-services ssh",
			},
			{
				// Block spelling, packed onto the MEMBER's Keys — the recursion
				// must reach member nodes, not just the synthesized compact one.
				name:     "block member with a packed body on its Keys",
				stanza:   `interfaces { ge-0/0/0.0 host-inbound-traffic system-services ssh; }`,
				wantLost: "system-services ssh",
			},
			{
				// Keyword FIRST: nothing precedes it, so this also compiles to
				// zero members and the #6525 non-empty gate would fire too. The
				// packed-tail gate runs first precisely so the operator is told
				// about the token that was dropped rather than "names no
				// interface", which would be true but misdirecting.
				name:     "keyword first, member after",
				stanza:   `interfaces host-inbound-traffic ge-0/0/1.0;`,
				wantLost: "ge-0/0/1.0",
			},
			{
				// A body-only block is NOT automatically silent here, which is
				// the correction this row pins. `system-services ssh` sits on
				// the SAME Keys as the keyword, so it is a tail and this gate
				// fires. Only the NESTED-block spelling
				// `interfaces { host-inbound-traffic { system-services ssh; } }`
				// — where the body's tokens are the keyword node's CHILDREN and
				// its own Keys tail is empty — stays silent and falls through to
				// the non-empty gate; that one is pinned by the sibling subtest
				// in TestZoneInterfaces6735OverlapShapeReportsThePackedTailGate.
				// Without this row the two spellings look interchangeable and
				// the gate's own doc comment said so.
				name:     "body-only block packed onto the member's Keys",
				stanza:   `interfaces { host-inbound-traffic system-services ssh; }`,
				wantLost: "system-services ssh",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tree := parseHierText(t, zonePackedTailConfig(tc.stanza))
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("CompileConfig ACCEPTED the ambiguous stanza %q; the truncator silently keeps only the names before `host-inbound-traffic`, so %q is dropped (#6735)",
						tc.stanza, tc.wantLost)
				}
				// #7028: the keyword is asserted through the RENDERED fragment,
				// not as a bare substring. `host-inbound-traffic` also appears
				// verbatim in the template's "rewrite in the block spelling"
				// clause, so `strings.Contains(err, "host-inbound-traffic")`
				// held for every reject this gate produced — including one whose
				// %q argument was a constant. The detector returns the matched
				// keyword precisely so the message cannot name the wrong token
				// (see zoneInterfaceKeysBeforeBody's doc comment), and that is
				// the property this row is here to bind.
				wantKeyword := fmt.Sprintf("with %q followed by", "host-inbound-traffic")
				for _, want := range []string{`"Z"`, wantKeyword, tc.wantLost} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("reject error %q does not name %q — the message must identify the zone, the keyword, and the tokens that would have been dropped (#6735)",
							err.Error(), want)
					}
				}
			})
		}
	})

	// POSITIVE CONTROL. Every spelling here is unambiguous and must still
	// compile. Without this table a gate that rejected every `interfaces`
	// stanza — or a members reader that always returned nil — would pass the
	// reject table above unnoticed.
	t.Run("still compiles", func(t *testing.T) {
		cases := []struct {
			name   string
			stanza string
			want   []string
			// wantHIB is the per-interface host-inbound override the stanza
			// must compile: member name -> the admission tokens that member
			// ends up carrying, in compiled order. Two of these spellings are
			// exactly what the reject message tells the operator to migrate
			// INTO, so an accepted spelling has to admit what the operator
			// wrote — not merely produce an entry under the right key.
			//
			// The VALUE is asserted, not just the key, because an override that
			// compiles to a keyed-but-EMPTY HostInboundTraffic is the failure
			// DEFAULT of this path: a body that parsed to nothing still leaves
			// an entry behind. Measured — with cloneHostInbound(hib) replaced by
			// &HostInboundTraffic{} (keys intact, values emptied) the key-only
			// form of this assertion stayed GREEN, i.e. it was green for exactly
			// the regression it names. Under the token form it goes RED.
			//
			// SCOPE, also measured, so nobody reads more into this than it
			// carries: this assertion does NOT independently bind the override.
			// That same empty-value edit reds a large set of assertions that
			// predate this branch and already pin override CONTENT for these
			// very shapes. It is here so the accept table states what it means;
			// the binding is done elsewhere.
			//
			// Deliberately not a census. This comment used to read "26
			// assertions ... (#6391 ×9, #5248, #3362, #3703, #4544, #4818,
			// #3226, #4455)" and both halves had gone stale: re-measured at
			// 560544992 the #6391 group is ELEVEN, not nine, and the red set
			// had grown four tags the enumeration never named (#6640 ×2, #2419,
			// #7484, plus the untagged TestSlotEscapeTable). The population
			// changes whenever any sibling round adds or removes an override
			// assertion, so a hand-maintained number goes stale by construction
			// and a corrected one would only reset the clock (#7030).
			//
			// The claim that matters is the PREDICATE, which does not rot: the
			// override's content is pinned by assertions outside this table, so
			// this row can be deleted without leaving the override unbound.
			// Re-measure rather than trust a number — replace
			// `cloneHostInbound(hib)` with `&HostInboundTraffic{}` at the
			// per-interface override site in compileZones
			// (pkg/config/compiler_security_zones.go) and run:
			//
			//	go test -count=1 -v ./pkg/config/ 2>&1 | grep -c '^--- FAIL'
			//
			// At 560544992 that is 28 top-level tests, 27 of them predating
			// this branch. See the mutation table in _Log.md.
			wantHIB map[string][]string
		}{
			{
				name:   "single compact member",
				stanza: `interfaces ge-0/0/0.0;`,
				want:   []string{"ge-0/0/0.0"},
			},
			{
				name:   "bracket list with no body keyword",
				stanza: `interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];`,
				want:   []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			},
			{
				name:   "block members",
				stanza: `interfaces { ge-0/0/0.0; ge-0/0/1.0; }`,
				want:   []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			},
			{
				// Body as a CHILD node — unambiguous, and the override still
				// compiles. This is the spelling the reject message recommends,
				// so it had better work.
				name:    "member with a body block",
				stanza:  `interfaces ge-0/0/0.0 { host-inbound-traffic { system-services ssh; } }`,
				want:    []string{"ge-0/0/0.0"},
				wantHIB: map[string][]string{"ge-0/0/0.0": {"system-services=ssh"}},
			},
			{
				// A MULTI-token body on a bracket membership: both members get
				// it, each with the full token set in authored order. The extra
				// tokens are not decoration — a single-token body cannot tell a
				// correct fan from one that keeps only the first service, and
				// the two members cannot tell a correct clone from a shared
				// backing store unless both carry the same non-trivial content.
				name:   "bracket members with a shared body block",
				stanza: `interfaces [ ge-0/0/0.0 ge-0/0/1.0 ] { host-inbound-traffic { system-services [ ssh ping ]; protocols ospf; } }`,
				want:   []string{"ge-0/0/0.0", "ge-0/0/1.0"},
				wantHIB: map[string][]string{
					"ge-0/0/0.0": {"system-services=ssh", "system-services=ping", "protocols=ospf"},
					"ge-0/0/1.0": {"system-services=ssh", "system-services=ping", "protocols=ospf"},
				},
			},
			{
				// Keyword with NOTHING after it: truncation loses nothing, so
				// rejecting would be the #4191 over-rejection class. The packed
				// body is NOT parsed into an override here — fail-CLOSED, the
				// residual #6525 left open — so wantHIB is deliberately nil.
				//
				// This row is the one accept case with a DISTINGUISHING
				// mutation, measured: widening the detector to fire whenever the
				// keyword is not first (`i > 0 || len(tail) > 0`) reds this row
				// and NOTHING else in the package. The obvious wider mutation —
				// firing on any body keyword regardless of tail — is not the
				// one to cite: it also reds pre-existing #6525 assertions, so it
				// proves nothing about this row.
				name:   "keyword last, empty body",
				stanza: `interfaces ge-0/0/0.0 host-inbound-traffic;`,
				want:   []string{"ge-0/0/0.0"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tree := parseHierText(t, zonePackedTailConfig(tc.stanza))
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("CompileConfig REJECTED the unambiguous stanza %q: %v — the packed-tail gate must fire only when a body keyword has tokens AFTER it (#6735/#4191)",
						tc.stanza, err)
				}
				if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("stanza %q compiled membership %v, want %v", tc.stanza, got, tc.want)
				}
				if got := hibTokens6735(cfg.Security.Zones["Z"].InterfaceHostInbound); !reflect.DeepEqual(got, tc.wantHIB) {
					t.Fatalf("stanza %q compiled per-interface host-inbound %v, want %v — the reject message tells operators to rewrite INTO the block spelling, so an accepted spelling must ADMIT what the operator wrote; a keyed but empty override is the failure default this asserts against",
						tc.stanza, got, tc.wantHIB)
				}
			})
		}
	})
}

// hibTokens6735 projects the compiled per-interface host-inbound overrides into
// member name -> ["system-services=<tok>", "protocols=<tok>", ...], preserving
// compiled order and multiplicity. It exists so an accept-table assertion binds
// what an override ADMITS rather than merely that an entry exists under the
// right key: the map keys alone are equal for a correct override, an empty one,
// and one carrying the wrong services. Returns nil for no overrides so a "no
// override expected" row is written as a nil want.
func hibTokens6735(m map[string]*HostInboundTraffic) map[string][]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string][]string, len(m))
	for name, hib := range m {
		if hib == nil {
			out[name] = nil
			continue
		}
		var toks []string
		for _, svc := range hib.SystemServices {
			toks = append(toks, "system-services="+svc)
		}
		for _, proto := range hib.Protocols {
			toks = append(toks, "protocols="+proto)
		}
		out[name] = toks
	}
	return out
}

// TestZoneInterfaces6735FlatSetReachesThePackedTail is the reachability
// correction. #6525 documented its compact-leaf defect as hierarchical-ingest
// only — "NOT reachable from the `set` CLI" — and that is true OF THAT SHAPE.
// It is NOT true of this one. `set` DOES reach the packed tail, because SetPath
// descends the interface-name wildcard for the first bracket token and then
// collapses the remaining tokens onto ONE nested leaf, keyword and all:
//
//	set ... interfaces [ ge-0/0/0.0 ge-0/0/1.0 host-inbound-traffic ge-0/0/2.0 ]
//
//	interfaces
//	  ge-0/0/0.0
//	    Keys=["ge-0/0/1.0","host-inbound-traffic","ge-0/0/2.0"]   <- nested leaf
//
// so the truncator runs on a NESTED member and `ge-0/0/2.0` is dropped. That
// makes this defect reachable from the ordinary operator CLI, not just from
// `load override` / the persisted file / HA SyncApply.
//
// This is also the test that binds the CHILD RECURSION in
// zoneInterfaceMemberPackedTail. Measured: with the recursion deleted, every
// other case in this file still passes — the stanza-level loop already checks
// each block member's own Keys — so without this case the recursion would be
// unbound decoration that a later cleanup could delete silently.
func TestZoneInterfaces6735FlatSetReachesThePackedTail(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}

	t.Run("the nested leaf really does carry the keyword", func(t *testing.T) {
		tree := build(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 host-inbound-traffic ge-0/0/2.0 ]")
		zonesNode := tree.FindChild("security").FindChild("zones")
		examined := 0
		for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
			for _, prop := range inst.node.Children {
				if prop.Name() != "interfaces" {
					continue
				}
				examined++
				kw, tail, ok := zoneInterfaceStanzaPackedTail(prop)
				if !ok {
					t.Fatalf("detector missed a `set`-authored packed tail; stanza Keys=%v — the child recursion is what finds it", prop.Keys)
				}
				if kw != "host-inbound-traffic" {
					t.Fatalf("detector reported keyword %q, want host-inbound-traffic", kw)
				}
				if !reflect.DeepEqual(tail, []string{"ge-0/0/2.0"}) {
					t.Fatalf("detector reported lost tail %v, want [ge-0/0/2.0]", tail)
				}
			}
		}
		if examined == 0 {
			t.Fatalf("no `interfaces` stanza examined; this subtest asserted nothing")
		}
	})

	t.Run("membership really does lose the trailing member", func(t *testing.T) {
		tree := build(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 host-inbound-traffic ge-0/0/2.0 ]")
		zonesNode := tree.FindChild("security").FindChild("zones")
		secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
		if err := compileZones(zonesNode, secCfg); err != nil {
			t.Fatalf("compileZones: %v", err)
		}
		want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}
		if got := secCfg.Zones["Z"].Interfaces; !reflect.DeepEqual(got, want) {
			t.Fatalf("membership = %v, want %v — this PINS the `set`-reachable loss (ge-0/0/2.0 dropped) the gate rejects", got, want)
		}
	})

	t.Run("control: the same list without the keyword keeps every member", func(t *testing.T) {
		tree := build(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 ge-0/0/2.0 ]")
		zonesNode := tree.FindChild("security").FindChild("zones")
		if _, _, ok := zoneInterfaceStanzaPackedTail(zonesNode.FindChildren("security-zone")[0].Children[0]); ok {
			t.Fatalf("detector fired on a clean bracket list — it must key on the body keyword, not on nesting")
		}
		secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
		if err := compileZones(zonesNode, secCfg); err != nil {
			t.Fatalf("compileZones: %v", err)
		}
		want := []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"}
		if got := secCfg.Zones["Z"].Interfaces; !reflect.DeepEqual(got, want) {
			t.Fatalf("control membership = %v, want %v — the loss above must be attributable to the keyword, not to nesting", got, want)
		}
	})
}

// TestZoneInterfaces6735TruncatorLosesTheTrailingMember measures the loss the
// gate exists to prevent, at the compiler level, so the gate is answerable to a
// demonstrated defect rather than a hypothesis. It drives compileZones directly
// (the TOLERANT reading, which still truncates) and asserts that the trailing
// member really does vanish.
//
// If a later change taught the compiler to resolve the ambiguity and keep both
// members, THIS test goes red first and says so — at which point the gate should
// be reconsidered rather than the test amended.
func TestZoneInterfaces6735TruncatorLosesTheTrailingMember(t *testing.T) {
	got, _ := zoneMembership6525(t, `
security {
    zones {
        security-zone Z {
            interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];
        }
    }
}`)
	want := []string{"ge-0/0/0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compileZones membership = %v, want %v — this test PINS the loss the #6735 gate exists to reject; if the compiler now keeps ge-0/0/1.0 the ambiguity was resolved and the gate needs revisiting, not this assertion",
			got, want)
	}
	// The control: with the keyword removed the same list keeps BOTH members,
	// so the loss above is attributable to the keyword and not to bracket
	// handling in general.
	both, _ := zoneMembership6525(t, `
security {
    zones {
        security-zone Z {
            interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];
        }
    }
}`)
	if wantBoth := []string{"ge-0/0/0.0", "ge-0/0/1.0"}; !reflect.DeepEqual(both, wantBoth) {
		t.Fatalf("control: bracket list without a body keyword compiled %v, want %v", both, wantBoth)
	}
}

// TestZoneInterfaces6735LenientPathWarnsInsteadOfRejecting pins the #1960
// no-brick side: on the tolerant load / peer-sync path the packed-tail gate
// downgrades to a cfg.Warnings entry, so a config an older binary accepted still
// boots — with the loss named rather than silent.
func TestZoneInterfaces6735LenientPathWarnsInsteadOfRejecting(t *testing.T) {
	tree := parseHierText(t, zonePackedTailConfig(
		`interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];`))

	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("premise broken: the strict path must REJECT this stanza, otherwise the lenient assertion below proves nothing")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a packed-tail stanza: %v — the tolerant path must warn, not brick the boot (#1960)", err)
	}
	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "packed tail") {
			found = w
			break
		}
	}
	if found == "" {
		t.Fatalf("tolerant path emitted no packed-tail warning; warnings=%v — a silent downgrade is the silent loss this gate was written to end (#6735)", cfg.Warnings)
	}
	if !strings.Contains(found, "ge-0/0/1.0") {
		t.Fatalf("packed-tail warning %q does not name the dropped member ge-0/0/1.0", found)
	}
	// Behavior on the tolerant path is unchanged from before the gate: the
	// trailing member is still dropped. The warning is the whole delta.
	if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, []string{"ge-0/0/0.0"}) {
		t.Fatalf("tolerant path membership = %v, want [ge-0/0/0.0] — the gate must not change what a leniently-loaded config forwards", got)
	}
}

// TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning pins the flat-set
// bracket SHAPE, which two comments and docs/config-schema.md previously
// described as "one child per member". It is not: the schema models the
// interface name as a wildcard CONTAINER, so SetPath descends it for the first
// token and then collapses the remainder onto ONE leaf beneath it —
//
//	interfaces            Keys=["interfaces"]  children=1
//	  a                   Keys=["a"]           children=1
//	    b c               Keys=["b","c"]       children=0
//
// zoneInterfaceMembers recurses and reads every key at each level, so the
// members are read correctly and this was a description bug, not a code bug.
// It is worth pinning anyway: the wrong description is exactly the mental model
// that produces a one-level `prop.Children` reader, which is the #6525 defect
// class this whole area exists to close.
func TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set security zones security-zone Z interfaces [ a b c ]")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	zonesNode := tree.FindChild("security").FindChild("zones")

	var stanza *Node
	for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
		for _, prop := range inst.node.Children {
			if prop.Name() == "interfaces" {
				stanza = prop
			}
		}
	}
	if stanza == nil {
		t.Fatalf("no `interfaces` stanza produced; this test asserted nothing")
	}

	if got := stanza.Keys; !reflect.DeepEqual(got, []string{"interfaces"}) {
		t.Fatalf("stanza Keys = %v, want [interfaces] (`set` never produces the COMPACT shape)", got)
	}
	if len(stanza.Children) != 1 {
		t.Fatalf("stanza has %d children, want exactly 1 — a flat bracket list NESTS, it does not fan out one child per member", len(stanza.Children))
	}
	first := stanza.Children[0]
	if got := first.Keys; !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("first child Keys = %v, want [a]", got)
	}
	if len(first.Children) != 1 {
		t.Fatalf("first child has %d children, want exactly 1 (the collapsed tail leaf)", len(first.Children))
	}
	if got := first.Children[0].Keys; !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatalf("tail leaf Keys = %v, want [b c] — the remaining bracket tokens collapse onto ONE leaf", got)
	}

	// The payoff: despite that shape, every member is read. A one-level
	// `prop.Children` reader would return [a] alone.
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	if got, want := secCfg.Zones["Z"].Interfaces, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("membership = %v, want %v — the recursion must recover every nested member (#5248)", got, want)
	}
}

// TestZoneInterfaces6735OverlapShapeReportsThePackedTailGate binds the GATE
// ORDER, which nothing else does.
//
// `interfaces host-inbound-traffic ge-0/0/1.0;` is rejectable by BOTH gates: the
// keyword is first, so the truncator keeps nothing and the stanza also compiles
// to zero members. validateZoneInterfacePackedTailStrict deliberately runs FIRST
// so the operator is told which token was dropped, instead of "names no
// interface" — true, but it sends someone who plainly wrote `ge-0/0/1.0` hunting
// the wrong defect.
//
// That ordering was previously unbound. Both gates return a non-nil error for
// this shape, so every test asserting only "rejected" — including the one in
// this file — stayed green with the two swapped, and the operator silently got
// the worse message. Worse, the packed-tail message happens to CONTAIN the zone,
// the keyword and the dropped token, so even asserting those three does not
// separate the gates: the non-empty message renders the same tokens via
// zoneInterfaceStanzaTokens.
//
// So this asserts on each gate's distinguishing clause, in BOTH directions:
// the overlap shape must carry the packed-tail reason and NOT the non-empty
// reason, and a genuinely empty stanza must carry the non-empty reason and NOT
// the packed-tail one. The second half is what stops a "fix" that simply makes
// the packed-tail gate swallow everything.
//
// Fail-on-revert, measured: swap the two gate invocations in
// compiler_uniformgates_cluster_zone.go and the failure set across the whole
// package is exactly this test's overlap subtest — an assertion, not a build
// break, and nothing else in pkg/config reds. That makes this the assertion
// that binds the order.
//
// SCOPE — read this before "strengthening" it. What is observed is the rendered
// REASON TEXT, not which function produced it. An overbroad packed-tail gate
// that also swallowed the empty-member shapes and rendered the non-empty reason
// for them would satisfy both directions here and pass. That is deliberate: the
// operator-visible message is the contract, so a refactor that keeps every
// rendered result identical is legitimate however the helpers are arranged. Do
// NOT read this test as pinning which helper ran, and do not add an assertion
// that tries to — it would convert a behavioural contract into a structural one.
func TestZoneInterfaces6735OverlapShapeReportsThePackedTailGate(t *testing.T) {
	t.Run("overlap shape reports the packed tail, not the empty stanza", func(t *testing.T) {
		tree := parseHierText(t, zonePackedTailConfig(`interfaces host-inbound-traffic ge-0/0/1.0;`))
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted the overlap shape; both gates should reject it")
		}
		if !strings.Contains(err.Error(), zoneInterfacePackedTailReason) {
			t.Fatalf("overlap shape was rejected by the WRONG gate.\ngot:  %v\nwant it to carry the packed-tail reason: %q\n\nThe packed-tail gate must run BEFORE the non-empty gate: telling an operator who plainly wrote ge-0/0/1.0 that the stanza \"names no interface\" sends them hunting the wrong defect (#6735).",
				err, zoneInterfacePackedTailReason)
		}
		if strings.Contains(err.Error(), zoneInterfacesNonEmptyReason) {
			t.Fatalf("overlap shape reported the non-empty gate's reason %q as well: %v — the two messages must not be conflated",
				zoneInterfacesNonEmptyReason, err)
		}
	})

	// The other direction. Without this, "make the packed-tail gate fire on
	// everything" would satisfy the subtest above.
	t.Run("a genuinely empty stanza still reports the non-empty gate", func(t *testing.T) {
		for _, stanza := range []string{
			`interfaces host-inbound-traffic;`,
			`interfaces { host-inbound-traffic { system-services ssh; } }`,
		} {
			t.Run(stanza, func(t *testing.T) {
				tree := parseHierText(t, zonePackedTailConfig(stanza))
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("CompileConfig accepted %q, which names no interface", stanza)
				}
				if !strings.Contains(err.Error(), zoneInterfacesNonEmptyReason) {
					t.Fatalf("stanza %q was not rejected by the non-empty gate.\ngot:  %v\nwant it to carry %q — the packed-tail gate must not swallow shapes that carry no trailing token",
						stanza, err, zoneInterfacesNonEmptyReason)
				}
				if strings.Contains(err.Error(), zoneInterfacePackedTailReason) {
					t.Fatalf("stanza %q was rejected by the PACKED-TAIL gate: %v — it has no token after the keyword, so that gate must stay silent (#4191 over-rejection class)",
						stanza, err)
				}
			})
		}
	})
}

// zonePackedTailSetTree builds a candidate tree from FLAT-SET commands the way
// the operator CLI does — ParseSetCommand + ConfigTree.SetPath, never
// NewParser, which treats newlines as whitespace and would merge every line
// into one giant node. It defines the same three interfaces
// zonePackedTailConfig defines (plus ge-0/0/2), so a rejection can only come
// from the gate under test.
func zonePackedTailSetTree(t *testing.T, zoneCmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
	}
	cmds = append(cmds, zoneCmds...)
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// zoneInterfacesStanza6735 returns zone Z's `interfaces` stanza node, failing
// the test if there is none. Returning it rather than looping in each caller
// keeps a subtest from silently asserting nothing when the stanza moves.
func zoneInterfacesStanza6735(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	zones := tree.FindChild("security").FindChild("zones")
	if zones == nil {
		t.Fatalf("no `security zones` node in the tree")
	}
	for _, inst := range namedInstances(zones.FindChildren("security-zone")) {
		if inst.name != "Z" {
			continue
		}
		for _, prop := range inst.node.Children {
			if prop.Name() == "interfaces" {
				return prop
			}
		}
	}
	t.Fatalf("zone Z has no `interfaces` stanza")
	return nil
}

// TestZoneInterfaces6735KeywordArrivesAsAChildNode closes the escape the
// original #6735 gate left open: `host-inbound-traffic` reaching the compiler as
// a child NODE with dropped member tokens parked underneath it, rather than as a
// token on some member's own Keys.
//
// This is the FLAT-SET (`set` CLI) ingest of the exact statement #6735 is built
// around, and it is why "the gate covers the headline statement" was false at
// the previous head. `schema_security.go` declares `host-inbound-traffic` as a
// named child of the interface-name wildcard, so when it is the token
// IMMEDIATELY AFTER the first bracket token, SetPath DESCENDS it instead of
// collapsing the bracket tail onto one leaf:
//
//	set ... interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ]
//	  interfaces -> ge-0/0/0.0 -> host-inbound-traffic -> ge-0/0/1.0
//
// The trailing member parks UNDER the keyword node, where the truncator
// (zoneInterfaceMembers) and the detector (zoneInterfaceMemberPackedTail) both
// skipped it by name. They agreed, so the statement committed with ge-0/0/1.0
// silently dropped: Zone == "", never AF_XDP-bound, no policy naming Z applying
// to it.
//
// The keyword's POSITION is the whole discriminator, which is why the position
// is varied here rather than fixed. With a non-schema token in slot 2 the tail
// collapses onto one Keys slice and the pre-existing Keys arm of the detector
// fires; the pre-#6735-fix test used exactly that arrangement, so the one
// flat-set case covered was the one that already passed.
func TestZoneInterfaces6735KeywordArrivesAsAChildNode(t *testing.T) {
	const headline = "set security zones security-zone Z interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ]"

	t.Run("SetPath really descends the keyword rather than collapsing the tail", func(t *testing.T) {
		// Pins the MECHANISM. If a schema change ever stops SetPath descending
		// `host-inbound-traffic`, this shape disappears and the subtests below
		// would start passing for a different reason; this says so out loud.
		prop := zoneInterfacesStanza6735(t, zonePackedTailSetTree(t, headline))
		if got, want := prop.Keys, []string{"interfaces"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("stanza Keys = %v, want %v — `set` never leaves members on the stanza's own Keys", got, want)
		}
		member := prop.Children[0]
		if got, want := member.Keys, []string{"ge-0/0/0.0"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("first member Keys = %v, want %v — the bracket tail must NOT have collapsed onto this node", got, want)
		}
		kw := member.Children[0]
		if got, want := kw.Keys, []string{"host-inbound-traffic"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("keyword node Keys = %v, want %v", got, want)
		}
		if got, want := zoneInterfaceNodeTokens(kw.Children[0]), []string{"ge-0/0/1.0"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("tokens parked under the keyword = %v, want %v — this is the member the compiler drops", got, want)
		}
	})

	t.Run("the truncator really does drop the parked member", func(t *testing.T) {
		// The loss the gate exists to prevent, measured at the compiler level so
		// the gate answers a demonstrated defect rather than a hypothesis. This
		// is the TOLERANT reading, which still truncates.
		prop := zoneInterfacesStanza6735(t, zonePackedTailSetTree(t, headline))
		got := zoneInterfaceStanzaMembers(prop)
		want := []string{"ge-0/0/0.0"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("stanza membership = %v, want %v — if the compiler learned to keep ge-0/0/1.0 this test goes red FIRST and the gate should become a no-op rather than a reject", got, want)
		}
	})

	t.Run("the detector sees the parked member", func(t *testing.T) {
		prop := zoneInterfacesStanza6735(t, zonePackedTailSetTree(t, headline))
		kw, tail, ok := zoneInterfaceStanzaPackedTail(prop)
		if !ok {
			t.Fatalf("detector missed the `set`-authored keyword CHILD node; stanza renders as %q — this is the headline #6735 statement and it escaped the gate entirely", zoneInterfaceStanzaTokens(prop))
		}
		if kw != "host-inbound-traffic" {
			t.Fatalf("detector reported keyword %q, want host-inbound-traffic", kw)
		}
		if want := []string{"ge-0/0/1.0"}; !reflect.DeepEqual(tail, want) {
			t.Fatalf("detector reported dropped tokens %v, want %v", tail, want)
		}
	})

	t.Run("commit rejects, and the message names the dropped member", func(t *testing.T) {
		_, err := CompileConfig(zonePackedTailSetTree(t, headline))
		if err == nil {
			t.Fatalf("CompileConfig ACCEPTED %q — ge-0/0/1.0 is silently dropped, left with Zone == \"\", never dataplane-bound, and no policy naming Z applies to it (#6735)", headline)
		}
		if !strings.Contains(err.Error(), zoneInterfacePackedTailReason) {
			t.Fatalf("rejected by the WRONG gate: %v\nwant the packed-tail reason %q", err, zoneInterfacePackedTailReason)
		}
		// The message must contain the dropped member itself. Asserting on
		// "host-inbound-traffic" alone would be vacuous — the reject template
		// contains that literal regardless of what the detector returned.
		if !strings.Contains(err.Error(), "ge-0/0/1.0") {
			t.Fatalf("reject message never names the dropped member ge-0/0/1.0: %v", err)
		}
	})

	t.Run("control: the same list without the keyword keeps every member", func(t *testing.T) {
		// Without this the gate could reject every bracket list and every
		// assertion above would still pass.
		const clean = "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 ]"
		cfg, err := CompileConfig(zonePackedTailSetTree(t, clean))
		if err != nil {
			t.Fatalf("CompileConfig REJECTED the unambiguous bracket list %q: %v", clean, err)
		}
		want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}
		if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, want) {
			t.Fatalf("control membership = %v, want %v — the reject above must be attributable to the keyword, not to bracket nesting", got, want)
		}
	})
}

// TestZoneInterfaces6735KeywordWithEmptyKeysTailStillWalksItsChildren closes the
// second escape of the same root: zoneInterfaceMemberPackedTail returned as soon
// as a body keyword appeared on a node's Keys, EVEN WHEN nothing followed it on
// Keys, so that node's children were never examined. Two ordinary `set` lines
// reach it:
//
//	set ... interfaces ge-0/0/0.0
//	set ... interfaces [ host-inbound-traffic ge-0/0/1.0 ]
//
// The second line makes `host-inbound-traffic` a member-slot node directly under
// the stanza with ge-0/0/1.0 parked beneath it. Before the fix this committed
// with ge-0/0/1.0 dropped and ZERO warnings — a strict REGRESSION against
// origin/master, where the same statement was rejected loudly (master compiled
// `host-inbound-traffic` as a phantom member, which the zone-interface-DEFINED
// gate then caught). #6525's truncation removed the phantom and, with it, the
// only thing making the loss visible.
func TestZoneInterfaces6735KeywordWithEmptyKeysTailStillWalksItsChildren(t *testing.T) {
	cmds := []string{
		"set security zones security-zone Z interfaces ge-0/0/0.0",
		"set security zones security-zone Z interfaces [ host-inbound-traffic ge-0/0/1.0 ]",
	}

	prop := zoneInterfacesStanza6735(t, zonePackedTailSetTree(t, cmds...))
	kw, tail, ok := zoneInterfaceStanzaPackedTail(prop)
	if !ok {
		t.Fatalf("detector missed a keyword node whose Keys tail is EMPTY but whose CHILDREN carry a dropped member; stanza renders as %q", zoneInterfaceStanzaTokens(prop))
	}
	if kw != "host-inbound-traffic" {
		t.Fatalf("detector reported keyword %q, want host-inbound-traffic", kw)
	}
	if want := []string{"ge-0/0/1.0"}; !reflect.DeepEqual(tail, want) {
		t.Fatalf("detector reported dropped tokens %v, want %v", tail, want)
	}

	_, err := CompileConfig(zonePackedTailSetTree(t, cmds...))
	if err == nil {
		t.Fatalf("CompileConfig ACCEPTED %v — ge-0/0/1.0 is silently dropped and origin/master rejected this same config loudly (#6735)", cmds)
	}
	if !strings.Contains(err.Error(), zoneInterfacePackedTailReason) {
		t.Fatalf("rejected by the WRONG gate: %v\nwant the packed-tail reason %q — the operator wrote ge-0/0/1.0 and must be told it was dropped", err, zoneInterfacePackedTailReason)
	}
	if !strings.Contains(err.Error(), "ge-0/0/1.0") {
		t.Fatalf("reject message never names the dropped member ge-0/0/1.0: %v", err)
	}
}

// TestZoneInterfaces6735StrayTokenTableAcrossBothIngests is the discriminating
// table for zoneInterfaceHostInboundStrayTokens: which subtrees under a
// `host-inbound-traffic` node are BODY (accept) and which are dropped members
// (reject). The two halves have to be read together — a detector that fired on
// every keyword child would pass the reject half and red the accept half, and a
// detector that fired on none would do the reverse.
func TestZoneInterfaces6735StrayTokenTableAcrossBothIngests(t *testing.T) {
	t.Run("rejected: a token under the keyword that cannot be body content", func(t *testing.T) {
		cases := []struct {
			name     string
			hier     string   // nil-able: hierarchical stanza
			set      []string // nil-able: flat-set commands
			wantLost string
		}{
			{
				name:     "hierarchical: stray token on the keyword node's Keys",
				hier:     `interfaces { ge-0/0/0.0 { host-inbound-traffic ge-0/0/1.0; } }`,
				wantLost: "ge-0/0/1.0",
			},
			{
				name:     "flat-set: keyword second in the bracket list",
				set:      []string{"set security zones security-zone Z interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ]"},
				wantLost: "ge-0/0/1.0",
			},
			{
				name:     "flat-set: keyword first in the bracket list",
				set:      []string{"set security zones security-zone Z interfaces [ host-inbound-traffic ge-0/0/1.0 ]"},
				wantLost: "ge-0/0/1.0",
			},
			{
				name: "flat-set: several members parked under the keyword",
				set:  []string{"set security zones security-zone Z interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ge-0/0/2.0 ]"},
				// Every parked token is named, not just the first — a
				// one-token echo would leave the operator restoring half a
				// zone.
				wantLost: "ge-0/0/1.0 ge-0/0/2.0",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var tree *ConfigTree
				if tc.hier != "" {
					tree = parseHierText(t, zonePackedTailConfig(tc.hier))
				} else {
					tree = zonePackedTailSetTree(t, tc.set...)
				}
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("CompileConfig ACCEPTED a stanza that silently drops %q (#6735)", tc.wantLost)
				}
				if !strings.Contains(err.Error(), zoneInterfacePackedTailReason) {
					t.Fatalf("rejected by the WRONG gate: %v\nwant the packed-tail reason %q", err, zoneInterfacePackedTailReason)
				}
				if !strings.Contains(err.Error(), tc.wantLost) {
					t.Fatalf("reject message does not name the dropped tokens %q: %v", tc.wantLost, err)
				}
			})
		}
	})

	t.Run("accepted: the keyword's subtree is legitimate body content", func(t *testing.T) {
		cases := []struct {
			name string
			hier string
			set  []string
			want []string
		}{
			{
				name: "hierarchical: nested body block",
				hier: `interfaces { ge-0/0/0.0 { host-inbound-traffic { system-services ssh; } } }`,
				want: []string{"ge-0/0/0.0"},
			},
			{
				name: "hierarchical: keyword node with nothing under it",
				hier: `interfaces { ge-0/0/0.0 { host-inbound-traffic; } }`,
				want: []string{"ge-0/0/0.0"},
			},
			{
				name: "flat-set: per-interface override, the ordinary CLI spelling",
				set: []string{
					"set security zones security-zone Z interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
				},
				want: []string{"ge-0/0/0.0"},
			},
			{
				name: "flat-set: multi-token body and a second body keyword",
				set: []string{
					"set security zones security-zone Z interfaces ge-0/0/0.0 host-inbound-traffic system-services [ ssh ping ]",
					"set security zones security-zone Z interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf",
				},
				want: []string{"ge-0/0/0.0"},
			},
			{
				name: "flat-set: bare keyword, no body at all",
				set: []string{
					"set security zones security-zone Z interfaces ge-0/0/0.0 host-inbound-traffic",
				},
				want: []string{"ge-0/0/0.0"},
			},
			{
				// `apply-groups-except` and `apply-macro` may appear at ANY
				// point in the Junos hierarchy and survive group expansion as
				// live nodes (ExpandGroups removes only `apply-groups`), so
				// they reach this gate verbatim under the keyword. Reading one
				// as a dropped interface name hard-rejects a legitimate config
				// at commit — measured, before zoneInterfaceNonMemberToken
				// existed, as `followed by apply-groups-except G`.
				name: "hierarchical: group machinery under the keyword",
				hier: `interfaces { ge-0/0/0.0 { host-inbound-traffic { apply-groups-except G; system-services ssh; } } }`,
				want: []string{"ge-0/0/0.0"},
			},
			{
				name: "hierarchical: apply-macro under the keyword",
				hier: `interfaces { ge-0/0/0.0 { host-inbound-traffic { apply-macro M { k v; } system-services ssh; } } }`,
				want: []string{"ge-0/0/0.0"},
			},
			{
				name: "flat-set: group machinery under the keyword",
				set: []string{
					"set security zones security-zone Z interfaces ge-0/0/0.0 host-inbound-traffic apply-groups-except G",
					"set security zones security-zone Z interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
				},
				want: []string{"ge-0/0/0.0"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var tree *ConfigTree
				if tc.hier != "" {
					tree = parseHierText(t, zonePackedTailConfig(tc.hier))
				} else {
					tree = zonePackedTailSetTree(t, tc.set...)
				}
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("CompileConfig REJECTED a legitimate host-inbound body: %v — the stray-token check must fire only on tokens that cannot be body content (#4191 over-rejection class)", err)
				}
				if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("membership = %v, want %v", got, tc.want)
				}
			})
		}
	})
}

// TestZoneInterfaces6735BodyKeywordsTrackTheSchema binds
// zoneInterfaceHostInboundBodyKeywords to the grammar it must mirror. The set
// decides which tokens under a `host-inbound-traffic` node are body and which
// are dropped members, so a divergence from the schema is ALWAYS a bug in one
// direction or the other: a body keyword missing here turns a legitimate
// override into a hard commit reject, and a token here that the schema does not
// accept lets a dropped member through as "body". They are derived from one
// source for that reason; this asserts the derivation actually holds.
func TestZoneInterfaces6735BodyKeywordsTrackTheSchema(t *testing.T) {
	schemaChildren := hostInboundSchemaChildren()
	if len(schemaChildren) == 0 {
		t.Fatalf("hostInboundSchemaChildren() is empty — this test would assert nothing")
	}
	for name := range schemaChildren {
		if !zoneInterfaceHostInboundBodyKeywords[name] {
			t.Fatalf("schema declares %q under host-inbound-traffic but zoneInterfaceHostInboundBodyKeywords does not — a legitimate override authored with it would be read as a dropped member and hard-rejected at commit", name)
		}
	}
	for name := range zoneInterfaceHostInboundBodyKeywords {
		if _, ok := schemaChildren[name]; !ok {
			t.Fatalf("zoneInterfaceHostInboundBodyKeywords carries %q, which the schema does not accept under host-inbound-traffic — a member token spelled that way would be silently swallowed as body", name)
		}
	}
}

// TestZoneInterfaces6735RejectEchoRendersTheWholeStanza pins the operator-facing
// echo. `set` builds this stanza by DESCENT, so rendering each child's own Keys
// alone showed a one-token stanza — `(ge-0/0/0.0)` — for a message that then
// discussed a keyword and a trailing token appearing nowhere in it. Every
// flat-set-authored reject was affected, i.e. every reject an operator hits from
// the CLI.
func TestZoneInterfaces6735RejectEchoRendersTheWholeStanza(t *testing.T) {
	tree := zonePackedTailSetTree(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ]")
	prop := zoneInterfacesStanza6735(t, tree)
	got := zoneInterfaceStanzaTokens(prop)
	want := "ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0"
	if got != want {
		t.Fatalf("stanza echo = %q, want %q — the operator must be shown the statement they wrote, not its first token", got, want)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted the ambiguous flat-set stanza")
	}
	if !strings.Contains(err.Error(), "("+want+")") {
		t.Fatalf("reject message does not echo the full stanza %q: %v", want, err)
	}
}
