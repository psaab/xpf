package config

import (
	"reflect"
	"sort"
	"testing"
)

// Tests for #6391: a per-interface `host-inbound-traffic` override authored
// under ONE member of a bracketed / shared-container interface membership must
// NOT leak onto the sibling members that merely share the bracket.
//
// Background. #5248 flattens the bracketed `interfaces [ a b c ]` membership so
// every member lands in `zone.Interfaces` (a security-boundary fix). SetPath
// nests the bracket tail under the first member — `interfaces -> a(container) ->
// b(leaf)` — so a subsequent `interfaces a host-inbound-traffic { ... }` reuses
// the SAME `a` container and the host-inbound body becomes a child of the node
// that also carries the `b` membership leaf.
//
// PR #6389 (advances #5609, CLOSED unmerged) tried to make a multi-member
// `load override` block apply the override to every member by fanning the parsed
// host-inbound across `zoneInterfaceMembers(iface)` — every name in the node's
// Keys AND its nested membership children. That fanout OVER-ADMITS: it opens the
// service on `b` for the common
//
//	set security zones security-zone Z interfaces [ a b ]
//	set security zones security-zone Z interfaces a host-inbound-traffic system-services ssh
//
// config that scopes ssh to `a` only, because SetPath nests the bracket tail under
// the first member and the second `set` reuses that same container. Codex's
// hostile review of #6389 plus a firsthand repro caught this host-inbound sibling
// leak; #6389 closed unmerged.
//
// #6391 REPLACED the fail-safe first-member-only status quo with a fan that keys
// on the node's KEYS and never on its CHILDREN. The premise #6389 and the original
// #6391 issue text both worked from — "the flat-set single-scoped case and the
// hierarchical multi-member case compile to the SAME AST, so no AST-keyed fan can
// tell them apart" — was TESTED against firsthand AST dumps and is FALSE. The two
// shapes are distinct:
//
//	`[ a b ] { host-inbound {...} }`  -> ONE container Keys=["a","b"], NO
//	                                    membership child. Multi-member intent.
//	`set ... interfaces [ a b ]`      -> container Keys=["a"] with a membership
//	`set ... interfaces a host-...`      CHILD leaf Keys=["b"]. Single-scoped.
//
// What IS identical is the flat-set shape and the `a { b; host-inbound {...} }`
// hierarchical shape — because the latter is the former's SERIALIZATION
// (`ConfigTree.Format()`, the render configstore persists and HA config sync
// ships, emits exactly it). That is why fanning on children leaks on every
// reload, and why first-member-only remains correct for THAT shape permanently.
//
// So the assertions below split by SHAPE, not by confidence:
//
//   - INDIVIDUALLY-SCOPED / CONTAINER-SHARING (first/later-member, three-member,
//     multi-service, protocols, the `a { b; ... }` hierarchical case, plus the
//     aliasing guard): a service or protocol authored under ONE named interface
//     must NEVER appear on a sibling. UNCONDITIONAL — this is the #6389 leak and
//     it stays pinned forever. Re-introducing a children-fan turns these RED.
//
//   - MULTI-MEMBER BODY (Keys=[a,b], authored ON the bracket membership): applies
//     to EVERY member. This expectation was INVERTED by #6391 — not a change of
//     mind about sibling isolation, but the consequence of the two shapes being
//     different. Reverting the Keys-fan turns this RED.
//
//   - NEGATIVE DIRECTION (FlatSetNeverYieldsMultiKeyContainer): no `set`-authored
//     config may produce a multi-key interface container, or the fan would
//     re-open the #6389 leak. Schema-guaranteed today; asserted so a future
//     SetPath / schema refactor cannot silently break it.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath, never NewParser; the hierarchical shape uses parseHierarchical.

// hib6391 is a normalized (sorted) view of one compiled per-interface
// HostInboundTraffic that captures BOTH admission dimensions — system-services
// AND protocols. Comparing the full struct (not just system-services) means a
// #6389-style fanout that leaked only host-inbound `protocols` (ospf/bgp/...) to
// a sibling is caught too, not just a system-services leak.
type hib6391 struct {
	SystemServices []string
	Protocols      []string
}

// compileHostInbound6391 compiles the zones subtree and returns the FULL
// per-interface host-inbound map: every key present in InterfaceHostInbound
// (an interface with no override is simply absent), each mapped to its sorted
// system-services + protocols. Returning the whole map — every key, both
// dimensions — is what makes the sibling-leak assertion airtight: an extra
// sibling key, or an extra service/protocol on any interface, fails the
// DeepEqual.
func compileHostInbound6391(t *testing.T, tree *ConfigTree) map[string]hib6391 {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatalf("no security node in tree")
	}
	zonesNode := sec.FindChild("zones")
	if zonesNode == nil {
		t.Fatalf("no security zones node in tree")
	}
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	out := map[string]hib6391{}
	for _, z := range secCfg.Zones {
		for ifName, hib := range z.InterfaceHostInbound {
			// Include EVERY key, even a (defensive) nil value, so an
			// unexpected sibling key fails the assertion regardless of its
			// contents. sort.Strings(nil) is a no-op and append([]string(nil),
			// nil...) stays nil, so an absent dimension normalizes to nil and
			// matches an unset field in the expected literal.
			v := hib6391{}
			if hib != nil {
				v.SystemServices = append([]string(nil), hib.SystemServices...)
				v.Protocols = append([]string(nil), hib.Protocols...)
				sort.Strings(v.SystemServices)
				sort.Strings(v.Protocols)
			}
			out[ifName] = v
		}
	}
	return out
}

func compileHostInbound6391FromSet(t *testing.T, cmds ...string) map[string]hib6391 {
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
	return compileHostInbound6391(t, tree)
}

// assertHostInbound6391 asserts the compiled per-interface host-inbound map is
// EXACTLY want — every key and both admission dimensions. Using the full map
// (not a spot check on one interface) makes the sibling-leak assertion airtight:
// an extra sibling key, or an extra service/protocol anywhere, is a failure.
func assertHostInbound6391(t *testing.T, got, want map[string]hib6391) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("per-interface host-inbound = %+v, want %+v (sibling leak?)", got, want)
	}
}

// TestHostInbound6391FlatSetFirstMemberNoSiblingLeak is the primary RED-on-revert
// guard and the exact issue repro: a two-member bracket with a host-inbound
// override written under the FIRST member via its own `set` statement must scope
// the service to that member ONLY. This is an UNCONDITIONAL invariant — an
// individually-authored per-interface stanza stays single-scoped under every
// design option (1/2/3). The #6389 fanout opens ssh on the sibling ge-0/0/1 →
// this goes RED.
func TestHostInbound6391FlatSetFirstMemberNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391FlatSetLaterMemberNoSiblingLeak covers the symmetric
// ordering: the override written under a LATER bracket member scopes to that
// member only, and the first member stays clean. In this ordering SetPath
// splits ge-0/0/1 into its own top-level container, so the direct-child keying
// is already correct — the case pins that the fix does not regress it.
func TestHostInbound6391FlatSetLaterMemberNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/1 host-inbound-traffic system-services ssh",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/1": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391ThreeMemberNoSiblingLeak proves the override does not reach
// ANY sibling, not just the adjacent one: a 3-member bracket with the override
// under the first member must leave BOTH later members clean. The #6389 fanout
// leaks onto ge-0/0/1 AND ge-0/0/2 → RED.
func TestHostInbound6391ThreeMemberNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391MultiServiceNoSiblingLeak proves no cross-SERVICE leak: two
// services (ssh AND ping) under the first member must both scope to that member
// only — the sibling gets neither.
func TestHostInbound6391MultiServiceNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ping",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ping", "ssh"}},
	})
}

// TestHostInbound6391ProtocolsNoSiblingLeak exercises the PROTOCOLS admission
// dimension (not just system-services): an override under the FIRST member
// carrying BOTH a system-service (ssh) and a protocol (ospf) must scope both to
// that member — the sibling gets neither. Without a Protocols case the guard's
// full-map assertion never observes a protocols leak; the #6389 fanout leaks
// ospf onto ge-0/0/1 too → RED. Individually-scoped, so an UNCONDITIONAL
// invariant under every design option.
func TestHostInbound6391ProtocolsNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic protocols ospf",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}},
	})
}

// TestHostInbound6391HierarchicalNestedChildNoSiblingLeak covers the AST shape
// #6389 targeted: a hierarchical block that NESTS the second member under the
// first alongside a host-inbound body
// (`interfaces { ge-0/0/0 { ge-0/0/1; host-inbound-traffic { ssh } } }`).
//
// THIS TEST STAYS GREEN UNDER THE #6391 FIX, and the reason is the whole reason
// #6389 was unsound. This shape is NOT a multi-member intent that merely
// resembles the flat-set one — it is the SERIALIZATION of the flat-set one.
// `ConfigTree.Format()` (what configstore persists through, store_format.go, and
// what HA config sync ships via d.store.ShowActive()) renders the flat-set
//
//	set ... interfaces [ ge-0/0/0 ge-0/0/1 ]
//	set ... interfaces ge-0/0/0 host-inbound-traffic system-services ssh
//
// as EXACTLY this text, and re-parsing it yields a byte-identical AST
// (Keys=["ge-0/0/0"], child leaf Keys=["ge-0/0/1"], child host-inbound-traffic).
// So a fan that fired here would leak ssh onto ge-0/0/1 on every RELOAD of an
// ordinary single-scoped flat-set config — which is precisely the regression
// #6389 shipped. First-member-only is therefore the CORRECT permanent answer for
// this shape, not a fail-safe compromise: ssh on ge-0/0/0, nested ge-0/0/1 clean.
//
// The genuine multi-member intent is the DISTINCT Keys=[a,b] shape covered by
// TestHostInbound6391HierarchicalBracketBodyFansToAllMembers.
func TestHostInbound6391HierarchicalNestedChildNoSiblingLeak(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0 {
                    ge-0/0/1;
                    host-inbound-traffic { system-services ssh; }
                }
            }
        }
    }
}`)
	got := compileHostInbound6391(t, tree)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391HierarchicalBracketBodyFansToAllMembers is the #6391 FIX
// assertion: the canonical MULTI-MEMBER BODY — a host-inbound stanza authored ON
// the bracket membership itself — applies to EVERY bracket member.
//
// This expectation was INVERTED by #6391 (it previously asserted first-member-
// only). That was not a change of mind about sibling isolation; it is the
// consequence of discovering that this shape and the flat-set single-scoped shape
// are STRUCTURALLY DIFFERENT, which the #6391 issue text and the pre-fix docs both
// denied. Dumping the compiled AST for each:
//
//	`[ a b ] { host-inbound {...} }`   -> ONE container, Keys=["a","b"] (len 2),
//	                                     NO membership child.
//	`set ... interfaces [ a b ]`       -> container Keys=["a"] (len 1) with a
//	`set ... interfaces a host-...`       membership CHILD leaf Keys=["b"].
//
// The discriminator is therefore len(Keys)>1, and it is safe in the direction
// that matters (a false positive would LEAK): no `set`-authored config can
// produce a multi-key interface container, because the interface name is
// `schemaNode.wildcard` with args:0 / multi:false / compoundKey:false
// (schema_security.go), so SetPath's `nodeKeyCount = 1 + args` is always 1.
// Surplus bracket tokens can only land on a child LEAF. That invariant is pinned
// independently by TestHostInbound6391FlatSetNeverYieldsMultiKeyContainer so a
// future schema refactor that broke it fails loudly rather than silently
// re-opening the #6389 leak.
//
// The multi-key shape is reachable only from a hierarchical parse — `load
// override` or a hand-authored config file. It survives Format()->NewParser
// (local persistence) and HA config sync byte-for-byte. It does NOT survive a
// `show | display set` round-trip, which mangles it into an uncompilable leaf —
// that is a separate pre-existing defect tracked as #6668, NOT introduced here.
func TestHostInbound6391HierarchicalBracketBodyFansToAllMembers(t *testing.T) {
	tree := parseHierarchical(t, `
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
}`)
	got := compileHostInbound6391(t, tree)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
		"ge-0/0/1": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391BareMultiMemberBodyFansToAllMembers pins the BRACKET-LESS
// spelling of the same shape. The lexer discards `[` and `]`, so
//
//	[ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic {...} }
//	  ge-0/0/0 ge-0/0/1   { host-inbound-traffic {...} }
//
// parse to a byte-identical multi-key node and must therefore compile
// identically. The brackets are cosmetic at this position.
//
// Worth pinning separately rather than trusting the equivalence: the whole
// safety argument for keying on Keys rests on which spellings can produce
// len(Keys)>1, so "the lexer drops brackets" is load-bearing rather than
// incidental. If a future lexer change made the two forms diverge, the
// bracketed test above would keep passing while this one caught it.
func TestHostInbound6391BareMultiMemberBodyFansToAllMembers(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0 ge-0/0/1 {
                    host-inbound-traffic { system-services ssh; }
                }
            }
        }
    }
}`)
	got := compileHostInbound6391(t, tree)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
		"ge-0/0/1": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391BracketBodyNestedExtraMemberScope pins the judgement call
// at the edge of the fan: a bracket body that ALSO nests a further membership
// statement (`[ a b ] { c; host-inbound {...} }`) applies the override to a and b
// — the names on the node the body was authored on — but NOT to c.
//
// The reason is stronger than a judgement call, and it is the same reason #6389
// was unsound: c is a nested CHILD, not a bracket PEER, and its position in the
// AST is INDISTINGUISHABLE from the flat-set membership tail that caused #6389
// (`set ... interfaces [ a b ]` nests `b` as exactly this kind of child). So
// applying the body to c would restore the forbidden children-fan — not merely
// over-apply in one unusual spelling, but RE-OPEN THE ORIGINAL LEAK by another
// route. Excluding c is therefore forced by the fix's own invariant rather than
// chosen.
//
// c is still a zone MEMBER (it appears in zone.Interfaces via
// zoneInterfaceMembers); it simply falls back to the zone-level host-inbound,
// which is the conservative direction.
func TestHostInbound6391BracketBodyNestedExtraMemberScope(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone trust {
            interfaces {
                [ ge-0/0/0 ge-0/0/1 ] {
                    ge-0/0/2;
                    host-inbound-traffic { system-services ssh; }
                }
            }
        }
    }
}`)
	got := compileHostInbound6391(t, tree)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
		"ge-0/0/1": {SystemServices: []string{"ssh"}},
	})

	// c IS a zone member, it just carries no per-interface override.
	sec := tree.FindChild("security")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(sec.FindChild("zones"), secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	if got, want := secCfg.Zones["trust"].Interfaces, []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zone.Interfaces = %q, want %q (the nested member must stay a zone member)", got, want)
	}
}

// TestHostInbound6391FlatSetNeverYieldsMultiKeyContainer is the NEGATIVE-direction
// guard for the #6391 discriminator, and the one that makes the fix durable.
//
// The fan keys on len(iface.Keys)>1. A false POSITIVE is the dangerous direction:
// if any `set`-authored config could produce a multi-key interface container, the
// fan would re-open the #6389 sibling leak on a config the operator scoped to one
// interface. Today that is impossible by schema construction (the interface name
// is a wildcard with args:0 / multi:false / compoundKey:false, so SetPath's
// nodeKeyCount is always 1) — but that is a fact someone would otherwise have to
// re-derive from the schema after any SetPath or schema_security.go refactor.
//
// This asserts it directly over the flat-set spellings that plausibly stress it:
// brackets of several widths, both authoring orders, bare multi-name membership,
// overlapping repeated brackets, and a host-inbound token tail. If a refactor
// ever makes one of these yield a multi-key container, this fails HERE with the
// offending Keys rather than silently widening admission.
func TestHostInbound6391FlatSetNeverYieldsMultiKeyContainer(t *testing.T) {
	spellings := [][]string{
		{"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]"},
		{"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ge-0/0/3 ]"},
		{"set security zones security-zone trust interfaces ge-0/0/0 ge-0/0/1"},
		{"set security zones security-zone trust interfaces ge-0/0/0 ge-0/0/1 host-inbound-traffic system-services ssh"},
		{
			"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
			"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		},
		{
			"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
			"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		},
		{
			"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
			"set security zones security-zone trust interfaces ge-0/0/1 host-inbound-traffic system-services ssh",
		},
		{
			"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
			"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/2 ]",
			"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic protocols ospf",
		},
		{
			"set security zones security-zone trust interfaces ge-0/0/0",
			"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		},
	}

	for i, cmds := range spellings {
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("spelling %d: ParseSetCommand(%q): %v", i, cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("spelling %d: SetPath(%q): %v", i, cmd, err)
			}
		}
		sec := tree.FindChild("security")
		if sec == nil {
			t.Fatalf("spelling %d: no security node", i)
		}
		zones := sec.FindChild("zones")
		if zones == nil {
			t.Fatalf("spelling %d: no zones node", i)
		}
		for _, zone := range zones.FindChildren("security-zone") {
			for _, prop := range zone.Children {
				if prop.Name() != "interfaces" {
					continue
				}
				// Only CONTAINER nodes matter: the fan reads Keys on a node that
				// carries a host-inbound-traffic child, and a leaf has no
				// children. Assert on containers at every depth anyway, so a
				// refactor that starts nesting containers is caught too.
				var walk func(n *Node)
				walk = func(n *Node) {
					if !n.IsLeaf && len(n.Keys) > 1 && n.Name() != "host-inbound-traffic" {
						t.Fatalf("spelling %d (%q): flat-set produced a MULTI-KEY interface container Keys=%q — "+
							"the #6391 fan would treat it as a multi-member bracket body and leak the override "+
							"to every name in Keys (the #6389 regression). Either SetPath or the "+
							"security-zone interfaces schema changed; re-derive the discriminator before "+
							"relaxing this assertion.", i, cmds, n.Keys)
					}
					for _, c := range n.Children {
						walk(c)
					}
				}
				for _, iface := range prop.Children {
					walk(iface)
				}
			}
		}
	}
}

// TestHostInbound6391BracketBodyMembersDoNotShareBackingStore guards the aliasing
// trap the multi-member fan introduces. mergeHostInbound returns src UNCHANGED
// when dst is nil (the #4544 no-copy fast path), so storing one parsed body under
// N member keys without cloning would alias ONE value across all N. A later merge
// mutates dst IN PLACE, so a subsequent single-scoped override on one member
// would silently surface on its bracket siblings.
//
// Here `ping` is authored on ge-0/0/0 ALONE after the bracket body opened `ssh`
// on both: ge-0/0/0 must end up with ssh+ping and ge-0/0/1 with ssh ONLY. Without
// cloneHostInbound, ge-0/0/1 wrongly admits ping too.
func TestHostInbound6391BracketBodyMembersDoNotShareBackingStore(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone trust {
            interfaces {
                [ ge-0/0/0 ge-0/0/1 ] {
                    host-inbound-traffic { system-services ssh; }
                }
                ge-0/0/0 {
                    host-inbound-traffic { system-services ping; }
                }
            }
        }
    }
}`)
	assertHostInbound6391(t, compileHostInbound6391(t, tree), map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ping", "ssh"}},
		"ge-0/0/1": {SystemServices: []string{"ssh"}},
	})

	// Pointer independence, not just value equality: the two members must not
	// share a backing array even when they carry equal token sets.
	sec := tree.FindChild("security")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(sec.FindChild("zones"), secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	zone := secCfg.Zones["trust"]
	a, b := zone.InterfaceHostInbound["ge-0/0/0"], zone.InterfaceHostInbound["ge-0/0/1"]
	if a == nil || b == nil {
		t.Fatalf("expected both members to carry an override, got a=%v b=%v", a, b)
	}
	if a == b {
		t.Fatalf("bracket members share the SAME *HostInboundTraffic — a later in-place merge on one leaks to the other")
	}
	if len(a.SystemServices) > 0 && len(b.SystemServices) > 0 &&
		&a.SystemServices[0] == &b.SystemServices[0] {
		t.Fatalf("bracket members share the SAME SystemServices backing array")
	}
}

// TestHostInbound6391NoSharedBackingStoreAcrossInterfaces guards the aliasing
// trap the #6389 review flagged: distinct per-interface overrides must not share
// a mutable backing slice. Two interfaces each authored with a DIFFERENT service
// must keep independent SystemServices — appending to one (as a later
// mergeHostInbound would) must never surface in the other. Assert the WHOLE
// compiled map (cardinality + both dimensions per interface) AND pointer
// independence of the backing arrays.
func TestHostInbound6391NoSharedBackingStoreAcrossInterfaces(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/1 host-inbound-traffic system-services ping",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// Full-map cardinality: EXACTLY the two authored interfaces, each with its
	// own single service and no protocols. An extra sibling key (or a leaked
	// service/protocol) fails here.
	assertHostInbound6391(t, compileHostInbound6391(t, tree), map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
		"ge-0/0/1": {SystemServices: []string{"ping"}},
	})
	sec := tree.FindChild("security")
	zonesNode := sec.FindChild("zones")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	zone := secCfg.Zones["trust"]
	a := zone.InterfaceHostInbound["ge-0/0/0"]
	b := zone.InterfaceHostInbound["ge-0/0/1"]
	if a == nil || b == nil {
		t.Fatalf("expected both interfaces to carry a host-inbound override, got a=%v b=%v", a, b)
	}
	if !reflect.DeepEqual(a.SystemServices, []string{"ssh"}) {
		t.Fatalf("ge-0/0/0 system-services = %v, want [ssh]", a.SystemServices)
	}
	if !reflect.DeepEqual(b.SystemServices, []string{"ping"}) {
		t.Fatalf("ge-0/0/1 system-services = %v, want [ping]", b.SystemServices)
	}
	// Mutating one must not disturb the other (independent backing arrays).
	a.SystemServices = append(a.SystemServices, "https")
	if len(b.SystemServices) != 1 || b.SystemServices[0] != "ping" {
		t.Fatalf("aliasing: mutating ge-0/0/0 leaked into ge-0/0/1: %v", b.SystemServices)
	}
}
