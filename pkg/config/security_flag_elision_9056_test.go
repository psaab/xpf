package config

import (
	"strings"
	"testing"
)

// #9056 — the VALUELESS-FLAG brace-elision family.
//
// A stanza body may be written with its brace elided, and the parser packs the
// elided tail onto the container's own Keys:
//
//	security { flow { allow-dns-reply; } }    Keys=[flow]  Children=[[allow-dns-reply]]
//	security { flow allow-dns-reply; }        Keys=[flow allow-dns-reply]  Children=[]
//
// A compiler reading `node.Children` sees an EMPTY body in the second, so the
// flag is silently lost on a commit that reports success, with `show
// configuration` rendering exactly what the operator typed.
//
// WHY IT SURVIVED THE #2419 CENSUS. That census admitted a site only when the
// folded token declared an `args` value or a wildcard:
//
//	(wildcard == nil && args == 1) || (args == 0 && wildcard != nil) || (args >= 1 && wildcard != nil)
//
// A valueless boolean flag is `args:0, wildcard:nil, children:nil` and satisfies
// NONE of the three. So it was never enumerated, appeared in no skip bucket, and
// its absence read exactly like a clean verdict — the WRONG-POPULATION failure
// mode, which no control at the census's own layer can reach. collectCompactSites
// now admits the shape with a PRESENCE discriminator; see compactSite.flag.
//
// The measured population at the widening: 511 flag sites, 93 divergent. The 19
// in the `security` subtree are normalized here; the rest are recorded, with
// per-class reasons, in testdata/compact_block_permanent_exclusions_8690.txt.

// securityFlagElisionCase is one admitted pair, asserted on the COMPILED value
// rather than on cfgEqual: two configs that both fail to set a flag are equal,
// and "equal" would pass for the defect.
type securityFlagElisionCase struct {
	pair   string // the (container, head) pair compactNormalizeInScope is asked
	braced string
	elided string
	get    func(*Config) bool
}

func securityFlagElisionCases9056() []securityFlagElisionCase {
	flow := func(f func(*FlowConfig) bool) func(*Config) bool {
		return func(c *Config) bool { return f(&c.Security.Flow) }
	}
	return []securityFlagElisionCase{
		{"flow allow-dns-reply",
			`security { flow { allow-dns-reply; } }`,
			`security { flow allow-dns-reply; }`,
			flow(func(f *FlowConfig) bool { return f.AllowDNSReply })},
		{"flow allow-embedded-icmp",
			`security { flow { allow-embedded-icmp; } }`,
			`security { flow allow-embedded-icmp; }`,
			flow(func(f *FlowConfig) bool { return f.AllowEmbeddedICMP })},
		{"flow force-ip-reassembly",
			`security { flow { force-ip-reassembly; } }`,
			`security { flow force-ip-reassembly; }`,
			flow(func(f *FlowConfig) bool { return f.ForceIPReassembly })},
		{"flow gre-performance-acceleration",
			`security { flow { gre-performance-acceleration; } }`,
			`security { flow gre-performance-acceleration; }`,
			flow(func(f *FlowConfig) bool { return f.GREPerformanceAcceleration })},
		{"flow power-mode-disable",
			`security { flow { power-mode-disable; } }`,
			`security { flow power-mode-disable; }`,
			flow(func(f *FlowConfig) bool { return f.PowerModeDisable })},
		{"flow preserve-incoming-fragment-size",
			`security { flow { preserve-incoming-fragment-size; } }`,
			`security { flow preserve-incoming-fragment-size; }`,
			flow(func(f *FlowConfig) bool { return f.PreserveIncomingFragmentSize })},
		{"flow sync-icmp-session",
			`security { flow { sync-icmp-session; } }`,
			`security { flow sync-icmp-session; }`,
			flow(func(f *FlowConfig) bool { return f.SyncICMPSession })},
		{"tcp-session no-sequence-check",
			`security { flow { tcp-session { no-sequence-check; } } }`,
			`security { flow { tcp-session no-sequence-check; } }`,
			flow(func(f *FlowConfig) bool { return f.TCPSession.NoSequenceCheck })},
		{"tcp-session no-syn-check",
			`security { flow { tcp-session { no-syn-check; } } }`,
			`security { flow { tcp-session no-syn-check; } }`,
			flow(func(f *FlowConfig) bool { return f.TCPSession.NoSynCheck })},
		{"tcp-session no-syn-check-in-tunnel",
			`security { flow { tcp-session { no-syn-check-in-tunnel; } } }`,
			`security { flow { tcp-session no-syn-check-in-tunnel; } }`,
			flow(func(f *FlowConfig) bool { return f.TCPSession.NoSynCheckInTunnel })},
		{"tcp-session rst-invalidate-session",
			`security { flow { tcp-session { rst-invalidate-session; } } }`,
			`security { flow { tcp-session rst-invalidate-session; } }`,
			flow(func(f *FlowConfig) bool { return f.TCPSession.RstInvalidateSession })},
		{"tcp-session strict-syn-check",
			`security { flow { tcp-session { strict-syn-check; } } }`,
			`security { flow { tcp-session strict-syn-check; } }`,
			flow(func(f *FlowConfig) bool { return f.TCPSession.StrictSynCheck })},
		{"security-zone tcp-rst",
			`security { zones { security-zone z1 { tcp-rst; } } }`,
			`security { zones { security-zone z1 tcp-rst; } }`,
			func(c *Config) bool { z := c.Security.Zones["z1"]; return z != nil && z.TCPRst }},
		{"source address-persistent",
			`security { nat { source { address-persistent; } } }`,
			`security { nat { source address-persistent; } }`,
			func(c *Config) bool { return c.Security.NAT.AddressPersistent }},
		{"natv6v4 no-v6-frag-header",
			`security { nat { natv6v4 { no-v6-frag-header; } } }`,
			`security { nat { natv6v4 no-v6-frag-header; } }`,
			func(c *Config) bool {
				return c.Security.NAT.NATv6v4 != nil && c.Security.NAT.NATv6v4.NoV6FragHeader
			}},
		// (gateway, no-nat-traversal) is the ONE pair in this family with more
		// than one schema site — `security ike gateway` and `security ipsec
		// gateway` (#8921 collision check). Both are asserted, because a
		// pair-keyed admission reaches every container with that keyword and a
		// table that exercises only one of them is claiming about a set from a
		// sample of one.
		{"gateway no-nat-traversal (ike)",
			`security { ike { gateway g1 { no-nat-traversal; } } }`,
			`security { ike { gateway g1 no-nat-traversal; } }`,
			func(c *Config) bool {
				g := c.Security.IPsec.Gateways["g1"]
				return g != nil && g.NoNATTraversal
			}},
		{"gateway no-nat-traversal (ipsec)",
			`security { ipsec { gateway g1 { no-nat-traversal; } } }`,
			`security { ipsec { gateway g1 no-nat-traversal; } }`,
			func(c *Config) bool {
				g := c.Security.IPsec.Gateways["g1"]
				return g != nil && g.NoNATTraversal
			}},
		{"vpn-monitor optimized",
			`security { ipsec { vpn v1 { bind-interface st0; vpn-monitor { optimized; } } } }`,
			`security { ipsec { vpn v1 { bind-interface st0; vpn-monitor optimized; } } }`,
			func(c *Config) bool {
				v := c.Security.IPsec.VPNs["v1"]
				return v != nil && v.VPNMonitorOptimized
			}},
		{"profile default-profile",
			`security { log { profile p1 { default-profile; } } }`,
			`security { log { profile p1 default-profile; } }`,
			func(c *Config) bool {
				p := c.Security.Log.Profiles["p1"]
				return p != nil && p.DefaultProfile
			}},
	}
}

// TestSecurityFlagElisionFamily9056 is the family's convergence table.
//
// The POSITIVE CONTROL is the braced arm, asserted LIVE rather than merely
// compared: a table that only compared the two spellings would pass for a leaf
// neither spelling sets, which is the "check that fails to a value
// indistinguishable from healthy" shape. Here the braced arm must be TRUE
// before the elided arm is judged against it, so a case that stops observing
// anything fails instead of going quiet.
func TestSecurityFlagElisionFamily9056(t *testing.T) {
	for _, c := range securityFlagElisionCases9056() {
		t.Run(c.pair, func(t *testing.T) {
			b := compileText(t, c.braced)
			if b == nil {
				t.Fatalf("braced spelling did not compile: %s", c.braced)
			}
			if !c.get(b) {
				t.Fatalf("POSITIVE CONTROL: the BRACED spelling does not set the flag, so "+
					"this case can no longer observe the property it exists for: %s", c.braced)
			}
			e := compileText(t, c.elided)
			if e == nil {
				t.Fatalf("elided spelling did not compile: %s", c.elided)
			}
			if !c.get(e) {
				t.Errorf("#9056: the brace-elided spelling LOST the flag.\n"+
					"    braced:  %s\n    elided:  %s\n"+
					"    The scope admission %q is missing from compactNormalizeInScope, "+
					"so the pass leaves the packed tail on the container's Keys and the "+
					"compiler's node.Children read sees an empty body.",
					c.braced, c.elided, c.pair)
			}
		})
	}
}

// TestSecurityFlagElisionRunsThroughTheRealPass9056 binds the WIRING rather
// than the outcome.
//
// The table above would still pass if a future change made the compiler read
// the packed tail directly at these containers — a legitimate outcome, but a
// different mechanism, and the scope entries would then be dead code nobody
// noticed. This cell asserts that production's own pass TOUCHES each site, by
// running it rather than by re-deriving which pair it asks about. Re-derivation
// has been wrong three separate times in this package (see the doc comment on
// compactNormalizeInScope); running the pass and asking whether it changed the
// tree cannot drift.
//
// Severing a single scope entry reds exactly the row that named it.
func TestSecurityFlagElisionRunsThroughTheRealPass9056(t *testing.T) {
	for _, c := range securityFlagElisionCases9056() {
		t.Run(c.pair, func(t *testing.T) {
			tree, perrs := NewParser(c.elided).Parse()
			if len(perrs) > 0 || tree == nil {
				t.Fatalf("elided spelling did not parse: %v", perrs)
			}
			if n := normalizeCompactStanzas(tree); n == 0 {
				t.Errorf("#9056: the brace-elision pass does not TOUCH %q. The pair is not "+
					"admitted by compactNormalizeInScope, so nothing folds and the flag is "+
					"dropped: %s", c.pair, c.elided)
			}
		})
	}
}

// TestSecurityFlagElisionStrictGateAgrees9056 runs the family through the
// STRICT commit gate, which is the channel an operator's `commit` takes.
//
// The convergence table above uses CompileConfigLenient (the census's channel).
// The two disagree — a defect present on one can be absent on the other — so the
// operator-facing channel is asserted separately rather than assumed to follow.
func TestSecurityFlagElisionStrictGateAgrees9056(t *testing.T) {
	for _, c := range securityFlagElisionCases9056() {
		t.Run(c.pair, func(t *testing.T) {
			for _, sp := range []struct{ name, text string }{{"braced", c.braced}, {"elided", c.elided}} {
				tree, perrs := NewParser(sp.text).Parse()
				if len(perrs) > 0 || tree == nil {
					t.Fatalf("%s: parse: %v", sp.name, perrs)
				}
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("%s spelling REJECTED at the strict commit gate: %v", sp.name, err)
				}
				if !c.get(cfg) {
					t.Errorf("#9056: %s spelling compiles clean at the strict gate but the "+
						"flag is not set: %s", sp.name, sp.text)
				}
			}
		})
	}
}

// TestPolicyTerminalActionElisionStaysRejected9056 is the family's NEGATIVE
// CONTROL, and it is the reason this change is a family rather than a blanket
// rule.
//
// `then permit` / `then reject` are valueless flags of exactly the admitted
// shape, and they diverge. They are deliberately NOT admitted: the elided
// spelling is REJECTED at the strict commit gate by the #3043 terminal-action
// check while the braced spelling is accepted, so admitting the pair would
// convert a LOUD rejection into a silent acceptance — the #8868 regression that
// wears the shape of a fix.
//
// Pinning it here means the exclusion cannot be reversed by adding a line to a
// scope table: doing so reds this cell by name.
func TestPolicyTerminalActionElisionStaysRejected9056(t *testing.T) {
	const match = `match { source-address any; destination-address any; application any; }`
	for _, action := range []string{"permit", "reject"} {
		t.Run(action, func(t *testing.T) {
			braced := `security { policies { global { policy p1 { ` + match + ` then { ` + action + `; } } } } }`
			elided := `security { policies { global { policy p1 { ` + match + ` then ` + action + `; } } } }`

			bt, perrs := NewParser(braced).Parse()
			if len(perrs) > 0 {
				t.Fatalf("braced parse: %v", perrs)
			}
			if _, err := CompileConfig(bt); err != nil {
				t.Fatalf("POSITIVE CONTROL: the braced spelling must be ACCEPTED at the "+
					"strict gate, otherwise the rejection below says nothing about the "+
					"elision: %v", err)
			}
			et, perrs := NewParser(elided).Parse()
			if len(perrs) > 0 {
				t.Fatalf("elided parse: %v", perrs)
			}
			_, err := CompileConfig(et)
			if err == nil {
				t.Fatalf("#9056 NEGATIVE CONTROL: the brace-elided `then %s` now COMMITS "+
					"clean. Either (then, %s) was admitted to compactNormalizeInScope — "+
					"which converts the #3043 terminal-action rejection into a silent "+
					"acceptance and owes the #8921 collision check across the fourteen "+
					"`then` containers — or the #3043 gate itself moved. Read the "+
					"`gate-open-question` entry for this site in "+
					"testdata/compact_block_permanent_exclusions_8690.txt before "+
					"changing this cell.", action, action)
			}
			if !strings.Contains(err.Error(), "no terminal action") {
				t.Errorf("#9056 NEGATIVE CONTROL: the elided spelling is rejected, but not "+
					"by the #3043 terminal-action gate this control is about: %v\n"+
					"    A control caught by the WRONG branch reads as a working guard.", err)
			}
		})
	}
}

// TestCompactCensusEnumeratesValuelessFlags9056 guards the INSTRUMENT.
//
// This is the half the issue calls "the part that keeps it fixed". The
// behavioural fix above closes 19 sites; without this cell, reverting the
// census widening would make the other 74 invisible again and the board would
// read clean — which is exactly the state that let this class survive.
//
// The floor is deliberately a LOWER BOUND rather than an exact count: adding a
// flag leaf to the schema is routine and must not red an unrelated diff, while
// the population collapsing to zero is the failure this cell exists for.
func TestCompactCensusEnumeratesValuelessFlags9056(t *testing.T) {
	total, security := 0, 0
	for _, s := range collectCompactSites() {
		if !s.flag {
			continue
		}
		total++
		if len(s.container) > 0 && s.container[0] == "security" {
			security++
		}
	}
	if total == 0 {
		t.Fatal("#9056: the #2419 census enumerates NO valueless-flag site. The " +
			"`flagLeaf` arm of collectCompactSites is gone, so `args:0, wildcard:nil, " +
			"children:nil` leaves are once again outside the population — invisible, in " +
			"no skip bucket, and indistinguishable from a clean board.")
	}
	// 511 at the widening. A floor well below it survives ordinary schema work
	// and still fails an arm that silently stops matching most of the shape.
	if total < 300 {
		t.Errorf("#9056: only %d valueless-flag sites enumerated, want >= 300 (511 when "+
			"the arm was added). The predicate has narrowed; a census that measures a "+
			"fraction of a shape reports a clean board over the rest.", total)
	}
	if security == 0 {
		t.Errorf("#9056: no valueless-flag site under `security` is enumerated, so the " +
			"family this change normalized is outside the census population and its " +
			"convergence is unmeasured by the inventory gate.")
	}
	t.Logf("#9056: %d valueless-flag sites enumerated (%d under `security`)", total, security)
}
