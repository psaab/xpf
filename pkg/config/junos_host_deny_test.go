package config

import "testing"

// jhZone builds a minimal enforceable ingress zone (one non-lifeline interface).
func jhTestConfig() *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.2.10/24"}}}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/1.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"good-host": {Name: "good-host", Value: "10.0.0.6/32"},
		"bad-net":   {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	return cfg
}

func jhDeny(name string, src []string, app []string) *Policy {
	return &Policy{Name: name, Action: PolicyDeny, Match: PolicyMatch{SourceAddresses: src, Applications: app}}
}

func jhPermit(name string, src []string, app []string) *Policy {
	return &Policy{Name: name, Action: PolicyPermit, Match: PolicyMatch{SourceAddresses: src, Applications: app}}
}

// TestJunosHostThreeTierComposition proves the effective program is assembled in
// Rust's exact tier order (exact -> from-any -> global): a from-any PERMIT ahead
// of a GLOBAL deny renders as a return BEFORE the deny's drop (#9504), and the
// global deny is rendered (its #4168 warning suppressed).
func TestJunosHostThreeTierComposition(t *testing.T) {
	cfg := jhTestConfig()
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "any", ToZone: "junos-host", Policies: []*Policy{
			jhPermit("allow-good", []string{"good-host"}, []string{"any"}),
		}},
	}
	cfg.Security.GlobalPolicies = []*Policy{
		{Name: "g-block", Action: PolicyDeny, Match: PolicyMatch{
			SourceAddresses: []string{"bad-net"}, Applications: []string{"any"},
			ToZones: []string{"junos-host"}}},
	}
	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 || !proj.Programs[0].Representable {
		t.Fatalf("want 1 representable program, got %+v", proj.Programs)
	}
	p := proj.Programs[0]
	if len(p.RulesV4) != 2 {
		t.Fatalf("want the from-any return then the global drop, got %+v", p.RulesV4)
	}
	if r := p.RulesV4[0]; r.Verdict != JunosHostReturn || len(r.Src) != 1 || r.Src[0] != "10.0.0.6/32" {
		t.Errorf("first v4 rule = %+v, want a return for [10.0.0.6/32] (the from-any carve, in tier order)", r)
	}
	if r := p.RulesV4[1]; r.Verdict != JunosHostDrop || len(r.Src) != 1 || r.Src[0] != "10.0.0.0/8" {
		t.Errorf("second v4 rule = %+v, want a drop for [10.0.0.0/8]", r)
	}
	if !proj.RenderedPolicyKeys[JunosHostGlobalPolicyKey("g-block")] {
		t.Errorf("global deny g-block should be rendered (warning suppressed)")
	}
	// The from-any PERMIT is never suppressed (it is not a deny).
	if proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("any", "allow-good")] {
		t.Errorf("a permit must never be marked rendered")
	}
}

// TestJunosHostUnresolvableApplicationGatesTheProgram9504 closes a hole the
// #9504 mutation matrix found: removing the application-resolution gate in
// junosHostProjectTerm red NOTHING (row V17, failing=[]).
//
// The residual rows could not see it. With the gate removed an unresolvable
// application still resolves to an empty L4 list, so junosHostBuildRule projects
// no rule for that term either way — the term looks equally inert. What changes
// is the WHOLE-PROGRAM contract: its SIBLING deny starts rendering. That matters
// most for a permit, because the kernel would then enforce a deny against
// traffic the operator's permit may have carved, and the projection cannot know
// what it carved precisely because the application did not resolve.
//
// The IKE-exempt tuple stands in for the whole unresolvable class here (the
// IPsec passthrough path owns that tuple, so the projection refuses it); an
// ALG-bearing application takes the same arm.
func TestJunosHostUnresolvableApplicationGatesTheProgram9504(t *testing.T) {
	build := func(permitApp string) *Config {
		cfg := jhTestConfig()
		cfg.Applications.Applications = map[string]*Application{
			"my-ike": {Name: "my-ike", Protocol: "udp", DestinationPort: "500"},
		}
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
				jhPermit("allow-good", []string{"good-host"}, []string{permitApp}),
				jhDeny("block-net", []string{"bad-net"}, []string{"any"}),
			}},
		}
		return cfg
	}

	proj := BuildJunosHostDenyProjection(build("my-ike"))
	if len(proj.Programs) != 1 {
		t.Fatalf("want one program for the ingress zone, got %+v", proj.Programs)
	}
	p := proj.Programs[0]
	if p.Representable || len(p.RulesV4) != 0 || len(p.RulesV6) != 0 {
		t.Errorf("an unresolvable application must make the WHOLE program un-representable, "+
			"so the sibling deny renders nothing: %+v", p)
	}
	if len(proj.RenderedPolicyKeys) != 0 {
		t.Errorf("no policy may be marked rendered when the program emits nothing, or the "+
			"sibling deny's #4168 warning is suppressed while nothing enforces it: %+v",
			proj.RenderedPolicyKeys)
	}

	// POSITIVE CONTROL: the same fixture with a resolvable permit application
	// renders the deny. Without this, a projection that returned nothing for
	// every config would satisfy the assertions above.
	ctrl := BuildJunosHostDenyProjection(build("any"))
	if len(ctrl.Programs) != 1 || len(ctrl.Programs[0].RulesV4) == 0 {
		t.Fatalf("control: a resolvable permit ahead of the same deny must render rules; got %+v",
			ctrl.Programs)
	}
	if !ctrl.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "block-net")] {
		t.Errorf("control: the deny renders and must be marked rendered: %+v", ctrl.RenderedPolicyKeys)
	}
}

// TestJunosHostWholeProgramGate proves an un-representable term in ANY tier
// suppresses the WHOLE ingress program (no exposed global/from-any deny, no
// dropped carve-out permit), and every contributing policy keeps its warning.
func TestJunosHostWholeProgramGate(t *testing.T) {
	cfg := jhTestConfig()
	// A feed-tainted source makes the exact-tier permit un-representable.
	cfg.Security.DynamicAddress.AddressBindings = map[string]*AddressBinding{
		"feedy": {Name: "feedy", FeedNames: []string{"f1"}},
	}
	cfg.Security.AddressBook.Addresses["feedy"] = &Address{Name: "feedy", Value: "10.9.9.0/24"}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
			jhPermit("allow-feed", []string{"feedy"}, []string{"any"}),
		}},
	}
	cfg.Security.GlobalPolicies = []*Policy{
		{Name: "g-block", Action: PolicyDeny, Match: PolicyMatch{
			SourceAddresses: []string{"bad-net"}, Applications: []string{"any"},
			ToZones: []string{"junos-host"}}},
	}
	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 || proj.Programs[0].Representable {
		t.Fatalf("feed-tainted term must suppress the whole program, got %+v", proj.Programs)
	}
	if proj.RenderedPolicyKeys[JunosHostGlobalPolicyKey("g-block")] {
		t.Errorf("global deny must NOT be rendered when a co-tier term is un-representable (would expose it while dropping the carve-out)")
	}
}

// TestJunosHostExemptionFlags proves the coarse-admit exemption flags: an
// ike-admitting zone sets CoarseAdmitsIKE; an ident-reset zone sets
// CoarseIdentResets; a full-admit (`any-service`) zone shadows ident-reset (the
// bare accept answers TCP/113 before the reject rule, so there is no RST
// verdict to protect).
//
// #3226: `system-services all` is no longer a full admit — it EXPANDS to the
// named-service union, which contains `ident-reset`, so the host-inbound chain
// really does emit `tcp dport 113 reject with tcp reset` for an `all` zone and
// the shield must carve TCP/113 out. The `{all, ident-reset}` row therefore
// flipped from "shadowed" to "resets"; `{any-service, ident-reset}` keeps the
// original shadowing property.
func TestJunosHostExemptionFlags(t *testing.T) {
	mk := func(svc ...string) config1Program {
		cfg := jhTestConfig()
		cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = svc
		cfg.Security.Policies = []*ZonePairPolicies{{FromZone: "untrust", ToZone: "junos-host",
			Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}}}
		proj := BuildJunosHostDenyProjection(cfg)
		if len(proj.Programs) != 1 {
			t.Fatalf("want 1 program, got %d", len(proj.Programs))
		}
		return config1Program{proj.Programs[0]}
	}
	if p := mk("ike"); !p.CoarseAdmitsIKE {
		t.Error("ike zone: want CoarseAdmitsIKE")
	}
	if p := mk("ident-reset"); !p.CoarseIdentResets {
		t.Error("ident-reset zone: want CoarseIdentResets")
	}
	if p := mk("any-service", "ident-reset"); p.CoarseIdentResets {
		t.Error("{any-service, ident-reset} zone: 113 is coarse-accepted (shadowed) — must NOT be treated as RST (no fail-open)")
	}
	// #3226: `all` expands to the named union INCLUDING ident-reset, so the
	// kernel chain does emit the RST rule and the shield must not drop it.
	if p := mk("all", "ident-reset"); !p.CoarseIdentResets {
		t.Error("{all, ident-reset} zone: `all` expands to include ident-reset, so 113 IS reset — want CoarseIdentResets (#3226)")
	}
	if p := mk("all"); !p.CoarseIdentResets {
		t.Error("`all` alone expands to include ident-reset — want CoarseIdentResets (#3226)")
	}
	// #3226 fail-CLOSED guard: `all` must still coarse-admit IKE via the
	// expansion. Losing this makes the shield drop the IKE/NAT-T it exempts.
	if p := mk("all"); !p.CoarseAdmitsIKE {
		t.Error("`all` zone: expansion contains ike — want CoarseAdmitsIKE (#3226, else the shield drops IKE)")
	}
}

type config1Program struct{ JunosHostDenyProgram }

// TestJunosHostCrossZoneAmbiguousTrunkKeepsWarning is the F1 fail-on-revert
// guard: a zone whose ONLY non-lifeline netdev is a cross-zone-ambiguous shared
// physical parent (its untagged unit-0 rides the SAME parent that carries other
// zones' tagged VLAN subunits) resolves to ZERO unambiguous iifname netdevs, so
// its junos-host DENY emits NO kernel rule — and therefore MUST keep its #4168
// warning (never suppressed). Reverting the warning-suppression gate to
// `len(non-lifeline interface refs) > 0` (which is TRUE here) wrongly suppresses
// the warning -> silent under-enforcement, and this test goes RED.
func TestJunosHostCrossZoneAmbiguousTrunkKeepsWarning(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"10.0.9.1/24"}},               // untagged, zone trunkzero
			50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}}, // VLAN 50, zone vlanb
			80: {Number: 80, VlanID: 80, Addresses: []string{"10.0.80.1/24"}}, // VLAN 80, zone vlanc
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"trunkzero": {Name: "trunkzero", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"vlanb": {Name: "vlanb", Interfaces: []string{"ge-0/0/2.50"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"vlanc": {Name: "vlanc", Interfaces: []string{"ge-0/0/2.80"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"bad-net": {Name: "bad-net", Value: "10.0.0.0/8"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "trunkzero", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-zero", []string{"bad-net"}, []string{"any"})}},
		{FromZone: "vlanb", ToZone: "junos-host", Policies: []*Policy{
			jhDeny("block-b", []string{"bad-net"}, []string{"any"})}},
	}

	nd := JunosHostZoneIngressNetdevs(cfg)
	if len(nd["trunkzero"]) != 0 {
		t.Fatalf("trunkzero must resolve to NO unambiguous netdev (shared parent ge-0-0-2), got %v", nd["trunkzero"])
	}
	if got := nd["vlanb"]; len(got) != 1 || got[0] != "ge-0-0-2.50" {
		t.Fatalf("vlanb must resolve to its own child netdev ge-0-0-2.50, got %v", got)
	}

	proj := BuildJunosHostDenyProjection(cfg)
	// The trunkzero deny produced no rule -> its warning is NOT suppressed.
	if proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("trunkzero", "block-zero")] {
		t.Error("trunkzero deny emits no kernel rule (ambiguous netdev) — its #4168 warning MUST NOT be suppressed (F1)")
	}
	// The vlanb deny DID render on its own child netdev -> suppressed.
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("vlanb", "block-b")] {
		t.Error("vlanb deny renders on ge-0-0-2.50 — its warning should be suppressed")
	}
}

// TestJunosHostCrossDimensionPermitUnrepresentable proves a narrow-application
// permit ahead of a deny is a cross-dimension carve nft cannot express — the
// whole program is un-representable.
func TestJunosHostCrossDimensionPermitRendersAReturn9504(t *testing.T) {
	cfg := jhTestConfig()
	cfg.Security.Policies = []*ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{
			jhPermit("allow-ssh", []string{"good-host"}, []string{"junos-ssh"}),
			jhDeny("block-net", []string{"bad-net"}, []string{"any"}),
		}},
	}
	proj := BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) != 1 || !proj.Programs[0].Representable {
		t.Fatalf("#9504: a narrow-application permit ahead of a deny renders as a return in "+
			"first-match order, so the program is representable: %+v", proj.Programs)
	}
	rules := proj.Programs[0].RulesV4
	if len(rules) != 2 {
		t.Fatalf("want the permit's return then the deny's drop, got %+v", rules)
	}
	if r := rules[0]; r.Verdict != JunosHostReturn || len(r.Src) != 1 || r.Src[0] != "10.0.0.6/32" || len(r.L4) == 0 {
		t.Errorf("first rule = %+v, want a return for good-host carrying the permit's own "+
			"application match — a return that widened to `application any` would admit more "+
			"than the permit authored", r)
	}
	if r := rules[1]; r.Verdict != JunosHostDrop || len(r.Src) != 1 || r.Src[0] != "10.0.0.0/8" {
		t.Errorf("second rule = %+v, want the deny's drop for bad-net", r)
	}
	if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", "block-net")] {
		t.Errorf("the deny renders and must be marked rendered: %+v", proj.RenderedPolicyKeys)
	}
}
