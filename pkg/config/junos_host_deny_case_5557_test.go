package config

import "testing"

// TestJunosHostExemptionFlagsCaseInsensitive_5557 is the fail-on-revert guard
// for the #5557 host-inbound service-token case drift. Enforcement lower-cases
// every host-inbound token before admitting (unionHostInboundTokens /
// lowerTokens in pkg/dataplane/userspace and the Rust classify_system_service),
// so a lenient-loaded UPPER-case `IKE`/`IPSEC`/`ALL` is admitted (and
// the projected coarse metadata must reach the SAME verdict, or the warning
// scope / retained ident RST can drift from the traffic enforcement. Only
// `ALL`/`any-service` are packet-wide full-admits; `IKE`/`IPsec` admit udp
// 500/4500.
//
// This mirrors the lower-case TestJunosHostExemptionFlags with upper-case
// tokens. Reverting the case-fold (junosHostSvcAdmitsIKE / the note() loop /
// HostInboundFullAdmitService going back to raw `==`) makes every upper-case
// token miss its match, so CoarseAdmitsIKE / CoarseIdentResets go false and this
// test goes RED via a clean assertion.
func TestJunosHostExemptionFlagsCaseInsensitive_5557(t *testing.T) {
	mk := func(svc ...string) JunosHostDenyProgram {
		cfg := jhTestConfig()
		cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = svc
		cfg.Security.Policies = []*ZonePairPolicies{{FromZone: "untrust", ToZone: "junos-host",
			Policies: []*Policy{jhDeny("block", []string{"bad-net"}, []string{"any"})}}}
		proj := BuildJunosHostDenyProjection(cfg)
		if len(proj.Programs) != 1 {
			t.Fatalf("want 1 program, got %d", len(proj.Programs))
		}
		return proj.Programs[0]
	}

	// IKE / IPsec / full-admit are all case-insensitive coarse-admits for IKE.
	for _, tok := range []string{"IKE", "IPsec", "ALL", "Any-Service"} {
		if p := mk(tok); !p.CoarseAdmitsIKE {
			t.Errorf("system-services %q: want CoarseAdmitsIKE (enforcement and warning metadata must agree)", tok)
		}
	}
	// Upper-case ident-reset must set the RST verdict, matching enforcement.
	if p := mk("IDENT-RESET"); !p.CoarseIdentResets {
		t.Error("system-services IDENT-RESET: want CoarseIdentResets")
	}
	// A zone-level upper-case IKE service must scope the exemption to a netdev
	// (the CoarseAdmitsIKE bit follows len(IKEExemptNetdevs)).
	if p := mk("IKE"); len(p.IKEExemptNetdevs) == 0 {
		t.Error("system-services IKE: want a scoped IKE-exempt netdev, got none")
	}
}

// TestHostInboundFullAdmitServiceCaseInsensitive_5557 pins the SSOT predicate
// itself. Enforcement lower-cases before calling it, but the coarse metadata
// and the commit-time full-admit advisory feed it the raw authored case; a
// case-sensitive `== "all"` let an upper-case `ALL` escape both. Reverting to
// the raw comparison makes these assertions RED.
func TestHostInboundFullAdmitServiceCaseInsensitive_5557(t *testing.T) {
	for _, tok := range []string{"Any-Service", "ANY-SERVICE", " any-service "} {
		if !HostInboundFullAdmitService(tok) {
			t.Errorf("HostInboundFullAdmitService(%q) = false, want true (case/space-insensitive full admit)", tok)
		}
	}
	// Non-full-admit tokens stay negative regardless of case. #3226 moved
	// `all` into this list: it is no longer a packet-wide admit but the union
	// of the named system-services.
	for _, tok := range []string{"ssh", "SSH", "ike", "IKE", "protocols-all", "",
		"all", "ALL", "All", " all "} {
		if HostInboundFullAdmitService(tok) {
			t.Errorf("HostInboundFullAdmitService(%q) = true, want false", tok)
		}
	}
}

// TestHostInboundServiceTokenExpansionCaseInsensitive_5557_3226 carries the
// #5557 case-fold contract onto the surface #3226 moved `all` to. Enforcement
// lower-cases every token (unionHostInboundTokens / lowerTokens in
// pkg/dataplane/userspace, the Rust classify_system_service), but the coarse
// junos-host shield feeds this helper the RAW authored case. A case-sensitive
// `== "all"` would leave a lenient-loaded upper-case `ALL` unexpanded, so the
// shield would not see the `ike` / `ident-reset` the expansion contains and
// would drop the very IKE it exists to exempt — the #5557 failure mode on a new
// surface.
func TestHostInboundServiceTokenExpansionCaseInsensitive_5557_3226(t *testing.T) {
	for _, tok := range []string{"all", "ALL", "All", " all "} {
		got := HostInboundServiceTokenExpansion(tok)
		if len(got) < 2 {
			t.Fatalf("HostInboundServiceTokenExpansion(%q) = %v, want the multi-token named-service union", tok, got)
		}
		var sawIKE, sawIdent bool
		for _, e := range got {
			switch e {
			case "ike":
				sawIKE = true
			case "ident-reset":
				sawIdent = true
			}
		}
		if !sawIKE || !sawIdent {
			t.Errorf("HostInboundServiceTokenExpansion(%q) must contain ike and ident-reset (the coarse-shield exemptions), got %v", tok, got)
		}
	}
	// Every other token — including the full-admit escape hatch, which is not a
	// per-service union at all — stands only for itself.
	for _, tok := range []string{"ssh", "any-service", "gre", "sssh"} {
		got := HostInboundServiceTokenExpansion(tok)
		if len(got) != 1 || got[0] != tok {
			t.Errorf("HostInboundServiceTokenExpansion(%q) = %v, want [%q]", tok, got, tok)
		}
	}
}
