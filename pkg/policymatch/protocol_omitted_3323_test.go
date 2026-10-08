package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// protoConstrainedAppCfg builds a trust->untrust permit policy whose application
// term is the predefined junos-http (TCP destination-port 80). Zones are defined
// so the #3355 transit guard passes and this test isolates the #3323 protocol
// semantics.
func protoConstrainedAppCfg() *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "http-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"junos-http"},
						},
					},
				},
			},
		},
	}
	return cfgWith(sec, config.ApplicationsConfig{})
}

// TestProtoConstrainedAppOmittedQueryProtoNoMatchDespitePermittedCompletion
// pins #3323 and documents the mixed omission semantics in #12227: a partly
// specified query without protocol fails closed for junos-http, even though the
// concrete tcp/80 completion is permitted. The runtime always carries a
// concrete protocol and keys per-application terms under it
// (policy.rs CompiledApplications.matches does `by_protocol.get(&protocol)?`).
//
// FAIL-ON-REVERT: restoring the `if proto == "" { return true }` short-circuit
// in matchApp makes the protocol-less query match the junos-http permit
// (Matched=true, permit), failing the want-default-deny assertion. The tcp/80
// positive control ensures the permitted completion remains visible.
func TestProtoConstrainedAppOmittedQueryProtoNoMatchDespitePermittedCompletion(t *testing.T) {
	cfg := protoConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"}) // Protocol omitted ("")
	if res.Matched {
		t.Fatalf("app-constrained policy over-matched an omitted query protocol (#3323/#12227); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for an omitted query protocol, got %+v", res)
	}

	completion := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !completion.Matched || completion.Action != config.PolicyPermit {
		t.Fatalf("permitted tcp/80 completion no longer matches junos-http, got %+v", completion)
	}
}

// TestProtoConstrainedAppWrongProtoNoMatch confirms the constraint is live: a
// concrete NON-matching protocol does not match the TCP-only app.
func TestProtoConstrainedAppWrongProtoNoMatch(t *testing.T) {
	cfg := protoConstrainedAppCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: 80})
	if res.Matched {
		t.Fatalf("udp matched a tcp-only app (#3323); res = %+v", res)
	}
}

// TestProtocolLessNamedAppNeverMatches pins the parity contract for a NAMED
// application that carries NO protocol. The dataplane cannot represent such an
// app and never enforces it: the snapshot builder fails the WHOLE snapshot
// closed (expandUserspacePolicyApplications returns ok=false for proto=="" →
// the __unsupported__ sentinel → the Rust integrity preflight rejects the whole
// snapshot, #3261/#3323) and strict commit hard-rejects it
// (pkg/config/compiler_validate_strict.go). A protocol-less named app can only
// exist via a lenient/HA-loaded config, where the runtime retains its
// previous-good snapshot (or fresh-boots default-deny) and enforces NONE of the
// config.
//
// #4394: the simulator must therefore report ContentRejected — NOT a fabricated
// default-policy verdict. The pre-#4394 simulator fell through to the configured
// default-policy (a "default verdict"), which is itself a divergence: under a
// default-PERMIT it would report PERMIT for a config the dataplane fail-closes,
// and under a default-DENY that retained a previous-good PERMIT snapshot it
// would report DENY while the dataplane still PERMITS. The config-wide
// ContentRejected gate mirrors the whole-snapshot fail-close for EVERY query,
// with or without a concrete query protocol (the app is unrepresentable
// regardless of the query).
//
// FAIL-ON-REVERT: dropping the #4394 config-wide gate (or the
// dpuserspace.PolicyContentRejectionReasons detection of proto=="") makes the
// protocol-less named app fall through to default-deny (DefaultUsed=true,
// ContentRejected=false), failing the want-ContentRejected assertions.
func TestProtocolLessNamedAppNeverMatches(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "badapp-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"noproto"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			// Named app with no protocol: unrepresentable by the dataplane.
			"noproto": {Name: "noproto"},
		},
	}
	cfg := cfgWith(sec, apps)

	// Omitted query protocol: the whole config is content-rejected.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"})
	if !res.ContentRejected {
		t.Fatalf("want ContentRejected for a protocol-less named app (dataplane fails the snapshot closed), got %+v", res)
	}
	if res.Matched || res.DefaultUsed {
		t.Fatalf("Matched=%v DefaultUsed=%v, want both false for a ContentRejected verdict; res = %+v", res.Matched, res.DefaultUsed, res)
	}

	// Concrete query protocol: still ContentRejected — the app is unrepresentable
	// regardless of the query, mirroring the whole-snapshot dataplane reject.
	res = Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !res.ContentRejected {
		t.Fatalf("want ContentRejected for a protocol-less named app with a concrete query, got %+v", res)
	}
	if res.Matched || res.DefaultUsed {
		t.Fatalf("Matched=%v DefaultUsed=%v, want both false for a ContentRejected verdict; res = %+v", res.Matched, res.DefaultUsed, res)
	}
}

// TestAnyApplicationOmittedQueryProtoStillMatches confirms the literal
// `application any` term remains match-any for an omitted protocol — it is
// handled by matchApp's `a == "any"` short-circuit, independent of the protocol
// gate, exactly like the runtime's match_any.
func TestAnyApplicationOmittedQueryProtoStillMatches(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "any-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					},
				},
			},
		},
	}
	cfg := cfgWith(sec, config.ApplicationsConfig{})

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"}) // Protocol omitted
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("`application any` must match an omitted protocol; res = %+v", res)
	}
}
