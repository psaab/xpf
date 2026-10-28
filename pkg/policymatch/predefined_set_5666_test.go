package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5666 — the operator-side policy simulator (matchApp / appTermL4Constrained,
// backing `test policy` / `show security match-policies` + the REST/gRPC
// MatchPolicies RPCs) gated application-set expansion on the USER-only
// cfg.Applications.ApplicationSets map. A strict PREDEFINED bundle
// (junos-ms-rpc/junos-sun-rpc/junos-cifs/junos-routing-inbound) referenced by a
// policy therefore resolved to NO members and never matched — while the
// #5629-fixed dataplane DOES match it. So the operator's dry-run reported the
// WRONG verdict (no match) for traffic the enforced dataplane permits/denies — a
// confusing simulator↔dataplane divergence. The fix routes both sites through
// config.ResolveApplicationSet (user sets first, then the #4102 predefined table),
// resolving an application FIRST so a user app shadowing a predefined-set name
// keeps application semantics (matching #5629 + resolveUserspaceApplicationNames).
//
// Fail-on-revert: restoring the user-only `ApplicationSets[a]` gate makes the
// predefined-bundle policy no longer match (falls through to default-deny).
func TestPredefinedApplicationSetPolicyMatches_5666(t *testing.T) {
	// No user application-sets — junos-ms-rpc is a PREDEFINED bundle only.
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-msrpc",
				config.PolicyMatch{Applications: []string{"junos-ms-rpc"}})),
		},
	}, config.ApplicationsConfig{})

	// junos-ms-rpc expands to junos-ms-rpc-tcp (tcp/135) + junos-ms-rpc-udp (udp/135).
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(135)})
	if res.ContentRejected {
		t.Fatalf("ContentRejected=true for a well-formed predefined bundle; reasons=%v", res.ContentRejectionReasons)
	}
	if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "permit-msrpc" {
		t.Fatalf("predefined bundle junos-ms-rpc tcp/135 did not match the permit: Matched=%v Action=%v Name=%q DefaultUsed=%v — the simulator must match the #5629-fixed dataplane",
			res.Matched, res.Action, res.PolicyName, res.DefaultUsed)
	}

	// udp/135 also matches (junos-ms-rpc-udp).
	resUDP := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: PortPtr(135)})
	if !resUDP.Matched || resUDP.Action != config.PolicyPermit {
		t.Fatalf("junos-ms-rpc udp/135 did not match: Matched=%v Action=%v", resUDP.Matched, resUDP.Action)
	}

	// A non-member (tcp/80) must NOT match — the bundle is narrow, not match-any.
	resNo := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if resNo.Matched {
		t.Fatalf("tcp/80 wrongly matched junos-ms-rpc (should be default-deny): Action=%v", resNo.Action)
	}
}

// TestUserAppShadowsPredefinedSetName_5666 pins the app-first precedence: a USER
// application whose name collides with a predefined-set bundle keeps APPLICATION
// semantics (resolves as the user app, NOT the predefined bundle).
func TestUserAppShadowsPredefinedSetName_5666(t *testing.T) {
	// User app "junos-ms-rpc" = tcp/9999 (shadows the predefined bundle name).
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-shadow",
				config.PolicyMatch{Applications: []string{"junos-ms-rpc"}})),
		},
	}, config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			"junos-ms-rpc": {Name: "junos-ms-rpc", Protocol: "tcp", DestinationPort: "9999"},
		},
	})

	// The user app matches tcp/9999, NOT tcp/135 (the predefined bundle's port).
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(9999)})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("user app junos-ms-rpc tcp/9999 did not match (app-first precedence broken): Matched=%v Action=%v", res.Matched, res.Action)
	}
	res135 := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(135)})
	if res135.Matched {
		t.Fatalf("tcp/135 matched — a user app shadowing junos-ms-rpc must NOT expand as the predefined bundle: Action=%v", res135.Action)
	}
}
