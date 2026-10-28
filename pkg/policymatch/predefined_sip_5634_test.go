package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5634 — the predefined `junos-sip` application was UDP-only, so a policy
// `match application junos-sip` matched UDP/5060 SIP but silently DROPPED
// TCP/5060 SIP (the flow fell through to default-deny). Real Junos junos-sip
// matches BOTH transports on 5060. The fix models junos-sip as a UDP+TCP/5060
// predefined application-set, so the operator simulator (this path) and the
// #5629-fixed dataplane both match TCP/5060 SIP.
//
// Fail-on-revert: restoring the UDP-only junos-sip application makes the
// tcp/5060 query below fall through to default-deny → this test goes RED.
func TestPredefinedSipPolicyMatchesTCP_5634(t *testing.T) {
	// No user applications/sets — junos-sip is a PREDEFINED bundle only.
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-sip",
				config.PolicyMatch{Applications: []string{"junos-sip"}})),
		},
	}, config.ApplicationsConfig{})

	// TCP/5060 SIP — the #5634 parity fix. Must match the permit, not default-deny.
	resTCP := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(5060)})
	if resTCP.ContentRejected {
		t.Fatalf("ContentRejected=true for junos-sip tcp/5060; reasons=%v", resTCP.ContentRejectionReasons)
	}
	if !resTCP.Matched || resTCP.Action != config.PolicyPermit || resTCP.PolicyName != "permit-sip" {
		t.Fatalf("junos-sip tcp/5060 did not match the permit (TCP/5060 SIP dropped — the #5634 bug): Matched=%v Action=%v Name=%q DefaultUsed=%v",
			resTCP.Matched, resTCP.Action, resTCP.PolicyName, resTCP.DefaultUsed)
	}

	// UDP/5060 SIP — the historical match must be preserved.
	resUDP := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: PortPtr(5060)})
	if !resUDP.Matched || resUDP.Action != config.PolicyPermit {
		t.Fatalf("junos-sip udp/5060 did not match: Matched=%v Action=%v", resUDP.Matched, resUDP.Action)
	}

	// A non-member (tcp/5061, the SIP-TLS port Junos has NO predefined app for)
	// must NOT match — the bundle is narrow, not match-any.
	resNo := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(5061)})
	if resNo.Matched {
		t.Fatalf("tcp/5061 wrongly matched junos-sip (should be default-deny): Action=%v", resNo.Action)
	}
}
