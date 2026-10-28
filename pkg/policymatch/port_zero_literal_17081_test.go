package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// portZeroRangeCfg17081: app udp destination-port 0-1023, one trust->untrust
// rule using it with the given action, and the opposite default policy.
func portZeroRangeCfg17081(action config.PolicyAction, def config.PolicyAction) *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: def,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{{
				Name:   "d",
				Action: action,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"app0"},
				},
			}},
		}},
	}
	apps := config.ApplicationsConfig{Applications: map[string]*config.Application{
		"app0": {Name: "app0", Protocol: "udp", DestinationPort: "0-1023"},
	}}
	return cfgWith(sec, apps)
}

// TestPortZeroLiteralMatchesRange17081 pins R4-Q45-04/#17081, restoring the
// Go test deleted in the 6bd30008fd revert of the #13920 simulator fix: a
// PRESENT literal port 0 matches a `0-N` term exactly as the dataplane does
// with l4_present (Rust zero_port_range_denies_literal_zero_when_l4_present_13920).
// Both directions are asserted — a 0-N deny must not report default permit,
// and a 0-N permit must not report default deny.
//
// FAIL-ON-REVERT: restoring the 0-sentinel gate makes the
// literal-0 queries fall through to the default, flipping both cases.
func TestPortZeroLiteralMatchesRange17081(t *testing.T) {
	// Deny rule, default permit: literal 0 must hit the deny.
	res := Match(portZeroRangeCfg17081(config.PolicyDeny, config.PolicyPermit),
		Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: PortPtr(0)})
	if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "d" || res.DefaultUsed {
		t.Fatalf("literal dport 0 vs 0-1023 deny: got %+v, want matched deny d", res)
	}
	// Permit rule, default deny: literal 0 must hit the permit.
	res = Match(portZeroRangeCfg17081(config.PolicyPermit, config.PolicyDeny),
		Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: PortPtr(0)})
	if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "d" || res.DefaultUsed {
		t.Fatalf("literal dport 0 vs 0-1023 permit: got %+v, want matched permit d", res)
	}
	// Control: an in-range non-zero port matches the same rule.
	res = Match(portZeroRangeCfg17081(config.PolicyDeny, config.PolicyPermit),
		Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: PortPtr(53)})
	if !res.Matched || res.Action != config.PolicyDeny {
		t.Fatalf("control dport 53: got %+v, want matched deny", res)
	}
}

// TestPortZeroOmittedStillFailsClosed17081 pins the other half: an OMITTED
// (nil) port still never matches a port-constrained term, so the verdict
// falls through to the default — the fail-closed #3330 posture is kept.
func TestPortZeroOmittedStillFailsClosed17081(t *testing.T) {
	res := Match(portZeroRangeCfg17081(config.PolicyDeny, config.PolicyPermit),
		Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp"}) // DstPort nil = omitted
	if res.Matched || !res.DefaultUsed || res.Action != config.PolicyPermit {
		t.Fatalf("omitted dport vs 0-1023 deny: got %+v, want default permit (fail-closed term)", res)
	}
}

// TestPortZeroSourceLiteral17081 pins the source-port sibling (#3415 gate):
// a present source port 0 matches a source-port `0-N` term; omitted does not.
func TestPortZeroSourceLiteral17081(t *testing.T) {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{{
				Name:   "s0",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"s0app"},
				},
			}},
		}},
	}
	apps := config.ApplicationsConfig{Applications: map[string]*config.Application{
		"s0app": {Name: "s0app", Protocol: "udp", SourcePort: "0-1023", DestinationPort: "53"},
	}}
	cfg := cfgWith(sec, apps)
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", SrcPort: PortPtr(0), DstPort: PortPtr(53)})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("literal sport 0 vs 0-1023: got %+v, want matched permit", res)
	}
	res = Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DstPort: PortPtr(53)}) // SrcPort omitted
	if res.Matched || !res.DefaultUsed {
		t.Fatalf("omitted sport vs 0-1023: got %+v, want default deny", res)
	}
}

// TestSelectorArgsPortZeroIsPresent17081 pins the CLI grammar half: an
// explicit `destination-port 0` token is PRESENT literal 0 after parsing,
// while no token leaves the selector omitted (nil).
func TestSelectorArgsPortZeroIsPresent17081(t *testing.T) {
	sel, err := ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "udp", "destination-port", "0"})
	if err != nil {
		t.Fatalf("ParseSelectorArgs: %v", err)
	}
	if sel.DstPort == nil || *sel.DstPort != 0 {
		t.Fatalf("destination-port 0 parsed as %v, want present 0", sel.DstPort)
	}
	if q := sel.Query(); q.DstPort == nil || *q.DstPort != 0 {
		t.Fatalf("Query dst port = %v, want present 0", q.DstPort)
	}
	sel, err = ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "udp"})
	if err != nil {
		t.Fatalf("ParseSelectorArgs: %v", err)
	}
	if sel.DstPort != nil || sel.Query().DstPort != nil {
		t.Fatalf("omitted destination-port = %v, want nil", sel.DstPort)
	}
}
