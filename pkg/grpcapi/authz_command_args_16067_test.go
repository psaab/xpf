package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16067: argument-scoped deny-commands patterns must fire on the gRPC
// surface. Pre-fix every cell below was ALLOWED because the gate matched
// only the argument-free command path.

func cfg16067(t *testing.T, deny, allow string) *config.Config {
	t.Helper()
	lc := &config.LoginClass{Name: "ops", DenyCommands: deny, AllowCommands: allow}
	if deny != "" {
		lc.DenyLeavesPresent = []string{"deny-commands"}
	}
	if allow != "" {
		lc.AllowLeavesPresent = []string{"allow-commands"}
	}
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{lc}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {}, "secret-zone": {}}
	cfg.ZoneQuarantineNames = []string{"secret-zone", "trust"}
	return cfg
}

func TestArgumentScopedDenyFiresOnGRPC16067(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, method string
		req                   any
		wantDeny              bool
	}{
		{"route table denied", `^show route table secret-vrf$`, "ShowText", &pb.ShowTextRequest{Topic: "route-table:secret-vrf"}, true},
		{"route table other allowed", `^show route table secret-vrf$`, "ShowText", &pb.ShowTextRequest{Topic: "route-table:public-vrf"}, false},
		{"route table unanchored", `show route table secret-vrf`, "ShowText", &pb.ShowTextRequest{Topic: "route-table:secret-vrf"}, true},
		{"ping prefix denied", `^ping 10\.99\.`, "Ping", &pb.PingRequest{Target: "10.99.1.1"}, true},
		{"ping other allowed", `^ping 10\.99\.`, "Ping", &pb.PingRequest{Target: "10.98.1.1"}, false},
		{"ping source denied", `^ping 10\.0\.0\.1 source 192\.0\.2\.1$`, "Ping", &pb.PingRequest{Target: "10.0.0.1", Source: "192.0.2.1"}, true},
		{"traceroute denied", `^traceroute 10\.99\.`, "Traceroute", &pb.TracerouteRequest{Target: "10.99.1.1"}, true},
		{"log any denied", `^show log .*`, "ShowText", &pb.ShowTextRequest{Topic: "log:messages"}, true},
		{"log counted denied", `^show log messages 100$`, "ShowText", &pb.ShowTextRequest{Topic: "log:messages:100"}, true},
		{"log other count allowed", `^show log messages 100$`, "ShowText", &pb.ShowTextRequest{Topic: "log:messages:50"}, false},
		{"screen zone denied", `^show security screen statistics zone secret-zone$`, "ShowText", &pb.ShowTextRequest{Topic: "screen-statistics:secret-zone"}, true},
		{"test policy denied", `^test policy from-zone trust to-zone secret-zone$`, "ShowText", &pb.ShowTextRequest{Topic: "test-policy:from=trust,to=secret-zone"}, true},
		{"test routing denied", `^test routing destination 10\.99\.0\.0/24$`, "ShowText", &pb.ShowTextRequest{Topic: "test-routing:dest=10.99.0.0/24"}, true},
		{"route prefix denied", `^show route 10\.99\.0\.0/24$`, "ShowText", &pb.ShowTextRequest{Topic: "route-prefix:10.99.0.0/24"}, true},
		{"route protocol denied", `^show route protocol bgp$`, "ShowText", &pb.ShowTextRequest{Topic: "route-protocol:bgp"}, true},
		{"session zone denied", `^show security flow session zone trust$`, "GetSessions", &pb.GetSessionsRequest{Zone: uint32(config.StableZoneID("trust"))}, true},
		{"session unfiltered allowed", `^show security flow session zone trust$`, "GetSessions", &pb.GetSessionsRequest{}, false},
		{"match policies denied", `^show security match-policies from-zone trust to-zone secret-zone$`, "MatchPolicies", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "secret-zone"}, true},
		{"interfaces filter denied", `^show interfaces ge-0/0/9$`, "ShowText", &pb.ShowTextRequest{Topic: "interfaces-detail", Filter: "ge-0/0/9"}, true},
		{"anchored path still denied with args", `^show route table$`, "ShowText", &pb.ShowTextRequest{Topic: "route-table:public-vrf"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern, "")
			err := gateDecide7172(t, cfg, tc.method, tc.req)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over %s was ALLOWED on gRPC; argument-scoped denies must fire remotely (#16067)", tc.pattern, tc.method)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over %s refused a command it does not name: %v", tc.pattern, tc.method, err)
			}
		})
	}
}

// The deny-with-exceptions idiom survives: an allow written against the
// full argument spelling lifts the anchored bare deny for that spelling
// only (EvaluateForms core-exception geometry).
func TestArgumentScopedAllowException16067(t *testing.T) {
	cfg := cfg16067(t, `^show log$`, `^show log messages 100$`)
	if err := gateDecide7172(t, cfg, "ShowText", &pb.ShowTextRequest{Topic: "log:messages:100"}); err != nil {
		t.Errorf("allow exception ^show log messages 100$ must admit log:messages:100: %v", err)
	}
	if err := gateDecide7172(t, cfg, "ShowText", &pb.ShowTextRequest{Topic: "log:messages"}); err == nil {
		t.Error("bare log:messages must stay denied under ^show log$; the exception names only the counted spelling")
	}
}

// A malformed packed topic the handler would reject cannot be named, so
// a restricted class denies rather than judging the bare path.
// #17081 fold (Rev18131 B2): a PRESENT literal port 0 on the optional
// MatchPoliciesRequest fields must reach the canonical command string. The
// pre-fold builder gated on GetSourcePort()/GetDestinationPort() != 0, which
// cannot distinguish absent from present-0, so an argument-scoped deny naming
// destination-port 0 / source-port 0 never fired for exactly the query
// #17081 made expressible - a fail-open in the restrictive direction. The
// ICMP fields beside it already gated on pointer presence.
//
// FAIL-ON-REVERT: restoring the != 0 gates drops the port-0 tokens and the
// three wantDeny cells below are ALLOWED again.
func TestMatchPoliciesLiteralPortZeroAuthz17081(t *testing.T) {
	zero := int32(0)
	fiftyThree := int32(53)
	for _, tc := range []struct {
		name, pattern string
		req           *pb.MatchPoliciesRequest
		wantDeny      bool
	}{
		{"destination-port 0 denied", "destination-port 0", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DestinationPort: &zero}, true},
		{"source-port 0 denied", "source-port 0", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp", SourcePort: &zero}, true},
		{"anchored full line with destination-port 0", "^show security match-policies from-zone trust to-zone untrust destination-port 0 protocol udp$", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DestinationPort: &zero}, true},
		{"destination-port 0 deny does not fire on 53", "destination-port 0", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DestinationPort: &fiftyThree}, false},
		{"destination-port 0 deny does not fire when omitted", "destination-port 0", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp"}, false},
		{"anchored absent-port line still denied bare", "^show security match-policies from-zone trust to-zone untrust protocol udp$", &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern, "")
			err := gateDecide7172(t, cfg, "MatchPolicies", tc.req)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over MatchPolicies with a present literal port 0 was ALLOWED; the port-0 token must reach the canonical form (#17081)", tc.pattern)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over MatchPolicies refused a command it does not name: %v", tc.pattern, err)
			}
		})
	}
}

func TestMalformedPackedTopicDenies16067(t *testing.T) {
	cfg := cfg16067(t, `^show version$`, "")
	for _, topic := range []string{
		"test-policy:from=trust,to=trust,from=dmz",
		"test-policy:bogus=trust,to=dmz",
		"test-routing:instance=dmz",
	} {
		if err := gateDecide7172(t, cfg, "ShowText", &pb.ShowTextRequest{Topic: topic}); err == nil {
			t.Errorf("topic %q was ALLOWED for a restricted class; an unnameable argument string must deny (#16067)", topic)
		} else if !strings.Contains(err.Error(), "cannot be") {
			t.Errorf("topic %q refusal should name the unnameable-arguments cause: %v", topic, err)
		}
	}
	// Unrestricted class is unaffected.
	open := cfg16067(t, "", "")
	if err := gateDecide7172(t, open, "ShowText", &pb.ShowTextRequest{Topic: "test-policy:from=trust,to=trust,from=dmz"}); err != nil {
		t.Errorf("unrestricted class must be unaffected by argument reconstruction: %v", err)
	}
}

// #16378 fold: selector-bearing RPCs that fell through to the bare
// charge — filtered GetSessionSummary, GetEvents, ClearSessions,
// MonitorInterface, filtered terse ShowInterfacesDetail.
func TestUnreconstructedSelectorRPCs16067(t *testing.T) {
	trustID := uint32(config.StableZoneID("trust"))
	for _, tc := range []struct {
		name, pattern, method string
		req                   any
		wantDeny              bool
	}{
		{"filtered summary zone denied", `^show security flow session zone trust$`, "GetSessionSummary", &pb.GetSessionSummaryRequest{Zone: trustID}, true},
		{"unfiltered summary allowed under zone deny", `^show security flow session zone trust$`, "GetSessionSummary", &pb.GetSessionSummaryRequest{}, false},
		{"unfiltered summary denied by summary deny", `^show security flow session summary$`, "GetSessionSummary", &pb.GetSessionSummaryRequest{}, true},
		{"filtered summary allowed under summary deny", `^show security flow session summary$`, "GetSessionSummary", &pb.GetSessionSummaryRequest{Zone: trustID}, false},
		{"events zone denied", `^show security log zone trust$`, "GetEvents", &pb.GetEventsRequest{Zone: trustID, HasZone: true}, true},
		{"events protocol denied", `^show security log protocol tcp$`, "GetEvents", &pb.GetEventsRequest{Protocol: "tcp"}, true},
		{"events unfiltered allowed", `^show security log zone trust$`, "GetEvents", &pb.GetEventsRequest{}, false},
		{"clear zone denied", `^clear security flow session zone trust$`, "ClearSessions", &pb.ClearSessionsRequest{Zone: "trust"}, true},
		{"clear other zone allowed", `^clear security flow session zone trust$`, "ClearSessions", &pb.ClearSessionsRequest{Zone: "dmz"}, false},
		{"monitor interface denied", `^monitor interface ge-0/0/9$`, "MonitorInterface", &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/9"}, true},
		{"monitor summary allowed", `^monitor interface ge-0/0/9$`, "MonitorInterface", &pb.MonitorInterfaceRequest{}, false},
		{"terse filtered interfaces denied", `ge-0/0/9`, "ShowInterfacesDetail", &pb.ShowInterfacesDetailRequest{Filter: "ge-0/0/9", Terse: true}, true},
		{"zonepair bare denied", `^show security flow session summary$`, "GetZonePairSummary", &pb.GetZonePairSummaryRequest{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg16067(t, tc.pattern, "")
			err := gateDecide7172(t, cfg, tc.method, tc.req)
			if tc.wantDeny && err == nil {
				t.Errorf("deny %q over %s was ALLOWED; the selector must be reconstructed (#16378 fold)", tc.pattern, tc.method)
			}
			if !tc.wantDeny && err != nil {
				t.Errorf("deny %q over %s refused a command it does not name: %v", tc.pattern, tc.method, err)
			}
		})
	}
}
