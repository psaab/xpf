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
