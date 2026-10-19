package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/natshow"
)

// nat_dest_ports_15226_test.go — #15226 (A42-02).
//
// GetNATDestination copied only the singular DestinationPort into dst_port
// and GetNATRuleStats appended ":<first port>", so a multi-port or
// port-range DNAT rule was understated as its first port on both RPCs
// while the dataplane enforces the full list.
//
// RED-on-revert: restore either singular read and the corresponding cell
// fails (dst_ports empty / destination_match ends at the first port).

func TestGetNATDestinationCarriesAllPorts15226(t *testing.T) {
	store := natViewGRPC10437CommitStore(t, []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule dr-multi match destination-address 203.0.113.10/32",
		"set security nat destination rule-set drs rule dr-multi match destination-port [ 80 443 ]",
		"set security nat destination rule-set drs rule dr-multi then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-range match destination-address 203.0.113.11/32",
		"set security nat destination rule-set drs rule dr-range match destination-port 20000 to 20003",
		"set security nat destination rule-set drs rule dr-range then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-single match destination-address 203.0.113.12/32",
		"set security nat destination rule-set drs rule dr-single match destination-port 8443",
		"set security nat destination rule-set drs rule dr-single then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-none match destination-address 203.0.113.13/32",
		"set security nat destination rule-set drs rule dr-none then destination-nat pool dp1",
	})
	s := &Server{store: store}
	cfg := store.ActiveConfig()

	resp, err := s.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		t.Fatalf("GetNATDestination: %v", err)
	}
	byName := map[string]*pb.NATDestInfo{}
	for _, info := range resp.GetRules() {
		byName[info.GetName()] = info
	}

	// Premise: the compiled rules really carry the plural port sets, so an
	// empty dst_ports below is the renderer's fault, not the fixture's.
	for name, want := range map[string]int{"dr-multi": 2, "dr-range": 4, "dr-single": 1, "dr-none": 0} {
		rule := natViewGRPC10437FindDestRule(t, cfg, name)
		if len(rule.Match.DestinationPorts) != want {
			t.Fatalf("PREMISE: %s compiled DestinationPorts = %v, want %d entries",
				name, rule.Match.DestinationPorts, want)
		}
	}

	for _, tc := range []struct {
		name string
		want []uint32
	}{
		{"dr-multi", []uint32{80, 443}},
		{"dr-range", []uint32{20000, 20001, 20002, 20003}},
		{"dr-single", []uint32{8443}},
		{"dr-none", nil},
	} {
		info, ok := byName[tc.name]
		if !ok {
			t.Errorf("rule %q missing from GetNATDestination", tc.name)
			continue
		}
		got := info.GetDstPorts()
		if len(got) != len(tc.want) {
			t.Errorf("#15226: %s dst_ports = %v, want %v (first-port-only rendering understates the match)",
				tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("#15226: %s dst_ports = %v, want %v", tc.name, got, tc.want)
				break
			}
		}
		// Back-compat control: dst_port remains the first port.
		var wantFirst uint32
		if len(tc.want) > 0 {
			wantFirst = tc.want[0]
		}
		if info.GetDstPort() != wantFirst {
			t.Errorf("control: %s dst_port = %d, want first port %d", tc.name, info.GetDstPort(), wantFirst)
		}
		// Agreement with the shared computation, not a second literal.
		rule := natViewGRPC10437FindDestRule(t, cfg, tc.name)
		if ports := natshow.RuleMatchDestPorts(rule); len(ports) != len(got) {
			t.Errorf("#15226: %s dst_ports disagrees with natshow.RuleMatchDestPorts (%v)", tc.name, ports)
		}
	}
}

func TestGetNATRuleStatsDestinationListsAllPorts15226(t *testing.T) {
	store := natViewGRPC10437CommitStore(t, []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule dr-multi match destination-address 203.0.113.10/32",
		"set security nat destination rule-set drs rule dr-multi match destination-port [ 80 443 ]",
		"set security nat destination rule-set drs rule dr-multi then destination-nat pool dp1",
		"set security nat destination rule-set drs rule dr-range match destination-address 203.0.113.11/32",
		"set security nat destination rule-set drs rule dr-range match destination-port 20000 to 20003",
		"set security nat destination rule-set drs rule dr-range then destination-nat pool dp1",
	})
	s := &Server{store: store}

	resp, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{NatType: "destination"})
	if err != nil {
		t.Fatalf("GetNATRuleStats: %v", err)
	}
	byName := map[string]string{}
	for _, r := range resp.GetRules() {
		byName[r.GetRuleName()] = r.GetDestinationMatch()
	}
	for name, want := range map[string]string{
		"dr-multi": "203.0.113.10/32:80,443",
		"dr-range": "203.0.113.11/32:20000-20003",
	} {
		got, ok := byName[name]
		if !ok {
			t.Errorf("rule %q missing from GetNATRuleStats", name)
			continue
		}
		if got != want {
			t.Errorf("#15226: %s destination_match = %q, want %q (all ports, not first only)", name, got, want)
		}
		if strings.HasSuffix(got, ":80") || strings.HasSuffix(got, ":20000") {
			t.Errorf("#15226: %s destination_match %q collapsed to its first port", name, got)
		}
	}
}
