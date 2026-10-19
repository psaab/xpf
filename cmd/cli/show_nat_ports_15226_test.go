package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// show_nat_ports_15226_test.go — #15226 (A42-02).
//
// The ctl destination views rendered ":<first port>" from the singular
// dst_port. They now render the complete dst_ports set the daemon carries.
//
// RED-on-revert: drop dst_ports from the suffix (singular fallback only)
// and the multi/range cells fail.

func TestNATDestPortsSuffix15226(t *testing.T) {
	for _, tc := range []struct {
		name string
		info *pb.NATDestInfo
		want string
	}{
		{"bracket list", &pb.NATDestInfo{DstPort: 80, DstPorts: []uint32{80, 443}}, ":80,443"},
		{"range", &pb.NATDestInfo{DstPort: 20000, DstPorts: []uint32{20000, 20001, 20002, 20003}}, ":20000-20003"},
		{"single via plural", &pb.NATDestInfo{DstPort: 8443, DstPorts: []uint32{8443}}, ":8443"},
		{"old daemon singular fallback", &pb.NATDestInfo{DstPort: 8443}, ":8443"},
		{"no constraint", &pb.NATDestInfo{}, ""},
		{"nil", nil, ""},
	} {
		if got := natDestPortsSuffix(tc.info); got != tc.want {
			t.Errorf("%s: natDestPortsSuffix = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The destination list view must show every port for a multi-port rule.
func TestShowNATDestinationListsAllPorts15226(t *testing.T) {
	client := &natShowClient13199{
		destination: &pb.GetNATDestinationResponse{Rules: []*pb.NATDestInfo{
			{Name: "dr-multi", DstAddr: "203.0.113.10/32", DstPort: 80, DstPorts: []uint32{80, 443}, TranslateIp: "10.0.0.5", PoolName: "dp1"},
			{Name: "dr-range", DstAddr: "203.0.113.11/32", DstPort: 20000, DstPorts: []uint32{20000, 20001, 20002, 20003}, TranslateIp: "10.0.0.5", PoolName: "dp1"},
		}},
	}
	c := &ctl{client: client}
	out := captureStdout(t, func() {
		if err := c.handleShowNAT([]string{"destination"}); err != nil {
			t.Fatalf("handleShowNAT: %v", err)
		}
	})
	for _, want := range []string{"dst=203.0.113.10/32:80,443", "dst=203.0.113.11/32:20000-20003"} {
		if !strings.Contains(out, want) {
			t.Errorf("#15226: destination view missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dst=203.0.113.10/32:80 ") || strings.Contains(out, "dst=203.0.113.10/32:80\n") {
		t.Errorf("#15226: multi-port rule collapsed to first port:\n%s", out)
	}
}
