package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type fibDumpProvider11370 struct {
	grpcRuntime
	generation uint32
	routes     []dpuserspace.FibRouteWire
}

func (f *fibDumpProvider11370) DumpFIB() (uint32, []dpuserspace.FibRouteWire, error) {
	return f.generation, f.routes, nil
}

func TestShowRouteFibReadsHelperSnapshot11370(t *testing.T) {
	provider := &fibDumpProvider11370{
		generation: 17,
		routes: []dpuserspace.FibRouteWire{{
			Table: "inet.0", Family: "inet", Destination: "203.0.113.0/24", Kind: "unicast",
			Preference: 25, MTU: 1400,
			NextHops: []dpuserspace.FibNextHopWire{{
				NextHop: "192.0.2.1", Interface: "xe-0/0/0", Weight: 3,
			}},
		}},
	}
	s := &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    provider,
	}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "route-fib"})
	if err != nil {
		t.Fatalf("ShowText(route-fib): %v", err)
	}
	for _, want := range []string{
		"Fast-path FIB (generation 17)", "inet.0", "203.0.113.0/24",
		"192.0.2.1 via xe-0/0/0 weight 3", "25", "1400",
	} {
		if !strings.Contains(resp.GetOutput(), want) {
			t.Errorf("ShowText(route-fib) output lacks %q:\n%s", want, resp.GetOutput())
		}
	}
}
