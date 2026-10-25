package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16556: GetZones and the gRPC text zones renderer must name a member
// claimed by two zones as bound to NEITHER, via the shared
// ZoneInterfaceQuarantine verdict. Control member stays plain.

func unboundZonesServer16556(t *testing.T) (*Server, *config.Config) {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone trust { interfaces [ ge-0/0/0.0 ge-0/0/1.0 ]; }
        security-zone untrust { interfaces [ ge-0/0/0.0 ]; }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse() errors = %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	store.SetCompiledForTesting(cfg)
	return &Server{store: store}, cfg
}

func TestGetZonesUnboundInterfaces16556(t *testing.T) {
	s, _ := unboundZonesServer16556(t)
	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones: %v", err)
	}
	for _, name := range []string{"trust", "untrust"} {
		zone := getGRPCZone(t, resp, name)
		found := false
		for _, unbound := range zone.UnboundInterfaces {
			if unbound == "ge-0/0/0.0" {
				found = true
			}
			if unbound == "ge-0/0/1.0" {
				t.Fatalf("%s marks control member unbound: %v", name, zone.UnboundInterfaces)
			}
		}
		if !found {
			t.Fatalf("%s UnboundInterfaces = %v, want ge-0/0/0.0", name, zone.UnboundInterfaces)
		}
	}

	// gRPC text: annotated under both zones.
	var buf strings.Builder
	s.showZonesDetail(s.store.ActiveConfig(), "", &buf)
	out := buf.String()
	annotated := "ge-0/0/0.0 [UNBOUND — claimed by zones trust and untrust]"
	if n := strings.Count(out, annotated); n < 2 {
		t.Fatalf("text annotated count = %d, want >=2:\n%s", n, out)
	}
	if strings.Contains(out, "ge-0/0/1.0 [UNBOUND") {
		t.Fatalf("control member annotated in text:\n%s", out)
	}
}
