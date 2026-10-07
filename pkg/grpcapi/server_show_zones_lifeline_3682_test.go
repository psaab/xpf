package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3682: the structured GetZones RPC must surface the management/cluster-control
// LIFELINE interfaces that are EXCLUDED from a zone's host-inbound deny scoping,
// so the remote CLI and automation can render the (otherwise invisible) implicit
// exemption. This is the fail-on-revert guard for the wire propagation: dropping
// the zi.LifelineInterfaces population in server_show_zones.go turns it RED.
func lifelineZonesGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    em0 { unit 0 { family inet { address 10.0.99.1/24; } } }
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
chassis {
    cluster {
        control-interface em0;
        authentication-key "xpf-test-cluster-authentication-key-1234567890";
    }
}
security {
    zones {
        security-zone mgmt {
            host-inbound-traffic {
                system-services {
                    ssh;
                }
            }
            interfaces {
                em0.0;
                ge-0/0/0.0;
            }
        }
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestGetZonesSurfacesLifelineExemption3682(t *testing.T) {
	s := &Server{store: lifelineZonesGRPCStore(t)}

	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones() error = %v", err)
	}
	byName := map[string]*pb.ZoneInfo{}
	for _, z := range resp.GetZones() {
		byName[z.GetName()] = z
	}

	mgmt, ok := byName["mgmt"]
	if !ok {
		t.Fatal("mgmt zone missing from gRPC inventory")
	}
	got := mgmt.GetLifelineInterfaces()
	if len(got) != 1 || got[0] != "em0.0" {
		t.Fatalf("mgmt lifeline_interfaces = %v, want [em0.0] (the data interface ge-0/0/0.0 is NOT a lifeline)", got)
	}

	// A zone with only data interfaces exposes no lifeline exemption.
	trust, ok := byName["trust"]
	if !ok {
		t.Fatal("trust zone missing")
	}
	if got := trust.GetLifelineInterfaces(); len(got) != 0 {
		t.Fatalf("trust lifeline_interfaces = %v, want none", got)
	}
}
