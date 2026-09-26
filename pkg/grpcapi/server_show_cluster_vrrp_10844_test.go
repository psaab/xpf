package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #10844: ShowText must identify the per-group detail as configuration when
// the configured VRRP group is not master. The live per-RG aggregate says
// vrrp-master=none; the config detail answers which configured VIP group that
// aggregate does not identify.
func TestShowTextClusterStatusLabelsConfiguredNonMasterVRRP10844(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 7 {
                        virtual-address 10.0.61.254/24;
                        priority 200;
                    }
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0-0-0.0;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	manager := cluster.NewManager(0, 1)
	manager.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{
			ID:             7,
			NodePriorities: map[int]int{0: 200, 1: 100},
		}},
	})
	manager.SetRGForwardingFunc(func(rgID int) (cluster.RGForwarding, bool) {
		return cluster.RGForwarding{}, rgID == 7
	})
	s := &Server{store: store, cluster: manager}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "chassis-cluster-status"})
	if err != nil {
		t.Fatalf("ShowText(chassis-cluster-status): %v", err)
	}
	for _, want := range []string{
		"vrrp-master=none",
		"VRRP on ge-0-0-0.0: configured: group 7, priority 200, VIP 10.0.61.254/24",
	} {
		if !strings.Contains(resp.GetOutput(), want) {
			t.Fatalf("configured non-master VRRP detail missing %q:\n%s", want, resp.GetOutput())
		}
	}
}
