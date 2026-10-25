package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3493: the gRPC zone/interface inventory, zone-name completion, screen text,
// and session-filter surfaces iterate cfg.Security.Zones (map[string]*ZoneConfig)
// and dereference the value. A nil map VALUE is reachable on the tolerant /
// HA-sync config path (#3474/#3476 premise) and the runtime walker
// (pkg/dataplane/userspace/zones.go) already skips it. These tests inject a nil
// zone value and drive each surface; reverting any of the server_*.go
// `if zone == nil { continue }` (or `ok && z != nil`) guards makes the matching
// subtest panic (RED on revert). Distinct from #3476 (nil zone-pair/rule/screen).

// nilZoneApplyGRPCDP returns a fixed ApplyResult so buildSessionFilter's
// cr-gated zone loop runs (the nil zone is present in ZoneIDs so the
// `ok && len(zone.Interfaces)` deref is actually reached on revert).
type nilZoneApplyGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *nilZoneApplyGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func nilZoneValueGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            screen sp;
        }
        security-zone untrust;
    }
    screen {
        ids-option sp {
            tcp { land; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		t.Fatalf("fixture missing zones")
	}
	cfg.Security.Zones["zz-nil-zone"] = nil
	return store
}

func TestGRPCZoneInventoryNilZoneNoPanic(t *testing.T) {
	s := &Server{
		store: nilZoneValueGRPCStore(t),
		dp: &schedulerCounterGRPCDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
	cfg := s.store.ActiveConfig()

	_ = allInterfaceNames(cfg) // server_helpers.go cited site

	if _, err := s.GetZones(context.Background(), &pb.GetZonesRequest{}); err != nil {
		t.Fatalf("GetZones error = %v", err)
	}
	if _, err := s.GetInterfaces(context.Background(), &pb.GetInterfacesRequest{}); err != nil {
		t.Fatalf("GetInterfaces error = %v", err)
	}

	// Zone-name completion (server_cluster.go valueProvider).
	_ = s.valueProvider(config.ValueHintZoneName, nil)

	// Screen text reverse map (server_show_security_text.go showScreen).
	var buf strings.Builder
	s.showScreen(cfg, &buf)
}

func TestGRPCSessionFilterNilZoneNoPanic(t *testing.T) {
	store := nilZoneValueGRPCStore(t)
	s := &Server{
		store: store,
		dp: &nilZoneApplyGRPCDP{
			Manager: dataplane.New(),
			// Both the real zone and the nil zone are present in ZoneIDs so
			// the `ok && len(zone.Interfaces)` branch is reached for the nil
			// zone — panics on revert of the session_filter zone-nil guard.
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
				"trust": 1, "untrust": 2, "zz-nil-zone": 9,
			}},
		},
	}
	_ = s.buildSessionFilter(&pb.GetSessionsRequest{}) // server_sessions.go cited site
}
