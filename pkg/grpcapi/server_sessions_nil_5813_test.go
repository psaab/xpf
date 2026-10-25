// #5813: the gRPC session filter builder (buildSessionFilter) walked
// cfg.Interfaces.Interfaces and ifc.Units with no nil guard — the same class as
// the CLI session-display builder. The tolerant load / HA config-sync path
// admits present-but-nil InterfaceConfig and InterfaceUnit map values
// (#3494/#5068), so a remote GetSessions/ClearSessions against a peer-synced
// config nil-dereferenced and panicked the in-process daemon. The builder now
// walks via config.RangeInterfaces / config.RangeUnits.
//
// FAIL-ON-REVERT: the nil slots sit on the loopback, so the production
// net.InterfaceByName lookup resolves and reaches the nil-deref site; reverting
// either guard (config.RangeInterfaces / config.RangeUnits) panics the matching
// sub-case.
package grpcapi

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// nilGuardSessionDP is a loaded dataplane exposing a non-nil ApplyResult, so
// Server.applyResult() is non-nil and buildSessionFilter runs its interface
// walk (gated on cr != nil).
type nilGuardSessionDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *nilGuardSessionDP) IsLoaded() bool                          { return true }
func (d *nilGuardSessionDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }

func require5813NoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked (nil-guard regression #5813): %v", name, r)
		}
	}()
	fn()
}

func TestBuildSessionFilterNilSlots5813(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	cases := []struct {
		name        string
		mutate      func(cfg *config.Config)
		wantLoEntry bool
	}{
		{"nil-interface-config", func(cfg *config.Config) {
			cfg.Interfaces.Interfaces["lo"] = nil
		}, false},
		{"nil-interface-unit", func(cfg *config.Config) {
			cfg.Interfaces.Interfaces["lo"].Units[7] = nil // alongside real unit 0
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newLoopbackZoneStore(t)
			cfg := store.ActiveConfig()
			if cfg == nil || cfg.Interfaces.Interfaces["lo"] == nil {
				t.Fatalf("fixture missing loopback interface")
			}
			tc.mutate(cfg)
			s := &Server{
				store: store,
				dp: &nilGuardSessionDP{
					Manager: dataplane.New(),
					result:  &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1}},
				},
			}
			var f *sessionFilter
			require5813NoPanic(t, "buildSessionFilter "+tc.name, func() {
				f = s.buildSessionFilter(&pb.GetSessionsRequest{})
			})
			if tc.wantLoEntry && len(f.egressIfaces) == 0 {
				t.Fatalf("nil-unit case: valid lo unit produced no egress entry: %v", f.egressIfaces)
			}
		})
	}
}
