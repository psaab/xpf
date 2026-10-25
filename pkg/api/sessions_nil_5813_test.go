// #5813: the REST session view builder (buildSessionView) walked
// cfg.Interfaces.Interfaces and ifc.Units with no nil guard — the same class as
// the CLI and gRPC session builders. The tolerant load / HA config-sync path
// admits present-but-nil InterfaceConfig and InterfaceUnit map values
// (#3494/#5068), so a REST /sessions query against a peer-synced config
// nil-dereferenced and panicked the in-process daemon. The builder now walks
// via config.RangeInterfaces / config.RangeUnits.
//
// FAIL-ON-REVERT: the nil slots sit on the loopback, so the production
// net.InterfaceByName lookup resolves and reaches the nil-deref site; reverting
// either guard panics the matching sub-case.
package api

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// nilGuardRESTDP is a loaded dataplane exposing a non-nil ApplyResult so
// Server.applyResult() is non-nil and buildSessionView runs its interface walk
// (gated on cr != nil).
type nilGuardRESTDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *nilGuardRESTDP) IsLoaded() bool                          { return true }
func (d *nilGuardRESTDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }

// loopbackZoneStoreREST commits a config binding lo.0 to a zone (a resolving
// interface), so an injected nil slot on "lo" reaches the production
// net.InterfaceByName path.
func loopbackZoneStoreREST(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    lo {
        unit 0 {
            family inet;
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces lo.0;
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

func TestBuildSessionViewNilSlots5813(t *testing.T) {
	requireLoopback(t)
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
			store := loopbackZoneStoreREST(t)
			cfg := store.ActiveConfig()
			if cfg == nil || cfg.Interfaces.Interfaces["lo"] == nil {
				t.Fatalf("fixture missing loopback interface")
			}
			tc.mutate(cfg)
			s := &Server{
				store: store,
				dp: &nilGuardRESTDP{
					Manager: dataplane.New(),
					result:  &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1}},
				},
			}
			var v sessionView
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("buildSessionView %s panicked (nil-guard regression #5813): %v", tc.name, r)
					}
				}()
				v = s.buildSessionView()
			}()
			if tc.wantLoEntry && len(v.egressIfaces) == 0 {
				t.Fatalf("nil-unit case: valid lo unit produced no egress entry: %v", v.egressIfaces)
			}
		})
	}
}
