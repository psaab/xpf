package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3493: the local CLI zone display, zone-name completion, screen reverse-map,
// and session/flow-filter surfaces iterate cfg.Security.Zones
// (map[string]*ZoneConfig) and dereference the value. A nil map VALUE is
// reachable on the tolerant / HA-sync config path (#3474/#3476 premise) and the
// runtime walker (pkg/dataplane/userspace/zones.go) already skips it. These
// tests inject a nil zone value and drive each surface; reverting any of the
// cli_show_security_zones.go / completion.go / cli_show_security_screen.go /
// session_filter.go `if zone == nil { continue }` guards makes the matching
// subtest panic (RED on revert). Distinct from #3476 (nil zone-pair/rule/screen).

// nilZoneApplyCLIDP returns a fixed ApplyResult so the cr-gated zone loops
// (populateIfaceMaps) run with the nil zone present in ZoneIDs, so the
// `ok && len(zone.Interfaces)` deref is reached on revert.
type nilZoneApplyCLIDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *nilZoneApplyCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func nilZoneValueCLIStore(t *testing.T) *configstore.Store {
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

func TestCLIZoneDisplayNilZoneNoPanic(t *testing.T) {
	store := nilZoneValueCLIStore(t)
	c := &CLI{store: store} // dp nil: skip counters, exercise the zone-value walk
	cfg := store.ActiveConfig()
	captureStdout(t, func() {
		// cli_show_security_zones.go: indexed zone := cfg.Security.Zones[name].
		if err := c.showZonesDisplay(cfg, false, ""); err != nil {
			t.Fatalf("showZonesDisplay(brief): %v", err)
		}
		if err := c.showZonesDisplay(cfg, true, ""); err != nil {
			t.Fatalf("showZonesDisplay(detail): %v", err)
		}
		// cli_show_security_screen.go: zone-value reverse map.
		if err := c.handleShowScreen(nil); err != nil {
			t.Fatalf("handleShowScreen: %v", err)
		}
	})
	// completion.go valueProvider(ValueHintZoneName): ranges zone values.
	_ = c.valueProvider(config.ValueHintZoneName, nil)
}

func TestCLISessionFilterNilZoneNoPanic(t *testing.T) {
	store := nilZoneValueCLIStore(t)
	c := &CLI{
		store: store,
		dp: &nilZoneApplyCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
				"trust": 1, "untrust": 2, "zz-nil-zone": 9,
			}},
		},
	}
	f := &sessionFilter{cfg: store.ActiveConfig()}
	f.populateIfaceMaps(c) // session_filter.go cited site
}
