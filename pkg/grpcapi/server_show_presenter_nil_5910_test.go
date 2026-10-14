// #5910: three read-only presenters OUTSIDE session scope carried the SAME
// present-but-nil InterfaceConfig/InterfaceUnit nil-deref class as #5813 that
// the #5068 pass missed:
//   - showVLANs (this file): a raw `range cfg.Interfaces.Interfaces` +
//     `range ifc.Units` walk with no nil guards.
//   - showZonesDetail (this file): `ifc, ok := cfg.Interfaces.Interfaces[name]`
//     then `range ifc.Units` — `ok` proves KEY presence, not a non-nil value,
//     so a present-but-nil InterfaceConfig still nil-derefs.
//
// Both now walk via config.RangeInterfaces / config.RangeUnits (the shared
// nil-safe iterators added for #5813). The tolerant load / HA config-sync path
// admits present-but-nil map values (#3494/#5068), so a routine `show vlans` /
// `show security zones detail` against a peer-synced config panicked the
// in-process daemon.
//
// FAIL-ON-REVERT: restoring a raw `range ifc.Units` (or dropping the RangeUnits
// unit-guard) makes the injected nil slot deref and panic; the recover turns
// that into a test FAILURE rather than a silent pass.
package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// require5910NoPanic fails the test (rather than crashing the run) if fn panics,
// naming the #5910 nil-guard regression.
func require5910NoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked (nil-guard regression #5910): %v", name, r)
		}
	}()
	fn()
}

// TestShowVLANsNilSlots5910 drives the REAL showVLANs presenter (receiver
// unused) against a tolerant config carrying a present-but-nil InterfaceConfig
// AND a present-but-nil InterfaceUnit alongside valid units. Dropping the
// RangeUnits unit-guard makes the nil unit's `unit.VlanID` deref panic. The
// valid siblings still render; the nil slots contribute nothing.
func TestShowVLANsNilSlots5910(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},              // access unit (renders because VlanTagging)
			50: {Number: 50, VlanID: 50}, // tagged subinterface
			7:  nil,                      // present-but-nil unit (tolerant path)
		}},
		"zz-nil-ifc": nil, // present-but-nil InterfaceConfig (tolerant path)
	}

	var buf strings.Builder
	require5910NoPanic(t, "showVLANs", func() {
		(&Server{}).showVLANs(cfg, &buf)
	})
	out := buf.String()
	if !strings.Contains(out, "ge-0/0/0") {
		t.Fatalf("valid interface dropped from VLAN table:\n%s", out)
	}
	if !strings.Contains(out, "50") {
		t.Fatalf("valid tagged unit 50 missing from VLAN table:\n%s", out)
	}
	if strings.Contains(out, "zz-nil-ifc") {
		t.Fatalf("present-but-nil InterfaceConfig leaked into VLAN table:\n%s", out)
	}
}

// zoneIfaceGRPCStore commits a config binding ge-0/0/0.0 to zone trust so the
// showZonesDetail interface-detail loop runs and resolves the bound name. The
// renderer resolves the member's BASE name (#12898/#5325) before the lookup,
// so the nil slots are injected under the "ge-0/0/0" key.
func zoneIfaceGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone untrust`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatalf("fixture missing active config")
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || len(z.Interfaces) == 0 {
		t.Fatalf("fixture zone trust missing interface binding: %+v", z)
	}
	return store
}

// TestShowZonesDetailNilIfaceSlots5910 drives the REAL showZonesDetail renderer
// (dp nil: counters skipped) against a zone that binds lo.0, with a nil
// InterfaceConfig / nil InterfaceUnit injected under the looked-up key. Without
// the guards a present-but-nil slot nil-derefs (`range ifc.Units` /
// `unit.Addresses`).
func TestShowZonesDetailNilIfaceSlots5910(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(cfg *config.Config)
		wantAddress bool
	}{
		{"nil-interface-config", func(cfg *config.Config) {
			// The renderer looks up the member's BASE ("ge-0/0/0"), so inject
			// the present-but-nil stanza under exactly that key (#12898);
			// LookupInterface treats it as absent, no deref.
			cfg.Interfaces.Interfaces["ge-0/0/0"] = nil
		}, false},
		{"nil-interface-unit", func(cfg *config.Config) {
			// Same key form on the unit side: a valid unit 0 the renderer
			// must show, alongside a present-but-nil unit 7 it must skip.
			cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0] =
				&config.InterfaceUnit{Number: 0, Addresses: []string{"127.0.0.1/8"}}
			cfg.Interfaces.Interfaces["ge-0/0/0"].Units[7] = nil
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := zoneIfaceGRPCStore(t)
			cfg := store.ActiveConfig()
			tc.mutate(cfg)
			s := &Server{store: store} // dp nil: skip counters, run interface detail
			var buf strings.Builder
			require5910NoPanic(t, "showZonesDetail "+tc.name, func() {
				s.showZonesDetail(cfg, "", &buf)
			})
			if tc.wantAddress && !strings.Contains(buf.String(), "127.0.0.1/8") {
				t.Fatalf("valid unit address dropped by nil-unit skip:\n%s", buf.String())
			}
		})
	}
}
