package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12530, bound at the tolerant ingresses (#1960). A group that packs an
// unmodelled tail on the interface, one level above an inline unit, committed
// clean on master because the inline-wins override dropped the tail, so boxes
// can carry it. The first version of the fix appended the tail beside the
// inline unit as a second `unit 0`. The compiler keeps the later unit, so
// Store.Load and SyncApply booted ge-0/0/0.0 with no address and no input
// filter. Both ingresses must keep the inline unit whole, and still warn for
// tails a post-expansion gate rejects.

func packedTailPersisted12530(tail string) string {
	return `groups { g { interfaces { ge-0/0/0 unit 0 ` + tail + `; } } }
apply-groups g;
interfaces { ge-0/0/0 { unit 0 { family inet { filter { input protect; } address 10.0.0.1/24; } } } }
firewall { family inet { filter protect { term t { then accept; } } filter f { term t { then accept; } } } }`
}

var packedTails12530 = []struct{ tail, warn string }{
	{"family mpls", ""},
	{"family iso", ""},
	{"frobnicate 7", ""},
	{"filter input f", "#12090"},
	{"mac 00:11:22:33:44:55", "#2008 H10"},
}

func assertInlineUnitKept12530(t *testing.T, cfg *config.Config, warn string) {
	t.Helper()
	var unit *config.InterfaceUnit
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc != nil {
		unit = ifc.Units[0]
	}
	if unit == nil || len(unit.Addresses) != 1 || unit.Addresses[0] != "10.0.0.1/24" || unit.FilterInputV4 != "protect" {
		t.Fatalf("ge-0/0/0.0 = %+v; want address 10.0.0.1/24 and input filter protect", unit)
	}
	if warn != "" && !strings.Contains(strings.Join(cfg.Warnings, "\n"), warn) {
		t.Fatalf("warnings = %q; want a %s warning for the packed tail", cfg.Warnings, warn)
	}
}

func TestLoadKeepsInlineUnitBesidePackedGroupTail12530(t *testing.T) {
	for _, tc := range packedTails12530 {
		t.Run(tc.tail, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			tree, errs := config.NewParser(packedTailPersisted12530(tc.tail)).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs[0])
			}
			if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
				t.Fatalf("persist: %v", err)
			}
			booted := newTestStoreAt(t, path)
			if err := booted.Load(); err != nil {
				t.Fatalf("Store.Load: %v", err)
			}
			cfg := booted.ActiveConfig()
			if cfg == nil {
				t.Fatal("Store.Load left ActiveConfig() nil")
			}
			assertInlineUnitKept12530(t, cfg, tc.warn)
		})
	}
}

func TestSyncApplyKeepsInlineUnitBesidePackedGroupTail12530(t *testing.T) {
	for _, tc := range packedTails12530 {
		t.Run(tc.tail, func(t *testing.T) {
			s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
			cfg, err := s.SyncApply(packedTailPersisted12530(tc.tail), nil)
			if err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			assertInlineUnitKept12530(t, cfg, tc.warn)
		})
	}
}
