package userspace

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAuthoredZoneRefsDeclaredDotted9821: the authored-ref map fans a
// declared-dotted bare member down like the zone map — but keeps its
// deliberate fan-UP exclusion (a unit ref binds exactly that unit, never
// the base). Compare against InterfaceZoneMap modulo that ONE documented
// difference (levelling them would be consistency in the wrong direction).
func TestAuthoredZoneRefsDeclaredDotted9821(t *testing.T) {
	newCfg := func(member string) *config.Config {
		return &config.Config{
			Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/5.0": {
					Name: "ge-0/0/5.0",
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0},
						1: {Number: 1},
					},
				},
			}},
			Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
				"z": {Interfaces: []string{member}},
			}},
		}
	}
	keys := func(m map[string]string) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	// Bare declared-dotted: full fan-down, identical to the zone map.
	cfg := newCfg("ge-0/0/5.0")
	want := []string{"ge-0/0/5.0", "ge-0/0/5.0.0", "ge-0/0/5.0.1"}
	if got := keys(authoredZoneRefs(cfg)); !reflect.DeepEqual(got, want) {
		t.Errorf("authoredZoneRefs(bare) = %q, want %q", got, want)
	}
	if got := keys(config.InterfaceZoneMap(cfg)); !reflect.DeepEqual(got, want) {
		t.Errorf("InterfaceZoneMap(bare) = %q, want %q", got, want)
	}

	// Unit ref: authored binds the unit ONLY (no fan-up); the zone map
	// additionally binds the base. The delta between the two maps is
	// exactly that one deliberate key.
	cfg = newCfg("ge-0/0/5.0.1")
	if got, want := keys(authoredZoneRefs(cfg)), []string{"ge-0/0/5.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("authoredZoneRefs(unit) = %q, want %q", got, want)
	}
	if got, want := keys(config.InterfaceZoneMap(cfg)), []string{"ge-0/0/5.0", "ge-0/0/5.0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("InterfaceZoneMap(unit) = %q, want %q", got, want)
	}

	// Padded spelling normalizes onto the canonical unit in both maps.
	cfg = newCfg("ge-0/0/5.0.01")
	if got := authoredZoneRefs(cfg); got["ge-0/0/5.0.1"] != "z" || len(got) != 1 {
		t.Errorf("authoredZoneRefs(padded) = %q, want exactly {ge-0/0/5.0.1: z}", got)
	}
}

// TestSnapshotStampsDottedOverride9821: a per-interface override authored on
// a declared-dotted base reaches the per-unit snapshot rows' effective sets
// (the override REPLACES the zone set, #6515). Struct-built config: strict
// admission still rejects single-declared dotted ZONE members, so this pins
// the runtime stamping the lenient path enforces.
func TestSnapshotStampsDottedOverride9821(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"p.0": {
				Name: "p.0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
					1: {Number: 1, Addresses: []string{"10.0.1.1/24"}},
				},
			},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				HostInboundTraffic: &config.HostInboundTraffic{
					SystemServices: []string{"ping"},
				},
				InterfaceHostInbound: map[string]*config.HostInboundTraffic{
					"p.0": {SystemServices: []string{"ssh"}},
				},
			},
		}},
	}
	snaps := buildInterfaceSnapshots(cfg)
	byName := make(map[string]InterfaceSnapshot, len(snaps))
	for _, s := range snaps {
		byName[s.Name] = s
	}
	for _, name := range []string{"p.0.0", "p.0.1"} {
		snap, ok := byName[name]
		if !ok {
			t.Fatalf("no snapshot row %q (have %v)", name, byName)
		}
		if !snap.HostInboundConfigured {
			t.Errorf("row %q carries no override stamp", name)
			continue
		}
		if got, want := snap.HostInboundSystemServices, []string{"ssh"}; !reflect.DeepEqual(got, want) {
			t.Errorf("row %q services = %q, want %q (override must replace zone ping)", name, got, want)
		}
	}
}
