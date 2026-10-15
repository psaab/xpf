package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compile13147(t *testing.T, cmds []string, lenient bool) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	var cfg *config.Config
	var err error
	if lenient {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func assignIfindexes13147(snaps []InterfaceSnapshot) {
	for i := range snaps {
		snaps[i].Ifindex = 10 + i
	}
}

// #13147 (D3-01): disabled, unzoned and quarantined tunnel endpoints must
// fail closed on every surface.
func TestTunnelEndpointsDisabledUnzonedQuarantine13147(t *testing.T) {
	// (1a) Disabled GRE tunnel must not be emitted.
	cfgGRE := compile13147(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces gr-0/0/0 disable",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces gr-0/0/0 unit 0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 192.0.2.2",
		"set security zones security-zone wan interfaces ge-0/0/0.0",
		"set security zones security-zone vpn interfaces gr-0/0/0.0",
	}, false)
	snaps := buildInterfaceSnapshots(cfgGRE)
	assignIfindexes13147(snaps)
	if eps := buildTunnelEndpointSnapshots(cfgGRE, snaps); len(eps) != 0 {
		t.Fatalf("disabled GRE tunnel emitted: %+v", eps)
	}

	// (1b) Disabled WG tunnel must not be emitted nor admitted.
	cfgDis := compile13147(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces wg0 disable",
		"set interfaces wg0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces wg0 unit 0 tunnel mode wireguard",
		"set interfaces wg0 unit 0 tunnel source 192.0.2.1",
		"set interfaces wg0 unit 0 tunnel wireguard listen-port 51820",
		"set security zones security-zone wan interfaces ge-0/0/0.0",
		"set security zones security-zone vpn interfaces wg0.0",
	}, true)
	snaps = buildInterfaceSnapshots(cfgDis)
	assignIfindexes13147(snaps)
	eps := buildTunnelEndpointSnapshots(cfgDis, snaps)
	if len(eps) != 0 {
		t.Fatalf("disabled WG tunnel emitted: %+v", eps)
	}
	_, steered, _ := config.SplitSteeredPorts(config.SteeredWireGuardListenPorts(cfgDis))
	snap := &ConfigSnapshot{Config: cfgDis, Zones: buildZoneSnapshots(cfgDis), Interfaces: snaps, TunnelEndpoints: eps, WgSteeredListenPorts: steered, ZoneSetValidated: true}
	plan, err := buildUserspaceWGZoneMaps(snap)
	if err != nil {
		t.Fatalf("buildUserspaceWGZoneMaps: %v", err)
	}
	if len(plan.admission) != 0 {
		t.Fatalf("disabled WG tunnel admitted: %v", plan.admission)
	}

	// (2) Unzoned WG endpoint (Zone=="") must not be admitted even when its
	// source address is owned by a zoned interface.
	unzoned := wgAdmissionTestSnapshot("wan", "")
	if plan, err := buildUserspaceWGZoneMaps(unzoned); err != nil || len(plan.admission) != 0 {
		t.Fatalf("unzoned WG endpoint admitted: plan=%v err=%v", plan.admission, err)
	}

	// (3) quarantineCollidingZones must scrub TunnelEndpoints zones.
	raw := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "z174", ID: config.StableZoneID("z174")},
			{Name: "z214", ID: config.StableZoneID("z214")},
		},
		Interfaces:      []InterfaceSnapshot{{Name: "wg0.0", Zone: "z214"}},
		TunnelEndpoints: []TunnelEndpointSnapshot{{Interface: "wg0.0", Zone: "z214", Mode: "wireguard", WgListenPort: 51820}},
	}
	quarantineCollidingZones(raw)
	if raw.TunnelEndpoints[0].Zone != "" {
		t.Fatalf("quarantined tunnel zone not scrubbed: %q", raw.TunnelEndpoints[0].Zone)
	}
	// Positive control: enabled zoned tunnel still emitted/admitted.
	zoned := wgAdmissionTestSnapshot("wan", "lan")
	if plan, err := buildUserspaceWGZoneMaps(zoned); err != nil || len(plan.admission) == 0 {
		t.Fatalf("zoned WG endpoint should be admitted: plan=%v err=%v", plan.admission, err)
	}
}
