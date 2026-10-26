package userspace

import (
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snapshotZoneNetdevs recomputes the per-zone iifname netdev scope from the
// interface SNAPSHOT (the pre-F1 authority) using the SAME claim-counting the
// config SSOT (config.JunosHostZoneIngressNetdevs) now owns. It exists only to
// pin the two resolutions byte-for-byte so the #4146 iifname enforcement scope
// (config-computed) cannot drift from what the dataplane snapshot would produce.
func snapshotZoneNetdevs(cfg *config.Config) map[string][]string {
	snaps := buildInterfaceSnapshots(cfg)
	lifelines := hostInboundLifelineSet(cfg)
	cand := map[string]map[string]bool{}
	claims := map[string]map[string]bool{}
	addCand := func(zone, nd string) {
		if zone == "" || nd == "" {
			return
		}
		if cand[zone] == nil {
			cand[zone] = map[string]bool{}
		}
		cand[zone][nd] = true
		if claims[nd] == nil {
			claims[nd] = map[string]bool{}
		}
		claims[nd][zone] = true
	}
	for _, s := range snaps {
		if s.Zone == "" || hostInboundLifelineInterface(s.Name, lifelines) {
			continue
		}
		addCand(s.Zone, s.LinuxName)
		if s.VLANID != 0 && s.ParentLinuxName != "" {
			addCand(s.Zone, s.ParentLinuxName)
		}
	}
	out := map[string][]string{}
	for zone, nds := range cand {
		var keep []string
		for nd := range nds {
			if len(claims[nd]) == 1 {
				keep = append(keep, nd)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			out[zone] = keep
		}
	}
	return out
}

// TestJunosHostZoneNetdevsMatchSnapshot pins config.JunosHostZoneIngressNetdevs
// (the #4146 iifname SSOT the F1 fix routes BOTH the kernel emission and the
// #4168 warning through) to the dataplane interface-snapshot resolution, across
// representative topologies including the cross-zone-ambiguous trunk. Any drift
// in the ported snapshotLinuxName / buildInterfaceZoneMap logic fails this
// (guarding the enforcement iifname scope, which the smoke exercised as
// ge-0-0-1).
func TestJunosHostZoneNetdevsMatchSnapshot(t *testing.T) {
	cases := map[string]*config.Config{
		"physical + reth + vlan": func() *config.Config {
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.1.1/24"}}}},
				"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
					50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
					80: {Number: 80, VlanID: 80, Addresses: []string{"172.16.80.8/24"}}}},
				"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.61.1/24"}}}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
				"wan":   {Name: "wan", Interfaces: []string{"reth0.50", "reth0.80"}},
				"lan":   {Name: "lan", Interfaces: []string{"reth1"}},
			}
			return cfg
		}(),
		// #6691: the parity corpus had no secure tunnel, which is how the
		// junos-host iifname scope came to name a netdev the snapshot no
		// longer used. Both spellings are here because they are the pair that
		// diverges: `bind-interface st0.0` and `bind-interface st0` describe
		// the SAME unit ref `st0.0` under DIFFERENT device names, so a
		// resolver that reconstructs the name from the ref gets exactly one of
		// them right.
		"secure tunnel (dotted bind-interface)": func() *config.Config {
			return secureTunnelParityConfig("st0.0")
		}(),
		"secure tunnel (bare bind-interface)": func() *config.Config {
			return secureTunnelParityConfig("st0")
		}(),
		"cross-zone-ambiguous trunk": func() *config.Config {
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, Addresses: []string{"10.0.9.1/24"}},
					50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}},
					80: {Number: 80, VlanID: 80, Addresses: []string{"10.0.80.1/24"}}}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trunkzero": {Name: "trunkzero", Interfaces: []string{"ge-0/0/2.0"}},
				"vlanb":     {Name: "vlanb", Interfaces: []string{"ge-0/0/2.50"}},
				"vlanc":     {Name: "vlanc", Interfaces: []string{"ge-0/0/2.80"}},
			}
			return cfg
		}(),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			want := snapshotZoneNetdevs(cfg)
			got := config.JunosHostZoneIngressNetdevs(cfg)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("config netdev SSOT diverged from snapshot:\n  config=%v\n  snap  =%v", got, want)
			}
		})
	}
}

// secureTunnelParityConfig builds a LAN plus a bind-only route-based VPN whose
// tunnel unit `st0.0` is in zone `vpn`, with the bind-interface authored exactly
// as given. No `interfaces st0` stanza is present: only the device named by
// bind-interface exists, so the fixture cannot invent a bare `st0` netdev.
// The two spellings derive the SAME if_id and unit ref but DIFFERENT kernel
// device names — that asymmetry is the point.
func secureTunnelParityConfig(bindIface string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.1/24"}}}},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"v": {Name: "v", BindInterface: bindIface},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
		"vpn":   {Name: "vpn", Interfaces: []string{"st0.0"}},
	}
	return cfg
}

// TestJunosHostDenyScopeNamesTheSecureTunnelDevice is the #6691 MAJOR guard,
// and it asserts an ABSOLUTE name rather than parity.
//
// A `from-zone vpn to-zone junos-host ... then deny` is rendered as an nft rule
// scoped by `iifname` (daemon_nft.go), and the names come from this SSOT. Route-
// based IPsec decrypts in the kernel XFRM stack and delivers the plaintext on
// the xfrmi netdev — which for `bind-interface st0.0` is literally named
// `st0.0`. If the SSOT emits `st0` instead, the rule is scoped to a device that
// exists on no box, the iifname never matches, and the deny CANNOT FIRE. A
// security guard silently unable to fire is worse than an absent one, because
// `show` reports it configured.
//
// Parity with the snapshot is necessary but NOT sufficient here: both planes
// collapsing `st0.0` onto `st0` agree perfectly and are both wrong — which is
// exactly the state before #5619. So this pins the name itself, derived from
// XFRMIfNameAndID (the constructor the xfrmi reconciler uses) rather than
// hardcoded.
//
// It is also a DIFFERENTIAL across the two spellings, because "contains the
// right name" alone can be satisfied by emitting both names. `st0.0` must
// appear in the scope for `bind-interface st0.0` and must NOT appear for
// `bind-interface st0`, where no such device is created.
//
// (`st0` appears in the scope under BOTH spellings. That is the BASE interface
// row — `set interfaces st0` itself, unit-less — which resolves to `st0` by
// design on both planes; see snapshotLinuxName's "Only the UNIT path resolves
// this way". Under `bind-interface st0.0` it names no device, so the iifname
// simply never matches: an over-narrow scope, never an over-broad one. It is
// pre-existing and out of this fix's scope.)
func TestJunosHostDenyScopeNamesTheSecureTunnelDevice(t *testing.T) {
	const unitDev = "st0.0" // the device created ONLY by `bind-interface st0.0`
	for _, tc := range []struct {
		bindIface   string
		wantUnitDev bool
	}{
		{bindIface: "st0.0", wantUnitDev: true},
		{bindIface: "st0", wantUnitDev: false},
	} {
		t.Run(tc.bindIface, func(t *testing.T) {
			cfg := secureTunnelParityConfig(tc.bindIface)

			wantDev, ifID := config.XFRMIfNameAndID(tc.bindIface)
			if ifID == 0 || wantDev == "" {
				t.Fatalf("premise broken: bind-interface %q creates no xfrmi", tc.bindIface)
			}
			if (wantDev == unitDev) != tc.wantUnitDev {
				t.Fatalf("premise broken: bind-interface %q creates device %q, which does "+
					"not match this row's expectation about %q", tc.bindIface, wantDev, unitDev)
			}

			got := config.JunosHostZoneIngressNetdevs(cfg)["vpn"]
			if !slices.Contains(got, wantDev) {
				t.Errorf("junos-host iifname scope for zone vpn = %v, missing %q — with "+
					"`bind-interface %s` the decrypted plaintext arrives on %q, so a deny "+
					"scoped to anything else never matches and CANNOT FIRE",
					got, wantDev, tc.bindIface, wantDev)
			}
			if has := slices.Contains(got, unitDev); has != tc.wantUnitDev {
				t.Errorf("junos-host iifname scope for zone vpn = %v: contains %q = %v, "+
					"want %v under `bind-interface %s` — the two spellings create DIFFERENT "+
					"devices, so the scope must discriminate between them",
					got, unitDev, has, tc.wantUnitDev, tc.bindIface)
			}
		})
	}
}
