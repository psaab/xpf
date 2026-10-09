package config

import (
	"reflect"
	"strings"
	"testing"
)

// #12087: a routing-instance member `st<N>.0` must resolve to the xfrmi netdev
// the IPsec reconciler actually creates — the AUTHORED bind-interface string —
// not to the unit-zero collapse `st<N>`. Before the fix,
// routingInstanceMemberLinuxName never consulted SecureTunnelUnitNetdev, so a
// member `st0.0` with `bind-interface st0.0` resolved to `st0`, the VRF bind
// warned "interface st0 not found", and the commit still succeeded.
func TestRIMemberSecureTunnelUnitResolvesAuthoredNetdev12087(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		// member is the RI interface-list spelling under test.
		member string
		// want is the single expected Linux device from
		// RoutingInstanceMemberLinuxNames, pinned against the name the
		// xfrmi reconciler creates (XFRMIfNameAndID of the bind).
		want string
	}{
		{
			name:   "explicit unit-zero bind keeps its dot",
			bind:   "st0.0",
			member: "st0.0",
			want:   "st0.0",
		},
		{
			name:   "bare bind resolves the unit ref to the bare netdev",
			bind:   "st0",
			member: "st0.0",
			want:   "st0",
		},
		{
			name:   "nonzero unit keeps its authored spelling",
			bind:   "st0.1",
			member: "st0.1",
			want:   "st0.1",
		},
		{
			name:   "second tunnel index keeps its authored spelling",
			bind:   "st1.0",
			member: "st1.0",
			want:   "st1.0",
		},
		{
			name:   "unbound in-range unit keeps the old collapse reading",
			bind:   "st9.0",
			member: "st0.0",
			want:   "st0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Security.IPsec.VPNs = map[string]*IPsecVPN{
				"vpn0": {Name: "vpn0", BindInterface: tc.bind},
			}
			if tc.bind != "st9.0" {
				if name, _ := XFRMIfNameAndID(tc.bind); name != tc.want {
					t.Fatalf("premise broken: XFRMIfNameAndID(%q) creates %q, want the asserted %q",
						tc.bind, name, tc.want)
				}
			}
			got := RoutingInstanceMemberLinuxNames(cfg, cfg.TunnelNameMap(), tc.member)
			if !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("RoutingInstanceMemberLinuxNames(%q) with bind %q = %q, want [%q]",
					tc.member, tc.bind, got, tc.want)
			}
		})
	}
}

func TestRIBareSecureTunnelUnitDualClaim11060(t *testing.T) {
	base := []string{
		"set interfaces st0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces st0 unit 1 family inet address 198.51.100.1/24",
		"set security ipsec vpn V bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.0",
	}
	conflictLines := append(append([]string{}, base...),
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface st0",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface st0.0",
	)

	t.Run("strict gate rejects bare versus explicit owner", func(t *testing.T) {
		_, err := CompileConfig(buildTree(t, conflictLines))
		if err == nil {
			t.Fatal("strict compile accepted bare st0 and explicit st0.0 ownership")
		}
		for _, want := range []string{"st0.0", "blue", "red", "#11060"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("strict conflict error %q does not name %q", err, want)
			}
		}
	})

	t.Run("tolerant path quarantines contested generated unit", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTree(t, conflictLines))
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 {
			t.Fatalf("quarantined conflicts = %+v, want one st0.0 conflict",
				cfg.QuarantinedRIMemberDeviceConflicts)
		}
		conflict := cfg.QuarantinedRIMemberDeviceConflicts[0]
		if conflict.LinuxName != "st0.0" || len(conflict.Claims) != 2 ||
			conflict.Claims[0].Instance != "blue" || conflict.Claims[1].Instance != "red" {
			t.Fatalf("quarantined conflict = %+v, want st0.0 claimed by blue and red", conflict)
		}

		keys := RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), "st0")
		if len(keys) != 3 || keys[0].InterfaceKey != "st0" || keys[0].LinuxName != "st0" ||
			keys[1].InterfaceKey != "st0.0" || keys[1].LinuxName != "st0.0" || !keys[1].Fanout {
			t.Fatalf("bare member keys = %+v, want unchanged primary plus owned generated st0.0", keys)
		}
		if len(cfg.QuarantinedRIMemberPrimaryClaims) != 1 ||
			cfg.QuarantinedRIMemberPrimaryClaims[0].Instance != "blue" ||
			cfg.QuarantinedRIMemberPrimaryClaims[0].InterfaceKey != "st0" ||
			cfg.QuarantinedRIMemberPrimaryClaims[0].LinuxName != "st0" {
			t.Fatalf("uncontested bare primary was not retained: %+v",
				cfg.QuarantinedRIMemberPrimaryClaims)
		}
		keptUnit := false
		for _, ri := range cfg.RoutingInstances {
			if ri.Name == "blue" {
				keptUnit = len(ri.Interfaces) == 1 && ri.Interfaces[0] == "st0.1"
			}
		}
		if !keptUnit {
			t.Fatalf("uncontested generated st0.1 unit was not retained: %+v", cfg.RoutingInstances)
		}
		for _, ri := range cfg.RoutingInstances {
			if ri.Name == "red" && len(ri.Interfaces) != 0 {
				t.Fatalf("contested explicit member remained in red: %v", ri.Interfaces)
			}
		}
	})

	t.Run("distinct explicit units remain independently owned", func(t *testing.T) {
		lines := append(append([]string{}, base...),
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances blue interface st0.0",
			"set routing-instances red instance-type virtual-router",
			"set routing-instances red interface st0.1",
		)
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("strict compile rejected distinct st0 units: %v", err)
		}
	})
}

func TestRIBareSecureTunnelUnitKeepsTunnelFallback12087(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		want string
	}{
		{name: "owned xfrmi precedes unit tunnel", bind: "st0.0", want: "st0.0"},
		{name: "unowned unit retains tunnel fallback", bind: "st9.0", want: "gre0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Security.IPsec.VPNs = map[string]*IPsecVPN{
				"vpn0": {Name: "vpn0", BindInterface: tc.bind},
			}
			cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
				"st0": {Name: "st0", Units: map[int]*InterfaceUnit{
					0: {Number: 0, Tunnel: &TunnelConfig{Name: "gre0"}},
				}},
			}
			keys := RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), "st0")
			if len(keys) != 2 || keys[1].LinuxName != tc.want {
				t.Fatalf("bare st0 generated keys = %+v, want unit 0 on %q", keys, tc.want)
			}
		})
	}
}
