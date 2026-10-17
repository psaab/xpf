package config

import (
	"strings"
	"testing"
)

// #14585: strict commit must reject BGP/OSPF combinations FRR refuses, so a
// commit-check-clean config is always FRR-loadable.

func TestBGPCrossField14585StrictRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want []string
	}{
		{
			name: "per-neighbor local-as equals router AS",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2 local-as 65001",
			},
			want: []string{"192.0.2.2", "local-as", "65001"},
		},
		{
			name: "group local-as equals router AS",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group ext peer-as 65002 local-as 65001",
				"set protocols bgp group ext neighbor 192.0.2.2",
			},
			want: []string{"local-as", "65001"},
		},
		{
			name: "route-reflector-client on eBGP neighbor",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2 route-reflector-client",
			},
			want: []string{"192.0.2.2", "route-reflector-client"},
		},
		{
			name: "remove-private on iBGP neighbor",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group int peer-as 65001",
				"set protocols bgp group int neighbor 192.0.2.3 remove-private",
			},
			want: []string{"192.0.2.3", "remove-private"},
		},
		{
			name: "remove-private at iBGP group level",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group int peer-as 65001 remove-private",
				"set protocols bgp group int neighbor 192.0.2.3",
			},
			want: []string{"remove-private"},
		},
		{
			name: "dampening suppress below reuse",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp damping reuse 750",
				"set protocols bgp damping suppress 500",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2",
			},
			want: []string{"damping", "suppress"},
		},
		{
			name: "dampening suppress equals reuse",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp damping suppress 750",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2",
			},
			want: []string{"damping", "suppress"},
		},
		{
			name: "ospf backbone stub",
			sets: []string{
				"set protocols ospf area 0.0.0.0 area-type stub",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
			},
			want: []string{"0.0.0.0", "stub"},
		},
		{
			name: "ospfv3 backbone nssa integer spelling",
			sets: []string{
				"set protocols ospf3 area 0 area-type nssa",
				"set protocols ospf3 area 0 interface ge-0/0/0.0",
			},
			want: []string{"nssa"},
		},
		{
			name: "routing-instance local-as equals router AS",
			sets: []string{
				"set routing-instances VRF-A instance-type virtual-router",
				"set routing-instances VRF-A protocols bgp local-as 65001",
				"set routing-instances VRF-A protocols bgp group ext peer-as 65002",
				"set routing-instances VRF-A protocols bgp group ext neighbor 192.0.2.2 local-as 65001",
			},
			want: []string{"VRF-A", "local-as"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.sets))
			if err == nil {
				t.Fatalf("strict compilation accepted %s; want rejection (#14585)", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("diagnostic %q does not name %q", err.Error(), w)
				}
			}
		})
	}
}

func TestBGPCrossField14585ControlsPass(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{
			name: "per-neighbor local-as different from router AS",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2 local-as 65009",
			},
		},
		{
			name: "route-reflector-client on iBGP",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group int peer-as 65001",
				"set protocols bgp group int neighbor 192.0.2.2 route-reflector-client",
			},
		},
		{
			name: "remove-private on eBGP",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.3 remove-private",
			},
		},
		{
			name: "dampening suppress above reuse defaults",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp damping half-life 15 reuse 750 suppress 2000 max-suppress 60",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2",
			},
		},
		{
			name: "dampening suppress only uses default reuse",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp damping suppress 2000",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.2",
			},
		},
		{
			name: "non-backbone stub",
			sets: []string{
				"set protocols ospf area 0.0.0.1 area-type stub",
				"set protocols ospf area 0.0.0.1 interface ge-0/0/0.0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, tc.sets)); err != nil {
				t.Fatalf("control %q rejected: %v", tc.name, err)
			}
		})
	}
}

func TestBGPCrossField14585LenientWarns(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{
			name: "remove-private on iBGP",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group int peer-as 65001 remove-private",
				"set protocols bgp group int neighbor 192.0.2.3",
			},
			want: "remove-private",
		},
		{
			name: "route-reflector-client on eBGP",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group ext peer-as 65002",
				"set protocols bgp group ext neighbor 192.0.2.3 route-reflector-client",
			},
			want: "route-reflector-client",
		},
		{
			name: "dampening suppress below reuse",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp damping reuse 750",
				"set protocols bgp damping suppress 500",
			},
			want: "suppress",
		},
		{
			name: "backbone stub",
			sets: []string{
				"set protocols ospf area 0.0.0.0 area-type stub",
			},
			want: "stub",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, tc.sets))
			if err != nil {
				t.Fatalf("lenient compilation must boot (#1960): %v", err)
			}
			if joined := strings.Join(cfg.Warnings, "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("lenient warnings missing %q: %v", tc.want, cfg.Warnings)
			}
		})
	}
}
