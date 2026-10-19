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

// #15016 (A12-04): a virtual link's effective transit area must relate to
// the backbone and to the transit area's type. FRR refuses a VL whose
// transit is the backbone itself or a stub/NSSA area, failing every
// frr-reload; the default transit (the enclosing area) covers the
// `area 0 { virtual-link … }` spelling with no explicit transit-area.
func TestVirtualLinkTransitStrictRejects15016(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want []string
	}{
		{
			name: "default transit is backbone when VL written under area 0",
			sets: []string{
				"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.0 virtual-link 10.0.0.2",
			},
			want: []string{"virtual-link", "10.0.0.2", "backbone"},
		},
		{
			name: "explicit transit-area is backbone integer spelling",
			sets: []string{
				"set protocols ospf area 0.0.0.1 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area 0",
			},
			want: []string{"virtual-link", "10.0.0.2", "backbone"},
		},
		{
			name: "transit area is stub",
			sets: []string{
				"set protocols ospf area 0.0.0.1 area-type stub",
				"set protocols ospf area 0.0.0.1 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2",
			},
			want: []string{"virtual-link", "stub"},
		},
		{
			name: "transit area is nssa via explicit transit-area",
			sets: []string{
				"set protocols ospf area 0.0.0.1 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.2 area-type nssa",
				"set protocols ospf area 0.0.0.2 interface ge-0/0/1.0",
				"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area 0.0.0.2",
			},
			want: []string{"virtual-link", "nssa"},
		},
		{
			name: "routing-instance transit is backbone",
			sets: []string{
				"set routing-instances VRF-A instance-type virtual-router",
				"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
				"set routing-instances VRF-A protocols ospf area 0.0.0.0 virtual-link 10.0.0.2",
			},
			want: []string{"VRF-A", "virtual-link", "backbone"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.sets))
			if err == nil {
				t.Fatalf("strict compilation accepted %s; want rejection (#15016)", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("diagnostic %q does not name %q", err.Error(), w)
				}
			}
		})
	}
}

func TestVirtualLinkTransitControlsPass15016(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{
			name: "normal transit area default",
			sets: []string{
				"set protocols ospf area 0.0.0.1 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2",
			},
		},
		{
			name: "normal transit area explicit different area",
			sets: []string{
				"set protocols ospf area 0.0.0.1 interface ge-0/0/0.0",
				"set protocols ospf area 0.0.0.2 interface ge-0/0/1.0",
				"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area 0.0.0.2",
			},
		},
		{
			name: "stub area without virtual link",
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

func TestVirtualLinkTransitLenientWarns15016(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		"set protocols ospf area 0.0.0.0 virtual-link 10.0.0.2",
	}))
	if err != nil {
		t.Fatalf("lenient compilation must boot (#1960): %v", err)
	}
	if joined := strings.Join(cfg.Warnings, "\n"); !strings.Contains(joined, "virtual-link") {
		t.Fatalf("lenient warnings missing virtual-link: %v", cfg.Warnings)
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

// #15663: iBGP classification must use the effective local AS
// (neighbor local-as > group local-as, already folded into LocalAS by
// the compiler, > router AS), not the router AS alone.
func TestBGPCrossField15663EffectiveLocalAS(t *testing.T) {
	// Unit-level classification, including peer-as 0 and router-AS 0.
	for _, tc := range []struct {
		name     string
		routerAS uint32
		n        *BGPNeighbor
		want     bool
	}{
		{"router AS iBGP", 65000, &BGPNeighbor{PeerAS: 65000}, true},
		{"router AS eBGP", 65000, &BGPNeighbor{PeerAS: 65002}, false},
		{"neighbor local-as iBGP", 65000, &BGPNeighbor{PeerAS: 65001, LocalAS: 65001}, true},
		{"neighbor local-as overrides router match", 65000, &BGPNeighbor{PeerAS: 65000, LocalAS: 65001}, false},
		{"neighbor local-as eBGP", 65000, &BGPNeighbor{PeerAS: 65002, LocalAS: 65001}, false},
		{"peer-as zero never iBGP", 65000, &BGPNeighbor{PeerAS: 0, LocalAS: 65001}, false},
		{"router zero with local-as", 0, &BGPNeighbor{PeerAS: 65001, LocalAS: 65001}, true},
		{"all zero", 0, &BGPNeighbor{}, false},
		{"nil neighbor", 65000, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BGPNeighborIsIBGP14585(tc.routerAS, tc.n); got != tc.want {
				t.Fatalf("BGPNeighborIsIBGP14585(%d, %+v) = %v, want %v", tc.routerAS, tc.n, got, tc.want)
			}
		})
	}
	if got := BGPNeighborEffectiveLocalAS15663(65000, &BGPNeighbor{LocalAS: 65001}); got != 65001 {
		t.Fatalf("effective = %d, want 65001", got)
	}
	if got := BGPNeighborEffectiveLocalAS15663(65000, &BGPNeighbor{}); got != 65000 {
		t.Fatalf("effective fallback = %d, want 65000", got)
	}
	if got := BGPNeighborEffectiveLocalAS15663(65000, nil); got != 65000 {
		t.Fatalf("effective nil = %d, want 65000", got)
	}

	// Strict-compile acceptance: valid iBGP under local-as.
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{
			name: "group local-as iBGP route-reflector-client",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group int peer-as 65001 local-as 65001",
				"set protocols bgp group int neighbor 192.0.2.2 route-reflector-client",
			},
		},
		{
			name: "neighbor local-as overrides group eBGP to iBGP",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group int peer-as 65001",
				"set protocols bgp group int neighbor 192.0.2.2 local-as 65001 route-reflector-client",
			},
		},
		{
			name: "neighbor local-as iBGP in routing-instance",
			sets: []string{
				"set routing-instances VRF-A instance-type virtual-router",
				"set routing-instances VRF-A protocols bgp local-as 65000",
				"set routing-instances VRF-A protocols bgp group int peer-as 65001 local-as 65001",
				"set routing-instances VRF-A protocols bgp group int neighbor 192.0.2.2 route-reflector-client",
			},
		},
		{
			name: "local-as eBGP remove-private still valid",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group ext peer-as 65002 local-as 65001",
				"set protocols bgp group ext neighbor 192.0.2.3 remove-private",
			},
		},
	} {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, tc.sets)); err != nil {
				t.Fatalf("valid local-as fixture rejected: %v", err)
			}
		})
	}

	// Strict-compile rejection: still eBGP/iBGP under effective AS, and
	// diagnostics must name the effective (65001), not router (65000), AS.
	for _, tc := range []struct {
		name string
		sets []string
		want []string
	}{
		{
			name: "group local-as true eBGP route-reflector-client rejected",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group ext peer-as 65002 local-as 65001",
				"set protocols bgp group ext neighbor 192.0.2.2 route-reflector-client",
			},
			want: []string{"192.0.2.2", "route-reflector-client", "peer-as 65002 != local-as 65001"},
		},
		{
			name: "group local-as iBGP remove-private rejected",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group int peer-as 65001 local-as 65001 remove-private",
				"set protocols bgp group int neighbor 192.0.2.3",
			},
			want: []string{"192.0.2.3", "remove-private", "peer-as 65001 == local-as 65001"},
		},
		{
			name: "router-AS peer under local-as override is eBGP for RRC",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group ext peer-as 65000 local-as 65001",
				"set protocols bgp group ext neighbor 192.0.2.2 route-reflector-client",
			},
			want: []string{"route-reflector-client", "peer-as 65000 != local-as 65001"},
		},
		{
			name: "router-AS peer under local-as override remove-private valid so RRC case only",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group int peer-as 65001",
				"set protocols bgp group int neighbor 192.0.2.3 local-as 65002 remove-private",
			},
			want: nil, // accepted: effective 65002 != peer 65001 => eBGP
		},
	} {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.sets))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("expected acceptance, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("strict compilation accepted %s; want rejection (#15663)", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("diagnostic %q does not name %q", err.Error(), w)
				}
			}
			if strings.Contains(err.Error(), "65000") && !strings.Contains(tc.name, "router-AS peer") {
				// Effective-AS diagnostics must not cite the router AS as local-as.
				if strings.Contains(err.Error(), "local-as 65000") {
					t.Fatalf("diagnostic cites router AS as local-as: %q", err.Error())
				}
			}
		})
	}
}
