package daemon

import (
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

func TestDynamicRoutingReadinessRequiresEvidenceForEveryProtocol(t *testing.T) {
	requirements := []haRoutingRequirement{
		{protocol: "bgp", routeProto: "bgp", tableID: 254, neighbors: []string{"192.0.2.2"}},
		{protocol: "ospf", routeProto: "ospf", tableID: 254, interfaces: []string{"reth0"}},
	}

	ready, reasons := dynamicRoutingReady(requirements, []routing.LearnedRoute{{TableID: 254, Protocol: "bgp"}}, haRoutingAdjacencies{})
	if ready || !strings.Contains(strings.Join(reasons, " "), "ospf") {
		t.Fatalf("BGP-only RIB evidence: ready=%v reasons=%v, want OSPF blocker", ready, reasons)
	}

	ready, reasons = dynamicRoutingReady(requirements, []routing.LearnedRoute{{TableID: 254, Protocol: "bgp"}}, haRoutingAdjacencies{
		ospf: map[string][]frr.OSPFNeighbor{"": {{Interface: "reth0", State: "Full/DR"}}},
		bgp:  map[string][]frr.BGPPeerSummary{"": {{Neighbor: "192.0.2.2", State: "Established"}}},
	})
	if !ready || len(reasons) != 0 {
		t.Fatalf("established BGP and OSPF adjacencies: ready=%v reasons=%v, want ready", ready, reasons)
	}
}

func TestDynamicRoutingReadinessMatchesLearnedRoutesByProtocolAndTable(t *testing.T) {
	requirements := []haRoutingRequirement{{protocol: "isis", routeProto: "isis", tableID: 1001, interfaces: []string{"reth0"}}}

	ready, reasons := dynamicRoutingReady(requirements, []routing.LearnedRoute{
		{TableID: 1001, Protocol: "bgp"},
		{TableID: 254, Protocol: "isis"},
	}, haRoutingAdjacencies{})
	if ready || len(reasons) == 0 {
		t.Fatalf("routes outside required protocol/table: ready=%v reasons=%v, want blocked", ready, reasons)
	}

	ready, reasons = dynamicRoutingReady(requirements, []routing.LearnedRoute{{TableID: 1001, Protocol: "isis"}}, haRoutingAdjacencies{})
	if !ready || len(reasons) != 0 {
		t.Fatalf("matching IS-IS route: ready=%v reasons=%v, want ready", ready, reasons)
	}
}
func TestDynamicRoutingReadinessMatchesOSPFRouteFamily(t *testing.T) {
	requirement := []haRoutingRequirement{{
		protocol: "ospfv3", routeProto: "ospf", routeFamily: netlink.FAMILY_V6, tableID: 1001,
	}}

	ready, reasons := dynamicRoutingReady(requirement, []routing.LearnedRoute{{
		TableID: 1001, Protocol: "ospf", Family: netlink.FAMILY_V4,
	}}, haRoutingAdjacencies{})
	if ready || len(reasons) == 0 {
		t.Fatalf("IPv4 OSPF route for OSPFv3 requirement: ready=%v reasons=%v, want blocked", ready, reasons)
	}

	ready, reasons = dynamicRoutingReady(requirement, []routing.LearnedRoute{{
		TableID: 1001, Protocol: "ospf", Family: netlink.FAMILY_V6,
	}}, haRoutingAdjacencies{})
	if !ready || len(reasons) != 0 {
		t.Fatalf("IPv6 OSPF route for OSPFv3 requirement: ready=%v reasons=%v, want ready", ready, reasons)
	}
}

func TestDynamicRoutingReadinessRequiresAdjacencyOnRGInterface(t *testing.T) {
	requirements := []haRoutingRequirement{{protocol: "ospf", tableID: 254, interfaces: []string{"reth0"}}}

	ready, _ := dynamicRoutingReady(requirements, nil, haRoutingAdjacencies{ospf: map[string][]frr.OSPFNeighbor{"": {{Interface: "reth1", State: "Full/DR"}}}})
	if ready {
		t.Fatal("OSPF adjacency on another interface must not satisfy this RG")
	}
	ready, _ = dynamicRoutingReady(requirements, nil, haRoutingAdjacencies{ospf: map[string][]frr.OSPFNeighbor{"": {{Interface: "reth0", State: "Init/DR"}}}})
	if ready {
		t.Fatal("non-Full OSPF neighbor must not satisfy takeover readiness")
	}
	ready, reasons := dynamicRoutingReady(requirements, nil, haRoutingAdjacencies{ospf: map[string][]frr.OSPFNeighbor{"": {{Interface: "reth0", State: "Full/DR"}}}})
	if !ready || len(reasons) != 0 {
		t.Fatalf("Full OSPF adjacency: ready=%v reasons=%v, want ready", ready, reasons)
	}
}

func TestDynamicRoutingReadinessUsesMatchingRoutingInstanceAdjacency(t *testing.T) {
	requirements := []haRoutingRequirement{{
		protocol: "ospfv3", routeProto: "ospf", tableID: 1001, vrf: "tenant", interfaces: []string{"reth0"},
	}}
	defaultVRFOnly := haRoutingAdjacencies{ospfV3: map[string][]frr.OSPFNeighbor{
		"": {{Interface: "reth0", State: "Full/DR"}},
	}}
	ready, _ := dynamicRoutingReady(requirements, nil, defaultVRFOnly)
	if ready {
		t.Fatal("default-VRF adjacency must not satisfy a routing-instance requirement")
	}

	tenantAdjacency := haRoutingAdjacencies{ospfV3: map[string][]frr.OSPFNeighbor{
		"tenant": {{Interface: "reth0", State: "Full/DR"}},
	}}
	ready, reasons := dynamicRoutingReady(requirements, nil, tenantAdjacency)
	if !ready || len(reasons) != 0 {
		t.Fatalf("tenant OSPFv3 adjacency: ready=%v reasons=%v, want ready", ready, reasons)
	}
}

func TestHARoutingRequirementsAreScopedToRGAndInstanceTable(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {
				Name:            "reth0",
				RedundancyGroup: 1,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
				},
			},
			"reth1": {
				Name:            "reth1",
				RedundancyGroup: 2,
				Units:           map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"198.51.100.1/24"}}},
			},
		}},
		Protocols: config.ProtocolsConfig{
			OSPF: &config.OSPFConfig{Areas: []*config.OSPFArea{{
				ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "reth0.0"}},
			}}},
			BGP: &config.BGPConfig{Neighbors: []*config.BGPNeighbor{{
				Address: "192.0.2.2", LocalAddress: "192.0.2.1",
			}}},
		},
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name: "tenant", TableID: 1001, Interfaces: []string{"reth0.0"},
			BGP: &config.BGPConfig{Neighbors: []*config.BGPNeighbor{{Address: "203.0.113.2"}}},
		}},
	}

	requirements := haRoutingRequirementsForRG(cfg, 1)
	if len(requirements) != 3 {
		t.Fatalf("RG1 requirements = %+v, want global BGP/OSPF and tenant BGP", requirements)
	}
	want := map[string]bool{
		"bgp/254/":        false,
		"ospf/254/":       false,
		"bgp/1001/tenant": false,
	}
	for _, requirement := range requirements {
		key := requirement.protocol + "/" + strconv.Itoa(requirement.tableID) + "/" + requirement.vrf
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected RG1 routing requirement %q", key)
			continue
		}
		want[key] = true
	}
	for key, found := range want {
		if !found {
			t.Errorf("missing RG1 routing requirement %q", key)
		}
	}
	if got := haRoutingRequirementsForRG(cfg, 2); len(got) != 0 {
		t.Fatalf("RG2 inherited RG1 routing requirements: %+v", got)
	}
}

func TestAllowDegradedRoutingTakeoverIsPerRG(t *testing.T) {
	cfg := &config.Config{Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1},
			{ID: 2, AllowDegradedRoutingTakeover: true},
		},
	}}}
	if allowsDegradedRoutingTakeover(cfg, 1) {
		t.Fatal("RG1 must retain the dynamic-routing gate")
	}
	if !allowsDegradedRoutingTakeover(cfg, 2) {
		t.Fatal("RG2 explicit degraded-routing override was ignored")
	}
}
