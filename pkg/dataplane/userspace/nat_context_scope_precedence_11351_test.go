// #11351: DNAT and static-NAT builders retain each rule-set scope but emit
// more-specific contexts first. Rust applies the same rank during matching;
// these cells pin deterministic, stable snapshot order as the shared handoff.
package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type natContextScope11351 struct {
	name, zone, iface, ri string
}

var natContextScopes11351 = []natContextScope11351{
	{name: "interface", iface: "ge-0/0/1.0"},
	{name: "zone", zone: "trust"},
	{name: "routing-instance", ri: "VR1"},
	{name: "unscoped"},
}

var natContextScopePairs11351 = [][2]int{
	{0, 1}, // interface > zone
	{0, 2}, // interface > routing-instance
	{0, 3}, // interface > unscoped
	{1, 2}, // zone > routing-instance
	{1, 3}, // zone > unscoped
	{2, 3}, // routing-instance > unscoped
}

func dnatContextOrder11351(t *testing.T, scopes []natContextScope11351) []string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"pool": {Name: "pool", Address: "10.0.0.1"}},
	}
	for _, scope := range scopes {
		cfg.Security.NAT.Destination.RuleSets = append(cfg.Security.NAT.Destination.RuleSets, &config.NATRuleSet{
			Name:                scope.name,
			FromZone:            scope.zone,
			FromInterface:       scope.iface,
			FromRoutingInstance: scope.ri,
			Rules: []*config.NATRule{{
				Name:  scope.name,
				Match: config.NATMatch{DestinationAddress: "203.0.113.10"},
				Then:  config.NATThen{Type: config.NATDestination, PoolName: "pool"},
			}},
		})
	}
	var got []string
	for _, snapshot := range buildDestinationNATSnapshots(cfg, nil) {
		got = append(got, snapshot.Name)
	}
	return got
}

func staticNATContextOrder11351(t *testing.T, scopes []natContextScope11351) []string {
	t.Helper()
	cfg := &config.Config{}
	for _, scope := range scopes {
		cfg.Security.NAT.Static = append(cfg.Security.NAT.Static, &config.StaticNATRuleSet{
			Name:                scope.name,
			FromZone:            scope.zone,
			FromInterface:       scope.iface,
			FromRoutingInstance: scope.ri,
			Rules: []*config.StaticNATRule{{
				Name:  scope.name,
				Match: "203.0.113.10",
				Then:  "10.0.0.1",
			}},
		})
	}
	var got []string
	for _, snapshot := range buildStaticNATSnapshots(cfg, nil) {
		got = append(got, snapshot.Name)
	}
	return got
}

func TestDNATContextScopePrecedenceAllPairsBothOrders11351(t *testing.T) {
	for _, pair := range natContextScopePairs11351 {
		preferred, broader := natContextScopes11351[pair[0]], natContextScopes11351[pair[1]]
		for _, order := range [][]natContextScope11351{
			{broader, preferred},
			{preferred, broader},
		} {
			got := dnatContextOrder11351(t, order)
			want := []string{preferred.name, broader.name}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("DNAT scope order %s > %s, config order %v: got %v, want %v", preferred.name, broader.name, []string{order[0].name, order[1].name}, got, want)
			}
		}
	}
}

func TestStaticNATContextScopePrecedenceAllPairsBothOrders11351(t *testing.T) {
	for _, pair := range natContextScopePairs11351 {
		preferred, broader := natContextScopes11351[pair[0]], natContextScopes11351[pair[1]]
		for _, order := range [][]natContextScope11351{
			{broader, preferred},
			{preferred, broader},
		} {
			got := staticNATContextOrder11351(t, order)
			want := []string{preferred.name, broader.name}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("static NAT scope order %s > %s, config order %v: got %v, want %v", preferred.name, broader.name, []string{order[0].name, order[1].name}, got, want)
			}
		}
	}
}

func TestNATContextScopePrecedenceKeepsSameTierConfigOrder11351(t *testing.T) {
	zoneA := natContextScope11351{name: "zone-a", zone: "trust"}
	zoneB := natContextScope11351{name: "zone-b", zone: "trust"}
	for _, tc := range []struct {
		name  string
		order func(*testing.T, []natContextScope11351) []string
	}{
		{name: "DNAT", order: dnatContextOrder11351},
		{name: "static", order: staticNATContextOrder11351},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.order(t, []natContextScope11351{zoneA, zoneB})
			want := []string{"zone-a", "zone-b"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("same-tier NAT scopes must preserve config order: got %v, want %v", got, want)
			}
		})
	}
}
