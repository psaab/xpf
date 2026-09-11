package ipsec

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsecname"
)

// #9624 DRIFT GUARD. The pkg/config commit gate derives SA names through ipsecname.SANames, and
// the renderer's effectiveTrafficSelectors through ipsecname.ChildNames. For a config every VPN
// of which renders, the gate's name set must equal the render index (BuildSANameIndex), and the
// names the gate would reject must equal the index's Collisions().

func driftConfig9624() *config.IPsecConfig {
	ts := func(name, l, r string) *config.IPsecTrafficSelector {
		return &config.IPsecTrafficSelector{Name: name, LocalIP: l, RemoteIP: r}
	}
	return &config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
		"a":        {Name: "a", Gateway: "198.51.100.1", TrafficSelectors: map[string]*config.IPsecTrafficSelector{"b-c": ts("b-c", "10.0.1.0/24", "10.9.1.0/24")}},
		"a-b":      {Name: "a-b", Gateway: "198.51.100.2", TrafficSelectors: map[string]*config.IPsecTrafficSelector{"c": ts("c", "10.0.2.0/24", "10.9.2.0/24")}},
		"blue":     {Name: "blue", Gateway: "198.51.100.3", TrafficSelectors: map[string]*config.IPsecTrafficSelector{"red": ts("red", "10.0.3.0/24", "10.9.3.0/24")}},
		"blue-red": {Name: "blue-red", Gateway: "198.51.100.4"},
		"site": {Name: "site", Gateway: "198.51.100.5", TrafficSelectors: map[string]*config.IPsecTrafficSelector{
			"x/a": ts("x/a", "10.0.5.0/24", "10.9.5.0/24"), "x:a": ts("x:a", "10.0.6.0/24", "10.9.6.0/24")}},
	}}
}

func TestSANameDerivationMatchesTheRenderIndex9624(t *testing.T) {
	cfg := driftConfig9624()
	idx := BuildSANameIndex(cfg)

	gate := map[string][]string{}
	for _, vpn := range sortedVPNNames(cfg.VPNs) {
		var sels []string
		for s := range cfg.VPNs[vpn].TrafficSelectors {
			sels = append(sels, s)
		}
		for _, sa := range ipsecname.SANames(vpn, sels) {
			gate[sa] = append(gate[sa], vpn)
		}
	}

	// Collisions() reports each colliding name as `name=[vpn ...]`; spell the gate's the same way.
	var gateNames, gateCollisions []string
	for sa, owners := range gate {
		gateNames = append(gateNames, sa)
		if len(owners) > 1 {
			gateCollisions = append(gateCollisions, fmt.Sprintf("%s=%v", sa, owners))
		}
		if got := idx.VPNs(sa); !reflect.DeepEqual(got, owners) {
			t.Errorf("SA %q: the gate attributes it to %v, the render index to %v", sa, owners, got)
		}
	}
	sort.Strings(gateNames)
	sort.Strings(gateCollisions)

	var indexNames []string
	for sa := range idx {
		indexNames = append(indexNames, sa)
	}
	sort.Strings(indexNames)
	if !reflect.DeepEqual(gateNames, indexNames) {
		t.Errorf("gate names %v != render index names %v", gateNames, indexNames)
	}
	if got := idx.Collisions(); !reflect.DeepEqual(gateCollisions, got) {
		t.Errorf("gate collisions %v != render index Collisions() %v", gateCollisions, got)
	}
	if !reflect.DeepEqual(gateCollisions, []string{"a-b-c=[a a-b]", "blue-red=[blue blue-red]"}) {
		t.Errorf("FIXTURE: the config must carry exactly the issue's two collisions, got %v", gateCollisions)
	}
}
