package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestApplyFullRejectsDivergentBGPNeighborDuplicates11399(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second *config.BGPNeighbor
		inInstance    bool
	}{
		{
			name:   "peer-as",
			first:  &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, GroupName: "blue"},
			second: &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, GroupName: "red"},
		},
		{
			name:   "missing versus valid peer-as",
			first:  &config.BGPNeighbor{Address: "192.0.2.1", FamilyInet: true, GroupName: "blue"},
			second: &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, GroupName: "red"},
		},
		{
			name:   "export policy",
			first:  &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, GroupName: "blue", Export: []string{"ALLOW_BLUE"}},
			second: &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, GroupName: "red", Export: []string{"ALLOW_RED"}},
		},
		{
			name:       "per-routing-instance peer-as",
			inInstance: true,
			first:      &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, GroupName: "blue"},
			second:     &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, GroupName: "red"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			confPath := filepath.Join(t.TempDir(), "frr.conf")
			if err := os.WriteFile(confPath, []byte("log syslog informational\n! operator config\n"), 0644); err != nil {
				t.Fatal(err)
			}
			m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
			lastGoodConfig := &FullConfig{BGP: &config.BGPConfig{
				LocalAS: 64512,
				Neighbors: []*config.BGPNeighbor{
					{Address: "198.51.100.1", PeerAS: 64513, FamilyInet: true},
				},
			}}
			if err := m.ApplyFull(lastGoodConfig); err != nil {
				t.Fatalf("ApplyFull(last-good config): %v", err)
			}
			lastGood, err := os.ReadFile(confPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(lastGood), "neighbor 198.51.100.1 remote-as 64513\n") {
				t.Fatalf("fixture did not install a valid last-good BGP stanza:\n%s", lastGood)
			}
			bgp := &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{tc.first, tc.second}}
			fc := &FullConfig{BGP: bgp}
			if tc.inInstance {
				fc.BGP = nil
				fc.Instances = []InstanceConfig{{Name: "tenant", VRFName: "vrf-tenant", BGP: bgp}}
			}
			if tc.name == "export policy" {
				fc.PolicyOptions = &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
					"ALLOW_BLUE": {Name: "ALLOW_BLUE", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
					"ALLOW_RED":  {Name: "ALLOW_RED", Terms: []*config.PolicyTerm{{Name: "t", Action: "reject"}}},
				}}
			}

			err = m.ApplyFull(fc)
			if err == nil || !strings.Contains(err.Error(), "192.0.2.1") {
				t.Fatalf("ApplyFull accepted divergent same-address BGP neighbors; want a fail-closed duplicate error naming 192.0.2.1, got %v", err)
			}
			got, readErr := os.ReadFile(confPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != string(lastGood) {
				t.Fatalf("failed duplicate-neighbor apply changed the last-good managed config:\n got %q\nwant %q", got, lastGood)
			}
		})
	}
}

func TestApplyFullPreservesSameGroupBGPNeighborFragments11399(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fc := &FullConfig{
		BGP: &config.BGPConfig{
			LocalAS: 65000,
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, GroupName: "blue"},
				{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, GroupName: "blue", Export: []string{"ALLOW_BLUE"}},
			},
		},
		PolicyOptions: &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"ALLOW_BLUE": {Name: "ALLOW_BLUE", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		}},
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull rejected same-group neighbor fragments: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "neighbor 192.0.2.1 route-map ALLOW_BLUE out\n") {
		t.Fatalf("the policy-bearing same-group fragment was dropped from the rendered config:\n%s", got)
	}
}
func TestApplyFullAllowsSameBGPAddressAcrossInstances11399(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fc := &FullConfig{
		BGP: &config.BGPConfig{
			LocalAS: 65000,
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true},
			},
		},
		Instances: []InstanceConfig{{
			Name: "tenant", VRFName: "vrf-tenant",
			BGP: &config.BGPConfig{
				LocalAS: 65000,
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true},
				},
			},
		}},
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull rejected the same peer address in independent BGP instances: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"neighbor 192.0.2.1 remote-as 65001\n",
		"neighbor 192.0.2.1 remote-as 65002\n",
	} {
		if !strings.Contains(string(got), statement) {
			t.Errorf("independent BGP instance statement %q missing from managed config:\n%s", statement, got)
		}
	}
}
