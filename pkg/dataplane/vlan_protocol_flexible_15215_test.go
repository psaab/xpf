package dataplane

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

// #15215 A28-02: an existing 802.1ad link at "<phys>.<vid>" must NOT be
// adopted as the configured 802.1Q unit. The create path builds
// netlink.Vlan{VlanId: vid} (default 802.1Q), so create and adopt must
// agree on protocol. A28-03: flexible-vlan-tagging must yield the same
// writer models as the vlan-tagging control.

func protoVLAN15215(proto netlink.VlanProtocol) *netlink.Vlan {
	return &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        provSubName6916(),
			Index:       provSubIdx6916,
			ParentIndex: provParentIdx,
			NetNsID:     netnsIDLocal,
			OperState:   netlink.OperUp,
		},
		VlanId:       provVID6916,
		VlanProtocol: proto,
	}
}

func TestVLANAdoptionRefuses8021AD15215(t *testing.T) {
	ad := protoVLAN15215(netlink.VLAN_PROTOCOL_8021AD)
	why := vlanAdoptionRefusal(ad, provParentIdx, provVID6916)
	if why == "" {
		t.Fatalf("ADOPTED an 802.1ad device as the configured 802.1Q child %#v; it becomes a delegated VLAN child whose parent XDP classifies 802.1Q only (#15215 A28-02)", ad)
	}
	if !strings.Contains(why, "802.1ad") && !strings.Contains(why, "88a8") && !strings.Contains(strings.ToLower(why), "protocol") {
		t.Errorf("refusal reason %q must name the protocol; the reason reaches the operator in the UnarmedSurface record", why)
	}
	if why := vlanAdoptionRefusal(protoVLAN15215(netlink.VLAN_PROTOCOL_8021Q), provParentIdx, provVID6916); why != "" {
		t.Errorf("802.1Q control refused: %q", why)
	}
	if why := vlanAdoptionRefusal(protoVLAN15215(netlink.VLAN_PROTOCOL_UNKNOWN), provParentIdx, provVID6916); why != "" {
		t.Errorf("absent-protocol (unknown/zero) control refused: %q — accept zero only when the attribute is absent", why)
	}
}

func TestEnsureVLANSubInterfaceRefuses8021AD15215(t *testing.T) {
	parent := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: provPhys6916, Index: provParentIdx}}
	orig := vlanLinkByNameSeam
	t.Cleanup(func() { vlanLinkByNameSeam = orig })
	vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
		switch name {
		case provPhys6916:
			return parent, nil
		case provSubName6916():
			return protoVLAN15215(netlink.VLAN_PROTOCOL_8021AD), nil
		}
		return nil, errors.New("no such link")
	}
	idx, created, err := ensureVLANSubInterface(provPhys6916, provVID6916)
	if err == nil {
		t.Fatalf("adopted the 802.1ad squatter: ifindex %d created=%v (#15215 A28-02)", idx, created)
	}
	if !errors.Is(err, errVLANAdoptRefused) {
		t.Errorf("refusal must carry errVLANAdoptRefused, got %v", err)
	}
	if idx != 0 || created {
		t.Errorf("refused adoption returned idx=%d created=%v, want 0/false", idx, created)
	}
}

func flexibleCfg15215(t *testing.T, tagging string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces ge-0/0/1 " + tagging,
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.100",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("%s must compile: %v", tagging, err)
	}
	return cfg
}

func TestFlexibleVlanTaggingYieldsVlanTaggingModel15215(t *testing.T) {
	for _, tc := range []struct{ name, tagging string }{
		{"vlan-tagging control", "vlan-tagging"},
		{"flexible-vlan-tagging", "flexible-vlan-tagging"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := flexibleCfg15215(t, tc.tagging)
			result := &CompileResult{ifCache: map[string]*net.Interface{
				"ge-0-0-1": {Index: 10, Name: "ge-0-0-1", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}},
			}}
			buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
			var parent, sub bool
			for _, m := range result.ManagedInterfaces {
				switch m.Name {
				case "ge-0-0-1":
					parent = true
					if !m.IsVLANParent {
						t.Errorf("parent IsVLANParent=false, want true (%s)", tc.tagging)
					}
					if len(m.Addresses) != 0 {
						t.Errorf("parent Addresses=%v, want none — address belongs on .100 (%s); parent answers untagged for the tagged unit's subnet", m.Addresses, tc.tagging)
					}
				case "ge-0-0-1.100":
					sub = true
					if len(m.Addresses) != 1 || m.Addresses[0] != "10.0.1.1/24" {
						t.Errorf("sub Addresses=%v, want [10.0.1.1/24] (%s)", m.Addresses, tc.tagging)
					}
				}
			}
			if !parent || !sub {
				t.Fatalf("missing models parent=%v sub=%v in %+v (%s)", parent, sub, result.ManagedInterfaces, tc.tagging)
			}
			if !isConfiguredVLANSubInterface("ge-0-0-1.100", cfg) {
				t.Errorf("isConfiguredVLANSubInterface(ge-0-0-1.100)=false (%s), want true", tc.tagging)
			}
		})
	}
}

func TestFlexibleBridgeDomainMemberEnslaved15215(t *testing.T) {
	mk := func(vlanTagging, flexible bool) *config.Config {
		return &config.Config{
			Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {VlanTagging: vlanTagging, FlexibleVlanTagging: flexible, Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 100}}},
			}},
			BridgeDomains: []*config.BridgeDomainConfig{{Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"}}},
		}
	}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"vlan-tagging control", mk(true, false)},
		{"flexible-vlan-tagging", mk(false, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &CompileResult{ManagedInterfaces: []networkd.InterfaceConfig{{Name: "ge-0-0-0.100"}}}
			buildBridgeDomainModels(tc.cfg, result, map[string]bool{})
			if got := result.ManagedInterfaces[0].BridgeMaster; got != "br-bd0" {
				t.Fatalf("BridgeMaster = %q (%s), want br-bd0 — bridge-domain member not enslaved", got, tc.name)
			}
		})
	}
}
