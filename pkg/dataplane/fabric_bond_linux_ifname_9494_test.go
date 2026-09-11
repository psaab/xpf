package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9494: the fabric-bond model must carry the Linux interface name, like its own
// members, so no "/" reaches networkd's file path. A plain name is unchanged.
func TestFabricBondNameIsLinuxIfName_9494(t *testing.T) {
	for _, tc := range []struct{ ifName, wantBond string }{
		{"a/../../../b", "a-..-..-..-b"},
		{"fab0", "fab0"},
	} {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			tc.ifName: {FabricMembers: []string{"ge-0/0/1", "ge-0/0/2"}},
		}
		result := &CompileResult{ifCache: map[string]*net.Interface{}}
		buildFabricBondModels(cfg, result, map[string]bool{})
		var bond string
		for _, ic := range result.ManagedInterfaces {
			if ic.IsBond {
				bond = ic.Name
			}
		}
		if bond != tc.wantBond || strings.Contains(bond, "/") {
			t.Fatalf("#9494: fabric bond for %q = %q, want %q (the Linux interface name)", tc.ifName, bond, tc.wantBond)
		}
		for _, ic := range result.ManagedInterfaces {
			if !ic.IsBond && ic.BondMaster != bond {
				t.Fatalf("member %q BondMaster = %q, want %q", ic.Name, ic.BondMaster, bond)
			}
		}
	}
}
