package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestBootstrapNonIndexRemedyIsActionable12151 pins the operator-facing
// remedies for a higher-index PCI lifeline and a non-PCI management route. The
// strict config path silently ignores system management-interface; neither
// refusal should mutate the interface or network-file state.
func TestBootstrapNonIndexRemedyIsActionable12151(t *testing.T) {
	tests := []struct {
		name     string
		lifeline string
		wantLog  []string
	}{
		{
			name:     "higher PCI index",
			lifeline: "enp5s0",
			wantLog: []string{
				"re-wire",
				"enumerates as index 0",
				"restart xpfd or reboot",
				"index0_interface=enp1s0",
				"index0_pci=0000:01:00.0",
				"silently ignored",
			},
		},
		{
			name:     "non-PCI management route",
			lifeline: "bond0",
			wantLog: []string{
				"not present in the pci nic enumeration",
				"bond, vlan, or bridge",
				"rewiring that interface cannot make it enumeration index 0",
				"move the management default route onto a pci nic",
				"restart xpfd or reboot",
				"index0_interface=enp1s0",
				"index0_pci=0000:01:00.0",
				"silently ignored",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			oldLinkDir, oldRecord := linkDir, lifelineRecordFileForTest
			oldDetect, oldEnumerate := detectLifelineInterfaceFn, enumeratePCINICsFn
			oldRename, oldReload, oldInstaller := renameInterfaceFn, networkctlReloadFn, nftInstaller
			oldLink, oldAddr, oldRoute := lifelineLinkByName, lifelineAddrList, lifelineRouteList
			t.Cleanup(func() {
				linkDir, lifelineRecordFileForTest = oldLinkDir, oldRecord
				detectLifelineInterfaceFn, enumeratePCINICsFn = oldDetect, oldEnumerate
				renameInterfaceFn, networkctlReloadFn, nftInstaller = oldRename, oldReload, oldInstaller
				lifelineLinkByName, lifelineAddrList, lifelineRouteList = oldLink, oldAddr, oldRoute
			})

			linkDir = filepath.Join(dir, "network")
			if err := os.MkdirAll(linkDir, 0o755); err != nil {
				t.Fatal(err)
			}
			lifelineRecordFileForTest = filepath.Join(dir, "lifeline-interface")
			detectLifelineInterfaceFn = func() (string, bool, error) { return tt.lifeline, true, nil }
			enumeratePCINICsFn = func() ([]pciNIC, error) {
				return []pciNIC{
					{sortKey: 0, busAddr: "0000:01:00.0", name: "enp1s0"},
					{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
				}, nil
			}
			lifelineLinkByName = func(name string) (netlink.Link, error) {
				return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 2}}, nil
			}
			lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
				ip, subnet, _ := net.ParseCIDR("192.0.2.10/24")
				subnet.IP = ip
				return []netlink.Addr{{IPNet: subnet, ValidLft: 0xffffffff}}, nil
			}
			lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
				if family == netlink.FAMILY_V4 {
					return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
				}
				return nil, nil
			}
			renamed, reloaded := false, false
			renameInterfaceFn = func(string, string) error { renamed = true; return nil }
			networkctlReloadFn = func() error { reloaded = true; return nil }
			nftInstaller = &fakeNftInstaller{}

			logs, restore := captureSlog(t)
			t.Cleanup(restore)
			(&Daemon{}).setupBootstrapLifeline()

			got := strings.ToLower(logs.String())
			for _, want := range tt.wantLog {
				if !strings.Contains(got, want) {
					t.Errorf("refusal remedy omitted %q; logs: %s", want, logs.String())
				}
			}
			if strings.Contains(got, "'system management-interface' and 'commit confirmed'") {
				t.Errorf("refusal still recommends the unsettable config leaf: %s", logs.String())
			}
			if tt.lifeline == "bond0" &&
				strings.Contains(got, "re-wire the management nic so it enumerates as index 0") {
				t.Errorf("non-PCI refusal offers an inapplicable rewire remedy: %s", logs.String())
			}
			if renamed || reloaded {
				t.Errorf("non-index-0 refusal mutated interface state: renamed=%v reloaded=%v", renamed, reloaded)
			}
			if _, err := os.Stat(filepath.Join(linkDir, linkPrefix+"fxp0.network")); !os.IsNotExist(err) {
				t.Errorf("non-index-0 refusal wrote an fxp0 network file: err=%v", err)
			}
		})
	}
}
