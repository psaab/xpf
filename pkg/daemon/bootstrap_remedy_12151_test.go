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
// remedies for higher-index PCI, non-PCI, and empty-PCI-enumeration lifelines.
// The strict config path silently ignores system management-interface; each
// refusal must leave interface and network-file state unchanged.
func TestBootstrapNonIndexRemedyIsActionable12151(t *testing.T) {
	tests := []struct {
		name       string
		lifeline   string
		nics       []pciNIC
		wantLog    []string
		wantAbsent []string
	}{
		{
			name:     "higher PCI index",
			lifeline: "enp5s0",
			wantLog: []string{
				"not enumeration index 0",
				"move the management default route and its addressing onto the nic identified by index0_interface and index0_pci",
				"virtio-first enumeration",
				"recabling alone can strand management",
				"chassis device-map interface fxp0 pci <mgmt pci>",
				"commit confirmed",
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
				"move the management default route and its addressing onto the nic identified by index0_interface and index0_pci",
				"restart xpfd or reboot",
				"index0_interface=enp1s0",
				"index0_pci=0000:01:00.0",
				"silently ignored",
			},
			wantAbsent: []string{"chassis device-map"},
		},
		{
			name:     "no PCI NIC enumerated",
			lifeline: "vmbus0",
			nics:     []pciNIC{},
			wantLog: []string{
				"no pci nic enumerated",
				"vmbus-only host",
				"refusing to rename/cycle any interface",
				"no interface changes",
				"silently ignored",
			},
			wantAbsent: []string{
				"bond, vlan, or bridge",
				"index0_interface=",
				"index0_pci=",
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
				if tt.nics != nil {
					return tt.nics, nil
				}
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
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("refusal remedy unexpectedly included %q; logs: %s", absent, logs.String())
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
				t.Errorf("refusal mutated interface state: renamed=%v reloaded=%v", renamed, reloaded)
			}
			if _, err := os.Stat(filepath.Join(linkDir, linkPrefix+"fxp0.network")); !os.IsNotExist(err) {
				t.Errorf("refusal wrote an fxp0 network file: err=%v", err)
			}
		})
	}
}
