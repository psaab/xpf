package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #13219 (D4-01): on last-RG demotion, clearRethServicesForRG must derive the
// Kea desired state from desiredClusterDHCPConfigWithMasters (the #6520/#6535
// SSOT), which preserves node-local fxp0.0 groups. Hardcoding nil stops Kea
// entirely and, because the stop succeeds, the #6535 converger never heals it.
func TestClearRethServicesPreservesNodeLocalDHCPOnLastRGDemotion(t *testing.T) {
	dir := t.TempDir()
	conf4 := filepath.Join(dir, "kea-dhcp4.conf")
	conf6 := filepath.Join(dir, "kea-dhcp6.conf")
	doneCh := make(chan string, 8)
	km := dhcpserver.NewManagerForTesting(
		conf4, conf6,
		func(args ...string) error {
			if len(args) > 0 && (args[0] == "restart" || args[0] == "stop") {
				doneCh <- args[0]
			}
			return nil
		},
		func(string) bool { return true },
	)

	lines := append([]string{}, dhcpConvergerClusterSet...)
	lines = append(lines,
		"set interfaces fxp0 unit 0 family inet address 192.168.100.1/24",
		"set system services dhcp-local-server group mgmt interface fxp0.0",
		"set system services dhcp-local-server group mgmt dhcp-attributes subnet 192.168.100.0/24",
	)
	store := testStoreWithSetConfig(t, lines)
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)

	d := &Daemon{
		rgStates:   make(map[int]*rgStateMachine),
		cluster:    cm,
		store:      store,
		vrrpMgr:    vrrp.NewManager(),
		dhcpServer: km,
	}

	// RG1 demoted: masters[1] == false, no other master RG.
	st := d.getOrCreateRGState(1)
	st.SetCluster(false)
	masters := d.snapshotRethMasterState()
	ssotCfg := d.desiredClusterDHCPConfigWithMasters(store.ActiveConfig(), masters)
	if ssotCfg == nil || ssotCfg.DHCPLocalServer == nil || ssotCfg.DHCPLocalServer.Groups["mgmt"] == nil {
		t.Fatalf("fixture: SSOT must preserve node-local mgmt group, got %+v", ssotCfg)
	}

	if err := os.WriteFile(conf4, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	d.clearRethServicesForRG(1)

	select {
	case action := <-doneCh:
		if action == "stop" {
			t.Fatalf("clearRethServicesForRG bypassed SSOT and stopped Kea, killing node-local fxp0.0 DHCP (desired groups %v)", ssotCfg.DHCPLocalServer.Groups["mgmt"].Interfaces)
		}
		// restart (or start) = node-local config reapplied: correct.
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for async DHCP apply from clearRethServicesForRG")
	}
}
