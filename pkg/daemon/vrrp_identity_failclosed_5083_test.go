package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestApplyTailReconcilesSurfacesVRRPIdentityCollision drives the real commit
// tail with two configured units that resolve to the same kernel interface,
// VRID, and family. The manager rejects that non-deterministic last-wins
// identity before mutating its live set; the apply tail must propagate the
// rejection so the operator never receives a successful commit for VRRP
// coverage that was not installed.
func TestApplyTailReconcilesSurfacesVRRPIdentityCollision(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	group := func(vip string) map[string]*config.VRRPGroup {
		return map[string]*config.VRRPGroup{
			vip + "_grp5": {ID: 5, VirtualAddresses: []string{vip}},
		}
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				100: {Number: 100, VlanID: 100, VRRPGroups: group("10.0.0.1/24")},
				200: {Number: 200, VlanID: 100, VRRPGroups: group("10.0.1.1/24")},
			},
		},
	}

	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("VRRP identity collision must fail the commit, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "duplicate VRRP instance identity") ||
		!strings.Contains(got, `interface="ge-0-0-0.100" VRID=5 family="inet"`) {
		t.Fatalf("commit error does not preserve the VRRP identity rejection: %v", err)
	}
	if states := d.vrrpMgr.States(); len(states) != 0 {
		t.Fatalf("rejected reconcile partially installed runtime state: %v", states)
	}
}
