package vrrp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func rethCfg14404() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}
}

// #14404: a RETH instance under the kernel-upgrade hold must not become
// MASTER even with zero peer adverts (dead-master timer expiry), and must
// promote normally once the hold clears.
func TestKernelUpgradeHold_BlocksBecomeMaster14404(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	m.SetKernelUpgradeHold(true)
	vi := newGateTestInstance(t, 100, false)
	// Seed via the manager path (production seeds on UpdateInstances build /
	// SetKernelUpgradeHold fan-out to existing instances).
	vi.setKernelUpgradeHold(m.KernelUpgradeHeld())
	if !vi.kernelUpgradeHeld() {
		t.Fatal("instance must report held after manager hold")
	}
	// Direct becomeMaster refusal.
	if vi.becomeMaster() {
		t.Fatal("held instance claimed MASTER via becomeMaster")
	}
	if vi.getState() == StateMaster {
		t.Fatal("held instance reached MASTER")
	}
	// Dead-master timer path via stepBackup: fire masterDown.
	masterDown := time.NewTimer(time.Millisecond)
	advert := time.NewTimer(time.Hour)
	preemptHold := time.NewTimer(time.Hour)
	defer masterDown.Stop()
	defer advert.Stop()
	defer preemptHold.Stop()
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() == StateMaster {
		t.Fatal("held instance reached MASTER via masterDown expiry")
	}
	// Clear hold: promotion succeeds on the next horizon.
	vi.setKernelUpgradeHold(false)
	m.SetKernelUpgradeHold(false)
	if vi.kernelUpgradeHeld() {
		t.Fatal("instance still held after clear")
	}
	if !vi.becomeMaster() {
		t.Fatal("cleared instance must promote normally")
	}
	if vi.getState() != StateMaster {
		t.Fatal("cleared instance must be MASTER")
	}
}

// Held RETH priority-0 collection: CollectRethInstances must not fabricate
// priority 100 for a held (explicit priority 0) RG, while an absent RG still
// defaults to 100.
func TestCollectRethInstances_HeldPriorityZeroNotDefaulted14404(t *testing.T) {
	cfg := rethCfg14404()
	held := CollectRethInstances(cfg, map[int]int{1: 0})
	if len(held) != 1 {
		t.Fatalf("held: got %d instances, want 1", len(held))
	}
	if held[0].Priority != 0 {
		t.Fatalf("held priority = %d, want 0 (explicit hold suppression preserved)", held[0].Priority)
	}
	absent := CollectRethInstances(cfg, map[int]int{})
	if len(absent) != 1 || absent[0].Priority != 100 {
		t.Fatalf("absent RG must default to 100, got %+v", absent)
	}
	// And the held priority-0 instance refuses MASTER.
	vi := newGateTestInstance(t, 0, false)
	vi.setKernelUpgradeHold(true)
	if vi.becomeMaster() {
		t.Fatal("held priority-0 instance must not become MASTER")
	}
	_ = net.IPv4zero
}
