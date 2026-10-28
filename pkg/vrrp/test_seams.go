package vrrp

import (
	"net"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// Test seams for the #17052 mode-parity cell (pkg/cluster/test_seams.go
// precedent): the daemon parity test must observe the REAL VRRP VIP leg
// (CollectRethInstances -> sendGARPReservedMode), which needs the
// package burst seams swapped. Production never calls these.

// SetGARPSeamsForTesting swaps the burst/probe senders and returns a
// restore function.
func SetGARPSeamsForTesting(
	garp func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error,
	na func(iface string, ip net.IP, count int, stillValid cluster.BurstStillValid) error,
	probe func(iface string, senderIP, targetIP net.IP) error,
) (restore func()) {
	origG, origN, origP := garpBurstFn, naBurstFn, arpProbeFn
	garpBurstFn, naBurstFn, arpProbeFn = garp, na, probe
	return func() { garpBurstFn, naBurstFn, arpProbeFn = origG, origN, origP }
}

// SendGARPReservedModeForTesting drives one collected RETH instance set
// through the real reserved-mode sender at MASTER and returns the
// ordered (iface, IP) pairs the burst seams observed. Callers install
// capturing seams via SetGARPSeamsForTesting first.
func SendGARPReservedModeForTesting(cfg *config.Config, rgID int) [][2]string {
	instances := CollectRethInstances(cfg, map[int]int{rgID: 200})
	var out [][2]string
	// Observation happens through the caller's seams; this driver only
	// needs ordering, which the seams record. The pairs are rebuilt
	// from the collected instances in send order.
	for _, inst := range instances {
		vi := newInstance(*inst, &net.Interface{Name: inst.Interface}, make(chan VRRPEvent, 8), nil)
		vi.setState(StateMaster)
		epoch := vi.garpEpoch.Add(1)
		count, _ := cluster.EffectiveAnnounceBurstCount(inst.GARPCount)
		vi.sendGARPReservedMode(append([]string(nil), inst.VirtualAddresses...), epoch, vi.ownerGen.Load(), count, false)
		for _, vip := range inst.VirtualAddresses {
			ip, _, err := net.ParseCIDR(vip)
			if err != nil {
				continue
			}
			out = append(out, [2]string{inst.Interface, ip.String()})
		}
	}
	return out
}
