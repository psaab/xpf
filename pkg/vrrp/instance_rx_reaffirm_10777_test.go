package vrrp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

func captureReaffirmBursts10777(t *testing.T) <-chan string {
	t.Helper()
	bursts := make(chan string, 8)
	origGARP, origNA, origProbe := garpBurstFn, naBurstFn, arpProbeFn
	garpBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error {
		bursts <- "GARP"
		return nil
	}
	naBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error {
		bursts <- "NA"
		return nil
	}
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { garpBurstFn, naBurstFn, arpProbeFn = origGARP, origNA, origProbe })
	return bursts
}

// RED-ON-REVERT: without the winner-side reaffirm, both positive cases leave
// garpEpoch unchanged and produce no GARP/NA frames; the state-only assertion
// would not catch the stale neighbor mapping.
func TestHandleMasterRx_ReaffirmsAfterOutrankingClaimant_10777(t *testing.T) {
	for _, tc := range []struct {
		name       string
		peerPri    uint8
		peerIP     net.IP
		localIP    net.IP
		wantMaster bool
		wantBurst  bool
	}{
		{
			name:       "lower-priority claimant",
			peerPri:    100,
			peerIP:     net.IPv4(10, 0, 0, 2),
			localIP:    net.IPv4(10, 0, 0, 1),
			wantMaster: true,
			wantBurst:  true,
		},
		{
			name:       "equal-priority winner",
			peerPri:    200,
			peerIP:     net.IPv4(10, 0, 0, 1),
			localIP:    net.IPv4(10, 0, 0, 2),
			wantMaster: true,
			wantBurst:  true,
		},
		{
			name:       "equal-priority loser",
			peerPri:    200,
			peerIP:     net.IPv4(10, 0, 0, 3),
			localIP:    net.IPv4(10, 0, 0, 2),
			wantMaster: false,
			wantBurst:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bursts := captureReaffirmBursts10777(t)
			vi := newInstance(Instance{
				Interface:        "xpf-test-nonexistent0",
				GroupID:          102,
				Priority:         200,
				VirtualAddresses: []string{"10.0.0.100/24", "fd00::100/64"},
			}, &net.Interface{Name: "xpf-test-nonexistent0"}, make(chan VRRPEvent, 8), nil)
			vi.setLocalIP(tc.localIP)
			vi.setState(StateMaster)
			vi.lastGARPOwnerGen.Store(vi.ownerGen.Load())
			// Model the burst emitted on the existing MASTER tenure. The winner's
			// reaffirm must bypass this recent-send dampener after the claimant's
			// per-node MAC has poisoned neighbor caches.
			vi.garpEpoch.Store(1)
			vi.lastGARPEpoch.Store(1)
			vi.lastGARPTime.Store(time.Now().UnixNano())

			masterDown := time.NewTimer(time.Hour)
			defer masterDown.Stop()
			advert := time.NewTimer(time.Hour)
			defer advert.Stop()
			pkt := &VRRPPacket{Priority: tc.peerPri, SrcIP: tc.peerIP}
			vi.handleMasterRx(pkt, masterDown, advert)

			if got := vi.getState() == StateMaster; got != tc.wantMaster {
				t.Fatalf("MASTER state = %v, want %v", got, tc.wantMaster)
			}
			if tc.wantBurst {
				if got := vi.garpEpoch.Load(); got != 2 {
					t.Fatalf("GARP epoch after first winner reaffirm = %d, want 2", got)
				}
				// Repeated adverts from the same brief claimant must not trigger a
				// burst storm; the cooldown is independent of GARP's send dampener.
				vi.handleMasterRx(pkt, masterDown, advert)
				if got := vi.garpEpoch.Load(); got != 2 {
					t.Fatalf("GARP epoch after repeated claimant advert = %d, want 2", got)
				}
				seen := make(map[string]bool, 2)
				timer := time.NewTimer(time.Second)
				defer timer.Stop()
				for len(seen) < 2 {
					select {
					case burst := <-bursts:
						if seen[burst] {
							t.Fatalf("duplicate %s reaffirm burst", burst)
						}
						seen[burst] = true
					case <-timer.C:
						t.Fatalf("timed out waiting for both GARP and NA; got %v", seen)
					}
				}
				if !seen["GARP"] || !seen["NA"] {
					t.Fatalf("neighbor refreshes = %v, want both GARP and NA", seen)
				}
				if len(bursts) != 0 {
					t.Fatalf("unexpected duplicate refreshes: %d", len(bursts))
				}
			} else if got := vi.garpEpoch.Load(); got != 1 {
				t.Fatalf("GARP epoch after losing tie-break = %d, want unchanged 1", got)
			}
		})
	}
}
