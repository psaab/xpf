package vrrp

import (
	"net"
	"testing"
	"time"
)

// TestRun_PriorityZeroResignPromotesPeerImmediately drives the real run loops
// for a priority-220 BACKUP and a lower-priority MASTER. The packet seam joins
// them, so the test observes the priority-0 advert emitted by each real
// resignation path and the peer's resulting MASTER advert without raw sockets.
//
// Both MASTER resignation paths are covered because shutdown and forced
// resignation have separate priority-0 bursts. Removing either burst, or the
// 1ms reset in handleBackupRx, leaves the peer BACKUP past this deadline.
func TestRun_PriorityZeroResignPromotesPeerImmediately(t *testing.T) {
	for _, path := range []string{"shutdown", "forced"} {
		t.Run(path, func(t *testing.T) {
			manager := NewManager()
			master := newInstance(Instance{
				Interface:         "reth10786",
				GroupID:           101,
				Priority:          200,
				Preempt:           true,
				AdvertiseInterval: 100,
				VirtualAddresses:  []string{"10.0.107.86/24"},
			}, &net.Interface{Name: "reth10786"}, manager.eventCh, nil)
			backup := newInstance(Instance{
				Interface:         "reth10786",
				GroupID:           101,
				Priority:          220,
				Preempt:           true,
				PreemptHoldTime:   60,
				AdvertiseInterval: 100,
				VirtualAddresses:  []string{"10.0.107.86/24"},
			}, &net.Interface{Name: "reth10786"}, manager.eventCh, nil)
			for _, vi := range []*vrrpInstance{master, backup} {
				vi.setLocalIP(net.IPv4(10, 0, 107, 86))
				vi.suppressGARP.Store(true)
				installFakeVIPNetlink(vi)
			}
			manager.mu.Lock()
			manager.instances = map[instanceKey]*vrrpInstance{
				{iface: "reth10786", groupID: 101}: master,
			}
			manager.mu.Unlock()

			masterAdvert := make(chan struct{}, 1)
			firstResignAdvert := make(chan time.Time, 1)
			peerMasterAdvert := make(chan time.Time, 1)
			resignAdvertCount := 0
			previousSendPacketFn := sendPacketFn
			sendPacketFn = func(sender *vrrpInstance, pkt *VRRPPacket, _ bool) error {
				if sender == master {
					if pkt.Priority == 0 {
						resignAdvertCount++
						if resignAdvertCount == 1 {
							firstResignAdvert <- time.Now()
						}
					} else {
						select {
						case masterAdvert <- struct{}{}:
						default:
						}
					}
					backup.rxCh <- pkt
				} else if sender == backup && pkt.Priority == 220 {
					select {
					case peerMasterAdvert <- time.Now():
					default:
					}
				}
				return nil
			}
			t.Cleanup(func() { sendPacketFn = previousSendPacketFn })

			go backup.run()
			go master.run()
			t.Cleanup(func() { stopPrio0RunTestInstance(t, master) })
			t.Cleanup(func() { stopPrio0RunTestInstance(t, backup) })

			// Use the same manager entry points as coordinated cluster promotion
			// and manual resignation; the peer alone is deliberately outside the
			// manager so ResignRG cannot signal both nodes.
			manager.ForceRGMaster(1)
			select {
			case <-masterAdvert:
			case <-time.After(time.Second):
				t.Fatal("source run loop did not advertise after forced promotion")
			}
			waitPrio0TestMasterPriority(t, backup, 200)
			if backup.getState() != StateBackup {
				t.Fatalf("peer state before resignation = %s, want BACKUP", backup.getState())
			}
			select {
			case <-peerMasterAdvert:
				t.Fatal("peer became MASTER before the source resigned")
			default:
			}

			var barrier *ResignBarrier
			switch path {
			case "shutdown":
				close(master.stopCh)
			case "forced":
				barrier = manager.ResignRG(1)
			}

			var resignedAt time.Time
			select {
			case resignedAt = <-firstResignAdvert:
			case <-time.After(time.Second):
				t.Fatalf("%s did not emit a priority-0 resignation advert", path)
			}
			deadline := resignedAt.Add(50 * time.Millisecond)
			select {
			case promotedAt := <-peerMasterAdvert:
				if elapsed := promotedAt.Sub(resignedAt); elapsed > 50*time.Millisecond {
					t.Fatalf("peer takeover took %v after priority-0 advert, want <50ms", elapsed)
				}
				if backup.getState() != StateMaster {
					t.Fatalf("peer emitted MASTER advert in state %s", backup.getState())
				}
			case <-time.After(time.Until(deadline)):
				t.Fatalf("peer stayed %s for 50ms after priority-0 resignation", backup.getState())
			}

			if barrier != nil {
				select {
				case <-barrier.Done():
				case <-time.After(time.Second):
					t.Fatal("forced resignation did not finish releasing the source")
				}
				if err := barrier.Err(); err != nil {
					t.Fatalf("forced resignation barrier error: %v", err)
				}
			} else {
				select {
				case <-master.stopped:
				case <-time.After(time.Second):
					t.Fatal("shutdown resignation did not stop the source run loop")
				}
			}
			if resignAdvertCount == 0 {
				t.Fatal("source resignation emitted no priority-0 advert")
			}
		})
	}
}

func waitPrio0TestMasterPriority(t *testing.T, vi *vrrpInstance, priority int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		vi.mu.RLock()
		got := vi.lastMasterPriority
		vi.mu.RUnlock()
		if got == priority {
			return
		}
		time.Sleep(time.Millisecond)
	}
	vi.mu.RLock()
	got := vi.lastMasterPriority
	vi.mu.RUnlock()
	t.Fatalf("peer learned master priority %d, want %d", got, priority)
}

func stopPrio0RunTestInstance(t *testing.T, vi *vrrpInstance) {
	t.Helper()
	select {
	case <-vi.stopCh:
	default:
		close(vi.stopCh)
	}
	select {
	case <-vi.stopped:
	case <-time.After(time.Second):
		t.Errorf("run loop for %s did not stop", vi.key())
	}
}
