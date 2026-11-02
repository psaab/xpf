package cluster

import "testing"

// #18791: the restart grace changes only WHEN the owner's arm debt lands:
// never, for a replacement that arms inside the grace, or at the deadline for
// one that does not. Run against two real Managers, both schedules hold the
// one-owner property:
//   - re-armed inside the grace: no debt, so the RG never moves;
//   - not armed by the grace: debt at the deadline, so exactly one move to the
//     healthy peer and no move back when the debt later clears (non-preempt).
//
// Neither has a round with two primaries.
func TestExitGraceDebtScheduleKeepsOneOwner18791(t *testing.T) {
	type roles struct{ owner, peer bool }
	run := func(t *testing.T, debtAt, clearAt int) (transitions, dual int, last roles) {
		t.Helper()
		owner, peer := armDebtPair12164(t)
		last = roles{owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)}
		for r := 0; r < 60; r++ {
			if r == debtAt {
				owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			}
			if r == clearAt {
				owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
			}
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
			peer.handlePeerHeartbeat(owner.buildHeartbeat())
			now := roles{owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)}
			if now != last {
				transitions++
			}
			if now.owner && now.peer {
				dual++
			}
			last = now
		}
		return
	}
	t.Run("re-armed-inside-the-grace", func(t *testing.T) {
		tr, dual, last := run(t, -1, -1)
		if tr != 0 || dual != 0 || !last.owner || last.peer {
			t.Fatalf("transitions=%d dual=%d final=%+v: with no debt the RG must stay on the owner", tr, dual, last)
		}
	})
	t.Run("not-armed-by-the-grace", func(t *testing.T) {
		tr, dual, last := run(t, 10, 40)
		if tr != 1 || dual != 0 || last.owner || !last.peer {
			t.Fatalf("transitions=%d dual=%d final=%+v: want exactly one move to the peer and none back", tr, dual, last)
		}
	})
}
