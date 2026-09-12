// Test-only helpers for pkg/cluster. They live in the PRODUCTION package so
// external packages (pkg/daemon's HA cells) can drive them without
// internal-export tricks — the same arrangement as pkg/dhcp/test_seams.go.
// Not for production callers.
//
// They live in their OWN FILE because sync.go sits at the 2000-LOC modularity
// floor (pkg/refactoraudit): adding this seam there crossed it. A new file is
// the honest answer rather than an entry in docs/refactoring-audit-accepted.txt
// — the guard was right that sync.go should not keep growing, and a test seam
// is the least load-bearing thing in it. Put the next one here too.

package cluster

import "time"

// SetPeerIPsecSAsForTesting installs the peer's advertised IPsec
// connection-name set without a wire round trip, mirroring
// SetPeerDHCPLeasesForTesting.
//
// #9139: it exists so the TAKEOVER LEGS can be driven. Both halves of that fix
// are wiring — an advertise gate and a per-RG re-initiate call site — and a
// unit test of the filter function alone leaves them unguarded, which is
// exactly how the defect survived: the filter was never the broken part.
func (s *SessionSync) SetPeerIPsecSAsForTesting(names []string) {
	s.peerIPsecSAsMu.Lock()
	defer s.peerIPsecSAsMu.Unlock()
	s.peerIPsecSAs = append([]string(nil), names...)
}

// SetConnectedForTesting sets the connected flag every queue producer checks,
// without a peer. With no Start there is no writer either, so the send queue
// holds exactly what the producers under test enqueued (#9767).
func (s *SessionSync) SetConnectedForTesting(connected bool) {
	s.stats.Connected.Store(connected)
}

// FillSendQueueForTesting fills the send queue with placeholder messages and
// returns how many it added.
func (s *SessionSync) FillSendQueueForTesting() int {
	n := 0
	for {
		select {
		case s.sendCh <- nil:
			n++
		default:
			return n
		}
	}
}

// TakeQueuedMessageTypeForTesting removes the oldest queued message, waiting up
// to wait for one, and names its type: "session_v4", "session_v6",
// "delete_v4", "delete_v6", "filler" for a FillSendQueueForTesting placeholder,
// or "other". ok is false when the queue stayed empty.
func (s *SessionSync) TakeQueuedMessageTypeForTesting(wait time.Duration) (typ string, ok bool) {
	select {
	case msg := <-s.sendCh:
		return queuedMessageTypeForTesting(msg), true
	default:
	}
	if wait <= 0 {
		return "", false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case msg := <-s.sendCh:
		return queuedMessageTypeForTesting(msg), true
	case <-timer.C:
		return "", false
	}
}

func queuedMessageTypeForTesting(msg []byte) string {
	if msg == nil {
		return "filler"
	}
	if len(msg) < syncHeaderSize {
		return "other"
	}
	switch msg[4] {
	case syncMsgSessionV4:
		return "session_v4"
	case syncMsgSessionV6:
		return "session_v6"
	case syncMsgDeleteV4:
		return "delete_v4"
	case syncMsgDeleteV6:
		return "delete_v6"
	}
	return "other"
}
