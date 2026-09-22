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

import (
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

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

// DischargeColdPrimeForTesting discharges the currently owed cold-prime debt,
// if any, through the production BulkAck discharge path. It is a no-op with
// nothing owed.
//
// #10387: it exists so daemon-level drain cells can reach the PRIMED state
// without a wire round trip. The owed state is the natural post-connect
// state, and only a matching BulkAck clears it.
func (s *SessionSync) DischargeColdPrimeForTesting() {
	s.dischargeColdPrime(s.coldPrimeOwedGen())
}

// SetPendingColdPrimeForTesting publishes a generation-matching pending bulk
// acknowledgement without a wire round trip. The daemon-level #10387 cell
// uses it to prove an owed debt with a qualifying bulk keeps the demotion
// barrier path.
func (s *SessionSync) SetPendingColdPrimeForTesting() bool {
	owed := s.coldPrimeOwedGen()
	if owed == 0 {
		return false
	}
	epoch := s.bulkSendNext.Add(1)
	s.pendingBulkOwed.Store(owed)
	s.pendingBulkAckEpoch.Store(epoch)
	s.pendingBulkAckSince.Store(time.Now().UnixNano())
	return true
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

// SentInstallGenerationV4ForTesting returns the sender-side generation stamp
// for key. It is used by daemon-level admission cells to prove that the
// daemon reached QueueSessionV4; a zero result means no install was stamped.
func (s *SessionSync) SentInstallGenerationV4ForTesting(key dataplane.SessionKey) uint64 {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	return s.genSentV4[key]
}

// DeleteJournalGenerationV4ForTesting returns the newest journaled v4 delete
// generation for key, parsing the same delete wire payload used by the reader.
func (s *SessionSync) DeleteJournalGenerationV4ForTesting(key dataplane.SessionKey) (uint64, bool) {
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	for i := len(s.deleteJournal) - 1; i >= 0; i-- {
		raw := s.deleteJournal[i]
		if len(raw) < syncHeaderSize || raw[4] != syncMsgDeleteV4 {
			continue
		}
		got, gen, _, _, _, ok := parseDeleteV4Wire(raw[syncHeaderSize:])
		if ok && got == key {
			return gen, true
		}
	}
	return 0, false
}

// ApplyQueuedMessagesForTesting drains this sender's queued wire frames in
// FIFO order and feeds each frame through the receiver's real handleMessage
// path. It is intentionally a receiver seam rather than a boolean model:
// decoding, generation guards, install-table identity, and dataplane helper
// vetoes remain production behavior. The returned types are the exact wire
// order observed by the receiver.
func (s *SessionSync) ApplyQueuedMessagesForTesting(receiver *SessionSync) ([]string, error) {
	if receiver == nil {
		return nil, fmt.Errorf("receiver session sync is nil")
	}
	var types []string
	for {
		select {
		case msg := <-s.sendCh:
			if len(msg) < syncHeaderSize {
				return types, fmt.Errorf("queued message too short: %d", len(msg))
			}
			types = append(types, queuedMessageTypeForTesting(msg))
			receiver.handleMessage(nil, msg[4], msg[syncHeaderSize:])
		default:
			return types, nil
		}
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
