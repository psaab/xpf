package cluster

import (
	"encoding/binary"
	"testing"
)

// #15212: the sender-side ACK callback must fire only when the peer's
// positive ACK advances peerAppliedConfigGen, so the daemon can clear the
// unshared mark at/after the carrying generation. Stale, unsent, and
// out-of-order ACKs must not fire it.
func TestOnPeerConfigApplyAckFiresOnlyOnAdvance15212(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	var fired []uint64
	s.OnPeerConfigApplyAck = func(gen uint64) { fired = append(fired, gen) }
	ack := func(gen uint64) {
		var p [8]byte
		binary.LittleEndian.PutUint64(p[:], gen)
		s.handleMessage(nil, syncMsgConfigApplyAck, p[:])
	}
	s.lastSentConfigGen.Store(8)
	ack(7)
	ack(7) // duplicate: no advance, no second fire
	ack(9) // unsent: ignored
	ack(8)
	ack(7) // out-of-order: no regression, no fire
	if len(fired) != 2 || fired[0] != 7 || fired[1] != 8 {
		t.Fatalf("OnPeerConfigApplyAck fired %v, want [7 8]", fired)
	}
	if got := s.PeerAppliedConfigGen(); got != 8 {
		t.Fatalf("PeerAppliedConfigGen = %d, want 8", got)
	}
}
