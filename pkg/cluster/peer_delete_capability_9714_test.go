package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9714 F5. An upgraded node is already safe from a peer's deletes — its own helper
// refuses one that would tear down a live local session. These cells cover the
// REMAINING direction: the deletes this node SENDS to a peer whose helper cannot
// refuse anything, which under a dual-primary split would destroy a flow that peer
// is still forwarding.
//
// The SessionSync here is deliberately unconnected, so queueMessage fails and a
// delete that is NOT withheld lands in the delete journal. "Withheld" and "sent"
// are therefore an empty versus non-empty journal, with no socket in the fixture.

func capabilityFrame9714(t *testing.T, flags ...uint8) []byte {
	t.Helper()
	p := make([]byte, 2)
	binary.LittleEndian.PutUint16(p, 8) // any real snapshot protocol version; 0 means "never advertised"
	if len(flags) > 0 {
		p = append(p, flags[0])
	}
	return p
}

func key9714() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 5}, DstIP: [4]byte{172, 16, 80, 200},
		SrcPort: 5001, DstPort: 443, Protocol: 6,
	}
}

func journalLen9714(s *SessionSync) int {
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	return len(s.deleteJournal)
}

// THE ACCEPTANCE CRITERION: a peer that did not advertise capFlagPeerDeleteOwnership
// applies our deletes unconditionally, so it must not be sent one.
func TestADeleteIsWithheldFromAPeerWithoutDeleteOwnership9714(t *testing.T) {
	s := &SessionSync{}
	// A build predating v16: version only, no flags byte.
	s.handleMessage(nil, syncMsgPeerCapabilities, capabilityFrame9714(t))
	if !s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: the capability frame did not land, so the gate cannot fire and the " +
			"assertions below would pass for the wrong reason")
	}
	if s.PeerDeleteOwnershipCapable() {
		t.Fatal("FIXTURE: a 2-byte frame must not read as delete-ownership capable")
	}

	s.QueueDeleteV4(key9714())

	if got := journalLen9714(s); got != 0 {
		t.Errorf("%d deletes reached the peer path; a peer without capFlagPeerDeleteOwnership applies them "+
			"unconditionally and would tear down a flow it is still forwarding (#9714 F5)", got)
	}
	if got := s.stats.DeletesSuppressedPeerIncapable.Load(); got != 1 {
		t.Errorf("DeletesSuppressedPeerIncapable = %d, want 1: the peer now retains sessions this node has "+
			"closed, and a suppression nobody can count is a leak nobody can see", got)
	}
}

// The CONTROL that gives the cell above its meaning: a CAPABLE peer still gets its
// deletes. Without this, a gate that suppressed everything would pass just as well.
func TestACapablePeerStillReceivesDeletes9714(t *testing.T) {
	s := &SessionSync{}
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if !s.PeerDeleteOwnershipCapable() {
		t.Fatal("FIXTURE: the advertised bit did not decode")
	}

	s.QueueDeleteV4(key9714())

	if got := journalLen9714(s); got != 1 {
		t.Errorf("journalled %d deletes, want 1: a peer advertising capFlagPeerDeleteOwnership must be sent "+
			"deletes exactly as before (#9714 F5)", got)
	}
	if got := s.stats.DeletesSuppressedPeerIncapable.Load(); got != 0 {
		t.Errorf("DeletesSuppressedPeerIncapable = %d, want 0 for a capable peer", got)
	}
}

// UNKNOWN IS NOT INCAPABLE — the cell that keeps this gate from becoming an
// every-reconnect regression.
//
// peerCapabilityFlags reads 0 both for a genuinely old peer AND for the window
// before this incarnation's advertisement lands, and the flags are CLEARED on every
// full disconnect. So a gate written the obvious way, `if
// !PeerDeleteOwnershipCapable()`, passes both cells above and then silently discards
// deletes on every reconnect of a perfectly matched pair. Only the paired
// peerCapabilitiesLearned check separates "the peer said it cannot" from "the peer
// has not said yet", and this cell is what holds that pairing in place.
func TestADeleteIsNotWithheldBeforeCapabilitiesAreLearned9714(t *testing.T) {
	s := &SessionSync{}
	if s.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: a fresh SessionSync must not claim it has learned the peer's capabilities")
	}
	if s.PeerDeleteOwnershipCapable() {
		t.Fatal("FIXTURE: a fresh SessionSync must not read as capable")
	}

	s.QueueDeleteV4(key9714())

	if got := journalLen9714(s); got != 1 {
		t.Errorf("journalled %d deletes, want 1: before the peer has advertised anything, behaviour must be "+
			"exactly pre-#9714. Suppressing on an unknown capability discards deletes on every reconnect, "+
			"turning a mixed-version safeguard into a same-version regression (#9714 F5)", got)
	}
	if got := s.stats.DeletesSuppressedPeerIncapable.Load(); got != 0 {
		t.Errorf("DeletesSuppressedPeerIncapable = %d, want 0 while the capability is UNKNOWN", got)
	}
}

// The suppression is not family-scoped.
func TestAV6DeleteIsWithheldFromAnIncapablePeer9714(t *testing.T) {
	s := &SessionSync{}
	s.handleMessage(nil, syncMsgPeerCapabilities, capabilityFrame9714(t))

	s.QueueDeleteV6(dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01}, Protocol: 6, SrcPort: 5001, DstPort: 443,
	})

	if got := journalLen9714(s); got != 0 {
		t.Errorf("%d v6 deletes reached an incapable peer: the hazard is the peer's unconditional apply, "+
			"which has nothing to do with address family (#9714 F5)", got)
	}
}

// This build must actually advertise the bit, or no peer can ever gate on it — and
// a fully-upgraded cluster would suppress deletes forever, each node believing the
// other cannot honour them. Binds the constant to the flag rather than assuming
// they agree.
func TestThisBuildAdvertisesPeerDeleteOwnership9714(t *testing.T) {
	t.Parallel()
	if localCapabilityFlags&capFlagPeerDeleteOwnership == 0 {
		t.Fatal("localCapabilityFlags does not set capFlagPeerDeleteOwnership, so this node tells its peer " +
			"it cannot honour a peer-marked delete, and two upgraded nodes would withhold deletes from " +
			"each other permanently")
	}
	if capFlagPeerDeleteOwnership == capFlagFenceAck {
		t.Fatal("capFlagPeerDeleteOwnership collides with capFlagFenceAck: one bit cannot carry two " +
			"capabilities, and the collision would make each imply the other")
	}
	if localCapabilityFlags&capFlagFenceAck == 0 {
		t.Fatal("adding capFlagPeerDeleteOwnership dropped capFlagFenceAck from localCapabilityFlags")
	}
}
