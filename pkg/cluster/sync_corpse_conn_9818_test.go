package cluster

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// #9818: a new peer process's connection installed BEFORE any reboot evidence
// arrives is stamped with the OLD incarnation, and the later retirement evicts
// it as a corpse — leaving a dual-fabric cluster on one fabric until the peer
// redials, plus a redundant cold prime.
//
// #9636 closed the orderings where one classifier had already retired the
// reboot and the other arrived later (each consumes the other's record). The
// cells below are the shapes with no earlier classification to consume: the
// epoch had not landed, nothing was superseded, or an install after a full
// disconnect never advances.
//
// The fix is a per-connection process identity: the sender's boot id + boot
// epoch + Manager-scoped process token, carried in the capabilities exchange
// handleNewConnection already sends on every installed connection. Retirement
// evicts only connections whose announced identity is the RETIRED process's and
// keeps (re-stamps) connections that prove they are newer; a connection that
// announced nothing falls back to today's stamp rule.
//
// Every cell drives handleNewConnection and sends later frames on the STORED
// connection, exactly like the #9636 cells: handleNewConnection wraps the
// socket, so a frame handed the raw socket never matches and silently skips
// the classification under test.

var (
	// Reuse the identities used by the #9636 harness so the capability
	// advertisement and BulkStart describe the same peer process.
	incA9818 = incA9636
	incB9818 = incB9636
)

const (
	epochA9818 = 100
	epochB9818 = 101
	tokenA9818 = uint64(0x1111_2222_3333_4444)
	tokenB9818 = uint64(0x5555_6666_7777_8888)
)

// capabilitiesFrame9818 builds a syncMsgPeerCapabilities payload carrying the
// sender's boot identity: the 5-byte base (snapshot protocol, flags, sync
// wire), then the 16-byte boot id, 8-byte boot epoch, and 8-byte
// Manager-scoped process token. Unknown trailing fields are OMITTED, never
// sent as zeros — the #5084/#2170 discipline: absent means "no information",
// and an explicit zero would compare as a real incarnation.
func capabilitiesFrame9818(t *testing.T, epoch uint64, inc *bootIncarnation) []byte {
	t.Helper()
	token := tokenB9818
	if inc != nil && *inc == incA9818 {
		token = tokenA9818
	}
	return capabilitiesFrameWithToken9818(t, epoch, inc, token)
}

func capabilitiesFrameWithToken9818(t *testing.T, epoch uint64, inc *bootIncarnation, token uint64) []byte {
	t.Helper()
	p := make([]byte, 5)
	binary.LittleEndian.PutUint16(p[:2], 8)
	p[2] = localCapabilityFlags
	binary.LittleEndian.PutUint16(p[3:5], SessionSyncWireVersion)
	if inc == nil || !inc.known() {
		return p
	}
	p = append(p, (*inc)[:]...)
	if epoch == 0 {
		return p
	}
	var fields [16]byte
	binary.LittleEndian.PutUint64(fields[:8], epoch)
	binary.LittleEndian.PutUint64(fields[8:], token)
	return append(p, fields[:]...)
}

// announce9818 delivers the peer's capabilities advertisement carrying the
// given boot identity on conn, as the peer's handleNewConnection sends it on
// every installed connection.
func announce9818(t *testing.T, e *rebootEnv9636, conn net.Conn, epoch uint64, inc bootIncarnation) {
	t.Helper()
	e.s.handleMessage(conn, syncMsgPeerCapabilities, capabilitiesFrame9818(t, epoch, &inc))
}

func primedAnnouncedA9818(t *testing.T, e *rebootEnv9636, acked bool) net.Conn {
	t.Helper()
	a := e.connect(0, "A (the corpse)")
	announce9818(t, e, a, epochA9818, incA9818)
	e.prime(a, incA9818)
	if acked {
		e.s.dischargeColdPrime(e.s.coldPrimeOwedGen())
		e.s.outboundBulkAcked.Store(true)
	}
	if n := e.settleDispatches(); n != 1 {
		t.Fatalf("setup: the first connection dispatched OnPeerConnected %d times, want 1", n)
	}
	e.dispatches.Store(0)
	e.s.mu.Lock()
	e.inc0 = e.s.peerIncarnation
	e.s.mu.Unlock()
	e.gen0 = e.s.coldPrimeGen.Load()
	return a
}

// Issue row 1: A's sockets are gone (full disconnect); B installs fab1, then
// fab0; B's BulkStart lands on fab1. The switch retires A — and B's fab0,
// installed before any reboot evidence and stamped with A's incarnation, must
// survive as B's: it announced B's identity.
//
// RED on revert: without per-connection identity the switch evicts B's fab0
// as a corpse and fabric 0 holds nothing.
func TestFullDisconnectPreEvidenceConnSurvivesBulkStartSwitch_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	a := primedAnnouncedA9818(t, e, true)
	e.s.handleDisconnect(a)
	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b0, epochB9818, incB9818)
	e.prime(b1, incB9818)
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 2, dispatches: 2})
}

// Capabilities can cross fabric loops after retirement evidence. An in-flight
// frame is therefore held stale until it identifies the connection.
func TestDelayedCapabilitiesPreserveReplacementSibling_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1", false)
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.prime(b0, incB9818)
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Issue row 2: A is still on fab0; B installs fab1 before its heartbeat; the
// epoch lands; B's fab0 supersedes A. The supersession retires A — and B's
// fab1, stamped old, must survive as B's.
//
// RED on revert: fabric 1 holds nothing; B's pre-evidence connection is
// evicted as a corpse.
func TestSupersessionKeepsPreEvidenceSibling_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Issue row 3: full disconnect; B installs fab1 before its heartbeat; the
// epoch lands; B installs fab0. The epoch arm retires A — and B's fab1 must
// survive.
//
// RED on revert: fabric 1 holds nothing.
func TestEpochRetirementKeepsPreEvidenceSibling_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	a := primedAnnouncedA9818(t, e, true)
	e.s.handleDisconnect(a)
	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b0, epochB9818, incB9818)
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 2, dispatches: 2})
}

// Daemon-restart flavor of row 2: the epoch raises but the boot id is
// UNCHANGED (a daemon restart keeps it; only an OS boot changes it). B's
// pre-evidence sibling proves it is new on the epoch axis alone, and the
// agreeing boot-id axis must not overrule that.
//
// RED on revert: fabric 1 holds nothing.
func TestSupersessionKeepsPreEvidenceSiblingOnDaemonRestart_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1")
	e.s.handleMessage(b1, syncMsgPeerCapabilities,
		capabilitiesFrameWithToken9818(t, epochB9818, &incA9818, tokenB9818))
	e.src.epoch = epochB9818
	b0 := e.connect(0, "B's fabric 0")
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Same-boot/same-epoch collision control: only the Manager-scoped token
// distinguishes B from A when persistence cannot advance the ordered epoch.
func TestSupersessionKeepsSiblingOnSameBootSameEpochToken_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1")
	e.s.handleMessage(b1, syncMsgPeerCapabilities,
		capabilitiesFrameWithToken9818(t, epochA9818, &incA9818, tokenB9818))
	e.src.epoch = epochA9818
	b0 := e.connect(0, "B's fabric 0")
	e.check(rebootWant9636{advances: 1, conn0: b0, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Control: a corpse that ANNOUNCED the retired identity is still evicted on
// an epoch retirement. The keep rule must fire only for a PROVEN-newer
// identity, never for a matching one.
//
// GREEN before and after the fix: it guards the fix against over-keeping.
func TestAnnouncedCorpseStillEvictedOnEpochRetirement_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	e.src.epoch = epochB9818
	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// stamp rule and is evicted.
//
// GREEN before and after the fix.
func TestLegacyCorpseStillEvictedOnEpochRetirement_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	a := e.primedA(0, true)
	e.s.handleMessage(a, syncMsgPeerCapabilities, make([]byte, 5))
	e.src.epoch = epochB9818
	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// Control: the BulkStart switch still evicts a corpse that announced the
// retired identity.
//
// GREEN before and after the fix.
func TestAnnouncedCorpseStillEvictedOnBulkStartSwitch_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.prime(b1, incB9818)
	e.check(rebootWant9636{advances: 1, conn1: b1, owed: true, arms: 1, dispatches: 1})
}

// GREEN before and after the fix.
func TestAnnouncedCorpseStillEvictedOnSupersession_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)
	a1 := e.connect(1, "A's fabric 1")
	announce9818(t, e, a1, epochA9818, incA9818)
	b0 := e.connect(0, "B's fabric 0")
	announce9818(t, e, b0, epochB9818, incB9818)
	e.check(rebootWant9636{advances: 1, conn0: b0, owed: true, arms: 1, dispatches: 1})
}

// TestSendCapabilitiesCarriesBootID_9818 binds the SENDER wiring for the
// #9818 carrier, the way the #5084 wire test does for BulkStart: the frame is
// read off a real connection through the production write path. Deleting the
// tail from sendCapabilities leaves every receiver-side cell above green —
// they inject their own payloads — and ships a build that never emits the
// field at all.
//
// With no local epoch source wired (a bare SessionSync), the sender carries
// the boot id alone and omits the epoch it cannot know.
//
// RED on revert: the payload is the legacy 5 bytes.
func TestSendCapabilitiesCarriesBootID_9818(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)

	frames := make(chan syncFrame, 8)
	readFramesInto(peer, frames)
	go s.sendCapabilities(local)

	var got syncFrame
	select {
	case got = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("no capabilities frame was written")
	}
	if got.typ != syncMsgPeerCapabilities {
		t.Fatalf("frame type = %d, want capabilities %d", got.typ, syncMsgPeerCapabilities)
	}

	want := localBootIncarnation()
	if !want.known() {
		t.Fatalf("this node's %s could not be read, so the sender has nothing to advertise "+
			"and the #9818 attribution is inert on it. On Linux this file always exists; a build "+
			"or sandbox that hides it silently disables the guard", bootIDPath)
	}
	if len(got.payload) != 5+bootIncarnationLen {
		t.Fatalf("capabilities payload = %d bytes, want %d (5B base + 16B boot id). "+
			"A 5-byte payload means the sender never appends the field, so an upgraded "+
			"receiver sees an un-attributed peer forever and the corpse eviction keeps "+
			"eating the new process's pre-evidence connections",
			len(got.payload), 5+bootIncarnationLen)
	}
	if !bytes.Equal(got.payload[5:], want[:]) {
		t.Fatalf("capabilities tail = %x, want this node's boot incarnation %s",
			got.payload[5:], want)
	}
}

func TestCapabilityLegacyAndPartialTails_9818(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ac := &authConn{Conn: local}
	s.installConn(0, ac)

	base := make([]byte, 5)
	binary.LittleEndian.PutUint16(base[:2], 8)
	binary.LittleEndian.PutUint16(base[3:5], SessionSyncWireVersion)
	s.handleMessage(ac, syncMsgPeerCapabilities, base)
	if !ac.peerCapabilitiesSeen || ac.peerIdentity.known() {
		t.Fatal("legacy 5-byte capabilities must mark delivery without inventing identity")
	}

	bootOnly := append(append([]byte(nil), base...), incA9818[:]...)
	s.handleMessage(ac, syncMsgPeerCapabilities, bootOnly)
	if !ac.peerIdentity.boot.known() || ac.peerIdentity.epoch != 0 || ac.peerIdentity.token != 0 {
		t.Fatalf("boot-only tail decoded as %+v", ac.peerIdentity)
	}

	bootEpoch := append(append([]byte(nil), bootOnly...), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(bootEpoch[len(bootOnly):], epochA9818)
	s.handleMessage(ac, syncMsgPeerCapabilities, bootEpoch)
	if ac.peerIdentity.epoch != epochA9818 || ac.peerIdentity.token != 0 {
		t.Fatalf("boot+epoch tail decoded as %+v", ac.peerIdentity)
	}
}

// TestLocalProcessIdentitySurvivesSessionSyncRecreation_9818 ensures the
// sender-side identity belongs to the daemon manager, not one transient
// SessionSync. A comms restart may construct another SessionSync while the
// heartbeat epoch is refined; both must carry the same process identity.
func TestLocalProcessIdentitySurvivesSessionSyncRecreation_9818(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.Stop)
	firstEpoch := m.LocalBootEpoch()
	if firstEpoch != 0 {
		t.Fatalf("unstarted Manager must expose zero local epoch, got %d", firstEpoch)
	}

	first := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	first.LocalBootEpochFn = m.LocalBootEpoch
	first.LocalProcessTokenFn = m.LocalProcessToken
	firstID := first.localProcessIdentity()

	// Simulate the heartbeat persistence refinement raising the live floor after
	// the first SessionSync has sampled the process identity.
	m.bootEpoch.Store(epochA9818 + 1)

	second := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	second.LocalBootEpochFn = m.LocalBootEpoch
	second.LocalProcessTokenFn = m.LocalProcessToken
	secondID := second.localProcessIdentity()
	if secondID != firstID {
		t.Fatalf("SessionSync recreation changed process identity from %+v to %+v", firstID, secondID)
	}
}

// TestSendCapabilitiesCarriesBootEpoch_9818 binds the ordered half of the
// process identity. A boot id alone cannot distinguish a daemon restart that
// callback is wired.
func TestSendCapabilitiesCarriesBootEpoch_9818(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	const wantEpoch = uint64(0x0102_0304_0506_0708)
	s.LocalBootEpochFn = func() uint64 { return wantEpoch }

	frames := make(chan syncFrame, 8)
	readFramesInto(peer, frames)
	go s.sendCapabilities(local)

	var got syncFrame
	select {
	case got = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("no capabilities frame was written")
	}
	if got.typ != syncMsgPeerCapabilities {
		t.Fatalf("frame type = %d, want capabilities %d", got.typ, syncMsgPeerCapabilities)
	}
	if len(got.payload) != 5+bootIncarnationLen+8 {
		t.Fatalf("capabilities payload = %d bytes, want %d (5B base + 16B boot id + 8B "+
			"epoch)", len(got.payload), 5+bootIncarnationLen+8)
	}
	if gotEpoch := binary.LittleEndian.Uint64(got.payload[5+bootIncarnationLen:]); gotEpoch != wantEpoch {
		t.Fatalf("capabilities epoch = %d, want %d", gotEpoch, wantEpoch)
	}
}

func TestSendCapabilitiesCarriesProcessToken_9818(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	const wantToken = uint64(0x8899_aabb_ccdd_eeff)
	s.LocalProcessTokenFn = func() uint64 { return wantToken }
	frames := make(chan syncFrame, 1)
	readFramesInto(peer, frames)
	go s.sendCapabilities(local)

	var got syncFrame
	select {
	case got = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("no capabilities frame was written")
	}
	if len(got.payload) != 5+bootIncarnationLen+8+8 {
		t.Fatalf("capabilities payload = %d bytes, want %d with token",
			len(got.payload), 5+bootIncarnationLen+8+8)
	}
	if gotToken := binary.LittleEndian.Uint64(got.payload[5+bootIncarnationLen+8:]); gotToken != wantToken {
		t.Fatalf("capabilities token = %#x, want %#x", gotToken, wantToken)
	}
}

// TestSendCapabilitiesKeepsOneProcessIdentityAcrossReconnects_9818 guards the
// one-shot sample: heartbeat epoch refinement may raise the manager's live
// value later in this daemon, but that must not turn an ordinary reconnect
// into a second process identity.
func TestSendCapabilitiesKeepsOneProcessIdentityAcrossReconnects_9818(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	epoch := uint64(1)
	s.LocalBootEpochFn = func() uint64 { return epoch }
	frames := make(chan syncFrame, 8)
	readFramesInto(peer, frames)

	go s.sendCapabilities(local)
	var first syncFrame
	select {
	case first = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("no first capabilities frame was written")
	}
	epoch = 2
	go s.sendCapabilities(local)
	var second syncFrame
	select {
	case second = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("no reconnect capabilities frame was written")
	}
	for name, frame := range map[string]syncFrame{"first": first, "reconnect": second} {
		if len(frame.payload) != 5+bootIncarnationLen+8 {
			t.Fatalf("%s capabilities payload = %d bytes, want %d", name,
				len(frame.payload), 5+bootIncarnationLen+8)
		}
		if got := binary.LittleEndian.Uint64(frame.payload[5+bootIncarnationLen:]); got != 1 {
			t.Fatalf("%s capabilities epoch = %d, want the first sampled epoch 1", name, got)
		}
	}
}

// Same-process supersession with an unannounced keep strands s.peerIdentity:
// the post-evict scan finds only the unannounced keep and zeroes it. The keep
// then announces A, a fresh B connection fills the empty alternate slot, and
// B's BulkStart must evict the known A corpse.
//
// RED pre-fix: the B switch leaves A0 installed as a corpse.
func TestSameProcessSupersessionThenBulkStartSwitchEvictsCorpse_9818(t *testing.T) {
	e := newRebootEnv9636(t)
	primedAnnouncedA9818(t, e, true)

	a0 := e.connect(0, "A same-process supersede", false)
	e.s.mu.Lock()
	retained := e.s.peerIdentity.known()
	e.s.mu.Unlock()
	if !retained {
		t.Error("same-process supersession lost the prior known A identity")
	}
	announce9818(t, e, a0, epochA9818, incA9818)

	b1 := e.connect(1, "B's fabric 1")
	announce9818(t, e, b1, epochB9818, incB9818)
	e.prime(b1, incB9818)
	e.check(rebootWant9636{advances: 2, conn1: b1, owed: true, arms: 2, dispatches: 2})
}
