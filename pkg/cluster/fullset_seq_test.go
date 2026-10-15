package cluster

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #5706: IPsec and DHCP full-set state sync now carries a per-peer-incarnation
// + per-type monotonic sequence so a stale full-set reordered across the
// redundant fabric receiveLoops cannot regress the standby's held set. These
// tests are FAIL-ON-REVERT: removing the ordering guard lets the stale set
// overwrite the newer one and turns the reorder assertions RED.

// TestFullSetSeqCodecRoundTrip pins the wire trailer: a stamped payload round
// trips, and a legacy payload (no trailer) decodes to the accept-always (0,0)
// sentinel with the whole payload preserved as the base.
func TestFullSetSeqCodecRoundTrip(t *testing.T) {
	base := []byte("some-full-set-body")
	frame := appendFullSetSeq(base, 0x1122334455667788, 42)
	if len(frame) != len(base)+fullSetSeqTrailerLen {
		t.Fatalf("frame len %d, want %d", len(frame), len(base)+fullSetSeqTrailerLen)
	}
	gotBase, inc, seq := stripFullSetSeq(frame)
	if !bytes.Equal(gotBase, base) {
		t.Fatalf("base round trip: got %q, want %q", gotBase, base)
	}
	if inc != 0x1122334455667788 || seq != 42 {
		t.Fatalf("trailer round trip: got (inc=%#x, seq=%d), want (0x1122334455667788, 42)", inc, seq)
	}

	// Legacy payload: no trailer -> whole payload is base, (0,0) sentinel.
	legacy := []byte("legacy-body-no-trailer")
	gotBase, inc, seq = stripFullSetSeq(legacy)
	if !bytes.Equal(gotBase, legacy) || inc != 0 || seq != 0 {
		t.Fatalf("legacy decode: got (base=%q, inc=%d, seq=%d), want (%q, 0, 0)", gotBase, inc, seq, legacy)
	}

	// A short payload (< trailer length) is always legacy.
	short := []byte{1, 2, 3}
	gotBase, inc, seq = stripFullSetSeq(short)
	if !bytes.Equal(gotBase, short) || inc != 0 || seq != 0 {
		t.Fatalf("short decode: got (base=%v, inc=%d, seq=%d), want (%v, 0, 0)", gotBase, inc, seq, short)
	}
}

// TestFullSetSeqDHCPTrailerIgnoredByOldDecoder proves backward compatibility in
// the new-sender -> old-receiver direction for DHCP: the pre-#5706 lease
// decoder reads exactly its record count and IGNORES the trailing (incarnation,
// seq), so a stamped frame decodes to the same lease set an old node would see.
func TestFullSetSeqDHCPTrailerIgnoredByOldDecoder(t *testing.T) {
	leases := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:01", Remaining: 3600, ValidLife: 3600},
		{Family: 4, Address: "10.0.0.6", HWAddress: "aa:bb:cc:dd:ee:02", Remaining: 3600, ValidLife: 3600},
	}
	stamped := appendFullSetSeq(encodeDHCPLeasePayload(leases), 999, 7)
	// An OLD receiver calls decodeDHCPLeasePayload on the WHOLE frame (it does
	// not know to strip a trailer). It must still recover exactly the 2 leases.
	got, okDecode := decodeDHCPLeasePayload(stamped)
	if !okDecode {
		t.Fatal("a well-formed stamped frame must decode completely (#7175)")
	}
	if len(got) != 2 {
		t.Fatalf("old decoder on stamped DHCP frame: got %d leases, want 2 (trailer must be ignored)", len(got))
	}
	if got[0].Address != "10.0.0.5" || got[1].Address != "10.0.0.6" {
		t.Fatalf("old decoder recovered wrong leases: %+v", got)
	}
}

// TestFullSetSeqGuardAdmit unit-tests the receiver high-water logic directly.
func TestFullSetSeqGuardAdmit(t *testing.T) {
	var g fullSetSeqGuard

	// First stamped set is admitted and advances the mark.
	if !g.admit(5, 1) {
		t.Fatal("first (5,1) must be admitted")
	}
	// Same pair replayed is NOT strictly newer -> rejected.
	if g.admit(5, 1) {
		t.Fatal("replay (5,1) must be rejected")
	}
	// Strictly-newer seq in the same incarnation -> admitted.
	if !g.admit(5, 2) {
		t.Fatal("(5,2) must be admitted after (5,1)")
	}
	// Reordered older seq -> rejected (the core regression guard).
	if g.admit(5, 1) {
		t.Fatal("reordered older (5,1) must be rejected after (5,2)")
	}
	// A higher incarnation ALWAYS supersedes, even with a lower seq (peer
	// restart draws a fresh epoch and restarts its counter).
	if !g.admit(6, 1) {
		t.Fatal("higher incarnation (6,1) must supersede (5,2)")
	}
	// A lower incarnation is stale -> rejected (no reset happened).
	if g.admit(4, 100) {
		t.Fatal("lower incarnation (4,100) must be rejected")
	}

	// Legacy (0,0) is accept-always and must NOT advance the mark: a real
	// stamped set at the current mark stays rejected afterwards.
	if !g.admit(0, 0) {
		t.Fatal("legacy (0,0) must be accept-always")
	}
	if g.admit(6, 1) {
		t.Fatal("legacy admit must not advance the mark: (6,1) still stale")
	}

	// reset() (peer bulk re-prime) re-admits a LOWER incarnation — the
	// OS-rebooted-peer case.
	g.reset()
	if !g.admit(3, 1) {
		t.Fatal("after reset, a lower incarnation (3,1) must be re-admitted")
	}
}

// TestIPsecSAOutOfOrderRejected is the IPsec FAIL-ON-REVERT: a newer full-set is
// applied, a reordered OLDER full-set is rejected (does not regress the held
// set), and a still-newer set applies. Reverting the guard lets the stale set
// overwrite the newer one -> RED.
func TestIPsecSAOutOfOrderRejected(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var lastApplied []string
	ss.OnIPsecSAReceived = func(names []string) { lastApplied = names }

	const epoch = uint64(1000)
	recv := func(seq uint64, names []string) {
		ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload(names), epoch, seq))
	}

	// Newer set (seq=2) is applied.
	recv(2, []string{"vpn-a", "vpn-b"})
	if got := ss.PeerIPsecSAs(); len(got) != 2 || got[0] != "vpn-a" || got[1] != "vpn-b" {
		t.Fatalf("seq=2 set must apply: got %v", got)
	}

	// Reordered OLDER set (seq=1) must NOT overwrite the newer held set.
	recv(1, []string{"stale-vpn"})
	if got := ss.PeerIPsecSAs(); len(got) != 2 || got[0] != "vpn-a" || got[1] != "vpn-b" {
		t.Fatalf("reordered seq=1 must be rejected, held set must stay [vpn-a vpn-b]: got %v", got)
	}
	if n := ss.Stats().IPsecSAStaleIgnored; n != 1 {
		t.Fatalf("IPsecSAStaleIgnored = %d, want 1", n)
	}
	// The apply callback must not have fired for the rejected set.
	if len(lastApplied) != 2 {
		t.Fatalf("OnIPsecSAReceived must not fire for a rejected set: last applied %v", lastApplied)
	}

	// A still-newer set (seq=3) applies.
	recv(3, []string{"vpn-c"})
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-c" {
		t.Fatalf("seq=3 set must apply: got %v", got)
	}
}

// TestIPsecSAMalformedFrameDoesNotPoisonSeq13541 is the #13541 regression:
// a malformed frame must not advance the high-water mark. The dual-fabric
// twin carrying the same (incarnation, seq) well-formed must still apply;
// a well-formed replay of that pair must still drop as duplicate.
func TestIPsecSAMalformedFrameDoesNotPoisonSeq13541(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var applied [][]string
	ss.OnIPsecSAReceived = func(names []string) {
		applied = append(applied, append([]string(nil), names...))
	}
	const epoch = uint64(3000)
	recv := func(seq uint64, payload []byte) {
		ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(payload, epoch, seq))
	}
	recv(1, encodeIPsecSAPayload([]string{"vpn-a"}))
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-a" {
		t.Fatalf("setup seq=1 must apply: got %v", got)
	}
	huge := make([]byte, 0, 2*(maxIPsecSANames+1))
	for i := 0; i <= maxIPsecSANames; i++ {
		huge = append(huge, 'a', '\n')
	}
	recv(2, huge)
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-a" {
		t.Fatalf("malformed seq=2 must retain held set: got %v", got)
	}
	// The well-formed dual-fabric twin at the SAME seq must apply.
	recv(2, encodeIPsecSAPayload([]string{"vpn-b", "vpn-c"}))
	if got := ss.PeerIPsecSAs(); len(got) != 2 || got[0] != "vpn-b" || got[1] != "vpn-c" {
		t.Fatalf("well-formed seq=2 twin must apply after malformed frame poisoned the guard: got %v", got)
	}
	if len(applied) != 2 {
		t.Fatalf("callback must fire only for the two good sets, got %v", applied)
	}
	// A well-formed replay at seq=2 is a duplicate and must drop.
	recv(2, encodeIPsecSAPayload([]string{"vpn-b", "vpn-c"}))
	if n := ss.Stats().IPsecSAStaleIgnored; n != 1 {
		t.Fatalf("well-formed replay must count as stale: IPsecSAStaleIgnored=%d want 1", n)
	}
	if len(applied) != 2 {
		t.Fatalf("replay must not fire callback: got %v", applied)
	}
}

// TestDHCPLeaseOutOfOrderRejected is the DHCP FAIL-ON-REVERT plus PER-TYPE /
// PER-FAMILY independence: a reordered older v4 set is rejected, while an
// independent v6 stream and the IPsec stream are NOT gated by the v4 high-water.
func TestDHCPLeaseOutOfOrderRejected(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var mu sync.Mutex
	applied := map[int]int{} // family -> last-applied lease count
	ss.OnDHCPLeasesReceived = func(family int, leases []dhcpserver.SyncLease) {
		mu.Lock()
		applied[family] = len(leases)
		mu.Unlock()
	}
	appliedCount := func(family int) int {
		mu.Lock()
		defer mu.Unlock()
		return applied[family]
	}

	const epoch = uint64(2000)
	v4 := func(seq uint64, leases []dhcpserver.SyncLease) {
		ss.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(encodeDHCPLeasePayload(leases), epoch, seq))
	}
	v6 := func(seq uint64, leases []dhcpserver.SyncLease) {
		ss.handleMessage(nil, syncMsgDHCPLeaseV6, appendFullSetSeq(encodeDHCPLeasePayload(leases), epoch, seq))
	}

	twoV4 := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:01", Remaining: 3600, ValidLife: 3600},
		{Family: 4, Address: "10.0.0.6", HWAddress: "aa:bb:cc:dd:ee:02", Remaining: 3600, ValidLife: 3600},
	}
	oneV6 := []dhcpserver.SyncLease{
		{Family: 6, Address: "2001:db8::5", DUID: "00:01:02", LeaseType: "IA_NA", Remaining: 3600, ValidLife: 3600},
	}

	// Newer v4 set (seq=2) applies.
	v4(2, twoV4)
	if c := appliedCount(4); c != 2 {
		t.Fatalf("v4 seq=2 must apply 2 leases, got %d", c)
	}

	// Reordered OLDER v4 set (seq=1, empty) must be rejected — the held set
	// must NOT regress to empty.
	v4(1, nil)
	if c := appliedCount(4); c != 2 {
		t.Fatalf("reordered v4 seq=1 (empty) must be rejected, last applied count must stay 2, got %d", c)
	}
	if n := ss.Stats().DHCPLeasesStaleIgnored; n != 1 {
		t.Fatalf("DHCPLeasesStaleIgnored = %d, want 1", n)
	}
	if got := ss.PeerDHCPLeases4(); len(got) != 2 {
		t.Fatalf("held v4 lease set must stay 2 after a rejected reorder, got %d", len(got))
	}

	// PER-FAMILY independence: v6 seq=1 must apply even though v4 is at seq=2.
	v6(1, oneV6)
	if c := appliedCount(6); c != 1 {
		t.Fatalf("v6 seq=1 must apply independently of the v4 high-water, got %d", c)
	}

	// PER-TYPE independence: an IPsec seq=1 must apply even though DHCP streams
	// are at higher marks.
	var ipsecApplied []string
	ss.OnIPsecSAReceived = func(names []string) { ipsecApplied = names }
	ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-a"}), epoch, 1))
	if len(ipsecApplied) != 1 || ipsecApplied[0] != "vpn-a" {
		t.Fatalf("IPsec seq=1 must apply independently of the DHCP high-water, got %v", ipsecApplied)
	}
}

// TestFullSetSeqLegacyPeerAccepted proves the mixed-version compat path: a
// legacy peer (no trailer, decoded as (0,0)) is accept-always, so its updates
// are applied in receive order exactly as before #5706 — an old peer is never
// wrongly refused.
func TestFullSetSeqLegacyPeerAccepted(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Legacy frames carry the bare payload with NO trailer.
	ss.handleMessage(nil, syncMsgIPsecSA, encodeIPsecSAPayload([]string{"vpn-a", "vpn-b"}))
	if got := ss.PeerIPsecSAs(); len(got) != 2 {
		t.Fatalf("legacy set must apply, got %v", got)
	}
	// A second legacy frame is also applied (accept-always, no high-water gate).
	ss.handleMessage(nil, syncMsgIPsecSA, encodeIPsecSAPayload([]string{"vpn-c"}))
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-c" {
		t.Fatalf("second legacy set must apply, got %v", got)
	}
	if n := ss.Stats().IPsecSAStaleIgnored; n != 0 {
		t.Fatalf("legacy peer must never be refused as stale, IPsecSAStaleIgnored=%d", n)
	}
}

// TestFullSetSeqReconnectResetReadmits proves resetRecvGen (a peer bulk
// re-prime, fired on reconnect) clears the full-set high-water so an
// OS-rebooted peer whose monotonic incarnation restarts LOWER is re-accepted
// rather than stranded on the pre-reboot set.
func TestFullSetSeqReconnectResetReadmits(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Boot 1: high incarnation.
	ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-a"}), 9000, 5))
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-a" {
		t.Fatalf("boot-1 set must apply, got %v", got)
	}

	// Without a reset, a LOWER incarnation would be refused as stale.
	ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-reboot"}), 100, 1))
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-a" {
		t.Fatalf("pre-reset lower incarnation must be refused, got %v", got)
	}

	// Peer bulk re-prime resets the high-water; the rebooted peer's fresh set
	// (lower incarnation) is now admitted.
	ss.resetRecvGen()
	ss.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-reboot"}), 100, 1))
	if got := ss.PeerIPsecSAs(); len(got) != 1 || got[0] != "vpn-reboot" {
		t.Fatalf("after reset, rebooted peer's lower-incarnation set must apply, got %v", got)
	}
}

// TestIPsecFullSetDelimOldDecoderRecoversAllNames is the #5706 review-fold
// FAIL-ON-REVERT for the new-sender -> OLD-receiver direction. A NEW sender
// inserts a '\n' delimiter between the SA name list and the trailer
// (appendIPsecFullSetSeq). An OLD pre-#5706 receiver has no stripFullSetSeq: it
// newline-splits the WHOLE frame. Every REAL connection name must decode
// cleanly — in particular the LAST name must NOT be fused with the trailer
// bytes. Reverting appendIPsecFullSetSeq to the bare appendFullSetSeq glues the
// trailer onto "vpn-gw2", so got[1] != "vpn-gw2" -> RED.
func TestIPsecFullSetDelimOldDecoderRecoversAllNames(t *testing.T) {
	names := []string{"vpn-gw1", "vpn-gw2"}
	// inc/seq deliberately avoid 0x0A bytes so the reverted (fused) frame splits
	// into exactly [vpn-gw1, "vpn-gw2"+trailer], making the fusion unambiguous.
	frame := appendIPsecFullSetSeq(encodeIPsecSAPayload(names), 0x1122334455667788, 42)

	// OLD receiver: decode the whole frame with NO trailer strip.
	got, _ := decodeIPsecSAPayload(frame)
	if len(got) < 2 {
		t.Fatalf("old decoder must recover both real names, got %v", got)
	}
	if got[0] != "vpn-gw1" || got[1] != "vpn-gw2" {
		t.Fatalf("old decoder fused a real SA name with the trailer: got %v, want first two [vpn-gw1 vpn-gw2]", got)
	}
	// The trailer becomes one-or-more SEPARATE trailing elements, never a real
	// name — assert no real name reappears past the two we sent.
	for i, n := range got {
		if i >= len(names) && (n == "vpn-gw1" || n == "vpn-gw2") {
			t.Fatalf("a real SA name reappeared as a trailer element (fusion/duplication): %v", got)
		}
	}
}

// TestIPsecFullSetDelimNewRoundTripExact pins the new->new SYMMETRY: the sender
// inserts the delimiter before the trailer and the receiver removes BOTH the
// trailer (stripFullSetSeq) and the delimiter (stripIPsecFullSetDelim), so the
// decoded name list is EXACTLY the sent names with no trailing empty name, and
// the (incarnation, seq) round-trips. This guards the byte-exact new->new
// property independent of decodeIPsecSAPayload's empty-name filtering.
func TestIPsecFullSetDelimNewRoundTripExact(t *testing.T) {
	names := []string{"vpn-gw1", "vpn-gw2"}
	frame := appendIPsecFullSetSeq(encodeIPsecSAPayload(names), 7777, 9)

	base, inc, seq := stripFullSetSeq(frame)
	if inc != 7777 || seq != 9 {
		t.Fatalf("trailer round trip: got (inc=%d, seq=%d), want (7777, 9)", inc, seq)
	}
	// The sender must have inserted the delimiter between the names and trailer.
	if n := len(base); n == 0 || base[n-1] != ipsecFullSetDelim {
		t.Fatalf("new sender must insert the IPsec trailer delimiter before the trailer; base=%q", base)
	}
	stripped := stripIPsecFullSetDelim(base)
	if n := len(stripped); n > 0 && stripped[n-1] == ipsecFullSetDelim {
		t.Fatalf("stripIPsecFullSetDelim must remove the trailing delimiter; stripped=%q", stripped)
	}
	got, _ := decodeIPsecSAPayload(stripped)
	if len(got) != 2 || got[0] != "vpn-gw1" || got[1] != "vpn-gw2" {
		t.Fatalf("new->new roundtrip must decode EXACTLY [vpn-gw1 vpn-gw2] with no trailing empty name, got %v (len %d)", got, len(got))
	}

	// An empty name set stays the bare trailer (no delimiter, no last name to
	// protect) and round-trips to no names.
	emptyFrame := appendIPsecFullSetSeq(encodeIPsecSAPayload(nil), 1, 1)
	eBase, _, _ := stripFullSetSeq(emptyFrame)
	if got, _ := decodeIPsecSAPayload(stripIPsecFullSetDelim(eBase)); len(got) != 0 {
		t.Fatalf("empty IPsec set must round-trip to no names, got %v", got)
	}
}

// TestIPsecFullSetDelimReceiveEndToEnd drives a real new-sender frame through
// the receiver's handleMessage path and asserts the held set is exactly the
// sent names (no bogus trailing name from the delimiter or trailer).
func TestIPsecFullSetDelimReceiveEndToEnd(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var applied []string
	ss.OnIPsecSAReceived = func(nn []string) { applied = nn }

	ss.handleMessage(nil, syncMsgIPsecSA,
		appendIPsecFullSetSeq(encodeIPsecSAPayload([]string{"vpn-gw1", "vpn-gw2"}), 5000, 3))

	if got := ss.PeerIPsecSAs(); len(got) != 2 || got[0] != "vpn-gw1" || got[1] != "vpn-gw2" {
		t.Fatalf("receiver must decode a delimited new-sender frame to exactly [vpn-gw1 vpn-gw2], got %v", got)
	}
	if len(applied) != 2 || applied[1] != "vpn-gw2" {
		t.Fatalf("OnIPsecSAReceived must see exactly the sent names, got %v", applied)
	}
}

// TestFullSetSeqDHCPBaseEndingInMagicSafe is reviewer Finding 3: lock the
// steady-state both-new DHCP invariant that the sender appends EXACTLY ONE
// trailer and the receiver strips EXACTLY ONE, even when the encoded lease base
// coincidentally ends in the fullSetSeqMagic. The strip peels only the real
// appended trailer (its magic sits at [n-24:n-16]); a legacy frame that merely
// ends in the magic (final 8 bytes) is not mistaken for a stamped frame.
func TestFullSetSeqDHCPBaseEndingInMagicSafe(t *testing.T) {
	leases := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.5", HWAddress: "aa:bb:cc:dd:ee:01", Remaining: 3600, ValidLife: 3600},
	}
	base := encodeDHCPLeasePayload(leases)

	// One stamp + one strip recovers the base byte-for-byte and the lease set.
	stamped := appendFullSetSeq(base, 424242, 99)
	gotBase, inc, seq := stripFullSetSeq(stamped)
	if inc != 424242 || seq != 99 {
		t.Fatalf("trailer round trip: got (inc=%d, seq=%d), want (424242, 99)", inc, seq)
	}
	if !bytes.Equal(gotBase, base) {
		t.Fatalf("DHCP base must round-trip byte-exact through one stamp/strip; got %d bytes want %d", len(gotBase), len(base))
	}
	if got, ok := decodeDHCPLeasePayload(gotBase); !ok || len(got) != 1 || got[0].Address != "10.0.0.5" {
		t.Fatalf("recovered base must decode to the original lease set, got %+v", got)
	}

	// Pathological coincidence: a base whose OWN last 8 bytes ARE the magic. One
	// stamp then one strip must peel only the real (appended) trailer and leave
	// this magic-ending base intact — no double-strip into the payload.
	trap := append(append([]byte(nil), base...), fullSetSeqMagic[:]...)
	stamped2 := appendFullSetSeq(trap, 7, 8)
	if gotTrap, _, _ := stripFullSetSeq(stamped2); !bytes.Equal(gotTrap, trap) {
		t.Fatalf("a base ending in the magic must survive one stamp/strip intact")
	}
	// And a LEGACY frame (no trailer) that merely ends in the magic decodes as
	// (whole, 0, 0): stripFullSetSeq checks [n-24:n-16], not the final 8 bytes.
	if legacyGot, li, ls := stripFullSetSeq(trap); li != 0 || ls != 0 || !bytes.Equal(legacyGot, trap) {
		t.Fatalf("legacy DHCP frame ending in magic must decode as (whole, 0, 0), got (inc=%d, seq=%d)", li, ls)
	}
}

// captureConn is a net.Conn that records everything written, so a test can
// inspect the frames a Queue* sender actually put on the wire.
type captureConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func (c *captureConn) frames() []captureFrame {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []captureFrame
	b := c.buf.Bytes()
	for len(b) >= syncHeaderSize {
		msgType := b[4]
		n := int(binary.LittleEndian.Uint32(b[8:12]))
		if len(b) < syncHeaderSize+n {
			break
		}
		out = append(out, captureFrame{msgType: msgType, payload: append([]byte(nil), b[syncHeaderSize:syncHeaderSize+n]...)})
		b = b[syncHeaderSize+n:]
	}
	return out
}

type captureFrame struct {
	msgType uint8
	payload []byte
}

// TestQueueStampsFullSetSeq proves the SENDER side (both-sides wire-protocol):
// QueueIPsecSA and QueueDHCPLeases stamp a strictly-monotonic PER-TYPE sequence
// with a stable incarnation, and v4/v6 draw from independent counters.
func TestQueueStampsFullSetSeq(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	ss.mu.Lock()
	ss.conn0 = cc
	ss.mu.Unlock()

	if ss.syncEpoch == 0 {
		t.Fatal("syncEpoch must be seeded nonzero at construction")
	}

	ss.QueueIPsecSA([]string{"vpn-a"})
	ss.QueueIPsecSA([]string{"vpn-a", "vpn-b"})
	ss.QueueDHCPLeases(4, nil)
	ss.QueueDHCPLeases(6, nil)
	ss.QueueDHCPLeases(4, nil)

	frames := cc.frames()
	if len(frames) != 5 {
		t.Fatalf("expected 5 frames written, got %d", len(frames))
	}

	var ipsecSeqs, v4Seqs, v6Seqs []uint64
	for _, f := range frames {
		_, inc, seq := stripFullSetSeq(f.payload)
		if inc != ss.syncEpoch {
			t.Fatalf("frame type %d: incarnation %d != syncEpoch %d", f.msgType, inc, ss.syncEpoch)
		}
		if seq == 0 {
			t.Fatalf("frame type %d: seq must be nonzero (never the legacy sentinel)", f.msgType)
		}
		switch f.msgType {
		case syncMsgIPsecSA:
			ipsecSeqs = append(ipsecSeqs, seq)
		case syncMsgDHCPLeaseV4:
			v4Seqs = append(v4Seqs, seq)
		case syncMsgDHCPLeaseV6:
			v6Seqs = append(v6Seqs, seq)
		default:
			t.Fatalf("unexpected frame type %d", f.msgType)
		}
	}

	// Each per-type counter is independent and strictly monotonic starting at 1.
	if len(ipsecSeqs) != 2 || ipsecSeqs[0] != 1 || ipsecSeqs[1] != 2 {
		t.Fatalf("IPsec seqs = %v, want [1 2]", ipsecSeqs)
	}
	if len(v4Seqs) != 2 || v4Seqs[0] != 1 || v4Seqs[1] != 2 {
		t.Fatalf("DHCP v4 seqs = %v, want [1 2] (independent counter)", v4Seqs)
	}
	if len(v6Seqs) != 1 || v6Seqs[0] != 1 {
		t.Fatalf("DHCP v6 seqs = %v, want [1] (independent counter)", v6Seqs)
	}
}
