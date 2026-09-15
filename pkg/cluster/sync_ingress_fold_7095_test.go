package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// sync_ingress_fold_7095_test.go — #7095.
//
// The ingress-identity fold rides the session-sync wire as a TRAILING
// LENGTH-GATED field — the #2170 Generation pattern that sync_protocol.go names
// as its own and warns is the alternative to a wire flag-day. These cells bind
// the two halves of that contract: a new peer round-trips it, and an old peer's
// shorter payload decodes to 0 with every earlier field intact.

func sessionValue7095(fold uint32) dataplane.SessionValue {
	return dataplane.SessionValue{
		State:            2,
		SessionID:        0x1122334455667788,
		Created:          11,
		LastSeen:         22,
		Timeout:          33,
		Generation:       44,
		AppTimeout:       55,
		PolicyCounterIdx: 66,
		ConfigEpoch:      77,
		RTFlowSessionID:  88,
		IngressZone:      9,
		IngressIfaceFold: fold,
	}
}

func sessionKey7095() dataplane.SessionKey {
	var k dataplane.SessionKey
	copy(k.SrcIP[:], []byte{10, 0, 0, 1})
	copy(k.DstIP[:], []byte{10, 0, 0, 2})
	k.SrcPort = 1234
	k.DstPort = 443
	k.Protocol = 6
	return k
}

func TestIngressFoldRoundTripsOnTheWire_7095(t *testing.T) {
	key := sessionKey7095()
	const fold = 0xDEADBEEF
	payload := encodeSessionV4Payload(key, sessionValue7095(fold))
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if got.IngressIfaceFold != fold {
		t.Fatalf("IngressIfaceFold round-tripped as %#x, want %#x", got.IngressIfaceFold, uint32(fold))
	}
	// The field is APPENDED, so everything ahead of it must be untouched — a
	// mis-sized buffer or a slipped offset shows up in these, not in the fold.
	if got.RTFlowSessionID != 88 || got.ConfigEpoch != 77 || got.Generation != 44 {
		t.Fatalf("appending the fold disturbed an earlier trailing field: "+
			"Generation=%d ConfigEpoch=%d RTFlowSessionID=%d",
			got.Generation, got.ConfigEpoch, got.RTFlowSessionID)
	}
}

// TestLegacyPeerPayloadDecodesFoldAsUnknown_7095 is the length-gating half, and
// the one that matters for a mixed-version cluster.
//
// An old sender's payload simply STOPS before this field; truncating a current
// payload by exactly the field width reproduces that byte-for-byte. The decode
// must yield 0 — the unknown sentinel — while every field the old sender DID
// send survives. A decoder that read past the end, or that treated the shorter
// payload as invalid, would corrupt or drop every session arriving from a peer
// on the previous release.
func TestLegacyPeerPayloadDecodesFoldAsUnknown_7095(t *testing.T) {
	key := sessionKey7095()
	// Every field appended BEHIND the fold widens this cut, and the cut must be
	// widened with it or the cell passes for the wrong reason — it would remove
	// the newer trailing field and leave the fold intact, then assert "absent
	// fold decodes to 0" against a frame that still carries the fold.
	//
	// The running total: #7188's 8-byte TunnelDiscriminator, then #7239's
	// 4-byte RoutingDomain, plus the 4-byte fold itself = 16.
	full := encodeSessionV4Payload(key, sessionValue7095(0xABCD1234))
	legacy := full[:len(full)-24]

	gotKey, got, ok := decodeSessionV4Payload(legacy)
	if !ok {
		t.Fatal("a legacy peer's shorter payload was REJECTED — every session from a " +
			"peer on the previous release would be dropped (#7095)")
	}
	if got.IngressIfaceFold != 0 {
		t.Fatalf("the absent field decoded as %#x, want 0 (unknown). A non-zero value "+
			"here names a device the peer never claimed", got.IngressIfaceFold)
	}
	if gotKey != key || got.RTFlowSessionID != 88 || got.ConfigEpoch != 77 ||
		got.Generation != 44 || got.SessionID != 0x1122334455667788 {
		t.Fatalf("truncation disturbed fields the legacy peer DID send: keyOK=%v "+
			"Generation=%d ConfigEpoch=%d RTFlowSessionID=%d SessionID=%#x",
			gotKey == key, got.Generation, got.ConfigEpoch, got.RTFlowSessionID, got.SessionID)
	}
}

// TestIngressFoldRoundTripsV6_7095 covers the SEPARATE v6 encoder/decoder pair.
// Wiring only v4 leaves every IPv6 session degraded after a failover while the
// v4 cells above stay green.
func TestIngressFoldRoundTripsV6_7095(t *testing.T) {
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8})
	copy(key.DstIP[:], []byte{0x20, 0x01, 0x0d, 0xb9})
	key.SrcPort = 5000
	key.DstPort = 443
	key.Protocol = 6
	val := dataplane.SessionValueV6{
		State:            2,
		SessionID:        7,
		RTFlowSessionID:  88,
		ConfigEpoch:      77,
		IngressIfaceFold: 0x0BADF00D,
	}
	payload := encodeSessionV6Payload(key, val)
	_, got, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("v6 decode failed")
	}
	if got.IngressIfaceFold != 0x0BADF00D {
		t.Fatalf("v6 fold round-tripped as %#x, want %#x", got.IngressIfaceFold, uint32(0x0BADF00D))
	}
	// Cut every field appended behind the fold — see the v4 cell above for the
	// running total (#7188 discriminator 8 + #7239 routing domain 4 + fold 4).
	_, shortGot, ok := decodeSessionV6Payload(payload[:len(payload)-24])
	if !ok || shortGot.IngressIfaceFold != 0 {
		t.Fatalf("v6 legacy truncation: ok=%v fold=%#x, want ok=true fold=0",
			ok, shortGot.IngressIfaceFold)
	}
	if shortGot.RTFlowSessionID != 88 || shortGot.ConfigEpoch != 77 {
		t.Fatalf("v6 truncation disturbed earlier fields: ConfigEpoch=%d RTFlowSessionID=%d",
			shortGot.ConfigEpoch, shortGot.RTFlowSessionID)
	}
}
