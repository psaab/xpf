package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// sync_tunnel_discriminator_7188_test.go — #7188.
//
// GRE is IP protocol 47 and carries no L4 ports, so two RFC 2890 tunnels
// between one pair of outer endpoints are ONE dataplane.SessionKey. The helper
// separates them on a typed TunnelDiscriminator that is part of ITS key; the
// cluster wire carries that discriminator as a length-gated trailing VALUE
// field and the peer helper folds it back into the key it reconstructs.
//
// These cells bind the two halves of the trailing-field contract for that
// value: a current peer round-trips it, and a peer on the previous release
// sends a shorter payload that must decode to 0 — the RESERVED "not carried"
// tag, which is what makes the peer helper WITHHOLD a protocol-47 session
// rather than import it aliased onto another tunnel's key.

func sessionValue7188(discriminator uint64) dataplane.SessionValue {
	return dataplane.SessionValue{
		State:               2,
		SessionID:           0x1122334455667788,
		Created:             11,
		LastSeen:            22,
		Timeout:             33,
		Generation:          44,
		AppTimeout:          55,
		PolicyCounterIdx:    66,
		ConfigEpoch:         77,
		RTFlowSessionID:     88,
		IngressZone:         9,
		IngressIfaceFold:    0xDEADBEEF,
		TunnelDiscriminator: discriminator,
	}
}

func greSessionKey7188() dataplane.SessionKey {
	var k dataplane.SessionKey
	copy(k.SrcIP[:], []byte{198, 51, 100, 7})
	copy(k.DstIP[:], []byte{203, 0, 113, 9})
	// Protocol 47 has no ports. These zeros are why the 5-tuple cannot tell two
	// tunnels apart and the discriminator has to ride separately.
	k.SrcPort = 0
	k.DstPort = 0
	k.Protocol = 47
	return k
}

func TestTunnelDiscriminatorRoundTripsOnTheWire_7188(t *testing.T) {
	key := greSessionKey7188()
	// The helper's Keyed(100) encoding: bit 32 set, RFC 2890 key in the low 32.
	const discriminator = uint64(1)<<32 | 100
	payload := encodeSessionV4Payload(key, sessionValue7188(discriminator))
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if got.TunnelDiscriminator != discriminator {
		t.Fatalf("TunnelDiscriminator round-tripped as %#x, want %#x",
			got.TunnelDiscriminator, discriminator)
	}
	// The field is APPENDED, so everything ahead of it must be untouched — a
	// mis-sized buffer or a slipped offset shows up here, not in the new field.
	if got.IngressIfaceFold != 0xDEADBEEF || got.RTFlowSessionID != 88 ||
		got.ConfigEpoch != 77 || got.Generation != 44 {
		t.Fatalf("appending the discriminator disturbed an earlier trailing field: "+
			"Generation=%d ConfigEpoch=%d RTFlowSessionID=%d IngressIfaceFold=%#x",
			got.Generation, got.ConfigEpoch, got.RTFlowSessionID, got.IngressIfaceFold)
	}
}

// TWO tunnels, ONE key. This is the cell a single-tunnel test cannot be: the
// records differ ONLY in the discriminator, so anything that drops it on the
// wire makes them byte-identical and the standby installs one session for both.
func TestTwoKeyedTunnelsSharingAKeyStayDistinctOnTheWire_7188(t *testing.T) {
	key := greSessionKey7188()
	first := encodeSessionV4Payload(key, sessionValue7188(uint64(1)<<32|100))
	second := encodeSessionV4Payload(key, sessionValue7188(uint64(1)<<32|200))

	_, gotFirst, ok1 := decodeSessionV4Payload(first)
	_, gotSecond, ok2 := decodeSessionV4Payload(second)
	if !ok1 || !ok2 {
		t.Fatalf("decode failed: ok1=%v ok2=%v", ok1, ok2)
	}
	if gotFirst.TunnelDiscriminator == gotSecond.TunnelDiscriminator {
		t.Fatalf("two RFC 2890 tunnels between the SAME outer endpoints decoded to "+
			"the same identity (%#x). Their 5-tuples are equal by construction, so "+
			"the discriminator is the only thing separating them: collapsing it here "+
			"makes the standby hold one session for two tunnels, sharing one policy "+
			"decision, NAT state, counter set and timeout after failover (#7188)",
			gotFirst.TunnelDiscriminator)
	}
}

// The length-gating half, and the one that matters for a mixed-version cluster.
// An old sender's payload simply STOPS before this field; truncating a current
// payload by exactly the field width reproduces that byte-for-byte.
//
// Absent MUST decode to 0. 0 is RESERVED for "not carried" and is NOT the
// helper's encoding of the None class, which is what lets the peer withhold a
// protocol-47 session it cannot express instead of importing it aliased.
func TestLegacyPeerPayloadDecodesDiscriminatorAsNotCarried_7188(t *testing.T) {
	key := greSessionKey7188()
	full := encodeSessionV4Payload(key, sessionValue7188(uint64(1)<<32|100))
	legacy := full[:len(full)-22]

	gotKey, got, ok := decodeSessionV4Payload(legacy)
	if !ok {
		t.Fatal("a legacy peer's shorter payload was REJECTED — every session from a " +
			"peer on the previous release would be dropped (#7188)")
	}
	if got.TunnelDiscriminator != 0 {
		t.Fatalf("the absent field decoded as %#x, want 0 (not carried). A non-zero "+
			"value here asserts an identity the peer never claimed",
			got.TunnelDiscriminator)
	}
	if gotKey != key || got.IngressIfaceFold != 0xDEADBEEF || got.RTFlowSessionID != 88 ||
		got.ConfigEpoch != 77 || got.Generation != 44 {
		t.Fatalf("truncation disturbed fields the legacy peer DID send: keyOK=%v "+
			"Generation=%d ConfigEpoch=%d RTFlowSessionID=%d IngressIfaceFold=%#x",
			gotKey == key, got.Generation, got.ConfigEpoch, got.RTFlowSessionID,
			got.IngressIfaceFold)
	}
}

// The SEPARATE v6 encoder/decoder pair. Wiring only v4 leaves every IPv6 GRE
// tunnel aliased after a failover while the v4 cells above stay green.
func TestTunnelDiscriminatorRoundTripsV6_7188(t *testing.T) {
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], []byte{0x20, 0x01, 0x0d, 0xb8})
	copy(key.DstIP[:], []byte{0x20, 0x01, 0x0d, 0xb9})
	key.Protocol = 47
	const discriminator = uint64(1)<<32 | 0x0BADF00D
	val := dataplane.SessionValueV6{
		Flags:               dataplane.SessFlagClusterSynced,
		State:               2,
		SessionID:           7,
		RTFlowSessionID:     88,
		ConfigEpoch:         77,
		IngressIfaceFold:    0x0BADF00D,
		TunnelDiscriminator: discriminator,
	}
	payload := encodeSessionV6Payload(key, val)
	_, got, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("v6 decode failed")
	}
	if got.TunnelDiscriminator != discriminator {
		t.Fatalf("v6 discriminator round-tripped as %#x, want %#x",
			got.TunnelDiscriminator, uint64(discriminator))
	}
	_, shortGot, ok := decodeSessionV6Payload(payload[:len(payload)-22])
	if !ok || shortGot.TunnelDiscriminator != 0 {
		t.Fatalf("v6 legacy truncation: ok=%v discriminator=%#x, want ok=true 0",
			ok, shortGot.TunnelDiscriminator)
	}
	if shortGot.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("v6 legacy truncation origin flags=%#x, want clear", shortGot.Flags)
	}
	if shortGot.IngressIfaceFold != 0x0BADF00D || shortGot.RTFlowSessionID != 88 {
		t.Fatalf("v6 truncation disturbed earlier fields: IngressIfaceFold=%#x "+
			"RTFlowSessionID=%d", shortGot.IngressIfaceFold, shortGot.RTFlowSessionID)
	}
}
