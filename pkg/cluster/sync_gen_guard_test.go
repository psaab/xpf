package cluster

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #2170 — HA session-sync install-generation guard tests.
//
// These exercise the cluster apply layer (installClusterSyncedV4/V6,
// deleteClusterSyncedV4/V6) through the mockSweepDP SessionStore, plus the
// wire round-trip for the new length-gated trailing generation field. Every
// guard test is written so it FAILS against the pre-fix behavior (where a
// delete unconditionally removes whatever sits at the key).

func gen2170KeyV4() dataplane.SessionKey {
	return dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  12345,
		DstPort:  5201,
	}
}

func gen2170KeyV6() dataplane.SessionKeyV6 {
	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 12345, DstPort: 5201}
	k.SrcIP[15] = 1
	k.DstIP[15] = 2
	return k
}

// installWithGenV4 drives the real apply layer with an explicit generation,
// as if the value had arrived off the wire (decode sets val.Generation).
func installWithGenV4(ss *SessionSync, key dataplane.SessionKey, gen uint64) {
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val.Generation = gen
	ss.installClusterSyncedV4(key, val)
}

func installWithGenV6(ss *SessionSync, key dataplane.SessionKeyV6, gen uint64) {
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val.Generation = gen
	ss.installClusterSyncedV6(key, val)
}

// TestStaleDeleteIgnoredForReplacement is the §3.4 race: S(K) closes (delete
// journaled at gen=1), a replacement S'(K) is installed with a NEWER gen=2,
// then the stale delete (gen=1) replays. The delete MUST be refused and S'
// MUST survive. Against the pre-fix code this deleted S'.
func TestStaleDeleteIgnoredForReplacement(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// T0..T1: install S(K) gen=1, then the replacement S'(K) gen=2 (overwrites,
	// stored gen=2).
	installWithGenV4(ss, key, 1)
	installWithGenV4(ss, key, 2)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("replacement session S' should be installed")
	}

	// T2: the journaled delete for the OLD incarnation (gen=1) replays.
	ss.deleteClusterSyncedV4(key, 1, false)

	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("stale delete (gen=1) wrongly removed the live replacement S' (gen=2)")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

func TestStaleDeleteIgnoredForReplacementV6(t *testing.T) {
	key := gen2170KeyV6()
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV6(ss, key, 1)
	installWithGenV6(ss, key, 2)
	ss.deleteClusterSyncedV6(key, 1, false)

	if _, ok := dp.v6sessions[key]; !ok {
		t.Fatal("stale v6 delete (gen=1) wrongly removed the live replacement (gen=2)")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// TestRealDeleteApplied: the delete of the very session installed (equal
// generation) MUST apply. Equality is NOT refusal (SMR C2: never <=).
func TestRealDeleteApplied(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV4(ss, key, 2)
	ss.deleteClusterSyncedV4(key, 2, false) // equal generation — must delete

	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("real delete (equal generation) did not remove the session")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 0 {
		t.Fatalf("DeletesStaleIgnored = %d, want 0 for an equal-generation delete", got)
	}
}

// TestNewerDeleteApplied: a delete with a strictly NEWER generation than the
// stored entry must apply (the stored entry is the older incarnation).
func TestNewerDeleteApplied(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV4(ss, key, 2)
	ss.deleteClusterSyncedV4(key, 5, false)

	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("newer-generation delete did not remove the session")
	}
}

// TestLegacyPeerNoGenStillDeletes: gen==0 on EITHER side falls back to today's
// unconditional delete (rolling-upgrade safe). Covers both directions.
func TestLegacyPeerNoGenStillDeletes(t *testing.T) {
	t.Run("legacy_install_then_genned_delete", func(t *testing.T) {
		key := gen2170KeyV4()
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
		installWithGenV4(ss, key, 0) // legacy peer install: stored gen stays 0
		ss.deleteClusterSyncedV4(key, 7, false)
		if _, ok := dp.v4sessions[key]; ok {
			t.Fatal("delete against a gen-0 stored entry must be unconditional")
		}
	})
	t.Run("genned_install_then_legacy_delete", func(t *testing.T) {
		key := gen2170KeyV4()
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
		installWithGenV4(ss, key, 9)
		ss.deleteClusterSyncedV4(key, 0, false) // legacy delete: unconditional
		if _, ok := dp.v4sessions[key]; ok {
			t.Fatal("a gen-0 (legacy) delete must be unconditional even against a genned entry")
		}
		if got := ss.stats.DeletesStaleIgnored.Load(); got != 0 {
			t.Fatalf("DeletesStaleIgnored = %d, want 0 for a legacy delete", got)
		}
	})
}

// TestStaleInstallDoesNotRegressStoredGen (SMR C3): a delayed stale install
// (gen=1) arriving after S'(K, gen=2) must be REFUSED so the stored generation
// stays 2 — otherwise a later stale delete (gen=1) could match and wrongly
// remove the live entry. Verifies the per-key stored gen never regresses.
func TestStaleInstallDoesNotRegressStoredGen(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	installWithGenV4(ss, key, 2)
	installWithGenV4(ss, key, 1) // delayed stale install — must be refused
	if got := ss.stats.InstallsStaleIgnored.Load(); got != 1 {
		t.Fatalf("InstallsStaleIgnored = %d, want 1", got)
	}

	// The stored generation must still be 2, so a stale delete (gen=1) is
	// refused and the live session survives.
	ss.deleteClusterSyncedV4(key, 1, false)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("stale install rolled the stored generation back, letting a stale delete kill the live entry")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// TestDeleteGenerationStrictlyGreaterThanInstallV4 (#2221) verifies the sender
// stamps a fresh, strictly-increasing generation on every install send and that
// the matching delete draws a FRESH generation STRICTLY GREATER than the last
// install of the key (rather than echoing it). A delete out-ranking its install
// is what lets the receiver order a reordered delete-then-install pair (the
// delete tombstone refuses the late, lower-generation install of the cancelled
// session). A key never installed still returns 0 (legacy unconditional path).
func TestDeleteGenerationStrictlyGreaterThanInstallV4(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)
	key := gen2170KeyV4()

	val := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &val)
	g1 := val.Generation
	if g1 == 0 {
		t.Fatal("first install generation must be non-zero")
	}

	val2 := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &val2)
	g2 := val2.Generation
	if g2 <= g1 {
		t.Fatalf("second install generation %d must be strictly greater than first %d", g2, g1)
	}

	// The delete draws a fresh generation strictly greater than the last
	// install, so it out-ranks the install it cancels.
	del := ss.takeDeleteGenV4(key)
	if del <= g2 {
		t.Fatalf("delete generation %d must be strictly greater than last install %d (#2221)", del, g2)
	}
	// After the take the entry is evicted; a second delete returns 0 (legacy
	// fallback) rather than a stale or fresh value.
	if again := ss.takeDeleteGenV4(key); again != 0 {
		t.Fatalf("delete after eviction returned %d, want 0", again)
	}
}

// TestDeleteGenerationStrictlyGreaterThanInstallV6 mirrors the V4 #2221 contract.
func TestDeleteGenerationStrictlyGreaterThanInstallV6(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)
	key := gen2170KeyV6()

	val := dataplane.SessionValueV6{}
	ss.stampInstallGenV6(key, &val)
	g1 := val.Generation
	if g1 == 0 {
		t.Fatal("first install generation must be non-zero")
	}
	del := ss.takeDeleteGenV6(key)
	if del <= g1 {
		t.Fatalf("delete generation %d must be strictly greater than install %d (#2221)", del, g1)
	}
	if again := ss.takeDeleteGenV6(key); again != 0 {
		t.Fatalf("delete after eviction returned %d, want 0", again)
	}
}

// TestGenerationMonotonicSameSecondSameSlot is the §3.3 trap: two installs of
// the same key get strictly increasing generations regardless of clock
// resolution — the case the old now_seconds<<16|slot SessionID could NOT
// distinguish.
func TestGenerationMonotonicSameSecondSameSlot(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	key := gen2170KeyV4()
	v1 := dataplane.SessionValue{}
	v2 := dataplane.SessionValue{}
	ss.stampInstallGenV4(key, &v1)
	ss.stampInstallGenV4(key, &v2)
	if v1.Generation == 0 || v2.Generation == 0 {
		t.Fatal("generations must be non-zero")
	}
	if v2.Generation <= v1.Generation {
		t.Fatalf("same-second/same-slot reuse must get strictly increasing generations: %d then %d", v1.Generation, v2.Generation)
	}
}

// TestFailoverDomainGenerationReStamp (SMR B1, unit-level model): after an
// ownership change the new owner re-installs an inherited key with its own
// (higher) generation, which re-stamps the stored generation. A delete the new
// owner then issues compares same-domain and applies; a stale cross-domain
// delete (older generation) does not wrongly remove a live flow.
func TestFailoverDomainGenerationReStamp(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// Old owner installed the inherited key with gen=100.
	installWithGenV4(ss, key, 100)
	// New owner re-syncs the inherited key with its own (higher) generation.
	installWithGenV4(ss, key, 250)

	// A stale delete from the OLD owner's domain (gen=100) must be refused.
	ss.deleteClusterSyncedV4(key, 100, false)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("a stale cross-domain delete removed the re-stamped live entry")
	}
	// The new owner's own delete (gen=250) applies.
	ss.deleteClusterSyncedV4(key, 250, false)
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("the new owner's same-domain delete did not apply")
	}
}

// --- Wire round-trip / cross-version decode -------------------------------

// TestSessionWireRoundTripGenerationV4 verifies the trailing generation field
// encodes and decodes identically through the v4 session wire format.
func TestSessionWireRoundTripGenerationV4(t *testing.T) {
	key := gen2170KeyV4()
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 0xDEADBEEFCAFE}
	payload := encodeSessionV4Payload(key, val)
	dKey, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dKey != key {
		t.Fatalf("key mismatch: %+v vs %+v", dKey, key)
	}
	if dVal.Generation != val.Generation {
		t.Fatalf("generation round-trip mismatch: got %#x, want %#x", dVal.Generation, val.Generation)
	}
}

func TestSessionWireRoundTripGenerationV6(t *testing.T) {
	key := gen2170KeyV6()
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 0x0102030405060708}
	payload := encodeSessionV6Payload(key, val)
	dKey, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dKey != key {
		t.Fatalf("key mismatch")
	}
	if dVal.Generation != val.Generation {
		t.Fatalf("generation round-trip mismatch: got %#x, want %#x", dVal.Generation, val.Generation)
	}
}

// #3301: the per-application idle timeout (AppTimeout, seconds) and the #3073
// per-rule hit-counter handle (PolicyCounterIdx) must round-trip on the
// cluster session-sync wire as length-gated trailing fields, AND a legacy
// payload truncated before the #3301 block must still decode (fields at 0,
// rolling-upgrade safe). Reverting the sync_protocol.go encode/decode drops
// the values and this fails RED.
func TestSessionWireRoundTripPolicyFields3301V4(t *testing.T) {
	key := gen2170KeyV4()
	val := dataplane.SessionValue{
		State:            dataplane.SessStateEstablished,
		IngressZone:      1,
		EgressZone:       2,
		PolicyID:         42,
		Generation:       0xDEADBEEFCAFE,
		AppTimeout:       30,
		PolicyCounterIdx: 7,
	}
	payload := encodeSessionV4Payload(key, val)
	_, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dVal.PolicyID != 42 {
		t.Fatalf("PolicyID round-trip = %d, want 42", dVal.PolicyID)
	}
	if dVal.AppTimeout != 30 {
		t.Fatalf("AppTimeout round-trip = %d, want 30", dVal.AppTimeout)
	}
	if dVal.PolicyCounterIdx != 7 {
		t.Fatalf("PolicyCounterIdx round-trip = %d, want 7", dVal.PolicyCounterIdx)
	}
	if dVal.Generation != val.Generation {
		t.Fatalf("Generation round-trip = %#x, want %#x", dVal.Generation, val.Generation)
	}

	// Mixed-version: truncate the trailing #3301 block (8 bytes), the #5274
	// ConfigEpoch (8 bytes), the #5212 RTFlowSessionID (8 bytes), the #7095
	// IngressIfaceFold (4 bytes) AND the #7188 TunnelDiscriminator (8 bytes) so
	// the frame ends after Generation (an old peer that stops there). Decode
	// must still succeed with the new fields at 0 and Generation preserved.
	legacy := payload[:len(payload)-48]
	_, lVal, ok := decodeSessionV4Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) decode failed")
	}
	if lVal.AppTimeout != 0 || lVal.PolicyCounterIdx != 0 {
		t.Fatalf("legacy frame: appto=%d counter=%d, want 0/0", lVal.AppTimeout, lVal.PolicyCounterIdx)
	}
	if lVal.Generation != val.Generation {
		t.Fatalf("legacy Generation = %#x, want %#x preserved", lVal.Generation, val.Generation)
	}
}

func TestSessionWireRoundTripPolicyFields3301V6(t *testing.T) {
	key := gen2170KeyV6()
	val := dataplane.SessionValueV6{
		State:            dataplane.SessStateEstablished,
		IngressZone:      1,
		EgressZone:       2,
		PolicyID:         99,
		Generation:       0x0102030405060708,
		AppTimeout:       45,
		PolicyCounterIdx: 11,
	}
	payload := encodeSessionV6Payload(key, val)
	_, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dVal.PolicyID != 99 {
		t.Fatalf("PolicyID round-trip = %d, want 99", dVal.PolicyID)
	}
	if dVal.AppTimeout != 45 {
		t.Fatalf("AppTimeout round-trip = %d, want 45", dVal.AppTimeout)
	}
	if dVal.PolicyCounterIdx != 11 {
		t.Fatalf("PolicyCounterIdx round-trip = %d, want 11", dVal.PolicyCounterIdx)
	}
	if dVal.Generation != val.Generation {
		t.Fatalf("Generation round-trip = %#x, want %#x", dVal.Generation, val.Generation)
	}

	// Drop the #3301 AppTimeout+PolicyCounterIdx (8 bytes), the #4565 trailing
	// Nat64SnatV4 (4 bytes), the #5274 ConfigEpoch (8 bytes), the #5212
	// RTFlowSessionID (8 bytes), the #7095 IngressIfaceFold (4 bytes) AND the
	// #7188 TunnelDiscriminator (8 bytes) to simulate a pre-#3301 peer that
	// omits all of the additive trailing fields.
	legacy := payload[:len(payload)-52]
	_, lVal, ok := decodeSessionV6Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) decode failed")
	}
	if lVal.AppTimeout != 0 || lVal.PolicyCounterIdx != 0 {
		t.Fatalf("legacy frame: appto=%d counter=%d, want 0/0", lVal.AppTimeout, lVal.PolicyCounterIdx)
	}
}

// TestSessionWireRoundTripNat64SnatV4_4565 verifies the NAT64 translated pool
// source rides the V6 cluster sync payload as a length-gated trailing field so
// a peer-PROMOTED NAT64 session can rebuild its reverse (v4->v6) BIB after
// failover. RED-on-revert: dropping the encode/decode of Nat64SnatV4 loses the
// pool source and the standby cannot reconstruct the reverse mapping.
func TestSessionWireRoundTripNat64SnatV4_4565(t *testing.T) {
	key := gen2170KeyV6()
	val := dataplane.SessionValueV6{
		State:       dataplane.SessStateEstablished,
		IngressZone: 1,
		EgressZone:  2,
		Nat64SnatV4: [4]byte{203, 0, 113, 5},
	}
	payload := encodeSessionV6Payload(key, val)
	_, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dVal.Nat64SnatV4 != ([4]byte{203, 0, 113, 5}) {
		t.Fatalf("Nat64SnatV4 round-trip = %v, want [203 0 113 5]", dVal.Nat64SnatV4)
	}

	// Legacy (pre-#4565) peer omits the trailing Nat64SnatV4 (4 bytes) — and,
	// being older, the #5274 ConfigEpoch (8 bytes), the #5212 RTFlowSessionID
	// (8 bytes), the #7095 IngressIfaceFold (4 bytes) and the #7188
	// TunnelDiscriminator (8 bytes) too — so truncate all of them to reach an
	// after-#3301 frame -> Nat64SnatV4 all-zero (not NAT64).
	legacy := payload[:len(payload)-44]
	_, lVal, ok := decodeSessionV6Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) decode failed")
	}
	if lVal.Nat64SnatV4 != ([4]byte{}) {
		t.Fatalf("legacy frame Nat64SnatV4 = %v, want all-zero", lVal.Nat64SnatV4)
	}
}

// TestDeleteWireRoundTripGeneration verifies the delete message carries the
// generation as a length-gated trailing uint64 (25/49-byte payload with the
// #9752 forward-only marker byte).
func TestDeleteWireRoundTripGeneration(t *testing.T) {
	key := gen2170KeyV4()
	msg := encodeDeleteV4(key, 0x1122334455667788, false)
	payload := msg[syncHeaderSize:]
	if len(payload) != 25 {
		t.Fatalf("v4 delete payload len = %d, want 25", len(payload))
	}
	if g := binary.LittleEndian.Uint64(payload[16:24]); g != 0x1122334455667788 {
		t.Fatalf("v4 delete generation mismatch: got %#x", g)
	}
	if payload[24] != 0 {
		t.Fatalf("v4 delete marker byte = %d, want 0 for forwardOnly=false", payload[24])
	}

	key6 := gen2170KeyV6()
	msg6 := encodeDeleteV6(key6, 0x8877665544332211, false)
	payload6 := msg6[syncHeaderSize:]
	if len(payload6) != 49 {
		t.Fatalf("v6 delete payload len = %d, want 49", len(payload6))
	}
	if g := binary.LittleEndian.Uint64(payload6[40:48]); g != 0x8877665544332211 {
		t.Fatalf("v6 delete generation mismatch: got %#x", g)
	}
	if payload6[48] != 0 {
		t.Fatalf("v6 delete marker byte = %d, want 0 for forwardOnly=false", payload6[48])
	}
}

// TestCrossVersionShortPayloadDecode: an OLD encoder's session payload (no
// trailing generation) must decode to Generation==0 on a NEW decoder, and the
// new (longer) payload must decode losslessly. This is the rolling-upgrade
// seam (#1961-class wire hazard).
func TestCrossVersionShortPayloadDecode(t *testing.T) {
	key := gen2170KeyV4()
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 42}
	full := encodeSessionV4Payload(key, val)
	// Simulate a pre-#2170 OLD encoder: drop every additive trailing field (the
	// #2170 generation u64 + the #3301 AppTimeout/PolicyCounterIdx block + the
	// #5274 ConfigEpoch u64 + the #5212 RTFlowSessionID u64 + the #7095
	// IngressIfaceFold u32 + the #7188 TunnelDiscriminator u64) so the payload
	// ends at FibGen.
	short := full[:len(full)-56]
	_, dVal, ok := decodeSessionV4Payload(short)
	if !ok {
		t.Fatal("short (legacy) payload should still decode")
	}
	if dVal.Generation != 0 {
		t.Fatalf("legacy short payload should decode to Generation 0, got %d", dVal.Generation)
	}
	if dVal.AppTimeout != 0 || dVal.PolicyCounterIdx != 0 {
		t.Fatalf("legacy short payload should decode AppTimeout/PolicyCounterIdx 0, got %d/%d",
			dVal.AppTimeout, dVal.PolicyCounterIdx)
	}

	// An OLD delete decoder (16-byte payload) must tolerate the longer 24-byte
	// payload; and a NEW delete decoder reading a 16-byte (legacy) payload sees
	// generation 0.
	legacyDelete := encodeDeleteV4(key, 0, false)[syncHeaderSize:][:16]
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{key: {State: 1}}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.handleMessage(nil, syncMsgDeleteV4, legacyDelete)
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("legacy 16-byte delete should still remove the session (gen=0 fallback)")
	}
}

// TestJournalFlushReplayRefusesStaleDelete is the end-to-end #2163 flush
// scenario: a delete is journaled at gen=1 (peer disconnected), the
// replacement S'(K) is synced at gen=2 over a healthy connection, then the
// journal flush replays the stale delete. S' must survive.
//
// It drives the receive side directly (the install + the journaled-delete
// replay both arrive on the wire) to model the cross-reconnect causality.
func TestJournalFlushReplayRefusesStaleDelete(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// The sender stamped D(K) with gen=1 at T0 (journaled). Model that as the
	// journaled delete wire message.
	journaledDelete := encodeDeleteV4(key, 1, false)[syncHeaderSize:]

	// T1: S'(K) is synced at gen=2 over a healthy connection and installed.
	syncedReplacement := func() []byte {
		v := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 2}
		return encodeSessionV4Payload(key, v)
	}()
	ss.handleMessage(nil, syncMsgSessionV4, syncedReplacement)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("replacement S' should be installed")
	}

	// T2: the journal flush replays the stale delete.
	ss.handleMessage(nil, syncMsgDeleteV4, journaledDelete)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("journal-flush replay of the stale delete killed the live replacement S'")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// synthKeyV4 produces the i-th distinct synthetic v4 key for filling the
// generation maps in the overflow tests.
func synthKeyV4(i int) dataplane.SessionKey {
	k := dataplane.SessionKey{
		Protocol: 17,
		SrcPort:  uint16(i & 0xFFFF),
		DstPort:  uint16((i >> 16) & 0xFFFF),
	}
	binary.LittleEndian.PutUint32(k.SrcIP[:], uint32(i))
	binary.LittleEndian.PutUint32(k.DstIP[:], uint32(i)^0xA5A5A5A5)
	return k
}

// fillRecvGenV4ToCount inserts distinct synthetic keys into recvGenV4 (directly,
// under lock) until it holds exactly `count` entries, never touching liveKey.
func fillRecvGenV4ToCount(ss *SessionSync, liveKey dataplane.SessionKey, count int) {
	ss.recvGenMu.Lock()
	defer ss.recvGenMu.Unlock()
	for i := 0; len(ss.recvGenV4) < count; i++ {
		k := synthKeyV4(i)
		if k == liveKey {
			continue
		}
		ss.recvGenV4[k] = uint64(i + 1)
	}
}

// TestGenMapOverflowKeepsLiveKeyV4 is the #2198 F1 hazard: when the receiver
// stored-generation map reaches genGuardMapCap, the OLD code cleared the WHOLE
// map (make(...)) on the NEXT record, dropping every live key's stored
// generation and disabling the guard cluster-wide. A stale delete could then
// kill a live re-established session — the exact #2170 bug.
//
// This drives the REAL recordInstalledGen path: a live key is installed
// (stored gen=2), the map is filled to one below cap, then a NEW key install
// pushes a recording at cap. Pre-fix that recording cleared the whole map →
// the live key's gen=2 was wiped → the stale delete (gen=1) saw stored=0 →
// unconditional delete killed the live session. Post-fix the new key is
// skip-recorded, the live key's gen=2 survives, and the stale delete is
// refused. Fails pre-fix, passes post-fix.
func TestGenMapOverflowKeepsLiveKeyV4(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// Install the live session through the real apply path (records stored
	// gen=2 via recordInstalledGenV4).
	installWithGenV4(ss, key, 2)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("live session should be installed")
	}

	// Fill the stored-generation map to exactly cap-1 (live key already counts
	// as one entry, so the map holds the live key + (cap-1) synthetic keys).
	fillRecvGenV4ToCount(ss, key, genGuardMapCap)
	if got := len(ss.recvGenV4); got != genGuardMapCap {
		t.Fatalf("recvGenV4 pre-condition: %d entries, want %d", got, genGuardMapCap)
	}

	// A NEW-key install now drives recordInstalledGenV4 while the map is at
	// cap. Pre-fix this make(...)-cleared the whole map (wiping the live key);
	// post-fix the new key is skip-recorded and the live key is untouched.
	newKey := dataplane.SessionKey{Protocol: 6, SrcPort: 0x1234, DstPort: 0x5678}
	installWithGenV4(ss, newKey, 3)

	// The live key's stored generation must still be 2 after the overflow.
	ss.recvGenMu.Lock()
	stored, ok := ss.recvGenV4[key]
	ss.recvGenMu.Unlock()
	if !ok || stored != 2 {
		t.Fatalf("live key stored generation lost across overflow: ok=%v stored=%d (want 2) — F1 overflow-clear regression", ok, stored)
	}

	// A stale delete (gen=1, strictly older) MUST be refused.
	ss.deleteClusterSyncedV4(key, 1, false)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("stale delete (gen=1) wrongly removed the live session after a gen-map overflow (F1 regression)")
	}
	if got := ss.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// TestRecordInstalledGenSkipsNewKeyOnFull verifies the F1 skip-record-on-full
// semantics directly: at cap, a NEW key is NOT recorded (the map is never
// cleared and never grows past cap), the GenMapOverflow counter increments, and
// an EXISTING key is still updated in place (its stored generation is never
// dropped).
func TestRecordInstalledGenSkipsNewKeyOnFull(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	live := gen2170KeyV4()

	// Record the live key first (it exists), then fill to cap around it.
	ss.recordInstalledGenV4(live, 2)
	fillRecvGenV4ToCount(ss, live, genGuardMapCap)

	// A NEW key at cap is skipped — map stays at cap, counter increments.
	newKey := dataplane.SessionKey{Protocol: 6, SrcPort: 0xBEEF, DstPort: 0xCAFE}
	ss.recordInstalledGenV4(newKey, 99)
	ss.recvGenMu.Lock()
	_, newStored := ss.recvGenV4[newKey]
	sz := len(ss.recvGenV4)
	liveStored := ss.recvGenV4[live]
	ss.recvGenMu.Unlock()
	if newStored {
		t.Fatal("a new key was recorded while the map was at cap (should skip-record)")
	}
	if sz != genGuardMapCap {
		t.Fatalf("map grew/shrank past cap on overflow: %d != %d", sz, genGuardMapCap)
	}
	if got := ss.stats.GenMapOverflow.Load(); got != 1 {
		t.Fatalf("GenMapOverflow = %d, want 1", got)
	}

	// An EXISTING key is still updated in place even at cap (never dropped).
	ss.recordInstalledGenV4(live, 7)
	ss.recvGenMu.Lock()
	liveStored2 := ss.recvGenV4[live]
	ss.recvGenMu.Unlock()
	if liveStored != 2 {
		t.Fatalf("existing live key stored gen = %d before update, want 2", liveStored)
	}
	if liveStored2 != 7 {
		t.Fatalf("existing live key not updated in place at cap: stored=%d, want 7", liveStored2)
	}
	if got := ss.stats.GenMapOverflow.Load(); got != 1 {
		t.Fatalf("GenMapOverflow = %d after updating an existing key, want 1 (no overflow on in-place update)", got)
	}
}

// TestPeerRebootBulkRePrimeAcceptedAfterReset is the #2198 F2 scenario:
// cross-boot generation regression. The peer installed S(K) at a HIGH
// generation (say 10_000) before it rebooted. After reboot its genCounter
// restarts LOWER (monotonic clock reset), so its cold-start bulk re-prime
// carries a LOWER generation (say 5). Without the recvGen reset on BulkStart,
// the install guard refuses the re-prime as stale (stored 10_000 > incoming 5)
// — the inverse of #2170 (stale-RETAIN) — and the standby never re-learns the
// flow. With the F2 reset, the bulk re-prime is accepted and re-records gen=5.
//
// Against the pre-F2 code (no resetRecvGen) the bulk re-prime is refused →
// the session is NOT (re)installed → this FAILS.
func TestPeerRebootBulkRePrimeAcceptedAfterReset(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// Pre-reboot: the peer synced S(K) at a high generation; we stored 10_000.
	installWithGenV4(ss, key, 10000)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("pre-reboot session should be installed")
	}
	// Drop the dataplane entry to model the standby losing the flow across the
	// reconnect window (the cold-start re-prime is what must re-establish it).
	delete(dp.v4sessions, key)

	// Peer reconnects after reboot and starts a fresh bulk transfer. This
	// resets our stored generations (F2).
	var bulkStart [8]byte
	binary.LittleEndian.PutUint64(bulkStart[:], 1) // epoch
	ss.handleMessage(nil, syncMsgBulkStart, bulkStart[:])

	// The rebooted peer's bulk re-prime carries a LOWER generation (genCounter
	// restarted). It MUST be accepted.
	rePrime := func() []byte {
		v := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Generation: 5}
		return encodeSessionV4Payload(key, v)
	}()
	ss.handleMessage(nil, syncMsgSessionV4, rePrime)

	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("post-reboot lower-generation bulk re-prime was wrongly refused (F2: stale-RETAIN inverse of #2170)")
	}
	if got := ss.stats.InstallsStaleIgnored.Load(); got != 0 {
		t.Fatalf("InstallsStaleIgnored = %d, want 0 (the re-prime must not be treated as stale after the reset)", got)
	}

	// The stored generation is now the re-primed gen=5; a peer delete at gen=5
	// (its own current generation) applies normally.
	ss.recvGenMu.Lock()
	stored := ss.recvGenV4[key]
	ss.recvGenMu.Unlock()
	if stored != 5 {
		t.Fatalf("stored generation after re-prime = %d, want 5", stored)
	}
}

// TestGenGuardConcurrentMaps stress-tests the sender- and receiver-side
// generation maps under concurrent access to surface any data race on
// genSentV4 / recvGenV4 (run with -race). It exercises the guard/echo helpers
// directly — the receiver apply path is single-threaded per connection in
// production, so this targets the maps' own locking, not the (non-thread-safe)
// mock session store.
func TestGenGuardConcurrentMaps(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	const workers = 8
	const perWorker = 500
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				key := dataplane.SessionKey{Protocol: 6, SrcPort: uint16(w + 1), DstPort: uint16(i + 1)}
				// Sender echo path.
				val := dataplane.SessionValue{}
				ss.stampInstallGenV4(key, &val)
				_ = ss.takeDeleteGenV4(key)
				// Receiver guard path.
				rec, apply := ss.installGenGuardV4(key, val.Generation)
				if apply {
					ss.recordInstalledGenV4(key, rec)
				}
				// #2221: a non-zero delete generation records a tombstone in
				// recvGenV4 rather than evicting, so the receiver map retains a
				// per-key entry. Use a fresh, strictly-greater delete generation
				// (as the real sender does via takeDeleteGenV4) so the delete
				// out-ranks its install.
				_ = ss.deleteGenGuardV4(key, ss.nextInstallGen())
			}
		}(w)
	}
	wg.Wait()

	// Every key was install-then-delete-guarded. The sender map evicts on
	// delete, so genSentV4 must be fully drained. The receiver map records the
	// delete generation as a tombstone (#2221) rather than evicting, so it
	// retains exactly one entry per distinct key (bounded by genGuardMapCap).
	ss.genSentMu.Lock()
	sentRemaining := len(ss.genSentV4)
	ss.genSentMu.Unlock()
	ss.recvGenMu.Lock()
	recvRemaining := len(ss.recvGenV4)
	ss.recvGenMu.Unlock()
	if sentRemaining != 0 {
		t.Fatalf("genSentV4 not drained: %d entries remain", sentRemaining)
	}
	if recvRemaining == 0 || recvRemaining > genGuardMapCap {
		t.Fatalf("recvGenV4 tombstone count = %d, want (0, %d]", recvRemaining, genGuardMapCap)
	}
}

// --- #2221: same-generation install/delete reorder convergence -------------

// applySendChInOrder drains the sender's sendCh and applies each framed message
// to the SAME SessionSync's receiver apply path in the exact order it was
// enqueued. This models a single ACTIVE fabric: the receiver applies messages
// in the order the sender placed them on the wire, so whichever of the
// install/delete pair won the enqueue race is applied first. Returns the count
// drained.
func applySendChInOrder(t *testing.T, ss *SessionSync) int {
	t.Helper()
	n := 0
	for {
		select {
		case msg := <-ss.sendCh:
			if len(msg) < syncHeaderSize {
				t.Fatalf("framed message too short: %d", len(msg))
			}
			ss.handleMessage(nil, msg[4], msg[syncHeaderSize:])
			n++
		default:
			return n
		}
	}
}

// TestSameGenReorderDeleteThenInstallConvergesV4 is the #2170 RESIDUAL (#2221):
// within the SAME generation domain, a session's install and its cancelling
// delete are reordered on sendCh so the receiver applies DELETE then INSTALL.
// The master closed the session, so the standby MUST end with the session GONE.
//
// It drives the REAL sender enqueue path: the sweep stamps a live key (model:
// stampInstallGenV4 + queue the install), then the delta-drain takes the close
// (QueueDeleteV4), then the install is enqueued AFTER the delete — exactly the
// "delete wins the sendCh enqueue race" ordering the issue documents. Both
// messages then apply through handleMessage in enqueue order.
//
// Pre-fix (delete echoes the install's IDENTICAL generation, delete evicts the
// stored generation): delete(N) applies + evicts; install(N) sees stored==0 →
// applies → the closed session is RESURRECTED on the standby. This FAILS.
// Post-fix (delete draws a strictly-greater generation + records a tombstone):
// delete(N+1) applies + tombstones N+1; install(N) is N < N+1 → REFUSED. GONE.
func TestSameGenReorderDeleteThenInstallConvergesV4(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)

	// The sweep re-stamps the LIVE session and builds the install message.
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	ss.stampInstallGenV4(key, &val)
	installMsg := encodeSessionV4(key, val)

	// The delta-drain closes the session and enqueues the delete FIRST (it won
	// the enqueue race against the still-queued install).
	ss.QueueDeleteV4(key, false)
	// The install is enqueued AFTER the delete.
	if !ss.queueMessage(installMsg, &ss.stats.SessionsSent, "test_install_v4") {
		t.Fatal("install enqueue failed")
	}

	// Apply in wire (enqueue) order: delete then install.
	if got := applySendChInOrder(t, ss); got != 2 {
		t.Fatalf("expected to drain 2 messages, drained %d", got)
	}

	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("#2221: reordered delete-then-install resurrected the closed session on the standby (master deleted it last)")
	}
}

func TestSameGenReorderDeleteThenInstallConvergesV6(t *testing.T) {
	key := gen2170KeyV6()
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)

	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	ss.stampInstallGenV6(key, &val)
	installMsg := encodeSessionV6(key, val)

	ss.QueueDeleteV6(key, false)
	if !ss.queueMessage(installMsg, &ss.stats.SessionsSent, "test_install_v6") {
		t.Fatal("install enqueue failed")
	}

	if got := applySendChInOrder(t, ss); got != 2 {
		t.Fatalf("expected to drain 2 messages, drained %d", got)
	}
	if _, ok := dp.v6sessions[key]; ok {
		t.Fatal("#2221: reordered v6 delete-then-install resurrected the closed session on the standby")
	}
}

// TestSameGenInstallThenDeleteConvergesV4 is the in-order half of #2221: the
// install is enqueued before its cancelling delete (the common case). The
// standby must still end with the session GONE. This guards against a fix that
// only handled the reorder direction and broke the normal path.
func TestSameGenInstallThenDeleteConvergesV4(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)

	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	ss.stampInstallGenV4(key, &val)
	installMsg := encodeSessionV4(key, val)

	// Install first, then the delete.
	if !ss.queueMessage(installMsg, &ss.stats.SessionsSent, "test_install_v4") {
		t.Fatal("install enqueue failed")
	}
	ss.QueueDeleteV4(key, false)

	if got := applySendChInOrder(t, ss); got != 2 {
		t.Fatalf("expected to drain 2 messages, drained %d", got)
	}
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("#2221: in-order install-then-delete left a stale session (the normal close path regressed)")
	}
}

// TestReestablishAfterDeleteAppliesV4 (#2221): after a session is closed (its
// delete recorded a tombstone), a GENUINELY NEW incarnation of the same key —
// re-established and re-stamped by a later sweep with a strictly-greater
// generation — MUST install. The tombstone must not block a legitimately newer
// session. This is the "install last, present" half of last-writer-wins.
func TestReestablishAfterDeleteAppliesV4(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// Install gen=5, delete at a strictly-greater gen=6 (as the fixed sender
	// produces). The delete applies and tombstones gen=6.
	installWithGenV4(ss, key, 5)
	ss.deleteClusterSyncedV4(key, 6, false)
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("delete did not remove the session")
	}

	// A new incarnation re-established later carries a higher generation (the
	// sweep re-stamps from a strictly-monotonic counter) and MUST install.
	installWithGenV4(ss, key, 7)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("#2221: a genuinely newer incarnation (gen>tombstone) was wrongly blocked by the delete tombstone")
	}
	if got := ss.stats.InstallsStaleIgnored.Load(); got != 0 {
		t.Fatalf("InstallsStaleIgnored = %d, want 0 for a newer-generation re-establishment", got)
	}
}

// TestReorderedInstallRefusedByTombstoneV4 (#2221, apply-layer unit): a delete
// applies at gen=6 (tombstone), then the OLDER install (gen=5) of the very
// session that delete cancelled arrives late and MUST be refused — the standby
// stays GONE. This is the direct receiver-side property the wire test exercises
// end-to-end.
func TestReorderedInstallRefusedByTombstoneV4(t *testing.T) {
	key := gen2170KeyV4()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	ss.deleteClusterSyncedV4(key, 6, false) // tombstone gen=6 (no prior stored entry)
	installWithGenV4(ss, key, 5)            // reordered older install — must be refused
	if _, ok := dp.v4sessions[key]; ok {
		t.Fatal("#2221: a reordered older install (gen<tombstone) resurrected the closed session")
	}
	if got := ss.stats.InstallsStaleIgnored.Load(); got != 1 {
		t.Fatalf("InstallsStaleIgnored = %d, want 1 (the reordered install must be refused by the tombstone)", got)
	}
}
