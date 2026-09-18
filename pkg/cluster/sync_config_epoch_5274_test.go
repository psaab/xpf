package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #5274 — HA session-sync config-epoch guard tests.
//
// The peer stamps every synced session with the #3931 config-sync generation
// it held at admit/queue time (SessionValue.ConfigEpoch, stampInstallGen*).
// The receiver refuses an install whose epoch is STRICTLY OLDER than its own
// lastAppliedConfigGen — the peer has since committed (and this node applied) a
// newer config that may DENY the session, so a delayed stale-permit install
// that lands after clearSessionsForDeletedPolicies is dropped
// (SessionsStaleConfigIgnored). These tests FAIL RED if either the wire
// carry (sync_protocol.go) or the receiver guard (installClusterSynced*) is
// reverted.

// configEpochKeyV4 builds a distinct v4 key per sub-case (varying src port) so
// the #2170 per-key install-generation guard never interferes with the
// config-epoch admission being exercised.
func configEpochKeyV4(srcPort uint16) dataplane.SessionKey {
	return dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  srcPort,
		DstPort:  5201,
	}
}

func configEpochKeyV6(srcPort uint16) dataplane.SessionKeyV6 {
	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: srcPort, DstPort: 5201}
	k.SrcIP[15] = 1
	k.DstIP[15] = 2
	return k
}

// installWithConfigEpochV4 drives the real apply layer with an explicit
// admitting config epoch, as if the value had arrived off the wire (decode
// sets val.ConfigEpoch). Generation is left 0 so ONLY the config-epoch guard
// governs admission.
func installWithConfigEpochV4(ss *SessionSync, key dataplane.SessionKey, epoch uint64) {
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val.ConfigEpoch = epoch
	ss.installClusterSyncedV4(key, val)
}

func installWithConfigEpochV6(ss *SessionSync, key dataplane.SessionKeyV6, epoch uint64) {
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val.ConfigEpoch = epoch
	ss.installClusterSyncedV6(key, val)
}

// TestStaleConfigEpochSessionRejected5274 is the immediate-policy-invalidation
// race: the peer admitted a session under config epoch E1, this node has since
// applied a strictly-newer config (lastAppliedConfigGen = E2 > E1) that may
// DENY it, and the delayed install arrives AFTER this node's config-apply
// sweep. The stale-epoch install MUST be refused; a current/newer/legacy-epoch
// install MUST be accepted. Reverting the installClusterSyncedV4 guard installs
// the stale permit and this fails RED.
func TestStaleConfigEpochSessionRejected5274(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)

	// This node has applied config generation 10 (the peer committed a newer
	// config and it was config-synced + applied here).
	ss.lastAppliedConfigGen.Store(10)

	// STALE: admitted under epoch 5 < 10 — must be REFUSED (a stale permit).
	staleKey := configEpochKeyV4(10001)
	installWithConfigEpochV4(ss, staleKey, 5)
	if _, ok := dp.v4sessions[staleKey]; ok {
		t.Fatal("stale-config-epoch session (epoch 5 < applied 10) was wrongly installed")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the stale reject", got)
	}

	// CURRENT: admitted under epoch 10 == applied 10 — must be ACCEPTED
	// (equality is not staleness; the config still admits it).
	curKey := configEpochKeyV4(10002)
	installWithConfigEpochV4(ss, curKey, 10)
	if _, ok := dp.v4sessions[curKey]; !ok {
		t.Fatal("current-config-epoch session (epoch 10 == applied 10) was wrongly refused")
	}

	// NEWER: admitted under epoch 15 > applied 10 (this node has not yet
	// applied the peer's newest config) — must be ACCEPTED.
	newKey := configEpochKeyV4(10003)
	installWithConfigEpochV4(ss, newKey, 15)
	if _, ok := dp.v4sessions[newKey]; !ok {
		t.Fatal("newer-config-epoch session (epoch 15 > applied 10) was wrongly refused")
	}

	// LEGACY: epoch 0 (a pre-#5274 peer, or local-origin) disables the check —
	// must be ACCEPTED unconditionally (rolling-upgrade safe).
	legacyKey := configEpochKeyV4(10004)
	installWithConfigEpochV4(ss, legacyKey, 0)
	if _, ok := dp.v4sessions[legacyKey]; !ok {
		t.Fatal("legacy epoch-0 session was wrongly refused (config-epoch check must be disabled for 0)")
	}

	// Only the single stale install was ignored.
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 (only the stale install)", got)
	}
}

// TestStaleConfigEpochSessionRejected5274V6 mirrors the v4 guard on the v6
// apply path.
func TestStaleConfigEpochSessionRejected5274V6(t *testing.T) {
	dp := &mockSweepDP{v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.lastAppliedConfigGen.Store(10)

	staleKey := configEpochKeyV6(20001)
	installWithConfigEpochV6(ss, staleKey, 5)
	if _, ok := dp.v6sessions[staleKey]; ok {
		t.Fatal("stale-config-epoch v6 session (epoch 5 < applied 10) was wrongly installed")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 1 after the v6 stale reject", got)
	}

	curKey := configEpochKeyV6(20002)
	installWithConfigEpochV6(ss, curKey, 10)
	if _, ok := dp.v6sessions[curKey]; !ok {
		t.Fatal("current-config-epoch v6 session (epoch 10 == applied 10) was wrongly refused")
	}

	legacyKey := configEpochKeyV6(20003)
	installWithConfigEpochV6(ss, legacyKey, 0)
	if _, ok := dp.v6sessions[legacyKey]; !ok {
		t.Fatal("legacy epoch-0 v6 session was wrongly refused")
	}
}

// TestConfigEpochNoRejectAgainstZeroBaseline5274 documents that with no config
// generation held locally (fresh node, lastAppliedConfigGen == 0) the guard
// admits everything — the check is a strict "older than a KNOWN newer config"
// test, never a reject against the zero baseline.
func TestConfigEpochNoRejectAgainstZeroBaseline5274(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	// lastAppliedConfigGen defaults to 0.

	key := configEpochKeyV4(30001)
	installWithConfigEpochV4(ss, key, 7)
	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("session refused against a zero applied-config baseline (guard must only reject a KNOWN-newer config)")
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 0 {
		t.Fatalf("SessionsStaleConfigIgnored = %d, want 0 with no applied config", got)
	}
}

// TestSessionWireRoundTripConfigEpoch5274V4 asserts the admitting config epoch
// round-trips on the cluster session-sync wire as a length-gated trailing
// field, AND a legacy payload truncated before the #5274 block still decodes
// (epoch 0, other fields preserved). Reverting the sync_protocol.go
// encode/decode drops the value and this fails RED.
func TestSessionWireRoundTripConfigEpoch5274V4(t *testing.T) {
	key := configEpochKeyV4(40001)
	val := dataplane.SessionValue{
		Flags:            dataplane.SessFlagClusterSynced,
		State:            dataplane.SessStateEstablished,
		IngressZone:      1,
		EgressZone:       2,
		PolicyID:         42,
		Generation:       0xDEADBEEFCAFE,
		AppTimeout:       30,
		PolicyCounterIdx: 7,
		ConfigEpoch:      0x1122334455667788,
	}
	payload := encodeSessionV4Payload(key, val)
	dKey, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dKey != key {
		t.Fatalf("key mismatch: %+v vs %+v", dKey, key)
	}
	if dVal.ConfigEpoch != val.ConfigEpoch {
		t.Fatalf("ConfigEpoch round-trip = %#x, want %#x", dVal.ConfigEpoch, val.ConfigEpoch)
	}
	// Prior trailing fields must be unaffected by the appended epoch.
	if dVal.Generation != val.Generation || dVal.AppTimeout != 30 || dVal.PolicyCounterIdx != 7 {
		t.Fatalf("adjacent trailing fields corrupted: gen=%#x appto=%d idx=%d",
			dVal.Generation, dVal.AppTimeout, dVal.PolicyCounterIdx)
	}

	// Mixed-version: truncate the trailing #5274 config epoch (8 bytes), the
	// #5212 RTFlowSessionID (8 bytes), the #7095 IngressIfaceFold (4 bytes) AND
	// the #7188 TunnelDiscriminator (8 bytes) so the frame ends after
	// PolicyCounterIdx (an old peer that stops there). Decode must still succeed
	legacy := payload[:len(payload)-42]
	_, lVal, ok := decodeSessionV4Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) decode failed")
	}
	if lVal.ConfigEpoch != 0 {
		t.Fatalf("legacy frame ConfigEpoch = %#x, want 0", lVal.ConfigEpoch)
	}
	if lVal.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("legacy v4 frame origin flags=%#x, want clear", lVal.Flags)
	}
	if lVal.Generation != val.Generation || lVal.PolicyCounterIdx != 7 {
		t.Fatalf("legacy frame corrupted prior fields: gen=%#x idx=%d", lVal.Generation, lVal.PolicyCounterIdx)
	}
}

func TestSessionWireRoundTripConfigEpoch5274V6(t *testing.T) {
	key := configEpochKeyV6(40002)
	val := dataplane.SessionValueV6{
		Flags:            dataplane.SessFlagClusterSynced,
		State:            dataplane.SessStateEstablished,
		IngressZone:      1,
		EgressZone:       2,
		PolicyID:         99,
		Generation:       0x0102030405060708,
		AppTimeout:       45,
		PolicyCounterIdx: 11,
		Nat64SnatV4:      [4]byte{192, 0, 2, 9},
		ConfigEpoch:      0x99aabbccddeeff00,
	}
	payload := encodeSessionV6Payload(key, val)
	_, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}
	if dVal.ConfigEpoch != val.ConfigEpoch {
		t.Fatalf("ConfigEpoch round-trip = %#x, want %#x", dVal.ConfigEpoch, val.ConfigEpoch)
	}
	// The #4565 NAT64 pool source (the trailing field before the epoch) must
	// be intact.
	if dVal.Nat64SnatV4 != val.Nat64SnatV4 {
		t.Fatalf("Nat64SnatV4 corrupted by appended epoch: got %v want %v", dVal.Nat64SnatV4, val.Nat64SnatV4)
	}
	if dVal.Generation != val.Generation || dVal.PolicyCounterIdx != 11 {
		t.Fatalf("adjacent trailing fields corrupted: gen=%#x idx=%d", dVal.Generation, dVal.PolicyCounterIdx)
	}

	// Mixed-version: truncate the trailing epoch (8 bytes), the #5212
	// RTFlowSessionID (8 bytes), the #7095 IngressIfaceFold (4 bytes) AND the
	// #7188 TunnelDiscriminator (8 bytes) so the frame ends after Nat64SnatV4
	// (an old peer stops there). Decode still succeeds with epoch 0 and the
	// NAT64 source preserved.
	legacy := payload[:len(payload)-42]
	_, lVal, ok := decodeSessionV6Payload(legacy)
	if !ok {
		t.Fatal("legacy (truncated) v6 decode failed")
	}
	if lVal.ConfigEpoch != 0 {
		t.Fatalf("legacy v6 frame ConfigEpoch = %#x, want 0", lVal.ConfigEpoch)
	}
	if lVal.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("legacy v6 frame origin flags=%#x, want clear", lVal.Flags)
	}
	if lVal.Nat64SnatV4 != val.Nat64SnatV4 {
		t.Fatalf("legacy v6 frame Nat64SnatV4 corrupted: got %v want %v", lVal.Nat64SnatV4, val.Nat64SnatV4)
	}
}

// TestConfigEpochStampedAtQueueTime5274 asserts the sender stamps the current
// config-sync generation (#3931 configGenCounter) onto every queued session
// (stampInstallGen*), so the receiver has an epoch to guard against. Reverting
// the stamp leaves ConfigEpoch 0 (guard permanently disabled) and this fails
// RED.
func TestConfigEpochStampedAtQueueTime5274(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.configGenCounter.Store(77)

	key := configEpochKeyV4(50001)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished}
	ss.stampInstallGenV4(key, &val)
	if val.ConfigEpoch != 77 {
		t.Fatalf("stampInstallGenV4 ConfigEpoch = %d, want 77 (current configGenCounter)", val.ConfigEpoch)
	}

	keyV6 := configEpochKeyV6(50002)
	valV6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished}
	ss.stampInstallGenV6(keyV6, &valV6)
	if valV6.ConfigEpoch != 77 {
		t.Fatalf("stampInstallGenV6 ConfigEpoch = %d, want 77", valV6.ConfigEpoch)
	}
}
