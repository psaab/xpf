package cluster

// #9752 round 3 item 2: the bilateral install fence. A peer that advertised
// its capabilities without capFlagInstallTableIdentity installs everything
// stamp-less, so a stamped install sent there would silently wrong-table
// after failover. Withhold it (counted); unstamped installs still flow, and
// an unlearned peer is never gated.
//
// Observed on sendCh (Connected): installs are not journaled, so the queue
// itself is the production-true observable.

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func stampedVal9752() dataplane.SessionValue {
	return dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811}
}

func fenceSync9752() *SessionSync {
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	return ss
}

func TestStampedInstallWithheldFromAnIncapablePeer9752(t *testing.T) {
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	if !ss.peerCapabilitiesLearned() {
		t.Fatal("FIXTURE: the capability frame did not land")
	}
	if ss.InstallTableIdentityCapable() {
		t.Fatal("FIXTURE: a frame without the install-table bit must not read as capable")
	}
	ss.QueueSessionV4(rtflowKeyV4(42001), stampedVal9752())
	if got := len(ss.sendCh); got != 0 {
		t.Fatalf("%d stamped installs reached an incapable peer; it would install them "+
			"stamp-less and wrong-table after failover", got)
	}
	if got := ss.stats.InstallsSuppressedNoPeerInstallTable.Load(); got != 1 {
		t.Errorf("InstallsSuppressedNoPeerInstallTable = %d, want 1", got)
	}
}

func TestStampedInstallReachesACapablePeer9752(t *testing.T) {
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	if !ss.InstallTableIdentityCapable() {
		t.Fatal("FIXTURE: the advertised bit did not decode")
	}
	ss.QueueSessionV4(rtflowKeyV4(42002), stampedVal9752())
	if got := len(ss.sendCh); got != 1 {
		t.Fatalf("sendCh holds %d, want 1: a capable peer must receive the install", got)
	}
	if got := ss.stats.InstallsSuppressedNoPeerInstallTable.Load(); got != 0 {
		t.Errorf("InstallsSuppressedNoPeerInstallTable = %d, want 0", got)
	}
}

func TestUnstampedInstallReachesAnIncapablePeer9752(t *testing.T) {
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	ss.QueueSessionV4(rtflowKeyV4(42003), dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77})
	if got := len(ss.sendCh); got != 1 {
		t.Fatalf("sendCh holds %d, want 1: unstamped installs are safe for old peers", got)
	}
}

func TestStampedInstallWithheldWhileUnlearnedThenFlows9752(t *testing.T) {
	ss := fenceSync9752()
	// No capability frame yet: the transport is connected before the
	// exchange, so default-deny (round 4) — pass-through here would plant
	// the lie on every connect to an old peer.
	ss.QueueSessionV4(rtflowKeyV4(42004), stampedVal9752())
	if got := len(ss.sendCh); got != 0 {
		t.Fatalf("sendCh holds %d, want 0: an undiscovered peer must not receive stamped installs", got)
	}
	if got := ss.stats.InstallsSuppressedNoPeerInstallTable.Load(); got != 1 {
		t.Fatalf("InstallsSuppressedNoPeerInstallTable = %d, want 1", got)
	}
	// Discovery lands capable: the next send flows (the sweep re-sends a
	// withheld install, so default-deny delays, never drops).
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	ss.QueueSessionV4(rtflowKeyV4(42004), stampedVal9752())
	if got := len(ss.sendCh); got != 1 {
		t.Fatalf("sendCh holds %d, want 1: post-discovery sends must flow", got)
	}
}

// TestCapableDiscoveryRearmsColdPrimeAfterSuppression9752 pins round 5 item
// 5: suppressed installs are never retried by the sweep (its window advances
// past them), so a capable discovery with suppress debt re-arms the cold
// prime — the redriven bulk snapshot (#82/#9626 machinery, pinned by its own
// tests) heals every withheld install at once.
func TestCapableDiscoveryRearmsColdPrimeAfterSuppression9752(t *testing.T) {
	ss := fenceSync9752()
	// Suppress while undiscovered.
	ss.QueueSessionV4(rtflowKeyV4(42004), stampedVal9752())
	if got := len(ss.sendCh); got != 0 {
		t.Fatal("FIXTURE: undiscovered send must be withheld")
	}
	if !ss.installTableSuppressDebt.Load() {
		t.Fatal("FIXTURE: suppression must record debt")
	}
	// Capable discovery transfers the debt into a re-arm.
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	if !ss.needColdPrime.Load() {
		t.Fatal("capable discovery with suppress debt must re-arm the cold prime")
	}
	if ss.installTableSuppressDebt.Load() {
		t.Error("re-arm must consume the debt (no double-pay on re-discovery)")
	}
}

// TestCapableDiscoveryWithoutSuppressionDoesNotRearm9752: no debt, no bulk.
func TestCapableDiscoveryWithoutSuppressionDoesNotRearm9752(t *testing.T) {
	ss := fenceSync9752()
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	if ss.needColdPrime.Load() {
		t.Error("capable discovery without suppressions must not re-arm (spurious bulk)")
	}
}

// TestIncapableDiscoveryDoesNotRearm9752: the peer still cannot take the
// sessions; no redrive until upgrade/reconnect.
func TestIncapableDiscoveryDoesNotRearm9752(t *testing.T) {
	ss := fenceSync9752()
	ss.QueueSessionV4(rtflowKeyV4(42004), stampedVal9752())
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	if ss.needColdPrime.Load() {
		t.Error("incapable discovery must not re-arm (peer cannot take a stamped snapshot)")
	}
	if !ss.installTableSuppressDebt.Load() {
		t.Error("debt must survive an incapable discovery (still owed)")
	}
}
