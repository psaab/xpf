package cluster

// #14359: PolicyRuleID (#11070) and PolicyCounterIdx (#3301) are sync-only:
// the BPF mirror drops both (bpfSessionValue has no slot for them), so a
// mirror-sourced sweep/bulk resend arrived with ""/0 and wiped the standby's
// per-policy hit-counter binding. These cells drive the real stamp / wire /
// receive-apply paths and assert the identity survives a mirror round.

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

const policyIdentityRule14359 = "trust\x00untrust\x00rule0"

func TestPolicyIdentitySurvivesSweepAndReceiverInstall14359(t *testing.T) {
	key := rtflowKeyV4(41459)
	sender := &SessionSync{}
	sender.initGenState()
	receiver, dp := lossyRecvSync9752(t)

	// Initial install: the helper-sourced frame carries the identity.
	initial := dataplane.SessionValue{
		SessionID: 14359, RTFlowSessionID: 14359,
		PolicyRuleID: policyIdentityRule14359, PolicyCounterIdx: 1,
	}
	sender.stampInstallGenV4(key, &initial)
	if initial.PolicyRuleID != policyIdentityRule14359 || initial.PolicyCounterIdx != 1 {
		t.Fatalf("FIXTURE: initial stamp disturbed identity (%q,%d)", initial.PolicyRuleID, initial.PolicyCounterIdx)
	}

	// Sweep/bulk resend: the mirror read-back zeroes both sync-only fields
	// (production toBPF().sessionValue() loss, simulated explicitly here).
	mirror := mirrorLoss14359(initial)
	if mirror.PolicyRuleID != "" || mirror.PolicyCounterIdx != 0 {
		t.Fatalf("FIXTURE: mirror simulation must zero policy identity, got (%q,%d)", mirror.PolicyRuleID, mirror.PolicyCounterIdx)
	}
	sender.stampInstallGenV4(key, &mirror)
	if mirror.PolicyRuleID != policyIdentityRule14359 || mirror.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: swept frame lost policy identity: rule=%q idx=%d, want (%q,1)",
			mirror.PolicyRuleID, mirror.PolicyCounterIdx, policyIdentityRule14359)
	}

	// The swept frame crosses the real wire codec intact.
	_, wireVal, ok := decodeSessionV4Payload(encodeSessionV4Payload(key, mirror))
	if !ok || wireVal.PolicyRuleID != policyIdentityRule14359 || wireVal.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: swept wire frame lost policy identity: ok=%v rule=%q idx=%d",
			ok, wireVal.PolicyRuleID, wireVal.PolicyCounterIdx)
	}

	// Receiver installs it: the value handed to the dataplane (and onward to
	// the userspace helper, which binds policy_counter from rule_id) keeps it.
	wireVal.SessionID = 14359
	wireVal.RTFlowSessionID = 14359
	if !receiver.installClusterSyncedV4(key, wireVal) {
		t.Fatal("receiver install did not land")
	}
	if got := lastSet9752(t, dp); got.PolicyRuleID != policyIdentityRule14359 || got.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: receiver-installed session lost policy identity: rule=%q idx=%d",
			got.PolicyRuleID, got.PolicyCounterIdx)
	}

	// A stamp-less resend from an old sender (same incarnation) must not wipe
	// the receiver's binding either.
	stale := dataplane.SessionValue{SessionID: 14359, RTFlowSessionID: 14359, Generation: wireVal.Generation + 1}
	if !receiver.installClusterSyncedV4(key, stale) {
		t.Fatal("stamp-less resend did not land")
	}
	if got := lastSet9752(t, dp); got.PolicyRuleID != policyIdentityRule14359 || got.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: stamp-less resend wiped receiver policy identity: rule=%q idx=%d",
			got.PolicyRuleID, got.PolicyCounterIdx)
	}

	// A promoted standby that only RECEIVED the incarnation resends from its
	// mirror (""/0 after the BPF round-trip): the receive memo restores it.
	promoted := dataplane.SessionValue{SessionID: 14359, RTFlowSessionID: 14359}
	receiver.stampInstallGenV4(key, &promoted)
	if promoted.PolicyRuleID != policyIdentityRule14359 || promoted.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: promoted-standby resend lost policy identity: rule=%q idx=%d",
			promoted.PolicyRuleID, promoted.PolicyCounterIdx)
	}
}

func TestPolicyIdentitySurvivesSweepAndReceiverInstallV614359(t *testing.T) {
	key := rtflowKeyV6(41459)
	sender := &SessionSync{}
	sender.initGenState()
	receiver, dp := lossyRecvSync9752(t)

	initial := dataplane.SessionValueV6{
		SessionID: 14359, RTFlowSessionID: 14359,
		PolicyRuleID: policyIdentityRule14359, PolicyCounterIdx: 1,
	}
	sender.stampInstallGenV6(key, &initial)
	mirror := initial
	mirror.PolicyRuleID, mirror.PolicyCounterIdx = "", 0
	sender.stampInstallGenV6(key, &mirror)
	if mirror.PolicyRuleID != policyIdentityRule14359 || mirror.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: swept v6 frame lost policy identity: rule=%q idx=%d",
			mirror.PolicyRuleID, mirror.PolicyCounterIdx)
	}
	_, wireVal, ok := decodeSessionV6Payload(encodeSessionV6Payload(key, mirror))
	if !ok || wireVal.PolicyRuleID != policyIdentityRule14359 || wireVal.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: swept v6 wire frame lost policy identity: ok=%v rule=%q idx=%d",
			ok, wireVal.PolicyRuleID, wireVal.PolicyCounterIdx)
	}
	wireVal.SessionID = 14359
	wireVal.RTFlowSessionID = 14359
	if !receiver.installClusterSyncedV6(key, wireVal) {
		t.Fatal("receiver v6 install did not land")
	}
	if got := lastSetV610068(t, dp); got.PolicyRuleID != policyIdentityRule14359 || got.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: receiver-installed v6 session lost policy identity: rule=%q idx=%d",
			got.PolicyRuleID, got.PolicyCounterIdx)
	}
	stale := dataplane.SessionValueV6{SessionID: 14359, RTFlowSessionID: 14359, Generation: wireVal.Generation + 1}
	if !receiver.installClusterSyncedV6(key, stale) {
		t.Fatal("stamp-less v6 resend did not land")
	}
	if got := lastSetV610068(t, dp); got.PolicyRuleID != policyIdentityRule14359 || got.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: stamp-less v6 resend wiped receiver policy identity: rule=%q idx=%d",
			got.PolicyRuleID, got.PolicyCounterIdx)
	}
	promoted := dataplane.SessionValueV6{SessionID: 14359, RTFlowSessionID: 14359}
	receiver.stampInstallGenV6(key, &promoted)
	if promoted.PolicyRuleID != policyIdentityRule14359 || promoted.PolicyCounterIdx != 1 {
		t.Fatalf("#14359: promoted-standby v6 resend lost policy identity: rule=%q idx=%d",
			promoted.PolicyRuleID, promoted.PolicyCounterIdx)
	}
}

// TestPolicyIdentityNewIncarnationDoesNotInherit14359: a reused tuple with a
// new SessionID stating no identity must apply with none — the memo is keyed
// to the incarnation, never to the tuple alone.
func TestPolicyIdentityNewIncarnationDoesNotInherit14359(t *testing.T) {
	key := rtflowKeyV4(41460)
	s := &SessionSync{}
	s.initGenState()
	first := dataplane.SessionValue{SessionID: 100, PolicyRuleID: policyIdentityRule14359, PolicyCounterIdx: 1}
	s.stampInstallGenV4(key, &first)
	next := dataplane.SessionValue{SessionID: 101}
	s.stampInstallGenV4(key, &next)
	if next.PolicyRuleID != "" || next.PolicyCounterIdx != 0 {
		t.Fatalf("#14359: new incarnation inherited policy identity (%q,%d)", next.PolicyRuleID, next.PolicyCounterIdx)
	}
	// A zero SessionID has no incarnation identity: nothing is recorded or restored.
	anon := dataplane.SessionValue{SessionID: 0, PolicyRuleID: policyIdentityRule14359, PolicyCounterIdx: 1}
	s.stampInstallGenV4(key, &anon)
	anonMirror := dataplane.SessionValue{SessionID: 0}
	s.stampInstallGenV4(key, &anonMirror)
	if anonMirror.PolicyRuleID != "" || anonMirror.PolicyCounterIdx != 0 {
		t.Fatalf("#14359: SessionID 0 must not restore policy identity (%q,%d)", anonMirror.PolicyRuleID, anonMirror.PolicyCounterIdx)
	}
}

// TestPolicyIdentityDeleteAndResetEvict14359: deletes and a peer namespace
// reset discard the memos, so a reused tuple+sessionID cannot resurrect a
// dead incarnation's policy binding.
func TestPolicyIdentityDeleteAndResetEvict14359(t *testing.T) {
	key := rtflowKeyV4(41461)
	receiver, _ := lossyRecvSync9752(t)
	val := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 10,
		PolicyRuleID: policyIdentityRule14359, PolicyCounterIdx: 1}
	if !receiver.installClusterSyncedV4(key, val) {
		t.Fatal("install did not land")
	}
	receiver.deleteClusterSyncedV4(key, 11, false)
	resend := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77}
	receiver.stampInstallGenV4(key, &resend)
	if resend.PolicyRuleID != "" || resend.PolicyCounterIdx != 0 {
		t.Fatalf("#14359: delete left policy identity behind (%q,%d)", resend.PolicyRuleID, resend.PolicyCounterIdx)
	}

	// Namespace reset (peer reboot): same tuple+sessionID re-prime stating no
	// identity must stay unbound. Generation 12 out-ranks the delete's
	// tombstone from the first incarnation.
	reprime := val
	reprime.Generation = 12
	if !receiver.installClusterSyncedV4(key, reprime) {
		t.Fatal("reinstall did not land")
	}
	receiver.resetRecvGen()
	noIdentity := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 13}
	if !receiver.installClusterSyncedV4(key, noIdentity) {
		t.Fatal("post-reset install did not land")
	}
	resend2 := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77}
	receiver.stampInstallGenV4(key, &resend2)
	if resend2.PolicyRuleID != "" || resend2.PolicyCounterIdx != 0 {
		t.Fatalf("#14359: namespace reset left policy identity behind (%q,%d)", resend2.PolicyRuleID, resend2.PolicyCounterIdx)
	}
}

// mirrorLoss14359 applies the production BPF-mirror loss for the policy
// fields: toBPF()/sessionValue() in pkg/dataplane has no slot for either,
// so a mirror read-back always arrives with ""/0.
func mirrorLoss14359(v dataplane.SessionValue) dataplane.SessionValue {
	v.PolicyRuleID = ""
	v.PolicyCounterIdx = 0
	return v
}
