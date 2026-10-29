package cluster

// #16700: per-app inactivity timeout (incl. 86401 never) and then-log
// flags must survive mirror-sourced sweep/bulk resends and stamp-less
// receiver resends, exactly like #14359 policy identity.

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestAppTimeoutLogSurvivesSweepAndReceiverV4_16700(t *testing.T) {
	key := rtflowKeyV4(46700)
	sender := &SessionSync{}
	sender.initGenState()
	receiver, dp := lossyRecvSync9752(t)
	initial := dataplane.SessionValue{SessionID: 16700, RTFlowSessionID: 16700, AppTimeout: 86401, LogFlags: dataplane.LogFlagSessionInit | dataplane.LogFlagSessionClose}
	sender.stampInstallGenV4(key, &initial)
	mirror := initial
	mirror.AppTimeoutLogStated = false // BPF mirror projection omits sync-only presence.
	mirror.AppTimeout, mirror.LogFlags = 0, 0
	sender.stampInstallGenV4(key, &mirror)
	if mirror.AppTimeout != 86401 || mirror.LogFlags != 3 {
		t.Fatalf("swept frame lost app timeout/log: %d/%d want 86401/3", mirror.AppTimeout, mirror.LogFlags)
	}
	_, wireVal, ok := decodeSessionV4Payload(encodeSessionV4Payload(key, mirror))
	if !ok || !wireVal.AppTimeoutLogStated || wireVal.AppTimeout != 86401 || wireVal.LogFlags != 3 {
		t.Fatalf("wire lost app timeout/log: ok=%v stated=%v %d/%d", ok, wireVal.AppTimeoutLogStated, wireVal.AppTimeout, wireVal.LogFlags)
	}
	wireVal.SessionID, wireVal.RTFlowSessionID = 16700, 16700
	if !receiver.installClusterSyncedV4(key, wireVal) {
		t.Fatal("receiver install did not land")
	}
	if got := lastSet9752(t, dp); got.AppTimeout != 86401 || got.LogFlags != 3 {
		t.Fatalf("receiver lost app timeout/log: %d/%d", got.AppTimeout, got.LogFlags)
	}
	stale := dataplane.SessionValue{SessionID: 16700, RTFlowSessionID: 16700, Generation: wireVal.Generation + 1}
	if !receiver.installClusterSyncedV4(key, stale) {
		t.Fatal("stamp-less resend did not land")
	}
	if got := lastSet9752(t, dp); got.AppTimeout != 86401 || got.LogFlags != 3 {
		t.Fatalf("stamp-less resend wiped app timeout/log: %d/%d", got.AppTimeout, got.LogFlags)
	}
	promoted := dataplane.SessionValue{SessionID: 16700, RTFlowSessionID: 16700}
	receiver.stampInstallGenV4(key, &promoted)
	if promoted.AppTimeout != 86401 || promoted.LogFlags != 3 {
		t.Fatalf("promoted resend lost app timeout/log: %d/%d", promoted.AppTimeout, promoted.LogFlags)
	}
}

func TestAppTimeoutLogSurvivesSweepAndReceiverV6_16700(t *testing.T) {
	key := rtflowKeyV6(46700)
	sender := &SessionSync{}
	sender.initGenState()
	receiver, dp := lossyRecvSync9752(t)
	initial := dataplane.SessionValueV6{SessionID: 16700, RTFlowSessionID: 16700, AppTimeout: 30, LogFlags: dataplane.LogFlagSessionClose}
	sender.stampInstallGenV6(key, &initial)
	mirror := initial
	mirror.AppTimeoutLogStated = false // BPF mirror projection omits sync-only presence.
	mirror.AppTimeout, mirror.LogFlags = 0, 0
	sender.stampInstallGenV6(key, &mirror)
	if mirror.AppTimeout != 30 || mirror.LogFlags != 2 {
		t.Fatalf("swept v6 lost: %d/%d want 30/2", mirror.AppTimeout, mirror.LogFlags)
	}
	_, wireVal, ok := decodeSessionV6Payload(encodeSessionV6Payload(key, mirror))
	if !ok || !wireVal.AppTimeoutLogStated || wireVal.AppTimeout != 30 || wireVal.LogFlags != 2 {
		t.Fatalf("v6 wire lost: ok=%v stated=%v %d/%d", ok, wireVal.AppTimeoutLogStated, wireVal.AppTimeout, wireVal.LogFlags)
	}
	wireVal.SessionID, wireVal.RTFlowSessionID = 16700, 16700
	if !receiver.installClusterSyncedV6(key, wireVal) {
		t.Fatal("receiver v6 install did not land")
	}
	if got := lastSetV610068(t, dp); got.AppTimeout != 30 || got.LogFlags != 2 {
		t.Fatalf("receiver v6 lost: %d/%d", got.AppTimeout, got.LogFlags)
	}
	stale := dataplane.SessionValueV6{SessionID: 16700, RTFlowSessionID: 16700, Generation: wireVal.Generation + 1}
	if !receiver.installClusterSyncedV6(key, stale) {
		t.Fatal("stamp-less v6 resend did not land")
	}
	if got := lastSetV610068(t, dp); got.AppTimeout != 30 || got.LogFlags != 2 {
		t.Fatalf("stamp-less v6 wiped: %d/%d", got.AppTimeout, got.LogFlags)
	}
	promoted := dataplane.SessionValueV6{SessionID: 16700, RTFlowSessionID: 16700}
	receiver.stampInstallGenV6(key, &promoted)
	if promoted.AppTimeout != 30 || promoted.LogFlags != 2 {
		t.Fatalf("promoted v6 lost: %d/%d", promoted.AppTimeout, promoted.LogFlags)
	}
}

func TestAppTimeoutLogNewIncarnationAndDelete16700(t *testing.T) {
	key := rtflowKeyV4(46701)
	s := &SessionSync{}
	s.initGenState()
	first := dataplane.SessionValue{SessionID: 100, AppTimeout: 86401, LogFlags: 3}
	s.stampInstallGenV4(key, &first)
	next := dataplane.SessionValue{SessionID: 101}
	s.stampInstallGenV4(key, &next)
	if next.AppTimeout != 0 || next.LogFlags != 0 {
		t.Fatalf("new incarnation inherited: %d/%d", next.AppTimeout, next.LogFlags)
	}
	anon := dataplane.SessionValue{SessionID: 0, AppTimeout: 30, LogFlags: 3}
	s.stampInstallGenV4(key, &anon)
	anonMirror := dataplane.SessionValue{SessionID: 0}
	s.stampInstallGenV4(key, &anonMirror)
	if anonMirror.AppTimeout != 0 || anonMirror.LogFlags != 0 {
		t.Fatalf("SessionID 0 must not restore: %d/%d", anonMirror.AppTimeout, anonMirror.LogFlags)
	}
	// Delete and namespace reset evict.
	receiver, _ := lossyRecvSync9752(t)
	val := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 10, AppTimeout: 45, LogFlags: 1}
	if !receiver.installClusterSyncedV4(key, val) {
		t.Fatal("install did not land")
	}
	receiver.deleteClusterSyncedV4(key, 11, false)
	resend := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77}
	receiver.stampInstallGenV4(key, &resend)
	if resend.AppTimeout != 0 || resend.LogFlags != 0 {
		t.Fatalf("delete left memo: %d/%d", resend.AppTimeout, resend.LogFlags)
	}
	reprime := val
	reprime.Generation = 12
	if !receiver.installClusterSyncedV4(key, reprime) {
		t.Fatal("reinstall did not land")
	}
	receiver.resetRecvGen()
	noVal := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 13}
	if !receiver.installClusterSyncedV4(key, noVal) {
		t.Fatal("post-reset install did not land")
	}
	resend2 := dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77}
	receiver.stampInstallGenV4(key, &resend2)
	if resend2.AppTimeout != 0 || resend2.LogFlags != 0 {
		t.Fatalf("reset left memo: %d/%d", resend2.AppTimeout, resend2.LogFlags)
	}
}

func TestAppTimeoutLogStatedZeroSurvivesLegacyStampLessResend_17780(t *testing.T) {
	key := rtflowKeyV4(47780)
	sender := &SessionSync{}
	sender.initGenState()
	receiver, dp := lossyRecvSync9752(t)

	const sessionID = 17780
	stated := dataplane.SessionValue{
		SessionID:       sessionID,
		RTFlowSessionID: sessionID,
		AppTimeout:      45,
		LogFlags:        dataplane.LogFlagSessionInit,
	}
	sender.stampInstallGenV4(key, &stated)
	if !stated.AppTimeoutLogStated {
		t.Fatal("nonzero sender pair was not marked present")
	}
	_, statedWire, ok := decodeSessionV4Payload(encodeSessionV4Payload(key, stated))
	if !ok || !statedWire.AppTimeoutLogStated || statedWire.AppTimeout != 45 || statedWire.LogFlags != 1 {
		t.Fatalf("nonzero stated wire pair: ok=%v stated=%v pair=%d/%d", ok, statedWire.AppTimeoutLogStated, statedWire.AppTimeout, statedWire.LogFlags)
	}
	if !receiver.installClusterSyncedV4(key, statedWire) {
		t.Fatal("receiver rejected stated nonzero install")
	}

	correction := dataplane.SessionValue{
		SessionID:           sessionID,
		RTFlowSessionID:     sessionID,
		AppTimeoutLogStated: true,
	}
	sender.stampInstallGenV4(key, &correction)
	if correction.AppTimeout != 0 || correction.LogFlags != 0 || !correction.AppTimeoutLogStated {
		t.Fatalf("stated zero correction changed: stated=%v pair=%d/%d", correction.AppTimeoutLogStated, correction.AppTimeout, correction.LogFlags)
	}
	_, zeroWire, ok := decodeSessionV4Payload(encodeSessionV4Payload(key, correction))
	if !ok || !zeroWire.AppTimeoutLogStated || zeroWire.AppTimeout != 0 || zeroWire.LogFlags != 0 {
		t.Fatalf("stated zero wire pair: ok=%v stated=%v pair=%d/%d", ok, zeroWire.AppTimeoutLogStated, zeroWire.AppTimeout, zeroWire.LogFlags)
	}
	if !receiver.installClusterSyncedV4(key, zeroWire) {
		t.Fatal("receiver rejected stated zero correction")
	}
	if got := lastSet9752(t, dp); got.AppTimeout != 0 || got.LogFlags != 0 || !got.AppTimeoutLogStated {
		t.Fatalf("receiver did not record stated zero: stated=%v pair=%d/%d", got.AppTimeoutLogStated, got.AppTimeout, got.LogFlags)
	}

	// An old peer omits the presence marker. Once this session has recorded a
	// stated zero, that legacy resend cannot resurrect the older nonzero pair.
	legacy := dataplane.SessionValue{
		SessionID:       sessionID,
		RTFlowSessionID: sessionID,
		Generation:      zeroWire.Generation + 1,
	}
	legacyPayload := encodeSessionV4Payload(key, legacy)
	_, legacyWire, ok := decodeSessionV4Payload(legacyPayload)
	if !ok || legacyWire.AppTimeoutLogStated {
		t.Fatalf("legacy resend unexpectedly carried presence marker: ok=%v stated=%v", ok, legacyWire.AppTimeoutLogStated)
	}
	if !receiver.installClusterSyncedV4(key, legacyWire) {
		t.Fatal("receiver rejected legacy stamp-less resend")
	}
	if got := lastSet9752(t, dp); got.AppTimeout != 0 || got.LogFlags != 0 || !got.AppTimeoutLogStated {
		t.Fatalf("legacy resend resurrected prior memo: stated=%v pair=%d/%d", got.AppTimeoutLogStated, got.AppTimeout, got.LogFlags)
	}

	// First-contact stamp-less zero remains absent and does not create a memo.
	first := &SessionSync{}
	first.initGenState()
	firstZero := dataplane.SessionValue{SessionID: sessionID + 1}
	first.stampInstallGenV4(rtflowKeyV4(47781), &firstZero)
	if firstZero.AppTimeoutLogStated || firstZero.AppTimeout != 0 || firstZero.LogFlags != 0 {
		t.Fatalf("first-contact stamp-less zero changed: stated=%v pair=%d/%d", firstZero.AppTimeoutLogStated, firstZero.AppTimeout, firstZero.LogFlags)
	}
	first.genState.genSentMu.Lock()
	_, recorded := first.genState.appTimeoutLogSentV4[rtflowKeyV4(47781)]
	first.genState.genSentMu.Unlock()
	if recorded {
		t.Fatal("first-contact stamp-less zero created a memo")
	}

	// Receiver-first legacy zero is also not a record or a correction.
	recvKey := rtflowKeyV4(47783)
	firstReceiver, recvDP := lossyRecvSync9752(t)
	recvZero := dataplane.SessionValue{SessionID: sessionID + 2, RTFlowSessionID: sessionID + 2}
	if !firstReceiver.installClusterSyncedV4(recvKey, recvZero) {
		t.Fatal("receiver rejected first-contact stamp-less zero")
	}
	if got := lastSet9752(t, recvDP); got.AppTimeout != 0 || got.LogFlags != 0 || got.AppTimeoutLogStated {
		t.Fatalf("receiver first-contact stamp-less zero changed: stated=%v pair=%d/%d", got.AppTimeoutLogStated, got.AppTimeout, got.LogFlags)
	}
	firstReceiver.genState.recvGenMu.Lock()
	_, recvRecorded := firstReceiver.genState.appTimeoutLogRecvV4[recvKey]
	firstReceiver.genState.recvGenMu.Unlock()
	if recvRecorded {
		t.Fatal("receiver first-contact stamp-less zero created a memo")
	}
}

func TestAppTimeoutLogStatedMarkerFailsClosed_17780(t *testing.T) {
	key := rtflowKeyV4(47782)
	val := dataplane.SessionValue{SessionID: 17782, AppTimeoutLogStated: true}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "unknown flag", mutate: func(payload []byte) { payload[len(payload)-1] = 2 }},
		{name: "malformed magic", mutate: func(payload []byte) { payload[len(payload)-appTimeoutLogStatedTailLen] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := encodeSessionV4Payload(key, val)
			tc.mutate(payload)
			_, decoded, ok := decodeSessionV4Payload(payload)
			if !ok || decoded.AppTimeoutLogStated {
				t.Fatalf("malformed marker did not fail closed: ok=%v stated=%v", ok, decoded.AppTimeoutLogStated)
			}
		})
	}
}
