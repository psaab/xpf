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
	mirror.AppTimeout, mirror.LogFlags = 0, 0
	sender.stampInstallGenV4(key, &mirror)
	if mirror.AppTimeout != 86401 || mirror.LogFlags != 3 {
		t.Fatalf("swept frame lost app timeout/log: %d/%d want 86401/3", mirror.AppTimeout, mirror.LogFlags)
	}
	_, wireVal, ok := decodeSessionV4Payload(encodeSessionV4Payload(key, mirror))
	if !ok || wireVal.AppTimeout != 86401 || wireVal.LogFlags != 3 {
		t.Fatalf("wire lost app timeout/log: ok=%v %d/%d", ok, wireVal.AppTimeout, wireVal.LogFlags)
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
	mirror.AppTimeout, mirror.LogFlags = 0, 0
	sender.stampInstallGenV6(key, &mirror)
	if mirror.AppTimeout != 30 || mirror.LogFlags != 2 {
		t.Fatalf("swept v6 lost: %d/%d want 30/2", mirror.AppTimeout, mirror.LogFlags)
	}
	_, wireVal, ok := decodeSessionV6Payload(encodeSessionV6Payload(key, mirror))
	if !ok || wireVal.AppTimeout != 30 || wireVal.LogFlags != 2 {
		t.Fatalf("v6 wire lost: ok=%v %d/%d", ok, wireVal.AppTimeout, wireVal.LogFlags)
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
