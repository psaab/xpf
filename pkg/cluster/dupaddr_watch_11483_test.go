package cluster

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func captureBeaconWarns11483(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &out
}

// A near-edge accepted stamp has the earliest live deadline. At capacity,
// admitting another frame must not evict it and reopen a clock-step replay.
func TestDuplicateIdentityReplaySaturationKeepsSkewedNonce_11483(t *testing.T) {
	var c duplicateIdentityReplayCache
	base := time.Unix(1_700_000_000, 0)
	oldButAccepted := beaconTestNonce(0)
	replay, full := c.checkAndRecord(oldButAccepted, base.Add(duplicateIdentityBeaconMaxAge), base)
	if replay || full {
		t.Fatal("first skewed beacon was reported as a replay or blocked")
	}
	for i := 1; i < duplicateIdentityReplayCap; i++ {
		replay, full := c.checkAndRecord(beaconTestNonce(i), base.Add(duplicateIdentityBeaconMaxAge+time.Second), base)
		if replay || full {
			t.Fatalf("insert %d was reported as a replay or blocked", i)
		}
	}
	if replay, full := c.checkAndRecord(beaconTestNonce(duplicateIdentityReplayCap), base.Add(time.Hour), base); replay || !full {
		t.Fatal("a unique beacon at capacity was not reported as suppressed")
	}
	if replay, full := c.checkAndRecord(oldButAccepted, base.Add(duplicateIdentityBeaconMaxAge), base); !replay || full {
		t.Fatal("cache pressure evicted an accepted skewed nonce")
	}
}

// Old-but-accepted stamps must retain their nonce for 30s after receipt so a
// backward clock step cannot reopen the frame immediately after early expiry.
func TestDuplicateIdentityReplayTTLRetainsOldNonceAcrossBackwardStep_11483(t *testing.T) {
	receipt := time.Unix(1_700_000_000, 0)
	stamp := receipt.Add(-29 * time.Second)
	ttl := duplicateIdentityReplayTTL(stamp, receipt)
	if ttl != duplicateIdentityBeaconMaxAge {
		t.Fatalf("TTL for 29s-old accepted stamp = %s, want at least %s",
			ttl, duplicateIdentityBeaconMaxAge)
	}
	nonce := beaconTestNonce(5000)
	var cache duplicateIdentityReplayCache
	deadline := receipt.Add(ttl)
	if replay, full := cache.checkAndRecord(nonce, deadline, receipt); replay || full {
		t.Fatal("initial old-but-fresh nonce was not recorded")
	}
	// At 29s the wall clock steps back 29s, making the stamp fresh again.
	// The replay cache must not have swept the nonce at its original 1s
	// freshness remainder.
	cache.sweep(receipt.Add(29 * time.Second))
	if replay, full := cache.checkAndRecord(nonce, deadline, receipt); !replay || full {
		t.Fatal("a backward wall-clock step reopened an accepted nonce")
	}
	if futureTTL := duplicateIdentityReplayTTL(receipt.Add(29*time.Second), receipt); futureTTL != 59*time.Second {
		t.Fatalf("TTL for a 29s-future accepted stamp = %s, want 59s",
			futureTTL)
	}
}

func TestDuplicateIdentityBroadcastRejectsPointToPointPrefixes_11483(t *testing.T) {
	logs := captureBeaconWarns11483(t)
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	for _, prefix := range []string{"192.0.2.0/31", "192.0.2.1/32"} {
		ip, network, err := net.ParseCIDR(prefix)
		if err != nil {
			t.Fatalf("parse %s: %v", prefix, err)
		}
		if got, err := duplicateIdentityBroadcastForNetwork(ip, network); err == nil {
			t.Errorf("%s produced unsupported beacon broadcast %s", prefix, got)
		} else {
			mgr.noteDuplicateIdentityBeaconUnavailable("em0", "no usable IPv4 broadcast address", err)
		}
	}
	out := logs.String()
	if got := strings.Count(out, "duplicate-identity beacon unavailable"); got != 1 {
		t.Fatalf("point-to-point setup emitted %d warnings, want one per 30s: %s", got, out)
	}
	if !strings.Contains(out, "192.0.2.0/31") {
		t.Fatalf("point-to-point warning omitted the unsupported prefix: %s", out)
	}
	ip, network, err := net.ParseCIDR("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	got, err := duplicateIdentityBroadcastForNetwork(ip, network)
	if err != nil {
		t.Fatalf("/30 broadcast: %v", err)
	}
	if got.String() != "192.0.2.3:4786" {
		t.Fatalf("/30 broadcast = %s, want 192.0.2.3:4786", got)
	}
}

func TestDuplicateIdentityReplayAfterProcessRestartIsActionableAndRateLimited_11483(t *testing.T) {
	logs := captureBeaconWarns11483(t)
	const publishedWeakPSK = "change-me"
	now := time.Now()
	foreign := beaconTestInstance(t)
	frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(publishedWeakPSK), foreign, now)
	if err != nil {
		t.Fatalf("sign captured frame: %v", err)
	}

	// A process restart creates an empty replay cache. Preserve the existing
	// immediate day-0 signal, but make its process-scoped replay uncertainty
	// and recovery action explicit to the operator.
	restarted := keyedBeaconManager(t, publishedWeakPSK, "")
	watcher := newDuplicateIdentityWatcher(restarted, "em0", nil, nil, nil,
		time.Second, restarted.beaconSenderID())
	watcher.handleBeacon(frame, now)
	second, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(publishedWeakPSK), beaconTestInstance(t), now.Add(time.Second))
	if err != nil {
		t.Fatalf("sign second frame: %v", err)
	}
	watcher.handleBeacon(second, now.Add(time.Second))

	if got := beaconHistoryCount(restarted, "authenticated control-link beacon"); got != 1 {
		t.Fatalf("one 30s warning budget recorded %d beacon events, want 1", got)
	}
	out := logs.String()
	for _, want := range []string{"process restart", "does not prove", "correct /etc/xpf/node-id on one node", "rotate the control-link PSK"} {
		if !strings.Contains(out, want) {
			t.Errorf("operator warning %q does not explain replay uncertainty and recovery; log: %s", want, out)
		}
	}
	if strings.Contains(out, publishedWeakPSK) {
		t.Errorf("operator warning disclosed the PSK %q: %s", publishedWeakPSK, out)
	}
}

func TestIPv6OnlyBeaconSkipIsWarnedAndRateLimited_11483(t *testing.T) {
	logs := captureBeaconWarns11483(t)
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	for range 2 {
		if w := prepareDuplicateIdentityWatcher(mgr, "lo", "::1", "", time.Second); w != nil {
			w.stop()
			t.Fatal("IPv6-only control link unexpectedly created an IPv4 beacon watcher")
		}
	}
	out := logs.String()
	if got := strings.Count(out, "duplicate-identity beacon unavailable"); got != 1 {
		t.Fatalf("IPv6-only setup emitted %d operator warnings, want one per 30s: %s", got, out)
	}
	if !strings.Contains(out, "IPv6") {
		t.Fatalf("warning did not identify the unsupported IPv6-only signal gap: %s", out)
	}
}

func TestDuplicateIdentityReplayCacheSaturationWarnsAndPreservesNodeIDBudget_11483(t *testing.T) {
	logs := captureBeaconWarns11483(t)
	mgr := keyedBeaconManager(t, beaconTestPSK, "")
	now := time.Now()
	entries := make(map[[16]byte]time.Time, duplicateIdentityReplayCap)
	for i := range duplicateIdentityReplayCap {
		entries[beaconTestNonce(i)] = now.Add(time.Hour)
	}
	mgr.beaconReplay.entries = entries
	watcher := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil,
		time.Second, mgr.beaconSenderID())
	for range 2 {
		frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
			[]byte(beaconTestPSK), beaconTestInstance(t), now)
		if err != nil {
			t.Fatalf("sign saturation probe: %v", err)
		}
		watcher.handleBeacon(frame, now)
	}
	if got := strings.Count(logs.String(), "replay cache is full"); got != 1 {
		t.Fatalf("full-cache warning count = %d, want one per 30s: %s", got, logs.String())
	}
	if got := beaconHistoryCount(mgr, "duplicate node-id"); got != 0 {
		t.Fatalf("cache-suppressed beacons produced %d duplicate events, want 0", got)
	}
	mgr.NoteDuplicateNodeIDHeartbeat()
	if got := strings.Count(logs.String(), "duplicate node-id detected"); got != 1 {
		t.Fatalf("full-cache warning consumed the separate node-id budget: %s", logs.String())
	}
}

func TestPublishedWeakPSKStillAuthenticatesBeaconWarning_11483(t *testing.T) {
	const publishedWeakPSK = "change-me"
	mgr := keyedBeaconManager(t, publishedWeakPSK, "")
	frame, err := marshalDuplicateIdentityBeacon(beaconTestCluster, beaconTestNode,
		[]byte(publishedWeakPSK), beaconTestInstance(t), time.Now())
	if err != nil {
		t.Fatalf("sign with published PSK: %v", err)
	}
	watcher := newDuplicateIdentityWatcher(mgr, "em0", nil, nil, nil,
		time.Second, mgr.beaconSenderID())
	watcher.handleBeacon(frame, time.Now())
	if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
		t.Fatalf("an authenticated beacon signed with the published PSK produced %d warnings, want 1", got)
	}
}

func TestDuplicateIdentityRuntimeSocketFailuresAreWarned_11483(t *testing.T) {
	logs := captureBeaconWarns11483(t)

	sendMgr := keyedBeaconManager(t, beaconTestPSK, "")
	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("open sender: %v", err)
	}
	if err := send.Close(); err != nil {
		t.Fatalf("close sender: %v", err)
	}
	sender := newDuplicateIdentityWatcher(sendMgr, "em0", nil, send,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, time.Second, sendMgr.beaconSenderID())
	sender.sendBeacon()
	sender.sendBeacon()

	readMgr := keyedBeaconManager(t, beaconTestPSK, "")
	listen, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("open listener: %v", err)
	}
	if err := listen.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	reader := newDuplicateIdentityWatcher(readMgr, "em0", listen, nil, nil,
		time.Second, readMgr.beaconSenderID())
	for range 2 {
		if n, alive := reader.readStep(make([]byte, duplicateIdentityBeaconReadLen)); n != 0 || !alive {
			t.Fatalf("closed-listener read returned n=%d alive=%v, want n=0 and alive", n, alive)
		}
	}
	out := logs.String()
	if got := strings.Count(out, "duplicate-identity beacon socket failure"); got != 2 {
		t.Fatalf("send/read socket failures emitted %d health warnings, want one per operation: %s", got, out)
	}
	for _, operation := range []string{"send", "read"} {
		if !strings.Contains(out, "reason="+operation) {
			t.Errorf("socket warning omitted %s operation: %s", operation, out)
		}
	}
}
