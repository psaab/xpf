package cluster

import (
	"fmt"
	"testing"
)

// samplePkt is a representative heartbeat with a couple of RGs and a monitor,
// used across the auth tests.
func samplePkt() *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         42,
		SoftwareVersion:   "xpf-test-1",
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 1, Priority: 150, Weight: 100, State: uint8(StateSecondary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 0, Weight: 10, Up: true, Interface: "ge-0-0-1"},
		},
	}
}

// TestMarshalHeartbeatAuth_RoundTrip verifies a signed frame carries a
// detectable, verifiable auth trailer while the body still parses.
func TestMarshalHeartbeatAuth_RoundTrip(t *testing.T) {
	key := []byte("cluster-shared-secret")
	pkt := samplePkt()
	data := MarshalHeartbeatAuth(pkt, key, 0xdeadbeef, 7)

	// The body still decodes (RG/monitor/version) with the trailer appended.
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal authed frame: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[0].Priority != 200 {
		t.Errorf("body parse wrong: %+v", got.Groups)
	}
	if got.SoftwareVersion != "xpf-test-1" {
		t.Errorf("software version lost under auth trailer: %q", got.SoftwareVersion)
	}

	session, counter, present := heartbeatAuthTrailer(data)
	if !present {
		t.Fatal("auth trailer not detected on signed frame")
	}
	if session != 0xdeadbeef || counter != 7 {
		t.Errorf("nonce = (%d,%d), want (%d,7)", session, counter, uint64(0xdeadbeef))
	}
	if !verifyHeartbeatMAC(data, key) {
		t.Error("valid HMAC rejected")
	}
}

// TestMarshalHeartbeatAuth_NoKeyIsLegacy verifies that an empty key yields a
// byte-identical legacy frame with no trailer (dual-accept: a node without a
// key emits legacy).
func TestMarshalHeartbeatAuth_NoKeyIsLegacy(t *testing.T) {
	pkt := samplePkt()
	legacy := MarshalHeartbeat(pkt)
	authed := MarshalHeartbeatAuth(pkt, nil, 1, 1)
	if len(authed) != len(legacy) || string(authed) != string(legacy) {
		t.Fatalf("empty key must produce legacy frame: authed=%d legacy=%d", len(authed), len(legacy))
	}
	if _, _, present := heartbeatAuthTrailer(authed); present {
		t.Error("legacy frame must not carry an auth trailer")
	}
}

// TestMarshalHeartbeatAuth_NeverUnsignedWhenKeyed is the #4107 invariant: a
// config large enough to overflow the frame (many interface monitors) STILL
// yields a SIGNED frame when a key is configured — the best-effort monitor
// section is truncated to make room, but the HMAC is always present and
// verifies, and the election-critical RG groups survive. RED on revert:
// dropping the trailer reserve (marshalHeartbeatBody tailReserve) lets the body
// fill to the cap so MarshalHeartbeatAuth would emit an UNSIGNED frame
// (present==false) that an enforcing peer rejects -> dual-primary split.
func TestMarshalHeartbeatAuth_NeverUnsignedWhenKeyed(t *testing.T) {
	key := []byte("cluster-shared-secret")
	pkt := &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         42,
		SoftwareVersion:   "xpf-overflow-version-string",
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 1, Priority: 150, Weight: 100, State: uint8(StateSecondary)},
		},
	}
	// Enough monitors with long names to blow well past the 1472-byte cap so
	// the monitor section MUST be truncated to fit the trailer.
	for i := 0; i < 300; i++ {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID:      uint8(i % 2),
			Weight:    10,
			Up:        true,
			Interface: fmt.Sprintf("monitor-interface-name-%04d", i),
		})
	}

	data := MarshalHeartbeatAuth(pkt, key, 0xabc, 1)

	if len(data) > maxHeartbeatSize {
		t.Fatalf("signed frame exceeds cap: %d > %d", len(data), maxHeartbeatSize)
	}
	if _, _, present := heartbeatAuthTrailer(data); !present {
		t.Fatal("keyed heartbeat emitted UNSIGNED under frame overflow — an enforcing peer would reject every frame (dual-primary)")
	}
	if !verifyHeartbeatMAC(data, key) {
		t.Error("overflow-truncated signed frame failed HMAC verification")
	}
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal truncated signed frame: %v", err)
	}
	if len(got.Groups) != 2 {
		t.Errorf("election-critical groups dropped under truncation: got %d, want 2", len(got.Groups))
	}
	// Monitors WERE truncated — that is how room for the HMAC was made.
	if len(got.Monitors) >= len(pkt.Monitors) {
		t.Errorf("expected monitor truncation to make room for the trailer, got %d of %d",
			len(got.Monitors), len(pkt.Monitors))
	}
}

// TestVerifyHeartbeatMAC_TamperAndWrongKey verifies the MAC rejects a modified
// frame and a wrong key — the core anti-forgery property.
func TestVerifyHeartbeatMAC_TamperAndWrongKey(t *testing.T) {
	key := []byte("cluster-shared-secret")
	data := MarshalHeartbeatAuth(samplePkt(), key, 5, 1)

	if !verifyHeartbeatMAC(data, key) {
		t.Fatal("baseline valid MAC rejected")
	}

	// Wrong key.
	if verifyHeartbeatMAC(data, []byte("attacker-guess")) {
		t.Error("MAC accepted under wrong key")
	}

	// Tamper a body byte (flip the priority of group 0). heartbeatHeaderSize is
	// the start of the group section.
	tampered := append([]byte(nil), data...)
	tampered[heartbeatHeaderSize+1] ^= 0xFF
	if verifyHeartbeatMAC(tampered, key) {
		t.Error("MAC accepted a tampered body")
	}

	// Tamper the MAC itself.
	tampered2 := append([]byte(nil), data...)
	tampered2[len(tampered2)-1] ^= 0xFF
	if verifyHeartbeatMAC(tampered2, key) {
		t.Error("MAC accepted a tampered digest")
	}
}

// TestHeartbeatAuthReplay verifies intra-session monotonic acceptance and
// session-change re-anchor (reboot tolerance).
func TestHeartbeatAuthReplay(t *testing.T) {
	var r heartbeatAuthReplay

	if !r.admit(100, 1) {
		t.Fatal("first heartbeat must be admitted")
	}
	if !r.admit(100, 2) {
		t.Error("strictly increasing counter must be admitted")
	}
	if r.admit(100, 2) {
		t.Error("replay of the same counter must be rejected")
	}
	if r.admit(100, 1) {
		t.Error("lower counter within a session must be rejected")
	}
	// New sender session (restart/reboot) re-anchors even with a lower counter.
	if !r.admit(200, 1) {
		t.Error("new session must re-anchor and be admitted (reboot tolerance)")
	}
	if !r.admit(200, 2) {
		t.Error("post-reanchor increasing counter must be admitted")
	}
	if r.admit(200, 2) {
		t.Error("replay after re-anchor must be rejected")
	}
}

// TestHeartbeatAuthReplay_RetiredSessionABA is the #5477 fail-on-revert gate:
// an on-link attacker who recorded authenticated frames from two peer
// incarnations A and B cannot replay them in an A->B->A alternation. Once B
// becomes the active session, A is RETIRED but its counter watermark is still
// remembered, so a return to A at (or below) that watermark is rejected — while
// a genuinely NEW, never-seen session C (a real reboot) is still admitted.
//
// RED-on-revert: the fix is the per-session watermark scan in
// heartbeatAuthReplay.admit (`for i := 0; i < a.count; i++`). Neutralizing that
// scan bound to `i < 0` reverts to the single-watermark behavior where any
// session switch re-anchors, so the replayed A(1) below is wrongly re-admitted
// and this test goes RED as an assertion failure (not a build break).
func TestHeartbeatAuthReplay_RetiredSessionABA(t *testing.T) {
	const (
		sessA = 0xAAAA
		sessB = 0xBBBB
		sessC = 0xCCCC
	)
	var r heartbeatAuthReplay

	// Genuine incarnation A: the attacker records A(1) and A(2).
	if !r.admit(sessA, 1) {
		t.Fatal("A(1): first frame from incarnation A must be admitted")
	}
	if !r.admit(sessA, 2) {
		t.Fatal("A(2): strictly increasing counter within A must be admitted")
	}

	// Genuine reboot to incarnation B (a routine HA event): fresh random
	// session, admitted. This RETIRES A.
	if !r.admit(sessB, 1) {
		t.Fatal("B(1): a genuinely new session (real reboot) must be admitted")
	}

	// The #5477 replay: the attacker re-injects the recorded A(1) after the B
	// switch. Pre-fix this re-anchored A and returned true (refreshing liveness
	// and applying A's stale role); the retired-session watermark must reject
	// it now.
	if r.admit(sessA, 1) {
		t.Error("#5477: replay of retired session A(1) after switch to B must be REJECTED")
	}
	if r.admit(sessA, 2) {
		t.Error("#5477: replay of retired session A(2) after switch to B must be REJECTED")
	}
	// Sustained alternation must stay closed: bouncing back to B replays are
	// also at/below B's watermark.
	if r.admit(sessB, 1) {
		t.Error("#5477: replay of B(1) after it is the active session must be REJECTED")
	}
	if r.admit(sessA, 1) {
		t.Error("#5477: a second A->B->A bounce must remain REJECTED")
	}

	// A genuinely fresh, never-seen session C (a real second reboot) must still
	// be admitted — the fix must not break legitimate reboot tolerance.
	if !r.admit(sessC, 1) {
		t.Error("a genuinely new session C (legit reboot) must still be admitted")
	}
	// And the live session B may still advance its own counter.
	if !r.admit(sessB, 2) {
		t.Error("the retired-B watermark must still admit a strictly newer B counter")
	}
}

// TestHeartbeatAuthReplay_BoundedRing verifies the retired-session set is
// bounded (heartbeatReplaySessions) with FIFO eviction, and documents the
// security consequence: an entry is evicted ONLY after heartbeatReplaySessions
// distinct NEWER sessions arrive — each of which requires a genuine peer reboot
// (an attacker cannot mint valid frames for new sessions).
//
// A post-eviction replay of ONE session re-anchors once and no more (further
// replays of THAT session are <= the restored watermark), which is all the
// assertions below exercise — they retry the same session immediately. That is
// NOT the same as "a post-eviction replay cannot be sustained", which an
// earlier revision of this header claimed: CYCLING all heartbeatReplaySessions+1
// captured sessions round-robin does sustain it, because FIFO eviction always
// leaves exactly one just-evicted session to replay back in as never-seen. See
// TestHeartbeatBootEpochClosesSustainedReplay_6169's
// baseline_legacy_over_ring_capacity_is_sustained subtest, which measures the
// sustained case this ring cannot close on its own — closing it is the boot
// epoch's job (heartbeat_epoch.go).
func TestHeartbeatAuthReplay_BoundedRing(t *testing.T) {
	var r heartbeatAuthReplay

	// Oldest remembered session.
	const oldest = 0x1000
	if !r.admit(oldest, 5) {
		t.Fatal("oldest session must be admitted")
	}
	// While the ring is not yet full, the oldest watermark still rejects a
	// replay at/below it.
	if r.admit(oldest, 5) {
		t.Fatal("replay of the oldest session (still remembered) must be rejected")
	}

	// Drive exactly heartbeatReplaySessions distinct NEWER sessions through the
	// ring. That is one full ring of fresh sessions, evicting `oldest`.
	for i := 0; i < heartbeatReplaySessions; i++ {
		s := uint64(0x2000 + i)
		if !r.admit(s, 1) {
			t.Fatalf("new session %#x must be admitted", s)
		}
	}
	if r.count != heartbeatReplaySessions {
		t.Fatalf("ring count = %d, want saturated at %d", r.count, heartbeatReplaySessions)
	}

	// `oldest` has now been evicted (FIFO). A replay is treated as a fresh
	// never-seen session and re-anchors ONCE — the accepted residual after
	// enough genuine reboots. This requires heartbeatReplaySessions genuine
	// reboots to reach, which an attacker cannot manufacture (HMAC blocks
	// minting new valid sessions).
	if !r.admit(oldest, 5) {
		t.Error("post-eviction replay re-anchors once (documented residual)")
	}
	// But it cannot be SUSTAINED: the re-anchor restored oldest's watermark, so
	// a further replay at/below it is rejected again.
	if r.admit(oldest, 5) {
		t.Error("post-eviction re-anchor must restore the watermark; a sustained replay must be rejected")
	}
}

// TestHeartbeatReplayGatesLivenessRefresh binds the read-loop consequence: a
// heartbeat may refresh peer liveness (r.lastSeen) and drive election
// (handlePeerHeartbeat) only when the auth gate ACCEPTS. A #5477 A->B->A replay
// must therefore leave lastSeen untouched.
//
// It drives heartbeatReceiver.admitFrame — the SAME function readLoop calls for
// every datagram — and asserts on the receiver's OWN r.lastSeen.
//
// It used to do neither. It reconstructed the gate in a local `gate` closure
// and counted a local `liveness` integer "standing in for
// r.lastSeen.Store(MonotonicNanos()) in the readLoop". That is a third
// hand-copy of the production gate (the two feed helpers were the others), and
// it was measuring its own copy: the readLoop epoch read could be severed and
// this test stayed green. A simulated consequence proves nothing about the real
// one — assert on the field production writes.
//
// RED-on-revert: reverting heartbeatAuthReplay.admit re-admits the replay,
// accept flips true, and lastSeen advances on a replayed frame.
func TestHeartbeatReplayGatesLivenessRefresh(t *testing.T) {
	m := epochGateManager() // keyed with epochTestPSK, which is the key below
	key := m.controlLinkAuthKey()
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)

	const (
		sessA = 0xA11CE
		sessB = 0xB0B
	)
	// feed drives the REAL receive gate and reports whether it accepted.
	feed := func(frame []byte) bool {
		t.Helper()
		pkt, err := UnmarshalHeartbeat(frame)
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return r.admitFrame(frame, pkt)
	}

	aOne := MarshalHeartbeatAuth(samplePkt(), key, sessA, 1)
	bOne := MarshalHeartbeatAuth(samplePkt(), key, sessB, 1)

	if !feed(aOne) {
		t.Fatal("genuine A(1) must be accepted")
	}
	if !feed(bOne) {
		t.Fatal("genuine reboot to B(1) must be accepted")
	}
	// The liveness stamp production actually writes, sampled after the last
	// GENUINE frame. MonotonicNanos has nanosecond resolution, so a refresh by
	// the replay below is observable as a change.
	after := r.lastSeen.Load()
	if after == 0 {
		t.Fatal("setup: an accepted frame must have stamped lastSeen")
	}

	if feed(aOne) { // #5477 replay of retired A(1)
		t.Error("#5477: replayed retired frame must fail the receive gate")
	}
	if got := r.lastSeen.Load(); got != after {
		t.Errorf("#5477: a replayed retired heartbeat refreshed peer liveness — "+
			"r.lastSeen moved %d -> %d. A replay that refreshes lastSeen keeps a DEAD peer "+
			"looking alive, so the survivor never takes over its RGs.", after, got)
	}
}

// TestHeartbeatAuthDecision is the RED-on-revert core: it pins the accept/reject
// truth table of the dual-accept policy. Reverting the enforcement (e.g. always
// returning accept, or dropping the macOK/peerAuthSeen checks) turns one of
// these REJECT cases GREEN — i.e. a forged/unauthenticated heartbeat would
// drive election.
func TestHeartbeatAuthDecision(t *testing.T) {
	cases := []struct {
		name                                       string
		keyConfigured, present, macOK, nonceFresh bool
		wantAccept                                 bool
	}{
		// No local key -> dual-accept everything (cannot verify; may be the
		// not-yet-keyed side of a rolling upgrade). No regression.
		{"no-key/legacy", false, false, false, false, true},
		{"no-key/authed-frame", false, true, false, false, true},

		// Local key + authed frame -> enforce.
		{"key/good-hmac-fresh", true, true, true, true, true},
		{"key/bad-hmac", true, true, false, false, false},       // forged/tampered -> REJECT
		{"key/good-hmac-replay", true, true, true, false, false}, // replayed nonce -> REJECT

		// Local key + no trailer is always rejected. There is no first-contact
		// grace; this mirrors the #5078 session-sync fail-closed policy.
		{"key/legacy-peer-not-yet-authed", true, false, false, false, false},
		{"key/legacy-after-peer-authed", true, false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := heartbeatAuthDecision(tc.keyConfigured, tc.present, tc.macOK, tc.nonceFresh)
			if got != tc.wantAccept {
				t.Fatalf("accept = %v (reason %q), want %v", got, reason, tc.wantAccept)
			}
			if !got && reason == "" {
				t.Error("a rejection must carry a non-empty reason")
			}
		})
	}
}

// TestHeartbeatAuthDecision_ForgedFrameRejected is the end-to-end anti-forgery
// assertion tying the wire path to the decision: a frame signed with the WRONG
// key (an attacker who does not hold the PSK) is rejected on a keyed node,
// including before the peer has authenticated in this process. RED on revert:
// if the receiver stops enforcing, macOK would be ignored and this forged
// frame would be accepted -> forced election.
func TestHeartbeatAuthDecision_ForgedFrameRejected(t *testing.T) {
	realKey := []byte("real-cluster-psk")
	forged := MarshalHeartbeatAuth(samplePkt(), []byte("attacker-psk"), 9, 1)

	_, _, present := heartbeatAuthTrailer(forged)
	macOK := present && verifyHeartbeatMAC(forged, realKey)
	if macOK {
		t.Fatal("forged frame verified under the real key — HMAC broken")
	}
	accept, reason := heartbeatAuthDecision(true, present, macOK, false)
	if accept {
		t.Fatalf("forged heartbeat accepted (reason %q) — forged frame drives election", reason)
	}

	// A correctly-signed frame from the genuine peer is accepted.
	good := MarshalHeartbeatAuth(samplePkt(), realKey, 9, 2)
	var replay heartbeatAuthReplay
	s, c, gp := heartbeatAuthTrailer(good)
	goodMAC := gp && verifyHeartbeatMAC(good, realKey)
	fresh := goodMAC && replay.admit(s, c)
	if accept2, _ := heartbeatAuthDecision(true, gp, goodMAC, fresh); !accept2 {
		t.Error("correctly-signed heartbeat rejected")
	}
}

// TestManagerHeartbeatPeerAuthSeen pins the #4107 arming wire the gRPC fabric
// listener reads to close its post-restart downgrade window: an unarmed
// manager reports false; once a verified authed heartbeat has arrived it
// reports true. #5086 additionally pins that the flag is sticky for the life
// of the PROCESS, not the life of a heartbeat — tearing the receiver down (as
// StopHeartbeat/RestartHeartbeat do) must not disarm the guard.
func TestManagerHeartbeatPeerAuthSeen(t *testing.T) {
	m := &Manager{}
	if m.HeartbeatPeerAuthSeen() {
		t.Error("no heartbeat started: expected false")
	}
	r := &heartbeatReceiver{mgr: m, auth: m.heartbeatAuthState()}
	m.hbReceiver = r
	if m.HeartbeatPeerAuthSeen() {
		t.Error("receiver unarmed (peer not yet authenticated): expected false")
	}
	// A verified authed heartbeat arms the sticky flag (readLoop does this).
	r.auth.notePeerAuthenticated()
	if !m.HeartbeatPeerAuthSeen() {
		t.Error("receiver armed: expected true")
	}

	// #5086: a heartbeat restart drops the receiver and installs a new one.
	// The peer has already PROVEN it holds the PSK, so the downgrade-guard
	// must stay armed across the whole restart window (a VRF-rebind restart
	// retries the bind for up to ~5s).
	m.hbReceiver = nil
	if !m.HeartbeatPeerAuthSeen() {
		t.Error("#5086: tearing down the receiver must NOT disarm the downgrade-guard")
	}
	m.hbReceiver = &heartbeatReceiver{mgr: m, auth: m.heartbeatAuthState()}
	if !m.HeartbeatPeerAuthSeen() {
		t.Error("#5086: a freshly installed receiver must inherit the armed guard")
	}
}

// #6968: the reason a rejected heartbeat carries must NAME THE ARM that
// refused it, and nothing bound that.
//
// THE SHAPE OF THE DEFECT IS MISATTRIBUTION, NOT ADMISSION. A forged or
// tampered frame is rejected either way — this was never a fail-open — so a
// test that asserts "rejected" passes identically against the working code and
// against the broken code. The only observable that separates them is WHICH
// reason string comes back, and until now no test in this package asserted any
// of them: `grep -rn "hmac verification failed" pkg/cluster/*_test.go` returned
// zero hits.
//
// WHY THE ARM CAN VANISH SILENTLY. `heartbeatAuthDecision`'s correctness here
// rests entirely on ARM ORDER. The caller computes
//
//	if macOK { nonceFresh, epochReason = r.auth.admitAuthed(...) }
//
// so a frame that fails its MAC leaves `nonceFresh` at the zero value FALSE and
// `epochReason` empty. Delete or disable the `!macOK` arm and the frame falls
// through to `!nonceFresh`, and a forged frame — a wrong key, a flipped byte, an
// active on-link attacker — is reported to the operator as `stale nonce
// (replay)`. The epoch gate's `epochReason` override cannot save it: on a bad
// MAC `admitAuthed` never runs, so there is no epoch reason to prefer.
//
// Measured on origin/master 63ef1fad6: changing `if !macOK` to `if false` left
// `go vet` at rc=0 and the ENTIRE pkg/cluster suite GREEN. That is the gap this
// test closes; it reds that mutation by name.
//
// The operator cost is the point. "Replay" points at a retired peer incarnation
// and the anti-replay machinery; a bad MAC points at a key mismatch or an
// attacker holding the wrong PSK. Sending someone to audit nonces while an
// on-link forger is active is the failure this reason exists to prevent.
func TestHeartbeatAuthDecisionReasonNamesTheArm_6968(t *testing.T) {
	const (
		reasonBadMAC  = "hmac verification failed"
		reasonReplay  = "stale nonce (replay)"
		reasonMissing = "missing auth trailer (enforced: local key configured)"
	)
	// The binding is only as good as the strings being DIFFERENT. If two arms
	// ever returned the same text, every assertion below would still pass while
	// the arms became indistinguishable again — the exact property under test.
	for _, pair := range [][2]string{
		{reasonBadMAC, reasonReplay},
		{reasonBadMAC, reasonMissing},
		{reasonReplay, reasonMissing},
	} {
		if pair[0] == pair[1] {
			t.Fatalf("two arms share the reason %q; the arms are indistinguishable "+
				"and every assertion in this test is vacuous", pair[0])
		}
	}

	cases := []struct {
		name                                       string
		keyConfigured, present, macOK, nonceFresh bool
		wantAccept                                 bool
		wantReason                                 string
	}{
		{"no-key/legacy", false, false, false, false, true, ""},
		{"no-key/authed-frame", false, true, false, false, true, ""},
		{"key/good-hmac-fresh", true, true, true, true, true, ""},

		// THE CELL THIS TEST EXISTS FOR. macOK=false forces nonceFresh=false in
		// the real caller, so both rejecting arms are live at once and only the
		// ORDER decides the reason. `if !macOK` -> `if false` reds here.
		{"key/bad-hmac", true, true, false, false, false, reasonBadMAC},
		// ...and its discriminating partner: a frame whose MAC is GOOD and whose
		// nonce is stale must still say replay. Without this row the test could
		// be satisfied by returning the bad-MAC reason unconditionally.
		{"key/good-hmac-replay", true, true, true, false, false, reasonReplay},

		// Both unsigned rows reject for the same local-key reason, regardless of
		// whether the process has seen a genuine peer frame.
		{"key/legacy-peer-not-yet-authed", true, false, false, false, false, reasonMissing},
		{"key/legacy-after-peer-authed", true, false, false, false, false, reasonMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := heartbeatAuthDecision(tc.keyConfigured, tc.present, tc.macOK, tc.nonceFresh)
			if got != tc.wantAccept {
				t.Fatalf("accept = %v (reason %q), want %v", got, reason, tc.wantAccept)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q. The frame's admission is unchanged either "+
					"way — this is the operator-facing CAUSE, and a wrong one sends them "+
					"hunting the wrong fault (#6968)", reason, tc.wantReason)
			}
		})
	}
}

// TestForgedHeartbeatIsNotReportedAsReplay_6968 binds the same property through
// a REAL forged frame rather than hand-set booleans.
//
// `macOK` here is DERIVED — the frame is signed with an attacker's key and
// verified against the real one — so this covers the frame -> trailer -> MAC ->
// reason chain, not just the decision function's truth table. The hand-set
// version cannot see a regression that makes `verifyHeartbeatMAC` succeed on a
// forged frame; this one reds on both that and on the arm removal.
//
// `nonceFresh` is passed FALSE because that is what the production caller
// necessarily passes when the MAC fails (`admitAuthed` is called only under
// `if macOK`). Passing true here would describe a state the receiver cannot
// produce and would let the bad-MAC arm look load-bearing when it is not.
func TestForgedHeartbeatIsNotReportedAsReplay_6968(t *testing.T) {
	realKey := []byte("real-cluster-psk")
	forged := MarshalHeartbeatAuth(samplePkt(), []byte("attacker-psk"), 9, 1)

	_, _, present := heartbeatAuthTrailer(forged)
	macOK := present && verifyHeartbeatMAC(forged, realKey)
	if !present {
		t.Fatal("forged frame carries no auth trailer — fixture does not reach the arm")
	}
	if macOK {
		t.Fatal("forged frame verified under the real key — HMAC broken")
	}

	accept, reason := heartbeatAuthDecision(true, present, macOK, false)
	if accept {
		t.Fatalf("forged heartbeat accepted (reason %q)", reason)
	}
	if reason == "stale nonce (replay)" {
		t.Fatal("a FORGED heartbeat is reported as `stale nonce (replay)`. The frame is " +
			"still refused, so admission is unaffected — but the operator is pointed at a " +
			"retired peer incarnation and the anti-replay machinery instead of at a key " +
			"mismatch or an on-link attacker holding the wrong PSK (#6968)")
	}
	if reason != "hmac verification failed" {
		t.Fatalf("reason = %q, want %q", reason, "hmac verification failed")
	}
}
