package cluster

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

var (
	rotKeyA = []byte("rotation-key-A-6630-long-enough-for-advice")
	rotKeyB = []byte("rotation-key-B-6630-long-enough-for-advice")
)

// rotNode is one side of the rotation: what it SIGNS with and what it ACCEPTS.
type rotNode struct {
	m *Manager
	r *heartbeatReceiver
}

func newRotNode(t *testing.T, nodeID int) *rotNode {
	t.Helper()
	m := NewManager(nodeID, 42)
	n := &rotNode{m: m}
	n.r = newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	n.r.startedAt = time.Now().Add(-2 * heartbeatStartupGrace)
	m.mu.Lock()
	m.hbReceiver = n.r
	m.mu.Unlock()
	return n
}

// commit applies a config exactly as a real commit does — through
// Manager.UpdateConfig — so the test exercises the production plumbing from
// the config leaves down, not a hand-set field. Severing the
// ControlLinkAuthKeyAlt plumb in group_state.go reds every step below.
func (n *rotNode) commit(signing, additional []byte) {
	cfg := &config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret(string(signing)),
		ControlLinkAuthKeyAlt: config.NewSecret(string(additional)),
	}
	n.m.UpdateConfig(cfg)
}

// sends builds a heartbeat signed with whatever this node currently SIGNS
// with. Nothing is ever signed with the additional key — that asymmetry is the
// whole reason the two commits can be separated in time.
//
// EPOCH-BEARING, because that is what the sender emits
// (heartbeatSender marshals with s.mgr.heartbeatBootEpoch()). An epochless
// fixture would not exercise the read at all: heartbeatFrameEpoch returns
// hasEpoch=false whatever key it is handed, so the epoch decode could be
// pointed at the wrong key and every assertion here would still pass. The
// #6630 mutation matrix caught exactly that — the epoch cell was GREEN until
// this fixture carried an epoch.
//
// That matters because the epoch read must use the key that actually
// VERIFIED, not the signing key. On a frame admitted under the additional key,
// decoding the epoch with the signing key yields garbage, which lands below
// the #6169 floor and REJECTS the frame the gate just accepted —
// reintroducing the outage inside the fix for it, and only ever on real
// traffic.
func (n *rotNode) sends(session, counter, epoch uint64) []byte {
	return marshalHeartbeatAuthEpoch(samplePkt(), n.m.controlLinkAuthKey(), session, counter, epoch)
}

// accepts drives the REAL gate (heartbeatReceiver.admitFrame — the same
// function readLoop calls for every datagram) and reports whether the frame
// was admitted. Acceptance is what refreshes lastSeen, so "accepted" IS
// "liveness refreshed"; a rejected frame leaves the peer ageing toward the
// ~1s dead-declaration that produces dual-master.
func (n *rotNode) accepts(t *testing.T, frame []byte) bool {
	t.Helper()
	pkt, err := UnmarshalHeartbeat(frame)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return n.r.admitFrame(frame, pkt)
}

// TestPSKRotationNeverLosesHeartbeatLiveness6630 is the gate #6630 asks for:
// walk a full A->B rotation ONE NODE AT A TIME and assert that at EVERY step,
// in BOTH directions, the receiving node still admits what the sending node is
// signing.
//
// This is the property, not a proxy for it. Admission is exactly what
// refreshes `lastSeen`; a rejected frame does not, and after
// heartbeat-interval x threshold (~1s at shipped settings) both nodes declare
// the peer dead and both take over their redundancy groups — dual-master with
// duplicate VIPs for the whole window between the two commits. Every step
// below is a state the cluster genuinely sits in for as long as the operator
// takes to run the next commit, which on a two-node maintenance is minutes,
// not milliseconds.
//
// FAIL-ON-REVERT: make admitFrame verify against controlLinkAuthKey() alone
// instead of controlLinkAcceptedKeys() and STEP 3 reds. Step 3 is the only one
// where the two nodes hold different SIGNING keys — and it is unavoidable,
// because the two commits cannot be simultaneous. Steps 1, 2 and 4 pass with
// or without the overlap; they are here because the sequence is the
// deliverable, and a test that jumped straight to the asymmetric state would
// not show an operator the path that reaches it safely. Only step 3 is load-
// bearing for the mechanism, and the matrix says so rather than letting the
// green steps imply coverage they do not provide.
func TestPSKRotationNeverLosesHeartbeatLiveness6630(t *testing.T) {
	node0 := newRotNode(t, 0)
	node1 := newRotNode(t, 1)

	// Distinct replay sessions per direction; the counter advances every frame
	// so the anti-replay ring never rejects for an unrelated reason. A shared
	// session or a static counter would make a later step fail as a replay and
	// be misread as the overlap failing.
	var counter uint64
	// A fixed, plausible boot epoch on both sides. It never moves during the
	// walk (neither node reboots), so the #6169 floor admits every frame —
	// leaving the overlap as the only thing that can reject one.
	const rotEpoch uint64 = 1_700_000_000
	step := func(name string, cfg0sign, cfg0alt, cfg1sign, cfg1alt []byte) {
		t.Helper()
		node0.commit(cfg0sign, cfg0alt)
		node1.commit(cfg1sign, cfg1alt)
		counter++
		if !node1.accepts(t, node0.sends(0xD0DE0, counter, rotEpoch)) {
			t.Fatalf("%s: node1 REJECTED the heartbeat node0 is signing — liveness lost in "+
				"node0->node1, so node1 ages node0 out in ~1s and takes over its RGs while "+
				"node0 is still healthy (#6630)", name)
		}
		if !node0.accepts(t, node1.sends(0xD0DE1, counter, rotEpoch)) {
			t.Fatalf("%s: node0 REJECTED the heartbeat node1 is signing — liveness lost in "+
				"node1->node0 (#6630)", name)
		}
	}

	step("step 0: steady state on A", rotKeyA, nil, rotKeyA, nil)
	step("step 1: node0 opens its window (both still SIGN A — passes without the overlap)",
		rotKeyA, rotKeyB, rotKeyA, nil)
	step("step 2: node1 opens its window (both still SIGN A — passes without the overlap)",
		rotKeyA, rotKeyB, rotKeyA, rotKeyB)
	step("step 3: node0 signs B, node1 still signs A — THE asymmetric state; only the overlap carries it",
		rotKeyB, rotKeyA, rotKeyA, rotKeyB)
	step("step 4: node1 signs B too (both SIGN B — passes without the overlap)",
		rotKeyB, rotKeyA, rotKeyB, rotKeyA)
	step("step 5: finalize — both retire A", rotKeyB, nil, rotKeyB, nil)
}

// TestPSKRotationFinalizeRejectsTheRetiredKey6630 is the other half of the
// gate: the overlap must not be permanent. After finalize, a frame signed with
// the retired key must be REJECTED — otherwise "rotation" only ever adds keys
// and the old one authenticates the control channel forever, which is the
// opposite of what a rotation is for.
//
// FAIL-ON-REVERT: make the UpdateConfig plumb keep a previously-set
// controlAuthKeyAlt when the leaf is cleared (an "additive" clear) and this
// reds — the retired key stays accepted.
func TestPSKRotationFinalizeRejectsTheRetiredKey6630(t *testing.T) {
	n := newRotNode(t, 0)

	// Mid-rotation: signing B, still accepting A.
	n.commit(rotKeyB, rotKeyA)
	if !n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyA, 0xA11CE, 1)) {
		t.Fatal("mid-rotation, a frame signed with the retired key must still be accepted — " +
			"otherwise the overlap does not exist and the finalize assertion below would " +
			"pass vacuously")
	}

	// Finalize: the operator deletes the leaf and commits.
	n.commit(rotKeyB, nil)
	if n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyA, 0xA11CE, 2)) {
		t.Fatal("after finalize the retired key must NOT authenticate a heartbeat; an overlap " +
			"that cannot be closed is not a rotation, it is a second permanent key (#6630)")
	}
	// The current key still works — so the rejection above is the retirement,
	// not the node having lost its ability to verify anything.
	if !n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyB, 0xB0B, 1)) {
		t.Fatal("after finalize the current key must still authenticate")
	}
}

// TestPSKRotationKeyIDIsNotTheKey6630 pins the property that lets the rotation
// status line exist at all: the id is derivable identically on both nodes with
// no exchange, is stable, differs per key, and does not carry the key.
func TestPSKRotationKeyIDIsNotTheKey6630(t *testing.T) {
	idA, idB := controlLinkKeyID(rotKeyA), controlLinkKeyID(rotKeyB)
	if idA == "" || idB == "" {
		t.Fatal("a configured key must have an id")
	}
	if idA == idB {
		t.Fatal("distinct keys must have distinct ids, or the operator cannot tell which key " +
			"the peer is signing with — which is the only question the line answers")
	}
	if controlLinkKeyID(rotKeyA) != idA {
		t.Fatal("the id must be stable: both nodes derive it independently and compare by eye")
	}
	if controlLinkKeyID(nil) != "" {
		t.Fatal("an absent key must have no id")
	}
	// The id must not be, contain, or be contained by the key. The keys here
	// are ASCII and the id is hex, so a substring test is meaningful in both
	// directions.
	if strings.Contains(string(rotKeyA), idA) || strings.Contains(idA, string(rotKeyA)) {
		t.Fatal("the key id must not expose the key")
	}
	if len(idA) != controlLinkKeyIDLen {
		t.Fatalf("id is %d chars, want %d — a longer id is more of the digest than an operator "+
			"needs and more than the key should surrender", len(idA), controlLinkKeyIDLen)
	}
}

// TestPSKRotationStatusAnswersIsItSafeToFinalize6630 binds the operator-facing
// consequence. The line must distinguish three states, because an operator
// acting on the wrong one reopens the dual-master window:
//
//	peer unknown       -> unknown, not known safe (README: not the same as
//	                      "not safe" — usually the peer is down; #16859)
//	peer on the old key -> do NOT finalize
//	peer on the new key -> safe
//
// FAIL-ON-REVERT: drop the notePeerControlKeyID call from admitFrame and the
// "safe" case collapses into "peer key UNKNOWN" — the line stops being able to
// answer the question at all.
func TestPSKRotationStatusAnswersIsItSafeToFinalize6630(t *testing.T) {
	n := newRotNode(t, 0)

	// No window open: no line at all.
	n.commit(rotKeyA, nil)
	if line := n.m.controlLinkRotationStatus(); line != "" {
		t.Fatalf("with no additional key there is no rotation and no line; got %q", line)
	}
	if n.m.ControlLinkRotationSafeToFinalize() {
		t.Fatal("with no window open there is nothing to finalize")
	}

	// Window open, peer silent.
	n.commit(rotKeyB, rotKeyA)
	line := n.m.controlLinkRotationStatus()
	if !strings.Contains(line, "UNKNOWN") || !strings.Contains(line, "not known safe to finalize") || strings.Contains(line, "do NOT finalize") {
		t.Fatalf("with no authenticated peer frame the answer is UNKNOWN — not known safe, "+
			"not a flat do-NOT-finalize (#16859/README); got %q", line)
	}
	if n.m.ControlLinkRotationSafeToFinalize() {
		t.Fatal("absence of evidence that the peer moved is not evidence that it did; this is " +
			"the direction where being wrong costs a dual-master window")
	}

	// Peer still signing the OLD key.
	if !n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyA, 0xA11CE, 1)) {
		t.Fatal("the old key must still be accepted mid-rotation")
	}
	line = n.m.controlLinkRotationStatus()
	if !strings.Contains(line, "still signing") || !strings.Contains(line, "do NOT finalize") {
		t.Fatalf("a peer still on the retired key must refuse finalize; got %q", line)
	}
	if n.m.ControlLinkRotationSafeToFinalize() {
		t.Fatal("finalizing while the peer still signs the old key reopens the dual-master window")
	}

	// Peer has moved to the NEW key.
	if !n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyB, 0xB0B, 1)) {
		t.Fatal("the current key must be accepted")
	}
	line = n.m.controlLinkRotationStatus()
	if !strings.Contains(line, "safe to finalize") {
		t.Fatalf("once the peer signs the current key, finalize is safe and the line must say "+
			"so — an operator with no answer leaves the overlap open indefinitely; got %q", line)
	}
	if !n.m.ControlLinkRotationSafeToFinalize() {
		t.Fatal("the predicate must agree with the line it renders")
	}
	// And it is NOT sticky: a peer that rolls back to the old key must be
	// visible as such, not remembered at its high-water mark.
	if !n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyA, 0xA11CE, 2)) {
		t.Fatal("the retired key is still accepted until finalize")
	}
	if n.m.ControlLinkRotationSafeToFinalize() {
		t.Fatal("the peer signing key must track the LATEST verified frame, not a high-water " +
			"mark: a peer that rolled back must make finalize unsafe again")
	}
}

// TestPSKRotationStatusNeverRendersAKey6630: the line is operator-facing and
// goes to `show chassis cluster statistics`, so it must survive being read by
// anyone who can run a show.
func TestPSKRotationStatusNeverRendersAKey6630(t *testing.T) {
	n := newRotNode(t, 0)
	n.commit(rotKeyB, rotKeyA)
	if !n.accepts(t, MarshalHeartbeatAuth(samplePkt(), rotKeyA, 0xA11CE, 1)) {
		t.Fatal("the retired key must be accepted mid-rotation")
	}
	line := n.m.controlLinkRotationStatus()
	for _, k := range [][]byte{rotKeyA, rotKeyB} {
		if strings.Contains(line, string(k)) {
			t.Fatalf("the rotation line rendered a control-link key: %q", line)
		}
	}
	if line == "" {
		t.Fatal("the line must be non-empty here, or the check above passes vacuously")
	}
}

// TestPSKRotationOverlapMustBeARealOverlap6630 pins the commit-time refusal of
// a degenerate window: an additional key identical to the signing key accepts
// exactly ONE key while reading, in the config and in the show line, as though
// a rotation window were open. An operator who proceeds to the next commit on
// that belief gets the dual-master window the leaf exists to close.
func TestPSKRotationOverlapMustBeARealOverlap6630(t *testing.T) {
	same := &config.Config{}
	same.Chassis.Cluster = &config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret(string(rotKeyA)),
		ControlLinkAuthKeyAlt: config.NewSecret(string(rotKeyA)),
	}
	err := config.ValidateClusterAuthKeyOverlapForTest(same)
	if err == nil {
		t.Fatal("an additional key identical to the signing key is not an overlap and must be " +
			"refused: the config and the show line would both read as though a rotation " +
			"window were open (#6630)")
	}
	if strings.Contains(err.Error(), string(rotKeyA)) {
		t.Fatalf("the refusal must not echo the key: %v", err)
	}

	// Boundary whitespace inside a quoted PSK is key material, so
	// trim-equal pairs with different raw bytes form a real overlap.
	// Padding is tested on either and both sides because the runtime
	// installs each Secret verbatim.
	for _, tc := range []struct {
		name, signing, additional string
	}{
		{"additional padded", string(rotKeyA), "  " + string(rotKeyA) + "  "},
		{"signing padded", "  " + string(rotKeyA) + "  ", string(rotKeyA)},
		{"both padded differently", " " + string(rotKeyA), string(rotKeyA) + "\t"},
	} {
		padded := &config.Config{}
		padded.Chassis.Cluster = &config.ClusterConfig{
			ControlLinkAuthKey:    config.NewSecret(tc.signing),
			ControlLinkAuthKeyAlt: config.NewSecret(tc.additional),
		}
		if err := config.ValidateClusterAuthKeyOverlapForTest(padded); err != nil {
			t.Fatalf("%s: byte-distinct PSKs must be accepted as a real overlap: %v", tc.name, err)
		}
	}

	// A genuine overlap passes — otherwise the refusals above would be
	// indistinguishable from the check rejecting everything.
	real := &config.Config{}
	real.Chassis.Cluster = &config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret(string(rotKeyB)),
		ControlLinkAuthKeyAlt: config.NewSecret(string(rotKeyA)),
	}
	if err := config.ValidateClusterAuthKeyOverlapForTest(real); err != nil {
		t.Fatalf("a genuine two-key overlap must be accepted: %v", err)
	}
}

var _ = fmt.Sprintf
