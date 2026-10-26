package cluster

import (
	"bytes"
	"testing"
	"time"
)

// #17889: a connection that began unauthenticated (pre-key anchor,
// strictGraceRetired=false) and then successfully completes the #6628
// in-place upgrade to the accepted key A must not keep its old pre-key
// anchor. The previous bug: upgrade completion stamped authPSK but never
// cleared a non-retired anchor, and both reconcile/enforce cleared only
// when strictGraceRetired was true. noteRetiredKeyGraceStartLocked then
// refused (set-once) to re-anchor when A was later retired, so enforcement
// closed the connection at the long-expired pre-key deadline before a
// cooperating peer had any retirement grace.
//
// FAIL-ON-REVERT #17889: the regression below drives the connection through
// the old pre-key deadline and into a later key retirement. Without clearing
// the old anchor after the successful upgrade, the later reconcile cannot
// start a retired-key grace and closes the cooperating connection.

// retiredKeyC17889 is the later signing/finalized key in the #17889 tests.
const retiredKeyC17889 = "retired-key-c-17889"

// TestPreKeyUpgradeSurvivesLaterRetirementGrace17889 is the defect cell:
// pre-key stale -> successful upgrade to A inside grace -> the old pre-key
// deadline expires while the connection stays healthy under A -> A is retired
// (accepted set becomes {C}) -> reconcile anchors a FRESH retirement grace.
func TestPreKeyUpgradeSurvivesLaterRetirementGrace17889(t *testing.T) {
	a := newUpgEnd(t, retiredKeyA16857, 0)
	b := newUpgEnd(t, retiredKeyA16857, 1)

	// Establish the pre-key anchor and then drive the exact three-frame
	// #6628 upgrade without a second reconcile superseding the outstanding
	// round.
	a.s.ReconcileConnectionAuth("keyed")
	a.s.writeMu.Lock()
	preStart := a.ac.strictGraceStart
	preRetired := a.ac.strictGraceRetired
	a.s.writeMu.Unlock()
	if preStart == 0 || preRetired {
		t.Fatalf("pre-key anchor not established: start=%d retired=%v, want nonzero/false", preStart, preRetired)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("first frame type %d, want Hello", typ)
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("second frame type %d, want Proof", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("third frame type %d, want Confirm", typ)
	}
	for _, e := range []*upgEnd{a, b} {
		if !bytes.Equal(e.ac.authPSK, []byte(retiredKeyA16857)) {
			t.Fatalf("successful upgrade did not stamp A: authPSK=%q", e.ac.authPSK)
		}
	}
	a.s.writeMu.Lock()
	upgradedAnchor := a.ac.strictGraceStart
	upgradedRetired := a.ac.strictGraceRetired
	a.s.writeMu.Unlock()
	if upgradedAnchor != 0 || upgradedRetired {
		t.Fatalf("successful pre-key upgrade retained its old grace anchor: start=%d retired=%v, want 0/false", upgradedAnchor, upgradedRetired)
	}
	// Let the original pre-key deadline elapse while A is accepted. The
	// fixed path has cleared this anchor, so there is nothing to backdate;
	// the pre-fix path retains it and must not evict a now-authenticated A
	// connection merely because that old deadline elapsed.
	a.s.writeMu.Lock()
	if a.ac.strictGraceStart != 0 {
		a.ac.strictGraceStart = MonotonicNanos() - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
	}
	a.s.writeMu.Unlock()
	if n := a.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connection(s) authenticated under accepted A after the pre-key deadline", n)
	}
	if !connStillInstalled(a) {
		t.Fatal("connection closed before A was retired")
	}

	// Retire A. If its pre-key anchor survived the successful upgrade, the
	// later retirement cannot start a fresh window and reconcile closes it.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(retiredKeyC17889), node: 0, cluster: upgClusterID})
	a.s.ReconcileConnectionAuth("retire-A")
	if !connStillInstalled(a) {
		t.Fatal("connection closed at retire reconcile; a fresh retirement grace must be honoured")
	}
	a.s.writeMu.Lock()
	anchor := a.ac.strictGraceStart
	retired := a.ac.strictGraceRetired
	a.s.writeMu.Unlock()
	if anchor == 0 || !retired {
		t.Fatalf("retire reconcile did not anchor a fresh retired grace: start=%d retired=%v", anchor, retired)
	}
	if n := a.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections inside a fresh retirement grace, want 0", n)
	}
	if !connStillInstalled(a) {
		t.Fatal("connection did not survive inside the fresh retirement grace")
	}

	// The new grace remains enforceable: expire it and confirm eviction.
	backdateGrace16857(a)
	if n := a.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d connections after the fresh retirement grace expired, want 1", n)
	}
	if connStillInstalled(a) {
		t.Fatal("connection survived past the fresh retirement grace expiry")
	}
}

// TestPreKeyUpgradeAnchorRetainedWithoutCompletion17889 is the control: a
// peer that never completes the upgrade keeps its original pre-key anchor.
// Repeated reconciles must not move it (set-once), and eviction at the
// pre-key deadline is unchanged.
func TestPreKeyUpgradeAnchorRetainedWithoutCompletion17889(t *testing.T) {
	e := newUpgEnd(t, retiredKeyA16857, 0)
	e.s.ReconcileConnectionAuth("keyed")
	e.s.writeMu.Lock()
	first := e.ac.strictGraceStart
	e.s.writeMu.Unlock()
	if first == 0 {
		t.Fatal("first reconcile did not anchor the pre-key grace")
	}
	// No upgrade completes (the Hello is never pumped onward). Repeated
	// reconciles inside the window must preserve the original deadline.
	for range 3 {
		e.s.ReconcileConnectionAuth("later-commit")
		if !connStillInstalled(e) {
			t.Fatal("un-upgraded connection was evicted inside the grace")
		}
		e.s.writeMu.Lock()
		after := e.ac.strictGraceStart
		e.s.writeMu.Unlock()
		if after != first {
			t.Fatalf("anchor moved %d -> %d without a completed upgrade; commits re-arm the pre-key grace", first, after)
		}
	}
	backdateGrace16857(e)
	e.s.ReconcileConnectionAuth("expired")
	if connStillInstalled(e) {
		t.Fatal("un-upgraded connection survived past the pre-key grace expiry")
	}
}

// TestStraddlingPreKeyUpgradeGetsFreshRetiredGrace17889 covers the
// straddling-round edge: an A upgrade is already outstanding when finalize
// changes the live key to C. The connection remains pre-key until the old
// round completes under A, after the original pre-key deadline has elapsed.
// That authenticated completion must establish a fresh retired-key grace
// for the immediately-triggered C round; otherwise the next enforcement tick
// closes a cooperating connection at the old pre-key deadline.
func TestStraddlingPreKeyUpgradeGetsFreshRetiredGrace17889(t *testing.T) {
	a := newUpgEnd(t, retiredKeyA16857, 0)
	b := newUpgEnd(t, retiredKeyA16857, 1)

	// Start the A round and deliver Hello, leaving the Proof in flight.
	a.s.ReconcileConnectionAuth("keyed")
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("first frame type %d, want Hello", typ)
	}

	// Finalize to C while a still has no authPSK, then simulate the original
	// pre-key grace expiring while the already-started A exchange is in flight.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(retiredKeyC17889), node: 0, cluster: upgClusterID})
	a.s.ReconcileConnectionAuth("finalize")
	a.s.writeMu.Lock()
	a.ac.strictGraceStart = MonotonicNanos() - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
	a.s.writeMu.Unlock()

	// Completing the outstanding Proof authenticates A, which is now retired.
	// The handler immediately prompts for C. Its success must re-anchor the
	// grace before enforcement can observe the expired pre-key deadline.
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("second frame type %d, want Proof", typ)
	}
	if !bytes.Equal(a.ac.authPSK, []byte(retiredKeyA16857)) {
		t.Fatalf("initiator authPSK = %q after straddling Proof, want A", a.ac.authPSK)
	}
	a.s.writeMu.Lock()
	anchor := a.ac.strictGraceStart
	retired := a.ac.strictGraceRetired
	a.s.writeMu.Unlock()
	if anchor == 0 || !retired || MonotonicNanos()-anchor >= strictSessionAuthGrace.Nanoseconds() {
		t.Fatalf("stale-key completion did not establish a fresh retired grace: start=%d retired=%v", anchor, retired)
	}
	if n := a.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d cooperating connections after straddling completion, want 0", n)
	}
	if !connStillInstalled(a) {
		t.Fatal("connection closed at the expired pre-key deadline after a successful straddling round")
	}
}

// TestStraddlingResponderUpgradeGetsFreshRetiredGrace17889 is the responder
// mirror of the straddle above: b answered the A Hello (Proof sent, Confirm
// outstanding) while holding a pre-key anchor; A is retired to C and the
// pre-key deadline expires before the Confirm lands. Completing the Confirm
// under retired A must refresh b's grace for the follow-up C rekey, a
// replayed Confirm must not refresh it again, and if the rekey then goes
// unanswered the refreshed grace still evicts at its own expiry.
func TestStraddlingResponderUpgradeGetsFreshRetiredGrace17889(t *testing.T) {
	a := newUpgEnd(t, retiredKeyA16857, 0)
	b := newUpgEnd(t, retiredKeyA16857, 1)

	// Establish b's pre-key anchor; the reconcile emits a Request, drained
	// here so the exchange below starts from a's Hello.
	b.s.ReconcileConnectionAuth("keyed")
	b.s.writeMu.Lock()
	preStart := b.ac.strictGraceStart
	preRetired := b.ac.strictGraceRetired
	b.s.writeMu.Unlock()
	if preStart == 0 || preRetired {
		t.Fatalf("responder pre-key anchor not established: start=%d retired=%v, want nonzero/false", preStart, preRetired)
	}
	if typ, _ := readUpgradeFrame(t, b, false); typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("responder reconcile frame type %d, want Request %d", typ, syncMsgAuthUpgradeRequest)
	}

	// Drive Hello and Proof; a completes under A and its Confirm stays
	// outstanding on the wire.
	a.s.ReconcileConnectionAuth("keyed")
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("first frame type %d, want Hello", typ)
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("second frame type %d, want Proof", typ)
	}
	typ, confirm := readUpgradeFrame(t, a, false)
	if typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("third frame type %d, want Confirm", typ)
	}

	// Retire A to C on b while its Confirm is outstanding, then let the
	// original pre-key deadline expire.
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(retiredKeyC17889), node: 1, cluster: upgClusterID})
	b.s.ReconcileConnectionAuth("finalize")
	b.s.writeMu.Lock()
	b.ac.strictGraceStart = MonotonicNanos() - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
	b.s.writeMu.Unlock()

	// The Confirm completes the round under retired A: fresh retired grace.
	b.s.handleMessage(b.ac, typ, confirm)
	if !bytes.Equal(b.ac.authPSK, []byte(retiredKeyA16857)) {
		t.Fatalf("responder authPSK = %q after straddling Confirm, want A", b.ac.authPSK)
	}
	b.s.writeMu.Lock()
	anchor := b.ac.strictGraceStart
	retired := b.ac.strictGraceRetired
	b.s.writeMu.Unlock()
	if anchor == 0 || !retired || MonotonicNanos()-anchor >= strictSessionAuthGrace.Nanoseconds() {
		t.Fatalf("responder stale-key completion did not establish a fresh retired grace: start=%d retired=%v", anchor, retired)
	}
	if n := b.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d cooperating responder connections after straddling completion, want 0", n)
	}
	if !connStillInstalled(b) {
		t.Fatal("responder closed at the expired pre-key deadline after a successful straddling round")
	}

	// Duplicate-Confirm control: replaying the same Confirm must not
	// refresh the grace a second time.
	b.s.writeMu.Lock()
	b.ac.strictGraceStart = anchor - strictSessionAuthGrace.Nanoseconds()/2
	aged := b.ac.strictGraceStart
	b.s.writeMu.Unlock()
	if !b.s.handleAuthUpgradeConfirm(b.ac, confirm) {
		t.Fatal("duplicate Confirm was not accepted as an already-completed round")
	}
	b.s.writeMu.Lock()
	afterDup := b.ac.strictGraceStart
	b.s.writeMu.Unlock()
	if afterDup != aged {
		t.Fatalf("duplicate Confirm refreshed the grace: %d -> %d; replayed completions must not renew", aged, afterDup)
	}

	// The follow-up rekey is never answered: the refreshed grace evicts at
	// its own expiry.
	backdateGrace16857(b)
	if n := b.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d responder connections after the refreshed grace expired unanswered, want 1", n)
	}
	if connStillInstalled(b) {
		t.Fatal("responder survived past the refreshed grace expiry")
	}
}
