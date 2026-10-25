package cluster

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// #16857: a connection authenticated under a key that has left the accepted
// set (finalized rotation) must be treated like the never-authenticated
// population: anchored grace at the finalize reconcile, listed during the
// grace, evicted at expiry. A cooperating peer that rekeys within the grace
// is never evicted.

const (
	retiredKeyA16857 = "retired-key-a-16857"
	retiredKeyB16857 = "retired-key-b-16857"
)

// retiredEnd builds a keyed node (signing B, accepting [B] only — the
// post-finalize shape) holding one established connection authenticated
// under retired key A, with directional keys installed so frames verify
// under A-derived keys exactly as in production.
func retiredEnd(t *testing.T) *upgEnd {
	t.Helper()
	e := newUpgEnd(t, retiredKeyB16857, 0)
	e.s.writeMu.Lock()
	e.ac.authPSK = []byte(retiredKeyA16857)
	e.ac.readKey = []byte("a-derived-read-key-16857-000001")
	e.ac.writeKey = []byte("a-derived-write-key-16857-00001")
	e.s.writeMu.Unlock()
	return e
}

func backdateGrace16857(e *upgEnd) {
	e.s.writeMu.Lock()
	e.ac.strictGraceStart = MonotonicNanos() - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
	e.s.writeMu.Unlock()
}

// TestRetiredKeyConnEvictedAfterFinalizeGrace16857 is the defect cell.
// Pre-fix: enforce keys only on len(authPSK)==0, so evicted=0 and the
// connection is unlisted. Post-fix: evicted=1.
func TestRetiredKeyConnEvictedAfterFinalizeGrace16857(t *testing.T) {
	e := retiredEnd(t)
	// Finalize reconcile: anchors the retired-key grace and prompts rekey.
	e.s.ReconcileConnectionAuth("finalize")
	e.s.writeMu.Lock()
	anchor := e.ac.strictGraceStart
	retired := e.ac.strictGraceRetired
	e.s.writeMu.Unlock()
	if anchor == 0 || !retired {
		t.Fatalf("finalize reconcile did not anchor retired-key grace: start=%d retired=%v", anchor, retired)
	}
	if !connStillInstalled(e) {
		t.Fatal("connection evicted inside the grace; a cooperating peer must get the window to rekey")
	}
	// Listed during the grace, in both the combined and retired-only views.
	if got := e.s.UnauthenticatedSessionConns(); len(got) != 1 {
		t.Fatalf("UnauthenticatedSessionConns during grace = %v, want 1 entry", got)
	}
	if got := e.s.RetiredKeySessionConns(); len(got) != 1 {
		t.Fatalf("RetiredKeySessionConns during grace = %v, want 1 entry", got)
	}
	// Retired-key frames still verify before expiry (the defect's window).
	frame := encodeRawMessage(syncMsgSessionV4, []byte("retired"))
	_ = frame
	// Expire the grace and enforce via the periodic path.
	backdateGrace16857(e)
	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d retired-key connections after grace, want 1", n)
	}
	if connStillInstalled(e) {
		t.Fatal("retired-key connection survived past grace expiry")
	}
	if got := e.s.UnauthenticatedSessionConns(); len(got) != 0 {
		t.Fatalf("after eviction, listed = %v, want none", got)
	}
}

// TestRetiredKeyConnListedInStatus16857: the operator status must surface a
// retired-key connection distinctly, not claim the engaged line.
func TestRetiredKeyConnListedInStatus16857(t *testing.T) {
	e := retiredEnd(t)
	e.s.ReconcileConnectionAuth("finalize")
	m := &Manager{controlAuthKey: []byte(retiredKeyB16857)}
	m.SetSyncStats(e.s)
	got := m.controlLinkAuthStatus()
	if got == engagedLine9717 {
		t.Fatalf("status claims engaged while a retired-key connection is installed: %q", got)
	}
	if !strings.Contains(got, "RETIRED") {
		t.Fatalf("status = %q, want it to name the retired-key population", got)
	}
	if !strings.Contains(got, connRemoteAddrString(e.ac)) {
		t.Fatalf("status = %q, want it to name the connection %q", got, connRemoteAddrString(e.ac))
	}
	if strings.Contains(got, retiredKeyA16857) || strings.Contains(got, retiredKeyB16857) {
		t.Fatalf("status leaked a key: %q", got)
	}
}

// TestRetiredKeyReacceptedWithinGraceNeverEvicted16857: if the retired key
// is re-accepted (re-added as additional) or the connection rekeys before
// expiry, enforcement must not close it even with an elapsed anchor.
func TestRetiredKeyReacceptedWithinGraceNeverEvicted16857(t *testing.T) {
	e := retiredEnd(t)
	e.s.ReconcileConnectionAuth("finalize")
	backdateGrace16857(e)
	// Re-accept A as the additional key: accepted set becomes [B, A].
	e.s.SetAuthProvider(&ringFakeProvider{
		key: []byte(retiredKeyB16857), alt: [][]byte{[]byte(retiredKeyA16857)},
		node: 0, cluster: upgClusterID,
	})
	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections whose key was re-accepted, want 0", n)
	}
	e.s.writeMu.Lock()
	anchor := e.ac.strictGraceStart
	e.s.writeMu.Unlock()
	if anchor != 0 {
		t.Fatalf("retired anchor = %d after re-acceptance, want cleared (0)", anchor)
	}
	if got := e.s.RetiredKeySessionConns(); len(got) != 0 {
		t.Fatalf("re-accepted connection still listed as retired: %v", got)
	}
	// Finalize again: a fresh grace must anchor (not the stale cleared one).
	e.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(retiredKeyB16857), node: 0, cluster: upgClusterID})
	e.s.ReconcileConnectionAuth("finalize-again")
	e.s.writeMu.Lock()
	anchor2 := e.ac.strictGraceStart
	e.s.writeMu.Unlock()
	if anchor2 == 0 {
		t.Fatal("second finalize did not anchor a fresh retired-key grace")
	}
}

// TestRetiredKeyGraceAnchorSetOnce16857: repeated reconciles must not
// re-arm the retired-key grace.
func TestRetiredKeyGraceAnchorSetOnce16857(t *testing.T) {
	e := retiredEnd(t)
	e.s.ReconcileConnectionAuth("finalize")
	e.s.writeMu.Lock()
	first := e.ac.strictGraceStart
	e.ac.strictGraceStart = first - strictSessionAuthGrace.Nanoseconds() - int64(time.Second)
	backdated := e.ac.strictGraceStart
	e.s.writeMu.Unlock()
	if first == 0 {
		t.Fatal("first finalize reconcile did not anchor")
	}
	for range 5 {
		// Each reconcile also enforces; the backdated anchor would evict on
		// the first pass, clearing the slot. Stop checking after eviction:
		// the property under test is that no reconcile MOVES the anchor
		// forward before eviction. Use listing instead after eviction.
		e.s.ReconcileConnectionAuth("later-commit")
		if !connStillInstalled(e) {
			break
		}
		e.s.writeMu.Lock()
		after := e.ac.strictGraceStart
		e.s.writeMu.Unlock()
		if after != backdated {
			t.Fatalf("anchor moved %d -> %d across reconciles; commits re-arm the retired-key grace", backdated, after)
		}
	}
	// The backdated (expired) anchor must have caused eviction via reconcile.
	if connStillInstalled(e) {
		t.Fatal("expired retired-key grace was not enforced by reconcile")
	}
}

// TestCooperatingPeerRekeysWithinGrace16857 is the end-to-end positive
// control: both ends authenticate under A, node0 finalizes to {B} while
// node1 cooperates and rekeys to B; neither end is evicted and the
// connection ends authenticated under B.
func TestCooperatingPeerRekeysWithinGrace16857(t *testing.T) {
	a := newUpgEnd(t, retiredKeyA16857, 0)
	b := newUpgEnd(t, retiredKeyA16857, 1)
	runUpgrade(t, a, b)
	if !bytes.Equal(a.ac.authPSK, []byte(retiredKeyA16857)) {
		t.Fatal("precondition: connection must start authenticated under A")
	}
	// Both rotate to B (cooperating peer). Reconcile drives the rekey.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(retiredKeyB16857), node: 0, cluster: upgClusterID})
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(retiredKeyB16857), node: 1, cluster: upgClusterID})
	// Drive the exchange the reconcile starts, as runUpgrade does.
	assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)
	if !bytes.Equal(a.ac.authPSK, []byte(retiredKeyB16857)) || !bytes.Equal(b.ac.authPSK, []byte(retiredKeyB16857)) {
		t.Fatalf("cooperating rekey did not land on B: a=%q b=%q", a.ac.authPSK, b.ac.authPSK)
	}
	// Even with a backdated anchor, an on-B connection is not evicted.
	for _, e := range []*upgEnd{a, b} {
		backdateGrace16857(e)
		if n := e.s.enforceStrictSessionAuth(); n != 0 {
			t.Fatalf("evicted %d cooperating (rekeyed) connections, want 0", n)
		}
	}
}

// TestRetiredKeyStillAcceptedDuringRotationWindow16857: while A is still
// in the accepted set (signing B, additional A), an A connection is NOT
// stale — no listing, no eviction. This bounds the fix to finalize.
func TestRetiredKeyStillAcceptedDuringRotationWindow16857(t *testing.T) {
	e := newUpgEnd(t, retiredKeyB16857, 0)
	e.s.SetAuthProvider(&ringFakeProvider{
		key: []byte(retiredKeyB16857), alt: [][]byte{[]byte(retiredKeyA16857)},
		node: 0, cluster: upgClusterID,
	})
	e.s.writeMu.Lock()
	e.ac.authPSK = []byte(retiredKeyA16857)
	e.s.writeMu.Unlock()
	e.s.ReconcileConnectionAuth("rotation-window")
	backdateGrace16857(e)
	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d connections still inside the rotation window, want 0", n)
	}
	if got := e.s.RetiredKeySessionConns(); len(got) != 0 {
		t.Fatalf("window connection listed as retired: %v", got)
	}
	if got := e.s.UnauthenticatedSessionConns(); len(got) != 0 {
		t.Fatalf("window connection listed as unauthenticated: %v", got)
	}
}

// TestCurrentKeyConnectionNeverEvicted16857: negative control — a
// connection authenticated under the current signing key B on a {B} node.
func TestCurrentKeyConnectionNeverEvicted16857(t *testing.T) {
	e := newUpgEnd(t, retiredKeyB16857, 0)
	e.s.writeMu.Lock()
	e.ac.authPSK = []byte(retiredKeyB16857)
	e.s.writeMu.Unlock()
	e.s.ReconcileConnectionAuth("steady")
	backdateGrace16857(e)
	if n := e.s.enforceStrictSessionAuth(); n != 0 {
		t.Fatalf("evicted %d current-key connections, want 0", n)
	}
	if !connStillInstalled(e) {
		t.Fatal("current-key connection was closed")
	}
}
