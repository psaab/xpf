package daemon

// RED batch A — 9506 S4 T12 permit-record/epoch cells (r6 §2.2 epoch/owner
// mapping, §5.2 cells 3/5a/6; r5 §12.3 emission/terminality).
//
// The permit record is the single authorization source for q0 validation:
// atomic.Pointer to an immutable {state,permitEpoch,closeRequestSeq,
// closeRequestKey,watchGeneration} snapshot; every changed record allocates a
// fresh snapshot and readers never mutate in place (Go GC keeps a reachable
// expected snapshot alive, making the full-record CAS ABA-safe).

import (
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func testOpenRecord(e, s uint64, k ipsecCloseRequestKey, w uint64) *permitRecord {
	return &permitRecord{state: ipsecPermitOpen, permitEpoch: e, closeRequestSeq: s, closeRequestKey: k, watchGeneration: w}
}

func testClosingRecord(e, s uint64, k ipsecCloseRequestKey, w uint64) *permitRecord {
	return &permitRecord{state: ipsecPermitClosing, permitEpoch: e, closeRequestSeq: s, closeRequestKey: k, watchGeneration: w}
}

func testKey(ready ipsecReadyResult, w uint64, tuples ...ipsecTopologyTuple) ipsecCloseRequestKey {
	return makeCloseRequestKey(ready, w, tuples)
}

// A fresh supervisor starts CLOSING (fail-closed until the first safe census
// drives the first OPEN CAS); epoch and sequence start at zero.
func TestIpsecPermitInitialClosing9506(t *testing.T) {
	s := newIpsecSupervisor()
	rec := s.loadPermit()
	if rec == nil {
		t.Fatal("loadPermit returned nil on a fresh supervisor")
	}
	if rec.state != ipsecPermitClosing {
		t.Fatalf("initial permit state = %v, want CLOSING", rec.state)
	}
	if rec.permitEpoch != 0 || rec.closeRequestSeq != 0 {
		t.Fatalf("initial record = epoch %d seq %d, want 0/0", rec.permitEpoch, rec.closeRequestSeq)
	}
}

// OPEN + distinct event → (CLOSING,e+1,s_new,k_new,w); s_new is the max of the
// current sequence and the event sequence.
func TestIpsecRevokeOpenToClosing9506(t *testing.T) {
	s := newIpsecSupervisor()
	open := testOpenRecord(4, 7, testKey(ipsecReadySafe, 3), 3)
	s.permit.Store(open)
	ev := ipsecTopologyEvent{Seq: 9, Key: testKey(ipsecReadyUnsafe, 3, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, MasterIndex: 21, Name: "st0"})}
	got, prev := s.revokeTransitPermitNonblocking(ev)
	if prev != open {
		t.Fatal("revoke did not report the pre-revoke record")
	}
	if got.state != ipsecPermitClosing || got.permitEpoch != 5 {
		t.Fatalf("post-revoke record = state %v epoch %d, want CLOSING/5", got.state, got.permitEpoch)
	}
	if got.closeRequestSeq != 9 {
		t.Fatalf("post-revoke seq = %d, want max(7,9)=9", got.closeRequestSeq)
	}
	if !got.closeRequestKey.equal(ev.Key) {
		t.Fatalf("post-revoke key = %+v, want event key %+v", got.closeRequestKey, ev.Key)
	}
	if got.watchGeneration != 3 {
		t.Fatalf("post-revoke watch generation = %d, want preserved 3", got.watchGeneration)
	}
	if cur := s.loadPermit(); cur != got {
		t.Fatal("loadPermit does not return the revoked record")
	}
}

// A distinct event while CLOSING advances the sequence without a second epoch
// increment.
func TestIpsecRevokeClosingSeqAdvance9506(t *testing.T) {
	s := newIpsecSupervisor()
	s.permit.Store(testClosingRecord(5, 9, testKey(ipsecReadyUnsafe, 3), 3))
	ev := ipsecTopologyEvent{Seq: 12, Key: testKey(ipsecReadyUnknown, 3)}
	got, _ := s.revokeTransitPermitNonblocking(ev)
	if got.state != ipsecPermitClosing || got.permitEpoch != 5 {
		t.Fatalf("CLOSING revoke changed state/epoch to %v/%d, want CLOSING/5", got.state, got.permitEpoch)
	}
	if got.closeRequestSeq != 12 {
		t.Fatalf("CLOSING revoke seq = %d, want 12", got.closeRequestSeq)
	}
}

// Same-key retry (same eventSeq) is a no-op: identical record, no allocation.
func TestIpsecRevokeSameKeyRetryNoop9506(t *testing.T) {
	s := newIpsecSupervisor()
	s.permit.Store(testOpenRecord(4, 7, testKey(ipsecReadySafe, 3), 3))
	ev := ipsecTopologyEvent{Seq: 9, Key: testKey(ipsecReadyUnsafe, 3)}
	first, _ := s.revokeTransitPermitNonblocking(ev)
	second, _ := s.revokeTransitPermitNonblocking(ev)
	if second != first {
		t.Fatal("same-event retry allocated a new record; want idempotent no-op")
	}
	if second.permitEpoch != 5 || second.closeRequestSeq != 9 {
		t.Fatalf("retry record = epoch %d seq %d, want 5/9", second.permitEpoch, second.closeRequestSeq)
	}
}

// Out-of-order and duplicate retries never regress the sequence nor increment
// the epoch more than once per close.
func TestIpsecRevokeOutOfOrderNoRegress9506(t *testing.T) {
	s := newIpsecSupervisor()
	s.permit.Store(testOpenRecord(4, 7, testKey(ipsecReadySafe, 3), 3))
	evA := ipsecTopologyEvent{Seq: 11, Key: testKey(ipsecReadyUnsafe, 3, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11})}
	evB := ipsecTopologyEvent{Seq: 12, Key: testKey(ipsecReadyUnsafe, 3, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 12})}
	// B arrives first, then A (stale), then A retried after B.
	s.revokeTransitPermitNonblocking(evB)
	mid, _ := s.revokeTransitPermitNonblocking(evA)
	if mid.closeRequestSeq != 12 {
		t.Fatalf("stale lower-sequence revoke regressed seq to %d, want 12", mid.closeRequestSeq)
	}
	after, _ := s.revokeTransitPermitNonblocking(evA)
	if after != mid {
		t.Fatal("duplicate stale retry was not a no-op")
	}
	if after.permitEpoch != 5 {
		t.Fatalf("epoch = %d after interleaved retries, want exactly one increment to 5", after.permitEpoch)
	}
	// Duplicate B is a no-op as well.
	dup, _ := s.revokeTransitPermitNonblocking(evB)
	if dup != after {
		t.Fatal("duplicate B was not a no-op")
	}
}

// A new OPEN-state event revokes even when its key equals the current key,
// provided its sequence is fresh (recurring fingerprint after a reopen).
func TestIpsecRevokeNewOpenEventSameKey9506(t *testing.T) {
	s := newIpsecSupervisor()
	key := testKey(ipsecReadySafe, 3)
	s.permit.Store(testOpenRecord(6, 12, key, 3))
	ev := ipsecTopologyEvent{Seq: 13, Key: key}
	got, _ := s.revokeTransitPermitNonblocking(ev)
	if got.state != ipsecPermitClosing || got.permitEpoch != 7 {
		t.Fatalf("same-key fresh-seq revoke = state %v epoch %d, want CLOSING/7", got.state, got.permitEpoch)
	}
	if got.closeRequestSeq != 13 {
		t.Fatalf("same-key fresh-seq revoke seq = %d, want 13", got.closeRequestSeq)
	}
}

// Expected-record OPEN CAS succeeds after a fresh safe census: the only
// allowed reopen path.
func TestIpsecOpenCasSuccess9506(t *testing.T) {
	s := newIpsecSupervisor()
	closing := testClosingRecord(7, 13, testKey(ipsecReadyUnsafe, 3), 3)
	s.permit.Store(closing)
	safe := testKey(ipsecReadySafe, 3)
	s.watch.Store(&TransitWatchSnapshot{Generation: 3, Ready: ipsecReadySafe})
	if !s.tryOpenPermit(closing, safe, 3) {
		t.Fatal("expected-record OPEN CAS failed on a fresh safe census")
	}
	got := s.loadPermit()
	if got.state != ipsecPermitOpen || got.permitEpoch != 8 {
		t.Fatalf("reopened record = state %v epoch %d, want OPEN/8", got.state, got.permitEpoch)
	}
	if got.closeRequestSeq != 13 {
		t.Fatalf("reopened seq = %d, want preserved 13", got.closeRequestSeq)
	}
	if !got.closeRequestKey.equal(safe) {
		t.Fatalf("reopened key = %+v, want safe key %+v", got.closeRequestKey, safe)
	}
}

func TestIpsecTopologyTransitionBlocksSafeReopen9506(t *testing.T) {
	s := newIpsecSupervisor()
	safe := testKey(ipsecReadySafe, 4, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, Name: "st0"})
	open := testOpenRecord(9, 17, safe, 4)
	s.permit.Store(open)
	s.watch.Store(&TransitWatchSnapshot{Generation: 4, Ready: ipsecReadySafe, Tuples: safe.Tuples})
	d := &Daemon{ipsecS4: s}
	d.noteIpsecTopologyLinkTransition()
	closing := s.loadPermit()
	if closing.state != ipsecPermitClosing || closing.closeRequestKey.Ready != ipsecReadyUnknown {
		t.Fatalf("link event authority = state %v ready %v, want CLOSING/UNKNOWN", closing.state, closing.closeRequestKey.Ready)
	}
	if s.tryOpenPermit(closing, safe, 4) {
		t.Fatal("safe reopen succeeded before post-event census")
	}
}
func TestIpsecTopologyCensusRejectsVRFMaster9506(t *testing.T) {
	oldList, oldByIndex := ipsecTopologyLinkList, ipsecFenceLinkByIndex
	t.Cleanup(func() {
		ipsecTopologyLinkList, ipsecFenceLinkByIndex = oldList, oldByIndex
	})
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue", Index: 22}}
	xfrmi := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st0", Index: 11, MasterIndex: 22}}
	outlet := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 33}}
	ipsecTopologyLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{xfrmi, vrf, outlet}, nil
	}
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		if index == vrf.Index {
			return vrf, nil
		}
		return nil, nil
	}
	s := newIpsecSupervisor()
	d := &Daemon{ipsecS4: s}
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	snapshot := s.watch.Load()
	if snapshot == nil || snapshot.Ready != ipsecReadyUnsafe {
		t.Fatalf("census ready = %v, want UNSAFE for VRF-master xfrmi", snapshotReady(snapshot))
	}
	var gotXfrmi *ipsecTopologyTuple
	for i := range snapshot.Tuples {
		if snapshot.Tuples[i].Kind == "xfrmi" {
			gotXfrmi = &snapshot.Tuples[i]
			break
		}
	}
	if gotXfrmi == nil || gotXfrmi.MasterIndex != vrf.Index {
		t.Fatalf("census tuples = %+v, want xfrmi master index %d", snapshot.Tuples, vrf.Index)
	}
}

func TestIpsecTopologyCensusRejectsEnslavedOutlet9506(t *testing.T) {
	oldList, oldByIndex := ipsecTopologyLinkList, ipsecFenceLinkByIndex
	t.Cleanup(func() {
		ipsecTopologyLinkList, ipsecFenceLinkByIndex = oldList, oldByIndex
	})
	xfrmi := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st0", Index: 11}}
	outlet := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 33, MasterIndex: 44}}
	ipsecTopologyLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{xfrmi, outlet}, nil
	}
	ipsecFenceLinkByIndex = func(int) (netlink.Link, error) {
		return nil, nil
	}
	s := newIpsecSupervisor()
	d := &Daemon{ipsecS4: s}
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	snapshot := s.watch.Load()
	if snapshot == nil || snapshot.Ready != ipsecReadyUnsafe {
		t.Fatalf("census ready = %v, want UNSAFE for enslaved outlet", snapshotReady(snapshot))
	}
	var gotOutlet *ipsecTopologyTuple
	for i := range snapshot.Tuples {
		if snapshot.Tuples[i].Kind == "outlet" {
			gotOutlet = &snapshot.Tuples[i]
			break
		}
	}
	if gotOutlet == nil || gotOutlet.MasterIndex != 44 {
		t.Fatalf("census tuples = %+v, want outlet master index 44", snapshot.Tuples)
	}
}

func TestIpsecTopologyNoiseLeavesPermitRecordUnchanged9506(t *testing.T) {
	s := newIpsecSupervisor()
	key := testKey(ipsecReadySafe, 4, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, Name: "st0"})
	open := testOpenRecord(9, 17, key, 4)
	s.permit.Store(open)
	s.watch.Store(&TransitWatchSnapshot{Generation: 4, Ready: ipsecReadySafe, Tuples: key.Tuples})
	d := &Daemon{ipsecS4: s}
	noise := []netlink.LinkUpdate{
		{Link: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy-noise", Index: 99}}},
		{Link: &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br-noise", Index: 98}}},
		{Link: &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-noise", Index: 97}}},
	}
	for _, update := range noise {
		if d.ipsecTopologyLinkEventRelevant(update) {
			t.Fatalf("unrelated %s link classified as relevant", update.Link.Type())
		}
	}
	if got := s.loadPermit(); got != open {
		t.Fatalf("noise changed permit record: got %p want %p", got, open)
	}
	if !d.ipsecTopologyLinkEventRelevant(netlink.LinkUpdate{
		Link: &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st0", Index: 11}},
	}) {
		t.Fatal("owned xfrmi link classified as irrelevant")
	}
}

func snapshotReady(snapshot *TransitWatchSnapshot) ipsecReadyResult {
	if snapshot == nil {
		return ipsecReadyUnknown
	}
	return snapshot.Ready
}

func TestIpsecPermitFinalizeClose9506(t *testing.T) {
	s := newIpsecSupervisor()
	key := testKey(ipsecReadyUnsafe, 4, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, Name: "st0"})
	closing := testClosingRecord(9, 17, key, 4)
	s.permit.Store(closing)
	if !s.finalizePermitClose(closing) {
		t.Fatal("close finalization CAS failed")
	}
	got := s.loadPermit()
	if got == nil || got.state != ipsecPermitClosed ||
		got.permitEpoch != closing.permitEpoch ||
		got.closeRequestSeq != closing.closeRequestSeq ||
		!got.closeRequestKey.equal(closing.closeRequestKey) {
		t.Fatalf("closed record = %+v, want preserved closing authority", got)
	}
	if s.finalizePermitClose(closing) {
		t.Fatal("stale close finalization succeeded")
	}
	if reopened := s.tryOpenPermit(closing, testKey(ipsecReadySafe, 4), 4); reopened {
		t.Fatal("closed permit reopened from stale closing record")
	}
	if current, previous := s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 18, Key: key}); current != got || previous != got {
		t.Fatal("closed permit accepted a later revoke")
	}
}

// A distinct event while CLOSING advances close_request_seq even when the
// canonical topology key is unchanged; only a duplicate sequence is a no-op.
func TestIpsecRevokeClosingSameKeyHigherSeq9506(t *testing.T) {
	s := newIpsecSupervisor()
	key := testKey(ipsecReadyUnsafe, 3)
	s.permit.Store(testClosingRecord(5, 9, key, 3))
	got, _ := s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 10, Key: key})
	if got.permitEpoch != 5 || got.closeRequestSeq != 10 {
		t.Fatalf("same-key CLOSING event = epoch %d seq %d, want 5/10", got.permitEpoch, got.closeRequestSeq)
	}
	dup, _ := s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 10, Key: key})
	if dup != got {
		t.Fatal("same-key duplicate sequence allocated another record")
	}
}

// A safe key from an older watch generation cannot authorize OPEN by passing
// the current generation as a separate argument.
func TestIpsecOpenCasSafeKeyWatchMismatchFails9506(t *testing.T) {
	s := newIpsecSupervisor()
	closing := testClosingRecord(7, 13, testKey(ipsecReadyUnsafe, 4), 4)
	s.permit.Store(closing)
	if s.tryOpenPermit(closing, testKey(ipsecReadySafe, 3), 4) {
		t.Fatal("OPEN CAS accepted a safe key from an older watch generation")
	}
}

// Safe-open interleaving (a): a revoke immediately before the OPEN CAS makes
// the expected record stale and the CAS must fail.
func TestIpsecOpenCasRevokedBeforeCasFails9506(t *testing.T) {
	s := newIpsecSupervisor()
	closing := testClosingRecord(7, 13, testKey(ipsecReadyUnsafe, 3), 3)
	s.permit.Store(closing)
	s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 14, Key: testKey(ipsecReadyUnsafe, 3)})
	if s.tryOpenPermit(closing, testKey(ipsecReadySafe, 3), 3) {
		t.Fatal("OPEN CAS succeeded over a revoked-before-CAS record; want failure + retry")
	}
}

// Safe-open interleaving (b): a new topology event while CLOSING (sequence
// advance, same epoch) before the OPEN CAS makes the expected record stale.
func TestIpsecOpenCasClosingEventBeforeCasFails9506(t *testing.T) {
	s := newIpsecSupervisor()
	closing := testClosingRecord(7, 13, testKey(ipsecReadyUnsafe, 3), 3)
	s.permit.Store(closing)
	s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 14, Key: testKey(ipsecReadyUnknown, 3)})
	cur := s.loadPermit()
	if cur.permitEpoch != 7 || cur.closeRequestSeq != 14 {
		t.Fatalf("CLOSING event did not advance seq-only: epoch %d seq %d", cur.permitEpoch, cur.closeRequestSeq)
	}
	if s.tryOpenPermit(closing, testKey(ipsecReadySafe, 3), 3) {
		t.Fatal("OPEN CAS succeeded over a seq-advanced CLOSING record; want failure + retry")
	}
}

// An OPEN CAS against a stale watch generation fails; only the current
// snapshot generation may reopen.
func TestIpsecOpenCasWatchMismatchFails9506(t *testing.T) {
	s := newIpsecSupervisor()
	closing := testClosingRecord(7, 13, testKey(ipsecReadySafe, 4), 4)
	s.watch.Store(&TransitWatchSnapshot{Generation: 4, Ready: ipsecReadySafe})
	s.permit.Store(closing)
	if s.tryOpenPermit(closing, testKey(ipsecReadySafe, 4), 3) {
		t.Fatal("OPEN CAS with stale watch generation succeeded; want failure")
	}
	if !s.tryOpenPermit(closing, testKey(ipsecReadySafe, 4), 4) {
		t.Fatal("OPEN CAS with current watch generation failed; want success")
	}
}
func TestIpsecOpenCasSameGenerationDifferentCensusFails9506(t *testing.T) {
	s := newIpsecSupervisor()
	published := &TransitWatchSnapshot{
		Generation: 4,
		Ready:      ipsecReadySafe,
		Tuples:     []ipsecTopologyTuple{{Kind: "xfrmi", Ifindex: 11, Name: "st0"}},
	}
	s.watch.Store(published)
	closing := testClosingRecord(7, 13, published.closeKey(), 4)
	s.permit.Store(closing)
	callerKey := testKey(ipsecReadySafe, 4, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 12, Name: "st0"})
	if s.tryOpenPermit(closing, callerKey, 4) {
		t.Fatal("OPEN CAS accepted a same-generation key with different census tuples")
	}
}

// Watch-snapshot publication is coupled, never pointer-only: the record CAS
// carries w_old → w_new and advances the close request key/sequence when the
// census changes; a pointer-only swap leaves the record behind and no OPEN
// with the new snapshot is possible.
func TestIpsecWatchPublishCoupled9506(t *testing.T) {
	s := newIpsecSupervisor()
	closing := testClosingRecord(7, 13, testKey(ipsecReadyUnsafe, 3), 3)
	s.permit.Store(closing)
	s.watch.Store(&TransitWatchSnapshot{Generation: 3})
	snap4 := &TransitWatchSnapshot{Generation: 4}
	if !s.publishWatchSnapshot(snap4) {
		t.Fatal("coupled watch publish failed while CLOSING")
	}
	got := s.loadPermit()
	if got.watchGeneration != 4 {
		t.Fatalf("published record watch generation = %d, want 4", got.watchGeneration)
	}
	if got.permitEpoch != 7 || got.closeRequestSeq <= 13 {
		t.Fatalf("publish moved epoch/seq to %d/%d, want 7/>13", got.permitEpoch, got.closeRequestSeq)
	}
	if !got.closeRequestKey.equal(snap4.closeKey()) {
		t.Fatalf("published close key = %+v, want %+v", got.closeRequestKey, snap4.closeKey())
	}
	if s.watch.Load() != snap4 {
		t.Fatal("watch pointer was not swapped to the new snapshot")
	}
	// Pointer-only mutant: swap the pointer without the record CAS, then no
	// OPEN CAS naming the new generation may succeed.
	s2 := newIpsecSupervisor()
	closing2 := testClosingRecord(7, 13, testKey(ipsecReadySafe, 3), 3)
	s2.permit.Store(closing2)
	s2.watch.Store(&TransitWatchSnapshot{Generation: 3})
	s2.watch.Store(&TransitWatchSnapshot{Generation: 5}) // no record CAS
	if s2.loadPermit().watchGeneration != 3 {
		t.Fatal("pointer-only swap moved the record; the record must lag the pointer")
	}
	if s2.tryOpenPermit(closing2, testKey(ipsecReadySafe, 5), 5) {
		t.Fatal("OPEN CAS with pointer-only w_new succeeded; want failure until the coupled CAS")
	}
}

func TestIpsecWatchPublishChangesCensusWhileClosing9506(t *testing.T) {
	s := newIpsecSupervisor()
	snapA := &TransitWatchSnapshot{
		Generation: 3,
		Ready:      ipsecReadyUnsafe,
		Tuples:     []ipsecTopologyTuple{{Kind: "xfrmi", Ifindex: 11, Name: "st0"}},
	}
	snapB := &TransitWatchSnapshot{
		Generation: 4,
		Ready:      ipsecReadyUnsafe,
		Tuples:     []ipsecTopologyTuple{{Kind: "xfrmi", Ifindex: 12, Name: "st1"}},
	}
	closing := testClosingRecord(7, 13, snapA.closeKey(), 3)
	s.permit.Store(closing)
	s.watch.Store(snapA)
	if !s.publishWatchSnapshot(snapB) {
		t.Fatal("changed census publication failed while CLOSING")
	}
	got := s.loadPermit()
	if got.watchGeneration != snapB.Generation || !got.closeRequestKey.equal(snapB.closeKey()) {
		t.Fatalf("record authority = gen %d key %+v, want gen %d key %+v", got.watchGeneration, got.closeRequestKey, snapB.Generation, snapB.closeKey())
	}
	if got.closeRequestSeq <= closing.closeRequestSeq {
		t.Fatalf("census change regressed close sequence from %d to %d", closing.closeRequestSeq, got.closeRequestSeq)
	}
}

func TestIpsecWatchPublishCannotEraseConcurrentRevoke9506(t *testing.T) {
	s := newIpsecSupervisor()
	snapA := &TransitWatchSnapshot{
		Generation: 3,
		Ready:      ipsecReadyUnsafe,
		Tuples:     []ipsecTopologyTuple{{Kind: "xfrmi", Ifindex: 11, Name: "st0"}},
	}
	snapB := &TransitWatchSnapshot{
		Generation: 4,
		Ready:      ipsecReadyUnsafe,
		Tuples:     []ipsecTopologyTuple{{Kind: "xfrmi", Ifindex: 12, Name: "st1"}},
	}
	s.permit.Store(testClosingRecord(7, 13, snapA.closeKey(), snapA.Generation))
	s.watch.Store(snapA)
	ready := make(chan struct{})
	proceed := make(chan struct{})
	s.publishBeforePermitCAS = func() {
		close(ready)
		<-proceed
	}
	done := make(chan bool, 1)
	go func() { done <- s.publishWatchSnapshot(snapB) }()
	<-ready
	concurrent := testKey(ipsecReadyUnknown, 3, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 99, Name: "st9"})
	s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 30, Key: concurrent})
	close(proceed)
	if <-done {
		t.Fatal("stale B publication succeeded over concurrent C revoke")
	}
	got := s.loadPermit()
	if got.closeRequestSeq != 30 || !got.closeRequestKey.equal(concurrent) {
		t.Fatalf("concurrent revoke authority = seq %d key %+v, want 30/%+v", got.closeRequestSeq, got.closeRequestKey, concurrent)
	}
	if s.watch.Load() != snapA {
		t.Fatal("failed publication did not restore the prior watch snapshot")
	}
	s.publishBeforePermitCAS = nil
	snapC := &TransitWatchSnapshot{
		Generation: 4,
		Ready:      ipsecReadyUnknown,
		Tuples:     []ipsecTopologyTuple{{Kind: "xfrmi", Ifindex: 99, Name: "st9"}},
	}
	if !s.publishWatchSnapshot(snapC) {
		t.Fatal("actual C census did not converge after rejecting stale B")
	}
	if got := s.loadPermit(); !got.closeRequestKey.equal(snapC.closeKey()) || s.watch.Load() != snapC {
		t.Fatalf("C census convergence lost authority: permit=%+v watch=%p want=%+v/%p", got.closeRequestKey, s.watch.Load(), snapC.closeKey(), snapC)
	}
}

// Publishing a snapshot while OPEN pre-revokes before the pointer swap, so a
// snapshot token cannot change behind an OPEN CAS.
func TestIpsecWatchPublishPreRevokesWhenOpen9506(t *testing.T) {
	s := newIpsecSupervisor()
	open := testOpenRecord(8, 13, testKey(ipsecReadySafe, 3), 3)
	s.permit.Store(open)
	s.watch.Store(&TransitWatchSnapshot{Generation: 3})
	if !s.publishWatchSnapshot(&TransitWatchSnapshot{Generation: 4}) {
		t.Fatal("watch publish failed while OPEN")
	}
	got := s.loadPermit()
	if got.state != ipsecPermitClosing || got.permitEpoch != 9 {
		t.Fatalf("publish-while-OPEN did not pre-revoke: state %v epoch %d", got.state, got.permitEpoch)
	}
	if got.watchGeneration != 4 {
		t.Fatalf("published watch generation = %d, want 4", got.watchGeneration)
	}
	if open.state != ipsecPermitOpen || open.permitEpoch != 8 {
		t.Fatal("pre-revoke mutated the old snapshot in place; records must be immutable")
	}
}

// Safe-open interleaving (c): a revoke immediately after the OPEN CAS (before
// any stale descriptor validates) makes the stale validation fail.
func TestIpsecPostOpenRevokeBeatsStaleValidation9506(t *testing.T) {
	s := newIpsecSupervisor()
	s.watch.Store(&TransitWatchSnapshot{Generation: 3, Ready: ipsecReadySafe})
	closing := testClosingRecord(7, 13, testKey(ipsecReadySafe, 3), 3)
	s.permit.Store(closing)
	if !s.tryOpenPermit(closing, testKey(ipsecReadySafe, 3), 3) {
		t.Fatal("OPEN CAS failed")
	}
	staleSnap := s.loadPermit()
	s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 14, Key: testKey(ipsecReadyUnsafe, 3)})
	gate := s.registerEmissionGate(1001, ipsecGateForward)
	sink := &recordingVerdictSink{}
	committed, refused, err := s.commitValidatedVerdict(s.leaseTokenForTest(), gate.id, ipsecVerdictAccept, staleSnap, ipsecPacketRef{GateID: gate.id, QueueNumber: gate.id, QueueEpoch: 1, SnapshotGeneration: staleSnap.watchGeneration, PacketID: 1}, sink)
	if err != nil {
		t.Fatalf("stale validation returned error %v; want terminal DROP, not error", err)
	}
	if !refused || committed != ipsecVerdictDrop {
		t.Fatalf("stale validation committed %v refused=%v; want DROP + refused", committed, refused)
	}
	if sink.calls != 1 || sink.last != ipsecVerdictDrop {
		t.Fatalf("sink calls = %d last=%v; want exactly one terminal DROP", sink.calls, sink.last)
	}
}

// The daemon-wide closeEventSeq allocator is the sole sequence source: strictly
// increasing across concurrent allocators, no collisions.
func TestIpsecCloseEventSeqMonotonic9506(t *testing.T) {
	s := newIpsecSupervisor()
	const n = 64
	got := make([]uint64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = s.allocCloseEventSeq()
		}(i)
	}
	wg.Wait()
	seen := map[uint64]bool{}
	for _, v := range got {
		if v == 0 {
			t.Fatal("allocator issued sequence 0; sequences start at 1")
		}
		if seen[v] {
			t.Fatalf("allocator issued duplicate sequence %d", v)
		}
		seen[v] = true
	}
}

type recordingVerdictSink struct {
	calls int
	last  ipsecVerdict
}

func (s *recordingVerdictSink) Verdict(v ipsecVerdict, _ uint32) error {
	s.calls++
	s.last = v
	return nil
}

// CloseRequestKey equality is canonical: tuple order-independent, ready-result
// sensitive, and an UNKNOWN episode is one persistent key (not one per tick).
func TestIpsecCloseRequestKeyCanonical9506(t *testing.T) {
	a := ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, MasterIndex: 21, Name: "st0", Owner: "owner-a"}
	b := ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 12, MasterIndex: 0, Name: "st1", Owner: "owner-b"}
	k1 := testKey(ipsecReadyUnsafe, 3, a, b)
	k2 := testKey(ipsecReadyUnsafe, 3, b, a)
	if !k1.equal(k2) {
		t.Fatal("key equality depends on tuple order; want sorted-canonical")
	}
	k3 := testKey(ipsecReadyUnknown, 3, a, b)
	if k1.equal(k3) {
		t.Fatal("UNSAFE and UNKNOWN keys compare equal; ready result must distinguish")
	}
	u1 := testKey(ipsecReadyUnknown, 3, a)
	u2 := testKey(ipsecReadyUnknown, 3, a)
	if !u1.equal(u2) {
		t.Fatal("repeated UNKNOWN observations produce distinct keys; want one persistent episode key")
	}
}

// Concurrent revokers linearize: one close, one epoch increment, max sequence
// wins, no lost update.
func TestIpsecRevokeConcurrentLinearizable9506(t *testing.T) {
	s := newIpsecSupervisor()
	s.permit.Store(testOpenRecord(4, 7, testKey(ipsecReadySafe, 3), 3))
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := ipsecTopologyEvent{Seq: uint64(100 + i), Key: testKey(ipsecReadyUnsafe, 3)}
			s.revokeTransitPermitNonblocking(ev)
		}(i)
	}
	wg.Wait()
	got := s.loadPermit()
	if got.state != ipsecPermitClosing || got.permitEpoch != 5 {
		t.Fatalf("concurrent revoke = state %v epoch %d, want CLOSING/5", got.state, got.permitEpoch)
	}
	if got.closeRequestSeq != 100+n-1 {
		t.Fatalf("concurrent revoke seq = %d, want max %d", got.closeRequestSeq, 100+n-1)
	}
}

type blockingVerdictSink struct {
	started chan struct{}
	release chan struct{}
}

func (s *blockingVerdictSink) Verdict(ipsecVerdict, uint32) error {
	close(s.started)
	<-s.release
	return nil
}

func TestIpsecCloseDrainWaitsForTerminalSink9506(t *testing.T) {
	s := newIpsecSupervisor()
	key := testKey(ipsecReadySafe, 3)
	open := testOpenRecord(4, 7, key, 3)
	s.permit.Store(open)
	gate := s.registerEmissionGate(1002, ipsecGateForward)
	token := s.leaseTokenForTest()
	sink := &blockingVerdictSink{started: make(chan struct{}), release: make(chan struct{})}
	commitDone := make(chan struct{})
	go func() {
		defer close(commitDone)
		_, _, _ = s.commitValidatedVerdict(token, gate.id, ipsecVerdictAccept, open,
			ipsecPacketRef{GateID: gate.id, QueueNumber: gate.id, QueueEpoch: 1, SnapshotGeneration: 3, PacketID: 1}, sink)
	}()
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("terminal sink did not start")
	}
	drainStarted := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: 8, Key: testKey(ipsecReadyUnsafe, 3)})
		close(drainStarted)
		s.drainCommitLeases()
		close(drainDone)
	}()
	select {
	case <-drainStarted:
	case <-time.After(time.Second):
		t.Fatal("close revoke did not linearize")
	}
	select {
	case <-drainDone:
		t.Fatal("close drain returned while terminal sink was blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(sink.release)
	select {
	case <-commitDone:
	case <-time.After(time.Second):
		t.Fatal("terminal sink did not complete after release")
	}
	select {
	case <-drainDone:
	case <-time.After(time.Second):
		t.Fatal("close drain did not complete after terminal sink")
	}
	current := s.loadPermit()
	committed, refused, err := s.commitValidatedVerdict(s.leaseTokenForTest(), gate.id,
		ipsecVerdictAccept, current,
		ipsecPacketRef{GateID: gate.id, QueueNumber: gate.id, QueueEpoch: 1, SnapshotGeneration: 3, PacketID: 2},
		&recordingVerdictSink{})
	if err != nil {
		t.Fatalf("post-close verdict returned error: %v", err)
	}
	if committed != ipsecVerdictDrop || !refused {
		t.Fatalf("post-close verdict = %v refused=%v, want DROP + refused", committed, refused)
	}
}
