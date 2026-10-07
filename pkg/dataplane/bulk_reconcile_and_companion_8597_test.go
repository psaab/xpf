package dataplane

import (
	"errors"
	"strings"
	"testing"
)

// #8597 K73 + K74, both in session_store.go.
//
// K73: ReconcileClusterBulk's V4 enumerate failure early-returned, skipping the
// V4 delete phase AND the whole V6 sweep. The two families are independent map
// dumps and a failure to read one says nothing about the other; the caller could
// not distinguish "V6 clean" from "V6 never looked at" because StaleV6 is 0
// either way.
//
// K74: the explicit reverse companion built by PutClusterSyncedV4/V6 did not
// apply ResetUnobservedForReverseCompanion, so it inherited the forward row's
// IngressIfaceFold — which ScrubNodeLocal deliberately preserves, being
// cluster-stable by design. See reverse_companion_reset_7917_test.go for the
// half of K74 that turned out to matter more: the reset itself had to learn
// #8612's FibGen conditional BEFORE it could safely be called.

// enumFailDP fails one family's batch iteration and delegates the rest.
type enumFailDP struct {
	*sessionStoreTestDP
	failV4 error
	failV6 error
}

func (m *enumFailDP) BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error {
	if m.failV4 != nil {
		return m.failV4
	}
	return m.sessionStoreTestDP.BatchIterateSessions(fn)
}

func (m *enumFailDP) BatchIterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	if m.failV6 != nil {
		return m.failV6
	}
	return m.sessionStoreTestDP.BatchIterateSessionsV6(fn)
}

// bulkFixture seeds one V4 and one V6 session, both stale by construction: the
// zone is one ShouldSyncZone reports true for (so they are peer-owned rows this
// node holds) and neither key is in the received set.
func bulkFixture() (*enumFailDP, ClusterBulkReconcileInput) {
	v4Key := SessionKey{Protocol: 6, SrcPort: 1000}
	v6Key := SessionKeyV6{Protocol: 6, SrcPort: 2000}
	base := &sessionStoreTestDP{
		v4: map[SessionKey]SessionValue{v4Key: {IngressZone: 7}},
		v6: map[SessionKeyV6]SessionValueV6{v6Key: {IngressZone: 7}},
	}
	in := ClusterBulkReconcileInput{
		ReceivedV4:     map[SessionKey]struct{}{},
		ReceivedV6:     map[SessionKeyV6]struct{}{},
		ShouldSyncZone: func(uint16) bool { return false },
		DeleteReason:   DeleteReasonClusterStale,
	}
	return &enumFailDP{sessionStoreTestDP: base}, in
}

// The positive control, first: with nothing failing both families are swept, so
// a zero below means "skipped" rather than "there was nothing to find".
func TestBulkReconcileSweepsBothFamilies_8597(t *testing.T) {
	dp, in := bulkFixture()
	res, err := (dataPlaneSessionStore{dp: dp}).ReconcileClusterBulk(in)
	if err != nil {
		t.Fatalf("clean reconcile: %v", err)
	}
	if res.StaleV4 != 1 || res.StaleV6 != 1 {
		t.Fatalf("the fixture is not stale in both families: %+v — every cell below "+
			"measures nothing if this is wrong", res)
	}
}

// K73. A V4 enumerate failure must not suppress the V6 sweep.
func TestAV4EnumerateFailureStillSweepsV6_8597(t *testing.T) {
	dp, in := bulkFixture()
	dp.failV4 = errors.New("v4 map dump refused")

	res, err := (dataPlaneSessionStore{dp: dp}).ReconcileClusterBulk(in)
	if err == nil {
		t.Fatal("the refused V4 enumeration must still be reported")
	}
	if !strings.Contains(err.Error(), "enumerate v4 sessions") {
		t.Errorf("the joined error does not say WHICH family failed to enumerate, so "+
			"the operator cannot tell which count to distrust: %v", err)
	}
	if res.StaleV6 != 1 {
		t.Errorf("StaleV6=%d, want 1: the V6 sweep was skipped because the V4 dump "+
			"failed. The two are independent map dumps, and a skipped sweep is "+
			"indistinguishable from a clean one at the caller (#8597 K73)", res.StaleV6)
	}
	if res.DeletedV6 != 1 {
		t.Errorf("DeletedV6=%d, want 1: stale peer sessions survive the bulk "+
			"reconcile on the standby (#8597 K73)", res.DeletedV6)
	}
}

// The mirror direction: a V6 enumerate failure must not lose the V4 work that
// already succeeded, and must be labelled too.
func TestAV6EnumerateFailureKeepsTheV4Result_8597(t *testing.T) {
	dp, in := bulkFixture()
	dp.failV6 = errors.New("v6 map dump refused")

	res, err := (dataPlaneSessionStore{dp: dp}).ReconcileClusterBulk(in)
	if err == nil {
		t.Fatal("the refused V6 enumeration must still be reported")
	}
	if !strings.Contains(err.Error(), "enumerate v6 sessions") {
		t.Errorf("the joined error does not name the v6 family: %v", err)
	}
	if res.StaleV4 != 1 || res.DeletedV4 != 1 {
		t.Errorf("the V4 work was lost: %+v", res)
	}
}

// ---- K74: the WIRING, not the function ----
//
// reverse_companion_reset_7917_test.go proves the reset is correct. These prove
// the store actually calls it — the distinction that let this row exist at all,
// since the reset has been correct and callerless since #8015.

func TestPutClusterSyncedV4CompanionDropsTheForwardDirectionFolds_8597(t *testing.T) {
	fwdKey := SessionKey{Protocol: 6, SrcPort: 1000}
	revKey := SessionKey{Protocol: 6, SrcPort: 2000}
	dp := &sessionStoreTestDP{v4: map[SessionKey]SessionValue{}}
	val := SessionValue{
		IngressZone:      1,
		EgressZone:       2,
		ReverseKey:       revKey,
		IngressIfaceFold: 0xABCD,
		EgressIfaceFold:  0xEF01,
		FibIfindex:       99,
	}
	if err := (dataPlaneSessionStore{dp: dp}).PutClusterSyncedV4(fwdKey, val); err != nil {
		t.Fatalf("PutClusterSyncedV4: %v", err)
	}
	fwd, ok := dp.v4[fwdKey]
	if !ok {
		t.Fatal("the forward row was not installed — this cell measures nothing")
	}
	rev, ok := dp.v4[revKey]
	if !ok {
		t.Fatal("the reverse companion was not installed — this cell measures nothing")
	}
	// Both folds are stable and scrubbed as peer values, but the companion reset
	// clears them because neither is an observation of the reply direction.
	if fwd.IngressIfaceFold != 0xABCD || fwd.EgressIfaceFold != 0xEF01 {
		t.Fatalf("the forward row did not preserve its cluster-stable folds: ingress=%#x egress=%#x",
			fwd.IngressIfaceFold, fwd.EgressIfaceFold)
	}
	if rev.IngressIfaceFold != 0 || rev.EgressIfaceFold != 0 {
		t.Errorf("the reverse companion carries forward-direction identity: ingress=%#x egress=%#x",
			rev.IngressIfaceFold, rev.EgressIfaceFold)
	}
	if rev.IsReverse != 1 || rev.IngressZone != 2 || rev.EgressZone != 1 {
		t.Errorf("the companion is not the swapped reverse: %+v", rev)
	}
}

func TestPutClusterSyncedV6CompanionDropsTheForwardDirectionFolds_8597(t *testing.T) {
	fwdKey := SessionKeyV6{Protocol: 6, SrcPort: 1000}
	revKey := SessionKeyV6{Protocol: 6, SrcPort: 2000}
	dp := &sessionStoreTestDP{v6: map[SessionKeyV6]SessionValueV6{}}
	val := SessionValueV6{
		IngressZone:      1,
		EgressZone:       2,
		ReverseKey:       revKey,
		IngressIfaceFold: 0xABCD,
		EgressIfaceFold:  0xEF01,
	}
	if err := (dataPlaneSessionStore{dp: dp}).PutClusterSyncedV6(fwdKey, val); err != nil {
		t.Fatalf("PutClusterSyncedV6: %v", err)
	}
	fwd := dp.v6[fwdKey]
	rev, ok := dp.v6[revKey]
	if !ok {
		t.Fatal("the v6 reverse companion was not installed")
	}
	if fwd.IngressIfaceFold != 0xABCD || fwd.EgressIfaceFold != 0xEF01 {
		t.Fatalf("the v6 forward row did not preserve its cluster-stable folds: ingress=%#x egress=%#x",
			fwd.IngressIfaceFold, fwd.EgressIfaceFold)
	}
	if rev.IngressIfaceFold != 0 || rev.EgressIfaceFold != 0 {
		t.Errorf("the v6 reverse companion carries forward-direction folds: ingress=%#x egress=%#x",
			rev.IngressIfaceFold, rev.EgressIfaceFold)
	}
}

// THE CELL THAT MAKES THE CORRECTION VISIBLE AT THE CALL SITE. The finding's
// literal fix — "one-line ResetUnobservedForReverseCompanion() at both sites" —
// applied to the reset AS IT STOOD would have zeroed a live tunnel endpoint id
// here. Unlike IngressIfaceFold, FibGen IS carried in the on-map ABI, so the
// erasure would have reached the map rather than a field nothing serialises.
func TestPutClusterSyncedCompanionKeepsTheTunnelEndpointID_8597(t *testing.T) {
	fwdKey := SessionKey{Protocol: 6, SrcPort: 1000}
	revKey := SessionKey{Protocol: 6, SrcPort: 2000}
	dp := &sessionStoreTestDP{v4: map[SessionKey]SessionValue{}}
	val := SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		ReverseKey:  revKey,
		LogFlags:    LogFlagUserspaceTunnelEndpoint,
		FibGen:      0x1234, // a StableTunnelEndpointID, not a FIB generation
		FibIfindex:  99,     // node-local, must still go
	}
	if err := (dataPlaneSessionStore{dp: dp}).PutClusterSyncedV4(fwdKey, val); err != nil {
		t.Fatalf("PutClusterSyncedV4: %v", err)
	}
	rev, ok := dp.v4[revKey]
	if !ok {
		t.Fatal("the reverse companion was not installed")
	}
	if rev.FibGen != 0x1234 {
		t.Errorf("the companion's tunnel endpoint id was zeroed to %#x. Under "+
			"LogFlagUserspaceTunnelEndpoint FibGen is a StableTunnelEndpointID "+
			"folded from the interface NAME — identical on both nodes and in both "+
			"directions — so the reply direction has not failed to observe it "+
			"(#8612 via #8597 K74)", rev.FibGen)
	}
	if rev.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
		t.Errorf("the tunnel bit was cleared though its value survives; flag and " +
			"value must agree by KEEPING both (#8612)")
	}
	if rev.FibIfindex != 0 {
		t.Errorf("FibIfindex=%d survived on the companion — the unconditional half "+
			"of the reset must still run, or 'preserved' just means the reset was "+
			"never called (#7917)", rev.FibIfindex)
	}
}
