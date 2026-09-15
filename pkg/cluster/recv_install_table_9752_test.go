package cluster

// #9752 round 3: the receive-side installing-table record lives in Go memory
// (restoreInstallTableLocked), never in the BPF mirror — which drops
// sync-only fields on read. These cells run the REAL receive apply
// (installClusterSyncedV4: real gen guard, real store, real delete paths)
// against a LOSSY dataplane double shaped like the BPF mirror: reads come
// back without the stamp. The observable is what the apply HANDS the mirror
// (recorded Set args — Set receives the full struct; the loss happens inside
// the real Manager, past this seam).

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// lossyMirrorDP9752 is a mockSweepDP whose session reads drop the
// installing-table identity, exactly as bpfSessionValue.sessionValue does in
// production (and whose writes are recorded so the test can see what the
// cluster apply handed down — the only place the restored stamp is
// observable, since the mirror itself cannot hold it).
type lossyMirrorDP9752 struct {
	*mockSweepDP
	sets []dataplane.SessionValue
}

func (f *lossyMirrorDP9752) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(f)
}

func (f *lossyMirrorDP9752) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	f.sets = append(f.sets, val)
	val.InstallTableDomain, val.InstallTableCheck = 0, 0
	return f.mockSweepDP.SetSessionV4(key, val)
}

func (f *lossyMirrorDP9752) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	v, err := f.mockSweepDP.GetSessionV4(key)
	v.InstallTableDomain, v.InstallTableCheck = 0, 0
	return v, err
}

func (f *lossyMirrorDP9752) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return f.mockSweepDP.BatchIterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		val.InstallTableDomain, val.InstallTableCheck = 0, 0
		return fn(key, val)
	})
}

func lossyRecvSync9752(t *testing.T) (*SessionSync, *lossyMirrorDP9752) {
	t.Helper()
	dp := &lossyMirrorDP9752{mockSweepDP: &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}}
	return NewSessionSync(":0", "10.0.0.2:4785", dp), dp
}

func lastSet9752(t *testing.T, dp *lossyMirrorDP9752) dataplane.SessionValue {
	t.Helper()
	if len(dp.sets) == 0 {
		t.Fatal("no Set reached the mirror")
	}
	return dp.sets[len(dp.sets)-1]
}

func TestRecvMemoRestoresOverLossyMirror9752(t *testing.T) {
	fwd := rtflowKeyV4(41001)
	ss, dp := lossyRecvSync9752(t)
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 10,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	if got := lastSet9752(t, dp); got.InstallTableDomain != 525590 {
		t.Fatal("FIXTURE: stamped install did not land")
	}
	// Old sender's resend: same incarnation, higher generation, no
	// install-table tail — encoded through the REAL message encoder (header
	// + payload, the sendCh/journal shape) and decoded through the real
	// decoder. The decoded key MUST equal the installed key or the cell is
	// vacuous (a resend to a garbage key proves nothing).
	wire := encodeSessionV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 11})
	payload := wire[syncHeaderSize:]
	truncated := payload[:len(payload)-8] // strip the (0,0) tail: pre-9752 shape
	key, val, ok := decodeSessionV4Payload(truncated)
	if !ok {
		t.Fatal("FIXTURE: truncated resend did not decode")
	}
	if key != fwd {
		t.Fatal("FIXTURE: decoded resend key does not name the installed session")
	}
	if val.SessionID != 77 || val.Generation != 11 {
		t.Fatalf("FIXTURE: decoded resend lost identity (sid=%d gen=%d)", val.SessionID, val.Generation)
	}
	ss.installClusterSyncedV4(key, val)
	got := lastSet9752(t, dp)
	if got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("#9752 round 3: a stamp-less resend over a lossy mirror installed "+
			"(%d,%d); the receive record must restore it from Go memory, never the mirror",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}

func TestRecvMemoNewIncarnationAppliesZero9752(t *testing.T) {
	fwd := rtflowKeyV4(41002)
	ss, dp := lossyRecvSync9752(t)
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 10,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	// New incarnation, genuinely default table: must apply, not inherit.
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 78, RTFlowSessionID: 78, Generation: 11})
	if got := lastSet9752(t, dp); got.InstallTableDomain != 0 || got.InstallTableCheck != 0 {
		t.Fatalf("#9752 round 3: a new incarnation stating (0,0) inherited (%d,%d)",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}

func TestRecvMemoStampedOverwrite9752(t *testing.T) {
	fwd := rtflowKeyV4(41003)
	ss, dp := lossyRecvSync9752(t)
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 10})
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 11,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	if got := lastSet9752(t, dp); got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("#9752 round 3: an explicit nonzero stamp was not applied, got (%d,%d)",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}

func TestRecvMemoDeleteEvicts9752(t *testing.T) {
	fwd := rtflowKeyV4(41004)
	ss, dp := lossyRecvSync9752(t)
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 10,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	ss.deleteClusterSyncedV4(fwd, 11, false)
	n := len(dp.sets)
	// Late resend for the deleted incarnation (higher gen so the gen guard,
	// not the memo, is out of the picture): the record is gone, so (0,0)
	// applies instead of resurrecting the stamp.
	ss.installClusterSyncedV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77, Generation: 12})
	if len(dp.sets) != n+1 {
		t.Fatal("FIXTURE: reinstall did not reach the mirror")
	}
	if got := lastSet9752(t, dp); got.InstallTableDomain != 0 || got.InstallTableCheck != 0 {
		t.Fatalf("#9752 round 3: a delete did not evict the received record; got (%d,%d)",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}
