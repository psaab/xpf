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

// lossyMirrorDP9752 is a mockSweepDP whose session reads drop EXACTLY the
// fields production drops: bpfSessionValue.sessionValue rebuilds only the
// on-map ABI prefix (through RoutingDomain) and zeroes every sync-only
// trailing field. Writes are recorded so the test can see what the cluster
// apply handed down — the only place a restored stamp is observable, since
// the mirror itself cannot hold it.
type lossyMirrorDP9752 struct {
	*mockSweepDP
	sets   []dataplane.SessionValue
	setsV6 []dataplane.SessionValueV6
}

// dropSyncOnly9752 mirrors the production loss field-for-field
// (pkg/dataplane/bpf_session_value.go: the toBPF projection drops, and
// sessionValue never restores, everything past RoutingDomain). If the BPF
// ABI grows a field, this list must grow with it — a narrower fake would
// hand the code under test state production never provides.
func dropSyncOnly9752(v *dataplane.SessionValue) {
	v.Generation = 0
	v.PolicyCounterIdx = 0
	v.ConfigEpoch = 0
	v.RTFlowSessionID = 0
	v.IngressIfaceFold = 0
	v.TunnelDiscriminator = 0
	v.TCPCloseClass = 0
	v.InstallTableDomain = 0
	v.InstallTableCheck = 0
}

func dropSyncOnlyV69752(v *dataplane.SessionValueV6) {
	v.Generation = 0
	v.PolicyCounterIdx = 0
	v.Nat64SnatV4 = [4]byte{}
	v.ConfigEpoch = 0
	v.RTFlowSessionID = 0
	v.IngressIfaceFold = 0
	v.TunnelDiscriminator = 0
	v.TCPCloseClass = 0
	v.InstallTableDomain = 0
	v.InstallTableCheck = 0
}

func (f *lossyMirrorDP9752) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(f)
}

func (f *lossyMirrorDP9752) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	f.sets = append(f.sets, val)
	dropSyncOnly9752(&val)
	return f.mockSweepDP.SetSessionV4(key, val)
}

func (f *lossyMirrorDP9752) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	v, err := f.mockSweepDP.GetSessionV4(key)
	dropSyncOnly9752(&v)
	return v, err
}

func (f *lossyMirrorDP9752) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return f.mockSweepDP.BatchIterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		dropSyncOnly9752(&val)
		return fn(key, val)
	})
}

func (f *lossyMirrorDP9752) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	f.setsV6 = append(f.setsV6, val)
	dropSyncOnlyV69752(&val)
	return f.mockSweepDP.SetSessionV6(key, val)
}

func (f *lossyMirrorDP9752) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	v, err := f.mockSweepDP.GetSessionV6(key)
	dropSyncOnlyV69752(&v)
	return v, err
}

func (f *lossyMirrorDP9752) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return f.mockSweepDP.BatchIterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		dropSyncOnlyV69752(&val)
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
	truncated := payload[:len(payload)-9] // strip table + high-flags tails: pre-10227 shape
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
	if val.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("FIXTURE: decoded legacy v4 origin flags=%#x, want clear", val.Flags)
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

// TestLossyMirrorMatchesProductionLossExactly9752 pins the fixture to the
// production loss (TestBPFConversionDropsExactlyTheSyncOnlyTail9752 in
// pkg/dataplane): the same fully-populated value must emerge identically
// from both. If the BPF ABI grows a field, that test breaks first — update
// dropSyncOnly9752 with it, or this cell fails next.
func TestLossyMirrorMatchesProductionLossExactly9752(t *testing.T) {
	full := dataplane.SessionValue{
		State: 1, Flags: 2, TCPState: 3, IsReverse: 1, AppTimeout: 4,
		SessionID: 5, Created: 6, LastSeen: 7, Timeout: 8, PolicyID: 9,
		IngressZone: 10, EgressZone: 11,
		NATSrcIP: 12, NATDstIP: 13, NATSrcPort: 14, NATDstPort: 15,
		FwdPackets: 16, FwdBytes: 17, RevPackets: 18, RevBytes: 19,
		ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 1, DstPort: 2},
		ALGType:    20, LogFlags: 21, AppID: 22,
		FibIfindex: 23, FibVlanID: 24,
		FibDmac: [6]byte{1, 2, 3, 4, 5, 6}, FibSmac: [6]byte{6, 5, 4, 3, 2, 1},
		FibGen: 25, IngressIfindex: 26, IngressVlanID: 27, RoutingDomain: 28,
		Generation: 29, PolicyCounterIdx: 30, ConfigEpoch: 31,
		RTFlowSessionID: 32, IngressIfaceFold: 33, TunnelDiscriminator: 34,
		TCPCloseClass: 35, InstallTableDomain: 36, InstallTableCheck: 37,
	}
	got := full
	dropSyncOnly9752(&got)
	want := full
	want.Generation, want.PolicyCounterIdx, want.ConfigEpoch = 0, 0, 0
	want.RTFlowSessionID, want.IngressIfaceFold, want.TunnelDiscriminator = 0, 0, 0
	want.TCPCloseClass, want.InstallTableDomain, want.InstallTableCheck = 0, 0, 0
	if got != want {
		t.Fatalf("lossy fixture diverges from production loss:\n got %+v\nwant %+v", got, want)
	}
	// The mirror reads must apply it (not just the helper): seed full, read lossy.
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	f := &lossyMirrorDP9752{mockSweepDP: dp}
	key := dataplane.SessionKey{Protocol: 6, SrcPort: 1, DstPort: 2}
	if err := dp.SetSessionV4(key, full); err != nil {
		t.Fatalf("seed: %v", err)
	}
	read, err := f.GetSessionV4(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if read != want {
		t.Fatalf("lossy Get diverges from production loss:\n got %+v\nwant %+v", read, want)
	}
}

func lastSetV610068(t *testing.T, dp *lossyMirrorDP9752) dataplane.SessionValueV6 {
	t.Helper()
	if len(dp.setsV6) == 0 {
		t.Fatal("no v6 Set reached the mirror")
	}
	return dp.setsV6[len(dp.setsV6)-1]
}

// TestRecvMemoRestoresOverLossyMirrorV610068 mirrors the current production
// shape of the removed v4 keep-rule cells: the received install memo, not the
// lossy BPF mirror, restores an old sender's stamp-less v6 resend.
func TestRecvMemoRestoresOverLossyMirrorV610068(t *testing.T) {
	fwd := rtflowKeyV6(41001)
	ss, dp := lossyRecvSync9752(t)
	ss.installClusterSyncedV6(fwd, dataplane.SessionValueV6{
		SessionID: 77, RTFlowSessionID: 77, Generation: 10,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811,
	})
	if got := lastSetV610068(t, dp); got.InstallTableDomain != 525590 {
		t.Fatal("FIXTURE: stamped v6 install did not land")
	}
	wire := encodeSessionV6(fwd, dataplane.SessionValueV6{
		SessionID: 77, RTFlowSessionID: 77, Generation: 11,
	})
	payload := wire[syncHeaderSize:]
	truncated := payload[:len(payload)-9] // strip table + high-flags tails: pre-10227 shape
	key, val, ok := decodeSessionV6Payload(truncated)
	if !ok {
		t.Fatal("FIXTURE: truncated v6 resend did not decode")
	}
	if key != fwd {
		t.Fatal("FIXTURE: decoded v6 resend key does not name the installed session")
	}
	if val.SessionID != 77 || val.Generation != 11 {
		t.Fatalf("FIXTURE: decoded v6 resend lost identity (sid=%d gen=%d)",
			val.SessionID, val.Generation)
	}
	if val.Flags&dataplane.SessFlagClusterSynced != 0 {
		t.Fatalf("FIXTURE: decoded legacy v6 origin flags=%#x, want clear", val.Flags)
	}
	ss.installClusterSyncedV6(key, val)
	got := lastSetV610068(t, dp)
	if got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("#10068: a stamp-less v6 resend over a lossy mirror installed "+
			"(%d,%d); the receive record must restore it from Go memory",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}
