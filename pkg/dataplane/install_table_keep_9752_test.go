package dataplane

// #9752: unknown-never-default on cluster-synced install. A (0,0)
// install-table identity over an already-stamped row of the same (or
// unknown) incarnation is an old sender's resend — absence decodes as zero —
// never a genuine re-stamp (stamps are install-stable per incarnation, and
// new senders memo-restore nonzero). The install keeps the recorded stamp
// instead of erasing it, so mixed clusters never silently wrong-table the
// fixed node's sessions on sweep/bulk resends.

import (
	"testing"
)

func installTableKeepStore9752(t *testing.T) (*dataPlaneSessionStore, *sessionStoreTestDP) {
	t.Helper()
	dp := &sessionStoreTestDP{
		v4: make(map[SessionKey]SessionValue),
		v6: make(map[SessionKeyV6]SessionValueV6),
	}
	return &dataPlaneSessionStore{dp: dp}, dp
}

func TestStampLessResendKeepsTheRecordedStamp9752(t *testing.T) {
	s, dp := installTableKeepStore9752(t)
	key := SessionKey{Protocol: 6, SrcPort: 47912, DstPort: 5203}
	stamped := SessionValue{
		SessionID: 77, InstallTableDomain: 525590, InstallTableCheck: 3318534811,
	}
	if err := s.PutClusterSyncedV4(key, stamped); err != nil {
		t.Fatalf("seed install: %v", err)
	}
	// Old sender's resend: same incarnation, stamp absent => (0,0).
	resend := SessionValue{SessionID: 77}
	if err := s.PutClusterSyncedV4(key, resend); err != nil {
		t.Fatalf("resend install: %v", err)
	}
	got, ok := dp.v4[key]
	if !ok {
		t.Fatal("resend removed the row")
	}
	if got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("#9752: a stamp-less resend for the same incarnation erased the recorded "+
			"identity to (%d,%d); the fixed node would re-resolve in inet.0",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}

func TestNewIncarnationAcceptsAZeroStamp9752(t *testing.T) {
	s, dp := installTableKeepStore9752(t)
	key := SessionKey{Protocol: 6, SrcPort: 47912, DstPort: 5203}
	stamped := SessionValue{
		SessionID: 77, InstallTableDomain: 525590, InstallTableCheck: 3318534811,
	}
	if err := s.PutClusterSyncedV4(key, stamped); err != nil {
		t.Fatalf("seed install: %v", err)
	}
	// New incarnation, genuinely default table: must apply, not inherit.
	fresh := SessionValue{SessionID: 78}
	if err := s.PutClusterSyncedV4(key, fresh); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	got := dp.v4[key]
	if got.InstallTableDomain != 0 || got.InstallTableCheck != 0 {
		t.Fatalf("#9752: a new incarnation stating (0,0) inherited (%d,%d)",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}

func TestStampedResendOverwrites9752(t *testing.T) {
	s, dp := installTableKeepStore9752(t)
	key := SessionKey{Protocol: 6, SrcPort: 47912, DstPort: 5203}
	if err := s.PutClusterSyncedV4(key, SessionValue{SessionID: 77}); err != nil {
		t.Fatalf("seed install: %v", err)
	}
	stamped := SessionValue{
		SessionID: 77, InstallTableDomain: 525590, InstallTableCheck: 3318534811,
	}
	if err := s.PutClusterSyncedV4(key, stamped); err != nil {
		t.Fatalf("stamped install: %v", err)
	}
	got := dp.v4[key]
	if got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("#9752: an explicit nonzero stamp was not applied, got (%d,%d)",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}
