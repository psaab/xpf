package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16697: GetSessions must stamp ha_state tri-state on all paths. Cluster
// with no RETH owners => "unknown" (not Backup/false guess); known RG =>
// Active/Backup unchanged; standalone => Active.
//
// RED pre-fix: HaState field does not exist / stays "" and renderers guess
// Backup from HaActive=false.

type ha16697DP struct {
	*filteredTotalDP
	apply *dataplane.ApplyResult
}

func (d *ha16697DP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

// newHA16697Server builds a Server whose store holds either no RETH
// (unknown) or reth1 RG1 (known), with a cluster manager that knows RG1.
func newHA16697Server(t *testing.T, withReth bool) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-16697",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
	}
	if withReth {
		lines = append(lines,
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
			"set interfaces reth1 redundant-ether-options redundancy-group 1",
			"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces reth1.0",
		)
	} else {
		lines = append(lines,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
		)
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatalf("fixture: no cluster config: %+v", cfg)
	}
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(cfg.Chassis.Cluster)
	mgr.SetGroupStateForTesting(1, cluster.StatePrimary)
	apply := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1}}
	dp := &ha16697DP{filteredTotalDP: &filteredTotalDP{Manager: dataplane.New(), v4: []v4Session{{
		key: dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 11}, DstIP: [4]byte{172, 16, 80, 8}, SrcPort: hostToNetwork16(40011), DstPort: hostToNetwork16(443), Protocol: 6},
		val: dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 1},
	}}}, apply: apply}
	return &Server{store: store, dp: dp, cluster: mgr}
}

func TestGetSessionsHAStateUnknown16697(t *testing.T) {
	for _, pageSize := range []int32{0, 100} {
		s := newHA16697Server(t, false)
		resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: pageSize})
		if err != nil {
			t.Fatalf("pageSize=%d GetSessions: %v", pageSize, err)
		}
		if len(resp.Sessions) != 1 {
			t.Fatalf("pageSize=%d sessions=%d want 1", pageSize, len(resp.Sessions))
		}
		se := resp.Sessions[0]
		if se.HaState != "unknown" {
			t.Errorf("pageSize=%d HaState=%q want unknown (no RETH owners)", pageSize, se.HaState)
		}
		if se.HaActive {
			t.Errorf("pageSize=%d HaActive=true for unknown, want false (compat bool)", pageSize)
		}
	}
}

func TestGetSessionsHAStateKnownUnchanged16697(t *testing.T) {
	// Control: session ingress is ge-0/0/0 zone name fallback; with reth the
	// zone fallback resolves RG1 primary => Active. Use direct stamp check
	// via sessionHAActive + HaState on a reth-ingress entry constructed
	// through GetSessions with zone-bound reth.
	s := newHA16697Server(t, true)
	// The fake session has no ifindex, so ingress falls back to zone name
	// "trust" which is bound to reth1.0 in this fixture.
	for _, pageSize := range []int32{0, 100} {
		resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: pageSize})
		if err != nil {
			t.Fatalf("pageSize=%d GetSessions: %v", pageSize, err)
		}
		if len(resp.Sessions) != 1 {
			t.Fatalf("pageSize=%d sessions=%d", pageSize, len(resp.Sessions))
		}
		se := resp.Sessions[0]
		if se.HaState != "Active" || !se.HaActive {
			t.Errorf("pageSize=%d known RG1 primary: HaState=%q HaActive=%v want Active/true", pageSize, se.HaState, se.HaActive)
		}
	}
}

func TestGetSessionsHAStateStandalone16697(t *testing.T) {
	s := newViewServer(t, newFilteredTotalDP())
	resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if len(resp.Sessions) == 0 {
		t.Fatal("no sessions")
	}
	for _, se := range resp.Sessions {
		if se.HaState != "Active" || !se.HaActive {
			t.Errorf("standalone: HaState=%q HaActive=%v want Active/true", se.HaState, se.HaActive)
		}
	}
}
