package cluster

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #18559: a requested transfer is make-before-break. The requester opens its
// own dataplane forwarding for the transferring DATA RGs before it asks the
// owner to demote, and releases that pre-activation when the request returns,
// whatever the outcome. These cells pin the ORDER (activate strictly before the
// request leaves; release strictly after the commit), the SCOPE (RG0 never),
// and the FAILURE policy (a failed activation is not a refused transfer).

type preActivateTrace18559 struct {
	mu     sync.Mutex
	events []string
}

func (tr *preActivateTrace18559) add(ev string) {
	tr.mu.Lock()
	tr.events = append(tr.events, ev)
	tr.mu.Unlock()
}

func (tr *preActivateTrace18559) get() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.events...)
}

// newTransferFixture18559 builds a requester (node 0) whose peer owns rgIDs,
// with every local readiness gate open, so a request can commit.
func newTransferFixture18559(t *testing.T, rgIDs []int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	groups := make([]*config.RedundancyGroup, 0, len(rgIDs))
	hbGroups := make([]HeartbeatGroup, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		groups = append(groups, makeRG(rgID, false, map[int]int{0: 100, 1: 200}))
		hbGroups = append(hbGroups, HeartbeatGroup{
			GroupID: uint8(rgID), Priority: 200, Weight: 255, State: uint8(StatePrimary),
		})
	}
	m.UpdateConfig(makeConfig(groups...))
	drainClusterEvents6527(m)
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 1, ClusterID: 1, Groups: hbGroups})
	m.mu.Lock()
	for _, rgID := range rgIDs {
		m.groups[rgID].Ready = true
		m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
		m.groups[rgID].ReadinessReasons = nil
	}
	m.mu.Unlock()
	drainClusterEvents6527(m)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	return m
}

func wireTrace18559(m *Manager, tr *preActivateTrace18559, activateErr error, requestErr error) {
	m.SetTransferPreActivateHooks(
		func(ids []int) error {
			tr.add("activate" + idsLabel18559(ids))
			return activateErr
		},
		func(ids []int) { tr.add("release" + idsLabel18559(ids)) },
	)
	m.SetPeerFailoverFunc(func(int) (uint64, error) {
		tr.add("request")
		return 77, requestErr
	})
	m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) {
		tr.add("request")
		return 77, requestErr
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error { tr.add("commit"); return nil })
	m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error { tr.add("commit"); return nil })
	m.SetPeerFailoverAbortFunc(func(int, uint64) error { tr.add("abort"); return nil })
	m.SetPeerFailoverAbortBatchFunc(func([]int, uint64) error { tr.add("abort"); return nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error { tr.add("commit-ready"); return nil })
}

func idsLabel18559(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, string(rune('0'+id)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestTransferPreActivationBracketsSuccessfulRequest18559(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rgIDs   []int
		request func(*Manager, []int) error
		want    []string
	}{
		{
			name:    "single",
			rgIDs:   []int{1},
			request: func(m *Manager, ids []int) error { return m.RequestPeerFailover(ids[0]) },
			want:    []string{"activate[1]", "request", "commit-ready", "commit", "release[1]"},
		},
		{
			// RG0 is a member of the batch but owns no forwarding: it must
			// not reach the dataplane hook.
			name:    "batch",
			rgIDs:   []int{0, 1, 2},
			request: func(m *Manager, ids []int) error { return m.RequestPeerFailoverBatch(ids) },
			want:    []string{"activate[1,2]", "request", "commit-ready", "commit", "release[1,2]"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTransferFixture18559(t, tc.rgIDs)
			tr := &preActivateTrace18559{}
			wireTrace18559(m, tr, nil, nil)
			if err := tc.request(m, tc.rgIDs); err != nil {
				t.Fatalf("request: %v", err)
			}
			if got := tr.get(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("sequence = %v, want %v: the dataplane must open BEFORE the owner is asked to demote, and close only after the commit", got, tc.want)
			}
			for _, rgID := range tc.rgIDs {
				if !m.IsLocalPrimary(rgID) {
					t.Errorf("RG%d not primary after a committed transfer", rgID)
				}
			}
		})
	}
}

func TestTransferPreActivationReleasedOnFailedRequest18559(t *testing.T) {
	m := newTransferFixture18559(t, []int{1})
	tr := &preActivateTrace18559{}
	wireTrace18559(m, tr, nil, errors.New("ack timeout"))
	if err := m.RequestPeerFailover(1); err == nil {
		t.Fatal("request with a failed ACK reported success")
	}
	got := tr.get()
	if len(got) == 0 || got[0] != "activate[1]" || got[len(got)-1] != "release[1]" {
		t.Fatalf("sequence = %v: a failed request must still release its pre-activation, last", got)
	}
	for _, ev := range got {
		if ev == "commit" {
			t.Fatalf("sequence = %v: no commit may follow a failed request", got)
		}
	}
	if m.IsLocalPrimary(1) {
		t.Fatal("RG1 primary after a failed request")
	}
}

// A dataplane that cannot pre-activate must not cost the operator the
// transfer: it degrades to the old break-before-make order. The release still
// runs (immediately), so a partial activation cannot leak.
func TestTransferPreActivationFailureDoesNotRefuseTransfer18559(t *testing.T) {
	m := newTransferFixture18559(t, []int{1})
	tr := &preActivateTrace18559{}
	wireTrace18559(m, tr, errors.New("no helper"), nil)
	if err := m.RequestPeerFailover(1); err != nil {
		t.Fatalf("a failed pre-activation refused the transfer: %v", err)
	}
	want := []string{"activate[1]", "release[1]", "request", "commit-ready", "commit"}
	if got := tr.get(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sequence = %v, want %v", got, want)
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("RG1 not primary after a committed transfer")
	}
}

func TestTransferPreActivationSkipsControlRG18559(t *testing.T) {
	m := newTransferFixture18559(t, []int{0})
	tr := &preActivateTrace18559{}
	wireTrace18559(m, tr, nil, nil)
	if err := m.RequestPeerFailover(0); err != nil {
		t.Fatalf("request: %v", err)
	}
	for _, ev := range tr.get() {
		if strings.HasPrefix(ev, "activate") || strings.HasPrefix(ev, "release") {
			t.Fatalf("sequence = %v: RG0 owns no forwarding and must not pre-activate", tr.get())
		}
	}
}
