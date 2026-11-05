package cluster

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

type manualFailoverStateSnapshot16016 struct {
	state                    NodeState
	weight                   int
	manualFailover           bool
	manualFailoverAt         time.Time
	failoverCount            int
	transferCommitRolePinned bool
}

func manualFailoverManager16016(t *testing.T, rgIDs ...int) (*Manager, *authorityClock16016) {
	t.Helper()
	m, clock, _ := setupAuthorityManager16016(t)
	groups := make([]*config.RedundancyGroup, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		groups = append(groups, makeRG(rgID, true, map[int]int{0: 200}))
	}
	cfg := makeConfig(groups...)
	cfg.ControlInterface = "em0"
	m.UpdateConfig(cfg)
	drainManualFailoverEvents16016(m)

	// Use an established-primary fixture so the refusal proves the roles are
	// held exactly as they stood before the request, rather than testing cold
	// boot election behavior.
	m.mu.Lock()
	for _, rgID := range rgIDs {
		rg := m.groups[rgID]
		rg.State = StatePrimary
		rg.Weight = 255
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		rg.FailoverCount = 3
		rg.transferCommitRolePinned = false
	}
	m.mu.Unlock()
	return m, clock
}

func snapshotManualFailoverState16016(m *Manager) map[int]manualFailoverStateSnapshot16016 {
	states := m.GroupStates()
	snapshot := make(map[int]manualFailoverStateSnapshot16016, len(states))
	for _, rg := range states {
		snapshot[rg.GroupID] = manualFailoverStateSnapshot16016{
			state:                    rg.State,
			weight:                   rg.Weight,
			manualFailover:           rg.ManualFailover,
			manualFailoverAt:         rg.ManualFailoverAt,
			failoverCount:            rg.FailoverCount,
			transferCommitRolePinned: rg.transferCommitRolePinned,
		}
	}
	return snapshot
}

func assertManualFailoverStateUnchanged16016(t *testing.T, m *Manager, want map[int]manualFailoverStateSnapshot16016) {
	t.Helper()
	got := snapshotManualFailoverState16016(m)
	if len(got) != len(want) {
		t.Fatalf("RG count after refusal = %d, want %d", len(got), len(want))
	}
	for rgID, expected := range want {
		if actual, ok := got[rgID]; !ok || actual != expected {
			t.Errorf("RG%d state after refusal = %+v, want unchanged %+v", rgID, actual, expected)
		}
	}
}

func drainManualFailoverEvents16016(m *Manager) {
	for {
		select {
		case <-m.Events():
		default:
			return
		}
	}
}

func assertNoManualFailoverEvent16016(t *testing.T, m *Manager) {
	t.Helper()
	select {
	case event := <-m.Events():
		t.Fatalf("refused manual failover emitted event: %+v", event)
	default:
	}
}

func assertUnkeyedAuthorityExpired16016(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("manual failover succeeded after unkeyed authority grace expired")
	}
	if err.Error() != unkeyedAuthorityExpiredReason {
		t.Fatalf("manual failover error = %q, want %q", err, unkeyedAuthorityExpiredReason)
	}
}

func blockedManualFailoverHook16016(m *Manager) (<-chan struct{}, func()) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	m.SetPreManualFailoverHook(func(int) error {
		startedOnce.Do(func() { close(started) })
		<-release
		return nil
	})
	return started, func() { releaseOnce.Do(func() { close(release) }) }
}

func waitManualFailoverHook16016(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("manual failover did not enter pre-hook")
	}
}

func TestExpiredClusterRefusesManualFailover16016(t *testing.T) {
	m, clock := manualFailoverManager16016(t, 0)
	before := snapshotManualFailoverState16016(m)
	clock.advance(unkeyedAuthorityGrace)

	_, err := m.ManualFailover(0)
	assertUnkeyedAuthorityExpired16016(t, err)
	assertManualFailoverStateUnchanged16016(t, m, before)
	assertNoManualFailoverEvent16016(t, m)
}

func TestInGraceClusterAllowsManualFailover16016(t *testing.T) {
	m, _ := manualFailoverManager16016(t, 0)

	outcome, err := m.ManualFailover(0)
	if err != nil {
		t.Fatalf("manual failover before unkeyed grace expiry: %v", err)
	}
	if outcome != FailoverApplied {
		t.Fatalf("manual failover outcome = %v, want applied", outcome)
	}
	got := snapshotManualFailoverState16016(m)[0]
	if got.state != StateSecondaryHold || !got.manualFailover || got.failoverCount != 4 ||
		got.weight != 255 || got.manualFailoverAt.IsZero() {
		t.Fatalf("in-grace manual failover state = %+v, want secondary-hold/applied with preserved weight", got)
	}
}

func TestManualFailoverRechecksExpiredGraceAfterPreHook16016(t *testing.T) {
	m, clock := manualFailoverManager16016(t, 0)
	before := snapshotManualFailoverState16016(m)
	started, release := blockedManualFailoverHook16016(m)
	defer release()

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	frames := make(chan syncFrame, 1)
	readFramesInto(peer, frames)

	type result struct {
		err error
	}
	resultCh := make(chan result, 1)
	ss.OnRemoteFailover = func(rgID int, _ uint64) error {
		_, err := m.ManualFailover(rgID)
		resultCh <- result{err: err}
		return err
	}
	go ss.handleRemoteFailover(local, 0, 16016)
	waitManualFailoverHook16016(t, started)
	clock.advance(unkeyedAuthorityGrace)
	release()

	select {
	case got := <-resultCh:
		assertUnkeyedAuthorityExpired16016(t, got.err)
	case <-time.After(2 * time.Second):
		t.Fatal("manual failover did not finish after releasing pre-hook")
	}
	select {
	case ack := <-frames:
		if ack.typ != syncMsgFailoverAck || len(ack.payload) < 10 {
			t.Fatalf("failover ack = %+v, want a single-RG failover result", ack)
		}
		if ack.payload[1] == failoverAckApplied {
			t.Fatal("manual failover emitted applied ACK after unkeyed grace expired")
		}
		if ack.payload[1] != failoverAckFailed || string(ack.payload[10:]) != unkeyedAuthorityExpiredReason {
			t.Fatalf("failover ack status/detail = %d/%q, want failed/%q",
				ack.payload[1], string(ack.payload[10:]), unkeyedAuthorityExpiredReason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manual failover did not return a failure ACK")
	}
	assertManualFailoverStateUnchanged16016(t, m, before)
	assertNoManualFailoverEvent16016(t, m)
}

func TestManualFailoverBatchRechecksExpiredGraceAfterPreHook16016(t *testing.T) {
	m, clock := manualFailoverManager16016(t, 0, 1)
	before := snapshotManualFailoverState16016(m)
	started, release := blockedManualFailoverHook16016(m)
	defer release()

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	frames := make(chan syncFrame, 1)
	readFramesInto(peer, frames)

	type result struct {
		batch BatchFailoverResult
		err   error
	}
	resultCh := make(chan result, 1)
	ss.OnRemoteFailoverBatch = func(rgIDs []int, _ uint64) error {
		batch, err := m.ManualFailoverBatch(rgIDs)
		resultCh <- result{batch: batch, err: err}
		return err
	}
	go ss.handleRemoteFailoverBatch(local, []int{0, 1}, 16016)
	waitManualFailoverHook16016(t, started)
	clock.advance(unkeyedAuthorityGrace)
	release()

	select {
	case got := <-resultCh:
		assertUnkeyedAuthorityExpired16016(t, got.err)
		if len(got.batch.Applied) != 0 || len(got.batch.Superseded) != 0 {
			t.Fatalf("batch result after refusal = %+v, want no applied or superseded members", got.batch)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch failover did not finish after releasing pre-hook")
	}
	select {
	case ack := <-frames:
		if ack.typ != syncMsgFailoverBatchAck {
			t.Fatalf("batch ack type = %d, want %d", ack.typ, syncMsgFailoverBatchAck)
		}
		gotIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(ack.payload)
		if err != nil {
			t.Fatalf("decode batch failover ACK: %v", err)
		}
		if len(gotIDs) != 2 || gotIDs[0] != 0 || gotIDs[1] != 1 || reqID != 16016 {
			t.Fatalf("batch ACK ids/request = %v/%d, want [0 1]/16016", gotIDs, reqID)
		}
		if status == failoverAckApplied {
			t.Fatal("batch manual failover emitted applied ACK after unkeyed grace expired")
		}
		if status != failoverAckFailed || detail != unkeyedAuthorityExpiredReason {
			t.Fatalf("batch ACK status/detail = %d/%q, want failed/%q", status, detail, unkeyedAuthorityExpiredReason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch failover did not return a failure ACK")
	}
	assertManualFailoverStateUnchanged16016(t, m, before)
	assertNoManualFailoverEvent16016(t, m)
}
