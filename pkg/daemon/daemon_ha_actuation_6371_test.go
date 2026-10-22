package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// actuationReqID is the peer request id these tests transfer RG1 under. The
// barrier is keyed by (RG, request), so arm and wait must name the same one
// (#6177).
const actuationReqID uint64 = 42

// errRGActiveRejected models the dataplane refusing an rg_active write — the
// helper is down, the control socket errored, the RG is unknown.
var errRGActiveRejected = errors.New("helper rejected rg_active write")

// actuationHA is an HAController whose SetRGActive verdict the test controls,
// and which records what it was asked to write.
type actuationHA struct {
	mu     sync.Mutex
	err    error
	writes []bool // `active` argument of every SetRGActive call
}

func (h *actuationHA) SetRGActive(_ context.Context, _ int, active bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writes = append(h.writes, active)
	return h.err
}

func (h *actuationHA) SetHAWatchdog(_ context.Context, _ int, _ uint64) error { return nil }

func (h *actuationHA) SetFabricForwarding(_ context.Context, _ dataplane.FabricID, _ dataplane.FabricFwdInfo) error {
	return nil
}

func (h *actuationHA) SyncFabricState(_ context.Context) error { return nil }

func (h *actuationHA) writeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.writes)
}

func (h *actuationHA) lastWrite() (bool, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.writes) == 0 {
		return false, false
	}
	return h.writes[len(h.writes)-1], true
}

// actuationDP is a RuntimeDataPlane whose only live surface is HA(). The nil
// embed panics if the demotion path reaches for anything else, which keeps the
// fake honest.
type actuationDP struct {
	dataplane.RuntimeDataPlane
	ha *actuationHA
}

func (d *actuationDP) HA() dataplane.HAController { return d.ha }

// Mode makes userspaceDataplaneActive() true so the demotion path takes the
// userspace early-return in injectBlackholeRoutes instead of issuing netlink
// route writes — this test is about the fence verdict, not blackholes.
func (d *actuationDP) Mode() dpuserspace.DataplaneMode { return dpuserspace.ModeUserspaceStrict }

// newActuationDaemon builds the minimum Daemon that can run
// handleClusterEvent's demotion branch: a committed cluster config, a cluster
// manager holding RG1, a VRRP manager (unused on the default private-RG-election
// path but present so the RETH-VRRP branch could not nil-panic), and the
// caller's HA fake published as the dataplane.
//
// Note the config takes the PRODUCTION default: `private-rg-election` is on
// unless `no-private-rg-election` is set, so isNoRethVRRP() is TRUE here and the
// demotion runs the direct-VIP-ownership path the loss userspace cluster runs.
// The fence-barrier release under test is shared by both branches.
func newActuationDaemon(t *testing.T, ha *actuationHA) *Daemon {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		},
	})
	d := &Daemon{
		store:                      fenceTestStore(t, fenceStartupClusterSet),
		cluster:                    cm,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	d.setDataplane(&actuationDP{ha: ha})
	return d
}

// primeRG1Primary establishes the pre-demotion posture. UpdateConfig elects a
// solo node primary for every RG, so this drains those promotion events and
// tells the daemon's rgStateMachine about the one for RG1 — which makes the
// demotion below a real rg_active transition (tr.Changed, cur == false) rather
// than a no-op edge.
func primeRG1Primary(t *testing.T, d *Daemon) {
	t.Helper()
	for drained := true; drained; {
		select {
		case <-d.cluster.Events():
		default:
			drained = false
		}
	}
	if !d.cluster.IsLocalPrimary(1) {
		t.Fatal("setup: RG1 must be cluster-primary before the demotion edge")
	}
	if tr := d.getOrCreateRGState(1).SetCluster(true); !tr.Active {
		t.Fatal("setup: RG1 must be desired-active before the demotion edge")
	}
}

// demoteRG1 runs the production transfer-out sequence for RG1: cluster
// ManualFailover (what the daemon's OnRemoteFailover closure calls once the
// barrier is armed), then the demotion event the manager ACTUALLY emitted is
// handed to handleClusterEvent — the same value watchClusterEvents would read
// off Events(). The returned debounce timer is stopped so no background VRRP
// update fires after the test returns.
func demoteRG1(t *testing.T, d *Daemon) {
	t.Helper()
	if _, err := d.cluster.ManualFailover(1); err != nil {
		t.Fatalf("ManualFailover(1): %v", err)
	}
	var ev cluster.ClusterEvent
	select {
	case ev = <-d.cluster.Events():
	case <-time.After(2 * time.Second):
		t.Fatal("cluster manager emitted no demotion event")
	}
	if ev.GroupID != 1 || ev.OldState != cluster.StatePrimary || ev.NewState == cluster.StatePrimary {
		t.Fatalf("unexpected cluster event %+v, want a RG1 primary -> non-primary edge", ev)
	}
	if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
		timer.Stop()
	}
}

// TestFailoverActuation_FailedRGActiveClearDoesNotAck is the #6371 regression
// guard. On a peer-requested transfer-out, handleClusterEvent clears rg_active
// and then releases the fence barrier that gates the applied-ack. When the
// dataplane REJECTS that clear, this node may still be forwarding for the RG —
// reporting the fence as actuated tells the peer to promote into a two-owner
// window.
//
// Fail-on-revert: restore the unconditional `d.signalFailoverActuated(...)` at
// the end of the demotion branch and waitFailoverActuated returns nil here,
// failing RED on a clean assertion.
func TestFailoverActuation_FailedRGActiveClearDoesNotAck(t *testing.T) {
	ha := &actuationHA{err: errRGActiveRejected}
	d := newActuationDaemon(t, ha)
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)

	// Positive control: the demotion really reached the rg_active write with
	// the clearing value, so the assertion below is not vacuous.
	if got := ha.writeCount(); got != 1 {
		t.Fatalf("SetRGActive call count = %d, want 1 (demotion must attempt the clear)", got)
	}
	if active, ok := ha.lastWrite(); !ok || active {
		t.Fatalf("SetRGActive wrote active=%v, want false (a demotion clears rg_active)", active)
	}

	err := d.waitFailoverActuated(1, actuationReqID)
	if err == nil {
		t.Fatal("waitFailoverActuated returned nil after a FAILED rg_active clear: " +
			"the applied-ack would tell the peer to promote while this node may still forward (#6371)")
	}
	if !errors.Is(err, errRGActiveRejected) {
		t.Fatalf("fence verdict = %v, want it to carry the dataplane rejection", err)
	}
	// The verdict must arrive from the resolved barrier, not from the wait
	// timeout — a timeout would delay the peer's failover by the full window.
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fence verdict = %v, want an immediate failure not a timeout", err)
	}
}

// TestFailoverActuation_SucceededRGActiveClearAcks is the negative control: an
// accepted rg_active clear must still report the fence as actuated, so the fix
// does not simply refuse every ack (which would break every planned failover).
func TestFailoverActuation_SucceededRGActiveClearAcks(t *testing.T) {
	ha := &actuationHA{}
	d := newActuationDaemon(t, ha)
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)

	if got := ha.writeCount(); got != 1 {
		t.Fatalf("SetRGActive call count = %d, want 1", got)
	}
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("waitFailoverActuated = %v, want nil after a successful clear", err)
	}
}

// TestFailoverActuation_ParkedWaiterSeesFailure covers the other resolution
// ordering: the applied-ack waiter is already blocked on the barrier when the
// demotion fails. It must observe the same failure verdict rather than waking
// as if the fence had completed.
func TestFailoverActuation_ParkedWaiterSeesFailure(t *testing.T) {
	ha := &actuationHA{err: errRGActiveRejected}
	d := newActuationDaemon(t, ha)
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	errCh := make(chan error, 1)
	go func() { errCh <- d.waitFailoverActuated(1, actuationReqID) }()
	// Give the waiter time to park on the barrier. The assertion holds for
	// either ordering — a waiter that has not parked yet takes the
	// consume-after-resolution path and reads the same verdict.
	time.Sleep(20 * time.Millisecond)

	demoteRG1(t, d)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("parked waiter woke with nil after a FAILED rg_active clear (#6371)")
		}
		if !errors.Is(err, errRGActiveRejected) {
			t.Fatalf("fence verdict = %v, want it to carry the dataplane rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parked waiter never woke — the barrier must be resolved on failure, not left hanging")
	}
}

// TestFailoverActuation_UnarmedRGIsNoop pins the RESOLVE-side contract for RGs
// that never armed a barrier: every ordinary local demotion resolves an RG with
// no barrier, and that must stay a no-op rather than panicking or blocking.
//
// #9259 SPLIT THIS CELL, and the split is the point. Its rationale used to read
// "resolving is a no-op AND a wait returns immediately with no error", as if the
// second followed from the first. It does not, and they are different subjects:
// "every ordinary demotion" is true of RESOLVING and false of WAITING — an
// ordinary local demotion never calls waitFailoverActuated at all. The wait-side
// half was #9036's final link (absence of a barrier read as proof of fencing)
// and is now pinned, inverted, by the sibling below.
func TestFailoverActuation_UnarmedRGIsNoop(t *testing.T) {
	ha := &actuationHA{err: errRGActiveRejected}
	d := newActuationDaemon(t, ha)
	primeRG1Primary(t, d)

	// No armFailoverActuation: this is an ordinary local demotion. It must not
	// panic, block, or disturb anything — that is the whole assertion.
	demoteRG1(t, d)

	if n := d.failoverActuations.armedCount(); n != 0 {
		t.Fatalf("resolving an unarmed RG created %d barrier(s); it must be a no-op", n)
	}
}

// #9259: the wait-side half, inverted. Absence of a barrier is NOT evidence
// that this node fenced, and sync_failover.go sends failoverAckApplied exactly
// when this returns nil — so a nil here promoted the peer on no evidence.
func TestFailoverActuation_UnarmedWaitIsNotProofOfFence9259(t *testing.T) {
	ha := &actuationHA{err: errRGActiveRejected}
	d := newActuationDaemon(t, ha)
	primeRG1Primary(t, d)
	demoteRG1(t, d)

	err := d.waitFailoverActuated(1, actuationReqID)
	if err == nil {
		t.Fatal("#9259: waitFailoverActuated returned nil for a request that never " +
			"armed a barrier. sync_failover.go sends failoverAckApplied exactly when " +
			"this returns nil, so the peer promotes on no evidence that this node " +
			"fenced — #5640's invariant, reached by a route PR #9247 did not close.")
	}
	if !errors.Is(err, ErrFailoverNeverArmed) {
		t.Errorf("#9259: verdict = %v, want ErrFailoverNeverArmed. The reason must "+
			"name WHICH route it took; 'never armed' and 'verdict already consumed' "+
			"send an operator to different places.", err)
	}
}
