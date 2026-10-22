package peerclient_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/peerclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #16154: byte-golden pin for the shared reconciliation table, captured
// from the pre-refactor twins (pkg/cli failoverProxyTimeoutMessage and
// pkg/grpcapi failoverProxyTimeoutOutcome, which carried verbatim
// templates). If any template drifts, this test fails with a byte diff,
// and both frontends' 15081 tests would still pass only on fragments —
// so this is the decisive golden check both frontends rely on.
//
// The fixture mirrors the 15081 frontend fixtures: RGs 1 and 2 are the
// data groups; SetPeerGroupStateForTesting also marks the peer alive.

func goldenManager16154(peerPrimary ...int) *cluster.Manager {
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
			{ID: 2, NodePriorities: map[int]int{0: 100, 1: 90}},
		},
	})
	primary := map[int]bool{}
	for _, rg := range peerPrimary {
		primary[rg] = true
	}
	for _, rg := range []int{1, 2} {
		if primary[rg] {
			mgr.SetPeerGroupStateForTesting(rg, cluster.StatePrimary)
		} else {
			mgr.SetPeerGroupStateForTesting(rg, cluster.StateSecondary)
		}
	}
	return mgr
}

// deadPeerManager16154 is a manager with configured groups but no peer
// heartbeat: PeerAlive()==false and PeerPrimaryRGs reports not alive.
func deadPeerManager16154() *cluster.Manager {
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
			{ID: 2, NodePriorities: map[int]int{0: 100, 1: 90}},
		},
	})
	return mgr
}

var deadlineErrs16154 = map[string]error{
	"grpc-deadline":    status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
	"context-deadline": context.DeadlineExceeded,
	"wrapped-context":  fmt.Errorf("proxy leg: %w", context.DeadlineExceeded),
}

func TestReconcileGolden16154(t *testing.T) {
	rgOp := clusterfailover.TargetedRGFailover(1, 1)
	dataOp := clusterfailover.DataFailover(1)

	cases := []struct {
		name string
		view *cluster.Manager
		op   clusterfailover.Op
		err  error
		want string
		ok   bool
	}{
		{
			name: "rg committed after timeout",
			view: goldenManager16154(1),
			op:   rgOp,
			err:  deadlineErrs16154["grpc-deadline"],
			want: "Manual failover completed for redundancy group 1 (transfer committed on node 1; proxy response timed out after the peer committed)",
			ok:   true,
		},
		{
			name: "rg peer reachable but not committed",
			view: goldenManager16154(),
			op:   rgOp,
			err:  deadlineErrs16154["context-deadline"],
			want: "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out; redundancy group 1 is not primary on node 1 — verify ownership before retrying",
			ok:   true,
		},
		{
			name: "rg peer down",
			view: deadPeerManager16154(),
			op:   rgOp,
			err:  deadlineErrs16154["grpc-deadline"],
			want: "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out and the peer is unreachable; verify redundancy group 1 ownership before retrying",
			ok:   true,
		},
		{
			name: "data committed after timeout",
			view: goldenManager16154(1, 2),
			op:   dataOp,
			err:  deadlineErrs16154["grpc-deadline"],
			want: "Manual failover completed for data redundancy groups [1 2] (transfer committed on node 1; proxy response timed out after the peer committed)",
			ok:   true,
		},
		{
			name: "data partially completed",
			view: goldenManager16154(1),
			op:   dataOp,
			err:  deadlineErrs16154["context-deadline"],
			want: "Data failover outcome unknown: forwarded request to node 1 timed out; data redundancy groups now primary on node 1: [1] — verify ownership before retrying",
			ok:   true,
		},
		{
			name: "data peer reachable none moved",
			view: goldenManager16154(),
			op:   dataOp,
			err:  deadlineErrs16154["grpc-deadline"],
			want: "Data failover outcome unknown: forwarded request to node 1 timed out; data redundancy groups now primary on node 1: [] — verify ownership before retrying",
			ok:   true,
		},
		{
			name: "data peer down",
			view: deadPeerManager16154(),
			op:   dataOp,
			err:  deadlineErrs16154["wrapped-context"],
			want: "Data failover outcome unknown: forwarded request to node 1 timed out and the peer is unreachable; verify redundancy group ownership before retrying",
			ok:   true,
		},
		// Gates: anything that is not a deadline outcome on a targeted
		// failover relays the original error (ok=false, empty message).
		{name: "nil error", view: goldenManager16154(1), op: rgOp, err: nil, ok: false},
		{name: "nil view", view: nil, op: rgOp, err: deadlineErrs16154["grpc-deadline"], ok: false},
		{name: "non-deadline error", view: goldenManager16154(1), op: rgOp, err: status.Error(codes.FailedPrecondition, "not ready for takeover"), ok: false},
		{name: "untargeted rg failover", view: goldenManager16154(1), op: clusterfailover.RGFailover(1), err: deadlineErrs16154["grpc-deadline"], ok: false},
		{name: "reset kind", view: goldenManager16154(1), op: clusterfailover.ResetFailover(1), err: deadlineErrs16154["grpc-deadline"], ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var view peerclient.Ownership
			if tc.view != nil {
				view = tc.view
			}
			got, ok := peerclient.Reconcile(view, tc.op, tc.err)
			if ok != tc.ok {
				t.Fatalf("Reconcile() ok = %v, want %v (message %q)", ok, tc.ok, got)
			}
			if got != tc.want {
				t.Fatalf("Reconcile() message byte-drift:\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestTimeoutFor16154(t *testing.T) {
	for _, tc := range []struct {
		action string
		want   int64 // seconds; -1 means "cluster budget"
	}{
		{"cluster-failover:1:node1", -1},
		{"cluster-failover-data:node1", -1},
		{"clear-persistent-nat", 5},
		{"cluster-failover:1", 5},
		{"cluster-failover-reset:1", 5},
		{"reboot", 5},
		{"", 5},
	} {
		got := peerclient.TimeoutFor(tc.action)
		if tc.want == -1 {
			if got != clusterfailover.ProxyFailoverTimeout {
				t.Errorf("TimeoutFor(%q) = %v, want cluster budget %v", tc.action, got, clusterfailover.ProxyFailoverTimeout)
			}
		} else if got.Seconds() != float64(tc.want) {
			t.Errorf("TimeoutFor(%q) = %v, want %ds", tc.action, got, tc.want)
		}
	}
}

func TestIsDeadline16154(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped context deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), true},
		{"grpc deadline", status.Error(codes.DeadlineExceeded, "x"), true},
		{"grpc unavailable", status.Error(codes.Unavailable, "x"), false},
		{"grpc failed precondition", status.Error(codes.FailedPrecondition, "x"), false},
		{"plain error", fmt.Errorf("boom"), false},
		{"context canceled is not deadline", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerclient.IsDeadline(tc.err); got != tc.want {
				t.Errorf("IsDeadline(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
