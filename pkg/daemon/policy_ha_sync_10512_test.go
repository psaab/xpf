package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// P2 HA-observed: the helper policy path queues a scoped delete per
// attempted match (domain+key+expectedID) when primary, so the standby
// retires what the owner retired and failover cannot resurrect.

func TestPolicyHelperPathQueuesHAScopedDeletes10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	d.cluster = clusterManagerPrimaryForRGs(1)
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	fwd, rev := collisionMatches10512(11, 12)
	fake := newCollisionDP10512(fwd, rev)
	d.setDataplane(fake)

	v4 := fwd[0]
	v6 := fwd[2]
	key4, _, err := policyTupleV4(v4.Tuple)
	if err != nil {
		t.Fatalf("FIXTURE: v4 tuple must parse: %v", err)
	}
	key6, _, err := policyTupleV6(v6.Tuple)
	if err != nil {
		t.Fatalf("FIXTURE: v6 tuple must parse: %v", err)
	}
	c := capturedSessions{
		targets: 1,
		policy:  []dpuserspace.SessionPolicyMatch{v4, v6},
	}
	if err := d.deleteInvalidatedSessions(c, dataplane.DeleteReasonPolicyDeleted, "deleted"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	domain, id, ok := ss.ScopedDeleteJournalEntryForTesting(key4)
	if !ok || domain != v4.RoutingDomain || id != v4.ExpectedRTFlowSessionID {
		t.Fatalf("v4 HA scoped = (%d, %#x, %v), want (%d, %#x, true)",
			domain, id, ok, v4.RoutingDomain, v4.ExpectedRTFlowSessionID)
	}
	domain6, id6, ok := ss.ScopedDeleteJournalEntryV6ForTesting(key6)
	if !ok || domain6 != v6.RoutingDomain || id6 != v6.ExpectedRTFlowSessionID {
		t.Fatalf("v6 HA scoped = (%d, %#x, %v), want (%d, %#x, true)",
			domain6, id6, ok, v6.RoutingDomain, v6.ExpectedRTFlowSessionID)
	}
}

func TestPolicyHelperPathSilentOnStandby10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	d.cluster = clusterManagerPrimaryForRGs()
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	fwd, rev := collisionMatches10512(11, 12)
	fake := newCollisionDP10512(fwd, rev)
	d.setDataplane(fake)

	v4 := fwd[0]
	key4, _, err := policyTupleV4(v4.Tuple)
	if err != nil {
		t.Fatalf("FIXTURE: v4 tuple must parse: %v", err)
	}
	c := capturedSessions{
		targets: 1,
		policy:  []dpuserspace.SessionPolicyMatch{v4},
	}
	if err := d.deleteInvalidatedSessions(c, dataplane.DeleteReasonPolicyDeleted, "deleted"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, _, ok := ss.ScopedDeleteJournalEntryForTesting(key4); ok {
		t.Fatal("standby must not queue HA deletes (not primary)")
	}
}
