package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #18521, live on loss: after fw0's VM restart, fw1 (RG0 primary) refused
// every failover onto fw0 with "the standby has not acknowledged applying
// config generation G (peer applied 0)" — G being exactly the generation fw0
// had received and skipped as "already matches active and is applied". The
// ACK fw0 owed was never credited on fw1, and nothing re-pushed: the
// reconcile marker for (epoch, generation) was already claimed, a NACK never
// came, and the config was in sync so no commit followed. Stuck until a
// commit.
//
// The cells below start from that stuck state — marker claimed by the
// peer-connect push, debt unacknowledged — and require the authority to
// re-push on its own.

func stuckUnackedDaemon18521(t *testing.T, debtAge time.Duration) (*Daemon, *cluster.SessionSync, func() int64) {
	t.Helper()
	d, pushes := newReconcileDaemon(t, true /*RG0 primary*/, 60*time.Second)
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	d.clusterCommsMu.Lock()
	d.sessionSync = ss
	d.clusterCommsMu.Unlock()
	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("fixture: peer-connect push count = %d, want 1", got)
	}
	ss.SetOverdueConfigApplyDebtForTesting(1890891765099, debtAge)
	if stale, reason := ss.PeerConfigStale(); !stale || !strings.Contains(reason, "peer applied 0") {
		t.Fatalf("fixture: gate must be stuck on the unacknowledged push: stale=%v reason=%q", stale, reason)
	}
	return d, ss, pushes.Load
}

// RED before the fix: the reconcile tick is a no-op forever (the marker is
// claimed) and the gate never clears.
func TestReconcileRepushesAnOverdueUnackedConfig18521(t *testing.T) {
	d, ss, pushes := stuckUnackedDaemon18521(t, 2*time.Minute)

	d.configSyncReconcileTick()
	if got := pushes(); got != 2 {
		t.Fatalf("an ACK-capable peer left the newest config unacknowledged for 2m and the "+
			"reconcile tick did not re-push (pushes=%d): nothing else ever will, so the "+
			"stale-config gate refuses failover onto an in-sync standby until the next "+
			"commit (#18521)", got)
	}
	// The standby answers the re-push with an ACK; the gate clears.
	ss.AckConfigApplyForTesting(1890891765099)
	if stale, reason := ss.PeerConfigStale(); stale {
		t.Fatalf("gate still stale after the ACK: %s", reason)
	}
	d.configSyncReconcileTick()
	if got := pushes(); got != 2 {
		t.Fatalf("an acknowledged config was re-pushed again (pushes=%d)", got)
	}
}

// The failover refusal itself kicks the re-push, so the operator's next
// attempt can pass without waiting for the 30s reconcile tick.
func TestStaleGateRefusalKicksTheRepush18521(t *testing.T) {
	d, _, pushes := stuckUnackedDaemon18521(t, 2*time.Minute)
	if stale, _ := d.peerConfigStale(); !stale {
		t.Fatal("fixture: the gate must refuse")
	}
	deadline := time.Now().Add(5 * time.Second)
	for pushes() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := pushes(); got != 2 {
		t.Fatalf("a refusal on an overdue ACK did not re-push (pushes=%d)", got)
	}
}

// Bounds: a debt younger than configAckOverdueAfter is not re-pushed (a
// deferred publication may still be in flight), and re-pushes are spaced by
// configAckOverdueAfter even while the ACK stays missing.
func TestOverdueRepushIsBounded18521(t *testing.T) {
	t.Run("young debt", func(t *testing.T) {
		d, _, pushes := stuckUnackedDaemon18521(t, configAckOverdueAfter/2)
		d.configSyncReconcileTick()
		if got := pushes(); got != 1 {
			t.Fatalf("a debt younger than the overdue bound was re-pushed (pushes=%d)", got)
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		d, ss, pushes := stuckUnackedDaemon18521(t, 2*time.Minute)
		if !d.repushIfConfigAckOverdue("test") {
			t.Fatal("first overdue re-push did not run")
		}
		ss.SetOverdueConfigApplyDebtForTesting(1890891765100, 2*time.Minute)
		if d.repushIfConfigAckOverdue("test") {
			t.Fatal("a second re-push ran inside the spacing bound")
		}
		if got := pushes(); got != 2 {
			t.Fatalf("pushes = %d, want 2", got)
		}
	})
	t.Run("not the RG0 authority", func(t *testing.T) {
		d, _, pushes := stuckUnackedDaemon18521(t, 2*time.Minute)
		d.cluster = newClusterManager(false)
		if d.repushIfConfigAckOverdue("test") {
			t.Fatal("a non-authority re-pushed config")
		}
		if got := pushes(); got != 1 {
			t.Fatalf("pushes = %d, want 1", got)
		}
	})
}
