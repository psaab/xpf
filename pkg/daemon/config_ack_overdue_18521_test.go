package daemon

import (
	"strings"
	"sync"
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
// re-send the SAME text at the SAME wire generation. A new generation would
// make the standby apply again and move its config-epoch barrier, which
// refuses synced session installs stamped with the older epoch (review of
// #18525 / the crash-takeover question).

const stuckGen18521 = uint64(1890891765099)

type resend18521 struct {
	text string
	gen  uint64
}

func stuckUnackedDaemon18521(t *testing.T, debtAge time.Duration) (*Daemon, *cluster.SessionSync, func() int64, func() []resend18521) {
	t.Helper()
	d, pushes := newReconcileDaemon(t, true /*RG0 primary*/, 60*time.Second)
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	d.clusterCommsMu.Lock()
	d.sessionSync = ss
	d.clusterCommsMu.Unlock()
	var mu sync.Mutex
	var resends []resend18521
	d.configResendForTest = func(text string, gen uint64) {
		mu.Lock()
		resends = append(resends, resend18521{text, gen})
		mu.Unlock()
	}
	d.reconcileConfigSyncToPeer("peer-connect")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("fixture: peer-connect push count = %d, want 1", got)
	}
	// What the production push records for the carrying generation.
	_, text, _ := d.activeConfigSnapshotForPeer()
	d.configSyncMu.Lock()
	d.configSyncPushedDigest = text
	d.configSyncPushedWireGen = stuckGen18521
	d.configSyncMu.Unlock()
	ss.SetOverdueConfigApplyDebtForTesting(stuckGen18521, debtAge)
	if stale, reason := ss.PeerConfigStale(); !stale || !strings.Contains(reason, "peer applied 0") {
		t.Fatalf("fixture: gate must be stuck on the unacknowledged push: stale=%v reason=%q", stale, reason)
	}
	return d, ss, pushes.Load, func() []resend18521 {
		mu.Lock()
		defer mu.Unlock()
		return append([]resend18521(nil), resends...)
	}
}

// RED before the fix: the reconcile tick is a no-op forever (the marker is
// claimed) and the gate never clears.
func TestReconcileResendsAnOverdueUnackedConfig18521(t *testing.T) {
	d, ss, pushes, resends := stuckUnackedDaemon18521(t, 2*time.Minute)
	_, text, _ := d.activeConfigSnapshotForPeer()

	d.configSyncReconcileTick()
	got := resends()
	if len(got) != 1 {
		t.Fatalf("an ACK-capable peer left the newest config unacknowledged for 2m and the "+
			"reconcile tick re-sent nothing (resends=%d): nothing else ever will, so the "+
			"stale-config gate refuses failover onto an in-sync standby until the next "+
			"commit (#18521)", len(got))
	}
	if got[0].gen != stuckGen18521 || got[0].text != text {
		t.Fatalf("re-send carried gen=%d (want the original %d) / same text=%v: a NEW generation "+
			"makes the standby re-apply and moves its config-epoch barrier",
			got[0].gen, stuckGen18521, got[0].text == text)
	}
	if p := pushes(); p != 1 {
		t.Fatalf("the overdue path ran a fresh reconcile push (pushes=%d); it must re-send, not re-push", p)
	}
	// The standby answers with an ACK; the gate clears and nothing more is sent.
	ss.AckConfigApplyForTesting(stuckGen18521)
	if stale, reason := ss.PeerConfigStale(); stale {
		t.Fatalf("gate still stale after the ACK: %s", reason)
	}
	d.configSyncReconcileTick()
	if n, p := len(resends()), pushes(); n != 1 || p != 1 {
		t.Fatalf("an acknowledged config was sent again (resends=%d pushes=%d)", n, p)
	}
}

// The failover refusal itself kicks the re-send, so the operator's next
// attempt can pass without waiting for the 30s reconcile tick.
func TestStaleGateRefusalKicksTheResend18521(t *testing.T) {
	d, _, _, resends := stuckUnackedDaemon18521(t, 2*time.Minute)
	if stale, _ := d.peerConfigStale(); !stale {
		t.Fatal("fixture: the gate must refuse")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(resends()) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(resends()); n != 1 {
		t.Fatalf("a refusal on an overdue ACK did not re-send (resends=%d)", n)
	}
}

// Bounds.
func TestOverdueResendIsBounded18521(t *testing.T) {
	t.Run("young debt", func(t *testing.T) {
		d, _, _, resends := stuckUnackedDaemon18521(t, configAckOverdueAfter/2)
		d.configSyncReconcileTick()
		if n := len(resends()); n != 0 {
			t.Fatalf("a debt younger than the overdue bound was re-sent (%d)", n)
		}
	})
	t.Run("rate limit", func(t *testing.T) {
		d, _, _, resends := stuckUnackedDaemon18521(t, 2*time.Minute)
		if !d.repushIfConfigAckOverdue("test") {
			t.Fatal("first overdue re-send did not run")
		}
		if d.repushIfConfigAckOverdue("test") {
			t.Fatal("a second re-send ran inside the spacing bound")
		}
		if n := len(resends()); n != 1 {
			t.Fatalf("resends = %d, want 1", n)
		}
	})
	t.Run("not the RG0 authority", func(t *testing.T) {
		d, _, _, resends := stuckUnackedDaemon18521(t, 2*time.Minute)
		d.cluster = newClusterManager(false)
		if d.repushIfConfigAckOverdue("test") || len(resends()) != 0 {
			t.Fatal("a non-authority re-sent config")
		}
	})
	t.Run("debt is not the recorded push", func(t *testing.T) {
		d, ss, _, resends := stuckUnackedDaemon18521(t, 2*time.Minute)
		ss.SetOverdueConfigApplyDebtForTesting(stuckGen18521+1, 2*time.Minute)
		if d.repushIfConfigAckOverdue("test") || len(resends()) != 0 {
			t.Fatal("re-sent a recorded push for a different generation than the one owed")
		}
	})
	t.Run("config moved on", func(t *testing.T) {
		d, _, _, resends := stuckUnackedDaemon18521(t, 2*time.Minute)
		commitHostName(t, d.store, "recon-host-2")
		if d.repushIfConfigAckOverdue("test") || len(resends()) != 0 {
			t.Fatal("re-sent a pushed config the active config has replaced; the ordinary reconcile owns it")
		}
	})
}
