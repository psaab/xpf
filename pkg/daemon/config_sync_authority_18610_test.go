package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #18610: the daemon's RG0-primary refusal must be the cluster sentinel, or
// configApplyLoop treats it as a failed apply: it arms CF on the primary and
// leaves the primary reading "standby config stale", which blocks a rolling
// upgrade started there. RED if errConfigSyncRejectedPrimary goes back to a
// daemon-local errors.New.
func TestRG0PrimaryRefusalIsTheClusterAuthoritySentinel18610(t *testing.T) {
	if !errors.Is(errConfigSyncRejectedPrimary, cluster.ErrConfigSyncRejectedAuthority) {
		t.Fatal("errConfigSyncRejectedPrimary is not cluster.ErrConfigSyncRejectedAuthority")
	}
}

// #18610 seat U: the refusal Warn says whether the refused config differs from
// the active one, and only then that the peer's version is discarded. RED if
// the divergence check is dropped or inverted.
func TestRG0PrimaryRefusalLogSaysWhetherPeerConfigIsDiscarded18610(t *testing.T) {
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	if _, err := d.store.SyncApply("system { host-name authority-18610; }", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	active := d.store.ShowActive()

	logs, restore := captureSlog(t)
	d.logConfigSyncRefusedAsAuthority(active + "\n")
	restore()
	if out := logs.String(); !strings.Contains(out, "differs_from_active=false") ||
		strings.Contains(out, "discarded") || !strings.Contains(out, "gen=0") {
		t.Fatalf("identical refused config must log differs_from_active=false and no discard notice: %q", out)
	}

	logs, restore = captureSlog(t)
	d.logConfigSyncRefusedAsAuthority("system { host-name peer-commit-18610; }")
	restore()
	if out := logs.String(); !strings.Contains(out, "differs_from_active=true") ||
		!strings.Contains(out, "discarded") {
		t.Fatalf("a different refused config must say the peer's config is discarded: %q", out)
	}
}

// waitPushes18610 polls the reconcile push counter: the re-push after an
// authority refusal is asynchronous.
func waitPushes18610(pushes func() int64, want int64) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pushes() >= want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return pushes() >= want
}

// Review T2: refusing a peer's push as RG0 authority re-pushes this node's
// config once, through the ordinary reconcile (a NEW wire generation in
// production), not the same-generation resend. The (epoch x generation)
// marker had already been claimed by the earlier push on this connection, so
// before the fix nothing ever sent it again and the loser stayed divergent
// with its own #9569 debt. RED if the refusal stops clearing the marker.
func TestAuthorityRefusalRepushesOnce18610(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*RG0 primary*/, 60*time.Second)
	var resends atomic.Int64
	d.configResendForTest = func(string, uint64) { resends.Add(1) }
	d.reconcileConfigSyncToPeer("peer-connect")
	d.reconcileConfigSyncToPeer("reconcile-loop")
	if got := pushes.Load(); got != 1 {
		t.Fatalf("fixture: peer-connect push count = %d, want 1 (marker claimed)", got)
	}

	if err := d.handleConfigSync("system { host-name loser-18610; }"); !errors.Is(err, cluster.ErrConfigSyncRejectedAuthority) {
		t.Fatalf("premise: the RG0 primary must refuse the peer's push, got %v", err)
	}
	if !waitPushes18610(pushes.Load, 2) {
		t.Fatalf("the authority did not re-push its config after refusing the peer's (pushes=%d)", pushes.Load())
	}
	for i := 0; i < 5; i++ {
		d.reconcileConfigSyncToPeer("reconcile-loop")
	}
	time.Sleep(20 * time.Millisecond)
	if got := pushes.Load(); got != 2 {
		t.Fatalf("one refusal must re-push exactly once; got %d pushes", got)
	}
	if got := resends.Load(); got != 0 {
		t.Fatalf("the re-push used the same-generation resend (%d); the loser's duplicate path would not supersede its debt", got)
	}
}

// Review T2: a peer that keeps pushing (and so keeps being refused) cannot
// drive a push loop. The refusal-driven re-push is paced at
// configAckOverdueAfter, like the overdue-ACK re-push. RED if the pacing is
// removed: every refusal would clear the marker and push again.
func TestRepeatedAuthorityRefusalDoesNotStorm18610(t *testing.T) {
	d, pushes := newReconcileDaemon(t, true /*RG0 primary*/, 60*time.Second)
	d.reconcileConfigSyncToPeer("peer-connect")
	_ = d.handleConfigSync("system { host-name loser-18610; }")
	if !waitPushes18610(pushes.Load, 2) {
		t.Fatalf("fixture: the first refusal must re-push (pushes=%d)", pushes.Load())
	}
	for i := 0; i < 20; i++ {
		_ = d.handleConfigSync("system { host-name loser-18610; }")
	}
	time.Sleep(100 * time.Millisecond)
	if got := pushes.Load(); got != 2 {
		t.Fatalf("20 refusals inside the pacing window pushed %d times, want the one re-push (2 total)", got)
	}
	// Once the window has elapsed, the next refusal may re-push again.
	d.configAuthorityRepushAtMono.Store(cluster.MonotonicNanos() - int64(configAckOverdueAfter) - int64(time.Second))
	_ = d.handleConfigSync("system { host-name loser-18610; }")
	if !waitPushes18610(pushes.Load, 3) {
		t.Fatalf("a refusal after the pacing window must re-push again (pushes=%d)", pushes.Load())
	}
}
