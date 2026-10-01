package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"
)

func routeListenerBumpDaemon11565(t *testing.T, dp *fakeOverlayDP) *Daemon {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := store.SyncApply("system { host-name route-listener-11565; }", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
	d.setDataplane(dp)
	return d
}

func requireRouteListenerCalls11565(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}

func TestRouteListenerBumpsAfterLearnedRoutePublish11565(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := routeListenerBumpDaemon11565(t, dp)

	if !d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("successful publish and FIB bump did not converge")
	}
	requireRouteListenerCalls11565(t, dp.calls, "publish", "bump")
	if d.pendingFIBBump {
		t.Fatal("pendingFIBBump remains set after a confirmed FIB bump")
	}
}

func TestRouteListenerRetriesPendingBumpAfterDuplicatePublish11565(t *testing.T) {
	dp := &fakeOverlayDP{publishErr: errors.New("snapshot unavailable")}
	d := routeListenerBumpDaemon11565(t, dp)

	if d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("failed publish reported convergence")
	}
	requireRouteListenerCalls11565(t, dp.calls, "publish")
	if d.pendingFIBBump {
		t.Fatal("failed publish created a pending FIB bump")
	}

	// A real publication whose invalidation fails must leave the listener dirty.
	dp.publishErr = nil
	dp.bumpErr = errors.New("generation control unavailable")
	if d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("failed FIB bump reported convergence")
	}
	requireRouteListenerCalls11565(t, dp.calls, "publish", "publish", "bump")
	if !d.pendingFIBBump {
		t.Fatal("pendingFIBBump not set after a published overlay's bump failed")
	}

	// A later publish failure cannot discard the unconfirmed bump obligation.
	dp.publishErr = errors.New("snapshot unavailable")
	if d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("failed retry publish reported convergence")
	}
	requireRouteListenerCalls11565(t, dp.calls, "publish", "publish", "bump", "publish")
	if !d.pendingFIBBump {
		t.Fatal("pendingFIBBump lost across a failed retry publish")
	}

	// Once publish resumes, a duplicate-skip still retries the pending bump.
	dp.publishErr = nil
	dp.publishSkipped = true
	if d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("failed duplicate-skip bump reported convergence")
	}
	requireRouteListenerCalls11565(t, dp.calls,
		"publish", "publish", "bump", "publish", "publish", "bump")
	if !d.pendingFIBBump {
		t.Fatal("pendingFIBBump cleared while the retried bump still failed")
	}

	dp.bumpErr = nil
	if !d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("successful duplicate-skip bump did not converge")
	}
	requireRouteListenerCalls11565(t, dp.calls,
		"publish", "publish", "bump", "publish", "publish", "bump", "publish", "bump")
	if d.pendingFIBBump {
		t.Fatal("pendingFIBBump remains set after the retry succeeded")
	}

	// With no outstanding retry, an unchanged duplicate must not churn caches.
	if !d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("confirmed duplicate-skip did not converge")
	}
	requireRouteListenerCalls11565(t, dp.calls,
		"publish", "publish", "bump", "publish", "publish", "bump", "publish", "bump", "publish")
}
