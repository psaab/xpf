package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sync/semaphore"
)

func TestDeferredSnapshotAppliedMarkerWaitsForLanding12235(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{
		applyResult: &dataplane.ApplyResult{SnapshotPublishDeferred: true},
	}
	d, _ := reinjectProductionHarness9637(t, dp)
	d.applySem = semaphore.NewWeighted(1)
	cfg, err := d.store.SyncApply("system { host-name deferred-12235; }", nil)
	if err != nil {
		t.Fatalf("promote config: %v", err)
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	d.applyConfigUnderSem(cfg)
	if d.store.ActiveApplied() {
		d.applySem.Release(1)
		t.Fatal("deferred generation was recorded applied before the helper enforced it")
	}
	generation := dp.lastApply.Generation
	completion := d.deferredSnapshotCompletion(generation)
	if completion == nil {
		d.applySem.Release(1)
		t.Fatalf("deferred generation %d has no pending completion", generation)
	}
	d.applySem.Release(1)

	d.policyInvalidationSnapshotPublished(generation)
	select {
	case err := <-completion:
		if err != nil {
			t.Fatalf("publication completion: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("published deferred generation did not complete its apply")
	}
	if !d.store.ActiveApplied() {
		t.Fatal("helper publication landed but the applied digest remains pending")
	}

}

func TestDeferredSnapshotRefusalSurfacesToHA12235(t *testing.T) {
	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
	cfg, err := d.store.SyncApply("system { host-name refused-deferred-12235; }", nil)
	if err != nil {
		t.Fatalf("promote config: %v", err)
	}
	d.recordDeferredSnapshotApply(cfg, 17)
	completion := d.deferredSnapshotCompletionForConfig(cfg)
	if completion == nil {
		t.Fatal("deferred HA config has no completion channel")
	}
	refusal := errors.New("helper rejected deferred publish")
	d.rejectDeferredSnapshotPublish(17, refusal)
	select {
	case err := <-completion:
		if !errors.Is(err, refusal) {
			t.Fatalf("HA completion error = %v, want refusal %v", err, refusal)
		}
	case <-time.After(time.Second):
		t.Fatal("in-band publish refusal was not surfaced to HA")
	}
	if d.store.ActiveApplied() {
		t.Fatal("refused snapshot must remain pending in commit status")
	}
}
