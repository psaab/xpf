package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

func TestPeerSyncPromotionWaitsForSnapshotSerializer10782(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	before := "system {\n    host-name serializer-before;\n}\n"
	after := "system {\n    host-name serializer-after;\n}\n"
	if _, err := store.SyncApply(before, nil); err != nil {
		t.Fatalf("SyncApply initial config: %v", err)
	}
	d := &Daemon{
		applySem:         semaphore.NewWeighted(1),
		store:            store,
		applyBodyForTest: func(*config.Config) {},
	}

	d.pendingRenameMu.Lock()
	locked := true
	defer func() {
		if locked {
			d.pendingRenameMu.Unlock()
		}
	}()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := d.syncAndApply(t.Context(), after, nil)
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("peer SyncApply promoted while the active-snapshot serializer was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if got := store.ActiveConfig().System.HostName; got != "serializer-before" {
		t.Fatalf("peer promotion bypassed pendingRenameMu while snapshot capture held it: active=%q", got)
	}

	d.pendingRenameMu.Unlock()
	locked = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("syncAndApply after serializer release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer sync did not resume after the snapshot serializer was released")
	}
	if got := store.ActiveConfig().System.HostName; got != "serializer-after" {
		t.Fatalf("peer promotion did not complete after serializer release: active=%q", got)
	}
}
