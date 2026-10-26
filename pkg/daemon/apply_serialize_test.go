// #846: Serialization contract for the apply semaphore.
//
// applyConfig + commitAndApply + commitConfirmedAndApply all share
// d.applySem so that two concurrent callers can never interleave
// across VRF/tunnel/FRR-reload steps and so the commit→apply pair
// is atomic per caller. These tests exercise the public API
// (applyConfig directly; commit*AndApply via context-respecting
// Acquire) and would fail if a future refactor:
//
//   - Removed Acquire from applyConfig (TestApplyConfigSerializes
//     would see >1 concurrent body invocation).
//   - Removed Acquire from commitAndApply / commitConfirmedAndApply,
//     or moved Commit() before Acquire (the held-semaphore test
//     would not see context.DeadlineExceeded).
package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// applyConfig must serialize concurrent callers via d.applySem.
// Uses applyBodyForTest as a seam so the body of applyConfigLocked
// (which would otherwise touch the dataplane / d.routing / d.frr) is replaced
// with a counter that records the maximum concurrent invocations.
func TestApplyConfigSerializes(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	var (
		inFlight int32
		maxSeen  int32
	)
	d.applyBodyForTest = func(_ *config.Config) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			cur := atomic.LoadInt32(&maxSeen)
			if n <= cur || atomic.CompareAndSwapInt32(&maxSeen, cur, n) {
				break
			}
		}
		// Hold long enough that any missing serialization would
		// be visible as inFlight > 1.
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
	}

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			d.applyConfig(nil)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("applyConfig must serialize via applySem; saw %d concurrent body invocations", got)
	}
}

// commitAndApply must Acquire the semaphore BEFORE calling store.Commit.
// #16719 samples the rollback-discard generation before Acquire, so this
// fixture supplies a real Store while the externally held semaphore proves
// neither commit path proceeds to its Commit call before the context expires.
func TestCommitAndApplyRespectsSemaphore(t *testing.T) {
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("setup acquire: %v", err)
	}
	defer d.applySem.Release(1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := d.commitAndApply(ctx, configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("commitAndApply must surface ctx err while semaphore is held; got %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := d.commitConfirmedAndApply(ctx2, configstore.InternalCommitter(), 1, peerSyncNever); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("commitConfirmedAndApply must surface ctx err while semaphore is held; got %v", err)
	}
}
