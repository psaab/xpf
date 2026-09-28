package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/configstore"
)

// #6719 — the management reconciler must not install a STALE auth snapshot when
// a config promotion races daemon startup, and `d.mgmt` must not be a plain
// field write racing its readers.
//
// The two halves are one issue because they are one window. Cluster comms start
// at `daemon_run.go` ~:405 and the HTTP server at ~:596, so for ~190 lines of
// Run the peer-sync apply path is live while `d.mgmt` does not exist yet. In
// that window the pre-fix code could BOTH race the pointer AND drop the
// promotion the peer just made.

// This file deliberately reuses the #5561 management-auth fixtures
// (mgmtAuthIfaceAddrs / mgmtAuthConfigFor / mgmtAuthCommit) rather than growing
// a second way to commit a web-management config. They already bind an
// OFF-LOOPBACK listener, which matters here: the #4047/#5127 runtime clamp pulls
// a credentialed non-loopback bind back to loopback only when there is no
// credential, so a loopback-only fixture resolves Auth to nil and the
// stale-vs-fresh question this test asks cannot even be posed.

// TestStartInstallsTheNewestSnapshotAcrossAPromotion6719 is the binder.
//
// It drives the PRODUCTION entry point `managementReconciler.start` — not
// `startLocked` and not `startTo` — because the defect is in where `start`
// reads the store relative to taking `m.mu`. A guard that called the locked
// helper directly would pin the helper and stay green when the caller
// regressed, which is exactly the shape that must not be shipped here.
//
// Sequence, deterministic by construction rather than by timing:
//
//  1. the store's active config carries api-key AAAA;
//  2. the test takes m.mu, standing in for a reconcile that won the lock;
//  3. start() is launched — post-fix it BLOCKS on the lock before reading the
//     store; pre-fix it had already read AAAA;
//  4. the peer promotion lands: BBBB replaces AAAA in the store;
//  5. the lock is released and start() proceeds.
//
// FAIL-ON-REVERT: move the derive back outside the lock —
// `return m.startTo(ctx, m.desired(m.d.store.ActiveConfig()))` — and start
// installs AAAA, a credential the active config has revoked.
func TestStartInstallsTheNewestSnapshotAcrossAPromotion6719(t *testing.T) {
	const oldSecret, newSecret = "AAAA-old-credential", "BBBB-new-credential"
	mgmtAuthIfaceAddrs(t)

	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	// (1) active config carries the OLD credential.
	mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0", oldSecret))

	d := &Daemon{store: store}
	reg := newFakeReg()
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// (2) hold the lock the way a racing reconcile would.
	m.mu.Lock()

	started := make(chan error, 1)
	go func() { started <- m.start(ctx) }()

	// The goroutine must be blocked on the lock, not past it. There is no
	// happens-before edge to wait on, so give it a real window; if the derive is
	// outside the lock (the pre-fix shape) it has certainly run by now, which is
	// what makes the assertion below discriminating rather than lucky.
	time.Sleep(150 * time.Millisecond)

	// (4) the promotion the peer sync makes: same interface, NEW credential, so
	// the endpoint is unchanged and only the credential distinguishes the two
	// snapshots. Pinning the bind removes "it rebound" as an alternative
	// explanation for the assertion below.
	mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0", newSecret))

	// (5) release and let start finish.
	m.mu.Unlock()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start never returned after the lock was released")
	}

	m.mu.Lock()
	srv := m.srv
	m.mu.Unlock()
	if srv == nil {
		t.Fatal("setup: start must adopt a server")
	}
	live := srv.LiveAuth()
	if live == nil {
		t.Fatal("the started server carries no auth snapshot at all; the promoted config " +
			"configures an api-auth user on an off-loopback bind, so this is not the " +
			"stale-vs-fresh question — the fixture is not reaching resolveAPIBinds")
	}
	if mgmtAuthSecretMatches(t, live, oldSecret) {
		t.Fatalf("the started listener honours the REVOKED credential. start() derived its " +
			"snapshot before taking m.mu, so a promotion that landed while it contended for " +
			"the lock was dropped: the reconcile that carried it found m.srv == nil and " +
			"no-opped, and start then installed the stale snapshot over it. The credential " +
			"stays accepted until some later reconcile or a restart (#6719)")
	}
	if !mgmtAuthSecretMatches(t, live, newSecret) {
		t.Fatalf("the started listener does not honour the newly promoted credential "+
			"(users=%d); the newest snapshot must win", len(live.Users))
	}
}

// TestMgmtPointerIsSafeAgainstConcurrentPublish6719 is the -race half.
//
// `d.mgmt` was a plain field write in startHTTPServer read unguarded by
// reconcileWebManagement, with no happens-before edge between them — and
// `daemon.go` said so outright: "Do not read this as `mgmt is guarded`; it is
// not, and the remaining readers are tracked separately." This is that reader.
//
// The two sides deliberately do NOT run equal iteration counts. The reader
// loops until the writer signals it is done, so the cheap side cannot finish
// inside the expensive side's first pass and report a false green; the observed
// read count is asserted to be non-trivial so a no-op probe is visible as one.
//
// FAIL-ON-REVERT: make `mgmt` a plain `*managementReconciler` field again and
// `go test -race` reports a data race between this reader and the publish.
func TestMgmtPointerIsSafeAgainstConcurrentPublish6719(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	cfg := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0", "RACE-secret"))
	d := &Daemon{store: store}

	// BOTH sides run for the same WALL CLOCK window rather than the same
	// iteration count. Matching the counts is the false-green shape: whichever
	// side is cheaper finishes inside the other's first pass, and the probe
	// reports success having never overlapped. Which side is cheaper here is not
	// even stable — reconcileWebManagement is a fast nil-check while the pointer
	// is unset and real work once it is set — so a duration is the only bound
	// that guarantees contention in both regimes.
	var reads, writes atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	reg := newFakeReg()

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			d.mgmt.Store(newManagementReconciler(d, api.Config{ListenFunc: reg.listen}))
			writes.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = d.reconcileWebManagement(cfg)
			reads.Add(1)
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(done)
	wg.Wait()

	r, w := reads.Load(), writes.Load()
	if r < 50 || w < 50 {
		t.Fatalf("the two sides did not actually contend (%d reads, %d publishes in 300ms), "+
			"so this probe would report a green under -race whatever the publish did", r, w)
	}
	t.Logf("#6719 race probe: %d reconcileWebManagement reads vs %d publishes in 300ms "+
		"(%.2f reads per publish)", r, w, float64(r)/float64(w))
}
