package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// cluster_comms_hooks_bound_7280_test.go — #7280.
//
// #6428 decomposed `Daemon.startClusterComms` and measured that most of its
// wiring was bound by NOTHING: 0.0% statement coverage for every builder
// running inside the constructor goroutine, and nilling all thirty wiring
// assignments at once left `pkg/daemon` and `pkg/cluster` fully green. It then
// bound the seventeen sites that were already observable. This file is the
// rest — the ones that needed an observation seam on `cluster.Manager`, which
// #7280 added (`InstalledHooks`, `RemoteTransferOutLease`, `HasAuthProvider`).
//
// The hooks are cluster failover, fencing and sync-transport selection. A
// silently dropped assignment there is not a cosmetic defect.
//
// THE TRAP THIS SHAPE ALREADY FELL INTO ONCE. #6428's first draft collected
// the func fields into a table of `any` and compared each against nil. FOURTEEN
// OF SEVENTEEN MUTATIONS STAYED GREEN, because boxing a typed nil into an
// interface yields a non-nil interface. That is why `InstalledHooks` does the
// `!= nil` comparisons inside `pkg/cluster` against the concrete typed fields
// and returns only bools: a caller here never touches a func value, so the
// boxing bug cannot be reintroduced from this side.
//
// COUNT NOTE. The #7280 baseline predates the #11566 never-seen sync-freshness
// hook. Keep every currently reported hook in the explicit list below.

// A fresh manager must report every hook UNINSTALLED.
//
// Without this the whole file is vacuous in the safe-looking direction: an
// `InstalledHooks` that returned true unconditionally — or a map built only
// from installed hooks, where a missing key reads as false only by accident —
// would satisfy every positive assertion below. This is the cell that proves
// the instrument can say "no".
func TestInstalledHooksReportsFalseBeforeWiring_7280(t *testing.T) {
	m := newClusterManager(true)
	got := m.InstalledHooks()

	if len(got) == 0 {
		t.Fatal("InstalledHooks returned an empty map; every assertion in this " +
			"file would then be reading a missing key, and a clean result would " +
			"certify nothing")
	}
	for name, installed := range got {
		if installed {
			t.Errorf("a freshly constructed Manager reports %s already installed; "+
				"the seam cannot distinguish wired from unwired", name)
		}
	}
}

// Every hook name the daemon wires must be a key InstalledHooks reports.
//
// A `_, ok :=` lookup of a renamed hook would silently skip its row and the
// suite would stay green with the hook unbound — the exact invisibility this
// issue exists to remove.
func TestEveryWiredHookHasAReportedKey_7280(t *testing.T) {
	got := newClusterManager(true).InstalledHooks()
	for _, name := range allWiredHooks7280() {
		if _, ok := got[name]; !ok {
			t.Errorf("InstalledHooks does not report %q. A hook that is not "+
				"reported cannot be bound, and a lookup for it here would read "+
				"as 'not installed' rather than as a missing key", name)
		}
	}
	if len(got) != len(allWiredHooks7280()) {
		t.Errorf("InstalledHooks reports %d hooks but this test knows %d. If a "+
			"hook was added, bind it below; if one was removed, drop it from "+
			"allWiredHooks7280 — an unreconciled count means a hook is wired "+
			"with nothing checking it", len(got), len(allWiredHooks7280()))
	}
}

func allWiredHooks7280() []string {
	return []string{
		cluster.HookPeerFailover,
		cluster.HookPeerFailoverCommit,
		cluster.HookPeerFailoverBatch,
		cluster.HookPeerFailoverCommitBatch,
		cluster.HookPreManualFailover,
		cluster.HookLocalTransferCommitRdy,
		cluster.HookTransferReadiness,
		cluster.HookPeerTimeoutGuard,
		cluster.HookPeerNeverSeenSyncFresh,
		cluster.HookPeerHeartbeatRecovered,
		cluster.HookHeartbeatRestartNotify,
		cluster.HookPeerFence,
		cluster.HookPeerFenceConfirm,
	}
}

// Manager hooks installed by wireClusterPeerFailoverHooks, plus the
// lease duration it computes.
func TestWireClusterPeerFailoverHooksInstallsManagerHooks_7280(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireClusterPeerFailoverHooks(ss)

	got := d.cluster.InstalledHooks()
	// Named individually rather than looped, so a failure says WHICH hook was
	// dropped without the reader decoding an index.
	for _, name := range []string{
		cluster.HookPeerFailover,
		cluster.HookPeerFailoverCommit,
		cluster.HookPeerFailoverBatch,
		cluster.HookPeerFailoverCommitBatch,
		cluster.HookPreManualFailover,
		cluster.HookLocalTransferCommitRdy,
		cluster.HookTransferReadiness,
		cluster.HookPeerTimeoutGuard,
		cluster.HookPeerNeverSeenSyncFresh,
		cluster.HookPeerHeartbeatRecovered,
		cluster.HookHeartbeatRestartNotify,
	} {
		if !got[name] {
			t.Errorf("wireClusterPeerFailoverHooks did not install %s. This is a "+
				"cluster failover hook; dropping it silently degrades failover "+
				"rather than failing loudly (#7280)", name)
		}
	}

	// The lease is a VALUE, not a callback, so "installed" is not the question.
	// The daemon computes 2*localFailoverCommitTimeout + 20s; the fixture sets
	// that timeout to 2s, so 24s is the arrival proof. Asserting the COMPUTED
	// value rather than merely "non-zero" is what makes this bind the
	// expression and not just the call: the field is never nil, so a
	// non-zero check would pass on the clamp floor alone.
	if want := 2*d.localFailoverCommitTimeout + 20*time.Second; d.cluster.RemoteTransferOutLease() != want {
		t.Errorf("RemoteTransferOutLease = %v, want %v — the daemon's computed "+
			"lease did not reach the Manager (#7280)",
			d.cluster.RemoteTransferOutLease(), want)
	}
}

// The two Manager fence hooks. #6428 bound this builder's ss.OnFenceReceived
// handle; these are the other half of the same call, and they are the ones
// that talk TO the peer.
func TestWireClusterFenceCallbacksInstallsManagerHooks_7280(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireClusterFenceCallbacks(t.Context(), ss)

	got := d.cluster.InstalledHooks()
	if !got[cluster.HookPeerFence] {
		t.Error("wireClusterFenceCallbacks did not install PeerFenceFunc — the " +
			"node cannot fence its peer (#7280)")
	}
	if !got[cluster.HookPeerFenceConfirm] {
		t.Error("wireClusterFenceCallbacks did not install PeerFenceConfirmFunc — " +
			"the `disable-rg-confirmed` policy silently loses its confirmation " +
			"leg and degrades to unsequenced fencing (#7280)")
	}
}

// The two transport refs: the auth provider on the SessionSync and the
// transport mode on the Manager.
func TestWireSessionSyncTransportRefsInstallsAuthAndTransport_7280(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()

	if ss.HasAuthProvider() {
		t.Fatal("a freshly constructed SessionSync already reports an auth " +
			"provider; the seam cannot distinguish wired from unwired")
	}
	// NOT an emptiness check: newClusterManager defaults SyncTransport to
	// "fabric". What the assertion below needs is that the fresh value DIFFERS
	// from the one being wired, or it could pass without anything having been
	// installed. Asserting the difference is the honest precondition; asserting
	// emptiness would have been a guess, and it was wrong.
	if got := d.cluster.SyncTransport(); got == "control-link" {
		t.Fatalf("a fresh Manager already reports SyncTransport=%q, the very "+
			"value this test wires — the assertion below could not tell an "+
			"installed transport from the default", got)
	}

	cc := &config.ClusterConfig{}
	d.wireSessionSyncTransportRefs(ss, cc, "control-link", "10.99.0.2", "")

	if !ss.HasAuthProvider() {
		t.Error("wireSessionSyncTransportRefs did not install the auth provider. " +
			"Without it the control link authenticates with no shared PSK (#7280)")
	}
	if got := d.cluster.SyncTransport(); got != "control-link" {
		t.Errorf("SyncTransport = %q, want \"control-link\" — the selected "+
			"transport did not reach the Manager (#7280)", got)
	}
}
