package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

func standaloneCfg() *config.Config {
	cfg := &config.Config{}
	cfg.System.HostName = "standalone-node"
	return cfg
}

func clusterCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1, NodeID: 0}
	return cfg
}

// TestConfiglessHANodeStartupDiagnosticRequiresRestart pins the operator-facing
// recovery message and the restart advice returned by the live topology preflight.
func TestConfiglessHANodeStartupDiagnosticRequiresRestart(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "xpf.conf")
	d := &Daemon{store: newConfigStore(t, configFile), opts: Options{ConfigFile: configFile}}

	savedNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return true }
	t.Cleanup(func() { hasNodeIDFileFn = savedNodeIDCheck })
	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	if failClosed, err := d.loadAndBootstrapConfig(); err != nil || failClosed {
		t.Fatalf("loadAndBootstrapConfig() = (%v, %v); want (false, nil)", failClosed, err)
	}
	if d.inBootstrap() || !d.emptyHANamingPending.Load() {
		t.Fatalf("config-less HA boot state: bootstrap=%v namingPending=%v; want false/true",
			d.inBootstrap(), d.emptyHANamingPending.Load())
	}

	message := logs.String()
	if !strings.Contains(message, "restart xpfd into that configuration") ||
		!strings.Contains(message, "cluster config arrival cannot start it or reconcile interface naming") {
		t.Fatalf("config-less HA boot log must explain why a restart is required; got %q", message)
	}
	if strings.Contains(message, "automatically when that config arrives") ||
		strings.Contains(message, "no restart required") {
		t.Fatalf("config-less HA boot log must not promise live cluster renaming; got %q", message)
	}

	err := clusterTopologyCommitPreflight(false /*runtimeClusterActive*/, clusterCfg())
	if err == nil || !strings.Contains(err.Error(), "restart xpfd into the clustered configuration") {
		t.Fatalf("adding cluster topology without an HA runtime must direct the operator to restart; got %v", err)
	}
}

// TestClusterTopologyDay2TransitionRejected is the #5840 fail-on-revert gate.
//
// The chassis-cluster runtime is constructed only at boot (daemon_run.go
// initManagers + startClusterComms). A DAY-2 commit that arms a mode the
// running HA runtime cannot serve cannot (de)construct that boot-only runtime,
// and silently accepting it publishes clustered dataplane semantics
// (clusterHA=true) with no election/watchdog runtime — a persistent transit
// outage until restart, plus a data race on the bare d.cluster pointer.
// clusterTopologyCommitPreflight keys on DESIRED-vs-ACTUAL-RUNTIME
// (runtimeClusterActive == d.cluster != nil), so it must REJECT a candidate
// whose mode disagrees with the running HA runtime BEFORE store promotion / any
// dataplane mutation, in both directions, while leaving an intra-mode edit
// untouched.
//
// Reverting the fix (clusterTopologyCommitPreflight returns nil, or forcing the
// desired/actual comparison to always match) makes the FIRST assertion below
// RED as an assertion — exactly one test binds the production reject line. The
// end-to-end commitAndApply legs then prove the preflight is wired into the
// commit path and that a rejected transition writes NO d.cluster and mutates NO
// dataplane — including the #4179 config-less-node case (nil active config, nil
// runtime) that an old-config proxy used to wrongly PERMIT.
func TestClusterTopologyDay2TransitionRejected(t *testing.T) {
	// --- Direct preflight: the precise binding (keyed on runtime state). ---
	// No HA runtime (d.cluster == nil) + a clustered candidate: the #5840 bug.
	// This uniformly covers standalone->cluster AND the #4179 config-less node
	// (both present a nil HA runtime + a clustered desire).
	err := clusterTopologyCommitPreflight(false /*runtimeClusterActive*/, clusterCfg())
	if err == nil {
		t.Fatal("adding chassis cluster with no HA runtime must be REJECTED " +
			"(cannot form the cluster without a restart)")
	}
	if !errors.Is(err, errClusterTopologyRequiresRestart) {
		t.Fatalf("rejection must wrap the restart-required sentinel; got %v", err)
	}
	if !strings.Contains(err.Error(), "chassis cluster") ||
		!strings.Contains(err.Error(), "restart xpfd into the clustered configuration") {
		t.Fatalf("rejection must carry an actionable operator diagnostic; got %q", err.Error())
	}

	// Running HA runtime (d.cluster != nil) + a standalone candidate: the
	// reverse teardown, also unsafe live.
	if rerr := clusterTopologyCommitPreflight(true /*runtimeClusterActive*/, standaloneCfg()); rerr == nil ||
		!errors.Is(rerr, errClusterTopologyRequiresRestart) {
		t.Fatalf("removing chassis cluster on a running HA runtime must be REJECTED "+
			"with the restart-required sentinel; got %v", rerr)
	}

	// #4179 config-less HA node: node-id present but a nil active config, so the
	// boot path never built d.cluster (runtimeClusterActive == false) and
	// inBootstrap() is false. A day-2 commit adding chassis cluster there was
	// the case the old `old == nil` proxy wrongly PERMITTED — the runtime
	// predicate REJECTS it (nil runtime, clustered desire), same as any other
	// add-cluster-without-a-runtime commit.
	if cerr := clusterTopologyCommitPreflight(false /*runtimeClusterActive*/, clusterCfg()); cerr == nil ||
		!errors.Is(cerr, errClusterTopologyRequiresRestart) {
		t.Fatalf("config-less HA node (nil runtime) adding chassis cluster must be "+
			"REJECTED with the restart-required sentinel; got %v", cerr)
	}

	// --- Controls: an intra-mode edit (runtime matches desired) is ACCEPTED. ---
	if aerr := clusterTopologyCommitPreflight(false /*runtimeClusterActive*/, standaloneCfg()); aerr != nil {
		t.Fatalf("standalone runtime + standalone commit must be accepted; got %v", aerr)
	}
	if aerr := clusterTopologyCommitPreflight(true /*runtimeClusterActive*/, clusterCfg()); aerr != nil {
		t.Fatalf("clustered runtime + clustered commit must be accepted; got %v", aerr)
	}

	// --- Wiring 1: commitAndApply rejects standalone->cluster, no runtime write. ---
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (standalone): %v", err)
	}
	if err := store.SetFromInput("system host-name standalone-node"); err != nil {
		t.Fatalf("set standalone host-name: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit standalone active: %v", err)
	}
	// Still in configuration mode after the commit — seed a chassis-cluster
	// CANDIDATE (not committed; commitAndApply performs the commit).
	if err := store.SetFromInput("chassis cluster cluster-id 1"); err != nil {
		t.Fatalf("set cluster-id: %v", err)
	}
	if err := store.SetFromInput("chassis cluster node 0"); err != nil {
		t.Fatalf("set node: %v", err)
	}
	// #6611: the strict commit path rejects an unkeyed chassis cluster; key the
	// candidate so the topology preflight is what decides this test.
	if err := store.SetFromInput("chassis cluster authentication-key test-cluster-psk-6611"); err != nil {
		t.Fatalf("set authentication-key: %v", err)
	}

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	_, cerr := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "add chassis cluster", peerSyncNever)
	if cerr == nil || !errors.Is(cerr, errClusterTopologyRequiresRestart) {
		t.Fatalf("commitAndApply of a standalone->cluster transition must be "+
			"rejected with the restart-required sentinel; got %v", cerr)
	}
	if d.cluster != nil {
		t.Fatal("a rejected transition must NOT construct the cluster runtime " +
			"(d.cluster must stay nil)")
	}
	// The candidate must NOT have been promoted: active is still standalone.
	if active := store.ActiveConfig(); clusterTopologyConfigured(active) {
		t.Fatal("a rejected transition must NOT promote the cluster candidate to active")
	}

	// --- Wiring 2: commitAndApply rejects the #4179 config-less-node commit. ---
	// A node with NO active config (nil) and NO HA runtime (d.cluster == nil,
	// inBootstrap() == false) that day-2-commits chassis cluster. The old
	// old==nil carve-out PERMITTED this (nil active) and armed clusterHA=true
	// against a nil runtime; the runtime predicate REJECTS it before any store
	// promotion, and the candidate never becomes active.
	cfgless := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := cfgless.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (config-less): %v", err)
	}
	// Seed a well-formed chassis-cluster CANDIDATE without ever committing a
	// standalone active — ActiveConfig() stays nil, mirroring the config-less
	// HA node's boot state.
	if err := cfgless.SetFromInput("system host-name cfgless-node"); err != nil {
		t.Fatalf("set config-less host-name: %v", err)
	}
	if err := cfgless.SetFromInput("chassis cluster cluster-id 1"); err != nil {
		t.Fatalf("set config-less cluster-id: %v", err)
	}
	if err := cfgless.SetFromInput("chassis cluster node 0"); err != nil {
		t.Fatalf("set config-less node: %v", err)
	}
	if err := cfgless.SetFromInput("chassis cluster authentication-key test-cluster-psk-6611"); err != nil {
		t.Fatalf("set config-less authentication-key: %v", err)
	}
	if active := cfgless.ActiveConfig(); active != nil {
		t.Fatalf("config-less precondition: active config must be nil before commit; got %+v", active)
	}

	dcl := &Daemon{store: cfgless, applySem: semaphore.NewWeighted(1)}
	_, clErr := dcl.commitAndApply(context.Background(), configstore.InternalCommitter(), "config-less add chassis cluster", peerSyncNever)
	if clErr == nil || !errors.Is(clErr, errClusterTopologyRequiresRestart) {
		t.Fatalf("commitAndApply on a config-less node (nil active, nil runtime) adding "+
			"chassis cluster must be rejected with the restart-required sentinel; got %v", clErr)
	}
	if dcl.cluster != nil {
		t.Fatal("config-less rejected commit must NOT construct the cluster runtime")
	}
	if active := cfgless.ActiveConfig(); clusterTopologyConfigured(active) {
		t.Fatal("config-less rejected commit must NOT promote the cluster candidate to active")
	}
}
