package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// errClusterTopologyRequiresRestart is the #5840 sentinel returned when a
// commit (or a peer-synced replay) would flip a running daemon between
// standalone and chassis-cluster mode. Callers surface it verbatim to the
// operator (CLI/gRPC/REST); tests match it with errors.Is.
var errClusterTopologyRequiresRestart = errors.New(
	"standalone<->cluster topology change requires a restart/offline workflow")

// clusterTopologyConfigured reports whether a compiled config engages
// chassis-cluster (HA) mode. A nil config is treated as standalone.
func clusterTopologyConfigured(cfg *config.Config) bool {
	return cfg != nil && cfg.Chassis.Cluster != nil
}

// clusterTopologyCommitPreflight is the #5840 standalone<->cluster topology
// commit guard.
//
// The chassis-cluster runtime — the d.cluster manager, its election,
// heartbeat/watchdog writer, session/config/DHCP-lease sync, event watcher,
// VRRP sync hold, and the gRPC fabric listener — is constructed EXACTLY ONCE,
// at process startup, and ONLY when the boot-time active config already
// contains `chassis cluster` (pkg/daemon/daemon_run.go: initManagers +
// startClusterComms). A DAY-2 apply reconciles that runtime only inside
// `if d.cluster != nil` guards (daemon_apply.go steps 19-20); it can neither
// construct it when no HA runtime exists nor tear it down when the new config
// drops the cluster.
//
// Constructing/tearing that runtime down live is UNSAFE for two independent
// reasons (issue #5840):
//
//   - d.cluster is a bare, write-once-at-boot *cluster.Manager pointer read
//     without a lifecycle lock from ~129 sites (gRPC/CLI `show chassis cluster`
//     handlers, the DHCP-relay decision, the RG reconcile ticker, the health
//     loop, ...). Assigning it during an apply is a data race and exposes a
//     partially-initialized runtime to those readers.
//   - The userspace dataplane arms clustered forwarding semantics
//     (clusterHA=true, seeded HA groups) from the NEW config DURING THE SAME
//     apply — before any watchdog writer or election exists — so the Rust HA
//     gate would treat transit as HAInactive and drop it persistently until a
//     restart.
//
// Silently accepting the commit therefore publishes a half-built hybrid state:
// no HA plus a persistent transit outage until xpfd restarts under the new
// config (the #5840 bug). Instead we REJECT the topology-mode change at commit
// time — BEFORE store promotion and any dataplane mutation — and direct the
// operator to the restart/offline workflow. An intra-mode edit (both
// standalone, or both clustered with only redundancy-group/interface/transport
// changes) is unaffected and still reconciles live.
//
// The gate keys on DESIRED-vs-ACTUAL-RUNTIME, not on the outgoing config.
// runtimeClusterActive is the actual constructed HA-runtime state — the caller
// passes `d.cluster != nil`, the single boot-only signal that the cluster
// runtime exists (daemon_run.go:1868). newCfg is the compiled candidate about
// to be promoted. Reject when the candidate's desired mode
// (clusterTopologyConfigured(newCfg)) disagrees with the runtime that is
// actually running.
//
// Keying on the runtime — rather than a proxy such as the old active config —
// is what closes the #4179 config-less-HA-node hole. That node boots with
// /etc/xpf/node-id present but a nil active config, so computeBootClass returns
// bootClassNormal (NOT bootstrap), initManagers SKIPS the `d.cluster` build
// (its boot-time config was nil), and d.cluster stays nil with inBootstrap()
// false. A day-2 `commit` adding `chassis cluster` there has no old config to
// compare against; an old-config proxy that permitted a nil old would let it
// through and arm clusterHA=true against a nil HA runtime — the exact #5840
// hybrid state. The runtime predicate uniformly REJECTS it (nil runtime,
// clustered desire), just like standalone->cluster and cluster->standalone,
// because that node cannot form the cluster live either: the HA runtime is
// boot-only-constructed, so the honest fail-closed answer is "restart into the
// clustered config", never a silent half-apply. The boot config LOAD does not
// reach this guard (Store.Load -> applyConfigLocked, not commitAndApply), and a
// bootstrap plain commit is refused earlier by the inBootstrap() gate, so no
// legitimate boot/bootstrap path is falsely rejected.
//
// This restart/offline workflow is the TERMINAL answer, not a placeholder. Live
// day-2 construction/teardown of the cluster runtime was tracked as #6187 and is
// PLAN-KILLED: it would require making d.cluster lifecycle-safe across 200+ bare
// read sites (a population that grows with every new handler), generation-fencing
// the dataplane clusterHA arm behind runtime readiness, and transactional rollback
// at every construction stage — all to skip a reboot that the reference platform
// also requires (on SRX the reboot is part of the command itself: `set chassis
// cluster cluster-id <id> node <n> reboot`, `set chassis cluster disable reboot`).
func clusterTopologyCommitPreflight(runtimeClusterActive bool, newCfg *config.Config) error {
	newCluster := clusterTopologyConfigured(newCfg)
	if newCluster == runtimeClusterActive {
		// Desired mode already matches the running HA runtime: an intra-mode
		// edit (both standalone, or both clustered) reconciles live.
		return nil
	}
	if newCluster {
		return fmt.Errorf("commit rejected: adding `chassis cluster` cannot form the "+
			"cluster without a restart — the HA runtime (election, heartbeat/watchdog, "+
			"session and config sync, VRRP) is constructed only at daemon startup, and "+
			"this daemon has no HA runtime. Commit this change with the system offline, "+
			"or restart xpfd into the clustered configuration: %w",
			errClusterTopologyRequiresRestart)
	}
	return fmt.Errorf("commit rejected: removing `chassis cluster` on a running "+
		"clustered system cannot tear down the HA runtime without a restart. "+
		"Restart xpfd into the standalone configuration: %w",
		errClusterTopologyRequiresRestart)
}

// errClusterIdentityRequiresRestart is the #6192 sibling of
// errClusterTopologyRequiresRestart: a day-2 commit that CHANGES the running
// cluster's node-id or cluster-id cannot re-key the boot-constructed HA manager
// live, so it is rejected with a restart-required diagnostic. Callers surface it
// verbatim to the operator (CLI/gRPC/REST); tests match it with errors.Is.
var errClusterIdentityRequiresRestart = errors.New(
	"chassis cluster node-id / cluster-id change requires a restart into the new identity")

// clusterIdentityCommitPreflight is the #6192 node-id / cluster-id restart
// boundary — a sibling of clusterTopologyCommitPreflight (#5840) covering the
// same boot-baked-runtime class the topology gate does NOT.
//
// cluster.NewManager(nodeID, clusterID) is called EXACTLY ONCE, at daemon
// startup (pkg/daemon/daemon_run.go:1868), with the boot config's identity.
// Manager.UpdateConfig — the only day-2 reconcile path — reconciles ONLY the
// redundancy groups (pkg/cluster/group_state.go); it never re-reads m.nodeID or
// m.clusterID. So a day-2 commit that CHANGES `chassis cluster node-id` or
// `cluster-id` is accepted and promoted, but the running manager keeps its OLD
// identity — heartbeat NodeID/ClusterID, RETH virtual MAC (02:bf:72:CC:RR:NN),
// election tie-break, FPC/slot naming — and the new identity takes effect only
// on restart. That is a silent partial no-op: the same false-success class #5840
// fixed for the standalone<->cluster topology flip.
//
// A live re-key of the write-once-at-boot manager is UNSAFE for the same reason
// #5840 declined to (de)construct it live: d.cluster is read bare, without a
// lifecycle lock, from ~129 sites, and its identity feeds the heartbeat writer,
// VRRP RETH MAC, and election already running under other goroutines. So we
// REJECT the identity change at commit time — BEFORE store promotion and any
// dataplane mutation — and direct the operator to restart into the new identity.
//
// Scope. This gate fires ONLY when a cluster runtime EXISTS (running != nil)
// AND the candidate is still clustered. The standalone<->cluster flip in either
// direction — including the #4179 config-less node (nil runtime, clustered
// desire) — is owned by clusterTopologyCommitPreflight and handled there; when
// running is nil or the candidate drops the cluster, this gate is a no-op and
// the topology gate decides. An intra-identity edit (same node-id AND
// cluster-id, e.g. a redundancy-group / interface / policy change) passes
// untouched and reconciles live.
//
// No legitimate boot/bootstrap path is falsely rejected, for the same reasons as
// #5840: the boot config LOAD reaches applyConfigLocked, not commitAndApply, and
// a bootstrap plain commit is refused earlier by the inBootstrap() gate. In
// steady state a peer-synced commit also passes — the synced text compiles for
// the LOCAL node, so node-id resolves to this node's running id and cluster-id
// is the shared value; the gate rejects only when the operator actually re-keys
// the identity, which requires a restart on both nodes regardless.
func clusterIdentityCommitPreflight(running *cluster.Manager, newCfg *config.Config) error {
	if running == nil || !clusterTopologyConfigured(newCfg) {
		// No running HA manager, or the candidate is not clustered: the
		// standalone<->cluster topology gate owns these cases.
		return nil
	}
	cc := newCfg.Chassis.Cluster
	runNode, runCluster := running.NodeID(), running.ClusterID()
	if cc.NodeID == runNode && cc.ClusterID == runCluster {
		// Identity unchanged: an intra-identity edit reconciles live.
		return nil
	}
	return fmt.Errorf("commit rejected: changing chassis cluster identity from "+
		"node-id %d / cluster-id %d to node-id %d / cluster-id %d cannot re-key the "+
		"running HA manager — its node/cluster identity (heartbeat, RETH virtual MAC, "+
		"election tie-break, FPC naming) is constructed only at daemon startup. "+
		"Restart xpfd into the new cluster identity, or make the change with the "+
		"system offline: %w",
		runNode, runCluster, cc.NodeID, cc.ClusterID, errClusterIdentityRequiresRestart)
}
