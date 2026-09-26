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
// clustered config", never a silent half-apply. Both local commits and peer
// syncs pass this preflight before applyConfig, so neither can reach the
// config-arrival naming hook to reconcile cluster names. The boot config LOAD
// does not reach this guard (Store.Load -> applyConfigLocked, not commitAndApply),
// and a bootstrap plain commit is refused earlier by the inBootstrap() gate,
// so no legitimate boot/bootstrap path is falsely rejected.
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

// clusterControlEndpointCommitPreflight refuses a LIVE move of the cluster
// control-link peer address (#8965).
//
// THE DEFECT IT PREVENTS. applyAndSyncCommitted applies before it pushes:
// applyConfigLocked's step 20 stops cluster comms and restarts them on the NEW
// endpoint, and only then does pushCommittedConfigToPeer run -- over a
// transport that was just torn down and rebuilt on a different address. The
// peer is still on the OLD endpoint, so it never receives the candidate.
//
// AND NOTHING HEALS IT. QueueConfig no-ops on a nil connection, so the push
// fails SILENTLY rather than erroring the commit. The #5863 reconciler returns
// early on !syncPeerConnected, and that flag is set in exactly one place -- the
// session-sync connect callback -- so it cannot bootstrap a mismatch in which
// nothing is connected. Heartbeats carry no config. Both nodes are durably
// configured, so retry and reboot REPRODUCE the split rather than repair it:
// the standby eventually promotes on the stale tuple while this node stays
// primary on the new one, and fencing cannot traverse the severed channel
// either. A commit whose purpose was to preserve HA is what removes it.
//
// WHY REFUSE RATHER THAN MAKE-BEFORE-BREAK. A stage-and-ACK would have to be
// implemented at EVERY apply path -- commitAndApply, syncAndApply and
// commitConfirmedAndApply all reach applyConfigLocked -- and a version landed
// at one of them would leave the others silently broken. A preflight runs
// BEFORE any of them and covers all three by construction. It is also the
// answer this file already gives twice, for mode changes and for identity
// changes, to exactly this class: a change that cannot be re-keyed live from
// one side. You cannot move both ends of a point-to-point control link
// atomically from one end of it.
//
// SCOPE, and it is narrower than "the control tuple". This gates the peer
// ADDRESS, which is what the node dials and therefore what determines whether
// the push can land. `control-interface` is NOT gated: the manager keeps no
// running value to compare a candidate against without further plumbing, so a
// gate on it would have to compare config-to-config and would fire on a
// peer-synced text that merely renders the interface differently. That bound
// is recorded rather than papered over -- an interface-only move has the same
// shape and is not covered here.
//
// PEER-SYNC IS SAFE. `PeerAddress` is per-node (each node's config names the
// OTHER node's address), and a synced text compiles for the LOCAL node, so in
// steady state the candidate's value equals the running one and this gate is a
// no-op -- the same reasoning the identity gate documents for itself.
func clusterControlEndpointCommitPreflight(running *cluster.Manager, newCfg *config.Config) error {
	if running == nil || !clusterTopologyConfigured(newCfg) {
		// No running HA manager, or the candidate is not clustered: the
		// topology gate owns those cases.
		return nil
	}
	return controlEndpointDecision8965(running.HeartbeatPeerAddr(),
		newCfg.Chassis.Cluster.PeerAddress,
		// #9166-class denominator, #9178 specifically: the DELETION arm needs
		// to know whether anything else can carry the config push. That is a
		// property of the CANDIDATE config, not of the two addresses, so it has
		// to be passed in — which is why the decision could not stay a
		// two-string function and still be total.
		fabricFallbackConfigured9178(newCfg.Chassis.Cluster))
}

// fabricFallbackConfigured9178 reports whether the candidate still has a fabric
// transport after the control endpoint is removed.
//
// It mirrors clusterSyncTransport's own fallback condition
// (daemon_ha_comms_wiring.go) — control link when interface AND peer address
// are both set, else fabric — hoisted from runtime to commit time. Keeping the
// two in agreement is the point: a deletion is safe exactly when the runtime
// would fall back, so the gate must ask the same question the runtime asks.
func fabricFallbackConfigured9178(cc *config.ClusterConfig) bool {
	if cc == nil {
		return false
	}
	return cc.FabricInterface != "" && cc.FabricPeerAddress != ""
}

// controlEndpointDecision8965 is the DECISION, split from the accessor plumbing
// above so a cell can exercise it without constructing a running
// cluster.Manager -- which would need interfaces and sockets a unit test has no
// business creating.
//
// THE SPLIT IS DELIBERATE AND THE FIRST VERSION OF IT WAS WRONG. That version
// exposed only the message builder for testing, so the cell asserted the
// operator-facing TEXT while the decision -- when to refuse at all -- went
// unexercised: neutering the gate to `return nil` left the cell GREEN. A seam
// that bypasses the thing under test is worse than no seam, because it reads as
// coverage. This one is the decision itself, so the same mutation reds.
// #9178 MADE IT TOTAL, AND THE ORIGINAL JUSTIFICATION WAS HALF TRUE. The first
// version returned nil whenever EITHER side was empty, on the reasoning that
// "unset on either side means there is no live endpoint to strand". That is
// true for `have == ""` -- an ADDITION, where the heartbeat has not started --
// and false for `want == ""`, a DELETION, where the live endpoint being
// stranded is the one being removed. Two of the four (have, want) combinations
// were decided by a sentence that only covered one of them.
//
// A deletion is admitted only when the candidate still has a FABRIC transport.
// That is not leniency: clusterSyncTransport falls back to the fabric when the
// control link is not fully configured, so the config push still lands and the
// deletion propagates -- the heartbeat dies on both nodes, which is what the
// operator asked for, and there is no partition. On a control-link-only
// cluster (which the strict compiler gate accepts) there is no fallback: no
// heartbeat AND no sync transport, which is exactly #8965's apply-then-push
// partition, and it is durable because the peer never learns why. That is
// reachable with an ordinary `delete chassis cluster peer-address` + `commit`.
func controlEndpointDecision8965(have, want string, fabricFallback bool) error {
	switch {
	case have == "":
		// ADDITION (or still unset): the heartbeat has not started on an old
		// address, so there is genuinely nothing live to strand.
		return nil
	case want == have:
		// Not a move.
		return nil
	case want == "":
		// DELETION of a LIVE endpoint.
		if fabricFallback {
			return nil
		}
		return controlEndpointDeleteRefusal9178(have)
	default:
		return controlEndpointMoveRefusal8965(have, want)
	}
}

// controlEndpointDeleteRefusal9178 is the operator-facing text for the deletion
// arm, factored for the same reason the move refusal is: the cell asserting it
// and the gate producing it cannot drift apart.
//
// It names the procedure. A refusal without a path is worse than the defect it
// prevents -- an operator mid-maintenance who is told only "no" finds the way
// around it, and the way around it (committing on each node separately while
// both run) is the same partition by hand.
func controlEndpointDeleteRefusal9178(have string) error {
	return fmt.Errorf("commit rejected: removing the chassis cluster control-link "+
		"peer address (%s) on a running cluster with no fabric transport "+
		"configured cannot be done — applying it stops this node's heartbeat AND "+
		"leaves no transport to push the config to the peer, which is still "+
		"configured for the control link, so the peer never receives the change "+
		"and the two nodes are durably partitioned.\n"+
		"To remove the control link: configure `chassis cluster fabric-interface` "+
		"and `fabric-peer-address` first so the sync has a fallback path, or take "+
		"the cluster down before the change. Do NOT commit the deletion on each "+
		"node separately while both are running — that produces the same partition "+
		"by hand", have)
}

// controlEndpointMoveRefusal8965 is the operator-facing text, factored so the
// cell asserting it and the gate producing it cannot drift apart.
func controlEndpointMoveRefusal8965(have, want string) error {
	return fmt.Errorf("commit rejected: changing the chassis cluster control-link "+
		"peer address from %s to %s cannot be done on a running cluster — applying "+
		"it restarts this node's cluster comms on the NEW address before the config "+
		"can be pushed to the peer, which is still on the OLD one, so the peer never "+
		"receives the change and the two nodes are durably partitioned.\n"+
		"To move the control link: set the new address on BOTH nodes and restart "+
		"xpfd on both, or take the cluster down before the move. Do NOT commit the "+
		"change on each node separately while both are running — that produces the "+
		"same partition by hand", have, want)
}

// clusterControlInterfaceCommitPreflight refuses a LIVE move of the cluster
// control-link INTERFACE (#8987).
//
// THE SAME PARTITION, BY THE OTHER HALF OF THE TUPLE. #8965 gated the peer
// ADDRESS and recorded, in its own SCOPE paragraph, that `control-interface`
// has the identical shape and was left uncovered. The mechanism is unchanged:
// applyConfigLocked's step 20 stops cluster comms and restarts them on the new
// interface, and only then does the push to the peer run -- over a transport
// just rebuilt somewhere the peer is not listening. QueueConfig no-ops on a nil
// connection so the push fails SILENTLY, the #5863 reconciler returns early on
// !syncPeerConnected, and that flag is set in exactly one place (the
// session-sync connect callback), so nothing bootstraps a mismatch in which
// nothing is connected. Both nodes end up durably configured on different
// interfaces, and retry and reboot REPRODUCE the split rather than repair it.
//
// WHY IT COULD NOT BE FIXED WITH THE ADDRESS HALF, and what changed. #8965
// stated the blocker exactly: the manager kept no RUNNING value for
// control-interface, so a gate would have had to compare config to config --
// unable to tell "the operator is changing it" from "this is what it already
// was". The plumbing now exists: Manager.HeartbeatControlInterface() returns
// the interface the RUNNING heartbeat was started on, recorded from the same
// StartHeartbeat call that records hbLocalAddr and hbPeerAddr.
//
// It is deliberately NOT m.controlInterface. That field is also an interface
// name and would have been the natural-looking mistake -- UpdateConfig
// overwrites it on every config apply, so it tracks the CONFIG and a gate on it
// is the config-to-config comparison #8965 refused to ship. Nor is hbLocalAddr
// a proxy: an operator who moves the control link to another interface and
// carries the same address across leaves it unchanged, so a gate keyed on it
// would wave through exactly the move that partitions the cluster.
//
// PEER-SYNC IS SAFE, and MEASURED rather than inherited from #8965 -- the
// address gate's argument does NOT transfer, which is the trap this had to get
// out of. #8965 is safe because PeerAddress is PER-NODE: each node's config
// names the other node's address, so a synced text compiles to the local node's
// own value and the gate no-ops. control-interface is safe for a DIFFERENT and
// stronger reason: in the shipped cluster config
// (docs/ha-cluster-userspace.conf) `peer-address` sits INSIDE `groups node0` /
// `groups node1` while `control-interface em0` sits OUTSIDE them -- it is one
// shared value, not a per-node one. A synced text therefore carries the
// IDENTICAL string, candidate equals running trivially, and the gate is a
// no-op. Both leaves are read by the same `nodeVal` call in the same container
// (compiler_system.go), so a config that DOES scope control-interface per node
// still expands for the LOCAL node exactly as peer-address does. The property
// holds either way; the reason differs, and asserting #8965's reason here
// would have been an unearned transfer.
func clusterControlInterfaceCommitPreflight(running *cluster.Manager, newCfg *config.Config) error {
	if running == nil || !clusterTopologyConfigured(newCfg) {
		return nil
	}
	return controlInterfaceDecision8987(running.HeartbeatControlInterface(),
		newCfg.Chassis.Cluster.ControlInterface)
}

// controlInterfaceDecision8987 is the DECISION, split from the accessor
// plumbing for the reason #8965's split records: its own first version exposed
// only the message builder, so the cell asserted the operator-facing TEXT while
// "when to refuse at all" went unexercised and neutering the gate to `return
// nil` left the cell GREEN. This seam is the decision itself, so that mutation
// reds.
func controlInterfaceDecision8987(have, want string) error {
	if want == "" || have == "" || want == have {
		// Unset on either side means there is no live control link to strand --
		// the heartbeat has not started, or the candidate leaves it to the
		// runtime default. Equal means this is not a move.
		return nil
	}
	return controlInterfaceMoveRefusal8987(have, want)
}

// controlInterfaceMoveRefusal8987 is the operator-facing text, factored so the
// cell asserting it and the gate producing it cannot drift apart.
//
// It NAMES THE PROCEDURE, which #8987 lists as something a fix owes: a refusal
// without a path sends the operator to the workaround that reproduces the
// defect -- committing on each node separately, which is the same partition by
// hand.
func controlInterfaceMoveRefusal8987(have, want string) error {
	return fmt.Errorf("commit rejected: changing the chassis cluster control-link "+
		"interface from %s to %s cannot be done on a running cluster — applying it "+
		"restarts this node's cluster comms on the NEW interface before the config "+
		"can be pushed to the peer, which is still reachable only over the OLD one, "+
		"so the peer never receives the change and the two nodes are durably "+
		"partitioned.\n"+
		"To move the control link: set the new interface on BOTH nodes and restart "+
		"xpfd on both, or take the cluster down before the move. Do NOT commit the "+
		"change on each node separately while both are running — that produces the "+
		"same partition by hand", have, want)
}

// clusterSyncEndpointCommitPreflight refuses a LIVE move of the endpoint that
// carries the CONFIG PUSH (#9121) — the third member of the #8965/#8987 family,
// and the one that establishes which set of fields the family should have been
// keyed on all along.
//
// WHICH SET IS AUTHORITATIVE. Three sets exist in this daemon and they answer
// three different questions. Getting the wrong one is how #8965 and #8987 came
// to miss a whole cluster shape:
//
//   - clusterTransportKey (6 fields, daemon_ha_sync.go) answers "does step 20
//     RESTART cluster comms?". It is deliberately wide and it is correct for
//     that question. It is NOT the set to gate on: a fabric1-only change
//     restarts comms, but fab1 is a REDUNDANT secondary path (sync_conn.go
//     logs "secondary fabric listen failed, using primary only") — the push
//     still lands over fab0, so refusing it would be a FALSE REJECTION.
//     #9121's own suggested fix direction named Fabric1PeerAddress; that is
//     the over-gate, and it is why the set had to be derived rather than
//     copied.
//   - the HEARTBEAT pair {ControlInterface, PeerAddress} is what #8965 and
//     #8987 actually read, via Manager.HeartbeatPeerAddr /
//     HeartbeatControlInterface. It answers "is the heartbeat running, and
//     where?".
//   - clusterSyncTransport's SELECTED PAIR answers "which endpoint carries the
//     config push?" — and the push is what a partition strands
//     (pushCommittedConfigToPeer -> syncConfigToPeer -> QueueConfig). **That is
//     the authoritative set for this family.**
//
// The heartbeat pair is a PROXY for the sync pair, and it is an exact one in
// control-link mode — which is the only mode the shipped fixtures configure
// (docs/ha-cluster-userspace.conf and test/incus/loss-userspace-cluster.env
// both set control-interface), so nothing measured the divergence. In FABRIC
// transport mode the two come apart completely: clusterSyncTransport falls back
// to {FabricInterface, FabricPeerAddress} when either control field is empty,
// and the heartbeat does not start at all in that shape
// (daemon_ha_sync.go: "if cc.ControlInterface != "" && cc.PeerAddress != """),
// so HeartbeatPeerAddr() is empty, controlEndpointDecision8965's have=="" arm
// returns nil, and BOTH existing gates no-op on the very commit that
// partitions the pair. A proxy that coincides in the measured mode and diverges
// in the unmeasured one is the shape this gate exists to remove.
//
// SO THIS GATE COMPARES SYNC ENDPOINTS, NOT FIELDS. It runs clusterSyncTransport
// over the RUNNING transport key and over the CANDIDATE config and refuses when
// the selected endpoint moves. Using the same selector on both sides is
// structural rather than stylistic: a hand-copied fallback rule would drift
// from the one that actually picks the transport, and this family's whole
// history is gates keyed on a set that had drifted from the mechanism.
//
// It therefore also covers, for free, a shape #9121 did not name and no gate
// held: a commit that ADDS a control link to a fabric-transport cluster (or
// removes one) moves sync from fabric to control-link while the peer is still
// on the fabric — the same durable partition by a transport-TYPE change rather
// than an address change. #8965's gate cannot see it (have=="") and #8987's
// cannot either.
//
// WHAT IT DOES NOT DO, deliberately. A control-link-to-control-link move is
// left to #8965/#8987, which run FIRST at all three call sites and produce the
// specific operator text for that move. The explicit defer arm below keeps this
// decision total instead of relying on that ordering.
//
// PEER-SYNC IS SAFE, MEASURED not inherited. In the shipped cluster config
// (docs/ha-cluster-userspace.conf) `fabric-peer-address` sits INSIDE
// `groups node0` / `groups node1` — lines 10 and 39, directly beside the
// per-node `peer-address` — so it is per-node exactly as #8965's field is: a
// synced text compiles for the LOCAL node, candidate equals running, and the
// gate no-ops. `fabric-interface` is safe for #8987's reason instead: it is
// auto-derived from the local fabric member (compiler_derivations.go keys on
// SlotToNodeID(slot) == cc.NodeID) or set outside the groups, so both nodes
// carry the identical name. Both halves are safe; the reasons differ, and
// asserting one of them for the other would be the unearned transfer #8987
// records.
func clusterSyncEndpointCommitPreflight(active clusterTransportKey, newCfg *config.Config) error {
	if active == (clusterTransportKey{}) || !clusterTopologyConfigured(newCfg) {
		// Comms never started (boot applies run before startClusterComms — the
		// same `active != zero` guard step 20 relies on), or the candidate is
		// not clustered: the topology gate owns those cases.
		return nil
	}
	haveIf, haveAddr, haveMode := clusterSyncTransport(&config.ClusterConfig{
		ControlInterface:  active.ControlInterface,
		PeerAddress:       active.PeerAddress,
		FabricInterface:   active.FabricInterface,
		FabricPeerAddress: active.FabricPeerAddress,
	})
	wantIf, wantAddr, wantMode := clusterSyncTransport(newCfg.Chassis.Cluster)
	return syncEndpointDecision9121(
		syncEndpoint9121{haveIf, haveAddr, haveMode},
		syncEndpoint9121{wantIf, wantAddr, wantMode})
}

// syncEndpoint9121 is one resolved config-sync endpoint: the interface and peer
// address clusterSyncTransport selected, plus which arm of it selected them.
type syncEndpoint9121 struct {
	iface string
	addr  string
	mode  string
}

// syncEndpointDecision9121 is the DECISION, split from the accessor plumbing
// for the reason controlEndpointDecision8965's own doc records: the first
// version of that split exposed only the message builder, so the cell asserted
// the operator-facing TEXT while "when to refuse at all" went unexercised and
// neutering the gate to `return nil` left it GREEN. This seam is the decision,
// so that mutation reds.
func syncEndpointDecision9121(have, want syncEndpoint9121) error {
	if have.addr == "" || want.addr == "" {
		// Nothing live to strand, or the candidate names no sync endpoint at
		// all — the same empty-side reading the two sibling gates take, and the
		// topology gate owns a candidate that stops being clustered.
		return nil
	}
	if have == want {
		return nil
	}
	if have.mode == "control-link" && want.mode == "control-link" {
		// Owned by #8965 (address) and #8987 (interface), which run first at
		// every call site and say the specific thing about a control-link move.
		// Stated rather than left to that ordering, so a reordering cannot turn
		// this into a second, differently-worded refusal of the same commit.
		return nil
	}
	return syncEndpointMoveRefusal9121(have, want)
}

// syncEndpointMoveRefusal9121 is the operator-facing text, factored so the cell
// asserting it and the gate producing it cannot drift apart. It NAMES THE
// PROCEDURE for the reason #8987 records: a refusal without a path sends the
// operator to the workaround that reproduces the defect.
func syncEndpointMoveRefusal9121(have, want syncEndpoint9121) error {
	return fmt.Errorf("commit rejected: changing the chassis cluster config-sync "+
		"endpoint from %s on %s (%s transport) to %s on %s (%s transport) cannot be "+
		"done on a running cluster — applying it restarts this node's cluster comms "+
		"on the NEW endpoint before the config can be pushed to the peer, which is "+
		"still on the OLD one, so the peer never receives the change and the two "+
		"nodes are durably partitioned.\n"+
		"To move the config-sync endpoint: set the new values on BOTH nodes and "+
		"restart xpfd on both, or take the cluster down before the move. Do NOT "+
		"commit the change on each node separately while both are running — that "+
		"produces the same partition by hand",
		have.addr, have.iface, have.mode, want.addr, want.iface, want.mode)
}
