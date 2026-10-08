# HA Mode: No Hitless Restart

Date: 2026-03-01  
Status: Implemented (Sprint #68)  
Tracking issue: https://github.com/psaab/xpf/issues/68

## Summary

In chassis cluster (HA) mode, hitless restart is the wrong default.
If the local daemon is down or wedged, the node should fail closed instead of
continuing to forward with stale in-kernel dataplane state.

## Why

Hitless restart is valuable for standalone upgrades, but HA has different
priorities:

- Deterministic failover and single-owner forwarding.
- Reduced split-brain risk when a node loses control-plane health.
- Clear operational behavior: HA node unhealthy means stop forwarding.

Current code intentionally preserves dataplane state on daemon shutdown:

- `pkg/daemon/daemon.go` keeps control-plane state and calls non-destructive
  dataplane close (the runtime dataplane's `Close()`).
- `pkg/dataplane/loader.go` `Close()` keeps pinned links/maps active for reuse.

That is desirable for standalone hitless restart, but risky as the default in
HA.

## Implemented behavior

When `chassis cluster` is enabled:

1. Disable hitless-restart semantics by default.
2. On daemon exit/failure, transition to fail-closed behavior for local
   forwarding ownership state.
3. Preserve current hitless behavior in non-HA standalone mode.
4. Provide an explicit opt-in if operators want hitless behavior in HA.

## Acceptance criteria

- In HA mode, stopping or crashing `xpfd` does not leave stale active
  forwarding on that node.
- Peer failover converges without prolonged dual-active forwarding.
- Standalone mode continues to support hitless restart.

## Standalone <-> cluster transitions require a restart (#5840)

Turning chassis-cluster mode ON or OFF is a topology change, not a live
day-2 reconfiguration. The cluster runtime — the `d.cluster` manager,
its election, the heartbeat/watchdog writer, session/config/DHCP-lease
sync, the event watcher, the VRRP sync hold, and the gRPC fabric
listener — is constructed **exactly once, at process startup**, and only
when the boot-time active config already contains `chassis cluster`
(`pkg/daemon/daemon_run.go` `initManagers` + `startClusterComms`). A
running daemon cannot construct or tear that runtime down from a commit:

- `d.cluster` is a bare, write-once-at-boot pointer read without a
  lifecycle lock from many gRPC/CLI/reconcile call sites, so assigning it
  mid-apply is a data race and exposes a partially-initialized runtime.
- The userspace dataplane arms clustered forwarding semantics
  (`clusterHA=true`, seeded HA groups) from the new config during the
  same apply, before any watchdog writer or election exists — the Rust HA
  gate then treats transit as HA-inactive and drops it persistently.

To avoid silently publishing that half-built hybrid state (no HA plus a
persistent transit outage until restart), a commit whose desired topology
mode disagrees with the running HA runtime is **rejected before any store
promotion or dataplane mutation** (`clusterTopologyCommitPreflight`,
wired into `commitAndApply` / `commitConfirmedAndApply`, and fail-closed
in the peer-sync replay path `syncAndApply`). The operator commits the
topology change with the system offline, or restarts `xpfd` into the new
configuration; the boot path then constructs the correct runtime. Intra-
mode edits (redundancy-group / interface / transport changes on an
already-clustered node, or any standalone-only edit) reconcile live as
before.

### The gate keys on runtime state, not the old config

The predicate compares DESIRED-vs-ACTUAL-RUNTIME: it rejects when the
candidate's desired mode (`clusterTopologyConfigured(newCfg)`) disagrees
with `runtimeClusterActive` — the actual constructed HA-runtime state,
which every wire site passes as `d.cluster != nil` (the single boot-only
signal that the cluster runtime exists, `daemon_run.go:1868`). Keying on
the runtime rather than an old-config proxy is load-bearing: it uniformly
catches standalone→cluster (nil runtime, clustered desire),
cluster→standalone (live runtime, standalone desire), **and** the #4179
config-less HA node.

That config-less node boots with `/etc/xpf/node-id` present but a nil
active config, so `computeBootClass` returns `bootClassNormal` (not
bootstrap), `initManagers` skips the `d.cluster` build (its boot-time
config was nil), and `d.cluster` stays nil while `inBootstrap()` is
false. It has no *old config* to transition from, so an old-config proxy
that treated "nil old" as safe would let its day-2 `chassis cluster`
commit through and arm `clusterHA=true` against a nil HA runtime — the
exact #5840 hybrid state. The runtime predicate rejects it instead, and
the rejection is correct: that node cannot form the cluster live either
(the HA runtime is boot-only-constructed), so the honest fail-closed
answer is "restart into the clustered config", never a silent
half-apply. The boot config LOAD never reaches this guard
(`Store.Load` → `applyConfigLocked`, not `commitAndApply`), and a
bootstrap plain commit is refused earlier by the `inBootstrap()` gate, so
no legitimate boot/bootstrap path is falsely rejected.

### The restart workflow is the terminal answer

First-class live day-2 construction/teardown of the cluster runtime (the
"full supervisor" contract) is **not planned**. It was tracked as #6187
and plan-killed, for three reasons:

- **It is not a parity gap.** On SRX, enabling and disabling chassis
  cluster are reboot-coupled commands — `set chassis cluster cluster-id
  <id> node <n> reboot` and `set chassis cluster disable reboot`. The
  reboot is part of the command. A live transition would *exceed* the
  reference platform, not match it.
- **The safety property is already achieved.** The dangerous outcome was
  the silent half-apply (no HA plus a persistent transit outage until
  restart); the preflight converts that into an explicit rejection naming
  the required workflow.
- **The cost is disproportionate and growing.** `d.cluster`
  (`pkg/daemon/daemon.go`) is read bare from 200+ non-test sites across
  `pkg/daemon`, `pkg/grpcapi`, `pkg/api` and `pkg/cli`, many on concurrent
  handlers, and that count rises with every new handler. Making it
  lifecycle-safe, generation-fencing the dataplane `clusterHA` arm behind
  runtime readiness, and adding transactional rollback at every
  construction stage is a large HA-critical refactor whose whole payoff is
  skipping a reboot.

If an operator is ever genuinely blocked by the reboot, the design sketch
is preserved on #6187. Note that the `d.cluster` lifecycle-safety work is
independently useful and can be taken on its own merits without it.

## Acceptance criteria (topology transition, #5840)

- A day-2 commit adding `chassis cluster` on a node with no HA runtime
  (`d.cluster == nil`) is rejected with a restart-required diagnostic;
  `d.cluster` stays nil and the candidate is not promoted. This covers
  both a standalone daemon and the #4179 config-less HA node (nil active
  config, nil runtime) that an old-config proxy used to wrongly permit.
- The reverse (removing `chassis cluster` on a running HA runtime,
  `d.cluster != nil`) is rejected the same way.
- A peer-synced replay encoding the same transition fails closed without
  arming the live dataplane.
- Intra-mode commits (desired mode matches the running runtime) are
  unaffected.

## Node-id / cluster-id changes require a restart (#6192)

Changing `chassis cluster node-id` or `cluster-id` on a **running
clustered node** is a restart-boundary change of the same class as the
standalone<->cluster flip above, for the same boot-baked-runtime reason.
`cluster.NewManager(nodeID, clusterID)` is called **exactly once, at
process startup** (`pkg/daemon/daemon_run.go:1868`), with the boot
config's identity. `Manager.UpdateConfig` — the only day-2 reconcile
path — reconciles **only the redundancy groups**
(`pkg/cluster/group_state.go`); it never re-reads `m.nodeID` or
`m.clusterID`. (Fabric / heartbeat-transport / control-interface
identity *is* reconciled live — `daemon_apply.go`, #87 — so only the
node-id / cluster-id **identity** is boot-baked.)

**That parenthetical is true and was reassuring for the wrong reason,
which #8965 and #8987 corrected.** "Reconciled live" describes the
mechanism, not its safety: the live reconcile stops cluster comms and
restarts them on the NEW control endpoint, and only then pushes the
config to a peer that is still on the OLD one. Being reconcilable live
is precisely what makes the control tuple dangerous, not what makes it
safe — so both halves of it are now refused at commit rather than
reconciled. See "Live control-link moves" below.

So a day-2 commit that changes the node-id or cluster-id used to be
accepted and promoted, while the running manager kept its **old**
identity — heartbeat `NodeID`/`ClusterID`, the per-RETH virtual MAC
(`02:bf:72:CC:RR:(2*reth-index+node-id)`), the election
tie-break, and FPC/slot naming. The new identity took effect **only on
restart**: a silent partial no-op, the same false-success the #5840
topology gate closes for the mode flip.

A live re-key of the write-once-at-boot manager is unsafe for the same
reason #5840 declined to (de)construct it live: `d.cluster` is read bare,
without a lifecycle lock, from many sites, and its identity feeds the
heartbeat writer, the RETH MAC, and the election already running under
other goroutines. Instead, `clusterIdentityCommitPreflight` **rejects the
identity change before any store promotion or dataplane mutation** — wired
into `commitAndApply` / `commitConfirmedAndApply` beside the topology
gate, and fail-closed in the peer-sync replay path `syncAndApply` — and
directs the operator to restart `xpfd` into the new cluster identity (or
make the change with the system offline). The gate fires only when a
cluster runtime exists (`d.cluster != nil`) **and** the candidate is still
clustered; the standalone<->cluster flip (either direction, including the
#4179 config-less node) stays owned by `clusterTopologyCommitPreflight`.
An **intra-identity** edit (same node-id **and** cluster-id — a
redundancy-group / interface / policy change) passes untouched and
reconciles live.

### Live control-link moves are refused (#8965 address, #8987 interface)

Changing either half of the cluster control tuple on a **running** pair
partitions it, and the two halves fail identically.

`applyConfigLocked`'s step 20 stops cluster comms and restarts them on
the new endpoint; only then does the push to the peer run, over a
transport just rebuilt somewhere the peer is not listening.
**Nothing heals it:** `QueueConfig` no-ops on a nil connection so the
push fails *silently* rather than erroring the commit, the #5863
reconciler returns early on `!syncPeerConnected`, and that flag is set in
exactly one place — the session-sync connect callback — so it cannot
bootstrap a mismatch in which nothing is connected. Heartbeats carry no
config. Both nodes are durably configured, so **retry and reboot
reproduce the split rather than repair it**: the standby eventually
promotes on the stale tuple while this node stays primary on the new one,
and fencing cannot traverse the severed channel either. A commit whose
purpose was to preserve HA is what removes it.

Both are refused by a preflight rather than staged, and the reason is
structural: three apply paths reach `applyConfigLocked`
(`commitAndApply`, `syncAndApply`, `commitConfirmedAndApply`), so a
make-before-break would have to be correct at each and a version landed
at one would leave the others silently broken. **You cannot move both
ends of a point-to-point control link atomically from one end of it.**

- `clusterControlEndpointCommitPreflight` — the peer **address** (#8965).
- `clusterControlInterfaceCommitPreflight` — the control **interface**
  (#8987). #8965 shipped without this half and recorded why: the manager
  kept no *running* value for `control-interface`, so a gate would have
  compared config to config and could not tell "the operator is changing
  it" from "this is what it already was". `Manager.HeartbeatControlInterface()`
  now returns the interface the running heartbeat was started on,
  recorded from the same `StartHeartbeat` call that records
  `hbLocalAddr` / `hbPeerAddr`, and carried across a restart.

  It is deliberately **not** `m.controlInterface`: that field is also an
  interface name, but `UpdateConfig` overwrites it on every config apply,
  so it tracks the config and a gate reading it compares the candidate
  against itself. Nor is `hbLocalAddr` a proxy — an operator who moves
  the control link to another interface and carries the same address
  across leaves it unchanged.

**#9178 — the address gate passed the DELETION case.** #8965's decision
returned nil whenever *either* side was empty, on the reasoning that
"unset on either side means there is no live endpoint to strand". That
sentence is true for `have == ""` — an **addition**, where the heartbeat
has not started — and **false** for `want == ""`, a **deletion**, where
the live endpoint being stranded is the one being removed. Two of the
four `(have, want)` combinations were decided by a justification that
covered one of them.

Severity is set by the fabric, not by the deletion:

- **With `fabric-interface` + `fabric-peer-address`**, `clusterSyncTransport`
  falls back to the fabric, so the config push still has a transport and
  the deletion **propagates**. The heartbeat dies on both nodes — which
  is what the operator asked for — and there is no partition. Admitted.
- **On a control-link-only cluster**, which the strict compiler gate
  accepts, there is no fallback: no heartbeat **and** no sync transport.
  That is exactly #8965's apply-then-push partition, and it is durable
  because the peer never learns why. Reachable with an ordinary
  `delete chassis cluster peer-address` followed by `commit`. Refused.

The decision is now **total** over the four combinations, with the fabric
fallback passed in as a third argument — it is a property of the
*candidate config*, not of the two addresses, which is why the gate could
not stay a two-string function and be total at the same time.

`fabricFallbackConfigured9178` mirrors the condition
`daemon_ha_sync.go` actually gates the sync goroutine on —
`syncIface != "" && syncPeerAddr != ""` — **not** the transport label.
`clusterSyncTransport` returns `"fabric"` whenever the control link is
incomplete, *including when the fabric is incomplete too*, so a check
reading the label would report a transport that never starts and admit a
deletion into a config with no sync at all.

**Peer-sync is a no-op for both, for *different* reasons**, and the
distinction matters because assuming #8965's reason transferred would
have refused legitimate syncs. `peer-address` is **per-node** — each
node's config names the other's address, so a synced text compiles to
the local node's own value. `control-interface` is not per-node at all:
in the shipped cluster config (`docs/ha-cluster-userspace.conf`)
`peer-address` sits *inside* `groups node0` / `groups node1` while
`control-interface em0` sits *outside* them, one shared value, so a
synced text carries the identical string.

Each refusal **names the procedure** — set the new value on both nodes
and restart `xpfd` on both, or take the cluster down first — and warns
explicitly against committing on each node separately while both run,
which is the same partition by hand. A refusal without a path sends the
operator to the workaround that reproduces the defect.

### And the set those two were keyed on was the wrong one (#9121)

Both gates above read the **heartbeat** pair — `HeartbeatPeerAddr()` and
`HeartbeatControlInterface()`. What a partition strands is the **config
push**, and the push rides the *config-sync* endpoint, which
`clusterSyncTransport` selects: the control link when
`control-interface` **and** `peer-address` are both set, else the
**fabric** (`fabric-interface` / `fabric-peer-address`, the legacy
shape).

In control-link mode those two sets coincide exactly, and control-link
mode is the only shape the shipped fixtures configure
(`docs/ha-cluster-userspace.conf`, `test/incus/loss-userspace-cluster.env`),
so nothing measured the divergence. On a **fabric-transport** cluster
they come apart completely: the heartbeat does not start at all in that
shape, so the running value both gates compare against is empty, both
take their "nothing live to strand" arm, and both return no-op **on the
very commit that partitions the pair**. The gate misses twice.

`clusterSyncEndpointCommitPreflight` (#9121) closes it by comparing
resolved **endpoints** rather than fields: it runs `clusterSyncTransport`
over the running transport key and over the candidate config and refuses
when the selected endpoint moves. Using the same selector on both sides
is structural — a hand-copied fallback rule would drift from the one that
actually picks the transport, which is this family's entire history.

Three consequences worth stating, because two of them are not obvious:

- **`fabric1` is deliberately NOT gated.** `clusterTransportKey` includes
  `fabric1-interface` / `fabric1-peer-address` and is right to — it
  answers "does step 20 restart comms?". But fab1 is a *redundant*
  secondary sync path (`pkg/cluster/sync_conn.go` falls back with
  "secondary fabric listen failed, using primary only"), so a fab1-only
  change restarts comms while the push still lands over fab0. Refusing it
  would be a **false rejection**. The gated set has to be derived from
  the transport *selector*, not copied from the restart *trigger*.
- **A transport-TYPE switch is covered for free.** Adding a control link
  to a running fabric-transport cluster, or removing one, moves sync from
  one transport to the other while the peer is still on the first — the
  same durable partition by a different edit. Neither #8965 nor #8987 can
  see it (their running value is empty on one side of the switch).
- **A control-link-to-control-link move stays with #8965/#8987**, which
  run first at all three apply paths and produce the specific text for
  it. Two refusals in different words for one commit is worse than one.

**Peer-sync is a no-op here too, per arm and for different reasons.**
`fabric-peer-address` is safe for #8965's reason — it sits *inside*
`groups node0` / `groups node1` in the shipped cluster config, directly
beside the per-node `peer-address`, so a synced text compiles to the
local node's own value. `fabric-interface` is safe for #8987's reason
instead — it is auto-derived from the local fabric member
(`compiler_derivations.go` keys on `SlotToNodeID(slot) == cc.NodeID`), so
both nodes carry the identical name.

### Acceptance criteria (identity change, #6192)

- A day-2 commit that changes `chassis cluster node-id` or `cluster-id`
  on a running clustered node (`d.cluster != nil`) is rejected with a
  restart-required diagnostic before store promotion; the candidate is
  not promoted.
- An intra-identity commit (same node-id and cluster-id) is unaffected.
- The standalone<->cluster transition remains owned by the #5840
  topology gate; the identity gate is a no-op when there is no running
  manager or the candidate is standalone.
- No legitimate boot/bootstrap or steady-state peer-sync path is falsely
  rejected: the boot LOAD reaches `applyConfigLocked` (not
  `commitAndApply`), a bootstrap plain commit is refused earlier by
  `inBootstrap()`, and a synced commit compiles for the local node so
  node-id resolves to this node's running id and cluster-id is the shared
  value.
