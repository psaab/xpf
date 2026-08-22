# Session Sync Architecture

## Overview

xpf HA clusters synchronize stateful firewall sessions between two nodes so
that a new primary can continue forwarding established flows after an RG move
or peer loss. Session sync rides a custom TCP protocol over the fabric link
(`fab0` / `fab1`).

The current implementation has four distinct pieces:

1. **Bulk sync** — cold transfer of the full owned session set on first
   connection after disconnect and when a different fabric transport becomes
   active.
2. **Incremental sweep** — periodic scan of kernel session maps for new or
   changed sessions.
3. **Userspace deltas** — low-latency event drain from the AF_XDP helper for
   userspace-managed sessions.
4. **Demotion handoff** — before graceful failover the demoting node writes a
   single ordered peer barrier (`WaitForPeerBarrier`) and waits for the ack, so
   demotion does not proceed until the peer has processed every delta already
   queued onto the sync stream.

The older mental model of "bulk once, then background sweep" is incomplete.
Current failover safety depends on sender-side bulk acknowledgement, the
continuous lossless userspace event stream (with gap OR undecodable session
frame → full-resync, see #2874 / #5483), the demotion peer barrier, and filtered
userspace delta replication.

## Session Representation

### BPF Maps

Sessions live in two BPF hash maps:

- `sessions_v4` — IPv4 sessions
- `sessions_v6` — IPv6 sessions

Each logical session has two entries:

- forward entry: `IsReverse = 0`
- reverse entry: `IsReverse = 1`

Only forward entries are sent on the wire. The receiver recreates the reverse
entry locally.

### Session Value

The session value includes state, policy, timestamps, counters, NAT fields,
reverse key, and a cached forwarding result (`FibIfindex`, MACs, VLAN,
generation). It also carries a `ConfigEpoch` (#5274) — the config-sync
generation (#3931) the sender held when it queued the session — used by the
receive-side config-epoch guard (see "Config-Epoch Guard" below), and a
`RTFlowSessionID` (#5212) — the ORIGINATING node's stable RT_FLOW session id
(`SessionTable::alloc_session_id`, distinct from the node-local BPF-ABI
`SessionID`) — which the importing node ADOPTS so a session's RT_FLOW
SESSION_CREATE (origin node) and SESSION_CLOSE (peer, after failover) share one
correlatable id across HA nodes (see "RT_FLOW Session Id" below). All three of
`Generation`, `ConfigEpoch`, and `RTFlowSessionID` are userspace-sync-only
metadata carried as length-gated trailing wire fields; none is part of the on-map
BPF conntrack ABI (`bpfSessionValue`).

`IngressIfindex` / `IngressVlanID` (#4983 — the interface a session's first
packet arrived on) are the opposite case on both counts: they ARE part of the
on-map C conntrack ABI, and they are deliberately NOT synced. An ifindex is
node-local — node 0's `ge-0-0-1` and node 1's `ge-7-0-1` are different numbers
for the same logical RETH member — so carrying the originating node's value
would make `show security flow session interface <name>` name the WRONG
interface on the importing node, which is worse than approximating. A
peer-synced session therefore lands in the "no ingress identity carried" (`0`)
branch — alongside the reverse companion and the host-outbound GRE path — and
the CLI answers it from the ingress zone, exactly as it did before #4983.

That branch does NOT include "a pre-#4983 session" (#6928, corrected): a new
daemon can never read one. `sessions` / `sessions_v6` are in the shim ABI
pre-flight's checked set and `validateUserspaceShimLivePins` hard-refuses a
`ValueSize` mismatch against the live pin, so the old-format rows are either
already gone with the unpinned map or the load is refused outright. See "True
ingress-interface identity on the session (#4983)" in
`userspace-dp/src/session/README.md`.

### Userspace Mirror

When the userspace dataplane is active, cluster-synced forward sessions are
installed into both places:

- the kernel/BPF session maps
- the Rust helper session table via the userspace manager RPC path

`SetClusterSyncedSessionV4()` / `SetClusterSyncedSessionV6()` do both. Before
install, they clear the cached FIB result so the receiving node recomputes
node-local forwarding.

**#5305 — the forward install is transactional.** A forward cluster-synced
install writes the pinned BPF session mirror FIRST, then mirrors the entry to
the Rust helper. If the helper mirror fails (connect/write/decode), the install
RESTORES the BPF pre-image before returning — it rewrites the prior value, or
DELETES the key if it was absent — so a failed install leaves the BPF map
exactly as it was. Without this, the pinned map would hold a session the helper
never received: a split truth the GC and the fallback bulk export
(`ExportOwnerRGSessions`) would propagate as if the install had succeeded,
producing nondeterministic HA session ownership after takeover. The pre-image
snapshot, the BPF write, the helper mirror, and the compensating restore all run
under `m.mu`, so the sequence is atomic against any other `m.mu`-holding path;
the per-peer receiver apply loop is single-threaded (`installClusterSyncedV4` in
`pkg/cluster/sync_conn.go`), so no concurrent install of the same key races. The
existing health behavior is preserved: `recordSessionMirrorFailureLocked` still
fires on the failure (takeover stays disarmed until the socket is proven healthy
again), and `recordSessionMirrorSuccessLocked` still clears the sticky #5247 flag
only on a genuine success. This is distinct from #5247/#5255, which self-heal the
sticky mirror-failed flag but do NOT restore the BPF pre-image. Reverse entries
are never mirrored to the helper (it synthesizes the reverse companion locally),
so they take no compensation — they only write the BPF mirror.

The pre-image snapshot's *absent* classification (`snapshotBPFSessionV4Locked` /
`snapshotBPFSessionV6Locked` → `bpfSessionReadAbsent`) accepts the SAME
key-not-found error set as the Layer-1 `dataplane.sessionNotFound` predicate —
`ebpf.ErrKeyNotExist` OR `unix.ENOENT`, via the shared `dataplane.IsKeyNotFound`
helper (#6194) — so both transaction layers agree on what "key absent" means.
Any OTHER read error is surfaced and the install is refused (the fail-safe
direction): the snapshot never guesses a pre-image it could not read. With the
production cilium `bpfShim` the two sentinels never diverge (a missing lookup
yields `ErrKeyNotExist`, not bare `ENOENT`), so this is a consistency fix rather
than a live-bug fix.

Locally-created forward sessions take a parallel path: `SetSessionV4()` /
`SetSessionV6()` install into the kernel/BPF maps, then mirror the forward
entry **and a pre-installed reverse companion** (#310 — so the helper holds the
reverse before RG activation, avoiding activation-time synthesis) to the local
Rust helper over the session control socket. Both requests resolve
egress/zone/tunnel-endpoint metadata from `m.lastSnapshot` and the compile
result. **#5007 invariant: the forward/reverse pair MUST be resolved against
ONE consistent snapshot.** The mirror helpers (`mirrorSessionPairV4` /
`mirrorSessionPairV6`) build BOTH `SessionSyncRequest`s under a single
uninterrupted `m.mu` hold — completing every snapshot read *before* any socket
I/O drops the lock — then transmit both. This preserves the deliberate "session
installs must not block snapshot publishes" property while closing the window
where a concurrent `ApplyConfig` (which swaps `m.lastSnapshot` under `m.mu`)
could make the reverse companion resolve against a different snapshot than the
forward.

**#5698 invariant: the pair's transmit must be CONTIGUOUS.** The `m.mu` unlock
above is about snapshot publishes and says nothing about session-socket
ordering — the two locks are independent. The general batch transmit
(`syncSessionRequestsLocked`) takes `m.sessionMu` once per REQUEST, so the lock
is free between consecutive requests and any other session-socket caller (an
operator clear, a policy invalidation, a GC delete, a stale-session
reconciliation) can land between a pair's forward and its reverse. A
generation-0 forward delete arriving in that gap removes BOTH halves in the
helper, and the pair's already-built explicit reverse then re-creates a
standalone reverse-only permit. The pair mirrors therefore transmit through
`syncSessionPairLocked`, which takes `m.sessionMu` ONCE for the whole pair.

That contiguous hold is deliberately capped at `sessionPairMaxRequests` (2, the
forward plus its reverse companion). Bulk paths — the delete chunks up to
`sessionHelperDeleteChunk` (256) and the authoritative clear-all — keep the
per-request discipline on purpose: holding `m.sessionMu` across a 256-request
chunk would starve live session installs for minutes, which is exactly the harm
the #5380 fast-fail exists to bound. An over-cap group falls back to the
per-request path (logged) rather than trading a rare interleave for an install
stall.

**Residual, not closed by #5698:** the pair's transmit is contiguous, not
atomic. If the SECOND request fails at the transport layer the helper keeps a
half-installed pair; nothing rolls the first half back. Closing that needs a
helper-side pair transaction on the wire.

That is only one direction of the userspace integration. Locally-created
userspace sessions do **not** flow back through `SetClusterSyncedSession*`.
They are exported through:

- the continuous userspace event stream (steady state), or its
  `DrainSessionDeltas(...)` fallback poll when the stream is down
- a one-shot `ExportOwnerRGSessions(...)` bulk republish, triggered by an
  event-stream **FullResync** (a #2874 sequence gap or a #2442 delta-ring
  overflow) — **not** by the demotion-prep path

## Wire Protocol

### Transport

Session sync uses TCP over the fabric overlays:

- `fab0` — primary fabric
- `fab1` — optional secondary fabric

When a management VRF (`vrf-mgmt`) is configured, sockets are bound to it with
`SO_BINDTODEVICE`; otherwise they use the default routing table. One
deterministic side initiates per fabric. `TCP_NODELAY` is enabled.

### Header

```
[0:4]   Magic "BPSY"
[4]     Type (uint8)
[5:8]   Reserved
[8:12]  Payload length (uint32, little-endian)
```

### Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| 1 | SessionV4 | Primary -> Secondary | Incremental IPv4 add/update |
| 2 | SessionV6 | Primary -> Secondary | Incremental IPv6 add/update |
| 3 | DeleteV4 | Primary -> Secondary | IPv4 delete |
| 4 | DeleteV6 | Primary -> Secondary | IPv6 delete |
| 5 | BulkStart | Primary -> Secondary | Start of bulk transfer |
| 6 | BulkEnd | Primary -> Secondary | End of bulk transfer |
| 7 | Heartbeat | Bidirectional | Keepalive |
| 8 | Config | Primary -> Secondary | Full config text |
| 9 | IPsecSA | Primary -> Secondary | IPsec connection names |
| 10 | Failover | Bidirectional | Remote failover request |
| 11 | Fence | Bidirectional | Peer fencing |
| 12 | ClockSync | Bidirectional | Monotonic clock exchange |
| 13 | Barrier | Primary -> Secondary | Ordered demotion marker |
| 14 | BarrierAck | Secondary -> Primary | Barrier acknowledgement |
| 15 | BulkAck | Secondary -> Primary | Bulk acknowledgement |

## Bulk Sync

### When It Triggers

Bulk sync is started when:

- the first session-sync connection appears after a total disconnect
- a different fabric connection becomes the active transport

On first connection after disconnect, the transport setup order is:

1. flush the delete journal
2. fire `OnPeerConnected`
3. start `BulkSync()`

That order matters because reconnect readiness and retry state are reset before
the new bulk is sent.

### Send Side

`BulkSync()`:

1. allocates a new monotonically increasing epoch
2. sends `BulkStart(epoch)`
3. iterates `sessions_v4` / `sessions_v6`
4. skips reverse entries
5. skips sessions not owned by this node for the ingress zone
6. sends forward entries only
7. records `pendingBulkAckEpoch` (**before** the `BulkEnd` write)
8. sends `BulkEnd(epoch)` and then waits for peer acknowledgement

The sender now treats outbound bulk acknowledgement as first-class state. A
bulk transfer is not considered fully primed until the peer returns `BulkAck`
for the current epoch.

**Record-then-send ordering (#3912).** `pendingBulkAckEpoch` must be stored
*before* the `BulkEnd` marker is written to the wire, not after. `BulkEnd` is
what solicits the peer's `BulkAck`, and the ack is processed on the read
goroutine (`handleMessage`, `syncMsgBulkAck`) independently of the send
goroutine. If the pending epoch were recorded *after* the write, a peer that
acked faster than the send goroutine could record the pending state would have
its ack processed against `pendingBulkAckEpoch == 0` — the ack handler's
`pending != 0` guard drops it — and the send goroutine would then latch a
phantom pending epoch that no future ack ever clears. A latched phantom epoch
permanently blocks manual failover, because the readiness gate waits on an
outbound bulk ack that already arrived. Recording first (mirroring the
#2170/#2198 gen-guard record-then-send discipline) guarantees an early ack can
only ever observe the pending epoch already in place, so it clears it
regardless of arrival timing. On a `BulkEnd` write failure the epoch is reset
to 0 (and `handleDisconnect` also clears it), so a failed send cannot leave the
pending state falsely armed. The same ordering applies to the empty-marker
`sendBulkMarkers` path used after event-stream export.

### Receive Side

On `BulkStart` the receiver:

- snapshots zone ownership for stale-session reconciliation
- resets the per-bulk receive tracking maps
- marks bulk in progress

For each received session it:

1. decodes key/value
2. tracks the forward key in the current bulk receive set
3. rebases timestamps into local monotonic time
4. clears cached FIB resolution
5. installs the forward entry through `SetClusterSyncedSession*`
6. creates and installs the reverse entry locally
7. recreates any SNAT `dnat_table` entry locally

On `BulkEnd` the receiver:

1. verifies the epoch
2. reconciles stale sessions using the frozen ownership snapshot
3. sends `BulkAck(epoch)`
4. fires `OnBulkSyncReceived`

### Stale Session Reconciliation

After a bulk completes, the receiver deletes sessions that are still present
locally but were not refreshed by the peer for zones that the frozen snapshot
says are peer-owned.

Important detail: zones missing from the frozen snapshot are conservatively kept
instead of deleted.

### Config-Epoch Guard (#5274)

The receiver applies a synced session install (bulk or incremental) through
`installClusterSyncedV4`/`V6`. Before it forwards the install to the dataplane
it runs two independent admission checks:

1. **Install-generation guard (#2170)** — per-key: refuse a strictly-older
   `Generation` for the same 5-tuple so the per-key stored generation never
   regresses (`InstallsStaleIgnored`).
2. **Config-epoch guard (#5274)** — global: refuse a session whose
   `ConfigEpoch` is strictly older than the receiver's `lastAppliedConfigGen`
   (`SessionsStaleConfigIgnored`).

The config-epoch guard closes the immediate-policy-invalidation gap across the
HA boundary. Without it, the primary could admit a session under config A, then
commit config B (which DENIES that session); config B is config-synced and
applied on the standby (running `clearSessionsForDeletedPolicies`), but a
delayed config-A session install that arrives **after** that sweep is installed
anyway — a stale permit. The standby would then forward under the revoked
config-A decision after failover.

The epoch is stamped by the SENDER at queue time (`stampInstallGen*` sets
`ConfigEpoch = configGenCounter.Load()`), and compared by the RECEIVER against
`lastAppliedConfigGen`. Both live in the **same** #3931 config-sync-generation
namespace (the sender's monotonic counter, which the receiver applies and
records), so the comparison is meaningful across nodes. A session still present
in the sender's table when it is queued has survived the sender's own
config-apply sweep, so it is legitimately admitted under the current config; the
receiver refuses it only once IT has applied a **strictly newer** config that
supersedes the stamped epoch. `ConfigEpoch == 0` (a pre-#5274 peer, or a
local-origin entry) disables the check — rolling-upgrade safe. On reconnect the
receiver resets `lastAppliedConfigGen` to 0 (`resetRecvGen`), so bulk re-sync
after a peer reboot is never falsely rejected (the reset makes the compare
baseline 0 until the peer re-pushes its current config).

**Enforcement is authoritative in the Go cluster layer, not the userspace
helper.** The #3931 config-sync-generation namespace lives entirely in
`SessionSync`; the helper's own `config_generation` is a *local* commit counter
(`Manager.bumpGeneration`) whose value is independent per node and therefore not
cross-node comparable. The receiver rejects a stale-epoch install BEFORE it ever
reaches the helper, so the helper needs no config-epoch field or guard. This
guard covers the config-authority → peer direction (the issue's scenario, where
the primary that admits the session is also the RG0 config-sync authority); a
non-authority's sessions carry the authority-independent seed epoch and the
guard is inert for them (no false reject), which is acceptable because config
changes originate on the authority.

#### Apply-in-progress fence — sweep-vs-advance window (#6284, item 2)

The bare epoch compare above (`ConfigEpoch < lastAppliedConfigGen`) closes the
gap only once `lastAppliedConfigGen` has advanced — but the high-water advances
**after** `OnConfigReceived` returns, while the deleted-policy sweep
(`clearSessionsForDeletedPolicies`) runs **inside** it. That leaves a residual
sub-µs window on the receiver: the moment between the sweep completing and the
high-water advancing. A session install racing on the `receiveLoop` in that
window is compared against the STALE high-water and wrongly admitted — reviving
exactly the permit the just-run sweep invalidated.

The apply-in-progress fence (`applyingConfigGen`) closes it. The single-consumer
`configApplyLoop` raises the fence to the generation it is about to apply
**before** calling `OnConfigReceived` (so it covers the whole apply, including
the sweep) and lowers it to 0 only **after** the high-water advances on success
(or immediately on an apply failure). `configEpochStale` refuses against
`max(applyingConfigGen, lastAppliedConfigGen)`, reading the fence **first** so
that on the success release order (high-water stored, then fence cleared) a
reader observing `fence == 0` has necessarily already observed the advanced
high-water — the effective refusal threshold never dips across the window.

Ordering and correctness:

- **No stale permit.** From before the sweep starts until the high-water
  advances, an install stamped with an epoch older than the applying generation
  is refused, so it can never land after the sweep against a stale high-water.
- **No false reject.** The fence refuses only STRICTLY-older epochs. A session
  the peer stamped with the CURRENT generation (equal to the one being applied)
  is still admitted, exactly like the post-advance steady state; a transiently
  refused older session is re-sent by the peer's next sweep.
- **Apply failure.** The high-water deliberately stays put (M-2/#4151) and the
  fence simply drops, restoring the pre-apply admission posture — the fence is
  never held against a generation that never took effect.
- **Bulk re-prime.** `resetRecvGen` clears the fence alongside the high-water so
  a rebooted peer's lower-generation re-prime is accepted (the same
  accept-everything reset the high-water already performs).

**Item 1 (deferred, documented residual).** The guard still covers only the
config-authority → peer direction (the primary that admits the session is also
the RG0 config-sync authority). A non-authority's sessions carry the
authority-independent seed epoch, so the guard is inert for the reverse
direction in an active/active deployment (fail-OPEN). Closing it requires a
bidirectional config-generation namespace that #5274 deliberately scoped out (a
design-heavy change, not part of #6284 item 2). #6284's residual-COVERAGE gap
is closed (item 2 by #6366, item 1 by #6418); the substantive hardening of this
inert direction is tracked separately as a future enhancement on #6419.

Both halves of this directional correctness are regression-pinned by
`sync_config_epoch_active_active_6284_test.go`: the SAME frozen non-authority
epoch is REFUSED at a receiver that applied a newer config (the protected
config-authority → peer direction) and ADMITTED at the config authority (whose
receive high-water never advances — the inert fail-OPEN reverse direction), and
the sender-side root cause is pinned too (`recordAppliedConfigGen` advances the
receive high-water but never the send-stamp `configGenCounter`, so a
non-authority stamps its synced-out sessions with the frozen boot-seed epoch).

### RT_FLOW Session Id (#5212)

The dataplane assigns each session a STABLE id (`SessionTable::alloc_session_id`)
that it stamps on its RT_FLOW SESSION_CREATE/SESSION_CLOSE records (#4915). That
id is node-local: before #5212 a peer-synced session was assigned a FRESH id on
import, so a session that opened on the primary and closed on the standby after a
failover carried DIFFERENT ids on the two nodes, breaking cross-node log/event
correlation. #5212 carries the originating node's id on the session-sync wire as
a length-gated trailing `RTFlowSessionID uint64` (appended after the #5274
`ConfigEpoch`), and the importing node ADOPTS it.

Unlike the config-epoch guard, this is pure identity carriage — the receiver
never rejects on it. The path is: the Rust dataplane harvests the id onto
`SessionDelta.session_id` and writes it as the trailing field of the
`MSG_SESSION_OPEN` event-stream frame; the daemon decodes it into
`SessionDeltaInfo.RTFlowSessionID` and stamps `SessionValue{,V6}.RTFlowSessionID`
(distinct from the node-local BPF-ABI `SessionID`, which since #6198 is minted
per converted session by `nextUserspaceSyncedSessionID` — see "Node-Local
BPF-ABI Session Id" below);
`SessionSync` carries it as the trailing wire field; the peer daemon forwards it
on `SessionSyncRequest.session_id`; and the peer helper's
`upsert_synced_with_origin` ADOPTS it (stamping the imported `SessionEntry`)
instead of allocating a fresh local id. A zero id (legacy peer / no live entry)
falls back to `alloc_session_id()` — rolling-upgrade safe. Because the id is
worker-namespaced, adopting the peer's id verbatim keeps it unique across the
importing node's shared-nothing worker tables. The standby's SESSION_CLOSE
RT_FLOW then correlates with the primary's SESSION_CREATE.

### Node-Local BPF-ABI Session Id (#6198)

`SessionValue{,V6}.SessionID` is the *other*, node-local id: the on-map BPF
conntrack ABI field. It is NOT a lookup key — forwarding matches the 5-tuple
`SessionKey` — and it is NOT carried to the peer helper (`buildSessionSyncRequest`
forwards only `RTFlowSessionID`). Its blast radius is display and correlation:
it rides the session wire, and on the receiving node `SetClusterSyncedSessionV4/V6`
writes it into the BPF conntrack mirror, where `show security flow session`
(`flowSessionDisplayID`), the REST session views, and the gRPC session RPCs
surface it.

Until #6198 the userspace converters synthesized it as
`uint64(now)<<16 | uint64(delta.Slot&0xffff)`. Both halves were wrong:

- `delta.Slot` is the AF_XDP **binding** slot (`BindingIdentity.slot`, one per
  interface/queue — a handful per node), not a session-table slot. The `&0xffff`
  mask was therefore unreachable in practice.
- The binary event stream that carries the primary delta path never decodes
  `Slot` at all (`decodeSessionEvent` leaves it `0`), so the low half was a
  constant.
- `now` is CLOCK_MONOTONIC **seconds**. Every session converted within one
  second collapsed onto ONE id, conflating unrelated flows wherever the id is
  displayed.

`nextUserspaceSyncedSessionID` replaces it with a node-local monotonic counter in
a reserved namespace: `0xFFFF << 48 | counter48`. The namespace keeps the
control-plane-minted ids disjoint from the dataplane ids the helper stamps into
the same mirror field (`(worker_id & 0xFFFF) << 48 | counter48`, worker ids being
tiny queue indices), so the two writers can never alias. That reservation is a
cross-language invariant, and it is ENFORCED on the Rust side rather than merely
recorded: `SessionTable::set_worker_id` asserts a worker id never lands on
`CONTROL_PLANE_SESSION_ID_WORKER_HI`. A hard `assert!`, not `debug_assert!` —
`make test-rust` and the shipped helper both build `--release`, where a debug
assertion is stripped and would guard nothing — and worker setup is config time,
where `docs/engineering-style.md` prefers crash-start over running with a wrong
invariant. The counter never
returns `0` — that is the established "unknown id" sentinel that makes
`flowSessionDisplayID` fall back to the per-row ordinal.

The counter is **seeded from the boot clock** on first use
(`userspaceSyncedSessionIDSeed`, `monotonic_nanos >> 10` masked to 48 bits).
Without a seed, an xpfd restart would re-mint `1, 2, 3…` and collide with entries
the peer's mirror still holds from the previous incarnation — sessions this node
closed while it was down, whose keys the post-restart bulk re-export never
overwrites. The old `now<<16|Slot` composition did not have that flaw, because
CLOCK_MONOTONIC is system uptime and keeps increasing across a daemon restart, so
seeding is what keeps the change a strict improvement rather than a trade.

The seed reads **nanoseconds, not seconds**. A second-resolution read gives two
incarnations whose first allocations land in the same integer second an identical
seed, and they then repeat from their very first id — and that is the common
restart, not the exotic one: systemd's `RestartSec=1` lands inside the window, and
the sub-second phase is uniform, so on average half of all restarts do. At
`>> 10` the seed granularity is ~1.024 µs, three orders of magnitude below the
teardown+exec of any real restart. The seed advances ~976,562 per second of
uptime, so a restarting incarnation starts above its predecessor's high-water mark
unless that predecessor *averaged* more than ~976k synced conversions per second.
The 48-bit seed space covers ~9.1 years of uptime before it cycles, and a cycle can
only alias ids from an incarnation that old.

The counter advances by **CAS, not a bare `Add`**, so the value stored is the value
returned. The counter must skip the reserved `0`, and the skip has to be committed:
`Add(1) & mask; if counter == 0 { counter = 1 }` corrects only the local copy, so at
the wrap the atomic still holds the masked-zero value and the NEXT call returns the
id just handed out. The duplicate stays inside the namespace, so nothing downstream
looks wrong — uniqueness just silently stops holding. The wrap is reachable rather
than theoretical, because the seed itself consumes counter space and the distance to
the boundary depends on uptime phase. Ringing is the right behaviour there: a wrap
re-mints only ids this incarnation issued 2^48-1 conversions ago (the ring skips
the zero counter, so 2^48-1 values are usable, not 2^48), or ids from an
incarnation whose entries are long gone. Refusing to mint would be worse — the id is
display-only, but the conversion carrying it installs an HA-synced session, so
failing it to protect a display field would trade a cosmetic alias for lost sessions
at failover.

The id is distinct per **conversion**, not stable per session. A bulk resync
re-converts live sessions and re-stamps them with fresh ids, and the `close`
branch of `queueUserspaceSessionDeltas` converts purely to derive the key and
discards the id it mints. Both are harmless in a 48-bit space, and the old
composition churned the id the same way — what changed is that concurrent
sessions no longer *share* one.

The fabric-redirect forward-wire alias entry (`userspaceForwardWireAliasV4/V6`)
takes the ALREADY-CONVERTED base session rather than re-converting the delta, so
the alias and its base — two conntrack keys for one logical session — share one
id. Re-converting would mint a second.

This id stays deliberately node-local; the cross-node correlatable id is the
separate `RTFlowSessionID` above. Regression coverage:
`TestUserspaceSyncedSessionID*6198` in `pkg/daemon`.

## Sync Readiness and Bulk Priming

This is the biggest place where older descriptions are wrong or incomplete.
There are now two distinct readiness signals:

- `syncBulkPrimed` — we received the peer's current-generation bulk
- `syncPeerBulkPrimed` — the peer acknowledged our current-generation bulk with
  `BulkAck`

They are not the same thing.

### Connection Lifecycle

On peer connect:

- `syncBulkPrimed = false`
- `syncPeerBulkPrimed = false`
- cluster sync readiness is forced false
- a guarded readiness timeout is armed
- a bulk-prime retry loop starts

On bulk receive:

- `syncBulkPrimed = true`
- the readiness timeout is stopped
- VRRP sync hold is released
- cluster sync readiness becomes true

On bulk ack receive:

- `syncPeerBulkPrimed = true`

On disconnect:

- both primed flags are cleared
- cluster sync readiness is forced false
- the readiness timeout is invalidated with a generation guard so a stale timer
  callback cannot flip readiness back to true after disconnect

### What cluster sync readiness does NOT do (#7102)

It is not a promotion gate. Nothing in the RG readiness conjunction
(`ifReady && takeoverGateReady && fabricReady && userspaceReady`,
`pkg/daemon/daemon_ha_userspace_readiness.go`) reads
`cluster.Manager.syncReady`; in no-RETH / private-rg-election mode
`takeoverGateReady` is VIP ownership alone. A node in that mode can take over an
RG before bulk sync completes. The gate that did read it — `vrrpReady =
d.cluster.IsSyncReady()`, reporting `session sync not ready` as a takeover
blocker — was deleted in `0781f7a60` (2026-04-05, empty commit body); whether it
should return is **#110**, open. Today `IsSyncReady()` has exactly three
production readers: the readiness timeout in `daemon_ha_sync.go` and two log
fields.

The **VRRP sync hold** released above is a real preemption suppressor, but it is
a separate mechanism (`vrrp.Manager.SetSyncHold` / `ReleaseSyncHold`) armed only
in RETH VRRP mode — do not read the two as one thing because they are released
on the same edge.

### Pre-Auth Connection Admission (#5303)

The accept loop admits every inbound connection into a small **pre-auth setup
pool** (`beginSetup` in `sync_admission.go`) *before* spawning its setup
goroutine. This closes the residual of the #4370 parallel-accept fix: a host on
the sync/control network could otherwise open connections at rate R and stall
each before authentication, and — because socket buffers were sized and a
goroutine spawned *before* the handshake — steadily pin FDs, goroutines, and
256 KiB-buffered sockets until a legitimate peer could no longer reconnect.

Three properties, all preserving #4370's parallel accept and the #4107 HMAC
handshake:

- **Bounded, with a reserved peer tail.** At most `preAuthSetupCap` (8)
  connections are in pre-auth setup at once. A flood from any address other
  than the configured peer can consume at most `preAuthSetupCap -
  preAuthPeerReserve` (6) slots; the reserved tail (2, one per fabric) is
  usable only by connections whose remote IP matches a configured peer fabric
  address, so a flood can never deny the legitimate peer a reconnect slot.
  Excess connections are closed immediately and bump `PreAuthRejected`
  (rate-limited warning). The reservation matches on peer **IP** only (the peer
  dials from an ephemeral port); an attacker able to source-spoof the exact
  peer IP could reach the reserved tail but still cannot pass the HMAC
  handshake, and the general-pool cap already bounds the total resource cost.
- **Cheap pre-auth sockets.** The large (256 KiB) read/write socket buffers
  (`configureSessionSyncConn`) are sized only **after** the handshake succeeds,
  not at accept — so a pre-auth connection costs a bare FD until it proves
  possession of the PSK. The admission slot is released the moment the
  handshake resolves (`finishSetup`), so it covers only the brief pre-auth
  window, never the subsequent bulk sync.
- **Clean shutdown.** Every in-flight setup connection (inbound *and* our own
  outbound dials) is tracked so `Stop()` closes them (`closeSetupConns`),
  unblocking a stalled handshake read instead of waiting out the 5s shutdown
  budget. Outbound dials bypass the cap (they are our own, bounded to one per
  fabric) but are still tracked for this shutdown close.

### Bulk-Prime Retry Loop

After reconnect, the daemon retries `BulkSync()` if the peer never acknowledges
our current-generation bulk.

Important current behavior:

- retries stop once `syncPeerBulkPrimed` becomes true
- retries are deferred while the current bulk is still waiting for `BulkAck`
- retries are also deferred while inbound sync progress is still advancing
- retries stop if the connection is replaced or disconnected

This exists because failover admission now depends on the standby having both
sides of the current-generation baseline, not just having received one bulk.

### Reconnect Re-Prime (#5480)

On the **first connection after a full (both-fabric) disconnect**
(`handleNewConnection`, `wasDisconnected == true`), the survivor **always**
re-pushes its authoritative session table (`doBulkSync`) — it no longer gates
that bulk on the sticky, process-local `bulkEverCompleted` flag.

The old gate (`coldStart := !bulkEverCompleted.Load()`) skipped the bulk on any
reconnect once the survivor had completed one bulk. But `bulkEverCompleted` is
sticky and per-process: when the **peer** daemon rebooted, its session table AND
its own flag reset, yet the survivor's flag stayed true — so the survivor logged
"skipping bulk sync on reconnect (already primed)" and never re-primed the peer.
The rebooted standby then held **no** synced sessions and blackholed every
established flow on the next failover to it.

The survivor cannot locally tell a rebooted peer (empty table, needs priming)
from a pure fabric flap (peer kept its table): the sync handshake
(`performSyncHandshake`) carries no peer-cold / boot-incarnation / session-count
signal, and an unkeyed dual-accept peer sends no HELLO at all. So it re-primes
unconditionally. Re-priming is safe and idempotent — the receiver upserts every
session and `reconcileStaleSessions` (run at `BulkEnd`) prunes anything the
survivor no longer owns — and a both-fabric outage may have dropped incremental
deltas anyway, so the "already primed" assumption does not hold even for a peer
that never rebooted.

Cost and scope: this fires **only** on a both-fabric down→up transition. A
routine single-fabric flip does NOT reach this arm (it hits the
`becameActive`/`else` branches, which still do not re-bulk), so the redundant
transfer is bounded to genuine full-reconnect events. This intentionally
reverses the pre-#5480 #466 "skip bulk on reconnect" optimization for the
`wasDisconnected` case: correctness (a rebooted standby must not blackhole) beats
one redundant bulk on a full-reconnect flap. A more surgical fix that keeps the
#466 flap-suppression would need a peer boot-incarnation field in the sync
handshake — a wire change tracked on #5480 and deferred.

### Atomic Install + Cold-Prime Decision (#4962)

Post-#4370 `handleNewConnection` runs **per-accept in its own goroutine**, so two
same-fabric accepts can race. The pre-#4962 code read `wasDisconnected` under
`s.mu` but **used it after unlock** to gate `OnPeerConnected` + `doBulkSync`.
From a fully-disconnected registry the two accepts interleave:

- **Accept A** observes the empty registry (`wasDisconnected`), installs `connA`,
  and starts cold-priming it.
- **Accept B** locks *after* A, observes `connA` (a **non-empty** registry),
  closes `connA` (aborting A's in-flight bulk), and installs `connB` as the
  surviving active connection.

Because B recomputed `wasDisconnected` from the post-supersession registry it saw
`false`, so B skipped cold-prime and hit the `becameActive` "resume incremental"
branch. The surviving connection `connB` therefore **never re-pushed the
authoritative session table** — the peer stayed un-primed and blackholed every
established flow on the next failover to it. (This is distinct from the #4090
survivor re-drive: when B closes `connA`, A's write failure calls
`handleDisconnect(connA)`, which is a **stale** disconnect — `conn0` is already
`connB` — so it is ignored and #4090 never fires.)

The fix makes the install and the cold-prime decision **atomic** under `s.mu`
(`installConn`, returning a `connColdPrimeDecision`), backed by a `needColdPrime`
latch:

- `needColdPrime` is armed under `s.mu` on a full-disconnect→connect edge (both
  fabric slots were empty) and **consumed only when a cold-prime bulk actually
  succeeds** (`doBulkSync() == nil`). On failure it stays armed.
- `shouldColdPrime = becameActive && needColdPrime`, both read under the same
  lock that installs the connection. A superseding same-fabric accept therefore
  **inherits** the outstanding obligation instead of dropping it, even though it
  observes a non-empty registry.

So in the race B now cold-primes `connB`. Both A and B may call `doBulkSync`;
they serialize on `bulkSendMu` and each targets `getActiveConn` (the survivor),
so the redundant attempt is idempotent — the same correctness-over-optimization
tradeoff as #5480. The latch also generalizes the #4090 intent into the accept
path: if a cold-prime never succeeded, the next connection that becomes the
active fabric re-drives it. Steady state is unchanged: once a cold-prime
succeeds the latch clears, and routine single-fabric flips (obligation
discharged) do not re-bulk.

`needColdPrime` is a plain `atomic.Bool` like `forceResync`; the narrow window
where a newer full-disconnect epoch's arm is cleared by an older epoch's success
self-heals via `forceResync` / the #4090 survivor re-drive / the next reconnect.

**The connected sweep is the third consumer (#82).** Both consumers above are
disconnect-edge triggered — `installConn` on a reconnect, `handleDisconnect` on
a survivor fabric. A cold-prime bulk that fails WITHOUT dropping the connection
therefore left the obligation armed with no consumer for the life of that
connection. `BulkSync`'s own preconditions produce exactly that shape: it
returns `session store not ready` (nil `s.sessions`) or `no peer connection`
before it writes a byte, so no `handleDisconnect` follows. The startup window is
the real trigger — `startClusterComms` used to call `ss.Start()` (which spawns
the accept/dial goroutines) and only then `ss.SetRuntime(rt)`, so a peer that
connected in between drove the cold prime against a nil session store.

The incremental sweep cannot cover for it: `StartSyncSweep` seeds
`lastSweepTime` to "now" and the sweep only queues sessions with
`Created >= threshold`, so every session that existed before the sweep started
is permanently invisible to it — and only a `BulkStart -> BulkEnd` window drives
the peer's authoritative `reconcileStaleSessions`. `syncSweep` therefore
re-drives an owed cold prime on the live connection, past its `s.sessions == nil`
guard so the store is known wired, discharging on success and leaving the arm in
place on failure so the next tick retries. It is an `else if` on the
`forceResync` consume (a forced resync sends the same authoritative snapshot, so
at most one bulk leaves per tick) and shares `bulkRedriveInFlight` with the
survivor re-drive so the two cannot stack. The daemon also now wires the runtime
BEFORE `ss.Start()`, which removes the trigger and gives the `SetRuntime` writes
a happens-before edge over the goroutines `Start` spawns.

## Incremental Sweep and Delete Journal

### Background Sweep

A background sweep periodically scans the kernel session maps for forward
entries whose `Created` or `LastSeen` timestamps moved since the previous sweep.
Only sessions owned by the local node for the ingress zone are sent.

The sweep is deliberately separate from userspace deltas. It is still the only
way the kernel conntrack path exports incremental session creation.

### Delete Journal

Delete messages are queued immediately from conntrack GC callbacks. If the peer
is disconnected — **or the peer is connected but `sendCh` is momentarily full
(backpressure)** — the delete is journaled in a bounded ring by
`QueueDeleteV4`/`V6` instead of being sent inline.

The journal is replayed on two triggers:

1. **Reconnect flush** — the next first-post-disconnect connection comes up,
   before `OnPeerConnected` and before the fresh bulk starts
   (`handleNewConnection` → `flushDeleteJournal`).
2. **Connected sweep flush (#3926)** — the periodic sweep (`syncSweep`) calls
   `flushDeleteJournal` on every tick while connected, mirroring the
   install-replay it already performs. This converges a delete that was
   journaled during a connected-but-backpressured moment **without requiring a
   disconnect**. Before #3926 the journal was flushed only on trigger (1), so a
   delete journaled while the link stayed up was never delivered until an
   unrelated disconnect — the standby kept the dead session and made the wrong
   forwarding decision on failover. The delete backpressure sets
   `syncBackfillNeeded`, which holds the sweep at the 1s active cadence, so
   convergence is bounded by one active sweep interval. The re-sent delete
   carries the same encoded #2170/#2221 generation drawn when it was first
   journaled, so a stale journaled delete that replays after a same-key
   replacement was re-synced is still refused by the peer's delete guard.

Replay goes through the ordered send channel (`queueMessage`), so a delete that
is delivered stays ordered behind any session frames already queued in `sendCh`
for the peer. (Note: cold-start bulk sync direct-writes session frames under
`writeMu` rather than via `sendCh`, so flush-vs-bulk wire order is not strictly
guaranteed; flush still completes — enqueueing all deletes — before bulk
starts, and a live session landing after a stale delete is the safe direction.)
If the send queue is full (or the peer disconnects) mid-replay,
`flushDeleteJournal` does **not** drop the un-sent deletes: it re-journals the
un-sent tail at the front of the ring (FIFO-preserving, evicting the oldest on
overflow) so they replay on the next reconnect flush — the same
journal-on-failure contract `QueueDeleteV4`/`V6` use for runtime deletes (#2121
fixed an earlier silent drop here). Genuine loss only occurs at the journal cap
and is counted in `DeletesDropped`; a cap eviction now also arms a full bulk
resync so the standby reconciles the evicted deletes (#5450, see "Delete Journal
Overflow" below).

Because deletes are key-only on the peer (no generation/session-identity guard
yet), a re-journaled delete that replays after a same-key replacement session
has been synced can remove the live replacement. This is a pre-existing
property of the journal (it also applies to `QueueDeleteV4`'s full-queue and
disconnect journaling); #2121 widens it to the flush path as a deliberate
trade-off (bounded retention instead of unrecoverable silent loss). Fully
closing it requires a wire-protocol generation guard on deletes — a tracked
follow-up.

## Userspace Session Integration

### NAT Pool Port Reservation for Synced Sessions (#4388)

When the helper installs a peer-synced session that carries a pool-mode
source-NAT translation, it **reserves** the translated `(pool_addr, port)` in
this node's LOCAL source-NAT allocator. The active node picks the pool port via
`allocate_translation` and syncs the completed NAT decision over the fabric; the
standby imports that pre-computed decision and never runs `allocate_translation`
itself, so without an explicit reservation its allocator has no record that the
port is in use. Post-failover the standby-turned-active would then hand the SAME
`(pool_addr, port)` to a fresh local flow — two sessions colliding on one NAT
source tuple (reply mis-delivery / a session-hijack surface).

- **Reserve site:** `handle_upsert_synced`
  (`afxdp/session_glue/commands/upsert_synced.rs`) calls
  `reserve_synced_source_nat_allocation` (`nat/source.rs`) for every forward,
  peer-synced entry that carries `rewrite_src` + `rewrite_src_port`. It resolves
  the pool address to its allocator index and marks the port owned via
  `PortAllocator::reserve_flow` (`nat/allocator.rs`) — the same
  `owner_by_translated` / `addr_index_by_translated` / `live_by_flow` state a
  normal allocation writes, keyed by the synced session's flow. The sequential
  port cursor (`claim_free_port_locked`) then skips the reserved port, exactly
  as it already skips a live local allocation (#3047 forward-probe). The #5178
  `deterministic` flag mirrors the active node's allocation mode so the standby's
  release takes `free_no_recycle` for a deterministic-CGNAT reservation.
- **Address-only reserve (#5338):** an ADDRESS-ONLY decision (`port
  no-translation` on a port-bearing protocol, or a port-less protocol such as
  GRE/ESP) carries `rewrite_src` (the pool address) but NO `rewrite_src_port` —
  the wire keeps the packet's own source port. The active node (#5269/#5336
  round-robin/persistent, #5341 deterministic) mints a reverse-identity
  occupancy token for such a flow via `PortAllocator::reserve_address_only`
  (keyed on protocol, pool address, PRESERVED source port, remote) so its
  reverse (1:N) index can disambiguate the public tuple. The synced reserve now
  mirrors that mint on the standby: the address-only arm claims the SAME token on
  the rule whose pool owns `rewrite_src`, consuming NO pool-port bit. Without it,
  a promoted standby could not disambiguate the synced address-only session's
  replies and a fresh local address-only flow could claim the same public
  identity. Like the port-bearing arm, a collision (a local flow already owns the
  identity) or a foreign pool address is skipped gracefully.
- **Rule selection (#6211):** WHICH rule the reservation lands on mirrors the
  ACTIVE node's choice.

  **Scope:** the motivating config is NOT reachable through a supported commit
  — #5144 hard-rejects duplicate source-NAT pool addresses at strict commit
  (`TestNAT5144ExactDuplicateSourcePools`). The live surface is the two paths
  that BYPASS the strict compiler: a pre-#5144 persisted config, and the
  tolerant load / peer-sync path (#1960 no-brick). That bounds the severity —
  this is not an ordinary operator configuration.

  Two source-NAT rules can carry the SAME public pool
  address in SEPARATE allocators — the allocator is shared per `allocator_key`
  (pool name + addresses + port range, `SourceNatRule::allocator_key`), so
  distinct `pool_name`s with a common member address give one address two
  independent `PortAllocator`s. The original selection ("the first rule whose
  pool CONTAINS `rewrite_src`") narrowed on no other axis, while the active
  picked its rule by zone/policy match, so under that config the standby's
  reservation could land in a DIFFERENT allocator than the active used for the
  same session. After a failover a new local flow matching the OTHER rule then
  missed the collision guard — the reverse-identity token sat in the wrong
  allocator, reintroducing the ambiguity the token exists to prevent.

  The fix is LOCAL, **not** a wire change: every input the active's rule match
  consumes is already synced. The zone pair rides as
  `ingress_zone_id`/`egress_zone_id` (`SessionSyncRequest` →
  `SessionMetadata::ingress_zone`/`egress_zone`, with the legacy name strings as
  the old-peer fallback) and the 5-tuple IS the session key, so
  `reserve_synced_source_nat_allocation` re-runs the active's OWN predicate
  (`SourceNatRule::matches_ignoring_scope`) rather than introducing a second
  rule-identity scheme. Note that the flow key it already built is byte-identical
  to the active's SNAT-match tuple (original source, POST-DNAT destination,
  original ports — `nat_match_flow.forward_key` in `poll_descriptor`), and, like
  `match_source_nat_result_for_tuple`, it takes the FIRST matching rule in
  snapshot order (that order IS the #4161 Junos specificity precedence).

  Only the #3096 interface / routing-instance scope is excluded: `NatScopeCtx` is
  built from the LOCAL `ifindex_to_config_name` / `ifindex_to_routing_instance`
  maps keyed on the ACTIVE's ingress/egress ifindices, which the standby does not
  have. That axis is therefore treated as UNCONSTRAINED rather than as a
  mismatch — rejecting an interface-scoped rule the standby cannot confirm would
  push the selection PAST the rule the active actually used and onto a later one,
  strictly worse than the first-pool-match it replaces.

  A **fallback** to the original first-pool-match runs whenever the narrowed pass
  reserves nothing: an unresolvable zone pair (an old peer, or a zone absent from
  this node's snapshot), no confirmable match owning the address (NAT config
  drift between the nodes), or every candidate refusing the reservation. This is
  unconditional by design, so no configuration ends up with FEWER reservations
  than before #6211 — the narrowing can only move a reservation to a
  better-justified allocator, never remove one. Rolling-upgrade safe, and
  single-rule / non-overlapping-pool configs are byte-identical either way.

  **Release sweeps every allocator (#6211).** Because selection is no longer a
  pure function of `rules`, a session re-upserted after the selection outcome
  changes (a zone delete/renumber flips the pair to unresolvable; a rule-set
  `from zone` / `match` edit moves the candidate set) reserves a SECOND time in
  a DIFFERENT, independent allocator — `reserve_flow`'s idempotence is per
  allocator, so it does not short-circuit. Every live session re-upserts on HA
  session-sync reconnect and on a post-delete-journal-overflow resync. So
  `release_source_nat_allocation` no longer stops at the first allocator that
  reports the flow released; it frees from EVERY pool-mode rule. Stopping at
  the first hit stranded the other reservation permanently — nothing reaps it
  (`live_by_flow` is removed only by `release_flow` / `rollback_flow` / the
  stale-tuple replace in `reserve_flow`; `gc_expired_chunked` sweeps persistent
  LEASES, not live flows), a config edit does not rebuild the allocator
  (carryover is keyed on `allocator_key()` alone), and the orphan counts
  against `max_tracked_flows` until the pool reports `AllocatorExhausted`. The
  sweep cannot over-free: `release_flow` / `rollback_flow` return false unless
  the stored translated tuple matches this one.
- **Release site:** the reservation uses the synced flow key, so the standard
  teardown — `release_source_nat_allocation_for_worker`, already called on GC reap
  (`reap_expired_sessions`), on a peer delete-sync (`handle_delete_synced`), and
  on DSCP-filter purge — frees it with no new delete path (the address-only token
  is cleared from `address_only_owners` by the same `release_flow`). A reverse
  synced entry, or a session with no source NAT at all (`rewrite_src` unset),
  reserves nothing.
- **Per-worker holder set (#6211 F2):** a synced entry is pushed to EVERY
  worker's session table (`afxdp/ha/session_import.rs` fans `UpsertSynced` out to
  each worker's command queue) while the source-NAT / NAT64 allocator is ONE
  shared `Arc`. So N workers reserve the same `(flow, translated)` and each
  releases it independently — the reap, the replicated `DeleteSynced`, and the
  alias purge all run per worker. `LiveAllocation.holders` is a `u128` bitmask,
  one bit per `worker_id`, OR-ed in at `reserve_flow`'s (and
  `reserve_address_only`'s) idempotent early return — which is BOTH where workers
  2..N land AND the path an already-holding worker takes on every refresh, so OR
  is required where an increment would inflate without bound. The port is freed
  only when the LAST holder's bit clears. `holders == 0` marks an untracked LOCAL
  allocation (RSS steers a 5-tuple to one worker, so it has a single holder by
  construction) and keeps the first-release-frees contract unchanged.

  Without the holder set the N reserves collapsed into one record and the FIRST
  worker to let go freed a port the other N-1 were still forwarding through. That
  is the expected steady state after any failover carrying a synced SNAT session
  older than the inactivity timeout: the active's periodic `UpsertSynced` refresh
  stops, RSS lands traffic on exactly one worker, and the other replicas idle out
  with nothing refreshing them.

  `worker_id` comes from `WorkerLaunchPlan::worker_id` — the worker's own
  identity established at spawn — threaded through `apply_worker_commands`,
  `reap_expired_sessions`, `resolve_flow_session_decision` and
  `delete_terminal_filtered_session`. The untracked entry points
  (`release_source_nat_allocation`, `reserve_synced_source_nat_allocation`, and
  their NAT64/rollback twins) are `#[cfg(test)]`, so a production path that
  forgot to thread its worker id is a BUILD failure rather than a silent
  single-holder release.
- **Worker-id bound (#6211 F2):** the mask tracks
  `nat::MAX_NAT_HOLDER_WORKERS` (128) workers, tied to the `u128` width by a
  `const` assertion so the two cannot drift. The bound is enforced where ids are
  MINTED — `replan_bindings_from_candidates` refuses the whole plan (fail-closed:
  no bindings, no forwarding) if any `queue_id % workers` would exceed it. It is
  deliberately NOT a cap on `--workers`: `queue_count` is the per-interface
  RX-queue minimum computed independently of `workers`, so the ids actually
  minted span `[0, min(queue_count, workers))` and a raw `--workers` cap would
  refuse a safe box (`--workers 200` on a 16-queue NIC mints ids 0..15).
- **Config-drift edge:** if the synced pool address is not a member of any local
  pool (the two nodes' pool config diverged), the reserve is skipped gracefully
  — never a panic, never a reservation on the wrong pool.
- **Idempotent:** re-reserving the same synced flow on a refresh is a no-op; the
  allocator is process-global (`Arc<PortAllocatorShared>`), so the reservation
  is visible to every worker regardless of which one imported the session.

### NAT64 Translated-Port Reservation for Synced Sessions (#4512)

NAT64 (RFC 6146 stateful v6→v4) has the identical exposure. Each `Nat64Prefix`
owns a `PortAllocator` (#4381, the same pool-mode allocator source NAT uses) and
`Nat64State::allocate_source` hands every admitted forward flow a unique
translated `(pool v4, port / ICMP identifier)`. The translated port rides the
synced `NatDecision` on `rewrite_src_port` (no new wire field), but the standby
imports the pre-computed decision without running `allocate_source`, so its NAT64
allocator has no record the port is in use. Post-failover the promoted node could
`allocate_source` the SAME `(snat_v4, port)` for a fresh local flow — two forward
flows on one translated source, so the 1:N reverse (v4→v6) index bucket mis-demuxes
the server's replies (the exact BIB collision #4381 closed for the same-node case).

- **Reserve site:** `handle_upsert_synced` calls
  `crate::nat64::reserve_synced_nat64_allocation` (`nat64.rs`) alongside the
  source-NAT reserve, for every forward, peer-synced entry whose decision is a
  NAT64 translation (`nat.nat64 && rewrite_src == V4 && rewrite_src_port`). It
  reconstructs the flow key EXACTLY as `allocate_source` built it (`dst_ip` is the
  translated v4 destination `nat.rewrite_dst`, not the synthetic v6 key), resolves
  `snat_v4` to its `pool_v4` position (the NAT64 allocator uses `family_offset ==
  0`, so the pool position IS the absolute index), and marks it owned via
  `reserve_nat64_pool_port` → `PortAllocator::reserve_flow`. The `nat.nat64` guard
  keeps the NAT64 and source-NAT reserves disjoint even if a pool address is shared.
- **Release site:** the reservation uses the synced flow key, so the standard
  teardown `release_nat64_allocation` — already called on GC reap
  (`reap_expired_sessions`), on delete-sync (`handle_delete_synced`), and on
  DSCP-filter purge — frees it with no new delete path. A reverse entry or a
  non-NAT64 decision reserves nothing.
- **Config-drift / scope:** a synced pool address not in any local NAT64 pool is
  skipped gracefully (no panic). This closes the port-COLLISION harm only;
  reverse-TRANSLATION of a promoted synced NAT64 session is completed by #4565
  (below), which also ARMS this reserve — see the note there.

### NAT64 Reverse-BIB Sync for Promoted Sessions (#4565)

Closes the reverse-TRANSLATION half of the NAT64 HA story #4512 left open, and is
the change that actually ARMS #4512/#4564's `reserve_synced_nat64_allocation`.

**The gap.** A NAT64 forward flow is keyed on the ORIGINAL IPv6 5-tuple; its
reverse (v4→v6) reply is keyed on the translated `(server_v4 → snat_v4,
translated port)` tuple and translated back to IPv6 using the original v6 src/dst
(`Nat64ReverseInfo`). Pre-#4565, `build_synced_session_entry` (`server/helpers.rs`)
built the standby's synced entry with `nat64: false` (via `..NatDecision::default()`)
and `nat64_reverse: None`, and `build_reverse_session_from_forward_match`
(`afxdp/shared_ops.rs`) hardcoded `nat64_reverse: None`. So a promoted NAT64
session (a) never reached `build_nat64_forwarded_frame` — TX dispatch keys
`is_nat64` off `nat.nat64`; (b) could not translate the v4 reply (the frame
builder hard-requires `nat64_reverse`); and (c) synthesized a WRONG (v6-family)
reverse companion KEY — `reverse_session_key` derives the reply's v4 address
family + `(dst_v4 → snat_v4)` tuple from `nat.nat64` + the v4 NAT addresses, so
without them the server's v4 reply never matched. Because the entry set
`nat64: false`, #4512/#4564's reserve (gated on `nat.nat64`) was ALSO a silent
no-op on the real HA path.

**What must ride the wire (verify-first).** The original v6 src/dst ARE the synced
forward v6 session key (`key.src_ip`/`key.dst_ip` == `orig_src_v6`/`orig_dst_v6`;
a NAT64 forward flow is keyed on the original tuple and `nat64_match` is gated on
no-DNAT/no-NPTv6, `<prefix>/96` only), and `dst_v4` is the RFC 6052 /96-embedded
low 32 bits of the key dst. So the ONE datum the standby cannot reconstruct is
the translated pool source `snat_v4` (chosen by the active node's
`allocate_source`, not embedded in the key). A single tag-matched wire field
carries it (self-signaling — non-empty ⟹ NAT64):

- **Event stream (Rust → Go active):** `FLAG_NAT64` (bit `1<<5`) on the SESSION_OPEN
  frame + a trailing 4-byte `snat_v4` (after the #3301 fields). Decoded to
  `SessionDeltaInfo.Nat64` / `Nat64SnatV4` (`eventstream.go`).
- **Shadow + cluster sync (Go active → Go standby):** stamped onto
  `SessionValueV6.Nat64SnatV4` (`daemon_ha_userspace.go`), a userspace-sync-only
  field carried as a length-gated trailing field in `encodeSessionV6Payload`
  (NOT in the BPF/C conntrack ABI).
- **Control socket (Go standby → Rust standby):** `SessionSyncRequest.nat64_snat_v4`
  (Go+Rust, the `protocol_wire_v1.json` / cross-language contract field).

**Rebuild on the standby.** When `nat64_snat_v4` is non-empty,
`build_synced_session_entry` sets `nat64 = true`, `rewrite_src = snat_v4`,
`rewrite_dst = dst_v4` (the /96 low 32 of the v6 key dst; the translated port
already rides `nat_src_port`), and stamps `metadata.nat64_reverse` (orig v6
src/dst) from the key. `build_reverse_session_from_forward_match` inherits
`nat64_reverse` onto the synthesized reverse companion, and `reverse_session_key`
then derives the correct v4 `(server → snat_v4)` reply tuple. Rolling-upgrade
safe: an old peer omits the field ⇒ not-NAT64 (bit-identical to pre-#4565).

### Reverse-SNAT `dnat_table` Publish for Synced Sessions (#4393)

The `dnat_table` / `dnat_table_v6` BPF maps are the **embedded-ICMP reverse-NAT
steering** maps. When an inbound ICMP error (PMTUD Packet-Too-Big, traceroute
Time-Exceeded) quotes a NATed inner packet whose source is a source-NAT pool
`(addr, port)`, the AF_XDP shim looks that tuple up in `dnat_table` to decide the
packet must be handed to the helper's slow path, where `try_embedded_icmp_nat_match`
reverse-translates the error back to the original pre-NAT client. Without the
`dnat_table` entry the shim passes the error to the kernel (which has no NAT
state) — the client never learns the PMTU, TCP stalls on large packets, and
traceroute breaks.

The active node populates `dnat_table` from the worker poll path
(`poll_descriptor`, `publish_dnat_table_entry`) when it forwards the first SNAT'd
packet of a flow. The standby never forwards that packet — it imports the
pre-computed NAT decision over the fabric — so before #4393 the standby held no
`dnat_table` entry for synced SNAT sessions. Post-failover the standby-turned-active
could not steer the inbound embedded-ICMP error into the helper, so PMTUD
blackholed for exactly the flows that survived the failover.

- **Publish site:** `Coordinator::upsert_synced_session` (`afxdp/ha/session_import.rs`) calls
  `publish_dnat_table_entry` for every forward peer-synced entry, immediately
  after the `publish_shared_session` that populates the (also process-global)
  `shared_nat_sessions` reverse-NAT map. `dnat_table` is a **single shared BPF
  map** (opened once, its fds cloned to every worker), so this is a
  once-per-synced-session publish, mirroring the primary's single publish rather
  than a redundant per-worker write. It is **not** gated on
  `synced_entry_allows_local_replace` (unlike the forward session-map publish):
  the `dnat_table` is a passive steering map that must be ready the instant this
  node becomes active, and inbound SNAT-return traffic never reaches the standby,
  so an early entry is inert until failover. A reverse companion carries no
  source rewrite and publishes nothing.
- **Release site:** `Coordinator::delete_synced_session_gen` (`afxdp/ha/session_import.rs`)
  calls `delete_dnat_table_entry` alongside the session-map delete, keyed on the
  same `dnat_v4_key_bytes` / `dnat_v6_key_bytes` SSOT the publish used, so the
  delete byte-matches the insert. The maps are non-LRU `HASH`
  (`max_entries = MAX_SESSIONS`, `BPF_F_NO_PREALLOC`); a missing delete leaks one
  slot per removed synced SNAT session. A non-SNAT / reverse entry is a no-op.
- **Observability:** a failed publish from this coordinator path (no per-binding
  `BindingLiveState`) bumps the shared `DNAT_PUBLISH_ERRORS_SHARED` static, which
  `Coordinator::dnat_publish_errors_total()` folds into the existing per-binding
  sum for `xpf_userspace_dnat_publish_errors_total` — so map-pressure reverse-NAT
  loss stays operator-visible on the standby path too (#2244 parity).

### Activation Refresh Recomputes `allow_replace_local` Per Session (#4805)

The forward session-map publish for a peer-synced entry is gated on
`synced_entry_allows_local_replace(ha_state, owner_rg_id, now_secs)`: for a
`LocalDelivery` (host-inbound) session whose owning RG is **not** locally
forwarding-active, it returns `true`, and
`force_live_redirect_for_worker_synced_entry` publishes the userspace
`REDIRECT` entry (policy enforced via fabric-redirect / drop) rather than a
kernel-local `PASS_TO_KERNEL` entry. A standby node must never let a
peer-synced, locally-undelivered session fall through to its own kernel stack.

`WorkerCommand::RefreshOwnerRGS` (dispatched to every worker on any RG
activation) runs a **wider scan** — it re-evaluates every HA-managed worker
session, not just those indexed under the activated RG, because a split-RG
reverse companion owned by RG2 can change local-forward vs fabric-redirect when
RG1 moves. Each touched session is republished. That republish MUST recompute
`allow_replace_local` from the refreshed owner RG against the current HA state,
exactly as the initial-sync path (`handle_upsert_synced`) does —
`collect_refresh_owner_rgs_items` in
`afxdp/session_glue/commands/refresh_owner_rgs.rs` computes it alongside the
refreshed metadata. Hardcoding `false` here (the pre-#4805 bug) flipped an
unrelated, still-standby-owned `LocalDelivery` session from `REDIRECT` to
`PASS_TO_KERNEL` on any routine RG activation elsewhere in the cluster —
delivering host-bound traffic straight to the standby's kernel with no policy
enforcement. Pinned by
`refresh_owner_rgs_standby_local_delivery_forces_live_redirect_4805` and
`refresh_owner_rgs_active_owner_local_delivery_publishes_kernel_local_4805`.

The wider scan **republishes** every touched session's forwarding decision, but
it must NOT re-stamp the standby *liveness* of a session it does not own.
`refresh_for_ha_transition` zeroes `first_held_ns` / `seen_rg_epoch` and
re-stamps `last_seen_ns` (the #2120 §6.4 promotion write-site) — correct for a
session this node now forwards, but WRONG for one that re-resolves to
`HAInactive`: it would reset that session's bounded-leak HOLD clock and defeat
the standby leak ceiling for a redundancy group that never activated here. So
`handle_refresh_owner_rgs` gates the `refresh_for_ha_transition` call on
`refreshed_decision.resolution.disposition != HAInactive`, exactly as the
demote path (`handle_demote_owner_rgs`) does, while still publishing the
refreshed forwarding decision for every scanned session. Activating one RG
therefore never resets the HOLD clock of an unrelated split-RG session (the
pre-#5152 bug — the leak ceiling of every still-inactive RG's synced sessions
was reset on any activation elsewhere in the cluster). Pinned by
`refresh_owner_rgs_skips_hainactive_hold_clock_5152`.

### Event Stream (Primary Path)

The Rust helper pushes session events over a persistent binary-framed Unix
socket (`/run/xpf/userspace-dp-events.sock`). Events (SessionOpen,
SessionClose, SessionUpdate) carry sequence numbers for reliable delivery.
The daemon reads events, applies ownership filtering, and queues them to the
peer sync stream. Ack frames flow back for replay buffer management. Pause and
Resume frames throttle the stream. The DrainRequest / DrainComplete frame pair
is **reserved and currently dormant** — see below.

The daemon owns the listener; `EventStream.Start` binds it (`net.Listen`) before
the helper is spawned so the local helper can dial immediately. This socket is
the primary push channel for post-bootstrap deltas from the helper into the
daemon's peer-sync pipeline. The daemon also polls `DrainSessionDeltas` while
the stream is disconnected (the fallback described below), but a listener bind
failure must not silently make that degraded path the startup baseline. A bind
failure (path too long, `EADDRINUSE`, permission, missing directory) therefore
fail-closes dataplane bring-up: `Start` returns an error,
`ensureProcessLocked` aborts before launching the helper instead of storing a
non-nil-but-dead stream, and takeover readiness is denied.
`Start` first acquires a nonblocking process-lifetime sidecar lock. While it
owns that lock it checks `/proc/net/unix` and removes an existing filesystem
socket only when the kernel table proves there is no live owner. This check is
non-invasive: dialing the old listener would displace its real helper because
the event stream permits one connection. A live or inconclusive owner is never
unlinked. `Close` tears down the listener and accepted connection, removes the
socket only when that `EventStream` owns it, and then releases the lock. This
makes active-owner collisions fail closed rather than detaching the first
daemon's pathname.
`EventStream.ListenerBound()` reports whether the local listener is up and is
distinct from `IsConnected()` (the local helper has dialed in). Takeover
readiness gates on `ListenerBound()`, not `IsConnected()`: transient helper
disconnects are covered by polling, while a listener that never bound is a
failed dependency rather than an accepted degraded startup (#5273). Before
#5273 the `net.Listen` failure was logged and swallowed with a void `Start`, so
the manager kept the dead stream and takeover readiness — which only checked
the control socket, ping, forwarding-arm, and XSK liveness — could advertise a
node without its primary delta stream.

#### DrainRequest fence (#2876, #2920) — RESERVED / DORMANT

> **Status: implemented and hardened, but not wired to any production path.**
> The live graceful-demotion path does **not** call `SendDrainRequest`; it uses
> `SessionSync.WaitForPeerBarrier` plus the continuous lossless event stream
> (see "Graceful Demotion" below). The seq-fenced drain is a strictly *weaker*
> guarantee than the unbounded `ExportOwnerRGSessions` full-resync republish
> that already backstops loss-of-sync (#2874 gap, #2442 overflow), so it is not
> on the failover critical path. The pair is retained — fully tested and
> hardened — for a possible future fenced-drain use; the wire frames
> (`MSG_DRAIN_REQUEST = 7`, `MSG_DRAIN_COMPLETE = 8`) are kept rather than
> deleted to avoid an invasive protocol-version churn. The semantics below
> describe the dormant primitive, **not** a live demotion step.

`EventStream.SendDrainRequest` fences the drain to the last fully-applied
sequence (`lastAppliedSeq`, the *target seq*) and blocks for the helper's
`DrainComplete`. The drain is only reported successful when the
**acked/drained seq has reached the target fence**:

- **Helper side** (`handle_drain_request`, `event_stream/mod.rs`): the drain
  loop tracks whether the target fence was reached. On a timeout below the
  fence (the channel never produced the target seq within the 200 ms deadline)
  the helper **withholds** `DrainComplete` rather than emitting one carrying a
  below-target `replay_buf.back().seq`.
- **Go side** (`SendDrainRequest`, `eventstream.go`): a `DrainComplete` with
  `seq < targetSeq` is rejected as a **hard error**, and a context expiry
  (helper withheld the completion) is likewise an error. Demotion must NOT
  proceed past an unflushed fence.

Before #2876 the Go side returned the first `DrainComplete` seq with no fence
check and the helper emitted `DrainComplete` even on a below-fence timeout, so
were this primitive ever wired into demotion, sessions created after the fence
could be reported drained without reaching the peer. #2876/#2920 hardened the
primitive so that defect cannot ship if it is wired in future. The fence carries no new wire field
(the existing `DrainRequest` target seq and `DrainComplete` seq are reused), so
the protocol is unchanged. Siblings in the same event-stream/drain cluster:
#2882 (drain ignores the target_seq filter), #2877 (blocking writes), #2883
(keepalive) — out of scope here.

When the event stream is disconnected (helper restart, startup race), the
daemon automatically falls back to RPC polling.

### Delta Drain (Fallback Path)

The Go daemon can poll helper-originated session deltas via
`DrainSessionDeltas(...)` as a fallback when the event stream is unavailable.

These deltas are **not** blindly mirrored. Filtering in
`shouldSyncUserspaceDelta()`:

- `local_delivery` disposition is never synced to the peer
- `FabricRedirect` with `!FabricIngress`: always synced even if the local node
  is no longer owner, because the peer needs the forward-wire alias to receive
  redirected traffic. The daemon also synthesizes forward-wire alias session
  keys via `userspaceForwardWireAliasFromDeltaV4/V6` so the new owner can
  materialize the translated forward tuple it will receive over the fabric.
- if the delta carries `OwnerRGID`, ownership is checked with `IsPrimaryForRGFn`
- otherwise the fallback is `ShouldSyncZone(ingressZone)`

The filtering fields on `SessionDeltaInfo` are `FabricRedirect` and
`FabricIngress` (boolean flags), not a single combined field.

### Bulk Owner-RG Export (FullResync republish)

`ExportOwnerRGSessions(rgIDs, 0)` dumps **all** userspace sessions owned by the
primary's RGs. The `max = 0` argument means unbounded (`usize::MAX` helper-side)
— it is an unbounded ground-truth snapshot of the entire conntrack table for the
owned RGs, not a Max-truncated or delta-replay export, so it cannot silently drop
post-snapshot sessions.

This is **not** triggered by demotion prep. Its only live caller is
`handleEventStreamFullResync` → `exportUserspaceOwnerRGSessionsWithConfig`: the
event stream signals a FullResync after a #2874 sequence gap, a #2442
delta-ring overflow (loss-of-sync), a #5483 **undecodable session frame**
(a COMPLETE-but-semantically-rejected open/close/update — same severity as a
gap, because the standby is missing that frame's session state), or a #6132
**oversized / framing-desynced frame** (a refused frame whose declared length
exceeds the sanity bound), and the export republishes the full owned set from
table truth. It is not the same thing as the
steady-state delta drain.

The #5483 case closes a silent-divergence hole: the reader used to skip an
undecodable session frame with `DecodeErrors.Add(1); continue`, leaving the
sequence watermark below the hole. A later lossy telemetry frame would then
advance the cumulative ACK past the unapplied session seq, the helper's replay
buffer would trim over it, and no subsequent gap would fire — so the standby
diverged with no recovery. `handleSessionDecodeFailure` forces a full resync
from table truth.

**#6130 — how a decode failure terminates (it does NOT mirror the #2874 gap
self-heal).** The first #5483 fix reused the gap mechanics verbatim: force the
resync, withhold the ACK, and drop the connection. That WEDGED the stream on a
persistently-undecodable frame, because a decode failure is fundamentally
different from a gap:

- A #2874 **gap** self-heals precisely because the frame is **ABSENT**. On
  reconnect the Rust `replay_buffered` sees `has_gap` (`oldest_buffered >
  acked+1`) and parks a re-baselining FullResync barrier — the frame cannot be
  re-sent because it was never buffered.
- An **undecodable** frame is **PRESENT**. The Rust replay buffer stores encoded
  frames and re-sends them verbatim; `has_gap` is FALSE for a present seq, so
  **no** re-baselining barrier is parked. Withholding the ACK therefore makes
  the helper re-send the identical frame on every reconnect: reconnect → replay
  N → decode-fail → resync → drop → reconnect — an unbounded busy-loop that
  hammers the shared control socket and floods the log (worst case on a STANDBY,
  whose `handleEventStreamFullResync` is a corrective no-op — pure churn). The
  bulk export (`ExportOwnerRGSessions`) publishes deltas peer-direct and never
  injects into the local replay buffer, so it cannot evict frame N; only 4096
  new live frames would — never, under no/low traffic.

#6130 terminates the loop by **advancing the watermark PAST the undecodable
frame** (unconditionally, on every such frame) and **keeping the connection
alive** (mirroring the helper-initiated FullResync path #5362, not the gap
path). The cumulative ACK then moves past seq N, the helper trims it
(`front.seq <= acked`), and it is never re-sent — so a single bad frame yields
**exactly one** resync and a persistently-undecodable stream yields at most one
resync per `decodeFailureResyncInterval` (rate-limited; the rest counted in
`DecodeResyncSuppressed`).

Advancing past N does **not** reintroduce the #5483 divergence, because we
advance only under cover of a resync that re-baselines from **table truth**: an
undecodable OPEN's session is still in the helper table, so the unbounded export
snapshot is a strict superset of the lost frame's state. An undecodable CLOSE
degrades to the pre-existing "missed close → idle-GC self-heal" bounded
staleness (a full owner-RG re-export cannot convey a delete — see #2880 above),
NOT a permanent divergence. This is unlike the pre-#5483 silent skip, which
advanced past N with **no** resync at all. **STANDBY:** the export early-returns
"not primary" (a cheap no-op that never reaches the control socket), and a
decoded session delta is itself a no-op on a standby (`handleEventStreamDelta`
drops it for a non-primary), so advancing past the undecodable frame there loses
nothing and the standby cannot spin. A decode failure on a lossy TELEMETRY frame
is still tolerated (skipped, watermark advanced) — it carries no HA session
state.

**#6132 — the oversized / framing-desync guard has the SAME replay loop, fixed
the same way.** The reader's length sanity check (`length > 1024`; the helper's
largest legitimate frame is a <=256B session event) used to do a bare `return`,
dropping the connection on any oversized declared length. That is the identical
pathology: the frame is **PRESENT** on the wire, the Rust replay buffer re-sends
it verbatim with no `has_gap` barrier, so a persistently-oversized / framing-
corrupt frame at seq N produced the same drop → reconnect → replay → drop storm
`#6130` eliminated for the undecodable-decode path. `handleOversizedFrame` now
recovers via the shared `triggerRateLimitedResync` machinery (same
`onFullResync`, same `decodeFailureResyncInterval` rate-limiter, same
`SessionSyncResyncs` / `DecodeResyncSuppressed` accounting) instead of an
unbounded reconnect loop. The header is written atomically and the reader
consumes exactly `length` payload bytes per frame, so the header stays aligned
and this frame's `seq` is trustworthy; the watermark is advanced PAST it (the
loop-break — the helper trims it and never re-sends it) and the payload is
handled by trust in the LENGTH: a length within
`maxDiscardableOversizedFrameBytes` is a trusted frame boundary, so the reader
discards exactly that many bytes to re-align on the next header and KEEPS the
connection (no drop); a length above the ceiling (or a failed drain) is not
trusted to re-align the byte stream, so the reader flushes the advanced ACK and
drops the connection to re-establish framing on reconnect — bounded, because the
ACK moved past the frame so it is trimmed, not replayed. The **security posture
is preserved**: the corrupt frame is REFUSED — never decoded or applied as valid
session state — it is superseded by the table-truth resync.

The `rgIDs` handed to the export are enumerated from the **configured
redundancy-group set** — `handleEventStreamFullResync` calls
`primaryOwnerRGIDs(cfg)`, which walks `cfg.Chassis.Cluster.RedundancyGroups`
(the same live active config `buildZoneIDs` reads) and keeps every id the node
is `IsLocalPrimary` for. It does **not** iterate a fixed `0..15` range. Junos
redundancy-group ids are not bounded to 15 (the `<group-id>` config slot has no
validator and is parsed via an unbounded `strconv.Atoi`), so the old hardcoded
`for rgID := 0; rgID < 16` loop silently skipped any RG with id >= 16 — its
owned sessions were never re-exported on a FullResync, so the standby never
received them and they were dropped on a failover of that RG (#4028). This
mirrors the live-config enumeration the watchdog/fence paths use
(`currentRedundancyGroups`, #3917).

**The export ack-wait runs OFF the global `ServerState` lock (#2962).** The
helper-side control-socket dispatcher (`server/handlers/mod.rs`) holds a single
`Mutex<ServerState>` across its request `match`, which serializes every control
RPC (status poll, session install, snapshot/FIB bump, HA state update, neighbor
update). The owner-RG export blocks up to 15 s waiting for every worker to ack
the export sequence — so doing that wait under the lock would freeze the whole
control plane for up to 15 s whenever a worker is slow or stalled (exactly the
failover-critical moment). The handler is therefore split into two phases:

- **Locked phase** (`Coordinator::kick_owner_rg_export`): enqueue the
  `ExportOwnerRGSessions` command to every worker, bump `export_seq`, and
  snapshot the lock-free handles the wait needs — the per-worker
  `session_export_ack` atomics (`Arc<AtomicU64>`) and the per-binding delta
  buffers (`Arc<BindingLiveState>`). Returns an `OwnerRgExportWait` immediately.
- **Lock-free phase** (`OwnerRgExportWait::wait_and_collect`): the dispatcher
  drops the `ServerState` lock, then runs the 15 s ack-wait + delta drain on the
  snapshotted `Arc`s. Status is re-derived afterward under a fresh short-lived
  lock acquisition. While one export drains, all other control RPCs proceed.

There is no TOCTOU: the worker SET (`workers.handles` / `workers.live`) is only
mutated by other control-socket handlers, which all hold the same lock, so the
worker set cannot change during the lock-free wait. The worker THREADS only
advance their ack atomics (monotonic seq) and push into their delta buffers —
both `Arc`-shared and lock-free — so the snapshot observes their progress
faithfully. The 15 s deadline and the timeout error are preserved verbatim.

**The all-sessions bulk export push ALSO runs OFF the global `ServerState`
lock (#4054).** The `export_all_sessions` verb
(`Coordinator::snapshot_all_sessions_export` → `AllSessionsExport::push`) is the
coordinator-driven bulk export used on peer connect / FullResync. It iterates the
shared session table and pushes each qualifying local forward session as an Open
delta through the event stream via `push_delta_lossless`, which retries a full
event-stream channel up to a **5 s** per-delta lossless-queue timeout. Pre-#4054
the whole export — the table iteration AND the `push_delta_lossless` serialization
loop — ran inside the dispatcher's `ServerState` `match` arm, i.e. UNDER the global
lock. On a firewall with many sessions, a bulk export against a slow/backpressured
peer stream could hold the lock long enough for the status poll to miss the control
plane's liveness deadline → a false dataplane-failure → a needless helper restart
(which drops all sessions and flaps forwarding) — precisely at failover, the worst
time. The handler is therefore split like the owner-RG path:

- **Locked phase** (`Coordinator::snapshot_all_sessions_export`, dispatcher
  `all_kick`): under the global lock, iterate the session table once under a brief
  `sessions.synced` lock, copy each qualifying session into an Open `SessionDelta`,
  and capture the Arc-cheap event-stream worker handle plus an OWNED clone of the
  zone-name→id map. Returns an `AllSessionsExport` immediately — no push yet.
- **Lock-free phase** (`AllSessionsExport::push`): the dispatcher drops the
  `ServerState` lock, then runs the `push_delta_lossless` loop over the captured
  snapshot. Status is re-derived afterward under a fresh short-lived lock. While
  one bulk export serializes/backpressures, all other control RPCs proceed.

The exported set is a consistent point-in-time snapshot (deltas built under
`sessions.synced`, zone map cloned in the same locked phase), so a session or zone
mutation racing the push is simply not in THIS bulk export — it rides the
incremental delta stream — identical to the pre-#4054 semantics, which already
snapshotted the deltas under `sessions.synced` before serializing (only the GLOBAL
lock scope changes). Event-stream ordering stays governed by `producer_seq_lock`
inside `push_delta_lossless`, not the `ServerState` lock, so releasing the latter
does not affect the lossless seq contract (#2874 / #3878).

**The worker-loop lossless push is time-BOUNDED per drain cycle (#5468).** Every
lossless send `flush_session_deltas` makes — it runs directly on the packet
worker loop — must NOT use the 5 s `LOSSLESS_QUEUE_TIMEOUT`. That timeout equals
`HEARTBEAT_STALE_AFTER` (5 s), so a connected-but-UNREAD peer (a slow/stalled
reader whose lossless channel is full) that blocked the worker for the full 5 s
would stop the loop stamping its per-binding heartbeat; the peer then sees this
node as stale and triggers a **false failover** — the exact defect #5468
describes. The worker loop therefore calls `push_delta_lossless_within` with a
short `WORKER_LOSSLESS_QUEUE_BUDGET` (one fifth of `HEARTBEAT_STALE_AFTER`,
~1 s), leaving ~5× headroom for the rest of the loop iteration plus the
heartbeat map write. On the bounded timeout the delta is **not** dropped: the
same `set_delta_loss` / `take_delta_loss` latch fires and forces a full owner-RG
resync (deliver-or-resync, the #2874 losslessness contract).

The per-call budget alone is **not** sufficient, because the drain region calls
`flush_session_deltas` many times per iteration: the steady-state drain is one
call, but the #2442 loss-of-sync resync and the #2653 command export
(`take_delta_loss` → `chunked_drain_as_you_export!` → `drain_and_flush_all!`,
`worker/loop_body/mod.rs`) call it ONCE PER 256-delta batch across the entire
owned-session set. For K owned sessions that is ~K/256 calls, so at one budget
each an unread peer would still stall the worker ~(K/256) budgets — past K≈1280
(5 batches) that re-crosses `HEARTBEAT_STALE_AFTER` and re-triggers the same
spurious failover **via the resync path**. The bound is therefore an AGGREGATE
one: a per-drain-cycle `worker_lossless_wedged` latch, reset at the top of every
loop iteration and threaded through every `flush_session_deltas` call, caps the
whole cycle at ~one budget total. The first wedged batch waits one budget and
sets the latch; every later call this cycle inherits it and SKIPS the lossless
wait entirely (it never re-attempts a push), while still draining each delta to
its other consumers — the per-binding live RPC buffer, the shared
conntrack/session tables, peer-worker delete replication, and best-effort
RT_FLOW. Every wedged batch still returns out-of-sync, so the loss-of-sync latch
stays set and the resync simply RETRIES next cycle until the consumer drains
(deliver-or-resync, never a silent drop). Net guarantee: the worker loop's total
lossless WAIT per drain cycle is ~1 budget **regardless of the owned-session
count K** — for both the incremental push and the resync/export.

Only the off-worker-loop exporters — `AllSessionsExport::push` (bulk export on
connect, above) and `push_purge_close_deltas` (tunnel-remap purge, below) — keep
the 5 s `LOSSLESS_QUEUE_TIMEOUT` via `push_delta_lossless`; they run off the
packet loop so a long backpressure wait there does not threaten the worker
heartbeat.

### Delta-ring overflow → loss-of-sync resync (#2442)

Each worker buffers session open/close deltas in an in-worker ring
(`SessionTable.deltas`, capped at `MAX_SESSION_DELTAS = 4096`). The worker loop
drains it 256 at a time. Under a churn burst (failover storm, SYN-cookie
admission flood) the ring can fill faster than the drain catches up, and
`push_delta` drops the overflowing delta — an HA-relevant open/close event the
downstream session-sync consumer will never see.

Pre-#2442 this only bumped a `delta_drops` counter, so the peer/session view
silently diverged from the table truth with no consumer-visible "rescan"
contract. The fix turns a drop into an explicit **loss-of-sync** signal:

- `push_delta` latches `delta_loss_pending` the moment it drops (alongside the
  existing `delta_drops` count). It is a single bool, not a count.
- The worker loop reads-and-clears it once per drain cycle via
  `take_delta_loss()`. A `true` result means the incremental stream went lossy.
- On loss the worker re-emits an Open delta for **every owned forward session**
  (the same table-truth set the `ExportOwnerRGSessions` command walks) so the
  consumer re-derives a complete snapshot instead of diverging.

**Drain-as-you-export (bounded against the ring).** A worker can own up to
`DEFAULT_MAX_SESSIONS = 131072` forward sessions — 32× the 4096-slot delta
ring. A naive "drain the backlog, then push all N" would overflow the ring at
delta 4097, drop sessions 4097..N, re-latch the loss, and storm a fresh resync
every cycle (the peer would never receive a complete snapshot, and `delta_drops`
would climb without bound). The resync therefore **interleaves the drain**:

1. drain+flush the existing backlog so the ring starts empty;
2. collect the export candidates once
   (`forward_export_candidates_for_owner_rgs`, the filter half of the export
   walk — it pushes nothing);
3. emit them in chunks of `RESYNC_EXPORT_CHUNK = 2048` (comfortably under the
   4096 cap), and drain+flush each chunk to the peer **before** emitting the
   next.

Because the ring is empty before every chunk and a chunk is smaller than the
cap, `push_delta` never overflows during a resync. The complete snapshot ships
in chunks regardless of session count, and the loss latch is not spuriously
re-armed by the export itself.

**The single-shot `ExportOwnerRGSessions` command path uses the same chunked
drain-as-you-export (#2653).** Pre-#2653 the command handler
(`handle_export_owner_rg_sessions`) called `export_forward_sessions_for_owner_rgs`
inline, pushing the whole owned-session set into the ring in one shot on the
theory that the caller's 15 s export-ack drain would mop it up. But the overflow
happens *inside* the emit, before any drain runs: with >4096 owned sessions the
ring overflowed at delta 4097 and silently dropped sessions 4097..N, so the HA
peer received an INCOMPLETE bulk snapshot on rejoin / RG transition (the
command-path sibling of the #2442 worker-loop overflow). Since
`apply_worker_commands` has no `BindingWorker`/flush access (it cannot drain the
ring to the peer mid-export), the handler now only **records** the requested
owner RGs in `WorkerCommandResults.export_owner_rgs`; the worker loop — which
owns the binding + flush machinery — performs the identical chunked
drain-as-you-export (collect candidates → emit in `RESYNC_EXPORT_CHUNK = 2048`
chunks → drain+flush between chunks) and only advances `session_export_ack` once
the complete export has drained to the peer. The unbounded
`export_forward_sessions_for_owner_rgs` helper is now `#[cfg(test)]`-only (a
candidate-selection fixture); both production paths are bounded.

**Debounce / composition with the sync state machine.** The signal is a single
bool cleared on read, so a burst that drops N deltas before the worker reads it
raises **exactly one** resync (one episode → one trigger); a *genuinely new*
drop after the resync completes re-arms a new episode on a later cycle. The
resync is entirely worker-local — it re-uses the same per-worker delta ring and
`flush_session_deltas` plumbing the steady-state drain already uses, so it needs
**no control-socket round-trip** and cannot deadlock or starve normal
incremental sync (the control-socket contention rules in CLAUDE.md). It runs at
most once per worker poll tick and only when an overflow actually occurred.

### Coordinator tunnel-remap purge records a dropped close delta (#2880)

The **coordinator-side** tunnel-endpoint-id remap purge
(`purge_remapped_tunnel_sessions`, #1873) deletes every session keyed to a
remapped tunnel id and then emits a `Close` delta on the event stream so the Go
shadow conntrack and the HA peer drop the stale entry too. That close delta is
pushed via `push_delta_lossless`. Pre-#2880 the result was discarded with
`let _ =`, so a disconnected / saturated event stream silently dropped the
delta with no diagnostic and no metric.

**This is an error-hygiene / observability fix, NOT a forwarding-correctness
leak fix — the purge is CLEANUP, not the correctness boundary.** Two facts make
a surviving stale entry harmless:

- **It cannot mis-encapsulate.** Re-resolution and the encap builders refuse a
  tunnel id whose owning netdev ifindex differs from the one stored in the
  session's resolution (documented at the call sites,
  `coordinator/snapshot_refresh.rs` and `coordinator/reconcile/snapshot.rs`). A
  stale entry that escapes the purge dead-ends; it never encaps to the wrong
  tunnel.
- **It self-heals.** The standby runs its OWN `purge_remapped_tunnel_sessions`
  when it applies the same config snapshot, and idle GC reaps the entry on its
  inactivity timeout regardless.

A full owner-RG re-export would **not** recover an undelivered close anyway. The
userspace cold-sync delivers sessions as **incremental `Open`s** through the
event stream and then sends **empty** `BulkStart`/`BulkEnd` markers
(`pkg/cluster/sync_bulk.go` `doBulkSync` → `BulkSyncOverride`); the peer's
`reconcileStaleSessions` (`pkg/cluster/sync.go`) short-circuits on an empty bulk
("skipped (empty bulk)"). Re-emitting `Open`s therefore cannot convey a delete —
only a non-empty **bracketed** bulk drives the stale-session prune, which the
event-stream path never produces. A disconnected stream also triggers a fresh
resync on reconnect (#2874) independently.

So the fix is the minimal honest change: stop silently swallowing the
`push_delta_lossless` error. `push_purge_close_deltas` records each undelivered
delta in the event-stream **dropped-frames** metric
(`EventStreamWorkerHandle::record_dropped_frames` → the same `frames_dropped`
counter the lossy `try_send` path uses, surfaced in `EventStreamStats` /
Prometheus) and logs once. It stops on the first failure — a disconnected stream
fails every subsequent push immediately and a saturated one would otherwise burn
one lossless-queue timeout per remaining delta — and counts the undelivered
remainder. The `usize` return of `purge_remapped_tunnel_sessions` is unchanged:
it remains the accurate **local** purge count (callers read it only for
logging); the propagation drop is recorded separately, not conflated.

### Drained deltas reach binding-independent consumers even with no binding (#2669)

The worker loop drains the delta ring **unconditionally** (`drain_deltas`
pops entries off permanently) and then calls `flush_session_deltas` to apply
them. A drain cycle can coincide with an **empty `bindings` slice** — the XSK
sockets are admin-down or unconfigured during a reload/transaction while the
session table is still aging entries out. `flush_session_deltas` does much
more than push into a per-binding queue:

- **binding-INDEPENDENT** (must always run): remove the closed session from
  the shared session / NAT / forward-wire / owner-RG tables, delete the BPF
  conntrack + live-session entries, replicate a `DeleteSynced` command to the
  peer-worker queues (the HA delete-sync path), append to the recent-deltas
  RPC buffer, and emit to the event stream (HA type-2 session-sync delta plus
  the RT_FLOW SESSION_CLOSE/SESSION_CREATE frames).
- **binding-DEPENDENT** (the only step that needs a binding): the per-binding
  RPC fallback push, `BindingLiveState::push_session_delta` — there is no
  interface-local RPC queue to push into when no binding exists.

Pre-#2669 the **entire** flush was gated behind `if let Some(binding) =
bindings.first()`, so when `bindings` was empty the deltas were drained off
the ring and then silently discarded: closed/expired sessions never left the
shared conntrack/session tables, no `DeleteSynced` reached the HA peer, and no
SESSION_CLOSE reached the event stream — a permanent session-state leak and HA
desync. The fix makes `flush_session_deltas` take `live: Option<&BindingLiveState>`
and flush every binding-independent consumer unconditionally, gating **only**
`push_session_delta` on a binding. When no binding exists the worker loop
synthesizes a labels-only `BindingIdentity` (interface `""`, ifindex `-1`) and
falls back to the loop-cached map fds (which are `-1`, making the live
session-map delete a harmless `EBADF` no-op — that live map belongs to the
absent binding; the shared tables, HA replication, and event stream are the
consumers that matter). This is applied at **all three** drain sites (the
#2442 resync `drain_and_flush_all!` macro, the exported-sequences branch, and
the steady-state else branch) via the shared `flush_drained_session_deltas!`
macro. The invariant: **a drained delta MUST be flushed to its
binding-independent consumers — never popped-and-discarded.**

## Clock Synchronization

At connection setup, both sides exchange monotonic timestamps with `ClockSync`.
The receiver computes a local offset and rebases received session timestamps
into the local monotonic clock domain before install.

That keeps session expiry behavior consistent across nodes even though the two
systems have different boot times and independent monotonic clocks.

## Failover Session Handling

### Promotion

When a node becomes primary for an RG:

- synced sessions for newly-owned zones become locally authoritative
- GC delete callbacks become active for those zones
- userspace session state for the newly-owned RG is refreshed or promoted as
  needed for local forwarding
- direct-mode failover also relies on post-transition re-announcements to move
  LAN-side ownership quickly

### Graceful Demotion

Graceful demotion relies on the continuous real-time session sync rather than a
staged quiesce/republish at demotion time: by the time a node demotes, both
nodes already hold full session state from the continuous lossless event stream
(#2874) plus the steady-state bulk-prime. The demotion-prep step therefore does
exactly one synchronization: a single peer barrier proving the peer has
processed every delta already queued onto the sync stream.

Current sequence (`prepareUserspaceRGDemotionWithTimeout()`):

1. Acquire the demotion prep gate (`acquireUserspaceRGDemotionPrep`) — prevents
   duplicate concurrent preps for the same RG. On failure, the gate is released
   via `releaseUserspaceRGDemotionPrep` so retries are not blocked.
2. If the sync transport is absent or disconnected, release the gate and return
   (a reconnect + retry re-runs the barrier check before demotion proceeds).
3. Bulk-sync readiness (`syncPeerBulkPrimed`) is deliberately **not** required
   here — planned failover must not depend on bulk-sync state because both nodes
   already have full session state from continuous real-time sync. The bulk
   retry loop is advanced (`syncPrimeRetryGen`) so it stops flooding the sync TCP
   connection and delaying the barrier ack; it is restarted if the barrier fails.
4. Write a single ordered peer barrier (`WaitForPeerBarrier`) and wait for the
   ack. The barrier shares the same FIFO `sendCh` as all sync messages, so the
   ack proves the peer has processed everything queued ahead of it. The actual
   demotion then happens atomically in `UpdateRGActive(false)`.

Manual failover uses the same demotion-prep path via
`prepareUserspaceManualFailover()`, but wraps failures as
`RetryablePreFailoverError` for transient conditions (previous barrier pending,
peer not quiescent, barrier ack timeout). The cluster state machine can retry
admission on retryable errors instead of proceeding unsafely.

### Remote-failover applied-ack is fenced on local demotion actuation (#5640)

When the peer requests this node to transfer an RG out of primary, the receiver
runs `OnRemoteFailover` → `cluster.ManualFailover`, which sets the RG to
`StateSecondaryHold` and **enqueues** an async demotion event onto the manager
event channel (`sendEvent`) before returning. The actual fence — `ResignRG`
(VRRP priority-0 advert + VIP removal) and `rg_active` clear — is actuated later
by the daemon's `watchClusterEvents` consumer, not synchronously inside
`ManualFailover`.

On the RETH-VRRP path `ResignRG` itself is only half-synchronous: it drops the
instance priority to 0 under the instance lock and then does a **non-blocking**
send on `resignCh`. The priority-0 adverts and the `becomeBackup` VIP removal
run on the VRRP instance's own loop, so "resigned" below means *resignation
signalled and priority driven to 0*, not *VIPs off the wire* (#6177 item 1).
Direct-VIP mode (`no-reth-vrrp`) has no such gap — `reconcileDirectVIPOwnership`
removes the addresses inline on the event goroutine.

`handleRemoteFailover` (`pkg/cluster/sync_failover.go`) therefore must **not**
reply `failoverAckApplied` the instant `OnRemoteFailover` returns: the sender
treats that ack as authorization to run `commitRequestedPeerFailover` and become
primary. Acking before the local event consumer has run left a window where the
peer promoted (adds VIPs, sends GARP) while the old owner still advertised as
MASTER and owned the VIPs — two external owners of the RG (duplicate GARP / VIP
ownership / traffic).

The fix gates the applied-ack on a fence-completion barrier:

1. The daemon `OnRemoteFailover`/`OnRemoteFailoverBatch` closures call
   `armFailoverActuation(rgID, reqID)` — registering a barrier keyed by
   **(RG, peer request id)** — **before** `ManualFailover` enqueues the demotion
   event, so the actuation signal can never be missed. A `ManualFailover` error
   disarms the barrier, passing back the handle `arm` returned so the disarm can
   only ever remove *that* barrier (#6177 item 2). Keying on the request rather
   than on the RG alone is what keeps one transfer-out cycle from disturbing
   another: the responder handles each `syncMsgFailover` on its own goroutine, so
   before #6177 an older request's expiry could delete the slot a newer request
   had just armed — the newer wait then found nothing, returned "actuated", and
   the node acked `failoverAckApplied` for a demotion it had not performed.
2. `handleRemoteFailover` calls the `WaitFailoverApplied` hook (wired to
   `waitFailoverActuated`) after `OnRemoteFailover` succeeds and before sending
   `failoverAckApplied`. It blocks on the barrier.
3. `handleClusterEvent` (the per-event body of `watchClusterEvents`), at the end
   of the demotion (non-primary) branch — after `ResignRG` / direct-VIP
   reconcile / `rg_active` clear — resolves the barrier and releases the ack.
   The demotion event carries no request id — it reports that *this node*
   finished demoting the RG — so `resolveFailoverActuation` fans the verdict out
   across every request in flight for that RG.
4. The barrier carries a **verdict**, not just a completion (#6371). The
   demotion branch tracks whether the dataplane accepted the `rg_active` write:
   on success it calls `signalFailoverActuated(rgID)` (verdict `nil`), and on a
   `SetRGActive` error it calls `signalFailoverActuationFailed(rgID, err)`.
   `waitFailoverActuated` returns that verdict, so a REJECTED clear — this node
   may still be forwarding for the RG — downgrades the ack to
   `failoverAckFailed` instead of reporting the fence applied. Failing loudly
   rather than staying silent also keeps the waiter from burning its whole
   timeout on a fence already known not to have landed. The resolved barrier is
   left in the map for `waitFailoverActuated` to consume (a re-arm replaces it):
   deleting it at resolution time would make a failure that lands before the
   waiter arrives read as "never armed", i.e. success.
5. The wait is bounded by `failoverActuateTimeout` (3s default). A demotion that
   never actuates (superseded reset, event-channel drop) downgrades the ack to
   `failoverAckFailed` so the peer **holds** rather than promoting into the
   two-owner window — safety over latency in the race. On the normal path the
   barrier releases as soon as the local resign completes, so failover latency is
   unchanged.

The batch path (`handleRemoteFailoverBatch` / `WaitFailoverAppliedBatch`) applies
the same barrier across the whole set, all members armed under the one batch
request id; the first non-nil verdict fails the batch ack.

**Residual (#6177 item 1, open).** On the RETH-VRRP path the barrier releases
once resignation has been *signalled* (priority 0 set synchronously) and
`rg_active` is cleared — not once `becomeBackup` has physically removed the
VIPs. A sub-millisecond window therefore remains in which the peer may promote
while the old owner's VIPs are still on the interface. It is safe-direction
rather than benign-by-luck: priority-0 is set synchronously so the resigning
node cannot win a re-election, and the demotion preflight
(`tryPrepareUserspaceRGDemotion`) has already shifted the flow cache to
`FabricRedirect`, so transit traffic reaching the old owner is forwarded over
the fabric rather than dropped. Closing it means gating the barrier release on a
`becomeBackup` completion signal from the VRRP instance loop, which is a change
to the VRRP state machine rather than to this barrier.

Once the RG is marked standby, each worker processes a
`WorkerCommand::DemoteOwnerRGS` on its packet thread
(`afxdp/session_glue/commands/demote_owner_rgs.rs`, `handle_demote_owner_rgs`):
it walks every session in the demoted owner RG, re-resolves forwarding (the peer
is now the forwarder), re-publishes the kernel session-map entry, and appends
each demoted key — deduplicated — to `cancelled_keys` so the worker loop can drop
any queued flow and delete stale local XSK redirect aliases. The dedup keeps a
companion `FxHashSet` for an O(1) membership test (#5155): `demote_owner_rg`
yields unique keys, so the pre-#5155 linear `cancelled_keys.iter().any(..)` scan
was O(N²) over the growing Vec — ~8.6e9 `SessionKey` comparisons at
`max_sessions` = 131072, all on the packet worker ahead of the heartbeat store,
i.e. a failover-time stall. The set makes the pass O(N); `cancelled_keys` stays a
Vec so the first-occurrence output order the worker loop iterates is preserved.
The dedup is load-bearing, not belt-and-braces: `demote_owner_rg` only flips a
session's origin to `SyncImport` (it does not remove the entry from the owner-RG
bucket), so a repeated `Demote{[rg]}` in the same dispatch stream re-discovers
the same key.

## Implementation Details

### Incremental Sync Pause/Resume

`PauseIncrementalSync(reason)` / `ResumeIncrementalSync(reason)` provide a
depth-counted pause mechanism. Multiple callers can pause independently; the
sweep only resumes when all callers have resumed. The pause stops only the
periodic sweep goroutine without affecting GC delete callbacks or explicit sync
producers. (These helpers — along with `WaitForIdle` and
`WaitForPeerBarriersDrained` — are retained primitives with no current live
caller; the demotion path uses only the single peer barrier described above.)

### Bulk-Prime Retry Loop

After reconnect, `startSessionSyncPrimeRetry()` retries `BulkSync()` at
increasing intervals (10s, 20s, 40s) if the peer never acknowledges our
bulk with `BulkAck`. Retries are deferred while:

- a pending bulk ack is still young (< 35s since BulkEnd was sent)
- inbound sync progress is still advancing (`syncPrimeProgressObserved`)
- the connection was replaced or disconnected

Retries stop once `syncPeerBulkPrimed` becomes true.

### Readiness Timeout Generation Guard

`armSyncReadyTimer()` captures a generation counter when the timer is armed.
The timeout callback checks that the generation is still current AND the sync
transport is still connected before releasing readiness. `stopSyncReadyTimer()`
increments the generation, invalidating any in-flight callback. This prevents
a stale timer from flipping readiness back to true after a disconnect in a
tight race.

### Barrier Ordering

`WaitForPeerBarrier()` enqueues the barrier message onto `sendCh` (the same
buffered channel used by `sendLoop` for all sync messages) rather than writing
directly to the socket. This preserves strict FIFO ordering — the barrier
cannot overtake messages that `sendLoop` has dequeued but not yet written.

## Invariants

1. Only forward entries are sent on the wire.
2. Reverse entries are recreated locally by the receiver.
3. Received sessions always have cached FIB resolution cleared before install.
4. Timestamps are rebased into the receiver's monotonic clock domain.
5. Session ownership filtering happens before incremental sync or userspace
   delta replication.
6. `local_delivery` sessions are helper-local and are not valid HA sync state.
7. Graceful demotion is ordered against the session-sync stream with a single
   ordered peer barrier (no separate quiesce/republish step on the demotion
   path; the seq-fenced DrainRequest/DrainComplete pair is reserved/dormant).

## Revision History

This document has been corrected through multiple passes:

- v1: Basic bulk + sweep description. Missing sender-side ack tracking,
  demotion protocol, userspace delta filtering.
- v2 (PR #264): Added two-readiness-signal model, bulk-prime retry loop,
  explicit demotion-prep sequence, userspace delta filtering details.
- v3: Corrected delta filtering field names (`FabricRedirect` +
  `FabricIngress`, not a combined field). Clarified that `PauseIncrementalSync`
  only pauses the sweep — GC delete callbacks are never suppressed. Added
  manual failover retry admission logic, depth-counted pause mechanism,
  readiness generation guard, barrier ordering via sendCh.
- v4 (current, #2930): Corrected demotion-path doc drift. The live graceful
  demotion path uses only a single `WaitForPeerBarrier` plus the continuous
  lossless event stream — it does **not** run the old staged
  quiesce/export/`PrepareRGDemotion` sequence (that helper does not exist, and
  `WaitForIdle`/`WaitForPeerBarriersDrained`/`PauseIncrementalSync` have no live
  caller). `ExportOwnerRGSessions(_, 0)` is an unbounded ground-truth republish
  triggered by event-stream **FullResync** (#2874 gap / #2442 overflow), not by
  demotion prep. The seq-fenced `DrainRequest`/`DrainComplete` pair (#2876/#2920)
  is documented as **reserved/dormant** — implemented and hardened but not wired
  to any production path.

## Known Limitations

### Sweep Latency

Kernel-originated session creation is still exported by periodic sweep, not by a
real-time event stream. Short-lived sessions can be missed between sweeps.

### No Real-Time BPF Session Event Stream

There is still no cheap real-time BPF event feed for full session state. The
current design intentionally uses periodic sweep for kernel sessions and keeps
the lower-latency userspace delta path scoped to the AF_XDP helper.

### Delete Journal Overflow

The delete journal is bounded (`deleteJournalCap`, default 10000). Extended
disconnects with high churn can push it past the cap, evicting the oldest queued
deletes. Those evicted records are session teardowns the standby still needs;
they are already gone from the primary's local table, so no incremental install
sweep can re-derive them.

**Recovery (#5450):** whenever an eviction actually DROPS records — in either
`journalDelete` (append past cap) or `rejournalTail` (re-journal-on-failure past
cap) — the drop site arms `forceResync` (a single atomic, CAS-armed once per
overflow episode; counted in `DeletesDropped`). `forceResync` is consumed by
whichever runs first:

- the periodic sweep (`syncSweep`) while connected, or
- the next reconnect (`handleNewConnection`, re-read AFTER `flushDeleteJournal`
  so an eviction during that flush is caught) even when the node is already
  primed (`bulkEverCompleted`),

and it sends a full authoritative `doBulkSync`/`BulkSync` snapshot. (Since #5480
the reconnect leg **always** re-primes regardless of `forceResync`, so the CAS
consume there is retained only to clear the arm, pick the log line, and re-arm on
bulk failure; the **connected-sweep** leg remains the load-bearing `forceResync`
path — it is the only way an overflow self-heals without a disconnect.) The peer's
`reconcileStaleSessions` (run at `BulkEnd`) then DELETES any session absent from
the snapshot — precisely the sessions the evicted deletes would have torn down.
On a failed bulk the arm is restored so a later sweep/reconnect retries. Before
#5450 an overflow only self-healed at the next unrelated full bulk reconcile,
which could be far away, so the standby carried ghost sessions (wrong forwarding
+ inflated session count) for a long time. `forceResync` is deliberately kept
distinct from `bulkEverCompleted` (which the daemon reads for VRRP sync-hold
gating) and from `syncBackfillNeeded` (which only re-drives INSTALLS).

Test coverage: `TestDeleteJournalOverflowArmsForceResync` guards the ARMING at
both drop sites; `TestForceResyncConsumeSweepReconcilesStandby` (#6081) guards
the CONSUME wiring end-to-end — an armed `forceResync` drives one connected
`syncSweep` tick through `doBulkSync` and the replayed bulk window makes the
standby's `reconcileStaleSessions` reap the ghost whose delete was dropped;
`TestForceResyncConsumeReconnectSurvivesRearmDuringBulk` (#6078 MINOR-1) guards
the reconnect CAS symmetry — a re-arm that fires DURING the in-flight cold-prime
bulk survives the consume (the success branch must not clear it) so a later
sweep/reconnect runs the follow-up resync.

### Counter Divergence

Counters are not kept perfectly current by incremental sync. Session state is
more important than exact byte/packet counters for failover.

### Failover Quality Still Depends on Dataplane Behavior

Correct session-sync admission does not guarantee zero-loss failover. The recent
userspace failover work showed that post-admission dataplane behavior can still
collapse if redirected traffic, queue selection, or translated alias handling is
wrong.

## Key Files

| File | Purpose |
|------|---------|
| `pkg/cluster/sync.go` | Wire protocol, bulk sync, barriers, retry state |
| `pkg/cluster/sync_test.go` | Session sync protocol tests |
| `pkg/daemon/daemon.go` | Readiness, retry, userspace delta filtering, demotion prep |
| `pkg/conntrack/gc.go` | GC delete callbacks |
| `pkg/dataplane/types.go` | Session key/value definitions |
| `pkg/dataplane/userspace/manager.go` | Userspace session install, helper RPCs |
| `userspace-dp/src/session.rs` | Rust session table |
| `userspace-dp/src/afxdp/session_glue.rs` | Userspace session promotion / refresh / export |
