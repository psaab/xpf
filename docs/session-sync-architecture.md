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
packet arrived on) are part of the on-map C conntrack ABI, and the IFINDEX
itself is still never synced. An ifindex is node-local — node 0's `ge-0-0-1` and
node 1's `ge-7-0-1` are different numbers for the same logical RETH member — so
carrying the originating node's value would make
`show security flow session interface <name>` name the WRONG interface on the
importing node, which is worse than approximating.

**What IS synced, since #7095, is a cluster-stable FOLD of the interface's
name.** The reth-relative name (`reth0.50`) is byte-identical on both chassis —
zones bind to it, and `RethToPhysical` resolves it to each node's own member — so
`config.StableIfaceID` over that name is agreed by construction.
`IngressIfaceFold` rides as a length-gated trailing u32 (the #2170 pattern, no
`SessionSyncWireVersion` bump), and the RECEIVER resolves it back to its OWN
`{ifindex, vlan}` before the helper stores it. Nothing node-local crosses the
wire; the importing node ends up with its own numbers for the interface the peer
named. Before #7095 every peer-synced session degraded to the zone
approximation, which meant half the sessions on a two-node cluster at all times
and all of them immediately after an RG transition — the diagnostic stopped
working exactly when it was most needed.

`0` still means "no ingress identity carried", and it now arrives from four
places that all want the same fallback: the reverse companion, the
host-outbound GRE path, a legacy peer whose frame stops before the field, and a
session whose interface has no cluster-stable name — including a
fabric-redirected one, which records nothing at all because the fabric stamp
carries a u16 zone id and nothing else (#7096). An UNKNOWN or AMBIGUOUS fold
resolves to nothing rather than to a device: a fold this node cannot place, or
one two stable names collide on, falls back to the zone, because naming no
interface costs an approximation while naming the wrong one is the confidently
wrong rendering #6928 refused to ship.

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
install they strip every NODE-LOCAL field from the peer's row — the cached FIB
result, so the receiving node recomputes forwarding, and the #4983 ingress
identity, so the row lands in the documented `0` branch rather than naming a
NIC by the peer's number.

That strip is single-sourced in `dataplane.SessionValue.ScrubNodeLocal()` /
`SessionValueV6.ScrubNodeLocal()` (`pkg/dataplane/session_node_local.go`,
#7097). It has four callers: these two userspace-manager installers — the pair
production reaches — and the `putClusterSyncedV4Raw` / `putClusterSyncedV6Raw`
fallbacks in `pkg/dataplane/session_store.go`, which run only when the dataplane
does not implement `clusterSyncedSessionInstaller`. Before #7097 each of the
four kept its own hand-written list, and all four listed the five FIB fields and
not the ingress pair that #6928 had added to the ABI: the lists went incomplete
together, in one change, with nothing to notice. Nothing reached any site with a
non-zero value — the session wire below never encodes `IngressIfindex` /
`IngressVlanID`, so a decoded peer row carries `0` — so the gap was latent, not
live. `TestScrubNodeLocalCoversExactlyTheNodeLocalFields7097` (a reflection
census, both directions, plus a struct field-count pin) and
`TestClusterSyncedInstallSitesDelegateTheScrub7097` (an AST pin that every
peer-install site delegates and none has re-grown a private list) are what keep
the one list complete.

A reverse COMPANION has its own reset, distinct from the node-local scrub:
`SessionValue.ResetUnobservedForReverseCompanion()`
(`pkg/dataplane/session_reverse_companion.go`, #7917). It clears fields because
the reverse direction has not OBSERVED them yet, not because they belong to
another node — a different question with a different answer.

**Since #8015 the Go control plane builds no reverse companion, so that helper
has no caller in tree.** The mirror sends the forward alone and the Rust helper
synthesizes the companion itself (`synthesized_synced_reverse_entry`,
`userspace-dp/src/afxdp/shared_ops.rs`), where the same rule is applied —
`ingress_ifindex: 0`, `ingress_vlan_id: 0`, with the reason stated inline — and
pinned by `synthesized_synced_reverse_entry_carries_no_ingress_identity_7917`
(`afxdp/session_glue/tests.rs`). The Go function and the table below remain as
the statement of the RULE, and
`TestCompanionResetAndNodeLocalScrubAreDifferentRules7917` still pins its
divergence from `ScrubNodeLocal`, so a future node-local field does not silently
become a companion reset (or vice versa).

Before #7917 the Go companion cleared only the cached FIB result, so it
inherited the FORWARD direction's #4983 ingress identity. `pkg/dataplane/types.go` already
named the companion as the first legitimate-`0` population and gave the reason —
the forward flow's egress is a PREDICTION of where the reply will arrive, not an
OBSERVATION of where it did, and routing may be asymmetric — so the code
contradicted the contract the design note states.

The two resets are NOT interchangeable, and since #7095 they no longer even
cover the same fields:

| field | `ScrubNodeLocal` | companion reset |
|---|---|---|
| `Fib*` (5) | yes | yes |
| `IngressIfindex` / `IngressVlanID` | yes | yes |
| `IngressIfaceFold` | **no** | **yes** |

`IngressIfaceFold` is the #7095 CLUSTER-STABLE fold whose entire purpose is to
cross the wire so the #4983 identity survives a failover, so the node-local scrub
must leave it alone. The companion must clear it, because
`buildSessionSyncRequestV4` resolves the request's ingress identity FROM the fold
(`resolveIngressFoldLocked`) — a companion that keeps it stamps the forward
direction's binding onto the row the helper installs, which is the wire half of
the same defect. `TestCompanionResetAndNodeLocalScrubAreDifferentRules7917` pins
the divergence so the two cannot be folded together.

**#7581 — a synced import with no pool to reserve from is not a collision.**
Before publishing a peer-synced session the helper reserves its translated NAT
tuple (#6600), so the standby cannot advertise a translation a local flow
already owns. That reservation walks the source-NAT rules for one whose POOL
contains the translated address. It used to return a bare `bool`, which
collapsed two opposite outcomes into one `false`: a pool-owning candidate that
DECLINED (a genuine collision), and NO candidate owning the address at all.

**Interface-mode source NAT is permanently the second case** — the translated
address is the egress interface's own address, no rule is `pool_mode`, and no
allocator has anything to hand out. So every peer-synced import under
interface-mode SNAT read as a collision, and `upsert_synced_session` refused it
BEFORE `publish_shared_session`: since #6600 those sessions reached neither the
standby's shared `synced` map nor its worker tables, and a promoted node had no
state for the flow. It was invisible because the Go side still wrote and kept
its BPF mirror row — which is what `show security flow session` reads — so an
operator saw synced sessions the forwarding path did not have. Measured on the
loss userspace cluster: 17 refusals on the standby during one iperf3 run, all
`reserve`, with `xpf_userspace_synced_import_cap_drops_total` at 0.

The reservation is now tri-state (`SyncedReserveOutcome`): `Reserved`,
`Refused`, and `NothingToReserve`. Only `Refused` blocks the publish;
`NothingToReserve` is answered exactly like the long-standing
`rewrite_src == None` early return one line above it.

**#9678 — local ownership is decided before the reservation.** The #6600
reservation runs before the worker's ownership check. The worker refuses a
peer upsert that would replace a locally-owned session while that session's
owner RG is locally forwarding-active (`upsert_synced_with_origin` with
`synced_entry_allows_local_replace`). But `reserve_flow` retires an incumbent
`live_by_flow` record holding a DIFFERENT translated tuple. So a same-flow peer
upsert in a dual-primary window, or in a failover race, evicted the local
flow's live allocation T1 and reserved an `Untracked` T2. The worker then kept
forwarding on T1 with no allocator record behind it, and T1 could be handed to
another flow. Every refusal inside the reserve happens after that unlink, so
even a `RejectedReserve` import had already freed T1.

`upsert_synced_session` now applies the worker's own predicate first: the
shared map holds a local-origin entry for the key AND the incoming owner RG
does not allow a local replace. In that case the import stops before the
reservation, the shared publish and the worker fan-out, and it reports
`Applied`, mirroring the worker's refusal, which is silent too. Skipping only
the reservation would still have published the peer's decision into the shared
maps, which is the #6600 shape of a shared entry naming a port this node does
not hold. Once the RG is no longer locally active, the next sync of the flow
imports normally. An active node with no local session for the flow still
reserves before it publishes.

**#7209 — an admitted import with no kernel session map is now visible.** After
the reservation, `upsert_synced_session` publishes the row to the kernel session
map. That publish sat behind one conjunction:

```rust
if synced_entry_allows_local_replace(..) && let Some(fd) = ..session_map_fd
```

whose two operands mean opposite things. The FIRST failing is correct: the peer
owns the redundancy group, so this node must not take the redirect. The SECOND
failing is a gap — the entry is recorded in the shared `synced` map and answered
to Go as installed, while no kernel row exists, and `SyncedImportOutcome::Applied`
is returned with no refusal reason. `bpf_maps.session_map_fd` is `None` before
the first successful reconcile and between `stop_inner` and the next
`reconcile::bringup`, so an HA standby taking bulk sync before its first snapshot
apply lands there for every session in the batch.

**That is not a loss today**, and the counter is not an alarm. Every `reconcile`
replays the shared synced map once the new session map is up, so an entry
recorded while the fd was absent is published by the next reconcile.

**Corrected by #8157 (PR #8171) — the capture→replay window is closed by construction, not
by the mutex.** This section previously said `teardown::tear_down` captures the
whole map via `snapshot_shared_session_entries()` before `stop_inner(false)` and
that an entry arriving between that capture and the replay was excluded only by
the snapshot-wide `ServerState` mutex. That was true when written and is no
longer: `replay_preserved_sessions` (`reconcile/bringup.rs`) now derives the
replay set from the LIVE shared map at replay time — after every arrival the
reconcile could race — carrying `filter_replayed_synced_sessions` with it so a
remapped-tunnel session is not resurrected. `stop_inner(false)` does not clear
`sessions.synced` (the clear is gated on `clear_synced_state`, which only full
shutdown passes, #6652), which is what makes the live read sound. The historical
shape is recorded here because the mutex-based reasoning it supported still
appears in older comments.

That mutex is what #7209 PROPOSES to remove for `sync_session` — still open at
the time of writing; `sync_session` continues to dispatch under it — which is why
the counter landed first. Before #8171, an import arriving in that window would have been
recorded, acked to Go as installed, never published and never replayed — with no
signal anywhere. The conjunction is therefore split into one authority,
`publish_synced_entry_or_note_unpublished`, and the absent-map arm bumps
`xpf_userspace_synced_import_unpublished_total`. It counts the GAP only: the
owner decision is not counted, or the metric would sit permanently nonzero on a
healthy node, and a publish that was ATTEMPTED and failed stays with the #1789
`session_publish_errors` counter. Whatever deferred-and-replay design accompanies
#7209 can then be shown to drive this counter to zero rather than asserting the
property from a reading of the lock graph.

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
`SetSessionV6()` install into the kernel/BPF maps, then mirror the forward entry
— and ONLY the forward entry — to the local Rust helper over the session control
socket. The request resolves egress/zone/tunnel-endpoint metadata from
`m.lastSnapshot` and the compile result.

**#8015: one upsert, not two.** Until #8015 the mirror also sent an explicitly
built `is_reverse=1` companion, added under #310 so the helper would hold the
reverse before RG activation. That second request was redundant:
`upsert_synced_session` (`userspace-dp/src/afxdp/ha/session_import.rs`) calls
`synthesized_synced_reverse_entry` for EVERY non-reverse import — a total
function on forwards — and publishes both halves through
`publish_shared_session`. A single forward upsert therefore already leaves a
COMPLETE PAIR; the #5674 aggregate ENTRY cap is sized at 2x the logical session
ceiling precisely because of it. Synthesis happens AT IMPORT, which is earlier
than the Go pre-install ever was, so #310's invariant is satisfied by the
request that remains — and the helper's companion is the better one, because it
resolves egress/FIB, fabric/tunnel and owner-RG against live node-local state
where the control plane could only copy the forward's (#5698).

What the second request added was a failure mode. If the helper SEMANTICALLY
refused the forward (`RejectedCapacity` and friends — a transport failure aborts
the batch instead), the explicit reverse still went out and published alone: a
reverse-only entry with no forward, which a later delete of that forward does
not remove, because `delete_synced_session_gen` derives the companion from the
STORED forward and there is none. It idles out under `reap_expired_sessions`.
#8015 removes the sender AND closes the door: `upsert_synced_session` now
REFUSES an entry that arrives already flagged `is_reverse`
(`SyncedImportOutcome::RejectedStandaloneReverse`, wire token
`synced-import-refused:standalone-reverse`), because a reverse entry is derived
state and can never be standalone authority.

With one request the #5007 single-snapshot build and the #5698 contiguous
transmit are both vacuous — there is no second half to resolve against a
different `m.lastSnapshot`, and none to be interleaved away from — so the mirror
takes the ordinary per-request path (`syncSessionV4Locked` /
`syncSessionV6Locked`) and `syncSessionPairLocked` / `sessionPairMaxRequests`
are gone. Bulk paths are unchanged: the delete chunks (up to
`sessionHelperDeleteChunk`, 256) and the authoritative clear-all keep the
per-request `m.sessionMu` discipline on purpose, because holding it across a
256-request chunk would starve live session installs for minutes — the harm the
#5380 fast-fail exists to bound.

Pinned by `TestMirrorSessionSendsOnlyTheForwardUpsertV4_8015` / `...V6_8015`
(`pkg/dataplane/userspace/session_mirror_single_upsert_8015_test.go`), which
assert the exact request set rather than the absence of a flag, and by
`upsert_synced_session_refuses_standalone_reverse_8015` (`afxdp/ha_tests.rs`),
whose control leg re-measures the forward-only-leaves-two-entries fact the
deletion rests on.

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

### Decode Contract: which short reads are legitimate (#7175)

A session payload may legitimately be SHORT — that is how the wire is extended.
Every field appended since the original format is length-gated, so a newer peer's
record decodes on an older node, which stops after the last field it knows:
`Generation` (#2170), `AppTimeout`/`PolicyCounterIdx` (#3301), `ConfigEpoch`
(#5274), `RTFlowSessionID` (#5212), `IngressIfaceFold` (#7095). An absent
extension reads as 0, meaning "legacy peer", and that is not an error.

**But a short read is only legitimate PAST the forwarding-semantic block.**
`SessionID`, `PolicyID`, both zone ids and the NAT fields are not extensions —
no encoder version has ever omitted them — so a payload that stops before them
is malformed, not old. Before #7175 the decoder accepted one anyway, returning
`ok=true` with every one of those fields left at **zero**.

Zero is not "missing" here — these are *values the standby installs and carries*,
and they become live forwarding state on the next failover. A decoder must not
report success for input it did not decode.

> **Correction.** An earlier version of this section claimed that zone id 0
> against zone id 0 is matched by a `from-zone any to-zone any permit` rule with
> no zone guard, citing #6682. That was the **problem statement of a closed
> issue**, not current behaviour. **Two** mechanisms make it false: #3110 fenced
> every rule tier against zone 0 — `policy.rs` records that the rule-tier block
> "is skipped entirely when either zone id is 0, which correctly stops every rule
> tier — zone-pair, from-any, to-any, both-any and junos-global — from matching"
> — and #6682 then made an unzoned **ingress** an explicit deny. A zero zone pair
> does **not** reach a wildcard permit.
>
> The corrected version was already recorded in this repo, at
> `compiler_wireguard_plaintext_warn_5618_test.go`, before the superseded claim
> was written here.
>
> The decode contract does not depend on that claim and is unchanged. What a
> zero-zone session does downstream once installed is **not** established here
> and should be measured rather than asserted. The precondition is a malformed frame no legitimate encoder emits
(fabric corruption, a version-skewed or buggy peer, a compromised peer), which is
narrow — and is exactly the case where fail-open decoding is worst, because the
receiving node has no other check.

`decodeSessionV4Payload` / `decodeSessionV6Payload` now return `ok=false` for a
payload truncated before that block; v6 has TWO such blocks because its 16-byte
NAT addresses are carried separately. Everything from the counters block onward
remains length-gated. Rejections increment `SyncStats.MalformedRecordsDropped`
and log — a silently skipped install is how corruption hides.

The same contract applies to the DHCP full-set push
(`decodeDHCPLeasePayload`), which returns an `ok` flag. It matters more there
than it looks: a full-set push **replaces** the peer lease set, so returning a
truncated prefix deletes every lease past the cut on the standby. Two cases are
distinguished deliberately:

| frame | disposition | why |
|---|---|---|
| a record CUT mid-stream (declared length overruns the buffer) | **reject**, retain prior set | part of a lease is gone |
| count over-declared, every shipped record whole | accept | no data lost, only the count is wrong |
| trailing bytes after the last record | accept | the #5073 full-set seq trailer is appended exactly so old decoders ignore it |

The retain-prior-set disposition mirrors the stale-sequence guard in the same
switch ("standby retains newer set").

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
| 9 | IPsecSA | Primary -> Secondary | IPsec SA names from `swanctl --list-sas`: child SA names, or the IKE connection name for an IKE SA with no child yet (#9511) |
| 10 | Failover | Bidirectional | Remote failover request |
| 11 | Fence | Bidirectional | Peer fencing |
| 12 | ClockSync | Bidirectional | Monotonic clock exchange |
| 13 | Barrier | Primary -> Secondary | Ordered demotion marker |
| 14 | BarrierAck | Secondary -> Primary | Barrier acknowledgement |
| 15 | BulkAck | Secondary -> Primary | Bulk acknowledgement |
| 30 | ConfigKeyExchange | Bidirectional | Ephemeral X25519 public key for config-payload encryption (#6629) |
| 31 | ConfigEncrypted | Primary -> Secondary | Type 8's payload, sealed (#6629) |
| 32 | AuthUpgradeHello | Initiator -> Responder | In-place authentication upgrade: Noise msg1 (#6628, #7163) |
| 33 | AuthUpgradeProof | Responder -> Initiator | In-place authentication upgrade: Noise msg2 (#6628, #7163) |
| 34 | *(retired)* | — | Was AuthUpgradeAck, the fourth frame of the pre-#7163 exchange. Left unused rather than recycled. |
| 36 | AuthUpgradeConfirm | Initiator -> Responder | In-place authentication upgrade: handshake-binding MAC, and the responder's read boundary (#7163) |
| 37 | AuthUpgradeRequest | Responder -> Initiator | In-place authentication upgrade: the responder-role node asking the initiator-role node to start (#7163) |

### In-Place Authentication Upgrade (#6628)

A connection's authentication was fixed at setup: `performSyncHandshake` runs
only when a local key is configured, and committing a key does not restart
cluster comms (`clusterTransportKey` excludes it, pinned by
`TestAuthKeyChangeDoesNotRestartClusterComms_5078`). So an established stream
stayed unauthenticated indefinitely after the key was committed, and a rotation
never rekeyed a live connection.

`ReconcileConnectionAuth` runs from the apply tail on every commit and starts an
upgrade on any connection whose recorded PSK differs from the live one. It is a
**mid-stream key switch**, so the frame key is held per direction
(`authConn.readKey` / `writeKey`) and each side switches at the boundary the
peer switched at — TCP's per-direction ordering makes a frame an unambiguous
boundary.

Since **#7163** the exchange is Noise_NNpsk0, the same construction as the
connect handshake (`sync_auth_noise_7163.go`), separated from it by a phase byte
in the prologue. It had to move: the pre-#7163 exchange called `syncAuthProof`
and `syncDeriveFrameKey`, so converting only the connect handshake would have
left this as a SECOND admission path carrying the identical two-connection
oracle — and the one an attacker picks, because it is the one that still
accepts.

```
I (node 0)                             R (node 1)
-- Hello{noise msg1} ----------->
                                       reads msg1 ⇒ key equality PROVEN
                                       (psk0 tags the first message)
                                       <-- Proof{noise msg2} --        then R sets writeKey
reads msg2 ⇒ sets readKey
(that frame IS the boundary)
-- Confirm{MAC(i2r, binding)} -->      then I sets writeKey
                                       verifies MAC, sets readKey
                                       (that frame IS the boundary)
```

**Three frames, where #6628 needed four.** The Ack existed because the responder
"has proven nothing" when it switches. Under Noise_NNpsk0 that premise is false:
psk0 mixes the PSK into the chaining key before the first message is encrypted,
so msg1 is 48 bytes — a 32-byte ephemeral plus a 16-byte Poly1305 tag over an
empty payload — and reading it proves key equality *before* R answers. This is
measured, not assumed (`TestUpgradeMsg1IsAuthenticated7163`); if it stopped
holding, the three-frame shape would be unsafe.

**The Confirm still carries a MAC** even though R has already authenticated I.
It is not a proof of possession — msg1 was that — it is an unforgeable BOUNDARY
MARKER: without it, anyone able to inject a frame into a not-yet-sealed stream
could make R start requiring a trailer while the real I is still writing
unsealed frames, and the connection would drop.

**Role comes from node id**, the lower id initiating. #6628 decided it by
comparing the two nonces, which made role a function of a peer-supplied value
feeding this node's own key derivation — the same mistake vector B exploited.
The higher-id node therefore cannot open the exchange; when it is the one that
becomes keyed first it sends an `AuthUpgradeRequest`, which carries no key
material and moves no boundary.

**A round is not replaceable while the peer may have committed to it.** A msg1
is 48 bytes of cleartext on a not-yet-sealed stream and its tag covers only the
prologue and the initiator's ephemeral, so a captured Hello RE-VERIFIES.
Answering a replayed one would mint a second round on top of a commitment
already made — the initiator derived its keys from the FIRST msg2 — and the
connection would desync in both directions. #6628 was immune because its round
state was set-once nonce state; Noise state is not. Three guards implement the
rule: the responder refuses a msg1 while awaiting a Confirm, the initiator never
supersedes an incomplete round (not even for a rotation), and the responder
stays silent rather than prompting in that window. The two escapes that keep a
rotation from stranding are an `AuthUpgradeRequest` from the peer and a round
that completes under a retired key re-triggering itself. Neither is a timer, and
a fourth frame would not help: the initiator's write install is unilateral
either way, so the fix is that the state a commitment depends on cannot be taken
away.

A Request carries no MAC — on a not-yet-sealed stream there is nothing to key
one with that a replay would not also carry — so it is treated as a hint, not an
instruction: a Request for a round still outstanding under the same key
RE-SENDS that round's Hello byte for byte rather than minting a new one. A
forged Request therefore cannot discard a round either. A rotation still starts
a fresh round, since the peer would refuse the old key's msg1; that narrow case
is the residual named in `sync_auth_upgrade.go` under NEVER DROPS, and its
precondition — frame injection on an unauthenticated session-sync stream — is
one where the attacker can already send `Fence` and disable every redundancy
group the victim owns.

**Two install points per direction, not one.** `Split()` returns two independent
keys where `syncDeriveFrameKey` returned one shared value, so read and write are
installed separately in each direction. They cannot land out of order: each is
anchored to one frame, the writer installs immediately after writing it inside
the `writeMu` section, and the reader installs while processing it. The two
frames that complete a direction — the Proof and the Confirm — are therefore
deliberately NOT gated on the live control-link key: a key rotated or cleared
between the Hello and one of them would otherwise leave the peer sealing into a
reader that never moved.

**Not closed:** a hostile stream admitted before the commit declines the upgrade
by staying silent, and a decliner is indistinguishable from a legitimate
not-yet-keyed peer. Closing that needs a bounded drop window — the mechanism
#5078 shipped and removed.

(Types 16-29 are listed in `pkg/cluster/sync.go`. Types 30-31 are called out in
the table above because they change how type 8 travels; 32/33/36/37 because they
are how an established connection becomes authenticated at all.)

### Config-Payload Confidentiality (#6629)

The config text a primary pushes is the ACTIVE TREE rendered unredacted —
`ShowActive()` goes through `ConfigTree.Format()`, which does not redact,
deliberately, because the same render backs persistence, rollback, the DR
archive and the on-box CLI, "none of which may lose the real secret"
(`pkg/configstore/store_format.go`). So every `config.Secret` leaf crosses the
fabric inside a type-8 payload, including `chassis cluster
authentication-key` — the PSK that authenticates this very link.

The exposure is circular. Session-sync authentication is fixed PER CONNECTION
at handshake time, and committing a key does not restart cluster comms
(`clusterTransportKey` excludes it, pinned by
`TestAuthKeyChangeDoesNotRestartClusterComms_5078`), so the connection that
carries the PSK to the peer is by construction the one handshaked while BOTH
ends were unkeyed: neither authenticated nor confidential. A passive observer
learns the key as it is introduced, and every subsequent HMAC on the link is
then forgeable by them. The rollout defeats itself on first use.

**Mechanism.** `installConn` generates a fresh ephemeral X25519 keypair per
connection; `handleNewConnection` advertises the public half beside
`sendCapabilities` (type 30). On receipt each end derives an AES-256 key with
HKDF-SHA256 over the ECDH shared secret, salted with the two public keys in
canonical order so neither end needs to know which dialled. `QueueConfig` then
seals the type-8 payload — byte-identical plaintext, generation trailer
included — and sends it as type 31. The receiver decrypts and hands the
plaintext to the same `handleConfigPayload` the cleartext arm uses, so the two
cannot diverge on ordering, generation accounting or apply admission.

**Forward secrecy.** The keypair is per connection and `handleDisconnect`
drops it, so a reconnect derives a different key and a key recovered later
cannot open a capture taken on an earlier connection
(`TestConfigCryptoReconnectDerivesFreshKey6629`).

**What it does NOT close.** An ACTIVE man-in-the-middle. The ephemeral
exchange on an unkeyed link is itself unauthenticated — there is nothing to
authenticate it WITH, which is the bootstrap problem — so an attacker who can
rewrite frames can substitute their own public keys and read the payload. That
concedes nothing already conceded: on an unkeyed control segment an active
attacker can already drive failover, call the allowlisted fabric RPCs and
inject sessions, which is #6611's own rationale for requiring a key. This is
not a confidential channel; it removes the passive-capture class from one
message type.

**Mixed version.** A peer that predates this never sends type 30, so no key is
derived and the push falls back to cleartext type 8 — exactly today's
behaviour — after a bounded wait that latches, so the cost is one wait per
connection rather than one per push. The fallback logs a WARNING naming the
exposure and whether a control-link key is configured (never the key). Both
types are additive with NO `SessionSyncWireVersion` bump: the receive switch
has no default arm, so an old peer ignores them, and bumping would make the
#1930 INC-3 mixed-base gate refuse SESSION sync across the very rolling
upgrade this must survive.

**Why not exclude the leaf from the payload.** `Store.SyncApply` promotes the
received tree WHOLESALE and its compile is lenient
(`compileTreeLenient` -> `lenientClusterAuthKey`), so #6611's validator warns
rather than rejects on that path: a payload with the leaf stripped makes the
standby's active config LOSE its own key, and every control channel there
silently reverts to fail-open dual-accept. On a rolling upgrade a new primary
would drive an old standby unkeyed. Encryption's mixed-version fallback is "no
worse than today" instead. Excluding the leaf and provisioning the PSK out of
band remains the eventual posture, but it lands as ONE design with #6628 and
#6630 — see "The three-way incompatibility" in `pkg/cluster/README.md`.

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

`doBulkSync()` frames one authoritative window. The window's SESSION SOURCE is
chosen once, up front:

- **table truth (production, #6031)** — when `SessionSync.BulkSnapshotSource` is
  wired, `BulkSyncSnapshot()` frames the caller-supplied snapshot;
- **the backend session store** — otherwise, `BulkSync()` walks
  `sessions` / `sessions_v6`.

Both then run the SAME lossless send core (`bulkSyncWindow`):

1. allocates a new monotonically increasing epoch
2. sends `BulkStart(epoch)`
3. walks the chosen source
4. stamps the install generation + config epoch on each entry
5. sends forward entries only
6. records `pendingBulkAckEpoch` (**before** the `BulkEnd` write)
7. sends `BulkEnd(epoch)` and then waits for peer acknowledgement

The store walk (and only the store walk) additionally skips reverse entries and
sessions whose ingress zone this node does not own. A caller-supplied snapshot is
framed VERBATIM — see "Why the window is not framed from the BPF mirror" below.

#### Why the window is not framed from the BPF mirror (#6031)

`BulkSync()`'s `ForEachV4/V6` walk reads the pinned `sessions` / `sessions_v6`
BPF **conntrack** maps. Under the userspace dataplane those maps are a
best-effort **display mirror**, not the authoritative session set.

When #6031 was written the gap was total: the Rust helper published a conntrack
row (`publish_bpf_conntrack_entry`) from only three sites in
`afxdp/poll_descriptor` — the host-inbound (LocalMiss) install, the
missing-neighbor seed, and the reverse-companion repair — and the ordinary
**transit** forward install, the site labelled "#4800: the single place a
locally learned transit forward flow is installed", wrote only the shim
steering map (`publish_live_session_entry`) and the shared session tables. **A
transit session therefore had no conntrack row at all**, and the store walk
could not see it.

**#6965 added the transit publish, so that particular blindness is gone — and
#6031's conclusion is unchanged anyway.** The mirror is still a DISPLAY mirror
rather than table-truth, for a reason that has nothing to do with which sites
publish: the helper owns session lifetime in its own `SessionTable`, the mirror
is written best-effort (a publish that fails under map pressure is counted, not
retried), and the Go GC has `SkipSweep` set precisely because the map is not
authoritative. Framing the window from it would still be framing it from a
copy. The table-truth window source stays.

The standby's copy of that same session IS in its mirror, because the Go receive
path writes it (`userspace.Manager.SetClusterSyncedSessionV4` →
`bpfShim.SetSessionV4`), and `reconcileStaleSessions` scans exactly that map.
Since #5085 removed the empty-bulk skip, an eligible session absent from the
window is DELETED. Framing cold prime from the mirror therefore deleted the
standby's live peer-owned **transit** sessions — the ones failover depends on —
on every cold prime, survivor-fabric re-drive, and forced resync. Measured with
the `pumpBulk` harness at base: the window carried only the host-inbound row and
the receiver logged `reconcile stale sessions applied stale_v4=1 deleted_v4=1`.

`BulkSnapshotSource` is wired in `startClusterComms` to
`Daemon.userspaceBulkSnapshot`, which gathers the owner-RG-filtered live set from
the helper's in-process `SessionTable` via `ExportOwnerRGSessionsPaged(rgIDs)`.
That control request is synchronous — the helper enqueues the export to every
worker, waits for their acks, and returns the drained delta set in the response
(`afxdp/ha/export.rs`, `OwnerRgExportWait::wait_and_collect`).

**The resolver reaches that method by RUNTIME TYPE ASSERTION, and that seam
silently broke the whole cold prime once (#9482).** `userspaceBulkSnapshot` does:

```go
exporter, ok := d.dataplane().(userspaceSessionExporter)
if !ok { return ..., errors.New("dataplane does not export owner-RG sessions") }
```

`userspaceSessionExporter` (unexported, `pkg/daemon`) names exactly one method,
and #9344 changed WHICH one — from `ExportOwnerRGSessions(rgIDs, max)` to
`ExportOwnerRGSessionsPaged(rgIDs)` — adding the new method to
`*dpuserspace.Manager`. But the value the daemon publishes for the userspace
backend is `*LegacyDataPlaneAdapter` (`dpuserspace.Boot()` returns
`NewLegacyDataPlaneAdapter(New())`), a hand-written forwarding subset of the
Manager, and the new method was not added to it. The assertion then failed on the
ONLY type it is ever handed. Measured on the loss userspace cluster: BOTH nodes
logged

```
cluster sync: owed cold-prime re-drive failed, will retry
  err="bulk sync table-truth snapshot: dataplane does not export owner-RG sessions"
```

once a minute, indefinitely, and every cold-start edge logged `bulk sync failed`
with the same cause. `doBulkSync` fails CLOSED — correctly — so a rejoining node
received **no bulk window at all**, only whatever incremental deltas arrived
afterwards.

Three things about that seam are worth keeping:

- **A runtime type assertion has no compile-time edge.** The two sides drifted and
  nothing said so until a cluster rejoined in production. The belt is now
  `pkg/daemon/bulk_snapshot_published_type_9482.go`, which spells the real
  interface and the real published types in one expression, so either side
  drifting breaks the BUILD. It asserts BOTH `*LegacyDataPlaneAdapter` and
  `*Manager`, because `pkg/dataplane/userspace` declares exactly those two as
  `dataplane.RuntimeDataPlane` — asserting only the one that broke would leave the
  identical hole in its already-publishable sibling.
- **Every pre-existing test was blind to it by construction.** `wiringExporterDP`
  (#7259) and `recordingExporter` (#6031) each declare
  `ExportOwnerRGSessionsPaged` on themselves, so the family proves the resolver
  correct *for a type that satisfies the interface* and says nothing about the type
  production publishes. Deleting the adapter's forwarder leaves all of them green.
  The #9482 cells go through `dpuserspace.Boot()` instead of a fake.
- **Scope, because it is easy to misread.** This is why the #7162 startup
  promotion hold always ran its full 30s and always released `timeout-degraded`
  (the `bulk-sync-complete` edge it prefers could never fire). It is NOT why a
  manual failover left an RG owned by neither node — that was #9452's readiness
  gate, which is fixed separately, and which is documented as releasing on its own
  timer regardless of sync state. #9452 was not incompletely fixed.

**The window is PAGED, and it has a terminating bound (#9344).** Until #9344 the
caller asked for `max = 0`, the UNBOUNDED set, because a capped export truncated
the window and the peer deleted the remainder — so the one knob the call
exposed had exactly one safe setting. The unbounded answer is bounded only by
the control socket's 64 MiB `MaxControlResponseBytes`, and a worst-case
`SessionDeltaInfo` is ~1.5 kB of JSON, so the cap is crossed at roughly 7.8k
sessions per worker on the loss cluster's six-queue VFs — at which point
`doBulkSync` fails closed and the cold prime fails PERMANENTLY, every attempt.
Raising the cap is not a fix: the theoretical maximum answer is
`workers x 131072 x 1.5 kB`, which is 1 GiB at six workers and 2.8 GiB at
sixteen, and the only source for the worker count is the helper — sizing an
allocation bound from a value the bounded party supplies is not a bound.

So the export pages:

- the helper reports `session_export_more` when a `max`-capped drain left
  deltas from the same window buffered. The bit is not new — the fair drain
  (`drain_session_deltas_fair`, #5290) always computed it and the owner-RG call
  site discarded it into `_overflow`;
- pages after the first set `continuation`, which drains the remainder WITHOUT
  re-running phase 1. An ordinary second call would kick every worker again and
  stack a fresh full set on top of the remainder, so the caller would assemble
  one window out of two different instants — a different bug from truncation,
  not a smaller one;
- the Go caller holds the manager lock across every page. The per-binding delta
  buffers this export drains are the same ones the incremental
  `drain_session_deltas` verb drains, so an interleaved incremental drain
  between pages would steal part of the window;
- the loop is bounded (`maxOwnerRGExportPages`) and fails CLOSED past it. A
  partial window is exactly what the receiver turns into deleted sessions, so
  "return what we have" is not an option here;
- every other error exit returns no window either (#9699). A helper-status
  apply that fails after a page used to return the deltas collected so far
  BESIDE the error. So did the same failure in the unpaged fallback and in the
  one-shot `ExportOwnerRGSessions`, and the runtime passthrough wrapped those
  deltas into a snapshot it returned with the error. Both production callers
  discard deltas on error, so no receiver was fed one, but the contract is one
  complete window OR an error, never both, and the API now keeps it;
- a helper that does not report the paging contract
  (`session_export_paging_protocol_version`) still gets the unbounded request.
  Such a helper honours `max` by TRUNCATING and reports no more-bit, so paging
  it would trade a loud failure for a silent one.

The verb also carries a WORK deadline floor (`controlVerbDeadlineFloors9344`).
`controlRoundtripDeadline` sizes the control-socket round trip off the REQUEST
body, and this request is ~60 bytes, so it landed on the 3 s small-request base
while the helper spends up to `OWNER_RG_EXPORT_ACK_WAIT` (15 s) waiting for
worker acks before writing its first byte — #4036's failure shape on the work
axis instead of the size axis. The floor does not move `controlMaxDeadline` or
the #7675 reachable bound.

Two invariants hold this together:

- **One admission filter.** The snapshot is built by `walkUserspaceSessionDeltas`
  — the SAME walk and the SAME `shouldSyncUserspaceDelta` filter the incremental
  delta stream uses, with a different sink. The standby must end up holding the
  same set whichever path delivered it, and the window DELETES whatever it omits,
  so a divergence between the two filters is always a bug. Single-sourcing the
  walk makes that divergence unrepresentable. This is also why the snapshot is
  framed verbatim: re-applying the coarser `ShouldSyncZone` filter on top of the
  owner-RG one could drop an entry the incremental path admits (a session whose
  owner RG this node holds but whose ingress zone maps elsewhere), and that
  entry would then be deleted on the receiver. Since #6599 a fabric-redirect
  wire alias is no longer such an entry — that branch now applies
  `ShouldSyncZone` itself — but the owner-RG example above is untouched, so the
  verbatim framing is still what keeps the two paths' sets identical.
- **Fail CLOSED.** If the snapshot source errors, `doBulkSync` returns the error
  and frames **no window at all** rather than falling back to the mirror walk. An
  incomplete authoritative window destroys live sessions; framing none merely
  defers the reconcile, and every `doBulkSync` caller leaves its cold-prime /
  resync obligation armed for the next attempt. For the same reason a failed
  export is never degraded into an EMPTY snapshot — an empty window is an
  assertion that this node owns nothing, which the peer acts on by deleting every
  session it holds for our RGs.

A close delta drained alongside the export retracts its key from the snapshot
(`snapshotDeltaSink.deleteV4/V6`): the export drains the same per-binding delta
buffers the incremental path reads, so an open and a later close for one key can
arrive in a single batch, and framing the already-closed session would resurrect
it on the peer.

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

**What "that sweep" reads (#6948).** The deletion-clear no longer enumerates the
session table after the apply. Runtime policy ids are POSITIONAL, so a new
snapshot renumbers them and a surviving policy can inherit a deleted policy's
id; and the helper's #3395 live-row refresh
(`refresh_bpf_conntrack_last_seen`) re-resolves every forward row's `policy_id`
against the CURRENT rule table into the same pinned conntrack map the control
plane enumerates. Both writers make a post-apply read mean something other than
what the old-numbering diff meant. The candidate sessions are therefore captured
in ONE pass at the last statement before `rt.ApplyConfig` publishes the snapshot
(`capturePolicyInvalidationLocked`) and the deletes — including the #2468 peer
delete-sync — are issued from that capture afterwards. The capture is a READ, so
it cannot re-admit anything; the deletes still land after the new policy set is
live, so a cleared flow re-evaluates against the new config.

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

**The reset does not drain the config-apply QUEUE (#5084).** A config payload
already sitting in `configApplyCh` when a rebooted peer re-primes belongs to the
peer's PREVIOUS boot, and its generation — drawn from the pre-reboot monotonic
seed — is far higher than anything the new boot can produce. Applying it after
the reset records that generation as the high-water and refuses the rebooted
peer's current config from then on. Every queued item is therefore stamped with
the peer's BOOT INCARNATION (`/proc/sys/kernel/random/boot_id`, carried as a
length-gated 8 → 24 byte extension of the `BulkStart` payload), and a payload
whose incarnation a re-prime has replaced is dropped — compared for EQUALITY
only, never ordered. Full design, fail-open rule, observability contract and the
bounded ~20s residual: `docs/sync-protocol.md`, "Peer boot incarnation".

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

#### Making the re-push reachable — the config-apply NACK (#7328)

Pinning the high-water on a failed apply only preserves *eligibility*. It does
not cause a re-push, and until #7328 nothing did: `reconcileConfigSyncToPeer`
claims its `(epoch × generation)` marker **before** sending and nothing ever
cleared it, so once a generation had been pushed on a connection no trigger —
the promotion hook, the periodic reconcile tick, or a repeat connect callback —
would send it again. A standby that refused or failed that apply stayed on the
previous config until a new commit changed the generation or a reconnect changed
the epoch.

Two shipped contracts said the opposite. M-2/#4151 above says the pin "keeps the
standby eligible for the primary's re-push so it re-converges", and
`errConfigSyncRejectedPrimary` says the dual-active window "must heal via the
peer's re-push". #6387's own comment records the same mechanism from the
receiver's side — "the sender pushes a generation at most once per connection,
so a stable connection with a persistent apply failure would otherwise never
re-enter this edge" — and answered it with a health alarm rather than
convergence.

The signal has to come from the receiver. The sender cannot infer the outcome:
`QueueConfig` is fire-and-forget with no ack, the cluster heartbeat carries no
config state (`HeartbeatPacket` is node/cluster id, per-RG group state,
interface monitors, software and protocol version), and `configSyncFailing`
never leaves the node it is raised on. So `configApplyLoop`'s failure branch
sends `syncMsgConfigApplyNack` carrying the generation that did not take effect;
the sender accepts it only when it names `lastSentConfigGen` — the generation it
most recently put on the wire — and invalidates the push marker, so the next
ordinary reconcile tick re-sends.

#6778 added a SECOND sender of that frame: `handleConfigPayload`'s queue-full
drop. When `configApplyCh` is full the non-blocking enqueue discards the
INCOMING payload — the newest generation — and no apply ever runs, so
`configApplyLoop` never reaches the failure branch and nothing re-armed the
sender's marker. The receive-edge drop is the same condition ("this node did not
apply the generation you pushed") reached one step earlier, so it takes the same
three actions: its own counter (`ConfigsQueueFullDropped`), the #6387 grace
timer, and this nack. Writing it from the receive loop matches the heartbeat-ack
and `sendBulkAck` shape already in that switch. The drop is documented in full
under **Queue-full drop (#6778)** in `docs/sync-protocol.md`.

Properties worth stating, because the asymmetry is the whole design:

- **It fires only on failure.** A successful apply sends no nack, nothing
  re-arms, and a healthy connection still pushes a generation exactly once. The
  #5863 no-storm property is preserved unchanged. #6778's queue-full sender is
  inside the `default:` arm for the same reason: an enqueue that SUCCEEDS must
  stay silent, or every push would re-arm the sender's marker.
- **The retry is bounded to the reconciler's cadence.** The nack handler clears
  the marker and returns; it deliberately does not push inline, so a failure
  that recurs instantly cannot become a push/fail/nack tight loop on the shared
  control path.
- **A straggler cannot cause a spurious push.** A nack naming any generation
  other than the last one sent is for a push already superseded and is dropped
  (counted nowhere; `ConfigApplyNacksReceived` counts only accepted nacks).
- **No silent-loss case.** The sync transport is TCP, so a nack is either
  delivered or the connection is gone — and a lost connection bumps the epoch,
  which re-pushes anyway.
- **Mixed-base pairs keep today's behaviour.** The message is additive and
  length-gated on the #2239 precedent with no `ProtocolVersion` bump: an old
  peer never sends a nack, so the marker is never re-armed and convergence still
  waits for a commit or a reconnect — exactly the pre-#7328 posture, and no
  worse.

**The check and the write are not one critical section (#6368).** The fence
above makes the *verdict* correct; it does not make the *evaluation* atomic
with the install it governs. `configEpochStale` reads the threshold and
`PutClusterSynced*` lands several statements later, on the `receiveLoop`
goroutine, while `configApplyLoop` runs on its own. A receiveLoop descheduled
across that gap — a GC pause is enough, and the window it has to miss is the
whole of `OnConfigReceived` (compile + promote + sweep), not a handful of
instructions — can pass the check against the pre-fence threshold and land its
write AFTER the sweep. What survives is a stale PERMIT no later sweep
re-examines: it lives until the next config apply, which on a quiet box may be
never, and on a standby it is precisely what that node forwards on after a
failover.

The install therefore re-reads the threshold AFTER a successful write and rolls
the session back (`DeleteWithCompanions*`, reason `cluster-stale`) when it has
gone stale. Act-then-verify rather than a lock: serializing the check with the
write would hold a mutex across dataplane I/O on the bulk-install hot path,
which the #2198 F3 note deliberately refuses, whereas the re-read costs one
atomic load per install. The rollback applies the guard's OWN verdict a moment
later rather than a fresh judgement — `configEpochStale` never consults policy,
it refuses on epoch alone — and deliberately does NOT record the per-key
generation, so the peer's next re-sync of that key is admitted rather than
refused as stale.

**A peer's delete cannot remove this node's live flow (#9714).** Three callers
use `DeleteReasonClusterStale`, and all three act on the PEER's authority, not
this node's:
- the rollback above removes a session the peer sent;
- `deleteClusterSynced*` removes one the peer said is gone;
- bulk stale reconciliation (`ReconcileClusterBulk`, which also defaults an
  empty reason to cluster-stale) removes the ones the peer's bulk sync left out.

In a dual-primary split both nodes forward the same flows, and each holds its
copy as a LOCAL session. Until #9714 such a delete reached the helper as an
ordinary `sync_session` delete. The worker-side guard in
`handle_delete_synced` kept only the forwarding worker's own entry. Everything
else still went:
- the shared rows;
- the steering row and the DNAT steering hold;
- every sibling worker's replica (`WorkerLocalImport`, which counts as
  peer-synced).

**How the delete is marked.** The session store routes a cluster-stale delete
through the optional `peerSyncedSessionDeleter` capability. The userspace
`Manager` implements it, and `*LegacyDataPlaneAdapter` forwards it. The
capability sets `peer_delete` on every helper request (protocol v16), and the
helper answers FIRST:
- the forward key goes before its reverse companion, and a refused forward's
  reverse is never sent;
- the Manager deletes a key's BPF mirror row only once the helper has applied
  the delete, and a mirror row that is already gone does not stop the helper
  being asked;
- the store deletes the reverse-SNAT DNAT row only for an applied forward. The
  unmarked path deletes that row before the helper is asked.

**What the helper refuses.** It refuses a marked delete of a local-origin
shared entry, forward or reverse, whose owner RG is locally active. The refusal
comes before any shared, steering or DNAT delete and before the worker fan-out.
It is counted on `peer_delete_refused_local_owned`, the counter the worker-side
guard already increments, and answered in-band as
`synced-delete-refused:peer-delete-local-owned`.

A delete that names no routing domain is probed across the routing instances
BEFORE anything is deleted. The exact (domain 0) key is deleted only when
shared authority holds it, or when no instance does. Deleting it first had
fanned DeleteSynced out to every worker, and a worker holding no entry at that
key deletes the bare tuple's steering row: the row a live routing-instance
session still forwards on.

**What stays authoritative.** Every other delete, such as an operator
`clear security flow session` or GC expiry, is unmarked and applies as before.
An older helper does not know the field and would apply a marked delete
too, which is why the field bumps the protocol.

**Item 1 (accepted residual — #6419 closed).** The guard covers only the
config-authority → peer direction (the primary that admits the session is also
the RG0 config-sync authority). A non-authority's sessions carry the
authority-independent seed epoch, so the guard is inert for the reverse
direction in an active/active deployment (fail-OPEN). #6284's residual-COVERAGE
gap is closed (item 2 by #6366, item 1 by #6418).

Closing the reverse direction itself requires a bidirectional
config-generation namespace that #5274 deliberately scoped out. #6419 evaluated
the one shortcut that appeared to avoid building a second namespace — "the
authority A's generations are already a name both nodes can say, so let the
non-authority B stamp `B.lastAppliedConfigGen` (the A-generation B is running)
and let A threshold on its own `configGenCounter`" — and closed it as
unworkable. Recorded here because it has been re-derived more than once; the
three reasons are structural, not implementation detail:

- **The two counters are never simultaneously live on one node, so the shortcut
  cannot be expressed role-free.** `configGenCounter` advances only through
  `nextConfigGen` ← `QueueConfig`, whose only production callers
  (`syncConfigToPeer`, `reconcileConfigSyncToPeer`) are gated on
  `rg0ConfigSyncAuthority` = `IsLocalPrimary(0)`. `lastAppliedConfigGen`
  advances only through `recordAppliedConfigGen` on a nil `OnConfigReceived`,
  and `handleConfigSync` returns `errConfigSyncRejectedPrimary` whenever
  `IsLocalPrimary(0)`. So a node's send counter is frozen for its whole
  non-authority tenure and its applied mark for its whole authority tenure, and
  the shortcut must therefore branch on `IsLocalPrimary(0)` at BOTH the stamp
  site and the threshold site. A role-FREE formulation is not available as a way
  out: coalescing with `max(configGenCounter, lastAppliedConfigGen)` chooses
  between two independent `MonotonicNanos()` boot seeds (`initGenState`), so
  which side wins is a function of relative node uptime rather than of config
  order.

  To be precise about what this does *not* claim: the role-branched mismatch
  that follows an RG0 handover is **not permanent by construction**.
  `reconcileConfigSyncToPeer` runs on the `"rg0-promotion"` trigger, so once the
  new authority has pushed and the new non-authority has applied, both counters
  are back in one namespace. Nor, however, is it bounded by the handover itself:
  the promotion reconciler claims its `(epoch × generation)` dedupe marker
  **before** sending, so if the demoted node still believed it was primary when
  the push landed it returns `errConfigSyncRejectedPrimary`, `configApplyLoop`
  drops that attempt without advancing the applied mark, and every later
  reconcile tick is deduped by the marker it already claimed. Convergence then
  waits for a new commit (new generation) or a reconnect (new epoch). So the
  window is *not* self-limiting to the transition — which makes the next point,
  not this one, the load-bearing objection.
- **The handover window needs the wire field the shortcut avoids.** RG0 role is
  not learned atomically by both nodes: each side updates on its own
  heartbeat/VRRP timing, so there is necessarily a skew window in which the old
  authority still believes it is the authority while the new one already does.
  Dual-active is not theoretical either — the election code has an explicit
  DUAL-ACTIVE branch (`pkg/cluster/election.go`) that detects both nodes primary
  for one RG and resolves it by effective priority then node ID, which takes a
  heartbeat round to converge. Throughout that window BOTH nodes stamp and
  threshold on `configGenCounter`, i.e. on two independent `MonotonicNanos()`
  boot seeds compared directly, so whether the guard is inert or refuses *every*
  inbound synced session is decided by relative uptime. The issue's own proposed
  remedy — treat the epoch as 0 (the documented disable value) for a session
  stamped under a different authority incarnation than the receiver's current
  one — is what would close this, and it requires the receiver to know a stamp's
  authority incarnation. `SessionValue.ConfigEpoch` is a bare `uint64`
  (`pkg/dataplane/types.go`) written as eight raw LE bytes with no companion tag
  (`encodeSessionV4Payload` / `encodeSessionV6Payload`), and nothing else on the
  session wire identifies the minting authority — so the remedy is exactly the
  wire field the shortcut set out to avoid.
- **It converts a self-healing failure into total reverse-direction loss.** A
  config apply that does not take effect on the non-authority (compile/promote
  failure, or the RG0-primary rejection above — counted by
  `ConfigsApplyFailed`) deliberately leaves `lastAppliedConfigGen` pinned so the
  authority's re-push re-converges (M-2/#4151). With the applied mark as the
  stamp source, that same condition pins the non-authority's stamp while the
  authority's threshold keeps climbing on every push, so the authority refuses
  EVERY reverse-direction session for as long as the apply keeps failing.
  `resetRecvGen` compounds it: it stores `lastAppliedConfigGen = 0` on each peer
  bulk re-prime, so the stamp would be 0 — the disable value — through cold
  prime, which is exactly when bulk sessions flow.

**What remains open: the tagged-epoch variant.** The three reasons above kill
the *untagged* shortcut, but they do not establish that a new wire field or a
`ProtocolVersion` bump is structurally required, and an earlier revision of this
section wrongly said they did. A hostile review of #6419 constructed a variant
that answers all three without either, and it is recorded here as the concrete
starting point rather than left to be re-derived:

Reserve the top bit of `ConfigEpoch` as a **stamp-source tag**. The authority
sends its raw `configGenCounter` (tag clear); a *converged* non-authority sends
`tag | lastAppliedConfigGen`; anything not converged sends 0. A receiver then
accepts only the encoding its own role expects — a non-authority expects an
untagged authority generation and compares it against `lastAppliedConfigGen`
(exactly today's behaviour), an authority expects a tagged reverse generation,
strips the tag and compares against `configGenCounter`. Any mismatch between the
tag and the receiver's role means the sender's role assumption disagrees with
the receiver's, so the epoch is treated as 0 and the guard disables.

That disagreement case is what dissolves reason 2: during a dual-primary window
both nodes send untagged and both expect tagged, so both disable rather than
compare two unrelated boot seeds; during a both-secondary window the symmetric
thing happens; and a message delayed across a role change fails open on the same
rule. Reason 3 is answered by the convergence precondition — stamp the tagged
form only when the received and applied marks agree and are nonzero, so a pinned
or reset applied mark stamps 0 (today's fail-OPEN) instead of a stale value that
would refuse everything.

The bit is available in practice: generations derive from `MonotonicNanos()`, so
the top bit is unused for centuries, and reserving it explicitly is a
compile-time invariant rather than a wire-layout change. Nor does a semantic tag
inside an existing field need a `ProtocolVersion` bump — the project bumps for
incompatible layout changes, session trailers are length-gated, and the
config-generation trailer itself deliberately avoided a bump. A legacy receiver
reads a tagged value as a very large generation, which its unsigned `epoch <
barrier` comparison admits — fail-OPEN, i.e. exactly today's behaviour.

This is a design sketch, not code, and it has not itself been hostile-reviewed
end to end; the RG0-role plumbing it needs at the stamp and threshold sites does
already exist. Anyone picking it up owes the usual HA gate — it is session-sync
coupled and owes a `test-failover` smoke.

Both halves of this directional correctness are regression-pinned by
`sync_config_epoch_active_active_6284_test.go`: the SAME frozen non-authority
epoch is REFUSED at a receiver that applied a newer config (the protected
config-authority → peer direction) and ADMITTED at the config authority (whose
receive high-water never advances — the inert fail-OPEN reverse direction), and

**#7323 — "the authority's receive high-water never advances" is true only of an
authority that has NEVER been a secondary.** `lastAppliedConfigGen` is written
by `recordAppliedConfigGen` and cleared by exactly two things: `initGenState`
(construction) and `resetRecvGen` (the peer's bulk re-prime). **Nothing clears
it on a role transition.** So a node that was the secondary, applied the
authority's config, and was then promoted to RG0 carries that high-water into
its authority life, and its guard is **LIVE** until the next bulk re-prime.

Measured, same receiver, opposite verdicts decided only by the top bit:

| receiver | barrier | untagged epoch 3 | top-bit-tagged epoch 3 |
|---|---|---|---|
| never-applied authority | 0 | admitted (inert) | admitted |
| **promoted** authority | 10 | **REFUSED** | **admitted** |

That is what #7323's rolling-upgrade argument turns on. Its claim that a legacy
receiver reading a tagged value is *"fail-OPEN, i.e. exactly today's behaviour"*
holds only where the barrier is 0. Against a live barrier today's behaviour is
REFUSE, so the tag does not preserve the status quo — it converts a working
fail-CLOSED guard into fail-OPEN on a receiver that cannot report it happened.
A rolling upgrade necessarily involves a failover, so the promoted-authority
state is the normal path through one rather than an exotic case.

The exposure is bounded — the window is promotion until the peer's next bulk
re-prime, not forever — and the sender cannot scope around it, because the
non-authority doing the stamping has no way to know whether the receiver's
barrier is live. That is what makes this a negotiation problem rather than an
encoding one.

Pinned by `config_epoch_promoted_authority_7323_test.go`, which asserts CURRENT
behaviour (it does not implement the tag) so the premise cannot rot again the
way this paragraph's wording did. The existing `sync_config_epoch_active_active_6284_test.go`
is not wrong: its INERT arm constructs a never-applied authority, which is a
real state — just not the only one.
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

### Tunnel Session-Identity Discriminator (#7188)

GRE is IP protocol 47 and carries no L4 ports, so two RFC 2890 tunnels between
one pair of outer endpoints are ONE 5-tuple. The helper's own `SessionKey`
separates them on a typed `TunnelDiscriminator`
(`userspace-dp/src/session/discriminator.rs`) with four DISJOINT classes:
`None` (no discriminator concept for this protocol — everything but GRE),
`Unkeyed`, `Keyed(u32)` (including the legal key `0`), and `Unparseable`.
`Unkeyed` is not `Keyed(0)` and `Unparseable` is not `Unkeyed`.

**The bug this section exists to record.** The sync path did not carry the
discriminator: `build_synced_session_key` hardcoded
`discriminator: Default::default()`, and `Default` is `None` — the class
reserved for non-tunnel protocols. So two keyed tunnels' sync records both
rebuilt to the SAME key on the standby, and `install.rs`'s unconditional
`remove_entry` made the second install evict the first. The standby held ONE
session for two tunnels, so after a failover they shared one policy decision,
one NAT state, one counter set and one timeout — the exact collapse #7188
exists to prevent, restored silently by the failover.

**Carriage.** Like `RTFlowSessionID` above, this is a length-gated trailing
VALUE field and needs no `CurrentHAProtocolVersion` bump. The path is:

1. the helper encodes `key.discriminator.to_wire()` as the trailing u64 of the
   `MSG_SESSION_OPEN` **and** `MSG_SESSION_CLOSE` frames, and as
   `SessionDeltaInfo.tunnel_discriminator` on the JSON RPC-fallback leg;
2. the daemon decodes it into `SessionDeltaInfo.TunnelDiscriminator` and stamps
   `SessionValue{,V6}.TunnelDiscriminator`;
3. `SessionSync` encodes it as the trailing wire field (after the #7095
   `IngressIfaceFold`), v4 and v6;
4. the peer daemon forwards it on `SessionSyncRequest.tunnel_discriminator`;
5. the peer helper folds it into the key it reconstructs.

Go never interprets the tag — it carries it — so the encoding is defined in
exactly one place.

### The PPTP call-id pair rides beside it (#7699)

`SessionSyncRequest.pptp_call_ids` carries the learned `(call-id lo, call-id
hi)` for a session whose discriminator is `Pptp(handle)` — the pair the handle
was **derived** from.

**Why it must travel at all.** The handle is a pure function of the association,
and a receiver resolves an incoming PPTP packet by looking its call id up in the
association table. A peer that sends the handle without the pair therefore sends
a session the receiver **can never match a packet against**: it cannot build the
table entry, so every packet for that call resolves unassociated while a session
for it sits in the table. Present-and-unusable is worse than absent.

**So such a record is WITHHELD**, carrying the same
`SYNCED_IMPORT_REFUSED_PREFIX` as the #7188 discriminator refusal and for the
same reason — it is the correct answer from a healthy helper, not a transport
failure, and Go discriminates on the token so a transport-class failure does not
gate takeover-readiness (#5247). Two refusals exist:
`pptp-call-ids-not-carried` and `pptp-handle-mismatch`.

**A mismatch is refused, not repaired.** Both nodes derive the handle with the
same pure function, so a handle that disagrees with its pair means they disagree
about the derivation — version skew or corruption. Recomputing it locally and
importing under the local value would make the two nodes' tables disagree
**silently**, which is the failure the check exists to catch.

**`0` is RESERVED for "not carried" here too**, and is NOT the pair `(0, 0)`.
PPTP call id 0 is not obviously illegal, so a raw pair of `u16`s would make an
older peer's `serde(default)` zeros indistinguishable from a real call — the
absent-vs-zero collapse this section is about, one field over. The present form
is `PPTP_CALL_IDS_PRESENT | (lo << 16) | hi`.

**`0` is RESERVED for "not carried", and is NOT the encoding of `None`.** This
is the load-bearing detail. `serde(default)` and a short length-gated record
both yield `0`, so `0` is the one value a peer produces WITHOUT meaning to; a
build that has the field always states a class, `None` included. That is what
lets the receiver tell "the peer cannot express this identity" from "the peer
says this protocol has no discriminator" — a real answer, which every non-GRE
session sends. It is also the answer a GRE session would carry with
`gre-performance-acceleration` off; today #6837 leaves such a session flowless
so none is created, and the receiver deliberately does not depend on that
staying true.

**Fail-closed import (#7188 decision 2).** On an INSTALL, an absent
discriminator on protocol 47 means the peer cannot tell two same-endpoint
tunnels apart, so the session is WITHHELD — `build_synced_session_key` returns a
`synced-import-refused:` error and the peer re-learns the session — rather than
imported onto a key that may evict another tunnel. An unrecognised tag (a class
from a future build) is refused for every protocol, same reasoning. Every other
protocol with an absent tag imports as `None`, bit-identical to pre-#7188.

The refusal carries the machine-readable `SYNCED_IMPORT_REFUSED_PREFIX` because
it is the CORRECT answer from a HEALTHY helper: Go discriminates on that token
(`process_control.go`) and a transport-class failure gates takeover-readiness
(#5247), which an older peer must not be able to trigger.

**A DELETE takes the opposite branch, deliberately.** The cluster delete message
carries the key and the #2170 delete generation only, and the local clear path
builds its request with `val == nil`, so a delete always arrives with tag `0`.
Refusing it would turn every ordinary GRE close into an error response for no
gain: a key rebuilt without a discriminator names the `None` class alone, so a
delete can only UNDER-match. Under-matching never merges two identities, which
is why install fails closed and delete does not.

**Bulk window.** `snapshotDeltaSink` dedupes on the session key PLUS the
discriminator (`snapshotDedupKeyV4`/`V6`, `daemon_ha_userspace_stream.go`). Keyed
on the 5-tuple alone it silently dropped one of two same-endpoint tunnels from
every cold-prime window. `BulkSnapshot` is a SLICE, so two entries with equal
keys and different discriminators both ride the window.

**Known residuals**, all recorded rather than fixed here:

- A keyed-GRE synced session is retracted by its idle timeout, not by an
  explicit delete, because the delete wire has no value slot to carry the
  discriminator (see above).
- ~~The REVERSE COMPANION of a keyed-GRE session is still shared.~~ **RESOLVED
  in #8103.** All five `SessionKey` transforms (`forward_wire_key`,
  `translated_session_key`, `reverse_wire_key`, `reverse_canonical_key`,
  `reverse_session_key`, `session/key.rs`) used to build their output with
  `discriminator: Default::default()` — preserving the sibling `routing_domain`
  and dropping this field — so two synced keyed tunnels produced THREE rows in
  `sessions.synced`, not four: two forward keys carrying `Keyed(100)` /
  `Keyed(200)` and ONE reverse companion carrying `None`. It was a defect in
  what the ACTIVE node's identity model produced (it reproduced on a standalone
  box with no cluster configured), not in the sync path.

  All five now carry it. The three REVERSE-direction transforms derive it
  through `reverse_direction_discriminator`, an **exhaustive match with no `_`
  arm**: every class today is direction-symmetric, but RFC 2637's PPTP call ID
  is not (#8382 carries the peer's call ID, so the two directions differ), and
  copying it unchanged would build a reverse key holding the wrong value —
  turning a shared reverse companion into NO reverse companion. The missing `_`
  makes that a compile error when the class lands rather than a note someone
  reads afterwards. The row count is now asserted, not described, in
  `tests_gre_session_sync_7188.rs`: four rows, two of them reverse.
- `dataplane.SessionKey` — the Go BPF-mirror key — still aliases two
  same-endpoint tunnels onto one row, so the mirror-backed `show`/clear surfaces
  and the #5085 `bulkRecvV4` reconcile see one entry for both. This is
  pre-existing from #7188's local half (the mirror key has no discriminator at
  all) and is display/bookkeeping, not forwarding: the peer HELPER's session
  table, which is what forwards after a failover, holds both.
- Rolling upgrade is asymmetric by construction. NEW active -> OLD standby: the
  old helper still hardcodes `Default::default()` and aliases, which cannot be
  fixed from the new side without a hello handshake. OLD active -> NEW standby:
  the new standby withholds the old peer's protocol-47 sessions, which is
  decision 2's intended conservative direction. The exposure is narrow:
  `metadata_tuple_complete` (`afxdp/frame/inspect.rs`) refuses protocol 47 on
  both arms since #6837, so a peer on a recent build creates a TRANSIT GRE
  session only with `gre-performance-acceleration` on — i.e. only in the
  configuration this field exists to serve.

### TCP Close Class (#9412)

A session that CLOSES on the owning node after it was synced used to stay open on
the peer. The incremental sweep only sends sessions CREATED since its last tick
(`val.Created >= threshold`), so it cannot carry a mid-life change. Nothing else
did either. After a failover with no traffic, the standby's copy reaped on the
ESTABLISHED window instead of its close window.

**Wire value.** `TcpCloseClass::to_wire`:

| value | meaning |
|---|---|
| `0` | open, or not carried |
| `1` | CLOSING |
| `2` | TIME_WAIT |
| `3` | RST |

The value is direction-neutral. The carrier is a NEW field. It is not
`SessionValue.TCPState`, which keeps its meaning as the BPF mirror's own field,
and not the synced `tcp_flags`, which stay `0`.

**Producer.** `emit_close_state_update` pushes a `SessionDeltaKind::Update` for
the forward entry when a packet changes the session's close class on the node
that owns it. Open deltas carry the entry's current class, so a resync re-export
restores a dropped Update. An Update emits no RT_FLOW SESSION_CREATE.

**Carriage.** Like `TunnelDiscriminator` above, it is a length-gated trailing field
on every hop:
1. The helper writes it as the trailing byte of the open-layout frame. An Update
   uses that layout on type 3, `MSG_SESSION_UPDATE`. The JSON RPC-fallback leg
   carries it as `SessionDeltaInfo.tcp_close_class`.
2. The daemon decodes it into `SessionDeltaInfo.TCPCloseClass` and stamps
   `SessionValue{,V6}.TCPCloseClass`. The walker syncs `"update"` like `"open"`.
3. `SessionSync` encodes it as a trailing byte after `RoutingDomain`, with no
   `SessionSyncWireVersion` bump.
4. The peer daemon forwards it on `SessionSyncRequest.tcp_close_class`.
5. `upsert_synced_with_origin` imports the copy with its close bits set and its
   expiry from `tcp_close_window_ns`. TIME_WAIT sets both FIN bits. CLOSING sets
   neither, because the wire does not say which direction FINed.

An old peer on either side sends and reads `0`, which is the pre-#9412 behaviour.
Volume: at most one Update per class transition, so no more than three per
session over its life.

**Resends never regress the class.** The live acceptance found the sender itself
undoing an Update.
- `syncSweep` and the bulk window resend a session FROM THE MIRROR, and the mirror
  row's `TCPCloseClass` is always `0`.
- So a session that closed inside one sweep window sent Open(0), then Update(1),
  then a sweep frame with 0, and the peer's copy went back to the established
  window.
- The fix: `stampInstallGenV4/V6`, the one stamp every session frame passes
  (delta, sweep and bulk), consults a memo of the class already sent.

The memo:
- **Identity.** Keyed by (tuple, `SessionID`).
  - The install generation cannot key it, because every send draws a fresh one.
  - `SessionID` is the helper's stable id on the mirror row (#6666). On the delta
    path it is the same id whenever the helper supplied one
    (`adoptedOrLocalSyncedSessionID`).
  - A reused tuple has a new id, so it misses the old record in any arrival order.
  - A mismatch, or `SessionID` 0 ("no identity"), makes the memo not apply. That
    fails toward class 0, never toward an early reap.
- **Semantics.**
  - Within one incarnation the class only progresses.
  - The record is evicted in `takeDeleteGenV4/V6`.
  - It is bounded by `genGuardMapCap`; at the cap no new record is written, which
    again fails toward 0.
  - It lives under `genSentMu`, inside critical sections that already held it.
- **The order identity cannot see** is the OLD incarnation's own closing frame
  arriving after a reused tuple's newer frame.
  - The receiver's install-generation guard refuses it as strictly older.
  - `TestLateOldIncarnationCloseFrameIsRefused9412` pins that dependency, with an
    in-order control.

**Companions and promote.**
- `synthesized_synced_reverse_entry` gives the reverse companion the forward
  entry's class.
- A promote republishes the session's live class into the shared maps.
- With `0` in either, the standby re-installed the reverse half on the established
  window. `companion_keeps_alive` does not read `closing`, so that companion can
  hold the closing forward alive.
- This is read from the code. The live probe's exact-key query never matched the
  reverse half, so the companion was not observed live.

**Replica workers announce (#9582).** A close that only a worker replica sees,
typically the server's FIN or RST on the other interface's RSS queue, is announced
to the peer under the installer's id.

- **One id per session on every worker.** The local shared publishes (the transit
  ForwardFlow install, the missing-neighbor seed, the promote republish) carry the
  installer's `session_id`, and replicas adopt it.
  - This id has to match: the conntrack mirror row is written only on install with
    that id, and the sender memo above keys on it.
  - A replica announcing under its own minted id would not match. The memo would
    drop the installer's record, and the next sweep would resend class 0. The peer
    would also adopt the flipped id (#5212).
- **Who announces.** A `WorkerLocalImport` replica, which by `worker_replica_origin()`
  is a replica of a session this node owns, and only when its id was carried from
  another worker. Carried means non-zero, with high 16 bits unlike this table's own
  namespace. Peer-import replicas stay silent.

| Close seen by | Announced? | Effect on the peer |
|---|---|---|
| installer (the client's FIN or RST) | yes | the close window |
| replica only: server RST | yes, class 3, installer's id | the RST window |
| replica only: server FIN | yes, CLOSING | CLOSING's window |
| client FIN on one worker, server FIN on another | each announces CLOSING; nobody announces TIME_WAIT | CLOSING's window, which shares TIME_WAIT's 30 s default |
| a replica holding an id minted locally | no (guard) | whatever the installer announced |

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

### #6666: the mirror now ADOPTS the cross-node id

The section above describes the two ids as independent, and until #6666 they
were. That independence was the defect, not the design.

**Two writers reach one field.** The control plane writes
`SessionValue{,V6}.SessionID` on every conversion; the helper writes the entry's
own stable id whenever a frame drives a local publish for the same key
(`publish_conntrack.rs`, #5213). They minted from disjoint namespaces, so the id
an operator saw FLIPPED depending on which wrote last.

**It was not only at promotion.** Because the control-plane id is distinct per
CONVERSION rather than per session (stated above), every bulk resync re-stamped
every live synced session with a fresh id. The issue described promotion; the
churn is wider than that.

**It also made #5213's invariant false.** `cli_show_flow.go` promises the
displayed id is IDENTICAL to the id RT_FLOW emits for the same session. For a
peer-synced session it was not: RT_FLOW carried the adopted peer id, the mirror
carried a local one.

So the mirror adopts the peer's id when it sent one, and mints a node-local id
only when it did not (a legacy or mid-rolling-upgrade peer). Both surfaces now
render one id for one session.

**Safe by construction rather than by bookkeeping.** #6311 gave every id a node
discriminator bit, so an adopted id carries the ORIGINATING node's bit and cannot
collide with anything this node mints — pinned by
`adopted_peer_id_cannot_collide_with_a_local_id_6311`. And nothing keys on the
id: `pkg/dataplane/types.go` states it is "never a lookup key", and a sweep of
every non-test `SessionID` reference finds no map key, index, dedup or generation
guard. The blast radius is display-only.

**What it does NOT close**, so the claim is not over-stated: synthesized reverse
companions still carry `session_id: 0` (they are not displayed — the CLI skips
reverse rows), and until #6965 an ordinary TRANSIT session had no conntrack row
at all, so the population this improved was the peer-synced, host-inbound and
neighbor-seed sets.

**#6965 IS now closed, and this is the widening it predicted.** The transit
population lands in the mirror with helper-minted ids, so the two-writer
surface described above now covers the dominant population rather than a
minority of it. The safety argument is unchanged and is what makes the widening
tolerable: #6311 gave every id a node discriminator bit, so an adopted peer id
cannot collide with a locally minted one, and nothing keys on the id — a sweep
of every non-test `SessionID` reference finds no map key, index, dedup or
generation guard. The blast radius stays display-only, at a larger scale.

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
connection. `doBulkSync`'s own preconditions produce exactly that shape: it
returns `session store not ready` (nil `s.sessions`), `no peer connection`, or
(#6031) a `bulk sync table-truth snapshot` error before it writes a byte, so no
`handleDisconnect` follows. The #6031 fail-closed path deliberately joins this
set: a snapshot source that cannot reach the helper leaves the obligation armed
for the connected sweep to re-drive, rather than shipping a mirror-sourced
window that would delete live sessions. The startup window is
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

#### Attributing sweep volume (#7842)

Since #6965 mirrored ordinary transit sessions into the conntrack maps, the
sweep and the authoritative delta stream cover **overlapping** populations, so a
transit session created and still alive at the next sweep is sent twice. The
duplication is bounded at **one extra copy per session**, not a repeating cost —
the sweep's filter is `Created >= lastSweepTime`, so once a session is behind the
window it is never re-sent. At `syncHeaderSize` (12) + a 220-byte v4 payload that
is **232 bytes per new transit session**.

The overlap is not exact, and the difference is worth stating because it bounds
how much of the sweep's volume is genuinely redundant. The sweep gates on
`ShouldSyncZone(val.IngressZone)` unconditionally. The delta stream
(`shouldSyncUserspaceDelta`, daemon_ha_userspace_stream.go:28) has THREE branches:
a fabric-redirect arm and a fallback arm that both use
`ShouldSyncZone(ingressZone)`, but a middle arm — taken whenever the delta
carries `OwnerRGID > 0` — that uses `IsPrimaryForRGFn(delta.OwnerRGID)` instead.
`ShouldSyncZone` resolves zone → RG through `zoneRGMap` and then asks the same
primary question, so the two agree when `zoneRGMap[ingressZone] ==
delta.OwnerRGID` and can diverge when they do not. A session the delta stream
admits on RG ownership but whose ingress zone the sweep declines (or the
reverse) is sent ONCE, not twice.

**Both producers increment the same `stats.SessionsSent`.** The sweep queues via
`queueMessage(msg, &s.stats.SessionsSent, "sweep_v4")` and the delta stream via
`QueueSessionV4` → the identical counter; the `source` string reaches only the
send-queue-overflow warning. So `SessionsSent` is their SUM, and #7842's own
proposal to settle the question by "measuring `stats.SessionsSent` and
`stats.Errors` at a realistic connection rate" **cannot** settle it — a
duplicate and an original are indistinguishable in that counter. Two runs on the
loss userspace cluster produced totals that could not be attributed for exactly
that reason.

`stats.SweepSessionsSent` is the mirror-sweep **sub-total** of `SessionsSent`
(a sweep send increments both), so the delta stream's share is the difference.
`show chassis cluster statistics` renders it under `Session create` as
`of which mirror sweep`. `sync_sweep_volume_attribution_7842_test.go` pins the
relationship from both sides — a sweep send must move both counters, a
delta-stream send must move only the total.

**The overflow knee is arithmetic, and it is what any "leave it as-is" decision
rests on.** `sendCh` holds 4096 messages and the userspace sweep runs every 15 s
(`SessionSyncSweepProfile`), and the walk has **no per-pass budget** — it queues
every matching session in one unbounded pass. So a sweep window containing more
than 4096 new transit sessions can exhaust the queue: roughly **273 new transit
flows/sec**, worst case with no concurrent drain. Below that the sweep costs one
232-byte duplicate per session and buys the only recovery path for a
daemon→peer queue drop (`syncBackfillNeeded`, whose only consumers are in the
sweep). Above it, overflow is self-feeding: an overflowing sweep declines to
advance `lastSweepTime`, so the next pass replays a window that has meanwhile
grown.

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
- **Stale-tuple eviction is a FOURTH teardown, and it must be mode-correct
  (#6528):** when a synced upsert re-decides a live flow onto a DIFFERENT
  translated tuple, `reserve_flow` evicts the incumbent `live_by_flow` record.
  That eviction used to be an unconditional
  `free_translated_port(existing.addr_index, existing.translated.port,
  !existing.deterministic)` — the PAT-shaped teardown — which is correct for
  exactly ONE of the three allocation modes. For the other two it mutated state
  belonging to an UNRELATED flow:

  - an ADDRESS-ONLY record (#5269/#6041) owns NO occupancy bit. Its `addr_index`
    is a hardcoded 0 and its `translated.port` is the PRESERVED internal source
    port, so the call cleared whatever bit pool address 0 held at that offset —
    and a `port no-translation` rule SHARES an allocator with a PAT rule whenever
    their pool name, addresses and port range agree, because `allocator_key()`
    does not include `no_translation`. So the bit belonged to a live PAT flow,
    and `free_recycle` queued the port for reuse: two flows on one translated
    tuple. Its actual property, the `address_only_owners` reverse-identity token,
    was never cleared, denying that public identity for the life of the
    allocator.
  - a PERSISTENT record's port belongs to the LEASE, not the flow (`release_flow`
    deliberately does not free it). The call freed a port the lease still
    claimed, and never dropped the lease's `active_flows` refcount. A leaked
    refcount is never idle, so the lease never enters `lease_expirations` and NO
    GC path reclaims it.

  All three retiring paths — `release_flow`, `rollback_flow` and this eviction —
  now share `unlink_live_allocation_locked` (remove the record, clear an
  address-only token, free a port only when the record actually owns one), so a
  fifth cannot diverge. `release_flow` and the eviction additionally share
  `complete_persistent_lease_locked`; `rollback_flow` keeps its own lease arm
  because it undoes an activation rather than completing a flow. The eviction
  takes RELEASE semantics because the incumbent tuple WAS in service — it is a
  re-decision of a live flow, not the withdrawal of an allocation that never
  shipped — and that is why `reserve_flow` (and the synced-reserve chain above
  it) now carries `now_ns`: re-arming a lease's idle expiry needs a real clock.
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
  only when the LAST holder's bit clears. `holders == 0` marks an UNTRACKED
  allocation and keeps the first-release-frees contract unchanged; #6522 narrowed
  which callers that is (see below).

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
- **The ALLOCATING worker is a holder too (#6522):** #6211 F2 left the LOCAL
  allocation path untracked on the ground that "RSS steers a 5-tuple to exactly
  one worker, so a local allocation has a single holder by construction". That
  ground does not hold, because a locally-born session is REPLICATED across
  workers exactly like a peer-synced one. `poll_descriptor` calls
  `replicate_session_upsert`, which fans a `WorkerLocalImport`-origin
  `UpsertSynced` to `peer_worker_commands` — the queue list
  `coordinator/reconcile/bringup.rs` builds with
  `.filter(|(id, _)| **id != worker_id)`, i.e. every worker EXCEPT the allocating
  one — and `SessionOrigin::is_peer_synced()` is TRUE for `WorkerLocalImport`, so
  every sibling's `handle_upsert_synced` reserves and takes a bit on the record
  the owner created. With the owner untracked the mask therefore named every
  worker EXCEPT the one forwarding: the sibling replicas see no traffic
  (flow-hash steering pins the flow to one worker), are never refreshed, all age
  out, and the LAST one to reap emptied the mask and freed a `(pool_addr, port)`
  the owner was still using — mid-flow pool-port reuse. A second path needs no
  reserve at all: `session_glue::materialize_shared_session_hit` installs a
  `WorkerLocalImport` replica off the shared map WITHOUT reserving, and
  `reap_expired_sessions` releases for every expired entry with no origin or
  holder filter.

  The local allocation now records `NatHolder::Worker(worker_id)` at every
  `LiveAllocation` mint (`allocate_translation` and its locked/lease twins, the
  deterministic v4/v6 claims, and both address-only reservations), so the mask is
  complete and the port survives until the OWNER releases. The packet-path
  funnels take a `u32`, not a `NatHolder` — `source_nat_decision_for_flow` and
  `Nat64State::allocate_source_for_worker` build the holder internally — so a
  packet-path call site cannot express "untracked"; the untracked twins
  (`Nat64State::allocate_source`) are `#[cfg(test)]`. The one production
  untracked caller is `source_nat_would_translate_fragment`, the read-only
  non-first-fragment probe, which mints nothing by contract.

  Direction of the residual: a holder bit is cleared only by that worker's own
  release, so a worker that dies with an allocation outstanding strands it
  (#7092). #6522 widens that from synced reservations to local ones. It fails
  closed — a leaked pool port, not a live flow's tuple handed to a new flow —
  and is second-order to an already-fatal event.
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
- **JSON RPC-fallback delta (Rust → Go active), since #6949:** the `nat64` and
  `nat64_snat_v4` keys on the same `SessionDeltaInfo`. Until #6949 this leg —
  `drain_session_deltas` polling and the owner-RG FullResync export — carried
  NEITHER, so a NAT64 session learned through it could not rebuild its reverse
  BIB at all. See "Policy attribution on BOTH session-delta legs (#6949)" below.
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
- **Shared alias removal is owner-checked (#9679):** `shared_nat_sessions`
  (reverse-wire and reverse-canonical aliases) and `shared_forward_wire_sessions`
  are single-value maps. `publish_shared_session` overwrites a colliding
  session's alias, counted by `record_shared_nat_displacement` (#1760).
  `remove_shared_session` deleted whatever occupied the removed session's alias
  keys, so removing a displaced session also removed the survivor's alias. A
  worker with no local copy of the survivor then missed both lookups and sent
  its replies to new-flow adjudication. Each alias is now deleted only while it
  still names the removed session (`remove_shared_alias_owned_by`). The reverse
  order, where the removed session had displaced the survivor at publish, lost
  the survivor's alias at that publish; removal cannot restore it.
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
- `missing_neighbor_seed` origin is never synced (a transient ARP-wait seed)
- `FabricRedirect` with `!FabricIngress`: synced even though the local node is
  not the owner of the session's `OwnerRGID`, because the peer needs the
  forward-wire alias to receive redirected traffic. A fabric redirect means the
  peer owns the flow's EGRESS side by construction, so running these deltas
  through the owner-RG gate below would refuse every legitimate split-RG
  handoff. The daemon also synthesizes forward-wire alias session keys via
  `userspaceForwardWireAliasV4/V6` so the new owner can materialize the
  translated forward tuple it will receive over the fabric.

  **#6599 — the branch still requires INGRESS ownership.** It used to admit
  every fabric-redirect delta unconditionally (`return ss != nil`), which made
  it the emission channel for the transient-purge re-entry class. On a node
  that is not the RG owner, a spoofed non-closing first packet carrying a
  peer-owned flow's translated wire tuple drives
  `should_keep_synced_hit_transient` -> `purge_translated_synced_hit`
  (`userspace-dp/src/afxdp/session_glue/promote.rs`), which tears down this
  node's replica of the peer's session family. The following packet
  clean-misses and installs a fresh `ForwardFlow` whose resolution is a FABRIC
  REDIRECT — precisely because this node does not own the RG, the same
  condition that fired the purge. That Open (and the forward-wire alias emitted
  alongside it) reached `QueueSessionV4` with a fresh #2170 install generation
  and overwrote the owner's authoritative session family under
  latest-generation-wins, swapping the victim's mid-flow translation.

  The fence is ownership of the INGRESS side: `ShouldSyncZone(ingressZone)` —
  the same predicate the non-fabric fallback below already uses. A node may
  hand a flow off over the fabric only when it is primary for the RG the flow's
  ingress zone belongs to, i.e. only when it actually owns the traffic it is
  handing off. The split-RG handoff (ingress RG local, egress RG the peer's)
  still syncs; a node that owns NEITHER side of a flow can no longer install
  anything on the peer. Regression coverage:
  `TestShouldSyncUserspaceDeltaFabricRedirectRequiresIngressOwnership6599` and
  `TestWalkUserspaceSessionDeltasDropsUnownedFabricRedirect6599` in
  `pkg/daemon` — the second binds the WALK, so the suppressed delta is proved
  to contribute zero sessions, forward-wire alias included.

  Residual (unchanged by #6599, tracked with the #6461 Phase-2 identity work):
  the deltas that survive this gate still carry no per-flow provenance, so an
  Open cannot prove which incarnation of a tuple it belongs to. A spoofed
  packet arriving on an ingress zone the node DOES own still fabricates a
  session on the victim's tuple; the ingress gate removes the unowned-emitter
  channel, not the identity-carriage gap.
- if the delta carries `OwnerRGID`, ownership is checked with `IsPrimaryForRGFn`
- otherwise the fallback is `ShouldSyncZone(ingressZone)`

## Session-delta schema identity (#7194)

The two session-open transports — the binary open frame and the JSON
RPC-fallback delta — are kept equivalent by two artefacts with different reach.

**Build time.** `session_delta_transport_parity_7194_test.go` (#8043) compares
the Rust JSON producer's wire names against the Go consumer's json tags, in both
directions, with the Rust struct located by brace counting and both extractions
carrying an anti-vacuity floor. It compares WIRE names, not field names, because
a `serde(rename)` drift breaks the wire while leaving both field names alone.

That test is a tripwire between two source trees. It cannot see what a RUNNING
helper carries.

**Run time.** The helper advertises a DERIVED fingerprint of its own
session-delta wire schema on `ProcessStatus.session_delta_schema_fingerprint`
(`userspace-dp/src/protocol/session_delta_schema.rs`), and the daemon compares
it against its own (`pkg/dataplane/userspace/session_delta_schema.go`).

It is derived, not a hand-maintained integer, because a constant someone must
remember to bump inherits exactly the discipline that already failed three
times: the five #5865 fields and #6312's `rt_flow_session_id` all shipped
divergent with no version bump, since the session-delta schema had no version at
all. The fingerprint is computed FROM the serialized shape — serializing a
default record on the Rust side, reflecting json tags on the Go side — so adding,
removing or renaming a wire field changes it whether or not anyone remembers.

Canonical form on both sides: wire names, sorted ascending as byte strings,
joined with `\n`, no trailing newline, FNV-1a/64. Neither implementation is
pinned to the other's output; both are pinned to the published FNV-1a vectors,
so agreement is a consequence of both being correct rather than of one having
been copied.

**The gate is three-state**, and the middle state is the point:

| advertised | verdict | action |
|---|---|---|
| `0` (or never observed) | unknown | PERMIT — helper predates the field; the snapshot-protocol gates already fence a genuinely old helper. Refusing here would be a brick, not a fence (#1960). |
| equal to the daemon's | match | proceed |
| anything else | mismatch | WITHHOLD the delta batch |

Enforcement sits on `queueUserspaceSessionDeltas`, the single chokepoint all
three producers funnel through (binary stream, JSON drain, FullResync export),
so one check covers every leg.

**The refusal is loud on purpose.** Withholding quietly would trade a silent
zero-fill for a silently dead HA sync — the standby would stop receiving
sessions and a failover would find nothing there, which is worse than the bug
being fixed. A mismatch warns once per episode (the drain runs at 100ms while
the stream is down) and increments a withheld-batch counter; the warning re-arms
when the schema recovers, so a second episode is not swallowed by the first.

The filtering fields on `SessionDeltaInfo` are `FabricRedirect` and
`FabricIngress` (boolean flags), not a single combined field.

#### Policy attribution on BOTH session-delta legs (#6949)

"Fallback" undersells how much traffic this leg carries. `eventStreamFallbackLoop`
drains it every **100 ms** while the binary event stream is down and every **5 s**
even while it is up, and `ExportOwnerRGSessions` re-serializes the whole owned
table through the same `SessionDeltaInfo` on **every** helper-requested
FullResync. A helper restart or an event-stream reconnect on any clustered node
reaches it.

Until #6949 the JSON leg's Rust producer (`SessionDeltaInfo` in
`userspace-dp/src/protocol/binding.rs`, built by `afxdp::session_delta_info`)
carried **none** of the five policy-attribution values the binary open frame had
carried since #3301/#4565:

| Field | Binary open frame | JSON leg before #6949 |
|-------|-------------------|-----------------------|
| `policy_id` (#3056/#3301) | trailing `[+0:+4]` | absent |
| `policy_counter_idx` (#3073) | trailing `[+4:+8]` | absent |
| app inactivity timeout (#3227) | trailing `[+8:+12]`, seconds | absent |
| `nat64` (#4565) | `FLAG_NAT64`, flags bit `1<<5` | absent |
| `nat64_snat_v4` (#4565) | trailing `[+12:+16]` | absent |

The Go consumer declared and read all five unconditionally, so a session learned
through the JSON leg imported `PolicyID = 0`, `PolicyCounterIdx = 0`, no
application timeout and no pool source. Consequences: it rendered
`unattributed`; it was exempt from the commit-time deletion-clear and the #4234
policy-rematch (both skip id 0); it accrued no per-rule hit count after a
promotion; it aged on the global per-protocol timeout; a NAT64 session could not
rebuild its reverse v4→v6 BIB at all; and because each reconciliation copy
carries a fresh #2170 install generation, a later JSON copy could **overwrite an
earlier, correct, event-derived copy on the peer** under latest-generation-wins.

Nothing surfaced it: a rendered id of 0 displays as `unattributed` (#6851),
exactly like a session no policy admitted — three states (attributed to N,
attributed to 0, attribution dropped) crushed into two.

**The fix is a single source, not a second copy.** Both producers now derive
these five from one helper, `session::SessionSyncAttribution::from_session`
(`userspace-dp/src/session/sync_attribution.rs`), which also owns the two
non-trivial conversions — the saturating ns→s timeout and the
`(nat64, rewrite_src)` pool-source selection. Both destructure it
**exhaustively** (no `..`), so a field added to the struct fails to COMPILE
until both legs carry it. Guards:

- `session_delta_json_and_binary_agree_on_policy_attribution_6949` — one session,
  both wires, asserts the two legs AGREE (neither side pinned to a literal).
- `session_delta_info_zero_attribution_is_present_not_absent_6949` — a genuinely
  unattributed session must emit the keys carrying an explicit 0, so
  "attributed to policy 0" stays distinguishable from "field dropped".
- `sync_attribution_exhaustive_destructure_6949` — forbids `..` at either
  destructure, since that would restore the silent-divergence escape hatch.
- `TestSessionDeltaPolicyAttributionWireKeysLockstepWithRust6949` (Go) — pins the
  Go struct tags to the serde renames parsed out of `binding.rs`.

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

**#6558 — the same pathology, reached through the PENDING-APPLY QUEUE.** The
paragraph above is the sibling case, and it stayed live in a second form until
#6558. The normal path is strictly receive → apply → ACK (`markFrameApplied`
runs only after `onEvent` returns true), and a callback returning false enqueues
the frame WITHOUT marking it — the withhold-ACK contract, pinned by
`TestEventStreamSessionCallbackFalseWithholdsAck` and its FullResync/dataplane
twins. But `dispatchOrQueue*` returns TRUE after a successful enqueue, so the
reader keeps reading with frames still queued unapplied, and every REFUSAL path
advanced `lastAppliedSeq` with no pending-queue check:
`markDroppedFrameApplied` (telemetry type/payload mismatch, decode failure,
unknown frame type — #1394), `handleSessionDecodeFailure` (#5483/#6130) and
`handleOversizedFrame` (#6132/#6160, which additionally FLUSHES the ACK
immediately). Enqueue delta N unapplied, receive refused frame N+1, and the
cumulative ACK names N+1: the helper trims on `front.seq <= acked`
(`event_stream/control.rs`) and the daemon calls `clearPendingCallbackFrames`
on the next accept, so delta N is gone from both sides. The oversized path did
both in one shot.

Each of the three refusal fixes reasoned correctly about the REFUSED FRAME
ITSELF; none reasoned about frames still queued BEHIND it, because the pending
queue did not exist when the first was written.

The repair keeps every loop-break intact — `prevSeq` and `lastRecvSeq` still
advance immediately, so nothing re-fires the gap detector and the helper is
never asked to replay a frame that would only be refused again (the #6130
wedge). Only the ACK watermark is held back: `applyRefusedFrameInOrder`
enqueues a **dropped marker** when the pending queue is non-empty, and the
flush releases it in FIFO order like any applied frame. With an EMPTY queue the
advance is immediate, exactly as before. `markFrameApplied` is also monotonic
now: it was a bare `Store`, so a later in-order flush could REWIND the watermark
below a value a drop path had jumped it to — and a rewound `lastAppliedSeq` is
silently swallowed by `sendAckIfNeeded`'s `applied <= acked` guard and can
regress `SendDrainRequest`'s fence.

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
redundancy-group ids were not bounded to 15, so the old hardcoded
`for rgID := 0; rgID < 16` loop silently skipped any RG with id >= 16 — its
owned sessions were never re-exported on a FullResync, so the standby never
received them and they were dropped on a failover of that RG (#4028). This
mirrors the live-config enumeration the watchdog/fence paths use
(`currentRedundancyGroups`, #3917).

> **#8317 narrowed the input, and #4028's enumeration is still load-bearing —
> do not simplify it back to a fixed loop.** A strict commit now refuses an id
> at or above `MaxRedundancyGroups` (16), because that id is used directly as
> the index into the dataplane's `rg_active` / `ha_watchdog` arrays: a BPF array
> with `max_entries` 16 accepts an update at key 15 and returns E2BIG at 16, and
> `UpdateRGActive` propagates that error before recording the group or syncing
> HA state, so such an RG never activates and its RETH interfaces never forward.
>
> That bounds what an operator can newly commit. It does **not** bound what this
> code can be handed. The typed-leaf and strict-compile gates are strict only on
> the operator commit path; `Store.Load` and `Store.SyncApply` deliberately
> downgrade a violation to a warning (#1319 PR 2, the #1960 no-brick doctrine),
> so a config persisted by an older binary — or peer-synced from one mid-upgrade
> — can still carry an id >= 16 and reach exactly this enumeration. Walking the
> configured set rather than `0..15` remains correct for that reason.
>
> The commit bound is derived from `config.MaxRedundancyGroups`, of which
> `dataplane.MaxRedundancyGroups` is an alias, so the bound and the array length
> cannot drift apart. Before #8317 the 16 existed only as the arrays'
> `max_entries` and nothing connected it to the id an operator types.

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

**Historical premise, corrected (#5085, #6031).** This section originally argued
that a full owner-RG re-export could **not** recover an undelivered close: the
userspace cold-sync delivered sessions as incremental `Open`s through the event
stream and then sent **empty** `BulkStart`/`BulkEnd` markers (`doBulkSync` →
`BulkSyncOverride`), and `reconcileStaleSessions` short-circuited on an empty
bulk ("skipped (empty bulk)"), so re-emitting `Open`s conveyed no delete.

That premise no longer holds at HEAD. #5085 removed both the empty-marker path
and the empty-bulk skip — `doBulkSync` always frames a real bracketed window —
and #6031 sources that window from table truth, so a bulk re-drive DOES now
prune a session the primary has closed. The conclusion below is unchanged, but it
rests on a different reason: a bulk re-drive is a much later convergence point
(the next cold prime, survivor re-drive, or forced resync), so an undelivered
close must still be surfaced rather than swallowed on the assumption that some
future bulk will mop it up. A disconnected stream also triggers a fresh resync on
reconnect (#2874) independently.

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
   ack proves the peer has processed everything queued ahead of it ON THE
   CONNECTION THE BARRIER TRAVELLED ON. The actual demotion then happens
   atomically in `UpdateRGActive(false)`.

   **Barrier fence (#9508).** `sendLoop` writes each message on whichever fabric
   connection is active when it is dequeued. The ordered stream therefore moves
   between connections on a partial drop, or when the preferred fabric connects
   with no fault at all. Frames written on the old connection can still be
   unprocessed, or be lost with it, while a barrier is acked on the new one. An
   ack alone would then admit a demotion that loses those sessions. The fence
   (`pkg/cluster/sync_barrier_fence_9508.go`) works as follows:
   - The first ordered-stream write (a `sendLoop` message or a BulkStart) on a
     different connection bumps a fence epoch under `writeMu`, BEFORE it writes.
     No ack for a frame on the new connection can be observed without the bump.
   - `WaitForPeerBarrier` fails a barrier that was pending across a bump, and
     refuses every later barrier while the fence is armed.
   - The move releases pending barrier waiters and starts one single-flight
     re-prime; every refused barrier re-kicks it. This cannot be left to the
     daemon, whose prime-retry loop restarts after a failed barrier only while
     the peer is still unprimed.
   - Only the ack of a bulk that captured the current epoch BEFORE reading its
     session source discharges the fence. A snapshot read after the move holds
     every delta written before it, on either connection. `doBulkSync` captures
     before `BulkSnapshotSource`. The store walk reads during the window, so it
     captures at BulkStart. A caller-read snapshot captures nothing. A move after
     the capture leaves the fence armed.

   The refusal surfaces as `demotion peer barrier failed: session sync barrier
   fenced ...`, which manual failover already classifies as retryable. Not
   claimed: a frame from a superseded connection that is still up can reach the
   peer after the re-prime and be applied after it. That ordering exists without
   the fence and is unchanged.

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
run on the VRRP instance's own loop, so `ResignRG` *returning* means
*resignation signalled and priority driven to 0*, not *VIPs off the wire*.
Direct-VIP mode (`no-reth-vrrp`) has no such gap — `reconcileDirectVIPOwnership`
removes the addresses inline on the event goroutine. `ResignRG` therefore
returns a `vrrp.ResignBarrier`, and the fence waits on it rather than on the
call returning (step 5 below, #6177 item 1).

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
5. On the RETH-VRRP path the verdict is deferred to the **VIP release itself**
   (#6177 item 1). `ResignRG` returns a `vrrp.ResignBarrier` armed on every
   targeted instance BEFORE `triggerResign`; each instance reports to it from
   the site that actually completes a release — `becomeBackup` (with the
   `removeVIPs` outcome), the MASTER-arm shutdown removal, the BACKUP arm of the
   run loop consuming a resign token for an instance that was already BACKUP,
   and `stop()` for a retired instance. `handleClusterEvent` hands the barrier to
   `awaitRethVIPRelease` **on its own goroutine** — `watchClusterEvents`
   serialises every cluster event, so blocking there would stall unrelated RGs
   behind one VIP removal — and that resolves the fence: `signalFailoverActuated`
   on a clean release, `signalFailoverActuationFailed` when `removeVIPs` failed
   (a stale VIP is still answering ARP, so it is not a two-owner-safe
   resignation) or when the release does not report within
   `rethVIPReleaseTimeout` (500 ms default — far below the 3 s
   `failoverActuateTimeout` so the verdict NAMES the un-released addresses, and
   far below the initiator's 20 s ack timeout so the ack is a decision, not a
   hang). Already-BACKUP and no-instance RGs resolve promptly rather than
   stalling, so a clean failover is not downgraded to a hold.
6. The wait is bounded by `failoverActuateTimeout` (3s default). A demotion that
   never actuates (superseded reset, event-channel drop) downgrades the ack to
   `failoverAckFailed` so the peer **holds** rather than promoting into the
   two-owner window — safety over latency in the race. On the normal path the
   barrier releases as soon as the local resign completes, so failover latency is
   unchanged.

The batch path (`handleRemoteFailoverBatch` / `WaitFailoverAppliedBatch`) applies
the same barrier across the whole set, all members armed under the one batch
request id; the first non-nil verdict fails the batch ack.

**Closed (#6177 item 1).** The RETH-VRRP path used to release the barrier once
resignation had been *signalled* (priority 0 set synchronously) and `rg_active`
was cleared — not once `becomeBackup` had physically removed the VIPs — leaving
a sub-millisecond window in which the peer could promote while the old owner's
VIPs were still on the interface. Step 5 above closes it by gating the release
on a `becomeBackup` completion signal out of the VRRP instance loop. The
pre-existing mitigations still stand behind it: priority-0 is set synchronously
so the resigning node cannot win a re-election, and the demotion preflight
(`tryPrepareUserspaceRGDemotion`) has already shifted the flow cache to
`FabricRedirect`, so transit traffic reaching the old owner is forwarded over
the fabric rather than dropped.

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
