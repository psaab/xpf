# Cluster Session Sync Protocol (RTO)

Reference for `pkg/cluster/sync.go` and `pkg/conntrack/gc.go`.

## Transport

- **Protocol:** TCP on port 4785 over the fabric link
- **Addressing:** `localAddr` = `:4785`, `peerAddr` = `<fabric-peer-ip>:4785`
- **Dual connection model:** Both nodes run accept + connect loops simultaneously
  - `acceptLoop`: Listens for incoming peer connections
  - `connectLoop`: Retries outbound connection every 5s (3s dial timeout) when disconnected
  - Whichever connects first wins; new connection replaces any existing one
- **Keepalive:** 30s read deadline; on timeout, sends `syncMsgHeartbeat` and continues
- **Send channel:** Buffered `chan []byte` (4096 entries), non-blocking send; overflow increments `Errors` counter and drops the message
- **Payload limit:** 16MB maximum per message (for config sync)
- **Disconnect handling:** Any I/O error closes the connection and sets `Connected = false`

## Wire Format

Every message is a 12-byte header followed by a variable-length payload:

```
Offset  Size  Field      Description
0       4     Magic      "BPSY" (0x42, 0x50, 0x53, 0x59)
4       1     Type       Message type (1-9)
5       3     Pad        Reserved, zero
8       4     Length     Payload length in bytes (little-endian uint32)
12      N     Payload    Type-specific data
```

All multi-byte integers in the wire format are **little-endian**, matching the native byte order of x86 systems and BPF maps.

## Message Types

| Type | Name             | Direction        | Payload Size        | Purpose |
|------|------------------|------------------|---------------------|---------|
| 1    | SessionV4        | Primary→Secondary | length-gated        | Create/update IPv4 session |
| 2    | SessionV6        | Primary→Secondary | length-gated        | Create/update IPv6 session |
| 3    | DeleteV4         | Primary→Secondary | 16 or 24 bytes      | Delete IPv4 session |
| 4    | DeleteV6         | Primary→Secondary | 40 or 48 bytes      | Delete IPv6 session |
| 5    | BulkStart        | Primary→Secondary | 8 or 24 bytes       | Marks start of bulk transfer: 8B epoch, plus the sender's 16B boot incarnation (#5084) when it has one |
| 6    | BulkEnd          | Primary→Secondary | 0                   | Marks end of bulk transfer |
| 7    | Heartbeat        | Bidirectional     | 0                   | Keepalive (sent on 30s idle) |
| 8    | Config           | Primary→Secondary | Variable (UTF-8) + 16B gen framing | Full config text + monotonic config generation (#3931) |
| 9    | IPsecSA          | Primary→Secondary | Variable (UTF-8) + 1B delim + 24B seq framing | Newline-separated connection names + `\n` delimiter + full-set (incarnation, seq) ordering trailer (#5706) |
| 25   | DHCPLeaseV4      | Primary→Secondary | count+records + 24B seq framing | Full-set v4 lease push (#2239) + (incarnation, seq) ordering trailer (#5706) |
| 26   | DHCPLeaseV6      | Primary→Secondary | count+records + 24B seq framing | Full-set v6 lease push (#2239) + (incarnation, seq) ordering trailer (#5706) |

## A wire-advertised `count` is untrusted (#7175, #8792)

Every `count+records` payload in the table above begins with a 4-byte record
count taken straight off the wire. **A decoder must prove that count is no
greater than what the body can physically hold BEFORE any allocation sized from
it.** Each record costs at least its own 4-byte length prefix, so the bound is
`(len(body) - 4) / 4`.

The check has to come first, not merely exist. #8792 was a decoder that had the
bound inside its loop, one line below a `make()` sized from the raw count — so a
four-byte frame of `ff ff ff ff` asked for 2^32-1 records before a single length
prefix had been read. The loop's guard was correct and unreachable.

**The two decoders answer an over-declared count differently, deliberately:**

| decoder | on `count > bound` | why |
|---|---|---|
| DHCP full-set (`sync_protocol.go`) | clamp to the bound, mark malformed, keep going | #7175 separates a wrong COUNT from lost DATA; the tolerance is pinned by `TestDHCPFullSetStillToleratesAnOverDeclaredCount7175` |
| persistent-NAT lease (`sync_persistent_nat_lease_8121.go`) | reject the frame outright | its bool means "decoded COMPLETELY", and a full-set push REPLACES the peer set — installing whatever fit would delete every lease past the point the count went wrong |

**Do not assert a crash when testing this class.** Whether an oversized
allocation is fatal is a property of the host, not the code: the sizes involved
stay under the runtime's `maxAlloc`, so no `makeslice` panic is inherent, and
under `overcommit_memory=1` the mapping can succeed unbacked and the process
survives to discard the frame. Assert the invariant — rejected before the
allocation, nothing installed, still serving — which holds in every environment.
Measuring the ALLOCATION is what distinguishes a real fix from a bound applied
one line too late: both produce the same return values.

And note the receive loop's `defer` only disconnects; it is not a recovery
boundary. Wrapping a decoder in `recover()` is not a fix even where the
allocation *is* fatal, because a Go runtime OOM is a `fatal error`, not a panic.

## Session V4 Payload Layout (120 bytes)

```
Offset  Size  Field
── Key (16 bytes) ──────────────────────
0       4     SrcIP           [4]byte (network order)
4       4     DstIP           [4]byte (network order)
8       2     SrcPort         uint16 LE
10      2     DstPort         uint16 LE
12      1     Protocol        uint8
13      3     Pad             -
── Value (104 bytes) ───────────────────
16      1     State           uint8 (0=new, 1=established, 2=closing)
17      1     Flags           uint8 -- low byte of SessionValue.Flags (SNAT/DNAT/StaticNAT/NAT64 bits 0-7)
18      1     TCPState        uint8
19      1     IsReverse       uint8 (always 0 for synced entries)
20      4     Pad0            -
24      8     Created         uint64 LE (monotonic seconds)
32      8     LastSeen        uint64 LE (monotonic seconds)
40      4     Timeout         uint32 LE (seconds)
44      4     PolicyID        uint32 LE
48      2     IngressZone     uint16 LE
50      2     EgressZone      uint16 LE
52      4     NATSrcIP        uint32 LE (NativeEndian IP bytes)
56      4     NATDstIP        uint32 LE
60      2     NATSrcPort      uint16 LE
62      2     NATDstPort      uint16 LE
64      8     FwdPackets      uint64 LE
72      8     FwdBytes        uint64 LE
80      8     RevPackets      uint64 LE
88      8     RevBytes        uint64 LE
── Reverse Key (16 bytes) ──────────────
96      4     RevSrcIP        [4]byte
100     4     RevDstIP        [4]byte
104     2     RevSrcPort      uint16 LE
106     2     RevDstPort      uint16 LE
108     1     RevProtocol     uint8
109     3     Pad             -
── Trailer (8 bytes) ───────────────────
112     1     ALGType         uint8
113     1     LogFlags        uint8
114     2     Pad1            -
116     4     (unused)        -
```

> **Flags field width (#5460).** `SessionValue.Flags` is a `uint16` in memory
> (the C `session_value.flags` and Rust `BpfSessionValueV4.flags` mirrors were
> widened from `__u8` to `__u16` so `SessFlagNPTV6` — bit 8, 0x100 — fits). The
> sync wire above still carries only the **low byte** at offset 17, because every
> flag a session actually sets today is in bits 0-7 (SNAT/DNAT/StaticNAT/NAT64).
> Bits ≥ 8 are never set at runtime, so the low-byte encoding is loss-free and
> the wire is unchanged (no version bump). If session-level NPTv6 flagging is
> ever added, carry the high byte as a length-gated trailing field (like
> `Generation`) rather than widening this fixed-offset byte in place.

## Session V6 Payload Layout (~196 bytes)

Same structure as V4 but with 16-byte IPs:

```
── Key (40 bytes): SrcIP[16] + DstIP[16] + SrcPort[2] + DstPort[2] + Protocol[1] + Pad[3]
── Value: Same fields as V4, except NATSrcIP/NATDstIP are [16]byte and ReverseKey uses 16-byte IPs
```

## Delete V4 Payload (16 bytes)

```
Offset  Size  Field
0       4     SrcIP         [4]byte
4       4     DstIP         [4]byte
8       2     SrcPort       uint16 LE
10      2     DstPort       uint16 LE
12      1     Protocol      uint8
13      3     (implicit)    -
```

## Delete V6 Payload (40 bytes)

```
Offset  Size  Field
0       16    SrcIP         [16]byte
16      16    DstIP         [16]byte
32      2     SrcPort       uint16 LE
34      2     DstPort       uint16 LE
36      1     Protocol      uint8
37      3     (implicit)    -
```

## Install-Generation Guard (#2170)

To stop a deferred/journaled delete from killing a same-5-tuple replacement
session, every **session** and **delete** message carries a length-gated
trailing `Generation uint64` (LE):

- **Session V4/V6**: 8 bytes appended after the existing last field (`FibGen`).
  An old decoder stops after `FibGen` and ignores it (`if off+8 <= len(payload)`
  block in `decodeSession*Payload`); a new decoder reading an old, shorter
  payload sees `Generation == 0`.
- **Delete V4**: 16 → 24 bytes; **Delete V6**: 40 → 48 bytes. The generation is
  the trailing 8 bytes after the 5-tuple block. The handler's `len(payload) >=
  16/40` check already tolerates the longer payload; the generation is read
  only when `len(payload) >= 24/48`.

**Semantics (sender, `pkg/cluster`):** a single process-wide strictly-monotonic
counter (seeded from `CLOCK_MONOTONIC` nanos) stamps every install send
(`QueueSession*`, sweep, bulk) and is recorded per wire key. A delete draws a
**fresh, strictly-greater** generation from the same counter (`takeDeleteGenV4/V6`
→ `nextInstallGen`) rather than echoing the install's stamp, and evicts the
sender record. A delete therefore always out-ranks the install it cancels — the
property that lets the receiver order a reordered delete/install pair (see #2221
below). A key never installed in this boot (no stamp recorded) yields `gen == 0`
(legacy unconditional delete). Generations are only ever compared
per-`(sender,key)` — never across keys — so a single sender-local counter
suffices.

**Semantics (receiver, `pkg/cluster`):** `SessionSync` keeps the authoritative
per-key stored generation in its own map (the BPF C conntrack struct stays
generation-free). The apply layer:

- **Delete guard** (`deleteClusterSynced*`): apply a delete only if its
  generation is **not strictly older** than the stored entry's. `delete < stored`
  with both non-zero → refuse (`DeletesStaleIgnored++`), short-circuiting BOTH
  the BPF map delete and the helper. Equality applies (the delete of the very
  session installed); `gen == 0` on either side falls back to today's
  unconditional delete (rolling-upgrade safe). On an applied **non-zero** delete
  the stored generation is **upgraded to the delete generation as a TOMBSTONE**
  (not evicted), so a reordered older install of the cancelled session is refused
  by the install guard (#2221). A `gen == 0` delete evicts (no tombstone).
- **Install guard** (`installClusterSynced*`): refuse to overwrite a stored
  entry (live OR a delete tombstone) with a strictly-older-generation install
  (`incoming < stored` → `InstallsStaleIgnored++`) so the per-key stored
  generation never regresses (closes the delayed-stale-install variant AND the
  reordered-install-after-delete residual).

The userspace helper mirrors the same field on its in-memory
`SyncedSessionEntry` (via `SessionSyncRequest.generation`) and enforces the
same guard in `upsert_synced_session` / `delete_synced_session_gen` as a
belt-and-suspenders for helper-originated deletes; the Go cluster apply layer is
authoritative. A mixed-version cluster degrades to exact pre-#2170 behavior for
any pair where either end lacks a generation.

### Generation is sync-only — it MUST NOT inflate the BPF map (#2360)

The install `Generation` lives in three places: the in-memory `SessionValue` /
`SessionValueV6` (Go) and `SyncedSessionEntry` (Rust), and the sync wire (the
length-gated trailing 8 bytes above). It is deliberately **absent** from the BPF
C conntrack struct (`struct session_value` / `struct session_value_v6` in
`bpf/headers/xpf_conntrack.h`), so the kernel-visible `sessions` / `sessions_v6`
HASH maps are 128 / 176 bytes per value — the same layout the Rust helper
mirrors as `BpfSessionValueV4` / `BpfSessionValueV6` (size-asserted at
`userspace-dp/src/afxdp/bpf_map_tests.rs`).

Because `SessionValue` carries the extra trailing `Generation uint64`, it is
136 / 184 bytes — 8 bytes larger than the on-map layout. The Go map
registration therefore must use the dedicated on-map ABI types
`bpfSessionValue` / `bpfSessionValueV6` (`pkg/dataplane/bpf_session_value.go`),
which mirror the C struct exactly without `Generation`, and all map I/O
(`SetSessionV4/V6`, `GetSessionV4/V6`, iterate/batch in
`pkg/dataplane/maps_session.go`) projects through `toBPF()` / `sessionValue()`
at the boundary. Registering at `sizeOf[SessionValue]` instead would make the
kernel `value_size` 8 bytes larger than the Rust helper's lookup buffer, so a
`bpf_map_lookup_elem` would copy `value_size` bytes into the smaller buffer — an
8-byte out-of-bounds write (latent because the trailing bytes are usually zero).
The parity guards `TestSessionMapRegisteredAtConntrackABISize` /
`TestBPFSessionValueMatchesConntrackABI` (Go) and the Rust size asserts pin the
128 / 176 contract on both sides. **A new sync-only field must be added to the
sync codec and the in-memory structs — never to the on-map ABI types.**

### Generation-map bounds and overflow (#2198 F1)

Both the sender echo maps (`genSentV4/V6`) and the receiver stored-generation
maps (`recvGenV4/V6`) are bounded by `genGuardMapCap` (200000) so a churning
workload cannot grow them without limit. Sender entries are evicted on the
matching delete. Receiver entries are evicted on a `gen == 0` (legacy) delete
but a non-zero delete **records a tombstone in place** (#2221, see below); the
cap (via `putGenBounded`) plus the bulk-barrier `resetRecvGen` keep the
receiver map bounded under steady churn, and the cap is also the safety valve
for keys whose delete never arrives (e.g. a dropped close delta).

On overflow the map is **never cleared**. A map at cap updates an EXISTING key
in place (its stored generation is never dropped) and **skip-records** a NEW
key, incrementing `GenMapOverflow`. A skipped key degrades to gen-0
(unconditional install / unconditional delete), which is safe: gen-0 never
causes a wrongful delete of a *different* live incarnation — it only forgoes the
stale-delete protection for that one new key. Clearing the whole map would drop
the stored generation of every live key, disabling the guard for a churn window
and re-opening the exact #2170 hazard (a stale delete killing a live
re-established session).

### Cross-boot generation regression and the bulk re-prime reset (#2198 F2)

The sender `genCounter` is seeded from `CLOCK_MONOTONIC` nanos, which is
boot-relative and **resets at OS reboot**. After a reboot this node's counter
can come up LOWER than a generation the peer stored from its previous boot, so a
post-reboot same-5-tuple re-install would carry a lower generation and the
peer's install guard would refuse it as stale (a stale-RETAIN — the inverse of
#2170), and the cold-start bulk re-prime would silently fail to land.

This is handled on the **receiver** side: when a (reconnecting, possibly
rebooted) peer begins its bulk transfer (`syncMsgBulkStart`), the receiver
resets its per-key stored generations (`resetRecvGen`). The bulk re-prime — the
authoritative live set — then lands unconditionally and re-records each key's
fresh generation, so the install guard accepts it. This is safe against opening
a stale-delete window: deletes are only acted on after the bulk completes
(`reconcileStaleSessions` at `BulkEnd`), and the re-prime re-establishes the
live set before any such delete; a delete that arrives mid-bulk for a
not-yet-re-recorded key falls back to gen-0 (unconditional), the legacy-safe
behavior. No persisted cross-boot high-water mark is required.

### Apply-sequence atomicity (#2198 F3)

The receiver apply sequence — install guard check, dataplane `PutClusterSynced`,
`recordInstalledGen` (and the delete path's `deleteGenGuard`) — does not hold
`recvGenMu` across the whole sequence; each helper takes the mutex
independently. This is safe because the receiver apply path for a given peer is
single-threaded: messages are decoded and dispatched serially within one
`receiveLoop` goroutine over the single ACTIVE fabric connection (conn0
preferred; conn1 only when conn0 is down). No two installs/deletes for the same
key are ever applied concurrently, so the per-key stored generation cannot be
interleaved between the guard read and the record write. Holding `recvGenMu`
across the dataplane `Put` would serialize unrelated keys under dataplane I/O
for no benefit the single-active-fabric invariant doesn't already provide.

### Same-generation install/delete reorder (#2221, residual of #2170)

The #2170 guard assumes per-key generations are strictly monotonic so a stale
(older-generation) delete is refused. The **residual** hazard is WITHIN a single
generation domain: the gen-stamp and the `sendCh` enqueue are not atomic, and two
producer goroutines mutate the same key — the 1s sweep re-stamps a LIVE session
to generation `N` and queues an install carrying `N`, while the userspace
delta-drain takes the close and (pre-fix) echoed that same `N` on the delete. The
delete can then win the `sendCh` enqueue race and be sent BEFORE the install. The
receiver applies `delete(N)` then `install(N)`. Because the guards refuse only a
*strictly-older* operation, an equal-`N` install after an equal-`N` delete was
re-applied — the standby resurrected a session the master had already closed
(the stale-RETAIN inverse of #2170, this time triggered by reorder rather than a
journaled replay).

The fix makes convergence **order-independent (last-writer-wins per key)** with
two composed changes:

1. **Sender** — a delete draws a FRESH generation strictly greater than the
   install it cancels (`takeDeleteGenV4/V6` → `nextInstallGen`, see above)
   instead of echoing it. A delete therefore always out-ranks its install.
2. **Receiver** — an applied non-zero delete records the delete generation as a
   **tombstone** in `recvGenV4/V6` (it does not evict). A reordered install of
   the cancelled session carries the OLDER install generation, so the install
   guard (`incoming < stored`) refuses it (`InstallsStaleIgnored++`) and the
   standby stays GONE — matching the master. A genuinely newer incarnation,
   re-established and re-stamped by a later sweep, carries a strictly-greater
   generation than the tombstone and still installs.

Both reorder directions, and the in-order close, converge to the master's final
state: GONE when the master deleted last, PRESENT when a strictly-newer install
arrived last. The tombstone is bounded by `genGuardMapCap` and cleared by the
bulk barrier (`resetRecvGen`), which also handles the cross-boot generation
regression (#2198 F2) so a tombstone never blocks a legitimate cold-start
re-prime. Regression coverage: `TestSameGenReorderDeleteThenInstallConverges{V4,
V6}` (drives the real sender enqueue + receiver apply in wire order),
`TestReorderedInstallRefusedByTombstoneV4`,
`TestReestablishAfterDeleteAppliesV4`, and
`TestDeleteGenerationStrictlyGreaterThanInstall{V4,V6}` in
`pkg/cluster/sync_gen_guard_test.go`.

## NAT-Port Reservation on Import (#6600)

A peer-synced session carries a pre-computed NAT decision, so the importing
node must RESERVE the translated port it names — the standby never runs the
allocation path that would otherwise claim it, and after failover a fresh local
flow could reuse it, putting two flows on one NAT source tuple.

That reservation used to happen ONLY inside the worker-local upsert, which is
driven by a command enqueued **after** the shared session entry was published.
`publish_shared_session` makes the entry visible on every packet-path lookup
surface at once (`synced`, `nat`, `forward_wire`), and
`materialize_shared_session_hit` forwards on `replica.decision` — including
`decision.nat` — without reserving anything. A worker that sampled an empty
command queue just before the coordinator's push proceeds straight into
`poll_binding` with the entry already live.

In that window a local flow can allocate the same port. `reserve_flow` then
REFUSES to steal it, which is the right call — but the refusal was returned by
nothing, counted by nothing and logged by nothing, so the imported session went
on advertising a translation this node did not own.

**The reservation is now taken by the coordinator, before the publish.** A
refusal drops the import: no session beats a session naming someone else's
port, and the peer re-syncs. It is counted as
`synced_import_reserve_refused_total` — a silent drop would only trade one
invisible failure for another. A nonzero value means a local flow held the
translated port at import time, which on a healthy standby (owning RG passive)
should not happen: look for overlapping pools, an active-active RG pair sharing
one SNAT pool, or NAT config drift between the nodes.

Three properties that are load-bearing and each pinned by a test:

- **The coordinator's reservation is `Untracked`, so it is ABSORBED rather than
  doubled.** It contributes no holder bit, so each worker's later reserve finds
  the identical `(flow, translated)` already live, takes `reserve_flow`'s
  idempotent early return and ORs its own bit in. The last worker's release
  still empties the mask and frees the port. Had the coordinator's reservation
  instead made the workers' REFUSE, no holder bit would ever be recorded and
  the port would leak.
- **Skipped when no worker is registered.** Nothing polls, so there is no racing
  local allocation to guard against, and an `Untracked` reservation no worker
  adopts has nobody to release it. Same carve-out as the zero-ceiling case.
- **A half-taken reservation is rolled back.** A NAT64 decision carries both a
  v4 pool source (source-NAT allocator) and a translated `(pool v4, port)` (the
  per-prefix allocator), so a session can be admissible to one and not the
  other. Without the rollback the source-NAT port taken moments before a NAT64
  refusal is held by nobody — the import is not published, so there is no
  session to reap.

The zone pair is resolved through the SAME helper the worker-side upsert uses.
If the two disagreed, the coordinator would reserve in one allocator while the
workers reserve in another: its check would pass while the port the session
actually names stayed free.

**Note on the import outcome.** The control RPC's `ControlResponse.ok` is not
yet driven by this refusal. The reservation now happens early enough that it
COULD be — which was impossible before, since the worker-side reserve runs long
after the RPC has answered — but wiring it through the handler, and the
Prometheus counter for the new metric, are tracked separately.

## Config-Epoch Guard (#5274)

Distinct from the per-key install generation (#2170), every **session** message
carries a length-gated trailing `ConfigEpoch uint64` (LE), appended after the
#3301 `AppTimeout`/`PolicyCounterIdx` block on V4 and after the #4565
`Nat64SnatV4` on V6. An old decoder stops before it and reads `ConfigEpoch == 0`
(`if off+8 <= len(payload)` block in `decodeSession*Payload`); a new decoder
reading an old, shorter payload also sees 0 — rolling-upgrade safe, no version
bump (the same additive-trailing-field discipline as #2170/#3301/#4565).

**Purpose.** It closes the immediate-policy-invalidation gap across the HA
boundary. The primary admits a session under config A, then commits config B
(which DENIES it). Config B is config-synced and applied on the standby (which
runs `clearSessionsForDeletedPolicies`), but a delayed config-A session install
that arrives **after** that sweep would otherwise install a stale permit that
the standby forwards under after failover.

**Semantics (sender, `pkg/cluster`).** `stampInstallGen*` stamps every queued
session with `ConfigEpoch = configGenCounter.Load()` — the #3931 config-sync
generation this node currently holds. A session still present in the local table
when it is queued has survived this node's own config-apply sweep, so it is
legitimately admitted under the current config.

**Semantics (receiver, `pkg/cluster`).** `installClusterSynced*` refuses an
install whose `ConfigEpoch` is **strictly older** than `lastAppliedConfigGen`
(`SessionsStaleConfigIgnored++`) and drops it BEFORE forwarding to the helper.
Both stamp and compare are in the SAME sender→receiver #3931 namespace (the
sender's monotonic counter, which the receiver applies via the config-sync path
and records as `lastAppliedConfigGen`), so the cross-node comparison is
meaningful. `ConfigEpoch == 0` (legacy peer / local-origin) disables the check;
the `resetRecvGen` bulk barrier zeroes `lastAppliedConfigGen`, so a rebooted-peer
cold re-prime is never falsely rejected.

**Authority is the Go cluster layer, NOT the userspace helper.** Unlike #2170's
`Generation` — which the helper mirrors and re-enforces per key — the config
epoch is a GLOBAL check against the receiver's current applied config, and the
only cross-node-comparable namespace is the #3931 config-sync generation, which
lives entirely in `SessionSync`. The helper's own `config_generation` is a
*local* commit counter (`Manager.bumpGeneration`) that is independent per node
and therefore cannot host this guard, so no `config_epoch` field is added to
`SessionSyncRequest` or `ha.rs`. Regression coverage:
`TestStaleConfigEpochSessionRejected5274{,V6}`,
`TestSessionWireRoundTripConfigEpoch5274{V4,V6}`,
`TestConfigEpochStampedAtQueueTime5274`, and
`TestConfigEpochNoRejectAgainstZeroBaseline5274` in
`pkg/cluster/sync_config_epoch_5274_test.go`.

## Ingress Interface Identity (#7095)

Every **session** message carries a length-gated trailing `IngressIfaceFold
uint32` after `RTFlowSessionID`. An old decoder stops before it and reads
`IngressIfaceFold == 0` (`if off+4 <= len(payload)`); there is no
`SessionSyncWireVersion` bump, for the same reason #2239/#3931 did not need one.

**It is not an ifindex.** An ifindex is node-local — node 0's `ge-0-0-1` and node
1's `ge-7-0-1` are the same logical RETH member with different numbers — so
#6928 synced nothing rather than name the wrong NIC on the peer. What rides the
wire is `config.StableIfaceID` over the RETH-RELATIVE name (`reth0.50`), which is
byte-identical on both chassis because zones bind to it and `RethToPhysical`
resolves it per node. The receiver resolves the fold back to its OWN
`{ifindex, vlan}` before the helper stores it.

**Zero is the unknown sentinel, and one encoding serves every producer of it:** a
legacy peer emits no field at all, an interface with no cluster-stable name folds
to 0, and a fabric-redirected session records no identity because the fabric
stamp carries a u16 zone id and nothing else (#7096). All three fall back to the
#4792 zone approximation on display. An unknown or ambiguous fold on the
receiving side resolves to nothing for the same reason — the zone is honest where
a guess is not.

Adding this field moved every mixed-version truncation constant in
`pkg/cluster/*_test.go` by 4 bytes. That is the standing cost of the trailing-field
pattern: those cells cut a payload back by a hard-coded width to simulate an old
peer, so each new trailing field has to be added to each count.

## RT_FLOW Session Id (#5212)

Every **session** message carries a length-gated trailing `RTFlowSessionID
uint64` (LE), appended **after** the #5274 `ConfigEpoch` on BOTH V4 and V6. An
old decoder stops before it and reads `RTFlowSessionID == 0` (`if off+8 <=
len(payload)` block in `decodeSession*Payload`); a new decoder reading an old,
shorter payload also sees 0 — rolling-upgrade safe, no version bump (the same
additive-trailing-field discipline as #2170/#3301/#4565/#5274).

**Purpose.** The dataplane assigns each session a STABLE id
(`SessionTable::alloc_session_id`, `(worker_id << 48) | counter`) and stamps it on
its RT_FLOW SESSION_CREATE/SESSION_CLOSE records (#4915). That id is NODE-LOCAL:
before #5212 a peer-synced session was assigned a FRESH id on import, so a session
that opened on the primary and closed on the standby after a failover carried
DIFFERENT ids on the two nodes and cross-node log/event correlation broke. #5212
carries the originating node's id across the sync wire so the importing node
ADOPTS it — the two nodes emit RT_FLOW records for the same session under one id.

**End-to-end path (both sides).** Rust `SessionDelta.session_id` → the
`MSG_SESSION_OPEN` event-stream frame's trailing `session_id` u64
(`encode_session_open`) → Go `SessionDeltaInfo.RTFlowSessionID`
(`decodeSessionEvent`) → `SessionValue{,V6}.RTFlowSessionID`
(`userspaceSessionFromDelta*`, distinct from the node-local BPF-ABI `SessionID`,
which the same converters mint per session via `nextUserspaceSyncedSessionID`
since #6198 — see "Node-Local BPF-ABI Session Id" in
`docs/session-sync-architecture.md`) → this
length-gated trailing wire field (`encode/decodeSessionV{4,6}Payload`) → the peer
Go `SessionSyncRequest.session_id` (`buildSessionSyncRequest*`) → the Rust helper
`build_synced_session_entry` → `SessionInstall::session_id`. On import,
`upsert_synced_with_origin` ADOPTS the wire id when non-zero and only falls back
to `alloc_session_id()` for a legacy peer (id 0). The id is adopted verbatim so
the same logical session carries the SAME id on both nodes — that cross-node
correlation is the entire point. It is a **metadata-only** stamp (RT_FLOW
correlation and the `show security flow session` mirror id), NEVER a lookup key
or slab handle, so adoption cannot affect forwarding, security, or memory
safety. Since #6311 it is also globally **collision-free**: the high-16
namespace is `node_bit << 15 | worker_id`, fed from `ConfigSnapshot.node_id`, so
an adopted id carries the ORIGINATING node's bit and can never equal an id the
importing node mints. Before that bit, both nodes ran the same worker set with
counters that both start at 1, so in an active/active cluster an adopted id
collided with a local same-worker id — and that also regressed pre-#5212
same-node uniqueness, where every import got a fresh local id. The node bit is
also why `upsert_synced_with_origin` does not reconcile `next_session_id`
against an adopted id: the two namespaces are disjoint, so a later local alloc
cannot re-hand-out an adopted value.

`node_id` rides `apply_snapshot` as an additive `omitempty` /
`#[serde(default)]` field with **no** `CONFIG_SNAPSHOT_PROTOCOL_VERSION` bump.
The snapshot handler gates on EXACT version equality, so a bump would make a
mixed-base pair refuse to apply a snapshot at all; an older helper that ignores
the field simply keeps the pre-#6311 layout. The pairing is monotone in both
directions — new-daemon/old-helper is today's behaviour, and
old-daemon/new-helper leaves node 1 in the un-bitted low half, also today's
behaviour — so neither direction introduces a NEW collision. It is consumed only
at worker SPAWN, so a node id that changes at runtime takes effect on the next
plan change or restart; `/etc/xpf/node-id` is read once at daemon start, so that
is already a reboot-level operation.

**Additive, not a guard.** Unlike #5274's `ConfigEpoch`, this field is pure
identity carriage — no receiver rejects on it. `RTFlowSessionID == 0` (legacy
peer, or a synthesized delta with no live entry) simply falls back to a fresh
local id. Regression coverage:
`TestSessionWireRoundTripRTFlowSessionID5212{V4,V6}` in
`pkg/cluster/sync_rtflow_session_id_5212_test.go`,
`TestDecodeSessionEventRTFlowSessionID5212` /
`TestBuildSessionSyncRequestCarriesRTFlowSessionID5212` in
`pkg/dataplane/userspace`, `TestUserspaceSessionFromDeltaCarriesRTFlowSessionID5212`
in `pkg/daemon`, and the Rust `synced_import_adopts_peer_session_id_5212` /
`test_encode_session_open_carries_session_id_5212`.

## Config Payload (Variable)

UTF-8 text of the full Junos-format configuration followed by a trailing
16-byte generation framing (#3931):

```
[config text bytes ...][configGenMagic (8 bytes)][gen (uint64 LE, 8 bytes)]
```

`configGenMagic` = `00 ff 78 70 66 43 47 00` (`\x00\xffxpfCG\x00`), chosen from
non-printable bytes so it cannot collide with real Junos config text. The
sender (`QueueConfig`) stamps a strictly-monotonic `gen` drawn from a
process-wide counter seeded from `CLOCK_MONOTONIC` nanos (same cross-boot
reasoning as the session install `genCounter`).

**Commit-side trigger — transport-independent (#5054).** An operator commit
pushes the newly-committed config to the peer regardless of which management
transport delivered it: the gRPC, REST, and local interactive-shell commit
handlers all route through `commitAndApplyOperator` /
`commitConfirmedAndApplyOperator` (`pkg/daemon/daemon_apply.go`), which derive
the push decision from **RG0 ownership** (`rg0ConfigSyncAuthority` — cluster
configured AND this node is the RG0 config-authority primary), not from the
transport. The same RG0-ownership rule gates the actual push in
`syncConfigToPeer`, so a standalone / non-owner node never pushes. Before #5054
only the gRPC handler synced; REST and the local shell passed `syncPeer=false`,
so a REST/shell commit on a healthy cluster left the standby on the prior config
until an unrelated transport-disconnect reverse-sync — an RG failover could then
silently restore config the operator believed changed. The autonomous
event-options engine is the deliberate exception: it commits with
`syncPeer=false` because each node fires remediation independently from its own
RPM events and must not push node-local state to the peer. The commit-side
trigger MUST still fire on every operator transport (a commit is the only edge
that carries a *new* generation), but it is no longer the sole convergence path
— the reconcile-side trigger below closes the connect/role/uptime ordering gap.

**Reconnect/reconcile-side trigger — level-triggered (#5863).** The commit push
alone is not sufficient. A peer can (re)connect while this node is not yet the
RG0 authority or is still within the post-boot stability window; the historical
code pushed only from the `OnPeerConnected` edge and evaluated the
primary/stability gates *only at connect time*, so a **later** promotion or the
crossing of the 30s stability threshold never re-pushed — the peer could stay
INDEFINITELY divergent until an unrelated commit/reconnect. The push is now
modeled as reconciliation to a desired state, not a one-shot edge.
`reconcileConfigSyncToPeer` (`pkg/daemon/daemon_ha_sync.go`) re-evaluates the
invariant — *this node is the RG0 config authority (`rg0ConfigSyncAuthority`)
AND stable (uptime ≥ 30s) AND a peer is connected AND config sync is enabled AND
the current config generation has not already been pushed on this peer's current
connection* — and pushes ONLY when desired-vs-actual diverges, at most once per
`(peer-connection-epoch × config-generation)`. It is invoked on every input
change: peer (re)connect (`OnPeerConnected`), RG0 promotion
(`applyRG0OwnershipTransition`), and a low-frequency reconcile loop
(`configSyncReconcileLoop`) that wakes at the stability threshold and thereafter
on a coarse 30s safety-net tick to recover any dropped promotion/connect edge.
The `(epoch × generation)` marker makes every already-satisfied evaluation a
cheap no-op (state gates + one config-text hash, no `QueueConfig`), so the
shared userspace control socket never sees a push storm and session installs are
never starved during bulk sync — the control-socket-contention rule. The
reconcile stays RG0-primary-gated exactly like the commit push, so a
reconnecting SECONDARY never overwrites the authoritative primary's config
(#2239/#4385); a fresh connection bumps the epoch, so it always re-receives the
config even when the generation is unchanged.

**Ordering guard (#3931).** Config sync historically applied via a racing
`go OnConfigReceived` goroutine per message with no sequence number, so a rapid
commit pair (C1 then C2) could apply out of order and leave the standby on the
older C1 with no alarm. The receiver now:

1. Decodes `(configText, gen)` with `decodeConfigPayload`. A payload without the
   trailing magic is a **legacy sender's** raw config text and decodes with
   `gen=0` (applied unconditionally — the pre-#3931 behavior).
2. Enqueues `{gen, configText}` onto a bounded, single-consumer ordered apply
   queue (`configApplyLoop`) — the `receiveLoop` is single-threaded per
   connection, so this preserves receive order. The non-blocking enqueue never
   stalls session sync / heartbeats behind a slow config apply. If the queue is
   full the enqueue drops — see **Queue-full drop (#6778)** below, because the
   `default:` arm discards the payload it is *holding*, which is the NEWEST
   generation, not the oldest queued one.
3. Applies a config only when `shouldApplyConfigGen` accepts its generation
   (strictly newer than the last-applied high-water mark, or `gen=0`). An
   out-of-order older config is **dropped with an alarm** and counted in
   `ConfigsStaleIgnored`. The standby therefore always converges to the newest
   config the primary sent.

**Apply-then-advance (M-2/#4151).** The high-water mark (`lastAppliedConfigGen`)
advances ONLY AFTER the apply succeeds — `OnConfigReceived` now returns an
`error`, and `configApplyLoop` calls `recordAppliedConfigGen` to advance the
mark only on a `nil` return. If the apply does NOT take effect — a
compile/promote failure (a mixed-build ISSU syntax error), a store rejection, or
a transient RG0-primary rejection (`handleConfigSync` refuses the config while
this node believes it is the RG0 config authority) — the loop counts
`ConfigsApplyFailed` and leaves the high-water at the last-applied generation.
The primary's re-push of the SAME generation is then re-admitted (not dropped as
stale) and the standby re-converges. The pre-#4151 order advanced the mark on
admission, BEFORE the apply, so an apply failure left the mark ahead of the
actually-applied config: the re-push was silently dropped and the standby stayed
stranded on the prior config (the failure class #4034 fixed on the *sender*,
reintroduced on the *receiver* by the #3931 ordering guard). This preserves the
#1960 lenient-load posture: whatever `syncAndApply` reports as its outcome
(nil = store promoted + applied; error = not applied) is exactly what gates the
mark, so the high-water always reflects the config actually in effect.

**Queue-full drop (#6778).** The non-blocking enqueue in step 2 takes its
`default:` arm when `configApplyCh` (cap 64) is full. The item it discards is
the INCOMING one — the newest generation the peer has sent — while the queue
retains the older ones, so the node finishes draining on a *superseded* config.
`recordRecvConfigGen` has already run for that payload (deliberately: see the
#5563 gate below), so the node correctly reads config-stale and manual-failover
promotion is refused. Before #6778 nothing closed that gap: the sender's #5863
`(epoch × generation)` marker was claimed BEFORE the push and only a nack clears
it, so on a stable connection the standby stayed behind the primary until the
next commit or reconnect — a wedge, not a blip.

The drop is now treated as the same class of event as an apply failure, because
the operator consequence is identical and the repairs already existed:

- **Counted** on its own `ConfigsQueueFullDropped` counter, rendered in
  `show chassis cluster information` as `Configs queue-full-dropped:`. It is
  deliberately NOT folded into `ConfigsApplyFailed` — the apply never ran, so
  sending an operator to look for a compile error would be wrong — nor left on
  the generic `Errors` counter, where "the standby is behind the primary's
  committed config" is indistinguishable from a send failure.
- **Debt.** `noteConfigApplyFailure(errConfigApplyQueueFull)` arms the #6387
  grace-expiry timer, so a drop that does not re-converge inside the grace
  raises `CF` on its own with no further delivery required.
- **Retry.** `sendConfigApplyNack(gen)` re-arms the sender's #5863 push marker
  through `OnPeerConfigApplyFailed`, and the sender's existing 30s
  `configSyncReconcileLoop` re-pushes. There is **no new retry queue**: buffering
  the dropped payload on the receiver is exactly the unbounded growth the
  non-blocking send exists to avoid, and the payload is the peer's ACTIVE config,
  so re-asking for it is strictly better than holding a copy that may already be
  superseded. Writing the nack from the receive loop is the established shape in
  that switch (the heartbeat ack and `sendBulkAck` do the same under `writeMu`),
  and it is rate-bounded by the peer's push rate.

The queue itself was left lossy rather than converted to an evict-oldest
"latest-generation slot". Evicting the oldest would require the receive loop to
become a second consumer of `configApplyCh`, and under a cross-fabric reorder
(the active connection flipping between `conn0`/`conn1`) it could evict a NEWER
queued item to make room for an OLDER arrival — losing a generation that, having
enqueued successfully, would take no nack and no debt. That trades a visible,
recovered loss for a silent one.

**Debt is not cancelled by a stale backlog apply (#6778).** A queue only fills
because the consumer is behind, so a drop is always followed within milliseconds
by successful applies of the backlog. `noteConfigApplySuccess` therefore takes
the generation whose apply just succeeded and no-ops while it is still below
`lastRecvConfigGen` — the same predicate `TransferReadinessSnapshot.ConfigStale`
uses. Under the pre-#6778 unconditional clear those backlog successes disarmed
the grace timer and the drop's debt evaporated long before `CF` could raise. The
gate cannot pin `CF` raised: a payload refused before `recordRecvConfigGen` never
raises the received mark, `resetRecvGen` clears BOTH marks to 0 on reconnect, and
a legacy peer leaves both at 0.

**Config-sync apply-failure health surfacing (`CF`, #6387).** Leaving the
high-water pinned on a persistent apply failure is correct for convergence but
made the failure *invisible*: a standby whose apply hard-fails every time (e.g.
the host-inbound enforcement step cannot install because a dependency is
missing) is stuck `Transfer ready: no`, `applied gen=0` forever, yet reports as
"healthy" in `show chassis cluster status`. `configApplyLoop` now drives a
**time-based** config-sync monitor-failure (`CF`) off that failure edge. On the
FIRST apply failure of an un-applied streak it stamps a monotonic timestamp
**and arms an independent grace-expiry timer** (`armConfigApplyGraceTimerLocked`
→ `time.AfterFunc`, overridable in tests via `SessionSync.afterFuncFn`). The
timer is the primary trigger because the loop only runs on a RECEIVED config and
the config sender pushes a generation **at most once per connection/generation**
(the daemon's level-triggered `reconcileConfigSyncToPeer` is idempotent after
the first push) — so a *stable* connection with one persistent apply failure
receives **no second delivery**, and any gate keyed on a re-delivery edge (an "N
consecutive failures" count, or the original elapsed-check that only re-ran on
another failure) could never fire and would strand the standby silently forever.
When the timer fires — grace elapsed, `DefaultConfigApplyFailGrace` 30s,
comfortably longer than a transient RG0-primary rejection so it never flaps — it
fires `OnConfigApplyHealth(true)` regardless of whether any further config
arrived. If a re-delivery *does* arrive after the streak has persisted
**strictly** longer than the grace (`>`, not `>=`), an on-edge fast path raises
immediately; both paths are idempotent and **epoch-guarded** so CF raises at
most once per streak and a success that cancels a timer already past its
`Stop()` cannot raise a stale CF (the cancelled-but-already-firing race).
Every `OnConfigApplyHealth` publish — the timer raise, the on-edge raise, and
the success clear — is delivered **while still holding `configApplyMu`** (#6398).
The epoch guard alone only covers *decision-time* staleness (the timer acquiring
the lock after a success); it does not order the two callback *deliveries*.
Publishing both edges under the one mutex serializes them, so a timer raise
callback preempted between deciding-to-raise and delivering cannot land *after* a
concurrent success has already cleared CF — the reorder that would otherwise
leave the manager stuck `configSyncFailing=true` after a successful apply. The
callback runs `SetConfigSyncHealth`, a cheap two-field setter under the manager's
`m.mu`, so the lock order is fixed `configApplyMu → m.mu` with no inverse
(nothing takes `m.mu` then calls back into a `configApplyMu` path). The
daemon translates `OnConfigApplyHealth` into `cluster.Manager.SetConfigSyncHealth`.
A successful apply cancels the timer, resets the streak, and clears CF
**unconditionally** — not gated on the instance's own local raised flag —
because a comms transport change tears down the `SessionSync` but **keeps the
`cluster.Manager`**: the replacement instance must be able to clear a CF the
prior instance raised, so an idempotent clear on the first success of *any*
instance re-converges the annotation (gating it on a local flag left the manager
CF stuck raised forever across a comms restart). The timer is also stopped on
`SessionSync.Stop()` so none leaks across reconnects.
The manager stores this as a **dedicated node-global field**
(`configSyncFailing` / bounded `configSyncFailReason`), NOT an
`rg.MonitorFails` sentinel — `reconcileMonitorDebtsLocked` would wipe any
non-interface/non-IP `MonitorFails` entry on the next `UpdateConfig`. It renders
as `CF` in the `Monitor-failures` column of every RG row, flips `Node health` →
`degraded`, and adds a `Config sync: failing (<reason>)` line beside the
`Configs apply-failed:` counter. It is **diagnostic only**: it never perturbs
`Weight`/`monitorWeights`/readiness/election, and it is **not** a second failover
gate — manual failover stays gated solely by `ConfigStale()`
(`ReadyForManualFailover`), and crash takeover stays intentionally ungated.

**Applied-not-just-active convergence shortcut (#4957).** `handleConfigSync`
short-circuits a re-push whose text already matches the active config so a
duplicate does not re-run the whole reconcile. That shortcut is gated on
**both** `activeText == incomingText` **and** `store.ActiveApplied()`, not on
active-text equality alone. `configstore.SyncApply` promotes `s.active` to the
peer config BEFORE `applyConfigLocked` runs and — under the #1799
degrade-not-fail doctrine — does NOT roll `s.active` back when the apply fails.
So active-text equality alone would treat a config that was PROMOTED but never
finished applying (a transient networkd/nft/IPsec tail error) as converged: the
primary's same-generation re-push would take the fast path, return `nil`, and
advance the high-water past a config whose dataplane never converged — a standby
that acks a generation it never applied and can expose stale/disarmed forwarding
at failover. `ActiveApplied()` is a config-text digest the daemon stamps ONLY
after a fully-successful apply — the boot apply (`applyConfig`) and a committed
config (`applyAndSyncCommitted`) stamp `MarkActiveApplied` while holding the
apply semaphore, and a peer config-sync stamps it from INSIDE `syncAndApply`
(#6296): it captures the digest of the tree `SyncApply` promoted via
`ActiveDigest` and replays it via `MarkAppliedDigest` on full success, both under
the apply semaphore, rather than re-reading `s.active` after the semaphore is
released (where a concurrent secondary-side promoter could have mutated it into a
different, never-applied tree). It is FALSE in the window between promotion and a
successful apply, so a re-push of a
promoted-but-unapplied config falls through to `syncAndApply` and RE-ATTEMPTS the
apply (reconcile retry) instead of being swallowed as converged. Because the
marker is keyed on the config text, a stale value can only make the shortcut MORE
conservative (one idempotent re-apply), never falsely converged; and because the
boot/commit/sync apply paths all stamp it, an already-applied config still takes
the shortcut on a reconnect (which zeroes the generation high-water, so the
primary re-pushes the current generation even when nothing changed) rather than
pointlessly re-applying a live config.

The last-applied high-water mark is reset to 0 on a peer bulk re-prime
(`resetRecvGen`, fired on `BulkStart`) so a **rebooted primary** — whose
monotonic counter restarts lower — is accepted instead of refused as stale
(the #2198 F2 inverse-of-stale-RETAIN reasoning applied to config). The next
config after a reconnect is always the peer's *current* config
(`pushConfigToPeer` sends `ShowActive`), so the newest content still wins.

**That reset is atomic against every advance of the marks (#5084).** Both
high-waters are advanced by a non-atomic read-modify-write — load, compare,
store — and `resetRecvGen` clears them from a *different* goroutine: the clear
runs on a receive loop (the `BulkStart` handler), the applied mark is advanced
by the single `configApplyLoop` consumer, and the received mark is advanced by a
receive loop, of which there are **two** (`conn0`/`conn1`). Nothing ordered
them, so a clear landing between an advance's load and its store was simply
LOST, and the store then re-raised the mark the reset had just zeroed.

That is not a transient. The marks are monotone-max and the whole reason the
reset exists is that a rebooted peer restarts its counter LOWER, so a surviving
pre-reboot generation refuses *every* generation the reconnected peer can
produce: on `lastAppliedConfigGen` the standby silently keeps running the
pre-reboot config, and on `lastRecvConfigGen` the readiness comparison below
inverts. Neither self-clears short of another accepted re-prime. `configGenMu`
now covers the reset and every advance (`recordAppliedConfigGen`,
`recordRecvConfigGen`, `beginConfigApply`/`endConfigApply`); readers stay
lock-free, since a reader racing a writer only ever observes one side of a
single monotone step. Two prior comments stated the contract wrongly and are
corrected at their sites — the applied advance claimed it is "called ONLY from
the single-consumer `configApplyLoop`", which ignores the clear, and the
received advance claimed "the receiveLoop is single-threaded per connection",
which is true per connection but there are two of them.

**Manual-failover config-staleness gate (#5563).** A second high-water mark,
`lastRecvConfigGen`, records the highest generation this node has *received*
from the peer (advanced in the `syncMsgConfig` handler at enqueue, BEFORE
apply, even if the ordered apply queue is full and the payload is dropped —
#6778 keeps that raise and adds the nack that closes the resulting gap). It
is the receiver's local view of the config *sender's* current committed
generation. `TransferReadiness` carries both marks (`PeerConfigGen =
lastRecvConfigGen`, `AppliedConfigGen = lastAppliedConfigGen`), and
`ReadyForManualFailover` refuses promotion when `PeerConfigGen >
AppliedConfigGen` — i.e. the standby has received a newer config than it has
successfully applied. Promoting a config-stale standby runs an OLDER
policy/zone/application snapshot than the operator committed: **fail-open** after
a tightening commit (admits traffic the operator denied) and **false-deny** after
a loosening commit (drops traffic the operator allowed). The gate is scoped to
this genuine behind-the-primary case: a legitimate same-generation failover
(`applied == received`) stays ready, and a legacy/fresh peer (both marks 0) is
never blocked. `resetRecvGen` zeroes `lastRecvConfigGen` alongside
`lastAppliedConfigGen`, so the `applied <= received` invariant holds across a
reconnect re-prime. This is a **planned/manual** readiness gate only; the
UNPLANNED/crash failover path is not gated (a stale-standby crash-takeover is a
separate availability-vs-security tradeoff — the alternative is a total outage).
The residual window is narrow: a config committed on the primary but whose
`syncMsgConfig` frame has not yet reached the standby is not yet reflected in
`lastRecvConfigGen`, so a promotion in that sub-millisecond window still sees the
prior generation — a strict improvement over the pre-#5563 behavior, which never
checked config generation at all.

**Wire compatibility.** #3931 deliberately does NOT bump
`SessionSyncWireVersion`: the framing is additive and self-detecting via the
magic, and that gate governs whether SESSIONS sync at all across a mixed-base
pair — bumping it would break session sync for the whole mixed-version ISSU
window (the #2239 lesson). The one asymmetric direction is a NEW sender's
framed payload reaching a LEGACY receiver in the brief ISSU window: the old
node treats the 16 trailing bytes as config text, its Junos parser rejects it,
and the config-sync apply fails — the old node retains its current config
(fail-safe, no crash, no divergence worse than today).

The secondary's `OnConfigReceived` callback invokes `load override` + commit to
apply the accepted config, and returns an `error` so the ordered apply loop
advances the high-water mark only on a successful apply (see Apply-then-advance
above).

**Receive-side session invalidation (#5564).** `syncAndApply`
(`pkg/daemon/daemon_apply.go`) is the receive-side analogue of the commit path's
`applyAndSyncCommitted`. `configstore.SyncApply` promotes the peer config to
active BEFORE the reconcile, and `applyConfigLocked` then arms the dataplane
snapshot — so once the apply reaches its tail the standby is forwarding under the
new policy set. The three session invalidators (`clearSessionsForPolicyChanges`:
the #4234 deletion-clear, the modified-policy re-eval, and the #4342
default-policy change) MUST therefore run to re-authorize surviving established
sessions against the now-active config. They are reached through
`reportSessionAuthorizationChanges` (#5858), the single commit-time entry point
for "authorization the operator just changed, versus sessions already
established". It used to carry a second half, the #5858 interface-input-filter
advisory; #7212 moved that half into the dataplane (lazy per-tuple revalidation
against the changed static filter on the session-hit path) and deleted the
advisory, whose claim that established sessions are not revoked is no longer
true. They run from a deferred, guarded block
so they ALWAYS fire once the config reached active+armed — including on a
NON-FATAL best-effort tail failure (host-inbound/lo0 nft, networkd, ...) that
`applyConfigLocked` joins and returns. Skipping them on such an error (the
pre-#5564 early `return nil, err`) was a security fail-open: a session a
peer-tightened/deleted policy should now DENY kept forwarding under its stale
authorization, and because the store already held the incoming text the primary's
equal-active-text re-push took the fast path (`activeText == incomingText`, at the
top of `handleConfigSync`) and never re-entered `syncAndApply` to correct it,
making the omission permanent (visible at failover). The classifier
`applyErrSkipsPeerSync` (shared with the commit path) still distinguishes the two
FATAL classes — a required-protocol-gate error (dataplane DISARMED, #2138) and a
daemon-stop context CANCELLATION (#2926; #7618 narrowed this from
cancel-or-deadline, since a deadline on this path is always a per-command
budget rather than an abort) — where the config is not live-forwarding and
the invalidators are correctly skipped; on those `syncAndApply` returns a nil
config plus the error. Any other tail error is surfaced (joined with any partial
#5578 invalidation error) AFTER the invalidators run, so the high-water mark does
not advance. On such a non-fatal tail error `syncAndApply` does NOT stamp the
applied marker (`MarkAppliedDigest` runs only when its deferred sees `retErr ==
nil` — no fatal or non-fatal apply error and no partial invalidation; #6296), so
`ActiveApplied()` stays false and the primary's re-push does NOT take the
active-text fast path (#4957): it re-enters `syncAndApply` and RE-ATTEMPTS the
apply and the invalidators, completing the reconcile/finalization the tail error
left unfinished — rather than the pre-#4957 behavior where the fast path returned
nil and advanced the mark over a config the dataplane never finished applying.

## Peer boot incarnation (#5084)

Config generations are comparable **only within one sender boot**.
`initGenState` seeds `configGenCounter` from `CLOCK_MONOTONIC` nanos, so a
daemon restart within a boot produces a strictly HIGHER seed (still comparable)
while an OS reboot restarts the clock and produces a LOWER one (not comparable).

Before #5084 the ordered apply queue (`configApplyCh`, cap 64) held only
`{gen, text}`. When the peer rebooted and re-primed, `resetRecvGen` zeroed the
generation high-waters but did **not** drain items already queued from the prior
boot. A queued prior-boot payload could then apply after the reset, record its
(large, pre-reboot) generation as the high-water, and the rebooted peer's
lower-generation CURRENT config was refused as stale from then on — persistent
HA policy/routing divergence.

**The guard is an EQUIVALENCE, never a ranking.** PR #6900 tried a floor over
the per-connection `syncConnID` counter and failed across seven review rounds: a
total order over connections cannot express "were these two payloads produced by
the same peer boot?". A floor that never descends locks out a live
same-incarnation sibling that merely connected earlier; a floor that descends
re-admits departed older-incarnation connections. The full post-mortem is on
#5084 and in `docs/peer-boot-incarnation-plan.md`.

### The field

`/proc/sys/kernel/random/boot_id` — a 128-bit UUID the kernel regenerates at
each OS boot, stable for that boot, unchanged by a daemon restart. That is
exactly the granularity at which `CLOCK_MONOTONIC` restarts, so it is forced by
the generation seed, not chosen. It is **compared for equality only**; ordering
two boot ids is the mistake #6900 made.

It rides in the `syncMsgBulkStart` payload as a length-gated trailing extension
(8 → 24 bytes), the same #2170 discipline the delete frames use. `BulkStart` is
the carrier because the prime IS the claim event: the incarnation arrives in the
frame that declares it current, so no connection is ever installed with an
unknown incarnation. The auth `HELLO` was rejected as a carrier —
`performSyncHandshake` returns immediately when the cluster is unkeyed, so a
HELLO-carried incarnation would be silently absent on unkeyed clusters.

### Receiver rules

- A `BulkStart` whose incarnation **differs** from the current one switches the
  namespace: the generation high-waters clear (`resetRecvGen`, which already
  fired here) and the new incarnation is recorded.
- A `BulkStart` carrying the **same** incarnation is a mid-connection re-prime
  (the #5450 forced resync) and invalidates nothing — same boot, comparable
  generations.
- A config payload whose incarnation differs from the current one is dropped
  **permanently** and is never re-admitted. Because membership is an
  equivalence, the dropped payload's generation carries no information the
  current high-water needs, so the drop cannot strand the mark the way #6900's
  fence could.
- A payload with **no** incarnation is never dropped on incarnation grounds.

There are **two** drop sites and neither subsumes the other:

- **At receive** (`handleConfigPayload`), before `recordRecvConfigGen`. The
  received-config high-water is a monotone max that gates manual-failover
  readiness (#5563 refuses promotion while `PeerConfigGen > AppliedConfigGen`),
  and a dead incarnation's generation comes from the peer's PRE-reboot counter,
  so it is higher than anything the live incarnation can produce. Letting it
  raise the received mark would strand the standby reading config-stale with
  nothing able to close the gap short of another re-prime.
- **At apply** (`configApplyLoop`), before the generation gate. This is the one
  that catches a payload already sitting in `configApplyCh` when the re-prime
  landed — the reported defect, since `resetRecvGen` does not drain the queue.

In the `BulkStart` handler the incarnation is recorded **before**
`resetRecvGen`. Reversing them opens a window where the high-waters are already
zeroed while the current incarnation is still the dead one, so a prior-boot
payload dequeued in that window passes the fence and records its generation.

### Fail-open across the mixed-version window

`len(payload) < 24` ⇒ no incarnation ⇒ exactly today's generation-only
ordering. This is the same legacy-sentinel convention the package already uses
(`gen == 0`, `epoch == 0`, `incarnation == 0 || seq == 0`), and the fallback is
`origin/master`'s behaviour rather than a weakened version of it. Failing
**closed** would refuse ALL config from a not-yet-upgraded peer for the whole
rolling-upgrade window, stranding the standby on stale config — strictly worse
than the bug being fixed. It is not a security decision: the incarnation is not
an authorisation token and grants nothing; the authentication boundary is the
PSK handshake and the frame HMAC, both untouched.

No capability negotiation exists, and that is the point — presence is decided
per-frame by payload length, so there is no handshake round to get wrong.
Upgrade order does not matter:

| receiver | sender | outcome |
|---|---|---|
| old | old | today's behaviour |
| old | new | 24-byte `BulkStart`; old receiver reads `payload[:8]`, ignores the tail |
| new | old | 8-byte `BulkStart`; no incarnation; today's behaviour |
| new | new | full #5084 guard |

A node whose own `boot_id` is unreadable appends **nothing** rather than 16 zero
bytes, so it presents as an un-incarnated (old-build) sender rather than as a
distinct boot that changes on every read.

**Contingency, recorded deliberately:** if a future requirement demands that an
un-incarnated peer be REFUSED, that forces either a flag day or making the keyed
handshake mandatory — an upgraded receiver cannot distinguish "old peer that
cannot send the field" from "peer suppressing the field" without a negotiated
capability, and a negotiated capability has nowhere to live on the unkeyed path.
Both are decisions well outside #5084.

### Observability — a status field and counters, NOT a health state

A silent fail-open is how a half-upgraded cluster hides, so both halves are
counted and rendered by `show chassis cluster information`:

- `Peer boot incarnation: <hex>|none` — rendered **always**, including `none`,
  because `none` is the operationally interesting value and a line that
  disappears in exactly that case would hide it.
- `Primes without incarnation: N` — the fail-open fallback is active.
- `Configs dead-incarnation-dropped: N` — the fence did its job.

Plus one `slog.Warn` per CONNECTION (not per frame) when a peer primes without
an incarnation.

This deliberately does **not** raise a cluster health annotation or alarm state.
An un-incarnated peer is the expected steady state of a rolling upgrade, not a
fault; raising health for it would make every upgrade look degraded, and a
stale-incarnation discard is an expected event during a peer reboot. #6387 set
the precedent in the other direction by making a config-sync APPLY FAILURE
diagnostic-only so it never gates failover — a less severe condition must not be
louder.

### Known residual — shipped BOUNDED, not closed

A pre-reboot socket that is half-open and has not yet errored can still hold a
buffered `BulkStart` from the DEAD incarnation. If it lands after the new
incarnation primed, the namespace switches BACK, and config from the live
incarnation is dropped until the next prime re-switches it.

The window is bounded by the receive loop rather than by luck: `receiveLoop`
arms a 10s read deadline and gives up at `missedHeartbeats >= 2`, so such a
socket self-evicts within **~20s** of silence — and an OS reboot, the only thing
that changes an incarnation, outlasts that window, which makes the frame hard to
produce at all. It is self-healing: the peer re-pushes its current config on the
reconnect that follows, and every drop is counted in
`ConfigsDeadIncarnationDropped` and rendered in status.

Closing it rather than bounding it means a receiver-local strictly-increasing
"namespace claim ordinal" bumped on each switch, with a switch refused from a
connection whose slot is no longer installed. That is deliberately out of scope:
it is the same add-an-ordering instinct that produced #6900, and it should be
added against a demonstrated failure, not pre-emptively.

## Full-set state-sync ordering (#5706)

IPsec SA sync (type 9) and DHCP-server lease sync (types 25/26) are **full-set
pushes**: each message REPLACES the peer's held set wholesale. Both fabric
connections (`conn0`/`conn1`) run their own `receiveLoop` goroutine, so a peer's
frames are processed by two concurrent streams. A full-set delivered OUT OF
ORDER across those redundant streams (or a reordered/duplicated stream) could
overwrite a newer set with an older one — a state **regression** (a torn-down
tunnel resurrected on the standby, a released lease revived). Unlike sessions
(#2170) and config (#3931), these full-sets carried no sequence, so nothing
rejected the reorder.

**Wire trailer.** Each full-set now carries a trailing framing, analogous to the
#3931 config-generation trailer, appended AFTER the existing payload:

```
[ base payload ][ fullSetSeqMagic (8B) ][ incarnation (8B LE) ][ seq (8B LE) ]
```

- `incarnation` is the SENDER's process epoch — the construction seed
  (`syncEpoch`, from CLOCK_MONOTONIC nanos, constant for the process lifetime).
  Within a boot a process restart draws a strictly-greater epoch, so a restart
  supersedes; cross-boot the monotonic clock resets lower and the RECEIVER reset
  (below) handles it.
- `seq` is a **per-type strictly-monotonic** counter: IPsec, DHCP-v4, and
  DHCP-v6 draw from INDEPENDENT counters (`ipsecSeqCounter`,
  `dhcpV4SeqCounter`, `dhcpV6SeqCounter`), so a v4 push never gates a v6 one and
  an IPsec seq never gates a DHCP one. The counters start at 0; the first push
  draws 1, so a stamped frame is never `(0,0)`.

**Ordering guard.** The receiver keeps a `fullSetSeqGuard` high-water per stream
(`ipsecRecvSeq` / `dhcpV4RecvSeq` / `dhcpV6RecvSeq`, guarded by `recvSeqMu`
because both `receiveLoop`s touch them). `admit(incarnation, seq)` accepts only a
strictly-newer pair — lexicographic on `(incarnation, seq)`: a strictly-HIGHER
incarnation always supersedes; within an incarnation a strictly-higher `seq`
wins; anything else is stale and DROPPED (counted as `IPsecSAStaleIgnored` /
`DHCPLeasesStaleIgnored`, logged once). The held set and its apply callback are
left untouched on a rejected reorder.

**Cross-boot / rebooted-peer reset.** A LOWER incarnation is normally stale, but
an OS-rebooted peer restarts its monotonic epoch lower. The per-stream guards are
`reset()` to zero on a peer bulk re-prime (`resetRecvGen`, fired on the reconnect
`BulkStart`), so the rebooted peer's fresh full-set — re-advertised on reconnect
— is admitted unconditionally instead of being stranded on the pre-reboot set.
This is the #2198 F2 stale-RETAIN inverse, applied to full-set sync.

**Wire compatibility (mixed-version ISSU).** The trailer is ADDITIVE and
self-detecting via the magic, so #5706 does NOT bump `SessionSyncWireVersion`
(same reasoning as #2239/#3931 — bumping it would refuse SESSION sync across a
mixed-base pair). A LEGACY sender (pre-#5706) emits no trailer, so
`stripFullSetSeq` yields `(base, 0, 0)`; the guard treats `incarnation==0 ||
seq==0` as the legacy sentinel and accept-always for that peer (never wrongly
refused). New sender → old receiver:

- **DHCP (25/26):** the old lease decoder reads exactly its record count and
  IGNORES the trailing bytes — fully clean.
- **IPsec (9):** the name payload is newline-JOINED with no terminator, so
  gluing the trailer straight on would FUSE it onto the LAST connection name —
  an old newline-decoder (no `stripFullSetSeq`) would recover a corrupted final
  name it can no longer `swanctl --initiate`, silently dropping that tunnel on
  takeover. The IPsec full-set therefore inserts a single `\n` **delimiter**
  between the name list and the trailer (`appendIPsecFullSetSeq`). An old
  decoder then splits the trailer off as a SEPARATE trailing element — a bogus
  name `reinitiateIPsecSAs` merely warns it cannot initiate — while EVERY real
  SA name decodes cleanly. A new receiver removes the trailer
  (`stripFullSetSeq`) and the delimiter (`stripIPsecFullSetDelim`), so a
  new→new roundtrip decodes to exactly the sent names with no trailing empty
  name. This is confined to the brief mixed-version window and self-heals once
  both nodes are upgraded.

## IPsec SA Payload (Variable)

Newline-separated (`\n`) list of strongSwan connection names (e.g., `vpn-gw1\nvpn-gw2`), followed by a single `\n` delimiter and then the 24-byte #5706 (incarnation, seq) ordering trailer — i.e. `vpn-gw1\nvpn-gw2\n<trailer>`. The delimiter keeps the trailer from fusing onto the last name for an old newline-decoder (see the mixed-version note above); a new receiver strips both the trailer and the delimiter. On failover, the new primary calls `swanctl --initiate` for each name.

## Sync Algorithms

### 1. Initial Bulk Sync (on TCP connect)

Triggered once when the `connectLoop` successfully dials the peer:

```
connectLoop() establishes TCP connection
  → BulkSync()
    → writeMsg(BulkStart, epoch)         // signal start
    → IterateSessions(all v4)            // send every v4 session as SessionV4
    → IterateSessionsV6(all v6)          // send every v6 session as SessionV6
    → record pendingBulkAckEpoch=epoch   // record-then-send (#3912): BEFORE BulkEnd
    → writeMsg(BulkEnd, epoch)           // solicit peer BulkAck(epoch)
```

The pending-ack epoch is recorded **before** the `BulkEnd` write, not after.
`BulkEnd` solicits the peer's `BulkAck`, which is processed on the read
goroutine; recording after the write races a fast peer whose ack would then
latch a phantom pending epoch that never clears and permanently blocks manual
failover (#3912). See `docs/session-sync-architecture.md` "Record-then-send
ordering".

Both forward and reverse entries are sent during bulk sync. The receiver calls `SetSessionV4/V6` to install each session directly into the BPF map.

#### Authoritative-snapshot cold-prime (#5085)

`doBulkSync` (the cold-prime and #4090 re-drive entry point) **always** delivers
the snapshot via the lossless `BulkSync()` window above. The receiver's
`reconcileStaleSessions` deletes every eligible peer-owned session **absent from
the window's key set** (`bulkRecvV4`/`bulkRecvV6`), so that window must carry a
COMPLETE, authoritative snapshot — a session merely absent is treated as stale
and removed.

An earlier optimization (#418, `BulkSyncOverride`) delivered sessions as async,
LOSSY event-stream incrementals (`QueueSessionV4/V6` → non-blocking `sendCh`,
cap 4096) and then sent an EMPTY `BulkStart`/`BulkEnd` pair (`sendBulkMarkers`).
The receiver recorded zero keys and skipped reconciliation, so a stale
peer-owned session the standby held survived cold-prime (the #5085 bug). Because
the event-stream stream can drop frames under load, it can never delimit an
authoritative snapshot: reconciling against an incomplete set would DELETE live
peer-owned sessions merely dropped in transit. The override is therefore no
longer wired in production (`startClusterComms`); `doBulkSync` always ends with
a lossless direct-write window under `writeMu`. `BulkSyncOverride` is retained
only as a test/extension seam and is regression-proof: the trailing window is
framed unconditionally, so an override can never re-send empty markers.

#### Table-truth window source (#6031)

The window's session SOURCE is no longer the shim `sessions`/`sessions_v6` BPF
maps. Under the userspace dataplane those are a best-effort **display mirror**.
When this was written the helper published a conntrack row only on the
host-inbound install, the missing-neighbor seed, and the reverse-companion
repair, so a **transit** session — which is what an HA firewall is actually
protecting — had no row there at all. #6965 added the transit publish, but the
reason for moving the window source stands without it: the mirror is a
best-effort copy of a table the helper owns, so it is not table-truth however
complete it becomes.
Combined with the authoritative reconcile above (absent from the window ⇒
DELETED), framing the window from that mirror deleted the standby's live
peer-owned transit sessions on every cold prime, survivor re-drive, and forced
resync.

`doBulkSync` now prefers `SessionSync.BulkSnapshotSource`, wired by the daemon to
`ExportOwnerRGSessions(rgIDs, 0)` — the helper's in-process `SessionTable`,
owner-RG-filtered, synchronous, and UNBOUNDED (a cap would truncate the window
and the peer would delete the remainder). The snapshot is converted by the SAME
walk and filter the incremental delta stream uses, so both admit one set, and it
is framed verbatim (no second `ShouldSyncZone` pass — that could drop an entry
the incremental path admits, which the receiver would then delete). If the source
errors, `doBulkSync` fails CLOSED and frames NO window rather than falling back
to the mirror: an incomplete authoritative window destroys live sessions, while
framing none only defers the reconcile to the next armed retry. `BulkSync()`'s
store walk remains for callers with no snapshot source wired.

#### Survivor-fabric cold-start bulk re-drive (#4090)

The cold-start bulk streams over a **single** fabric connection: `BulkSync`
captures `getActiveConn()` once and pins every session + `BulkStart`/`BulkEnd`
marker to that connection with no per-message failover. On a dual-fabric cluster both
`conn0` and `conn1` are established concurrently, and the cold-start bulk is
triggered exactly once — gated on `wasDisconnected` (BOTH conns nil) AND
`!bulkEverCompleted` in `handleNewConnection`. If the pinned fabric dropped
mid-bulk while the *other* fabric stayed up, the bulk was stranded: the
per-message send loop only fails over the steady-state delta stream, not the
one-shot bulk, and `handleNewConnection`'s `wasDisconnected` gate cannot
re-fire while a survivor is up. The standby cold-started with an incomplete
session table until BOTH fabrics happened to drop together.

`handleDisconnect` now closes that gap. After clearing the dropped conn and
computing `connected := conn0 != nil || conn1 != nil`, when a survivor is still
up AND `!outboundBulkAcked.Load()` (our outbound bulk was never acked by the
peer), it schedules a single re-drive of `doBulkSync()` over the survivor:

- **Goroutine, not inline.** `handleDisconnect` holds `s.mu`, and
  `doBulkSync → BulkSync → getActiveConn` re-locks `s.mu`; an
  inline call would self-deadlock. The re-drive runs on a `wg`-tracked
  goroutine that takes no lock across the `handleDisconnect` boundary.
- **CAS in-flight guard.** `bulkRedriveInFlight` (an `atomic.Bool`,
  compare-and-swap `false→true`) bounds re-drives to one at a time and is reset
  when the goroutine returns, so a survivor that *also* flaps (its own write
  failure re-entering `handleDisconnect`) cannot start a storm of re-drives.
- **Stranded epoch reset.** The goroutine stores `pendingBulkAckEpoch = 0`
  before the re-run so the fresh bulk's epoch supersedes the stranded one (a
  latched phantom pending epoch would block manual failover, #3912).
- **Receiver unchanged.** A fresh `BulkStart` resets the receiver's
  `bulkInProgress`/`bulkRecvV4`/`bulkRecvV6` (and `resetRecvGen`, #2198 F2), and
  `BulkEnd` runs `reconcileStaleSessions`, so the re-driven bulk cleanly
  re-primes the standby.

Once the peer acks **our outbound** bulk (`outboundBulkAcked` set on a received
`BulkAck`), the gate closes: steady-state incremental sync already fails over
via the send loop, so no re-drive is needed and a normal post-cold-start
single-fabric drop does not re-bulk.

**#4360 — gate on the outbound-only flag, not the shared one.** The re-drive
exists to guarantee the peer received *our* table, so its gate keys on
`outboundBulkAcked`, which is set **only** by an inbound `BulkAck` (the peer
acknowledging our outbound bulk). It is distinct from `bulkEverCompleted`, which
is *also* set by an inbound `BulkEnd` (the peer's bulk arriving at us). If the
gate used the shared `bulkEverCompleted`, a small **inbound** bulk completing
first would set it and wrongly suppress re-driving a **stranded outbound** bulk,
leaving the peer with an incomplete view of our sessions. The inner re-check
inside the re-drive goroutine (the "a concurrent reconnect may have already
re-primed" early-out) uses the same `outboundBulkAcked` flag for the same
reason — keying it on `bulkEverCompleted` there would re-open the bug by bailing
whenever an inbound bulk had completed. `outboundBulkAcked` is sticky (never
reset): once the peer holds our full table, incremental sync keeps it fresh
across reconnects. `handleNewConnection`'s `coldStart` gate is unchanged and
still keys on `bulkEverCompleted` — a both-fabrics-down reconnect is a separate
path from the survivor re-drive.

### 2. Periodic Sync Sweep (1s interval, new sessions)

`StartSyncSweep()` launches a goroutine with a 1-second ticker:

```
syncSweep():
  if !IsPrimaryFn() → skip
  if !Connected     → skip
  threshold = lastSweepTime
  now = CLOCK_MONOTONIC seconds

  for each v4 session where IsReverse==0 && Created >= threshold:
    QueueSessionV4(key, val) → sendCh

  for each v6 session where IsReverse==0 && Created >= threshold:
    QueueSessionV6(key, val) → sendCh

  lastSweepTime = now
```

Key properties:
- **Forward-only:** Only sends IsReverse==0 entries; the receiver creates both forward and reverse via `SetSessionV4/V6`
- **Monotonic clock:** `Created` timestamps come from `bpf_ktime_get_ns()/1e9`, which matches `CLOCK_MONOTONIC`
- **Non-blocking send:** Messages dropped silently if sendCh is full (4096 buffer)
- **Primary-only:** Skips when not primary for redundancy group 0

### 3. GC Delete Callbacks (expired session cleanup)

Wired in `daemon.go` after GC creation:

```
gc.OnDeleteV4 = func(key SessionKey) {
    if isPrimary && sessionSync != nil {
        sessionSync.QueueDeleteV4(key)
    }
}
```

The conntrack GC (`sweep()` in gc.go) runs every 10 seconds:
1. Iterates all sessions, checks `LastSeen + Timeout < now`
2. Builds `toDelete` slice as pairs: `[fwd, rev, fwd, rev, ...]`
3. After each successful `DeleteSession(key)`, fires callback for forward entries only (`i%2 == 0`)
4. The callback queues a DeleteV4/V6 message to the peer

The peer receives the delete and calls `DeleteSession(key)` to remove the forward entry from its BPF map. The peer's own GC handles cleaning up any orphaned reverse entries.

### 4. Ring Buffer Callback (near-real-time, <1ms)

Registered on the BPF ring buffer event reader in `daemon.go`:

```
er.AddCallback(func(rec EventRecord, raw []byte) {
    if rec.Type != "SESSION_OPEN" → skip
    if !isPrimary || !isConnected → skip

    Parse 5-tuple from raw event bytes:
      v4: SrcIP raw[8:12], DstIP raw[24:28]
      v6: SrcIP raw[8:24], DstIP raw[24:40]
      Ports raw[40:44] (BigEndian), Protocol raw[53], AF raw[55]

    Lookup full session from BPF map via GetSessionV4/V6(key)
    If found and IsReverse==0:
      QueueSessionV4/V6(key, val) → sendCh
})
```

This is **additive** to the periodic sweep — it provides sub-millisecond sync for logged sessions. Sessions that don't generate ring buffer events are caught by the 1s sweep.

## Receiver-Side Processing

`handleMessage()` dispatches by type:

| Type | Action |
|------|--------|
| SessionV4/V6 | Decode → install forward → create reverse → create dnat_table (SNAT) |
| DeleteV4/V6 | Lookup → delete reverse → delete dnat_table (SNAT) → delete forward |
| BulkStart/End | Log markers; a BulkEnd for a bulk that was **actually in progress** (`bulkInProgress` set by a preceding BulkStart) with a matching epoch triggers `reconcileStaleSessions` + `OnBulkSyncReceived` (releases the VRRP sync hold). `reconcileStaleSessions` deletes every eligible peer-owned session absent from the window's key set — including when that set is EMPTY: a completed real transfer with zero sessions is an authoritative "peer holds nothing" snapshot, so all eligible-absent stale sessions are reconciled away (#5085; there is **no** empty-bulk skip). A BulkEnd with `bulkInProgress==false` — no active transfer — is dropped as spurious/replayed (#5272); it does NOT reconcile, ACK, set `bulkEverCompleted`, or release the hold |
| BulkAck | Completes an **outbound** bulk only when it matches a pending outbound epoch (`pendingBulkAckEpoch != 0 && epoch >= pending`): clears the pending epoch, sets `bulkEverCompleted`/`outboundBulkAcked`, fires `OnBulkSyncAckReceived`. A BulkAck with no pending outbound bulk is dropped as spurious/replayed (#5272) — it does NOT set the flags or fire the callback |
| Heartbeat | No-op (resets read deadline) |
| Config | Decode `(text, gen)` → enqueue on the single-consumer ordered apply queue (`configApplyLoop`); `shouldApplyConfigGen` drops out-of-order older gens, then `OnConfigReceived` applies and the high-water advances (`recordAppliedConfigGen`) ONLY on a successful apply — a failure counts `ConfigsApplyFailed` and re-admits the peer's re-push (#3931, M-2/#4151) |
| IPsecSA | `stripFullSetSeq` → `fullSetSeqGuard.admit`; a stale reorder is dropped (`IPsecSAStaleIgnored`), otherwise store names + call `OnIPsecSAReceived` (#5706) |
| DHCPLeaseV4/V6 | `stripFullSetSeq` → per-family `fullSetSeqGuard.admit`; a stale reorder is dropped (`DHCPLeasesStaleIgnored`), otherwise store the lease set + call `OnDHCPLeasesReceived` (#2239/#5706) |

### Bulk completion safety gate (#5272)

`BulkEnd`/`BulkAck` are the two frames that release the stateful-failover
safety gate — completing a bulk sets the sticky completion flags
(`bulkEverCompleted`/`outboundBulkAcked`) and fires the callbacks that let VRRP
release its sync hold, making the node MASTER-eligible. That release is only
safe once a *real* bulk transfer has moved the peer's session table. Both
handlers therefore require an **active, matching transaction** before they
complete:

- **`BulkEnd` requires `bulkInProgress`.** A BulkEnd is only honored when a
  preceding `BulkStart` set `bulkInProgress = true` (then the existing epoch
  check applies). A BulkEnd that arrives with `bulkInProgress == false` — a
  buggy / mixed-version / replaying peer frame, or one that lands after the
  transfer was torn down on disconnect — is dropped (debug log, no ACK, no
  completion flag, no callback). Without this gate a spurious BulkEnd on a node
  that never received a bulk would release the hold with an **empty/stale peer
  session table**, so a failover mid-session blackholes. This gate is what makes
  the #5085 empty-snapshot reconcile safe: only a **real** transfer
  (`bulkInProgress` set by its own `BulkStart`) ever reaches
  `reconcileStaleSessions`, so a spurious empty BulkEnd can never trigger a
  delete-all-eligible pass.
- **`BulkAck` requires a pending outbound bulk.** A BulkAck only completes when
  it matches a pending outbound epoch (`pendingBulkAckEpoch != 0 && epoch >=
  pending`, recorded before the outbound `BulkEnd` write per #3912). A BulkAck
  with no pending outbound bulk is dropped — otherwise it would prematurely set
  `outboundBulkAcked` (releasing the outbound-bulk gate and suppressing the
  #4090/#4360 stranded-bulk re-drive) with no real outbound transfer acked.

The gate is **local state** (`bulkInProgress` / `pendingBulkAckEpoch`), not a
wire field — no protocol version bump — so a legacy peer's *legitimate* bulk
(BulkStart → sessions → BulkEnd, or a real ack of our outbound bulk) still
completes and releases the hold exactly as before.

### Session Reconstruction on Receiver

Forward-only sweep entries are reconstructed into full conntrack state:
1. **Forward entry:** Install as-is via `SetSessionV4/V6(key, val)`
2. **Reverse entry:** If `IsReverse==0 && ReverseKey.Protocol != 0`: copy val, set `IsReverse=1`, set `ReverseKey = original key`, install at `val.ReverseKey`
3. **dnat_table (SNAT only):** If `Flags & SessFlagSNAT && !(Flags & SessFlagStaticNAT)`: create `{Protocol, NATSrcIP, NATSrcPort} → {SrcIP, SrcPort}`

### FIB Cache (Not Synced — By Design)
- `fib_ifindex`, `fib_dmac`, `fib_smac`, `fib_gen` are zeroed in synced sessions
- Interface indices and MACs differ between nodes; zero forces fresh `bpf_fib_lookup`
- **Userspace-dataplane exception (#1873):** when
  `LogFlagUserspaceTunnelEndpoint` is set, `fib_gen` carries the
  session's `tunnel_endpoint_id` across the cluster as a bare LE u16.
  Ids are content-derived (`config.StableTunnelEndpointID` — a frozen
  FNV-1a fold of the unit-qualified tunnel interface name), so both
  nodes compute identical ids from identical config and the value is
  portable by construction. The receiving node resolves it against its
  own snapshot (`sessionSyncTunnelEndpointLocked`); an unknown id
  degrades that synced session to NoRoute until configs converge.

### LogFlags bits (userspace dataplane)
The 1-byte `LogFlags` field (offset 113 V4) carries, in addition to the
userspace-internal `LogFlagUserspaceTunnelEndpoint` (1<<6) /
`LogFlagUserspaceFabricIngress` (1<<7), the **per-policy log selection**
(#2785): `LogFlagSessionInit` (1<<0) / `LogFlagSessionClose` (1<<1). These
mirror the admitting policy's `then log session-init`/`session-close` so a
session that fails over to the standby emits the same RT_FLOW
SESSION_CREATE/CLOSE syslog records on the new active node. They reach the
cluster wire via the helper's open-frame flags byte
(`FLAG_LOG_SESSION_INIT`/`CLOSE`, `event_stream/codec.rs`) and are re-applied
to the peer helper's synced session via `SessionSyncRequest.log_session_init/
close`. An old peer leaves the bits clear -> no per-policy log (pre-#2785
behavior), so the carry is rolling-upgrade safe.

### Known Issues
- **NO_NEIGH after failover (FIXED, `0080cbc`):** Cold ARP cache on takeover previously caused `bpf_fib_lookup` rc=7 and mis-forward behavior. This was fixed in HA sync hardening.
- **Monotonic clock skew (FIXED, `0080cbc`):** Remote timestamps in synced sessions previously caused premature GC expiry; this was fixed in receiver-side handling.

## Statistics (SyncStats)

All counters are `atomic.Uint64` / `atomic.Bool`, lock-free:

| Counter | Meaning |
|---------|---------|
| SessionsSent | Sessions queued to sendCh |
| SessionsReceived | Session messages received from peer |
| SessionsInstalled | Sessions successfully written to BPF map |
| SessionsStaleConfigIgnored | Session installs refused by the #5274 config-epoch guard: the peer stamped a config epoch (#3931 `configGenCounter`) strictly older than this node's `lastAppliedConfigGen`, so a newer config that may deny the session is already applied here (a stale permit across the HA boundary) |
| DeletesSent | Delete messages queued |
| DeletesReceived | Delete messages received |
| BulkSyncs | Completed bulk sync operations |
| ConfigsSent/Received | Config sync messages |
| ConfigsStaleIgnored | Config messages dropped by the #3931 ordering guard (incoming generation not strictly newer than last-applied) |
| ConfigsApplyFailed | Config messages admitted by the ordering guard but whose apply did NOT take effect (compile/promote failure or a transient RG0-primary rejection). The high-water is left unadvanced so the peer's re-push re-converges the standby (M-2/#4151) |
| ConfigsQueueFullDropped | Config payloads that never reached the ordered apply queue because it was full at enqueue (#6778). The non-blocking send discards the INCOMING payload — the NEWEST generation — so the node is left on a superseded config. The received high-water is still raised (the node reads config-stale), a config-apply nack re-arms the sender's #5863 marker, and the #6387 grace timer arms. A nonzero value climbing while `ConfigApplyNacksReceived` on the PEER stays at zero means the recovery path itself is broken |
| ConfigApplyNacksReceived | #7328 config-apply nacks accepted from the peer — one per generation this node pushed that the peer refused, failed to apply, or dropped at its receive edge (#6778). A nack naming a superseded generation is ignored and not counted |
| BulkPrimesWithoutIncarnation | `BulkStart` frames received carrying no boot incarnation (#5084) — a peer on a pre-#5084 build, or a peer whose own `boot_id` was unreadable. The incarnation fence is in its fail-open state against that peer; expected during a rolling upgrade, and NOT a health/alarm state |
| ConfigsDeadIncarnationDropped | Config payloads dropped because the boot incarnation they arrived under has been replaced by a re-prime (#5084) — a queued prior-boot config that would otherwise apply across the reset and strand the generation high-water. Expected once per peer reboot that races a queued config; a persistently rising counter means the peer is flapping |
| IPsecSASent/Received | IPsec SA list messages |
| IPsecSAStaleIgnored | IPsec SA full-sets dropped by the #5706 ordering guard (incoming `(incarnation, seq)` not strictly newer — a reorder across the redundant fabric streams) |
| DHCPLeasesSent/Received | DHCP-server full-set lease push messages (per family) |
| DHCPLeasesStaleIgnored | DHCP lease full-sets dropped by the #5706 ordering guard (per family) — the DHCP analog of `IPsecSAStaleIgnored` |
| Errors | Send failures, channel overflows, bad magic |
| Connected | Peer TCP connection active |

## Timing Summary

| Event | Interval | Latency |
|-------|----------|---------|
| Bulk sync | Once on connect | Seconds (depends on table size) |
| Periodic sweep | 1 second | 0-1s for new sessions |
| Ring buffer callback | Per SESSION_OPEN event | <1ms |
| GC delete propagation | 10 second GC interval | 0-10s |
| Heartbeat | 30s idle timeout | - |
| Connect retry | 5 seconds | - |

## Data Flow Diagram

```
Primary Node                              Secondary Node
─────────────                             ──────────────
BPF creates session
  │
  ├─ Ring buffer event ──→ Callback ─┐
  │                                  │
  ├─ 1s sweep ticker ──→ syncSweep ──┤
  │                                  ├──→ sendCh ──→ TCP ──→ receiveLoop
  │                                  │                         │
  │  GC expires session              │                    handleMessage
  │    │                             │                         │
  │    └── OnDeleteV4/V6 ───────────┘                    SetSessionV4/V6
  │                                                      DeleteSession
  │                                                           │
  │                                                      BPF map updated
```
