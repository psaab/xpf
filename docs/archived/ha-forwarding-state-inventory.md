# HA Forwarding State Inventory

Date: 2026-03-31
Related: #309, PR #301

## Purpose

Enumerate every piece of forwarding-relevant state in the xpf HA
cluster, classify its replication status, and identify gaps that cause
packet loss or require post-failover reconstruction. This drives the
work in #310, #311, and #312.

## Classification Key

| Label | Meaning |
|-------|---------|
| **Replicated** | Actively sent to peer via the sync stream |
| **Derived** | Computed locally from replicated inputs (deterministic) |
| **Fenced** | Ordered at cutover via barrier / demotion-prepare |
| **Local-only** | Not replicated; must be rebuilt on activation |
| **Gap** | Should be replicated or derived but currently is not |

---

## State Inventory

### 1. Forward Session State (eBPF conntrack)

- **What:** Forward (non-reverse) session entries in BPF `sessions` / `sessions_v6` hash maps.
  Each entry contains 5-tuple key, NAT rewrite fields, zone IDs, flags, timestamps, FIB cache.
- **Where:** `bpf/headers/xpf_maps.h:92-106` (BPF maps); `pkg/cluster/sync.go:27-28`
  (syncMsgSessionV4 = 1, syncMsgSessionV6 = 2)
- **How populated on standby:** Continuous incremental sync from primary
  (`syncUserspaceSessionDeltas` at `pkg/daemon/daemon.go:3639`; event-stream variant
  at line 3681). Periodic 1s sweep + ring-buffer deltas. Bulk sync on connect
  (`BulkSync()` in `pkg/cluster/sync.go`).
- **Classification:** **Replicated**
- **Notes:** FIB fields (`FibIfindex`, `FibDmac`, `FibSmac`, `FibGen`) are
  zeroed on install (`pkg/dataplane/userspace/manager.go:3663-3667`) so the
  standby does a fresh `bpf_fib_lookup` on first hit. Timestamps are rebased
  via monotonic clock exchange (`syncMsgClockSync = 12`).
- **Impact if missing:** New primary has no conntrack state; all existing
  TCP flows are treated as new (RST or timeout). Complete session loss.
- **Target:** Replicated (achieved)

### 2. Reverse Companion Sessions

- **What:** Reverse session entries synthesized from forward sessions so
  return traffic matches conntrack.
- **Where:** Created in `pkg/cluster/sync.go:1382-1403` (Go, on receive of
  forward session). In the Rust helper: `prewarm_reverse_synced_sessions_for_owner_rgs()`
  at `userspace-dp/src/afxdp/session_glue.rs:592`.
- **How populated on standby:** Synthesized locally when a forward session
  is received. On RG activation, `RefreshOwnerRGs` re-resolves reverse
  sessions with local FIB/neighbor info (`session_glue.rs:332-427`).
- **Classification:** **Derived** (synthesized from replicated forward sessions)
- **Notes:** Prior to PR #301, reverse sessions were not pre-warmed until
  activation, causing a brief window. Now `prewarm_reverse_synced_sessions_for_owner_rgs`
  runs immediately on RG activation detection.
- **Impact if missing:** Return traffic for existing sessions is dropped
  until the reverse session is re-learned (typically first RTT).
- **Target:** Derived (achieved)

### 3. SNAT dnat_table Pre-routing Entries

- **What:** When a forward session has SNAT, the return traffic needs a
  `dnat_table` entry mapping `(proto, snat_ip, snat_port) -> (original_client_ip, original_port)`
  so `xdp_zone` can rewrite the destination before conntrack lookup.
- **Where:** Created in `pkg/cluster/sync.go:1405-1423` (V4) and
  `sync.go:1495-1510` (V6) on session receive.
- **How populated on standby:** Piggybacks on session sync -- created
  automatically for every synced forward SNAT session.
- **Classification:** **Derived** (from replicated forward sessions with SNAT flag)
- **Impact if missing:** Return traffic to SNAT'd flows hits the wrong
  `dnat_table` lookup, causing policy re-evaluation or drop.
- **Target:** Derived (achieved)

### 4. HA Runtime State (rg_active BPF map)

- **What:** Per-RG boolean flag in BPF `rg_active` array map. Controls
  whether BPF forwards or fabric-redirects packets for a given RG.
- **Where:** `bpf/headers/xpf_maps.h:799-804` (BPF map);
  `pkg/dataplane/userspace/manager.go:2751` (`UpdateRGActive`);
  `pkg/daemon/rg_state.go:31-51` (`rgStateMachine`).
- **How populated on standby:** Set locally by the Go daemon's
  `rgStateMachine` based on cluster state-machine events + VRRP events.
  The Rust helper receives it via `update_ha_state` control request
  (`userspace-dp/src/afxdp.rs:1036`).
- **Classification:** **Local-only** (derived from cluster election + VRRP state)
- **Notes:** `rgStateMachine` combines `clusterPri` (cluster says Primary)
  with `vrrpInstances` (per-interface VRRP master state). Strict VIP
  ownership mode derives solely from VRRP.
- **Impact if missing:** Node forwards traffic for an RG it doesn't own
  (dual-active), or drops traffic for an RG it does own (dual-inactive).
- **Target:** Local-only (correct -- election is inherently local)

### 5. HA Watchdog Timestamps (ha_watchdog BPF map) — RETIRED by #1476
> **RETIRED (#1476/#10791):** This inventory preserves historical behavior.
> No live userspace-XDP shim calls `check_egress_rg_active()`; the Go map
> write remains bookkeeping only. The current daemon-loss backstop is the
> helper's receipt-anchored 10s `update_ha_state` lease. Do not treat the
> stale implementation details below as current behavior.


- **What:** Per-RG monotonic timestamp written every 500ms by the Go daemon.
  BPF and Rust helper check freshness; if >2s stale, treat RG as inactive
  (fail-closed liveness check).
- **Where:** `bpf/headers/xpf_maps.h:852-857`;
  `pkg/dataplane/userspace/manager.go:2822` (`UpdateHAWatchdog`);
  `userspace-dp/src/afxdp/forwarding.rs:1078-1086` (staleness check).
- **How populated on standby:** Written locally by the Go daemon's
  periodic 500ms watchdog tick.
- **Classification:** **Local-only**
- **Impact if missing:** A missing or stale watchdog causes the RG to be
  treated as inactive even if `rg_active=true`, preventing forwarding.
  This is by design (fail-closed).
- **Target:** Local-only (correct)

### 6. Flow Cache Entries (Rust helper, per-worker)

- **What:** Per-worker direct-mapped 4096-entry cache of
  `(5-tuple, ingress_ifindex) -> RewriteDescriptor`. Avoids session
  lookup + policy + FIB resolution on cache hit.
- **Where:** `userspace-dp/src/afxdp/types.rs:37-135` (`FlowCache`, `FlowCacheEntry`);
  per-worker in binding worker thread.
- **How populated on standby:** Built locally from packet processing.
  Invalidated on: RG demotion (`invalidate_owner_rg`), config generation
  change, FIB generation change, `FlushFlowCaches` command.
- **Classification:** **Local-only**
- **Notes:** `RewriteDescriptor` contains `config_generation` and
  `fib_generation` fields; cache lookup rejects stale entries. On RG
  activation, `FlushFlowCaches` + `RefreshOwnerRGs` forces full
  invalidation and re-resolution.
- **Impact if missing:** First few packets after failover go through
  slow path (full pipeline). No functional impact -- just ~microseconds
  of extra latency per first-hit flow.
- **Target:** Local-only (correct -- ephemeral, self-healing)

### 7. Neighbor / ARP / NDP State (kernel + Rust helper)

- **What:** MAC addresses for next-hop resolution. Kernel ARP/NDP table
  plus the Rust helper's `dynamic_neighbors` cache.
- **Where:** Kernel netlink neighbor table; Rust:
  `userspace-dp/src/afxdp/neighbor.rs:321` (`dynamic_neighbors: FastMap<(i32, IpAddr), NeighborEntry>`);
  `ForwardingState.neighbors` at `types.rs:235`.
- **How populated on standby:** Initial dump from kernel via `RTM_GETNEIGH`
  (`neighbor.rs:565`), then live updates via netlink subscribe
  (`neighbor.rs:518`). Static neighbors from config snapshot
  (`ForwardingState.neighbors`). On RG activation, `proactiveNeighborResolveAsyncLocked`
  (`manager.go:2772`) triggers ARP/NDP for all configured next-hops.
- **Classification:** **Local-only** (kernel neighbor table is per-node)
- **Notes:** After failover, the new primary sends GARP/unsolicited NA
  for VIPs, which populates downstream switch CAM tables. Upstream
  neighbors typically have existing ARP entries that are still valid.
  Missing neighbors cause `ForwardingDisposition::MissingNeighbor` ->
  `XDP_PASS` -> kernel resolves ARP -> retransmit enters pipeline.
- **Impact if missing:** First packet to each unique next-hop takes
  kernel slow path for ARP resolution (~5-50ms). For active TCP flows,
  this causes 1 RTT delay on first packet.
- **Target:** Local-only (correct -- kernel ARP is authoritative)
- **Gap note:** Neighbor prewarm (`proactiveNeighborResolveAsyncLocked`)
  only covers configured static next-hops. Dynamic next-hops learned
  via FRR BGP/OSPF are not prewarmed.

### 8. Fabric Link State (BPF fabric_fwd map + Rust FabricLink)

- **What:** Cross-chassis forwarding info: fabric interface ifindex,
  peer MAC, local MAC, FIB ifindex for main-table lookups.
- **Where:** BPF: `bpf/headers/xpf_maps.h:810-822` (`fabric_fwd` array[2]);
  Go daemon: `pkg/daemon/daemon.go:142-156` (fabricMu fields);
  Rust: `userspace-dp/src/afxdp/types.rs:339-345` (`FabricLink`).
- **How populated on standby:** Go daemon writes BPF `fabric_fwd` map
  via `refreshFabricFwd()` using ARP-resolved peer MAC. Rust helper
  receives fabric snapshots via `SyncFabricState()` control request
  (`manager.go:2542`). Refresh triggered by netlink events + 30s ticker.
- **Classification:** **Local-only** (each node resolves its own fabric
  neighbor)
- **Impact if missing:** Fabric cross-chassis redirect fails silently.
  Synced sessions that need to reach the peer for return-path forwarding
  are dropped until fabric state is populated (~1-2s on fresh boot).
- **Target:** Local-only (correct)

### 9. Interface NAT / Local-Address Classification

- **What:** Sets of local IPv4/IPv6 addresses used to classify packets
  as local delivery vs. transit. Also `interface_nat_v4/v6` mapping
  interface IPs to ifindex for interface-mode SNAT.
- **Where:** Rust: `ForwardingState.local_v4`, `.local_v6`,
  `.interface_nat_v4`, `.interface_nat_v6` at `types.rs:225-228`.
- **How populated on standby:** Derived from `ConfigSnapshot.Interfaces`
  in `build_forwarding_state()` (`forwarding.rs:58`). Rebuilt on every
  `Compile()` / snapshot push.
- **Classification:** **Derived** (from config)
- **Impact if missing:** Transit traffic misclassified as local delivery
  (or vice versa). Would only happen if config snapshot is not loaded.
- **Target:** Derived (achieved)

### 10. FIB Generation Counter

- **What:** Global counter in BPF `fib_gen_map[0]` (u32). Bumped on
  recompile, route changes, HA transitions. Sessions cache `fib_gen` in
  their value; BPF/Rust check `session.fib_gen == fib_gen_map[0]` to
  invalidate stale FIB cache entries.
- **Where:** BPF: `bpf/headers/xpf_maps.h:328-333`; Go:
  `pkg/dataplane/maps.go:1969` (`BumpFIBGeneration`);
  Rust: `ValidationState.fib_generation` at `types.rs:211`.
- **How populated on standby:** Written locally by `BumpFIBGeneration()`.
  On HA transition, `UpdateRGActive` bumps it (`manager.go:2778`).
- **Classification:** **Local-only** (monotonic counter, local semantics)
- **Impact if missing:** Sessions continue using stale FIB cache entries
  that may point to wrong egress interfaces after failover.
  `UpdateRGActive` correctly bumps it, so this is handled.
- **Target:** Local-only (correct)

### 11. Config Generation Counter

- **What:** Monotonic counter incremented on each `Compile()`. Used by
  the XDP metadata and Rust helper to reject packets processed with a
  stale config snapshot.
- **Where:** Go: `manager.go:47` (`generation uint64`); Rust:
  `ValidationState.config_generation` at `types.rs:210`;
  `ConfigSnapshot.Generation` at `protocol.go:42`.
- **How populated on standby:** Incremented locally on each `Compile()`.
  Config sync from primary triggers recompile on secondary.
- **Classification:** **Local-only**
- **Impact if missing:** Packets processed with stale config are
  classified as `ConfigGenerationMismatch` and fall back to eBPF
  pipeline (`forwarding.rs:15-17`). Briefly increases latency until
  snapshot catches up.
- **Target:** Local-only (correct)

### 12. BPF userspace_sessions Map

- **What:** Hash map keyed by 5-tuple with value = action byte
  (`REDIRECT=1`, `PASS_TO_KERNEL=2`). The XDP shim program checks this
  map; hits redirect packets to XSK for Rust helper processing.
- **Where:** BPF shim: `userspace-xdp/src/lib.rs:284`;
  Go: `pkg/dataplane/loader_ebpf.go:211`; Rust publish:
  `userspace-dp/src/afxdp/bpf_map.rs:275-347`.
- **How populated on standby:** Written by Rust helper for locally-owned
  sessions and synced sessions. On RG demotion, entries for the demoted
  RG are deleted immediately from this map (`afxdp.rs:1092-1099`).
  On RG activation, `RefreshOwnerRGs` + `prewarm_reverse_synced_sessions`
  re-publishes entries.
- **Classification:** **Derived** (from session table + HA state)
- **Notes:** This is the critical map for the XDP-to-userspace handoff.
  A missing entry causes XDP_PASS (kernel path), not a drop. On RG
  demotion, clearing these entries is time-critical -- there's a race
  window where `rg_active=false` but the shim still redirects to XSK.
- **Impact if missing:** Packets fall through to eBPF pipeline (slower
  but functional). On activation, sessions must be re-published to
  restore userspace fast-path forwarding.
- **Target:** Derived (achieved -- gap is the demotion race window)

### 13. Owner RG Resolution Cache (ForwardingState.egress)

- **What:** Maps egress ifindex to `EgressInterface` struct containing
  `redundancy_group`, `vlan_id`, `src_mac`, `mtu`, zone name, and
  primary addresses.
- **Where:** `userspace-dp/src/afxdp/types.rs:312-326` (`EgressInterface`);
  built in `build_forwarding_state()` at `forwarding.rs:58`.
- **How populated on standby:** Derived from config snapshot on every
  `refresh_runtime_snapshot()` (`afxdp.rs:1022`).
- **Classification:** **Derived** (from config)
- **Impact if missing:** `owner_rg_for_resolution()` returns 0 for all
  flows, bypassing HA checks entirely (all traffic treated as active).
- **Target:** Derived (achieved)

### 14. SNAT Port Allocation State (Rust PortAllocator)

- **What:** Per-SNAT-rule round-robin port allocator tracking current
  position in the port range and pool address rotation.
- **Where:** `userspace-dp/src/nat.rs:61-96` (`PortAllocator`);
  `SourceNatRule.pool_allocator` at `nat.rs:140`.
- **How populated on standby:** Initialized from config snapshot
  (`parse_source_nat_rules` at `nat.rs:210`). State is reset on
  activation -- port counter starts from configured low port.
- **Classification:** **Local-only**
- **Notes:** The allocator is per-rule and purely local. After failover,
  the new primary allocates from the beginning of the range. Duplicate
  SNAT ports are prevented by session lookup (existing sessions already
  have the port allocated). There's a theoretical collision window if
  both nodes allocate the same port before session sync catches up.
- **Impact if missing:** No impact on correctness -- allocator restarts
  from port_low. Possible port collision is mitigated by session-first
  lookup.
- **Gap note:** If both nodes are briefly dual-active, they could
  allocate the same SNAT port for different flows, causing NAT ambiguity
  on the return path. This is an inherent dual-active window issue, not
  a sync gap.
- **Target:** Local-only (acceptable)

### 15. SNAT Port Allocation State (eBPF nat_port_counters)

- **What:** Per-CPU per-pool NAT port counter used by BPF `xdp_nat.c`
  for port allocation in the eBPF pipeline.
- **Where:** `bpf/headers/xpf_maps.h:437-442` (`nat_port_counters`,
  PERCPU_ARRAY).
- **How populated on standby:** Populated locally by BPF on each SNAT
  allocation. Counter wraps within the configured port range.
- **Classification:** **Local-only**
- **Impact if missing:** BPF allocates from port 0 in the range. Same
  theoretical collision window as Rust allocator above.
- **Target:** Local-only (acceptable)

### 16. Session Count Limits (screen per-IP counts)

- **What:** Per-source-IP and per-destination-IP session counts used by
  screen/IDS session limiting. Two variants:
  (a) BPF: `session_count_src`, `session_count_dst` LRU hash maps
  (b) Rust: `SessionLimitTracker` in `ScreenState`
- **Where:** BPF: `bpf/headers/xpf_maps.h:864-878`;
  Rust: `userspace-dp/src/screen.rs:108-135` (`SessionLimitTracker`).
- **How populated on standby:** BPF maps populated by Go GC sweep.
  Rust counters incremented on session create, decremented on expire.
- **Classification:** **Local-only**
- **Notes:** After failover, counts are initially zero on the new primary.
  They rebuild as the GC sweep runs (BPF) or as sessions are counted
  by the Rust helper. This means session limits are briefly unenforced.
- **Impact if missing:** Session-limit screen checks are disabled for a
  brief window (~1-5s until GC sweep or Rust counters are rebuilt).
  Allows potential burst above the configured limit.
- **Gap note:** Could be derived from session table scan on activation,
  but current approach is acceptable for most deployments.
- **Target:** Local-only (acceptable -- self-healing)

### 17. Screen Rate Counters (Rust ScreenState)

- **What:** Per-zone ICMP/UDP/SYN flood rate counters, port-scan trackers,
  IP-sweep trackers. Window-based counters (1s/10s windows).
- **Where:** `userspace-dp/src/screen.rs:242-266` (`ScreenState`);
  includes `RateCounter`, `PortScanTracker`, `IpSweepTracker`.
- **How populated on standby:** Incremented locally from live traffic.
  Reset on each window boundary.
- **Classification:** **Local-only**
- **Impact if missing:** Flood/scan detection starts from zero on the
  new primary. Brief window where attacks are not rate-limited.
- **Target:** Local-only (acceptable -- counters reset every 1-10s anyway)

### 18. Policer Token Bucket State (Rust FilterState)

- **What:** Per-policer token bucket with `tokens` (current bytes),
  `last_refill_ns`, `rate_bytes_per_ns`, `burst_bytes`.
- **Where:** `userspace-dp/src/filter.rs:74-88` (`PolicerState`).
  BPF counterpart: `bpf/headers/xpf_maps.h:836-842` (`policer_states`,
  PERCPU_ARRAY).
- **How populated on standby:** Initialized from config. Token bucket
  starts full. BPF per-CPU state is independent.
- **Classification:** **Local-only**
- **Impact if missing:** After failover, token buckets start full,
  briefly allowing traffic above the policer rate until steady state.
- **Target:** Local-only (acceptable)

### 19. Config Sync (Active Configuration Text)

- **What:** Full Junos configuration text pushed from primary to secondary.
- **Where:** `pkg/cluster/sync.go:35` (`syncMsgConfig = 8`);
  `pkg/daemon/daemon.go:5441` (`handleConfigSync`).
- **How populated on standby:** Pushed on connect (`OnPeerConnected`),
  and on every commit. Secondary's `handleConfigSync` loads the config
  into its configstore and recompiles.
- **Classification:** **Replicated**
- **Impact if missing:** Secondary runs with stale config. After failover,
  policies/NAT/zones may not match the latest committed state.
- **Target:** Replicated (achieved)

### 20. IPsec SA Connection Names

- **What:** List of active IPsec connection names synced to peer for
  post-failover `swanctl --initiate`.
- **Where:** `pkg/cluster/sync.go:37` (`syncMsgIPsecSA = 9`);
  callback `OnIPsecSAReceived`.
- **How populated on standby:** Pushed by primary when IPsec config
  changes. Stored in `peerIPsecSAs` (`sync.go:172`).
- **Classification:** **Replicated**
- **Impact if missing:** After failover, IPsec tunnels are not
  re-established until manual intervention or config recompile.
- **Target:** Replicated (achieved)

### 21. Cluster Peer Clock Offset

- **What:** `localMono - peerMono` offset for timestamp rebasing.
  Applied to synced session `Created`/`LastSeen` timestamps.
- **Where:** `pkg/cluster/sync.go:186-187` (`peerClockOffset`,
  `clockSynced`); message type `syncMsgClockSync = 12`.
- **How populated on standby:** Exchanged on every new connection
  (`sendClockSync` at `sync.go:491`).
- **Classification:** **Replicated**
- **Impact if missing:** Session timestamps are in the peer's clock
  domain, causing premature or delayed expiry.
- **Target:** Replicated (achieved)

### 22. Shared Sessions Table (Rust helper, coordinator-level)

- **What:** Thread-safe map of all sessions known to the Rust helper:
  locally-created + synced-from-peer. Three parallel indexes:
  `shared_sessions`, `shared_nat_sessions`, `shared_forward_wire_sessions`.
- **Where:** `userspace-dp/src/afxdp.rs:1908-1915` (`SyncedSessionEntry`);
  referenced throughout `session_glue.rs`.
- **How populated on standby:** Synced sessions arrive via
  `WorkerCommand::UpsertSynced` (`session_glue.rs:442-493`); locally-created
  sessions via `WorkerCommand::UpsertLocal` (`session_glue.rs:494-517`).
- **Classification:** **Derived** (union of replicated sessions + locally-created)
- **Notes:** On RG demotion, `DemoteOwnerRG` marks sessions as synced
  and removes from `userspace_sessions` BPF map. On RG activation,
  `RefreshOwnerRGs` re-resolves all sessions for the activated RGs.
- **Impact if missing:** The new primary has no session awareness in the
  Rust helper. All traffic falls back to the eBPF pipeline or creates
  new sessions.
- **Target:** Derived (achieved)

### 23. Demotion Prepare Barriers

- **What:** Two-phase ordered cutover for planned failover:
  (a) `ExportOwnerRGSessions` -- primary exports all sessions for RGs
      being demoted to the sync stream.
  (b) `PrepareDemoteOwnerRGs` -- invalidates flow caches, refreshes
      reverse sessions, collects cancelled session keys.
  (c) `syncMsgBarrier` / `syncMsgBarrierAck` (types 13/14) -- ensures
      peer has installed all queued sessions before demotion completes.
- **Where:** `pkg/daemon/daemon.go:4054` (`prepareUserspaceRGDemotionWithTimeout`);
  `userspace-dp/src/afxdp/session_glue.rs:274-295` (`PrepareDemoteOwnerRGs`);
  `pkg/cluster/sync.go:220-223` (barrier tracking).
- **How populated on standby:** Triggered locally on the demoting node.
  Barrier ack confirms peer installation.
- **Classification:** **Fenced**
- **Notes:** Barrier timeout is configurable (5-30s depending on caller).
  `WaitForPeerBarriersDrained` ensures no stale barriers block new demotions.
- **Impact if missing:** Without barriers, the peer may not have all
  sessions installed when it takes over, causing a brief session loss
  window for flows in transit during the handoff.
- **Target:** Fenced (achieved)

### 24. Delete Journal (Disconnect Buffer)

- **What:** Bounded ring buffer (10000 entries) of encoded delete messages
  accumulated during sync disconnection. Flushed on reconnect.
- **Where:** `pkg/cluster/sync.go:193-197` (`deleteJournal`,
  `deleteJournalCap`).
- **How populated:** Deletes are journaled when `queueMessage` fails
  (peer disconnected). On reconnect, journal is flushed before normal sync.
- **Classification:** **Replicated** (eventually)
- **Notes:** If journal overflows, `DeletesDropped` counter increments
  and `syncBackfillNeeded` is set for a full sweep on reconnect.
- **Impact if missing:** Stale sessions persist on the peer after
  disconnect. Reconciled by bulk sync on reconnect.
- **Target:** Replicated (achieved)

### 25. Bulk Sync Stale Reconciliation

- **What:** During bulk receive (BulkStart..BulkEnd), all received forward
  session keys are tracked. On BulkEnd, sessions in peer-owned zones that
  were NOT refreshed are deleted as stale.
- **Where:** `pkg/cluster/sync.go:209-218` (`bulkRecvV4`, `bulkRecvV6`,
  `bulkZoneSnapshot`).
- **Classification:** **Derived** (reconciliation pass from replicated data)
- **Target:** Derived (achieved)

### 26. Routing / FIB State (Kernel + FRR)

- **What:** Kernel routing tables (main + per-VRF), managed by FRR.
  Includes static routes, OSPF/BGP/IS-IS learned routes.
- **Where:** Kernel FIB (netlink); FRR configuration in `/etc/frr/frr.conf`.
  BPF uses `bpf_fib_lookup()` which reads kernel FIB directly.
  Rust helper: `ForwardingState.routes_v4/v6` at `types.rs:231-232`.
- **How populated on standby:** FRR runs independently on each node.
  Config sync from primary includes routing config, which triggers
  FRR reload on the secondary. FRR protocols (OSPF/BGP) converge
  independently.
- **Classification:** **Derived** (from config sync + FRR convergence)
- **Notes:** After failover, FRR convergence may take 1-5s for dynamic
  protocols. Static routes are applied immediately on config commit.
  `bpf_fib_lookup` returns `NO_NEIGH` (rc=7) for routes with
  no ARP entry, triggering kernel slow path.
- **Impact if missing:** Packets to unknown routes are dropped or
  fabric-redirected. Dynamic protocol convergence is the dominant delay.
- **Target:** Derived (correct -- each FRR instance is authoritative)

### 27. VRRP Instance State

- **What:** Per-RETH VRRP state machine (MASTER/BACKUP/INIT).
  Controls VIP ownership and GARP/NA announcements.
- **Where:** `pkg/vrrp/` (Go VRRP state machine);
  30ms advertisement interval, AF_PACKET sockets.
- **How populated:** Local VRRP state machine. On activation, becomes
  MASTER; sends GARP burst (async) and unsolicited NA.
  On deactivation, sends priority-0 adverts.
- **Classification:** **Local-only** (VRRP is inherently local election)
- **Impact if missing:** VIP not claimed; traffic to VIP addresses is
  black-holed until VRRP election completes (~97ms masterDown interval).
- **Target:** Local-only (correct)

### 28. Blackhole Routes for Inactive RG Subnets

- **What:** When an RG goes BACKUP, blackhole routes are injected for
  its RETH subnets. This forces `bpf_fib_lookup` to return BLACKHOLE,
  triggering fabric redirect to the peer instead of escaping via WAN.
- **Where:** `pkg/daemon/daemon.go:129-135` (`blackholeRoutes`).
- **How populated:** Written locally on RG state change.
  Removed when RG becomes active again.
- **Classification:** **Local-only** (derived from RG state)
- **Target:** Local-only (correct)

### 29. Pending Neighbor Packets (Rust helper)

- **What:** Packets buffered while waiting for ARP/NDP resolution.
  `PendingNeighPacket` with `XdpDesc`, metadata, and timeout.
- **Where:** `userspace-dp/src/afxdp/types.rs:138-144`.
- **How populated:** Queued locally when `ForwardingDisposition::MissingNeighbor`
  is returned. Drained when neighbor resolution completes.
- **Classification:** **Local-only** (ephemeral, sub-second lifetime)
- **Impact if lost:** At most a few packets are dropped during failover.
  The original sender will retransmit.
- **Target:** Local-only (acceptable)

### 30. SlowPath Reinjector State

- **What:** TUN device for reinserting packets that need kernel processing
  (ARP resolution, local delivery of control-plane traffic).
- **Where:** `userspace-dp/src/slowpath.rs:166` (`SlowPathReinjector`).
- **How populated:** Created locally when helper starts. Dedicated thread.
- **Classification:** **Local-only**
- **Target:** Local-only (correct)

---

## Summary Table

| # | State Item | Classification | Gap? | Impact |
|---|-----------|---------------|------|--------|
| 1 | Forward sessions (eBPF conntrack) | Replicated | No | Complete session loss if missing |
| 2 | Reverse companion sessions | Derived | No | 1-RTT delay per flow |
| 3 | SNAT dnat_table entries | Derived | No | Return NAT failure |
| 4 | rg_active BPF map | Local-only | No | Dual-active/inactive |
| 5 | ha_watchdog timestamps | Local-only | No | Fail-closed (by design) |
| 6 | Flow cache entries | Local-only | No | Microseconds extra latency |
| 7 | Neighbor/ARP/NDP state | Local-only | Minor | 1 RTT per unique next-hop |
| 8 | Fabric link state | Local-only | No | 1-2s fabric blackout on boot |
| 9 | Interface NAT/local classification | Derived | No | Misclassification |
| 10 | FIB generation counter | Local-only | No | Stale FIB (handled) |
| 11 | Config generation counter | Local-only | No | Temporary slow-path |
| 12 | userspace_sessions BPF map | Derived | Minor | XDP_PASS fallback (slower) |
| 13 | Owner RG resolution cache | Derived | No | Bypassed HA checks |
| 14 | SNAT port allocator (Rust) | Local-only | Minor | Theoretical port collision |
| 15 | SNAT port counter (eBPF) | Local-only | Minor | Theoretical port collision |
| 16 | Session count limits (screen) | Local-only | Minor | Brief unenforced window |
| 17 | Screen rate counters | Local-only | No | Brief unprotected window |
| 18 | Policer token buckets | Local-only | No | Brief over-admission |
| 19 | Config text | Replicated | No | Stale config |
| 20 | IPsec SA names | Replicated | No | Tunnel re-establishment |
| 21 | Peer clock offset | Replicated | No | Timestamp skew |
| 22 | Shared sessions (Rust) | Derived | No | No userspace session awareness |
| 23 | Demotion prepare barriers | Fenced | No | Session loss during handoff |
| 24 | Delete journal | Replicated | No | Stale sessions after disconnect |
| 25 | Bulk sync reconciliation | Derived | No | Stale session cleanup |
| 26 | Routing/FIB (FRR) | Derived | No | 1-5s protocol convergence |
| 27 | VRRP instance state | Local-only | No | ~97ms election delay |
| 28 | Blackhole routes | Local-only | No | Fabric redirect failure |
| 29 | Pending neighbor packets | Local-only | No | Few packets dropped |
| 30 | SlowPath reinjector | Local-only | No | None (recreated on start) |

---

## Identified Gaps (Ordered by Severity)

### Gap 1: SNAT Port Collision During Dual-Active Window (Minor)

Both nodes may allocate the same SNAT port during the brief dual-active
overlap (~60ms). The collision probability is low (depends on
connection rate and port range size) but nonzero.

**Mitigation:** Each node could use a disjoint port range (odd/even
split) derived from node-id. This is a configuration-level fix.

### Gap 2: Session Count Limits Unenforced After Failover (Minor)

Screen session-limit counters (`session_count_src/dst` in BPF,
`SessionLimitTracker` in Rust) start at zero on the new primary.
An attacker could exploit the ~1-5s rebuild window to exceed limits.

**Mitigation:** Scan the session table on RG activation and pre-populate
counters. Low priority given the short window.

### Gap 3: Dynamic Neighbor Prewarm Incomplete (Minor)

`proactiveNeighborResolveAsyncLocked` only resolves configured static
next-hops. Neighbors learned via FRR dynamic routing (BGP, OSPF) are
not prewarmed.

**Mitigation:** Dump kernel neighbor table after FRR convergence and
ping missing entries. The current behavior (XDP_PASS -> kernel resolves)
is functionally correct but adds ~1 RTT.

### Gap 4: userspace_sessions BPF Map Demotion Race (Minor)

Between `rg_active=false` (BPF) and `delete_live_session_key` (Rust),
there's a brief window where the XDP shim still redirects to XSK for
demoted RG sessions. The Rust helper handles this by checking HA state,
but the double-check adds latency.

**Mitigation:** Addressed in current code by immediate BPF map deletion
in `update_ha_state` (`afxdp.rs:1092-1099`) before sending
`DemoteOwnerRG` commands to workers. Remaining window is microseconds.

---

## Recommendations for Future Work

1. **#310 - Deterministic reverse companions:** Already implemented via
   `prewarm_reverse_synced_sessions_for_owner_rgs`. Verify that all
   edge cases (NAT64, NPTv6, GRE tunnel sessions) are covered.

2. **#311 - Install fence for planned failover:** Barrier mechanism is
   in place (`syncMsgBarrier`/`syncMsgBarrierAck`). Tighten the
   demotion prep to include a final session export flush before the
   barrier is sent.

3. **#312 - Session count prewarm on activation:** Scan session table
   on RG activation, populate `session_count_src/dst` counters.
   Low-priority quality improvement.

4. **SNAT port range partitioning:** Add optional `node-id`-based port
   range splitting to eliminate dual-active port collision risk.
