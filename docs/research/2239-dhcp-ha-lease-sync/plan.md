# Plan of action — #2239: HA DHCP-server lease synchronization

Research branch: `research/2239-dhcp-ha-lease-sync`
Base: `origin/master` @ 828cceacb
Companion (orthogonal, do NOT re-plan here): #2243 (static/reserved bindings —
config-derived, already HA-consistent by construction via config sync).

---

## 1. Status

PLAN-READY. Recommended path: **PATH C** — xpf-managed lease replication over
the existing `pkg/cluster` session-sync channel, reading/writing Kea leases via
the `lease_cmds` hook over a Kea control socket. PATH C is the only path that
cleanly resolves the BACKUP-stops-Kea tension without inverting xpf's
single-owner RG model; PATHs A and B both require Kea to keep running on the
BACKUP node, which directly contradicts the authoritative-stop the daemon
performs today (`clearRethServicesForRG` → `ApplyAsync(nil)`).

The BACKUP-stops-Kea answer (the crux): **do not require the BACKUP's Kea to be
running.** Persist the peer's leases in xpf process state (the
`SessionSync.peer*` precedent already used for IPsec SA names), and on MASTER
takeover **seed** the just-started Kea's lease DB from that held state via
`lease_cmds` (`lease4-add`/`lease6-add` bulk, or a memfile pre-seed before Kea
start) — exactly as `reinitiateIPsecSAs()` re-initiates peer-synced IPsec
connections on takeover. The standby holds lease *state*, not a running Kea.

Convergence note (Claude-SMR r1, MINOR-1): the acceptance criterion "the
promoted node will not hand the in-use address to a different client" is **fully**
met only once the last-tick window is closed. v1's periodic full-set push BOUNDS
that window to ≤ one push interval but does not eliminate it: a lease granted in
the final tick before an ABRUPT (non-priority-0) failover may not have reached
the standby. Full criterion satisfaction therefore depends on EITHER the
incremental on-grant push (§10 Q1) OR seeding the promoting node's lease DB
BEFORE Kea answers (§10 Q3, option (a) pre-seed-memfile-before-start). The
/engineer phase MUST resolve Q1 and Q3 early so the duplicate-allocation window
is closed in the shipped design rather than deferred. This is a scoping
precision on the v1 boundary; it does not change the chosen architecture (C).

---

## 2. Framing

Today both Kea families write a node-local memfile CSV
(`/var/lib/kea/kea-leases{4,6}.csv`, `dhcpserver.go:668-671 / 748-751`) that is
never replicated. On VRRP MASTER the daemon starts Kea for that RG's filtered
config; on BACKUP it issues an authoritative stop. The promoted node therefore
boots Kea against an empty/stale memfile and can re-allocate an in-use address
(duplicate allocation) while clients are forced to re-DISCOVER.

xpf already synchronizes flow sessions and IPsec SA names across the pair over a
single TCP sync channel on the cluster control/fabric network (em0 / 10.99.x),
with a monotonic-clock-offset handshake, a generation-guarded message protocol,
and a node-level MASTER gate. DHCP-server leases are the one remaining piece of
serving state that does not ride that channel.

The deep-research report (ISC Kea ARM) gives the *native* mechanism — the HA
hook `libdhcp_ha.so` + mandatory `libdhcp_lease_cmds.so`, hot-standby mode,
synchronous RESTful peer replication, full-DB resync on recovery, <60s
clock-skew hard hazard. The native mechanism is correct for a vanilla Kea HA
pair but assumes **both** Kea instances run continuously. xpf's HA model does
not run Kea on the standby. The job of this plan is to pick the design that
delivers the report's failover guarantee (client keeps lease, no duplicate
allocation) **within** xpf's single-owner RG model, not to bolt a second
always-on service model onto the appliance.

---

## 3. Scope / value

In scope:
- Dynamic DHCPv4 and DHCPv6 lease state surviving RG MASTER/BACKUP transitions
  in both directions and across daemon restart.
- A Kea control socket (`unix` type) added to the generated Kea config so
  leases can be read/written via `lease_cmds` without scraping/writing the
  memfile under a running Kea.
- Lease replication ownership that follows the existing RG/VRRP model
  (only the RG-MASTER node mutates that RG's bindings).
- Observability (counters/status/logs) and fail-open serving (sync failure
  never blocks lease granting on the active node).
- Standalone (non-cluster) behavior unchanged.

Out of scope (see §10): static reservations (#2243, config-sync'd), DHCP relay,
DHCP client, DDNS (#1387 — already MASTER-gated and orthogonal), shared external
lease DB as the default, a Kea control agent (`kea-ctrl-agent`) HTTP REST stack.

Value: closes the last unsynchronized serving-state gap for SRX chassis-cluster
DHCP-local-server parity. A failover no longer drops or duplicates client
bindings.

---

## 4. What exists (code-grounded integration surface)

**Kea config generation** — `pkg/dhcpserver/dhcpserver.go`:
- `generateKea4Config` (601-678) / `generateKea6Config` (680-758) emit
  `interfaces-config`, `lease-database` (memfile), `valid-lifetime`,
  `subnet{4,6}`. **No `hooks-libraries`, no `control-socket`** today (grep of
  `pkg/dhcpserver/` for `control-socket|libdhcp|hook` returns nothing in the
  generator). Adding either is a localized change to these two functions.
- `Manager.apply` (199-244) is generation-ordered, fail-closed, and restarts
  the unit for configured families. `ApplyAsync` (262-268) is the latest-wins
  mailbox the VRRP path uses. `ApplyClusterCommit` (186-188) generates config
  on commit without restarting an inactive unit.

**Existing lease read layer** — `pkg/dhcpserver/ddns_leases.go`:
- `parseActiveLeases4/6` (95-103) is a STATE-AWARE memfile parser that already
  extracts per-lease address, **stable identity** (v4 `client-id||hwaddr`, v6
  `DUID/IAID`), subnet, hostname, and expiry, with hard-error-on-mangled-header
  posture (destructive-safe). This is ~80% of the read side PATH C needs; it is
  reusable as a memfile fallback if `lease_cmds` is unavailable.
- `parseLeaseCSV` (403-540) is the lenient display parser (`show dhcp server
  leases`).

**HA service lifecycle** — `pkg/daemon/daemon_ha.go`:
- `applyRethServicesForRG` (911-977): on MASTER, enqueues
  `dhcpServer.ApplyAsync(filterDHCPConfigForMasterRGs(cfg), ...)` (958-967).
- `clearRethServicesForRG` (983-1031): on BACKUP, enqueues
  `dhcpServer.ApplyAsync(nil, ...)` (1027) — **the authoritative stop. THIS is
  the BACKUP-stops-Kea behavior.** If other RGs remain MASTER it re-applies the
  filtered config for the remaining masters instead (1022-1024).
- `filterDHCPConfigForMasterRGs` (1036-1089): renders Kea config containing only
  groups whose RETH interface is MASTER on this node. **Consequence: each node's
  memfile holds ONLY its own MASTER-RG leases — the two nodes' input sets are
  disjoint by RG ownership.** (Same property the DDNS gate relies on.)
- `resolveDHCPRethInterfaces` (1283-1297): RETH → physical Linux name for Kea.

**DDNS gate precedent** — `pkg/daemon/daemon_ddns.go`:
- `ddnsWriterGateOpen` (136-160): open IFF this node is MASTER for ≥1 RG
  (standalone always open). Reads `snapshotRethMasterState` only. This is the
  exact single-writer model lease replication must adopt.
- `runDDNSReconcileLoop` / `nudgeDDNSReconcile`: 30s poll + immediate nudge on
  commit and MASTER takeover; guarded skip-if-in-flight; file/DNS I/O only,
  never touches the helper control socket (CLAUDE.md control-socket rule). This
  is the loop shape PATH C's lease push/pull loop should mirror.

**Cluster sync channel** — `pkg/cluster/`:
- Message protocol (`sync.go:38-61`): `syncMsg*` constants 1-24; **next free
  type = 25.** `syncSchemaVersion` must be bumped when the set grows
  (`sync.go:24-31`). Framing: `syncMagic` `BPSY` + 1-byte type + 4-byte length
  (`syncHeaderSize=12`).
- IPsec SA sync is the EXACT analog (newline-joined names):
  - encode/decode: `sync_protocol.go:511-538` (`encodeIPsecSAPayload` /
    `decodeIPsecSAPayload`).
  - send: `SessionSync.QueueIPsecSA` (`sync.go:760-776`) → `writeMsg(conn,
    syncMsgIPsecSA, payload)`.
  - receive: `sync_conn.go:1280-1289` stores into `s.peerIPsecSAs` and fires
    `OnIPsecSAReceived`.
  - hold state: `peerIPsecSAs` + `PeerIPsecSAs()` (`sync.go:240-241, 752-758`).
  - periodic push from MASTER: `daemon_ha.go:syncIPsecSAPeriodic` (1237-1262),
    30s ticker, gated on `IsLocalPrimary(0)` + `cc.IPsecSASync`.
  - takeover re-apply: `reinitiateIPsecSAs` (1266-1281), wired from
    `daemon_ha.go:335-336` on becoming primary.
  - launch: `daemon_ha_sync.go:793-794` (`go d.syncIPsecSAPeriodic(commsCtx)`).
- Clock handshake: `sync_conn.go` `sendClockSync` (947-955) / receive
  (1368-1378) exchange CLOCK_MONOTONIC and store an OFFSET. **This is NOT a
  wall-clock sync** — it cannot satisfy Kea HA's <60s wall-clock requirement
  (relevant only to PATH A; see §7).
- Config field bag: `config.ClusterConfig` (`types_chassis.go:91-117`) carries
  `IPsecSASync`, `NATStateSync`, `ConfigSync`, control/fabric addresses. A new
  `DHCPLeaseSync bool` slots in beside these (compiler in `compiler_system.go`
  near line 976 where `IPsecSASync = true` is set).

**Kea hook availability** (live-verified on `loss:xpf-userspace-fw0`):
- `kea-common` 3.0.3 ships BOTH `/usr/lib/x86_64-linux-gnu/kea/hooks/
  libdhcp_ha.so` AND `libdhcp_lease_cmds.so`. **No new apt package needed** for
  either PATH A or the `lease_cmds` control-socket read/write PATH C uses.
- `chrony` is installed and active on the cluster (xpf manages it via
  `system ntp` → `daemon_system.go:applySystemNTP`). NTP discipline exists but
  there is no guaranteed *mutual* time source between the two nodes by default.

---

## 5. Concrete design per path

### PATH A — Kea HA hook hot-standby (`libdhcp_ha.so` + `lease_cmds`)

Mechanism: emit, in both generated Kea configs, a `control-socket` (unix) plus
`hooks-libraries: [libdhcp_lease_cmds.so, libdhcp_ha.so{ high-availability:
[{ this-server-name, mode: hot-standby, peers:[primary, standby] }] }]`. Wire
the two peers' control endpoints over the cluster control net. Each node keeps
its own `persist=true` memfile. The primary answers all queries and replicates
each lease to the standby synchronously (parking the response until ack); a
recovering node resyncs the full lease DB from the partner on startup.

Required for HA replication to work: **the standby's Kea must be RUNNING** to
receive lease updates over its control channel. Kea HA peers talk HTTP REST; in
a no-`kea-ctrl-agent` deployment the DHCP servers open their own HTTP listeners
for the HA hook (Kea 2.4+ embeds the HA HTTP listener in `kea-dhcpN` when a
`http` control socket / multi-threading is configured) — so this also pulls in
an HTTP control socket per family, bound to the control-net address.

Pros:
- Native, battle-tested ISC mechanism; synchronous replication + auto full
  resync; the report's exact recommended design.
- xpf-side logic is thin: generate config, manage two services.

Cons / blockers:
- **Directly contradicts xpf's BACKUP-stops-Kea model.** Today
  `clearRethServicesForRG` STOPS Kea on the BACKUP. For PATH A the standby must
  keep Kea UP. Resolving this means INVERTING a core HA behavior: the standby
  would run a second always-on DHCP server (just not answering). That is a large
  behavioral change with its own risks (a standby Kea bound to RETH member
  interfaces that are DOWN/owned-by-MASTER; dual-DHCP if the HA hook's
  answer-suppression fails; interface-binding races on RETH failover).
- **Adds an HTTP listener + REST surface** on the appliance (the HA hook's
  inter-server transport), on the control net. New attack/operational surface;
  needs auth/TLS consideration. Contravenes the appliance's "no extra network
  services" posture.
- **<60s wall-clock skew is a hard split-brain hazard** for the HA hook, and
  xpf's cluster channel only syncs MONOTONIC offset, not wall clock. PATH A
  would need a NEW guarantee that both nodes hold NTP-tight WALL clocks (mutual
  chrony peering or a shared upstream), which xpf does not enforce today.
- VRRP role and Kea-HA role become two independent state machines that must be
  kept consistent (xpf decides MASTER via VRRP; Kea HA decides primary via its
  own heartbeat). Two arbiters of "who serves" is a split-brain generator.
- RETH-interface binding: Kea on the standby would try to bind subnet
  interfaces that are administratively the MASTER's. Kea v6 REQUIRES an
  interface selector and the standby's RETH members are not the active VIP
  holder.

Verdict: architecturally misaligned. Would require inverting BACKUP-stops-Kea
AND adding an HTTP service AND a new wall-clock guarantee. High risk, high
surface. **Reject** (see SMR).

### PATH B — Shared / replicated external lease DB

Mechanism: point both Kea instances at a shared MySQL/PostgreSQL lease DB (or a
DB pair with native replication), with the HA hook in `send-lease-updates=false`
/ `sync-leases=false` mode (DB replicates; hook only arbitrates) OR no HA hook
at all if only one Kea runs at a time against the shared DB.

Pros:
- Lease state is centralized; a freshly promoted Kea reads current leases
  directly. If only the MASTER's Kea runs, BACKUP-stops-Kea is preserved (the
  DB holds state while the BACKUP Kea is down).
- No xpf-side reconciler.

Cons / blockers:
- **Adds a database dependency to a self-contained firewall appliance.** A
  MySQL/PG server (and its replication) is a new always-on service, new failure
  domain, new attack surface, new package set, new backup/restore story. This is
  the least aligned with xpf's local-memfile + node-autonomy design (the issue
  itself flags it "least aligned... note for completeness").
- A SINGLE shared DB is itself a single point of failure (defeats HA) unless it
  is ALSO replicated — which re-introduces a DB-replication HA problem to solve.
- Where does the DB live? On one node = SPOF; on both with replication = a
  second HA cluster to operate; external = breaks the two-box appliance model.
- DB on the BACKUP node reachable from the MASTER's Kea requires the control net
  to carry DB traffic and the DB to be up even when that node is "down" for DHCP
  — muddies the failure model.

Verdict: introduces an unwanted heavy dependency and a new SPOF/HA sub-problem.
**Reject for the default appliance.** (Could be a future opt-in for operators
who already run an external Kea DB, but not the answer to #2239.)

### PATH C — xpf-managed lease replication over the existing sync channel (RECOMMENDED)

Mechanism: reuse the `pkg/cluster` sync channel and the IPsec-SA periodic-push /
hold-on-peer / re-apply-on-takeover pattern, but for DHCP leases. The standby's
Kea stays STOPPED (BACKUP-stops-Kea preserved); xpf holds the peer's lease state
in process memory and seeds Kea on takeover.

Components:

1. **Kea control socket + `lease_cmds` hook** (config generation,
   `dhcpserver.go`): add to BOTH generated configs a `control-socket`
   (`{ "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl.sock" }`) and
   `hooks-libraries: [{ "library": ".../libdhcp_lease_cmds.so" }]`. This is the
   ONLY Kea-config change. It enables reading the live lease set
   (`lease4-get-all` / `lease6-get-all`) and writing leases (`lease4-add` /
   `lease6-add` / `lease4-update`) without racing the memfile under a running
   Kea. (Reading the memfile via `parseActiveLeases4/6` remains a fallback when
   the socket is not yet up.) `persist=true` stays on the memfile so a single-
   node restart keeps leases locally too.

2. **Lease read API** (`pkg/dhcpserver`): add `GetActiveLeases4/6() []Lease`
   that prefers the `lease_cmds` control socket (`lease{4,6}-get-all` over the
   unix socket, JSON response) and falls back to `parseActiveLeases4/6` on the
   memfile. Add `SeedLeases4/6(leases)` that issues `lease{4,6}-add`
   (idempotent; `lease{4,6}-update` on "already exists") over the socket, used
   on takeover. Both are SOCKET-LOCAL I/O — they NEVER touch the userspace-
   helper control socket (CLAUDE.md rule), only Kea's own unix socket.

3. **Sync message type** (`pkg/cluster/sync_protocol.go` + `sync.go`): add
   `syncMsgDHCPLeaseV4 = 25` and `syncMsgDHCPLeaseV6 = 26` (and bump
   `syncSchemaVersion`). Encode a compact per-lease record: family, address,
   identity (client-id/hwaddr or DUID/IAID bytes), subnet-id, valid-lifetime,
   absolute expiry **expressed as a remaining-lifetime delta** (NOT a wall-clock
   epoch — see §6 invariant) , hostname, state. Mirror the
   length-gated-trailing-field discipline already used for sessions (#2170) so
   the schema can grow. A bulk push is a sequence of these framed messages
   (optionally bracketed like `syncMsgBulkStart/End`).

4. **Periodic push from MASTER** (`pkg/daemon/daemon_ha.go`): a
   `syncDHCPLeasesPeriodic(ctx)` loop modeled on `syncIPsecSAPeriodic` — ticker
   (start at 30s; tune to lease churn), gated on `IsLocalPrimary(rg)` per RG (or
   the node-level `ddnsWriterGateOpen` equivalent) + a new `cc.DHCPLeaseSync`.
   Each tick reads this node's active leases (its MASTER-RG-filtered set, since
   the memfile already holds only those) and `QueueDHCPLeases(...)` over the
   channel. Optionally also push incrementally on lease grant (future; the
   periodic full-set push is the v1, matching IPsec SA's full-list-every-tick
   simplicity). Frequency MUST respect the control-socket-contention rule:
   Kea's own socket is separate, but keep the cadence ≥ per-second budget and
   coalesce.

5. **Hold peer state** (`pkg/cluster/sync.go`): add `peerDHCPLeases4/6` slices +
   `PeerDHCPLeases4/6()` accessors + `OnDHCPLeasesReceived` callback, exactly
   like `peerIPsecSAs` / `PeerIPsecSAs` / `OnIPsecSAReceived`. The receive case
   in `sync_conn.go` decodes and stores. This is what the STANDBY holds while
   its Kea is stopped.

6. **Seed on takeover** (`pkg/daemon/daemon_ha.go`): in the
   become-primary path (where `reinitiateIPsecSAs` is fired,
   `daemon_ha.go:335-336`, and in `applyRethServicesForRG`), AFTER the Kea
   `ApplyAsync` start, run `seedDHCPLeasesFromPeer()` — wait for the just-
   started Kea's control socket to be ready, then `SeedLeases4/6` the held peer
   leases (with remaining-lifetime → fresh absolute expiry computed at seed
   time on the LOCAL clock). This makes the promoted Kea authoritative over the
   leases the old MASTER handed out: the client keeps its address+lifetime and
   the promoted node will not re-hand the in-use address. (`lease{4,6}-add`
   collisions degrade to `lease-update`; an address already locally leased wins
   the newer of the two.)

7. **Observability**: `xpf_dhcp_lease_sync_{sent,received,seeded,errors}`
   counters in `SyncStats` (mirror `IPsecSASent/Received` in `sync.go:88-89`,
   surfaced through `SyncStatsSnapshot` + `status.go` + the checked API
   collector). `show chassis cluster` / `show dhcp server leases` annotate
   sync state. Fail-open: a sync or seed error is logged + counted, NEVER blocks
   lease granting on the active node and NEVER fails a commit (DHCP fail-policy
   posture, matching DDNS R9).

Pros:
- **Resolves BACKUP-stops-Kea with ZERO change to the stop behavior**: the
  standby's Kea stays down; xpf holds the lease state and seeds on takeover.
  Single owner of "who serves" remains VRRP/RG — no second arbiter, no
  split-brain generator.
- One sync transport, one ownership model (the disjoint-by-RG memfile property
  already proven sound by the DDNS gate). Reuses a battle-tested pattern
  (IPsec SA sync) almost verbatim.
- No new always-on service, no HTTP listener, no DB, no new apt package
  (`lease_cmds` ships in already-installed `kea-common`).
- Remaining-lifetime-delta encoding sidesteps the <60s wall-clock skew hazard
  entirely (see §6): leases are re-anchored to the promoting node's local clock
  at seed time, so peer clock drift cannot mis-age a synced lease.
- Standalone mode untouched (the loop is gated on `cluster != nil` +
  `DHCPLeaseSync`).

Cons:
- xpf owns a reconciler (the periodic push + seed), as the issue's mechanism (2)
  notes. More xpf code than PATH A's "just generate config".
- v1 periodic full-set push has up-to-one-tick staleness: a lease granted in the
  last tick before an abrupt failover may not have reached the standby. This is
  the same bounded-staleness the IPsec SA sync and session-sync-sweep accept;
  the duplicate-allocation risk is mitigated because the promoted Kea ALSO
  honors any lease already in its own persisted memfile, and a brand-new
  unsynced lease is the same as a never-existed lease (client re-DISCOVERs and
  the promoted node, lacking that binding, can safely allocate). Acceptable;
  an incremental on-grant push is a documented future tightening.
- Reading via `lease_cmds` requires the control socket up; before it is up, the
  memfile fallback covers reads. Seeding requires the socket up post-start
  (bounded wait).

Verdict: **RECOMMENDED.** Only path that preserves the single-owner RG model and
the authoritative-stop, with no new service/DB/HTTP surface and a clean answer
to clock skew.

---

## 6. API preservation & hidden invariants

- **BACKUP-stops-Kea is PRESERVED.** No change to `clearRethServicesForRG`'s
  `ApplyAsync(nil)`. The standby holds lease state in xpf, not in a running Kea.
- **Single-owner RG model PRESERVED.** Push is gated on RG-MASTER; the
  MASTER-filtered memfile guarantees disjoint input sets (same property the DDNS
  gate `ddnsWriterGateOpen` relies on). No dueling writers.
- **CLAUDE.md control-socket-contention rule.** The DHCP-lease loop talks to
  KEA's unix socket and the CLUSTER sync channel — NEVER the userspace-helper
  control socket. It cannot starve session installs. (Same isolation the DDNS
  loop documents.)
- **Clock domain invariant (the <60s answer).** Leases MUST be synced as
  REMAINING LIFETIME, re-anchored to the local clock at seed time — NEVER as a
  raw wall-clock expiry epoch. The cluster channel syncs only a MONOTONIC
  offset, not wall clock, so a raw epoch from a clock-skewed peer would mis-age
  the lease on the promoting node. Remaining-lifetime + local re-anchor makes
  the design IMMUNE to peer wall-clock skew (this is strictly better than PATH
  A, which inherits Kea HA's hard <60s split-brain hazard).
- **Generation/length-gated wire discipline.** New `syncMsg*` records use the
  same length-gated-trailing-field rule as #2170 sessions so the schema can grow
  without breaking older peers; bump `syncSchemaVersion`.
- **fsatomic / persist=true.** memfile stays `persist=true` so a single-node
  daemon/Kea restart keeps leases locally (no regression of today's behavior).
- **`apply` generation ordering.** The Kea config change (adding control-socket
  + hook) flows through the existing `Manager.apply` gen-ordered path; no new
  apply semantics.
- **Standalone unchanged.** Loop gated on `cluster != nil` && `DHCPLeaseSync`.

---

## 7. Risk table

| # | Risk | Severity | Path | Mitigation |
|---|------|----------|------|-----------|
| R1 | BACKUP-stops-Kea contradicts always-on standby Kea | Blocker | A | PATH C avoids it (standby Kea stays down; xpf holds state). |
| R2 | Peer wall-clock skew mis-ages synced leases | High | A,C | C: sync remaining-lifetime, re-anchor to local clock at seed. A: inherits Kea's hard <60s hazard; needs new NTP guarantee. |
| R3 | New HTTP listener / REST surface on appliance | High | A | PATH C uses no HTTP; only Kea unix socket + existing TCP sync channel. |
| R4 | DB dependency / new SPOF / second HA sub-problem | High | B | PATH C uses no DB. |
| R5 | Up-to-one-tick lease staleness before abrupt failover | Medium | C | Bounded (same as IPsec/session sweep); promoted Kea also honors its own persisted memfile; unsynced new lease == never-existed (client re-DISCOVERs safely). Future: incremental on-grant push. |
| R6 | Duplicate allocation if standby seeds late / socket not ready | Medium | C | Seed BEFORE Kea answers (seed during/after start, gated on socket-ready wait); `lease-add` is idempotent; conflicting local lease wins newer. |
| R7 | Two arbiters of "who serves" (VRRP vs Kea HA) split-brain | High | A | PATH C has a single arbiter (VRRP/RG). |
| R8 | Sync failure blocks lease granting / commit | Medium | C | Fail-open: log+count, never block serving or fail commit (DDNS R9 posture). |
| R9 | RETH-member interface binding on standby Kea | Medium | A | N/A for C (standby Kea down). |
| R10 | Control-socket contention starving session installs | Medium | C | Kea unix socket is separate from the helper control socket; cadence ≥1s + coalesced (CLAUDE.md rule). |
| R11 | lease_cmds hook missing on some base image | Low | A,C | Live-verified present in kea-common 3.0.3; add a startup capability check + memfile fallback for reads. |
| R12 | Bulk seed of a large lease set blocks takeover path | Medium | C | Seed runs async post-start (like reinitiateIPsecSAs go-routine); bounded; fail-open. |

---

## 8. Test plan

Unit (Go, `pkg/dhcpserver`, `pkg/cluster`):
- Kea config generation emits `control-socket` + `lease_cmds` hook for each
  configured family; absent when no DHCP server configured; golden-file diff.
- `GetActiveLeases4/6`: socket path parses a `lease{4,6}-get-all` JSON response;
  memfile-fallback path reuses `parseActiveLeases` (already tested).
- Lease wire encode/decode round-trip (v4 + v6), length-gated trailing fields,
  legacy-peer (short payload) tolerance — mirror the session-sync decode tests.
- Remaining-lifetime re-anchor: a lease synced with remaining=T and seeded at
  local now → absolute expiry == now+T (clock-skew-immune assertion: inject a
  skewed peer "now" and assert the seeded expiry ignores it).
- Single-writer gate: push fires only on RG-MASTER; BACKUP holds peer state and
  pushes nothing.
- Fail-open: a socket/seed error increments the error counter and does NOT
  return an error to the caller / commit path.

Integration (loss userspace cluster, lock-cell wrapped):
- Configure a DHCP-server group on a RETH; lease a container client; confirm the
  lease appears in the standby's `peerDHCPLeases` (status/counter).
- `make test-failover` (MANDATORY — touches cluster/sync/failover code): during
  failover the client KEEPS its address + remaining lifetime, does NOT
  re-DISCOVER, and the promoted node does NOT re-hand the in-use address to a
  new client. Verify duplicate-allocation does not occur (a second client gets a
  DIFFERENT address).
- Bidirectional MASTER→BACKUP→MASTER; daemon restart on each node; standalone
  regression (no cluster → no lease-sync loop, behavior bit-identical).
- Confirm session-install throughput is unaffected during bulk lease seed
  (control-socket isolation).

---

## 9. Out of scope

- #2243 static/reserved bindings — config-derived, already identical on both
  nodes via config sync; this plan does not touch reservation config/render.
- DHCP relay, DHCP client, DDNS (#1387, already MASTER-gated/orthogonal).
- External shared lease DB as the default (PATH B; could be a future opt-in for
  operators already running an external Kea DB).
- `kea-ctrl-agent` HTTP REST control stack.
- Incremental on-grant lease push (v1 is periodic full-set; on-grant is a
  documented future tightening of R5).
- Native Kea HA hook (PATH A) — rejected; preserved here as the analyzed
  alternative.

---

## 10. Open questions (≥5)

1. **Push cadence vs lease churn.** Start the periodic full-set push at 30s
   (IPsec SA parity). Is a tighter cadence (e.g. 5-10s) warranted for typical
   DHCP churn, or should v1 add an incremental on-grant push to bound R5
   staleness from the start? (Trade-off: control-socket/CPU budget vs failover
   freshness.)
2. **Lease read transport.** Prefer `lease_cmds` over the unix control socket
   (live, authoritative) with memfile fallback, OR read the memfile directly
   (reuses `parseActiveLeases`, no socket dependency, but races Kea's append)?
   Recommendation: socket-first with memfile fallback — confirm acceptable.
3. **Seed timing on takeover.** Seed leases (a) by pre-writing the memfile
   BEFORE `systemctl start kea` (no socket wait, but bypasses Kea's lease
   manager), or (b) via `lease-add` over the socket AFTER start (clean, but
   needs a bounded socket-ready wait and there is a brief window where Kea could
   answer before seeding completes)? Recommendation: (b) with the seed kicked
   off in the start path and a short socket-ready bound; confirm the answer
   window is acceptable or whether (a) pre-seed is preferred to fully close R6.
4. **Config knob.** Auto-enable lease sync whenever a DHCP-server stanza exists
   in a cluster, OR gate behind an explicit `set chassis cluster
   dhcp-lease-sync` (parity with `ipsec-sa-sync` / `nat-state-sync`)?
   Recommendation: explicit knob for parity and opt-in safety.
5. **v6 identity completeness.** The existing `parseActiveLeases6` keys on
   DUID/IAID. Does `lease6-get-all` expose the same identity fields needed for a
   faithful `lease6-add` on the peer (DUID, IAID, prefix/PD vs NA)? Confirm PD
   (prefix delegation) leases are handled or explicitly scoped out of v1.
6. **Wall-clock guarantee for safety margin.** Even with remaining-lifetime
   re-anchoring (which removes the hard dependency), should xpf additionally
   enforce mutual chrony peering between the two nodes over the control net as a
   defense-in-depth NTP guarantee (and to keep `show` timestamps coherent)?
   Recommendation: document as optional hardening, not a hard requirement for C.
7. **Standby restart while holding peer leases.** If the BACKUP daemon restarts,
   its in-memory `peerDHCPLeases` is lost until the next periodic push from the
   MASTER. Is a one-tick re-push-on-reconnect (the bulk-sync precedent) needed
   so a freshly restarted standby is not briefly empty? Recommendation: trigger
   a full lease push on sync (re)connect, mirroring session bulk-sync-on-connect.
