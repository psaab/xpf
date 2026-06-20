# #1387 Increment 2 — DHCP DDNS live backend + daemon reconcile loop + HA coupling

**Status: DRAFT** (Claude /research draft-fanout — awaiting serial Codex + AGY plan-review.)

This is the increment-2 plan for #1387 (DHCP server dynamic DNS). Increment 1
shipped the config model + the fully-unit-testable reconciler core via PR #2043
(merged). This plan covers the three pieces Inc-1 explicitly deferred: the LIVE
RFC 2136 DNS backend, the daemon reconcile loop that drives the reconciler from
real Kea lease events, and the HA single-writer ownership coupling. The
observability surface (Prometheus + `show`) is included as the small companion
that makes the new runtime operable.

Predecessor plan: `docs/research/1387-dhcp-ddns/plan.md` (branch
`research/1387-dhcp-ddns`, commit `6dbcc6655`). Read its §12 for the
multi-increment sequencing this plan executes.

---

## 1. Issue framing

#1387 wants DHCP-handed-out hostnames to resolve in DNS while leases are active,
and the A/AAAA/PTR records cleaned when the lease expires, is released/declined/
reclaimed, the client moves address, the address is reassigned to a different
client, or the pool/group is removed from config. It must survive daemon restart
and HA failover, must never delete a record xpf did not create, and must keep
DHCP serving available even when the DNS update backend is down (fail-open for
DHCP).

Inc-1 built every pure, lab-free piece of that (config, lease parsing, name
normalization, the diff/transition reconciler, the ownership state store, the
`DNSUpdater` interface, the no-op backend). Today, with DDNS enabled, the system
PARSES and VALIDATES the config and emits a commit-time warning that nothing is
published, because:

- `NewDDNSManager` substitutes a `nopUpdater` (every upsert/delete is a logged
  no-op) — `pkg/dhcpserver/ddns.go:131-152`.
- Nothing constructs a `DDNSManager` in the daemon: `grep DDNSManager pkg/daemon`
  is empty. There is no reconcile loop, no Kea-lease trigger, no HA gate.
- The Prometheus collector declares no `dhcp_ddns_*` descriptors and the `show`
  tree has no `dynamic-dns` node.
- `config.validateDDNSDeferredBackendWarnings` (`pkg/config/compiler.go:1545`)
  fires a commit warning telling the operator no records are published.

Inc-2 turns the lights on: real DNS writes, driven by a real loop, gated to the
HA-active node, observable, with the deferred-backend warning retired.

---

## 2. Honest scope / value — the feasible-slice vs lab split

**The central scoping question the prompt asks: how much of Inc-2 is unit-testable
without a live DNS server, and what genuinely needs the cluster lab?**

Answer: **almost all of Inc-2 is feasible (unit/integration-testable in CI) by
running the live RFC 2136 backend against an in-process DNS responder.** The
`miekg/dns` library — the canonical Go RFC 2136 + TSIG implementation, and the
exact library the issue's Phase 3 names — ships an embeddable `dns.Server` that
binds a real UDP/TCP socket on `127.0.0.1:0`, parses real DNS UPDATE messages,
verifies real TSIG, and lets the test assert the exact wire-level adds/deletes.
This is the same shape as the repo's existing in-process test servers (`httptest`,
`net.Listen`, used in `pkg/api/*_test.go`, `pkg/snmp/traps_test.go`,
`pkg/cluster/sync_test.go`). The live backend is therefore NOT lab-bound: it is a
normal Go package tested against a fake authoritative server in the same process.

**FEASIBLE SLICE (this plan — engineer it, no cluster lab needed):**

1. **Live RFC 2136 backend** (`rfc2136Updater` implementing `DNSUpdater`) — real
   DNS UPDATE construction (A/AAAA/PTR add + delete), real TSIG signing via
   `TSIGSecret.Reveal()`, conflict-policy handling, bounded timeout. Tested
   end-to-end against an in-process `miekg/dns` server with TSIG verification.
2. **Daemon reconcile loop** — a guarded, context-cancellable background loop
   (modeled on the neighbor periodic loop) that polls the Kea lease CSVs on a
   periodic tick and is re-driven on config commit, calling
   `DDNSManager.Reconcile(ctx, cfg)`. No control-socket contention (file I/O +
   network to the operator's DNS server only).
3. **HA single-writer coupling** — the loop reconciles only when this node is the
   DHCP-serving node for the relevant RG(s), reusing the exact RG-ownership
   predicate (`snapshotRethMasterState` / `filterDHCPConfigForMasterRGs`) the Kea
   manager already uses; immediate reconcile on MASTER transition; emission
   stops on BACKUP without deleting valid records. The *correctness* of this
   gate is unit-testable (inject the ownership predicate); the *timing* on a real
   failover is the one true-lab item — see below.
4. **Observability** — `dhcp_ddns_*` Prometheus metrics wired through the checked
   collector (`DDNSManager.Stats()` → `Server`), and `show system services
   dhcp-server dynamic-dns` via the generic `ShowText` topic.
5. **Retire the deferred-backend commit warning** and constrain the TSIG/
   update-server leaves now that a live path consumes them.

**TRUE-LAB / DEFERRED (NOT engineered in this plan's PR — flagged):**

- **Live Kea→DNS end-to-end on the loss cluster**: a real `kea-dhcp4-server`
  handing a real lease to a real client, the loop seeing the real memfile row,
  publishing to a throwaway authoritative BIND/Knot, and `dig` resolving it; then
  forcing expiry/reassign and confirming removal. This needs a DNS fixture that
  does not exist in CI and a Kea lease-grant client harness. **Scope: a manual
  lab validation checklist run once before declaring Inc-2 complete (§9), NOT a
  blocking CI gate.** The in-process responder proves the wire format and the
  reconcile semantics; the lab proves the plumbing to a real resolver.
- **HA failover *timing*** (records re-published within N ms of MASTER takeover):
  validated by `make test-failover` on the loss cluster with DDNS enabled. The
  single-writer *correctness* (never two nodes writing the same record) is
  unit-tested; the live no-dueling-writes + reconcile-on-takeover is the lab gate
  per CLAUDE.md ("Any change touching cluster, VRRP, session sync, or failover
  code MUST pass `make test-failover`").

**Value:** real, but bounded. It is the difference between "DDNS config is
accepted" and "DDNS actually works." The risk is the cardinal sin (deleting a
production record xpf didn't create) and DNS-zone churn from a buggy loop. Inc-1
built the never-delete-non-owned boundary precisely so this increment can wire a
live backend without that risk; Inc-2's job is to not breach it.

**Recommendation: PLAN-READY for the feasible slice (items 1-5), with the live
Kea→DNS end-to-end and the failover-timing run flagged as lab-gated manual
validation, not CI.** This keeps Inc-2 a single reviewable PR whose every line is
exercised by deterministic tests, with the lab as a confirmation pass rather than
a merge blocker.

---

## 3. What Inc-1 shipped (current state of the code)

All in `pkg/dhcpserver/` (PR #2043, merged; commits `2c8685f3f` … `ea3dd0d67`):

- **`ddns.go`** — `DDNSManager` (mutex-guarded; owns the state store + updater +
  counters + `nodeID` watermark seed), `policyFromConfig`, `Reconcile(ctx, cfg)`
  (the production entry point — resolves policy, parses both families' active
  leases, marks an unreadable family untrusted, calls `reconcileOnceLocked`),
  `reconcileOnceLocked` (build-desired / Pass-1 expire+reassign delete /
  Pass-2 add, with blocked-maps so a failed delete blocks the dependent add),
  `withdrawAllLocked` (feature-OFF cleanup), `upsertLocked` / `deleteOwnedLocked`
  (the sole delete authority, re-derives the exact tuple from owned state),
  `Stats()`. The no-op path (nopUpdater) deliberately does NOT record ownership.
- **`ddns_dns.go`** — `LeaseDNSRecord`, the `DNSUpdater` interface (both methods
  MUST be idempotent), `nopUpdater` + `isNopUpdater`, `buildLeaseRecord`,
  `reversePTRName` (textual in-addr.arpa / ip6.arpa — NOT the dataplane __be32
  convention).
- **`ddns_leases.go`** — the state-aware Kea memfile parser
  (`parseActiveLeases4/6`): state column, expire epoch, fqdn_fwd split, v4/v6
  identity, case-insensitive + duplicate-rejecting + required-column-validated +
  per-row-conformance header handling. The mass-delete class is closed at both
  header and row level. Returns `(nil,nil)` ONLY when provably empty.
- **`ddns_hostname.go`** — `deriveFQDN` / `finalizeFQDN` — name ALWAYS contained
  in the configured zone (client picks host, firewall picks zone).
- **`ddns_state.go`** — the JSON ownership store via `fsatomic.WriteFileDurable`,
  versioned (`ddnsStateVersion = 1`), fail-open on corrupt/unknown-version.
- **`config.DHCPDynamicDNSConfig`** (`pkg/config/types_system.go:838`) — nilable
  field on `DHCPServerConfig`; `TSIGSecret` is now `config.Secret` (#2053,
  redacted on JSON/YAML, cleartext via `.Reveal()`). Dual-AST compiler
  (`compileDHCPDynamicDNS` + `mergeDHCPDynamicDNS`, dual-family merge). Typed
  schema leaves under both `dhcp-local-server`/`dhcpv6-local-server`.
- **Commit warning** `validateDDNSDeferredBackendWarnings` (`compiler.go:1545`).

Net behaviour change for existing users today: zero (nil block = no-op).

---

## 4. Concrete design

### 4.1 Live RFC 2136 backend (`rfc2136Updater`)

New file `pkg/dhcpserver/ddns_rfc2136.go`. Implements `DNSUpdater`.

**Dependency:** add `github.com/miekg/dns` to `go.mod` (Go 1.24.9; not currently
present, no vendor dir). This is the library the issue names and the de-facto Go
RFC 2136 standard.

**Constructor** takes the resolved policy fields it needs (update-server,
forward/reverse zone derivation, TSIG key name/alg/secret-revealed, TTL, conflict
policy, a timeout, and an injectable `dns.Client`-like seam for tests). The
backend is STATELESS beyond its config — all ownership/state lives in the
`DDNSManager` store, unchanged.

**Exact-RR discipline for BOTH upsert and delete (was the SMR's M2).** The
backend NEVER issues a delete-whole-RRset — that would remove a co-resident,
xpf-did-not-create record on the same name (the R1 cardinal sin). Every wire op
targets one EXACT RR (name+type+rdata).

**`UpsertLease(ctx, rec)`** builds ONE `dns.Msg` per zone affected:

- Forward zone (derived from `rec.FQDN` — the longest configured forward-zone
  suffix, or `policy.Domain`): an idempotent **ADD** of the exact A/AAAA RR for
  `rec.FQDN` → `rec.Addr`. It does NOT delete the RRset. An address MOVE is
  already handled upstream by Inc-1's reconciler, which deletes the OLD owned
  tuple (via `DeleteLease`, exact-RR) BEFORE the new add — so `UpsertLease` only
  ever needs to add. Re-adding an identical RR is a harmless idempotent no-op at
  the server (and Inc-1's `recordsEqual` short-circuit means a stable lease is
  not even re-upserted). Under `replace-owned`, no prerequisite is sent (we own
  what we add; the delete-old-then-add-new ordering is the reconciler's job). The
  add carries `rec.TTL`.
- Reverse zone (derived from `rec.PTRName` — the configured reverse-zone suffix,
  or the canonical in-addr.arpa/ip6.arpa zone): an idempotent ADD of the exact
  PTR RR `rec.PTRName` → `rec.FQDN`.

**`DeleteLease(ctx, rec)`** builds the symmetric DELETE of the EXACT A/AAAA RR
(`rec.FQDN`/type/`rec.Addr`) and the EXACT PTR RR (`rec.PTRName`→`rec.FQDN`).
A manually-added co-resident record on the same name is never collateral.
(`DDNSManager.deleteOwnedLocked` re-derives the exact tuple from the store; the
backend honors that exactness on the wire.) Per RFC 2136 a delete RR carries
TTL=0 and CLASS=NONE regardless of the stored TTL — the backend zeroes it (m7).

**TSIG:** if `TSIGKeyName != ""`, set the message's TSIG with
`TSIGSecret.Reveal()` and the configured algorithm (default
`hmac-sha256.`); use `dns.Client{TsigSecret: ...}` and `SetTsig` per miekg. No
TSIG configured ⇒ unauthenticated UPDATE (server must permit; operator's choice).

**Transport:** UDP first; on a truncated response, retry over TCP (standard DNS
UPDATE behavior). Per-call timeout from the context / a config default
(e.g. 5s). A non-NOERROR rcode is an error returned to the reconciler, which
counts the fail and retries next cycle (Inc-1 reconcile is idempotent + bounded).

**Conflict policy** (the `conflict-policy` leaf):
- `replace-owned` (default): the delete-RRset-then-add upsert above — we own what
  we publish; collisions with a record we didn't create are still avoided because
  the *delete* path only touches exact owned tuples.
- `skip-existing`: precede the add with a prerequisite ("name not in use" /
  RRset-does-not-exist); on YXDOMAIN/YXRRSET skip (count `SkippedConflict`).
- `strict-fail`: as skip-existing but treat the collision as an error
  (surfaced/counted; still must not block DHCP).

**Zone resolution helper** (pure, unit-tested): given `rec.FQDN` /`rec.PTRName`
and the configured `ForwardZones`/`ReverseZones` (or `Domain` fallback),
pick the zone the UPDATE's `Question`/`SOA` section targets. **Open question:
the Inc-1 config has `Domain` but the issue's surface lists `forward-zone` /
`reverse-zone` lists that Inc-1 did NOT add to the typed struct — see §11 Q1.**

### 4.2 Daemon reconcile loop

New: the daemon constructs a `*dhcpserver.DDNSManager` and runs a background
reconcile loop. Modeled on the neighbor periodic loop
(`runPeriodicNeighborResolution` / `neighborPeriodicLoop` /
`runGuardedNeighborPhase`, `pkg/daemon/daemon_neighbor.go:440`), which is the
project's blessed no-freeze guarded-phase loop pattern.

- **Construction — ALWAYS at daemon start, updater resolved per-Reconcile (hard
  constraint, was the SMR's M3).** The `DDNSManager` + its loop are constructed
  UNCONDITIONALLY at daemon start (in `daemon_run.go` near `d.dhcpServer =
  dhcpserver.New()`, line ~443), regardless of whether DDNS is currently enabled.
  This is mandatory: if the manager were "not started when disabled," a config
  that goes enabled→disabled would have no running loop to execute
  `withdrawAllLocked`, so the records published while enabled would NEVER be
  withdrawn — silently failing the issue's "config removal deletes owned records"
  acceptance criterion. An always-on, idle-when-disabled manager (cheap) with the
  updater resolved per-Reconcile from the current policy (§6 fork 1) lets ONE
  manager serve both the disabled (nopUpdater) and enabled (rfc2136Updater) states
  with no swap and no missed withdraw. The `nodeID` watermark seed comes from the
  cluster node-id when present; in standalone there is no node-id file, which is
  harmless — `ownerWatermark` folds nodeID only as a TXT hint, never into the
  delete-matching key (Inc-1 `ddns.go:176`), so an empty seed changes no
  correctness (m5).
- **Backend lifecycle on commit:** the backend config (update-server, TSIG, zones)
  can change at commit time. The cleanest design: the `DDNSManager` holds the
  updater, and `Reconcile(ctx, cfg)` is the single re-drive point; on a commit
  that changes backend config, the daemon rebuilds the updater and swaps it into
  the manager (a `SetUpdater` method, mutex-guarded) before the next reconcile.
  **Alternative: resolve the updater from policy inside `Reconcile`** — simpler,
  no swap race, but rebuilds a `dns.Client` each cycle (cheap; no connection
  pooling needed for an at-most-per-few-seconds loop). Lean toward resolve-in-
  Reconcile for statelessness. See §6.
- **Cadence:** periodic tick (default 30s — DNS records are not latency-critical;
  this is well under any reasonable lease time and far above the 1/s control-
  socket throttle, which it does not touch anyway), PLUS an immediate reconcile
  on config commit and on HA MASTER transition. A `reconcileNowCh`-style
  non-blocking nudge channel (as the RG-state loop uses) drives the event-path
  reconciles. **fsnotify on the Kea CSV is explicitly NOT adopted** (it is not a
  dependency, adds a watch-descriptor lifecycle, and the issue itself lists
  periodic-reconcile as the robust path; the near-event trigger is the
  commit/transition nudge, not a file watch). See §11 Q3.
- **No-freeze guard:** each reconcile runs as a guarded phase (skip-if-in-flight
  atomic, like `neighborWarmupInFlight`) so a hung DNS server can never wedge the
  loop; a per-reconcile context timeout bounds the network calls.
- **Stop:** context cancellation in the for-select, joined via the daemon's
  `wg` like every other loop.
- **Disabled fast-path:** when the active config has no DDNS or DDNS disabled, the
  loop still ticks but `Reconcile` takes the `withdrawAllLocked` no-op-fast path
  (returns immediately if the store is empty). Turning DDNS OFF withdraws records
  exactly once (Inc-1 `withdrawAllLocked`), then idles.

### 4.3 HA single-writer coupling

The invariant: **only the node actively serving DHCP for an RG publishes/cleans
DNS for that RG's leases.** Two nodes writing the same record is the dueling-
writer failure.

- **Gate predicate:** reuse `d.snapshotRethMasterState()` (`daemon_ha.go:156`,
  returns `map[rgID]bool` of active RGs) — the SAME source of truth the Kea
  manager uses via `filterDHCPConfigForMasterRGs`. In standalone (non-cluster)
  mode the node is always the writer. In cluster mode, the loop reconciles only
  when this node owns the RG(s) that own the DHCP groups producing the leases.
- **Lease→RG attribution — PER-RG, NOT node-level (resolved against the Kea
  render; was the SMR's M1).** VERIFIED in `pkg/dhcpserver/dhcpserver.go`: Kea
  writes exactly ONE memfile per family (hardcoded
  `/var/lib/kea/kea-leases4.csv` / `kea-leases6.csv`, lines 558-560/638-640) and
  ALL groups across ALL RGs render their subnets into that single per-family Kea
  config (`for _, group := range cfg.DHCPLocalServer.Groups` → one `subnet4`
  array → one memfile, lines 512/589). Therefore in an active/active multi-RG
  layout (the normal HA posture — node A MASTER for RG1, node B MASTER for RG2),
  BOTH RGs' leases live in the SAME memfile. A node-level gate ("if MASTER for
  any RG, reconcile all readable leases") would make the RG1-master node publish
  RG2's leases too — and the RG2-master node also publishes them — which is the
  dueling-writer bug the gate exists to prevent. The "BACKUP Kea is stopped → its
  memfile is stale" argument FAILS for a mixed MASTER/BACKUP node, because its Kea
  IS running (it's MASTER for the other RG) and the shared memfile is live for
  both. So Inc-2 MUST attribute each lease to an RG and act only on
  locally-owned RGs: `subnet_id` (in the memfile) → group → interface → RG (the
  same group→RG mapping `filterDHCPConfigForMasterRGs` walks), then publish/clean
  a lease ONLY when this node is MASTER for that lease's RG. The
  `parseActiveLeases` output already carries `SubnetID`. **The gate must be "am I
  the DHCP-serving MASTER for THIS LEASE's RG", anchored to the active-RG
  snapshot AND the subnet→RG map, NOT a raw read of the memfile and NOT a
  node-level any-RG check.** (Single-RG and standalone collapse to "always the
  writer," so the common case is unaffected.) See §11 Q2.
- **On MASTER transition:** nudge the loop for an immediate reconcile (records
  re-published / refreshed within one loop iteration of takeover). Wire this into
  the existing `applyRethServicesForRG` MASTER path (`daemon_ha.go:926`) right
  next to the `dhcpServer.ApplyAsync` call.
- **On BACKUP transition:** STOP emitting (the gate flips closed). **Do NOT
  delete records just because this node went BACKUP** — the records are still
  valid (the peer MASTER now owns them and will keep them fresh). Deletion is
  lease-state-driven (expiry/release on the new MASTER) or config-removal-driven,
  never local-ownership-loss-driven. This is the subtle part Inc-1's §5 flagged
  and Inc-2 must get right: a BACKUP transition is a "stop writing" event, not a
  "withdraw" event.
- **State store across failover:** the store is local to each node
  (`/var/lib/xpf/dhcp-ddns-state.json`). The `ownerWatermark` is
  identity+address-derived (node-independent, Inc-1 `ddns.go:176`), so when the
  new MASTER reconciles it computes the SAME desired records and the SAME
  watermark; if its local store is empty (never served before) it will *add*
  records the peer already published — but those adds are idempotent
  (replace-owned upsert), so no churn, no duplicate, no delete of a non-owned
  record. The cross-node store divergence is benign by construction. **Risk: a
  record published by old-MASTER, lease then expires while NO node is MASTER (both
  down), then new-MASTER comes up with an empty store and never learns it should
  delete that record → leak.** Mitigated by: the new MASTER's reconcile builds
  desired from *current* active leases; an expired lease is simply absent from
  desired AND absent from the new MASTER's empty store, so nothing deletes it.
  This is the documented fail-open leak (record stays until TTL/manual cleanup),
  consistent with Inc-1's corrupt-store fail-open. Acceptable; noted in §8.

### 4.4 Observability

- **Prometheus:** add `dhcp_ddns_*` descriptors to the checked collector
  (`pkg/api/metrics_descriptors.go` `newCollector`, declare in `Describe`, emit in
  a new `collectDDNSMetrics` called from `Collect`). The data source is a
  `DDNSManager.Stats()` reachable from `Server` (the daemon must expose the
  `DDNSManager` to the API `Server` the way it exposes `dhcp`). **Critical:** the
  descriptor-coverage canary (`pkg/api/metrics_descriptor_coverage_test.go`,
  pedantic registry) FAILS if a declared desc is not emitted — so every declared
  `dhcp_ddns_*` desc MUST be emitted with a value source. The coverage test must
  be extended to wire a `DDNSManager` stub into its fake `Server`. Metrics:
  `xpf_dhcp_ddns_upserts_total{result}`, `..._deletes_total{result}`,
  `..._reconcile_runs_total{result}`, `..._owned_records`,
  `..._skipped_total{reason}`, `..._last_reconcile_timestamp_seconds`,
  `..._last_reconcile_leases`. (Counter→gauge choice per metric; map onto the
  existing `DDNSStats` fields, extending `DDNSStats` where a counter is missing.)
  **Label cardinality is CLOSED (m4):** `result` ∈ {`ok`,`fail`} only and
  `reason` ∈ a fixed enum (`no-name`,`no-backend`,`conflict`,`not-owner-rg`) —
  never a raw rcode/error string, to avoid a cardinality leak.
- **`show system services dhcp-server dynamic-dns [detail]`:** add the cmdtree
  node under the existing `dhcp-server` node (`pkg/cmdtree/tree.go:530`), add the
  `ShowText` topic cases (`pkg/grpcapi/server_show.go`) + a render
  (`server_show_dhcp_lldp_snmp.go`) reading `DDNSStats` + the owned-record list;
  the CLI dispatches through the generic `ShowText` RPC (no new RPC needed).

### 4.5 Config + commit-warning changes

- **Retire/soften** `validateDDNSDeferredBackendWarnings` (`compiler.go:1545`):
  once the backend is live, "no records are published" is false. Replace with a
  validation that the live path now needs: e.g. DDNS enabled with
  `backend rfc2136` but no `update-server` → a real warning/error (nothing to
  update); `kea-d2` backend → still-deferred warning (D2 not in the image).
- **Constrain the now-consumed leaves:** `update-server` (host or host:port,
  parseable), TSIG algorithm (enum of supported HMACs), and — if §11 Q1 adds
  them — `forward-zone`/`reverse-zone`. Inc-1 left these free-form precisely
  because no live path consumed them; Inc-2 consumes them, so commit-time
  validation is now warranted.

---

## 5. Preserved interfaces / what Inc-2 must NOT change

- **`DNSUpdater` interface shape** — Inc-2's `rfc2136Updater` slots in behind the
  existing two-method interface. **No interface change should be needed** (see
  §11 Q4): `UpsertLease`/`DeleteLease` over a `LeaseDNSRecord` carry FQDN, Addr,
  TTL, ForwardType, PTRName — everything the backend needs except the *zone* and
  *server/TSIG*, which are backend-construction config, not per-record. If the
  conflict-policy needs to be per-call it can read it from backend config; the
  interface stays put. Keep it stable so the future Kea-D2 backend and the test
  fakeUpdater remain interchangeable.
- **`reconcileOnceLocked` algorithm** — unchanged. Inc-2 wires a real updater
  behind it; the diff/transition logic, the blocked-maps, the untrusted-family
  skip, the delete-before-add are all Inc-1 and must not be perturbed.
- **The ownership state store + `deleteOwnedLocked` as sole delete authority** —
  unchanged. The never-delete-non-owned boundary is Inc-1's contract; Inc-2 must
  not introduce any delete path that bypasses `deleteOwnedLocked`.
- **`ownerWatermark`** (identity+address derived, node-independent) — unchanged;
  it was laid down in Inc-1 specifically for the HA forward-compat this increment
  relies on.
- **`config.DHCPDynamicDNSConfig` field set** — additive only (if §11 Q1 adds
  zone lists). Do not rename/repurpose existing fields (compiled config is
  GET-able via the API; renaming breaks consumers).
- **`DDNSStats`** — additive only (new counters); existing fields keep their
  meaning so the future `show` reads stay valid.
- **Kea `Manager` and its generation-ordered applier** — untouched. `DDNSManager`
  is a SEPARATE type (Inc-1 §7) so the Kea applier is never perturbed.
- **Default-OFF behaviour** — a nil/disabled `DynamicDNS` block must remain
  byte-for-byte today's behaviour. The loop must be a no-op (or not constructed)
  when disabled.

---

## 6. Design forks (the real decisions)

1. **Updater lifecycle: resolve-per-Reconcile vs swap-on-commit.**
   - *Resolve-per-Reconcile* (preferred): `Reconcile` builds the `rfc2136Updater`
     from the current policy each cycle; stateless; no swap race; rebuilds a
     `dns.Client` (cheap at 30s cadence). The nopUpdater path in `NewDDNSManager`
     becomes vestigial for production (still used by tests/disabled).
   - *Swap-on-commit*: daemon rebuilds the updater on backend-config change and
     `SetUpdater`s it. Avoids per-cycle construction but adds a mutex-guarded swap
     and an "is the updater current?" question. **Lean resolve-per-Reconcile.**

2. **HA gate granularity — RESOLVED to per-RG-lease (node-level is unsafe).**
   The SMR's M1 + a read of the Kea render settled this: one memfile per family,
   all RGs' subnets in it, active/active mixed MASTER/BACKUP is normal ⇒
   node-level "any-RG-master reconciles all leases" is a dueling-writer bug.
   Inc-2 ships **per-RG-lease attribution**: `subnet_id`→group→interface→RG, act
   on a lease only when this node is MASTER for that lease's RG. Single-RG and
   standalone collapse to "always the writer," so the common case is identical to
   what node-level would have done — the per-RG logic only diverges (correctly) in
   the active/active multi-RG case. (See §4.3.)

3. **Backend transport: per-call client vs pooled connection.** DNS UPDATE is
   request/response; at 30s cadence there is no benefit to pooling. Per-call
   `dns.Client.Exchange` (UDP→TCP-on-truncation). **Per-call.**

4. **Reconcile trigger: poll-only vs poll+nudge vs fsnotify.** Poll+nudge (the
   RG-state-loop pattern) — periodic tick for robustness, nudge channel for
   commit/MASTER-transition immediacy. **fsnotify rejected** (new dep, watch
   lifecycle, marginal benefit over a 30s poll for non-latency-critical records).

5. **Where the live updater is constructed: daemon vs dhcpserver factory.** A
   `dhcpserver.NewRFC2136Updater(policy)` factory keeps DNS-wire concerns inside
   the package; the daemon just passes config. **Factory in dhcpserver.**

---

## 7. Public API preservation

- **gRPC:** no new RPC — `show ... dynamic-dns` reuses the generic `ShowText`
  topic dispatch (`server_show.go`). Additive topic strings only.
- **HTTP/Prometheus:** additive metric families (`xpf_dhcp_ddns_*`). No existing
  metric renamed/removed. The `/api/v1/config` compiled dump already redacts
  `TSIGSecret` (Inc-1 #2053) — no new leak surface.
- **CLI:** additive cmdtree node. Prefix-matching/`?`-help inherit automatically.
- **Config schema:** additive leaves (and possibly zone lists). Existing leaves
  keep their names; the only *behaviour* change is that previously-free-form
  consumed leaves (update-server, tsig-algorithm) now get commit-time validation
  — a stricter accept, which is a deliberate, reviewed tightening (note it in the
  PR; an existing config with a malformed update-server that "worked" because it
  was never consumed would now warn/error — acceptable, the value was inert).

---

## 8. Risk table

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| R1 | **Cardinal sin: delete a DNS record xpf did not create**, in the operator's production zone. | Critical | Inc-2 adds NO delete path outside `deleteOwnedLocked` (sole authority, re-derives exact owned tuple). Backend deletes the EXACT RR (name+type+rdata), never the whole RRset. Unit-test: assert the wire DELETE targets only the owned rdata. |
| R2 | **Dueling writers**: two HA nodes UPDATE the same record, churning the zone. | High | Single-writer gate on `snapshotRethMasterState` (same source as Kea). BACKUP stops emitting. Idempotent replace-owned upsert means even a brief overlap converges without churn. Lab: `make test-failover` with DDNS enabled. |
| R3 | **BACKUP transition wrongly withdraws valid records** (records vanish on every failover). | High | BACKUP = stop-writing, NOT withdraw. Deletes are lease-state/config-removal driven only. Explicit unit test: MASTER→BACKUP transition issues ZERO deletes. |
| R4 | **A hung/slow DNS server wedges the reconcile loop** (and starves nothing, but the loop stops making progress). | Medium | Guarded-phase skip-if-in-flight + per-reconcile context timeout (no-freeze pattern from #1780). The loop never blocks the daemon; a stuck server only delays DNS, never DHCP. |
| R5 | **DNS-zone churn / amplification** from a buggy diff re-publishing every cycle. | Medium | `recordsEqual` short-circuit (Inc-1) means a stable lease is `seen` and NOT re-upserted. Counter `upserts_total` flat across cycles in a steady state is the canary; assert in a multi-cycle test. |
| R6 | **TSIG secret leak** in logs / config dump / error messages. | Medium | `Secret` type redacts JSON/YAML/String (#2053); backend reads via `.Reveal()` only at wire-build; error messages must not include the secret (test a wrong-key error string contains no secret). |
| R7 | **Cross-node store divergence → record leak** when a lease expires while both nodes were down. | Low | Fail-open (record stays until TTL/manual cleanup), consistent with Inc-1 corrupt-store policy. Documented, not blocking. New MASTER never wrong-deletes. |
| R8 | **Descriptor-coverage canary breaks the build** if a `dhcp_ddns_*` desc is declared but not emitted. | Low (build-time, self-correcting) | Wire the value source + extend the coverage test's fake `Server` with a `DDNSManager` stub. This is a feature (the canary is doing its job), not a risk to runtime. |
| R9 | **DHCP serving blocked by DNS failure** (violates fail-open requirement). | High | The reconcile loop is fully decoupled from the Kea apply path; a DNS failure is counted/logged/retried, never propagated to commit or to Kea. Test: backend returns error → DHCP unaffected, counter increments, next cycle retries. |

---

## 9. Test plan

### 9.1 Lab-free unit/integration (CI — the feasible slice)

**In-process DNS responder (the key to keeping the live backend lab-free):** spin
an embedded `miekg/dns` `dns.Server` on `127.0.0.1:0` (UDP+TCP), with a TSIG
secret map matching the test config, recording every received UPDATE message.
The test asserts the EXACT adds/deletes on the wire. This is the same in-process
pattern as `pkg/api/*_test.go` / `pkg/snmp/traps_test.go`.

Backend (`rfc2136Updater`):
- Upsert v4 → server receives an UPDATE for the forward zone with a delete-RRset
  + add A; reverse zone with delete + add PTR.
- Upsert v6 → AAAA + ip6.arpa PTR.
- Delete → exact-RR delete (assert it targets only the owned rdata; a co-resident
  manually-added A on the same name is left intact — directly tests R1). Assert
  the delete RR carries TTL=0 / CLASS=NONE per RFC 2136 (m7).
- Upsert → exact-RR ADD only, NO delete-RRset on the wire (a co-resident
  manually-added A on the same name survives an upsert too — the other half of R1).
- TSIG: a wrong secret ⇒ the server rejects ⇒ backend returns error, counter
  increments, secret absent from the error string (R6).
- Conflict policies: replace-owned overwrites; skip-existing skips on a
  pre-existing RRset (prereq); strict-fail errors.
- Transport: a truncated UDP response triggers TCP retry.
- Timeout: a non-responding server ⇒ context-timeout error within bound (R4).

Reconcile loop + HA gate (inject the ownership predicate + the fake updater +
synthetic Kea CSVs, no daemon):
- Node is writer (standalone): active lease → upsert; expiry → delete.
- Node MASTER for RG → reconciles; node BACKUP → ZERO upserts AND ZERO deletes on
  the transition (R3); MASTER takeover nudge → immediate reconcile (R2 correctness).
- Steady state: lease unchanged across N cycles → `upserts_total` flat (R5).
- DNS backend errors → DHCP/Kea path untouched, counter up, retry next cycle (R9).
- Disabled→enabled→disabled: enable publishes; disable withdraws exactly once.

Observability:
- Prometheus: extend the descriptor-coverage test's fake `Server` with a
  `DDNSManager` stub; `Gather()` on the pedantic registry passes; assert the new
  families appear (R8).
- `show ... dynamic-dns`: golden-render test from a populated `DDNSStats` + store.

Config:
- The retired/softened commit warning: enabled+rfc2136+update-server → no
  "deferred" warning (and resolves); enabled+rfc2136 with no update-server →
  warning; `kea-d2` → still-deferred warning.
- New leaf validation: malformed update-server / bad TSIG algorithm rejected/warned.

`make test` must pass; `go test ./pkg/dhcpserver/... ./pkg/config/... ./pkg/api/...`.

### 9.2 Lab-gated manual validation (run once before declaring Inc-2 done — NOT a CI gate)

On the loss userspace cluster (`loss:xpf-userspace-fw0/fw1`), with a throwaway
authoritative BIND/Knot + TSIG reachable from the cluster:
- Configure DHCPv4 pool + DDNS (update-server, TSIG, domain); hand a real lease;
  `dig` the A + reverse PTR resolve.
- Renew the lease → record stable (no churn; counter flat).
- Force lease expiry/reclaim → A + PTR removed.
- Reassign the address to another MAC/hostname → old name removed, new added.
- Repeat for DHCPv6 AAAA / ip6.arpa.

### 9.3 Failover (mandatory per CLAUDE.md — touches cluster/VRRP path)

`make test-failover` with DDNS enabled: confirm no dueling writes (zone not
churned across the failover), records re-published/kept on the new MASTER, and
the 14/0 iperf failover result is unaffected (DDNS must not regress data-plane
failover). This is the one cluster-lab gate this plan treats as blocking.

---

## 10. Out of scope (Inc-2)

- **Kea D2 backend** (`backend kea-d2`) — D2 is not in the image (`bake.py`);
  reserved enum stays deferred (Inc-4).
- **The #660 local authoritative/DNS-runtime backend** — future, gated on #660
  landing.
- **Per-RG-lease attribution** — node-level gate ships; per-RG refinement filed
  as a follow-up (§11 Q2).
- **fsnotify near-real-time lease watch** — periodic poll + commit/transition
  nudge is the chosen trigger; a sub-second file watch is not warranted.
- **strict-mode lease withholding** (block a DHCP lease if DNS update fails) — the
  issue explicitly says do NOT implement strict mode first; DDNS stays fail-open
  for DHCP.
- **Pool-level DDNS overrides** — server/global defaults only (issue: "per-pool
  override later").

---

## 11. Open questions (for adversarial review)

1. **Forward/reverse zone config surface.** The issue's proposed surface lists
   `forward-zone`/`reverse-zone` (and even multiple), but Inc-1's typed
   `DHCPDynamicDNSConfig` shipped only `Domain` (no zone lists). Does Inc-2:
   (a) derive the UPDATE target zone purely from `Domain` + the canonical
   reverse zone of the address, or (b) add explicit `ForwardZones`/`ReverseZones`
   leaves now? RFC 2136 UPDATE needs a zone name in the message; deriving it from
   `Domain` works for the common case but breaks when the authoritative zone cut
   differs from the DHCP domain (e.g. delegated `lab.example.net` vs domain
   `corp.lab.example.net`). Recommendation: add the zone leaves (additive,
   §4.5/§5), default to `Domain`/canonical-reverse when unset.

2. **HA gate granularity — RESOLVED (kept here for the review trail).** Verified
   against `pkg/dhcpserver/dhcpserver.go`: one memfile per family, all RGs'
   subnets in it, so node-level gating IS unsafe in active/active. Resolution:
   per-RG-lease attribution (subnet_id→group→RG→is-this-node-master), §4.3/§6.
   Residual sub-question for review: confirm the subnet_id Kea writes in the
   memfile matches the subnet_id the renderer assigns per group (so the
   attribution map is keyable) — verify against the keaSubnet4/6 render
   (`dhcpserver.go:499-643`) when engineering.

3. **Reconcile cadence + the lease-event latency requirement.** 30s poll means a
   new lease can take up to 30s to appear in DNS. Is that acceptable, or does the
   issue's "near-event trigger" intent require faster (commit/transition nudge
   covers config changes but NOT a mid-interval client lease grant)? If sub-30s
   lease→DNS latency matters, fsnotify or a shorter poll is back on the table —
   but a shorter poll re-reads the CSV more often (cheap) without touching the
   control socket, so a 5-10s poll is a low-cost middle ground.

4. **Does the `DNSUpdater` interface need extension?** §5 argues no — but the
   conflict-policy and the zone are backend-construction config, not per-record.
   Is there a per-lease conflict decision (e.g. honor a per-pool policy) that
   would force policy into `LeaseDNSRecord` or the method signature? If per-pool
   DDNS lands later (out of scope now), does that retroactively want the
   interface to carry policy? Decide whether to future-proof the interface now or
   keep it minimal (lean: keep minimal; YAGNI, and Inc-1 deliberately made it
   minimal).

5. **TSIG algorithm default + supported set.** Inc-1 left `tsig-algorithm` free-
   form. miekg/dns supports hmac-md5/sha1/sha224/sha256/sha384/sha512. What is
   the default when unset (recommend `hmac-sha256.`) and which do we accept at
   commit? hmac-md5 is deprecated/insecure — reject it, or accept-with-warning?

6. **Reverse-zone authority we may not own.** If the operator configures a forward
   zone they control but the address's reverse zone (in-addr.arpa) is delegated
   to an ISP they do NOT control, the PTR UPDATE will REFUSE (NOTAUTH). Should
   PTR publishing be independently toggleable (publish A but skip PTR when no
   reverse-zone is configured/authorized), so a NOTAUTH on PTR doesn't mark the
   whole lease's reconcile as failed and retry-storm? Recommendation: only attempt
   PTR when a reverse-zone is configured (or `Domain`-derivable AND a future
   `publish-ptr` toggle is on); treat a PTR NOTAUTH as a counted skip, not a
   blocking error.

7. **Where does the `DDNSManager` live for the API `Server` to read `Stats()`?**
   The daemon owns it; the API `Server` reads `dhcp` already — does Inc-2 add a
   `ddns` field to `Server` (and the gRPC server), and is the lifecycle (manager
   may be nil when DDNS disabled) handled so the collector/show no-op cleanly?

---

## 12. Recommendation

**PLAN-READY for the feasible slice (§2 items 1-5): the live RFC 2136 backend, the
daemon reconcile loop, the HA single-writer coupling, and the Prometheus + `show`
surface — all unit/integration-testable in CI against an in-process `miekg/dns`
responder.** The live Kea→DNS end-to-end on the cluster (§9.2) is flagged as a
manual lab confirmation, NOT a merge-blocking CI gate; `make test-failover` with
DDNS enabled (§9.3) is the one mandatory cluster gate because Inc-2 touches the
HA/VRRP transition path.

The single largest open decision before engineering is now §11 Q1 (zone config
surface) — it changes the config schema and the backend's zone-resolution helper.
The Q2 correctness unknown (HA gate granularity / Kea memfile↔RG mapping) was
RESOLVED in this revision against the Kea-render code: one memfile per family
forces per-RG-lease attribution (§4.3/§6) — node-level gating is a dueling-writer
bug. Recommend serial Codex + AGY plan-review focus on Q1 (zone surface) and on
hardening the per-RG attribution + the exact-RR upsert discipline.

### SMR-disposition (r1 self-review folded)

The hostile Claude-SMR (`claude-smr-plan-r1.md`) returned PLAN-READY-WITH-
CONDITIONS, no blocker, three MAJORs. All three are folded into this revision:
M1 (memfile↔RG, node-level unsafe) → per-RG attribution now in-scope, verified
against `dhcpserver.go`; M2 (upsert atomicity) → exact-RR ADD discipline,
no delete-RRset, §4.1; M3 (disabled-loop lifecycle) → always-construct + resolve-
per-Reconcile hard constraint, §4.2. Minors m4 (closed result-label set),
m5 (standalone no node-id is harmless), m6 (DDNS-specific failover observation),
m7 (TTL=0/CLASS=NONE on deletes) folded into §4.1/§4.4/§9. Open questions Q-A
(new go.mod dep `miekg/dns` — confirm no project policy bars it) and Q-C
(warn-not-error on legacy free-form leaves) remain for Codex/AGY.
