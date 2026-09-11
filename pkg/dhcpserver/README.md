# pkg/dhcpserver

Manages Kea DHCPv4/v6 server config and lifecycle. Generates
`/etc/kea/kea-dhcp{4,6}.conf` from the typed config and reloads the
`kea-dhcp{4,6}-server` units via systemd. Config writes are
AtomicGeneratedConfig (#1894): `fsatomic.WriteFileAtomic` — Kea never
parses a torn file, no fsync on the apply path.

## Entry points

- `Manager` — `dhcpserver.go`.
- `New()` — `dhcpserver.go`.
- `Apply(cfg *config.DHCPServerConfig) error` — `dhcpserver.go`.
  Authoritative reconcile (#1778): for each configured family it
  regenerates the Kea config and restarts the unit; for each
  unconfigured family (including `cfg == nil`) it stops the unit if
  `systemctl is-active` reports it active — even if a PREVIOUS xpfd
  instance started it — and removes the generated config.
  **Fail-closed:** restart failures (and failures to stop an active
  unit that left the config) are returned, so a commit surfaces
  "DHCP server failed" instead of silently succeeding with no
  service. A failed restart gets exactly one recovery attempt first
  (#9601, `restartClearingStartLimit`): `systemctl reset-failed` and a
  second restart. A node taking several redundancy groups at once
  restarts Kea once per MASTER apply, which can trip the unit's systemd
  start limit; systemd then refuses every start, including the #6535
  converger's retry, until the interval passes or the failed state is
  reset. A unit that still fails after the reset returns the combined
  error and stays retryable. The `systemctl is-active` probe (`unitIsActive`) is itself
  tri-state (#4870): a recognized state string is authoritative
  (active / inactive / failed) regardless of exit code, but a query
  that CANNOT determine the state — timeout, exec error, garbled/empty
  output — returns an error rather than the previous silent "inactive".
  On such an uncertain query the reconcile fails closed: it restarts a
  configured family (to enforce the freshly generated config) or stops
  a removed family (to enforce the removal) AND surfaces the query
  error, so a transient probe blip during a cluster commit can no
  longer skip the enforcement while the commit reports success (the old
  fail-open left stale/removed Kea policy serving). The generated-config
  unlink error on a removed family is surfaced too (a leftover file
  could resurrect a removed subnet on a later manual/boot start).
- `Shutdown() error` — `dhcpserver.go`. The authoritative DHCP stop
  for daemon shutdown (#6787), and the only one on that path. Before
  it, an orderly HA shutdown withdrew VRRP ownership, cleared
  `rg_active` and stopped the heartbeat while leaving the Kea units
  RUNNING — they are separate systemd services that outlive xpfd — so
  the promoted peer started its own Kea and both nodes served DHCP on
  one segment: duplicate OFFERs, two lease databases issuing addresses
  from one pool with neither aware of the other, persisting for the
  whole xpfd downtime.

  It is **synchronous**: `ApplyAsync`'s mailbox is drained by a worker
  goroutine, so a stop enqueued during shutdown races process exit and
  is simply lost — a fix that is present and does nothing looks exactly
  like one that works.

  It also **latches** (`shuttingDown`): once set, EVERY applier —
  `Apply`, `ApplyClusterCommit` and the async worker — coerces its
  desired state to `nil`. The latch is not belt-and-braces. `Shutdown`
  runs BEFORE the priority-0 withdrawal, so this node stops serving
  before the peer starts, and that ordering leaves a window in which a
  VRRP MASTER transition can still enqueue an apply. That request
  allocates a strictly NEWER generation, so the #1835 supersession
  guard cannot refuse it — without the latch it would re-arm the units
  after the stop had already reported success. Coercing rather than
  REFUSING keeps the reconcile idempotent: a late applier still runs,
  and still lands on "stopped".

  **Cluster mode only** at the call site (`pkg/daemon`,
  `runShutdownSequence`). Standalone has no peer to hand the segment
  to and Kea deliberately survives an xpfd restart there; stopping it
  would turn every daemon restart into a DHCP outage. The
  discriminator is `haMode`, NOT `hitless` — VRRP sends its priority-0
  burst even on a hitless HA restart, so the peer takes over and an HA
  node must stop serving either way.
- `ApplyAsync(cfg, reason)` — `dhcpserver.go`. Enqueues an `Apply` to
  a single lazily started worker via a 1-slot latest-wins mailbox and
  returns immediately (#1835 F2). Used by the VRRP transition
  callbacks in `pkg/daemon` so the event loop never waits behind a
  15s-bounded systemctl. Every applier — sync `Apply`,
  `ApplyClusterCommit`, and `ApplyAsync` — allocates a monotonic
  generation at call entry; the shared apply body skips requests
  superseded by a newer generation, so a queued async request is
  never applied over a later synchronous commit, and the mailbox slot
  is only overwritten by a higher generation (no ABA between racing
  producers). Coalescing is correct because `Apply` is an idempotent
  reconcile to desired state: intermediate states may be skipped but
  the newest desired state always wins. `cfg == nil` is the
  authoritative clear. Errors are logged with `reason`; the commit
  path keeps synchronous `Apply` (fail-closed; a superseded sync
  applier returns nil — being outraced is not a failure).
- `ClaimApplyRetry(now) bool` — `dhcpserver.go`. The converger predicate
  (#6535): true when the last COMPLETED apply attempt returned an error,
  claiming a spaced retry window (`applyRetryInterval`, 30s) when it says
  yes. It is the debt marker the cluster reconcile loop consumes — see
  "Failed applies had no converger" under Gotchas. Guarded by `retryMu`,
  deliberately NOT `mu`: `mu` is held for the whole apply body (a
  15s-bounded systemctl shell-out) and the caller is the daemon's 2s
  reconcile pass, which must not block behind a restart still in flight.
  Lock order is `mu` -> `retryMu`; only the tail of `apply` takes both.
- `ApplyClusterCommit(cfg) error` — `dhcpserver.go`. Cluster-commit
  reconcile (#1835 F3): always regenerates configs for configured
  families but restarts only units that are currently active; clears
  unconfigured families like `Apply`. Fail-closed.
- `Clear()` — `dhcpserver.go`. Stops both Kea units if systemd
  reports them active and removes config files. Void signature for
  the VRRP-transition callers (`pkg/daemon` HA path); stop failures
  are logged at Warn. Commit-path callers use `Apply(nil)` to get the
  error.
- `IsRunning()` — `dhcpserver.go`. Queries systemd unit state
  (authoritative; survives daemon restarts).
- `Lease` — `dhcpserver.go`. Surfaced to the CLI for `show dhcp
  server leases`.
- `NewManagerForTesting(...)` — `test_seams.go`. Injectable
  `systemctl` seams + config paths, per the `pkg/dhcp/test_seams.go`
  convention.

## Static host reservations — #2243

Fixed / reserved address bindings let an operator pin a client (by
hardware address) to a stable address served by the DHCP server, e.g. a
printer, NAS, or appliance. Junos shape, scoped to a pool's subnet:

```
set system services dhcp-local-server group lan pool office \
    static-binding 00:11:22:33:44:55 fixed-address 10.0.1.50
set system services dhcp-local-server group lan pool office \
    static-binding 00:11:22:33:44:55 host-name printer
```

(The `dhcpv6-local-server` hierarchy takes the same `static-binding`
subtree with an IPv6 `fixed-address`.)

- **Config model:** `DHCPPool.StaticBindings []*DHCPStaticBinding`
  (`pkg/config/types_system.go`); each carries `MACAddress`,
  `FixedAddress`, optional `HostName`. The schema subtree is
  `dhcpStaticBindingSchema()` (`pkg/config/schema_system.go`), a
  MAC-keyed named-instance container (`keyValidator: ValidateMAC`) with a
  typed `fixed-address` leaf (`ValidateIPAddress`) and a free-form
  `host-name`. Compile is the `static-binding` case in
  `compileDHCPLocalServer` (`pkg/config/compiler_services.go`), handling
  both AST shapes via `namedInstances`.
- **Commit validation (strict/lenient split):**
  `validateDHCPStaticBindingsStrict`
  (`pkg/config/compiler_validate_strict.go`) rejects a missing/malformed
  fixed-address, a family-mismatched literal, an address outside the pool
  subnet (Kea would silently drop it), and a duplicate MAC identity or
  duplicate fixed-address within the same pool. The strict commit /
  commit-check path (`CompileConfig`) hard-rejects; the tolerant load /
  peer-sync paths (`CompileConfigLenient` / `CompileConfigForNodeLenient`,
  flag `lenientDHCPStaticBindings`) DOWNGRADE the violation to a
  `cfg.Warnings` entry so an already-persisted or peer-synced config
  carrying a bad binding still BOOTS (#1960 no-brick) — the validator runs
  AFTER the strict accumulator (mirroring `validatePolicyMatchAddressesStrict`),
  not inside it, so it no longer hard-rejects the whole config-load like
  the original #2243 placement did.
- **Kea render:** `generateKea4Config`/`generateKea6Config` emit a
  per-subnet `reservations` array — v4 `hw-address` → `ip-address`, v6
  `hw-address` → `ip-addresses[]`, plus optional `hostname`. The MAC is
  canonicalized to Kea's accepted colon-lowercase form
  (`aa:bb:cc:dd:ee:ff`) via `canonicalMAC` (`net.ParseMAC().String()`) at
  BOTH render sites: `ValidateMAC`/`net.ParseMAC` accept the Cisco
  dotted-triplet (`0011.2233.4455`) and uppercase, but Kea's hw-address
  parser REJECTS the dotted form, so a config that commits clean would
  otherwise break the entire Kea Dhcp4/6 reconfigure. A binding whose MAC
  fails to parse at render (not expected after commit-time validation) is
  skipped with a warning rather than emitted malformed. A pool with no
  bindings emits no `reservations` key (`omitempty`), byte-for-byte
  identical to pre-#2243 output.
- **HA:** reservations derive entirely from committed config, which the
  cluster config-sync already replicates, so both nodes serve identical
  reservations and the reserved client gets the same address regardless
  of which node is MASTER — reservation-consistent by construction, no
  per-lease replication. (Dynamic-lease HA sync across failover is the
  separate companion gap, #2239.) ISC Kea handles static reservations
  entirely in the config file, independent of its HA hook.

## Stable subnet IDs — #2668 / #5041 / #5203

`generateKea4Config`/`generateKea6Config` assign each rendered subnet a Kea
`subnet_id` (the `id` field of `subnet4`/`subnet6`). Kea binds memfile leases
(`kea-leases4.csv`/`kea-leases6.csv`) to a subnet by the `subnet_id` COLUMN,
so the ID a subnet receives MUST be stable — both across config regenerations
on ONE node (commit / reload, #2668) and across the two HA nodes (#5041). A
shifted ID remaps live leases onto the wrong subnet/pool and corrupts
diagnostics, lease-sync, and DDNS (which keys desired records by SubnetID,
#2663). A synced lease carries its `subnet_id` verbatim, so if the peer
renders the same subnet under a different id, the lease misbinds on the
receiver (#5041).

The id is a pure function of the subnet's canonical CIDR identity
(`stableSubnetID`): an FNV-1a hash of the CIDR string folded into the valid
Kea range `[1, 0xFFFFFFFE]` (avoiding the reserved sentinels `0` =
SUBNET_ID_UNUSED and `0xFFFFFFFF` = SUBNET_ID_GLOBAL). Hashing the CIDR — not
the subnet's POSITION — is what makes the id identical on both HA nodes: each
node renders only its MASTER-filtered subset (`filterDHCPConfigForMasterRGs`),
so the same subnet lands at a different position on the two nodes, and the
pre-#5041 positional counter therefore gave it a different id per node. The
#2668 reload-stability property (an unchanged config always renders identical
ids) is subsumed, since the hash never depends on map-iteration order.

Rendering still walks a DETERMINISTIC order — **groups** sorted by name
(`stableGroups`), **pools** sorted by subnet then name (`stablePools`), and
the `interfaces-config.interfaces` list collected over the same order — but
that order now only governs the COLLISION probe, not the id value itself.

**Collision probe (#5203).** Two DISTINCT CIDRs in one rendered config can
hash to the same id (astronomically rare, ~k²/2³³ for k subnets). Two subnets
on one Kea instance must never share an id, so the loser probes for a free id
(`resolveSubnetID`). The probe sequence is `base + k*step` folded into
`[1, 0xFFFFFFFE]`, where `step` is derived from a SECOND, independently-salted
FNV-1a hash of the CIDR (`subnetProbeStep`). Because both the base and the
step are pure functions of the CIDR — never of the surrounding subnets — a
colliding subnet walks the SAME sequence on both nodes and resolves to the
SAME id even under asymmetric RG mastering. The earlier +1 linear probe
stepped through the node's render order, so the free id it found depended on
which OTHER subnets that node mastered and could differ across nodes,
reintroducing the #5041 misbind for the colliding pair. The step is forced
coprime with `0xFFFFFFFE` (= 2·(2³¹−1)) so the walk visits every id exactly
once and always finds a free slot.

Residual: the probe converges cross-node unless a THIRD subnet, present in one
node's subset but not the other, hashes onto the loser's CIDR-derived probe
path — a second-order coincidence far rarer than the first-order collision,
and the practical limit of a stateless (no persisted name→id map) scheme. A
persisted map would also close the add/remove-shifts-later-ids gap but adds a
new on-disk state file with its own HA-sync and stale-entry-GC concerns;
add/remove is a deliberate operator change, not the per-reload churn #2668
addressed. Regression guards: `TestKeaSubnetIDStableAcrossRegenerations`
(#2668, reload), `TestKeaSubnetIDStableAcrossFilteredSubsets` (#5041,
cross-node), and `TestKeaSubnetIDCollisionProbeIsNodeIndependent` (#5203,
colliding pair).

## Expired-lease reclamation — #1387 (stale-lease-cleanup slice / Path S)

The "stale lease cleanup" half of #1387. Kea keeps an expired / released /
declined lease ROW in its memfile (`kea-leases4.csv` / `kea-leases6.csv`)
as an appended record until its reclamation cycle removes it; the defaults
are conservative. Without tuning, expired rows accumulate — they bloat the
memfile, slow startup re-load, and delay Kea's internal reclamation/reuse
of the expired address. (They do NOT make `show dhcp-server` lie: since
#2085 the lease display already filters non-active / expired rows, so the
display is truthful today. This slice makes the *source* truthful by
actually removing the rows Kea would otherwise keep.) This is the
DHCP-lease-database layer — entirely distinct from the DDNS stale-*record*
cleanup below (the reconciler withdrawing A/AAAA/PTR when a lease leaves
the active set).

Opt-in, per family, Junos-shaped — the keys map to Kea's per-`Dhcp4` /
per-`Dhcp6` `expired-leases-processing` block:

```
set system services dhcp-local-server expired-leases-processing enable
set system services dhcp-local-server expired-leases-processing reclaim-timer 10
set system services dhcp-local-server expired-leases-processing flush-timer 25
set system services dhcp-local-server expired-leases-processing hold-time 600
set system services dhcp-local-server expired-leases-processing max-leases 100
set system services dhcp-local-server expired-leases-processing max-time 250
set system services dhcp-local-server expired-leases-processing unwarned-cycles 5
```

(The `dhcpv6-local-server` hierarchy takes the same subtree; v4 and v6 are
tuned independently because Kea renders the block once per family.)

- **The per-subnet `interface` selector is handled OPPOSITELY in v4 and v6,
  and that asymmetry is deliberate (#6520 / #1835 / #9122).** A group whose
  member list was narrowed at runtime by the chassis-cluster master-RG filter
  (`MembersFiltered`) has no pool→member edge, so the surviving interface
  cannot be attributed to any particular pool.
  - **v4 SUPPRESSES the selector** and lets Kea fall back to address-based
    subnet selection. Emitting it would cross-bind a removed member's network
    to the survivor's interface (#6520).
  - **v6 REFUSES the group.** Kea v6 cannot fall back to address matching —
    clients talk from link-local source addresses — so a `subnet6` with no
    `interface` key is *unselectable*, and Kea silently answers no SOLICIT for
    it. Before #9122 the narrowed group rendered exactly that: the
    `len(Interfaces) > 1` guard sees the FILTERED list, which is a singleton,
    so the loud path was bypassed and the outage was total and silent. It is
    the STEADY state on an active/active pair, not a failover transient —
    `filterDHCPConfigForMasterRGs` runs on the 2 s converger as well as on RG
    edges.
  - The v6 refusal carries its **own** message, distinct from the
    authored-multi-interface one, because the remedies differ: "author one
    DHCPv6 group per redundancy group" versus "split this over-broad group".
  - **Never bind a narrowed v6 group to `Interfaces[0]`.** That is the #6520
    cross-bind re-opened for v6: Kea would lease a foreign prefix on the
    survivor's link.
- **Reclamation is GLOBAL per family, NOT per pool.** Kea's
  `expired-leases-processing` is a top-level `Dhcp4`/`Dhcp6` block — there
  is no per-subnet reclamation. The config model therefore attaches to the
  per-family `DHCPLocalServerConfig.ExpiredLeases`
  (`pkg/config/types_system.go`), never to `DHCPPool` (invariant H3).
- **Reclamation is ORTHOGONAL to lease-time (invariant H4).** `valid-lifetime`
  / per-pool `lease-time` set how long a lease stays VALID;
  `expired-leases-processing` sets how aggressively Kea REMOVES leases that
  have ALREADY expired. This slice does NOT touch lease-time — do not
  conflate the two.
- **Config model:** `DHCPExpiredLeasesConfig` carries `Enabled` plus the six
  Kea knobs. The two CAP knobs (`max-leases` → `max-reclaim-leases`,
  `max-time` → `max-reclaim-time`) carry a companion `*Set bool` because in
  Kea **0 means UNLIMITED** there — a value distinct from "omit the key and
  inherit Kea's default" (invariant H2). The model tracks set-vs-unset so an
  operator can express `max-leases 0` (unlimited) distinctly from not
  configuring it; a naive `if x > 0` render would make 0 un-expressible. The
  schema is `dhcpExpiredLeasesSchema()` (`pkg/config/schema_system.go`),
  returned fresh per call so the two parents do not alias a mutable map.
- **Schema floor split (fail-safe):** the three TIMERS (`reclaim-timer`,
  `flush-timer`, `hold-time`) use `ValidateIntegerMin(1)` because a 0 some
  Kea versions reject would take DHCP DOWN on the fail-closed restart; the
  two CAP knobs use `ValidateIntegerMin(0)` (0 = unlimited is documented Kea
  behaviour) and `unwarned-cycles` is `Min(0)`. No schema-only upper cap
  (Kea documents no hard ceiling; min-only validation per the
  `docs/config-schema.md` range policy).
- **Compile:** `compileDHCPExpiredLeases` (`pkg/config/compiler_services.go`),
  handling both the hierarchical and flat-set AST shapes (walk +
  first-value-wins, mirroring `compileDHCPDynamicDNS`); a truly empty /
  garbage block returns nil (no block forced on, nothing rendered —
  closing the empty-tree-compiles-non-nil trap). It runs inside the shared
  `compileExpanded` core, so it lands on BOTH the strict commit and the
  tolerant load / peer-sync compile sites — a peer-synced or stored config
  carrying the block compiles on both (invariant R4); the typed-leaf schema
  gate hard-rejects on commit but downgrades to a warning on Load /
  SyncApply (boot/HA safety, invariant H7).
- **Kea render:** `keaExpiredLeasesMap` (`pkg/dhcpserver/dhcpserver.go`)
  renders the per-family `expired-leases-processing` JSON, or nil when the
  block is absent OR disabled (UNCONDITIONAL omit → byte-identical to
  pre-#1387 output, the cardinal invariant H1). Each numeric field emits
  only when set (an operator tunes one knob without pinning the rest); the
  two cap knobs emit on their `*Set` bool so `max-reclaim-leases: 0`
  (unlimited) is rendered distinctly. `Enabled` with no knobs renders a
  present empty `{}` (Kea reads it as "reclaim with built-in defaults"; the
  block surfaces that the feature is on).
- **No service-lifecycle / HA change.** The block is read by Kea on the
  existing (re)start / reconfigure path exactly like every other generated
  key — no new `systemctl` call, no extra daemon. It is in the
  MASTER-filtered config each node already renders, so it is HA-neutral by
  construction.

**Validation status:** fully unit-tested (golden render for v4/v6,
disabled/absent omit, `max-leases 0` vs unset, per-family independence,
dual-AST compile, schema completion + commit-check floor split, stored /
peer-sync lenient tolerance). End-to-end reclamation against a live Kea
(hand a lease, let it expire, confirm the row is removed within
`reclaim-timer + flush-timer + hold-time`) is lab-deferred — the unit
golden is the binding gate; a `kea-dhcp4 -t <generated.json>` acceptance
check on deploy confirms Kea parses the rendered block.

## Dynamic DNS (DDNS) — #1387, increment 1

> **Moved in #2691 P1a — the DDNS spine now lives in `pkg/ddns`.** The
> reconcile engine (`DDNSManager`, now `ddns.Manager`), the ownership state
> store, the RFC 2136 backend, and the `DNSUpdater`/record/hostname helpers
> were extracted VERBATIM (no behavior change) into `pkg/ddns` — see
> `pkg/ddns/README.md` and `docs/research/ddns-world-class/plan.md` §9. The
> file names in the sections below (`ddns.go`, `ddns_rfc2136.go`,
> `ddns_state.go`, `ddns_dns.go`, `ddns_hostname.go`) now refer to their
> `pkg/ddns` homes (`manager.go`, `backend_rfc2136.go`, `state.go`,
> `backend.go`, `hostname.go`). What STAYS in `pkg/dhcpserver`: the
> state-aware **Kea-memfile lease parser** (`ddns_leases.go` —
> `parseActiveLeases4/6`, entangled with the lease-sync fallback), the config
> compile/merge path, and the thin glue (`ddns.go`) that re-exports the
> cross-package type aliases and injects the lease parser into the engine via
> the `ddns.LeaseParser` seam. `pkg/daemon`'s HA writer gate
> (`ddnsWriterGateOpen`) is unchanged and unmoved.

Opt-in publishing of forward (`A`/`AAAA`) and reverse (`PTR`) DNS records
for active DHCP leases, with stale-record cleanup on expire / release /
decline / reclaim / reassign. Default OFF — an absent `dynamic-dns` block
is byte-for-byte today's behaviour. This is the FIRST increment of the
multi-increment plan in `docs/research/1387-dhcp-ddns/plan.md`
(recommended Path C: a pluggable `DNSUpdater` backend, RFC 2136 first).

What increment 1 ships (the fully unit-testable, lab-free slice):

- **Config model** — `config.DHCPDynamicDNSConfig` (a nilable field on
  `DHCPServerConfig`), compiled from both AST shapes by
  `compileDHCPDynamicDNS` (`pkg/config/compiler_services.go`), typed
  schema leaves under `dhcp-local-server`/`dhcpv6-local-server`
  (`pkg/config/schema_system.go`). TSIG secret is redacted in
  `DHCPDynamicDNSConfig.String()`. The block can appear under BOTH
  families; the typed model carries a single config, and the two blocks are
  MERGED field-by-field (`mergeDHCPDynamicDNS`) — a field set in either
  family wins, `enable` latches on — so a partial second-family block never
  clears the first family's settings (a whole-struct overwrite would
  silently disable DDNS).
- **State-aware lease parser** — `parseActiveLeases4/6` (`ddns_leases.go`)
  honors Kea's `state` column (default/declined/expired-reclaimed), the
  `expire` epoch, and the `fqdn_fwd` split between host-name and
  client-supplied FQDN, and extracts the v6 DUID/IAID identity. SEPARATE
  from the display-only `parseLeaseCSV` — NOT because the display parser
  is unfiltered (since #2085 it also filters non-active state + expired
  rows and dedups per address), but because the two have opposite
  failure postures: the DDNS parser is **destructive** (its empty result
  authorizes deleting owned DNS records), so it must hard-error on a
  mangled / duplicate-column / ragged header; the display parser is
  **non-destructive and lenient** — an exotic or short row must degrade
  to showing what it can, never blank the whole `show`. That leniency is
  enforced at BOTH layers: #2085 made the per-record SEMANTICS lenient
  (dedup/expire/state), and #2154 made the READ itself robust — the
  display parser reads the memfile record-by-record (`csv.Reader.Read`)
  and logs+SKIPS a malformed row (torn/concurrent Kea append, e.g. an
  unterminated quote on the in-progress last line) instead of `ReadAll`'s
  all-or-nothing abort, which used to blank `show dhcp server leases`
  exactly when lease churn was highest. (`FieldsPerRecord = -1` makes a
  short concurrent line a non-event, and `csv.Read` recovers after a
  `*csv.ParseError`, so the skip loop terminates naturally.) The DDNS
  parser keeps the opposite posture by design: there a torn/short row is
  delete-UNSAFE, so it is rejected, not skipped. Merging the two parsers
  would force one posture onto the other (re-opening the #1387
  mass-delete, or blanking the display on one bad row). Header columns are
  matched CASE-INSENSITIVELY (both the header keys AND the lookup name are
  lower-cased in `leaseColumnValue`; field values are data and stay
  verbatim). A header maps to columns UNAMBIGUOUSLY: a DUPLICATE column name
  (case-insensitive) is rejected with an error (Codex r5) — a healthy Kea
  memfile has all-unique columns, and a duplicate would otherwise overwrite
  the earlier index with the last occurrence, so a lookup could resolve to
  the wrong/empty column → wrong desired set → destructive delete. We reject
  ANY duplicate (not just duplicate required columns). Extra/unknown columns
  and a reordered header are TOLERATED (lookups are by name, not position).
  The header is VALIDATED against a FAMILY-SPECIFIC
  `requiredLeaseColumns` set: any column whose absence would silently change
  whether a lease is published (naming), how it is keyed for ownership
  (identity), or whether it is active (state) is REQUIRED, because a mangled
  header parses with no error and the reconciler then deletes/churns owned
  records on the basis of an empty or wrongly-keyed desired set. If any
  required column is missing/renamed the parser returns an ERROR, so
  `Reconcile` marks the family untrusted and SKIPS the destructive diff —
  never mass-delete or record-loss on an unrecognizable header. Required:
  `address`, `state`, `hostname` (both families) + `client_id`,`hwaddr`
  (v4 identity) / `duid`,`iaid` (v6 identity). Deliberately OPTIONAL
  (absence degrades safely, no record loss): `fqdn_fwd` (defaults to
  host-name semantics), `expire` (no expiry tombstoning — `state` still
  gates active/tombstone; over-retain, not delete), `subnet_id` (pure
  metadata, not compared by `recordsEqual`). The header is validated BEFORE
  the zero-data-row early return (Codex r4), so the trusted-empty result —
  which is what PERMITS `Reconcile` to clear a family's owned records — is
  returned ONLY when the lease set is provably empty: the file is genuinely
  MISSING (`os.IsNotExist`, "no leases yet"), OR the header is present AND
  valid AND there are simply no active data rows (a genuinely-drained Kea).
  A present-but-mangled header errors WITH OR WITHOUT data rows (so a
  header-only mangled file cannot short-circuit to trusted-empty), and a
  0-record EXISTING file (no header at all — anomalous, mid-write/corrupt)
  fails SAFE as an error rather than trusted-empty. Per-ROW conformance
  (Codex r6) complements the header-schema check: a DATA ROW too short to
  supply every required column (a torn/truncated memfile append — the CSV
  reader allows ragged rows) would otherwise read a required column as ""
  (bounds-safe via `leaseColumnValue`'s `idx < len(fields)`, but NOT
  delete-safe — the lease silently drops and its owned record is deleted).
  So a row with `len(fields) <= maxRequiredIdx` (the max index among the
  family's required columns) is a hard parse error → the whole family's
  source is untrusted → the destructive diff is skipped; we do NOT silently
  skip just the row (we cannot know which lease it is, and skipping still
  drops its record). A row with MORE fields than the header is tolerated
  (extra trailing fields ignored by name-based lookup). The fail direction
  (over-mark-untrusted for an exotic/unreadable file → no publish/clean,
  operator-visible) is SAFE; silent mass-delete/record-loss is not. The
  destructive-delete class is now closed at BOTH the header level (required
  columns present, each once, no duplicates) and the row level (every data
  row long enough to supply every required column).
- **Kea LFC file-set snapshot (#5796)** — Kea never rewrites the memfile in
  place; it APPENDS every renewal/release/decline/reclaim and periodically runs
  Lease File Cleanup (`kea-lfc`) to compact the log. During and after a cleanup
  the live lease set is NOT the current file alone — it spans Kea's LFC file
  set. For a current lease file `<f>` (authoritative from Kea src
  `memfile_lease_mgr.cc appendSuffix` / `LFCFileType`): `<f>.1` is the INPUT file
  (the current file the server moves aside at the START of a cleanup) and
  `<f>.2` is the PREVIOUS file (the COMPACTED result of the last COMPLETED
  cleanup, one row per active lease); `.output`/`.completed`/`.pid` are kea-lfc
  scratch/markers with no lease union and are ignored. Reading only `<f>` LOST
  every lease living in `.2`/`.1`: right after LFC rotates the current file it
  is a fresh, often header-only append log while the active leases sit in the
  compacted previous file — so a valid header-only current file wrongly read as
  a trusted-empty set would authorize the DDNS reconciler to MASS-DELETE every
  owned A/AAAA/PTR (fail-open). BOTH the destructive `parseActiveLeases4/6` and
  the display `parseLeaseCSV` now read the whole set via the one shared
  `keaLFCLeaseFilePaths` (`lease_lfc.go`) in Kea CHRONOLOGICAL order — PREVIOUS
  (`.2`) → INPUT (`.1`) → CURRENT (`<f>`), oldest first — and replay the rows
  through the SAME append-only, last-row-wins dedup, so a newer row in the input
  or current file supersedes an older row in previous and a release/expiry row
  still tombstones a lease a later re-allocation reclaims. A missing `.1`/`.2`
  (the common no-LFC steady state) collapses the set to exactly the current file
  (byte-identical to the pre-#5796 read). The fail-safe posture is preserved and
  EXTENDED across the set: any EXISTING sibling that is headerless / mangled /
  ragged makes the WHOLE family untrusted (error → destructive diff skipped),
  and the trusted-empty result is returned only when every existing file in the
  set validates AND the merged active set is empty. `readSyncLeasesViaMemfile`
  (the HA lease-sync fallback) inherits the union through `parseActiveLeases`.
  The #5796 residual invariants 2/3/8 are now CLOSED (#5938):
  - **Invariant 2 — live `lease_cmds` socket preference (display):** when the
    `lease_cmds` hook is EXPECTED (lease-sync enabled), the display path
    (`getDisplayLeases` → `GetLeasesWithSource{4,6}`, `lease_source.go`) queries
    the authoritative live lease DB (`lease{4,6}-get-all` over the control
    socket, reusing the HA-sync `keaControl` plumbing) and only falls back to the
    memfile file set when the socket is unavailable. On a box WITHOUT the hook the
    memfile is the normal source, so a memfile read there is NOT flagged degraded.
    (The HA-sync `getSyncLeases` already preferred the socket; this extends the
    same discipline to the display.)
  - **Invariant 3 — crash-interrupted-cleanup safety:** the reader IGNORES
    kea-lfc's `.output`/`.completed` intermediates. This is proven safe by an
    exact argument (documented at `keaLFCLeaseFilePaths`, `lease_lfc.go`): every
    lease reachable through `.output` is a subset of `.1 ∪ .2` (kea-lfc builds
    `.output` by merging them) which the reader already ingests, and the atomic
    `.output → .2` swap means no active lease is ever reachable ONLY through an
    intermediate — so a torn cleanup never presents a stale-yet-authoritative set.
    No generation protocol is needed for this read-only path. Pinned by
    `TestKeaLFCIntermediatesIgnored_5938`.
  - **Invariant 8 — degraded-source display banner:** a `LeaseSource`
    (`lease_source.go`) is threaded from the read to BOTH the gRPC
    `show dhcp server` handler AND the in-process interactive CLI (#5967 achieved
    this parity — see below); when the source is degraded — the expected live
    socket was unavailable (memfile fallback in use) OR a present LFC sibling was
    unreadable and skipped — a one-line banner is printed above the lease table so
    a partial display is never mistaken for a healthy empty set. The memfile
    file-set read on the display path is now degrade-TOLERANT
    (`parseLeaseCSVDegradable`): an unreadable sibling is skipped (recorded) rather
    than blanking the whole show. Both surfaces select which banner(s) to print
    through the shared `DegradedBanners(src4, src6)` helper (`lease_source.go`),
    which emits one line per DEGRADED family (v4 then v6) and collapses an exact
    duplicate — so when BOTH families are degraded with DISTINCT reasons the
    v6-specific detail is not suppressed (#5967 PART 2; the pre-#5967 handlers
    used `if src4 else if src6` and dropped the v6 detail).
  - **#5967 — local-CLI display parity:** the in-process interactive
    `show dhcp server` (`pkg/cli/show_services_dhcp.go`) now reads through
    `GetLeasesWithSource{4,6}` + `DegradedBanners`, matching the remote `cli` →
    gRPC path. Before #5967 it called `GetLeases{4,6}` (memfile only, no live-
    socket preference, no banner) and surfaced a read failure only as a
    `warning: could not read ... leases` line — so a degraded read on this surface
    alone looked like a healthy empty set. The #4908 "a degraded read is never
    rendered as a clean empty table" invariant is now carried by the shared
    degraded banner instead of the per-family read warning. (The local handler
    still builds a throwaway `dhcpserver.New()` manager with no hook context, so
    the live-socket preference is inert there; the banner — the operator-visible
    signal — is what reaches parity.)
- **Hostname normalization** — `deriveFQDN` / `finalizeFQDN`
  (`ddns_hostname.go`) ALWAYS contains the published name in the configured
  zone: the client picks the host part, the firewall picks the domain. A
  client-offered dotted name (e.g. `host.attacker.tld`, a trailing-dot or
  double-dot escape) that is not already within the configured domain is
  relabeled to `<first-label>.<domain>`; a name already inside the zone is
  kept verbatim. With no configured domain, only the first label is kept. A
  client can never publish outside the configured zone.
- **`DNSUpdater` interface** (`ddns_dns.go`) + the pure record/PTR-name
  construction. PTR names are built from the TEXTUAL address (reversed
  octets / nibbles), NOT the dataplane native-endian `__be32` convention. A
  nil updater (the increment-1 default — the live backend is deferred) is
  substituted with a `nopUpdater`: every upsert/delete is a LOGGED no-op,
  never a panic, and a no-op upsert does NOT record phantom ownership (so a
  later real backend still publishes the record).
- **Reconciler core** — `DDNSManager.reconcileOnceLocked` (`ddns.go`):
  build-desired / diff-owned / add-move-reassign-expire transitions,
  cleaning the old owner before the new one, with bounded retry that never
  wedges the loop. FAIL-SAFE: when a lease family's CSV cannot be
  read/parsed, that family is marked untrusted and its destructive diff is
  SKIPPED this cycle (a transient malformed CSV can never mass-delete a
  family's owned records); the parse error is surfaced to the caller.
- **Ownership state store** — `ddns_state.go`, JSON via
  `fsatomic.WriteFileDurable` (fsync-on-write; slow-path). This is the
  PROTECTION BOUNDARY for never-delete-a-record-xpf-did-not-create:
  `deleteOwnedLocked` re-derives the EXACT (name, type, address) from the
  store and is the sole delete authority. A corrupt store fails OPEN
  (reset to empty + log), never blocking commit/boot/DHCP serving. The
  stored `version` is validated on load: an unknown (future) non-zero
  version is treated like a corrupt store (fail-open to empty + warn), so a
  later format bump cannot be mis-decoded into wrong-tuple deletes. (A
  fail-open store may LEAK previously-owned records — they stay in DNS until
  authoritatively removed; record TTL is resolver caching, not removal — but
  never deletes records xpf did not create.)
  **Write-ahead durability (#2662).** Ownership of a published RR is durable
  BEFORE the wire add, not only at the end of the reconcile pass.
  `upsertLocked` persists the ownership intent (`PTRPending=true`) and
  `save()`s it BEFORE calling `UpsertLease`, then confirms (clears
  `PTRPending`) with a second save after a fully-successful add. This closes
  the crash-after-add ORPHAN window the old end-of-pass-only save left: a
  crash / kill / disk-full / `WriteFileDurable` failure between a successful
  DNS add and any later save can no longer strand a LIVE RR with no durable
  ownership. On restart the durable record says "xpf owns X", so a later
  reconcile re-adds (idempotent) or a release deletes it — and deleting a
  maybe-uncreated RR is safe (the #2648 DHCID-match / exact-RR delete
  prerequisite fails on a non-existent RR, a no-op). A REFUSED add
  (`errDDNSConflictRefused`) removes the pre-written intent so no phantom
  ownership survives (a phantom would let a later release delete a third
  party's record); a FAILED pre-write suppresses the publish entirely (the
  record is reported "not safely owned" and retried next cycle — xpf never
  publishes a RR it could not first record ownership for). Deletes do not
  write-ahead: a delete leaves "ownership without a live RR", which the
  idempotent re-delete on the next pass self-heals — never an orphaned live
  RR.
- **Counters** via `DDNSManager.Stats()` (the `show ... dynamic-dns`
  + Prometheus surface reads this).

Net behaviour change for existing users in increment 1: zero.

## Dynamic DNS (DDNS) — #1387, increment 2 (live backend + loop + HA gate)

Increment 2 (`docs/research/1387-inc2-ddns-backend/plan.md`) turns the
lights on: a LIVE RFC 2136 backend, a daemon reconcile loop driving it from
real Kea lease events, a NODE-LEVEL HA single-writer gate, and the
Prometheus + `show` observability surface. The increment-1 reconciler core,
ownership store, and `DNSUpdater` interface are UNCHANGED — Inc-2 only wires
a real updater behind them and a real loop in front.

What increment 2 ships (the feasible, CI-testable slice):

- **Live RFC 2136 backend** — `rfc2136Updater` (`ddns_rfc2136.go`),
  implementing the existing `DNSUpdater` interface with `github.com/miekg/dns`.
  An UpsertLease is an idempotent EXACT-RR ADD of the A/AAAA forward record
  + the PTR reverse record; a DeleteLease is the symmetric EXACT-RR delete
  (RFC 2136 §2.5.4, TTL=0 / CLASS=NONE). The backend NEVER issues a
  delete-RRset or delete-name, so a manually-added co-resident record on the
  same name is never collateral — the R1 cardinal-sin boundary holds on the
  wire. TSIG (when a key is configured) is signed via `TSIGSecret.Reveal()`
  with a supported HMAC algorithm (sha1/224/256/384/512; hmac-md5 rejected as
  insecure; default hmac-sha256). UDP-first with a TCP retry on truncation
  that is derived from the CALLER's context (so a canceled/deadline'd reconcile
  pass cancels the in-flight retry), a bounded per-call timeout, and
  conflict-policy handling (replace-owned = DHCID ownership-proving add/delete,
  see below; skip-existing = no-RRset prerequisite, REFUSE on collision via the
  same sentinel so no phantom ownership is recorded, see below; strict-fail =
  error on collision). The backend is STATELESS beyond its config — all
  ownership lives in the unchanged state store.

  **`replace-owned` DHCID ownership (RFC 4701 / RFC 4703, #2648).** The
  default `replace-owned` policy no longer sends a BARE RFC 2136 Insert. A bare
  Insert is unsafe because DNS RRsets are set-like: if a third party had
  already published the identical A/AAAA, the add succeeded idempotently, xpf
  recorded ownership, and a later release deleted a record xpf did not create —
  breaking the never-delete-non-owned boundary on the wire. The fix writes an
  RFC 4701 DHCID resource record alongside the A/AAAA as an on-wire ownership
  marker. The DHCID RDATA is `identifier-type(2B) || digest-type=SHA-256(1B) ||
  SHA-256(client-identity || canonical-FQDN-wire-form)`, where the client
  identity is the same stable lease identity (v4 client-id‖hwaddr, v6
  DUID/IAID) the reconciler keys ownership on, threaded through
  `LeaseDNSRecord.ClientID` and persisted in the ownership store as
  `ownedRecord.ClientID` so a delete recomputes the SAME DHCID. The RFC 4701
  §3.3 identifier-type code is derived from the lease-identity form: `0x0002`
  (DUID) for a v6 `duid:` identity, `0x0001` (DHCPv4 client-identifier option)
  for a `cid:` identity, `0x0000` (htype+chaddr) for the `mac:` hwaddr
  fallback. **Residual**: the digest is computed over xpf's canonical identity
  STRING (the parser's prefixed colon-hex form), not the raw DHCP option byte
  stream RFC 4701 §3.5 specifies, so cross-vendor DHCID *digest* match on a
  shared name (ISC Kea / Windows DHCP) is best-effort — but the identifier-type
  is RFC-correct, xpf is internally consistent (same lease ⇒ same DHCID across
  add/delete, which is all the ownership boundary needs), and a non-matching
  foreign DHCID is treated as "owned by another party" and left untouched (the
  SAFE direction). A byte-exact digest would require threading the un-mangled
  DHCP option through the lease parser; deferred as an interop enhancement.

  - **On add** (`sendAddOwned`): the RFC 4703 §5.3.2 two-attempt sequence —
    prerequisites are AND-combined in one message, so "DHCID matches OR name
    unused" cannot be a single message. Attempt A adds A/AAAA + DHCID under a
    NAME-NOT-IN-USE prerequisite (a fresh name we may claim). On a name-exists
    collision, Attempt B retries under a DHCID-MATCHES-OURS prerequisite (a
    value-dependent RRset-exists prereq), which succeeds only for a name WE
    already own. If neither holds — a third party owns the name (different or
    absent DHCID) — the add is REFUSED: `sendAddOwned` returns the
    `errDDNSConflictRefused` sentinel (counting the conflict). The manager's
    `upsertLocked` classifies that sentinel as a skip (not a success, not a
    hard failure) and records NO ownership in the state store. This is what
    closes #2648 MAJOR-1: a refused add must NOT record phantom ownership,
    because a later release of phantom-owned state would delete a record xpf
    did not create — and for a **no-identity** lease the delete has no
    DHCID-match guard, so that delete actually fires. No phantom ownership ⇒
    no later delete.
  - **On delete** (`sendRemoveForward`): the forward A/AAAA + DHCID are removed
    under a DHCID-MATCHES-OURS prerequisite. If the on-wire DHCID is not ours
    (or absent — a manual record), the prerequisite fails and the delete is
    SKIPPED + counted. This is a SECOND, on-wire guard on top of the
    store-driven `deleteOwnedLocked` authority, closing the narrow race where a
    third party adopted the exact name+address between xpf's add and release.
  - **No client identity**: when a lease carries no stable identity there is no
    DHCID to write; the add falls back to the name-not-in-use prerequisite
    alone (still never adopting a pre-existing third-party RR) and the delete
    falls back to the plain exact-RR delete of the firewall's own tuple.
  - **Reverse PTR** records carry no DHCID (RFC 4701 binds the marker to the
    forward owner name); they remain idempotent exact adds / exact-RR deletes.

  **`skip-existing` refusal sentinel (#2660).** `skip-existing` prepends an
  RFC 2136 `RRsetNotUsed` ("name not in use") prerequisite to the Insert. On a
  `YXRRSET`/`YXDOMAIN` collision the name already exists — a third party owns
  it — so `sendAdd` now REFUSES by returning the SAME `errDDNSConflictRefused`
  sentinel `replace-owned` uses (and counts the conflict). It used to return
  `nil`, which `upsertLocked` reads as a SUCCESS and records phantom ownership.
  That is the #2648/#2659 boundary breach on the skip-existing path: skip-
  existing NEVER writes a DHCID, so the phantom-owned record's later release
  takes `sendRemoveForward`'s `!hasDHCID` plain exact-RR delete branch and
  DELETES the third party's RR. Returning the sentinel makes `upsertLocked`
  record NO ownership (the same skip classification as replace-owned), so no
  later delete is ever constructed. A FRESH (unused) name still publishes
  normally and is owned — only a collision is refused. This is the #2648
  mechanism extended to skip-existing.
- **Zone surface** (plan §11 Q1): the forward zone is the configured
  `Domain` ONLY when the lease's FQDN is actually under it (an out-of-domain
  `ClientFQDN` derives its own parent zone instead of being misrouted into the
  domain, which the authoritative server would reject NOTAUTH); the reverse
  zone is the canonical in-addr.arpa/ip6.arpa derived from the PTR name. A
  reverse-zone NOTAUTH/REFUSED (a reverse zone we do not own, e.g. delegated to
  an ISP) is a COUNTED SKIP
  (`skipped_total{reason="ptr-notauth"}`), NOT a blocking error — the forward
  add still succeeds and the lease's reconcile is not failed (plan §11 Q6).
  The zone-resolution helpers take an optional explicit zone list (always
  empty in Inc-2) so explicit `forward-zone`/`reverse-zone` leaves are a
  purely additive follow-up.
- **Resolve-per-Reconcile** (plan §6 fork 1): the always-on production
  manager (`NewProductionDDNSManager`) rebuilds the live backend from the
  current policy at the START of each Reconcile, so a commit-time
  backend-config change takes effect on the next cycle with no swap race, and
  the SAME manager serves both the disabled (nopUpdater) and enabled states —
  an enabled→disabled commit (keeping the backend config) still resolves a
  live backend and runs `withdrawAllLocked` through it.
- **Withdraw never goes through the nop while records are owned**: removing the
  WHOLE `dynamic-dns` stanza leaves no update-server/TSIG to build the live
  backend from, so the per-Reconcile factory resolves a `nopUpdater`. Reconcile
  must NOT replace a still-live updater with that nop before withdrawing —
  doing so would drop the ownership entries while sending NO real DNS delete,
  orphaning the published records. The guard in `Reconcile` keeps the existing
  live updater for the withdraw cycle when the newly-resolved updater is a nop
  AND records are still owned; the swap to nop happens on the next cycle once
  nothing is owned.
- **Daemon reconcile loop** (`pkg/daemon/daemon_ddns.go`,
  `runDDNSReconcileLoop`): an ALWAYS-ON guarded background goroutine modeled
  on the neighbor periodic loop. It ticks on a 30s poll AND is nudged for an
  immediate pass on config commit and on VRRP MASTER takeover. Each pass runs
  in a guarded skip-if-in-flight goroutine with a per-pass context timeout, so
  a hung DNS server can never wedge the loop or starve the nudge channel. It
  does FILE I/O (the Kea memfile CSVs) + DNS network ONLY — it NEVER touches
  the userspace-helper control socket, so it cannot starve session installs
  (CLAUDE.md control-socket rule).
- **NODE-LEVEL HA single-writer gate** (`ddnsWriterGateOpen`, plan §4.3): this
  node reconciles DDNS from its own Kea memfile(s) IFF it is MASTER for ≥1 RG
  (standalone is always the writer). This is SOUND without any per-lease RG
  attribution because the Kea config each node serves is rendered
  MASTER-FILTERED (`filterDHCPConfigForMasterRGs`), so a node's memfile holds
  ONLY its own MASTER-RG leases — the two nodes' input sets are disjoint by RG
  ownership, so dueling writers are impossible. The gate reads
  `snapshotRethMasterState` ONLY (the same source the Kea manager uses), never
  the `subnet_id` (which is now reload-stable per #2668, but the gate still
  reads RG master state, not the ID). A BACKUP-for-all
  node STOPS WRITING — it does NOT withdraw valid records (the peer MASTER
  owns them; deletion is lease-state / config-removal driven only). The
  async-takeover ordering (Kea `ApplyAsync` may lag the DDNS nudge) is benign:
  the reconcile is store-driven and add-only-from-current-leases, so a
  too-early pass against a not-yet-repopulated memfile issues ZERO deletes.
- **Observability** — `xpf_dhcp_ddns_*` metrics through the CHECKED API
  collector (`collectDDNSMetrics`, `pkg/api/metrics_system.go`):
  `upserts_total{result}`, `deletes_total{result}`,
  `reconcile_runs_total{result}`, `skipped_total{reason}`, `owned_records`,
  `last_reconcile_timestamp_seconds`, `last_reconcile_leases`. Label
  cardinality is CLOSED: `result` ∈ {ok,fail}; `reason` ∈
  {no-name,no-backend,conflict,ptr-notauth}. `show system services
  dhcp-server dynamic-dns [detail]` renders the config summary + counters
  (and, in detail, the owned records) via the in-process CLI and the gRPC
  `ShowText` topic.
- **Retired the deferred-backend commit warning** and replaced it with live
  WARN-only validation (`validateDDNSBackendWarnings`,
  `pkg/config/compiler_validate_warn.go`): enabled rfc2136 with no
  update-server, a malformed update-server, an unsupported TSIG algorithm, an
  INCOMPLETE TSIG tuple (`tsig-key` without `tsig-secret`, or `tsig-secret`
  without `tsig-key` — #2666/#2691 P0; RFC 8945 requires the full {key name,
  algorithm, secret} triple), and the still-deferred kea-d2 backend each WARN
  (never error, so a previously-inert malformed value cannot brick a boot —
  plan §7 Q-C).

LAB-GATED (NOT in this PR — flagged for the merge gate, plan §9.2/§9.3):

- Live Kea→DNS end-to-end on the loss cluster (a real kea-dhcp{4,6}-server
  handing a real lease, publishing to a throwaway authoritative BIND/Knot,
  `dig` resolving the A + PTR, then expiry/reassign removing them).
- `make test-failover` WITH DDNS enabled — the mandatory cluster gate
  (CLAUDE.md: any change touching the HA/VRRP transition path). The
  in-process responder proves the wire format + single-writer correctness;
  the lab proves the no-dueling-writes + reconcile-on-takeover timing.

Still deferred (Inc-3+):

- The Kea D2 backend (reserved `backend kea-d2` enum; D2 is not in the
  image, `bake.py`) — still WARN-deferred.
- Explicit `forward-zone`/`reverse-zone` + `publish-ptr` config leaves — an
  additive follow-up; the zone-resolution helpers already take the optional
  list so the follow-up wires straight in.

## HA lease synchronization (#2239) — `lease_sync.go`

This package owns the KEA side of #2239 cross-chassis DHCP-server lease sync
(PATH C). The cluster wire + standby-hold + takeover orchestration live in
`pkg/cluster` + `pkg/daemon`; here:

- `SetLeaseSyncEnabled(bool)` — when set (the daemon flips it from the cluster
  `dhcp-lease-synchronization` knob before an apply), `generateKea{4,6}Config`
  injects a unix `control-socket` + the `libdhcp_lease_cmds.so` hook
  (`addLeaseSyncStanza`). Knob-off / standalone renders bit-identical to
  pre-#2239 (no socket, no hook). `memfile` stays `persist=true`.
- `GetSyncLeases{4,6}(ctx, now)` — read the active lease set, preferring the
  control socket (`lease{4,6}-get-all`) and falling back to the
  destructive-safe memfile parser (`parseActiveLeases`) when the socket is not
  up. Each `SyncLease` carries REMAINING LIFETIME (`expire - now` on the
  reader's clock), never an absolute epoch — the clock-skew-immunity invariant.
  Expired / non-active leases are dropped at read time. The v6 fallback
  PRESERVES the lease kind: it reads the memfile `lease_type` (0=IA_NA,
  1=IA_TA, 2=IA_PD) and `prefix_len` columns and maps them to
  `SyncLease.LeaseType` / `PrefixLen` exactly as the socket path does, so an
  IA_PD prefix-delegation lease read during the socket-down window is no longer
  mis-seeded as an IA_NA address lease (#2262). A present-but-unparseable
  `lease_type` is fail-closed: the row is skipped (logged), never defaulted to
  IA_NA. An absent/empty column (old memfile, v4) stays IA_NA-equivalent.
  The v6 owner identity (`splitV6Identity`, `"duid:DUID/IAID"`) is fail-closed
  the same way (#2379): a present-but-unparseable IAID (non-decimal, empty,
  oversized) returns an error and the row is skipped (logged), never silently
  defaulted to IAID 0 — because 0 is a valid IAID, swallowing the parse error
  would seed the peer's Kea lease DB with the wrong IAID on takeover and a
  non-zero-IAID client could fail to renew with nothing logged. The legitimate
  "no IAID present" form (`"duid:DUID"`) stays a clean IAID 0.
- `SeedSyncLeases{4,6}(ctx, leases, now)` — write held peer leases into a
  just-started Kea via `lease{4,6}-add` (→ `lease{4,6}-update` on collision,
  idempotent), re-anchoring `expire = now + remaining` on the LOCAL clock.
  Faithful v6 identity (DUID/IAID/`type`/`prefix-len`, so IA_PD is synced).
- `PreSeedMemfile{4,6}(leases, now)` — write the held leases into the Kea
  memfile CSV (canonical header) BEFORE Kea start so it loads the in-use
  bindings at boot and can never hand an in-use address to a different client
  even in the pre-`lease-add` window (the duplicate-allocation-window closer).
  Durable (`fsatomic.WriteFileDurable`). **Chowned to the Kea runtime user
  (#2450):** xpfd runs as root but distro Kea runs unprivileged (`_kea` on
  Debian/Ubuntu, `kea` on RHEL-family) and opens its memfile lease DB for
  READ+WRITE at startup; a root-owned 0640 pre-seed would be unreadable by Kea
  → it fails to start (EACCES) on the node that just took over → DHCP outage at
  failover. The pre-seed therefore resolves the Kea user once (cached) and
  installs the file already owned by it (0640 + owner=_kea ⇒ owner RW). The
  chown rides on the `fsatomic` temp fd (`fsatomic.WithOwner` fchowns BEFORE
  the rename), so the FINAL renamed inode is _kea-owned atomically — no
  post-rename root-owned window and no orphaned root-owned temp. Best-effort
  when the Kea user is absent (dev host / Kea not installed): one warning is
  logged (once per process, in the cached owner resolution — not per pre-seed,
  so an absent-user takeover does not warn twice for v4+v6 or again on every
  later takeover), the file is written without the owner override, and
  **takeover is never aborted**. Both the v4 and v6 memfiles are covered.
  The v6 WRITE side (memfile pre-seed AND `lease6-add`) encodes the lease kind
  SYMMETRICALLY with the read side: `stringToKeaLeaseType` is the exact total
  inverse of the read path's `keaLeaseTypeToString`, so IA_NA / IA_TA / IA_PD
  all round-trip (read IA_TA → write `lease_type=1`, not a downgrade to IA_NA).
  Both write callers go through this one inverse so the read↔write mapping
  cannot drift to re-introduce the #2268 IA_TA downgrade. Only IA_PD carries a
  delegated `prefix_len`; IA_NA and IA_TA are full `/128` address bindings, so
  their `prefix_len` column is 128. An unknown lease-type string falls back to
  IA_NA (logged), never silently mis-typed. The v6 pre-seed also emits the
  lease hardware address in the canonical `hwaddr` column (field 13 of
  `keaMemfileHeader6`), matching the v4 writer — `SyncLease.HWAddress` is
  populated for v6 leases (`keaLeaseToSync` sets it for both families), so a
  takeover no longer strips the MAC from every IPv6 lease (#2386). DHCPv6 keys
  on DUID so the lease itself was never lost, but the empty column dropped
  hwaddr-based logging / reservation matching / operator visibility.
- `WaitControlSocket{4,6}(ctx, within)` — bounded readiness wait before the
  post-start seed.

**Memfile CSV schema is pinned as external ground truth (#2261).** The live
Kea loader reads the pre-seeded memfile POSITIONALLY, so `keaMemfileHeader{4,6}`
must be byte-exact against the Kea 3.0.x schema (the appliance ships kea-common
live-verified at 3.0.3) or the promoted node fails to load the standby's leases
on failover. `TestKeaMemfileHeadersMatchKea30xSchema` asserts both consts equal
a LITERAL golden header transcribed from the Kea source of truth (lease4 = 12
cols, lease6 = 18 cols), NOT derived from the const itself — so a co-drift of
the header const AND the writer (which the older self-referential positional
tests cannot catch) fails the golden. The remaining live acceptance — a real
DHCP client keeping its binding across a hard failover with the knob ON — is
lab-gated (plan-deferred-lab on #2261); its steps are codified as a manual
harness in `test/incus/dhcp-lease-failover.sh` (not in `make test`/CI: it
reboots a shared-cluster node and needs a DHCP-client fixture).

All of these talk ONLY to KEA's own unix control socket (or the memfile) —
NEVER the userspace-helper control socket (CLAUDE.md rule), so they cannot
starve session installs. All seed/read errors are fail-open (logged + counted
by the daemon; serving is never blocked). Test seams:
`SetLeaseSyncSeamsForTesting` injects a stub dialer + paths.

**Cluster enablement fixes (#4647, found via the #2261 live smoke).** The
memfile loader itself was correct; two bugs in the surrounding daemon-side
enablement plumbing (`pkg/daemon`) meant the feature never engaged with the
canonical config:

- **BUG A — untagged `reth1.0` never matched the master-RG filter.**
  `filterDHCPConfigForMasterRGs` (`daemon_ha.go`) keeps a `dhcp-local-server`
  group only if its resolved interface belongs to a MASTER RG. For an UNTAGGED
  reth unit, `rethInterfacesForRG` emits the bare member `ge-0-0-1`, but
  `resolveDHCPRethInterfaces` resolves `reth1.0` → `ge-0-0-1.0` (ResolveReth
  keeps the `.0`). The exact string compare failed, the group was dropped, and
  `clearFamilyLocked` wiped `/etc/kea/kea-dhcp4.conf` even though the RG was
  MASTER — so DHCP-server-in-cluster was non-functional with the canonical
  `interface reth1.0` in `docs/ha-cluster-userspace.conf`. The fix normalizes a
  trailing `.0` (untagged unit) on BOTH sides of the compare
  (`stripUntaggedUnitSuffix`) AND keeps the normalized bare member in the kept
  set — `ge-0-0-1` is the real kernel device Kea binds to; `ge-0-0-1.0` is not a
  device.

  **#9407 corrected the tagged half of this note, which was wrong.** It used to
  read "a TAGGED unit (`reth1.100` → `ge-0-0-1.100`) is left intact and still
  matches only its VLAN member". It did not match anything.
  `rethInterfacesMatchingRG` has always emitted `<member>.<vlan-id>`, while
  `resolveDHCPRethInterfaces` emitted `<member>.<unit-number>` — the two
  coincide only when the operator numbers the unit after the VLAN. Measured on
  `unit 80 { vlan-id 180; }`: the RG side produced `ge-0-0-1.180`, the Kea side
  `ge-0-0-1.80`, so the compare missed BOTH `masterIfaces` and `rgScoped`, and
  the filter's #6520 "not RG-scoped implies node-local, always keep" arm kept
  the group **on a node mastering nothing** — the opposite of BUG A's symptom,
  from the same mismatch. `resolveDHCPRethInterfaces` now uses
  `Config.ResolveKernelIfName`, which owns the `.<vlan-id>` arm, so both sides
  derive the same name. `stripUntaggedUnitSuffix` stays as a belt; for a
  declared unit it is now a no-op.
- **BUG B — runtime knob-flip was a silent no-op.** The `#2239` lease-sync push
  loop (`runDHCPLeaseSyncLoop`) was launched ONLY from the cluster
  connect-time block, gated on the knob at connect. A runtime `set chassis
  cluster dhcp-lease-synchronization; commit` on a RUNNING cluster left the loop
  unstarted (counters stayed 0/0 until an xpfd restart). The apply path now
  reconciles the loop against the just-committed knob via the idempotent
  `ensureDHCPLeaseSyncLoop` (shared with the connect-time launch, so it cannot
  double-launch): a knob-ON commit (re)launches it against the live comms
  context, a knob-OFF commit stops it, without a restart.

## Callers

`pkg/daemon` (constructs the always-on `DDNSManager`, runs the reconcile
loop, owns the node-level HA gate, exposes `DDNSStats`/`OwnedDDNSRecords` to
the API/CLI; for #2239 it sets `SetLeaseSyncEnabled`, runs the lease-sync push
loop, and drives the pre-seed + takeover seed), `pkg/cluster` (#2239 holds the
peer `SyncLease` set), `pkg/cli`, `pkg/grpcapi`, `pkg/api`.

## Dependencies

`pkg/config` and `pkg/fsatomic` (the latter for the Kea config writes and
the #1387 DDNS ownership state store). The #1387 inc-2 live RFC 2136 backend
adds `github.com/miekg/dns` (DNS UPDATE construction + TSIG signing).

## Gotchas

- Config is regenerated fully on every `Apply()` (no diff). The Kea config
  schema is JSON-based, so this is cheap.
- **`dhcp-socket-type` defaults to unset, so Dhcp4 runs Kea's default
  `raw` (#6460, opt-in knob added in #7318).** Unless the operator sets
  `system services dhcp-local-server dhcp-socket-type`,
  `interfaces-config` carries only the `interfaces` list and the key is
  not emitted at all. AF_PACKET delivery happens BEFORE the netfilter
  input hook, so on the default the `xpf_hostinbound` chain cannot gate
  DHCPv4 at all — a zone whose `host-inbound-traffic system-services`
  omits `dhcp` does **not** stop this server answering on an interface
  its group binds.

  Precisely, and this is easy to state wrongly: the input hook is not
  *skipped*. Measured on a live node (#7318), an INPUT drop at priority
  -100 for `udp dport 67` COUNTED the packet — on both the
  `255.255.255.255` and the interface-unicast destination — and Kea
  answered anyway. netfilter sees the packet and drops it; it just drops
  a copy Kea never reads, because AF_PACKET took its own copy at
  `ptype_all`, before `ip_rcv`. That is why no nft rule can ever fix
  this, and it is a different claim from "the packet never reaches the
  chain".

  Note the raw socket's LPF admits **broadcast OR unicast to the
  interface's own address**, so the relayed/renewing unicast leg is
  ungateable too — not just the broadcast DISCOVER.

  Setting `dhcp-socket-type udp` moves Dhcp4 onto an ordinary UDP socket
  that does traverse the input hook, at which point the zone's `dhcp`
  token governs the server path. It is opt-in and **not** a default flip
  because, per Kea's documentation, UDP sockets "can be used for relayed
  traffic only" — directly-attached clients with no address yet stop
  being served. `validateDHCPSocketTypeWarnings` states that trade at
  commit time. Dhcp6 has no
  raw mode but is addressed at the `ff02::1:2` multicast group, which
  matches no per-zone unicast `daddr` rule and falls through the input
  chain's accept policy — same outcome, different mechanism. A
  commit-time advisory names the mismatch
  (`validateDHCPServerHostInboundBypassWarnings`); see
  `docs/host-inbound-multicast.md` "The DHCP-server sibling (#6460)".
  Do not switch Dhcp4 to `udp` to "fix" this: UDP sockets cannot serve
  clients that have no address yet, so it is a behaviour change with its
  own migration, not a bug fix.
- If the typed config drops the DHCP server entirely, `Apply()` stops the
  service and removes the config file. Running Kea processes are not
  killed via SIGKILL — systemd manages the lifecycle.
- The manager keeps NO process-local running state (#1778). All
  start/stop decisions reconcile against `systemctl is-active`, so a
  stale Kea left over from a previous daemon is stopped on the first
  `Apply`/`Clear` after restart. Every `systemctl` shell-out is
  bounded by a 15s timeout (#1794).
- Commit semantics: in standalone mode `pkg/daemon` calls `Apply`
  unconditionally on every config apply and surfaces its error
  through the commit (fail-closed); the boot path logs the error and
  continues, so an unavailable Kea binary cannot brick daemon boot.
  In cluster mode the commit path calls `ApplyClusterCommit`
  (#1835 F3) with the master-RG-filtered config: configs are always
  regenerated, but units restart only if currently active (this node
  is serving) — also fail-closed. VRRP MASTER/BACKUP transitions own
  start/stop via `ApplyAsync`.
- **Failed applies had no converger (#6535).** In cluster mode every
  Kea driver is an EDGE: `applyRethServicesForRG` /
  `clearRethServicesForRG` run only under `if tr.Changed`,
  `applyDirectVIPOwnership` only on an ownership change, and
  `ApplyClusterCommit` only when an operator commits. The async worker
  logs an apply error and drops it — it does not retry. So a failover
  whose Kea apply failed left the wrong node serving: persistent
  dual-DHCP (both nodes' Kea up) or no-DHCP (neither), until the next RG
  transition or commit. Neither happens on its own.
  The fix pairs a success-gated debt marker here (`applyFailed`, set on
  every completed attempt, cleared only by a success) with a periodic
  converger in `pkg/daemon` (`reconcileClusterDHCPServices`, called from
  `reconcileRGState` beside the RA converger it mirrors). Two rules for
  future edits: the marker advances only on a COMPLETED attempt — a
  superseded apply (`gen <= lastAppliedGen`) never ran and leaves it
  alone — and the retry must stay SPACED, because re-driving a
  permanently broken Kea on every 2s tick is a continuous systemctl
  restart loop.
  Note `lastAppliedGen` still advances on failure, deliberately: a retry
  allocates a fresh generation so it is never blocked by the superseded
  guard, and leaving that ordering invariant alone keeps the #1835
  coalescing reasoning intact.
  The desired state every driver applies is single-sourced in
  `pkg/daemon` as `desiredClusterDHCPConfig` — a converger that
  disagreed with the edge would fight it every tick.
- Lease queries read Kea's CSV lease backends directly:
  `/var/lib/kea/kea-leases4.csv` and `kea-leases6.csv`. No control
  channel / socket call. Missing files yield an empty list, not an
  error. Parsing uses `encoding/csv` (#1778) so quoted fields with
  embedded commas don't shift columns. Kea's memfile is **append-only**
  between lease-file-cleanup (LFC) compactions — every renewal,
  re-allocation, release, decline, and expiry-reclaim is a new row — so
  `parseLeaseCSV` (#2085) collapses the append log to one row per
  address (the last/newest row wins), drops non-active rows
  (`state != 0` — declined / expired-reclaimed, which can still carry a
  future `expire`, so state is filtered before expire) and lapsed rows
  (`expire <= now`), and emits in first-appearance order. The clock is
  injected (`parseLeaseCSV(path, now)`) for deterministic tests. The
  filter is lenient: an absent or unparseable `state` / `expire` column
  degrades to "treat the row as active", preserving the pre-#2085
  behaviour for older Kea or exotic headers.
- Per-subnet interface binding (#1778): Kea allows at most ONE
  interface per subnet. Single-interface groups bind explicitly;
  multi-interface groups omit the binding so Kea uses address-based
  subnet selection (the pre-#1778 renderer silently bound only the
  first interface). All group interfaces are always listed in
  `interfaces-config`.
