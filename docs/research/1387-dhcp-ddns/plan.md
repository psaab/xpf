# #1387 — DHCP server dynamic DNS (DDNS) updates + stale lease cleanup

**Status:** DRAFT v1 (draft-fanout, not yet reviewed)
**Base:** origin/master (`c4e7c77cd`)
**Branch:** `research/1387-dhcp-ddns`
**Issue:** #1387 — "DHCP server: dynamic DNS updates and stale lease cleanup"
**Scope of this doc:** `/research` PLAN ONLY. No production code, no Codex/AGY/Copilot
run yet. The deliverable is this plan for manual approval BEFORE any implementation.

> If reviewers conclude the perf gain / scope is too small to justify the churn,
> PLAN-KILL is acceptable. (This is a net-new feature, not a perf change — the
> relevant test here is operator-value vs. surface-area churn and the long-lived
> reconciler/state-store that a single increment introduces.)

---

## 1. Issue framing

The Kea-backed DHCP server (`pkg/dhcpserver`) hands out leases but never publishes
client hostnames into DNS and never cleans stale `A`/`AAAA`/`PTR` records when a
lease expires, is released/declined/reclaimed, or when the address is reassigned to
a different client. Operators want active DHCP clients to resolve by name, and want
stale records gone on every lease-end transition.

The issue ships a full architecture (5 phases: state store, hostname normalization,
DNS-update backend, lease watcher/reconciler, HA behavior) plus a config surface, an
observability surface, a failure policy (fail-open for DHCP serving), a test matrix,
and 4 open questions. The most consequential decision is buried in those open
questions: **who emits the DNS updates** — xpfd directly via RFC 2136/TSIG, or Kea's
own `kea-dhcp-ddns` (D2) daemon — and **what authoritative DNS server they target**
(there is no DNS runtime inside xpf yet; `docs/next-features/dns-proxy.md` is still a
proposal tracked under #660).

This plan does not re-derive the issue. It (a) quantifies the blast radius against
current source, (b) surfaces the cross-cutting invariants the issue under-states
(HA ownership ordering, the existing generation-ordered Kea applier, the lease-CSV
parser's lack of state filtering, boot-class, byte-order on PTR construction), (c)
lays out 2-3 viable design paths with tradeoffs, and (d) gives an honest
shippable-increment recommendation rather than over-promising a single PR.

---

## 2. Honest scope / value

**Value.** Real. Name resolution for DHCP clients is table-stakes for a lab/branch
firewall, and stale-record cleanup is the part everyone gets wrong (and the part the
issue is most careful about: "never delete records xpf did not create"). vSRX has
this. It is a credible feature-gap closure.

**Scope.** Large. This is unambiguously a **multi-increment feature**, not a
one-PR change:

- New config subtree (types + compiler + schema + dual-AST handling + CLI completion).
- A new persistent, ownership-aware **state store** (`/var/lib/xpf/dhcp-ddns-state.json`
  or sqlite) that is the *protection boundary* for never-delete-non-owned.
- A new long-lived **reconciler** goroutine (file-watch + periodic) with retry/backoff.
- A new **DNS-update backend** (RFC 2136/TSIG via a new dep, or Kea D2 wiring).
- A **lease parser rewrite** — current `parseLeaseCSV` does no active/expired state
  filtering and is display-only; DDNS needs Kea expiry/state semantics.
- **HA ownership coupling** to the existing per-RG MASTER/BACKUP DHCP gating.
- New Prometheus counters + CLI `show` + status surface.

**Honest framing.** If reviewers conclude the perf gain/scope is too small to justify
the churn, PLAN-KILL is acceptable — but the more likely correct disposition here is
**DEFER-MULTI-INCREMENT** (ship a thin, safe first increment; gate the runtime on
the lab) rather than kill. The first increment that delivers operator-visible value
without committing to a wrong backend is small and reversible (see §11/§12).

---

## 3. What's already shipped (current state of the code)

Quantified blast radius. All paths relative to repo root.

### Config model — `pkg/config`
- `pkg/config/types_system.go:671-699`: `DHCPServerConfig`, `DHCPLocalServerConfig`,
  `DHCPServerGroup`, `DHCPPool`. **No DDNS fields at all.** `DHCPPool` carries
  `Name, RangeLow, RangeHigh, Subnet, Router, DNSServers, LeaseTime, Domain`.
- `pkg/config/compiler_system.go:302-315`: `services { dhcp-local-server / dhcpv6-local-server }`
  dispatch into `compileDHCPLocalServer`.
- `pkg/config/compiler_services.go:114-174`: `compileDHCPLocalServer` — handles both
  hierarchical and flat-set pool shapes (note the `len(prop.Keys) < 2` flat-set
  unwrap at line 138-140; a DDNS subtree must replicate this dual-AST handling).
- `pkg/config/schema_system.go:310-319`: `dhcp-local-server` / `dhcpv6-local-server`
  schema nodes — only `group` -> `pool`, no leaves. A DDNS subtree adds typed leaves
  here for completion + commit-time validation.

### Runtime manager — `pkg/dhcpserver` (662 LOC `dhcpserver.go`, 768 LOC tests)
- Renders `/etc/kea/kea-dhcp{4,6}.conf`, restarts `kea-dhcp{4,6}-server` (`:75-80`).
- **Generation-ordered applier** (`applyGen`/`lastAppliedGen`, `:100-242`): EVERY
  applier (sync `Apply`, `ApplyClusterCommit`, async worker) allocates a monotonic
  gen at call entry; the shared `apply()` body skips superseded gens. This is the
  #1835 F2 redesign and is a load-bearing invariant any DDNS hook must respect.
- **`ApplyAsync` mailbox** (`:244-317`): 1-slot latest-wins, single worker, used by
  VRRP transition callbacks so the event loop never blocks behind 15s systemctl.
- **`parseLeaseCSV`** (`:377-430`): reads Kea memfile CSV, extracts
  `address, hwaddr, hostname, valid_lifetime, expire, subnet_id`. **Display-only:
  no active/expired filtering, no state column, no v6 DUID/IAID.** The DDNS
  reconciler CANNOT reuse this as-is (issue Phase 4 calls this out explicitly).
- `generateKea4Config`/`generateKea6Config` (`:491-648`): build Kea JSON. No
  `dhcp-ddns` block emitted today (Path B would add one here).

### Daemon wiring — `pkg/daemon`
- `daemon_run.go:430`: `d.dhcpServer = dhcpserver.New()`.
- `daemon_apply.go:1067-1091, 1290`: commit path. Standalone -> `Apply` (fail-closed,
  error returned at `:1290`). Cluster -> `ApplyClusterCommit`. `resolveDHCPRethInterfaces`
  at `:1077`.
- `daemon_ha.go:918-983`: VRRP MASTER/BACKUP per-RG gating. **Only the MASTER node
  for an RG serves DHCP for that RG** (`filterDHCPConfigForMasterRGs`, `:988-1024`;
  `resolveDHCPRethInterfaces`, `:1235`). This is the ownership contract DDNS must
  mirror exactly.

### Surfacing — CLI / gRPC / metrics
- `pkg/cli/cli_show_services.go`, `cli_show_system.go`: `show ... dhcp` lease display.
- `pkg/grpcapi/server_show_dhcp_lldp_snmp.go`, `pkg/api/dhcp.go`: lease RPC/REST.
- `pkg/api/metrics*.go`: Prometheus collector — **no DHCP-server counters today**;
  DDNS counters are net-new descriptors (`pkg/api/metrics_descriptors.go` +
  coverage test `metrics_descriptor_coverage_test.go`).

### Environment facts (load-bearing for path choice)
- `scripts/image/bake.py:57`: production image installs **`kea-dhcp4-server`,
  `kea-dhcp6-server`** only. **`kea-dhcp-ddns-server` (D2) is NOT installed**, in
  neither `bake.py` nor `test/incus/{setup,cluster-setup}.sh`. Choosing Path B (Kea
  D2) requires a packaging change + a new managed systemd unit.
- `go.mod`: no `miekg/dns`, no `fsnotify`, no sqlite driver. Path A (direct RFC 2136)
  adds `miekg/dns`; the reconciler's file-watch adds `fsnotify` (or a poll loop to
  avoid the dep). The state store can be JSON via existing `pkg/fsatomic` (no new dep).
- There is **no authoritative DNS server inside xpf** to point updates at; #660
  dns-proxy is a *forwarder/cache* proposal (unbound), not an authoritative zone
  server. DDNS targets an **external** authoritative DNS (operator's BIND/Knot/etc.)
  regardless of path.

---

## 4. Concrete design

### 4.1 Config surface (all paths share this)

Extend the typed model with an opt-in DDNS block. Default OFF; absent block ==
today's behavior byte-for-byte.

```go
// pkg/config/types_system.go
type DHCPServerConfig struct {
    DHCPLocalServer   *DHCPLocalServerConfig
    DHCPv6LocalServer *DHCPLocalServerConfig
    DynamicDNS        *DHCPDynamicDNSConfig // nil == disabled (default)
}

type DHCPDynamicDNSConfig struct {
    Enabled        bool
    Domain         string   // default suffix when name not FQDN
    ForwardZones   []string
    ReverseZones   []string
    TTLSeconds     int      // default 300
    HostnameSource string   // client-hostname | fqdn | client-id | mac-fallback
    ConflictPolicy string   // replace-owned | skip-existing | strict-fail
    UpdateServer   string   // RFC 2136 target (Path A) — host[:port]
    TSIGKeyName    string
    TSIGSecret     string   // never logged; redact in show/marshal
    TSIGAlgorithm  string   // e.g. hmac-sha256
    Backend        string   // rfc2136 (Path A) | kea-d2 (Path B) — default rfc2136
}
```

Compiler: add a `dynamic-dns` arm in `compileDHCPLocalServer` (or a sibling
`compileDHCPDynamicDNS`) that handles **both** the hierarchical and flat-set AST
shapes (mirror the `len(prop.Keys) < 2` unwrap at `compiler_services.go:138`).
Schema: add typed leaves under `dhcp-local-server` (and v6) in
`schema_system.go:310` with `ValidateEnum` for `hostname-source`/`conflict-policy`,
`ValidateIntegerMin(1)` for `ttl`, IP validation for `update-server`. TSIG secret is
a free-form leaf marked redact.

### 4.2 Lease identity + state store (the protection boundary)

`/var/lib/xpf/dhcp-ddns-state.json`, written via `pkg/fsatomic.WriteFileAtomic`
(durability-on-write; the reconciler is slow-path so an fsync per write is fine —
unlike the Kea config apply path which deliberately skips fsync). Each owned record
set keys on a stable owner identity:

- v4: `(subnet_id, client-id || hwaddr)`; v6: `(DUID, IAID)`.
- Stored: family, identity, address, FQDN, forward zone, reverse zone, record types
  created (`A`/`AAAA`/`PTR`), an **owner-id watermark** (deterministic, node-stable —
  see HA §5), lease expiry, pool/group/interface metadata, last-success time, retry
  state.

**Delete only what matches owned state.** Before every delete, the reconciler
re-derives the exact (name, type, address) it once wrote and only issues a delete
for those. Optional `TXT xpf-dhcp-ddns=<owner-id>` ownership marker (issue suggests
it) is a *defense-in-depth* over the state DB, not a replacement.

### 4.3 Hostname normalization

Deterministic, per issue Phase 2: prefer DHCP FQDN option -> host-name option -> (if
`mac-fallback`) `dhcp-<sanitized-id>` -> append configured/pool domain when not FQDN ->
sanitize to DNS label rules (lower-case `[a-z0-9-]`, label <=63, name <=255, no
leading/trailing dash) -> reject/fallback on empty/invalid. Pure function, heavily
unit-tested.

### 4.4 DNS-update backend interface

```go
type DNSUpdater interface {
    UpsertLease(ctx context.Context, rec LeaseDNSRecord) error
    DeleteLease(ctx context.Context, rec LeaseDNSRecord) error
}
```

Backend is selected by `DynamicDNS.Backend`. See §6 for the path options. A
`fakeUpdater` (records calls) backs every unit/integration test so the reconciler
logic is validated with zero network/DNS dependency.

### 4.5 Reconciler

Long-lived goroutine owned by the DDNS manager:
1. trigger: file-watch on Kea lease CSVs (fsnotify) **and** periodic rescan +
   on-startup rescan (do not trust a single event path — issue Phase 4).
2. parse current leases with a **state-aware** parser (new — see §5 invariant),
   ignore expired/inactive rows.
3. build desired DNS state from active leases + current config; diff vs. owned state.
4. apply add/move/reassign/expire transitions (issue Phase 4 algorithm 5-9), each
   reconciled against owned state so reassignment cleans the old owner first.
5. bounded-backoff retry of failed updates; expose counters; never block reconcile
   forever (a permanently-down DNS server must not wedge the loop).

**PTR construction note (byte-order):** reverse names are built from the textual
address (`net/netip` -> reversed nibbles for `ip6.arpa`, reversed octets for
`in-addr.arpa`). This is string manipulation on the *display* form, NOT the
native-endian `__be32` map convention — do not import the BPF byte-order habit here;
getting it "consistent with the map" would be wrong for DNS.

---

## 5. Hidden invariants (the part the issue under-states)

1. **Generation-ordered Kea applier (#1835 F2).** DDNS must NOT bolt a second,
   independently-ordered side effect onto `Apply`. If the reconciler is driven by
   config (it is, for zones/enable), it must read the *same* desired state the
   winning apply gen installed, or it must be driven purely off the lease files
   (which Kea writes only after a successful apply). Recommendation: drive the
   reconciler off **lease files + a config snapshot taken atomically with apply**,
   never off a stale captured `cfg`.
2. **HA ownership ordering.** `daemon_ha.go:918-983` gates DHCP per-RG: only the
   MASTER for an RG serves it. DDNS emission MUST follow identically — only the
   DHCP-serving node updates DNS for that RG. On MASTER transition: immediate
   reconcile. On BACKUP transition: **stop emitting, do NOT delete valid records**
   just because this node stopped serving — deletion is lease-state-driven or
   config-removal-driven only. Both nodes becoming MASTER over time must use
   **deterministic owner-ids** so cleanup stays safe regardless of which node runs
   it (state store survives restart/failover; the BACKUP node should not "win" a
   delete race against the MASTER's fresh add).
3. **Lease-CSV state semantics.** `parseLeaseCSV` (`:405-428`) has no
   active/expired filtering and no v6 DUID/IAID. The reconciler needs a parser that
   honors Kea's `state` column (0=default/active, 1=declined, 2=expired-reclaimed)
   and the `expire` epoch. Reusing the display parser would publish/keep stale
   records — the exact bug the issue is about.
4. **Boot-class / never-brick.** Today an unavailable Kea binary cannot brick boot
   (commit logs + continues per README). A DDNS reconciler/state-store failure
   (corrupt JSON, missing dir, DNS unreachable) MUST be the same: fail-open, log,
   counter — never block commit, never block DHCP serving, never affect boot class.
5. **Dual-AST.** The new config subtree must parse identically via hierarchical
   `dynamic-dns { ... }` and flat `set ... dynamic-dns ttl 300`. Test with
   `ParseSetCommand()` + `tree.SetPath()` loop, never `NewParser()` (CLAUDE.md gotcha).
6. **TSIG secret handling.** Must be redacted in `show`, in any marshaled config
   echo, and never written to logs (Logging Rules). It is the one genuinely
   sensitive leaf.
7. **No hot-path impact.** Nothing here touches the AF_XDP forwarding path; the
   reconciler is slow-path (seconds cadence). Stated explicitly so reviewers don't
   look for allocation regressions where there are none.

---

## 6. Multiple path options (the real design fork)

### Path A — xpfd-direct RFC 2136 + TSIG (`miekg/dns`)
xpfd's reconciler sends dynamic-update packets straight to the operator's
authoritative DNS.
- **Pros:** ownership-state + cleanup live entirely in xpfd -> easiest to test with a
  fake updater; no new system daemon; cleanup-on-config-removal is trivial; matches
  the issue's stated lean ("easier ownership-state cleanup and tests"). No image
  packaging change beyond a Go dep.
- **Cons:** adds `miekg/dns` dep; xpf re-implements update batching/retry that Kea
  D2 already has; we own the TSIG crypto config surface.

### Path B — Kea D2 (`kea-dhcp-ddns-server`)
Emit a `dhcp-ddns` block in the Kea config; let D2 do RFC 2136.
- **Pros:** native Kea behavior; Kea owns the DNS-update protocol details; closer to
  "how Kea is meant to run."
- **Cons:** **D2 is not in the image** (`bake.py:57`) -> packaging + a new managed
  systemd unit (`kea-dhcp-ddns-server`) + a third unit in the generation-ordered
  applier. **Cleanup-on-reassign/expire is Kea's job, not xpf's** -> we lose the
  tight "never delete non-owned" state boundary the issue demands (D2's conflict
  resolution is its own policy, harder to assert in tests). Config-removal cleanup
  becomes "stop D2 and hope it withdrew" — weaker guarantee.

### Path C — pluggable backend, ship Path A first
The `DNSUpdater` interface (§4.4) makes the backend swappable. Ship Path A
(rfc2136) as the only implemented backend; reserve `Backend: kea-d2` /
`local-dns-runtime` (the future #660 unbound/authoritative runtime) as named-but-
unimplemented enum values that compile-warn.
- **Pros:** delivers value now with the testable ownership model; doesn't bet the
  feature on D2 packaging or the not-yet-existent xpf DNS runtime; clean migration
  path. **Recommended.**
- **Cons:** the interface is mild speculative generality if Path B is never built.

**Recommendation: Path C (interface + Path A backend first).** It matches the
issue's own preference for xpfd-owned cleanup, needs no image change, and the fake
updater makes the whole reconciler unit-testable without a lab.

---

## 7. Public API preservation

- `DHCPServerConfig` gains one nilable field (`DynamicDNS`); nil == today's exact
  behavior. No existing field changes. Existing configs replay byte-identically.
- `dhcpserver.Manager` public methods (`Apply`, `ApplyClusterCommit`, `ApplyAsync`,
  `Clear`, `IsRunning`, `GetLeases4/6`, `Lease`) are unchanged in signature. The
  DDNS manager is a **separate** type (e.g. `dhcpserver.DDNSManager` or a new
  `pkg/dhcpddns`) so the generation-ordered Kea applier is not perturbed.
- New gRPC/REST `show ... dynamic-dns` is additive. New Prometheus descriptors are
  additive (must be registered in `metrics_descriptors.go` to satisfy the coverage
  test).
- CLI: additive completion/help under existing `dhcp-local-server` trees.

No public surface is removed or repurposed.

## 8. Risk table (4 classes)

| Class | Risk | Likelihood | Impact | Mitigation |
|-------|------|-----------|--------|------------|
| **Correctness** | Deleting a non-owned DNS record (the cardinal sin) | Med if state boundary is sloppy | High (data loss in operator's zone) | State-store is sole delete authority; re-derive exact (name,type,addr) before delete; optional TXT owner marker; refuse delete on any state mismatch; fake-updater tests for move/reassign |
| **Correctness** | Stale records survive because lease parser ignores Kea state column | Med (reusing display parser) | High (feature fails its own goal) | New state-aware parser honoring `state`+`expire`; unit tests with expired/declined/reclaimed rows |
| **HA / failover** | BACKUP node deletes records the new MASTER just added (split-brain cleanup race) | Med | High (flapping records on failover) | Deterministic owner-ids; BACKUP stops emission, never deletes on transition; deletion only lease-state/config-removal driven; reconcile-on-MASTER; must pass `make test-failover` |
| **HA / failover** | Both nodes emit during transition window -> duplicate/conflicting updates | Low-Med | Med | Per-RG gating mirrors `filterDHCPConfigForMasterRGs`; idempotent upsert; gen-ordered with Kea apply |
| **Boot / lifecycle** | DDNS init failure (corrupt state JSON, DNS down) blocks commit or boot | Low if fail-open enforced | High | Fail-open by contract; load errors -> fresh state + counter; commit/boot never gated on DDNS |
| **Lab / env** | D2 (Path B) not in image; or no authoritative DNS to point at in test env | High for Path B | Med | Path C avoids D2 packaging; lab needs a throwaway BIND/Knot with a TSIG key to validate end-to-end |

## 9. Test plan

**Unit (no lab, fake updater):**
- hostname normalization / FQDN / domain-append / sanitize / reject (table-driven).
- v4 `A`+`PTR` and v6 `AAAA`+`PTR` payload generation; PTR name byte-order.
- delete only records present in owned state (negative: never delete unowned).
- client moves address -> delete old, add new.
- address reassigned to new client -> clean old owner before new owner.
- expired/declined/reclaimed lease rows dropped from desired state (new parser).
- config removal -> delete owned records for that pool/group.
- retry/backoff does not wedge reconcile (permanently-failing updater).
- dual-AST: hierarchical vs flat-set parse equality (`ParseSetCommand` loop).
- TSIG secret redaction in show/marshal.
- generation-ordering: DDNS reconcile reads the winning apply's config snapshot.

**Integration (fake updater + synthetic Kea CSV):**
- CSV change -> expected upsert; expiry/reconcile -> expected delete; daemon restart
  with existing state + active leases -> no duplicate updates; HA MASTER/BACKUP gates
  emission.

**Does it need the lab / test-failover / multi-increment?**
- **make test-failover: YES, mandatory** for any increment that wires DDNS to the
  VRRP transitions (touches cluster/failover code per CLAUDE.md). The state-store +
  reconciler logic alone (increment 1) does not.
- **loss-cluster lab: YES** for true end-to-end validation — needs a throwaway
  authoritative DNS (BIND/Knot) with a TSIG key reachable from the firewall, then:
  configure a v4 pool with domain, lease to a client with hostname, verify `A`+`PTR`
  resolve; renew -> stable; force expiry/reclaim -> removed; reassign to new MAC ->
  old gone/new added; repeat for v6 `AAAA`/`ip6.arpa`. This DNS fixture does not
  exist in the env today and is part of the lab cost.
- **multi-increment: YES** — see §12.

## 10. Out of scope

- The xpf-managed authoritative/forwarder DNS runtime (#660 dns-proxy) — DDNS
  targets an *external* authoritative server; `Backend: local-dns-runtime` is a
  reserved future enum only.
- Strict mode (withhold/fail leases on DNS-update failure) — default fail-open per
  issue; strict mode is a later knob.
- DNSSEC / signed-zone update specifics beyond TSIG.
- Per-pool DDNS override (issue says start with server/global + pool `domain-name`
  default).
- Cache/record sync between HA peers beyond the deterministic-owner-id contract.
- Kea D2 (Path B) — reserved enum, not implemented in increment 1.

## 11. Open questions (for adversarial review)

1. **Path A vs B vs C.** The issue's own Q1. Does the team accept Path C (xpfd-direct
   rfc2136 first, pluggable backend) — or is native Kea D2 (Path B) a hard
   requirement despite the image-packaging cost and the weaker never-delete-non-owned
   guarantee?
2. **Authoritative DNS dependency.** DDNS is useless without an authoritative server
   that accepts dynamic updates. Is requiring the operator to run/point at an
   external BIND/Knot+TSIG acceptable for v1, or must this wait on the #660 xpf DNS
   runtime to provide a local update target?
3. **State store format.** JSON via `pkg/fsatomic` (no new dep, simple, fsync-on-write
   on the slow path) vs sqlite (better for large lease counts, new dep). At what
   lease scale does JSON-rewrite-per-reconcile stop being acceptable?
4. **fsnotify dep vs poll.** Add `fsnotify` for near-instant lease-file triggers, or
   keep zero new runtime deps with a short periodic poll (e.g. 2-5s) + on-apply
   kick? Latency vs dependency-surface tradeoff.
5. **Owner-id determinism across HA.** What exactly is the stable owner-id —
   `(node-independent: subnet_id + client-id)` so either node computes the same
   value, plus a node tag only in the TXT marker? How do we prove the BACKUP cannot
   delete the MASTER's fresh add during the transition window?
6. **Generated fallback names default.** Issue Q3: are `dhcp-<mac>` fallback names
   on by default, or are hostname-less leases skipped unless `mac-fallback` is
   configured? (Default-on risks polluting the operator's zone with junk names.)
7. **Junos syntax fidelity.** Issue Q4: how much real Junos `dynamic-dns` grammar do
   we mirror vs an xpf-native subtree? Affects schema + import compatibility with
   `vsrx.conf`.

---

## 12. Claude self-SMR (hostile)

**Strongest objection to my own plan:** This is a net-new subsystem — a persistent
state store, a long-lived reconciler, a new external dependency, a new config
subtree, and an HA-coupled side-effect — justified by a feature (DHCP-client name
resolution) that a lab/branch operator can often get *good enough* by pointing DHCP
clients at an external DDNS-capable DHCP server, or by static DNS, or by simply not
caring. The cardinal-sin failure mode (deleting a record xpf didn't create, in the
operator's production zone) is severe, and the safety of the never-delete boundary
depends on a state store that must survive restart, failover, and corruption — a lot
of machinery to get one operator convenience right without blowing up their DNS. The
HA cleanup race (BACKUP vs MASTER over the same owned record during a transition) is
genuinely subtle and is exactly the kind of thing that passes unit tests and fails in
the lab. And the whole runtime is **un-mergeable as a single PR** without a DNS
fixture in CI that does not exist.

**Counter to my own objection:** none of that argues for *kill* — it argues for
*sequencing*. The config-model + state-store + reconciler-with-fake-updater
increment is small, fully unit-testable, ships zero behavior change when DDNS is
disabled (the default), and de-risks every later increment. The dangerous parts
(live RFC 2136 emission, HA wiring) are deferred to increments that explicitly carry
the lab + `make test-failover` gates.

**Disposition: LIKELY-DEFER-MULTI-INCREMENT.**

Reasoning: the feature is real and worth building, but it is too large and too
lab-dependent for one PR, and the highest-risk surfaces (live DNS deletes, HA
ownership races) must be validated on the loss cluster with a DNS fixture that
doesn't exist yet.

**Named shippable first increment (Increment 1, mergeable without the lab):**
- `DHCPDynamicDNSConfig` types + compiler (dual-AST) + schema leaves + CLI
  completion + TSIG redaction. Default OFF; nil == today's behavior byte-for-byte.
- State-aware Kea lease parser (honors `state`/`expire`, adds v6 DUID/IAID) as a
  *new* parser; existing `parseLeaseCSV` stays for display.
- `DNSUpdater` interface + `fakeUpdater` + the reconciler core (build-desired /
  diff-owned / transition logic) driven entirely by unit tests with the fake.
- State store (JSON via `pkg/fsatomic`) + never-delete-non-owned boundary, unit-tested.
- New Prometheus descriptors registered (no emission yet) + `show ... dynamic-dns`
  scaffold reporting "configured, backend not yet wired."
- **No live RFC 2136 backend, no HA wiring, no Kea D2.** Net behavior change for
  existing users: zero.

Increment 2 (lab-gated): real rfc2136 backend + reconciler activation on the
DHCP-serving node, validated against a throwaway BIND/Knot+TSIG. Increment 3
(test-failover-gated): HA ownership coupling (MASTER reconcile / BACKUP no-delete /
deterministic owner-ids). Increment 4 (optional): Path B Kea D2 backend, or
integration with the #660 local DNS runtime once it exists.

Alternative disposition if reviewers reject the external-DNS dependency for v1:
**LIKELY-DEFER-LAB** pending #660 (a local authoritative/update target), in which
case Increment 1 still ships as pure groundwork.
