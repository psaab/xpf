# pkg/api

HTTP REST API on `127.0.0.1:8080`. Read-only access to system state plus
operational commands (clear, ping, traceroute). Health probes for
liveness/readiness. Prometheus metrics endpoint. SSE event streams.

## Entry points

- `Server` — `server.go`
- `NewServer(cfg Config) *Server` — `server.go`.
- `Config` — `server.go`. All dependencies (configstore, dataplane, frr,
  vrrp, etc.) injected here; the package has no global state.

## Surface

- `GET /health` — liveness/readiness. `CompileHealthFn` (#758) lets the
  daemon downgrade `/health` to 503 when a recent compile failed
  silently; without the callback it defaults to 200.
  **Redaction (#5031):** `/health` is unconditionally unauthenticated
  (`authMiddleware` exempts it), so it exposes only status, counters,
  timestamps, and stable reason codes — never the raw compile/bootstrap
  error strings. `compile_last_error` and `bootstrap_import_error` are NOT
  emitted (those strings are copied verbatim from the parser/compiler and
  can carry file paths, config internals, or a secret echoed by a schema
  validator). The failure is still signalled by `compile_failure_count` /
  `compile_last_error_unix` and `bootstrap_import_status` /
  `bootstrap_import_failed` / `bootstrap_import_unix`; the full detail
  stays in the journal (compile WARN/ERROR) and the authenticated in-band
  `BOOTSTRAP_IMPORT_FAILED` event (event stream / ring buffer).
  `ConfigPersistDegradedFn` (#1799, same injection pattern) downgrades
  `/health` to 503 while the running active config failed to persist to
  disk (HA config-sync or commit-confirmed auto-rollback hit a write
  error and the configstore's background retry has not yet succeeded —
  a restart would load a stale config). The same state is exported as
  the `xpf_daemon_config_persist_degraded` 0/1 gauge, emitted even when
  the dataplane is not loaded.
  `RollbackHistoryDegradedFn` (#3441, same injection pattern) reports
  whether the most recent commit failed to durably persist its text
  rollback-history files. UNLIKE the two above it does NOT downgrade
  `/health` to 503 — the commit succeeded and the active config is
  durable, so a forwarding firewall must not be pulled from rotation over
  a degraded recovery aid; it is surfaced as the non-fatal
  `rollback_history_degraded` field plus the
  `xpf_config_rollback_persist_degraded` 0/1 gauge (also emitted even
  when the dataplane is not loaded) for alerting.
  `ConfigApplyDebtFn` (#9811, same injection pattern) reports whether the
  dataplane is known to be enforcing something OTHER than the active
  configuration, and DOES downgrade `/health` to 503. The distinction from
  `RollbackHistoryDegradedFn` directly above is the one that decides it,
  and it is not severity-by-feel: a degraded rollback history is a
  recovery aid failing on a node that forwards exactly what it reports,
  and such a node must not be pulled from rotation. Here the reported
  state and the enforced state DISAGREE — a commit-confirmed auto-rollback
  promotes the store first, so a failed apply leaves the node enforcing
  the abandoned config while this payload, `show configuration` and the
  peer resync all name the promoted one. That is
  `ConfigPersistDegradedFn`'s class ("a restart would load a stale
  config"), not `RollbackHistoryDegradedFn`'s. It is transient by
  construction: the daemon's `configApplyReassertLoop` re-applies the
  active config every 30s until it converges. Two fields are surfaced,
  `config_apply_debt_owed` and `config_apply_failure_count`; the raw
  error is withheld under the #5031 rule, and the COUNT is the field that
  separates a retry owner that is running and failing from one that is
  not running at all.
- `GET /metrics` — Prometheus exposition.
- `GET /api/v1/...` — REST mirrors of the gRPC API: sessions, routes,
  NAT, DHCP, IPsec, VRRP, OSPF, BGP, etc.
  - `GET /api/v1/security/policies` enumerates zone-pair policies AND
    global policies (#3045). Global rules are emitted as a single
    trailing `PolicyInfo` row with `from_zone="*"`/`to_zone="*"`,
    matching gRPC `GetPolicies` and the Prometheus collector. Global
    counter IDs follow the zone-pair policy-set count (the `policySetID`
    continues from the zone-pair loop), so per-policy hit counters stay
    aligned with the dataplane when `policy-stats system-wide enable` is
    set. A scoped global policy (#3148 `match from-zone`/`to-zone`)
    carries its narrowing on the per-rule `match_from_zone` /
    `match_to_zone` fields (#3286), omitted when empty; the group row
    stays `*`/`*` (the all-zones tier). Before #3286 these were absent,
    so a scoped global looked all-zones to automation. The Prometheus
    `xpf_policy_hits_total` collector (metrics_counters.go) likewise emits
    the scoped global's real zones on its `from_zone`/`to_zone` labels
    (#3286) — an unscoped global keeps `*`/`*` — so counter-based
    validation is unambiguous on the canonical metrics surface. Each rule
    also carries the runtime `policy_id` (the RT_FLOW/session-table join
    key, #3336). #3623: `policy_id` is emitted ALWAYS (no `omitempty`).
    #3965: both this endpoint and the `xpf_policy_hits_total` collector read
    the WHOLE policy set from ONE dataplane snapshot rather than calling
    `ReadPolicyCounters` once per policy. The per-policy read rebuilt the
    ruleID->counter index and rescanned the config UNDER the dataplane's
    policy mutex on every call, so a scrape of P policies was `O(P*(P+C))`
    with the mutex held the entire time — periodically stalling the scrape
    AND starving commit/apply and session classification on a firewall with
    many policies. `dpuserspace.NewPolicyCounterReader` now builds the index
    ONCE (`O(P+C)`) from a snapshot taken under a single brief lock (the
    userspace `Manager.ReadAllPolicyCounters`), then resolves outside the
    lock; a dataplane without the bulk snapshot (test fakes / retired eBPF)
    transparently falls back to the per-policy read, and the skip-and-bump
    (#3345/#3408) / HTTP-500 degraded-read contracts are unchanged for a
    GENUINE read failure. #7016 split the UNPUBLISHED case out of that
    contract — see the bullet below.
    #4344: the migration is now complete across EVERY policy-counter display
    surface — this endpoint's default-policy row (which had bypassed the
    reader with a standalone sentinel read, M02), the CLI `show security
    policies hit-count` / `brief` tables, and the gRPC `show security
    policies hit-count` / `detail` text renderers plus the structured
    `GetPolicies` RPC all read through the same `NewPolicyCounterReader`
    snapshot. The returned counter values are identical to the per-policy
    read (`ReadAllPolicyCounters` is a batching layer, not a semantic
    change — pinned by `TestReadAllPolicyCountersMatchesPerPolicy`); a
    per-surface static canary forbids a new show surface from regressing to
    a direct per-rule `ReadPolicyCounters` call.
    #7016: an UNPUBLISHED per-rule counter is NOT a read failure. #6743
    activated the bulk path on all seven observability call sites for the
    first time, and the bulk reader signals a rule the helper has not
    published with `dpuserspace.ErrPolicyCounterUnpublished`. Every surface
    folded that into its degraded-read channel, so a single unpublished rule
    discarded the WHOLE response: this endpoint returned **HTTP 500**, gRPC
    `GetPolicies` returned **codes.Internal**, the CLI/gRPC text tables
    printed `warning: policy counter read failed` naming a fault that does
    not exist, and the Prometheus collector bumped
    `xpf_counter_read_errors_total` — a permanent FALSE #3345 alert of the
    same class #3643 removed the per-zone family to stop. The condition is
    reachable whenever a counter-eligible rule (`then count`, or system-wide
    `policy-stats`) exists and the helper has not published its stable rule
    id: the window before the first 1 Hz status poll lands — `IsLoaded()` is
    already true because the shim is loaded — or config skew after a
    non-abort-class apply failure (#5679), where the store has promoted a
    config the helper is not yet enforcing.

    The disposition is now the one the ZONE half of this handler already
    used for `dataplane.ErrCounterNotPopulated` (#6843): flag the affected
    ITEM, serve the response.
    - REST: 200 with `hit_counters_unavailable:true` on the affected rules
      (the #5580 field, whose contract now covers loaded-but-unpublished as
      well as dataplane-unloaded); the rest of the inventory serializes
      normally.
    - gRPC `GetPolicies`: the additive `PolicyRule.hit_counters_unavailable`
      (field 23) carries the same flag; the RPC succeeds. The remote CLI
      renders `Hit count: not available` / an `n/a` Hits cell.

    **Distinct from policy-stats being OFF (#8177).** `hit_counters_unavailable`
    means counter-ELIGIBLE but unanswered; a rule that is not eligible is
    signalled by `count=false`. Eligibility has TWO inputs, `statsEnabled ||
    rule.count`, and only the second used to be on the wire — so "stats on,
    count=false" (the counter WAS read; 0 means no traffic) and "stats off,
    count=false" (never read; 0 means nothing) serialized identically. Both
    structured surfaces now carry the system-wide knob: `policy_stats_enabled`
    on `GetPoliciesResponse`, and the same field repeated on each REST
    `PolicyInfo` block — repeated because this endpoint's payload is a bare
    array inside the generic envelope, so there is no per-endpoint place to hang
    a system-wide field without breaking `data`'s shape. Setting
    `hit_counters_unavailable` for the stats-off case was the tempting shortcut
    and would redefine a shipped field rather than add one.

    The four TEXT surfaces (CLI `hit-count` and `brief`, gRPC `hit-count` and
    `detail`) instead print a trailing `note: N policy count(s) read 0 because
    policy-stats is disabled system-wide`. The wording is byte-identical across
    all four; N is NOT, and must not be made so — each surface renders a
    different row population (the hit-count table includes the implicit
    default-policy row, the brief and detail views do not).

    The Prometheus collector is deliberately NOT in that list: it SKIPS the
    series rather than emitting a zero, because an absent sample is not a zero
    sample and a time series has nowhere to carry the note.
    - CLI `show security policies hit-count` / `brief` and the gRPC text
      hit-count / detail renderers: the count cell reads `n/a` with a
      trailing `note: N policy counter(s) not yet published by the
      dataplane`, distinct from the retained `warning: policy counter read
      failed`.
    - Prometheus: the sample is still OMITTED (never a `0` standing in for
      an unknown), but the rule counts into the new
      `xpf_policy_counters_unpublished_rules` gauge instead of bumping
      `xpf_counter_read_errors_total`. The gauge is the policy sibling of
      `xpf_zone_counters_unpopulated_zones` and counts exactly the rules
      this endpoint reports `hit_counters_unavailable:true` for while the
      dataplane is loaded. Unlike the zone gauge it is NOT emitted above the
      dataplane-loaded gate: `Collect` reaches `collectPolicyCounters` only
      on the loaded path, so an unloaded boot emits no policy family at all
      (pre-existing) and REST's flag is the signal for that state.

    A GENUINE read failure — the bulk snapshot itself erroring — keeps every
    pre-#7016 behaviour: HTTP 500, `codes.Internal`, the text warning, and
    the `xpf_counter_read_errors_total` bump.

    The first rule of the first zone-pair set legitimately has runtime id
    0 (`policySetID*MaxRulesPerPolicy + ruleIndex = 0`), and since #3057
    the implicit default policy uses a distinct sentinel (`0xFFFFFFFF`),
    so id 0 is UNAMBIGUOUSLY a real policy; `omitempty` previously dropped
    it, so a consumer joining an RT_FLOW event (`policy_id=0`) to the
    inventory found no row for the highest-priority rule. The gRPC
    `PolicyRule.policy_id` mirror is `optional uint32` (proto3 explicit
    presence) for the same reason. Each rule also carries `scheduler_name`
    and `inactive` (#3624) — the structured sibling of the #3062 TEXT
    policy-detail surface (`State: inactive` + `Scheduler:` lines).
    `scheduler_name` is the policy's configured `scheduler-name` (empty /
    omitted for an always-on rule); `inactive` is true when the policy is
    bound to a scheduler that is currently runtime-inactive — the dataplane
    is skipping the rule right now. Both are populated for zone-pair AND
    global policies from the same live-state provider the text surface uses
    (`Server.policySchedActiveFn` / gRPC `policySchedulerActiveState`), and
    like that surface they FAIL OPEN on the display: when live scheduler
    state cannot be queried (accessor not wired, early boot, NoDataplane)
    `inactive` stays false, so the output is unchanged for existing
    consumers — this differs deliberately from the `match-policies`
    simulator, which fails CLOSED (#3414). Without these an audit read a
    time-gated, currently-dormant permit/deny as an active allow/deny, so
    the structured API disagreed with effective dataplane behavior. The
    gRPC mirror is `PolicyRule.scheduler_name` (19) / `inactive` (20).
    A final synthetic `PolicyInfo` row with `from_zone="-"`/`to_zone="-"`
    carries a single rule named `default-policy` (#3363) — the implicit
    catch-all — with `policy_id` set to the reserved sentinel
    (`0xFFFFFFFF`) and, when `policy-stats system-wide enable` is set, the
    live hit counter read through the `DefaultPolicySentinelID` handle.
    This row reflects the configured `default-policy` action and, since
    #3670, its own RT_FLOW log intent: `log` / `log_session_init` /
    `log_session_close` are populated from `default-policy-log
    session-init`/`session-close` (compiled to
    `Security.DefaultPolicyLogSessionInit`/`Close`, threaded to the
    dataplane via `ConfigSnapshot.DefaultLogSessionInit`/`Close`, #3534) —
    the same log fields the configured rows expose (#3336). Before #3670
    the synthetic row omitted these, so audit tooling read the
    default-deny/permit boundary — the most security-relevant fallback —
    as unlogged while the dataplane was emitting default-verdict
    session-init/close records. The gRPC `GetPolicies` default row is
    identical (`PolicyRule.log` / `log_session_init` / `log_session_close`).
  - `GET /api/v1/security/zones` enumerates security zones (`ZoneInfo`,
    types.go). The host-inbound admission set is surfaced distinctly
    (#3328): `host_inbound_configured` is the dataplane posture bit
    (mirrors `ZoneSnapshot.HostInboundConfigured`, #3070/#3362/#3405).
    Post-#3405 EVERY configured security zone is host-inbound ENFORCING
    (Junos default-deny parity), so this bit is `true` for every zone the
    endpoint returns — it reports the dataplane truth, not config shape.
    A zone with NO `host-inbound-traffic` stanza default-DENIES host-bound
    traffic exactly like an explicit empty stanza; there is no admit-all
    posture for a configured zone. The admitted set lives in
    `host_inbound_system_services` and `host_inbound_protocols` (empty =
    deny-all; kept split so a system-service such as ssh/ping/dhcp is
    distinguishable from a routing protocol such as ospf/bgp), plus any
    `interface_host_inbound` per-interface override (#3362, omitted when
    none; the effective set for such an interface IS the override — it REPLACES
    the zone-level set, #6515). The legacy flattened `host_inbound_services`
    (services + protocols concatenated) is retained as a back-compat alias.
    Before #3653 the bit was re-derived from config shape and reported
    `false` for a no-stanza zone — the pre-#3405 "false = admit-all"
    reading, the OPPOSITE of the runtime default-deny, so an auditor read
    the management plane as open when it is fail-closed. (Global
    ICMP/ND/PMTUD accepts and lifeline interfaces fxp0/em0/fab* still
    bypass the per-zone host-inbound deny.) Before #3328 REST exposed only
    the flattened list and no `configured` flag at all.
  - `GET /api/v1/security/screen` enumerates the configured screen
    profiles. Each `ScreenInfo` carries the profile `name`, a `checks`
    string list, and a `thresholds` map (keyed by check name). The
    `checks` list and the shared helper are the single source of truth
    with gRPC `GetScreen` (`config.ScreenChecks` /
    `config.ScreenThresholds`, #3327) — before #3327 each API carried a
    byte-identical copy that omitted `port-scan`, `ip-sweep`,
    `limit-session-source`, `limit-session-destination`, and
    `icmp-fragment` even though the compiler and userspace dataplane
    (`pkg/dataplane/userspace/screens.go`) fully enforce them, so an
    operator reading structured state saw active protection as absent.
    The `checks` set is kept a superset of the dataplane-enforced set.
    `thresholds` surfaces the configured numeric values (icmp/udp/syn
    flood, port-scan, ip-sweep, session limits) — only explicitly-set
    positive values appear, so a consumer can tell a default threshold
    from an intentionally tight or accidentally clamped one. The
    SYN-flood profile's several sub-thresholds are keyed individually
    (`syn-flood-attack-threshold`, `-alarm-`, `-source-`,
    `-destination-`, `-timeout`).
  - `GET /api/v1/statistics/global` — global dataplane counters
    (`GlobalStats`, types.go). The field set mirrors the gRPC
    `GetGlobalStats` reader: as of #3426 it includes `nat64_translations`
    (`GlobalCtrNAT64Xlate`) and `host_inbound_allowed`
    (`GlobalCtrHostInbound`) alongside the long-standing
    `host_inbound_denies`. Before #3426 REST omitted both, so an automation
    client reading only REST could not see NAT64 translation volume or the
    host-inbound allow count even though gRPC and Prometheus
    (`xpf_nat64_translations_total`) exposed them. A userspace-dp global
    counter read failure returns HTTP 500 (#3345), not a clean zero.
    The kernel nftables host-inbound DROP counters (the PRIMARY
    host-inbound enforcement signal — `host_inbound_kernel_denies`, its
    per-zone/family `host_inbound_kernel_deny_detail`, and the
    `host_inbound_kernel_denies_unavailable` marker) are handled on a path
    that mirrors the Prometheus collector rather than the userspace-dp
    counters (#3681):
    - **H04 (read before the gate):** the `inet xpf_hostinbound` chain is
      installed by the daemon INDEPENDENT of dataplane load and keeps
      dropping control-plane traffic on a config-only / degraded boot, so
      these counters are read BEFORE the `dataplane not loaded` check —
      matching `metrics_counters.go collectHostInboundKernelDenies`, which
      runs before its own dataplane gate. On an unloaded dataplane the
      endpoint returns a PARTIAL 200 with `dataplane_degraded: true` and the
      kernel host-inbound counters populated, instead of the old blanket
      503 that hid the host-inbound signal exactly when management-plane
      exposure matters most. The 503 gate is now scoped to the
      genuinely dataplane-dependent userspace counters.
    - **H05 (unavailable != zero):** a netlink read failure sets
      `host_inbound_kernel_denies_unavailable: true` (leaving the aggregate
      and detail at their zero values but marked non-authoritative) rather
      than silently reporting a misleading "0 denies" — the REST analogue of
      the Prometheus skip-the-series + `xpf_counter_read_errors_total` bump,
      and the same `Unavailable` idiom as per-interface counters (#3464). An
      absent chain (no host-inbound stanza enforced) reads as a clean 0 with
      no marker.
    - **#5719 (the counter-LESS table is unavailable too):** the same marker
      now covers a third kernel state the read previously could not see. The
      #5644 M37 cold-boot fail-closed FENCE installs `inet xpf_hostinbound`
      with catch-all DROPs and, by design
      (`buildHostInboundFencePayload`/`buildHostInboundFenceNetlink`: "NO
      per-service accepts, NO named counters"), NO counter objects — so the
      object walk returned an empty set from a table that is ACTIVELY
      DROPPING host-bound traffic, indistinguishable from a torn-down table.
      REST published `host_inbound_kernel_denies: 0` with the marker absent,
      certifying "no denies" during exactly the degraded window that most
      needs the signal. `pkg/nftables.ReadHostInboundDenyCounters` now
      returns a `HostInboundTableState` alongside the rows, and a
      `HostInboundTableCounterless` read sets
      `host_inbound_kernel_denies_unavailable: true`. Three states, three
      answers:
      | kernel state | `xpf_hostinbound` | named counters | REST |
      |---|---|---|---|
      | real policy loaded | present | >=1 | authoritative counts |
      | cold-boot fence (#5644 M37) | present, DROPping | none | `unavailable: true` |
      | table absent | absent | — | authoritative `0` |
      Two things this deliberately does NOT do. It does not make every zero
      unavailable: a table whose real deny counters merely READ zero still
      HAS those counter objects, so the read is `Counted` and its `0` stays
      authoritative (pinned by the `real counters reading zero stay
      AUTHORITATIVE` case in `stats_global_host_inbound_fence_5719_test.go`).
      And it does not false-alarm on a legitimate generation with no
      per-zone catch-all DROP (a junos-host program-only ruleset): a real
      table always declares the three #4759 ICMP/ND ACCEPT counters, so the
      discriminator is "the table carries NO named counter OBJECT", not "no
      DENY counters". The Prometheus analogue bumps
      `xpf_counter_read_errors_total` for the counterless state (there is no
      series to omit — there are no counter objects to label), keeping the
      two surfaces in agreement. **Not in scope, tracked separately:** this
      is a kernel-observable proxy, NOT the daemon's applied-state latch
      (`pkg/daemon` `hostInboundEnforced`, still unexported) and NOT a
      dedicated `host_inbound_enforcement_degraded` discriminator across
      REST/gRPC/CLI — no new REST field, Prometheus series, or gRPC field
      was added here.
    - **L03 (zone/family split):** `host_inbound_kernel_deny_detail` carries
      the per-`{zone, family}` breakdown the aggregate scalar collapses,
      matching the `xpf_host_inbound_kernel_denies_total` labels.
- `GET /api/v1/events/stream` — Server-Sent Events stream of dataplane
  events. Backed by the `pkg/logging` event ring buffer; long-lived
  consumers must drain. Concurrent SSE subscribers are BOUNDED (#4484 L-2):
  both stream handlers subscribe via `EventBuffer.TrySubscribe`, which
  returns nil once the live subscriber count reaches the cap
  (`defaultMaxSubscribers`, 64) — the handler then responds `503` BEFORE
  switching to event-stream. This mirrors `metricsMaxInFlight` (#4162): each
  event `Add` fans out O(N) over the subscriber set and each subscription
  holds a buffered channel, so an unbounded set is a memory + per-event-CPU
  DoS vector on this untrusted surface. Trusted internal consumers (gRPC
  event stream, CLI monitor) use `Subscribe`, which never fails but still
  counts toward the cap. `?category=` (and `?severity=` on
  `/api/v1/logs/stream`) is fail-closed (#3383): an unrecognized token is
  rejected with `400` BEFORE the connection switches to event-stream, so a
  typo cannot silently widen the live feed to everything. A `SCREEN_DROP`
  with `action=permit` (the scan-table-pressure alarm — the packet still
  forwards) is classified `notice`, not `error`, mirroring the canonical
  `logging.eventSeverity`; an unknown event type fails closed under a
  narrow category mask.
- `GET /api/v1/security/events` (and the SSE event stream) return the full
  RT_FLOW forensic `EventEntry` (#3337). Both surfaces share one mapper,
  `eventEntryFromRecord`, so they never drift: beyond the 5-tuple they carry
  the resolved ingress/egress zone names, policy name, application name,
  ingress interface, close reason / policy reason, the reverse
  (server→client) packet/byte counters, the post-NAT source/destination
  tuples, session ID, elapsed/created time (with `created_nanos` sub-second
  remainder), ingress/egress SNMP ifIndex, IP TOS, and the OR of the TCP
  control bits. These mirror the gRPC `EventEntry`
  (`pkg/grpcapi` `GetEvents`) and the CLI RT_FLOW line. All forensic fields
  are `omitempty`, so a non-close event (or an unNAT'd / screen-drop record)
  omits the ones it does not carry. The machine APIs format timestamps with
  `RFC3339Nano` (sub-second), so high-rate events keep ordering/burst
  fidelity for cross-system correlation; the CLI keeps human-friendly
  whole-second output.

## Server-side authorization (#5561, reads #6660)

Every route under `/api/v1` — state-changing **and** read — is gated on a
**server-derived principal** before it reaches its handler. `authz.go` owns the route table and the middleware; the
decision itself lives in `pkg/authz` so the gRPC surface reaches the same
verdict. That gRPC leg has since landed (#5278) — see
[`pkg/grpcapi/README.md`](../grpcapi/README.md) "Server-side authorization",
which documents where the two legs deliberately differ: gRPC gates READS too,
has no `api-auth` credential and therefore no precedence rule, resolves the peer
inline (grpc-go calls its accept hook off the accept loop, `http.Server` does
not), and prices the multiplexed `SystemAction` verb-by-verb because a unary
interceptor is handed the decoded request that this middleware deliberately
never reads.

### The read surface (#6660)

#5561 gated the 19 mutating routes and deliberately scoped reads out. That left
every read route open: any local process could `GET /api/v1/config` without
being identified, and no login-class permission was consulted. #6660 closes it —
`restReadPermissions` + `readAuthz`, reusing #5561's identification machinery
unchanged.

**What was actually disclosed, measured rather than assumed.** `GET
/api/v1/config` json-encodes the COMPILED `*config.Config`, so #2053's
`config.Secret` marshaller applies and **no operator secret is rendered in
cleartext** — verified by marshalling a populated `ControlLinkAuthKey` and
checking the output. So this was **not** credential disclosure. What it was is
full CONFIGURATION disclosure: zones, policies, NAT rules, interface addressing,
routing neighbours — a complete map of the firewall, to any local uid, including
one with no `system login user` entry at all. On a firewall that is
reconnaissance.

**Every route is `PermView`**, not a per-route tier. These are all `show`
verbs, and Junos gates `show` on `view`; inventing finer tiers here would be a
policy the CLI's own table does not have, and the two would drift. The finer
question — whether a read should be REDACTED by class rather than denied — is a
different contract and is left open.

**Why this is not a no-brick problem.** `PrincipalForUID` returns a **superuser**
principal for uid 0 unconditionally, with no login model required, so root-run
monitoring and support tooling on a box that never adopted RBAC keeps working
byte-for-byte. What changes is a NON-root local uid outside the login model —
exactly the population the issue exists to stop.

**`/health` and `/metrics` stay open** and are not in the table. They carry no
configuration, `authCheck` already exempts them, and the in-tree incus harnesses
read `/metrics`. A sweep of every in-tree consumer found those two and nothing
else touching REST at all, so gating `/api/v1` breaks no shipped tooling.

`readAuthz` serves an UNGUARDED safe route rather than refusing it — the
opposite of the mutation gate's fail-closed default — precisely so those two
keep working. The cost is that a NEW read route added without a table entry
would serve unauthenticated, so `TestEveryReadRouteHasAPermission_6660`
enumerates the routes `server.go` actually registers and fails on any `/api/v1`
GET the table does not cover, moving that risk from runtime to the suite.

It adjudicates ONCE, where the mutation gate adjudicates twice. That is a
difference rather than an omission: the mutation gate drains the body between
its two passes because a caller owns its body and can hold an authorization open
for the whole read timeout. A GET has no body to withhold.

**Why the loopback bind was not enough.** The daemon provisions every `system
login user` a real shell account (`useradd -m -s /bin/bash`), and the CLI's RBAC
check runs *in the CLI process*. A `read-only` class holder could therefore
`curl 127.0.0.1:8080/api/v1/config/set` and commit, and the class boundary never
ran. The pre-existing gates do not cover this: the #4047/#5127 clamp constrains
*where* the listener binds, not *who* connects; `api-auth` is off by default on
a loopback bind (`dynamicAuthMiddleware` passes every request through when the
snapshot is nil) and is a shared secret rather than an identity; and the #5055
cross-site guard is a browser-CSRF defense that a non-browser client passes by
design.

**How the caller is identified.** The peer's UID is read out of the kernel's
socket table (`/proc/net/tcp` and `/proc/net/tcp6`), resolved to an account name
via `/etc/passwd`, and then to a class via `system login user <name> class`. The
caller supplies no part of the answer, so there is nothing to forge.
`SO_PEERCRED` would answer the same question but only for AF_UNIX, and this is
an AF_INET listener.

Three properties make the lookup safe rather than merely plausible. Each has a
mutation proof; each was added because its absence was a live bypass.

- **Both the local AND remote address must match exactly.** The first
  implementation asked INET_DIAG through `netlink.SocketGet`, assuming a request
  carrying a 4-tuple is answered for that 4-tuple. It is not: the library issues
  an `NLM_F_DUMP`, whose kernel-side filter (`inet_diag_dump_icsk`) matches on
  family, states, `idiag_sport` and `idiag_dport` and **ignores the addresses**,
  then returns the first reply without checking it. Identity was decided by port
  pair alone — and since every address in 127/8 is bindable by any local user, a
  caller that reused the source port of a root-owned connection was reported as
  **root**. Demonstrated: with one socket at `127.0.0.2:35591`, a query for
  `127.0.0.9:35591` returned uid 1000 and a reply whose id read `127.0.0.2`.
  netlink is gone; the socket table is read directly, matched in full.
- **Only a socket in `TCP_ESTABLISHED` yields a UID.** The kernel reports UID 0
  for a TIME_WAIT mini-socket, so without the state check a caller that closes
  right after writing the request is reported as **root**. Demonstrated by
  mutation, running as uid 1000.
- **Resolution happens at accept, once per connection** (`connContext`), not per
  request. Deferring it lets the caller pick the moment — and pick to make it
  fail (see the precedence rule below).

Those accept-time lookups are **admission-controlled**: a pool of
`maxConcurrentPeerLookups` (1024) tokens bounds how many run at once, because the
wedge that motivates the bound is inside the interface enumeration holding its
own mutex, where a context would not help — only admission control would. Past
the cap a connection resolves IMMEDIATELY to an unattributable local identity,
which DENIES, reached without spawning anything.

**There are TWO such pools, split by whether a connection can reach that
enumeration (#6974).** `authz.couldBeLocal` short-circuits on loopback delivery
and returns *before* `isLocalAddr`, so a loopback-delivered connection never
takes `localAddrCache.mu` — it cannot participate in the wedge, and it draws on
`peerLookupLoopbackSlots` instead of the pool defending the connections that can.
On the default `127.0.0.1` posture that is every connection, which is what stops
an on-box unprivileged process exhausting the routable listeners' budget by
opening TCP connections alone, unauthenticated and without sending one HTTP byte.

The acquire stays **at accept** and the slot is still held across the lookup —
that call *is* the wedge, so moving the acquire after authentication would move
it past the thing it protects. A **per-listener** split (the other refinement
#6974 proposed) was declined: `localAddrCache.mu` is process-global, so under a
real wedge every listener blocks on the same mutex whatever the partitioning is,
and per-listener pools would multiply the goroutine bound while buying no
isolation. Splitting on *reachability of the mutex* does buy it, because the two
classes contend for different things. The predicate is
`authz.LoopbackDeliveryCannotEnumerate`, single-sourced with the short-circuit it
depends on so the two cannot drift; that it really does avoid the enumeration is
measured in `pkg/authz/peer_loopback_noenumerate_6974_test.go`, with a negative
row so the claim is not vacuous.

The pool's accounting has three rules and all three are load-bearing: a running
lookup HOLDS a token, a finished one RETURNS it, and a connection REFUSED
admission touches the count in neither direction. Get the second wrong and the
pool stops being a concurrency ceiling and becomes a *lifetime budget* — the
1024th connection ever accepted exhausts it permanently and every connection
after it is denied, which is a total management-plane lockout reached by ordinary
use with no attacker and no wedge. Get the third wrong in the releasing direction
and the pool admits past the cap it exists to enforce.
`TestPeerLookupSlotsAreReturned_5561` pins all three.
`PeerLookupSlotsInUseForTest()` and `PeerIdentityWaitersForTest()` are the
accept-side and request-side gauges; a wedge pins both at once.

An **`api-auth` credential** is the second identity. It authorizes as a
full-power principal, which is what it already grants (#4047 makes it the sole
gate on an off-loopback bind), so narrowing it would be a separate breaking
change.

**Precedence: when the caller is LOCAL, the peer identity is authoritative.** A
credential may speak only for a caller the login model does not describe, or one
that is not on this host. The four outcomes are explicit because the interesting
one is the failure:

| peer lookup | principal |
|---|---|
| local, attributed to a `system login user` | that class |
| local, attributed to an account **outside** the login model | **DENIED** |
| local, **NOT** attributable | **DENIED** |
| not on this host | a credential may speak for it (remote administrator) |

Rows 1-3 collapse to one sentence: **a caller this host can PLACE never reaches
the credential check.** If such an account needs access it is given a class —
that is the one place access is supposed to be written down.

Read "can place", not "is local". The two are not the same, and the gap between
them is where the residuals live: placement is **namespace-scoped** (a container
on this box has its own `/proc/net/tcp` and its own interface list, so it is
local to the machine and unplaceable by this daemon) and **time-scoped** (an
address can arrive or leave between the two observations). A caller this host
cannot place is governed by the `api-auth` credential — which is exactly what
#4047 makes that credential for, not a leak in it. See
[Residuals](#residuals).

Row 4 is the only one that *admits* on the strength of a negative, so it carries
one extra obligation: the "not on this host" verdict was drawn at accept from a
**cached** interface-address snapshot, and the credential row **re-derives it
from a fresh interface enumeration** (`authz.PeerCouldBeLocalNow`) before
honoring the credential. That re-derivation can only move a caller from row 4
into a denial, never the other way, so it narrows row 4 without widening
anything. It closes the direction that motivated it — an address ADDED since the
snapshot — and cannot close the reverse; see [Residuals](#residuals) for which
direction is which. It runs **after** the
credential is validated — a caller presenting none cannot drive a kernel
enumeration.

**Every input to the decision is read after the last thing that can block.**
An authorization verdict is only as current as the state it was drawn from, and
this gate has two blocking steps a request can sit inside for a long time:
`pendingPeer.wait` (up to `peerLookupTimeout`, 5s, and the caller can lengthen
its own by connecting while the socket table is contended) and, on the
credential row, the fresh interface enumeration above (single-flighted, so a
request can wait out another goroutine's). Both used to sit *after* the state
they superseded had already been captured:

- The active config was read *before* the peer wait, so a `commit` demoting a
  `super-user` to `read-only` — or deleting it from `system login user`
  outright — did not reach that principal's own in-flight request. The wait now
  comes first and the snapshot is read after it (`authorizeInputs`), so exactly
  one snapshot feeds both the principal's class and `Authorize`, and nothing
  blocks between the read and the verdict. Since round 10 this ordering no
  longer decides the *outcome* — pass 2 re-reads the snapshot unconditionally
  and would overrule a stale pass 1 — but it still decides **when** the denial
  lands: with the fresh read, a revoked caller is refused before the gate
  buffers a byte on its behalf; with the stale one it is admitted into the
  caller-controlled body drain first. `TestConfigSnapshotIsReadAfterThePeerWait_5561`
  asserts that timing (a body-carrying route whose body is declared and never
  sent must still answer 403), because an assertion on the status alone passes
  under either ordering.
- The credential principal was minted *before* the enumeration. It is a value
  and `ReplaceAuth` swaps a pointer, so a rotated or revoked secret did not
  invalidate a principal already speaking. The credential is now re-validated
  against the LIVE snapshot after the enumeration (`authz.go`, the second
  `s.credential(r)` inside the credential branch); a request whose secret was
  revoked mid-flight is denied. The re-check compares the *credential*, not
  snapshot pointer identity — the reconciler republishes on every commit, so
  pointer identity would 403 a valid caller for an unrelated commit.

The residual is named rather than papered over: a `/etc/passwd` read still
separates the snapshot from the verdict on the peer-UID row. Snapshot and
decision cannot be made simultaneous without holding the config store's lock
across the whole gate; they can be made adjacent.
`authz_freshness_5561_test.go` pins both orderings, each case with a control
that must be ADMITTED so a reverted ordering cannot be "caught" by an unrelated
403. Which case pins which is worth being precise about, because for the
credential bullet it is *not* the obvious one:
`TestConfigSnapshotIsReadAfterThePeerWait_5561` pins the first, and
`TestCredentialRereadDeniesBeforeTheBodyIsSupplied_5561` — not
`TestRevokedCredentialCannotFinishAnInFlightRequest_5561` — pins the second.
The next section says why.

**What `TestRevokedCredentialCannotFinishAnInFlightRequest_5561` actually
proves, stated precisely (#6645 r21).** It proves a DISJUNCTION — that *at
least one* live credential re-validation happens between `PeerLocalityFn` and
the handler — not that the re-read inside the credential branch is the thing
doing it. There are two independent live re-validations on that path, and they
MASK EACH OTHER: reverting the credential branch to return the principal minted
before the enumeration leaves the test green, because the mutation gate's second
pass (`reauthorizeInputs`) still re-derives; deleting that second pass also
leaves it green, because the credential branch still re-reads. Measured, at
`-count=2`, all three cells:

| mutation | result |
|---|---|
| credential branch returns the pre-enumeration principal | PASS |
| second-pass `reauthorizeInputs` deleted | PASS |
| **both** | **FAIL** |

So no single-site deletion distinguishes, and an earlier revision of this
section — which said the test "pins both" — overstated it.

Isolating the credential-branch re-read specifically needs a case the second
pass cannot answer, and
`TestCredentialRereadDeniesBeforeTheBodyIsSupplied_5561` (#6645 r22) is it: a
body-carrying route (`POST /api/v1/config/set`) whose body is declared and never
sent, with the FIRST pass blocked inside `Config.PeerLocalityFn`, the credential
revoked while it is parked, locality released, and a **prompt 403 required
before the body is supplied**. Only pass 1 runs before the body, and within pass
1 only the branch's own re-read can see a revocation that landed after the check
at the top of `principalFrom` — so the denial has exactly one possible author.
Its control arm must PARK rather than answer, which is what makes "prompt"
mean something. Measured against the same three cells:

| mutation | `…CannotFinishAnInFlightRequest` | `…RereadDeniesBeforeTheBody` |
|---|---|---|
| credential branch returns the pre-enumeration principal | PASS | **FAIL** |
| second-pass `reauthorizeInputs` deleted | PASS | PASS |
| **both** | **FAIL** | **FAIL** |

The middle row is the point as much as the first: the new case stays green when
the *second* pass is deleted, so it isolates the branch re-read rather than
restating the disjunction. Two guards that each cover for the other read as
redundancy and are actually a gap — worth recognising as a shape, not just as
this instance.

**And the gate is not the last thing that blocks.** Ordering the gate's own
blocking steps is necessary and was not sufficient, because the *handler* blocks
too — on the one input the caller owns outright, its request body.
`decodeJSONBody` reads it after the middleware has already returned its verdict,
for as long as `apiReadTimeout` (30s) allows, and the caller chooses how long
that takes:

```
send headers for POST /api/v1/system/action, withhold the body
  -> the gate authorizes; the handler is entered and parks in Decode
another session revokes the credential / demotes the class
  -> nothing re-reads it
supply {"action":"reboot"}
  -> the box reboots on an authorization made 30 seconds ago
```

So the body is drained **inside the gate**, between two adjudications:

| step | why it is where it is |
|---|---|
| **pass 1** | Fail-fast, and it comes first for *availability*, not authorization. Buffering before deciding would let any caller that can open a socket park daemon memory behind a 30s read timeout. With the check first, only a principal already authorized for **this** route can make the daemon hold a buffer. That is a necessary bound and not a sufficient one — the cheapest permission on the surface is `PermView`, held by a `read-only` shell account — so the drain is bounded again below. |
| **drain** | The caller-controlled block, moved in front of the verdict that admits the mutation, and bounded in **three** dimensions. **Per route** (`restMutationBodyLimits`): `POST /api/v1/config/load` keeps the 16 MiB whole-configuration ceiling, config edits get 1 MiB, diagnostics and `system/action` get 64 KiB, and the routes whose handlers never read a body are **not buffered at all** — their own immediate answer is restored rather than moved behind a read the caller controls. That no-body class is `security/sessions/clear`, `security/counters/clear`, and the candidate-lifecycle and commit verbs addressed by the `X-Config-Session` header alone: `config/enter`, `config/exit`, `config/commit`, `config/commit-check` and `config/confirm`. `dhcp/identifiers/clear` is deliberately *not* in it — #4794 made it decode an optional body, so it keeps the ordering — but note its 413 threshold **moved from 16 MiB to 64 KiB**: the gate's ceiling now trips before the handler's own `MaxBytesReader`. **In aggregate** (`mutationBodyBudgetBytes`, 64 MiB): a request is charged for the buffer it has actually ALLOCATED, grown as the caller's bytes arrive, and is refused **429** when a growth step would breach its share — so the memory a caller can pin is capped no matter how many sockets it opens, and a declared `Content-Length` buys nothing on its own. **Per privilege tier** (`mutationBodyTierCeilings`): that aggregate is partitioned by the permission the route requires — view 8 MiB, clear 16 MiB, config 48 MiB, maint 64 MiB — so a caller flooding the cheapest routes cannot deny a privileged one. (`PermControl` had an equal-to-clear row from round 11 to round 19 and it was **vacuous**: no route requires that permission and the lookup is keyed on a route's requirement, so the row was never consulted. It is gone; the unlisted-permission fallback assigns the smallest share, so a `PermControl` route added later is bounded from the moment it exists.) The guarantee is **one-directional**: each ceiling is tested against the *aggregate*, so a tier is protected only from the tiers strictly below it, and a privileged flood can still refuse a cheap one (scheduling, not a denial primitive). That is a statement about **tiers**; it reads as a statement about **privilege** only while the tiers a principal can reach grow with its privilege, which holds for the **system-defined** classes (`read-only` ⊂ `operator` ⊂ `super-user`) and not for a **custom** one. `set system login class configure-only permissions configure` compiles to `[PermConfig]` — configure *without* view — and commits, so its holder reaches the 48 MiB configure tier while holding a strict **subset** of what a `[ configure view ]` class holds, and 8 MiB of flood (not 48 — what must be cleared is the victim's lowest tier) refuses that richer principal's view-tier request, on a route the flooder is itself answered **403** on. No assignment of the four numbers repairs it: the ladder is a total order over single permissions and the lattice is a partial order over permission **sets**. Fixing it means re-keying the reservation on the permission set or per principal, giving up the property route-keying has — a super-user's pings cannot crowd out that same super-user's commit — and that trade is not made here (#6954). That is also why view is **half** what clear gets rather than the same 16 MiB round 11 first gave view, clear and control alike: equal shares put no tier below any other, so a view tier driven to its own ceiling left the clear tier nothing, and 383 sockets on `diagnostics/ping` from a `read-only` account made a super-user's 24-byte `dhcp/identifiers/clear` answer **429**. Each step reserves the **peak charge** of the largest body the tier above it can carry — peak, not body size, because a buffer growing by doubling holds the old allocation and the new one across the copy, so a body that steps to a route's limit *L* is charged 1.5*L* (16−8 = 8 MiB ≥ the 96 KiB a 64 KiB clear body drives; 48−16 = 32 MiB ≥ the 24 MiB a 16 MiB `config/load` drives; 64−48 = 16 MiB ≥ 96 KiB for `system/action`), and 8 MiB still holds **127** concurrent *maximum-size* view bodies (measured: the 128th cannot reach 64 KiB, because its own last doubling would peak at 96 KiB). Round 18 stated those steps in **body** bytes and configure−clear came out **one byte short** — a clear tier at its own ceiling made a super-user's 16 MiB `config/load` answer 429, the exact primitive the ladder removes — because the buffer then grew a whole extra doubling to hold the one byte that DETECTS an oversized body, peaking at 2*L*+1. That byte now lands in a one-byte scratch array instead (round 19). The read is still at most `limit+1` bytes. An oversized body answers **413 from the gate on every route** — same status and same body `decodeJSONBody` writes, measured byte-identical on the wire — and a body of exactly the limit is handed to the handler whole, with the 400/413 split landing exactly on `limit`. One thing is **not** preserved and an earlier revision of this table claimed it was: `http.MaxBytesReader` marks the response `requestTooLarge`, so the pre-gate 413 carried `Connection: close` and the gate's does not. That predates the scratch-byte change — the gate's first commit already took the write away from `MaxBytesReader` — so it is a long-standing wire-level difference, not a round-19 regression. |
| **pass 2** | The verdict the handler actually runs under. It re-reads the **live** half — the config snapshot and the api-auth credential, the two things a commit can change under an in-flight request — **on every row**, not only on the credential row. The credential re-check used to sit inside `principalFrom`'s off-box branch, which an attributed *local* caller never reaches, so a configured administrator on this host could present secret A, withhold its body, let another session rotate A to B, and still have the mutation run; the same hole in its worst spelling let a request admitted while the listener had *no* api-auth stay credentialless after a commit added one. The **connection-fixed** half (the accept-time peer UID, and the credential row's locality re-derivation) is reused: a connection's addresses do not change mid-request, and re-enumerating interfaces per pass would make every credentialed mutation pay twice for an unchanged answer. The `/etc/passwd` resolution *is* repeated, deliberately — it is a page-cached read of a small local file, and repeating it means an account deleted mid-request is noticed. |

Two residuals, both named. Locality is answered from an enumeration started on
pass 1, so an address added to this host *while the body was being read* is not
seen — the same direction [Residuals](#residuals) already names for the
accept-time snapshot (a scan cannot observe an address that arrives after it),
widened from the snapshot's TTL to the body window. And a handler that read its
body in pieces, or blocked on something else of the caller's choosing after the
decode, would reopen a window the gate cannot see; every mutating handler today
decodes once, up front, before it acts.
`TestAuthorizationIsRemadeAfterTheCallerSuppliesItsBody_5561` drives both
revocation shapes — a class demotion (caught by the fresh snapshot) and an
`api-auth` revocation (caught by the fresh credential check) — because a fix
that re-read only one of the two leaves the other on the old behaviour. It also
pins the enumeration count at exactly one per request.
`TestLocalCallerCredentialIsRevalidatedAfterTheBody_5561`
(`authz_bodywindow_5561_test.go`) drives the **intersection** those two rows
leave empty — a LOCAL attributed caller whose credential is rotated, or newly
required, inside the window — which is exactly where the credential re-check
did not run. `authz_bodybudget_5561_test.go` owns what the window may cost:
`TestPerRouteBodyLimitIsEnforced_5561`,
`TestGateBodyBufferIsBoundedInAggregate_5561` (concurrent requests really
holding more than the budget must be REFUSED, not admitted), and
`TestEveryGuardedRouteDeclaresABodyLimit_5561`, which keeps the permission and
body-limit tables from diverging.

**The observability hooks these cases wait on are PROCESS-GLOBAL, and that is a
test-hygiene obligation (#6645 r22).** `MutationBodyWaitersForTest`,
`MutationBodyBytesAdmittedForTest` and `PeerLookupSlotsInUseForTest` are
package-level gauges shared by every `api.Server` in the process, so "some
request is parked" and "*this* case's request is parked" are the same
observation unless the count is known to have started at zero. Two rules keep
them meaningful, and both are load-bearing rather than tidiness:

- A case that waits on a waiter edge passes a BASELINE it read immediately
  before opening its own request: `waitForNewMutationBodyWaiter(t, baseline)`
  waits for the count to rise ABOVE it (#6977). That is attributable by
  construction — a request somebody else left parked raises the baseline too, so
  only a NEW park can answer the wait. The earlier form accepted any count above
  zero and was made attributable by calling `waitForGateQuiescent` first; that
  works, but it is a convention living in a different statement — for
  `parkFlood`, a different function — from the wait that depends on it, and it
  does not survive a case that parks TWICE, where the second wait is answered by
  the first park. `waitForGateQuiescent` is still the right precondition where a
  case asserts on the aggregate BYTE budget, which is a level rather than a
  delta.
- A case must not RETURN with a request still parked. `authzServer`'s cleanup
  closes the server and then waits for the gate to go quiescent, which puts the
  failure on the case that leaked rather than on whichever innocent case
  `-shuffle` ran next. `TestNoBodyRouteIsNotBufferedByTheGate_5561` ends by
  design with a control request parked on a body it never finishes (measured:
  `waiters=1 admitted=512` at the end of its body), so it hangs up and drains
  explicitly.

The same shape bit the accept-time pool from the other side until #6977.
`connContext` registers `defer close(p.done)` FIRST and the token release
SECOND, and defers run LIFO, so the token is back before `p.done` closes: a
caller that joins on `p.done` knows the slot is available as well as that the
lookup finished. In the order that shipped the two were reversed, `p.done`
closed first, and a case that joined on it (or simply drove HTTP and read the
response) returned while the token was still out — so a case that then filled
the pool observed a preceding lookup's transient token and failed on its own
precondition, `pool holds 1024 tokens before the case starts, want 1023`, with
nothing wrong in production. `TestPeerLookupSlotsAreReturned_5561` still waits
for genuine zero occupancy before filling the pool; that precondition is now
belt-and-braces rather than the thing standing between the case and a spurious
failure. The ordering is pinned structurally by
`TestPeerDoneIsClosedAfterTheSlotIsReturned_6977` — the property is a
happens-before with no deterministic behavioural seam, so a source-order
assertion is the honest instrument and the behavioural cell beside it states the
invariant rather than detecting its absence. And because a SAFE request never enters the
mutation gate, nothing on its request path waits for the lookup at all, so
`TestPeerIdentityIsResolvedAtAccept_5561` reads its resolver counts through
`waitForPeerLookupsToFinish` (count reached *and* pool empty) rather than
sampling when the response lands.

`authz_bodybudget_fairness_5561_test.go` owns the other direction of the same
availability property — that the bound is not itself a denial lever.
`TestHalfOpenBodyIsChargedForWhatItHoldsNotWhatItDeclared_5561` pins the
denomination (a socket that declares a route ceiling and sends one byte is
charged for one small buffer, not for the declaration);
`TestLowPrivilegeCallerCannotDenyAPrivilegedOne_5561` drives the exact shape
that broke — a `read-only` principal opening enough half-open `diagnostics/ping`
requests to have emptied the undivided budget, after which a super-user's
`config/set` must still be served;
`TestViewTierSaturationLeavesHeadroomForTheConfigureTier_5561` does the same
with real bytes and asserts the view tier is capped with a whole-configuration
load still free behind it;
`TestViewTierFloodCannotDenyTheClearTier_5561` drives the *view-versus-clear*
step — a `read-only` flood saturating the view tier, after which a super-user's
`dhcp/identifiers/clear` must still be served — which is the step the equal
16 MiB shares left unprotected;
`TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561`
states the ladder in the units of the work it protects (a merely monotonic
ladder can still protect nothing), walking **every** privilege step derived from
`config.LoginClassPermissions` against the *measured* peak charge of the largest
body derived from the route tables — `peakChargeForMaxSizeBody` binary-searches
the smallest ceiling at which production `bufferMutationBody` admits such a body,
so one side of every comparison comes from the code rather than from a second
human-written number — and holding the operational tiers to a concurrency floor
so separating them by starving one is caught too;
`TestATierAtItsCeilingCannotRefuseTheTierAboveIt_5561` then *spends* those
numbers, pinning each lower tier at its ceiling and requiring a real max-size
request for the tier above to be admitted;
`TestBufferedBodyLimitBoundaryIsUnchanged_5561` is the over-reach guard on that
charge fix — 413 starts at exactly `limit+1` and everything under it reaches the
handler byte for byte, which held before the fix and holds after;
`TestEveryGuardedRouteDeclaresABodyTier_5561` keeps the ladder covering the
routes it arbitrates between **and** rejects a tier row no route requires; and
`TestBodyBudgetReservationIsReleasedOnEveryExitPath_5561` binds the release on
each of the three exit paths (handler returned, caller hung up mid-body, body
overran the ceiling) rather than leaving it to whichever later test inherits a
poisoned counter.

Membership of the no-body class is checked against the handlers themselves, not
asserted: `TestNoBodyClassMatchesTheHandlersThatDecode_5561` sends every guarded
route a malformed body and requires the set that DECODES it to be exactly the
complement of the class. A probe that asked "did this request park" would be a
tautology — the gate parks a buffered route whether or not its handler would
have read anything — which is how five routes sat in the buffered class while
answering from headers alone. `TestNoBodyRouteIsNotBufferedByTheGate_5561` then
pins the resulting behaviour across the whole class, with a control
(`config/set`) that parks because its handler decodes rather than because of how
it is classified.

The rule has been narrowed twice, each time because a weaker version had a hole
the claim did not admit to:

- **v1** used the peer UID when the lookup *succeeded* and fell back to the
  credential otherwise. The caller controlled whether it succeeded: a
  `read-only` account holding the api-auth secret escalated to full power by
  calling `shutdown(SHUT_WR)` before the request was authorized — 403 when
  polite, **200 on `/config/enter`** when hostile. A precedence rule that only
  holds on the success path is not a precedence rule.
- **v2** denied an *unattributable* local caller but still let the credential
  speak for an *attributed* one outside the login model — the exact population
  #5561 exists to constrain. It made the per-principal gate optional for anyone
  holding the shared password, and it contradicted `docs/system-login.md`, which
  already said such a caller is denied.

**What "local" is allowed to mean.** Absence from *this* namespace's socket
table is not evidence of being off-box: a peer in another network namespace
appears in neither `/proc/net/tcp` nor `net.InterfaceAddrs()` here, and calling
that "remote" would hand it the credential — the same unsound "not found means
remote" inference that produced the v1 bypass. So "remote" is never inferred
from a failed lookup.

It is bounded instead by the delivery address: **a connection delivered on a
loopback address is treated as local.** Under a default configuration that is
also true — martian filtering drops packets carrying loopback addresses that
arrive on a real interface — but it is a *conservative* rule, not a guarantee:
`route_localnet=1`, `IP_TRANSPARENT` and DNAT-to-loopback each defeat that
filtering. The rule still **fails safe** under all three, because each of them
classifies a *remote* caller as local, and a local caller with no socket row is
denied. **That rule** over-denies; it never inverts — scoped to the loopback
rule, not a claim about the classification as a whole, two of whose
[residuals](#residuals) do grant. A routable delivery address
falls back to "is the peer one of *our* addresses", sound positively and
carrying the residuals below negatively.

The classification is consulted **after** the socket-table read, not before it,
and only where the table has nothing to say — a matched row settles locality on
its own. A row that matches the 4-tuple but whose state or uid column will not
parse proves a socket exists without naming its owner: local, unattributable,
denied, and logged once per scan rather than dropped in silence.

**A failed table read denies unconditionally — including a remote administrator
holding a valid credential.** If you are diagnosing a total management-plane
lockout, this is the paragraph you want. Two states are read failures, and both
deny: **any** candidate table that could not be read (hidepid, an LSM
confinement, a `/proc` remount, ENOMEM under pressure) — *one* of two is enough —
and **no** candidate table read at all. In either, `LookupPeer` returns
*local-and-unattributable* for every caller, so every `POST /api/v1/config/*`
answers **403** until `/proc` recovers, whoever is calling and whatever
credential they present. It does **not** fall back to the address rule "in both
directions"; an earlier revision of this document said it did, and that was
wrong.

That is the deliberate trade, and the direction is the reason. The alternative —
falling back to the address rule on a failed read — makes a *negative* answer
decisive on the strength of an observation that was never made: the caller's row
may be in exactly the file that failed (`tcp` and `tcp6` are alternatives, not
duplicates, so a partial failure is *half* an observation, not a small one), and
a local caller the cached snapshot did not recognise would be reported off-box
and handed the credential path. One side of that trade is an availability outage
on a box whose `/proc` is broken; the other is a privilege-boundary bypass. Only
the second is unrecoverable, so the read failure denies.

An **absent** table is not a failed read, and the distinction is load-bearing:
`scanBatch` skips ENOENT, so a kernel with no `/proc/net/tcp6` alongside a
readable `/proc/net/tcp` reads normally and nothing is denied. Absence only
denies when it leaves *nothing* read — zero files read **and** zero failed —
which is the state a scope-qualified IPv6 caller reaches when `/proc/net/tcp6`
is missing, since `tcp6` is that caller's only candidate. The recovery is to
restore `/proc/net/tcp{,6}` readability for the daemon's UID; no config change
reopens the surface, by design.

<a id="residuals"></a>
**Residuals, stated rather than papered over.** There are FOUR, and they are not
the same kind — an earlier version of this header said "the first two over-deny
and grant nothing; the third is closed", which under-counted the list and
mischaracterised it. Read the kind before the detail:

| # | residual | kind |
|---|---|---|
| 1 | DNAT to loopback | over-denies; grants nothing |
| 2 | Another network namespace | **open** — spatial |
| 3 | A brand-new local address | **closed** |
| 4 | Address churn between accept and adjudication | **open** — temporal |

Only #1 over-denies. Only #3 is closed. #2 and #4 are open, both grant, and they
are one shape rather than two curiosities:

> The locality re-derivation answers **"is this address on this host, in my
> namespace, right now."** The question authorization actually needs is **"was
> this caller local when it connected."** Those coincide for the case the fix was
> written for and come apart in two directions.

- **Spatially** — a caller local to the BOX but not to the daemon's network
  namespace. Both halves of the lookup are namespace-scoped, so it reads as
  remote. That is the container case below.
- **Temporally** — a caller whose address was on this host at accept and is not
  by the time the request is adjudicated. A fresh scan is by construction fresher
  than the connection, so it cannot see that. That is the churn case below.

Be precise about what the address-snapshot fix closed, because "closed" without a
direction is what the previous version of this list got wrong in the other
direction. It closes the case that motivated it — an address ADDED recently,
where a stale cache said *not local* and handed the caller the credential. It is
**definitionally unable** to close the reverse: a scan cannot observe an address
that is already gone. Both remaining cases need the `api-auth` secret *plus*
timing, and neither is a regression — before #5561 any secret holder had full
power unconditionally, so this is a narrowing with a race hole in it rather than
a new hole.

- **DNAT to loopback.** If a remote connection is redirected to a loopback
  address before it reaches the listener, the delivery address is loopback, the
  caller has no socket row here, and it is denied — so a legitimate remote
  administrator behind such a redirect cannot use the mutation surface even with
  a valid credential. This is the most plausible of the three; bind
  `web-management` to a real address rather than DNAT-ing to loopback.
- **Another network namespace, off-loopback bind — the SPATIAL case of the shape
  above, and an argument corrected.** A
  container's veth peer and a real remote client are indistinguishable in the
  socket table, so a netns caller on a routable bind reaches the credential path.
  Both halves of the lookup are namespace-scoped: `findPeerSocket` reads only
  *this* namespace's `/proc/net/tcp{,6}`, and `PeerCouldBeLocalNow` repeats the
  same namespace-scoped `net.InterfaceAddrs()` test, so a peer in another
  namespace produces a clean no-match in both and lands `(OK=false, Local=false)`.

  An earlier version of this list argued the path was narrow because "an
  unprivileged user cannot get there": `unshare -Urn` yields a namespace
  containing only `lo`, and attaching a veth to the host needs CAP_NET_ADMIN in
  the host namespace. **That reasoning does not hold, and it is the wrong thing
  to lean on.** A caller does not have to *create* its own namespace. A process
  inside an already-provisioned container — Docker, Kubernetes,
  `systemd-nspawn` — is handed a veth by the runtime and needs no capability of
  its own; possession of the shared credential is then sufficient.

  The correct statement of the bound is not "nobody can get here", it is **what
  governs a caller who does**: a peer this host cannot place is treated as
  remote, and the `api-auth` credential is the authority for it. That is the
  design #4047 mandates — on an off-loopback bind the credential is the sole
  gate — not a leak in it. The operational consequence is concrete and worth
  stating plainly: **a container on this host that holds the `api-auth` secret
  has the same power over the mutation surface as a remote administrator
  holding it.** If that is not wanted, do not give containers the secret, and
  keep `web-management` on loopback where `couldBeLocal` short-circuits before
  any of this applies.
- **A brand-new local address — the direction that IS closed.** The
  host-address snapshot is refreshed at most once per second, for hits *and*
  misses, so for up to a second after an address is added to this host a caller
  arriving from that address is classified **off-box**. An earlier version of
  this list claimed such a caller "still cannot escape a class it holds, because
  a local caller with a class is only reachable through the socket table, which
  is not cached." **That was backwards.** Being classified off-box meant the
  socket table was never read at all — `LookupPeer` short-circuited on
  `!couldBeLocal` before consulting it — so the caller landed on the credential
  row, which authorizes as a *full-power* principal. The staleness granted
  access; it did not over-deny.

  It was reachable, not theoretical: address adds are observable to any
  unprivileged account (`ip monitor address` needs no privilege) and this box
  performs them routinely — VRRP VIPs on failover, DHCP leases, RA-derived
  addresses. Reproduced against one live ESTABLISHED socket, changing only
  whether the snapshot predated the client's address add:

  ```
  truthful cache : OK=true  Local=true  uid=1000
  stale cache    : OK=false Local=false uid=0  "peer 10.166.99.1 is not on this host"
  ```

  Two changes bound it, and neither is the cache. They close the ADDED
  direction; residual #4 below is the reverse, which they cannot reach:

  1. **The socket table is read first.** `couldBeLocal` is consulted only where
     the table has nothing to say. A row hit proves locality from the kernel, so
     for any caller that has a socket — which is every caller that can read a
     response — the cached negative decides nothing. The early-out existed only
     to keep churn off the table, and the single-flight batcher had already
     removed that argument (120 concurrent fresh connections: **3** reads in
     82 ms).
  2. **The credential row re-derives locality.** The one case the table cannot
     answer is "no row at all", where a local caller that reset its own socket
     before the read still meets the stale negative. It cannot read a response,
     but the handler still runs, so a fire-and-forget commit is a real outcome.
     `authz.PeerCouldBeLocalNow` answers that case from a *fresh* enumeration.

  What remains is an over-denial: for at most a second, a local caller with no
  socket row is denied instead of resolved to its class.

  **Bounds (of the closed direction).** It required an *off-loopback* bind (on
  the default loopback bind
  `couldBeLocal` short-circuits before the cache is ever consulted, so the
  default posture was provably never exposed), a configured `api-auth` secret in
  the caller's hands, and an address added to the host within the last second.
  `pkg/config/compiler.go` still rejects an off-loopback bind with no `api-auth`
  at strict commit (#4047), so those two conditions travel together.
- **Address churn between accept and adjudication — the TEMPORAL case, and
  the direction that is NOT closed.** A *successful*
  enumeration that finds nothing is not proof the caller is off-box — errors
  fail closed, omissions cannot. A clean no-match reads the same whether the
  caller is genuinely remote, in another namespace, or was on this host a moment
  ago and is not now. The last is reachable without the caller doing anything
  privileged, because it can ride address churn the **system** performs: on this
  product a VRRP VIP moves on every failover, and DHCP and RA churn constantly.
  Both observations are used rather than one — the accept-time verdict still
  denies before the credential row is reached, and the fresh check adds denials
  for callers that only became placeable later — but neither covers an address
  that appeared *and* vanished between them. Closing that needs address-change
  notification (`RTM_NEWADDR`) rather than two point samples, and is not
  attempted here. The bound is the same one as for the namespace residual above:
  a caller this host cannot place is governed by the `api-auth` credential.

**Scoped IPv6 is refused, not guessed.** `/proc/net/tcp6` prints only the 128
address bits, never the scope id, so two link-local callers on different
interfaces render an identical key and the first matching row would win — an
order-dependent identity, the same defect class as matching on ports alone. A
scope-qualified peer address that we would otherwise have to *attribute* is
therefore reported local-and-unattributable (denied). Mutating the guard out
attributes such a caller **uid 0**.

The refusal is checked **after** the locality classification, deliberately: a
scoped peer that is *not* on this host is a remote administrator reaching an
IPv6 link-local management bind, and refusing before the locality test locked
out every credentialed remote on such a bind.

**UID 0 is authorized unconditionally**, without consulting `/etc/passwd` or the
active config. Root owns the daemon and the on-disk config DB, so denying it
would be theater — and making root's access depend on an active config would
lock the operator out of a box that has not loaded one yet.

**Route table.** `restMutationPermissions` is an ALLOW-list keyed by the exact
`"METHOD /path"` a route was registered under; permissions mirror
`pkg/cli/permissions.go` so `curl` and the CLI answer the same. A non-safe
method with no entry is **denied**, so a future `mux.HandleFunc("POST …")`
without a table entry is inert rather than unguarded.
`TestEveryMutatingRouteHasAPermission_5561` reads the registrations out of
`server.go` and requires coverage in both directions, turning that from a
runtime surprise into a test failure. `POST /api/v1/system/action` is gated at
**maintenance** — the highest permission any of its body-selected verbs needs —
because the middleware does not consume the request body; the effect is that an
`operator` principal cannot use its `clear-config-lock` verb over REST. It
over-restricts rather than under-restricts.

**Safe methods are untouched.** GET/HEAD/OPTIONS/TRACE, `/health`, `/metrics`
and the SSE streams keep exactly their previous access rules (the #4162 metrics
gate and `api-auth` still apply to them).

**What this breaks, and the remedy.** One population changes behavior: a local
process running as a **non-root UID that is not a configured `system login
user`** and presenting no credential. It could previously mutate and commit
config; it now gets `403` naming the reason. Nothing in this repository is in
that population — the CLI speaks gRPC, and the deploy/day-0/harness tooling
reads `/metrics` only — but operator automation might be. Any one of these
restores it:

- run the caller as root, or
- `set system login user <account> class super-user` (the account then also
  gets the class's CLI rights), or
- configure `set system services web-management api-auth …` and present the
  credential.

A denial is confined to the REST mutation surface: forwarding, the dataplane,
the console CLI and gRPC are unaffected, so this cannot brick a running box.

**Identity plumbing.** `connContext` (the `http.Server.ConnContext` hook)
resolves the peer once, at accept, and caches it on the connection;
`http.Request` exposes `RemoteAddr` only as a string and no local address at
all. It must be set on **every** `http.Server` literal, including the #5866
day-2 rebind path in `listener.go` — a listener without it can identify nobody,
which would refuse every mutation on it after an unrelated bind change.
`TestEveryListenerCarriesPeerIdentity_5561` enforces that across the package,
and `TestPeerIdentityIsResolvedAtAccept_5561` pins the once-per-connection
timing (a per-request lookup is what the caller used to be able to defeat).
`pendingPeer` keeps the connection's own addresses for the same reason the hook
exists — the credential row needs them for its locality re-derivation.

`Config` carries two test seams, and they answer different questions at
different moments: `PeerLookupFn` is the accept-time identity, `PeerLocalityFn`
the authoritative locality re-check the credential row performs. Both nil in
production. A case that fabricates an off-box caller over a real *loopback*
listener has to state that premise in both, because the production re-check
enumerates the host's real interfaces and would — correctly — call `127.0.0.1`
one of ours. `TestBrandNewLocalAddressCannotBorrowCredential_5561` leaves the
second one nil on purpose: that is precisely the "accept-time verdict says
off-box, the caller is really on this host" state the re-check exists for.

**Cost.** This is load-bearing, not tuning: the lookup runs once per accepted
CONNECTION, and reading `/proc/net/tcp{,6}` is **not** proportional to row count
— the kernel walks its entire TCP hash table, sized from RAM. Measured on an idle
box carrying 11 and 39 rows, a single raw read costs 4.3 ms and 10.1 ms, and a
full lookup 6-9 ms. Unbounded and per connection, that is a denial of service
available to any local process with **no credentials at all**: a connect loop at
~110 conn/s saturates a core inside the daemon — the same unprivileged local
population #5561 exists to constrain. Three bounds:

- **Single-flight** (`socketscan.go`). One goroutine reads the tables; every
  waiter registered before that read *started* is answered from it, and a waiter
  arriving mid-read is served by the next one. 60 concurrent connections cost
  **2** reads, not 60. The security property is untouched: a connection accepted
  at T is still only ever answered from a read that started at or after T,
  because the batch is taken under the same lock the request was appended under.
- **Off the accept loop.** `ConnContext` runs serially in `http.Server`'s accept
  loop, so the lookup is *started* there but runs in its own goroutine. A request
  arriving before its lookup finishes waits for it; a wedged lookup denies rather
  than hangs, on a deadline stamped **per connection** (not per request, which
  would charge the full timeout again on every request the connection makes).
- **The address snapshot, for the cases the table does not answer.** Locality is
  classified from a cached interface-address snapshot, refreshed at most once per
  second for hits **and** misses — an earlier version refreshed on every miss,
  which is precisely the flooding case, so the amplification was fully intact
  while the comment claimed otherwise. This used to *also* short-circuit the
  table read for a peer that could not be local; that early-out is **gone**, for
  the security reason under [residuals](#residuals). Reinstating the read costs
  nothing measurable because of the bound above — the read it reinstates is the
  batched one.
- **The authoritative locality re-check is behind the credential.** The row-4
  re-derivation enumerates interfaces for real (~32 µs on a box carrying 14
  addresses, against 4.3–10.1 ms for one `/proc/net/tcp` read). It runs only for
  a request that already presented a **valid** credential on a connection
  classified off-box, so an unauthenticated flood — the population that can open
  sockets without holding anything — drives **zero** enumerations, and a caller
  that does hold the credential is authorized regardless. Concurrent
  re-derivations collapse into one enumeration through the same
  waiter-set-before-read batching `socketscan.go` uses, so the batch is answered
  from an observation newer than every arrival in it.
  `TestUncredentialedCallerDrivesNoLocalityRecheck_5561` pins the ordering
  and `TestConfirmationIsSingleFlighted_5561` the batching.

A *local* attacker can still make connections that each join a batched read.
They already have a shell on the box, the cost no longer scales with connection
count, and the outcome is fail-closed.

**Known residual (not #5561).** The READ surface — REST GETs, `/api/v1/show-text`
— is unchanged and remains reachable by any local process on a loopback bind.
#5561 is scoped to the mutation surface; a read-side principal check is a
separate question with a different blast radius (`/metrics` scrapers, health
probes). The gRPC leg (#5278) made the opposite call on ITS surface and gates
reads as well, because its read surface has no scraper population: nothing polls
`GetSessions` on a timer, and `show configuration` there is exactly the render a
`config-viewer` class exists to scope. The two legs therefore disagree about
read gating BY DESIGN, and this is the sentence that says so rather than leaving
a reader to infer a bug.

## Callers

`cmd/xpfd` builds the `Server` from its assembled dependencies and runs it
under the daemon's errgroup. Nothing else imports this package.

## Dependencies

`authz`, `config`, `configstore`, `conntrack`, `dataplane`, `dhcp`, `frr`,
`ipsec`, `logging`, `routing`, `vrrp`.

## NAT show views delegate to `pkg/natshow` (#6565)

`show-text?topic=nat-static` and `topic=nat-nptv6` call
`natshow.RenderStatic` / `natshow.RenderNPTv6` — the SAME renderers the CLI
(`cli_show_nat.go`) and gRPC (`server_show_nat.go`) call. They must never be
reimplemented here.

REST used to reimplement both, printing every rule straight from config. That
third copy made the fail-closed NOT-INSTALLED annotations a per-surface
lottery: #5323 taught two surfaces to annotate a rule the userspace snapshot
builder drops, #6534 taught two surfaces a further set of exclusion reasons,
and each time REST kept rendering the dropped rule as live. CLI and gRPC each
had a byte-equality test against the shared renderer (#1687); REST did not, and
REST is the copy that drifted.

`show_nat_shared_test.go` is the third leg of that invariant. Two things about
its fixture are load-bearing and were both learned by a mutation cell failing
to red:

- **It is staged through the TOLERANT ingress (`Store.SyncApply`), not a
  commit.** Every exclusion `staticRuleNotInstalledReason` reports is also
  hard-rejected by a strict commit gate (`then static-nat inet` by #5859, the
  NPTv6 scope forms by #5818), so an excluded rule cannot reach `ActiveConfig`
  through a commit at all. A commit-staged fixture contains no exclusion, both
  renderers agree byte-for-byte, and the test passes on the UNFIXED code. The
  tolerant ingress — a persisted config at boot, or an HA peer sync — is where
  those gates downgrade to warnings (#1960) and therefore the only path on
  which REST was lying.
- **It carries an excluded rule in EACH view.** With only a static-NAT
  exclusion the `nptv6` subtest compares two renderings that agree trivially
  and passes on the unfixed code.

The test guards both premises explicitly, so a fixture that stops exercising
the drop fails loudly instead of going quietly vacuous.

## Gotchas

- **Management-plane DoS hardening (#4150).** Both `http.Server` literals in
  `NewServer` carry read-side timeouts and a header cap — `ReadHeaderTimeout`
  (`apiReadHeaderTimeout`, 10s), `ReadTimeout` (`apiReadTimeout`, 30s),
  `IdleTimeout` (`apiIdleTimeout`, 120s), and `MaxHeaderBytes`
  (`apiMaxHeaderBytes`, 1 MiB). Header reads happen BEFORE `authMiddleware`, so
  without these a pre-auth slowloris (dribbled headers/body) could pin a
  goroutine/socket per connection once web-management binds a non-loopback
  interface. `WriteTimeout` is deliberately left UNSET (0/unlimited): the SSE
  event/log streams (`/api/v1/events/stream`, `/api/v1/logs/stream`) are
  long-lived and a full metrics/session-table scrape is a large slow response —
  a `WriteTimeout` would sever them. **#6809 correction:** this used to add
  "the response side is bounded by per-handler context deadlines instead",
  which does not hold as written — a context deadline bounds a handler's WORK,
  not a write already blocked in the kernel because the peer stopped reading.
  Cancelling a context releases what the handler owns downstream (a child
  process, a lock) while the goroutine stays parked in `Write`. Only
  `http.ResponseController.SetWriteDeadline` ends that. A streaming endpoint
  therefore has to arrange its own per-write deadline; see the BGP route stream
  below. Separately, every REST MUTATION handler decodes its
  body through `decodeJSONBody`, which wraps `r.Body` in
  `http.MaxBytesReader(maxRequestBodyBytes)` (16 MiB) and returns **HTTP 413** on
  overflow instead of buffering a multi-gigabyte POST to an OOM-kill (config
  `set`/`delete`/`activate`/`deactivate`/`load`/`rollback`/`commit-confirmed`/
  `annotate`, `system/action`, `ping`/`traceroute`, `dhcp/identifiers/clear`).
  Read-only GET handlers do not read a body and are out of scope. Add a new
  mutation handler via `decodeJSONBody`, not a bare `json.NewDecoder(r.Body)`,
  so the cap and 413 are inherited. Pinned by `http_dos_hardening_4150_test.go`.
- **Constant-time credential comparison (#4157).** `authMiddleware` /
  `checkAuthorization` (`auth.go`) validate every credential in constant
  time to avoid a network-timing side channel. API keys and Bearer tokens
  go through `constantTimeAPIKeyMatch`, which compares the presented token
  against EVERY configured key with `subtle.ConstantTimeCompare` and OR-s
  the results — it never short-circuits on the first match (so *which* key
  matched does not leak either) and never uses the old `cfg.APIKeys[token]`
  map lookup (whose latency varied with hash-bucket collisions / presence).
  Basic-auth passwords already used `ConstantTimeCompare`; the username path
  no longer early-returns on `!exists` — it always runs the password compare
  and AND-s with existence, so a known vs. unknown username is not
  distinguishable by response timing. `ConstantTimeCompare` returns 0 on a
  length mismatch (reveals length, not content — acceptable). Pinned by
  `auth_consttime_4157_test.go`, including an AST regression guard that fails
  if any auth path reverts to a bare `cfg.APIKeys[...]` lookup.
- **Day-2 listener + auth reconcile (#5866).** The management server used to be
  constructed ONCE at daemon startup and never reconciled, so a committed
  web-management change (bind address / port / TLS on/off / api-auth) reported
  success while the process kept enforcing the old policy until a restart —
  revoked or tightened credentials stayed usable, a bind removal left the API on
  the old address. Two mechanisms close this:
  - The authentication snapshot is a live `atomic.Pointer[AuthConfig]` (`s.auth`)
    read per request by `dynamicAuthMiddleware`; `ReplaceAuth` swaps it, so a
    revoked/tightened credential is rejected on the NEXT request with no listener
    bounce and no restart. The `authCheck` core is shared with the static
    `authMiddleware`, so the swap enforces byte-identical semantics (the #4157
    constant-time + #5636 empty-secret guards, `/health` + loopback-`/metrics`
    exemptions).
  - **What is published, and when (#5561 rounds 7/9/10/12).** A commit's
    credential set is not published as one atomic thing, because a credential
    change is really two changes with opposite safety directions and a listener
    may be serving an address the commit asked to leave.
    - The **revocation** half goes out FIRST — before either leg is (re)bound and
      regardless of the outcome. Deferring it behind a bind that may never
      succeed left the retained listener honouring a replaced secret permanently
      (round 7), and publishing after the rebind left a freshly-bound socket
      serving under the old snapshot for the width of the intervening HTTPS
      reconcile (round 9; `ReconcileHTTP` serves before it returns).
    - The **grant** half waits until every listener that is SERVING sits at an
      address the committed config names. A credential set is committed together
      with the endpoint it is meant for, so while a listener is retained at an
      address this config asked to leave, only
      `AuthForRetainedListener(live, next)` — the intersection of what that
      listener already accepted with what is still committed — may be enforced
      (round 12). Otherwise a commit that moves management to loopback while
      introducing a credential would, on a failed rebind, publish that credential
      on the routable address the operator was withdrawing. A **nil** live
      snapshot is the UNIVERSAL set, not the empty one (it is the pass-through
      posture), which is what keeps the round-9 case publishing whole. A commit
      with nothing to converge publishes whole, and so does one whose only
      failure was to ENABLE a leg — that leaves no listener behind at all, so
      there is nothing to protect (`mgmtEndpoint.everyLiveLegNamedBy`, round 13;
      the previous `rebinding && len(errs) == 0` was a proxy wider than the
      property, and the excess denied every caller on an address the same commit
      had named).
    - The intersection can be EMPTY, which denies everyone on the retained
      listener until a later reconcile converges. That is deliberate — refusing
      to represent `∅` would mean keeping a credential the committed config no
      longer carries alive on a listener the operator asked to leave, which is
      the round-7 fail-open — and it is acceptable because every state that can
      reach it has an EXIT a later commit reaches: converge the failing bind, or
      commit the address that is actually serving. **It is not, however, visible
      to the operator.** `show system services` reports the retained leg as
      `Listening`, because it genuinely is serving (`pkg/daemon/README.md`
      "Effective-listener snapshot"); there is no HTTPS row at all
      (`sysservices.Listeners` renders gRPC and HTTP only); and `applyConfig`
      logs the reconcile error as a warning rather than failing the commit, so
      the operator sees a SUCCESSFUL commit. The only signal is in the log — the
      `Warn` `reconcileTo` emits naming how many credentials it withheld (counted by
      `CredentialCount`, which skips api-keys mapped to `false` — they authenticate
      nobody and `AuthForRetainedListener` does not copy them, so counting them
      over-reported the withholding), and
      the `Warn` for the incomplete reconcile. Exitability, not diagnosability,
      is what makes the state acceptable; a dedicated HTTPS row in
      `show system services` would be a real improvement and is not in this
      change.
    - **Removing all api-auth is a revocation and lands immediately** (round 14).
      The **nil** — the pass-through — publishes only when every live bind
      address is loopback, because the justification for a nil is the #4047/#5127
      clamp, which `resolveAPIBinds` evaluates against the config being applied
      and never re-evaluates against the listener that is serving. While any live
      leg is still off-loopback, what publishes is the **deny-all** set (non-nil,
      empty). Rounds 7-13 left the live snapshot ALONE there, so the credential
      the operator had just deleted kept authenticating on that routable address
      for as long as the loopback bind kept failing — indefinite, and the exact
      inversion of the instruction. The decision is re-taken after the rebinds
      (`publishNilDirectionLocked`), which is what converges deny-all to nil once
      the loopback bind lands.
    - **Freshness — one COMMITTED generation, endpoint AND credentials** (round
      14, `committedDesired`). An apply caller that snapshots `ActiveConfig()`
      and then waits on the apply semaphore (the DHCP lease-change callback) can
      be overtaken by commits: serializing applies orders them but not their
      CONTENT, so an OLDER generation can still be the last one applied. Rounds
      10 and 12 pinned only the credential half, which left the listener driven
      toward the STALE endpoint under the COMMITTED policy — a hybrid belonging
      to no committed generation. With the policy nil that is an off-loopback
      listener with NO authentication and nothing left to restore; with it
      non-nil, the hybrid's `next` NAMES the stale address, so
      `everyLiveLegNamedBy` reads TRUE and the full set publishes at an endpoint
      the committed config never authorized it for. Deriving both halves from
      `ActiveConfig()` removes both: a stale replay computes the newest commit's
      desired state, so it is a no-op or a bind retry. This fences the management
      listener only; the rest of the apply pipeline reconciling toward a
      superseded generation is #6716.
    - **A RETIRED leg never gains a credential** (round 14). `stopLegLocked` only
      closes a channel — the socket keeps accepting until the serve goroutine
      reaches `Shutdown`, and what it accepted is served for the whole
      drain — while `ReconcileHTTP`/`ReconcileHTTPS` return immediately, and the
      reconciler then publishes. Each leg therefore carries its own `authSlot`:
      LIVE legs FOLLOW `s.auth` (the live swap above is unchanged), and a leg is
      PINNED at retirement to what it was already serving, after which
      `ReplaceAuth` only intersects it. Revocations still reach a draining
      listener; grants and nils never do.

      **The slot travels WITH the server it judges** (#6734, `legPlan`). The
      pin is only worth anything if the slot `pin`/`tighten` operate on is the
      one the handler actually reads. `pkg/api` used to substitute a fresh slot
      for a nil in two INDEPENDENT places — `listenerHandler` when building the
      handler and `serveLegLocked` when registering the leg — so a call site
      passing nil to both would have pinned the leg to one slot while every
      request on it was judged by another, making the retirement pin a silent
      no-op. No production path did that, but nothing stopped one. `legPlan`
      allocates the `*http.Server` and its slot together and `serveLegLocked`
      has no slot parameter at all, so there is nothing left to substitute; the
      `Start` path's `httpLegPlan`/`httpsLegPlan` adopt a missing slot and
      **store it back**, which is what keeps the field, the plan and the leg one
      object rather than three. The guard is behavioural, not a pointer
      compare: pin a leg's slot, rotate `s.auth` away from it, and drive a real
      request through that leg's own handler.
    - **Every leg exit DRAINS its connections** (#6827 round 7, `drainLeg`).
      `ReplaceAuth` keeps tightening a retired leg's pin only while the leg is on
      `s.retiring`, and `pruneRetiredLocked` reaps it the moment `drained` is
      set — so `drained` has to mean **"nothing this leg accepted is still being
      served"**: no further request admitted AND no response still in flight.
      It meant neither. The unexpected-serve-exit arm returned WITHOUT any
      `Shutdown`: `Serve` closes the listener on its way out, but the HTTP/1
      keep-alive and HTTP/2 connections it had already accepted kept being
      served, under a slot the recovery reconcile then PINNED and the next
      `ReplaceAuth` PRUNED before tightening — a revoked credential going on
      working on a socket the box believed was gone. All three exits (requested
      retirement, root-context shutdown, unexpected exit) now run a bounded
      `Shutdown` followed by `Close` on deadline.
      **Both halves of that, and which call does which (#6827 round 8 — round 7
      named the wrong mechanism here).** `Shutdown` sets `inShutdown`, so
      `doKeepAlives()` goes false: idle connections are closed and a connection
      it is still waiting on finishes its current response and then closes, so
      **no further request** is possible from `Shutdown` alone — measured. What
      `Shutdown` does not do is END the response already in flight; it WAITS for
      it and, at the deadline, returns `ctx.Err()` leaving it open and streaming.
      This server runs with no `WriteTimeout` by design (SSE, large scrapes), so
      that response has no bound of its own and outlives the drain indefinitely
      on a leg already marked `drained`. `Close` is what ends it, which is why it
      is not optional and not redundant. Bound by
      `TestInFlightResponseIsSeveredOnEveryLegExit_6827` across all three exits;
      deleting the `Close`, or reverting the retirement/root arm to a bare
      `Shutdown`, reds it — before round 8 both edits left the package green.
      **`Server.serveBound` runs the same drain** (#6827 round 10). It had kept
      the exact shape `drainLeg` exists to fix — a bare `Shutdown` under a
      deadline with no `Close` — which made this invariant, stated package-wide,
      FALSE about it; round 9 edited its doc ("bounded 5s drain" → "5s-deadline
      drain") without touching the behaviour. It is test-only (`Server.Run` has
      no production caller; the daemon uses `NewServer` + `Start`), which made
      fixing it cheap rather than optional: narrowing the invariant instead would
      have left the shape in the tree for the next reader to copy. Bound by
      `TestServeBoundSeversInFlightResponses_6827`, which runs BOTH legs with a
      stream held on each (#6827 round 11). BEFORE round 11 that cell passed
      `nil` for `httpsLn`, so it never entered the `if s.httpsServer != nil`
      branch and the HTTPS statement was unbound: against THAT tree, reverting
      it alone to a bare `Shutdown` left `pkg/api` and `pkg/daemon` green, and
      deleting it redded only `TestRunGracefulShutdownClosesBothListeners`.
      Neither cell was re-measured when round 11 bound the HTTPS leg, and the
      second stopped being true (#7046). Re-measured on the SHIPPED tree — head
      `f8e720c3e`, `pkg/api` green at baseline, exit codes read from `$?`:

      - **Deleting** the HTTPS `drainLeg` reds TWO, not one:
        `TestRunGracefulShutdownClosesBothListeners`
        (`server_run_leak_5058_test.go:152`, "Run did not return after ctx
        cancellation") and `TestServeBoundSeversInFlightResponses_6827`
        (`tls_stale_cert_6827_test.go:1393`, "serveBound did not return after
        ctx cancellation"). Both fail on the SAME observable and neither
        reaches its severing assertion: with no `Shutdown` at all the HTTPS
        `Serve` goroutine is never unblocked, so `wg.Wait()` never joins.
      - **Reverting** it to a bare `Shutdown` (deadline, no `Close`) reds ONE:
        `TestServeBoundSeversInFlightResponses_6827` alone
        (`tls_stale_cert_6827_test.go:1404` — the HTTPS connection "was still
        OPEN 3s later"), with `TestRunGracefulShutdownClosesBothListeners`
        PASSING.

      So "the listener CLOSES, not a response SEVERED" is the right distinction
      attached to the wrong mutation. It is the BARE-SHUTDOWN cell that isolates
      severing, because a `Shutdown` still unblocks `Serve` and both tests get
      their join; the DELETE cell is coarser — it breaks the join, which any
      test that cancels and waits can see. Note also what cannot be fixed by
      testing harder: a "reds only X" claim is a statement about the rest of the
      suite, and no test can assert it. State the mutation, the head it was
      measured at, and the observed cells — a bare count silently goes stale the
      next time a fixture grows a leg, which is exactly what happened here.
      Round 10's own revert mutation
      flipped both statements together, and the bound HTTP leg redded the cell
      and masked the unbound HTTPS one: a compound mutation cannot localise. The
      cell also ASSERTS the returned error now — `drainLeg` grew a return value
      for exactly that, and with it merely logged, `return err` could become
      `return nil` with both packages still green.
      One behavioural consequence,
      and it is NOT a bigger fixed number: the old code ran a bare `Shutdown` on
      each server under ONE shared 5s context and never reached a `Close` phase
      at all, whereas each server now gets its own `legDrainTimeout` AND the
      severing `Close` behind it. Read that as the package's drain shape, not as
      "5s for both" becoming "5s each" — `legDrainTimeout` is a POLL deadline
      with serial per-connection closes in front of it in BOTH phases, each
      HTTPS `close_notify` carrying a five-second write deadline of its own, so
      the worst case here grows with the number of stalled connections and has
      no fixed ceiling, exactly as described below.
      **On the unexpected-serve-exit arm, `dead` is stored BEFORE the drain, and
      the ORDER is load-bearing** (#6827 round 10). `serving()` has to flip the
      instant the socket dies, because for the whole width of the drain — which
      has no wall-clock ceiling, see below — a same-address `ReconcileHTTPS`
      takes the `serving()` no-op arm and returns nil, `reconcileTo`'s
      `next.TLS && !HTTPSServing()` recovery term is false, and
      `WarnStaleMgmtCertForHostName` diagnoses a certificate no socket is
      presenting. Moving the store below `drainLeg` left both `pkg/api` and
      `pkg/daemon` green until round 10: every other dead-leg cell kills a leg
      with NO connection, whose drain returns in microseconds, so both orders
      look identical there. `TestServingFlipsDuringTheDrainNotAfterIt_6827` holds
      a stream open and asserts the flip happens WHILE `drained` is still unset.
      **`legDrainTimeout` bounds NEITHER the drain nor the `Shutdown` in
      wall-clock terms** — round 8 said "the Shutdown" and that was the second
      wrong version of the sentence (#6827 round 9). It is a POLL deadline
      consulted between quiescence checks, and serial per-connection closes sit
      in front of it in BOTH phases: `Shutdown`'s loop calls `closeIdleConns()`
      and only reaches its `ctx.Done()` select if that returns false, and
      `closeIdleConns` walks `activeConn` under `s.mu` closing one at a time; then
      `Close`, which takes no context at all, does the same again. On an HTTPS leg
      each close is a `*tls.Conn` sending `close_notify` under its own five-second
      write deadline (`crypto/tls`), so a stalled peer costs up to five seconds
      EACH, in series, in either phase. The worst case grows with the number of
      such connections and has no fixed ceiling, and the
      knock-on is worth knowing: `Server.Wait` holds `lifeMu` across the drain
      and `WarnStaleMgmtCertForHostName` holds `staleCertMu` while waiting for
      `lifeMu`, so a `set system host-name` racing daemon shutdown waits for it.
      Bounding the sever phase for real needs per-connection tracking with
      concurrent deadlined closes — a larger change than #6827, deliberately not
      taken here, and the claim is narrowed to what is true instead of asserting
      a bound that is not.
      **Hijacked connections are IN SCOPE since #7011**, and that is what
      removed the caveat this paragraph used to carry. Go excludes them from
      both calls (`Shutdown` "does not attempt to close nor wait for hijacked
      connections", `Close` "does not even know about" them) and a hijacked conn
      leaves `activeConn`, so neither can reach one — but the `ConnState` hook
      can: it fires with `StateHijacked` and hands over the `net.Conn` at the
      moment the server loses track of it. Every leg constructor installs that
      hook (`trackHijackedConns`, `listener_hijack_drain.go`) and `drainLeg`
      closes what it recorded, on both the graceful and the deadline path.
      What that does NOT claim: the connection is closed, not the goroutine the
      hijacking handler started — nothing can join that, and the guarantee is
      about what is still being SERVED.

      **The tripwire that used to defend the caveat is deleted, not re-keyed.**
      `TestNoHijackerInThisPackage_6827` maintained a map of hijacking types and
      was defeated three times: `golang.org/x/net/websocket` (round 8),
      `golang.org/x/net/http2/h2c` (round 9), and `net/rpc` — a STANDARD LIBRARY
      hijacker. The last is why re-keying was the wrong answer: the hijacker set
      is a function of the TOOLCHAIN rather than of `go.mod`, so the corpus the
      map was derived over moves with nothing in the repository changing, and a
      `go list -deps` closure would have missed `net/rpc` too unless written to
      include the standard library. The property is now asserted DIRECTLY
      against a real hijacking handler
      (`listener_hijack_drain_7011_test.go`) instead of proxied through type
      names, and a leg constructor that forgot the hook fails there.
      **Cost, stated:** `ConnState` is never called again for a hijacked
      connection, so a handler that hijacks and then closes leaves a tracker
      entry until the leg drains — the map grows with the number of hijacks a
      leg serves, not with the number live. This package has no hijacker today,
      so it stays empty.
  - The HTTP and HTTPS listeners run in INDEPENDENT legs (`listener.go`), each
    make-before-break: `ReconcileHTTP(addr)` rebinds only the HTTP leg and
    `ReconcileHTTPS(tls, addr)` enables / disables / rebinds only the HTTPS leg —
    neither touches the sibling. This is the fix for the earlier whole-server
    rebuild: enabling TLS keeps the HTTP bind, so re-binding the whole server
    re-bound the still-held HTTP socket and failed `EADDRINUSE` (Go sets
    `SO_REUSEADDR`, not `SO_REUSEPORT`), and the TLS change could never converge
    without a restart — the same collision hit an HTTP-addr change that left the
    HTTPS bind unchanged. Each leg binds the new socket and serves it BEFORE
    retiring the old (no unreachable window on that plane, no double-bind of an
    unchanged socket); a bind (or HTTPS cert) failure fail-closes to the retained
    previous leg.
    **`ReconcileHTTPS` BINDS BEFORE IT BUILDS (#7041).** Building resolves the
    durable certificate, and `certGen` has no cache — `LoadX509KeyPair` re-reads
    the on-disk pair and `warnStaleLoadedCert` re-runs on every call. Because the
    #6827 liveness disjunct re-enters `ReconcileHTTPS` on EVERY commit while HTTPS
    is wanted and not serving, building first meant a box whose bind fails
    persistently and whose cert is stale re-emitted the whole stale-cert
    diagnostic once per commit, forever. A leg that cannot bind serves no client,
    so nothing can be verifying against that certificate yet — the same
    reachability argument as the #7039 loopback gate, and like it the suppression
    is bounded in TIME: the first commit that binds successfully emits the
    diagnostic. The bind failure itself is unchanged and still returned on every
    attempt, so retry debt and the daemon's reconcile warnings are untouched.
    Two consequences are asserted rather than left implicit: a cert failure now
    happens with the socket already held, so the listener is CLOSED on that path
    (retaining it would hold the port and turn a transient cert fault into a
    permanent `EADDRINUSE` on every retry); and when BOTH the bind and the cert
    fail, the reported error is now the BIND error rather than the cert error.
    `Start(ctx)` binds HTTP synchronously (fail-closed if it fails)
    and HTTPS best-effort (a boot HTTPS failure leaves HTTP up). BOTH boot
    failures are retried on the next commit — but only since #5561 round 14,
    which made the retry debt real: the reconciler now keeps the `Server` after a
    failed boot HTTP bind (it holds no socket on that path, and dropping it made
    every later reconcile a no-op), and asks `HTTPSServing()` instead of
    inferring a converged HTTPS leg from `Start`'s nil error. `Wait()` joins
    every live + retiring leg goroutine on shutdown.
    Listeners bind via `Config.ListenFunc` (default `net.Listen`) so tests inject
    a fake factory that models `EADDRINUSE`. Pinned by
    `server_authswap_5866_test.go` (live auth swap) +
    `pkg/daemon/management_5866_test.go` (HTTP-bind change, TLS enable/disable/
    re-enable, HTTPS-bind-only change, HTTP-change-keeps-HTTPS, auth swap,
    bind-failure retain-old). `Run`/`serveBound` remain the single-lifecycle test
    entry point.
  - `EffectiveHTTPAddr()` (#6385/#6401) returns the live HTTP leg's ACTUAL bound
    address (`httpLeg.ln.Addr()`) — an ephemeral `:0` request resolves to its
    concrete port, a wildcard/hostname bind is normalized — or `""` when no HTTP
    leg is serving OR the live leg's serve loop exited UNEXPECTEDLY (the serve
    goroutine marks the leg `dead` — an ATOMIC store, NOT under `lifeMu`, so a
    serve-exit racing a shutdown `Wait()` cannot deadlock: the goroutine still
    holds its `wg` count when it marks dead and `Wait()` holds `lifeMu` across
    `wg.Wait()`, so a lifeMu-guarded marker would form a lock-ordering cycle; a
    requested shutdown via `stopLegLocked`/`rootCtx` does NOT mark dead). The
    daemon's `show system services`
    effective-listener snapshot reads it
    (`managementReconciler.effectiveHTTPListener`) and renders a dead leg
    `Failed`, symmetric with the gRPC serve-exit clear.
  - The auto-generated HTTPS cert (`generateSelfSignedCertAt`, used when no
    operator cert is provisioned) carries Subject Alternative Names, not just a
    CommonName (#5719, codex-review-182 C-API TLS hygiene). Every modern TLS
    client (Go's own client since 1.15, browsers, curl) rejects a SAN-less
    cert for hostname verification, so a CN-only cert broke `curl
    https://localhost:8443` / health probes even though the bind succeeded.
    What the SANs cover, precisely:
    - **Always present:** the loopback IP SANs `127.0.0.1` / `::1` and the DNS
      SAN `localhost` — so a **loopback-bound** HTTPS API (the default) always
      verifies. These can never fail to encode.
    - **Best-effort:** the kernel hostname. A valid ASCII hostname is added as
      a DNS SAN; an IP-literal hostname is added to the IP SANs (a DNS SAN of
      an IP never verifies as an IP). A **non-ASCII / malformed** hostname
      (e.g. a `café` kernel hostname) is DROPPED, not appended — x509 marshals
      DNS SANs as an IA5String and HARD-FAILS on non-ASCII, which under the
      #5058 all-or-nothing management-server lifecycle would abort cert
      generation and tear down the entire HTTP+HTTPS server. The cert degrades
      to loopback-only SANs (`isDNSSANSafeHostname` guard) instead of failing.
    - **HTTPS bind host (#5719 C001 residual, now closed):** the listener's
      bind host is threaded from the resolved `web-management https interface`
      address into cert generation (`buildHTTPSServer` → `net.SplitHostPort` →
      `certGen(bindHost)`). A non-loopback management IP lands in the IP SANs
      and a DNS-safe bind hostname in the DNS SANs, so
      remote-verification-by-mgmt-IP (`https://<mgmt-ip>:8443` with strict
      verification) succeeds. A loopback / unspecified (`0.0.0.0`/`::`) /
      wildcard (`:8443` → empty) / non-encodable bind host is skipped, and a
      value already present is coalesced. Like the hostname path this only ever
      ADDS an encodable SAN, so it never aborts generation.
    - **Re-mint STILL deferred, but no longer SILENT (#5719 C001 residual,
      #6827):** a later `set system host-name` (or a bind-address change) does
      NOT re-mint an already-persisted cert, so its DNS/IP SANs can go stale.
      Re-minting is deferred (it needs a mint-ordering / invalidation hook and a
      decision on churning the durable TOFU pin). What WAS a silent failure is
      diagnosed from **two** entry points, because one alone cannot reach every
      way a cert goes stale:
      - `generateSelfSignedCertAt` calls `warnStaleLoadedCert` on the
        load-success path — boot, and any HTTPS enable/rebind;
      - `Server.WarnStaleMgmtCertForHostName` is reached from
        `Daemon.applyHostname` after a successful `set system host-name` — not
        synchronously: the rename records a DEBT and the daemon's delivery path
        makes the call, at the rename when a certificate is already served and
        otherwise at the first later retry point that finds one. The load path
        could never see a rename: the HTTPS leg is rebuilt only when the TLS
        flag or the HTTPS bind address changes
        (`managementReconciler.reconcileTo`), so a rename on an unchanged
        endpoint reloads nothing. And `reconcileWebManagement` runs EARLY in
        `applyConfigLocked` while the kernel name is set in the apply tail, so
        even a commit that DID move the HTTPS bind would have diagnosed the OLD
        name — which is why this entry point takes the host name as a
        PARAMETER instead of re-reading `os.Hostname()` itself: the read moves
        to the daemon, which performs it after `Sethostname` has returned and
        abandons the delivery if a newer rename has since been recorded.
        At BOOT this hook runs before its own dependency exists: the first
        config apply is startup phase 4 while `startHTTPServer` builds `d.mgmt`
        later in `Run`. So a rename records a DEBT (`Daemon.staleCertPending`)
        and `deliverStaleMgmtCertDiagnosis` retries it — at the boot management
        start, and on every web-management reconcile. Skipping on nil would
        reproduce the original silence: the load path is not a fallback that
        covers it, because it runs only while a certificate is being loaded,
        which on an unchanged endpoint next happens at a restart or an HTTPS
        rebind (and for a CROSS-shape rename it declines even then — see the
        narrowing rule below).
        Two properties matter:
        - **The debt clears only when a delivery actually reaches a served
          certificate** (`WarnStaleMgmtCertForHostName` returns that). Clearing
          it whenever the delivery merely RAN loses the diagnosis permanently
          when the HTTP start failed or HTTPS is off: the next boot's
          `applyHostname` sees the name already applied and returns early, and
          the load path declines cross-shape drift by design. The certificate is
          durable on disk, so the staleness outlives the listener and the debt
          must outlive it too.
        - **The host name is read from the kernel at DELIVERY, never stored at
          rename time.** A deferred diagnosis is therefore never the replay of a
          name captured at some earlier commit — and marking the debt and
          attempting delivery are a single path, so a rename racing `d.mgmt`'s
          publication cannot be silently dropped. The delivery is also
          GENERATION-FENCED before it speaks: one whose rename has been
          superseded abandons without warning and without clearing, so it cannot
          emit a name a recorded rename has already replaced. The emitted name IS
          the kernel's current one for every rename the daemon performs (#6827
          round 7): `Daemon.renameHostNotingStaleMgmtCert` holds `staleCertMu`
          across BOTH the `Sethostname` and the generation bump, so the two
          critical sections are ordered and neither order can produce a stale
          line. Rounds 5 and 6 recorded that gap as unclosable; it was closable
          by moving the lock acquisition ahead of the syscall. A privileged
          `sethostname(2)` from outside the daemon remains unfenceable.
      The RENAME entry point reads the LIVE HTTPS leg via
      `listenerLeg.serving()` — not a non-nil pointer. (The load path has no leg
      to read: it runs inside cert generation, before any leg exists, and judges
      the pair it just loaded.) An unexpected serve exit leaves the leg
      INSTALLED with `dead` set, and ROOT-CONTEXT SHUTDOWN leaves it installed
      with `stopping` set; diagnosing either reports a certificate no socket is
      presenting. `serving()` therefore tests BOTH: `dead` for a
      self-termination, and `stopping` — stored explicitly at the top of both
      drain arms (requested retirement AND root-context shutdown), before
      the drain, so it covers the leg from the moment the drain is decided
      through the goroutine's return (the listener closes an instant later, in
      `Shutdown`, and already-accepted requests drain on the schedule
      `legDrainTimeout`'s comment describes — which bounds NEITHER the drain nor
      the `Shutdown` in wall-clock terms, being a POLL deadline with serial
      per-connection closes in front of it. `serving()` answers "is this the leg
      in front of clients", not "is every byte done").
      The same predicate now gates `ReconcileHTTPS`'s same-address no-op, so a
      dead leg is REBUILT rather than mistaken for a converged one (#6827 round
      6): before that, a self-terminated HTTPS leg could not be replaced by any
      commit and HTTPS stayed down until a restart. The dead leg's CONNECTIONS
      are taken down too (#6827 round 7) — see the leg-drain bullet above; the
      recovery alone left them serving. It does NOT test `stopCh`: a requested
      retirement is unobservable through `s.httpsLeg`, though not by the
      ordering — the disable arm retires the leg and THEN clears the field. What
      makes the interval unobservable is that the whole `ReconcileHTTPS` switch
      runs under ONE `lifeMu` hold and every `serving()` caller takes `lifeMu`,
      so a reader lands before the retirement or after the clear, never between;
      the rebind arm installs the replacement first, so the leg it retires is
      never the installed one. Either way that would be an arm for a state that
      cannot occur. `serving()` is
      stricter than `EffectiveHTTPAddr`'s inline check, which answers
      `show system services`, where a leg finishing a drain should still report
      its address.
      Both parse the leaf ONCE and share these checks (`certCoversHost` — the
      same strict `x509.VerifyHostname` check a remote client applies):
      - **no SAN at all** (`certHasNoSANs`) — a pair persisted by an older build
        or placed by an operator can carry no subjectAltName, and then it covers
        NOTHING: modern clients do not fall back to CommonName, so even
        `https://localhost` fails. This case is reported first and is TERMINAL
        (the per-identity lines below would each report "does not cover X" for a
        cert that covers no X at all). The per-identity predicates gate out
        loopback on the premise that the durable cert always carries the
        loopback SANs, which is true only of certs this mint path produced — so
        without this check the most broken certificate possible was the one that
        warned least.
      - the **HTTPS bind host**, when it is a concrete non-loopback management
        host (`bindHostWarnable`) — stale after an A→B `web-management https
        interface` rebind. It needs no plausibility test: the operator
        configured the listener to answer there. The rename entry point does NOT
        re-report it (the bind did not change).
      - the **kernel host name**, when it is one a re-mint could actually cover
        (`hostnameSANWarnable`) — stale after `set system host-name`. This half
        was previously UNCHECKED, and because renaming a firewall does not move
        its management IP the bind-host check did not fire either: the operator
        got a bare `certificate is not valid for any names` with nothing in the
        log. `hostnameSANWarnable` additionally requires the name to be
        DNS-encodable or an IP literal, so a `café` host name — which
        `isDNSSANSafeHostname` DROPS from the SANs by design and which no
        re-mint could ever cover — does not warn on every reload.
        On the LOAD path it is additionally narrowed by
        `hostNameLikelyAccessIdentity`: a box named `fw` whose cert covers
        `mgmt.example.com` plus its management IP is verifiable at every URL in
        use, and telling that operator to re-mint churns remote TOFU pins for
        nothing. Since this package's mint path is the only thing that puts a
        bare, unqualified name in a cert (and what it puts there is the kernel
        host name), an unqualified DNS SAN next to an unqualified kernel name
        means the TLS identity IS the kernel name and has drifted — diagnose; a
        domain-qualified SAN next to a short kernel name means the TLS identity
        is independent of it — stay quiet. The RENAME entry point skips that
        heuristic: the operator just chose the name, which is direct evidence
        rather than inference.
        **BOTH entry points are gated on the listener being remotely reachable
        (`bindIsLoopbackOnly`, #7039).** On a loopback-only HTTPS bind — which is
        what `set system services web-management https` with no `interface`
        resolves to, `127.0.0.1:443` — there is no remote client, so nothing can
        verify by host name and a re-mint would fix nothing. The bind-host half
        above already declined there (`bindHostWarnable("127.0.0.1")` is false);
        the host-name half had no equivalent gate, so every `set system
        host-name` on a loopback-bound management plane warned about clients that
        cannot exist. That is the failure mode this whole heuristic exists to
        prevent, arriving through the door it left open. The gate is a property
        of the BIND, not of the name, so it composes with the rename path's
        direct evidence rather than contradicting it.
        **It is deliberately NOT `!bindHostWarnable`.** Those two answer
        different questions and disagree on the wildcard binds: `0.0.0.0` and
        `::` are `bindHostWarnable == false` — because they name no single host,
        not because they are unreachable — so suppressing on the complement would
        silence the diagnostic on the most remotely-reachable listener there is.
        `TestLoopbackOnlyIsNotTheComplementOfBindHostWarnable_7039` pins the
        divergence, and the wildcard binds appear as MUST-STILL-WARN cells beside
        the loopback silence cells so the suppression cannot widen unnoticed.
        An **empty** bind host is likewise not loopback: `":8443"` splits to an
        empty host, so `""` usually means WILDCARD (the same reading the bind-host
        bullet above already uses), and suppressing there would silence the
        diagnostic on a listener reachable from every interface.
        **Accepted residual:** a rename that CROSSES the
        qualified/unqualified boundary is diagnosed at the commit but not on any
        later boot, so it is never diagnosed at all in the two states that had
        no commit-time diagnosis behind them — a box already drifted before this
        shipped, and a box RUNNING this build whose commit-time debt was still
        OWED at shutdown and was discarded by the restart,
        `Daemon.staleCertPending` being process-local. That second state has
        more ways in than the obvious one, each an ordinary configuration rather
        than a fault: HTTPS disabled, its bind failed, its serve loop terminated
        and no later commit rebuilt the leg, the API disabled entirely
        (`--api-addr` empty, so there is no reconciler to deliver through), the
        boot HTTP start failed, the kernel name unreadable at every delivery, or
        startup aborted on a signal (#5807) after the phase-4 config apply but
        before the management server was built.
        Shape-preserving drift (the ordinary case) is still caught on
        every boot. Closing either half needs persistent state — an upgrade
        marker, or a durable pending flag plus an invalidation story for a name
        that changed again while the daemon was down — for one
        narrow class, and would re-fire the false positive on exactly the boxes
        the heuristic cannot judge — weighed and declined, see the comment on
        `hostNameLikelyAccessIdentity`.
      Each uncovered identity emits its own `slog.Warn` naming the identity and
      the cert's DNS/IP SANs — which are exactly the identities it DOES cover,
      so an operator re-mints (remove `/etc/xpf/tls`) or dismisses the line in
      one read, instead of chasing a silent verification failure.
    An already-persisted cert is NOT auto-regenerated — the #1916 D6
    durable-cert contract keeps the on-disk pair stable so remote clients' TOFU
    pins survive a power loss; only freshly generated certs gain SANs (delete
    `cert.pem`/`key.pem` to force a regenerate). Pinned by
    `tls_san_5719_test.go` (SAN presence, hostname classification, the
    non-ASCII no-abort guard, the bind-host mgmt-IP/DNS threading +
    `buildHTTPSServer` host-extraction, and the stale-cert mismatch warnings on
    the rebind path) and `tls_stale_cert_6827_test.go` (the SAN-less cert — one
    fixture for the REACH the check adds where both per-identity gates decline,
    a second with a warnable bind host so the TERMINAL `return` is observable at
    all; the unused-kernel-name false positive and its matched positive control;
    the rename entry point; and the two leg-state transitions driven by the real
    serve goroutine — `stopping` on a root-context drain, `dead` on an
    unexpected serve exit, the reconcile that REPLACES a dead leg, the held
    connection that must not outlive a revocation, and the in-flight response
    severed on all three leg exits), with
    the daemon-side wiring pinned by
    `pkg/daemon/hostname_stale_cert_6827_test.go`: a host-name commit on an
    UNCHANGED HTTPS endpoint reaches the diagnostic with the NEW name, the debt
    outlives a delivery that reached nothing, an unreadable kernel name settles
    nothing, the generation fence defers a rename that lands mid-delivery (once
    with the test supplying the competing rename, once driving it through the
    production note path so the `staleCertGen++` itself is bound), a dead HTTPS
    leg is rebuilt by the next commit so the debt is dischargeable at all, and
    BOTH deferred retry points are bound at their own call site. Those two are
    bound on different observables, and the reason is worth stating rather than
    discovering twice: `reconcileWebManagement`'s per-commit retry is bound on
    the debt FLAG, because the reconcile that brings HTTPS up makes the
    certificate LOAD path emit the same warning text — a text assertion there
    passes with the retry deleted. `startHTTPServer`'s boot delivery is bound on
    the kernel-name read plus the fact that the management server already
    exists when it happens; that call site cannot be given a serving HTTPS leg
    in-process, because `startHTTPServer` CONSTRUCTS the `api.Server` itself and
    `SetTLSCertDirForTest` only exists after construction, so the alternative is
    driving the production `/etc/xpf/tls` generator. Deleting either call reds
    its own subtest and only its own. The boot cell's limit is stated in the
    test rather than implied: it proves the call happens and happens after the
    server is built, NOT that it reached a certificate, warned, or discharged
    anything — replacing the delivery with a bare `osHostname()` would satisfy
    it, and a stronger cell needs a pre-construction certificate seam on
    `api.Config`, which was declined as a production knob added for one test.
- The status-poll path (1 Hz) shares the userspace dataplane control socket
  with HA sync, session installs, snapshot sync, and forwarding sync.
  Adding a new caller at >1 Hz here will starve session installs during
  bulk sync (per CLAUDE.md control-socket rules).
- A `/metrics` scrape performs at most ONE control-socket `Status()` round
  trip. `Collect` fetches the `ProcessStatus` once (`fetchUserspaceStatus`,
  after the dataplane gate) and shares the snapshot with BOTH the filter-term
  hit merge (`collectFilterCounters`) and the userspace-status families
  (`collectUserspaceStatus`). Before #5317 those two collectors each issued
  their own `Status()`, so one scrape did two serialized `status` RPCs on the
  contention-critical control socket (and read two A/B-skewed snapshots). On a
  Status() failure the shared fetch returns nil once and is NOT retried — the
  filter merge falls back to the map path and the userspace families emit
  nothing, exactly as each collector degraded before.
- Userspace CoS metrics are emitted from a single `Status()` snapshot per
  scrape. Queue-scoped drain-phase counters
  (`xpf_userspace_cos_drain_{guarantee,surplus}_sent_bytes_total` and
  `xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total`)
  deliberately include non-exact queues so best-effort/exact contention can be
  diagnosed. Exact-backlog cross-binding visibility uses per-binding
  cacheline-padded atomic slots (`SharedCoSExactBacklog`) written from the
  enqueue and completion paths; metric collection still reads from a single
  `Status()` snapshot per scrape rather than instrumenting the scrape path
  itself.
- Per-queue park-reason counters
  (`xpf_userspace_cos_root_token_starvation_parks_total`,
  `xpf_userspace_cos_queue_token_starvation_parks_total`,
  `xpf_userspace_cos_drain_park_root_tokens_total`,
  `xpf_userspace_cos_drain_park_queue_tokens_total`) attribute *why* a CoS
  queue stalled (#1642/#760, exported for #1359). A rising
  `root_token_starvation_parks` delta on a best-effort / mouse queue while a
  surplus-sharing borrower drains is the fingerprint of root-surplus
  arbitration — the borrower is holding the shared root tokens — and pins a
  surplus-sharing mouse-latency tail to *that* cause rather than this queue's
  own per-queue cap (`queue_token_*`) or worker scheduling. The Rust helper
  already carried these on the CoS snapshot; #1359 surfaced them to
  Prometheus. The `root_token_starvation_parks` / `queue_token_starvation_parks`
  pair is shaper-side; the `drain_park_root_tokens` / `drain_park_queue_tokens`
  pair counts the per-batch drain-loop decision (see
  `docs/cos-validation-notes.md`).
- Session-view read paths must NOT publish a partial scan as success
  (#2469). A backend session-iterator error (e.g. helper restart
  mid-scan) makes `IterateSessions`/`IterateSessionsV6` return non-nil.
  The REST session handlers (`/sessions`, `/sessions/summary`,
  `/sessions/zone-pair`, interface-mode NAT pool stats) return HTTP 500
  on that error instead of an HTTP 200 with a partial/zero body. The
  Prometheus session-breakdown collector emits
  `xpf_sessions_breakdown_scrape_ok` (1 = full scan, 0 = truncated) and
  OMITS the `xpf_sessions_{active,established,ipv4,ipv6,snat,dnat}` gauges
  when the scan failed, so an alert fires rather than a graph silently
  dropping to zero. The gRPC `GetSessions` (legacy + cursor) and
  `GetSessionSummary` return `codes.Internal` on the same error. The
  contract is pinned by `sessions_iterator_error_test.go` in this package
  and in `pkg/grpcapi` / `pkg/cli` (CLI top-talkers fails the command; NAT
  summaries print a stderr warning).
- The static-route `/routing/routes` handler (`routesHandler`, `routing.go`)
  renders one `RouteInfo` per next-hop for a normal route. A route with no
  forwarding next-hop instead carries a `disposition` label distinguishing
  `reject` (FRR `RTN_UNREACHABLE`, drop + ICMP unreachable), `discard` (FRR
  `Null0`/`RTN_BLACKHOLE`, silent drop), and `connected` (no gateway). This
  mirrors the `reject`/`discard` labels the CLI/gRPC `show route` text already
  renders, closing the #5410 gap where a first-class `reject` route (#5298)
  was lumped into the same unlabeled no-next-hop branch as `discard`. The
  `disposition` field is additive and `omitempty`, so a route with a real
  next-hop or a `next_table` leaks nothing new and existing consumers reading
  `destination`/`next_hop`/`interface`/`preference`/`next_table` are
  unaffected. Pinned by `routes_disposition_5410_test.go`.
- The same handler covers the FULL static-route set the CLI/gRPC `show route`
  iterate, not just the global inet.0 table (#5439). It walks
  `RoutingOptions.StaticRoutes` (inet.0), `RoutingOptions.Inet6StaticRoutes`
  (inet6.0), AND every routing-instance's per-VRF `StaticRoutes` /
  `Inet6StaticRoutes`, tagging each `RouteInfo` with its `family` (`inet` /
  `inet6`) and Junos RIB `table` name (`inet.0` / `inet6.0`, or
  `<instance>.inet.0` / `<instance>.inet6.0` for a VRF). Before #5439 it
  iterated ONLY inet.0, so the REST view silently omitted every IPv6 static
  route and every per-VRF static route — not even their destination — while
  the CLI/gRPC rendered both families and every VRF. The disposition labeling
  above applies uniformly across all four sources (an `appendStaticRoutes`
  helper renders each table). The `family` / `table` fields are additive and
  `omitempty`, the inet.0 rows still lead in their original order, so a legacy
  consumer reading the pre-#5439 inet.0 subset positionally is unaffected.
  Pinned by `routes_ipv6_vrf_5439_test.go`.
- Long full-table read handlers must ABORT when the client disconnects
  (#5232/#5233). The REST server cancels `r.Context()` on disconnect, so a
  handler that walks a large structure has to sample `r.Context().Err()`
  periodically and stop rather than run to completion for a response nobody
  will read. `bgpHandler` (`/routing/bgp?type=routes`) checks once per
  1024-route chunk in its streaming loop and returns — a full internet table
  (900k+ routes) otherwise keeps formatting + JSON-escaping every remaining
  route and writing to a dead connection (CPU/GC waste, #5232). That check now
  runs inside a `frr.StreamBGPRoutes` callback: the UPSTREAM RIB is streamed
  too, not buffered (#5056). Previously the handler called `GetBGPRoutes`,
  which ran `vtysh "show bgp ipv4 unicast"` and buffered the ENTIRE stdout
  into one string plus a parsed `[]BGPRoute` before the first byte went out —
  hundreds of MB for a full table, and the client-cancel check could not stop
  the already-completed vtysh work. `StreamBGPRoutes` scans vtysh stdout one
  line at a time (bounded `bufio.Scanner`), delivers each route to the
  callback, and cancels the vtysh process on `r.Context()` cancellation or a
  downstream write failure, so peak memory is O(1) in table size regardless of
  RIB size. The rendered output is capped at `maxBGPRoutes` (100000); when the
  cap trips a trailing `... table truncated at N routes` notice is appended to
  the `output` string (envelope shape unchanged) and the client is pointed at
  the CLI for the complete table. Operators needing the full RIB use
  `show route protocol bgp`. The cap/truncation contract is pinned by
  `bgp_routes_cap_5056_test.go`; the streaming/non-buffering + wire-format
  invariants by `bgp_routes_stream_4708_test.go`.

  **SSE streams carry the same bound, on a different axis (#7632).**
  `writeSSEEvent` wrote straight to the `ResponseWriter` and **discarded every
  write error**, and `WriteTimeout` is 0 process-wide, so a subscriber that
  stays CONNECTED and stops reading parked the handler in `Write` indefinitely
  while holding a subscriber slot. Both stream handlers
  (`/api/v1/events/stream`, `/api/v1/logs/stream`) now write through
  `sseStream`, which wraps the `ResponseWriter` in the same
  `deadlineArmingWriter` the BGP route stream uses and **returns** the first
  failure — from a write *or from the flush*; both loops treat it as terminal.

  **Armed before the write, CLEARED after it (#7654 review, finding 1).** A
  deadline is not cancelled by the write succeeding — it stays live. Under
  HTTP/1.1 that is invisible; under **HTTP/2** Go implements the write deadline
  with a timer that **resets the stream** when it fires, so a deadline left
  armed tore down an idle feed one deadline after its last event, with a client
  that had consumed everything. Reproduced before fixing: `read n=0 err=stream
  error: stream ID 1; INTERNAL_ERROR`. So **"per-write, not elapsed" is
  necessary and not sufficient — the window has to close as well as open.**
  Cleared after the *flush*, not after the last `Write`, because
  `http.Flusher.Flush()` does not go through the arming writer and clearing
  earlier would leave it unbounded.

  Pinned by `TestIdleSSEStreamIsNotResetOnHTTP2_7632`. Note why a separate cell
  was needed: every other cell here uses `httptest.NewServer`, which is
  **HTTP/1.1 only**, while production permits HTTP/2 on the TLS listener.
  Removing the clear reds that one cell and **leaves every HTTP/1.1 cell green**
  — a test can be sound on the protocol it exercises and blind to the one where
  the defect lives.

  **The payload is written in bounded chunks — and the first cell for it did
  not bind (finding 2).** The mutation matrix returned GREEN for "chunking
  removed": the cell drained a 256 KiB payload over loopback as fast as it
  could, and over loopback that transits in microseconds, so the window never
  came close to expiring either way. It varied the right axis and sampled only
  the passing point. The hazard needs a reader that is slow but *still
  progressing*, which neither a full-speed loopback client nor a stalled conn
  can be, so `stalledConn6809` gained `slowRate`/`slowWindow`: bytes move, at a
  rate, honouring the armed deadline. `TestLargeEventSurvivesASlowButProgressingReader7632`
  now reds on the revert (truncated after 3 841 of 1 048 576 payload bytes) and
  passes with the chunking. Its margins are wall-clock (#9807): a 400 ms
  deadline over 40 ms chunks leaves 360 ms per chunk, and the 32-chunk payload
  (1.28 s) still cannot fit one window. The first version used 100 ms and 8
  chunks, and a scheduler stall on a loaded host ate its 60 ms margin and
  failed the cell with the #7654 message.

  Worth knowing for anyone changing `sseWriteChunk`: net/http's own 4 KiB
  `conn.bufw` means the **socket** sees ~4 KiB writes whatever the chunk size
  is, so chunking does not change the write pattern at all — **it changes when
  `SetWriteDeadline` is re-armed.** It is a re-arming schedule, not a write
  schedule. The original cell was implicitly testing the write pattern, which is
  identical in both arms, which is why it could never have failed.

  **What the chunking is for.** One `Fprintf` of the
  whole event gave the entire payload a single absolute window, so a large event
  to a slow-but-*progressing* reader was cut off partway — the budget measuring
  elapsed time rather than lack of progress, which is the same conflation this
  design rejects at the stream level. The "a few hundred bytes" premise is
  unenforced: event JSON carries operator-authored strings whose only external
  bound is the 16 MiB config limit. Each `sseWriteChunk` (32 KiB) re-arms, so a
  reader that keeps draining keeps the stream however large the event.

  **Per-write, never elapsed** — this is where SSE differs from the RIB dump and
  the difference is load-bearing. An event feed on a quiet firewall is
  *supposed* to sit silent for long stretches; that is its normal operating
  state, not a symptom. An elapsed budget would sever exactly the healthy case.
  A per-write deadline bounds a write that has BEGUN and says nothing about the
  gap between events. `TestIdleSSEStreamIsNotSevered7632` pins it, and reds if
  anyone adds an elapsed budget here by analogy with `bgpStreamTotalBudget`.

  **The FLUSH error is reported, not discarded (finding 2).** `writeEvent`'s doc
  comment claimed it returned the first write error. For an ordinary event that
  was **false**: net/http buffers the response in a 2 KiB `bufio.Writer` and an
  SSE event is a few hundred bytes, so the handler's `Write` calls never touch
  the socket — the write that can block is the one *inside* the flush, and
  `http.Flusher.Flush()` has no error return (net/http's `response.Flush` calls
  `FlushError()` and throws it away). So the only write that can genuinely fail
  was the only one whose failure was guaranteed to be dropped. `sseStream.flush`
  now goes through `http.ResponseController.Flush()`, which returns what
  `response.Flush` swallows. `ErrNotSupported` is latched as "this writer cannot
  flush" rather than treated as a dead peer — pinned by a paired control, since
  "return whatever Flush says" is otherwise satisfied by severing every stream
  on its first event.

  **The error returns are precautionary, not bound — measured, not assumed.**
  The obvious claim is that arming the deadline alone would be worse than the
  pin, with the loop draining the subscription into a dead connection. It is
  not. Nine runs per variant against a 250 ms deadline, on both paths a small
  event can take — the flood that overruns the 2 KiB buffer into direct socket
  writes, and the single small event whose only socket contact is the flush:

  | variant | write path (flood) min/med/max | flush path (1 event) |
  |---|---|---|
  | as shipped | 251.0 / 251.9 / 254.9 ms | 250.3 / 250.7 / 250.8 ms |
  | write check discarded | 251.1 / 251.5 / 252.4 ms | 250.3 / 250.5 / 250.8 ms |
  | flush check discarded | 251.1 / 251.4 / 252.9 ms | 250.6 / 250.6 / 250.7 ms |

  Every variant returns inside one deadline window and the distributions overlap
  completely, because net/http cancels the request context when a connection
  write fails — measured directly at `250.69 ms` after the blocking write began
  — so the loop exits through its `ctx.Done()` arm regardless.

  The deadline is what fixes the pin. Both checks are kept because that exit
  depends on net/http cancelling on a write error — behaviour, not contract — so
  a wrapping `ResponseWriter` or a different server that does not do it would
  leave the loop draining. Removing either leaves the suite green, which is
  recorded here rather than papered over: it is defence in depth, and calling it
  load-bearing would put a false claim into the next reader's reasoning. What
  the flush fix repairs is the **claim**, not the bound.

  **"Still running" is not "pinned" (finding 3).** Both slow-reader cells, and
  the negative control above all, now witness a genuinely PARKED write
  (`stalledListener6809.waitForParkedWrite`) before drawing any conclusion from
  a timeout. An idle handler and a blocked one look identical to a deadline, and
  that confusion produced two wrong readings during this PR — once about HTTP/2,
  where a goroutine dump showed the handler sitting in its `select` rather than
  in `Write`, and once about the flush, where a byte budget let a whole flush
  through and the "pin" was an idle stream. The fixture also gained `maxWrites`,
  an exact "the buffer filled after the first event" that a byte budget cannot
  express: it is checked *before* the write and then passes the whole thing.

  **No fixed wall-clock point stands in for readiness (finding 4).** The cells
  used to sleep 100 ms and then publish, but subscriptions have no replay — a
  flood landing before the handler subscribes is simply lost, and the cell then
  fails 15 s later blaming the deadline, which is the wrong diagnosis for a lost
  publish. `floodUntilParked7632` publishes until a write has genuinely parked
  (the observable that implies *both* that the handler subscribed and that it
  reached the blocking write) and fails loudly naming what never arrived,
  per the #7563 ordering in `docs/engineering-style.md` — never a longer sleep
  or a retry. `readSSEChunk7632` likewise accumulates to the `\n\n` SSE
  terminator instead of assuming one `Body.Read` returns a whole event: a short
  read of `id: 1\n` would have failed the healthy-reader assertion while
  delivery was perfectly correct.

  **The subscriber SLOT is the product-visible half (finding 5).** A pinned
  handler holds one of 64 capped subscriber slots (#4484), so non-reading
  clients accumulate until `TrySubscribe` returns nil and the endpoint 503s for
  everyone — a client that is not reading taking the feed away from clients that
  are. Bounding the write lets the handler return; `defer sub.Close()` turns
  that return into a freed slot; only both together deliver the property, and
  `TestASeveredSSEReaderReleasesItsSubscriberSlot7632` reds if either is
  removed. It runs against **both** handlers, as does the slow-reader cell —
  before this, every assertion here went through `eventStreamHandler` and
  `logStreamHandler` could have been reverted whole without reddening anything.

  Note one pre-existing behaviour #7632 did **not** change: net/http does not
  send response headers until the first `Write` or `Flush`, and `setSSEHeaders`
  only sets header VALUES — so a client connecting to a feed with no traffic
  blocks waiting for headers nobody has sent. A browser `EventSource` on an idle
  firewall hangs rather than establishing the stream. Out of scope here;
  recorded because the test harness has to work around it.

  **A slow reader is a different hazard from a disconnected one (#6809).**
  Every bound above is a bound on PROGRESS. A client that stays CONNECTED and
  stops reading produces neither a disconnect nor a write error: the socket
  buffers fill, `bw.Flush()` parks in the kernel, the stream callback never
  returns, and the `cancel`/`Close`/reap that would kill vtysh all sit AFTER
  the scan loop. Handler goroutine, vtysh child, pipe and connection stayed
  pinned indefinitely. Three bounds now apply, and they are not
  interchangeable:

  - **`bgpStreamWriteDeadline` (30s, per write)** — the PROGRESS budget, and
    the load-bearing one: it is the only thing that can unpin a goroutine
    already blocked in a write. Armed by `deadlineArmingWriter`, which sits
    between `bufio` and the `ResponseWriter` so *every* socket write is
    covered. Arming at the handler's explicit flush points is not enough and
    the regression cell catches it — `bufio` auto-flushes when its 4 KiB
    buffer fills, so ~17 real writes happen between two consecutive 1024-route
    flush boundaries, and those block first. Each write gets a FRESH window, so
    a legitimately large table on a slow-but-progressing link still completes.
  - **`bgpStreamTotalBudget` (10m, per request)** — the ELAPSED backstop,
    derived from `r.Context()` and handed to `StreamBGPRoutes` so
    `exec.CommandContext` kills and reaps vtysh. It catches a client that
    dribbles just enough to reset the write window forever. On a
    `ResponseWriter` that cannot carry a write deadline it frees the CHILD but
    **not** this goroutine — a partial bound, stated as such.
  - **`ribStreamLimiter` (2 concurrent)** — a bounded stream is still a vtysh
    child, so an unbounded NUMBER of them still accumulates. **#9143 generalized
    this reasoning to every other FRR read.** It was true of `?type=routes` and
    equally true of `GET /api/v1/routing/ospf` (both branches) and this
    endpoint's own `bgp` SUMMARY branch, which forked one uncancellable 15s child
    per request with no admission at all — #6809 had gated exactly one branch of
    one handler. The bound now also lives in `pkg/frr`'s single
    `Manager.vtysh` funnel (`diagcmd.VtyshLimiter`), so every present and future
    FRR read on BOTH surfaces is bounded by construction rather than one handler
    at a time, and `realExecutor.Vtysh` takes the caller's context so a
    disconnect reaps the child. `writeFRRError` renders `frr.ErrVtyshBusy` as
    **429 + `Retry-After`**, matching this branch; gRPC renders the same event as
    `codes.ResourceExhausted`. Additive on the status axis — every error that
    rendered 500 before still does. `ribStreamLimiter` stays as the STREAM-shaped
    bound on top (memory + held connection), which is a different cost from the
    fork the funnel counts. Non-blocking
    `Acquire`: over-cap requests get **429 + `Retry-After`** rather than
    queueing, because a queued request holds the same connection it would hold
    while streaming. Local to REST on purpose — the gRPC/CLI `show route
    protocol bgp` paths call the BUFFERED `GetBGPRoutes`, which completes
    before any client sees a byte and cannot be pinned by a reader, so there is
    no second surface to share a budget with.

  Pinned by `bgp_slow_reader_pin_6809_test.go`, whose fixture is a `net.Conn`
  that accepts a fixed prefix and then parks the writer exactly as a full send
  buffer does — including a negative-control cell proving the fixture can
  genuinely pin, so the passing cell means something. The session
  handlers (`/sessions`, `/sessions/summary`, `/sessions/zone-pair`) share a
  per-batch sampler (`newRequestCancelSampler`, `sessionWalkCancelInterval`
  = 1024): each `IterateSessions`/`IterateSessionsV6` callback returns
  `false` once the context is cancelled, breaking the conntrack map walk and
  releasing the per-bucket BPF-map lock back to the live dataplane
  session-sync path (#5233) instead of holding it for a discarded scan. The
  sampler probes `ctx.Err()` once per batch (not per session) so the check
  adds no per-entry cost, and it never fires on the normal path — output and
  ordering are unchanged. The `/sessions` CURSOR path (`page_size>0`,
  `sessionsCursor` over `IterateSessionsFrom`/`IterateSessionsV6From`) uses the
  SAME sampler in both cursor callbacks — a selective/no-match query never
  fills the page, so without it the callback would walk the rest of the table —
  PLUS a direct `r.Context().Err()` check at each phase boundary: it does not
  start the second (v6) full walk after a cancelled v4 phase, and does not emit
  a misleading terminal `next_page_token`/partial-page envelope (nor the
  `include_peer` fan-out inside `writeSessionList`) to a dead connection. A full
  page is still emitted normally — it is a complete, valid result. Pinned by
  `api_ctx_cancel_5232_5233_test.go` (`TestSessionsCursorAbortsWalkOnCanceledContext_5233`
  for the cursor path). This is the REST analog of the gRPC `streamDiagCmd`
  cancellation cleanup (#5060).
- Session-count metrics come from the LIVE dataplane session table, not
  the BPF GC sweep stats (#3929). `collectSessionGauges`
  (`metrics_sessions.go`) derives `xpf_sessions_active` (forward entries)
  and `xpf_sessions_established` (forward entries in the ESTABLISHED
  state) from the SAME `IterateSessions`/`IterateSessionsV6` scan that
  backs the type breakdown, so all session gauges share one scan (no new
  periodic scan; the #333 GC-skip optimization stands) and one
  fail-loud `scrape_ok` gate. The REST `/status` and gRPC `GetStatus`
  `SessionCount` read `dp.SessionCount()` (forward-only live total).
  Before #3929 all three read `gc.Stats().TotalEntries` /
  `EstablishedSessions`, which are permanently 0 on the userspace
  dataplane (the only live forwarding path) because the BPF GC sweep is
  skipped (#333) — so active-session metrics/dashboards read a constant 0
  regardless of real load. `xpf_gc_sweep_duration_seconds` still reflects
  the (skipped, 0) BPF sweep and is orthogonal.
- Dataplane counter read failures get a uniform observability-integrity
  treatment (#3345 global; #3408 per-zone / per-policy / screen-flood /
  filter): a failed counter read is no longer swallowed to `0`, because a
  degraded counter bridge must not be indistinguishable from "no events"
  on a security appliance. The fix covers EVERY global, per-zone,
  per-policy, screen-flood, and filter read surface (NOTE: per-zone traffic +
  per-zone flood counters were later HIDE'd as "not available" by #3643 — a
  structural not-populated state is no longer treated as a read error; the
  genuine-error handling below still applies to the other surfaces — see the
  #3643 bullet):
  - **Structured APIs** return an explicit failure instead of clean-zero
    counter fields. REST `/stats/global` (global), `/security/zones`
    (per-zone), and `/security/policies` (per-policy) return HTTP 500 on
    a read error; gRPC `GetGlobalStats`, `GetZones`, and `GetPolicies`
    return `codes.Internal`. The error is checked AFTER the full response
    is built, so a failure on a late read (e.g. `RxPackets` after the
    screen-detail loop, or any policy/zone in the loop) is covered. The
    kernel-nftables host-inbound counters on `/stats/global` are the one
    exception: because they are dataplane-INDEPENDENT and read before the
    load gate (#3681), a read failure there does NOT 500 the whole response
    (which would hide the good userspace counters) — it sets the
    `host_inbound_kernel_denies_unavailable` marker, the same non-authoritative
    idiom as per-interface `unavailable` (#3464). That marker also covers the
    #5719 counter-LESS table (the #5644 cold-boot fence enforces with no named
    counters, so its empty read is NOT a certified zero); an ABSENT table, and
    real deny counters that merely read zero, both stay authoritative.
  - **Prometheus** (`metrics_counters.go`) OMITS the affected sample
    (rather than emitting a misleading `0`) for global, per-zone,
    per-policy, and per-filter reads, and bumps the monotonic
    `xpf_counter_read_errors_total` scrape-error counter, always emitted
    (0 when healthy) for alerting. The same counter is ALSO bumped by the
    pre-gate kernel-nftables host-inbound collector (`#3361`) when its
    netlink read fails — and (#5719) when that read finds the host-inbound
    table PRESENT but carrying no named counter objects, the cold-boot-fence
    state whose empty result cannot be certified as zero; the bump is the
    Prometheus analogue of the REST `unavailable` marker, since there is no
    series to omit when no counter object exists to label. The descriptor Help
    text names every read surface
    that increments it — global, zone, policy, and filter dataplane reads
    PLUS the kernel-nftables host-inbound read (#3463), not global-only, so
    it matches this contract. The error-counter SAMPLE is emitted via a
    `defer c.emitCounterReadErrors(ch)` established at the TOP of `Collect`
    (#5045), so it runs at function exit — AFTER the global/zone/policy/filter
    sub-collectors (and the pre-gate host-inbound collector) have run — on
    EVERY return path. A read failure in any collector is reflected in THIS
    scrape's value rather than lagging one scrape behind (#3462). Crucially the
    deferred emit also covers the `dp == nil || !dp.IsLoaded()` early return: a
    config-only / degraded boot with a failing pre-gate nft read previously
    skipped the only (post-gate) emit site and carried NEITHER the data series
    NOR the error sample — a clean absence that broke the omit-plus-error
    contract in exactly the degraded state the pre-gate collectors observe
    (#5045). The per-filter collector also
    merges the userspace-dp helper-published `filter_term_counters` into
    `xpf_filter_hits_total` (the same `BuildFirewallFilterTermCounterIndex`
    the CLI/gRPC text paths use), so the canonical metrics path does not
    report 0/stale while `show firewall filter` shows real hits (#3461); the
    per-term counter-slot stride is the shared
    `config.FilterTermExpansionCount` SSOT (#3459).
  - **Text commands** print a `warning: ... counter read failed ...` line
    instead of a clean zero: `show security screen` / `show security
    alarms` / `show security flow statistics` / `show chassis cluster
    fabric statistics` / `show security nat source` (global + flood), and
    `show security policies hit-count` + brief (per-policy), `show
    security zones` (per-zone), `show security screen statistics` (flood),
    and `show firewall filter` (filter) — across both the CLI and the gRPC
    text mirrors.
  - **Ordering invariant**: in every multi-read renderer the `readErr`
    check runs AFTER all counter reads in the function (incl. the detail /
    per-type screen-breakdown and per-policy/per-zone loops), so a failure
    on a LATE read is surfaced rather than printing a stale `0` under an
    earlier passed check. The structured APIs follow the same rule (check
    after the full response is built).
  - **Out of scope**: NAT-rule/port counters are not security counters and
    keep their existing per-read handling. Per-interface counters are also
    out of the SECURITY-counter contract, but they now carry their OWN
    uniform unavailable/error contract (#3464, below) so a degraded
    interface-counter bridge is no longer handled divergently across surfaces.

    **`ReconcileHTTP` asks `serving()`, not just the address** (#6803).
    `ReconcileHTTPS`'s same-address arm has tested `httpsLeg.serving()` since
    #6827 round 6; `ReconcileHTTP`'s tested a non-nil pointer. An unexpected
    serve exit marks a leg dead and leaves it INSTALLED, so the address compare
    matched a corpse and a rebind to the same endpoint returned `nil` having done
    nothing — the HTTP management API was unrecoverable on an unchanged
    configuration for the life of the process. `HTTPServing()` is the new exact
    counterpart of `HTTPSServing()`, and it is what both this no-op and the
    daemon-side `reconcileTo` gate now ask. Pinned by
    `reconcile_http_dead_leg_6803_test.go`, paired against the over-reach
    direction: a HEALTHY same-address leg must still be a no-op, or the
    management socket is rebuilt on every commit and every 30s re-assert tick.

  Pinned by `stats_counter_error_test.go` +
  `zones_policies_counter_error_test.go` (REST + Prometheus),
  `pkg/grpcapi/global_stats_counter_error_test.go` (incl. the late-read
  ordering case) + `flow_cluster_counter_error_test.go` +
  `zones_policies_counter_error_test.go`, and
  `pkg/cli/show_security_counter_error_test.go` (incl. late-read ordering
  cases that fail if a warn is moved before the per-type screen-breakdown
  loop). This resolves both #3345 and #3408.
- **#3643 — per-zone traffic + flood counters are HIDE'd ("not available"),
  not errored.** The per-zone traffic counters (`zone_counters`) and per-zone
  flood counters (`flood_counters`) were never populated in the userspace era
  (the eBPF writers were deleted in #1476) AND, worse, zone ids are stable
  name-hashes in `[1,65533]` (#3075) while the backing BPF arrays are dense
  `MaxZones*2` / `MaxZones`-entry arrays, so every read of a stable-hash id `>=
  MaxZones` OOB'd the bounded `Lookup` and surfaced as a HARD failure — REST
  `/security/zones` returned **HTTP 500** for essentially every real config, and
  the Prometheus per-zone collector bumped `xpf_counter_read_errors_total` once
  per zone per scrape (a permanent FALSE #3345 alert). The HIDE fix:
  `dataplane.ReadZoneCounters`/`ReadFloodCounters` now key a Go-side sparse
  offset map and NEVER index the dense array (the #2255 `nat_rule_counters`
  treatment), returning the distinct `dataplane.ErrCounterNotPopulated`
  sentinel while unpopulated. The read surfaces recognize that sentinel and
  render an explicit **"not available"** — REST `/security/zones` returns 200
  with `per_zone_counters_available:false` (counts unset, not a misleading 0);
  `show security zones` and `show security screen ids-option statistics` print a
  "not available" line; and the always-erroring `xpf_zone_packets_total` /
  `xpf_zone_bytes_total` Prometheus metrics were **dropped** (there is no
  per-zone flood Prometheus/REST surface to remove). The #3345/#3408
  genuine-error contract is UNCHANGED for every other surface (global, policy,
  filter, interface, host-inbound): a real read failure — anything other than
  `ErrCounterNotPopulated` — still 500s / warns / bumps
  `xpf_counter_read_errors_total`. See
  `docs/research/3643-dead-counters/plan.md` (§5A POPULATE spec, §5B HIDE).
  Pinned by `pkg/dataplane/zone_flood_counters_hide_test.go`,
  `pkg/cli/zone_flood_counters_hide_test.go`, and
  `pkg/grpcapi/zone_flood_counters_hide_test.go`. (#3651 later POPULATED both
  families — see the two bullets below. The HIDE *read-path* fix is unchanged and
  still load-bearing: the sparse offset map is still never a dense-array index,
  and `ErrCounterNotPopulated` is still distinct from a read error. What changed
  is that the sentinel is now the exception rather than the permanent state.)
- **Per-zone TRAFFIC counters are populated again, and the Prometheus family is
  back (#3651).** The reason #3643 dropped the metrics — nothing populated them
  — no longer holds: the Rust helper accounts per-zone ingress/egress
  packet+byte volume on the forward path
  (`userspace-dp/src/afxdp/zone_counters.rs`), publishes it in
  `ProcessStatus.zone_traffic_counters`, and the Go status poll mirrors each row
  into the sparse offset map via `Manager.ReplaceZoneCounterOffsets`. `show security
  zones` and REST `/security/zones` picked that up immediately;
  `xpf_zone_packets_total` / `xpf_zone_bytes_total` (labels `zone`,
  `direction` ∈ `{ingress,egress}` — unchanged from the pre-#3643 family, so
  existing dashboards keep working) were restored separately in #3651, since
  Prometheus is the surface an operator actually alerts on.
  `collectZoneCounters` reads ONLY `ReadZoneCounters`, i.e. the sparse offset
  map, so it cannot reintroduce the dense-array OOB read-error storm above.
  Its three-way disposition:
  - **populated** → emit ingress/egress packets and bytes.
  - **`ErrCounterNotPopulated`** → **omit** all four samples and count the zone
    into the `xpf_zone_counters_unpopulated_zones` gauge; do NOT bump
    `xpf_counter_read_errors_total`. Unpopulated is a legitimate steady state,
    and treating it as an error is exactly the per-scrape false alert #3643
    removed the family to stop. The samples are omitted rather than published
    as `0` because the helper's status snapshot is sparse and drops all-zero
    rows, so this sentinel cannot distinguish a pre-#3651 helper, a zone past
    the helper's 63 assignable hot-path slots (whose traffic really is
    uncounted), and a merely idle zone — a `0` would be an authoritative zero
    over an unknown. The gauge is always emitted (0 when healthy) and counts
    exactly the zones REST reports `per_zone_counters_available:false` for.

    **Emitted ABOVE the dataplane-loaded gate (#6843 R1), which widens the
    membership set beyond the sentinel's.** The gauge is contractually always
    emitted so `> 0` is alertable and its absence is not confusable with a
    scrape that failed to run — which means it must also be emitted on a
    degraded / config-only boot, where per-zone volume is least available. So
    `collectZoneCounters` runs before the `dp == nil || !dp.IsLoaded()` early
    return, alongside `collectPBRStatus` and the host-inbound families.

    **`xpf_zone_counters_overflow_active` disambiguates it (#6845).** The
    sentinel above is three-way ambiguous BY CONSTRUCTION — pre-#3651 helper,
    slot-capacity overflow (traffic genuinely missed), or an idle zone — and only
    the middle case needs action. The bit that separates it was already on the
    wire (`ProcessStatus.ZoneCounterOverflowActive`, from
    `userspace-dp/src/afxdp/zone_counters.rs`) and was read by **nothing**: no
    CLI, no REST, no gRPC, no Prometheus. This 0/1 gauge publishes it.

    **Its absence semantics are the OPPOSITE of the sibling gauge's, and that is
    the design.** `xpf_zone_counters_unpopulated_zones` is config-derived, so it
    is emitted above the dataplane gate and keeps reporting the full configured
    zone count through a degraded boot. Overflow is a property of the RUNNING
    helper's slot table: with no helper there is no slot table and nothing to
    overflow, so a `0` would be a false all-clear about a machine nothing asked.
    It is therefore emitted from `collectUserspaceStatus` — **only on a scrape
    that actually read a status**. Absent means "no helper to ask"; `0` means
    "the helper reported no overflow".

    Not an error, and it must never touch `xpf_counter_read_errors_total`: an
    overflowed zone degrades to "not known" on every read surface rather than
    publishing a false zero, so no surface reports wrong numbers. What overflow
    costs is the ability to tell **why**, which is what this restores.

    `show security zones` consumes the same flag: on the unpopulated branch it
    names capacity exhaustion specifically instead of listing three causes the
    operator cannot choose between. It fails to the ambiguous line on any status
    error — telling someone to reduce their zone count when the real cause was an
    idle zone is worse than saying "cannot tell".

    **REST deliberately does NOT carry it.** `/security/zones` returns a bare
    `[]ZoneInfo` with no response envelope, so a response-level field would mean
    changing the response from an array to an object — a breaking API shape change
    that should be decided on its own merits, not ridden in on an observability
    fix. Per-zone placement was rejected too: overflow is a property of the slot
    TABLE, and the helper does not report which zones lost their slots, so a
    per-zone flag would be an invention.

    Consequence: **the gauge's cause set is strictly wider than
    `ErrCounterNotPopulated`'s.** The sentinel has exactly three meanings; the
    gauge has those plus every pre-read membership branch. The authoritative
    enumeration is the metric's own HELP in
    `pkg/api/metrics_descriptors_zone.go`, and **this document deliberately
    states no count** — the count is the part that rots, and it rotted right
    here: this paragraph claimed "a fourth reason" and "three causes none of
    which applies" while the Go comment it mirrors had already grown past four.

    Two causes are worth naming here because an operator is least likely to
    guess them, and both follow from the config store being promoted BEFORE the
    dataplane apply: the dataplane is **loaded but has no apply result yet**
    (shim loaded, first apply pending or failed), and a zone is **in the active
    config but absent from the last apply result** (a commit whose apply failed
    leaves the store ahead of the dataplane). Neither produces the sentinel —
    the collector increments and `continue`s before it ever calls
    `ReadZoneCounters` — so do not read the HELP list as a list of sentinel
    meanings.

    All of this is named in the HELP because there is no `xpf_dataplane_loaded`
    series to disambiguate against, so an operator paging on `> 0` would
    otherwise triage toward causes none of which applies.

    **Retention (#6843).** "Not populated" must also be reachable *backwards* —
    a zone that WAS reporting and stops. The helper's store outlives its slot
    map: config apply carries the store forward and retains every
    still-configured zone, so a zone pushed past the hot-path slot capacity by a
    later config keeps its accumulated totals while no longer being counted. Two
    guards keep that from becoming a frozen counter. The helper publishes a row
    only when the zone is configured **and** holds a live slot
    (`publishable_zone_rows`), and the Go status mirror **replaces** the whole
    offset map from each snapshot rather than merging into it
    (`Manager.ReplaceZoneCounterOffsets`). Both are required: without the first
    the stale row keeps being published; without the second a row that stops
    being published leaves its last value stranded. Either way the metric would
    emit a total that can never advance — worse than an omission, because a
    frozen counter looks alive.
  - **any other error** → omit the samples and bump
    `xpf_counter_read_errors_total` (the #3345/#3408 skip-and-bump contract is
    intact — a degraded counter bridge stays alertable).

  Pinned by `pkg/api/zone_counters_metrics_test.go`, which replaced the
  `pkg/api` HIDE pin.
- **Per-zone FLOOD counters are populated too (#3651, flood half).** The helper
  now tallies per-zone `syn-flood` / `icmp-flood` / `udp-flood` screen DROPS on
  the `record_screen_drop` path
  (`userspace-dp/src/afxdp/flood_counters.rs`), publishes them in a second
  pre-summed sparse `ProcessStatus` block (`zone_flood_counters`, layout version
  1, nonzero rows only), and `syncBPFCountersLocked` REPLACES the whole Go flood
  offset map from it (`Manager.ReplaceFloodCounterOffsets`) — replace, not merge,
  for the same frozen-counter reason as the traffic half. `show security screen
  ids-option statistics` (CLI and gRPC text) therefore reports live per-zone
  flood-event counts. `ErrCounterNotPopulated` stays reachable and is NOT an
  error: it covers a helper predating the accounting, a zone past the hot-path
  slot capacity, and a zone that has never tripped a flood check, so the surfaces
  keep rendering an explicit "not available" (with the CAUSE named, not the
  retracted "not implemented" claim). There is still no per-zone flood REST or
  Prometheus surface — the aggregate `xpf_screen_drops_total` by reason (#3343)
  remains the alerting surface for flood drops. An operator clear
  (`ClearAllCounters`) sends a `clear_flood_counters` IPC so the helper's
  cumulative store resets and the cleared value does not snap back on the next
  1 s poll. Pinned by `pkg/dataplane/flood_counter_retention_3651_test.go`,
  `pkg/dataplane/userspace/flood_counter_syncloop_3651_test.go`,
  `.../zone_flood_counters_status_test.go`,
  `.../flood_counter_clear_3651_test.go`, and the populated-path leg of
  `pkg/cli/zone_flood_counters_hide_test.go`.
- Per-interface counter read failures get a uniform unavailable/error
  contract across all four interface-counter surfaces (#3464). Interface
  counters are intentionally out of the #3345 SECURITY-counter contract
  (above), but they used to be handled DIVERGENTLY on a failed
  `ReadInterfaceCounters`: REST `/stats/interfaces` dropped the whole row
  (the interface vanished), REST `/interfaces` and gRPC `GetInterfaces` left
  a clean `0` (indistinguishable from a real idle interface), and the
  Prometheus collector silently omitted the sample with no error metric. An
  operator could not tell "interface idle" from "counter bridge unavailable".
  The uniform contract:
  - **Structured APIs** KEEP the interface row and set an explicit
    `unavailable` flag (`InterfaceStats.unavailable` on REST `/stats/interfaces`
    + `/interfaces`; `InterfaceInfo.unavailable` on gRPC `GetInterfaces`). The
    counter fields stay `0` but are not authoritative — a real idle `0` is
    distinguishable from a degraded read. `/stats/interfaces` no longer drops
    the row (the old `continue`). A read failure does NOT escalate to HTTP 500
    / `codes.Internal` (unlike the security counters): interface counters are
    operability telemetry, not a security signal, so per-row degradation is
    preferred over failing the whole inventory.
  - **Prometheus** (`metrics_counters.go`) still OMITS the affected
    `xpf_interface_{packets,bytes}_total` sample (rather than emitting a
    misleading `0`) and bumps the dedicated
    `xpf_interface_counter_read_errors_total` monotonic counter — SEPARATE
    from `xpf_counter_read_errors_total` so interface-counter degradation is
    alertable without conflating it with security-counter health. The sample
    is always emitted (0 when healthy) and emitted AFTER
    `collectInterfaceCounters` (`emitInterfaceCounterReadErrors`) so a failure
    this scrape is reflected this scrape.
  - The kernel-link `net.InterfaceByName` "not present" case (a different
    axis — interface absent from the kernel, not a counter-bridge failure)
    keeps each surface's existing handling and is NOT flagged `unavailable`.

  Pinned by `interface_counter_error_test.go` (REST + Prometheus) and
  `pkg/grpcapi/interface_counter_error_test.go` (gRPC). This resolves #3464.
- Named source-NAT pool stats are sourced from the userspace helper's
  LIVE runtime status, not config text (#2938). `natPoolStatsHandler`
  (`/security/nat/source/pools`) reads `s.runtimeSourceNATPools()` — the
  helper's `ProcessStatus.SourceNATPools` (`SourceNATPoolStatus`),
  deduplicated by pool name (rules sharing a pool reference the same
  `Arc<PortAllocatorShared>` and report identical occupancy, so one entry
  per pool is kept, never summed — same contract as
  `pkg/dataplane/userspace/applied_nat_view.go`). The reported
  `AddressCount`, port window (`PortLow`/`PortHigh`), and `UsedPorts` come
  from that runtime view; `TotalPorts` = `(PortHigh-PortLow+1) *
  AddressCount`. The helper is authoritative because it rejects malformed
  addresses, splits pools by IP family, shares allocator state across
  rules, and reports actual used ports — config text + the retired-eBPF
  `ReadNATPortCounter` could over-report capacity or report a dead-map
  count under the AF_XDP dataplane. The config-derived window +
  `ReadNATPortCounter` path remains ONLY as a fallback when the helper has
  no runtime entry for a pool (helper not running / before the first
  apply lands). Pinned by `TestNATPoolStatsHandlerUsesRuntimeStatus`
  (fail-on-revert) in `nat_stats_test.go`. The gRPC `GetNATPoolStats`,
  CLI `show security nat source pool`, and the Prometheus
  `xpf_nat_pool_total_ports` / `xpf_nat_pool_used_ports` collector
  (`metrics_nat.go`) still derive named-pool capacity/used from config +
  the legacy counter and are the follow-up SSOT surfaces (the Prometheus
  `xpf_userspace_snat_pool_*` family in `metrics_userspace.go` already
  exposes the runtime per-pool view).
- NAT-stats telemetry read failures fail CLOSED as *unavailable*, never as a
  healthy zero (#5046, the #3345 counter-error contract). A read is a
  *failure* only when the id resolves and the telemetry call errors (a
  missing apply-id / absent runtime entry is a legitimate "no counter" and
  is NOT flagged). On such a failure:
  - **REST** (`nat.go`) returns HTTP 500: `runtimeSourceNATPools()` now
    returns `(map, error)` and propagates a `Status()` read failure (instead
    of the old bare `nil`, indistinguishable from provider-absent);
    `natPoolStatsHandler` also 500s on a fallback `ReadNATPortCounter`
    failure, and `natRuleStatsHandler` 500s on a `ReadNATRuleCounter`
    failure — rather than emitting `used_ports`/`hit_packets` = 0 with 200.
  - **gRPC** (`server_nat.go`) returns `codes.Internal`: `GetNATPoolStats`
    on a `NATPortCounter` failure and `GetNATRuleStats` on a `NATRuleCounter`
    failure (the `readCounter` helper now returns an error), matching the
    `GetZones`/`GetPolicies` #3408 contract.
  - **Prometheus** (`metrics_nat.go`) OMITS the affected
    `xpf_nat_pool_used_ports` sample (never a fake `0`) and bumps the shared
    `xpf_counter_read_errors_total`; `collectNATPoolMetrics` now runs BEFORE
    `emitCounterReadErrors` so the bump is reflected in the same scrape
    (#3462 ordering). Pinned by `nat_counter_error_test.go` (REST +
    Prometheus) and `pkg/grpcapi/nat_counter_error_test.go` (gRPC),
    fail-on-revert.
- Interface-mode source-NAT rows (`source-nat interface`, no named pool)
  report `UsedPorts` as the count of forward SNAT sessions that traversed
  THAT rule set's own from/to zone pair — not the firewall-wide SNAT total
  (#3417). `natPoolStatsHandler` iterates sessions once, keying the count by
  the session's ingress/egress zone (mapped to names via the apply result's
  `ZoneIDs`), and each `<from>-><to>` row reads only its own bucket. Without
  the zone map (no apply result yet) attribution is impossible, so rows
  report 0 rather than a wrong aggregate. The #2469 fail-closed behavior is
  preserved: a partial session scan returns HTTP 500 rather than a
  healthy-but-low figure. The gRPC `GetNATPoolStats` mirrors this, setting
  each interface row from `counts.ruleSetSessions[{from,to}]` (the same
  per-rule-set breakdown it already surfaces in `RuleSetSessions`); CLI `show
  security nat source pool` renders the gRPC value directly. Pinned by
  `TestNATPoolStatsHandlerInterfaceModePerRuleSet` (REST) and
  `TestGetNATPoolStatsInterfaceModePerRuleSet` (gRPC), both fail-on-revert.
- The gRPC `GetNATRuleStats` `nat_type` selector fails CLOSED (#5719,
  codex-review-182 C-API). Only `""` (default = source), `"source"`, and
  `"destination"` select a rule family; any other value (a typo like `"src"`
  or `"static"`) is rejected with `codes.InvalidArgument` rather than falling
  through both branches to an empty "no NAT rules" response — a false-empty
  diagnostic indistinguishable from a firewall with no rules. Same discipline
  as the show routing/zones/firewall unknown-selector diagnostics. Pinned by
  `TestGetNATRuleStatsRejectsUnknownSelector` (gRPC), fail-on-revert.
- Query-filter parsing fails CLOSED, matching the gRPC contract
  (#2934/#2935/#2939). A filter sentinel of `0`/`""` means "no filter",
  so a *malformed* filter value must error rather than silently fall
  through to no-filter (which widens the query to everything — a
  cross-zone observability leak). `queryUint16Strict`/`queryIntStrict`
  (`api.go`) return `(0, false)` on a malformed non-empty value; the
  sessions/events `zone` filter and the policy-match `dst_port`/`src_port`
  return HTTP 400 instead of zeroing the predicate. #4926: the
  security-events `limit` parameter is likewise parsed strict — a
  present-but-malformed/negative value (`limit=abc`, `limit=-1`), a
  non-canonical spelling (`limit=+5`), or a value past the 10000 upper cap
  (`limit=10001`) returns HTTP 400 instead of silently defaulting to 50 or
  clamping (a fail-open that mirrored the lenient `queryInt` and could
  under-report the requested event window). An absent/empty `limit` still
  defaults to 50, matching the zone filter's "absent = no constraint"
  semantics; a valid `limit` in `[0..10000]` is used as-is. #3679:
  `queryIntStrict`
  parses via `config.ParseCanonicalUint` rather than `strconv.Atoi`, so a
  signed/non-canonical spelling (`dst_port=+80`, which `Atoi` accepted as `80`)
  is rejected here exactly as the #3606 commit-time and dataplane port parsers
  reject it — no commit-vs-diagnostic split. The session `protocol`
  filter (`sessions.go` `protoFilterMatches`) is case-insensitive AND
  accepts a numeric IP protocol number (`tcp`/`TCP`/`6` all match TCP),
  mirroring gRPC (`pkg/grpcapi` `protoFilterMatches`) and CLI. The event
  filter (`pkg/logging` `EventFilter.matches`) matches protocol/action
  EXACTLY (case-insensitive), not by substring — `protocol=C` no longer
  over-matches TCP/ICMP/ICMPv6. These contracts are pinned by
  `rest_filter_failclosed_test.go` (and, for the events `limit`,
  `rest_events_limit_failclosed_4926_test.go`) in this package.
- The `GET /api/v1/security/sessions` view mirrors the gRPC `GetSessions`
  session contract (#3419). The REST `SessionEntry` previously diverged from
  gRPC — `age_seconds` carried IDLE time (now-LastSeen) instead of wall age,
  a session with both SNAT and DNAT lost the SNAT part (the DNAT branch
  overwrote the single `nat` string), the reverse entry's counters were not
  merged into the forward entry, and the application/interface/policy-name/
  zone-name/session-id/ha-active fields were absent. The handler now:
  - splits `age_seconds` (now-`Created`) from `idle_seconds` (now-`LastSeen`);
  - joins BOTH NAT parts in `nat` and exposes structured `nat_src_addr/port`
    and `nat_dst_addr/port`;
  - merges the companion reverse entry's counters via `GetSessionV4/V6`
    (added to `apiRuntimeDataPlane`) so top-talkers/accounting report full
    bidirectional volume;
  - resolves `application` (`appid.ResolveSessionName`), `ingress_interface`/
    `egress_interface` (FIB ifindex+VLAN → unit name), `policy_name`,
    `ingress_zone_name`/`egress_zone_name`, `session_id`, and `ha_active`
    (wired from the daemon via `HAActiveFn`, default true standalone).

  It also accepts the gRPC filter set: `application=`, `interface=`,
  `nat_only=true`, and `source_nat_pool=<pool>` (an unresolved pool fails
  CLOSED with HTTP 400, like the gRPC `sessionFilter.validate`). The numeric
  `policy_id`/`ingress_zone`/`egress_zone` fields are retained for
  compatibility. Pinned by `sessions_parity_test.go`.
- HA scope on the session list/summary (#3423 M5). The REST list and summary
  report the LOCAL node's table only; previously they carried no node identity
  and no way to include the peer, so a dashboard polling one node could not
  tell WHICH node it observed and understated total cluster session state. Both
  now always carry `node_id` (this node's cluster id, 0 standalone; wired from
  the daemon via `NodeIDFn` → `cluster.NodeID()`), and both accept
  `include_peer=true` (a malformed value fails CLOSED with HTTP 400). When set,
  the handler delegates the PEER fetch to the live gRPC server through the
  `ClusterSessionFn`/`ClusterSessionService` seam and attaches the peer node's
  list/summary under a nested `peer` field (mirroring gRPC `GetSessions`/
  `GetSessionSummary` `include_peer`). The peer's table is attached only on
  the FIRST page — in BOTH pagination modes (cursor mode's first page has no
  `page_token`; offset mode's first window has `offset==0`). A non-first page
  must not re-attach the peer table or a client summing `peer.sessions`
  across pages would OVER-COUNT the peer; the offset path never sets a
  `page_token`, so the `sessionFirstPage` guard checks `offset==0` too. The peer
  fetch honors the SAME page bound the local list did: `peerSessionsRequest`
  forwards offset-mode `limit` AND cursor-mode `page_size` to the peer gRPC
  request (#4920). Before that fix a cursor-mode caller (`page_size` without
  `limit`) sent the peer `Limit==0` AND `PageSize==0`, so `getSessionsLegacy`
  defaulted the peer list to 100 sessions and the first REST page silently
  undercounted a peer holding >100 sessions. `page_token` is intentionally NOT
  forwarded — tokens encode node-local map keys and the peer fetch only runs on
  the first page. A standalone node or unreachable peer leaves `peer` absent.
  Pinned by `sessions_ha_scope_3423_test.go`.
- The zone-pair summary (`GET /api/v1/security/sessions/summary/zone-pairs`,
  `sessionZonePairHandler`) is the same SUMMARY class and carries `node_id` —
  the response shape changed from a bare array to
  `ZonePairSummaryResponse {node_id, zone_pairs:[...]}` so it can (#3423 M5). It
  now also supports `include_peer=true` cross-node fan-out (#3592), matching its
  `/sessions/summary` sibling. A malformed `include_peer` value fails CLOSED with
  HTTP 400 before any work. When set, the handler forwards to the new gRPC
  `GetZonePairSummary` RPC through the `ClusterSessionFn`/`ClusterSessionService`
  seam (`IncludePeer` set) and attaches the cluster peer's OWN zone-pair
  breakdown under a nested `peer` field (`ZonePairSummaryResponse.Peer`, carrying
  the peer's own `node_id`). Unlike the session LIST there is no first-page gate
  — the breakdown is a summary, not a paginated list, so the whole peer breakdown
  attaches whenever `include_peer` is set (just as `/sessions/summary` attaches
  the whole peer summary). The gRPC RPC computes the peer's breakdown locally and
  uses the `x-peer-forwarded` metadata recursion guard so A→B never recurses back
  into A; a standalone node, an unreachable peer, or a failed peer RPC leaves
  `peer` absent (a read summary degrades gracefully). Pinned by
  `sessions_ha_scope_3423_test.go` (node_id), `sessions_zonepair_peer_3592_test.go`
  (REST fan-out + fail-closed), and `zonepair_summary_3592_test.go` (gRPC RPC +
  recursion guard).
- Session list pagination and the remaining filter dimensions reach gRPC
  parity in #3421, folded into the SAME `sessionQuery` + `sessionView` +
  enriched `sessionEntryV4/V6` machinery above (one filter type, not two).
  Added filters: `source_prefix`, `destination_prefix`, `source_port`,
  `destination_port` (prefixes accept a CIDR or a bare IP; mirror the gRPC
  `matchV4`/`matchV6` predicates), each parsing FAIL-CLOSED — a malformed
  prefix/port returns HTTP 400 instead of zeroing the predicate and widening
  the query (#3421 M2). Pagination has two modes: the default best-effort
  `limit`/`offset` window (now parsed strict — malformed/negative → 400,
  #3421 M8), and a stable cursor mode selected by `page_size>0`. Cursor mode
  iterates v4 then v6 from an opaque `page_token`, returning up to
  `page_size` rows plus a `next_page_token` that resumes exactly after the
  last row (no skip/duplicate across map mutation, the offset path's hazard);
  an empty `next_page_token` marks the last page. Both modes share the
  reverse-counter merge + enrichment, so they report IDENTICAL rows and
  counters. The token codec mirrors the gRPC page-token format and encodes
  node-local session-map keys (opaque to clients); when the runtime
  dataplane lacks cursor iteration the handler falls back to the offset path.
  Pinned by `sessions_pagination_test.go`.
- Bounded pagination walk + admission gate (#5318, connected-client residual
  after the #5237 disconnect-abort). Two hardenings on `GET /security/sessions`
  so a small paginated read cannot force unbounded full-table work per page:
  - **Admission bound.** A session list is a full conntrack-table walk that
    contends with the live session-sync path for per-bucket BPF-map locks. The
    handler now acquires a slot from `sessionWalkLimiter`
    (an alias of the process-wide `diagcmd.SessionWalkLimiter`, capacity
    `diagcmd.MaxConcurrentSessionWalks` = 4, the SAME fail-fast
    counting-semaphore idiom the diagnostic ping/traceroute handlers use, #5057)
    BEFORE the walk and the peer fan-out, releasing on every exit path. Over-cap
    requests are rejected immediately with **HTTP 429** (`session list
    concurrency limit reached; retry shortly`) rather than each driving its own
    simultaneous walk — a scrape flood can no longer multiply lock contention.
    The #5237 disconnect-abort bounds a SINGLE client's walk once ITS connection
    drops; this bounds how many CONNECTED clients walk at once, which the
    disconnect-abort does not. **#5433 extends the SAME gate to the aggregation
    siblings** `GET /security/sessions/summary` and
    `GET /security/sessions/summary/zone-pairs`, which drive the identical full
    v4+v6 walk. All three share ONE `sessionWalkLimiter` so the bound is on the
    AGGREGATE walk concurrency across the scan endpoints, not one budget per
    endpoint (they contend for the same locks). The aggregation handlers compute
    an EXACT summary / zone-pair breakdown, so `sessionCountCap` is NOT applied —
    an exact aggregate genuinely needs the full walk and a cap would change the
    response contract; the admission gate alone is the fix (no response-shape
    change). Over-cap aggregation requests return **HTTP 429** (`session scan
    concurrency limit reached; retry shortly`). Pinned by
    `sessions_aggregation_bound_5433_test.go` (per-handler concurrency bound +
    shared-limiter cross-endpoint 429 + permit-release, RED-on-revert).
    **#5708 hoists this limiter to `diagcmd.SessionWalkLimiter`** so the SAME
    aggregate budget also covers the gRPC session-scan paths
    (`GetSessions`, `GetSessionSummary`, and `GetZonePairSummary` in
    `pkg/grpcapi/server_sessions.go`, plus the `ShowText` `sessions-top:*`
    scan in `server_show_flow.go` — gRPC-only, no REST twin), which drive the
    identical full v4+v6 walk and previously bypassed the REST bound
    (codex-review-182 M35). The `sessions-top` scan's #5319 bounded top-K caps
    only the OUTPUT (K survivors), not the full-table WALK. The gRPC
    zone-pair RPC was a particularly clear gap — its REST twin
    (`GET /security/sessions/summary/zone-pairs`) was already gated, so
    zone-pairs was bounded on REST but unbounded on gRPC. A gRPC caller can no
    longer issue unbounded full-table scans; over-cap gRPC scans return
    `codes.ResourceExhausted`. A mix of REST + gRPC scrapers cannot collectively
    exceed `diagcmd.MaxConcurrentSessionWalks`.
    **#6216 extends the SAME gate to `natPoolStatsHandler`
    (`GET /security/nat/source/pools`)**, whose interface-mode `UsedPorts`
    accounting (#3417 above) drives the identical full conntrack walk via
    `IterateSessions` and previously bypassed the aggregate bound entirely — a
    scrape flood of the NAT-pool-stats endpoint could each drive a concurrent
    unbounded walk, contending with session installs on the shared control
    socket. The handler now `AcquireCtx`es a slot BEFORE the walk (429 on
    over-cap: `nat pool stats concurrency limit reached; retry shortly`),
    honors the returned admission-lease context inside the `IterateSessions`
    callback (stops early on client disconnect), and releases on every exit
    path. Pinned by `nat_pool_stats_walk_limiter_6216_test.go` (RED-on-revert).
    Note: only the interface-mode session-walk arm is gated; the pool-mode rows
    read the helper's live `SourceNATPoolStatus` (no table walk) and need no
    admission slot.
    **#6553 closes the mirror-image gap on the gRPC side** — the direction that
    matters, because across this campaign 12 of 14 measured REST-vs-gRPC parity
    gaps ran gRPC-UNhardened, the reverse of #6451's direction. Six gRPC NAT
    surfaces drove full v4+v6 walks with no admission at all: `GetNATPoolStats`
    and `GetNATDestination` (loopback; the latter has NO REST twin, since
    `natDestHandler` does not scan), and the four `ShowText` topics
    `persistent-nat`, `persistent-nat-detail`, `nat-source-rule-detail`,
    `nat-dest-rule-detail`, which reach `pkg/natshow`'s walks and are
    reachable over the FABRIC listener. The two RPCs `AcquireCtx` and sample
    the lease inside `countNATSessions`; the four `ShowText` topics took the
    plain `Acquire` (the existing ShowText precedent) because `pkg/natshow` is
    shared with `pkg/cli` and took no context — the admission half landed in
    #6553, the cancellation half was the stated residual. Because both surfaces
    alias ONE `diagcmd.SessionWalkLimiter`, an un-cancellable gRPC walk was
    actively degrading the REST twin that does honour cancellation.
    **#7315 closes that residual and corrects its count.** `pkg/natshow`'s
    walking renderers (`RenderPersistentDetail`, `RenderSourceRuleDetail`,
    `RenderDestRuleDetail`) now take a `context.Context`, the `ShowText`
    handlers `AcquireCtx` and pass the lease context down, and `pkg/cli` passes
    `context.Background()` (a local render has no request to cancel and does
    not draw on the shared limiter). The three hand-copied
    `IterateSessions`/`IterateSessionsV6` pairs collapse into ONE
    `walkSessionValues` authority inside `pkg/natshow` whose visitor callbacks
    have no `bool` return, so a renderer cannot decide to keep walking and a
    NEW renderer inherits the cancellation check instead of having to remember
    it — the same shape `countNATSessions` gives the gRPC NAT RPCs. Admission
    bounds CONCURRENCY and the lease bounds DURATION; they fail independently,
    since a handler can hold its slot correctly and still walk the whole table
    for a client that has hung up. The count correction: only **three** of the
    four `ShowText` topics walk. `persistent-nat` (`RenderPersistent`) reads
    only `PersistentNATTable.All()`, an O(bindings) snapshot copy of an
    in-process map under that table's own RWMutex — it touches no conntrack
    bucket — so it takes no context (a cancellation guarantee over nothing);
    #6553's line cites for it, `persistent.go:85`/`:102`, are both inside
    `RenderPersistentDetail`. **#8151 resolves the budget it draws
    from.** Its admission slot is KEPT — the snapshot is still an O(bindings)
    allocation on a fabric-reachable surface, and dropping a bound from a
    peer-reachable surface is a security-shaped change that should not be a
    side effect of correcting an accounting error — but it now takes
    `diagcmd.SnapshotReadLimiter`, its own budget, rather than
    `SessionWalkLimiter`. Charging it to the session budget was exploitable,
    not merely inaccurate: `MaxConcurrentSessionWalks` is 4, REST and gRPC
    alias ONE limiter, and `ShowText` is on `fabricAllowedUnaryMethods`, so a
    cluster peer polling `persistent-nat` could hold all four slots and make
    genuine scans (`GET /api/v1/sessions`, `GetSessions`, `GetStatus`'s
    `SessionCount`) start refusing. The two budgets are sized independently
    because they bound different costs — a map copy versus per-bucket BPF-map
    locks held across the whole v4+v6 table — so tying them would make one a
    hostage to the other's tuning. Pinned by
    `TestPersistentNATUsesTheSnapshotBudget8151`, which asserts the
    independence in BOTH directions: saturating either budget must not refuse
    the other's topic. One direction alone would pass on an implementation
    that had merely renamed the shared limiter. Pinned by `pkg/natshow/walk_cancellation_7315_test.go`
    (mechanism) and `pkg/grpcapi/nat_showtext_cancellation_7315_test.go`
    (the WIRING — nothing in `pkg/natshow` can see a handler passing
    `context.Background()` instead of the request context), both counting
    VISITED ROWS with a live-context control, because a rendered tally of 0 is
    also what "the walk never ran" looks like.
    **#7294 makes a failed peer fetch on the session LIST surface visible.**
    `writeSessionList` discarded the error (`if pr, err := ...; err == nil`),
    so a failed or refused peer fetch returned HTTP 200 with the peer table
    simply absent and no indication why — an operator could not tell "the peer
    has no sessions" from "we never asked". The summary and zone-pair surfaces
    have always classified this; the list surface was the one that did not,
    which is the shape that survives review because two of three places look
    right. The response now carries `peer_status` / `peer_error`, set ONLY when
    the request opted in with `include_peer` so a response that never asked for
    a peer is byte-identical to the pre-#7294 shape.
    A fetch failure is also no longer uniformly reported as `unreachable`: an
    admission refusal (`codes.ResourceExhausted`) means the peer is REACHABLE
    and this node declined to ask, and calling that a partition sends an
    operator debugging a fabric problem after a network fault that does not
    exist. Refusals now report `busy`; genuine failures still report
    `unreachable`, and both sides are pinned so the fix cannot degrade into
    renaming everything.

    **#8308 closes both of #7294's scoped residuals**, which were left open
    because each is a wire change with its own rolling-upgrade question.
    `pb.PeerFetchStatus` gains `PEER_FETCH_STATUS_BUSY = 4` and
    `GetSessionsResponse` gains `peer_status` (8) and `peer_error` (9). Both
    are ADDITIONS, never redefinitions: in a rolling HA upgrade the two nodes
    run different binaries against one wire, so narrowing UNREACHABLE to mean
    "unreachable or refused" would silently change what the older binary
    reports about an unchanged event. The cost of the additive choice is that
    an older client renders BUSY as the raw integer `4` rather than a word —
    visibly odd rather than quietly wrong, which is the trade being bought, and
    the member numbers are pinned so the redefinition cannot be reintroduced
    (renumbering BUSY to 3 fails to COMPILE). The other direction is pinned
    too: a response from an older server omits the new fields entirely, so a
    new client decodes `UNSPECIFIED`, whose documented meaning is already "not
    evaluated / older server" — a reader must treat it as "this server does not
    report it", never as an outcome. The REST list surface consequently reports
    what the SERVER classified instead of asserting `"ok"` locally, keeping the
    local `"ok"` only for an UNSPECIFIED response so an older peer does not
    regress below #7294's behaviour during the upgrade window. REST and gRPC
    now agree on the word for a refusal, and the agreement is asserted rather
    than either side being pinned to a literal.
    The path is currently UNREACHABLE — the REST handler stamps the session-walk
    lease before delegating, so `PeerSessions` takes `AcquireCtx`'s reuse arm and
    never returns `ErrBusy` — and #7294 item 3's separate remote budget is what
    makes it reachable. It is fixed because it is wrong, not because item 3
    needs it: unreachable today is a property of the current call graph, not a
    guarantee, and the next change to that graph gets no warning.
    **#7294 item 3 gives peer-directed work its own budget.** The peer-only
    entry points (`PeerSessions`, `PeerSessionSummary`, `PeerZonePairSummary`)
    drive NO local walk, but took a slot from `SessionWalkLimiter` anyway — so
    a burst of peer-directed requests could refuse genuine local scans while
    the local table was untouched, on a 4-slot budget shared across REST and
    gRPC with `ShowText` fabric-reachable. They now take
    `diagcmd.RemoteWalkLimiter`: same capacity (4), same fail-fast semantics,
    same lease-aware `AcquireCtx`, its own budget. **This is not a loosening** —
    an unleased peer call was bounded by 4 slots before and is bounded by 4
    now; what changes is which budget, and therefore that saturating one can no
    longer refuse the other. The budget is GLOBAL rather than per-peer (a
    per-peer bound would fail to bound N peers, which is the reason to bound a
    fabric-reachable surface at all) and its sole consumers are those three
    methods; a shared budget bounds the SUM, so adding a consumer tightens it
    for the existing ones and is a decision rather than a refactor.
    Independence is asserted in BOTH directions, following #8151: one direction
    alone passes on an implementation that merely renamed the shared limiter.
    That was not hypothetical — measured by mutation, pointing the alias at
    `SessionWalkLimiter` left all three independence cells green, because each
    substitutes both aliases with fresh instances and the substitution destroys
    the property. An instance-identity cell closes it.
    #5880's lease-propagation property moved with the path rather than being
    retired, and its guard was RESTATED rather than relaxed: the control still
    requires an unleased call to be refused at capacity, now on the budget that
    bounds it. That guard was landed first, in #8301, precisely so it could
    observe this change instead of certifying it; #8306 landed second because
    taking a real remote slot makes a previously-unreachable silent-degradation
    path reachable.
    **#7294 also makes the admission discipline structural rather than remembered.** Every
    extension above — #5433, #5708, #5779, #5782, #5939, #6216, #6553, #7315,
    #8151 — was a surface someone noticed was walking without admission, and
    each was pinned by its own behavioural test covering exactly that surface.
    Nothing failed when a NEW scan surface appeared, which is what #6216 was:
    `natPoolStatsHandler` drove the identical walk and bypassed the bound until
    a human noticed. `pkg/diagcmd/session_walk_registration_7294_test.go` is a
    registration guard over `pkg/api` and `pkg/grpcapi` — it parses both
    packages, finds every call of a session-scan primitive (`IterateSessions`,
    `IterateSessionsV6`, `IterateSessions[V6]From`, `BatchIterateSessions[V6]`,
    `SessionCount`) plus the `pkg/natshow` carriers that reach one, and
    requires each such function to be admitted either directly or through every
    caller that reaches it. Adding a scanning endpoint without an acquire fails
    the build's test gate, with the function named.
    Three properties it was built to have, each verified by mutation rather
    than asserted. It matches CALL POSITION, so `apiRuntimeDataPlane`'s
    `SessionCount()` interface field is not a scan. It requires the SESSION-WALK
    budget specifically, so the #8151 shape — a surface that acquires, but on
    `SnapshotReadLimiter` — still reds; a guard asking only "does it acquire?"
    would have rated that compliant. And it admits through a caller or a
    dedicated acquire helper (one that returns the release closure, like
    `acquireNATShowWalk`) but NOT through arbitrary transitive reachability:
    the first version propagated admission callee-to-caller, which silently
    marked every handler a partly-acquiring `ShowText` dispatcher reaches as
    covered, and deleting the real acquire from `showSessionsTop` or
    `GetSessions` left it green.
    Scope is `pkg/api` + `pkg/grpcapi`, the two packages where a new endpoint
    can appear and the ones `MaxConcurrentSessionWalks` documents itself as
    bounding. `pkg/cli` is deliberately outside: it has 18 scan sites and no
    acquires, and it runs IN-PROCESS in the daemon, but there is exactly one
    non-test `cli.New(...)` call site, it is inside `if isInteractive()`, and a
    REPL runs one command at a time — so the console contributes at most one
    concurrent walk rather than a flood, and the remote `cli` binary is bounded
    at the gRPC surface it connects through. The daemon-internal background
    walkers (`conntrack` GC sweep, cluster bulk/conn sweeps,
    `warmNeighborCache`, policy invalidation, `ReconcileClusterBulk`) are
    outside for a different reason: they are not request-driven, so a REQUEST
    admission budget is the wrong instrument. Both groups are named in the test
    file so a later reader knows they were considered; pulling either in scope
    would mean ~20 exemption entries, and a list like that drifts until the
    guard stops meaning anything.
    #6553 also single-sources the NAT pool port formula
    (`config.NATPoolTotalPorts`): `(portHigh - portLow + 1) * addrCount` had
    been written out five times and had already diverged — only this REST
    handler carried the `portHigh >= portLow` guard, so the gRPC handler, the
    Prometheus NAT collector and both CLI renders would compute a NEGATIVE
    capacity for a reversed window. (Reachability of a reversed window is not
    claimed: #5457's `parseSourcePoolPortRange` fails closed and strict commit
    rejects one; the tolerant load / peer-sync path is the residual. Four
    surfaces disagreeing about one formula is the defect being fixed.)
    **#5880 makes the shared limiter request-graph-aware to fix a reentrant
    double-acquire.** A REST list/summary/zone-pair handler acquires a slot and
    then delegates IN-PROCESS to the gRPC session service for `include_peer`
    fan-out; that service acquired the SAME limiter AGAIN, double-charging one
    logical operation and self-rejecting at capacity (`include_peer` failed under
    load). The fix is an unforgeable **in-process admission lease** carried on
    `context.Context` (`diagcmd.Limiter.AcquireCtx`, keyed by the private
    `leaseKey{*Limiter}` — never derivable from any external header): the FIRST
    handler to admit at the external trust boundary stamps the lease on the
    context it delegates on (REST re-stamps the request via `r.WithContext`), and
    the nested gRPC entry point REUSES that slot instead of re-acquiring. The
    lease is **per-request-graph, not global**: two DISTINCT external requests
    each acquire independently (the per-node bound is preserved), and the lease
    never crosses a process/network boundary, so a peer node's own gRPC entry
    acquires its own local slot (remote admission unchanged). Release stays
    idempotent + cancellation-safe (a real slot via `sync.Once`; the lease-reuse
    path is a no-op). Pinned by `TestAcquireCtx_5880` (mechanism),
    `TestGetSessions_InProcessLeaseReuse_5880` (gRPC reuse at cap 1), and
    `TestRESTIncludePeerReusesLease_5880` (REST include_peer succeeds at cap 1),
    each RED on revert.
    **#5968 removes the redundant local WALK on the same path.** #5880 fixed the
    double-ACQUIRE; the delegation still walked the local table TWICE. The REST
    handler builds its own local list/summary/breakdown and then called the
    in-process gRPC method purely for `.Peer`, discarding that method's own local
    result — a second full v4+v6 traversal per request, contending with the live
    session-sync path for the same per-bucket map locks. The three handlers now
    delegate to `PeerSessions` / `PeerSessionSummary` / `PeerZonePairSummary`,
    in-process-only methods on `ClusterSessionService` that fetch the peer view
    with NO local walk. They cost no protobuf or wire change (the REST bridge and
    the gRPC server are the same process), and they acquire through the SAME
    lease-aware `AcquireCtx` the full methods use — slot accounting is identical
    before and after, so the #5880 lease guarantee is preserved rather than
    quietly retired by a path that never acquires. Peer-status classification
    (#5320 OK / UNREACHABLE / NOT_APPLICABLE) is single-sourced in
    `attachPeerSessionSummary` / `attachPeerZonePairSummary`, shared with the
    full paths, because a divergence there would always be a bug. Pinned by
    `pkg/grpcapi/peer_only_5968_test.go`: a walk-counting dataplane proves ZERO
    local traversals, with `GetSessions` on the same server as the positive
    control so the assertion cannot be satisfied by a dataplane that never
    iterates.
    The rest of the redesign #5880/#5968 ask for — structural per-surface
    admission via a registration/source-level test, weighted cost for
    local+peer/cursor/clear, and a separate remote budget — is deferred to a
    follow-up.
    **#5779 extends the SAME shared bound to the session-CLEAR (mutation)
    path**, which was the remaining uncovered full-table walk: `ClearAllSessions`
    is a chunked full-table scan+delete (not O(1)), and the gRPC `ClearSessions`
    filtered path (`clearFilteredSessionsV4/V6`, cursor or rescan) walks the
    whole table too. The gRPC `ClearSessions` handler now acquires one shared
    slot covering both its clear-all and filtered branches (over-cap →
    `codes.ResourceExhausted`); this REST clear endpoint's local-only fallback
    (`s.dp.ClearAllSessions()`) acquires the same shared limiter (over-cap →
    HTTP 429). The HA-delegated REST clear path is gated by the gRPC handler it
    forwards to, so it is not double-charged. A keyed single-session delete (no
    walk) is a different operation and is not gated.

    **#9142: the delegated refusal answers 429 too.** Being gated by the gRPC
    handler is not the same as REPORTING what that handler decided. The
    delegated branch flattened every error from the in-process `*grpcapi.Server`
    to `writeError(w, http.StatusInternalServerError, err.Error())`, so the same
    saturation of the same process-wide `sessionWalkLimiter` answered **429 on a
    standalone node and 500 on a clustered one** — and since ordinary
    `GET /security/sessions` scrapes are what saturate that limiter, this is a
    routine condition, not an exotic one. A client keyed on the status class
    (back off on 429, page a human on 5xx) therefore behaved differently based
    only on whether the node it hit had an HA session service wired. The branch
    now switches on `status.Code`: `ResourceExhausted` → **429**, `Unavailable` →
    **503** (matching the handler's own dp-loaded guard, so the two routes to
    that condition cannot disagree), everything else → **500**. The body carries
    `status.Convert(err).Message()` rather than `err.Error()`, so the gRPC
    framing (`rpc error: code = ... desc = ...`) — an internal detail of a
    delegation the REST caller cannot see — stays out of the JSON payload;
    `Convert` yields `codes.Unknown` plus the error's own text for a non-status
    error, so the default arm loses nothing. This is the same distinction
    `peerFetchErrorStatus` (#7294/#8308) already draws on the neighbouring
    peer-fetch surfaces: an admission refusal is not a fault. Guards:
    `sessions_clear_delegated_status_9142_test.go`, including the cell that
    drives BOTH wirings against the same refusal in one run — the delegated
    branch previously had no cell at all (`TestRESTClearSessionsConcurrencyBound`
    pins only the `clusterSessionFn == nil` fallback, by its own comment).
  - **Bounded Total.** The offset mode's exact `total` previously forced a FULL
    v4+v6 table scan on EVERY 100-row page (O(table) per page, repeated per
    poll) just to count. The walk now caps the count at `sessionCountCap`
    (`defaultSessionCountCap` = 1,000,000) matching rows: `countCap` is
    `max(sessionCountCap, offset+limit)` so an explicitly requested deep window
    still fills to `limit`. UNDER the cap `total` is EXACT and the response is
    **byte-identical** to before (`total_approximate` is `omitempty`, so it is
    absent for normal-sized tables). PAST the cap the walk stops and `total`
    becomes a bounded LOWER BOUND with `total_approximate: true` — only the
    multi-million-session case degrades, and it degrades gracefully rather than
    re-walking the whole table per page. Cursor mode (`page_size>0`) is already
    bounded (it stops at `page_size` and reports no `total`) and is unchanged.
    A fuller keyset/cursor-default redesign of the offset contract is a possible
    follow-up; this fix is the minimal bounded one. Pinned by
    `sessions_pagination_bound_5318_test.go` (RED-on-revert: the bounded-walk and
    admission assertions both fail if either hardening is removed).
- Session clear (`POST /api/v1/security/sessions/clear`) clears ALL local
  sessions and accepts NO parameters: a non-empty query string
  (`r.URL.RawQuery`) or request body returns HTTP 400 rather than silently
  ignoring filter parameters and wiping the whole table (#3421 H6).
- HA fan-out on the clear (#3423 H5). In a chassis cluster the clear MUST also
  reach the peer: a local-only clear left the peer/synced sessions, which could
  reappear as active state on failover, with no indication to the operator that
  the clear was local-only. When the HA-aware session service is wired (the
  daemon's `ClusterSessionFn` → live gRPC server), the handler now delegates the
  clear-all to it, sharing the SAME service-layer path gRPC uses: local clear +
  peer propagation (`clearPeerSessions`, the `x-peer-forwarded` recursion guard)
  + partial-failure summary. The `ClearSessionsResult` carries `node_id` (which
  node served it) and `failures`/`failure_summary` — a non-zero `failures` with
  a `peer clear:` summary (now naming the PEER NODE, e.g. `dial peer node 1`,
  so it is operator-actionable) means the local clear succeeded but the peer's
  sessions were NOT cleared. **Partial-failure status:** when the local clear
  succeeds but the peer clear fails the endpoint still returns **HTTP 200** —
  the project uses no `207 Multi-Status` anywhere, so the failure is surfaced in
  the body, NOT the status line. **Clients MUST inspect `failures` /
  `failure_summary`; a status-only check will read a peer-clear failure as
  success.** A hard LOCAL clear failure still returns HTTP 500. A standalone
  node (no service wired) falls back to the local-only `ClearAllSessions` — the
  pre-#3423 behavior. Pinned by `sessions_ha_scope_3423_test.go`. The
  gRPC-parity FILTERED REST clear (clear a narrowed subset) remains a separate,
  unimplemented follow-up.
- `GET /api/v1/security/match` (`matchPoliciesHandler`) is a THIN adapter
  over the single shared policy simulator `pkg/policymatch` (#3042). It only
  validates/parses inputs (400 on a malformed IP/port) and renders the
  verdict; all matching logic lives in `policymatch.Match`, which replicates
  the runtime evaluator (`userspace-dp/src/policy.rs`): zone-pair → global →
  configured `default-policy` (NOT a hard-coded deny), predefined apps,
  multi-level application-sets, literal CIDRs, `any-ipv4`/`any-ipv6`,
  source/destination exclusion, and the live feed-prefix overlay
  (`FeedOverlayFn`). The pre-#3042 hand-written matcher scanned only
  zone-pair policies, hard-coded `deny (default)`, and missed predefined
  apps / literal CIDRs — so the diagnostic could report the OPPOSITE of what
  the dataplane enforces. #3104: the handler also threads live per-scheduler
  active-state (`PolicySchedulerActiveStateFn`, wired from the daemon-local
  `Manager.PolicySchedulerActiveState`) into `policymatch.Query.PolicyInactiveFn`,
  so a scheduler-inactive policy is SKIPPED exactly like the runtime
  (`policy.rs try_match_rule`) and the verdict falls through to the next active
  rule / default-policy. #3414: when live state is unavailable (no dataplane /
  early boot) the handler binds the predicate to a nil state map, which
  `PolicyInactiveFn` treats as fail-closed — scheduled policies are simulated
  as INACTIVE, matching the snapshot builder (nil scheduler state => dropped)
  rather than certifying an as-if-active verdict the dataplane is skipping. A
  non-scheduled policy is unaffected either way. On a MATCH the response
  carries the matched policy's runtime `policy_id` (#3331 scope/id
  disambiguation). #3623: this field is a `*uint32` — set (present, even at
  0) ONLY on a match, omitted otherwise. The first zone-pair set's first
  rule has runtime id 0; a plain `uint32`+`omitempty` dropped it, so a
  matched-first-policy answer was indistinguishable from an unmatched one
  (both encoded as absent). The gRPC `MatchPoliciesResponse.policy_id`
  mirror is `optional uint32` for the same reason. #3627 M06: the response
  ALSO echoes the queried zone pair on `queried_from_zone`/`queried_to_zone`
  on EVERY answer — positive match, no-match/default, and host-inbound — so a
  stored JSON diagnostic for a default-deny or host-inbound verdict proves
  which zone pair produced it without a separate copy of the request URL.
  These are the query context and are DISTINCT from `from_zone`/`to_zone`
  (the matched policy's declared SCOPE, #3331, set only on a positive match):
  for a wildcard-zone or global match the two can differ. The gRPC
  `MatchPoliciesResponse.queried_from_zone`/`queried_to_zone` (fields 13/14)
  mirror this. #3668: on a MATCH the response also carries
  `source_address_excluded`/`destination_address_excluded` and the stable
  `rule_id`. The exclusion flags report whether the matched policy carries Junos
  `source-address-excluded`/`destination-address-excluded` — the rule matches
  every address EXCEPT those in `src_addresses`/`dst_addresses`. The shared
  matcher already inverts the address test correctly; without the flags a
  positive verdict against a source OUTSIDE an excluded set printed the excluded
  list as if it were the reason for the match (backwards for an audit tool). The
  renderers annotate the exclusion as `Source addresses (except): ...`. `rule_id`
  is the stable `<from>-><to>/<name>` identity the inventory (`GetPolicies`), the
  snapshot, and the event path carry (`dpuserspace.StablePolicyRuleID`), so a
  simulator hit joins to the inventory row / logs / tests even after a policy
  reorder shifts the numeric `policy_id`; a matched global policy uses the
  `junos-global->junos-global/<name>` form, matching the inventory global rows.
  All three are additive and set only on a positive match. The gRPC
  `MatchPoliciesResponse.source_address_excluded`/`destination_address_excluded`
  (fields 15/16) and `rule_id` (field 17) mirror this. #3685 M05/M06: on a MATCH
  the response also carries the policy `description` and the scheduler binding.
  `description` (M05) is the matched policy's `description` text — the same field
  the inventory (`GetPolicies`) and the local `show security match-policies`
  result carry over the SAME `policymatch.Result`; descriptions often hold
  ticket / change-control context, so a match verdict without it was weaker than
  the inventory / CLI answer. `scheduler_name`/`scheduler_active` (M06) name the
  time-gate: `scheduler_name` is the policy's `scheduler-name` binding
  (mirroring the inventory `PolicyRule` field, #3624), and `scheduler_active` is
  the explicit effective-active flag. A positive match is by construction
  currently active — the handler always threads a fail-closed
  `PolicyInactiveFn` (#3414) that SKIPS a scheduler-inactive rule before it can
  match — so a matched scheduled policy always reports `scheduler_active=true`;
  it names the gate admitting the rule right now, not a rule that is gated off.
  All three are additive and set only on a positive match; both scheduler fields
  are omitted for a non-scheduled (always-on) policy. The gRPC
  `MatchPoliciesResponse.description` (field 18), `scheduler_name` (field 19),
  and `scheduler_active` (field 20) mirror these.
- #3627 B1a: a `to-zone junos-host` query also carries the structured
  `host_inbound` object — WHICH host-inbound-traffic system-service / protocol
  token admits the host-bound tuple, or that the box denies / globally accepts /
  cannot classify it. It is the REST projection of the shared
  `policymatch.Result.HostInbound` (`dataplane/userspace.HostInboundAdmission`),
  the SAME classifier the local CLI `show security match-policies` host-inbound
  line renders (the merged #4352) and the gRPC `host_inbound` message (field 21)
  carries, so the three surfaces cannot drift (#3375). Fields: `status`
  (`token-admit` / `global-accept` / `denied` / `indeterminate`), `token` and
  `kind` (`system-services` / `protocols`, set only for `token-admit`), and
  `description` (the one-line CLI explanation, so a JSON client renders the same
  sentence without re-deriving it). The classifier reads the same structured
  token->tuple SSOT the kernel-nft builder renders from
  (`config.HostInboundServiceMatch` / `HostInboundProtocolMatch`), so a reported
  token can never claim a port the box does not open. Present ONLY for a
  host-bound query — on both the `host_inbound_unmatched` verdict and a matched
  `to-zone junos-host` policy (the host-inbound gate is a separate admission
  stage); OMITTED for every transit / global / default / content-rejected
  verdict, which has no host-inbound gate. It is additional context and never
  changes `matched` / `host_inbound_unmatched`.
- The SSE handler reads from `pkg/logging.EventBuffer`. The buffer is
  bounded; if a consumer stops reading, events are dropped silently — by
  design.
- `CompileHealthFn` may be `nil` when the daemon is in `-no-dataplane`
  mode. All readyz code paths null-check it.
- Request-path external commands must be time-bounded (#1805): the
  deferred reboot/halt power actions go through `runTimeout` in
  `exec_timeout.go` (15s timeout + 5s WaitDelay, mirroring the
  apply-path contract in `pkg/daemon/exec_timeout.go`, #1794 — not
  importable here because pkg/daemon imports this package; the
  Output/CombinedOutput variants live in the pkg/grpcapi sibling copy).
  Power actions take `context.Background()` — client disconnect must
  not cancel a confirmed reboot — and keep ignoring errors. The
  `POST /api/v1/system/action` handler (`systemActionHandler`) journals
  reboot/halt to the configstore audit journal (`s.logSystemAction` →
  `Store.LogSystemAction`) BEFORE scheduling the power action, mirroring
  the gRPC `SystemAction` handler (#4108 F8 / #4484 L-1) — the REST path
  previously left NO durable attributable trail. The power action itself is
  invoked through the `apiSchedulePowerAction` package-var seam so a test can
  assert the journal wiring without taking the host down. The handler also
  serves the non-destructive `clear-config-lock` verb (parity with gRPC):
  it force-exits a wedged candidate-config lock (`Store.ForceExitConfigure`)
  so an operator can self-recover from an H-3/#4476 lock wedge over REST. The
  ping/traceroute handlers keep their own request-ctx bounds but set
  `WaitDelay` so an inherited pipe cannot block past the kill; their
  budgets are request-sized (#1819) via `pingExecTimeout` (count × 1s +
  15s slack, 30s floor) and `diagTracerouteTimeout` (60s), capped at the
  150s `diagExecCeiling` and mirrored in `pkg/grpcapi/exec_timeout.go`.
  The argv builders (`buildPingArgv`/`buildTracerouteArgv`) place the
  user-supplied target after a `--` end-of-options separator so a
  `-`-prefixed target is an operand, not a flag (option-confusion
  hardening, #2084).
  Do not add raw `exec.Command` calls in handlers: a wedged binary pins
  the handler goroutine and its HTTP connection.
  A per-job deadline is necessary but NOT sufficient: without an
  aggregate bound a request flood holds hundreds of processes/FDs/
  goroutines at once and starves the control plane. So each handler first
  takes a slot from the process-wide `diagcmd.DefaultLimiter`
  (`MaxConcurrentDiagnostics = 4`) via the `diagLimiter` package var —
  SHARED with the gRPC Ping/Traceroute RPCs, so one aggregate cap covers
  BOTH surfaces (a diagnostic admitted over REST and one over gRPC draw
  from the same budget, #5057). Acquire is fail-fast: when the cap is
  reached the handler returns **HTTP 429** immediately (no queue, no
  wait) rather than piling up work, and the slot is released via `defer`
  on every path (success, exec error, ctx timeout/cancel, panic). The
  child is spawned through the `diagRun` package-var seam so a test can
  inject a fake slow diagnostic and assert the cap without real
  subprocesses.
