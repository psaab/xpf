# Junos CLI Output Format Reference

Captured from vSRX 24.4R1-S2.9 chassis cluster (node0: vsrx-ernie, node1: vsrx-bert) at 172.16.100.1.
User: claude (read-only, no config/log permission).

This document preserves exact spacing, column widths, headers, and separators for replicating
Junos output formatting in xpf.

---

## Table of Contents

1. [Cluster Header Format](#cluster-header-format)
2. [Security: Flow Sessions](#security-flow-sessions)
3. [Security: Flow Session Summary](#security-flow-session-summary)
4. [Security: Flow Statistics](#security-flow-statistics)
5. [Security: Policies](#security-policies)
6. [Security: Policies Detail](#security-policies-detail)
7. [Security: Policies Hit-Count](#security-policies-hit-count)
8. [Security: Global Policies](#security-global-policies)
9. [Security: Zones](#security-zones)
10. [Security: NAT Source Rule All](#security-nat-source-rule-all)
11. [Security: NAT Destination Rule All](#security-nat-destination-rule-all)
12. [Security: NAT Source Summary](#security-nat-source-summary)
13. [Security: Screen IDS](#security-screen-ids)
14. [Security: ALG Status](#security-alg-status)
15. [Security: IPsec SAs](#security-ipsec-security-associations)
16. [Security: IPsec SAs Detail](#security-ipsec-security-associations-detail)
17. [Security: IKE SAs](#security-ike-security-associations)
18. [Security: Log](#security-log)
19. [Firewall: Filters (raw and effective)](#firewall-filters-raw-and-effective)
20. [Interfaces: Terse](#interfaces-terse)
21. [Interfaces: Detail](#interfaces-detail)
22. [Interfaces: Extensive](#interfaces-extensive)
23. [System: Uptime](#system-uptime)
24. [System: Memory](#system-memory)
25. [System: Processes Summary](#system-processes-summary)
26. [System: Version](#system-version)
27. [Chassis Cluster: Status](#chassis-cluster-status)
28. [Chassis Cluster: Interfaces](#chassis-cluster-interfaces)
29. [Routing: Route Table (Brief)](#routing-route-table-brief)
30. [Routing: Route Destination Lookup](#routing-route-destination-lookup)
31. [Routing: Route Summary](#routing-route-summary)
32. [Routing: BGP Summary](#routing-bgp-summary)
33. [Routing: ARP](#routing-arp)
34. [Pipe Filters](#pipe-filters)
35. [Configuration Display](#configuration-display)

---

## Cluster Header Format

Every show command on a cluster prefixes output with per-node headers:

```
node0:
--------------------------------------------------------------------------
<output for node0>

node1:
--------------------------------------------------------------------------
<output for node1>
```

- The separator line is exactly 74 dashes.
- Blank line before each `nodeN:` header (except first).
- Active node shows full output; standby may show less data.

---

## Security: Flow Sessions

**Command:** `show security flow session`

Filters: `protocol tcp|udp|icmp`, `source-prefix X.X.X.X/N`, `destination-prefix X.X.X.X/N`,
`destination-port NNN`, `application-firewall`, etc.

**Strict filter validation (#3439).** Both CLI surfaces and the direct
gRPC `GetSessions` RPC reject malformed filters rather than silently
dropping the predicate (which would widen the inspected set):

- The remote `cli` parser (`parseFlowSessionArgs`, `cmd/cli/show.go`)
  mirrors the strict local parser (`pkg/cli/session_filter.go`): an
  unparseable numeric value (`destination-port abc`), an out-of-range
  port, a non-numeric `zone`/`limit`, an unknown protocol token
  (`protocol tcpip`), a missing value, or an unknown filter keyword all
  fail the command instead of leaving the field at its zero (wildcard)
  default. Previously these were silently ignored, so a typo widened the
  query and the two CLI surfaces disagreed on identical command shapes.
- `summary` and `sort-by` are global aggregations on the remote surface
  (the `GetSessionSummary` RPC takes no filter; the top-talkers path
  walks the whole table). Combining them with a traffic filter
  (`protocol`, `zone`, ports, prefixes, `nat`, `application`,
  `interface`, `source-nat-pool`) is **rejected** rather than silently
  dropping the filter. Use the filtered per-session listing for a
  narrowed view, or the interactive local CLI (which applies filters to
  its summary/top-talkers). `brief` is a display modifier, not a filter,
  so it may accompany `summary`.
- **Clear takes selectors only, never display modifiers (#5066).** The
  presentation tokens `summary`, `brief`, and `sort-by` are meaningful
  only for `show security flow session` — they change how sessions are
  rendered, not which sessions are selected. On `clear security flow
  session` they are **rejected** with an error. This is a fail-closed
  invariant: `clear` interprets an EXACTLY-empty selector as clear-all, so
  a token that parses but selects nothing (as these did before #5066 — the
  shared parser accepted them but `hasFilter()` excluded all three) must
  never be silently swallowed, or a pasted show-syntax modifier would wipe
  the entire session table on both HA nodes. The remote `cli` clear parser
  (`cmd/cli/clear.go`) already rejected them; the local interactive CLI
  now matches (`parseClearSessionFilter`, `pkg/cli/session_filter.go`).
- **`clear security policies hit-count` is global-only and rejects
  trailing selectors (#5570).** The backend `clear-policy-counters`
  action carries no zone or policy selector, so the command resets
  EVERY policy hit counter. The remote `cli` parser
  (`cmd/cli/clear.go`) requires EXACT arity: `clear security policies
  hit-count` with no trailing token clears all; any trailing token
  (e.g. `... from-zone trust`, `... policy <name>`) is **rejected**
  with an error and issues no clear. This is the same fail-closed
  invariant as `clear security flow session` — an operator who types a
  scope believing the clear is scoped must get an error, never a silent
  global wipe that destroys policy evidence. Per-scope hit-count
  clearing is not a supported feature; adding it would require a typed
  RPC with explicit selectors.
- Direct gRPC `GetSessions` (`pkg/grpcapi/server_sessions.go`) validates
  the `protocol` token and rejects a negative `offset` (centrally in
  `GetSessions`, covering both the cursor and legacy paths); both return
  `codes.InvalidArgument` so an invalid input is distinguishable from an
  empty result set. Protocol-name filters with no `protoName()` reverse
  (e.g. `sctp`, `ospf`) match their sessions correctly. The protocol
  token is resolved via `appid.ProtocolNumberLenient`, which also accepts
  a display-only name the strict `appid.ProtocolNumber` does not reverse
  — notably `ipv6` (IP protocol 41), the one-way mapping of #3393 — so a
  protocol the system still **displays** is never rejected as an invalid
  filter. The strict `appid.ProtocolNumber` SSOT used by config
  compilation / policy matching is unchanged (Refs #3393).

```
Session ID: 17179902569, Policy name: allow-everything-out-not-logged/270, HA State: Active, Timeout: 18, Session State: Valid
  In: 192.168.99.201/18277 --> 76.214.233.95/722;icmp, Conn Tag: 0x0, If: reth1.1000, Pkts: 1, Bytes: 84,
  Out: 76.214.233.95/722 --> 50.220.171.30/11623;icmp, Conn Tag: 0x0, If: reth0.0, Pkts: 0, Bytes: 0,
```

### Format Details

- **Session header line:** Comma-separated key-value pairs, no fixed column widths.
  - `Session ID: <u64>`
  - `Policy name: <name>/<index>` (policy name slash policy index number)
  - `HA State: Active|Backup`
  - `Timeout: <seconds>`
  - `Session State: Valid|Invalid`
- **Two policy indexes are RESERVED and do not name a configured policy**
  (#4626). The index is always printed, so nothing is hidden:
  - `unattributed/0` — no configured policy admitted this session.
    Index `0` is carried by host-inbound, neighbor-seed, fabric and tunnel
    installs, by any pre-#3056 session, and by every session synced from an
    older HA peer during a rolling upgrade. It is ALSO the index of the
    literal first configured policy, so the value is genuinely ambiguous on
    the wire; the display deliberately under-claims rather than naming a
    real rule that may never have seen the traffic. Retiring the overload
    (reserving the id space so real policies start at 1) is the remaining
    half of #4626.
  - `default-policy/4294967295` — the implicit `security policies
    default-policy` verdict admitted or denied this session, not a
    configured rule (#3057).
  The same two reserved indexes appear as `policy_name` on the REST
  `/sessions` and gRPC `GetSessions` surfaces, which carry `policy_id`
  alongside, and in the `policy-name` field of RT_FLOW syslog records
  (#6851) — the one surface where the attribution is DURABLE, since those
  records ship off-box to a collector.
- **Cluster peer sessions carry the same guarantee** (#6851), on every
  surface that shows them: the gRPC and REST fan-outs sanitize in
  `grpcapi fetchPeerSessions`, and the on-box interactive CLI — which dials
  the peer daemon directly rather than going through that fan-out — does so
  at its own ingress. The peer resolved those names itself; a peer on a
  pre-#4626 build sent the name of ITS first configured policy for every
  reserved-index session. The local node overrides the name for RESERVED
  indexes only. It deliberately
  does NOT re-resolve an unreserved index against its own policy table:
  indexes are node-local, so the peer is authoritative for the names of
  its own sessions, and re-resolving would name whichever local policy
  happened to occupy that slot.
- **In/Out lines:** Indented 2 spaces.
  - `In: <src_ip>/<src_port> --> <dst_ip>/<dst_port>;<proto>, Conn Tag: 0x0, If: <interface>, Pkts: <N>, Bytes: <N>, `
  - Note the trailing comma+space after Bytes value.
  - Protocol is appended after dst_port with semicolon separator: `443;tcp`, `722;icmp`
  - For ICMP: port field is the ICMP ID.
  - `Conn Tag: 0x0` always present.
- **TCP sessions** show src/dst port normally: `52207 --> 192.73.252.65/443;tcp`
- **ICMP sessions** show ICMP ID as port: `18277 --> 76.214.233.95/722;icmp`
- **Session trailer:** `Total sessions: <N>` at the end of each node's output.
- Blank line between sessions.
- **NAT visible in Out line**: translated addresses appear in Out (SNAT changes src in Out, DNAT changes dst in In pre-NAT vs Out post-NAT).

### TCP Session with NAT Example

```
Session ID: 249108372496, Policy name: allow-everything-out-not-logged/240, HA State: Backup, Timeout: 7022, Session State: Valid
  In: 172.16.100.201/52207 --> 192.73.252.65/443;tcp, Conn Tag: 0x0, If: reth1.100, Pkts: 0, Bytes: 0,
  Out: 192.73.252.65/443 --> 50.220.171.30/2772;tcp, Conn Tag: 0x0, If: reth0.0, Pkts: 0, Bytes: 0,
```

Note: On backup node, Pkts/Bytes are 0 (no traffic flowing through it).

### Brief Format

**Command:** `show security flow session brief`

On vSRX 24.4, `brief` produces the **same format** as the regular session output (no tabular view).
This differs from SRX hardware platforms where `brief` may produce a condensed tabular format.
xpf currently implements a tabular brief view which is a useful enhancement over vSRX behavior.

---

## Security: Flow Session Summary

**Command:** `show security flow session summary`

```
Unicast-sessions: 3231
Multicast-sessions: 0
Services-offload-sessions: 0
Failed-sessions: 0
Sessions-in-drop-flow: 0
Sessions-in-use: 3680
  Valid sessions: 3230
  Pending sessions: 0
  Invalidated sessions: 450
  Sessions in other states: 0
Maximum-sessions: 4194304
```

### Format Details

- Key-value with colon separator, value right after colon+space.
- Sub-items indented 2 spaces (Valid/Pending/Invalidated/Other).
- `Maximum-sessions: 4194304` (4M max on vSRX).

### xpf implementation notes (#5323 / #5320)

- **`Maximum-sessions` is DYNAMIC, not a fixed literal.** xpf renders the
  live AF_XDP helper's `max_sessions` (worker_count x per-worker capacity,
  131072/worker) taken from the userspace `ProcessStatus`. It replaces the
  historical hardcoded `10000000` on both the remote CLI
  (`cmd/cli/show_flow.go`, from `GetSessionSummaryResponse.max_sessions`) and
  the local CLI (`pkg/cli/cli_show_flow.go`, from `userspaceDataplaneStatus()`).
  When no dataplane status is available the value renders `unknown` rather than
  a fabricated authoritative bound.
- **Multicast/Failed/Services-offload counters stay `0`.** The AF_XDP helper
  publishes no multicast/failed-session counters, so those Junos rows are
  reported as `0` for format parity (documented follow-up, not authoritative).
- **HA completeness (`include_peer`).** `GetSessionSummary` /
  `GetZonePairSummary` and the REST `/api/v1/security/sessions/summary`
  [`/zone-pairs`] endpoints now carry a machine-readable peer-fetch status
  (`peer_status` = `ok` | `unreachable` | `not-applicable`, plus `peer_error`).
  A cluster peer that is requested but unreachable is reported as `unreachable`
  (the totals are LOCAL-ONLY) instead of being swallowed and returned as a
  healthy-looking standalone view; the remote CLI prints a
  `warning: cluster peer unreachable; counts above are LOCAL-ONLY` line.

---

## Security: Flow Statistics

**Command:** `show security flow statistics`

```
    Current sessions: 5545
    Packets received: 53426518218
    Packets transmitted: 53091802103
    Packets forwarded/queued: 40436060
    Packets copied: 1208046
    Packets dropped: 293072009
    Services-offload packets processed: 0
    Fragment packets: 21545
    Pre fragments generated: 0
    Post fragments generated: 0
```

### Format Details

- Every line indented 4 spaces.
- Key-value with colon separator.
- All numbers right-aligned (no fixed width, just the number).
- **`Packets dropped` = ENFORCEMENT drops only (#4508).** This figure sums
  policy denies, screen/IDS drops, host-inbound denies, and source-NAT
  allocation failures — it is NOT the literal total of every discarded
  packet. No-route / missing-neighbor drops (helper status `Route misses:`),
  fabric-forwarding drops, VLAN-push failures, and NAT64 fail-closed drops
  are counted separately and are excluded here, so `Packets dropped`
  undercounts total discards. See the `Packets dropped` scope caveat
  (#4477/#4508) in the counter-accounting notes further below for the full
  breakdown of excluded paths and their counter indices.

---

## Security: Policies

**Command:** `show security policies`

```
Default policy: deny-all
Default policy log Profile ID: 0
Pre ID default policy: permit-all
Default HTTP Mux policy: permit-all
From zone: trust, To zone: trust
  Policy: default-permit, State: enabled, Index: 4, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: any
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: permit
  Policy: default-deny, State: enabled, Index: 5, Scope Policy: 0, Sequence number: 2, Log Profile ID: 0
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: any
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: reject, log
From zone: guest, To zone: lan
  Policy: allow-airgroup, State: enabled, Index: 8, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: airgroup-devices
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: permit, log
```

### Format Details

- **Zone header:** `From zone: <name>, To zone: <name>` (no indentation).
- **Policy line:** 2-space indent, comma-separated: `Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>, Log Profile ID: 0`
  - **Index (#3063):** the `Index:` value is the runtime/RT_FLOW policy
    ID — the same numeric ID printed by RT_FLOW policy-deny logs and the
    session surfaces — so an operator can cross-reference a log line to
    the exact detail row. It is span-accumulated: a policy whose match
    references an application-set that expands to multiple application
    terms advances the next policy's Index by the expansion count, not by
    one. So the Index of a policy that follows a multi-application policy
    is NOT its 1-based position. The global-policy block starts at a fresh
    policy-set base (`len(zone-pair sets) * 256`). Configs with no
    multi-application policy keep Index == the previous per-policy ordinal
    (byte-identical to pre-#3063). The `Sequence number:` field remains
    the 1-based per-set position. This Index is a display identity only;
    per-policy hit counters are name-keyed internally and unaffected.
  - **Scheduler state (#3062):** the `State:` field reflects runtime
    scheduler state, not just configuration. A policy bound to a
    scheduler (`scheduler-name <name>`) that is currently inactive renders
    `State: inactive` — the dataplane is dropping that rule for the
    duration of the off-window. Active and non-scheduled policies render
    `State: enabled` (bit-identical to pre-#3062 output). The state is
    read from the daemon-maintained per-scheduler active-state map (the
    same map that drives enforcement), not recomputed against the wall
    clock. When the dataplane cannot report scheduler state (offline CLI),
    every policy renders `enabled`.
- **Policy fields:** 4-space indent, `<Key>: <value>`.
- **Action line:** `Action: permit` or `Action: reject, log` or `Action: deny, log`.
- Multiple addresses shown as named address entries.
- **`junos-host` self-traffic policy (#3019):** a `from-zone <z> to-zone
  junos-host` policy is the Junos self-traffic (host-bound) security policy.
  As of #3019 these policies are ENFORCED on the dataplane LocalDelivery path
  (host-bound traffic destined to a firewall-local interface IP), not merely
  accepted at commit. Ordering follows Junos: **host-inbound-traffic admission
  (`set security zones security-zone <z> host-inbound-traffic ...`, #3070)
  runs FIRST**, then the `to-zone junos-host` security policy. A packet that
  host-inbound already rejected never reaches policy, so a `to-zone junos-host
  then permit` cannot re-admit a service host-inbound denies. A matching
  `then deny`/`then reject` drops the host-bound packet (emitting the same
  policy-deny RT_FLOW + `reject`/zone-`tcp-rst` reply as a transit deny) and
  tears down any cached host-local session on the next hit. Hit counters for
  these rules now advance.
  - **Reject-event truthfulness (#3615):** the policy/filter-log RT_FLOW
    record reports `action reject` ONLY when the RST/ICMP-unreachable reply was
    actually enqueued. If the generated reply fail-closes after the action is
    decided (TX-frame budget exhausted, reject rate-limit bucket empty, an
    unparseable built frame, or an egress output-filter that discards the
    reflected reply), the packet is a silent drop and the event reports the
    truthful `action deny` — the forensic log never claims an active reject
    that was not sent. Reply-free deny paths (non-first fragments with no L4
    header, the forward/output-filter path that has no reply synthesis pending
    #3608) log `deny` for the same reason. Both SUCCESS and SUPPRESSION are
    counted per source in `show ... status` (#3657), each split
    `policy_reject`/`filter_reject` so a security-policy `then reject` is
    never conflated with a firewall-filter `then reject`:

    - `Generated-reply sent` — replies actually enqueued (active reject
      volume; a zone `tcp-rst` counts under `policy_reject`).
    - `Generated-reply budget drops` — replies suppressed because the
      per-tick TX-frame budget was exhausted.
    - `Generated-reply drops` — replies dropped by an egress output firewall
      filter applied to the reflected reply's own tuple (`policy_reject` /
      `filter_reject` legs, alongside `time_exceeded` / `syn_cookie` / `ptb`
      / `classify_parse_errors`).
    - `Generated-reply rate-limited` (#3661) — replies suppressed because the
      shared per-reason rate-limit token bucket was empty, split
      `policy_reject`/`filter_reject`. Distinct from a TX-frame budget drop
      and an egress output-filter drop; the split tells policy-reject
      starvation from filter-reject starvation under a rejected-flow flood.

    The global reject rate-limit bucket itself is a single global-per-reason
    token bucket; its source-NEUTRAL aggregate is `reject_rate_limited_total`
    (Prometheus `xpf_userspace_reject_rate_limited_total`), kept for
    back-compat. #3661 attributes each drop to the reply's source at the
    consume site, so `policy_reject`+`filter_reject` sum to the aggregate.
    The source-split legs are exported to Prometheus as
    `xpf_userspace_reject_sent_total`,
    `xpf_userspace_reject_reply_budget_drops_total`,
    `xpf_userspace_reject_output_filter_drops_total`, and
    `xpf_userspace_reject_rate_limited_by_source_total`, each labeled
    `source="policy"|"filter"`.
  - **Default-deny posture (#3405):** EVERY configured security zone denies
    host-bound traffic by default (Junos/vSRX parity). A zone with interfaces
    but NO `host-inbound-traffic` stanza is treated exactly like an empty
    `host-inbound-traffic { }` stanza — it admits nothing, so SSH / HTTP / SNMP
    / routing protocols to a firewall-local interface IP in that zone are
    DROPPED unless the operator adds the matching `system-services` /
    `protocols` token. Before #3405 a no-stanza zone admitted ALL host-bound
    traffic (`None => true` on the Rust path; no kernel rule), a permit-all
    management-plane exposure on any zone the operator never locked down. Both
    enforcement surfaces flip together: the kernel-nft chain scopes a catch-all
    DROP to the zone's addresses, and the Rust AF_XDP classifier inserts the
    zone with an empty admission set. The lifeline interfaces (fxp0 / em0 /
    fab*) are excluded from the deny address sets and the global ICMP / IPv6 ND
    / PMTUD / established-session accepts precede every deny, so the default-deny
    cannot strand management or break HA. (All shipped reference configs already
    declare a `host-inbound-traffic` stanza per zone, so they are unaffected.)
  - **Lifeline-exemption visibility (#3682):** the lifeline exclusion above is
    an IMPLICIT policy exception — a zone-assigned interface whose base name is a
    lifeline (`fxp0` / `em0` / `fab<N>`, plus a configured chassis-cluster
    `control-interface` / `fabric-interface` / secondary fabric) is EXCLUDED from
    that zone's host-inbound deny scoping and always admits host-bound traffic
    regardless of the zone's admission set. Before #3682 no rendered zone view
    told the operator this, so such an interface silently dropped out of the
    default-deny. Every host-inbound surface now surfaces it: `show security
    zones` (local, gRPC-text, remote CLI) prints a `Host-inbound lifeline-exempt
    interfaces (management/fabric, bypass host-inbound deny): <ifaces>` line;
    `show interfaces` and `test security-zone interface` print `Host-inbound:
    lifeline-exempt (management/fabric, bypasses host-inbound deny)` in place of
    the (misleading) default-deny line; and the structured `GetZones` gRPC adds a
    `lifeline_interfaces` field. The matcher SSOT is `config.HostInboundLifeline*`
    (`pkg/config/lifeline.go`), shared by the dataplane deny-scoping path and the
    display presenter so enforcement and audit can never drift. This is a
    VISIBILITY change only — the exemption semantics are unchanged. (Design
    follow-up, RESOLVED in #5250: the fabric half of that match is now EXACT —
    `fab` followed by digits only (`fab0`, `fab1`, `fab10`), the names the daemon
    itself creates. An interface literally named `fab-foo` / `fabric-uplink` /
    `fabx0` no longer gains a silent host-inbound bypass; a fabric or control
    link with such a name still reaches the lifeline set from the
    chassis-cluster stanza, so nothing configured is stranded. `em0` was already
    an exact match. A standalone config that merely names an interface `em0`
    with no configured cluster role is still exempted — that is the retained
    backward-compatible default.)
  - **Host-inbound deny accounting (#3326):** a host-bound packet dropped by
    the `host-inbound-traffic` admission gate (a service/protocol not in the
    ingress zone's set) now increments the host-inbound deny counter, surfaced
    as `Host-inbound denies` in `show security flow statistics`,
    `host_inbound_denies` in the REST stats, and
    `xpf_host_inbound_denies_total` in Prometheus
    (`dataplane.GlobalCtrHostInboundDeny`). Before #3326 the AF_XDP userspace
    dataplane silently dropped these denies and bumped only an internal debug
    counter, so the exported counter sat at 0 even while host-inbound
    enforcement was dropping traffic — control-plane-protection verification,
    alerting, and post-incident forensics were blind. The Rust helper counts
    each host-inbound deny per worker (`host_inbound_denied_packets`) and the Go
    manager mirrors the per-poll delta into the global counter, identical to the
    policy-deny plumbing.
  - **Service-port matrix (#3619):** the authoritative operator-facing mapping
    of every `host-inbound-traffic` `system-services` / `protocols` token to the
    exact ports it opens across all three enforcement surfaces (Go SSOT
    allowlist, nft kernel mirror, Rust AF_XDP classifier) — including the
    deliberate narrowings (sip UDP+TCP 5060 only / no SIP-TLS 5061, tftp UDP 69
    only, traceroute UDP-only, router-discovery v6 global, ipsec=ike alias) and
    the ident-reset reject-vs-drop divergence — is
    `docs/host-inbound-service-matrix.md`.
  - **Per-screen-reason drop accounting (#3343):** the per-reason screen/IDS
    drop counters (`syn-flood`, `icmp-flood`, `udp-flood`, `port-scan`,
    `ip-sweep`, `land-attack`, `ping-of-death`, `teardrop`, `tcp-syn-fin`,
    `tcp-no-flag`, `tcp-fin-no-ack`, `winnuke`, `ip-source-route`, `syn-frag`,
    `session-limit`) now carry live values. Before #3343 the AF_XDP userspace
    counter bridge published only the aggregate `screen_drops`, so every
    per-reason breakdown read a permanent 0: the aggregate climbed during an
    attack while `show security screen`, `show security flow statistics detail`,
    the IDS alarms in `show security alarms` (which could read "No security
    alarms currently active" mid-attack), the gRPC `GetGlobalStats`
    `screen_drop_details`, and the REST/Prometheus surfaces all showed zero per
    reason. The Rust helper now counts each drop per reason
    (`BindingStatus.screen_reason_drops`, indexed by
    `screen::screen_reason_drop_index`); the Go manager sums them across
    bindings and pushes each ordinal's per-poll delta into its
    `dataplane.GlobalCtrScreen*` counter, mirroring the host-inbound / NAT64
    plumbing. The shared `dataplane.ScreenReasonCounters` table is the single
    source of truth for the reason ordinal→counter mapping AND the display
    rows, so port-scan / ip-sweep / session-limit (previously omitted from
    several hardcoded lists) now appear consistently across every surface. A new
    labeled Prometheus series `xpf_screen_drops_by_reason_total{reason=...}`
    exposes the breakdown for alerting; the aggregate `xpf_screen_drops_total`
    is unchanged.
  - **Packets-dropped / NAT-allocation-failure accounting (#4477):** the
    `Packets dropped` (`dataplane.GlobalCtrDrops`) and `NAT allocation failures`
    (`dataplane.GlobalCtrNATAllocFail`) rows of `show security flow statistics`
    were dead counters — the userspace counter bridge never wrote either index,
    so `ReadGlobalCounter` returned a clean `(0, nil)` (the #3345
    `ErrCounterNotPopulated` disclosure never fired) and the CLI, gRPC, REST
    (`drops` / `nat_alloc_fails`), and Prometheus (`xpf_drops_total` /
    `xpf_nat_alloc_fails_total`) surfaces printed a false, always-0 value even
    while the firewall was actively dropping traffic under attack. The Rust
    helper now counts each source-NAT allocation failure per worker at the single
    `record_source_nat_failure` chokepoint (`BindingStatus.nat_alloc_fail` — a
    rule matched but no translated mapping could be allocated: missing/empty/
    invalid/exhausted pool, wrong family, or a non-first fragment on a
    port-translating rule; the packet is dropped). The Go manager sums it across
    bindings and pushes the per-poll delta into `GlobalCtrNATAllocFail`, and
    folds it — together with policy denies, screen/IDS drops, and host-inbound
    denies — into the aggregate `Packets dropped` figure pushed into
    `GlobalCtrDrops` (a total whose breakdown is exactly the four rows rendered
    beneath it), mirroring the host-inbound / NAT64 / per-screen-reason plumbing.
    Once bridged the counters carry real values, so the #3345 disclosure
    correctly stays silent for them.
  - **`Packets dropped` scope — ENFORCEMENT drops only (#4508):** the
    `Packets dropped` counter is the sum of the four ENFORCEMENT/discard
    reasons above (policy deny + screen/IDS + host-inbound deny + source-NAT
    allocation failure). It is deliberately **not** the literal total of every
    packet the dataplane discards. Other real drop paths are counted
    elsewhere or not folded into this figure, so `Packets dropped`
    **undercounts** total discards. Excluded paths and where to read them:
    - **No-route** (userspace has no route to the destination) and
      **missing-neighbor** (route resolved but ARP/ND unresolved) drops are
      counted per binding as `route_miss_packets` / `neighbor_miss_packets`
      and surfaced separately as the `Route misses:` line in the userspace
      helper status (`pkg/dataplane/userspace/format/status.go`) — never in
      `Packets dropped`.
      - **Martian drops** (#4743): a no-route drop whose destination is a
        martian address (IPv4 multicast/broadcast/unspecified/loopback, IPv6
        multicast/unspecified/loopback) is ALSO counted distinctly as
        `martian_dropped` and shown as the `Martian drops:` status line. It is a
        strict sub-breakout of `route_miss_packets` (a martian dst misses the
        FIB and drops as no-route, so it bumps both), letting an operator tell a
        martian-dst drop apart from an ordinary route miss and correlate it with
        the firewall-filter `accept` log.
    - **IPv6 extension-header fail-closed drops** (#4743): an IPv6 packet whose
      extension-header chain is still on an extension header after
      `MAX_IPV6_EXT_HEADERS` (8) iterations (an over-limit, uninspectable chain)
      is dropped fail-closed and counted as `ipv6_ext_header_dropped`, shown as
      the `IPv6 ext-header drops:` status line. Before #4743 such a packet was
      forwarded flowless (`l4_present = false`), an ext-header IDS-evasion; it is
      distinct from a TRUNCATED chain (which stays flowless). Not in `Packets
      dropped`.
      - **Prometheus (#4768):** both counters are also exposed as aggregate
        scrape series — `xpf_userspace_martian_dropped_total` and
        `xpf_userspace_ipv6_ext_header_dropped_total` — summed across bindings
        and emitted unconditionally (0 is a real "no such drops" signal), so an
        operator can alert on them without polling the status text.
    - **Fabric-forwarding drops** (`GlobalCtrFabricFwdDrop`, index 32) — a
      peer-owned synced session whose fabric redirect could not be completed.
    - **VLAN-push failures** (`GlobalCtrVlanPushFail`, index 40).
    - **NAT64 fail-closed drops** — the NAT64 translator dropping a packet it
      cannot safely translate (distinct from the source-NAT allocation
      failure that IS in the total).
    This is the vSRX `show security flow statistics` field name, so the label
    is kept verbatim for Junos parity; the caveat lives here rather than in a
    relabel. The Prometheus mirror `xpf_drops_total` carries the same scope in
    its help text (`enforcement drops … does NOT include no-route`).
  - **Token validation (#3200):** `host-inbound-traffic system-services
    <tok>` / `protocols <tok>` is now validated at commit against the
    recognized-token SSOT (`pkg/config/host_inbound_tokens.go`:
    `KnownHostInboundSystemServices` / `KnownHostInboundProtocols`). An
    unknown/typo token (e.g. `system-services sssh`) is HARD-REJECTED at
    `commit` / `commit check` with a clear error. Before #3200 such a typo
    committed silently and the two enforcement layers then disagreed — the
    nftables kernel mirror emitted no match (and, for an all-unknown stanza,
    failed OPEN) while the Rust AF_XDP classifier ignored the token and denied
    everything else (failed CLOSED) — a split-brain posture from one typo. The
    SSOT is the same set the nft builder (`pkg/daemon` host-inbound matchers)
    and the Rust classifier (`classify_system_service`/`classify_protocol`)
    recognize, so the runtime only ever sees a token both layers agree on; a
    Go parity test (`TestHostInboundNftMatchesKnownTokens`) keeps the nft
    matcher domain equal to the SSOT, and a second Go parity test
    (`TestHostInboundRustClassifierMatchesGoSSOT`, #3486) parses the Rust
    classifier source and asserts its `classify_system_service` /
    `classify_protocol` arms + `KNOWN_ROUTING_PROTOCOL_TOKENS` /
    `HOST_INBOUND_L2_PROTOCOLS` token sets EXACTLY equal the Go SSOT — so a
    token added to one side only turns the build RED instead of silently
    diverging the dataplane allowlist. The tolerant load / peer-sync paths
    downgrade the rejection to a warning so an already-persisted or peer-synced
    config still boots (#1960 no-brick), and a zone whose stanza yields zero
    recognized matches (an empty `host-inbound-traffic { }`) now emits a
    catch-all kernel drop — fail CLOSED, matching the Rust classifier — instead
    of the pre-#3200 fail-open. Matching is case-sensitive against the
    canonical lowercase spellings (the nft matcher switch is case-sensitive, so
    accepting `SSH` would itself reintroduce a split-brain). Recognized tokens
    (`ssh`, `ping`, `all`, `any-service`, `ipsec`/`ike`, `protocols all`
    routing-scoped per #3199, …) are unaffected.
  - **`system-services all` is the named-service union (#3226):** `all` follows
    the Junos definition — "traffic from the defined system services available
    on the Routing Engine" — and expands to the union of the named
    system-service tokens, so the zone keeps its catch-all host-inbound drop.
    It does NOT admit raw IP protocols (GRE/OSPF/PIM/VRRP or future
    protocol numbers) or unlisted TCP/UDP ports; list those explicitly under
    `system-services` / `protocols`. The two xpf-only tokens are excluded from
    the expansion and must be listed explicitly: `gre` (Junos has no
    raw-IP-protocol system-service) and `r-exec`/`rexec` (Juniper's host-inbound
    list documents `rlogin` and `rsh` but not rexec, and tcp/512 is opened by no
    other token). Conversely, the services in Juniper's schema that xpf did not
    previously recognize — `r2cp`, `reverse-ssh`, `reverse-telnet`, `rpm`,
    `lsselfping`, `tcp-encap`, `appqoe` and `high-availability` — are now
    accepted at commit and included in the union, so scoping `all` cannot strand
    a defined service. The union's membership is derived from Juniper's
    published YANG schema, vendored at
    `pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz`.
    `any-service` remains the packet-wide escape hatch and is the one-token way
    to restore the pre-#3226 behaviour. Both draw a WARN-only commit advisory.
    See `docs/host-inbound-service-matrix.md`.
  - **Junos services xpf admits nothing for (#3226):** `r2cp`, `rpm`,
    `tcp-encap`, `appqoe` and `high-availability` are real Junos services, so
    they COMMIT — but xpf found no authoritative host-inbound listening tuple
    for any of them and deliberately opens nothing rather than guessing. This is
    a CHOICE under uncertainty, not an inference: a guessed port is wrong in both
    directions at once (it opens a port with no listener AND still denies the one
    in use, invisibly), whereas opening nothing is wrong in one direction and is
    announced at commit. Their traffic is DENIED, and `system-services
    any-service` is the ONLY remedy — an lo0 input filter does not help on
    either enforcement path. (On AF_XDP, #3485 evaluates host-inbound before the
    filter and never reaches it after a deny. On the kernel path `xpf_lo0` is
    priority 0 and `xpf_hostinbound` is 10, but nftables `accept` ends the
    current BASE CHAIN, not the hook — the packet advances to the next base
    chain and still hits the catch-all drop. Only `drop` is terminal for the
    hook.) Naming one of these tokens draws a WARN-only commit advisory saying
    exactly this. Ports xpf DOES open for this group:
    `reverse-telnet` tcp/2900 and `reverse-ssh` tcp/2901 (explicit YANG platform
    defaults) and `lsselfping` udp/8503 (RFC 7746 — not 3503, which is `lsping`).
  - **IS-IS host-inbound (L2 no-op, #3311):** `host-inbound-traffic protocols
    isis` is now ACCEPTED at commit (vSRX parity) — before #3311 it was
    hard-rejected even though IS-IS routing is supported via FRR, a fail-closed
    gap that prevented the operator from authoring the stanza. IS-IS rides
    OSI/CLNP directly over L2 (LLC-encapsulated, NOT IP), so it cannot be
    expressed as an IP host-inbound match (a protocol number, a TCP/UDP port, or
    an ICMP type) on either enforcement surface. It is therefore a
    recognized-but-no-op token (`config.HostInboundL2Protocols`): it admits at
    commit but contributes ZERO match to both the nftables `ip`/`ip6` input
    chains and the Rust AF_XDP IP-keyed classifier. This is consistent (neither
    surface admits an IP match, so no split-brain) and correct — the kernel
    delivers IS-IS PDUs to FRR's `isisd` via an LLC packet socket, entirely
    outside the IP host-inbound filter, so adjacencies form regardless. The nft
    parity test skips L2 tokens and instead asserts they produce no IP match;
    the Rust `classify_protocol` mirrors this with an explicit no-op arm.
  - **Routing-control protocol tokens (#3341):** four further Junos/vSRX
    `host-inbound-traffic protocols` tokens are now recognized — before #3341
    they were absent from `KnownHostInboundProtocols`, so since #3200 made the
    set typed a valid vSRX config naming them was HARD-REJECTED at commit. Unlike
    IS-IS, all four ride IP and so map to a concrete IP host-inbound match on
    BOTH enforcement surfaces (nft kernel mirror + Rust AF_XDP classifier):
    `rsvp` (RSVP, IP protocol 46, dual-family), `pgm` (Pragmatic General
    Multicast, IP protocol 113, dual-family), `sap` (Session Announcement
    Protocol, UDP/9875, dual-family), and `dvmrp` (carried inside IGMP, IP
    protocol 2, **IPv4-only** via `config.HostInboundProtocolFamily` — like
    `igmp`). Each is included in the `protocols all` expansion. Fail-on-revert
    Go (`TestHostInboundRoutingProtocolTokensCommit`,
    `TestHostInboundRoutingProtocolTokenMatches`) + Rust
    (`routing_control_protocol_tokens_classify`) tests guard commit acceptance,
    the nft match/family scoping, and the Rust admit semantics.
  - **`system-services traceroute` admit contract (UDP-probe-only, #3368):**
    `host-inbound-traffic system-services traceroute` admits the **UDP probe
    ports 33434-33523, dual-family (IPv4 + IPv6)** on both enforcement surfaces
    (nft kernel mirror `udp dport 33434-33523`; Rust classifier inserts
    `33434..=33523` into the family-agnostic UDP set). This is the **same range
    as the Junos predefined `junos-traceroute` application** and is a deliberate
    **superset** of the Junos `traceroute` system-service, which Juniper
    documents as exactly "Traceroute traffic (UDP port 33434)" — the single base
    probe port. xpf opens the full Unix default probe window (base 33434 +
    30 hops × 3 probes − 1 = 33523) so a default `traceroute <xpf-ip>` reaches
    the box on every probe, on both address families (Junos does not
    family-scope this token, and neither does xpf).
    - This token is **UDP-only by design — there is no under-admission** (the
      #3368 audit premise of a missing "full traceroute admit set" is not borne
      out against the Junos contract). Per Junos, the **other** traceroute
      variants are admitted by **other** tokens, not by `traceroute`:
      - **ICMP-based traceroute** (`mtr`/`traceroute -I`/Windows `tracert`)
        sends ICMP echo-request, which is admitted by the **`ping`**
        system-service (v4 type 8 / v6 type 128, see #3201/#3240), exactly as
        on Junos — Juniper's own troubleshooting guidance is to enable BOTH
        `traceroute` AND `ping` for full traceroute reachability.
      - **TCP-based traceroute** (`traceroute -T`) is **not** a Junos
        host-inbound system-service at all; there is no Junos token that opens
        it, and folding it into `traceroute` would be a non-parity posture
        change (silently answering TCP SYN probes on a traceroute-only zone).
    - Widening `traceroute` to also admit ICMP echo or TCP would therefore
      DEVIATE from Junos and change a zone's security posture, so it is
      intentionally NOT done. Sources: Juniper CLI reference *system-services
      (Security Zones Host Inbound Traffic)* ("traceroute — Traceroute traffic
      (UDP port 33434)"); Juniper community "Force SRX to use ICMP based
      traceroute?" (ICMP traceroute requires the `ping` service).
  - **RETH VRRP VIP scoping (#3172):** the kernel host-inbound chain scopes
    its accept/deny rules to each zone's firewall-local addresses. Those
    addresses now include the zone's RETH **VRRP virtual IPs** (the
    `vrrp-group ... virtual-address` entries on the reth unit), resolved from
    config rather than only from the live kernel address list. A VIP is present
    on the kernel interface only of the node that currently owns the redundancy
    group (master); on the BACKUP node the VIP is not yet live, so before #3172
    a host-inbound deny was not scoped to the VIP there and `chain input` fell
    through to `policy accept` (FAIL-OPEN) for VIP-destined host-bound traffic.
    Resolving the VIPs from config scopes the deny identically on both nodes
    regardless of mastership; on the master the live address dedups so the rule
    set is byte-identical. Management/cluster-control lifeline interfaces
    (fxp0/em0/fab*) are still excluded — a VIP on em0 is never scoped — and
    standalone (no-VRRP) zones are unchanged.
  - **Per-interface host-inbound override (#3362):** Junos models
    `host-inbound-traffic` at BOTH the zone level (`set security zones
    security-zone <z> host-inbound-traffic ...`, applies to every interface in
    the zone) AND the interface level (`set security zones security-zone <z>
    interfaces <if> host-inbound-traffic ...`, applies only to that interface).
    xpf now supports the interface-level stanza; the EFFECTIVE admission set for
    an interface is the UNION of the zone-level set and its interface-level
    override (Junos additive semantics). A zone is host-inbound-ENFORCING when it
    declares a zone-level stanza OR any interface-level override — so an operator
    can expose a service (e.g. `ssh`) on one interface of a zone while denying it
    on the others by setting the override only on the exposed interface and
    leaving the zone-level set empty (the motivating use case: management/routing
    protocols on a single uplink/loopback, denied on the rest of the zone).
    Enforcement on BOTH surfaces: the kernel-nft primary path
    (`BuildZoneHostInboundViews`) emits one address-scoped view per distinct
    effective token set, so the overridden interface's addresses accept its
    services while the zone's other interfaces get a catch-all drop; the Rust
    AF_XDP secondary (XSK local-delivery) path keys the admit check by ingress
    interface (`ForwardingState::ifindex_host_inbound` /
    `host_inbound_admits_iface`), falling back to the zone-keyed check where no
    override exists. Interface-level tokens are validated at commit by the same
    SSOT as the zone-level stanza (#3200), and management/cluster-control
    lifeline interfaces are excluded from the override exactly as from the
    zone-level deny scoping. (Distinct from #3328, which is the API-display gap.)
  - **Per-interface host-inbound in the TEXT/CLI views (#3654):** the structured
    REST/gRPC inventory (#3328) carried the per-interface override rows and the
    split `system-services` / `protocols` sets, but every text surface used to
    print ONLY the zone-level set — an interface with a narrower/wider effective
    admission set than its zone was shown as if it inherited the zone set, and a
    no-stanza zone printed nothing even though it default-DENIES (#3405). All six
    surfaces now render the override and posture through one shared presenter
    (`pkg/config/host_inbound_view.go`): `show security zones`, `show
    interfaces`, `test security-zone interface`, the gRPC text `show security
    zones` + interface diagnostic, and the remote `cmd/cli show security zones`.
    Each shows the effective (zone UNION interface) admitted set, flags an
    interface-local override, and prints an explicit `Host-inbound: default deny
    (no stanza | empty stanza | interface override: deny-all)` line when the
    effective set is empty so "not shown" can never be misread as "not
    enforced". The remote CLI additionally consumes the split
    system-services/protocols instead of the legacy flattened
    "Host-inbound services" line.
  - **Zone posture survives a partial interface override (#3671):** the shared
    zone presenter used to suppress the zone-level `Host-inbound: default deny
    (...)` line whenever the zone had ANY per-interface override, even though the
    zone posture still governs every NON-overridden interface. A zone with an
    empty zone-level set and an override on one interface now renders BOTH the
    zone default-deny posture line (governing the rest of the zone) AND the
    override block below it — the override is additional context, never a
    replacement for the zone posture. Because the fix is in the shared presenter
    (`HostInboundView.Render`), it propagates to all six #3654 surfaces.
  - **Lifeline set derived from cluster config (#3277):** the lifeline
    interfaces excluded from host-inbound deny scoping are no longer a fixed
    fxp0/em0/fab* hardcode. The set is now `fxp0` (always-mgmt) UNION the
    configured chassis-cluster `control-interface` and `fabric-interface` /
    `fabric1-interface` names, UNION the backward-compatible defaults em0 and
    fab*. So a deployment whose control/heartbeat link rides a non-default name
    (e.g. `set chassis cluster control-interface fxp1`) has that interface
    correctly excluded — its address is never subjected to a host-inbound deny,
    closing a latent HA split-brain (heartbeat drop) gap that would surface once
    the control zone's host-inbound set is scoped rather than full-admit.
    Canonical em0/fab*-named configs are byte-identical (the defaults still
    match unconditionally); a standalone config with no chassis-cluster stanza
    keeps fxp0 as its only lifeline (#1960).
  - **Lifeline fail-safe:** enforcement is strictly MATCH-DRIVEN. If NO
    `junos-host` policy is configured, or a host-bound flow matches no
    `junos-host` rule, behavior is UNCHANGED from before #3019 — there is no
    implicit junos-host default-deny, so configuring some junos-host policy
    cannot silently brick management/host traffic that does not match a deny
    rule. (The stricter Junos "any configured junos-host zone-pair implies a
    default-deny for that pair" posture is intentionally deferred.)
  - **Scope:** `to-zone junos-host` (host-INBOUND) is enforced — as an exact
    `from-zone <ingress> to-zone junos-host` pair, a `from-zone any to-zone
    junos-host` wildcard, AND a GLOBAL `set security policies global policy <p>
    match to-zone junos-host` (#3639 / #3611 Piece B). The three are consulted
    most-specific-first (exact → from-any → global). `from-zone junos-host`
    (host-ORIGINATED / locally-generated traffic) rules — the zone-pair
    `from-zone junos-host to-zone <z>` form OR the global
    `match from-zone junos-host` form — are NOT consulted: locally-generated
    traffic does not traverse the ingress LocalDelivery path (it egresses via
    the kernel TX path), so that direction would commit but silently never
    match. BOTH forms are therefore rejected at STRICT commit: the global form
    since #3611 Piece A, the zone-pair form since #4230 (which previously
    committed clean and was silently inert). The lenient load / peer-sync path
    downgrades either to a warning so an already-persisted config still boots.
    Actually wiring host-originated policy against the kernel TX path remains a
    documented follow-up.

### Filtering

- `show security policies from-zone lan to-zone Internet-ATT` shows only that zone pair.
  Global policies that govern the pair are also shown (#3357): an unscoped/`any`
  global and a scoped global (#3148) whose `match from-zone`/`to-zone` equals the
  filter; a scoped global bound to a different pair is omitted.

---

## Security: Policies Detail

**Command:** `show security policies detail from-zone lan to-zone Internet-ATT`

```
Policy: log-control4, action-type: permit, services-offload:not-configured , State: enabled, Index: 23, Scope Policy: 0
  Policy Type: Configured
  Sequence number: 1
  From zone: lan, To zone: Internet-ATT
  Source vrf group:
    any
  Destination vrf group:
    any
  Source addresses:
    host_control4_core5_adu(global): 172.16.1.38/32
    host_control4_ca10(global): 172.16.1.10/32
  Destination addresses:
    any-ipv4(global): 0.0.0.0/0
    any-ipv6(global): ::/0
  Application: any
    IP protocol: 0, ALG: 0, Inactivity timeout: 0
      Source port range: [0-0]
      Destination ports: [0-0]
  Source identity feeds:
    any
  Destination identity feeds:
    any
  Per policy TCP Options: SYN check: No, SEQ check: No, Window scale: No
  Session log: at-create, at-close
```

### Format Details

- **Policy header:** No indent. `Policy: <name>, action-type: permit, services-offload:not-configured , State: enabled, Index: <N>, Scope Policy: 0`
  - Note: space before comma after `not-configured `.
  - **Scheduler state (#3062):** `State:` reflects runtime scheduler
    state. A scheduler-bound policy whose scheduler is currently inactive
    renders `State: inactive` and an extra `  Scheduler: <name> (inactive)`
    line below `Policy Type: Configured`. Active and non-scheduled
    policies are bit-identical to pre-#3062 (`State: enabled`, no
    Scheduler line). The gRPC text detail surface agrees: it appends
    `, State: inactive, Scheduler: <name>` to the per-policy
    `action-type:` header only for inactive scheduled policies.
- **Policy fields:** 2-space indent.
- **Address entries:** 4-space indent. Format: `<name>(global): <prefix> ` (trailing space).
  - `(global)` suffix for global address-book entries.
  - **Zone-local address books (#3358 / #3061):** a name defined in a zone's
    local `address-book` is folded into the global book at compile time under
    an internal synthetic key `zone-local/<zone>/<name>`. The detail view
    unqualifies that key back to the authored name and labels its zone scope:
    `web(zone trust): 10.0.1.100/32`. The internal `zone-local/...` token never
    leaks to operator output, and a zone-scoped address is no longer mislabelled
    `(global)`. The REST (`GET /api/v1/security/policies`) and gRPC
    (`GetPolicies`) inventories, and the gRPC `show security policies` text
    surface, likewise expose the authored name (e.g. `web`, not
    `zone-local/trust/web`); the zone is implied by the rule's from/to-zone.
  - **Match inversion (#3336):** when a policy sets
    `source-address-excluded` / `destination-address-excluded`, the
    address header is annotated `Source addresses (except):` /
    `Destination addresses (except):` — the rule matches every address
    EXCEPT those listed. An un-inverted policy keeps the plain
    `Source addresses:` / `Destination addresses:` header (bit-identical
    to pre-#3336). The REST (`GET /api/v1/security/policies`) and gRPC
    (`GetPolicies`) inventory surface the same inversion via the
    `source_address_excluded` / `destination_address_excluded` booleans,
    alongside the independent `log_session_init` / `log_session_close`
    modes and the runtime `policy_id` / `rule_id` (the latter joins a
    runtime event back to an inventory row).
    - **gRPC text parity (#3667):** the gRPC-rendered
      `show security policies detail` text surface annotates its
      `      Source addresses (except):` / `      Destination addresses
      (except):` headers the same way (both the zone-pair and global
      blocks). Before #3667 that surface printed the excluded set under a
      plain header — the OPPOSITE security meaning — while also collapsing
      the log modes into a bare `log` and omitting the Index; it now prints
      `Session log: at-create, at-close` and `, Index: <N>` (the runtime
      policy ID) in the per-policy header, matching the local CLI.
- **Application block:** 2-space indent for app name, 4-space for protocol details, 6-space for ports.
  - `IP protocol: tcp|udp|0, ALG: 0, Inactivity timeout: <seconds>`
  - `Source port range: [<low>-<high>]`
  - `Destination ports: [<low>-<high>]` or just `<port>` for single port.
- **Session log:** `Session log: at-create, at-close` (only present if logging configured on policy).

---

## Security: Policies Hit-Count

**Command:** `show security policies hit-count`

```
Logical system: root-logical-system
Index   From zone        To zone           Name           Policy count  Action
1       all-zone         all-zone          default-policy 0             Deny
2       all-zone         all-zone          default-http-mux 0           Permit
3       junos-host       dmz               allow-junos-host-to-dmz 18939 Permit
5       junos-global     junos-global      icmpv6-allow   934734        Permit
6       junos-global     junos-global      default-log-deny 299946      Deny
```

### Format Details

- Tabular output with column headers.
- Columns: Index (left-aligned, ~8 wide), From zone (~17 wide), To zone (~18 wide), Name (variable), Policy count (right-justified before Action), Action (left-aligned).
- Spacing is not strictly fixed-width -- names can overflow into adjacent columns.
- Actions: `Permit`, `Deny`, `Reject`.

---

## Security: Global Policies

**Command:** `show security policies global`

```
Global policies:
  Policy: icmpv6-allow, State: enabled, Index: 524, Scope Policy: 0, Sequence number: 1, Log Profile ID: 0
    From zones: any
    To zones: any
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any-ipv6
    Destination addresses: any-ipv6
    Applications: junos-icmp6-all
    Source identity feeds: any
    Destination identity feeds: any
    Action: permit
  Policy: default-log-deny, State: enabled, Index: 525, Scope Policy: 0, Sequence number: 2, Log Profile ID: 0
    From zones: any
    To zones: any
    Source vrf group: any
    Destination vrf group: any
    Source addresses: any
    Destination addresses: any
    Applications: any
    Source identity feeds: any
    Destination identity feeds: any
    Action: deny, log
```

### Format Details

- Same as regular policies but with `Global policies:` header.
- Uses `From zones:` and `To zones:` (plural) instead of `From zone:` / `To zone:`.
- **Zone context (#3148, #4626 M03, display #3286).** A global policy may carry
  optional `set security policies global policy <p> match from-zone [ <z> ... ]`
  / `match to-zone [ <z> ... ]` to scope it to a SET of zones (or one wildcard
  side) instead of every zone pair. The scope is a zone set on each side: a
  packet matches iff its from-zone is in the from-set AND its to-zone is in the
  to-set (#4626 M03). With a context set, `From zones:` / `To zones:` shows the
  configured zones (space-joined, sorted) instead of `any`; absent, it shows
  `any` (all zones — the historical behaviour). A single-zone scope behaves
  exactly as before. A zone-scoped global policy is still evaluated in the global
  ordering, AFTER the exact zone-pair and the `from-zone any` / `to-zone any`
  wildcard policies — it does not jump ahead of them. An omitted leaf and an
  explicit `match from-zone any` are identical (all zones); an undefined match
  zone is rejected at commit (per element); a scope list that MIXES `any` with
  concrete zones — or a to-zone list that mixes `junos-host` with other zones —
  is rejected at commit (#4626). A multi-zone scoped global that references a
  zone-local address book resolves it against the GLOBAL book (zone-local
  resolution is defined only for a single concrete zone — a documented parity
  limitation). A `match to-zone junos-host`
  global (host-INBOUND) commits and IS enforced on the LocalDelivery gate
  (#3639 / #3611 Piece B) — consulted in the global tier, after the exact
  `from-zone <ingress> to-zone junos-host` pair and the `from-zone any to-zone
  junos-host` wildcard. A `match from-zone junos-host` global (host-ORIGINATED)
  is still rejected: locally generated traffic egresses via the kernel TX path,
  not the AF_XDP RX gate, so it could only ever silently never-match (#3611
  Piece A, documented not built). The zone-pair `from-zone junos-host to-zone
  <z>` spelling is rejected at strict commit for the same reason (#4230); before
  #4230 it committed clean and was silently inert.
- **#3286 — scope shown on EVERY inventory surface.** Before #3286 only the
  dataplane enforced the scope; the show/inventory surfaces dropped it and
  rendered scoped globals as all-zones. All surfaces now reflect the configured
  scope consistently: CLI `show security policies` (`From zones:`/`To zones:`),
  `... detail` (`From zone:`/`To zone:`), `... brief` (the From/To columns),
  and `... hit-count` (the From zone/To zone columns) print the scoped zone for
  a scoped global; the gRPC `GetPolicies` `PolicyRule` carries
  `match_from_zone`/`match_to_zone` (the first zone, back-compat) PLUS the full
  set in `match_from_zones`/`match_to_zones` (#4626 M03) and the gRPC text
  `policies-hit-count`/`policies-detail` views show the scope; the REST
  `GET /api/v1/security/policies` `PolicyRule` carries
  `match_from_zone`/`match_to_zone` and the additive plural
  `match_from_zones`/`match_to_zones` (omitted when empty). The global PolicyInfo
  group still reports `from_zone="*"`/`to_zone="*"` (the all-zones tier) — the
  per-rule fields carry the narrowing. An unscoped global is unchanged
  (junos-global / any / `*`).
- **#3357 — scope shown in the FILTERED and remote views too.** #3286 fixed the
  *unfiltered* surfaces; the *filtered* form (`show security policies hit-count
  from-zone X to-zone Y`, `... detail ...`, the standard/brief forms, and the
  gRPC `policies-hit-count`/`policies-detail` text views) plus the remote CLI
  still suppressed scoped globals. A `from-zone X to-zone Y` filter now includes
  every global that GOVERNS that pair — an unscoped/`any` global (enforced for
  every pair) and a scoped global whose `match from-zone`/`to-zone` equals the
  filter — and excludes a scoped global bound to a different pair, mirroring the
  runtime `globalScopeMatches` selection. The remote `show security policies`
  (filtered) renders each global rule under its effective scope, and the remote
  `... brief` prints the per-rule `match_from_zone`/`match_to_zone` (falling back
  to `*`/`*` only for an unscoped global) instead of the group `*`. The shared
  selection predicate is `policymatch.GlobalPolicyAppliesToZonePair`.
- **#3683 (M02) — remote FILTERED policy view normalizes the global scope to
  `any`.** The remote `show security policies` (filtered) `showPoliciesFiltered`
  (`cmd/cli/show.go`) hand-rolled an all-zones global scope as `*`, so an
  unscoped global printed `From zone: *, To zone: *` while the local / gRPC /
  Junos surfaces show `any`. It now renders each axis through the shared
  `matchScopeZone` normalizer (empty -> `any`), so an unscoped global reads
  `From zone: any, To zone: any` — the explicit policy model, not an internal
  wildcard. A scoped global still prints its configured zone(s) unchanged.
- **#3672 — remote non-detail renderer surfaces per-rule metadata.** The remote
  CLI `show security policies` (non-detail) `renderRule` (`cmd/cli/show.go`)
  previously printed only name / description / raw addresses / action / hits,
  silently dropping security-relevant fields the gRPC `PolicyRule` already
  carries (#3336 / #3623 / #3624). It now renders, matching the local/gRPC-text
  surfaces:
  - **Match inversion (M01):** `src=[...] (except)` / `dst=[...] (except)` when
    `source_address_excluded` / `destination_address_excluded` is set — an
    exclusive ("all EXCEPT these") match no longer reads identical to an
    inclusive one.
  - **Session logging (M02):** `Log: at-create, at-close` from the independent
    `log_session_init` / `log_session_close` modes (falls back to `Log: enabled`
    when only the collapsed `log` bool is set). A logged permit is no longer
    indistinguishable from an unlogged one.
  - **Scheduler state (M03):** `Scheduler: <name> (inactive)` (or
    `Scheduler: <name>` when active), and `Inactive: true` for a rule marked
    inactive without a scheduler name — a scheduled rule outside its active
    window is no longer shown as a plain `Action: permit`.
  - **Count state (M04):** a `then count` rule prints `Hit count: 0 packets,
    0 bytes` even when idle, so counted-but-idle is distinguishable from
    not-counted. A plain rule with no metadata bits set renders byte-identically
    to the pre-#3672 output (no `(except)` / `Log:` / `Scheduler:` /
    `Inactive:` / zero `Hit count:` lines).

---

## Security: Policy Simulator (match-policies / test policy)

**Commands:** `show security match-policies from-zone <z> to-zone <z> [...]`
and `test policy from-zone <z> to-zone <z> [...]` (both local and remote CLI).

The 5-tuple policy simulator answers "which policy does this flow match?" over
the same precedence the dataplane enforces. Selectors: `source-ip`,
`destination-ip`, `source-port`, `destination-port`, `protocol <name|number>`,
`icmp-type`, `icmp-code`, `ingress-interface` (#5579), and the valueless
`non-first-fragment` (#5572). `from-zone` and `to-zone` are required; an OMITTED
selector matches any.

**Per-interface host-inbound scoping (#5579).** A security zone can carry
MULTIPLE per-interface `host-inbound-traffic` effective views (#3362) — e.g. SSH
exposed on one unit of a zone and default-denied on a sibling. For a `to-zone
junos-host` query the host-inbound classifier used to OR every view in the zone
and report on the FIRST admitting view, so it certified a zone-wide
`token-admit`/permit even for a packet entering the sibling interface the runtime
DENIES — a false-admission diagnosis. Two changes remove it:

- `ingress-interface <if>` scopes the host-inbound classification to ONE
  interface's EFFECTIVE view (zone-level ∪ that interface's override), so the
  reported admission is that interface's TRUE posture (admit vs deny), not a
  zone-wide fold. The ref must name an interface assigned to `from-zone`; an
  unknown, zone-mismatched, or management/cluster lifeline (fxp0/em0/fab*) ref is
  rejected fail-closed (the lifeline is served unconditionally, so a
  per-interface verdict would itself be false). Example: `show security
  match-policies from-zone trust to-zone junos-host protocol tcp destination-port
  22 ingress-interface ge-0/0/1.0` reports the sibling's `denied`, not the
  zone-wide `token-admit ssh`.
- WITHOUT the selector, a zone-scoped query whose per-interface views DISAGREE now
  reports `ambiguous` (naming the differing interface groups and directing the
  operator at `ingress-interface`) instead of OR-ing them into a first-admit that
  lies for the denying interfaces. A zone with no per-interface override yields a
  single view, so it is unchanged.

The selector threads through every surface: local + remote `show security
match-policies` / `test policy`, the gRPC `MatchPolicies` RPC `ingress_interface`
field (proto field 11), the gRPC `test-policy:` bridge `iif=` token, and the REST
`match-policies` `ingress_interface` query parameter. The classifier reads the
same host-inbound SSOT the kernel-nft builder renders from, so a scoped verdict
cannot drift from the port the box actually opens. The gRPC/REST host-inbound
status gains an `ambiguous` value (`HOST_INBOUND_ADMISSION_STATUS_AMBIGUOUS`).

**Non-first fragment simulation (#5572).** The valueless `non-first-fragment`
selector evaluates the query as a NON-FIRST IP fragment — the dataplane's
flowless / no-L4 packet shape (`l4_present == false`). A non-first TCP/UDP
fragment carries the datagram's payload after the IP header, not an L4 header,
so it has no ports; the simulator then reproduces the dataplane's #4569
fragment-associated deny: a port-bearing DENY the FIRST fragment (with real
ports) would hit denies the non-first fragment too, even though a plain
omitted-port query on the same tuple would fall through to a later permit.
Without this selector a fragment could only be expressed as `... source-port 0
destination-port 0`, which the simulator matched as a real port-0 packet and
reported PERMIT while the live firewall dropped it — the exact operator lie
#5572 removes. Example: `show security match-policies from-zone trust to-zone
untrust source-ip 10.1.2.3 protocol tcp non-first-fragment` reports the enforcing
deny plus a `fragment-associated deny advisory:` line. The selector threads
through every surface (local + remote `show security match-policies` / `test
policy`, the gRPC `MatchPolicies` RPC `non_first_fragment` field, the gRPC
`test-policy:` bridge `frag=1` token, and the REST `non_first_fragment` query
parameter). A protocol-only / `application any` deny still matches the fragment
directly; a deny for a DIFFERENT protocol, or one whose source/destination
address does not overlap the fragment, leaves it on the forward path.

**Strict selector validation (#3696).** All four CLI surfaces (local + remote
`show security match-policies` / `test policy`) and the gRPC `ShowText`
`test-policy:` bridge reject malformed selector grammar rather than silently
widening the query — a firewall diagnostic must answer the query the operator
typed, not a broader one. All four CLI surfaces now share one strict grammar,
`policymatch.ParseSelectorArgs`, the SSOT sibling of the #3439 (H5)
session-filter fix:

- a selector present WITHOUT a value (`... destination-port` with nothing after
  it) is an error `selector "destination-port" requires a value` — previously it
  left the port at 0 (the wildcard) and evaluated ALL ports;
- an UNKNOWN / misspelled selector (`... protcol tcp`, or the plausible
  abbreviation `... proto tcp`) is an error `unknown selector "protcol"` —
  previously the token and its value were both silently dropped, yielding an
  any-protocol verdict;
- an explicit-empty typed value is an error, not the omitted-wildcard (M01);
- malformed IP / port / protocol / icmp values still error through the shared
  `ParsePort` / `ValidateProtocol` / `ParseICMPValue` / `net.ParseIP` validators
  (#3116 / #3108 / #3284 / #1711).

On the gRPC `test-policy:` text bridge a comma segment lacking `key=value`, an
unknown key, or an explicit-empty typed value (`port=`) is reported as a
diagnostic instead of being skipped; a bare `test-policy:` still reports the
missing-from/to-zone message. A VALID query behaves exactly as before.

**Duplicate selectors are rejected (#3709).** A repeated selector (e.g.
`... source-port 80 source-port 443` or `from-zone trust from-zone dmz`) is an
error `selector "source-port" specified more than once` on ALL surfaces —
`ParseSelectorArgs` (local + remote `show security match-policies` / `test
policy`), the gRPC `test-policy:` bridge (`selector "from" specified more than
once`), and REST `match-policies` (a repeated query parameter such as
`?from_zone=trust&from_zone=dmz` returns HTTP 400). Before #3709 a duplicate
silently WON: the CLI and gRPC surfaces last-won (the second value survived)
while REST first-won (the first value survived), so the three surfaces returned
an allow/deny verdict for a DIFFERENT packet than the operator typed, and even
disagreed with each other on WHICH value applied. A policy simulator must answer
the exact query, and there is no correct silent pick for a duplicate, so the
ambiguity is a hard error (the fail-closed posture #3696 set for the rest of the
grammar).

**Comma-in-zone-name round-trip (#3709).** The config permits a zone name
containing a comma or equals (only the exact reserved tokens are rejected in
`compiler_validate_strict.go`). The legacy `test-policy:` ShowText topic is a
comma/equals-delimited `key=value` string that cannot carry such a name, so the
REMOTE `test policy` surface now fails closed with a clear error
(`from-zone "trust,blue" contains a comma or equals, which the 'test policy'
topic cannot carry; use 'show security match-policies' instead`) rather than
silently corrupting the query into bogus segments. `show security
match-policies` uses the typed `MatchPolicies` RPC with no delimiter fragility
and handles the comma-bearing zone directly; the LOCAL `test policy` (which
evaluates in-process, no serialization) is likewise unaffected.

**No-config grammar ordering (#3709).** REST `match-policies` now validates
request grammar (duplicate / missing-zone / malformed IP-port-protocol-icmp)
BEFORE the no-active-config fail-closed default-deny verdict, so a malformed
query returns HTTP 400 consistently whether or not a config is loaded. Before
#3709 the `cfg == nil` branch returned 200 default-deny before any grammar
check, so a malformed request (e.g. `dst_port=abc`) returned 200 during the
boot window monitors poll but 400 once a config was active. A well-formed
boot-window query still returns the 200 fail-closed default-deny.

**Content-rejected verdict (#3727, #4394).** When the ACTIVE config names policy
content the userspace dataplane cannot represent, the helper fails the WHOLE
snapshot closed — it retains its previous-good snapshot or fresh-boots
default-deny and enforces NONE of the config. The simulator reports this as a
first-class `policy content rejected by dataplane (fail-closed)` verdict (naming
the offending policy + object), NOT a permit/deny/default verdict — matching the
dataplane instead of misleading the operator (under a default-permit the pre-fix
simulator answered PERMIT while the dataplane denied). The detection is the
single dataplane SSOT `dpuserspace.PolicyContentRejectionReasons` and covers: an
unexpandable application-set (#3727), a protocol-less application, an
unrepresentable protocol/port, an undefined application reference, and an
unresolvable address (undefined address-book / prefix-list name, or a book whose
value is a non-literal dns-name / wildcard / range) (#4394). A single
unrepresentable rule content-rejects EVERY query for the config (whole-snapshot
semantics); a healthy config is never flagged.

**Route-drop-before-policy advisory (#4373 E4/H2/H7).** A transit query whose
`destination-ip` is a class the forwarding path drops at ROUTE LOOKUP *before*
the policy engine runs — IPv4/IPv6 multicast, the IPv4 limited broadcast
`255.255.255.255`, the unspecified address (`0.0.0.0` / `::`), or loopback
(`127.0.0.0/8` / `::1`) — now carries an advisory line next to the verdict:

```
route-drop advisory: destination is multicast — transit traffic to this
address is dropped at route lookup BEFORE security-policy evaluation, so this
verdict does not describe real forwarding (the packet is dropped at route
regardless of the matching policy / filter-accept log)
```

This closes an operator-confusion class: without it the simulator (and a
firewall filter `then accept; then log` for the same tuple) reports a PERMIT
the dataplane never forwards — the packet is silently dropped at route with no
session and no policy eval, so the operator sees a permit/accept verdict but no
traffic. The advisory is **additive** — it does NOT change the permit/deny
verdict, `Matched`, or `default_used` — and rides both a positive match and the
default-policy fall-through. It is emitted on all four live surfaces from one
SSOT wording (`policymatch.RouteDropNote`): local + remote CLI `show security
match-policies` / `test policy`, REST `match-policies`
(`route_drop_before_policy` / `route_drop_class` / `route_drop_note` JSON
fields), and the gRPC `MatchPolicies` RPC (fields 22–24). A `to-zone
junos-host` query is exempt (it takes the local-delivery gate, not the transit
route lookup), and an OMITTED `destination-ip` is never classified (nil dst
means "any destination", not `0.0.0.0`).

Note the two remaining halves of the same #4373 class: (1) the runtime
RT_FLOW/event log already distinguishes a filter action from a teardown — a
`then reject` emits a `FILTER_LOG`/`POLICY_DENY` with `action=reject` (and a
`FILTER_LOG` `source=pbr|input|output`), while a `SESSION_CLOSE` deliberately
omits `action` and carries a close `reason` (#2513/#3610), so a filter-reject,
a policy-deny, and a session-teardown are already tellable apart in the log
(the E1 confusion does not reproduce). (2) A dataplane NoRoute/martian drop
COUNTER — so a *live* filter-accept log has a matching visible drop on the box —
is the DEFERRED userspace-dp (Rust) half of the E4/H2/H7 remedy, tracked in
#4373; the Go simulator advisory above is the control-plane half.

---

## Security: Zones

**Command:** `show security zones`

```
Security zone: ATH-SAAB-VPN-HUB
  Zone ID: 24
  Send reset for non-SYN session TCP packets: Off
  Policy configurable: Yes
  Interfaces bound: 4
  Interfaces:
    st0.2
    st0.3
    st0.4
    st0.5
  Advanced-connection-tracking timeout: 1800
  Unidirectional-session-refreshing: No

Security zone: untrust
  Zone ID: 8
  Send reset for non-SYN session TCP packets: Off
  Policy configurable: Yes
  Screen: untrust-screen
  Interfaces bound: 0
  Interfaces:
  Advanced-connection-tracking timeout: 1800
  Unidirectional-session-refreshing: No

Security zone: junos-host
  Zone ID: 2
  Send reset for non-SYN session TCP packets: Off
  Policy configurable: Yes
  Interfaces bound: 0
  Interfaces:
  Advanced-connection-tracking timeout: 1800
  Unidirectional-session-refreshing: No
```

### Format Details

- **Zone header:** `Security zone: <name>` (no indent).
- **Fields:** 2-space indent.
- `Zone ID: <N>` -- auto-assigned numeric ID.
- `Send reset for non-SYN session TCP packets: On|Off`
- `Policy configurable: Yes  ` (trailing spaces)
- `Screen: <screen-name>` -- only present if screen is bound to zone.
- `Interfaces bound: <N>` -- count of bound interfaces.
- `Interfaces:` header, then each interface indented 4 spaces.
- Empty `Interfaces:` line with no entries if none bound.
- **Host-inbound (#3654):** `Allowed host-inbound traffic: <services>` /
  `Allowed host-inbound protocols: <protocols>` for the zone-level set; a
  `Host-inbound interface overrides:` block listing each interface's override
  and its effective (zone UNION interface) admitted set; and a
  `Host-inbound: default deny (no stanza)` line when the zone admits nothing and
  declares no override (a no-stanza zone default-DENIES host-bound traffic
  post-#3405). The gRPC text view labels the zone-level lines
  `Host-inbound system-services:` / `Host-inbound protocols:`.
- Blank line between zones.
- **#3669 — policy-inventory failure fails loud (remote CLI).** The remote
  `show security zones` (`cmd/cli/show.go`) issues a second RPC (`GetPolicies`)
  to render each zone's policy summary. It previously discarded that RPC's error
  (`polResp, _ := ...`) and returned success, so a control-plane degradation
  rendered the zones as policy-free with exit 0 — indistinguishable from zones
  that genuinely have no policies. The zone bodies (from the successful
  `GetZones`) are still printed, but the command now surfaces the `GetPolicies`
  error (`policy inventory unavailable ...`) and exits non-zero so an operator
  or automation can tell a degraded partial view apart from a truly empty one.
- **#3683 (M01) — remote `show security zones` renders all three policy tiers.**
  The remote (non-detail) summary previously built a compact
  `Policies: from <peer> (N rules)` reference line from ONLY the zone-pair groups
  whose group-level zones matched the zone. The global group is exposed by
  `GetPolicies` with group zones `*`/`*` and the synthetic default-policy row
  (#3363) with `-`/`-`, so NEITHER appeared in the per-zone summary — an operator
  scraping the ctl binary could miss an applicable global or default-policy rule.
  The summary now renders the SAME three-tier `Policy summary` block the local
  detail view (`pkg/cli/cli_show_security_zones.go`) and gRPC text
  (`pkg/grpcapi/server_show_zones_text.go`) use (see the block below), filtering
  the global group PER-RULE by each rule's scope
  (`config.GlobalPolicyAppliesToZone` over the wire `match_from_zone`/
  `match_to_zone`, #3148/#3680) and always closing with the `[default]` catch-all.

**`show security zones detail` policy summary (#3658, #3684).** In `detail`
mode each zone gains a `Policy summary` block that lists the policies that
decide the zone's transit, in the SAME precedence order the dataplane
evaluates them (zone-pair, then global, then the implicit default-policy
catch-all). Each row carries a trailing `[...]` annotation that threads the
per-rule metadata the REST/gRPC inventory already exposes, so a zone-centric
audit can express scheduler state, join a rule to its telemetry id, and see
its logging/inversion intent (#3684):

```
  Policy summary (evaluation order: zone-pair, global, default-policy):
    [zone-pair] trust -> untrust: allow-web (permit) [id 0, log at-create, count]
    [zone-pair] trust -> untrust: night-block (deny) [id 1, scheduler off-hours (inactive)]
    [global] any -> untrust: block-bad (deny) [id 256, source-address (except)]
    [default] default-policy: deny [id 4294967295, log at-create]
```

- `[zone-pair] <from> -> <to>: <name> (<action>) [<modifiers>]` -- a
  from-zone/to-zone policy referencing this zone (either side).
- `[global] <from> -> <to>: <name> (<action>) [<modifiers>]` -- a GLOBAL
  policy that can affect this zone (M04). An unscoped global prints `any` for
  both scopes; a scoped global (`match from-zone`/`to-zone`, #3148) prints its
  zone scope. A global is listed for a zone only when the zone can appear on
  either side of a pair the global matches
  (`config.GlobalPolicyAppliesToZone`). Both the omitted scope and the
  EXPLICIT Junos token `any` are the all-zones wildcard on an axis --
  `config.IsWildcardZone` is the single source of truth shared with the
  `policymatch` selection helpers and the Rust runtime
  (`build_global_zone_scope` maps both `""` and `"any"` to
  `GlobalZoneScope::Any`), so an idiomatic `match from-zone any` / `to-zone
  any` global is no longer hidden from the affected zones' detail (#3680).
- `[default] default-policy: <action> [<modifiers>]` -- the effective
  default-policy catch-all is ALWAYS shown (M05), so a zone with no explicit
  rule reports `default-policy: deny` / `permit` / `reject` rather than a bare
  `(no policies)`, which hid whether unmatched transit is denied or permitted.
- The trailing `[<modifiers>]` annotation (#3684), a comma-separated list:
  - `id <N>` -- the runtime/RT_FLOW policy id (always present). This is the
    numeric identity the session/event/RT_FLOW telemetry logs, so the summary
    can be joined to `policy_id=N`. Ids are span-accumulated exactly as the
    snapshot builder assigns them, so a multi-application policy that shifts
    the id namespace still shows the id the dataplane enforces. The global
    tier's ids continue in the policy-set namespace after the zone-pair sets
    (e.g. `id 256` == policy-set 1 x `MaxRulesPerPolicy`). The `[default]` row
    always carries the reserved `DefaultPolicySentinelID` (`4294967295`), the
    id the implicit default-verdict RT_FLOW record logs (M11/M13).
  - `scheduler <name>` / `scheduler <name> (inactive)` -- the policy's
    scheduler binding (#3624) and, when the runtime reports that scheduler
    currently inactive, an `(inactive)` marker: the dataplane is SKIPPING the
    rule, so it can no longer read as an active participant (H03). The marker
    tracks live runtime state -- when the scheduler state cannot be queried no
    rule is claimed inactive (matching the #3062 policy-detail renderer).
  - `log <modes>` -- the session-log triggers (`at-create`, `at-close`) via
    the shared `PolicyLog.SessionLogModes` SSOT (#3667). The `[default]` row
    reflects `default-policy-log session-init/session-close` (#3534), the log
    posture for flows that hit the implicit default verdict (M13). NOTE: this
    line shows the CONFIGURED modes even on a `then deny`/`then reject` policy,
    where they are inert -- a deny/reject installs no session, so no
    session-init/session-close record fires (the deny is logged via the
    policy-deny RT_FLOW record). Commit emits a WARN naming the inert selection
    (#4373); `then log` session records fire only for a `then permit` policy.
  - `count` -- the policy has `then count` hit-count accounting.
  - `source-address (except)` / `destination-address (except)` -- a Junos
    `source-address-excluded` / `destination-address-excluded` inverted match
    (M12), using the `policymatch.ExceptSuffix` SSOT shared with the
    match-policies renderer.
- When a zone has no zone-pair AND no applicable global policy, the summary
  prints `(no zone-pair or global policies affecting this zone)` above the
  always-present `[default]` line.
- The gRPC text `zones-detail` view renders the identical three-tier block, and
  the remote (ctl) `show security zones` non-detail summary now renders it too
  (#3683 M01); both the local CLI and gRPC-text surfaces delegate to the single
  `policymatch.ZoneDetailPolicySummary` presenter (#3684 L10) so they cannot
  drift, and all mirror the REST inventory global + synthetic default-policy
  rows (`pkg/api/security.go`) and structured `GetPolicies` (#3363/#3624).

---

## Security: NAT Source Rule All

**Command:** `show security nat source rule all`

```
Total rules: 14
Total referenced IPv4/IPv6 ip-prefixes: 16/28
source NAT rule: source-as-bci
  Rule set                   : bci-to-internet
  Rule Id                    : 1
  Rule position              : 1
  From zone                  : guest
                             : lan
  To zone                    : Internet-BCI
  Match
    Source addresses         : 0.0.0.0         - 255.255.255.255
    Destination addresses    : 0.0.0.0         - 255.255.255.255
  Action                        : bci_pool
    Persistent NAT type         : N/A
    Persistent NAT mapping type : address-port-mapping
    Inactivity timeout          : 0
    Max session number          : 0
    Persistent NAT block session: disabled
  Translation hits           : 0
    Successful sessions      : 0
  Number of sessions         : 0
```

### Format Details

- **Header:** `Total rules: <N>` and `Total referenced IPv4/IPv6 ip-prefixes: <N>/<N>`.
- **Rule header:** `source NAT rule: <name>` (no indent).
- **Fields:** 2-space indent, fixed-width label column (~27 chars) padded with spaces, then `: <value>`.
- **Multi-zone:** Continuation lines use spaces up to the colon: `                             : lan`.
- **Match block:** `Match` header alone, then 4-space indent for source/dest addresses.
  - Address ranges: `<start_ip>         - <end_ip>` (spaces padded to ~16 char width for first IP).
  - Multiple ranges shown on continuation lines with same spacing.
- **Action block:** `Action                        : <pool_name|interface|off>`.
  - Sub-fields at 4-space indent under Action.
- **Counters:** `Translation hits`, `Successful sessions`, `Number of sessions` at 2-space indent.
- Action `off` means NAT is explicitly disabled for that rule.

---

## Security: NAT Destination Rule All

**Command:** `show security nat destination rule all`

```
Total destination-nat rules: 23
Total referenced IPv4/IPv6 ip-prefixes: 17/9
Destination NAT rule: firehouse-syslog
  Rule set                   : internet-in-dmz-dnat
  Rule Id                    : 1
  Rule position              : 1
  From zone                  : Internet-ATT
                             : Internet-BCI
    Destination addresses    : 108.85.109.0    - 108.85.109.0
    Destination port         : 514             - 514
  Action                     : host_syslog_container
  Translation hits           : 18564
    Successful sessions      : 18491
  Number of sessions         : 1
```

### Format Details

- Same structure as source NAT but with `Destination NAT rule:` header.
- **Destination port ranges:** `<low>             - <high>` (padded).
- Multiple port ranges on separate lines.
- **Application match:** `Application              : configured` (instead of port).
- **IP protocol match:** `IP protocol              : icmp6` or `47` (for GRE).
- **Source address match:** `Source addresses         : <address-book-name>` (named, not expanded).

---

## Security: NAT Source Summary

**Command:** `show security nat source summary`

```
Total port number usage for port translation pool: 64512
Maximum port number for port translation pool: 201326592
Total pools: 1
Pool                 Address                  Routing              PAT  Total
Name                 Range                    Instance                  Address
bci_pool             50.247.115.21-50.247.115.21 default           yes  1

Total rules: 14
Rule name : source-as-bci
    Rule set  : bci-to-internet
    Action    : bci_pool
    From      : guest                 To : Internet-BCI
Rule name : source-as-bci
Rule name : source-as-bci
    From      : lan
```

### Format Details

- **Pool table:** Fixed columns: Pool Name (~21), Address Range (~25), Routing Instance (~21), PAT (~5), Total Address.
- **Rule summary:** `Rule name : <name>` (note spaces around colon).
  - Sub-fields at 4-space indent: `Rule set  :`, `Action    :`, `From      :`, `To :`.
  - Continuation rules share the rule name but show additional From/To zones.
  - Zone names padded to fixed width (~22 chars).

---

## Security: Screen IDS

**Command:** `show security screen ids-option <screen-name>`

```
Screen object status:

Name                                       value
  IP tear drop                               enabled
  TCP SYN flood attack threshold             200
  TCP SYN flood alarm threshold              1024
  TCP SYN flood source threshold             1024
  TCP SYN flood destination threshold        2048
  TCP SYN flood timeout                      20
  ICMP ping of death                         enabled
  IP source route option                     enabled
  TCP land attack                            enabled
```

### Format Details

- Header: `Screen object status:` followed by blank line.
- Column headers: `Name` (left-aligned, ~43 chars) and `value` (left-aligned).
  - Header uses trailing spaces for padding.
- Each entry: 2-space indent, name padded to ~43 chars, then value padded.
- Values: `enabled` or numeric thresholds.

---

## Security: ALG Status

**Command:** `show security alg status`

```
ALG Status:
  DNS      : Disabled
  FTP      : Disabled
  H323     : Enabled
  MGCP     : Enabled
  MSRPC    : Enabled
  PPTP     : Enabled
  RSH      : Disabled
  RTSP     : Enabled
  SCCP     : Enabled
  SIP      : Enabled
  SQL      : Disabled
  SUNRPC   : Enabled
  TALK     : Enabled
  TFTP     : Enabled
  IKE-ESP  : Disabled
  TWAMP    : Disabled
```

### Format Details

- Header: `ALG Status:`.
- Each line: 2-space indent, name (~9 chars left-aligned), ` : ` separator (space-colon-space), value.
- Values: `Enabled` or `Disabled` (capitalized).
- **Note:** NOT per-node output (no node0/node1 headers). This is a single global output.

---

## Security: IPsec Security Associations

**Command:** `show security ipsec security-associations`

```
  Total active tunnels: 6     Total Ipsec sas: 6
  ID    Algorithm       SPI      Life:sec/kb  Mon lsys Port  Gateway
  <131073 ESP:aes-gcm-128/None 94337ff7 1932/ unlim - root 500 50.233.235.222
  >131073 ESP:aes-gcm-128/None b941875f 1932/ unlim - root 500 50.233.235.222
  <131074 ESP:aes-cbc-256/sha256 b95afaf0 3029/ unlim - root 500 104.193.170.172
  >131074 ESP:aes-cbc-256/sha256 ca3156de 3029/ unlim - root 500 104.193.170.172
```

### Format Details

- **Summary line:** `  Total active tunnels: <N>     Total Ipsec sas: <N>` (2-space indent).
- **Column header:** `  ID    Algorithm       SPI      Life:sec/kb  Mon lsys Port  Gateway   ` (2-space indent).
- **Each SA:** 2-space indent.
  - Direction: `<` (inbound) or `>` (outbound) prefix, no space before ID.
  - ID: SA index.
  - Algorithm: `ESP:<enc>/<auth>` e.g. `ESP:aes-gcm-128/None`, `ESP:aes-cbc-256/sha256`.
  - SPI: 8-char hex.
  - Life: `<seconds>/ unlim` or `<seconds>/<kbytes>`.
  - Mon: `-` (monitoring off) or status.
  - lsys: `root`.
  - Port: `500` or `4500`.
  - Gateway: remote peer IP.
- Inbound/outbound pairs share the same ID.

---

## Security: IPsec Security Associations Detail

**Command:** `show security ipsec security-associations detail`

```
ID: 131073 Virtual-system: root, VPN Name: BV-FIREHOUSE
  Local Gateway: 50.220.171.30, Remote Gateway: 50.233.235.222
  Local Identity: ipv4_subnet(any:0,[0..7]=0.0.0.0/0)
  Remote Identity: ipv4_subnet(any:0,[0..7]=0.0.0.0/0)
  Version: IKEv1
  DF-bit: copy, Copy-Outer-DSCP Disabled, Bind-interface: st0.0
  Port: 500, Nego#: 959, Fail#: 0, Def-Del#: 0 Flag: 0x600a29
  Multi-sa, Configured SAs# 1, Negotiated SAs#: 1
  Tunnel events:
    Sat Feb 14 2026 20:53:59 -0800: IPSec SA negotiation successfully completed (25 times)
    Sat Feb 14 2026 17:02:56 -0800: IKE SA negotiation successfully completed (56 times)
  Direction: inbound, SPI: 94337ff7, AUX-SPI: 0
                              , VPN Monitoring: -
    Hard lifetime: Expires in 1858 seconds
    Lifesize Remaining:  Unlimited
    Soft lifetime: Expires in 1285 seconds
    Mode: Tunnel(0 0), Type: dynamic, State: installed
    Protocol: ESP, Authentication: None, Encryption: aes-gcm (128 bits)
    Anti-replay service: counter-based enabled, Replay window size: 64
  Direction: outbound, SPI: b941875f, AUX-SPI: 0
                              , VPN Monitoring: -
    Hard lifetime: Expires in 1858 seconds
    Lifesize Remaining:  Unlimited
    Soft lifetime: Expires in 1285 seconds
    Mode: Tunnel(0 0), Type: dynamic, State: installed
    Protocol: ESP, Authentication: None, Encryption: aes-gcm (128 bits)
    Anti-replay service: counter-based enabled, Replay window size: 64
```

### Format Details

- **SA header:** `ID: <N> Virtual-system: root, VPN Name: <name>` (no indent).
- **Fields:** 2-space indent.
- **Tunnel events:** 4-space indent, timestamp format: `<Day> <Mon> <DD> <YYYY> <HH:MM:SS> <TZ>: <event> (<N> times)`.
- **Direction blocks:** 2-space indent for header, 4-space for details.
  - `Direction: inbound|outbound, SPI: <hex>, AUX-SPI: 0`
  - Second line is continuation with VPN Monitoring.
  - Sub-fields: Hard lifetime, Lifesize, Soft lifetime, Mode, Protocol, Anti-replay.

---

## Security: IKE Security Associations

**Command:** `show security ike security-associations`

```
Index   State  Initiator cookie  Responder cookie  Mode           Remote Address
10827715 UP    ccb95f0882a044a8  67c1a3d54ae8f069  IKEv2          174.70.192.83
10827718 UP    f737bec6d2d877ff  9cb755d0c21be9c3  IKEv2          172.3.77.209
10827726 UP    0f33732903bd3ed7  ed31e2cf6088415f  Main           50.233.235.222
```

### Format Details

- **Column header:** `Index   State  Initiator cookie  Responder cookie  Mode           Remote Address   `
- **Index:** Left-aligned ~9 chars.
- **State:** `UP` or `DOWN`, ~7 chars.
- **Cookies:** 16-char hex each, ~18 chars.
- **Mode:** `IKEv2` or `Main` (for IKEv1), ~15 chars.
- **Remote Address:** IP address.

### Drill-downs (fable-167 C-1, #4314)

The operational tree (`pkg/cmdtree`) now advertises these grouped
drill-downs (tab-completion + `?` help):

- `show security ike security-associations detail` — per-SA local/remote
  traffic selectors, SPI in/out, and lifetime (was: bare list only).
- `show security ipsec security-associations detail` — already rendered by
  the handler; now surfaced in completion/help.
- `show security nat static rule [detail]` — per-rule drill-down mirroring
  source/destination NAT; `detail` adds the source-address restriction,
  destination-port / mapped-port translation, `prefix-name`, and the
  translation-target routing-instance.
- `request security policies check` — a config lint that reports **shadowed**
  (an earlier terminal policy matches a superset with a *different* action →
  the later rule is unreachable) and **redundant** (same action) policies. It
  is a conservative name-set containment pass over the configured zone-pair
  policies; it never resolves address-book names to prefixes (no false
  positives) and never treats an inverted-match or schedule-gated policy as a
  shadower. It does not mutate config.

---

## Security: Log

**Command:** `show security log`

```
error: permission denied: log
```

**Note:** Requires specific permissions. The `claude` user did not have access. On a fully privileged
session, this would show structured security log events. The format is known from documentation:

```
<timestamp> <hostname> RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.102" source-port="54321" destination-address="10.0.2.102" destination-port="80" connection-tag="0x0" nat-source-address="10.0.1.102" nat-source-port="54321" nat-destination-address="10.0.2.102" nat-destination-port="80" nat-connection-tag="0x0" src-nat-rule-type="N/A" src-nat-rule-name="N/A" dst-nat-rule-type="N/A" dst-nat-rule-name="N/A" protocol-id="6" policy-name="trust-to-untrust-permit" source-zone-name="trust" destination-zone-name="untrust" session-id-32="1234" packets-from-client="0" bytes-from-client="0" packets-from-server="0" bytes-from-server="0" elapsed-time="0" application="UNKNOWN" nested-application="UNKNOWN" username="N/A" roles="N/A" packet-incoming-interface="trust0.0" encrypted="UNKNOWN"]
```

The `show configuration security log` was also permission-denied.

**Filter syntax:** `show security log [<count>] [zone <name>] [protocol <proto>]
[action <action>]`. Argument parsing fails **closed** (#3347): an unknown
token (e.g. a typo `zon trust`), a filter keyword with no value (`action`
with nothing after it), or a non-positive count returns a usage error rather
than silently dropping the filter and dumping every event. A `zone <name>`
filter requested before a successful dataplane apply exists (early startup or
after a failed commit, when zone-name→ID mapping is unavailable) is likewise
refused instead of widening to all zones — in incident response, silently
broadening a scoped forensic query is worse than failing the query.

Zone IDs are 1-based, so zone **0** is the "unknown" / unassigned zone carried
by pre-classification drops, host-inbound traffic, and events emitted before
zone resolution. Those events are selectable with `zone unknown` (also `none`
or the literal `0`) — `show security log zone unknown` (#3338). They were
previously invisible to any zone-filtered query because zone 0 was overloaded
as the "no filter" sentinel. The same selector is exposed on the public event
APIs: REST `GET /api/v1/security/events?zone=unknown` (or `?zone=0` /
`?zone=none`) and the gRPC `GetEvents` RPC via the `has_zone` field set with
`zone=0`. A bare gRPC `zone=0` with `has_zone` unset stays "no filter"
(match-all) for backward compatibility; an unfiltered query on any surface
always includes the zone-0 events.

The full filter grammar (count plus the `zone`/`protocol`/`action` selectors,
including the `unknown`/`none`/`0` zone-0 sentinel) is honored identically on
the local CLI and the remote `cli` (gRPC text path). Both share one parser,
`logging.ParseEventFilterArgs` (#3547); before #3547 the remote `cli`
forwarded only a numeric count to the daemon and dropped any zone/protocol/
action selector, so `show security log zone <name>` on the remote client
silently dumped every event instead of isolating the requested zone.

---

## Firewall: Filters (raw and effective)

**Commands:**

- `show firewall` — all filters, RAW typed config.
- `show firewall filter <name> [family inet|inet6]` — one filter, RAW.
- `show firewall effective [family inet|inet6]` — all filters, EFFECTIVE
  (compiled) view.
- `show firewall filter <name> effective [family inet|inet6]` — one filter,
  EFFECTIVE.

The RAW view (`show firewall …`) prints the typed configuration as authored —
literal addresses, `from source-prefix-list <name>` references by NAME,
symbolic DSCP names, and each term's raw `then` selectors, alongside live
per-term hit counters read from the dataplane.

The EFFECTIVE view (`… effective`, #4422) rebuilds and prints the
`FirewallFilterSnapshot` the userspace dataplane actually receives — the exact
match/action the matcher enforces. It is read-only and derives entirely from
the active config (it reads `dpuserspace.BuildFirewallFilterSnapshots`, the
same builder `buildSnapshot` threads into `ConfigSnapshot.Filters`); it touches
no dataplane state and reports no hit counters. It differs from the RAW view
where compilation transforms the term:

- **Prefix-list references are resolved** to their literal prefixes
  (`from source-prefix-list trusted` → `from source-address 10.0.0.0/8,
  192.168.0.0/16`), matching #2506 lowering.
- **`except` prefix-lists** render as `from source-address except …`; an empty
  positive set renders `(empty set — matches nothing)` and an empty `except`
  set `(empty set — matches any)`, exposing the fail-closed / match-all
  Junos empty-set semantics. A mixed positive+except term (rejected at strict
  commit, #3359) is shown positive-wins.
- **Multi-value match lists** (bracketed `[ … ]`, #2419) survive the collapse
  and render every value (`from destination-port 22, 80`).
- **Symbolic DSCP names resolve to numeric code points** (`ef` → `46`).
- **`tcp-flags` expressions** render as lowered `require`/`forbid` masks
  (#3076).
- **Fall-through** — a `then next term` or modifier-only term (no terminating
  action) renders `then next term (fall-through)` (#2544); a terminating term
  renders `then <action>` (default `accept`).
- **Unrepresentable matches** — a token the compiler cannot lower (an
  out-of-range ICMP type, an unknown DSCP, an unparseable `tcp-flags`) that
  reaches the snapshot on the lenient / peer-sync path renders
  `<unrepresentable — snapshot fails closed>`, mirroring the fail-closed
  markers the Rust filter compiler acts on (#3406/#3367).

The heading carries a `[effective]` tag (`Filter: demo (family inet)
[effective]`) so the compiled view is never confused with the raw output.

**Generation-liveness banner (#5067).** The effective view compiles its
snapshots from the ACTIVE config, which `commitAndApply` promotes via
`store.Commit()` BEFORE the dataplane apply runs. A required-protocol-gate apply
error (`applyErrSkipsPeerSync` / `compileErrorMustAbortApply`, see
`pkg/daemon/daemon_apply.go`) leaves the dataplane DISARMED while the active
config is already the new generation — so the compiled-desired snapshot is NOT
what the dataplane is enforcing. The local CLI therefore binds the view to the
HELPER-ACKNOWLEDGED generation before rendering:

- **Armed + acknowledged** (dataplane armed and the acknowledged generation is
  at or ahead of the daemon's last applied generation): the snapshots are
  prefixed with `Effective firewall filters — dataplane-acknowledged
  (generation N).` and are safe to read as live. Helper-ahead is benign — a
  scheduler-only republish (`Manager.UpdatePolicyScheduleState`) advances the
  helper's snapshot generation without bumping the last recorded apply
  generation, and it carries the same filter content, so the view is still live.
- **Disarmed or generation drift**: the snapshots are prefixed with a prominent
  `WARNING: dataplane is NOT enforcing the active configuration.` banner that
  labels the output `COMPILED-DESIRED`, states the reason (dataplane disarmed, or
  the helper is BEHIND the applied generation), and surfaces the last
  dataplane-acknowledged generation versus the desired (active, not-yet-
  acknowledged) configuration. The compiled snapshots are still printed under the
  banner so the operator can inspect the desired compile, but they are never
  certified as live.
- **Dataplane status unavailable** (no runtime wired): a soft note records that
  the snapshots are compiled-desired and the acknowledged generation could not be
  confirmed.

This applies to the local CLI (`pkg/cli`). The remote CLI's gRPC `ShowText`
path renders the same compiled snapshots without the liveness banner; adding the
generation-liveness context to the gRPC surface is a follow-up.

Both the local and the remote (`cli`) CLI render this identically (#4967). The
snapshot renderer is the single source of truth
`dpuserspace.RenderFirewallFilterSnapshot`; the local CLI calls it directly and
the remote CLI routes `show firewall … effective` to the gRPC `ShowText`
topics (`firewall-effective`, `firewall-effective:<family>`,
`firewall-effective-filter:<name>[:<family>]`) which call the same renderer.
Before #4967 the remote dispatcher recognized only `filter`, so
`show firewall effective` fell through to the RAW view even though the
completion/help tree advertised the effective leaf — a silent
advertised-vs-executable divergence. `show bgp …` had the same class of bug on
the remote surface (advertised as the alias for `show protocols bgp` but not
dispatched) and is likewise fixed.

```
Filter: demo (family inet) [effective]
  Term: t1
    from source-address 10.0.0.0/8, 192.168.0.0/16
    from protocol tcp
    from destination-port 22, 80
    from dscp 46
    then forwarding-class best-effort
    then count c1
    then next term (fall-through)
  Term: t2
    then accept
```

### Format Details

- Heading: `Filter: <name> (family inet|inet6) [effective]`.
- Per term: `  Term: <name>`, then `from …` match lines, then `then …` action
  and modifier lines (2-space / 4-space indent).
- The `effective` keyword is a trailing modifier and composes with the loose
  `family <f>` selector in either order.

---

## Interfaces: Terse

**Command:** `show interfaces terse`

```
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   aenet    --> reth0.0
gr-0/0/0.0              up    up   inet     10.255.192.22/30
gr-0/0/0.1              up    up   inet     10.255.192.34/30
                                   inet6    fc00::e/126
                                            fe80::8/64
ge-0/0/1                up    down
reth0                   up    up
reth0.0                 up    up   inet     50.220.171.30/30
                                   inet6    2001:559:800c:1900::881a/126
                                            fe80::210:dbff:feff:1000/64
lo0                     up    up
lo0.0                   up    up   inet
                                   inet6    fe80::86c1:c10f:fc03:5100
```

### Format Details

- **Column header:** `Interface               Admin Link Proto    Local                 Remote`
- **Column positions (0-indexed):**
  - Interface: 0-23 (24 chars)
  - Admin: 24-28 (5 chars, `up` or `down`)
  - Link: 30-33 (4 chars)
  - Proto: 35-42 (8 chars, `inet`, `inet6`, `aenet`, `tnp`)
  - Local: 44-64 (21 chars)
  - Remote: 66+
- **Continuation lines** for additional addresses: same column positions, blank Interface/Admin/Link.
- `aenet    --> reth0.0` for aggregated ethernet member links.
- **Pipe filters work:** `show interfaces terse | except down` removes down interfaces.

---

## Interfaces: Detail

**Command:** `show interfaces <name> detail`

```
Physical interface: reth0, Enabled, Physical link is Up
  Interface index: 128, SNMP ifIndex: 501, Generation: 131
  Description: Comcast Gigabit Pro
  Link-level type: Ethernet, MTU: 1514, Speed: 1Gbps, ...
  Device flags   : Present Running
  Interface flags: SNMP-Traps Internal: 0x4000
  Current address: 00:10:db:ff:10:00, Hardware address: 00:10:db:ff:10:00
  Last flapped   : 2026-01-13 15:40:40 PST (4w4d 05:41 ago)
  Statistics last cleared: Never
  Traffic statistics:
   Input  bytes  :       26021579096863              8442760 bps
   Output bytes  :       32458307878019             86493408 bps
   Input  packets:          20655442875                 2006 pps
   Output packets:          24187455940                 7723 pps
  Ingress queues: 8 supported, 4 in use
  Queue counters:       Queued packets  Transmitted packets      Dropped packets
    0                                0                    0                    0
  Egress queues: 8 supported, 4 in use
  Queue counters:       Queued packets  Transmitted packets      Dropped packets
    0                       2707422561           2707422561                    0
  Queue number:         Mapped forwarding classes
    0                   best-effort

  Logical interface reth0.0 (Index 93) (SNMP ifIndex 525) (Generation 158)
    Flags: Up SNMP-Traps 0x4004000 Encapsulation: ENET2
    Statistics        Packets        pps         Bytes          bps
    Bundle:
        Input :   20655442875       2006 26021579096863      8442760
        Output:   24184316839       7721 32454800570987     86491176
    Security: Zone: Internet-Gigabit-Pro
    Allowed host-inbound traffic : dhcp ike ping ssh traceroute dhcpv6
    Flow Statistics :
    Flow Input statistics :
      Self packets :                     38653109
      ICMP packets :                     23960745
      VPN packets :                      15299304
      Multicast packets :                3192
      Bytes permitted by policy :        26016665651961
      Connections established :          158020411
    Flow Output statistics:
      Multicast packets :                0
      Bytes permitted by policy :        32452687300274
    Flow error statistics (Packets dropped due to):
      Address spoofing:                  0
      No route present:                  14603
      No SA for incoming SPI:            0
      Policy denied:                     632620
      TCP sequence number out of window: 3129
    Protocol inet, MTU: 1500
      Flags: Sendbcast-pkt-to-re, Is-Primary, Sample-input, Sample-output
      Addresses, Flags: Primary Preferred Is-Default Is-Preferred Is-Primary
        Destination: 50.220.171.28/30, Local: 50.220.171.30, Broadcast: 50.220.171.31
    Protocol inet6, MTU: 1500
      Flags: Is-Primary, Sample-input, Sample-output
      Addresses, Flags: Is-Default Is-Preferred Is-Primary
        Destination: 2001:559:800c:1900::8818/126, Local: 2001:559:800c:1900::881a
```

### Format Details

- **Physical header:** `Physical interface: <name>, Enabled, Physical link is Up|Down`
- **All fields:** 2-space indent under physical, 4-space under logical.
- **Traffic stats:** Right-aligned numbers with rate (bps/pps) on same line.
  - Counter name padded to ~14 chars, colon, then number right-aligned ~20 chars, rate ~20 chars.
- **Flow statistics:** Under logical interface, indented further.
  - `Flow Input statistics :` and `Flow Output statistics:` headers.
  - `Flow error statistics (Packets dropped due to):` header.
  - Each counter: 6-space indent, name padded, colon, right-aligned number.
- **Protocol blocks:** `Protocol inet, MTU: 1500` and `Protocol inet6, MTU: 1500`.
  - Address entries under each protocol.
- **Bondless reth resolution (#4328):** a reth (`reth0`) has no kernel netdev
  of its own, so `show interfaces reth0`, `show interfaces reth0 detail`, and
  `... extensive` render the aggregate over its local physical member — link
  state / MAC / counters from the member, addresses/units from config — with a
  `Redundant-ethernet: aggregate over member <ge-...>` line naming the member.
  A physical reth member queried by name shows its `aenet --> reth<N>.<unit>`
  aggregation. Previously only `show interfaces terse` was reth-aware; the
  other variants reported `Not present` / empty / `not found`. All four
  surfaces (summary, detail, extensive, terse) now build the same reth maps via
  `config.RethShowMaps` (CLI + gRPC) so they cannot drift again.
- **Canonical name identity (#4984):** every `show interfaces` variant renders
  the **authored Junos name** (`ge-0/0/0`, logical `ge-0/0/0.N`) as the
  interface identity — never the Linux kernel netdev name (`ge-0-0-0`). The
  kernel name is an implementation detail used only for lookups. The
  netlink-driven `detail` / `extensive` / `statistics` presenters previously
  printed the kernel dash-form name as the identity (and keyed the zone /
  description joins by the authored name but looked them up by the kernel name,
  so both were silently blank; an authored-form filter reported `not found`).
  They now resolve each kernel netdev back to its authored name via a shared
  `kernelToAuthoredMap` (`config.LinuxIfName` reverse map from the active
  config), key the zone / description joins by that authored form, and accept
  **either** spelling as the `<name>` filter (`ifaceFilterMatches`). The summary
  path additionally resolves each logical unit's address lookup to the kernel
  VLAN sub-device (`ge-0-0-0.<vlan-id>`) instead of the authored name, so a
  VLAN unit no longer falls back to the parent and prints the parent's addresses
  under the sub-unit (was #4884 sub-defect B). `show interfaces queue` is a
  separate CoS runtime-snapshot surface (`pkg/cli/show_services_cos.go`) and is
  out of scope here.

---

## Interfaces: Extensive

**Command:** `show interfaces <name> extensive`

Same as `detail` but adds:

```
  Dropped traffic statistics due to STP State:
   Input  bytes  :                    0
   Output bytes  :                    0
   Input  packets:                    0
   Output packets:                    0
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0, Resource errors: 0
  Output errors:
    Carrier transitions: 1, Errors: 0, Drops: 0, MTU errors: 0, Resource errors: 0
```

### Format Details

- Includes STP drop stats, Input/Output error counters.
- Error fields are comma-separated on one line.
- Otherwise identical to `detail` output.

---

## System: Uptime

**Command:** `show system uptime`

```
Current time: 2026-02-14 21:22:05 PST
Time Source:  NTP CLOCK
System booted: 2026-01-13 15:47:21 PST (4w4d 05:34 ago)
Last configured: 2026-02-14 19:49:01 PST (01:33:04 ago) by ps
 9:22PM  up 32 days,  5:35, 0 users, load averages: 6.38, 5.88, 5.88
```

### Format Details

- Key-value pairs with timestamp format: `YYYY-MM-DD HH:MM:SS TZ`.
- Relative time in parentheses: `(4w4d 05:34 ago)` or `(01:33:04 ago)`.
- Last line is BSD-style uptime: `<time>  up <days> days, <hours>:<mins>, <users> users, load averages: <1m>, <5m>, <15m>`.
- `Time Source:  NTP CLOCK ` (trailing space).
- node1 also shows `Protocols started:` line.
- `Last configured:` includes ` by <username>`.

---

## System: Memory

**Command:** `show system memory`

```
System memory usage distribution:
        Total memory: 16715220 Kbytes (100%)
     Reserved memory:  454076 Kbytes (  2%)
        Wired memory: 13798816 Kbytes ( 82%)
       Active memory:   95164 Kbytes (  0%)
     Inactive memory: 1579984 Kbytes (  9%)
        Cache memory:       0 Kbytes (  0%)
         Free memory:  785412 Kbytes (  4%)
Pid     VM-Kbytes(  %  ) Resident(  %  ) Process-name
      0         0(00.00)        0(00.00) [kernel]
      1         0(00.00)        0(00.00) /sbin/init
  17402  14018780(83.87)  12968400(77.59) srxpfe
```

### Format Details

- Header: `System memory usage distribution:`.
- Memory lines: right-aligned label (variable indent), then `: <number> Kbytes (<percent>%)`.
- Process table: `Pid` (right-aligned 7), `VM-Kbytes(  %  )` (right-aligned), `Resident(  %  )`, `Process-name`.
- Numbers formatted with right-alignment within parenthesized percentages.

---

## System: Processes Summary

**Command:** `show system processes summary`

```
last pid: 21215;  load averages:  5.19,  5.63,  5.78  up 32+05:35:30    21:22:51
584 threads:   11 running, 540 sleeping, 1 zombie, 32 waiting
CPU: 84.2% user,  0.0% nice,  1.9% system,  0.2% interrupt, 13.7% idle
Mem: 93M Active, 1543M Inact, 13G Wired, 307M Buf, 766M Free
Swap: 1024M Total, 1024M Free

  PID USERNAME    PRI NICE   SIZE    RES STATE    C   TIME    WCPU COMMAND
17402 root        -52   r0    13G    12G CPU4     4 773.3H 100.00% srxpfe{lcore-worker-4}
17402 root        -52   r0    13G    12G CPU2     2 773.3H 100.00% srxpfe{lcore-worker-2}
   11 root        187 ki31     0B    80K RUN      0 530.0H  66.36% idle{idle: cpu0}
```

### Format Details

- First 5 lines are FreeBSD `top` header format.
- Process table columns: PID (right-aligned 5), USERNAME (left-aligned 12), PRI (right-aligned 4), NICE (right-aligned 5), SIZE (right-aligned 7), RES (right-aligned 7), STATE (left-aligned 9), C (right-aligned 2), TIME (right-aligned 8), WCPU (right-aligned 7), COMMAND.
- TIME format: `<hours>.<tenths>H` for hours, `<min>:<sec>` for minutes.
- WCPU: percentage with 2 decimal places.
- Thread names in curly braces: `srxpfe{lcore-worker-4}`.

---

## System: Version

**Command:** `show version`

```
Hostname: vsrx-ernie
Model: vSRX
Family: junos-es
Junos: 24.4R1-S2.9
JUNOS hsm [20250306.002422_builder_junos_244_r1_s2]
JUNOS OS Kernel 64-bit XEN [20250128.8676a19_builder_bsd15_244]
JUNOS modules [20250306.002422_builder_junos_244_r1_s2]
...
```

### Format Details

- First 4 lines are key-value with colon separator: `Hostname:`, `Model:`, `Family:`, `Junos:`.
- Remaining lines are package names with version in brackets: `JUNOS <package> [<version>]`.
- Per-node output in cluster.

---

## System: Log

**Commands:**

```
> show log [N]              # last N daemon (journald) lines, default 50
> show log <name> [N]       # last N lines of the /var/log/<name> syslog file
```

### Format Details

- With no filename, tails the `xpfd` journald unit. With a filename argument,
  reads `/var/log/<name>`; `<name>` is restricted to the operator-configured
  `system syslog file` allowlist (#4860) — a view-only (PermView) account cannot
  read arbitrary root-readable files under `/var/log`.
- The optional line count `N` defaults to 50. A non-positive or unparseable `N`
  is ignored and falls back to the default (Junos-compatible leniency).
- `N` is clamped to a fixed maximum (100,000 lines, the same `maxTailLines` cap
  as `| last N`) so a view-only account cannot request `show log 1000000000` and
  force `tail`/`journalctl` to emit — and the control plane to buffer in-process
  — an unbounded number of lines (#5069).

---

## Chassis Cluster: Status

**Command:** `show chassis cluster status`

```
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    GR  GRES monitoring             HW  Hardware monitoring
    IF  Interface monitoring        IP  IP monitoring
    LB  Loopback monitoring         MB  Mbuf monitoring
    NH  Nexthop monitoring          NP  NPC monitoring
    SP  SPU monitoring              SM  Schedule monitoring
    CF  Config Sync monitoring      RE  Relinquish monitoring
    IS  IRQ storm

Cluster ID: 1
Node   Priority Status               Preempt Manual   Monitor-failures

Redundancy group: 0 , Failover count: 1
node0  100      secondary            no      no       None
node1  1        primary              no      no       None

Redundancy group: 1 , Failover count: 1
node0  100      secondary            no      no       None
node1  1        primary              no      no       None

Redundancy group: 4 , Failover count: 1
node0  0        secondary            no      no       IF
node1  0        primary              no      no       IF
```

### Format Details

- **Monitor failure codes legend:** 4-space indent, 2-char code, 2 spaces, description. Two columns per line.
- **Cluster ID:** `Cluster ID: <N>`.
- **Column header:** `Node   Priority Status               Preempt Manual   Monitor-failures`
  - Node: 7 chars, Priority: 9 chars, Status: 21 chars, Preempt: 8 chars, Manual: 9 chars, Monitor-failures: variable.
- **RG header:** `Redundancy group: <N> , Failover count: <N>` (note space before comma).
- **Node entries:** Fixed columns matching header.
  - Status: `primary`, `secondary`, `hold`, `lost`, `disabled`.
  - Monitor-failures: `None` or failure code(s) like `IF`. `CF` (Config Sync
    monitoring) appears node-globally on every RG row when a received config-sync
    generation has stayed un-applied past the stale-duration grace (#6387) — a
    persistent config-apply failure that leaves the standby stuck
    `Transfer ready: no`. It is diagnostic only (also degrades `Node health` and
    adds a `Config sync: failing (<reason>)` line under `show chassis cluster
    information`); it never gates failover.
- Blank line between redundancy groups.

---

## Chassis Cluster: Interfaces

**Command:** `show chassis cluster interfaces`

```
Control link status: Up

Control interfaces:
    Index   Interface   Monitored-Status   Internal-SA   Security
    0       em0         Up                 Disabled      Disabled

Fabric link status: Up

Fabric interfaces:
    Name    Child-interface    Status                    Security
                               (Physical/Monitored)
    fab0    ge-0/0/7           Up   / Up                 Disabled
    fab1    ge-7/0/7           Up   / Up                 Disabled

Redundant-ethernet Information:
    Name         Status      Redundancy-group
    reth0        Up          1
    reth1        Up          2
    reth3        Down        4

Redundant-pseudo-interface Information:
    Name         Status      Redundancy-group
    lo0          Up          0

Interface Monitoring:
    Interface         Weight    Status                    Redundancy-group
                                (Physical/Monitored)
    ge-7/0/0          255       Up  /  Up                 1
    ge-0/0/0          255       Up  /  Up                 1
    ge-7/0/6          255       Down  /  Down             4
```

### Format Details

- **Sections:** Control, Fabric, Redundant-ethernet, Redundant-pseudo-interface, Interface Monitoring.
- Each section has its own column headers.
- `Status` shows `(Physical/Monitored)` as sub-header on the next line for fabric/monitoring.
- Status format: `Up   / Up` or `Down  /  Down` (variable spacing around `/`).
- Fixed-width columns within each section.
- Trailing spaces after values for column padding.
- A monitored interface whose live link-state is not yet available (the
  routing interface-monitor sweep has produced no result for its redundancy
  group) renders `Down`, not `Up` (#4480). The display never asserts a
  monitor is healthy on missing data — the same honest default the peer-owned
  (config-only) monitors already use. This is a display convention only; the
  failover decision reads the live link-state, not this fallback.

---

## Routing: Route Table (Brief)

**Command:** `show route` / `show route table inet.0`

The default display format. Shows all active routes across all routing tables.

```
inet.0: 72 destinations, 78 routes (72 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 4d 07:44:55
                       to table Comcast-GigabitPro.inet.0
10.0.100.0/24      *[BGP/170] 02:27:21, MED 0, localpref 100
                      AS path: 65500 I, validation-state: unverified
                    >  to 192.168.255.5 via st0.1
10.5.1.0/24        *[Direct/0] 1d 11:31:02
                    >  via reth1.51
10.5.1.1/32        *[Local/0] 1d 11:31:02
                       Local via reth1.51
192.168.0.0/24     *[Direct/0] 1d 11:31:02
                    >  via reth1.1
                    [Direct/0] 1d 11:31:02
                    >  via reth1.1
```

### Format Details

- **Table header:** `<table>: <N> destinations, <N> routes (<N> active, <N> holddown, <N> hidden)`.
- **Legend:** `+ = Active Route, - = Last Active, * = Both` — always printed after header, blank line follows.
- **Destination column:** Left-aligned, padded to ~19 chars. Long prefixes (IPv6) flow naturally.
- **Route markers:**
  - `*` = Both active and last active (most common).
  - `+` = Active only (another protocol was previously active).
  - `-` = Last active (now replaced by a better route).
- **Protocol/preference in brackets:** `[Static/5]`, `[BGP/170]`, `[Direct/0]`, `[Local/0]`.
- **Age:** Follows brackets. Format varies by duration:
  - `< 1h` → `MM:SS` (e.g. `05:32`)
  - `< 1d` → `HH:MM:SS` (e.g. `16:40:36`)
  - `1-6d` → `Nd HH:MM:SS` (e.g. `4d 16:40:36`)
  - `7d+` → `NwNd HH:MM:SS` (e.g. `2w4d 14:37:16`)
- **BGP attributes on same line:** `, MED 0, localpref 100`.
  - Separate line: `AS path: 65500 I, validation-state: unverified`.
- **OSPF attributes:** `, metric <N>` after age.
- **Next-hop lines:** Indented ~20 chars.
  - `>  to <nexthop> via <interface>` — best next-hop, `>` marker.
  - `   to table <table>` — route leak / next-table reference.
  - `   Local via <interface>` — local route (no `>` marker).
  - `   Reject` or `   Discard` — reject/discard route (no `>` marker).
- **Multiple routes** for same destination: first gets prefix, subsequent indented to bracket column.
- **ECMP:** Multiple `>` next-hop lines for the same route.

### Protocol Names and Default Preferences

| Source | Display Name | Default Preference |
|--------|-------------|-------------------|
| Directly connected | `Direct` | 0 |
| Local addresses (/32 or /128) | `Local` | 0 |
| Static routes | `Static` | 5 |
| OSPF internal | `OSPF` | 10 |
| DHCP/PPP learned | `Access-internal` | 12 |
| IS-IS L1 internal | `IS-IS` | 15 |
| IS-IS L2 internal | `IS-IS` | 18 |
| RIP/RIPng | `RIP` | 100 |
| Aggregate | `Aggregate` | 130 |
| OSPF AS external | `OSPF` | 150 |
| BGP | `BGP` | 170 |

### Table Naming Convention

| Table Name | Description |
|------------|-------------|
| `inet.0` | Default IPv4 unicast |
| `inet6.0` | Default IPv6 unicast |
| `<instance>.inet.0` | IPv4 unicast for routing instance |
| `<instance>.inet6.0` | IPv6 unicast for routing instance |

---

## Routing: Route Destination Lookup

**Command:** `show route <destination>`

Performs longest-prefix-match against ALL routing tables. Shows every route whose prefix contains the specified IP.

```
inet.0: 8 destinations, 8 routes (8 active, 0 holddown, 0 hidden)

10.0.1.0/24        *[Direct/0]
                    >  via trust0

ATT.inet.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)

10.0.1.0/24        *[Direct/0]
                    >  via trust0
```

### Modifiers

| Modifier | Behavior |
|----------|----------|
| `show route 10.1.2.3` | LPM: all routes containing this IP (default /32 for IPv4, /128 for IPv6) |
| `show route 10.0.0.0/8` | All routes contained within or equal to 10.0.0.0/8 |
| `show route 10.0.0.0/24 exact` | Only routes exactly matching /24 |
| `show route 10.0.0.0/16 longer` | Only routes with prefix length strictly longer than /16 |
| `show route 10.0.0.0/16 orlonger` | Equal to or longer than /16 |

---

## Routing: Route Summary

**Command:** `show route summary`

```
Router ID: 10.5.1.1

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 1014 at 2026-02-12 10:56:49 / 1013
    RIB routes                   : 1074 at 2026-02-12 11:07:40 / 1065
    FIB routes                   : 871 at 2026-02-13 09:49:44 / 838
    VRF type routing instances   : 0 at 2026-01-13 15:39:20

inet.0: 72 destinations, 78 routes (72 active, 0 holddown, 0 hidden)
              Direct:     34 routes,     28 active
               Local:     35 routes,     35 active
                 BGP:      8 routes,      8 active
              Static:      1 routes,      1 active

ATT.inet.0: 62 destinations, 68 routes (62 active, 0 holddown, 0 hidden)
              Direct:     33 routes,     27 active
               Local:     34 routes,     34 active
     Access-internal:      1 routes,      1 active
```

### Format Details

- **Router ID line.**
- **Highwater marks:** 4-space indent, label padded to ~35 chars, `: <N> at <timestamp> / <N>`. (xpf omits this section.)
- **Per-table summary:** Table header same as route table. IPv4 and IPv6 in separate sections (`inet.0` / `inet6.0`).
  - Protocol lines: right-aligned protocol name to 21 chars including colon, `: %7d routes, %7d active`.
  - Numbers right-aligned within 7 chars.
- **VRF tables** listed after main tables as `<instance>.inet.0` and `<instance>.inet6.0`.

---

## Routing: BGP Summary

**Command:** `show bgp summary`

```
Threading mode: BGP I/O
Default eBGP mode: advertise - accept, receive - accept
Groups: 6 Peers: 6 Down peers: 0
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
inet.0
                       8          8          0          0          0          0
inet6.0
                       1          0          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
192.168.255.1         65909       2714       2676       0      51    20:20:46 Establ
  inet.0: 3/3/3/0
  inet6.0: 0/0/0/0
192.168.255.5         65500        302        329       0     110     2:28:38 Establ
  inet.0: 2/2/2/0
```

### Format Details

- **Header lines:** Key-value pairs.
- **Table summary:** `Table` (left, ~15), `Tot Paths` (~10), `Act Paths` (~10), `Suppressed` (~11), `History` (~8), `Damp State` (~11), `Pending` (~8).
  - Table name on first line, counts on continuation line below.
- **Peer table header:** `Peer` (~25), `AS` (~8), `InPkt` (~10), `OutPkt` (~10), `OutQ` (~7), `Flaps` (~7), `Last Up/Dwn` (~12), `State|#Active/...`.
- **Peer entries:**
  - IP left-aligned ~25 chars.
  - AS right-aligned ~5 chars.
  - Counts right-aligned in their columns.
  - State: `Establ` (truncated `Established`), `Active`, `Connect`, `Idle`.
  - Per-table summary: 2-space indent, `<table>: <active>/<received>/<accepted>/<damped>`.

---

## Routing: ARP

**Command:** `show arp no-resolve`

```
MAC Address       Address         Interface                Flags
6a:56:98:81:8e:2d 10.5.1.160      reth1.51                 none
86:73:ed:47:e8:67 10.5.1.192      reth1.51                 none
4c:96:14:51:39:ae 30.17.0.2       fab0.0                   permanent
Total entries: 384
```

### Format Details

- **Column header:** `MAC Address       Address         Interface                Flags`
- **Columns:**
  - MAC Address: 17 chars (xx:xx:xx:xx:xx:xx), left-aligned + 1 space.
  - Address: 16 chars, left-aligned.
  - Interface: 25 chars, left-aligned.
  - Flags: `none`, `permanent`.
- **Footer:** `Total entries: <N>`.
- `no-resolve` flag prevents DNS lookups for addresses.
- **Note:** NOT per-node output. Single output (from active node).

---

## Pipe Filters

### `| match <pattern>`

Filters output to lines matching the pattern (case-sensitive grep):

```
> show route | match 0.0.0.0
0.0.0.0/0          *[Static/5] 4d 07:45:39
0.0.0.0/0          *[Access-internal/12] 4w4d 05:42:19, metric 0
0.0.0.0/0          *[Static/5] 4w4d 05:42:26
```

### `| except <pattern>`

Filters out lines matching the pattern (inverse grep):

```
> show interfaces terse | except down
```

Removes all lines containing "down" (case-sensitive).

### `| count`

Counts lines in output:

```
> show security flow session | count
Count: 12345 lines
```

(Note: this is slow on large outputs like full session tables.)

### `| no-more`

Disables pagination (like `| less` in Unix). Essential for non-interactive SSH.

### `| last <N>`

Shows last N lines:

```
> show log messages | last 20
```

`N` is clamped to a fixed maximum (100,000 lines) so an oversized operand
cannot force an unbounded allocation in the control plane (#5037); the
buffer also grows lazily, so it only ever holds `min(N, lines produced)`
lines regardless of how large `N` is.

### Combined Filters

Pipe filters can be chained:

```
> show route | match 0.0.0.0 | count
```

---

## Configuration Display

### `show configuration`

Permission was denied for the `claude` user on this vSRX. The standard format is:

```
security {
    log {
        mode stream;
        format sd-syslog;
        source-address 192.168.99.1;
        stream syslog-server {
            severity info;
            format sd-syslog;
            host {
                192.168.99.252;
                port 514;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy permit-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                    log {
                        session-init;
                        session-close;
                    }
                }
            }
        }
    }
}
```

### `show configuration | display set`

Flat set format:

```
set security log mode stream
set security log format sd-syslog
set security log source-address 192.168.99.1
set security log stream syslog-server severity info
set security log stream syslog-server format sd-syslog
set security log stream syslog-server host 192.168.99.252
set security log stream syslog-server host port 514
```

### `| display set | match <pattern>`

```
> show configuration | display set | match log
```

---

## Notes for xpf Implementation

### Key Differences to Address

1. **Cluster headers:** xpf is single-node, so no `node0:/node1:` headers needed (unless cluster mode).
   In cluster mode, should replicate the `nodeN:` + 74-dash separator format.

2. **Session format:** xpf currently has a different format. Should match:
   - `Session ID: <id>, Policy name: <name>/<index>, HA State: Active, Timeout: <N>, Session State: Valid`
   - `  In: <src>/<port> --> <dst>/<port>;<proto>, Conn Tag: 0x0, If: <iface>, Pkts: <N>, Bytes: <N>, `
   - Note the trailing comma+space on In/Out lines.

3. **Policy format:** xpf should use the 2-space/4-space indent hierarchy.
   - `From zone:` header with no indent.
   - Policy entries at 2-space indent with comma-separated metadata.
   - Field values at 4-space indent.

4. **NAT rules:** The field-label alignment (padding to ~27 chars before colon) is distinctive.
   Multi-zone continuation lines align at the colon position.

5. **Route table:** The `*[Protocol/preference]` format with `>` best-nexthop marker is critical.
   Age format: `Xd HH:MM:SS` for days, `HH:MM:SS` for hours, or `Xw Xd HH:MM:SS` for weeks.

6. **Interface terse:** Fixed column positions are important for pipe filter compatibility.

7. **BGP summary:** `Establ` is truncated from `Established`. The per-table `active/received/accepted/damped`
   format under each peer is distinctive.

8. **Screen IDS:** Simple two-column table with name and value.

9. **ALG status:** Single global output (not per-node), 2-space indent.

10. **IPsec SAs:** `<`/`>` direction markers, algorithm format `ESP:<enc>/<auth>`.

11. **Policy hit-count:** Tabular format with Index, From zone, To zone, Name, Count, Action columns.

12. **Security log:** Structured syslog format (SD-SYSLOG) with `RT_FLOW` event types.
    Key fields: source-address, source-port, destination-address, destination-port,
    nat-source-address, nat-source-port, nat-destination-address, nat-destination-port,
    protocol-id, policy-name, source-zone-name, destination-zone-name, session-id-32.

### Trailing Spaces / Padding

Junos often pads values with trailing spaces to maintain column alignment. This is visible
in fields like `Policy configurable: Yes  ` and in tabular outputs. While not strictly
necessary for correctness, matching this improves compatibility with scripts that parse
fixed-width columns.
