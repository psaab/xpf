# xpf feature coverage

xpf replicates the Juniper vSRX feature set on a Rust AF_XDP userspace
dataplane driven by a Go control plane. vSRX parity tracking lives in
[`feature-gaps.md`](feature-gaps.md) and [`vsrx-gaps.md`](vsrx-gaps.md);
the userspace dataplane admission boundary is in
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

## Firewall & security

- **Zone-based policies** with stateful inspection, address books,
  application matching (multi-term apps), global policies, filtered
  session clearing.
- **NAT**: source (interface + pool, userspace-v2 address-persistent),
  destination (with hit counters), static 1:1 (with optional
  `match destination-port` + `mapped-port` per-port forwarding, #2491),
  NAT64, NPTv6 (RFC 6296 stateless prefix translation).
- **Dual-stack**: IPv4 + IPv6, DHCPv4/v6 clients, embedded Router
  Advertisement sender (replaces radvd), SLAAC.
- **Screen/IDS**: 16 checks (land, SYN flood, ping of death, teardrop,
  winnuke, ip-sweep, port-scan, SYN-FIN, no-flag, FIN-no-ACK, syn-frag,
  source-route-option, icmp-flood, udp-flood, icmp-fragment, limit-session)
  — each enforced in the dataplane; 15 carry a dedicated per-reason drop
  counter (`SCREEN_REASON_DROP_COUNT` in userspace-dp/src/screen/mod.rs,
  session-limit-src/dst folded to one) and icmp-fragment folds to the
  aggregate counter. Plus SYN cookie flood
  protection (userspace-minted/validated SYN-ACK cookies replied through
  the AF_XDP TX path). **SYN-flood sub-thresholds (#3315)**:
  `source-threshold` / `destination-threshold` are per-source-IP /
  per-destination-IP SYN/s caps enforced by a per-zone count-min sketch of
  `RateCounter`s (no eviction, fail-closed over-count). The per-destination
  cap is primary and spoof-resistant (all SYNs to a victim land in the same
  sketch cells) and runs even when the zone is SYN-cookie active; the
  per-source cap is secondary and skipped while the zone is cookie-active
  (the cookie governs the spoofed-flood regime). `alarm-threshold` raises a
  log-only, ≤1/sec/zone NOTICE alarm event below `attack-threshold` without
  dropping. Memory per configured zone per worker is ~192 KiB
  (`ROWS*DST_COLS + ROWS*SRC_COLS` × 16 B); the Go compiler emits a
  commit-time advisory if `attack-threshold / source-threshold` exceeds
  ~1000 (the regime where the sketch can over-throttle). `timeout` is
  ENFORCED (#3527, the #3315 follow-up): it is NOT a screen-rate control —
  it maps to the per-zone half-open TCP session window (`tcp_opening_ns`,
  20 s default), crossing the wire as `ScreenProfileSnapshot.syn_flood_timeout`
  and applied as a per-ingress-zone override (`session_opening_overrides` →
  `SessionTable::set_opening_overrides`), so a bare-SYN session in a screened
  zone reaps on the operator's window instead of the global default. It is
  node-local config-derived state (re-derived per HA node, never on the
  session-sync wire); the #3315 accepted-but-inert commit warning is removed.
  **Flood shaper token bucket (#3607)**: the ICMP/UDP flood per-zone
  aggregates, the standby SYN-cookie ACK validation budget, and the SYN-flood
  aggregate DROP path when `syn-cookie` is OFF use a monotonic-ns fixed-point
  `TokenBucket` (`screen/rate.rs`, 16 B, integer refill, no per-packet clock
  read) so a sustained sender parked at exactly the threshold is admitted at
  the configured rate instead of being throttled to ~0 after the first second
  (the fixed-window over-throttle), while a sub-ms burst is still bounded to
  the capacity (#2937). The SYN-flood aggregate that ACTIVATES cookies when
  `syn-cookie` is ON, the alarm-threshold measurement, and the #3315 sketch
  deliberately stay on the count-all sliding-window `RateCounter` (there
  "admitted" means "skip the cookie / alarm / per-IP cap").
- **Dynamic-neighbor map cap (#5673, pre-policy DoS bound)**: source-address
  learning runs on RX (`stage_parse_flow_and_learn`) BEFORE screen/policy
  admission, so a spoofed-source flood on an untrusted segment could otherwise
  grow the shared `dynamic_neighbors` map by one entry per distinct fake
  source (memory) and serialize every worker on the 64-shard `with_all_shards`
  bulk lock (CPU) WITHOUT passing any policy check. The map now enforces a
  per-shard cap (`MAX_DYNAMIC_NEIGHBORS_PER_SHARD`, aggregate
  `MAX_DYNAMIC_NEIGHBORS`, `afxdp/sharded_neighbor.rs`): a NEW data-path learn
  whose target shard is full is refused (the packet still forwards — a
  learn-path guard, not a packet filter), while an UPDATE to an already-learned
  neighbor (a real MAC failover) and the authoritative control-plane /
  on-demand-resolver installs are never capped. The RX-learn caller
  short-circuits the bulk lock once its pre-check sees every candidate key
  new-and-at-cap, so a steady flood no longer serializes the shards. Refusals
  are surfaced as `xpf_userspace_dynamic_neighbor_learn_cap_drops_total`.
- **Firewall filters**: policer (token bucket + three-color), lo0 filter,
  flexible match, port ranges, hit counters, logging, forwarding-class
  DSCP rewrite.
  - **`source-address 0.0.0.0/0` + `source-prefix-list X except`
    composes (#4338).** The canonical Junos "match any EXCEPT the
    management hosts, then reject" lockdown idiom — a match-any positive
    address (`0.0.0.0/0` / `::/0`) alongside an `except` prefix-list in
    one direction — is ACCEPTED at commit (both inet and inet6). The
    match-any is the universe, so `any AND NOT X` reduces to the
    sole-`except` representation, and the userspace lowering
    (`ResolveFilterPrefixListAddrs`) drops the redundant `0/0` and emits
    the term as `except=true` over X ("match every address NOT in X").
    A SPECIFIC positive literal (e.g. `10.0.0.0/8`) or a positive
    prefix-list combined with an `except` list is still REJECTED — that
    mixed shape would need both a positive and a negated set in one
    direction, which the boolean-inversion matcher cannot represent, so
    it would fail open for discard/reject (#3359). The #3359 reject
    message no longer falsely claims "Junos rejects this"; it explains
    the xpf single-term representability limit instead.
  - **No-match default is implicit ACCEPT (deliberate divergence from
    Junos, #3295).** A packet matching no term in a stateless firewall
    filter (interface input/output and lo0) is ACCEPTED, whereas Junos
    stateless filters carry an implicit final discard. xpf keeps
    implicit-accept on purpose: flipping the no-match default to discard
    would blackhole the classify-and-pass OUTPUT-filter idiom (the CoS
    `bandwidth-output` allowlist on `reth0 unit 80 ... filter output`),
    violating the "keep GOOD" doctrine (#2124/#3261). For Junos-style
    deny-by-default, append an explicit final `term <last> { then
    discard; }`. A commit WARNING is emitted for any filter attached to
    an interface/lo0 hook that has no terminal catch-all term. See
    `userspace-dp/src/filter/README.md` and
    `docs/research/3295-filter-failopen/plan.md`.

## Flow processing

- **TCP MSS clamping** in the userspace AF_XDP dataplane (all-tcp,
  ipsec-vpn, and GRE gre-in/gre-out).
- **Path MTU Discovery** on the forwarding path: a forwarded frame that
  exceeds the egress interface MTU and is not transparently TCP-segmented
  (UDP, ICMP, ESP, GRE, TCP seg-miss) triggers an ICMPv4 Fragmentation
  Needed (type 3 code 4, next-hop MTU) for IPv4 DF / ICMPv6 Packet Too
  Big (type 2, MTU) for IPv6 back to the sender, instead of a silent MTU
  drop (#2301). RFC 792/4443 suppression applies (no reply to inbound
  ICMP errors or non-first fragments). NAT64 already translates
  PTB↔Frag-Needed across the boundary (#2219). The generated PTB is
  classified by its OWN egress 5-tuple through the shared
  `classify_generated_reply` output classifier (#2328, #2238 contract
  parity with the Time Exceeded / policy-reject / SYN-cookie generators):
  an output firewall filter `then discard` / CoS forwarding-class / DSCP
  rewrite keyed on the generated ICMP fires, and a parse failure of the
  built bytes fails CLOSED (drop + `generated_reply_classify_parse_errors`).
  Output-filter drops of the PTB land on `ptb_output_filter_drops`.
- **Forwarded TCP over egress MTU is re-segmented, not PTB'd — including
  DF-set (#1199, #6125).** An oversize *whole* (unfragmented) transit TCP
  datagram whose L3 length exceeds the egress interface MTU is transparently
  re-segmented into within-MTU TCP segments
  (`forwarded_tcp_may_need_segmentation` → `tx/tcp_segmentation.rs`),
  regardless of the IPv4 Don't-Fragment bit. This is a **deliberate
  delivery-over-strict-PMTUD choice**: each output is an independent whole IP
  datagram ≤ MTU (no IP fragmentation, so it is DF-compliant on the wire) and
  it guarantees delivery even where ICMP Frag-Needed is filtered (a common
  PMTUD black-hole). The tradeoff is that a DF sender's PMTUD is not driven by
  re-segmentation — it never learns the real path MTU the way it would from a
  Frag-Needed reply. The PTB path (the bullet above) fires only for the
  datagram classes that are NOT transparently TCP-segmented (UDP, ICMP, ESP,
  GRE, and the TCP seg-miss cases: any IP fragment, or an unknown egress MTU).
  #5159 made this uniform — master previously PTB'd DF TCP only in the
  sub-1280 MTU gap, an artifact of the removed `.max(1280)` floor, not a
  design choice. Adjudicated in #6125: the delivery posture is retained;
  strict PMTUD (DF → PTB) would require an explicit operator config knob.
- **ALG control**, allow-dns-reply, allow-embedded-icmp.
- **Configurable timeouts** (per-application inactivity).
- **Session management**: filtered clearing, idle time tracking, brief
  tabular view, aggregation reporting.

## Routing & networking

- **FRR integration**: static, OSPF, BGP, IS-IS, RIP, ECMP multipath,
  export/redistribute.
- **VRFs** with inter-VRF route leaking (next-table + rib-group). The
  `interface-routes rib-group` import into the main table leaks each source
  instance's connected (interface) routes per-prefix so a specific imported
  prefix wins over a main-table default route — see
  `docs/rib-group-route-leaking.md` (#3876).
- **GRE tunnels**, XFRM interfaces, PBR (policy-based routing).
- **Probe-driven WAN failover** (`services ip-monitoring` preferred-route
  injection, #1827).
- **VLANs**: 802.1Q tagging, trunk ports.
- **IPsec**: strongSwan config generation, IKE proposals, gateway
  compilation.
- **Full interface management**: xpfd owns ALL interfaces — renames via
  `.link` files, configures addresses/DHCP via `.network` files, brings
  down unconfigured interfaces (see
  [`network-topology.md`](network-topology.md) and the interface-management
  notes in [`critical-patterns.md`](critical-patterns.md)).

## High availability

- **Chassis cluster** with ~60ms failover (30ms VRRP intervals).
- **Native VRRPv3**: Go state machine, AF_PACKET, per-instance sockets,
  IPv6 NODAD, 30ms RETH advertisements, async GARP burst, single-interface
  tracking (nested `track-interface <if> priority-cost <n>`). Tracking
  follows the configured interface NAME (Junos semantics) and is robust to a
  runtime kernel rename: the link watcher keys rename detection on the stable
  ifindex, so when the tracked name is renamed away (a single `RTM_NEWLINK`
  with the same ifindex but a new name, no `RTM_DELLINK`) the instance demotes
  rather than holding stale "up" state (#2944). The IP address owner (priority
  255) always preempts a lower-priority master irrespective of the `no-preempt`
  flag (RFC 5798 §6.1, #4116) and is exempt from track-down demotion.
  **VRRP `authentication-type` / `authentication-key` are REJECTED at commit**
  (#4288): RFC 5798 VRRPv3 removed authentication (VRRPv2 had it), so the
  native dataplane cannot authenticate adverts. Accepting the auth config
  silently would be a false-security posture — an operator would believe
  mastership is protected when a rogue host can still hijack it. The compiler
  hard-rejects the statement on operator commit. On the tolerant load /
  peer-sync path it FAILS CLOSED (#5834): the auth-carrying vrrp-group is
  DROPPED from the AST before compilation and a loud warning is recorded, so a
  persisted or peer-synced legacy config never leaves an unauthenticated group
  ACTIVE claiming the VIP while the operator required authentication. Only the
  VRRP VIP claim is dropped — the base interface address survives, and no-brick
  is preserved (only the one group is dropped, not the whole config). The
  operator's REQUIRE-auth intent wins over availability
  (`validateVRRPAuthenticationAST`, `pkg/config/compiler_interfaces.go`).
- **Redundancy-group IP monitoring** (`chassis cluster redundancy-group N
  ip-monitoring`): each configured target is ICMP-echo probed every poll,
  driving weight-based failover. **`global-threshold` gates `global-weight`
  (vSRX semantics, #5271):** when `global-threshold` is configured (> 0), each
  unreachable target's `weight` accumulates into a per-RG cumulative
  reachability-loss sum, and a **single** deduction of `global-weight` is
  applied to the RG only while that cumulative sum is ≥ `global-threshold`
  (cleared when it falls back below). Below the threshold **no** election debt
  is applied, so a single (or otherwise sub-threshold) probe loss cannot move
  services — closing the split-brain / premature-failover risk of the previous
  behavior, which deducted every failed target's weight independently and
  ignored `global-threshold` entirely. A target with no explicit `weight`
  contributes `global-weight` to the cumulative sum (the same effective weight
  it would subtract in independent mode). Each poll **reconciles** the RG's
  installed ip-monitor debts to exactly what the current mode + dampened
  reachability dictate (firing only on a change), so a live `global-threshold`
  edit while a target is down is correct in both directions: enabling it drops
  the stale per-target debts in favor of the single aggregate deduction (else
  they would coexist and over-demote the RG → spurious failover), and disabling
  it (or removing `ip-monitoring`) on a **kept** group releases the stale
  aggregate deduction (else the RG stays stuck demoted), and a `global-weight`
  value change while the RG stays crossed re-installs the deduction at the new
  amount (else the stale amount would persist until the RG clears and
  re-crosses). An already-down target produces no dampening transition, so this
  cleanup relies on the reconcile, not transition edges; the reconcile fires
  `SetMonitorWeight` only when the installed value actually changes, so steady
  state is churn-free (#5271).
  When `global-threshold` is unset (0),
  the historical **independent per-target** behavior is preserved exactly: each
  unreachable target subtracts its own `weight` (or `global-weight` when the
  per-target weight is unset) immediately. The probe **validates the echo
  reply against the request** before counting it as reachable — the responder
  source must equal the probed target, the ICMP identifier must equal the
  one the request used, and the sequence must match the value just sent. The
  probe uses a Linux SOCK_DGRAM ICMP socket, where the kernel overwrites the
  identifier with the socket's local port and demuxes replies by it, so the
  matched identifier is that port (per-probe unique), not a fixed constant;
  the sequence is stamped per probe. A reply failing any check is ignored, so
  a stray or spoofed echo reply cannot mask a genuinely down path and
  suppress the intended failover (#4156). Each poll probes a per-cycle
  immutable snapshot of every target (across all RGs) **concurrently** through
  a bounded worker pool (`ipProbeConcurrency`) under an overall cycle deadline,
  then applies the results **serially in stable RG/target order** — so a sweep
  of N unreachable targets completes in roughly one probe deadline per
  `ipProbeConcurrency` targets instead of N × the 800 ms per-socket deadline
  (an all-down 64-target sweep no longer blocks ~51 s, starving later RGs and
  delaying failover detection). The failover decision + weight accumulation is
  byte-identical to the old serial path; only the probe I/O is parallelized.
  `Stop()` cancels in-flight probe sockets so shutdown does not wait out a
  sweep, and a cycle that exceeds its deadline records
  `IPMonitorCycleOverruns` and defers (never fails) its unfinished targets
  (#5301). `pkg/cluster/monitor.go`.
- **Bondless RETH**: VRRP on physical member interfaces, per-node virtual
  MAC (`02:bf:72:CC:RR:NN`), no Linux bonding required.
- **VRRP L2 identity is a deliberate deviation from RFC 5798 (#5091).** The RFC
  specifies a *shared* virtual-router MAC — `00-00-5E-00-01-{VRID}` for IPv4 and
  `00-00-5E-00-02-{VRID}` for IPv6 — which both routers use, so the virtual
  router's L2 identity survives a failover untouched. xpf instead derives a
  **per-node** locally-administered MAC (`02:bf:72:CC:RR:NN` = cluster, RG,
  node) and advertises from the physical member interface. Two consequences an
  operator must plan for:
  - **Failover changes the L2 identity**, so recovery depends on the
    gratuitous-ARP burst (IPv4) and unsolicited neighbour advertisements
    (IPv6) reaching peers and updating switch FDBs, rather than on the MAC
    simply not moving. That path is engineered rather than best-effort —
    `becomeMaster` sends GARP asynchronously with a forced burst after a MAC
    change (#2081) — but it is still an update-the-peers mechanism, not an
    identity-preserving one.
  - **xpf cannot form a virtual router with a third-party VRRP speaker.** The
    protocol is on the wire, but a standards-conformant peer expects the shared
    MAC. Treat RETH VRRP as an xpf-to-xpf mechanism between the two chassis of
    one cluster, not as general VRRP interop.

  The reason is not oversight: on this platform both nodes' member interfaces
  routinely share an L2 domain — SR-IOV VFs from the same PF, or two ports on
  the same physical switch — and a genuinely shared MAC there produces FDB
  conflicts and MAC flapping as the switch sees one address on two ports. The
  per-node MAC trades RFC conformance for a deterministic L2 topology. See
  `RethMAC` in `pkg/cluster/reth.go`.
- **Session sync**: incremental 1s sweep + ring buffer + GC delete
  callbacks, TCP on fabric link.
- **Config sync**: primary → secondary with `${node}` variable expansion,
  reverse-sync on reconnect. Each push carries a monotonic config generation
  and applies through a single-consumer ordered queue, so a rapid commit pair
  cannot leave the standby on the older config (#3931).
- **IPsec SA sync**: shared IKE/ESP state across cluster nodes.
- **Dual fabric links**: independent fab0/fab1 for redundancy (no
  bonding).
- **Fabric cross-chassis forwarding**: redirects to peer when FIB fails
  for synced sessions — prevents TCP death on VRRP failback (see
  [`fabric-cross-chassis-fwd.md`](fabric-cross-chassis-fwd.md)).
- **Dataplane watchdogs**: userspace heartbeat fails closed on
  daemon/helper failure; config naming the retired `ebpf` backend runs in
  config-only mode until updated.
- **Readiness gate**: per-RG readiness (interfaces + VRRP) + hold timer
  gates election.
- **Planned shutdown**: near-instant takeover (priority-0 burst);
  failback ~130ms.
- **ISSU**: in-service software upgrade with rolling deploy.
- **RA lifecycle**: goodbye RAs (lifetime=0) on failover/startup to
  prevent stale IPv6 ECMP routes.

## Observability

- **Syslog**: facility/severity/category filtering, structured RT_FLOW
  format, TCP/TLS transport, event mode local file. A `system syslog file`
  destination is written to `/var/log/<name>` via an rsyslog drop-in; its
  `archive` block (rotation, retention, `start-time`, `transfer-interval`,
  `archive-sites`) is accepted for Junos compatibility but **not implemented**
  and raises a commit advisory saying so (#7146) — xpf does not rotate or
  archive these files.
- **NetFlow v9 / IPFIX**: 1-in-N sampling (IPFIX advertises the rate to
  collectors via a sampler Options Template — Set ID 3, template 258,
  `selectorAlgorithm`/`samplingPacketInterval`/`samplingPacketSpace`, scoped by
  the group's Observation Domain ID; #3748. Note: xpf samples 1-in-N at
  session-record granularity, so a collector scales the record COUNT by N but
  must not multiply per-record volume — each record carries the full
  per-session byte/packet counts. Active-timeout interim records are deferred,
  #3748 sub-part a), per-collector write-health
  (`show flow-monitoring statistics`, REST `/api/v1/services/flow-exporters`,
  `xpf_flow_export_collector_*` Prometheus metrics — a collector going
  unreachable surfaces write_failures + a state-change warn, #2464).
  Per-collector source-address bind: a `flow-server <addr> {
  source-address <src>; }` pins THAT collector's local bind independently,
  so two collectors of the same family can each dial with their own
  source; a bare `source-address` under `output` is the per-output
  default every flow-server inherits. The effective source is resolved
  per collector, not collapsed to one family-wide value (#3745), and is
  surfaced in every health surface (`... source <src>` in the CLI,
  `source_address` in the REST JSON, and the `source` label on the
  `xpf_flow_export_collector_*` metrics). The Prometheus family is also
  labeled by `instance` and `template` (#3741): the daemon returns one
  health row per template group / family-disjoint sampling instance, so
  two groups that share a single collector address stay distinct series —
  without those labels the rows collide on an identical `{protocol,
  collector, source}` labelset and Prometheus either rejects the duplicate
  (scrape error) or silently collapses the failing group.
- **Prometheus metrics** (`/metrics` endpoint). Three kernel-nftables surfaces
  are scraped independent of dataplane load (emitted before the dataplane gate,
  so they stay visible in a config-only / degraded boot):
  `xpf_host_inbound_kernel_denies_total{zone,family}` (host-inbound catch-all
  DROP counters), `xpf_lo0_counter_hits_total{counter}` (#4422 — lo0
  loopback input-filter `then count` hits from the `inet xpf_lo0` chain,
  DISTINCT from the userspace fast-path `xpf_filter_hits_total`), and
  `xpf_host_inbound_icmp_nd_accept_total{type}` (#4759 — the GLOBAL ICMP-error /
  ND accept rules on the `inet xpf_hostinbound` chain, counted per type-class
  `icmp6_nd` / `icmp6_error` / `icmp4_error`; AGGREGATE across all zones because
  those accept rules are global, not per-zone). Policy-based
  routing (filter-based-forwarding) build health is exported as the
  config-derived gauges `xpf_pbr_rules_installed` and `xpf_pbr_degraded_terms`
  (#4422 — the count of routing-instance filter terms dropped from the kernel
  FBF mirror by the fail-closed under-steer rule; see `docs/multi-wan.md`).
- **SNMP**: system + ifTable MIB. Community `clients` source-IP restriction
  ENFORCED (#4289): `snmp community <c> clients { <prefix> [restrict]; }`
  scopes a community to the listed source prefixes — a v2c query from a source
  outside the allowlist is dropped (longest-prefix match, `restrict` denies; a
  community without `clients` is allow-all). Enforced in the agent v2c path
  (`pkg/snmp/agent.go` `handleV2cPacket` → `SNMPCommunity.AllowsSource`).
  Same-name `community <c>` blocks MERGE (#5472): two hierarchical
  `community public { ... }` siblings accumulate their `clients`/authorization
  into one entry before the immutable client-prefix cache is built, so a later
  duplicate with NO `clients` cannot overwrite an earlier block and silently
  erase its allowlist (an empty allowlist reads as allow-all → fail-open).
  A malformed `clients` token is REJECTED at commit (#4834) and, on the tolerant
  load / peer-sync path, QUARANTINES the affected community to deny-all (#5833):
  a mistyped `restrict` (e.g. `0.0.0.0/0 restric`) detaches from its prefix and
  used to leave a surviving unrestricted `0.0.0.0/0` allow, so on
  restart/upgrade/peer-sync the community answered from every source. A
  LEADING/orphan `restrict` — `restrict` BEFORE any prefix (`clients restrict
  0.0.0.0/0`, invalid-Junos ordering) — was likewise silently dropped, leaving
  the following prefix a plain allow (#5898); `parseSNMPClients` now records that
  orphan `restrict` as a client entry so it is flagged malformed on the SAME
  path. The lenient path compiles the affected community fail-CLOSED
  (`snmpQuarantineClientNets` → deny-all) instead of fail-open, while the rest of
  the config loads with a warning; the strict commit path rejects it outright,
  naming the token. A well-formed `<prefix> restrict` is unaffected.
  Trap-group `categories` ENFORCED (#5522): `snmp trap-group <g> categories
  [ <cat> ]` scopes which notification categories a group receives — a link
  up/down trap (category `link`) is dispatched to a group only if the group
  lists `link` (or has no `categories` stanza = all categories, the Junos
  default). Enforced in `pkg/snmp/traps.go` `groupWantsCategory`
  (`sendLinkTraps` dispatch gate). Before #5522 the compiler recognized
  `categories` but DISCARDED it, so a group scoped to exclude a category still
  received every trap (a silent filter bypass; concrete instance under #4313).
- **RPM probes**, dynamic address feeds.
- **Dataplane buffer utilization** (`show system buffers`): AF_XDP
  UMEM/TX-ring capacity, CoS queued-byte capacity, helper-published
  session-table and flow-cache capacity.
- **LLDP**: link layer discovery protocol.

## Management

- **Interactive CLI**: Junos-style prefix matching, tab completion, `?`
  help, pipe filters (`| match`, `| count`, `| except`).
- **Remote CLI**: `cli` binary connects via gRPC with full tab/`?` parity.
- **gRPC API**: 48+ RPCs (config, sessions, stats, routes, IPsec, DHCP,
  cluster).
- **REST API**: HTTP on port 8080 (health, Prometheus, config). Broad
  surface parity with gRPC, but NOT parity of the cluster guards: the
  configure-mode entry point (`pkg/api/config.go`) has no RG0 check,
  where gRPC guards on `IsLocalPrimary(0)` and the interactive CLI has
  its own check (#6890).
- **Config management**: candidate/active with commit model, 50 rollback
  slots, `load override`/`load merge`, `show | display set`.
- **Configure mode protection**: the RG0 primary is the intended config
  authority, and on a secondary **whose read-only gate is armed** the
  configstore rejects every user mutation (`ErrClusterReadOnly`) at every
  entry point. Arming happens only on an RG0 transition
  (`applyRG0OwnershipTransition`) and `clusterReadOnly` starts `false`,
  so a node that cold-starts as secondary and never transitions is NOT
  gated — see `pkg/configstore/README.md` "Cluster read-only gate" and
  #6890 (#6889 is the dropped-event variant).
- **DHCP server**: Kea integration with lease display; static / fixed /
  reserved host bindings (`static-binding <mac> { fixed-address; host-name; }`
  under `dhcp-local-server`/`dhcpv6-local-server` → Kea per-subnet
  `reservations`, HA-consistent via config-sync — #2243).
- **DHCP relay**: Option 82 support.
- **Event engine**: event-driven automation.

## Userspace dataplane capability matrix

The userspace dataplane covers the transit feature set in native Rust.
The exact admission boundary is documented in
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

| Capability | Userspace AF_XDP (the runtime path) |
|------------|-----------|
| Stateful forwarding | Yes |
| Zone + global policies | Yes |
| Application matching | Yes |
| Source NAT (interface + pool) | Interface and pool mode yes; userspace `address-persistent` uses a documented userspace-v2 seeded FxHash selector (#2349 replaced the prior SHA-256; see `docs/userspace-dataplane-gaps.md` for the authoritative algorithm/contract). Non-HA per-pool `persistent-nat` lease reuse and pool exhaustion counters are implemented in helper-local runtime state; HA/restart persistence and cross-backend new-flow parity remain outside the current contract |
| Destination NAT | Yes; `match destination-address` accepts a host (bare IP, /32, /128), a bracket list of hosts (#2395, one table entry per host), AND a non-host CIDR prefix (#3164). A prefix DNAT (`match destination-address 198.51.100.0/24`) translates EVERY host in the block to the rule's pool (many:1) — the Go builder carries the canonical prefix on the additive `destination_prefix` wire field and the Rust `DnatTable` installs a longest-prefix-match entry. Overlapping prefixes resolve by longest match, and an exact-host entry (the longest possible prefix) always wins over a covering block via the O(1) exact-host fast path. Block-mapping semantics (a 1:1 host-N->host-N offset map) remain out of scope. The #3029 commit-time reject of a multi-host prefix destination (fail-closed against the old silent-narrowing) is removed now that the prefix is honored. Whole-block local-address registration (proxy-ARP/ND) is bounded: a block at or below 4096 usable hosts (a v4 /20 or longer) is expanded host-by-host; a larger block registers only its network base and must be ROUTED to the firewall (the DNAT match itself is independent of this set, so a large block still translates fully). **Bare `match destination-port` matches tcp AND udp (#6462):** a destination-port rule with no `match protocol` installs BOTH a tcp- and a udp-keyed entry (Junos matches a bare destination-port across both), so UDP services behind a port-based DNAT (DNS, SIP, VPN) are translated — before #6462 the builder defaulted to tcp-only and UDP to the VIP:port was silently NOT translated (a silent outage plus an observability lie: `show security nat destination` still listed the rule). An explicit `match protocol` is honored verbatim; a protocol-less rule with no destination-port stays a single match-any entry. Two explicit protocol rows (never PROTO_ANY, which would over-match ICMP/other) share the rule's single hit counter. **Static NAT takes precedence over destination NAT (#6473, Junos parity):** the inbound pre-routing evaluation consults static NAT FIRST and falls back to the DNAT pool table only on a static miss — the Junos first-packet order (static NAT → destination NAT → route → policy → reverse static → source NAT; "static NAT rules take precedence over destination NAT rules"), and the same order the outbound direction already used (static SNAT before pool SNAT). Before #6473 the pool table was consulted first, so an external address covered by BOTH a static rule and a DNAT pool rule took the pool translation and the static mapping was silently shadowed (policy, written for the static tuple, diverged from the delivered tuple). Where the static rule does NOT match (e.g. a port-specific static rule and a packet to another port) the pool still applies. Migration: a deployment that RELIED on the DNAT-first shadowing (a pool rule intentionally overriding a co-covering static rule) changes behavior — the static mapping now wins for every packet the static rule matches; make the override explicit by narrowing the static rule's scope (`from` zone / interface / routing-instance, or `match source-address` / `match destination-port`) or by removing the overlap. **Unspecified base excluded (#5658, security):** a `/0` DNAT match prefix (`0.0.0.0/0` / `::/0`) is a legitimate "all routed destinations" rule and is PRESERVED for routed traffic (the pre-routing lookup keys on the destination directly), but its canonical network base is the UNSPECIFIED address, which `destination_ips_scoped` no longer projects into `local_v4`/`local_v6` — registering `0.0.0.0` / `::` as a firewall-local / proxy-ARP / ND-owned address would perturb local-delivery classification and proxy-ARP for the unspecified address. Only the base push was affected; host expansion for a `/0` is already skipped by the 4096-host bound |
| Static NAT (1:1) | Yes; optional per-port forwarding (#2491) — `match destination-port <port>` + `then static-nat prefix <ip> mapped-port <port>` translates the destination port on the inbound DNAT and un-translates the source port on the reverse SNAT, so several services can share one external IP. A port-less rule is the whole-address 1:1 fallback; both can coexist on one external IP. Per-port forwarding is HOST-scope only: a subnet block map (`static-nat prefix <subnet>`, #3031) is address-only 1:1 and a `match destination-port` / `mapped-port` combined with a block prefix is REJECTED at commit (`StaticNatBlock` has no port fields, so the port mapping would be silently dropped into an all-port whole-subnet NAT, #3202). **Zero-length block rejected (#5658, security):** a block pair whose prefix length is `/0` on both sides (`0.0.0.0/0 <-> 10.0.0.0/0`, or `::/0 <-> ::/0`) remaps the ENTIRE address family 1:1 — the host mask for a `/0` is all-ones, so `contains()` matches every address and the equal-length offset remap preserves all host bits, an identity translation that, installed in the ordered block scan, SHADOWS every narrower static/DNAT rule while claiming to translate (traffic hijack / blackhole / policy bypass). It is HARD-REJECTED at strict commit (`validateNATHostMaskStrict`, downgraded to a warning on the tolerant load / peer-sync path) and DROPPED with a bounded parse-error diagnostic by the Rust `StaticNatTable::from_snapshots` backstop. The reject is zero-length ONLY (no arbitrary non-zero floor): a legitimate large-but-intentional equal-length block (`/8`, `/64`, …) still commits, preserving documented subnet static-NAT parity. Applies identically to IPv4 and IPv6. The inbound DNAT lookup evaluates the `from zone` constraint PER CANDIDATE (#2864): a port-specific entry whose zone does not match the packet's ingress zone falls through to the whole-address `(dst_ip, None)` entry (which is then zone-checked on its own) instead of short-circuiting to no-DNAT — the port-specific entry still wins when its zone matches. The reverse SNAT lookup is symmetrically gated on the EGRESS zone (#2871): static NAT is bidirectional, so the reverse (source) translation applies only when the packet egresses TOWARD the rule's configured `from zone` (the same per-candidate zone check as DNAT, but on the destination/egress zone instead of the ingress zone). An empty `from zone` ("any zone") still matches every egress zone. Without this gate an outbound packet sourced from a static-NAT internal IP but destined for ANOTHER internal zone was source-translated to the public external IP — an east-west cross-zone leak. Scope-differentiated (split-horizon) rules that share the same `(external_ip, match-port)` key but differ by `from zone` / `from interface` / `from routing-instance` / `match source-address` now COEXIST (#3605): each map key holds a `Vec` of entries (mirroring the #3031 block Vec and the sibling `DnatTable`), so the same public address can translate to a different internal host per ingress context. Before #3605 the single-entry map silently overwrote all but the last such rule (last-write-wins), so a packet hitting a lost rule's scope was forwarded UNtranslated (identity leak) or mis-translated. Within a key a zone-SCOPED entry that admits the packet wins over a coexisting zone-WILDCARD entry regardless of config order (two-tier specificity match); the finer interface/routing-instance/source gates are AND-ed in per candidate  On an overlap with a destination-NAT pool rule the static rule wins (#6473, Junos static-first order — see the Destination NAT row for the precedence and migration note) |
| NAT64 (IPv6↔IPv4) | Yes; translates ICMP echo AND error messages (Destination-Unreachable, Time-Exceeded, Packet-Too-Big↔Fragmentation-Needed with MTU adjustment, Parameter-Problem) per RFC 7915 §4.2/§5.2, including the embedded quoted packet — so PMTUD and traceroute work across the boundary (#2219, wired live on the flowless arm in #6472: a non-query ICMP error never has a flow, so the translators previously reachable only from the flow-backed arm were dead in production — the same-family #5690 builders decline the cross-family `original_src` and the flowless L3 enforcement dropped the error). The flowless NAT64 arm runs BEFORE the #5690 same-family reversal and is NOT gated on `allow_embedded_icmp` (translating errors for the translator's OWN admitted sessions is core RFC 7915 behavior). Both directions match the quote against the installed session halves with an RFC 792 fail-closed consistency gate (the error's outer destination must equal the quote's source): v4→v6 (an error about the forward wire packet, matched via the v4 reverse companion) translates to ICMPv6 toward the client with outer src = Pref64 ∷ error-sender (§6 stateless mapping), and v6→v4 (an error about the translated reply, matched via the forward session) translates to ICMPv4 toward the server with outer src = the translator's pool address. The embedded quote's L4 port/echo identifier is restored to the value the error RECEIVER carries for the flow (v4→v6 the client's original source port, v6→v4 the translated pool port) — without the restore the error would be delivered but unassociable. Per-packet **fragment translation** is RFC 7915 §4/§5 compliant (#2488): v6→v4 derives the IPv4 MF/offset/Identification from the IPv6 Fragment Header (low 16 bits of its 32-bit id) instead of the `no-v6-frag-header` config; v4→v6 inserts an IPv6 Fragment Header (next-header 44) for a fragmented IPv4 input. The TCP/UDP checksum on a first fragment is adjusted incrementally for the pseudo-header address change (RFC 1624, the full payload is not present). **Non-first fragment traversal (#2562):** a stateful fragment-association cache (`nat64::Nat64FragAssoc`, port-free key `(family, src, dst, ip_id, protocol, ingress-authority)`, bounded LRU + ~2s TTL, cross-worker via the shared `Arc<ForwardingState>`, NOT HA-synced) lets a non-first fragment INHERIT the first fragment's translation instead of dropping: the FIRST fragment installs the association on the cold path, and a non-first fragment consults it on the flowless arm and translates L3-only (payload verbatim, no L4 checksum — there is no L4 header), so the whole datagram reassembles at the receiver. The forward (v6→v4, large client uploads) direction is wired end-to-end; the reverse (v4→v6, large DNS64/DNSSEC replies) translator + frame-builder are in place with the reverse-reply poll-loop install/consult a follow-up. **Fail-closed:** a non-first fragment with NO association (reorder / orphan / eviction / cross-node failover) is dropped (#4617, `nat64_frag_dropped`) rather than forwarded to a wrong source, on the disposition where that could otherwise happen. The enforcing gate is scoped to `ForwardCandidate` — the only arm that would emit the packet natively — so this is not a blanket claim over every disposition: NoRoute, MissingNeighbor, HAInactive and LocalDelivery reach their own arms and are safe for their own reasons (#6927 r2). **#6927 — what enforces that:** until #6927 nothing did. `nat64_consult_forward_fragment_assoc` returns `None` on a miss, which means only "no association"; the packet then resolved like any other IPv6 destination and, with a default route in the FIB, FORWARDED — untranslated, still addressed to the synthetic Pref64 destination and still carrying the client's real IPv6 source. The claim read as true because the test fixture DELETED the v6 default route. The enforcement is now a Pref64-destination gate on the flowless arm (`poll_descriptor/mod.rs`): a packet reaching that arm whose destination lies inside a configured Pref64 is refused, because a Pref64 is a translation namespace and no downstream router can deliver it as native IPv6. The fixture keeps `::/0`, and `nat64_frag_assoc_miss_must_drop_with_default_route_6927` asserts the drop against it. **Ingress-authority scoping (#5798):** the key additionally carries the upper-layer protocol (the IPv4 Protocol byte / the IPv6 Fragment Header's Next Header — both L3 fields present in EVERY fragment, so no payload byte is read as L4) AND the ingress security authority the first fragment was admitted under: effective logical ingress interface (ifindex + VLAN), ingress zone after the RAW fabric/tunnel stamp (deliberately pre-#6458-gate — the owner-RG gate needs a resolved decision that does not exist yet at the install/consult sites, and both sites read the same pre-gate value so the key stays symmetric), and routing instance. A hit short-circuits the flowless enforcement arm and returns the first fragment's WHOLE decision, so without this a non-first fragment from ANY other security domain that merely reproduced `(src, dst, ident)` — a **16-bit** IPv4 Identification (32-bit on the IPv6 Fragment Header), guessable or brute-forceable, and in neither case an authorization mechanism — inherited the first domain's permit + egress + NAT and bypassed its own input filter, PBR, zone derivation and zone policy (broadened from NAT64 to all SNAT/DNAT/static-NAT/NPTv6 by #6095). Scoping the key is FAIL-CLOSED BY CONSTRUCTION: a cross-domain fragment computes a different key, MISSES cleanly, and falls through to full enforcement under its own real identity — there is no window in which a wrong decision is returned and then rejected. The shard index deliberately stays the coarse `(family, src, dst, ident)` digest; membership is decided by full-key equality inside the shard, so same-datagram candidates stay co-located. **A hit does not bypass the interface input filter (#5798):** the per-packet non-PBR input filter previously ran ONLY in the association-MISS branch, so even a correctly-scoped same-domain hit skipped a `from is-fragment then discard` / address / protocol term. It now evaluates on BOTH the hit and miss paths against the non-first fragment's own L3 identity; a hit inherits only the STATEFUL zone-policy permit + NAT translation + egress route. Screen is unaffected (it already runs earlier in the poll loop for every packet). **#6927: the hit path also evaluates PBR.** `evaluate_non_pbr_input_filter` — the only evaluator the hit arm ran — returns `FilterResult::default()` the moment a matching term carries a non-empty `routing-instance`, BEFORE recording its counter and BEFORE applying its action, and that default action is `Accept`. So a configured `from { is-fragment; } then { routing-instance scrub; discard; count X; }` was silently ACCEPTED on an association hit and `X` stayed at zero — a reachable configured drop guard that could not fire, with no counter to notice it by. The hit arm now also calls `ingress_route_table_override` (sink-less, the flowless contract: `reject` degrades to the same silent drop as `discard`), honours its `RouteOverride::Drop`, and deliberately does NOT apply a non-drop routing-instance steer — re-steering only the non-first fragments would split one datagram across two egresses. Counter ownership follows: `routing_eval_follows = true` on both arms now, because a routing evaluator really does follow on both. It was `false` before #6927 for a reason that has inverted — with nothing following, `Always` was the only way the fragment got counted at all; with the routing walk following (it counts every matched term unconditionally), `false` would count each matched term twice. **Config-generation invalidation (#5624):** because the cache `Arc` is deliberately shared across config reloads (so in-flight datagrams keep translating), each association is STAMPED with the config-snapshot generation it was installed under (`Nat64State::build_generation`, sourced from `snapshot.generation`), and a lookup REJECTS (miss + evicts) any association whose stamped generation != the current one — so a commit that changed deny/NAT64 rules cannot keep hit-refreshing and forwarding fragments the OLD config admitted; a new first fragment must re-establish the association under the current config. Mirrors the flow-cache `config_generation` guard. **Fragmented ICMP/ICMPv6 stays dropped** both directions (#4617): the ICMP checksum covers the whole datagram and cannot be recomputed from a fragment. TCP/UDP only. True IP reassembly (`force-ip-reassembly`) remains a separate feature. **Source eligibility (#5623, RFC 6146 §3.5):** an incoming IPv6 packet whose SOURCE lies within a configured Pref64 — a looping/synthesized "already-translated" source (the §5 hairpin construction), including the lower boundary `<prefix>::`, the upper boundary `<prefix>::ffff:ffff`, and any source whose embedded v4 is non-global — is rejected fail-closed BEFORE route lookup, policy, or `allocate_source` (`Nat64State::classify_ipv6_packet` → `Nat64Match::IneligibleSource`), so no session, BIB, or allocation state is minted for a spoofed/looping source. Distinct from the pool counters, the drop is surfaced as the `NAT64 ineligible-source drops` operator counter. A legitimate global-unicast source outside every Pref64 translates unchanged (no over-reject). **Extension-header translation eligibility (#5625, RFC 7915 §5.1/§5.1.1):** the v6→v4 forward translator now REJECTS fail-closed — before resolving the terminal L4 — a packet carrying an Authentication Header (AH authenticates IP fields NAT64 rewrites → a translated packet's ICV is broken, §5.1.1 "SHOULD be dropped and logged"), an ACTIVE Routing header (Segments Left > 0, an undelivered source route → §5.1 "MUST NOT be translated"), or a Mobility/HIP/Shim6 header (active end-to-end semantics with no IPv4 equivalent that the parity walker would otherwise silently strip). Hop-by-Hop, Destination Options, a Routing header with Segments Left == 0, and Fragment headers are NOT rejected (they are "ignored ... and the packet translated normally" per §5.1 — no over-reject). Surfaced as the `NAT64 ext-header ineligible drops` operator counter. **Destination eligibility (#6475, RFC 6052 §2.2):** a prefix-matched destination whose extracted embedded IPv4 is non-global — 0.0.0.0/8 (includes the `<prefix>::` lower boundary), 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, or 240.0.0.0/4 (subsumes 255.255.255.255/32 and the `<prefix>::ffff:ffff` upper boundary) — is rejected fail-closed BEFORE the pool check, route lookup, policy, or `allocate_source` (`Nat64State::classify_ipv6_dest` → `Nat64Match::IneligibleDestination`), so no session, BIB, or allocation state is minted and the destination never reaches the `local_v4` LocalDelivery resolution. Pre-gate, `64:ff9b::127.0.0.1` classified `MatchReady(127.0.0.1)` and, with lo0 configured (its addresses land in `state.local_v4`), LocalDelivered NAT64-client traffic to sockets bound to 127.0.0.1 on the firewall itself (the localhost-only admin plane, gRPC 50051 / REST 8080). The gate applies to every configured Pref64; RFC 1918 / TEST-NET embedded destinations still translate (the issue scopes that screening to optional — an NSP may legitimately target internal v4). Surfaced as the `NAT64 ineligible-destination drops` operator counter. **Cold-start neighbor-miss (#5174, fail-closed):** because NAT64 classification + source allocation are gated inside the ForwardCandidate session-miss branch, a NAT64 forward flow whose extracted-IPv4 next-hop's ARP/NDP is unresolved reaches the MissingNeighbor cold-path arm carrying a NON-NAT64 decision (`decision.nat` default). The arm now (a) re-classifies the destination (`classify_ipv6_dest`) so its zone-policy is evaluated on the SAME post-translation (V6 src, extracted V4 dst) tuple as the ForwardCandidate path (#2358) rather than the synthetic IPv6 dst (closing a policy-divergence bypass — a v4-destination rule otherwise matches the synthetic IPv6 dst as match-any), and (b) for a PERMITTED such flow fires the kernel ARP/NDP probe then DROPS the packet fail-closed (`nat64_missing_neigh_drop`) instead of seeding a plain-forward `MissingNeighborSeed` + buffering the untranslated IPv6 frame — the same-family cold-path replay (`rewrite_forwarded_frame_in_place`, MAC/VLAN/NAT only) cannot perform the v6→v4 cross-family rebuild, so a buffered replay would TX the untranslated IPv6 frame to the IPv4 gateway and persist a broken, HA-synced session that poisons the flow. The flow forwards correctly via the ForwardCandidate path (which builds the real NAT64 translation) once the neighbor resolves — the first cold-start packet(s) drop and TCP retransmits. Full buffer-and-translate parity (zero cold-start packet loss) is a deferred follow-up. A DENIED NAT64 MissingNeighbor flow exits via the normal PolicyDenied path (never probe-loops); a non-NAT64 MissingNeighbor flow is unchanged (still seeds/buffers) |
| NPTv6 (RFC 6296) | Yes; stateless 1:1 source-prefix translation, checksum-neutral by design (the RFC 6296 adjustment word preserves the address's ones-complement sum, so the L4 checksum is untouched for the NPTv6 term). **Composes with destination NAT (#3121):** an outbound IPv6 flow that matches BOTH an NPTv6 source rule and a DNAT/static-DNAT destination rule now applies BOTH translations — DNAT rewrites the destination, NPTv6 the source — because the two NAT stages are orthogonal. The decision path attempts NPTv6 regardless of whether a `rewrite_dst` is already present and `merge()`s the source rewrite into the DNAT decision (previously NPTv6 was gated on `rewrite_dst.is_none()`, so a composed flow leaked its internal IPv6 source onto the wire). The composed L4 checksum folds in the DNAT destination delta while the NPTv6 source term nets zero (checksum-neutral, direction-agnostic — the neutral side is the source on the forward path and the destination on the reverse), so the checksum path no longer blanket-skips on the `nptv6` flag when a destination rewrite is also present. **Checksum-neutral prefix pair (#3233):** when the internal and external prefixes have equal ones-complement sums the precomputed adjustment is ones-complement zero (`compute_adjustment` represents this as `0xFFFF`, never the literal `0x0000`), so the interface-ID word fixup is SKIPPED entirely — the translation is a pure prefix swap. Previously `adjust_word` still ran and folded a host whose adjustment word (word[3] for /48, word[4] for /64) was `0xFFFF` down to `0x0000` outbound and never restored it inbound, collapsing that host onto the `0x0000` host (return traffic misdelivered, the `0xFFFF` host unreachable). The RFC-6296-mandated `0xFFFF -> 0x0000` fold is unchanged for the general (non-neutral) case. **Multi-scope self-overlap fixed (#4339):** the #2241 overlap gate (`validateNPTv6Strict`) now skips comparing a rule against ITSELF. A single NPTv6 rule bound to more than one from-scope (`from zone A; from zone B`, or several interfaces) is scope-expanded into one rule-set entry per scope, all sharing the rule-set + rule name; the shared seen-lists made the second expansion's prefixes match the first's exactly, so the rule was rejected as "overlaps rule-set NPTv6-INBOUND rule map-v6-neutral" — blocking any NPTv6 mapping with >1 from-scope. The gate now skips the same `(rule-set, rule)` identity while still detecting a genuine overlap between DISTINCT rules. **Zone-scoped translation enforced (#5176, security):** an NPTv6 rule now matches ONLY within its static-NAT rule-set `from` scope — a rule scoped `from zone untrust` translates (and thus routes) NPTv6 traffic ONLY for the matching zone, not for every zone as before. The rule-set `FromZone` (Go `nat_nptv6.go`, already serialized on the `from_zone` snapshot field — a bounded consume of existing wire data, no protocol bump) is now carried on `Nptv6Rule.from_zone` and gated in both lookups: `translate_inbound` checks the packet's INGRESS zone, `translate_outbound` the EGRESS zone, and an empty `from_zone` is a wildcard that matches any zone (unscoped rule-sets are unchanged). Before #5176 both lookups selected purely by prefix, so a scoped rule performed a security-domain crossing (translated traffic from every zone) and the #2241 overlap gate wrongly rejected legitimate per-zone split-horizon (same prefix, distinct zones). The overlap check is now partitioned by zone scope: two rules conflict only when their zone scopes can both match one packet (either empty, or equal). **Other scope dimensions fail closed (#5818, security):** the config model retains the full static-NAT match scope, but the NPTv6 snapshot/wire/dataplane carry ONLY `from zone` — a rule-set `from interface` / `from routing-instance` scope and a per-rule `match source-address` are all dropped. Before #5818 an NPTv6 rule so scoped was installed as a broader zone/global rewrite, translating (and routing) traffic that could not match the configured rule — the same security-widening class #5176 fixed for `from zone`, for the remaining dimensions. Until the wire+dataplane carry and evaluate those dimensions (deferred /research follow-up #6043), an NPTv6 rule carrying `from-interface`, `from-routing-instance`, or `match source-address` is REJECTED at strict commit (`validateNPTv6ScopeStrict`) and FAILS CLOSED on the tolerant/lenient load (downgraded to a warning; `buildNptv6Snapshots` excludes the scope-carrying rule so it installs nothing rather than a widened rewrite). A `from zone`-only or fully-unscoped NPTv6 rule is unaffected; ordinary (non-NPTv6) static NAT still honors interface/RI scope (#3096) and `match source-address` (#3435) |
| Screen/IDS (16 checks) | Yes; userspace SYN-cookie runtime is wired. **Unresolved profile reference visibility (#5806):** strict commit REJECTS a zone that references an undefined `screen ids-option` profile, but tolerant startup/recovery of an older or externally modified `active.json`, HA config-sync from a schema-skewed peer, and rolling-upgrade intervals all downgrade that to a warning — and the dataplane then enforces NONE of that zone's screen checks while the active config still claims a screen is attached. That state is now reported on three surfaces instead of a single rate-limited runtime WARN (and #6860 records that the WARN itself cannot fire when NO profile resolves at all — other reporting such as tolerant-load configuration warnings and daemon logging still exists, but the runtime dataplane WARN specifically is unreachable in that configuration): the Prometheus gauge `xpf_screen_unresolved_profile_zones{zone,profile}` (config-derived, so it is emitted even on a config-only / degraded boot, and present ONLY while a reference is unresolved — `max_over_time(...)` alerts on any zone ever left unscreened), plus an `Unresolved screen profile references:` block at the top of `show security screen` in BOTH the local CLI and the gRPC renderer. All three derive from ONE exported builder, `dpuserspace.ScreenMissingProfileRefs` — the same function whose output is published to the helper as `ConfigSnapshot.ScreenMissingProfiles` and drives the dataplane WARN. Routing every surface through it is the CONTRACT, not a convenience — stated with its condition: WHENEVER a snapshot has been published for the config being rendered, that snapshot's `ScreenMissingProfiles` and every surface above are the same function of the same input, so no surface can name a different set than the dataplane was told about. That identity is Go-struct to Go-struct; the dataplane is the Rust helper and reads JSON, so struct → wire → decoder is a SECOND hop, bound separately by `TestScreenMissingProfilesPublishedToSnapshot`, which marshals the snapshot and pins the wire key `screen_missing_profile_zones` with its `zone`/`profile` elements. The unqualified form ("impossible to report a different set") is false when NO snapshot has been published — the config-only / degraded boot these surfaces exist to cover — because there is then no told-about set to disagree with, and what the surfaces report is the set the dataplane WOULD be told on the next publish. The enforcement disposition is carried in the metric's HELP text and in ONE status line — not as a label — because it is a global statement about the implementation, identical for every zone, and a prose label value would add unbounded cardinality the day it varies. Its wording is deliberately narrow (`dpuserspace.ScreenUnresolvedDisposition`): *the profile reference does not resolve, so no screen checks are applied to this zone; policy evaluation is unaffected*. It is NOT "forwarded unscreened", which reads as a permit and would suggest the firewall is passing traffic it would otherwise deny — zone policy still evaluates the packet normally. That string carries a literal `#5806` anchor because it asserts a decision made in the RUST runtime (`screen/mod.rs` returns `ScreenVerdict::Pass` on the `None` branch) that the Go control plane cannot derive: when the posture is settled, a grep for the issue number must land on every place asserting today's behaviour. The fail-closed-vs-pass posture remains an open design decision owned by #5806 (a runtime fail-closed posture is itself an availability brick under the #1960 no-brick rationale, and these tolerant paths are the only ones that reach the state). |
| Firewall filters + policers | Filters yes; three-color policers admitted for the reviewed color-blind `then discard` slice; broader color-aware and non-drop action work is tracked as production hardening |
| TCP MSS clamping | Yes |
| GRE tunnel transit | Yes (passthrough). **Same-outer-family required (#5162):** a GRE/IPIP tunnel's outer `tunnel source` and `tunnel destination` must be the SAME address family (both IPv4 or both IPv6). A mixed pair (v4 source + v6 destination, or the reverse) passes per-leaf validation but the snapshot producer tags it `inet6` whenever either endpoint is v6, so the encoder hits the AF_INET6 arm, finds the v4 endpoint, and silently drops every encapsulated packet. It is HARD-REJECTED at strict commit (`validateTunnelOuterFamilyStrict`, mirroring the WireGuard endpoint-family gate — one encap = one outer family), downgraded to a warning on the tolerant load / peer-sync path (#1960 no-brick), and the Rust `populate_tunnel_endpoints` independently SKIPS a mixed-family non-WG row with a loud diagnostic so a peer-synced degenerate row installs nothing rather than a blackhole |
| IPIP (ip-in-ip) tunnel transit | **IPIP is NOT supported and is rejected at commit (#4785 half 1):** the userspace dataplane has no IPIP primitive in either direction (an endpoint is entered into the decap index only when its mode classifies `TunnelKind::Gre`; `TunnelKind::Unknown` is the egress dispatcher's fail-closed drop arm), so a `mode ipip` tunnel was created, came UP, and passed no traffic. `validateIpipTunnelUnimplementedStrict` hard-rejects it on the strict commit / commit-check path and warns on the tolerant load / peer-sync path (#1960), replacing the #4788 warn-only advisory. An `ip-*` interface defaults to `mode ipip` without an explicit `mode` statement, so this fires on configs that never name it. On a chassis cluster the rejection also covers the PEER's effective view (`ValidatePeerEffectiveStrict`), because the strict gate compiles only the submitting node while the RAW group tree is what synchronises and the standby ingests it leniently — a peer-only `${node}` IPIP stanza would otherwise commit green and install on the node that received it. That gate is handed the tree AFTER `rewriteRetiredDataplaneType` (#6861), on a clone: peer ingestion strips a retired `system dataplane-type` leaf before compiling, so on the raw tree a peer group carrying BOTH a retired leaf and an IPIP tunnel failed to compile at all and the gate returned success without ever running its IPIP subject. A stanza that emits no endpoint is not rejected but can still create a kernel ANCHOR device (`collectAppliedTunnels` screens the interface level on `tunnel source` and screens units on nothing); those raise a standing advisory naming the device and why no endpoint was emitted. A record that is ITSELF emitted is never reported — it belongs to the strict gate and the dead-endpoint advisory. That advisory keys on the RUNTIME DEVICE NAME, not on which `*TunnelConfig` the emitter published (#6861): an unemitted record whose Linux device name is ALSO produced by an emitted endpoint — `unit 0`, which shares the interface's base name, or a unit under an interface-level `tunnel mode wireguard` whose device the WireGuard endpoint resolves to via `TunnelNameMap` — is live and is not reported. Its remediations never instruct removing an interface-level `tunnel` stanza outright, because units inherit `source`/`destination` from it and would stop emitting; and under an interface-level `tunnel mode wireguard` stanza they do not suggest completing the unit's endpoints either, since the emitter publishes only the lowest unit so a completed unit still emits nothing (#6861). Use `mode gre` or `mode wireguard`; half 2 of #4785 implements the decap stage |
| IPsec / XFRM | Yes (passthrough) |
| VLANs (802.1Q) | Yes. The XDP dataplane derives VLAN (security-domain) identity SOLELY from the in-frame 802.1Q tag, so a parent NIC's RX-VLAN hardware offload (which strips the tag into `skb->vlan_tci`, unreadable by XDP) MUST be disabled. **#5268 (security): disabling it is an ACTIVATION PRECONDITION** — if `ensureRxVlanOff` cannot turn the offload off AND the parent carries ≥1 configured VLAN subinterface, the compile/apply FAILS CLOSED (`rxVlanOffloadActivationError`, `pkg/dataplane/compiler.go`) rather than proceeding to shim attachment; otherwise HW-stripped tagged frames parse as `vlan_id=0`, fall back to the parent ifindex, and are classified into the parent's/first-subinterface's zone — a cross-zone screen/policy bypass. A NIC that reports the feature `off`/`off [fixed]` (e.g. virtio) or ABSENT never strips tags and is unaffected, as is a plain parent with no 802.1Q units. (#5268 also corrected a latent `strings.Contains(line,"off")` bug that matched the feature name `rx-vlan-offLOAD` and so read an ACTIVE offload as already-off — the offload is now detected by the value after the colon.) |
| Flow export (NetFlow v9) | Yes |
| HA cluster + session sync | Integrated; HA hardening tracked in open issues |
| SYN cookie flood protection | Yes |
| Throughput (25G mlx5) | See validation/perf docs for current results |

SYN-cookie-dependent screen behavior runs in userspace with bounded
SYN-ACK/RST replies and userspace status counters (#1374 closed). Port
mirroring has bounded userspace runtime admission (#1376 closed).
Three-color policers are admitted for the bounded color-blind
`then discard` runtime slice (#1375 closed); remaining color-aware,
non-drop action, and HA/restart continuity work is production hardening
tracked in open issues such as
[#1614](https://github.com/psaab/xpf/issues/1614) (CoS regression) and
[#1608](https://github.com/psaab/xpf/issues/1608) (cold-path hardening),
not the closed #1373 feature-gap trackers. Pool-mode SNAT is admitted,
#1385 added userspace-v1 `address-persistent` selection, and the runtime
fails closed for unusable or exhausted source-NAT pool rules before
forwarding.
