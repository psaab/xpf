# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-08-21

## Deprecation Context

Issue #1373 retired the legacy eBPF dataplane; the staged retirement is
complete. The Rust AF_XDP userspace dataplane is the only runtime forwarding
path and the effective default when `system dataplane-type` is omitted. The
#1476 source-removal phase deleted the legacy BPF source (`bpf/xdp/*.c`,
`bpf/tc/*.c`), the bpf2go bindings, and the legacy loader targets; the only
retained eBPF artifacts are the userspace XDP shim and the shared
`bpf/headers/*.h` map/struct bootstrap. Explicit `system dataplane-type ebpf`
is hard-rejected: the strict commit validator returns `ErrEBPFDataplaneRetired`
and the runtime factory returns `ErrEBPFBackendRetired`. The parser still
accepts the `ebpf` token so that `load merge`/`load override` of a
pre-retirement config does not syntax-error during a rolling upgrade, but
`commit check` then fails and the remediation is
`set system dataplane-type userspace`.

DPDK is retired (#1525). The DPDK backend, `dpdk_worker/`, and
`pkg/dataplane/dpdk/` are removed in #1527/#1528. The historical
`#1475` policy that confined DPDK's root `DataPlane` dependency to
`pkg/dataplane/dpdk` and the `cmd/xpfd/main.go` registration import
applied pre-retirement; this document focuses on the userspace
AF_XDP dataplane retirement gate, not DPDK.

## Implemented In The Current Runtime

These capabilities exist in the current Rust userspace dataplane code path:

| Feature | Current state | Notes |
|---------|---------------|-------|
| Stateful forwarding | Implemented | Per-worker sessions plus shared session tables |
| Zone + global policies | Implemented | Address and application terms are pre-expanded by the daemon |
| Implicit default-policy hit counter | Implemented (#3363) | The IMPLICIT default-policy verdict (returned when a flow matches no configured zone-pair, wildcard, or `junos-global` policy) now carries a reserved per-rule hit counter, closing the observability gap where `policy_counter_idx` was hard-coded `0` and the catch-all was uncounted. `PolicyState.default_counter` (an `Arc<PolicyRuleCounter>` persisted in the `PolicyCounterStore` under the reserved rule id `dataplane.DefaultPolicyName`/`DEFAULT_POLICY_COUNTER_RULE_ID` = "default-policy", retained across snapshot rebuilds by `reconcile_rules`) is incremented on the cold path for EVERY default verdict — for default-DENY this is the only count (a denied flow installs no session, so each dropped packet re-evaluates), and for default-PERMIT the established fast path re-counts the rest via the reserved handle `DEFAULT_POLICY_COUNTER_IDX` (`u32::MAX`), which `hit_counter_by_idx` routes to `default_counter` (mirroring the #3073 per-rule fast-path counting). The Go control plane reads it through the existing `ReadPolicyCounters(dataplane.DefaultPolicySentinelID)` path: `policyRuleIDForCounter` resolves the reserved sentinel to "default-policy", so the CLI `show security policies hit-count`, gRPC text hit-count, REST `/policies` inventory, and the `xpf_policy_hits_total` Prometheus metric (all labeled `-`/`-`/`default-policy`) surface it as a final row separated from the configured-rule totals — gated on `policy-stats system-wide enable` like every other counter row for cross-surface consistency. Operator-facing default-deny *audit logging* is achievable today via an explicit `from-zone any to-zone any` catch-all policy with `then { deny; log session-init; }` (honored by the wildcard tier with its own counter + log selection); grafting `then log` onto the implicit default's enum leaf is a config-grammar change (the `default-policy` schema leaf is a typed enum that cannot also carry structural `then` children) tracked separately. |
| Policy schedulers | Implemented; live HA evidence captured | Scheduled-policy `scheduler_name` and `inactive` bits are published in userspace snapshots, old helper protocol mismatches disarm forwarding, missing policy-scheduler references are commit errors, and Rust hit counters survive active/inactive snapshot rebuilds by stable rule ID. The 2026-05-19 #1378 live artifact set is accepted by `test/incus/policy_scheduler_validate.py` for `lan->wan/scheduled-allow`. **#5648 (M43b):** the required-generation protocol gate is also enforced on the EXPLICIT arm path — `SetForwardingArmed(true)` re-runs `ensureRequiredSnapshotProtocolLocked` against the last-applied config and REFUSES (returning the required-protocol sentinel) when the helper's accepted image is too old, so an operator/gRPC `request`/arm cannot re-arm a stale accepted image after a protocol disarm. This closes the "re-arm after protocol mismatch" gap the #2138 plan left explicitly out of scope. The gate is scoped: it re-polls the helper first and is a no-op unless the config requires the protocol, so a helper that satisfies it still arms normally, and disarm (`armed=false`) is never blocked. |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented with scoped caveats | IPv4/IPv6 pool address and port allocation. The pool port block is set by `port range <low> to <high>` (Junos grammar; the legacy `port range low <lo> high <hi>` shape is still accepted) and defaults to 1024-65535 when unconfigured; `port no-translation` PRESERVES the original source port (translate the address only) by taking the address-only path (`rewrite_src_port` left unset, no pool port consumed). Before #3906 the `port range <low> to <high>` grammar and `no-translation` were SILENTLY dropped — the pool fell back to the 1024-65535 default and PAT-translated the port regardless — and a reversed/out-of-range range committed green then dropped the rule at runtime; the parser now applies both shapes and `validateSourceNATPoolStrict` hard-rejects a reversed (low > high) or out-of-range (not 1-65535) range at commit. Both shapes have a FIXED arity since #6688: a token the grammar does not consume rejects instead of being discarded, so the bracketed `port range [ 1000 2000 ]` and the mistyped bare `port range 1000 2000` (which reach the compiler as the same bracket-free token slice) no longer compile the ONE-port pool `PortLow == PortHigh == 1000` (lenient-load downgrades to a warning per #1960, the snapshot builder independently failing closed via `sourceNATPoolPortRange` → `source_nat_pool_invalid_port_range`). Global `source address-persistent` uses a seeded non-cryptographic FxHash (`rustc_hash`) over the source IP (userspace-v2; #2349 replaced the prior SHA-256 selector — load distribution, not security) and is stable only within the AF_XDP backend, pool family, pool order, and pool size. The mapping is computed live, never persisted or HA-synced, so the only contract is same-source→same-pool-address within a process lifetime (and identical across nodes running the same binary). Legacy eBPF uses C-word IPv4 modulo / IPv6 lane-XOR selection (DPDK retired #1525), so new-flow pool address parity is not promised across retained backend transitions. Pool-mode rules with missing pools, empty pools, invalid port ranges, malformed addresses, no address for the packet family, or exhausted live translated tuples fail-closed at the `poll_descriptor.rs` source-NAT call sites before session creation or forwarding, with recent-exception reasons such as `source_nat_pool_missing`, `source_nat_pool_empty`, `source_nat_pool_invalid_port_range`, and `source_nat_pool_exhausted`. Per-pool `persistent-nat` now has snapshot fields and runtime lease reuse to a translated tuple, keyed by the source tuple `(protocol, source IP, source port)` scoped by the full three-way Junos `persistent-nat permit` enum (#2823, generalizing the #2397 binary `permit-any-remote-host` flag): `any-remote-host` keys the lease by the source tuple ALONE (`remote = None`), so any remote host:port reuses the mapping; `target-host` folds in the remote destination IP only (`remote = (destination IP, 0)` — the destination PORT is dropped), so a second flow from the same source to a NEW remote PORT on the SAME remote host reuses the binding while a different remote host gets a distinct lease; `target-host-port` folds in the full remote endpoint `(destination IP, destination port)`, so a different remote port keys to a distinct lease and gets a fresh mapping. The enum rides the wire as `persistent_nat_permit` (string); the legacy `persistent_nat_permit_any_remote_host` bool is still emitted for skew against an older helper, which falls back to it (`true`→`any-remote-host`, `false`→`target-host-port`). The default mode (when `persistent-nat` is configured with no explicit `permit`) is `target-host-port`, byte-identical to the pre-#2823/#2819 disabled-flag `(destination IP, destination port)` keying. Before #2397 the disabled-flag mode was silently a no-op; before #2823 only the two endpoints of the enum (`any-remote-host` and the `target-host-port`-equivalent disabled flag) were reachable — `target-host` (IP-only scope) could not be selected. Persistent source-NAT is a required helper-protocol gate: committing a persistent-NAT config against a helper whose `ConfigSnapshotProtocolVersion` is below the requirement disarms forwarding and ABORTS the commit (`ErrPersistentSourceNATProtocolIncompatible`, same required-gate class as the policy scheduler; #2138). An already-persisted or peer-synced persistent-NAT config is still admitted on a too-old helper (lenient-load #1960): the boot apply uses the void `applyConfig` wrapper (logs `Warn`, swallows) and the peer config-sync receiver logs `Error` and returns, both disarming the helper rather than bricking the node — only the operator-facing commit path surfaces the abort. The lease table is bounded in helper memory, survives compatible in-process snapshot refreshes, and expires after the configured inactivity timeout once no live flow uses the lease. It does not consult Go `PersistentNATTable` and does not survive helper restart. The closed #1449 contract gates HA behavior explicitly: HA configs that reference persistent source-NAT pools are not admitted because leases are not synchronized, and status reports `userspace persistent-nat source pool leases are not HA-synchronized`. Userspace status, CLI summary, and Prometheus expose live-flow, used-port, persistent-lease, allocation, reuse, and exhaustion counters for admitted non-HA pools. The operator SHOW path reports the actual three-way permit mode (#3193): `show security nat source persistent-nat-detail` renders a `Permit: <mode>` line (`any-remote-host` / `target-host` / `target-host-port`) per binding, and the source-NAT pool status table carries a `Permit` column; both replace the pre-#3193 binary any-remote-host flag, which collapsed `target-host` and `target-host-port` to the same output. The mode rides the status wire as `persistent_nat_permit` (string) on `SourceNatPoolStatus`, falling back to the legacy `persistent_nat_permit_any_remote_host` bool for an older helper. **#6041 (parity follow-up to #5819): `persistent-nat` combined with `port no-translation` on the SAME pool is now SUPPORTED** via an address-only persistent lease (`reserve_address_only_persistent`, `userspace-dp/src/nat/allocator.rs`). The lease pins a public pool ADDRESS across the configured permit scope WITHOUT consuming a translated pool port: it is keyed by the same `PersistentSourceKey` permit semantics as a port-translating lease (`any-remote-host` / `target-host` / `target-host-port`), refcounts live flows (increment on reuse, decrement on release), and is reclaimed only after the inactivity timeout elapses with zero live flows. Because the lease selects and pins the address, persistence no longer depends on the global `source address-persistent` hash — every flow in the permit scope reuses the SAME public address (the round-robin address selection is bypassed once a lease exists). The per-flow #5269 reverse-identity collision guard (`address_only_owners`) still runs on top: two DIFFERENT sources that would produce the same public reverse tuple (same pinned address, preserved source port, and remote) are denied as exhaustion, and the token is cleared per flow on the SAME `release_flow` / `rollback_flow` teardown path. The address-only lease lives in the SAME `persistent_by_source` map counted by the `persistent-lease` status/capacity accounting, and every lease teardown site (idle-reuse, rollback, GC eviction) skips the port-bitmap free because an address-only lease holds no port bit. The #5819 fail-closed reject (`validateSourceNATPersistentNoTranslationStrict` + the `persistent_nat_no_translation` snapshot marker) was removed — the combo now commits cleanly and installs a usable pool. HA behavior is consistent with ordinary persistent leases: the lease is in-memory and NOT HA-synced (an address-only synced session carries no translated port, so `reserve_synced_source_nat_allocation` reserves nothing for it — the same model as the #5269 non-persistent address-only path), and the closed #1449 gate still refuses to admit HA configs that reference persistent source-NAT pools because the leases are not synchronized. |
| Destination NAT | Implemented | Pre-expanded tuple snapshots from Go. Per-rule translation hits are counted (see Source NAT note; #2218). |
| Static NAT | Implemented | Bidirectional 1:1 translation. Per-rule translation hits are counted (see Source NAT note; #2218). |
| NAT per-rule translation hits | Implemented (#2218; counter-ID stability #2255) | Each SNAT/DNAT/static-NAT rule carries a compiler-assigned `counter_id` (non-zero; 0 = no counter) stamped onto its snapshot (`CompileResult.NATCounterIDs` → `SourceNATRuleSnapshot`/`DestinationNATRuleSnapshot`/`StaticNATRuleSnapshot.counter_id`). **The `counter_id` is STABLE across compiles (#2255): `assignNATCounterID` DERIVES it as a 32-bit FNV-1a hash of the type-namespaced `dataplane.NATCounterKey` (the rule's identity), not a sequential position counter. A rule therefore keeps the same id across a config reorder or the removal/re-add of an unrelated rule, so the helper's cumulative numeric-keyed store stays correctly attributed BY CONSTRUCTION — a reused config slot can no longer inherit a different rule's prior count (the pre-#2255 sequential-reset id was reused across a reorder, mis-attributing in `show security nat ... rule` Translation hits). The wide 32-bit id space makes a distinct-key hash collision negligible (~8e-6 at the 256-rule cap); the rare in-compile collision is resolved deterministically (re-hash with a `#N` suffix) so every rule still gets a unique id, reproduced identically on every compile. The JSON wire is unchanged — a JSON number is integer-width agnostic, so widening the Go/Rust `counter_id` field u16→u32 needed no `protocol_wire_v1.json` regen.** The Rust dataplane holds an `Arc<NatRuleCounter>` per rule (lock-free atomic packets+bytes, `NatCounterStore` keyed by the `u32` `counter_id`, mirroring `PolicyCounterStore`) and increments it ONCE per committed translated forward flow on the cold (session-miss) path — past every SNAT-rollback door, so a refused/rolled-back allocation is not counted. `NatCounterStore::reconcile_ids` retains only the ids present in the new snapshot and drops the rest; because ids are identity-bound, a retained id always refers to the SAME rule it did before. The fast (established-flow) path adds no work. Counts are reported per `counter_id` in `ProcessStatus.nat_rule_counters` and mirrored by the Go control plane into the sparse `bpfShim` NAT offset map (`Manager.SetNATRuleCounterOffset`, `map[uint32]CounterValue`), so `Manager.ReadNATRuleCounter` and `show security nat source/destination/static rule` report the live total. `ReadNATRuleCounter` keys that sparse offset map directly and no longer indexes the legacy 256-entry `nat_rule_counters` BPF array (a hash id ≥ `MaxNATRuleCounters` would fail that bounded `Lookup`); the Rust forwarder never WROTE that array (the #1476 eBPF retirement dropped the XDP increment), so it only ever held zeros and dropping the lookup changes no observable value — the legacy `snat_value.counter_id` BPF struct field is now vestigial in the userspace runtime. The compiler keys each `counter_id` by NAT TYPE (`dataplane.NATCounterKey` → `snat/`, `dnat/`, `static/` prefix on `ruleset/rule`) so a rule name reused across source-, destination-, and static-NAT gets distinct counters instead of colliding on one slot. The counter is PER-FLOW (one packet + its byte length per new translated flow), not per-transit-packet — before #2218 it was a perpetual 0 (the #1476 eBPF retirement dropped the legacy per-packet XDP increments). Counts are node-local (not cluster-aggregated) and reset on helper restart. `clear security nat source/destination rule` (and `clear`-all) drops BOTH the helper store and the Go offset: `userspace.Manager.ClearNATRuleCounters` zeroes the `bpfShim` offset map AND sends the `clear_nat_counters` IPC so the helper `NatCounterStore` resets — without the IPC the helper's cumulative-since-start total would be re-mirrored on the next 1/s status poll (`SetNATRuleCounterOffset` overwrites absolutely) and the cleared value would snap back within ≤1s. |
| NAT64 | Implemented | Forward and reverse translation with reverse-session state. Each successful v6↔v4 translation (both directions, counted at the single forward-candidate site since NAT64 flows are non-cacheable) bumps a per-binding `nat64_translations` counter that the Go control plane sums into `GlobalCtrNAT64Xlate`; surfaced by `show security flow statistics` ("NAT64 translations"), the userspace status summary, the gRPC `Nat64Translations` field, and the `xpf_nat64_translations_total` Prometheus metric (#2161 — the counter previously read 0 even while translated traffic flowed). Inbound security policy is evaluated on the POST-translation tuple (v6 source matched in the IPv6 ingress zone, real internal IPv4 destination matched in the destination zone) via the cross-family `(V6 src, V4 dst)` policy arm (#2358), consistent with the same-family DNAT/static-DNAT/NPTv6 post-translation matching (#2345); NAT64 policy is authored against the real IPv4 host, not the synthetic NAT64 prefix. |
| NPTv6 | Implemented (zone-scope only) | Stateless prefix translation. Honors `from zone` scope (#5176); a rule-set `from interface` / `from routing-instance` scope and a per-rule `match source-address` or `match destination-port` are NOT yet carried on the wire, so a rule carrying any of them is REJECTED at strict commit and excluded from the snapshot on the tolerant load (fail-closed, #5818) rather than silently installed as a broader rewrite. Full scoped support is a deferred /research follow-up (#6043). |
| Firewall filters | Implemented | Filter snapshots and evaluation in Rust |
| Flow export | Implemented | Userspace flow export snapshot and runtime |
| Three-color policers | Implemented with caveats | srTCM/trTCM runtime, forwarding-path and flow-cache-hit metering, red drops for `then discard`, status/CLI/Prometheus counters, and compatible in-process snapshot continuity. A policer with NO explicit `color-blind`/`color-aware` statement now compiles to COLOR-BLIND mode (Junos default, #4535) so it is enforced instead of disarming forwarding — before #4535 the unspecified case left `color_blind=false`, which the capability gate read as unsupported color-aware mode and disarmed the whole dataplane (`ForwardingSupported=false`), refusing a config Junos accepts. Explicitly-configured color-aware, non-`discard`, and malformed snapshots still fail closed in Rust if they bypass Go admission. Sharded state, HA/restart continuity decision, full non-drop action propagation, and integration evidence remain production hardening work, not active feature-gap blockers. |
| TCP MSS clamping | Implemented | Flow snapshot fields are delivered and used in Rust |
| Embedded ICMP NAT reversal | Implemented | Includes reverse-session repair paths |
| Configurable session timeouts | Implemented | Snapshot-driven global per-protocol timeouts in `session.rs`. Per-application `inactivity-timeout` (#3227) rides `PolicyApplicationSnapshot.inactivity_timeout` and is stamped on the admitted session (`SessionMetadata.inactivity_timeout_ns`) so the conntrack GC ages an app-matched flow out on the app's idle window instead of the global timeout, restoring legacy-eBPF `appTimeout` parity; first matching policy rule + first matching app term wins, where "first" is CONFIG order — the application terms are emitted in the order the apps appear in the policy `match application` list and, within an application-set, the configured member order, NOT alphabetical name order (#3298; the Rust matcher is first-writer-wins on the exact port, so a lexical sort would have let the alphabetically-first overlapping app's timeout win instead of the operator-listed-first one); closing/RST reap windows are unaffected. #3301 carries the per-application timeout (plus the admitting `policy_id` and the #3073 `policy_counter_idx`) on the cross-node HA session-sync wire (SESSION_OPEN delta in seconds + `SessionSyncRequest.inactivity_timeout`), so a peer-PROMOTED session is correctly aged/attributed/counted after failover instead of degrading to the global timeout / policy 0 / no counter; the receiver re-applies it via `app_inactivity_timeout_ns`, and an old peer that omits the additive `serde(default)` fields falls back to the pre-#3301 behavior (rolling-upgrade safe). |
| VLAN handling | Implemented | Ingress VLAN tracking and egress tagging |
| Route and neighbor lookup | Implemented | Per-table routes, neighbor cache, next-table support |
| HA state ingestion | Implemented | Helper receives RG active/watchdog state |
| Session delta export | Implemented | Rust helper exports open/close deltas back to Go |

## Remaining Explicit Configuration Gates

These are the explicit configuration gates that still hold after the
feature-gap closeout. The earlier source-removal evidence caveats are
retrospective: the #1373 feature-gap audit (#1374-#1381) and the #1477
final-validation artifact set are closed. The explicit gates live in
[`pkg/dataplane/userspace/manager.go`](../pkg/dataplane/userspace/manager.go).

| Feature/config shape | Userspace status | Tracker / disposition |
|----------------------|-------------|--------------------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace. #2124: an application term whose protocol the matcher cannot represent (sctp/esp/ah/vrrp/igmp/pim/egp now parse and are canonicalized to their IANA number; anything else, or a malformed port, is unrepresentable) fails `expandUserspacePolicyApplications`. On a failed expansion the daemon emits a reserved `__unsupported__` sentinel term so the Rust matcher rejects the whole snapshot via `SnapshotIntegrityError` (keeping the previous good state) — an action-agnostic fail-closed that never turns a permit into match-any nor a deny into a pass. The SAME mechanism now covers unrepresentable ADDRESSES symmetrically (#3261): a policy naming an undefined address-book name, or a static book whose value is a non-literal (Junos dns-name / wildcard-address / range that resolves to no prefix), emits a reserved `__unsupported_address__` literal (stamped onto BOTH the v3 book-id/literal and legacy address shapes) which the Rust preflight rejects as `SnapshotIntegrityError::UnrepresentableAddress`. Before #3261 the address side had NO sentinel/reject backstop, with TWO distinct fail-opens: (a) an address-book entry whose value is a Junos dns-name / wildcard-address / range-address compiles to `Value==""`, and `expandBookNameToCIDRs` USED to widen `""` to `0.0.0.0/0` + `::/0` (match-any) — so a `deny <dns-name-book>` installed an overbroad DENY-ALL and a `permit` WIDENED to permit-any; (b) an undefined book name, or a book MIXING a literal member with a non-literal member, silently dropped the bad token, collapsing/narrowing the side to MatchNone so a `deny <bad-address>` matched nothing and fell through. The fix: `expandBookNameToCIDRs` now skips an empty value (contributes nothing, never `0.0.0.0/0`; explicit `any` still widens), and address representability is decided by a STRUCTURAL, content-independent check (`nameRepresentable`): a name is representable only if every recursively-resolved member is a feed-bound name, an Address whose value parses to a concrete prefix (CIDR / bare IP / `any`), or an AddressSet all of whose members are representable. ANY unrepresentable member (empty/unparseable value, undefined reference) taints the whole name → the `__unsupported_address__` sentinel → whole-snapshot reject. The check is feed-AWARE: a dynamic-address feed name (#2049) is representable, an empty feed is MatchNone BY DESIGN (overlay key present) and is NOT rejected, and a set that CONTAINS a feed member is not falsely rejected. **#3294 (A′)** completes this for the in-set case: a feed-backed MEMBER of an address-set now merges its live feed prefixes into the enclosing set's address-book row (the feed-aware `expandBookNameRecursive`), so a `deny <set-containing-a-feed>` ENFORCES the feed portion instead of under-denying it; a feed-only set ENFORCES when its feed is live and is `__unsupported_address__`-rejected (fail-closed) only when the feed is currently empty. A DIRECT feed reference also now COMMITS under strict validation (the #2008 `bookNames` one-liner); the shared `policyMatchAddressBookResolves` resolver stays feed-UNaware so a feed member nested in a set is still strict-rejected at a fresh commit (the enforcement lives on the lenient/peer-sync path via the dataplane merge). The Go-side policy simulator (`pkg/policymatch`) mirrors the empty-value→match-nothing change for `show security match-policies` parity. The content-rejection signal (`PolicyContentRejected`) is therefore computed from the ACTUAL built snapshot rules' sentinels (`collectPolicyContentRejections`), NOT from the cfg-only capability gate, so a healthy feed policy does not false-positive. **#3261 refinement (the keep-armed contract):** unrepresentable policy *content* (this class, application OR address) is now treated DISTINCTLY from a genuinely-unsupported dataplane *semantic*. It is recorded in `snap.Capabilities.PolicyContentRejected` and does **NOT** set `ForwardingSupported=false` / does NOT disarm the helper. Disarming would `XDP_PASS` transit to the kernel and BYPASS the integrity reject — a system-level fail-OPEN. Instead the helper stays armed, publishes the sentinel snapshot, and the helper's non-mutating integrity preflight rejects it: a running node RETAINS the previous-good policy state; a fresh boot whose first-ever snapshot is bad lands on the default-deny `PolicyState` (never kernel-forwarded). The deny-rule case stays fail-CLOSED (the whole-snapshot reject keeps a dropped `deny BAD` term from letting blocked traffic fall through to a later permit). The reject is observable: `ProcessStatus.LastSnapshotRejectReasons`, a one-shot `slog.Warn` on the transition, and the `xpf_userspace_policy_content_rejected` 0/1 gauge surface the deliberate Go/Rust skew (`ForwardingSupported=true` while the helper rejected the snapshot). **#3376 (reason specificity):** each reason now names the SCOPE-qualified rule identity (`from-zone->to-zone/name`, or `global/name` — `global(from->to)/name` when the global rule carries zone context) plus the offending SIDE and the exact configured token(s): `source-address "<book>"`, `destination-address "<book>"`, `application "<app>"`. `collectPolicyContentRejections` reads the build-time-only offending-token lists captured by `buildOneRuleSnapshot` (`offendingAddressTokens` / `offendingApplicationTokens`); these are unexported, NOT serialized, so the wire snapshot is unchanged. Before #3376 a reason keyed only on the bare `name` was ambiguous across duplicate policy names in distinct zone pairs / global scope and reduced every cause to "an application" / "an address", forcing a hand-audit of every token on the security-sensitive keep-armed path. It is in-band recoverable: the config still loads via `CompileConfigLenient`, so the operator edits out the offending application/address and re-commits. The ONE narrow disarm kept for this class is keyed on the helper's snapshot protocol version: an OLDER local helper that predates the integrity preflight cannot be trusted to reject the sentinel, so `disarmBeforeUnsupportedPublishLocked` disarms only when `ConfigSnapshotProtocolVersion < ProtocolVersion`. GENUINELY-unsupported semantics with no fail-closed snapshot representation (color-aware three-color policers, SYN-cookie screen material, persistent SNAT under HA) still set `ForwardingSupported=false` and still disarm — that legitimate path is unchanged. |
| Screen behavior requiring SYN cookies | Supported | Closed feature-gap (#1374); #1477 final validation closed |
| HA with per-pool source NAT `persistent-nat` | Gated | Closed/documented contract: helper-memory persistent-NAT leases are not HA-synchronized, so HA configs that reference persistent source-NAT pools are not admitted |
| Port mirroring | Supported | Closed feature-gap (#1376); #1477 final validation closed |

Port mirroring now has snapshot/wire plumbing plus a bounded runtime slice
that samples and queues discardable full-L2 mirror clones with drop counters.
Runtime coverage includes the pending-forward path, self-target flow-cache
mirror surface, deferred neighbor-resolution retry path, CoS-bound reserve
handling, and mirror-specific counter attribution. **#5167 sample-before-reserve
(COMPLETE across dispatch + hot path). Ordering invariant: on every mirror
surface the worker-local sampler (`mirror_sample_allows`) runs BEFORE reserving
the cross-worker clone queue (`admit_mirror_clone_to_live`, a true-shared AcqRel
CAS on the target's `pending_tx_admitted`, #4096 — an unused reservation costs a
second AcqRel RMW on its `PendingTxAdmission` Drop). Reserve-before-sample made
acknowledged cross-core true-sharing scale with the FULL unsampled ingress rate
O(PPS) instead of the sample rate O(PPS/R); sample-first means a non-sampled
packet touches nothing shared — no reserve, no copy, no clone-queue pressure
report. #6113 (#5167) fixed the DISPATCH path (both branches of
`enqueue_sampled_mirror_clone`, `mirror/fast_path.rs` — session-miss /
neighbor-resolution-retry). #6114 (#5167) fixes the remaining LIVE site, the
ESTABLISHED-FLOW HOT PATH (`poll_descriptor/flow_cache_hit.rs`), which dominates
sustained high-PPS mirror, plus the `enqueue_sampled_mirror_clone_to_live` sibling
that shares it. Both now route the ordering through one shared
`sample_then_admit_mirror_clone` (`mirror/resolver.rs`), so the invariant has a
single IMPLEMENTATION — but a single tested home bounds the HELPER, not its
wiring, and the live call site needed its own binding (see the #6304 note
below; the original "cannot silently diverge again" claim here was wrong).
Intent note: the earlier
"admit-first preserves sample budget on a full queue" behavior (documented by
`sampled_live_mirror_queue_full_does_not_advance_sampler`) was adjudicated a
SECOND instance of the #5167 bug, not a real requirement — budget preservation
only matters during a pressure event where clones are already dropped, is
statistically irrelevant to a 1-in-N decimation of a lossy clone stream, and cost
an O(PPS) shared-CAS hit on the dominant path; the test is flipped to assert
sample-first (a SELECTED packet advances the sampler, then reports the full-queue
pressure).** **#6304 call-site binding:** "a single tested home" bounds the
HELPER, not its wiring. The #6114 tests reach `sample_then_admit_mirror_clone`
through `enqueue_sampled_mirror_clone_to_live`, which is DEAD in non-test builds
(drop its `allow(dead_code)` and `cargo build --release` reports the function
"is never used"), so reverting ONLY the live `stage_flow_cache_hit` call site to
reserve-before-sample left the entire Rust suite green — the unit was bound and
the wiring was not. `poll_descriptor/flow_cache_hit_tests.rs` closes that by
driving `stage_flow_cache_hit` itself, covering BOTH arms of
`MirrorSampleAdmission` at the live site, since #6114's two tests split the same
way and only one of them was ported first: a NON-sampled packet must not reserve
the full queue; a SELECTED packet on a full queue must advance the sampler
BEFORE reporting the pressure (revert that and the hot path pins itself at the
sampler's first slot, restoring the O(PPS) shared-CAS hit); and a SELECTED
packet whose target has room must actually land its clone (drop the
`Sampled(Ok)` arm and port mirroring silently stops delivering on this path —
green under both other tests). A fourth covers ROLLBACK: sampling and admission
run before the in-place rewrite, but the sampler commit and the clone delivery
are deferred until it succeeds, and every other test needs a SUCCESSFUL rewrite
— so hoisting the commit above that check passed all of them. It drives a cache
hit where BOTH in-place rewriters decline (an IPv4 IHL overrunning the L3
payload, the one gate they share and both apply before their first UMEM write)
and asserts the sampler does not advance, because `tx/dispatch` re-runs mirror
selection on the fallback path and committing here would silently halve the
flow's effective mirror rate.

That decline is reachable ONLY for a frame whose bytes changed AFTER the shim
described them — NIC DMA into a recycled UMEM frame, the hazard `expected_ports`
and the #5466/#4965 preflight-then-commit contract exist for — so the fixture
models exactly that and the metadata it passes is the PRISTINE frame's.
`parse_ipv4` (`userspace-xdp/src/lib.rs`) does `read_bytes(data, data_end,
l3_offset, ihl)?` before deriving `l4_offset`, so a shim-delivered IPv4 packet
always satisfies `frame.len() - l3 >= ihl`, and `ipv4_declared_l3_end` then
clamps the trimmed payload UP to at least `ihl`: no self-consistent, shim-
produced IPv4 frame can take the `l3_payload.len() < ihl` bail at all. Those two
facts COMPOSE rather than corroborate, and the order matters: the shim leg is
the load-bearing one. `ipv4_declared_l3_end` returns `None` — not a clamp — on
exactly `frame.len() < l3 + ihl` (`frame/inspect.rs`), the input the shim leg
excludes, and `trim_l3_payload` then falls through to a `meta.pkt_len`-derived
length carrying no `ihl` relation at all (`frame/mod.rs`). So the clamp bites
only where the shim leg already holds; it is not an independent second guard,
and a reader must not lean on it alone. That is measured, not argued —
`live_flow_cache_callsite_ip_options_frame_takes_the_in_place_path_6304` feeds
the SELF-CONSISTENT IHL-15 packet (40 bytes of NOP options, an honest 80-byte
datagram, metadata derived from it) and the rewrite succeeds. The rollback
branch is therefore defense-in-depth against a post-parse frame change rather
than a hot-path case, which is why nothing else in the suite covered it. An
earlier revision of the fixture asserted an IHL the parser could not have
emitted alongside those offsets and called the pair well-formed.

The same module also binds `telemetry.dbg.forward` / `.tx` on BOTH staging arms.
`run_stage` built the debug counters and dropped them unread, so either
increment could be deleted with every guard above green — an undercounted
forward-debug metric on every established-flow cache hit **that forwards**. Both
increments sit inside the forwarding-disposition arm and after successful
staging, so a cached terminal drop, a red policer, a TTL-expired packet, a
LocalDelivery/Discard disposition, or a fallback whose builder returned `None`
never reached them and is not undercounted by the deletion. On a long-lived
permitted flow that qualifier excludes almost nothing, but it is not "every
hit", and an earlier revision of this line said it was.

The `BatchCounters` triple on the same arm — `forward_candidate_packets`,
`snat_packets`, `dnat_packets` — was unbound for the same structural reason and
one more: `run_stage` constructed `BatchCounters::default()` and dropped it, so
`StageRun` had nowhere to report them from, AND every fixture carried
`NatDecision::default()`, which makes the two `rewrite_*.is_some()` guards false
on every packet the module ever staged. Retention alone would have left the NAT
pair unreachable as well as unread. All three flush onto the operator-visible
`BindingLiveState` atomics of the same name (`BatchCounters::flush`,
`afxdp/mod.rs`) and reach the wire through `protocol/binding.rs`.
`live_flow_cache_callsite_accounts_forward_and_nat_packets_6304` closes them with
a fixture whose cached DECISION and cached DESCRIPTOR both carry a real SNAT and
a real DNAT, and asserts the translated addresses on the staged TX bytes so the
counters cannot claim a translation the wire never carried; an untranslated
second run binds the two guards rather than the two increments.

`lookup_counted`'s byte ARGUMENT was unbound in the "reaches past the adapter"
shape: every other caller in the tree (`flow_cache_tests.rs`,
`debug_state.rs`) invokes `lookup_counted` DIRECTLY with a literal, so they all
bind the callee's accumulation, and nothing bound what the cache-hit call site
chooses to pass. Replacing `meta.pkt_len` with `0` there leaves every lookup
decision identical and silently zeroes per-hit observed bytes — the number
`show flow-cache` reports per cached flow and the #4800 connection-rate analysis
reads. `live_flow_cache_callsite_counts_observed_bytes_on_the_hit_6304` drives
the stage and reads the entry back, on a fresh entry and on one pre-loaded with a
non-zero count so `+=` is distinguishable from `=`.

Two lines above those, the `record_in_place_l2_rewrite(rewrite_result
.l2_rewrite)` call was deletable with the WHOLE CRATE green — at the pre-fold
head, 4283 passed / 0 failed / 2 ignored plus every integration target,
measured rather than argued — and for a reason worth recording because it
recurs: the call RAN on every fixture and was observable to none of them. Every frame in the module egressed on the VLAN it arrived on, so
`eth_len == current_l3 == 18`, the classification was
`InPlaceL2Rewrite::SameLength`, and that arm of `record_in_place_l2_rewrite` is
an empty block — while nothing else in the tree asserted
`pending_in_place_vlan_push_desc_packets` or `_pop_desc_packets` either. A
counter whose only reachable arm is a no-op looks covered and binds nothing.
`live_flow_cache_callsite_accounts_vlan_pop_l2_rewrite_6304` closes it by giving
the same tagged frame an UNTAGGED egress: the tag is popped by sliding the TX
descriptor 4 bytes forward inside the same UMEM frame, and the cell asserts the
transmitted extent shrank by exactly 4 (so the label is honest) with the pop
counter at 1 and its three siblings at 0 (so the CLASSIFICATION is bound, not
merely "some counter moved").

The fixtures also keep every ifindex DISTINCT — wire VLAN 80 on physical
ifindex 6 resolving to logical unit 20080, and mirror output unit 200 resolving
through `forwarding.egress[].bind_ifindex` to physical XSK port 22 — because
`resolve_mirror_config` is keyed by the LOGICAL unit while `MirrorTargetMap` is
keyed by the PHYSICAL bind port. An earlier revision collapsed both onto one
constant and configured no VLAN or interface maps, which left two live
call-site regressions green: ignoring `meta.ingress_vlan_id` (no mirror config
resolves at all) and passing `config.output_ifindex` to admission unresolved
(`NoBinding`, and cache-hit mirroring stops).

Each of these reds under its own call-site-only mutation while both #6114 tests
stay green — with ONE measured exception worth recording, because it bounds
what this kind of test can prove. Reserve-before-sample INLINED at the call site
(rather than reverting the shared helper) is indistinguishable to a
SINGLE-THREADED observer of one COMPLETED invocation: the reservation is taken
with an AcqRel CAS and handed straight back by `PendingTxAdmission::drop` before
the call returns, so no counter, queue, frame, or sampler value differs
afterwards, and at cap it is not even reachable —
`try_acquire_pending_tx_admission` bails at its relaxed
`admitted >= admission_cap` load before the `compare_exchange_weak`.

That scope matters, and an earlier revision of this note got it wrong by
dropping it: the ordering IS observable to a CONCURRENT producer. While the
transient reservation is held the target's `pending_tx_admitted` is one higher,
so another worker pushing to the same mirror target sees the queue full and its
request is dropped — `mirror/mod_tests.rs::
live_mirror_admission_reserves_slot_against_interleaving_producer` demonstrates
exactly that exclusion. Reserve-first can therefore LOSE a second producer's
clone that sample-first would have admitted. State created and destroyed inside
one call is invisible to that call by construction and visible to anyone racing
it; "no state differs" was established by walking one invocation to completion,
which cannot decide the concurrent case.

No test observes that transient window, and none can observe THE WINDOW
deterministically: it is a pair of atomic RMWs entirely inside
`stage_flow_cache_hit`, with no production hook to synchronise against, so a
racing-producer test would have to catch the window open and would fail only
probabilistically.

DETECTING THE MUTATION is a strictly weaker requirement than observing the
window, and that IS deterministically available. It is now TAKEN:
`live_flow_cache_callsite_nonsampled_makes_no_shared_admission_attempt_6304`
counts calls into `try_acquire_pending_tx_admission`
(`afxdp/binding_state/tx_inbox.rs`) and asserts a NOT-SAMPLED packet reads ZERO
— reserve-first reads ONE. Single-threaded, no race, no flake, no release cost,
because it counts the ATTEMPT rather than catching the window open.

The counter is a `#[cfg(test)]` THREAD-LOCAL, not a `#[cfg(test)]` field on
`BindingLiveState`. That distinction is the whole reason the instrument is
takeable, and an earlier revision of this note missed it: it evaluated only the
field form, correctly rejected it — `BindingLiveState` is the very struct whose
cross-core cacheline behaviour #6114 exists to fix — and then generalised that
rejection to the instrument as a whole. A thread-local lives in its own storage,
and `#[cfg(test)]` is false for any non-test build, so the bump does not exist in
the shipped hot path. Thread-local rather than a process-global atomic for the
#6294 reason: the default `cargo test` runs in parallel and every sibling test
that enqueues a redirect bumps the same counter, so a global would be a
load-sensitive flake. The pattern already exists in the tree —
`OUTER_ROUTE_RESOLVE_COUNT` in `afxdp/frame/wg.rs`.

Four layout values are MEASURED rather than asserted — "a thread-local lives in
its own storage" is a claim about the compiler, and the struct it is a claim
about is the one #6114 is entirely concerned with. What was measured is size,
alignment and two field offsets. That is a tripwire aimed at one hazard, not
whole-struct neutrality; the scope paragraph below is part of the claim, not a
caveat on it. `BindingLiveState`, rustc 1.96.0, x86_64:

| instrument | size | align | off(`pending_tx_admitted`) | off(`delta_loss_pending`) |
|---|---|---|---|---|
| none — production build | 2304 | 64 | 2152 | 2280 |
| `cfg(test)` THREAD-LOCAL (the one taken) | 2304 | 64 | 2152 | 2280 |
| `cfg(test)` FIELD ahead of the counter | 2304 | 64 | **2160** | **2288** |
| `cfg(test)` FIELD declared last | 2304 | 64 | 2152 | **2288** |

Two things follow, and the second corrects the earlier note rather than restating
it. (1) The thread-local moves none of those four values, and four
`const _: [(); N]` asserts beside the struct hold it to that — none of the four,
which is a real result and a narrower one than "moves nothing": the other ~90
fields are not pinned and a perturbation confined to them would not show up.
They are deliberately NOT `cfg`-gated, so the
same literals are evaluated in the production build AND the test build, and an
instrument that moved ANY OF THOSE FOUR VALUES could satisfy at most one of the
two. That is the cross-configuration comparison a `#[test]` cannot make on its
own, since it only ever observes the test configuration. (2) The reason to decline a
`cfg(test)` FIELD is NOT that it changes the struct's size — measured, it does
not; it lands in existing tail slack. It moves OFFSETS, the #6114 counter's own
among them, so a size-only guard would have called both field shapes harmless.
`repr(Rust)` reorders, so even a field declared LAST moves a neighbour — which is
why the sentinel offset is pinned as well as the counter's.

What those four asserts are NOT, stated so the guard is not read as stronger than
it is. Size, alignment and two field offsets do not fingerprint a ~90-field
struct: a perturbation that moves only UNPINNED fields satisfies all four
literals in both configurations. They are a tripwire aimed at one hazard — a
`cfg(test)` member reaching this struct, in the two shapes measured above — not a
proof that the test-configuration layout equals the production one. They are also
toolchain- and target-specific: `BindingLiveState` is `repr(Rust)` and the crate
pins neither a `rust-version` nor a toolchain file, so a compiler upgrade can trip
these literals with nothing in the source having moved. That failure direction is
safe (a changed value is a compile ERROR carrying the actual number, never a
silent accept), but it means the right response to a trip is to re-measure, not to
widen the guard. The runtime cell in `binding_state/tests/tx_inbox.rs` mirrors the
same four numbers and, for the same reason, cannot FAIL — the un-gated `const _`
fails the build first, so the test binary carrying it would never be produced.

And nothing pins the four asserts themselves. Measured: deleting all four
compiles the complete test binary and the mirrored runtime cell still passes,
and each line is individually deletable with the same result. They are given no
guard of their own on purpose. The only shapes available for guarding a source
construct are a match on its NAME or on its TEXT, both of which are proxies a
differently-spelled equivalent satisfies, and a guard that is itself a `const`
would be exactly as deletable as what it guards. No runtime witness is possible
either: what the four lines assert is a statement about the PRODUCTION
configuration, and a test binary is by construction the test configuration.
Every tripwire terminates somewhere and this one terminates at itself, so the
scope is written down instead.

What their presence buys is measured, with a `cfg(test)` `AtomicU64` declared
ahead of `pending_tx_admitted` — the hazard's own shape. Asserts present and
literals untouched: `cargo build` succeeds and the test build fails, reporting
2152 -> 2160 and 2280 -> 2288. Asserts present and literals re-measured to
2160/2288 so the test build passes: the test build succeeds and `cargo build`
then fails, reporting the two values back the other way — the "at most one of
the two builds" property, which is what makes the guard un-satisfiable by
re-measuring in whichever configuration is in front of you. Asserts DELETED and
the runtime cell's own literals re-measured to 2160/2288: production build and
test run both pass and the test-only perturbation is accepted in silence. That
last cell is what deleting the four lines costs, and it is the difference
between them and the runtime cell — the runtime cell can be re-measured green,
and they cannot.

Measured, at the head that added it: reverting `sample_then_admit_mirror_clone`
itself to reserve-first (reserve, then drop the reservation when the sampler
declines) reds that ONE test and leaves the other 4284 green — including the
delegation canary, since the call site still delegates. That form was previously
caught by nothing at all. Also bound either side of the window:

- DELEGATION — a source canary asserts the call site reaches the queue through
  `sample_then_admit_mirror_clone` and never calls `admit_mirror_clone_to_live`
  directly. It is retained for diagnosis — it localises a regression to "the
  call site stopped delegating" rather than leaving only a counter mismatch —
  but it is no longer what the ordering rests on. Its two enumerated escapes are
  now covered by the attempt-count test, both measured: a reserve-first rewrite
  INSIDE the helper (canary green, attempt count red), and the rename escape
  `use ...::admit_mirror_clone_to_live as admit;` with a stale comment retaining
  the required spelling (canary green, attempt count red). A call-site
  open-coding that keeps the plain spelling reds both.
- SHARED-CAPACITY ACCOUNTING —
  `live_flow_cache_callsite_leaves_no_admission_stranded_on_target_6304` drives
  the target at a soft cap of exactly one slot, so an interleaving producer is
  the instrument: after a non-sampled packet and after a declined rewrite the
  slot must be free, and after an admitted clone it must be taken. That reds on
  any reservation the call site takes and fails to hand back (measured: leaking
  it on the rollback path reds only that test, with the whole rest of the suite
  green).

**Telemetry call sites in this function, swept individually.** Two rounds found
an unbound `record_*` call by severing one line, so the whole set was severed one
at a time against the full crate rather than continuing one report at a time.
The sweep was then re-run rather than inherited, and the re-run changed two rows.

| site | single-line production edit | result |
|---|---|---|
| `filter::record_filter_counter` TX/output side (#2573) | walk reduced to `.for_each(\|_counter\| {})` | **was GREEN — UNBOUND** |
| `filter::record_filter_counter` INPUT side (#3777) | same | RED — `txn_flow_cache_hit_replays_input_filter_then_count_3777` |
| `policy::record_policy_hit_counter` (#3073) | call replaced by `let _ = counter;` | **was GREEN — UNBOUND** |
| `zone_counters::record_zone_traffic` (#3651) | call deleted | **was GREEN — UNBOUND** |
| `record_mirror_clone_result` (#6304) | call replaced by `let _ = (..);` | RED — 4 cells |
| `tx_counters.record_in_place_l2_rewrite` | call deleted | RED — the r3 cell |

Three sites bound nothing, in THREE shapes of one failure:

- `policy::record_policy_hit_counter` was UNREACHABLE — every fixture left
  `policy_counter: None` with `policy_counter_idx: 0` against a
  `ForwardingState::default()` policy snapshot, so `resolve_session_hit_counter`
  returned `None` and the guarded block never ran. Bound by
  `live_flow_cache_callsite_recounts_the_established_policy_hit_6304`, which binds
  a real counter handle onto the cached entry and asserts packets AND bytes — the
  byte cell distinguishes `meta.pkt_len` from a stripped L3 length, which the
  packet count alone cannot.
- `zone_counters::record_zone_traffic` RAN on every fixture and did nothing — an
  empty `ZoneCounterSlotMap` and an `EGRESS_IFINDEX` absent from
  `forwarding.egress` make both slot lookups 0, and the function returns at
  `if ingress_slot == 0 && egress_slot == 0`. Bound by
  `live_flow_cache_callsite_accounts_per_zone_traffic_6304` through a
  `with_zone_accounting` fixture builder. Both directions are asserted, because
  the ingress zone comes from the shim metadata and the egress zone from
  `egress_zone_id(..)` — two independent resolutions, and asserting one leaves the
  other free.
- the TX-side `filter::record_filter_counter` RAN and iterated an EMPTY
  collection, so the closure holding the call never executed. Crate-wide, the one
  test that puts a real counter on the cached TX-side `tx_selection` is
  `txn_flow_cache_hit_ttl_check_precedes_egress_accounting_3779`, and both of its
  assertions on that counter are NEGATIVE — the seed packet charges it on the COLD
  path, and the TTL=1 cache-hit packet must NOT charge it. Severing the hit-path
  replay satisfies both, so a test that looks like coverage for #2573's replay is
  coverage for #3779's suppression. Bound by
  `live_flow_cache_callsite_replays_every_filter_count_term_6304`, which carries
  TWO tx-side handles (#2573's guarantee is that ALL matched count terms replay,
  not just the last) and asserts the input side at this call site as well, since
  #3777 exists because the two sides regressed independently once already.

The arguments are bound too, not merely the occurrence: swapping
`record_zone_traffic`'s ingress/egress zone arguments, zeroing its byte argument,
zeroing `record_policy_hit_counter`'s byte argument, zeroing
`record_mirror_clone_result`'s frame length, and forcing its result to `Enqueued`
each red exactly the cell that asserts that property.

SCOPE, stated with a measurement rather than an assertion. The swept set was the
calls named `record_*`. That name is not the boundary of the per-packet
accounting `stage_flow_cache_hit` performs, and an earlier revision of this
paragraph said there were only two others. The full non-`record_*` set, as of the
round-3 head:

- `sessions.touch_if_stale(..)` (#918 staleness) and `sessions.account_packet(..)`
  (#2501 byte/packet accounting, #2749 TCP-flags and DSCP capture for the
  SESSION_CLOSE RT_FLOW record). Deleting EITHER leaves the whole crate green —
  4264 passed, 0 failed, on each — so both are STILL unbound at this call site.
  Recorded rather than closed: binding the session table's accounting is its own
  piece of work.
- `flow_cache.lookup_counted(.., meta.pkt_len)` — per-hit observed bytes. Its
  byte argument is now bound by
  `live_flow_cache_callsite_counts_observed_bytes_on_the_hit_6304`.
- `apply_cached_three_color_policers(.., meta.pkt_len as u64)` — the cached
  policer consumes credit per packet from its byte argument. Not swept.
- The direct field increments: `telemetry.counters.forward_candidate_packets` /
  `.snat_packets` / `.dnat_packets`, `telemetry.dbg.forward` / `.tx`, and
  `tx_counters.pending_in_place_tx_packets`. All are now bound (see above); none
  of them is a `record_*` CALL, and a sweep keyed on that spelling would have
  missed every one. (`tx_counters.record_in_place_l2_rewrite(..)`, two lines
  from three of them, IS named `record_*` and IS in the table above — which is
  how the sweep reached that neighbourhood at all and then walked past its
  neighbours.)

The generalisation: a sweep keyed on a NAME is a proxy for the property "every
per-packet accounting effect is bound". It found three real gaps and then
under-reported its own residue by four, which is what a proxy does.

**#5190: the hit TALLY itself, not just the per-hit side effects.** The sweep
above bound what a SERVED hit records. It did not ask whether the packets counted
as hits were served. `lookup_counted` commits `hits += 1` (plus the LRU promote,
the `last_used_epoch` stamp and the `observed_bytes` add) as soon as
key/generation/epoch/lease pass, because it has to hand the caller a borrow of
the entry and cannot hold a mutable borrow across the caller's own validation.
`stage_flow_cache_hit` then re-checks two things the cache cannot see — the
per-shard neighbor MAC epoch (#3048/#5147) and the HA/fabric decision validity —
and on failure evicts the slot and returns `FallThrough`. That packet went to the
slow path, and it was still published as a cache hit. The per-ENTRY state needed
no undo (the eviction takes it), but the three tallies outlive the entry, so
`FlowCache::reclassify_hit_as_miss` now moves a rejected candidate to the
miss/eviction side at the reject branch — off the steady-state fast path, which
is untouched. It matters because the inflation is correlated: it peaks during
gateway VRRP failover, a NIC swap or an RG transition, i.e. exactly when an
operator reads `flow_cache_hits` to explain a stall. Bound by
`live_flow_cache_callsite_rejected_candidate_is_not_a_hit_5190` (which asserts
`FallThrough` FIRST, so a fixture that stopped reaching the reject branch fails
loudly instead of passing vacuously) plus the
`..._served_hit_still_counts_as_a_hit_5190` control, which is what stops the
correction being mis-wired onto the accept path.

The generalisation worth keeping: a telemetry call reached by every test is not
thereby covered. It binds nothing if a guard above it is false in every fixture,
nothing if its arguments select a no-op arm, nothing if the collection it walks is
empty — and nothing if the only test holding a live handle asserts the case where
it must NOT fire. None of the four is visible in a coverage report; all four are
visible to a one-line severance.

A second canary, living in `mirror/mod_tests.rs` because one inside the module
could not fire, asserts the test module is still registered at all — deleting
its three-line `#[cfg(test)] #[path] mod` declaration unregisters every guard
above with no build error. It matches the block CONTIGUOUSLY, `#[cfg(test)]`
included, because unregistering needs no deletion: rewriting the predicate to
`#[cfg(any())]` removes the module from every build while leaving the `#[path]`
attribute and the `mod` item in place, and a canary looking for those two
substrings independently passed under exactly that edit (measured — all eight
module guards silently stopped compiling and the suite stayed green). The
mirror clone is captured BEFORE the in-place rewrite and `packet_frame` ALIASES
the UMEM, so the fixtures slice `raw_frame` out of the UMEM as the poll loop
does: hand them a detached heap buffer instead and "the clone carries the
pre-rewrite frame" becomes true for free, and deferring the capture past the
rewrite — which ships a TTL-decremented, checksum-adjusted copy to the analyzer
port — goes unnoticed. The dispatch-path copy of the ordering
(`enqueue_sampled_mirror_clone`'s cross-worker
arm, which inlines the sampler rather than calling the shared helper) is
separately bound: flipping it to admit-first reds
`cross_worker_nonsampled_does_not_reserve_full_queue_5167` and
`cross_worker_sampled_reports_queue_full_5167`. The
`deriveUserspaceCapabilities()` gate has been removed; #1376 is closed for the
feature-gap audit, and the #1477 final-validation artifact set is closed.
Any further mirror-fidelity and pressure-survival work is production hardening,
not a retirement blocker.

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Userspace now publishes a snapshot key when cluster-synced root encrypted-password material exists, mints/validates cookies against the Unix wall-clock epoch, sends bounded SYN-ACK and validated-ACK RST replies through the AF_XDP TX path, and reports challenge/no-secret/SYN-ACK/ACK-RST/budget/valid/invalid/bypass counters. Active SYN-cookie screen profiles require that secret material at userspace capability admission; missing secret material also fails closed at runtime. #1374 is closed for the feature-gap audit; the final live HA/flood proof was delivered with the closed #1477 validation set. |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Live kernel-owned/tunnel-control cases use cpumap or pass-through; degraded helper/XSK states pass only proven local/control traffic and drop non-local transit |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed. The DECRYPTED plaintext is not zone-adjudicated — see [Tunnel plaintext is not zone-adjudicated](#tunnel-plaintext-is-not-zone-adjudicated-5618-wireguard-5619-ipsec) (#5619). |
| WireGuard (`interfaces <if> tunnel mode wireguard`) | The XDP shim steers inbound WireGuard transport to the kernel (#5582) and the helper's WireGuard control thread owns the UDP socket and the `wgN` TUN. The DECAPSULATED plaintext is not zone-adjudicated — see [Tunnel plaintext is not zone-adjudicated](#tunnel-plaintext-is-not-zone-adjudicated-5618-wireguard-5619-ipsec) (#5618). |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility. Operator metadata reads in API/gRPC/CLI/daemon now use `LastApplyResult()` instead of `LastCompileResult()`, with a canary preventing those surfaces from regressing to compile-result metadata. GC and HA session sync use `SessionStore`/`Telemetry`. The manager still holds a named userspace shim manager for XDP/map bootstrap state. API/gRPC/CLI session/counter readers plus daemon control paths still name root `pkg/dataplane` session/counter types (e.g. `SessionKey`, `CounterValue`); those imports are tracked as the intentional, documented allowlist in `pkg/dataplane/retirement_boundary_canary_test.go` and move to a domain package as that type-relocation work continues. This is post-retirement interface cleanup, not a retirement blocker |
| DPDK backend | Retired in #1525. The historical #1475 backend-local exception for its root `DataPlane` dependency applied pre-retirement; #1527 removes the registration import and #1528 deletes the package. |
| Dataplane event logging | Session open/close/update are emitted by userspace. Policy-deny, screen-drop, logged routing-instance filter hits, non-PBR input filter logs, output filter logs, cached output-filter hits, and lo0 filter logs now enqueue RT_FLOW frames through the non-blocking Rust event-stream producer with existing per-event rate-limit/loss accounting. Go decode/status handling feeds raw userspace RT_FLOW frames through the same `EventReader.ProcessRawEvent` syslog/local-log path as eBPF, with a deterministic UDP syslog fanout harness for policy deny, screen drop, and filter log. Policy-deny events now carry the snapshot's compiled numeric policy ID; filter-log events carry filter/term/action identity from the matched compiled term. #1379 is closed for the feature-gap audit; the final live cluster syslog proof was delivered in the closed #1477 validation set. |
| `show system buffers` | Userspace helper-status rendering covers AF_XDP UMEM/TX capacity, CoS queued-byte capacity, helper-published session-table and flow-cache capacity, active-session footer, neighbor counts, and worker queue pressure counters. The Phase 5 denominator decision is explicit: session-table and flow-cache values become fill percentages only from Rust-owned helper fields; neighbor-cache entries remain counters in the utilization table. #5673 added a bounded aggregate cap (`MAX_DYNAMIC_NEIGHBORS`) as a pre-policy anti-DoS growth bound on the learned map, but surfacing the neighbor-cache count as a fill percentage against it is a separate `show system buffers` display change (deferred) — the cap refuses over-cap learns, it is not yet wired as a utilization denominator. Formatter tests pin that dynamic counts cannot move into the utilization table without real denominators. |

### Tunnel plaintext is not zone-adjudicated (#5618 WireGuard, #5619 IPsec)

Both supported VPN modes decapsulate OUTSIDE the AF_XDP forwarding pipeline and
hand the inner packet to the Linux kernel. The kernel then routes and forwards
it, so **no xpf zone policy, session, NAT or screen is applied to the inner
traffic**. This is a real authority gap, not a wording nicety: an operator can
put the tunnel interface in a security zone, the commit is accepted, and nothing
in the CLI or the commit output distinguishes that zone from one that is
enforced.

| Protocol | Where decapsulation happens | Why the dataplane does not see the inner packet |
|----------|-----------------------------|--------------------------------------------------|
| WireGuard (#5618) | `userspace-dp/src/afxdp/coordinator/wg_control/dispatch.rs` — the helper's WireGuard control thread authenticates the record, enforces the peer's `allowed-ips` against the inner SOURCE address, then calls `slowpath::write_packet_nonblocking(tun_fd, inner)`. | The XDP shim deliberately steers inbound UDP on the configured listen port to the kernel (`wg_steer_to_kernel`, #5582) so the control thread can receive the outer transport, and the plaintext is written straight to the `wgN` TUN. The in-source comment states it: "the kernel routes/firewalls it (NOT the AF_XDP policy engine)". |
| Route-based IPsec (#5619) | The kernel XFRM stack; the plaintext is delivered on the `xfrmi` netdev. | There is no path to hand a plaintext frame back INTO an `xfrmi` for the egress direction, so the dataplane cannot own the interface end-to-end. |

In both cases the interface row is excluded from the ingress-adjudication set:
`userspaceSkipsIngressInterface` (`pkg/dataplane/userspace/ingress_exclusions.go`)
matches WireGuard through the `Tunnel` class of `netdevExclusionClasses` and
IPsec through the `SecureTunnel` class, so the row is left out of
`buildUserspaceIngressIfindexes` and of the AF_XDP binding plan, and
`syncInterfaceAttachments` detaches the shim from the netdev.

**Operator-visible consequence.** Inter-zone authority for tunnel traffic is
delegated to the kernel FIB plus nftables, and xpf installs only `hook input`
chains while force-enabling `ip_forward` — so tunnel-to-LAN transit is
forwarded unfiltered. `allowed-ips` is not a substitute: it is a cryptographic
peer/source ownership gate on the inner source address, with no destination, no
zone-pair, no application and no direction. Leaving the tunnel out of a zone is
not a mitigation either: the plaintext never reaches zone policy at all, so
zoning or not zoning the interface does not change whether it is adjudicated.

(This paragraph used to add that an interface in no zone resolves to zone id 0
and "a `from-zone any to-zone any permit` rule matches zone-pair (0,0)". That
was never true: the #3110 guard has fenced every rule tier, wildcard tiers
included, against zone 0 since before the claim was written, and #6682 went
further and made an unzoned INGRESS an explicit counted deny. The conclusion
above is unchanged; only the mechanism was wrong, and the mechanism is what an
operator would have acted on.)

**Commit-time signal.** Both gaps now emit a commit-time advisory naming the
affected tunnels and, where one is assigned, the zone that does not govern them:
`warnWireGuardPlaintextUnadjudicatedAST`
(`pkg/config/compiler_wireguard_plaintext_warn.go`, #5618) and
`warnSecureTunnelPlaintextUnadjudicatedAST`
(`pkg/config/compiler_ipsec_plaintext_warn.go`, #5619). They share their
aggregation shape and zone-membership reader
(`pkg/config/compiler_tunnel_plaintext_advisory.go`). Each emits ONE aggregated
advisory per commit on every compile path — strict commit, lenient
restart/peer-sync, and both HA node views — and NEITHER can reject: they have no
error return and no `lenient` flag, so a box already running a tunnel can still
commit an unrelated change (#1960 no-brick).

The advisories make the bypass VISIBLE. They do not enforce policy on the inner
traffic; enforcement (re-injecting the decapsulated packet into the AF_XDP
forward/zone-policy pipeline on the tunnel's logical interface, the model native
GRE decap already follows in `userspace-dp/src/afxdp/gre.rs`) is tracked
separately. Native GRE is the contrast case and is NOT affected: it decaps
inside the worker pipeline, rebinds `ingress_ifindex` to the tunnel's
`logical_ifindex`, derives `ingress_zone` from
`ForwardingState.ifindex_to_zone_id`, and continues through screen, session,
route, filters and zone-pair policy.

## Observability — per-zone traffic + flood counters (both populated, #3651)

Per-zone ingress/egress packet+byte volume (`show security zones` "Traffic
statistics") and per-zone SYN/ICMP/UDP flood-event counts (`show security screen
ids-option statistics` "Per-zone flood counters") are both now **populated by
the userspace dataplane** (#3651). Either surface still renders an explicit
**"not available"** for a zone the helper did not publish — which is a real
state, not a feature gap: the helper's blocks are sparse, so the sentinel covers
a helper predating the accounting, a zone past the hot-path slot capacity, and a
zone with no traffic / no flood events alike.

- **HIDE (#3643) is what shipped first.** `dataplane.ReadZoneCounters` /
  `ReadFloodCounters` key a Go-side sparse offset map instead of indexing the
  dense array (so a stable-hash zone id `>= MaxZones` no longer OOB-errors the
  read), returning the distinct `dataplane.ErrCounterNotPopulated` sentinel
  while unpopulated. The always-erroring `xpf_zone_packets_total` /
  `xpf_zone_bytes_total` Prometheus metrics were dropped — and restored later
  in #3651, once the populate path below made them meaningful again (see
  `pkg/api/README.md` for the collector's populated / not-populated / failed
  disposition and the `xpf_zone_counters_unpopulated_zones` gauge).

- **POPULATE traffic (#3651) is what now ships.** The Rust helper accounts
  per-zone traffic on the forward hot path via a flat direct-index
  `[u8; 65536]` zone-id → slot LUT (`userspace-dp/src/afxdp/zone_counters.rs`
  `ZoneCounterSlotMap`, 63 assignable slots + `overflow_active`): two array
  reads per forwarded packet into a per-worker thread-local coalescer (no
  per-packet hash, no per-packet atomic — the same coalesce-then-fold pattern
  as the policy/filter hit counters), folded per RX batch into a
  coordinator-owned, zone-id-keyed `ZoneCounterStore` that rides `ForwardingState`
  and survives config commits. The per-batch fold is **lock-free** (#5163): the
  store holds one four-`AtomicU64` `ZoneTotalsAtomic` block per zone id and each
  slot caches its zone's block, so the fold `fetch_add`s straight into per-zone
  atomics with no shared mutex — the `ZoneCounterStore` mutex only guards the
  map STRUCTURE for the ≤ 1 s snapshot / clear / reconcile ops. (Before #5163 the
  fold locked that single mutex on every worker every batch, bouncing one cache
  line at line rate — cross-worker serialization on the hot path.) The helper
  pre-sums across workers into ONE
  `ProcessStatus`-level sparse per-zone block (`zone_traffic_counters`, layout
  version 1, only nonzero rows). The Go status poll
  (`syncBPFCountersLocked`) mirrors each row into the bpfShim offset map via
  `ReplaceZoneCounterOffsets`, so `show security zones` Traffic statistics, the REST
  `/security/zones` endpoint, and the Prometheus collector report live volume.
  A `clear_zone_counters` control IPC resets the helper's cumulative store (the
  Go `ClearZoneCounters` / `ClearAllCounters` overrides send it) so an operator
  clear does not snap back on the next 1 s poll. Design of record:
  [`docs/research/3643-dead-counters/plan.md`](research/3643-dead-counters/plan.md)
  §5A.

  **Rejected-build safety (#5716).** The store is `Arc`-backed, so the
  carry-forward `clone()` in
  `build_forwarding_state_with_policy_counters_and_previous` is a handle on the
  LIVE map, not a copy. Binding a candidate to it mutates it **two** ways:
  `ZoneCounterSlotMap::build` GET-OR-CREATES a block per SLOT-ASSIGNED zone —
  a SUBSET of the configured set, not one per configured zone (#7040) — and
  `reconcile` DROPS the blocks for zones the candidate no longer configures. A
  snapshot the reconcile/refresh preflight REJECTS ("keeping previous forwarding
  state") must do neither — the prune would zero an operator's
  `show security zones` totals for a commit that never applied, and the
  get-or-create would leave a zero-valued block behind for a candidate-only
  zone (invisible to the sparse status snapshot, but accumulating one block per
  rejected commit under ordinary config churn).

  The SUBSET qualifier is load-bearing and was corrected in three code sites by
  the same PR that introduced this block (#6832), which left the doc behind.
  `build` filters zone id 0 out of its input and `break`s once
  `ZONE_COUNTER_ASSIGNABLE_SLOTS` are taken, setting `overflow_active`; every
  configured zone past that point is assigned no slot and therefore gets no
  block. So the get-or-create half of the mutation is bounded PER APPLY by the
  slot capacity rather than by the size of the candidate's zone set. It is not
  bounded ACROSS applies — successive rejected commits naming different
  candidate-only zone ids each add up to that many blocks to the zone-id-keyed
  store — so the accumulation described above stands; only its per-commit
  magnitude was overstated.

  Code of record: `ZoneCounterSlotMap::build`
  (`userspace-dp/src/afxdp/zone_counters.rs`), whose own doc comment states the
  same qualifier, as do `attach_zone_counters`
  (`afxdp/forwarding_build/mod.rs`) and `afxdp/coordinator/reconcile/snapshot.rs`.
  The capacity stop and the `overflow_active` flag are already bound by tests in
  `afxdp/flood_counters.rs` (`flood_and_traffic_slot_maps_cover_the_same_zones`
  and the overflow assertions around it), so this correction needs no new test —
  the code fact was never in doubt, only its restatement here.

  Both mutations therefore live in `attach_zone_counters`, which the public
  entry point calls **after** the fallible `build_fallible_forwarding_state`
  has returned `Ok`. That makes the ordering STRUCTURAL: a fallible step added
  anywhere in the inner builder is above the `?` by construction. The earlier
  shape put the prune last inside one big function and relied on a source-order
  comment, which is not a guard — moving the NPTv6 `?` step below the prune left
  the entire pre-existing Rust suite green (measured, #6832 fold r2: 4280 of
  4281, the one failure being this round's new zone-block assertion, a different
  defect).

  Guards, in `userspace-dp/src/afxdp/forwarding_build/tests.rs`:
  `rejected_build_does_not_prune_live_zone_counters` and
  `rejected_build_does_not_create_zone_blocks_in_the_live_store` each drive
  FOUR of the inner builder's ten fallible integrity belts, chosen by POSITION
  rather than exhaustively — #3719 duplicate zone id (the first `?`) and #2410
  CoS queue id (the last, with nothing fallible after it), via #2240 NPTv6 and
  #3367 filter — so hoisting the binding back into the fallible region reds
  them. Span, not count: every STRAIGHT-LINE statement position the binding
  could be relocated to and still be a defect has a `?` below it, hence lies
  above the LAST belt, so the CoS row sees all of them. (A hoist below the last
  `?` stays green, correctly — nothing after it can reject. A relocation into a
  conditionally-evaluated closure a row's snapshot never enters is outside the
  quantifier, and is stated in the builder's doc comment rather than assumed
  away.) The dup-zone row pins where the fallible region BEGINS, which is what
  makes "the last belt" a checkable bracket rather than one arbitrary belt. It
  stays green only for a relocation strictly BELOW it — it rejects first, so
  the relocated block never runs — and those are exactly the ones the CoS row
  catches; a hoist ABOVE it, to the top of the fallible region, reds the
  dup-zone row of both zone tests (measured, #6832 fold r4).
  A single-belt fixture binds neither: it stays green when a *different* belt
  moves. `accepted_build_defers_the_prune_to_the_commit_point` is the
  anti-over-fix control. The create half is only observable through
  `ZoneCounterStore::tracked_zone_ids_for_test`, since the operator-facing
  `snapshot()` omits all-zero rows by design.

  **The rejection surface is wider than the integrity belts (#6832 fold r5).**
  Everything above concerns a snapshot the BUILDER rejects. A build can also
  succeed and the apply still be rejected afterwards, by a worker-thread spawn
  failure (#4952) or an incomplete queue bind (#5143) — and the destructive
  prune used to have already run by then, so a removed zone's cumulative totals
  were destroyed for a configuration that never brought up a worker (measured:
  live `{100,200}`, candidate `{100,300}`, forced spawn failure → visible rows
  `[100]`). The two bring-up failure arms are not equivalent:
  `WorkerBindIncomplete` calls `stop_inner`, which defaults `coord.forwarding`;
  `WorkerSpawn` does not, so the candidate state stays PUBLISHED and
  `show security zones` keeps reporting from the store it just pruned.

  The prune therefore now lives in `forwarding_build::commit_zone_counter_prune`
  and each apply path calls it at its own commit point — the full reconcile only
  after `bring_up_workers` returns `Ok`, the same-plan refresh at its
  `self.forwarding` swap (nothing fallible follows it). The build keeps only the
  ADDITIVE get-or-create, which cannot be deferred: the slot map caches real
  per-zone `Arc`s at build time. Bound by
  `rejected_apply_does_not_prune_live_zone_counters_6832` (negative) plus
  `committed_reconcile_…` / `committed_refresh_…` (one per call site).

  Scope note: #6832 was the ZONE-counter store only. The same rejected build
  also left get-or-create residue in the shared `PolicyCounterStore` and
  `NatCounterStore` — pre-existing, untouched by #6832, and tracked as
  **#6995**. **#6995 is now CLOSED**, by a different mechanism: those two
  bindings cannot be deferred the way the zone binding was (the handles are
  embedded in `PolicyState` and the NAT tables at construction), so
  `build_forwarding_state_with_policy_counters_and_previous` instead CAPTURES
  both registries before the fallible build and retains them back to the
  captured sets on `Err`. A retain to the pre-build set evicts only ids that
  build created and cannot drop a row carrying live totals.

  The NAT half was the operator-visible one: `NatCounterStore::snapshots()`
  emits a row per stored id regardless of value, feeding
  `ProcessStatus.nat_rule_counters`, so a refused commit put phantom NAT
  rule-counter rows on the status surface until the next successful commit
  evicted them. Bound by
  `rejected_build_does_not_leave_policy_blocks_in_the_live_store_6995`,
  `rejected_build_does_not_leave_nat_rows_in_the_live_store_6995` and
  `rejected_build_leaves_no_phantom_rows_on_the_nat_status_surface_6995` — the
  store and the surface asserted SEPARATELY, because a fix that filtered
  zero-valued rows out of `snapshots()` would satisfy the surface one while
  leaving the store dirty.

  `rejected_build_leaves_the_zone_store_clean_against_live_sibling_stores`
  still drives the belts with all three stores LIVE (the other rejection tests
  pass fresh siblings, so they prove the zone guarantee only against empty
  neighbours). Its residue predicates — which pin the relative ORDER of the
  policy parse, the NAT parse and the belts — moved down one layer to
  `build_fallible_forwarding_state`, where the get-or-create happens and where
  nothing has rolled back yet; at the caller's layer the row now asserts both
  sibling stores come back UNCHANGED. The comment that said "a later fix to
  either half of #6995 reds it instead of leaving this note stale" did exactly
  that: the fix reddened the row, and this is the note it was protecting.

  "Both" is load-bearing and was not true when first written: the row seeded
  only the NAT store and left the policy store a bare `default()`, so the
  policy half was still the empty neighbour the row exists to stop relying on.
  It now seeds the policy store through the production path (a clean build,
  which get-or-creates the reserved default-policy counter), carries a
  candidate-only `probe-rule` so the residue is distinguishable from the seed,
  and asserts both halves belt-by-belt. The enumeration is by POSITION relative
  to the two counter-binding call sites — the policy parse
  (`parse_policy_state_with_counters`) and the source-NAT parse
  (`parse_source_nat_rules_with_previous`, about sixty lines below it) — and
  since #6832 round 7 it is a THREE-way split, not two (#7042):

  | belt | position | policy residue | NAT residue |
  |---|---|---|---|
  | `#3719` duplicate zone id | above both parses | absent | absent |
  | `#3402` unresolvable policy zone | **between** them | **present** | **absent** |
  | `#2240` NPTv6 | below both | present | present |
  | `#3367` filter | below both | present | present |
  | `#2410` CoS queue id | below both | present | present |

  The middle row is the point of the set, not an extra. Over the other four the
  two residue predicates are the SAME expression — every one of them sits either
  above both parses or below both — so the table could not tell them apart, and
  that was true only by coincidence of the current builder layout. A belt landing
  anywhere in the region BETWEEN the two parses makes one of the two assertions
  wrong, and none of the four could detect it.

  `#3402`'s `UnresolvableZoneReference` rejects INSIDE the policy parse's rule
  loop — downstream of the per-rule `rule_hit_counter` that resolves the probe
  rule's counter, upstream of the source-NAT parse — so it occupies that region
  and the two predicates can no longer be written as one expression without a row
  contradicting them. It lives in `policy_parse_interior_rejection_row` and is
  deliberately NOT folded into `zone_counter_rejection_rows`, whose four rows are
  chosen by a different argument (span over the fallible region) that this row
  would blur.

- **POPULATE flood (#3651) now ships too.** Per-zone SYN/ICMP/UDP flood-event
  attribution is NEW drop-path accounting, not a snapshot of existing state: the
  screen module holds per-zone rate-LIMITER state (token buckets, count-min
  sketches), and the only durable screen accounting was global/per-reason
  (`record_screen_drop` → `screen_reason_drops`, #3343). The tally therefore
  lives on the DROP path — `BatchCounters::record_screen_drop` now also calls
  `flood_counters::record_zone_flood_drop`, so one call feeds the aggregate, the
  per-reason ordinal, and the per-zone family and a new drop site cannot bump one
  while forgetting the others. Structure mirrors the traffic half exactly
  (`userspace-dp/src/afxdp/flood_counters.rs`): flat `[u8; 65536]` zone-id → slot
  LUT built from the same configured zone set (a static assert pins the two
  capacities equal, so a zone is slotted for both families or neither), a
  per-worker thread-local coalescer, and a lock-free per-RX-batch fold into
  per-zone `AtomicU64` blocks the slot map cached at build time. It is coalesced
  rather than folded at the drop site because a SYN flood IS the primary
  screen-drop trigger — at attack rate every worker would otherwise `fetch_add`
  the SAME zone's cache line per packet, the #1187 constraint `stage_screen_check`
  already documents for the aggregate. The helper pre-sums into a second
  `ProcessStatus`-level sparse block (`zone_flood_counters`, layout version 1,
  nonzero rows only); the Go status poll mirrors it via
  `ReplaceFloodCounterOffsets`; a `clear_flood_counters` control IPC resets the
  helper store (the Go `ClearAllCounters` override sends it) so an operator clear
  does not snap back on the next 1 s poll.

  **Rejected-build safety, flood half.** The flood store is the exact sibling
  of the traffic store above — `Arc`-backed, carried forward by the same
  `previous` handle — so the #5716/#6832 split applies to it verbatim, and it
  rides the SAME two functions rather than getting its own pair.
  `attach_zone_counters` binds both families (additive get-or-create only,
  after the fallible builder has returned `Ok`), and
  `commit_zone_counter_prune` reconciles both stores at each apply path's own
  commit point. Sharing the call sites is deliberate: a
  `const _: () = assert!(FLOOD_COUNTER_SLOTS == ZONE_COUNTER_SLOTS)` in
  `flood_counters.rs` exists so a zone is slotted for BOTH families or NEITHER,
  and a separate `attach_flood_counters` / `commit_flood_counter_prune` pair
  could be reordered, relocated, or forgotten at a new apply path independently
  of the traffic pair — which would make that assert claim a coupling the code
  no longer had. One call site makes the divergence unrepresentable rather than
  merely tested for.

- **Live substitutes and companions.** Global flow statistics, per-interface
  `Bindings[].RX/TX{Packets,Bytes}`, per-policy hit counters (#2118, zone-pair
  scoped), and per-screen-reason drop counters (#3343). Note that simply summing
  per-interface binding counters into zones (the §5C DERIVE shortcut) was
  rejected as the traffic source: one physical binding hosting VLAN units in
  different zones cannot be split by logical unit, so DERIVE would mis-attribute
  — worse than the honest hot-path accounting that #3651 now does.

- **Global counter clear is an epoch (#5098).** `ReadGlobalCounter` returns the
  per-CPU `global_counters` BPF array sum PLUS an in-memory `userspaceCounterOffsets`
  entry. `IncrementGlobalCounter` — driven by `syncBPFCountersLocked` — ACCUMULATES
  each 1/s helper delta (`cur - prevBindingCounters`) into that offset so
  userspace-forwarded packets (RX/TX, aggregate/per-reason drops #4477/#3343/#3326,
  SYN-cookie, NAT64) that bypass the BPF pipeline are reflected. This is an
  ACCUMULATE, not an absolute overwrite like the NAT (#2218) and per-zone (#3651)
  offset stores — so a clear must zero the offset explicitly or the cleared total
  snaps straight back on the next read. `ClearGlobalCounters` now drops the whole
  offset map first (under the same `m.mu` that guards every offset read/write, and
  even without a loaded BPF map — parity with `ClearZoneCounters`/
  `ClearNATRuleCounters`), and `ClearAllCounters` inherits it; the userspace
  `ClearAllCounters` also rebases `prevBindingCounters` to the last-recorded
  cumulative so the next poll's delta measures traffic strictly AFTER the clear.
  There is no `clear_global_counters` helper IPC: the helper's cumulative binding
  counters keep climbing from launch, and the rebased delta baseline (not an IPC
  reset) is what makes the cleared value stick.

## Retirement History (closed)

The #1373 eBPF retirement is complete. This section is a record of the closed
removal phases, not pending work.

The #1374-#1381 feature-gap audit is closed. #1377 closed source-NAT pool
retirement; its SNAT follow-ups #1448, #1449, and #1450 are closed as
documented contracts: helper restart resets helper-local persistent-NAT
leases, HA configurations with persistent source-NAT pools are gated because
leases are not synchronized, and new-flow pool-address parity is not promised.

| Issue | Removal phase (closed) |
|-------|--------------------|
| #1451 | Closed the eBPF-retirement removal-phase blocker: the userspace manager no longer embeds the legacy `dataplane.DataPlane`, runtime backend selection and forwarding are off the legacy surface, and the operator surfaces moved to apply-result metadata + `SessionStore`/`Telemetry`. Remaining root `pkg/dataplane` session/counter *type* imports in API/gRPC/CLI/daemon are the documented canary allowlist (`retirement_boundary_canary_test.go`) and are post-retirement interface cleanup, not a retirement blocker. |
| #1473 / #1493 | Split shim-only generation and the userspace shim loader/bootstrap from the legacy in-kernel forwarding loader so the retained shim survives while the legacy XDP/TC programs were removed. |
| #1476 | Removed legacy BPF source, generated artifacts, and build hooks, preserving the retained AF_XDP userspace shim path. |
| #1477 | Published the final userspace-only validation artifact set (cluster, screen/flood, CoS, HA, degraded-path evidence). |

#1474 is closed: omitted `system dataplane-type` selects userspace, and
explicit `system dataplane-type ebpf` is now hard-rejected (commit-time
`ErrEBPFDataplaneRetired`, runtime `ErrEBPFBackendRetired`); the
deprecation-warning surface that preceded the hard reject is gone.

The current canonical fallback contract is in the "Actual Fallback Mechanisms"
section below, which already reflects the post-#1476 hard reject.

## What This Document Does Not Mean

A feature being "implemented" here means the runtime has code for it. It does
not guarantee:

- that every configuration shape using the feature is currently admitted
- that every path is already hardened for HA failover
- that current performance is at parity with the legacy dataplane
- that there are no active correctness bugs in the forwarding path

Those are separate questions. Use:

- [`userspace-ha-validation.md`](userspace-ha-validation.md)
- [`userspace-perf-compare.md`](userspace-perf-compare.md)
- [`userspace-debug-map.md`](userspace-debug-map.md)

## Actual Fallback Mechanisms

There are two distinct fallback boundaries:

1. **Compile-time / reconcile-time gate**
   - The Go manager chooses the userspace runtime path by default.
     Explicit legacy eBPF selection (`set system dataplane-type ebpf`)
     was retired in #1476: the strict commit validator now hard-rejects
     it with `ErrEBPFDataplaneRetired`, and the runtime factory returns
     `ErrEBPFBackendRetired`. The deprecation-warning surface that
     preceded the hard reject is gone.
   - The Go manager keeps `xdp_userspace_prog` as the userspace-mode
     XDP entry. Capability gates for genuinely-unsupported *semantics*
     (class ii: color-aware policers, SYN-cookie material, persistent
     SNAT under HA) disarm helper forwarding rather than swapping
     userspace runtime traffic into the (now-deleted) `xdp_main_prog`.
     Unrepresentable policy *content* (class i) does NOT disarm (#3261):
     it relies on the helper integrity reject (previous-good retained /
     fresh-boot default-deny) so it never fails open to the kernel.
   - Required-generation protocol gates (policy schedulers, persistent
     source NAT, and — since #5488 — a scoped-global policy whose zone scope
     holds MORE THAN ONE zone on a side, which a pre-v4 helper would NARROW
     to the first zone by reading only the singular `match_from_zone`/
     `match_to_zone`) that disarm forwarding on a too-old helper are ALSO
     enforced on the explicit arm path (#5648 / M43b): `SetForwardingArmed(true)`
     re-runs `ensureRequiredSnapshotProtocolLocked` and refuses to arm a
     stale accepted image, so an operator/gRPC arm cannot undo the disarm.
     The SAME gate now also guards the ~1s desired-state reconcile
     (#6165): `syncDesiredForwardingStateLocked` re-runs the protocol check
     before it re-arms, because `desiredForwardingArmedLocked()` returns true
     whenever forwarding is *supported* and never consults the accepted
     snapshot protocol version. Without it, a scheduler-tick disarm
     (`UpdatePolicyScheduleState` → `disarmSnapshotProtocolFailureLocked`,
     which unlike an operator commit does NOT revert the active config) would
     leave `m.lastSnapshot` requiring the protocol while the helper is
     disarmed + protocol-stale, and the next reconcile tick would re-arm it —
     forwarding a config the helper cannot represent. The reconcile gate is
     scoped identically: only the ARM direction is checked (a disarm — demotion,
     shutdown, the protocol disarm itself — is never blocked), and it is a
     no-op unless the last-applied config requires the protocol.

2. **Runtime XDP decision**
   - Even when `xdp_userspace_prog` is active, the XDP shim can still:
     - redirect to AF_XDP
     - send kernel-owned traffic to cpumap / kernel
     - pass proven local/control traffic while helper/XSK is degraded
     - drop degraded non-local transit in both compat and strict modes
     - count those drops as `transit_drop` in `degraded_path_counters`; the
       pinned BPF map keeps the internal compatibility name
       `userspace_fallback_stats` until the mixed-version boundary is retired

## Priority Work

The #1373 retirement (including the #1451 removal-phase blocker, the
#1473/#1493 userspace XDP shim split, the #1476 source removal, and the
#1477 validation artifact set) is complete. Residual root `pkg/dataplane`
session/counter *type* imports in the operator surfaces are post-retirement
interface cleanup tracked by the canary allowlist, not a retirement blocker.
The highest-value remaining work on `master` is correctness, operational
hardening, and performance optimization on the active AF_XDP userspace
forwarding path — for example CoS regression work (#1614) and cold-path
hardening (#1608).

Keep #1377, #1448, #1449, and #1450 closed. SNAT helper-restart reset
behavior, HA persistent-lease gating, and cross-backend selector divergence
remain documented userspace contract limits, not active #1373/#1451 blockers.
