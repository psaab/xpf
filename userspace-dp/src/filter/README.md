# userspace-dp/src/filter/

Junos-style firewall filter compiler, evaluation engine, and policer.
Mirrors the BPF firewall-filter pipeline in userspace.

## Files

- `mod.rs` — public surface: `FilterAction` (`Accept` / `Discard` /
  `Reject` only), `FilterTerm` (the matched-and-action carrier),
  `PortMatcher`, `FilterTermCounter`, and three-color policer runtime
  counters. Side-effect actions like counting, logging, policing,
  forwarding-class assignment, and DSCP rewrite are **fields on
  `FilterTerm`** (e.g. `count`, `log`, `policer_name`,
  `three_color_policer`, `forwarding_class`, `dscp_rewrite`), not enum
  variants — the engine applies them around the action verdict.
- `compiler.rs` — parses the typed config's filter terms and lowers
  them to `FilterTerm`s (prefix vectors, protocol bitmap, port
  matcher, DSCP bitmap). Three-color policer snapshots are sorted by
  name for deterministic iteration and compiled into name-derived
  stable runtime IDs before terms are linked.
  - **Protocol resolution (#2505)** uses the SHARED, normalizing
    resolver `crate::ip_proto::proto_number` (trim + lowercase + the
    full `appid.ProtocolNumber` acceptance set — tcp/udp/icmp/icmpv6/
    gre/ospf/ipip/esp/ah/sctp/vrrp/igmp/pim/egp + the specific
    `junos-*` aliases + bare numeric). It does NOT carry a local
    protocol table. A `from protocol` token reaches the snapshot
    VERBATIM (Go's `compileFilterFrom` does no alias resolution), so
    the resolver must accept exactly what the Go filter commit gate
    (`filterProtocolResolvable`) accepts or a gate-passing filter would
    lose its protocol constraint in the dataplane.
  - **Fail closed, not fail wide (#2505):** an EMPTY protocol list
    means "no constraint" (`protocol_match_enabled = false`, match-any,
    preserved). A NON-EMPTY list with any UNRESOLVABLE token raises
    `SnapshotIntegrityError::UnrepresentableFilterProtocol`, which
    propagates up through `build_forwarding_state_*` to the reconcile
    preflight (`build_reconcile_forwarding`) and aborts the reconcile
    BEFORE teardown/publish (post-#2484), keeping the prior good filter
    state live. Silently dropping the token (the pre-fix `filter_map`)
    collapsed the list to empty and disabled the match, so a `from
    protocol esp; then discard` term matched EVERY protocol — a
    fail-wide security bug. The Go gate is the primary defense; this is
    the helper-boundary backstop against version/snapshot drift.
- `engine/` — per-term evaluation, first-match-wins (the #1546 split of
  the monolithic `engine.rs` into `mod.rs` / `eval.rs` / `matching.rs` /
  `policer.rs` / `tx_selection.rs` / `cache_sensitive*.rs`). It carries the
  matched `then policer ...` name in the filter result. Routing-instance
  evaluation can also return log/action/filter/term metadata so AF_XDP
  can emit PBR RT_FLOW filter-log events without re-evaluating the term
  or allocating on the packet path. The routing-instance result also
  carries an accumulated `log_match` (#2619) so a fall-through
  `then { log; next term; }` term ahead of the routing-instance term is
  not dropped from the PBR RT_FLOW path. The no-count log-only helper
  (`evaluate_filter_ref_log_match`) accumulates the LATEST matched logging
  term — sharing the full evaluator's semantics (#2618) instead of
  returning on the first one — while still skipping routing-instance terms
  so PBR logs are emitted only on the PBR path. TX-selection evaluation meters
  three-color policers, carries output filter-log identity through live
  forwarding and cached flow-cache hits, and preserves terminal
  `discard`/`reject` actions so output filters cannot log deny while
  forwarding. Input/output filters with DSCP match terms force the
  flow-cache insertion path to decline caching because DSCP is not part
  of the session key. Established session hits still re-evaluate
  DSCP-sensitive input filters per packet, and — since #7212 — re-derive a
  purely STATIC input filter's verdict once per config generation, revoking
  the session only when the verdict has become a DENY (see "Static
  input-filter revalidation stamp (#7212)" in `session/README.md`).
  Forwarding rotations compare
  DSCP-sensitive input filter content by stable names, terms, and
  three-color policer runtime shape, not by compiler-positional filter
  IDs, before deciding whether existing sessions need a conservative
  packet-family purge.

  **Interface `filter output` matches the POST-NAT on-wire tuple (#3642).**
  Junos applies an egress interface output firewall filter AFTER NAT
  (DNAT pre-route, SNAT post-policy), so the addresses/ports an output
  filter sees are the TRANSLATED (on-wire) values. On the TX-selection /
  CoS leg the transit callers therefore feed the classifier the egress
  wire key — `forward_wire_key(&flow.forward_key, decision.nat)` (see
  `session/key.rs`) — instead of the raw pre-NAT `forward_key`. This is
  applied at every TX-selection eval site that owns a NAT decision: the
  live forward builder (`afxdp/forward_request.rs`), the cached
  descriptor build (`afxdp/flow_cache.rs`), the ARP/NDP-resolved
  retransmit (`afxdp/neighbor_dispatch.rs`), and the deferred re-resolve
  (`afxdp/tx/dispatch/cos.rs`). `decision.nat` is in apply-to-this-packet
  form — `rewrite_forwarded_frame_in_place` / `apply_nat_ipv4|6` write the
  same `rewrite_src`/`rewrite_dst` to the frame regardless of direction —
  so `forward_wire_key` yields the correct egress tuple for BOTH the
  forward leg and the reverse/reply leg (no separate `reverse_wire_key`
  is needed at these sites). For NAT64 the wire key also carries the
  EGRESS address family, so `resolve_cos_tx_selection_*` selects the
  correct-family output filter from the (post-NAT) key rather than the
  ingress `meta.addr_family` — a v6→v4 flow evaluates the v4 output
  filter against the v4 tuple. The pre-NAT `flow_key` is still stored on
  the pending request for CoS flow-bucket hashing / session glue, so the
  hash bucketing is unchanged.

  **The ingress INPUT filter re-walk keeps the PRE-NAT tuple (#5158).**
  The post-NAT wire key above is correct ONLY for the egress OUTPUT
  filter. The same `resolve_cos_tx_selection_*` call ALSO re-walks the
  ingress interface input filter to pick up an input-filter
  `then forwarding-class` / dscp-rewrite / three-color policer (the
  `#hb166 T-3` leg, folded with `.or()` so an output-filter class still
  wins). Junos applies input filters BEFORE NAT, so that re-walk must
  match the ORIGINAL ingress tuple — feeding it the post-NAT wire key
  made a NAT'd flow miss its ingress classification/policer entirely. The
  transit callers that build a post-NAT `forward_wire_key`
  (`afxdp/forward_request.rs`, `afxdp/neighbor_dispatch.rs`, the
  `afxdp/flow_cache.rs` seed) therefore call the split entry points
  `resolve_cos_tx_selection_at_prenat` /
  `resolve_cached_cos_tx_selection_prenat`, passing the post-NAT wire key
  as the egress/output key and the pre-NAT session `forward_key` as the
  `ingress_flow_key`. The resolver evaluates the ingress input filter
  (its family gate, interface-filter lookup, and 5-tuple) on the pre-NAT
  key and the output filter + BA/queue selection on the post-NAT key. For
  a non-NAT flow both keys are identical, so the single-key entry points
  (`resolve_cos_tx_selection` / `_at`, `resolve_cached_cos_tx_selection`)
  pass the same key for both stages — behaviour-preserving.

  **Fall-through terms (`then next term` / modifier-only) (#2544).**
  "First-match-wins" applies only to TERMINATING terms. A term whose
  `then` carries NO terminating action — an explicit `then next term`
  OR a modifier-only term (only `count`/`log`/`forwarding-class`/
  `policer`/`dscp`) — must APPLY its modifiers and FALL THROUGH to the
  next term, per Junos semantics. The Go control plane records this:
  `buildFirewallFilterSnapshots` sets the wire field `next_term` true
  for a term with `NextTerm` OR an empty `Action` (a routing-instance
  PBR term is excluded — it takes its own routing decision). The Rust
  compiler maps `next_term` (or a belt-and-suspenders empty action) to
  `FilterTerm.continue_term`. Every per-term eval loop (`eval.rs`
  standard/non-routing/routing-instance/log-match, `tx_selection.rs`
  live, `cache_sensitive.rs` cached TX-selection) now: on a MATCH,
  applies the term's modifiers (count/policer side effects fire, and
  forwarding-class/dscp-rewrite/log/routing-instance accumulate into the
  running result, latest matched term winning per scalar, `log` and
  policer-drop OR'd); then, if `continue_term`, CONTINUES to the next
  term instead of returning. A matched TERMINATING term sets the result
  action and returns. If no term terminates, the accumulated modifiers
  ride the implicit default Accept. Before #2544 the empty action
  compiled to `FilterAction::Accept` and the loop returned on first
  match, so a packet matching a fall-through term was ACCEPTED there and
  a later `discard` was never reached. `continue_term` is compared in
  `filter_term_semantics_match` (it flips terminate-vs-fall-through
  without changing the parsed match vecs, so a flow-cache rebuild must
  catch a `then next term` toggle). The cached TX-selection result
  accumulates EVERY matched `then count` term in `CachedFilterCounters`
  (#2573), deduped by counter identity, so a flow whose fall-through set
  carries multiple `then count` terms increments all of them on the
  cached replay — matching the uncached full-eval path. The container is
  a `SmallVec<[_; 2]>` (built once at flow-cache install, only read on
  the per-packet replay), so the common single/dual-counter case records
  with no heap allocation. Before #2573 the result held a single
  `counter` Arc and the cached rebuild path recorded only the LAST
  matched count term (the earlier fall-through count terms were silently
  under-counted on the cached path only).

  **Terminal + next_term is fail-CLOSED (#5142, security).** A term with
  a REAL terminating action (`discard`/`reject`/`accept`) MUST terminate
  and apply that action — a `next_term` / fall-through bit must NEVER
  suppress it (vSRX filter semantics). The Go commit gate
  (`validateFilterTerminalConflictStrict`) now hard-rejects `then discard;
  then next term;` (a single terminal co-located with next-term), so the
  contradiction never reaches a snapshot through a commit. Belt-and-
  suspenders, the Rust compiler computes `continue_term :=
  snap.action.is_empty() && routing_instance.is_empty()` — a term FALLS
  THROUGH only when it carries no terminating action, so even a
  mixed-version peer-sync snapshot that sets `next_term` on a
  discard/reject term still TERMINATES (applies the deny). Before #5142
  the compiler read `(snap.next_term || snap.action.is_empty()) &&
  routing_instance.is_empty()`, so a discard/reject term carrying
  `next_term=true` fell through and left the `FilterResult::default()`
  implicit Accept in place — the deny was silently dropped (fail-OPEN).
  A modifier-only next-term term (empty action) still falls through, and
  a routing-instance (PBR) term is unchanged. Distinct from #4375 (two
  DISTINCT terminals) and #2544 (empty-action modifier-only next-term).

  The same accumulate-all-fall-through-terms contract applies to
  three-color policers via `CachedThreeColorPolicers`. Every matched
  fall-through term's `then policer` runtime is folded into the cached
  TX-selection result (deduped by policer `id`) and re-metered on each
  cached replay (`apply_cached_three_color_policers` → `for_each`), so a
  flow escapes NO term's committed/peak rate limit on the cached path.
  Like `CachedFilterCounters`, the container is a `SmallVec<[_; 2]>`
  (built once at flow-cache install, only `for_each`-read on the
  per-packet replay), so the common single/dual-policer case records with
  no heap allocation and any spill to the heap for >2 policers happens off
  the packet hot path. **Before #4566 this was a fixed two-`Option`
  (`first`/`second`) layout that SILENTLY DROPPED the 3rd (and beyond)
  fall-through policer on the cached path** — a flow with >=3 fall-through
  three-color policer terms escaped the 3rd+ term's rate limit on every
  cached packet (rate-limit slack, not a permit/deny bypass; the uncached
  full-eval path always metered each). Growing the array (option a) was
  chosen over declining the flow-cache for such flows (option b): the
  cached-path replay already iterates a variable count via `for_each`, the
  spill is off the hot path, and this keeps the cached and live paths
  meter-identical for ALL policer counts rather than diverging above two.

  **No-match default is implicit ACCEPT — a deliberate divergence from
  Junos (#3295).** When a packet matches NO term in a filter, the
  evaluation returns `FilterResult::default()`, whose action is
  `FilterAction::Accept` (`mod.rs`). The same default-Accept applies to a
  missing filter key and to a cross-family mismatch, and the separate
  TX-selection path has its own Accept defaults
  (`TxSelectionFilterResult` / `CachedTxSelectionFilterResult`). Junos
  stateless firewall filters instead carry an implicit final **discard**:
  a packet matching no explicit term is silently dropped. xpf keeps
  implicit-accept as the no-match default ON PURPOSE and does NOT flip it
  to discard. A global flip would blackhole the classify-and-pass OUTPUT
  filter idiom that rides the implicit accept — concretely the CoS
  `bandwidth-output` filters attached as `interfaces reth0 unit 80 family
  inet/inet6 filter output` (a pure dest-port allowlist with no final
  catch-all), whose unmatched egress would be dropped at TX selection
  (`afxdp/tx/cos_classify.rs` gates `drop` on `action != Accept`). That
  violates the project "keep GOOD" doctrine (#2124/#3261). The research
  record is `docs/research/3295-filter-failopen/plan.md`.

  **Operator workaround for Junos-style deny-by-default.** An operator
  who wants Junos stateless-filter parity appends an explicit final
  unconstrained term: `term <last> { then discard; }` (the inverse of
  Junos's "write a final accept"). The Go control plane emits a commit
  WARNING (`validateFilterNoCatchAllWarnings`,
  `pkg/config/compiler_validate_warn.go`) for any filter attached to an
  interface/lo0 input/output hook that has no terminal catch-all term, so
  the divergence and the workaround are surfaced at commit; it is never a
  commit error (implicit-accept is the documented default and a hard
  reject would brick a previously-accepted config). A `then next term` /
  modifier-only fall-through term is NOT a catch-all; a `then
  routing-instance` PBR term terminates but is not accept/discard/reject
  and so is also not treated as a catch-all.

  **Fall-through log action follows the terminal verdict (#2616).** A
  matched fall-through logging term records its identity
  (`filter_id`/`term_id`) into the accumulated `log_match`, but its
  `action` field holds the Accept PLACEHOLDER the compiler assigns an
  empty/`next term` action — NOT the verdict the packet receives. Every
  evaluator entry point (`evaluate_filter_ref_counted_v4/v6`, the
  `_non_routing_` variants, the routing-instance evaluators, and the
  log-only helper) now normalizes the stored `log_match.action` to the
  FINAL terminal action before returning. A `then { log; next term; }`
  term ahead of a terminal `discard`/`reject` therefore logs DENY, not
  permit — the RT_FLOW record no longer lies about the action while the
  dataplane denies the packet. For a terminating logging term
  `term.action` already equals the final verdict, so normalization is a
  no-op there.

  **PBR session-miss counts each fall-through term exactly once (#2620).**
  When an interface input filter is route-lookup-affecting (it has a
  `then routing-instance` term), the session-miss path can run TWO
  evaluators over the same filter: the non-routing precheck
  (`evaluate_interface_filter_non_routing_counted`) for the terminal
  verdict, and — ONLY on the precheck's Accept verdict — the
  routing-instance evaluator
  (`evaluate_interface_filter_routing_instance_event_counted`, via
  `ingress_route_table_override`) for the route override. On a NON-Accept
  verdict (`discard`/`reject`) the poll path `continue`s and the routing
  evaluator NEVER runs. Both evaluators walk every matched term, so without
  care a `then { count X; next term; }` fall-through term ahead of the
  routing-instance term was counted TWICE on the Accept exit. Counter
  ownership is therefore per-EXIT, not a property of the filter:

  - **Accept / defer exit** (fall-through to default, or a matched
    routing-instance term): the routing evaluator runs and counts every
    matched term up to and including the routing-instance term. The
    precheck must NOT count.
  - **Terminal `discard`/`reject` exit** (a non-Accept term matched, with
    `then count` fall-through terms ahead of it): the routing evaluator
    never runs, so the precheck is the sole counter and records each
    matched `then count` term up to and including the terminating one.
  - **Plain non-PBR filter** (no routing-instance term): the routing
    evaluator returns early at the `affects_route_lookup` guard and counts
    nothing, so the precheck owns the count on every exit.
  - **DSCP/L4 session-HIT re-eval**
    (`evaluate_dscp_sensitive_input_filter_on_session_hit`): this never
    invokes the routing evaluator, so the precheck counts per packet on
    every exit (pre-#2620 behavior).

  The precheck takes a `count_policy: NonRoutingCountPolicy`:
  `OnlyTerminalNonAccept` (count only on the terminal discard/reject exit —
  the routing evaluator owns the Accept exit count) vs `Always` (precheck
  is the sole counter, counts on every exit) vs `Never` (#7212 — count
  nothing at all).
  `evaluate_non_pbr_input_filter` derives it as `OnlyTerminalNonAccept`
  when `routing_eval_follows && interface_filter_affects_route_lookup(...)`
  else `Always`. The miss-path call site passes `routing_eval_follows =
  true` (an Accept proceeds to `ingress_route_table_override`); the
  session-hit re-eval passes `false`. This yields exactly one count per
  matched `then count` term on all four exits — neither the double-count on
  the Accept exit nor an under-count on the discard/reject or session-hit
  exits. (The earlier coarse fix gated the precheck solely on
  `affects_route_lookup`; that under-counted to zero on the discard/reject
  and session-hit exits, where the routing evaluator is never the counter.)

- **`Never` is the side-effect-free STATIC verdict (#7212).**
  `filter_ref_static_verdict` runs the SAME
  `evaluate_filter_ref_non_routing_counted` walk with counting suppressed on
  BOTH of its arms and returns only `.action`, so its verdict is the counted
  walk's verdict by construction — there is no second walk to drift. Its caller
  is the established-session-hit STATIC revalidation
  (`afxdp/poll_descriptor/filter.rs`), which re-derives an already-admitted
  session's verdict once per config generation to find out whether a newly
  attached or tightened purely-static filter now DENIES the flow. That packet is
  not a new arrival at the filter — it was adjudicated under the previous
  generation — so counting it would inflate every matched `then count` term by
  one packet per permitted session per commit, and `then log` would re-fire for a
  flow whose record was already emitted. Nothing else in the walk is a side
  effect: `then log` is DATA on the returned `FilterResult` (the caller emits the
  record) and the three-color policer is not metered by this evaluator at all
  (`now_ns = None`, #5857). On the DENY exit the caller re-runs the ordinary
  `Always` walk, so the one newly-denied packet is counted and logged exactly
  once. `NonRoutingCountPolicy::counting()` is an exhaustive `match` returning
  `(count during the walk, replay on a terminal non-Accept)` rather than two `==`
  comparisons, so a policy added later must classify itself on both axes instead
  of inheriting whichever answer a negated comparison happened to give it.

  **The route-lookup-affecting case is COMPOSED, not declined (#8114 item 1).**
  `filter_ref_static_verdict` alone cannot answer for a filter carrying a
  `routing-instance` term: its walk DEFERS on a matched one, returning the
  default `Accept` before that term's own action is examined, and #4392
  established that `then { routing-instance X; discard; }` is a DROP. #7212
  therefore declined such filters outright, which cost the revocation even for
  flows their plain static deny terms matched.

  The revalidation now composes the verdict exactly the way the packet path
  composes it, so the two cannot disagree:

  - Ask `evaluate_filter_ref_routing_instance_uncounted` first. `Some(r)` means a
    matched TERMINATING term carried a routing-instance — what
    `ingress_route_table_override` acts on. It drops on `Reject`/`Discard` and
    otherwise applies the table override and forwards, so `r.action` IS the
    verdict.
  - `None` means no PBR term terminated the walk (a matched terminating term had
    no routing-instance, or nothing matched). Production returns
    `RouteOverride::None` there and the ordinary non-routing verdict applies, so
    `filter_ref_static_verdict` is asked.

  The only case where the two walks differ is the matched routing-instance term
  carrying a drop action — precisely the gap.

  `_uncounted` is a separate entry point rather than the counted one with
  `packet_bytes = 0`, because `record_filter_counter` bumps the PACKET count even
  with zero bytes; the flag is what suppresses the record. On the DENY exit the
  caller replays the COUNTED routing walk once, so the newly denied packet is
  charged and logged exactly once — the routing-aware twin of the `Always`
  replay above. A PLAIN `routing-instance` term (no drop action) is a PERMIT that
  changes the route table and does NOT revoke: #7212 revokes on DENY, and
  revoking on a route CHANGE is a separate question with a different blast
  radius.

  The emitted record carries `FilterLogSource::Pbr` for a verdict from a
  routing-instance term, which is what `ingress_route_table_override` stamps on
  the same term for a session-MISS packet. Labelling it `Input` would not change
  what is dropped; it would mislabel the record an operator correlates against.

  **The revalidation passes `TermMatchExtra::default()`, not the frame — and
  `varies_per_packet_within_flow()` is NOT a complete purity gate.** That
  predicate covers the #1430 DSCP condition and the #2362 per-packet-L4
  conditions, and it is tempting to conclude that a filter failing it reads
  nothing from `TermMatchExtra`. It is not true: `port_terms_match` reads
  `is_fragment`, `l4_present` and `ports_unknown`, gated on a PORT constraint
  rather than on either flag. Against a NON-FIRST FRAGMENT, that gate suppresses
  every port-constrained term — so `term web { from destination-port 5201; then
  accept; } term deny-rest { then discard; }` skips its permit, falls through to
  the deny, and would REVOKE a session the operator permits, off one fragment.
  The revalidation asks a question about the FLOW, so it evaluates on the flow's
  5-tuple alone: `default()` leaves the fragment gate untriggered and every
  per-packet-L4 condition inert, which is exactly the 5-tuple verdict, and the
  DENY-path counted walk is handed the same value so the two cannot disagree. A
  future read of `TermMatchExtra` from OUTSIDE `per_packet_l4_matches` — the one
  place `varies_per_packet_within_flow()` actually summarises — has to be
  re-checked against this argument.

- **A routing-instance term that ALSO carries `reject`/`discard` is a DENY
  (#4392).** The non-PBR precheck DEFERS any matched routing-instance term
  (`eval.rs`: a matched term with a non-empty `routing_instance` returns the
  default `Accept` result), so a `then { routing-instance X; reject; }` term
  reaches the routing evaluator via `ingress_route_table_override`, NOT the
  precheck's terminal discard/reject exit above. The routing evaluator carries
  the term's `action`; when it is `reject`/`discard` the override is now GATED
  — `ingress_route_table_override` returns `RouteOverride::Drop` instead of a
  forward table, so the caller drops (synthesizing the reject reply on the
  flow-backed session-miss path, silent otherwise) rather than steering the
  packet into VRF X. Before #4392 the override was applied unconditionally and
  the deny was silently FORWARDED into the routing instance (a VRF leak + false
  audit). Counter ownership is unchanged: the routing evaluator still counts the
  matched term on this defer exit.

  **The CoS TX-selection INGRESS leg is counter-suppressed (#4085).** An
  interface INPUT filter is action-evaluated for its `then count` exactly
  once (the #2620 precheck above / the DSCP-sensitive session-hit re-eval).
  But when the resolved egress interface has NO output filter and the input
  filter `affects_tx_selection` (a `then forwarding-class` / `then dscp`
  term) OR carries a three-color policer, the CoS classifier
  (`afxdp/tx/cos_classify.rs` `resolve_cos_tx_selection[_at]`) RE-WALKS the
  same ingress filter to recover the forwarding-class queue / dscp-rewrite
  and to METER the ingress three-color policer. That re-walk reads the SAME
  `term.counter` Arc, so counting it there double-counts every packet of a
  non-cacheable flow (DSCP-sensitive / NAT64 / NPTv6) and the seed packet of
  a cacheable one. The ingress leg therefore uses the counter-suppressed
  eval variant (`evaluate_filter_ref_tx_selection_{,runtime_}uncounted`,
  `count_terms == false`): fc/dscp/log accumulate and the policer STILL
  meters, but `record_filter_counter` is NOT called. The OUTPUT-filter leg
  KEEPS counting: an output filter is action-evaluated nowhere else, so its
  single `then count` belongs to the TX-selection walk. On the flow-cache
  HIT path the ingress count is replayed exactly once from the cached
  `tx_selection.filter_counters` (deduped against the dedicated
  `input_filter_counters` set at seed, #3777), so miss (action-eval) + hits
  (cached replay) still total exactly one per packet.
- `policer.rs` — the #1375 RFC 2697/2698 three-color meter core. Token
  math is integer-only, byte-granular, and **lock-free** (#5390): the
  shape (`ThreeColorPolicerConfig`: mode, byte/sec rates, bursts,
  treatments) is immutable and set at compile; the hot state
  (`ThreeColorPolicerHot`) is a `#[repr(align(64))]` struct of atomics —
  both token buckets packed into ONE `AtomicU64` (committed high 32 bits,
  peak/excess low 32) plus per-rate `last_refill_ns` `AtomicU64`s.
  `meter(&self)` refills through a win-the-window timestamp CAS and
  consumes through a bounded `compare_exchange_weak` loop, so the RSS-
  spread flow aggregate (6 workers on the mlx5 VF) no longer serializes on
  a per-packet `Mutex` futex. Packing both buckets in one word makes a
  green consume (which debits committed AND peak in trTCM) atomic; the
  `afxdp/types/shared_cos_lease` v8 lease is the precedent. The aggregate
  CIR/PIR/CBS/PBS contract is preserved EXACTLY — all workers meter one
  shared bucket, only the primitive changed from Mutex to CAS. The sub-
  byte fractional refill credit the pre-#5390 scaled-`u128` bucket kept in
  the token count is now carried across refills by rewinding
  `last_refill_ns` (the #4261 conservation rewind, as
  `afxdp::cos::token_bucket::refill_cos_tokens` does); bursts clamp to the
  packed u32 byte range (a Junos burst-size is far below 4 GiB). #4514
  removed the standalone single-rate `PolicerState` token bucket (its
  `consume` had zero non-test call sites, so `then policer X` was silently
  unenforced); legacy single-rate `firewall policer`s are now lowered at
  compile into this same srTCM core (see
  `compiler.rs::build_single_rate_policer_state`) so they share the
  metering, drop-on-exceed, flow-cache handle+replay, and status export
  path.
- `tests.rs` — co-located unit tests covering matching ports, prefix
  vectors, TCP flags.

## Conventions

- Prefix matching uses linear scan over `Vec<PrefixV4>` /
  `Vec<PrefixV6>` per term (`source_v4`, `source_v6`, `dest_v4`,
  `dest_v6` on `FilterTerm`). There is no LPM trie in this package
  today — the previous README claim of an "adaptive scan above 8
  entries" was incorrect.
- Hit counters live on each `FilterTerm` (`Arc<FilterTermCounter>`)
  and are surfaced through the status JSON.
- `Filter.id` and `FilterTerm.id` are deterministic within the compiled
  snapshot order and are carried in userspace RT_FLOW filter-log records.
  Do not invent IDs beyond the compiled snapshot until the ApplyResult or
  snapshot schema exposes richer stable filter-name mapping.
- `from-interface` is matched at the binding level (caller sets the
  ingress interface; the term doesn't re-derive it).

## #1375 Three-Color Policer Runtime

Implemented here:

- srTCM (RFC 2697): committed tokens fill at CIR; overflow fills the
  excess bucket only after the committed bucket is full.
- trTCM (RFC 2698): committed and peak buckets refill independently at
  CIR and PIR.
- Color-aware classification never promotes incoming yellow or red
  packets. Color-blind classification ignores inherited color.
- Per-color treatments can carry DSCP rewrite and drop decisions in the
  meter decision.
- The Go snapshot schema, Rust wire DTO, and commit-time structural
  validation are wired for three-color policers. Commit validation
  rejects ambiguous mode declarations (`single-rate` with `two-rate`)
  and ambiguous color declarations (`color-blind` with `color-aware`)
  before they can reach the helper.
- Filter terms link to stable name-sorted runtime handles. The live
  forwarding path meters the handle at packet time, applies red drops,
  and records per-color/drop counters. Flow-cache hits carry the same
  handle in the cached TX-selection descriptor and meter before cached
  forwarding. Packets buffered for missing-neighbor retry carry their
  session key and meter at retry dispatch time before prepared TX.
- The Rust snapshot compiler also fail-closes unsupported or malformed
  three-color policer snapshots. If color-aware mode, non-`discard`
  treatment, an unknown mode, or invalid token parameters bypass Go
  admission, matching traffic still links to an explicit unsupported runtime
  that returns red/drop instead of silently forwarding unmetered.
- Rust status, Go status, CLI status formatting, and Prometheus export
  expose green/yellow/red packet and byte counters plus drop counters.
- `deriveUserspaceCapabilities()` no longer rejects the color-blind `then
  discard` `firewall three-color-policer` runtime slice.
- #4514: legacy single-rate `firewall policer`s are lowered into this
  runtime at compile. A `then discard` policer maps to an srTCM state with
  `CIR = bandwidth-limit` (bits/sec → bytes/sec), `CBS = burst-size-limit`,
  `color-blind`, and per-color treatments GREEN=pass / YELLOW=drop /
  RED=drop — so only in-rate packets pass and everything above the committed
  bucket is discarded (the committed bucket IS the single-rate token bucket;
  the required non-zero excess bucket is irrelevant because yellow also
  drops). A degenerate zero rate/burst `then discard` policer fails closed
  (drop all). A non-discard single-rate policer is metered but its marking
  action is inert (same limitation as three-color `then loss-priority`).

Concurrency model (#5390):

- Runtime token state is a **lock-free packed-atomic** token bucket per
  logical policer — NOT a per-packet `Mutex` (removed in #5390) and NOT a
  per-worker shard. All workers still meter one SHARED aggregate bucket,
  so the observable policing rate is the exact configured aggregate
  CIR/PIR (no per-worker rate division, no RSS-distribution dependence).
  The metered hot path takes no lock: both buckets live in one `AtomicU64`
  (`ThreeColorPolicerHot`, `#[repr(align(64))]` to isolate the CAS word
  from the Relaxed per-color counters) and are refilled/consumed through
  bounded `compare_exchange_weak` loops. Removing the lock also removed
  the poison failure mode; the only fail-closed path is the
  `Unsupported`-mode Red/drop. A per-worker-shard design was rejected
  because it would divide the observable rate by the worker count and make
  enforcement depend on RSS flow spread — the CAS approach keeps the exact
  aggregate contract while eliminating the futex convoy.

Remaining limitations:

- Equivalent snapshot replacements preserve token buckets and per-color
  counters by reusing the same runtime handle when the name-derived runtime ID
  and shape are unchanged. Shape changes intentionally create a fresh runtime
  so old tokens cannot leak across a different rate/burst contract. HA
  failover and process restart still rebuild from configured bursts until a
  broader state-sync design exists.
- Snapshot `then_action` handling currently wires red drop for
  `then discard`. Other actions, such as loss-priority propagation, stay
  fail-closed until downstream loss-priority behavior is wired. Color-aware
  mode also stays fail-closed until inherited packet color is carried through
  trusted metadata.
- Firewall-filter `then loss-priority <level>` (#2507) is likewise NOT wired:
  it carries no `FirewallTermSnapshot` field and there is no per-packet
  loss-priority consumer here (`apply_term_three_color_policer` always meters at
  `PacketColor::Green`). The Go control plane emits a commit WARNING that the
  action is accepted-but-inert (`validateFilterLossPriorityWarnings` in
  `pkg/config/compiler_validate_warn.go`) rather than silently committing a
  QoS no-op. Wiring a real per-packet loss-priority action onto the egress
  CoS/drop-profile path is a follow-up.
- Traffic-level integration, failover, and performance evidence remain
  production-hardening follow-ups for #1375, not active feature-gap blockers.

## Cache-key invariants for per-packet match fields (#1431)

PR #1430 closed the immediate filter-log enforcement gaps by treating
DSCP as cache-sensitive metadata that lives outside the 5-tuple
session/flow-cache key. #1431 codifies the contract going forward.

**The invariant.** When a filter match depends on packet fields that
are not part of the cache key, the dataplane must not reuse a
first-packet forwarding decision for later packets that can differ
on those fields.

**The cache key.** `SessionKey`
(`userspace-dp/src/session/key.rs`) is the standard 5-tuple
(`protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`) plus an
`addr_family` byte. The `addr_family` byte is redundant with the
`IpAddr` variant carried by `src_ip` / `dst_ip` but is materialized
on the struct for cheap branchless checks on the hot path.
For ICMP and ICMPv6 sessions, `parse_flow_ports`
(`userspace-dp/src/afxdp/frame/inspect.rs`) reads bytes 4-5 of the
ICMP header into `src_port` (the ICMP identifier word) and stores
zero in `dst_port` — but ONLY for the identifier-bearing query types
(#3067): ICMPv4 Echo Request/Reply and the Timestamp/Information
query+reply pairs (types 0/8/13/14/15/16), and ICMPv6 Echo
Request/Reply (128/129). For error and control types — where bytes
4-5 are a gateway address / next-hop MTU / pointer / unused field,
not an identifier — `parse_flow_ports` returns `None` so no
identifier-keyed session is installed for transit ICMP control
traffic. ICMP **type**
and **code** are NOT in the cache key — adding an explicit
`icmp_type` or `icmp_code` filter match makes the filter
cache-sensitive unless `SessionKey` or trusted per-session
metadata is extended to carry those fields.

**Classification table.** Every match criterion (not action /
modifier) on the wire DTO `FirewallTermSnapshot`
(`userspace-dp/src/protocol/security.rs`) and the runtime
`FilterTerm` (`userspace-dp/src/filter/mod.rs`) must fall into
exactly one of these two classes:

| Match criterion | In cache key? | Notes |
|-----------------|---------------|-------|
| `source_addresses` / `source_v4` / `source_v6` | yes | `src_ip` in `SessionKey` |
| `destination_addresses` / `dest_v4` / `dest_v6` | yes | `dst_ip` |
| `protocols` / `protocol_bitmap` (+ `protocol_match_enabled`) | yes | `protocol` |
| `source_ports` | yes (TCP/UDP); ICMP-special | `src_port` carries the ICMP identifier word from bytes 4-5 of the ICMP header (meaningful for Echo Request/Reply, opaque otherwise) |
| `destination_ports` | yes (TCP/UDP); ICMP-zero | `dst_port` is 0 for ICMP |
| `dscp_values` / `dscp_bitmap` (+ `dscp_match_enabled`) | NO — cache-sensitive | see #1430 pattern below |
| (future) `tos_match` / ECN bits (non-DSCP TOS) | NO — cache-sensitive | TOS lower bits and ECN vary per packet |
| `tcp_flags_mask` (#2362) | NO — cache-sensitive | required-bits mask over the TCP flags byte: matches when `(flags & mask) == mask`. TCP flags vary per packet. Threaded via `TermMatchExtra` (path (b)) |
| `tcp_flags_forbidden` (#3076) | NO — cache-sensitive | forbidden-bits mask over the same byte: matches only when `(flags & forbidden) == 0`. Carries the negated operands of a Junos tcp-flags expression (`syn & !ack` → required SYN, forbidden ACK). Independent of `tcp_flags_mask`. Unrepresentable expressions (disjunction `\|`, negated groups, unknown flags) are rejected at commit by the Go compiler; if one reaches the snapshot builder anyway (corrupt / hand-built / version-drifted), the Go builder sets the `tcp_flags_unparseable` wire marker and the compiler raises `SnapshotIntegrityError::UnrepresentableFilterTCPFlags` (#3367) — never silently dropped (the pre-#3367 builder logged + left both masks nil, which this matcher reads as "no tcp-flags constraint" → match every TCP segment, fail-WIDE) |
| `is_fragment` (#2362) | NO — cache-sensitive | Junos `is-fragment`: matches ANY fragment (IPv4 MF set OR offset != 0; IPv6 fragment header present). Computed by `is_any_fragment` |
| (future) `ihl_match` / IP options | NO — cache-sensitive | IHL varies per packet |
| `icmp_type` / `icmp_code` (#2362) | NO — cache-sensitive | exact match on the ICMP/ICMPv6 type/code byte; non-ICMP packets never match. Could later be promoted to cache-key by adding (type, code) to `SessionKey` |
| `flex_match` (#3077, #3232) | NO — cache-sensitive | Junos `from flexible-match-range`: reads `length` bytes (1..4) at `offset` from the START of the base header selected by `flex_match_start` (#3232) — `Layer3` (match-start layer-3, the default) reads from `TermMatchExtra::flex_l3` (the L3/IP header); `Layer4` (match-start layer-4) reads from `TermMatchExtra::flex_l4` (the transport header at `meta.l4_offset`); `Unsupported` (any other match-start, e.g. `payload`, that the Go commit gate rejects but the tolerant peer-sync path could still deliver) always FAILS CLOSED. The chosen bytes are ANDed with `mask` and required to `== value`. Byte-offset read, fully per-packet. The base slice being `None` (no frame / deferred CoS path; or, for layer-4, a non-first fragment whose post-IP bytes are payload) or a packet too short for the window FAILS CLOSED (no match, no OOB). **#5150: both base slices end at the IP-DECLARED datagram end (`l3_offset + IPv4 total-length`, or `l3_offset + 40 + IPv6 payload-length`), CLAMPED to `frame.len()` — NOT the physical frame end.** So attacker-controlled bytes in Ethernet slack (padding beyond the declared IP length) are excluded (a byte-match can only see the logical IP datagram), and a lying oversized IP length can never over-read past the frame. Before #5150 the slices extended to `frame.len()`, letting a flex term match padding bytes (match-on-padding / filter-evasion). Compiled from `FlexMatchSnapshot`; before #3077 the constraint was parsed but dropped on the wire (matched too broadly, fail-open); before #3232 a layer-4/payload match-start was silently evaluated at the L3 base (wrong-offset match — security evasion). **#5293: all six `flex_*` fields (`flex_enabled`, `flex_offset`, `flex_length`, `flex_value`, `flex_mask`, `flex_match_start`) are now compared in `filter_term_semantics_match` (`engine/cache_sensitive/rotation.rs`) — before #5293 they were omitted from the forwarding-rotation change detector, so a rotation touching only a flex field skipped the session purge and stranded established sessions on their stale routing-instance / forwarding decision (cross-VRF policy-coherency failure)** |

The `tcp_flags_mask` / `tcp_flags_forbidden` / `is_fragment` / `icmp_type` /
`icmp_code` inputs (and the #3077 `flex_match` L3 slice, `flex_l3`) are
carried in a small `TermMatchExtra` built once per packet at the filter-eval
call sites (`term_match_extra_from_frame` — one unified builder since #6435,
generic over `impl Into<ForwardPacketMeta>` so the input-filter
`UserspaceDpMeta` and TX-selection `ForwardPacketMeta` callers share it, the
byte-identical `_fwd` twin retired — and the meta-only
`term_match_extra_from_meta`). `flex_l3` borrows the live frame's L3 header, so
`TermMatchExtra` is parameterized by a lifetime; the deferred CoS/TX-selection
snapshot drops the borrow (`to_static()` → `flex_l3 = None`) and the flex term
fails closed there (the frame may be recycled). The builder is fragment-safe:
for a NON-FIRST fragment
(no L4 header at `l4_offset` — its bytes are payload) it sets an explicit
`l4_present = false`, and the matcher (`per_packet_l4_matches`) gates the
tcp-flags / icmp-type / icmp-code constraints on that flag — NOT on the byte
value, because 0 is a valid `icmp-type` (echo-reply) and a valid `icmp-code`, so
a zeroed byte would still match `from { icmp-type 0 }` / `from { icmp-code 0 }`.
The L4 byte fields are also zeroed (defense-in-depth) but the gate is the flag.
The L3-derived `is_fragment` bit is NOT gated by `l4_present` and stays true
(a non-first fragment IS a fragment). This applies on the
CoS / TX-selection leg too (`tx/cos_classify.rs`): the TX-selection evaluators
thread the same `TermMatchExtra`, built from the LIVE frame at
request-build time. The flow-cache decline (output and input legs) keeps
the precomputed TX-selection descriptor from being built for a
per-packet-L4 filter, so the live per-packet evaluator always runs. (There
is no deferred snapshot: the `PendingForwardRequest.filter_match_extra`
field and the deferred-recompute path that consumed it were removed as
dead code in #hb166 T-7 — CoS TX selection is always resolved upstream on
the live frame.)

#2449 also covers a NON-FRAGMENTED but TRUNCATED ICMP/ICMPv6 frame (shorter than
`l4_offset + 2`, so the type/code bytes are absent): the frame builders force
`(0, 0, 0)` AND drop `l4_present`, failing the icmp-type/code terms closed rather
than spuriously matching `icmp-type 0` / `icmp-code 0`.

**#5568 (SCALAR declared-length bound).** #2449 keyed the ICMP presence test on
the physical `frame.len()`; #5568 keys EVERY scalar L4/fragment input on the
IP-DECLARED datagram end (`ip_declared_end` — the same SSOT that bounds the
#5150 flex slices), computed FIRST in the frame builder (one unified builder
for both metadata flavors since #6435). The shim stamps
`l3_offset`/`l4_offset` from the raw frame, so without this, attacker-controlled
Ethernet padding beyond the declared IP length manufactures a scalar match out of
slack. Concretely: (a) the fragment walkers (`is_any_fragment` /
`is_non_first_fragment`) see only `frame.get(l3..declared_end)`, so an IPv6
fragment/extension header lurking in padding beyond `payload_len` — or an IPv4
`frag_off` in slack — cannot manufacture fragment state; (b) ICMP type/code
presence requires `l4_offset + 2 <= declared_end`; (c) TCP flags require
`l4_offset + TCP_FLAGS_DECLARED_MIN (14) <= declared_end` (the flags byte at TCP
offset 13) — a short/padded TCP frame whose declared length stops before the
flags byte drops `l4_present`, failing tcp-flags terms closed. On the common
no-slack path `declared_end == frame.len()`, so classification is byte-identical.
The sibling `parse_embedded_v4`/`parse_embedded_v6` quote parsers
(`icmp_embed/parse.rs`) apply the same bound to the QUOTED inner datagram's
declared length (clamped to the available quote — a legitimately-truncated
RFC-792 minimum quote whose original length exceeds the quoted bytes is NOT
rejected), so outer-frame padding cannot manufacture an embedded-session tuple.

**Meta-only builder (`term_match_extra_from_meta`, #3008 — meta sibling of
#2449).** A few cold TX-selection callers (re-derived locally-generated replies,
ARP/NDP-deferred forwards, control-plane injects;
`poll_descriptor/mod.rs`, `tunnel.rs`, `tx/cos_classify.rs`) have NO contiguous
ingress frame, so the real ICMP type/code can never be read. The shim-stamped
`tcp_flags` is still authoritative, but `icmp_type`/`icmp_code` are unknown. The
matcher shares ONE `l4_present` bit across tcp-flags AND icmp-type/code, so the
builder sets `l4_present = false` for the ICMP/ICMPv6 family (failing the
icmp-type/code terms closed — the type/code is genuinely unknown) and
`l4_present = true` otherwise (preserving authoritative `tcp_flags` matching;
tcp-flags terms only apply to TCP). Before #3008 this builder stamped an
unconditional `l4_present = true` with `icmp_type = icmp_code = 0`, so a term
keyed on `icmp-type 0` (echo-reply) or `icmp-code 0` false-matched every
ICMP-family packet on these paths.

Fields like `action`, `count`, `log`, `policer`, `routing_instance`,
`forwarding_class`, and `dscp_rewrite` are forwarding actions and
modifiers, applied after a match has succeeded. They do not
participate in match-time key lookup and are out of scope for the
cache-key contract.

### All-malformed match sets fail CLOSED (#2400)

A term's `source-address` / `destination-address` / `source-port` /
`destination-port` match set restricts which traffic the term's action applies
to. The Rust compiler drops any entry that fails to parse
(`parse_address` skips an unparseable prefix; `parse_port_spec` returns `None`).
Historically an EMPTY parsed list meant "no constraint → match any", so a term
whose match set was non-empty in the config but whose entries ALL failed to
parse (every address typo'd, every port out of range) silently broadened to
match-ANY on that dimension — a `discard` term scoped to bad addresses became
discard-all (fail-OPEN filter broadening, codex 032-18 / 032-19).

`FilterTerm` now carries four derived flags —
`source_addr_constrained` / `dest_addr_constrained` /
`source_port_constrained` / `dest_port_constrained` — set at compile time when
the snapshot list held at least one REAL entry (`addr_is_real` ignores the empty
string and the literal `any`; `port_is_real` ignores the empty string). The
matcher (`engine/matching.rs` `nets_match_v4` / `nets_match_v6` / `port_match`)
then distinguishes:

- unconstrained (no real entry) → match any (unchanged unscoped behavior);
- constrained but the parsed set is empty for this packet's family (all entries
  failed to parse) → match NOTHING (fail closed);
- otherwise → the IP/port must fall in a parsed prefix/range.

This mirrors the NAT `*_constrained` fail-closed pattern (#2398 SNAT, #2394
DNAT). A bare-host address (`203.0.113.7`, no `/32`) is handled by
`parse_address`'s bare-IP fallback (`IpNet::parse` rejects a bare IP). The flags
are DERIVED from the existing snapshot lists, so there is NO new wire field
(`protocol_wire_v1.json` is unchanged). The flags are also compared in
`filter_term_semantics_match` (`engine/cache_sensitive/rotation.rs`) because the
unscoped↔all-malformed transition flips match semantics WITHOUT changing the
parsed vecs/matcher, so a flow-cache rebuild must catch it.

### Prefix-list expansion + `except` inversion (#2506)

`from source-prefix-list <name>` / `destination-prefix-list <name>` (with the
optional `except` modifier) is resolved in the GO control plane before the
snapshot is emitted, not in Rust. The Go snapshot builder
(`resolvePrefixListAddrs`, `pkg/dataplane/userspace/filters.go`) looks each
reference up in `cfg.PolicyOptions.PrefixLists` and merges the resolved CIDRs
into the term's `source_addresses` / `destination_addresses` list — so the Rust
compiler sees them exactly like literal `from source-address` entries (no
prefix-list concept exists Rust-side). Before #2506 these references were
silently dropped, leaving the term with no address scope (action-dependent
fail-open / fail-closed).

The `except` modifier ("match every address NOT in the list") is the one piece
that cannot be expressed by the address vectors alone, so it travels as two
per-direction wire flags on `FirewallTermSnapshot` — `source_except` /
`destination_except` (Go `pkg/dataplane/userspace/protocol.go`, Rust
`protocol/security.rs` with `serde(default)` for #1961 wire parity). They map to
`FilterTerm.source_except` / `dest_except`, and the matcher
(`engine/matching.rs` `nets_match_v4` / `nets_match_v6`) evaluates
`nets.iter().any(contains) ^ except`. The except flags are compared in
`filter_term_semantics_match` (`engine/cache_sensitive/rotation.rs`) — they flip the
address decision without changing the parsed vecs, so a flow-cache rebuild must
catch a toggle.

**Explicit `constrained` signal + empty-set semantics (#2506, Copilot).** A
prefix-list can resolve to ZERO prefixes — a defined-but-empty list (passes the
strict gate) or an unresolved reference on the lenient/peer-sync path. The
empty-resolution case is exactly the address-scope-loss bug #2506 fixes, so
"constrained" must NOT be derived from the resolved list length (an empty list
would collapse to match-any: fail-open for `accept`, wrong scope for
`discard`). Two explicit wire flags `source_constrained` /
`destination_constrained` (Go sets them whenever the term wrote ANY scope —
literal address or prefix-list ref) are OR'd into
`FilterTerm.source_addr_constrained` / `dest_addr_constrained` in the compiler.
The matcher's empty guard then returns `except`:

- positive (`except == false`), empty vec → `false` → match NOTHING (Junos
  `addr ∈ {}` = none; this is the #2400 all-malformed case AND the #2506
  empty-positive case);
- `except == true`, empty vec → `true` → match ALL (Junos `addr ∉ {}` = all);
- `constrained == false` (no scope at all) → match any, unchanged.

Cross-family falls out of this for free: a v4-only `... except` list leaves the
v6 vec empty, and a v6 address is trivially "not in" a v4 list, so the empty
guard's `return except` (= true for an except term) correctly matches v6 — the
v4 list does not constrain v6. (A v4-only POSITIVE list correctly fails closed
for v6 via the same guard returning `except` = false.)

Go-side scope: a plain prefix-list OR's into the positive set (with any literal
addresses); an `except` prefix-list sets the inversion flag ONLY when it is the
sole address source for the direction. The mixed literal/positive + `except`
case in one direction folds `except` away to a positive set with a warning —
there is no single boolean-inversion representation for "match A but not B". The
fold is **action-dependent in safety**: under-broadening is fail-safe for
`accept`/permit terms but fail-OPEN for a `discard`/`reject` term (traffic the
operator meant to drop via `except` is no longer dropped). Splitting into two
terms is the operator workaround, and the structured form is a documented
follow-up. An undefined prefix-list reference is rejected at commit by
`validateFirewallPrefixListReferencesStrict` (Go), so the Rust side never has to
reason about a dangling name.

### Undefined interface/lo0 filter reference (#3296)

A hook that attaches a filter to an interface (`interfaces <if> unit <n> family
inet|inet6 filter input|output <name>`) or to lo0 (`interfaces lo0 unit 0 family
inet|inet6 filter input <name>`) can name a filter that does not exist under
`firewall family inet|inet6 filter <name>` — a typo on a security hook (e.g.
`filter input WAN-BLOCK` where the defined filter is `WAN_BLOCK`). Before #3296
this was only a commit WARNING, and the snapshot compiler (`compiler.rs`) left
the per-interface fast-path map (`iface_filter_*_fast`) and — for output hooks —
the `iface_filter_out_*_needs_tx_eval` set with NO entry for the missing key, so
the hot path returned the default `FilterResult` — **Accept**. The hook was
silently disarmed, indistinguishable from "no filter configured": a fail-OPEN on
a firewall filter.

Primary defense (Go): `validateFirewallFilterReferencesStrict`
(`pkg/config/compiler_validate_strict.go`) hard-rejects a dangling interface/lo0
filter reference at commit / commit-check, downgraded to a warning on the
tolerant load / peer-sync path (`opts.lenientFirewallRefs`, #1960) so an already-
persisted or peer-synced config still boots. It supersedes the old warn-only
interface filter-reference loop in `ValidateConfig`.

Dataplane backstop (Rust): `parse_filter_state` raises
`SnapshotIntegrityError::MissingFilterRef` when an interface (or lo0) names a
filter not present in the compiled table. As a preflight snapshot-integrity
error it aborts the reconcile BEFORE teardown/publish, preserving the prior good
filter state on a warm reconcile rather than degrading the hook to Accept —
consistent with the #2124/#2391/#2505 fail-closed family. The Go gate is the
primary defense (a freshly committed config can never carry a dangling
reference); this backstop guards against version/snapshot drift on the lenient /
peer-sync path. An EMPTY reference (no filter on the hook) is the legitimate
"unfiltered" case and is NOT an error. Covers all four interface directions plus
both lo0 input families. Tests: `missing_filter_ref_3296_*` /
`defined_filter_ref_3296_compiles_cleanly` in `filter/tests.rs` (fail-on-revert).

#### Dangling `then policer <name>` (#6540)

`then policer <name>` naming a policer defined nowhere was the odd one out of
three sibling reference mechanisms. Filters raise `MissingFilterRef` and screen
reports `ScreenMissingProfileRef`, but the policer reference had NO backstop:
the compiler resolved it with a bare `.get(...)` yielding `None`, and
`apply_term_three_color_policer` then no-opped the meter — so a configured rate
limit forwarded UNPOLICED with no `Err`, no warning and no counter.

Primary defense (Go): the strict commit gate (#2217 Finding A,
`pkg/config/compiler_validate_strict_filter.go`) hard-rejects a term whose
`then policer` names neither a defined `firewall policer` nor a defined
`firewall three-color-policer`, downgraded to a warning on the tolerant
load / peer-sync path (`opts.lenientFirewallRefs`, #1960).

Dataplane backstop (Rust): `preflight_term_policer_ref` raises
`SnapshotIntegrityError::MissingPolicerRef`, rejecting the whole snapshot.

The predicate is DEFINEDNESS — the name appears in the `policers` or
`three_color_policers` snapshot collection — and deliberately NOT presence in
the compiled `three_color_policer_by_name` map. Those two differ, and the
difference is load-bearing: `lower_single_rate_policer_runtimes` (#4514) SKIPS
a degenerate zero-rate METER-ONLY policer because it has no action to enforce,
so that policer is defined, absent from the map, and boots fine today. Keying
the rejection on the map would refuse a working config. Definedness is also the
same question the Go gate asks, so the two cannot disagree about which
references are dangling. An EMPTY reference (no policer on the term) is the
legitimate "unpoliced" case and is NOT an error.

Severity is Medium, not High: a policer is a RATE control, so its absence
over-permits bandwidth rather than admitting traffic a policy would deny.

Tests: `missing_policer_ref_6540_rejects_rather_than_forwarding_unpoliced`,
`defined_{single_rate,three_color}_policer_ref_6540_compiles`,
`degenerate_meter_only_policer_ref_6540_is_defined_and_must_not_be_rejected`
(the cell that pins definedness-not-map), and
`empty_policer_ref_6540_is_unpoliced_not_an_error` in `filter/tests.rs`.

The fail-closed contract keys off the RETAINED per-interface fast maps
(`iface_filter_*_fast`) — the structures the per-interface hot path consults —
and the FAMILY-WIDE global TX gate keys off the `has_output_needs_tx_eval_*`
aggregate (#6236 PR-2A; see "Output-filter TX-eval predicate and aggregates"
below). #6236 PR-2B deleted the parallel per-interface property sets
(`iface_filter_v{4,6}_affects_route_lookup` / `_has_dscp_match` /
`_has_per_packet_l4_match` and `iface_filter_out_{v4,v6}_needs_tx_eval`); every
capability accessor now reads the mirrored `Filter` flag off the fast-map entry,
so a single `.get()` returns the filter and every derived flag. #6236 PR-1
removed the dead parallel bookkeeping that shadowed these:
the four `"family:name"` name maps (`iface_filter_v4`/`iface_filter_v6`/
`iface_filter_out_v4`/`iface_filter_out_v6`), the two input
`iface_filter_v{4,6}_affects_tx_selection` sets (their only reader was a
test-only helper; production reads the family-wide `has_input_tx_selection_*`
aggregate), and the two `lo0_filter_v{4,6}` qualified-key Strings (now compiler
locals used only to look up `lo0_filter_v{4,6}_fast`). The `MissingFilterRef`
guards are byte-for-byte unchanged — deleting a name-map `.insert` never touched
the `filters.get()` presence check that precedes it. `FilterState` drops from 31
to 23 fields with zero live-dataplane behavior change.

### Output-filter TX-eval predicate and aggregates (#6236 PR-2A/2B)

An output filter must still be walked on the TX path when it can change or
observe the packet: CoS/DSCP tx-selection, a `then count`, a `then log`, a
terminal (non-`accept`) action, or a three-color policer. That five-flag OR is
now the **single** `Filter::needs_tx_eval()` method (`filter/mod.rs`), the SOLE
definition. Every consumer routes through it — the
`interface_output_filter_needs_tx_eval` accessor (fast-map backed since PR-2B),
the `has_output_needs_tx_eval_*` aggregates, and all four `cos_classify` TX arms
(cached/runtime × flow-keyed/flowless) — so the composite can never drift
between the compile path and the hot path.

**Capability accessors read the fast map (#6236 PR-2B).** The four hot
per-interface capability prechecks — `interface_filter_affects_route_lookup`,
`interface_input_filter_has_dscp_match`,
`interface_input_filter_has_per_packet_l4_match`, and
`interface_output_filter_needs_tx_eval` — read the mirrored `Filter` flag off
`iface_filter_*_fast.get(&ifindex)` (e.g. `.is_some_and(|f| f.has_dscp_match_terms)`)
rather than a parallel `FxHashSet<i32>`. PR-2B deleted those eight property sets
(`iface_filter_v{4,6}_affects_route_lookup` / `_has_dscp_match` /
`_has_per_packet_l4_match` and `iface_filter_out_{v4,v6}_needs_tx_eval`). For a
unique ifindex the fast-map read is bit-identical to the old `set.contains`
(the set was populated iff the same `Filter` flag was set); for a duplicate
ifindex the fast map is the last-wins canonical source, so the precheck now
agrees with the filter the evaluator that follows actually walks. `FilterState`
drops from 25 to 15 fields.

**Co-located lookups fold to one (#6236 PR-2C).** After PR-2B a call site that
checks N flags of the same ifindex paid N separate `iface_filter_*_fast.get()`
lookups. PR-2C folds each co-located multi-flag check into ONE `.get()` that
borrows `Option<&Arc<Filter>>` and evaluates every needed flag off that single
borrow, through shared pure `&Filter` evaluator cores so the folded site and the
per-flag accessor can never drift:

- **Route-lookup / PBR precheck** (`afxdp/forwarding/pbr.rs`): the
  `affects_route_lookup` precheck and the routing-instance evaluator used to look
  the same ingress ifindex up twice on the input fast map. The SOLE lookup+gate
  is now `interface_filter_route_lookup_affecting` (returns the borrowed
  route-lookup-affecting `&Filter`); the bool `interface_filter_affects_route_lookup`
  is `.is_some()` of it, and the PBR site feeds the borrow straight into the new
  `&Filter` core `evaluate_filter_ref_routing_instance_event_counted`. One lookup.
- **Session-hit DSCP/L4 re-eval gate** (`afxdp/poll_descriptor/filter.rs`): the
  `has_dscp_match` + `has_per_packet_l4_match` prechecks fold to one lookup of
  `interface_input_filter_varies_per_packet`, which reads the SOLE OR core
  `Filter::varies_per_packet_within_flow()`. The flow-cache decline gate
  (`afxdp/flow_cache.rs`) still consults the two per-flag accessors individually
  (input **and** output directions), so they stay live.

  #7212 widened this site rather than adding a second lookup beside it. The
  session-hit gate now has to answer two questions in sequence — does the filter
  vary per packet, and if not what is its static verdict — so it takes the
  `&Filter` BORROW (`interface_input_filter`) and reads
  `varies_per_packet_within_flow()` off it. Same single `.get()`, same cost for
  the overwhelmingly common no-input-filter case;
  `interface_input_filter_varies_per_packet` stays as the flow-cache path's own
  single-lookup accessor and as the independent reference the equivalence tests
  compare the folded borrow against (delegating would make that comparison
  tautological).
- **CoS TX-selection output arms** (`afxdp/tx/cos_classify.rs`, all four
  cached/runtime × flow-keyed/flowless): the `needs_tx_eval` bool precheck + the
  separate output-filter `.get()` + a redundant `.filter(needs_tx_eval)` fold to
  one `interface_output_filter_needing_tx_eval` borrow (gated on
  `Filter::needs_tx_eval()`; the bool `interface_output_filter_needs_tx_eval` is
  `.is_some()` of it). The PR-2A family-wide `has_output_needs_tx_eval_*`
  aggregate still short-circuits the whole TX path (`tx_selection_enabled_*`)
  BEFORE any per-interface lookup — that fast branch is unchanged.

The fold is behavior-preserving: for a unique ifindex the single borrow is the
same `Arc<Filter>` the second lookup would have returned; the fast map is the
last-wins SSOT for a duplicate. Anti-drift invariant: the accessor is
`map.get(&if).is_some_and(|f| core(f))` and the folded site evaluates `core(f)`
off the borrow — BOTH through the same `&Filter` core
(`affects_route_lookup` field / `varies_per_packet_within_flow()` /
`needs_tx_eval()`), pinned by `pr2c_folded_single_lookup_equals_two_lookup_path`
in `filter/tests.rs`.

**Aggregate-from-final-map rule.** Every retained family-wide `FilterState`
aggregate (`has_input_tx_selection_*`, `has_input_three_color_policer_*`, and
`has_output_needs_tx_eval_*`) is recomputed **after** the interface loop from the
FINAL fast maps via `iface_filter_*_fast.values().any(..)`, NOT accumulated
monotonically inside the loop. The fast maps overwrite last-wins on a duplicate
ifindex, so a positive filter followed by a non-sensitive filter at the same
ifindex must not leave a stale-true aggregate; deriving each aggregate from the
final map makes it agree with the filter the hot path actually evaluates. For the
common unique-ifindex case this is bit-identical to the old in-loop OR (only the
duplicate-ifindex drift case changes, and it changes to the correct value).

**Global TX gate.** `forwarding_build` computes the family-wide
`tx_selection_enabled_v{4,6}` gate that short-circuits the entire `cos_classify`
TX path. Its output clause is the single `has_output_needs_tx_eval_*` aggregate,
which SUBSUMES both the old `has_output_tx_selection_*` clause AND the old
`!iface_filter_out_*_needs_tx_eval.is_empty()` clause (because
`needs_tx_eval ⊇ affects_tx_selection`, also covering counter/log/terminal/
policer). This is behavior-equivalent — a counter/log/terminal/policer-only
output filter keeps the gate armed, so its enforcement never fails open — and
cannot be tricked by a duplicate-ifindex overwrite. PR-2A rewired the gate onto
this aggregate; PR-2B then deleted the now-unread `has_output_tx_selection_*`
fields and their production-dead accessor `filter_state_has_output_tx_selection`.

Unparseable tcp-flags backstop (#3367): a term whose Junos `tcp-flags`
expression the Go control plane could not parse into required/forbidden masks
(disjunction, negated groups, unknown flags) is marked with the
`tcp_flags_unparseable` wire bool. `parse_term` raises
`SnapshotIntegrityError::UnrepresentableFilterTCPFlags` on the marker, aborting
the reconcile before teardown/publish. The pre-#3367 Go builder logged the parse
error and left both masks nil, and the matcher treats absent masks as "no
tcp-flags constraint" — silently WIDENING a `then discard`/`reject` term to match
every TCP segment (fail-WIDE). The Go commit gate (`config::ParseTCPFlagsExpression`
in `compileFirewall`) is the primary defense; this backstop guards the lenient /
peer-sync path, consistent with the #2505/#3296 fail-closed family. Tests:
`tcp_flags_unparseable_*` (Rust) and `TestFilterSnapshotTCPFlagsUnparseableSetsMarker`
(Go) (fail-on-revert).

Unrepresentable match-content backstops (#3406): four more filter-term fields
that the pre-fix builder silently dropped/capped on the lenient / peer-sync path,
each a sibling of the #3367 tcp-flags backstop and consistent with the
#2505/#3296 fail-closed family. The Go commit gates
(`validateFilterMatchValuesStrict`, `validateFilterDSCPStrict`,
`validateFilterFlexMatchStrict`) are the primary defense; these backstops guard a
corrupt / hand-built / version-drifted snapshot. The first three FAIL THE
SNAPSHOT CLOSED because the silent drop WIDENED the term (an empty match vector
reads as "no constraint" = match-any); the fourth WARNS because it has no
match/action widening:

- **`from icmp-type` / `from icmp-code` out of range (104-M07):** a token the Go
  compiler could not resolve to a byte in `0..255` (recorded on
  `term.UnknownICMPTypes` / `UnknownICMPCodes`) sets the
  `icmp_type_unrepresentable` / `icmp_code_unrepresentable` wire bool; `parse_term`
  raises `SnapshotIntegrityError::UnrepresentableFilterICMP`. Pre-fix an
  all-unresolvable list emitted an empty `icmp_types`/`icmp_codes` vec → the term
  matched every ICMP(v6) packet (fail-WIDE for a discard/reject term).
- **`from dscp` / `from traffic-class` MATCH token (104-M09 match half):** a token
  resolving to neither a code-point name nor `0..63` sets `dscp_match_unrepresentable`;
  `parse_term` raises `SnapshotIntegrityError::UnrepresentableFilterDSCP`. Pre-fix
  an all-unresolvable list left `dscp_values` empty → match all DSCPs (fail-WIDE).
- **`from flexible-match-range` oversized width (104-M08):** the Go builder no
  longer caps an oversized byte width to 4; it carries the real `flex_match.length`
  and `parse_term` raises `SnapshotIntegrityError::UnrepresentableFilterFlexMatch`
  for any length outside `1..=4` (the `value`/`mask` wire fields are u32). Pre-fix
  the cap-to-4 still emitted the term, comparing only the truncated 4-byte window —
  BROADENING the match (fail-open).
- **`then dscp` / `then traffic-class` REWRITE token (104-M09 rewrite half):** an
  unresolvable rewrite is CoS-only (no match/action widening), so it is NOT failed
  closed — the Go builder emits NO rewrite and a `slog.Warn` so the lost CoS marking
  is operator-visible (failing forwarding over a cosmetic marking would be worse).
- **Raw DSCP wire value out of the 6-bit 0..=63 range (#3715):** a `dscp_values`
  entry >= 64 (match) or a `dscp_rewrite` byte >= 64 (rewrite) can only arrive from
  a corrupt / hand-built / version-drifted snapshot — the Go commit gate
  (`validateFilterDSCPStrict`) and the builder both bound DSCP to a code-point name
  or 0..63. `parse_term` raises `SnapshotIntegrityError::FilterDSCPOutOfRange` for
  either. Unlike the `dscp_match_unrepresentable` marker above (which fires after the
  Go builder has already DROPPED an unresolvable NAME), the raw numeric value is
  directly visible on the wire, so the range check is done in Rust without a Go-side
  marker. Pre-fix the MATCH value was silently SKIPPED by `build_u6_match_bitmap`
  (`value < 64` guard) while `dscp_match_enabled` stayed true → a `[46, 64]` term
  matched only EF (fail-WIDE / silently-wrong); the REWRITE value was MASKED with
  `& 0x3f`, turning e.g. 110 into 46 (EF) → traffic marked with a code point the
  operator never authored. BOTH now fail the snapshot closed (the reconcile preflight
  keeps the previous good filter state), so neither mis-applies.
- **Mixed positive + `*-port-except` in one direction (104-M05):** the Rust
  compiler already resolves this positive-wins (the except list is dropped — a
  fail-SAFE narrowing, see "Negated port match" below), but the pre-#3406 drop was
  SILENT; the Go builder now emits a `slog.Warn` symmetric with the mixed
  address-except warning (#3359), so the dropped except set is operator-visible.

Tests: `icmp_type_unrepresentable_marker_*`, `icmp_code_unrepresentable_marker_*`,
`dscp_match_unrepresentable_marker_*`, `dscp_match_out_of_range_fails_closed_not_dropped`,
`dscp_rewrite_out_of_range_fails_closed_not_masked`, `flex_match_oversized_width_*`
(Rust) and
`TestFilterSnapshot{ICMP,DSCPMatch,DSCPRewrite,FlexMatchOversizedWidth,MixedPortExcept}*`
(Go) (fail-on-revert).

Partially-unresolvable port/address list backstops (#6459/#6463): the same
fail-closed family, a different failure MECHANISM. The #3406 markers cover the
case where a dropped token leaves an EMPTY match vector (which the matcher
reads as "no constraint" = WIDENING). A partially-unresolvable
`from {source,destination}-port[-except]` list or literal
`from {source,destination}-address` list fails the OTHER way: the surviving
tokens still build a matcher, so the term silently enforces a NARROWER set
than the operator wrote — a `then discard`/`reject` term drops only the
surviving subset and the rest falls through to the implicit accept (fail-OPEN
for the deny). The all-unresolvable case was already covered at match-time
(`constrained && PortMatcher::Any` / `constrained && empty`, #2400/#3205);
the partial case was not. Two wire bools close it, same shape as the #3406
markers (Go builder sets, `parse_term` rejects the whole snapshot; strict
commit gates `validateFilterMatchValuesStrict` /
`validateFilterAddressLiteralsStrict` are the primary defense):

- **`ports_unrepresentable` (#6459):** set when compileFilterFrom records any
  unresolvable port token on `term.UnknownPorts`; `parse_term` raises
  `SnapshotIntegrityError::UnrepresentableFilterPorts`.
- **`address_unrepresentable` (#6463):** set when compileFilterFrom records
  any literal address token `classifyFilterAddrFamily` rejects on
  `term.UnknownAddresses`; `parse_term` raises
  `SnapshotIntegrityError::UnrepresentableFilterAddress`.

Sibling parser-alignment fix (#6477): the filter-side `parse_port_spec`
(compiler.rs) now routes every numeric token through the SHARED digit-only
`crate::policy::parse_port_u16` (#3606) instead of Rust's u16 `FromStr`, which
accepts a leading `+` ("+80" → 80). One of four port parsers (Go commit gate,
Go capability gate, policy-side Rust, filter-side Rust) was more lenient than
the rest — the #3606 agreement-invariant residual; a tolerant-path `from
destination-port +80` survived verbatim and was enforced as port 80 HERE only.
A rejected token yields zero ranges on a constrained direction, so the term
fails closed (matches nothing) rather than enforcing a token the other three
parsers reject.

Tests: `ports_unrepresentable_marker_*`, `address_unrepresentable_marker_*`,
`filter_parse_port_spec_rejects_signed_6477`,
`firewall_term_snapshot_unrepresentable_marker_wire_keys_6459_6463` (Rust) and
`TestFilterSnapshot{Ports,Address}Unrepresentable*`,
`TestFilterSnapshotLenientPartial{Port,Address}List*`,
`TestFirewallTermSnapshotUnrepresentableMarkerWireKeys_6459_6463`,
`TestFilterMalformedAddressRecorded_6463` (Go) (fail-on-revert).

Whole-`from`-leaf widening backstop (#9875): the same fail-closed family, a
coarser failure GRANULARITY. The #3406/#6459/#6463 markers cover unresolvable
tokens WITHIN a leaf the dataplane otherwise enforces. A whole `from` leaf
the dataplane does not enforce at all (recorded on `term.UnknownFrom`, #3307
— ttl / source-mac-address / ip-options / fragment-offset / hop-limit / ...)
or a value-bearing leaf written with NO operand (recorded on
`term.ValuelessFrom`, #8480 — `from protocol;`) compiles to a term missing
an entire authored constraint: the snapshot carried only the surviving match
set — byte-identical to a term authored without the leaf — so an accept term
over-permitted and a discard/reject term over-dropped with no signal past
the boot warning. One wire bool closes it, same shape as the family (Go
builder sets, `parse_term` rejects the whole snapshot; strict commit gates
`validateFilterFromMatchStrict` / `validateFirewallFilterValuelessFromStrict`
are the primary defense):

- **`from_unrepresentable` (#9875):** set when compileFirewall records any
  unenforced `from` leaf on `term.UnknownFrom` or any valueless leaf on
  `term.ValuelessFrom`; `parse_term` raises
  `SnapshotIntegrityError::UnrepresentableFilterFrom`.

Whole-snapshot rejection — not term poisoning — because poisoning a
discard/reject term to match-nothing would let its traffic fall through to
the implicit accept (fail-OPEN); only refusing the snapshot is
action-agnostic.

Tests: `from_unrepresentable_marker_*`,
`firewall_term_snapshot_from_unrepresentable_wire_key_9875` (Rust) and
`TestFilterSnapshotFromUnrepresentable*`,
`TestFirewallTermSnapshotFromUnrepresentableWireKey_9875` (Go)
(fail-on-revert).

### Negated port match — `source-port-except` / `destination-port-except` (#2622)

Junos `from source-port-except` / `from destination-port-except` matches every
port EXCEPT the listed ones — the port-dimension counterpart to the address
`except` above. The negated list travels as two additive wire fields on
`FirewallTermSnapshot` — `source_ports_except` / `destination_ports_except` (Go
`pkg/dataplane/userspace/protocol.go`, Rust `protocol/security.rs` with
`serde(default)` for #1961 mixed-version parity).

The Rust compiler (`compiler.rs`) selects ONE port spec list per direction: the
positive `source_ports` / `destination_ports` if it carries a real entry,
otherwise the `*_except` list. It builds the SAME `PortMatcher` from the
selected list, sets `*_port_constrained` from the selected list, and sets a
per-direction `source_port_except` / `dest_port_except` inversion flag on
`FilterTerm` when the except list is the source (positive wins if both are
present — there is no single matcher that expresses "ports in A but not B", same
fold as the address mixed case). The matcher `port_match`
(`engine/matching.rs`) evaluates `matcher.matches(port) ^ except`, mirroring
`nets_match_v4` / `nets_match_v6`:

- positive (`except == false`), `PortMatcher::Any` while constrained → match
  NOTHING (the #2400 all-malformed fail-closed case);
- `except == true`, `PortMatcher::Any` while constrained → match NOTHING —
  **FAIL CLOSED (#3205, agy-070 #08)**. Unlike the address path, a port scope
  has no prefix-list indirection: a real listed port (numeric or a resolved
  service name) always yields a range, so `constrained + Any` can ONLY mean
  every token was unparseable (e.g. an unresolved symbolic port name). The
  except branch therefore must NOT invert empty into match-ALL — that was the
  fail-OPEN hole where `destination-port-except domain` accepted every port,
  including the one meant to be excluded. (The Junos "empty-except = match all"
  semantic still applies to the ADDRESS path above, where an empty prefix-list
  scope is reachable and legitimate.)
- otherwise → `(port ∈ ranges) XOR except`.

Symbolic match values resolve in Go (#3205). Named/service ports (`ssh`,
`http`, `domain`, ...) and symbolic `icmp-type` names (`echo-request`, ...) are
resolved to their NUMERIC value at commit time by `pkg/config`
(`filter_match_resolve.go` — the Junos service-name + icmp-type-name SSOT; the
icmp-type table is family-selected, ICMPv4 vs ICMPv6). An unresolved symbolic
value is hard-rejected at commit by `validateFilterMatchValuesStrict` rather
than silently dropped (a dropped icmp-type matched ALL ICMP; a dropped named
port left the port set constrained-but-empty → the fail-open above). The
dataplane therefore normally sees only numerics; the `constrained + Any`
fail-closed guard is defense-in-depth for the tolerant load / peer-sync path,
where an unresolved token is kept verbatim on the wire.

Tests: `destination_port_except_negation` / `source_port_except_negation` /
`destination_port_except_unresolved_fails_closed_3205` /
`destination_port_except_resolved_name_matches_3205` in `filter/tests.rs` (port
IN the except list does NOT match, port NOT in it DOES, an unresolved except
port fails closed; fail-on-revert). Scope is ports only — `packet-length` from
the same review-039 finding is not implemented.

### Path (b) runbook — cache-sensitive

Adding a per-packet match field that is NOT in the cache key
requires wiring all of these hooks. DSCP is the reference
implementation (#1430); use it as the template:

1. **Aggregate flag** on `Filter` —
   `Filter.has_<X>_match_terms: bool`, computed during snapshot
   compile. See `Filter.has_dscp_match_terms` in
   `userspace-dp/src/filter/mod.rs`.
2. **Per-interface sets** on `FilterState` —
   `iface_filter_v4_has_<X>_match: FxHashSet<i32>` and the v6
   sibling, populated during snapshot compile. See the
   `iface_filter_v{4,6}_has_dscp_match` fields in
   `userspace-dp/src/filter/mod.rs`.
3. **Lookup helpers** in
   `userspace-dp/src/filter/engine/cache_sensitive/rotation.rs` —
   `interface_input_filter_has_<X>_match` and
   `interface_output_filter_has_<X>_match` (or thread the new
   flag through one general helper if the DSCP-specific
   functions are generalized in a future PR).
4. **Flow-cache insertion gate** —
   `userspace-dp/src/afxdp/flow_cache.rs:297-309` calls the
   input + output helpers and returns `None` if either fires.
5. **Established-session re-evaluation** —
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs:217-244`
   (`evaluate_dscp_sensitive_input_filter_on_session_hit`) is
   the DSCP shape; mirror it.
6. **Forwarding-rotation purge** —
   `userspace-dp/src/afxdp/worker/loop_body/mod.rs:295-330`
   uses `input_dscp_filter_families_changed` to decide whether
   to purge sessions. Extend the semantics-match comparison in
   `userspace-dp/src/filter/engine/cache_sensitive/rotation.rs`
   (`filter_term_semantics_match`) to cover the new match
   field's aggregate flag and per-term content. **Compare by
   content, never by compiler-positional filter/term IDs** —
   `Filter.id` and `FilterTerm.id` are stable only within a
   snapshot. **#5293: `filter_term_semantics_match` now derives
   its equality from an EXHAUSTIVE `let FilterTerm { .. } = new;`
   destructure with NO `..` rest pattern** — a newly-added
   FilterTerm field fails to compile there until it is classified
   as compared (bound to a name and checked) or intentionally
   ignored (bound to `_`, e.g. `id`/`counter`). This closes the
   class of bug where a match field is silently omitted from the
   change detector: before #5293 the six `flex_*`
   flexible-match-range fields (#3077/#3232) were absent, so a
   PBR/filter rotation touching ONLY a flex value/mask/offset/
   length/enable/match-start compared equal, the worker skipped
   its per-packet-L4 session purge, and an established session
   stranded on its stale (pre-rotation) routing-instance /
   forwarding decision until timeout. Regression test:
   `filter/engine/cache_sensitive/rotation.rs`
   ::`flex_field_change_is_not_cache_equal`.
7. **Tests** in `userspace-dp/src/afxdp/flow_cache_tests.rs`
   following the DSCP runbook pattern in
   `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
   /`_output_filter` (DSCP-bespoke regression tests) and the
   #1431 references
   `dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern`
   / `_output_*`. The flow-cache test home is `afxdp/` because
   `FlowCacheEntry::from_forward_decision` is
   `pub(super)`-scoped to `afxdp::flow_cache`.

Reference tests (already in the tree, cite from new field PRs):

- gate insertion: `afxdp/flow_cache_tests.rs` ::
  `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
  / `_output_filter`
- rotation purge positional-ID immunity:
  `filter/tests.rs:1806`
  (`input_dscp_filter_families_changed_ignores_positional_filter_id_change`)
- session-hit re-eval: `afxdp/tests.rs:3184`

### Path (a) — extend `SessionKey`

Promoting a per-packet match field into the cache key requires
extending `SessionKey` in `userspace-dp/src/session/key.rs` AND
proving stability across:

- HA session sync wire format (`pkg/cluster/`),
- session-table reverse / NAT-translated / forward-wire indices
  (`userspace-dp/src/session/mod.rs`),
- flow-cache key derivation (`flow_cache.rs`),
- session expiry hash bucket math,
- reverse-NAT lookup keys.

This is a significant cross-cutting refactor — file a tracker
issue against `session/key.rs` before attempting it.

### lo0 is not on the flow-cache path

Host-bound traffic resolves to
`ForwardingDisposition::LocalDelivery`, which
`is_cacheable()` returns `false` for at
`userspace-dp/src/afxdp/types/forwarding.rs:196`. Per-packet lo0
filter evaluation runs at
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:700` (session-hit
path) and `:1153` (miss path). lo0 filters therefore do NOT need
a per-interface `has_<X>_match` set — the flow-cache never holds
a lo0 decision in the first place. This is noted here so future
readers do not repeat the v1 plan investigation that mistook lo0
for a missing cache-sensitive gate.

### lo0 host-bound filters meter their policer (#5857)

A firewall filter attached to `lo0` can carry a `then policer`, and the
compiler links the three-color runtime onto the term exactly as it does
for interface filters. Before #5857 the lo0 / local-delivery path
evaluated the filter with `evaluate_lo0_filter_counted` but consumed only
`action` + `log_match` — it never metered the named policer nor applied a
policer drop, so a strict-valid control-plane rate limit (SSH / BGP /
routing / ICMP to the routing engine) was **inert** (a
control-plane-protection gap: an untrusted peer could exceed the
operator's envelope).

lo0 has NO separate tx-selection leg (unlike interface input/output
filters, which meter their policer in the tx-selection walk), so the lo0
action-eval is the ONLY place its policer can be metered — there is no
double-meter risk. `evaluate_lo0_filter_counted` now threads a
poll-iteration `now_ns` (`Some(..)` on the live path) so the shared
term walk meters each matched term's three-color policer via
`apply_term_three_color_policer` — the SAME runtime the interface
tx-selection leg uses — folding the drop into `FilterResult.policer_drop`
(OR-accumulated across a `then next term` chain, so a later permit cannot
erase an earlier policer drop). `apply_lo0_filter_action` then downgrades
an `Accept` verdict to a silent `Discard` when `policer_drop` is set
(policer drops are silent per Junos semantics — no TCP RST / ICMP
unreachable is synthesized). The three non-lo0 callers of the shared walk
(interface input/output action-eval + PBR prechecks) pass `now_ns = None`
so they do NOT meter here (byte-for-byte identical to pre-#5857). Test:
`lo0_policer_meters_and_drops_host_bound_traffic` in
`poll_descriptor/filter.rs`. Host-bound **DSCP/color rewrite** for a
policed lo0 packet is not applied to the delivered frame (the lo0
local-delivery path has no frame-DSCP-rewrite mechanism — even a term's
plain `then dscp` is not applied on lo0); only the drop is enforced.

### `then reject` synthesizes an active reply (#2521)

`FilterAction::Reject` (`then reject`) no longer realizes as a silent
drop. It now synthesizes and transmits an active reject reply — a TCP
RST for TCP, an ICMP/ICMPv6 administratively-prohibited Destination
Unreachable otherwise — using the **same** machinery as policy
`reject`. `FilterAction::Discard` (`then discard`) is unchanged: still
a silent drop, no reply.

The synthesis is the shared `enqueue_reject_reply` in
`poll_descriptor/reject_reply.rs`; `enqueue_policy_reject_reply` and
`enqueue_filter_reject_reply` are thin wrappers over it that differ
only in the success counter (`policy_reject_sent` vs
`filter_reject_sent`). Filter reject is wired at every input/lo0
filter drop site in `poll_descriptor/mod.rs` that previously recycled
the descriptor on a terminal action: the new-flow input filter, the
DSCP/L4-sensitive session-hit re-evaluation, and both lo0 local-delivery
paths. `apply_lo0_filter_action` returns the matched `FilterAction`
(not a bare drop `bool`) so the caller can tell `Reject` from
`Discard`.

The OUTPUT-firewall-filter (interface `filter output`) `then reject` on
the transit forward / TX/CoS path is wired the same way (#3608). The
TX/CoS classifier (`resolve_cos_tx_selection*` / `resolve_cached_cos_tx_selection`)
collapses every non-`Accept` terminal action plus any three-color-policer
drop into a single `drop` bit, so it now also carries a `reject` bit
(`CoSTxSelection.reject` / `CachedTxSelectionDescriptor.reject`) that
isolates exactly the `then reject` subset (`FilterAction::Reject`) — a
`then discard` or a red policer keeps `reject == false`. The transit
forward-request builder (`build_live_forward_request_from_frame`) and the
flow-cache-hit fast path (`poll_descriptor/flow_cache_hit.rs`) consume
that bit: on a reject drop they call `enqueue_filter_reject_reply` (the
same shared synthesis) BEFORE returning `None` / recycling, reflecting the
ORIGINAL inbound frame back toward the source via the ingress interface.
The output filter-log is emitted AFTER the enqueue with the truthful
outcome, so a reject whose reply fail-closes logs DENY, not REJECT
(#3615). The builder gets the ingress TX pipeline + counters via the
`ForwardRejectReply` context passed by its poll-loop callers.

Zone-level Junos `tcp-rst` (#3071) reuses the same `enqueue_policy_reject_reply`
machinery through the unified `enqueue_deny_reply` decision helper. Both
policy-deny call sites in `poll_descriptor/mod.rs` now call
`enqueue_deny_reply(..., is_reject, from_zone_id)`: when `is_reject` (policy
`then reject`) it actively rejects every protocol as before; otherwise (plain
`deny` / default-deny) it sends a TCP RST **only** when the flow is TCP and the
INGRESS (from) zone has `tcp-rst` enabled (`ForwardingState::zone_tcp_rst_enabled`,
populated from `ZoneSnapshot.tcp_rst`). Non-TCP denied traffic and a deny in a
non-tcp-rst zone stay silent drops. A zone-tcp-rst RST is counted under
`policy_reject_sent` — it is a policy-deny-driven reset. Junos applies `tcp-rst`
to the source/from zone so the RST is sent back toward the connection
initiator, whose interface is bound to the from-zone.

Because the generated reply runs through the SAME path as policy
reject, it inherits the #2238 output-filter / CoS / DSCP
classification (`classify_generated_reply`, keyed on the reply's OWN
egress tuple) and the SYN-cookie TX-frame budget gate — and a future
per-reason generated-reply rate limiter (#2472) covers filter reject
automatically (no parallel, un-limitable emit path). Budget exhaustion,
output-filter drops, and parse-error drops share policy reject's
counters and its fail-closed behavior (the caller still drops the
packet when synthesis returns `false`). The RT_FLOW filter-log action
maps `Reject → reject` (matching policy reject and Junos), `Discard →
deny`.

**Scope (resolved #3608):** output-firewall-filter `then reject` on the
TX/CoS path is now an active reject too — see the OUTPUT-filter paragraph
above. There is no remaining collapse-to-drop site: the deferred-CoS
dispatch path (`resolve_pending_forward_cos_tx_selection` in
`tx/dispatch/`) that used to be one was deleted as dead code in #hb166 T-7
(every `PendingForwardRequest` is built with `cos_tx_selection_resolved:
true`, so the deferred re-resolve never ran). CoS TX selection — including
its `reject` bit — is resolved entirely on the live build-time path.
