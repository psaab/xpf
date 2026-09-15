# Generated-reply rate limiting (userspace-dp)

SSOT for the token-bucket rate limiter on **locally-generated error/reset
replies** in the AF_XDP userspace dataplane
(`userspace-dp/src/afxdp/icmp_ratelimit.rs`). This is distinct from the screen
flood limiter (`userspace-dp/src/screen/rate.rs`, #3607), which detects inbound
floods; this one bounds the RATE at which the box AMPLIFIES a trigger into a
generated reply.

## What is limited

Three locally-originated reply generators run on cold exception paths, each
building + enqueuing a reply after the RFC-suppression and output-classification
gates:

| Reason | Generator | Rate-limit scope |
|--------|-----------|------------------|
| `TimeExceeded` | ICMPv4 Time Exceeded / ICMPv6 Hop-Limit Exceeded (`icmp::build_local_time_exceeded_request`) | **Per ingress (from) zone (#5856), per-source-fair within the zone (#9901 F-074)** |
| `PacketTooBig` | ICMPv4 Frag-Needed / ICMPv6 Packet Too Big (PMTUD, #2301/#2330) | **Per ingress (from) zone (#5856), per-source-fair within the zone (#9901 F-074)** |
| `Reject` | Policy `then reject`, firewall-filter / lo0 `then reject`, and a zone `tcp-rst` deny → TCP RST or ICMP/ICMPv6 admin-prohibited unreachable (`poll_descriptor::reject_reply`) | **Per ingress (from) zone (#3618), per-source-fair within the zone (#9901 F-074)** |

Without a limiter, an attacker driving a flood of TTL-1 packets, oversized DF=1
packets, or rejected flows makes the box emit one generated reply per trigger
packet — a CPU / TX amplification sink and a reflection vector (the reply is
addressed to the trigger's spoofable source). The limiter is modelled on Linux's
`net.ipv4.icmp_msgs_per_sec` (default 1000/s): bounded-state GCRA tiers with
fixed cardinality, so there is no attacker-driven map growth.

The `ZoneLimiter` is a per-source-fair hierarchy (#9901 F-074): a per-source
tier (64 fixed slots, 100/s + burst 100 each, plus a same-budget overflow
bucket for sourceless errors) in front of the zone aggregate (1000/s + burst
1000). Each tier is a single-atomic-word GCRA (theoretical-arrival-time);
refill and consume commit together in one CAS so concurrent workers can never
double-credit or over-admit (#2955). Gate order is source-FIRST then
aggregate: a source-deny consumes NOTHING shared, so one flooder cannot starve
another source in the same zone. Default aggregate rate/burst are compile-time
constants `DEFAULT_RATE_PER_SEC = DEFAULT_BURST = 1000` (mirroring Linux's
`icmp_msgs_per_sec`); a zero rate disables the limiter. Slot collisions share
the slot's sustained rate (tag hint-only, no takeover reset); cardinality is
config-bounded (~1.5KB per zone limiter), never attacker-growable.

## #2472 → #3618 → #5856: why every reason is per-zone

`#2472` introduced a **single global** bucket per reason. That global bucket
coupled all zones: a flood ingressing **one** (e.g. untrusted WAN) zone drained
the shared bucket, so a legitimate generated error in a **different** (e.g.
trusted/internal) zone fail-closed to a silent drop even though that zone was not
under attack. The aggregate cap was being asked to also deliver per-zone
fairness, and it could not — an operator troubleshooting in the quiet zone never
saw that zone's diagnostic while the busy zone stayed flooded.

`#3618` split the **Reject** reason into one bucket per configured zone.
`#5856` extended the IDENTICAL mechanism to **TimeExceeded** and **PacketTooBig**
(their generator call sites always carried ingress identity — the missing zone
key was an API omission, not absence of attribution). All three reasons now use
**one bucket per configured zone**:

- `ForwardingState::{reject_buckets, time_exceeded_buckets, packet_too_big_buckets}:
  FastMap<u16, Arc<ZoneLimiter>>` — one per-source-fair hierarchical limiter
  per configured zone id per reason (#9901 F-074; before, one bare GCRA
  `TokenBucket`), built in `forwarding_build::zones::populate_zones` from the
  SAME validated zone set as `zone_id_to_name`. Cardinality = configured zones
  (the Go control plane caps distinct zones at `MaxUsableZoneID = 65533`), so
  it is config-bounded, never attacker-growable.
- At each generator call site the ingress **from-zone** is resolved via
  `ifindex_to_zone_id`, but the two paths key that map by DIFFERENT ifindexes, so
  their per-zone granularity differs:
  - Reject — `poll_descriptor::reject_reply::enqueue_reject_reply` resolves the
    LOGICAL ingress unit ifindex first (`resolve_ingress_logical_ifindex` →
    `logical_ingress_ifindex`, the same SSOT the reply build and output classify
    key off), so a VLAN sub-interface keys its OWN zone's bucket and a non-VLAN
    port resolves identically.
  - TimeExceeded (`icmp::build_local_time_exceeded_request`) and PacketTooBig
    (the TX dispatch PTB path) key the RATE-LIMIT BUCKET on the PHYSICAL ingress
    bind ifindex (`ingress_ident.ifindex`, the fixed per-binding socket-bind
    port) WITHOUT resolving the logical unit. For an untagged port physical ==
    logical, so the zone is exact; but VLAN sub-interfaces on the same physical
    port all resolve through that port's `ifindex_to_zone_id` entry (the physical
    parent inherits its FIRST sub-interface's zone — `forwarding_build/interfaces.rs`),
    so they SHARE the physical port's TE/PTB bucket rather than getting a
    per-sub-interface one. This is still correct and strictly better than the
    pre-#5856 single global bucket (distinct physical ingress ports no longer
    starve each other); it is simply coarser than the Reject path's
    per-logical-unit granularity. **This physical bucket keying is deliberate and
    distinct from the reply BUILD + output CLASSIFY, which (post-#6102) DO resolve
    the logical unit** via `resolve_ingress_logical_ifindex` — so a tagged sub-if
    sources its reply from its own address/VLAN and enforces its own output
    filter / CoS, while the per-zone amplification bound stays per-physical-port.
- An unzoned (id 0) or otherwise-unknown from-zone falls back to the reason's
  process-global `{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_FALLBACK_LIMITER` — a
  full `ZoneLimiter` (#9901 F-074; a real limiter, so the gate is **never
  fail-open** and never panics on a missing key). Unzoned/unknown errors share
  that one budget (the rare/degenerate case), with per-source fairness inside
  it.

The zone-keyed lookup is the single accessor
`ForwardingState::generated_error_bucket(reason, from_zone_id)`, and the single
gate is `icmp_ratelimit::allow_generated_error_zoned[_at]` (the `Reject`-specific
`allow_generated_reject[_at]` wrappers delegate to it). Every gate takes the
trigger's source address (`Some` keys the per-source tier, `None` the shared
overflow tier): TE and Reject pass `flow.src_ip` (the pre-NAT session flow);
the PTB path passes the shim-stamped META addrs (the PTB frame itself is
post-NAT, so frame bytes would key the wrong identity).

### Why this does not weaken the anti-amplification cap

The realistic reflection attacker floods ONE ingress path (the WAN zone); each
zone's bucket still caps that path at 1000/s per reason — **identical** to the
pre-split global cap for the single-ingress case. Per-zone buckets remove the
cross-zone starvation while preserving the per-ingress-zone cap. Reaching the
`N × 1000/s` aggregate requires an attacker already inside the trust boundary
driving errors across many zones at once (a multi-VLAN trunk / compromised
internal host), who can emit far more damaging traffic than reflected
RST/ICMP/PTB backscatter; each zone is still individually capped. A global
second-level ceiling for that east-west amplifier is a filed optional follow-up,
not built here.

### #5856: TimeExceeded / PacketTooBig are now per-zone too

Before #5856, TE and PTB kept their single global-per-reason bucket, so an
attacker flooding TTL=1/hop-limit=1 (→ Time-Exceeded) or oversized-DF (→
Packet-Too-Big) traffic through ONE untrusted zone drained the shared bucket and
**suppressed legitimate traceroute / PMTUD replies for every OTHER zone** — a
cross-zone denial of the generated-error service (suppressing PTB can turn
unrelated large flows into persistent PMTUD blackholes). The generator sites DID
carry ingress identity (`ingress_ident.ifindex`); the missing zone key was an
API/design omission. #5856 resolves the from-zone at each site and keys a
per-zone bucket exactly as #3618 did for Reject, closing the cross-zone denial.

## Lifetime / sharing model (why `Arc<ZoneLimiter>`)

All workers gate against the SAME per-zone limiter (for every reason): each worker
holds an `Arc<ForwardingState>` loaded from the shared `ArcSwap` (`load_full()`),
so within one forwarding generation they share the one `ForwardingState` instance
and its atomics — the cap is per-zone, not per-worker.

The limiters are held behind `Arc` (not plain values) because the coordinator
re-stores a CLONE of the forwarding state at runtime cadence (fabric refresh,
`snapshot_refresh.rs`), not only on config commit. A plain-value clone would
snapshot the coordinator-side (stale, worker-untouched) atomics on every refresh
and effectively RESET the limiter. `Arc<ZoneLimiter>` is shared by reference
across `ForwardingState::clone()`, so the limiter state persists across a refresh.
A genuine config rebuild re-runs `populate_zones` and installs fresh limiters —
**reset-on-commit**, which is accepted for a diagnostic limiter (a commit is rare,
operator-initiated, and a fresh burst allowance right after a commit is benign).

## Observability (metric unchanged)

Each reason's aggregate `*_rate_limited_total` is a SINGLE process-global atomic
(`{REJECT,TIME_EXCEEDED,PACKET_TOO_BIG}_RATE_LIMITED_TOTAL`) bumped on ANY deny —
per-zone aggregate-denies, source-denies, and fallback denies alike — NOT a sum
over the per-zone limiters' fields — so `rate_limited_count(reason)` stays an
O(1) atomic load and the coordinator status
/ Prometheus `xpf_userspace_{reject,time_exceeded,packet_too_big}_rate_limited_total`
wire contract is UNCHANGED by the per-zone (#3618/#5856) and per-source (#9901
F-074) splits. Each tier's `TokenBucket` keeps its own `rate_limited` field for
OPTIONAL future attribution; the aggregate metric never reads it. (Before #5856,
TE/PTB read their single global bucket's field directly; now they read the
dedicated aggregate atomic, which every gate bumps — the surfaced value is
unchanged.)

## Fail-closed invariants preserved

- Every failure leg (bucket-empty, budget-exhausted, unparseable, output-filter
  drop) still returns false and the caller silently drops the trigger packet —
  the reject reply is a courtesy; the trigger is dropped regardless, so this is a
  fairness/observability fix, never a good-traffic-drop or security bypass.
- A missing zone id maps to the fallback limiter, never a fail-open skip.
- #3656: a frame that can never produce a reply (inbound RST, inbound ICMP error,
  non-first fragment, ...) is proven unreplyable BEFORE the token is consumed, so
  a flood of unreplyable frames cannot drain a zone's bucket (H11).
- #5567: the SAME build-before-consume ordering now holds for the **TimeExceeded**
  and **PacketTooBig** reasons, closing the residual the #3656 fix left on those
  two generators. Both consume their token ONLY after the reply is proven
  FEASIBLE + built — the egress-object lookup and the v4/v6 builder each return
  `None` (a drop) when the reply cannot be produced (no egress object for the
  ingress ifindex, no primary address of the inbound family, or an unparseable
  trigger). Previously the token was consumed BEFORE the build, so a flood of
  reply-eligible-but-UNBUILDABLE triggers on ONE interface (e.g. a wrong-family or
  no-egress ingress) drained the TE/PTB bucket (then a single global one;
  per-zone since #5856) and starved buildable PMTUD / traceroute diagnostics on
  ANOTHER interface — a cross-interface false-deny DoS. The build-before-consume
  ordering still matters per-zone: it stops an unbuildable flood from draining
  even the ingress zone's own bucket. The gate order is: RFC/suppression gate →
  build (feasibility proof) → token. A buildable reply that the token denies is
  still dropped
  (rate-limited, counter bumped); an unbuildable reply never touches the token.
  The trigger-packet disposition is unchanged in every case: TE returns `None`
  (drop) exactly as before, and the oversized-original PTB drop stays gated on
  `mtu_signalled`, independent of whether the PTB was built.
- #5569: for the **Reject** reason the per-zone token is now consumed only AFTER
  the #2238/#3035 output-filter classification ADMITS the reply, not before it.
  The reject-path gate order in `enqueue_reject_reply` is now: build (feasibility,
  #3656) → TX-frame budget → **output-filter classify (`classify_generated_reply`)**
  → **per-zone token (`allow_generated_reject`)** → enqueue. Previously the token
  was consumed BEFORE the classify-drop, so a flood of egress-FILTERED rejects —
  rejects whose generated ICMP/RST is discarded by the reply's OWN egress output
  filter or three-color policer — drained the ingress zone's shared reject bucket
  and suppressed a later TCP RST the SAME zone's output filter would have
  PERMITTED (same-zone cross-protocol starvation: a filtered-ICMP flood starving a
  permitted-RST). This is the reject-path analogue of the #3656 H11 (unreplyable)
  and #5567 (unbuildable TE/PTB) build-before-consume ordering: a resource meant
  to bound amplification must not be spent on a reply the box discards. A reply the
  output filter DROPS (terminal `discard`/`reject`, a policer discard, or a
  fail-closed re-parse error of our own bytes) now spends NO zone token and is
  attributed to `*_reject_output_filter_drops` / `generated_reply_classify_parse_errors`;
  a reply that SURVIVES classify but the token DENIES is still dropped
  (rate-limited, `*_reject_rate_limit_drops` + the aggregate
  `reject_rate_limited_total` bumped exactly once — `allow_generated_reject` is
  still called exactly once, no double-consume); a reply that survives classify AND
  the token allows is enqueued carrying the SAME `verdict.cos_queue_id` /
  `verdict.dscp_rewrite`. The trigger-packet disposition is unchanged (the caller
  drops the trigger on a `false` return regardless); only WHEN the token advances
  changed.
- #9901 (F-074): WITHIN a zone the tier order is source-FIRST then aggregate —
  the #5567 build-before-consume principle applied to the tier order. A
  source-denied reply consumes NOTHING shared (only the reason's aggregate
  deny counter moves, for observability), so one flooder cannot spend another
  source's budget or the zone aggregate. An aggregate-denied reply consumed
  its source token first (conservative: the source spent budget on a reply
  the zone could not emit); the alternative (peeking the aggregate without
  consuming) would race under concurrent workers for no operator benefit.
