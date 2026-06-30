# Claude SMR — hostile plan review r1 (#2562)

Reviewing `docs/research/2562-nat64-frag/plan.md` v1 against origin/master
`a30a1f98b`. Hostile pass — trying to falsify the load-bearing claims, not
confirm them.

**Verdict: PLAN-DEFER (with changes).** The bug confirmation is correct, the
SHARE-the-#3291-stage-4 conclusion is correct, and PLAN-DEFER is the right
terminal state. But two claims are overstated and must be corrected before this
is an honest plan a future `/engineer` can trust. None is a verdict-flipper.

## Findings

### S1 (HIGH) — the reverse-direction cached value does NOT fit `NatDecision`; §3.3/§5.1 are wrong as written

The plan claims (§3.3, §5.1.1): *"a fragment-association cache that stores the
first fragment's full `SessionDecision` already carries the NAT64 forward
translation … the reverse first reply fragment's `SessionDecision` carries the
reverse cross-family `NatDecision` the same way … No NAT64-specific key/value is
required."*

Verified false for the reverse direction. The reverse v4→v6 translation is
driven by **`Nat64ReverseInfo { orig_src_v6, orig_dst_v6 }`**, which is stamped
on the **session metadata** (`poll_descriptor/mod.rs:2180` forward entry, `:2428`
reverse entry) and recovered on the warm/TX path
(`afxdp/frame/mod.rs:248` `let info = nat64_reverse?` → `build_nat64_v4_to_v6_frame`).
It is **not** part of `NatDecision` (`nat/mod.rs:67` has only
`rewrite_src/rewrite_dst/ports/nat64/nptv6` — no v6 original-source field).
`Nat64State::forward_decision` (nat64.rs:373) populates `NatDecision` only for
the FORWARD direction (`rewrite_src=snat_v4`, `rewrite_dst=dst_v4`).

**Consequence:** the forward direction fits the generic `SessionDecision` value
unchanged, but the **reverse** direction requires the cached value to ALSO carry
the `Nat64ReverseInfo` (or an equivalent v6 src/dst). The correct statement is:
*the cache is still ONE shared subsystem (same key, eviction, TTL, DoS, HA, and
the process-shared placement of §5.3), but the cached VALUE must be extended for
NAT64 — `SessionDecision` covers forward; reverse needs the session's
`nat64_reverse` mapping folded into the cached value.* This is the cross-family
extension, just on the value side as well as the egress side. The SHARE
conclusion survives; the "no NAT64-specific value required" sentence does not.
Fix §3.3 and §5.1.1, and add the reverse value field to §5.4.

### S2 (MED) — overstated certainty on the cross-worker RSS split

§3.4 / §5.3 assert *"they hash to different RX queues → different workers."* That
is config/hardware-dependent, not guaranteed. Whether the FIRST fragment is
hashed by 4-tuple (it carries ports) while non-first fragments are hashed by
2-tuple depends on the NIC's RSS fragment policy; some configs hash all fragments
(first included) by the 2-tuple, co-locating them. The honest argument is
*robustness*: a correct design must not DEPEND on RSS co-locating fragments,
because under a plausible default it does not. Soften "they hash to different
workers" to "are not guaranteed to co-locate; under a default mlx5 RSS config
they can split" — which still justifies process-shared (§5.3) on robustness
grounds. Do not weaken the §5.3 recommendation; weaken only the certainty of the
claim it rests on.

### S3 (MED) — "share one subsystem" oversells; the egress half is genuinely NAT64-specific

The cache (storage, key, eviction, TTL, DoS bound, IP-ID aliasing defense, HA
non-sync, process-shared placement) is truly shared with #3291 stage 4. But the
#3291 stage-4 egress step (AGY-2) is a SAME-FAMILY outer-header rewrite + IPv4
checksum recompute; NAT64 is CROSS-FAMILY — the non-first fragment is rebuilt
into a different-size L3 frame (40-byte v6 ⇄ 20-byte v4, 8-byte Fragment Header
insert/remove), a different UMEM-frame length, no L4 checksum. That is genuinely
separate code dispatched on `nat.nat64`, not a shared rewrite. The plan does say
this in §5.2, but the framing elsewhere ("one subsystem, hazards solved once")
should be precise: **shared CACHE; NAT64-specific egress dispatch + value
extension.** This matters for the verdict comment so the reader does not expect
#2562 to be free once #3291 stage 4 lands.

### S4 (LOW) — the dependency must shape #3291 stage 4's value type NOW

Because the reverse value needs `Nat64ReverseInfo` (S1) and the egress needs a
cross-family dispatch (S3), #3291 stage 4 must design its cached-value type as an
EXTENSIBLE container (generic `SessionDecision` + an optional NAT64 reverse
mapping) and its egress step as a dispatch, from day one — otherwise #2562 forces
a retrofit. This strengthens the recommendation from "defer behind stage 4" to
"defer behind stage 4 AND require stage 4 to reserve the cross-family value/egress
seam." Add this as an explicit dependency note for the verdict comment and Q1/Q7.

### S5 (LOW, unresolved open question, NOT a blocker) — how does reverse NAT64 reach the right worker today?

The session table is per-worker (`worker/loop_body/setup.rs:40`). The v6 forward
session is on worker A (v6 hash); the v4 reply hashes by v4 tuple to possibly
worker B. The reverse `nat64_reverse` metadata is on both entries, but both live
in worker A's table. How a reverse reply on worker B finds it today is
unverified. The plan correctly flags this as Q3 and it does not block the DEFER
verdict — but it is load-bearing for WHERE the reverse cache/decision must live,
so it must be answered at `/engineer` time before the reverse half is built. Keep
Q3 prominent.

## What I could NOT disprove (stands)

- **The bug.** Non-first NAT64 fragments get no translation today: the
  translators fail closed (nat64.rs:763, ~999) AND the post-#3600 flowless arm
  returns `nat: NatDecision::default()` (`poll_descriptor/mod.rs:~2905`) and
  never calls `classify_ipv6_dest` (only the cold path at mod.rs:1055 does).
  Two-layered, exactly as the plan states. Confirmed.
- **SHARE > NAT64-specific** as the cache architecture. Option B duplicates every
  hazard and lacks the session-lifetime fallback; Option C (reassembly) is a
  different, bigger feature. Option A is right.
- **Process-shared/sharded placement** (§5.3) as the robust choice given
  per-worker session/flow-cache state — modulo the S2 certainty softening.
- **Drop fragmented ICMP** (the ICMP checksum covers the whole datagram; can't
  recompute from a fragment) — correct, resolves agy-039-03.
- **PLAN-DEFER** as the verdict: #2562 is strictly dependent on the deferred
  #3291 stage 4; the NAT64 delta is converged but not standalone-shippable.

## Required edits for r2
Fold S1 (correct §3.3/§5.1, add reverse value field to §5.4), S2 (soften the RSS
certainty), S3 (precise "shared cache / NAT64-specific egress+value" framing),
S4 (stage-4-must-reserve-the-seam dependency). S5 stays an open question.
