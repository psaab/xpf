# Claude SMR — hostile plan review r1 (#3608)

Reviewer: Claude SMR (in-conversation, hostile). Base: origin/master `a2c524281`.
Verdict below is adversarial-first: I tried to KILL the plan.

## Verdict: PLAN-READY-WITH-REVISIONS (option (a)), conditional on a v2 that
corrects the site map. NOT a KILL. NOT a DEFER — the change is SMALLER than v1
claimed, which strengthens the case for doing it.

## Blocking findings (must be fixed in plan v2)

### B1 — The site map is WRONG. There are 2 live transit-reject sites, not 3; one of the "3" is dead code.
I verified every `PendingForwardRequest` constructor. ALL set
`cos_tx_selection_resolved: true` (forward_request.rs:232, icmp.rs:268,
poll_descriptor/mod.rs:1998). There is NO `cos_tx_selection_resolved: false`
setter anywhere in production. Therefore `pending_forward_needs_cos_tx_selection`
(= `!resolved`, cos.rs:165) is ALWAYS false, and the `if cos.drop` at
**tx/dispatch/mod.rs:136 is UNREACHABLE in production** — a defensive/legacy path.
The plan calling it "drop site 2" and proposing synthesis there is dead work.

The REAL live transit-reject drop sites are exactly two:
1. `poll_descriptor/flow_cache_hit.rs:181` — HOT, established-flow packets.
2. `forward_request.rs:215` (`if cos.drop { return None }`), surfaced to its
   production callers **poll_descriptor/mod.rs:3444** (THE main transit
   forward-candidate site, first packet of a flow, both directions, carries NAT)
   and **mod.rs:1057** (fabric-return fast path). `flow_cache_hit.rs:402` also
   calls the builder but only AFTER the :181 drop check returned Consumed, so it
   is never a drop for a cached reject.

v2 must: (i) demote dispatch/mod.rs:136 to "dead defensive path — assert/no-op,
no synthesis"; (ii) rename sites to the two above; (iii) name mod.rs:3444 as the
primary slow-path synthesis point (enum-return handled there, where
`packet_frame`, the ingress binding, and counters are all in scope).

### B2 — The plan does not distinguish transit-reject drops from GENERATED-REPLY drops, which must be EXCLUDED.
Three sites drop a LOCALLY-GENERATED frame on an output-filter match and must
stay silent (they are not transit traffic from a remote source; synthesizing a
reject-for-our-own-reply is nonsense and risks a loop):
- `poll_descriptor/mod.rs:1959/1973` (generated ICMP-error reply, `Prebuilt`).
- `tx/dispatch/mod.rs:1150` (#2328 PTB reply classify).
- `classify_generated_reply` internal drop (reject_reply.rs:222).
v2 must state the reject-synthesis branch fires ONLY for a `Live`/`Owned` transit
frame with a real remote source, never for a `Prebuilt`/generated frame. (Open
question 3 in v1 gestures at this for `Prebuilt` but the plan body does not carry
the exclusion as an invariant.)

### B3 — Reflection source-address parity must be a stated decision, not an inherited accident.
For a transit TCP reject, `build_reject_rst_frame` reflects the original frame →
RST L3 src = original DESTINATION (i.e., the RST appears to come from the server
the client was talking to). That is correct/desirable for `then reject`
(the client must believe the peer reset it), and it matches policy reject
(#2089/#2521). But v1 leaves it as an "open question." v2 must AFFIRM this is the
intended Junos-parity behavior and cite that input/policy reject already do it,
so implementation does not "fix" it into sourcing from the firewall.

## Non-blocking concerns

- N1 (value/risk): the honest value is Medium (parity/diagnostics; the drop
  already enforces). But B1 shows the blast radius is 2 sites (one hot, one cold),
  reusing an existing rate-limited interface — LOW marginal cost. This tips me to
  READY over DEFER. If the reviewers weight the hot-path touch higher, option (c)
  commit-warning is the correct DEFER, and it is genuinely cheap (#3445/#3295
  precedent). Keep (c) as the documented fallback.
- N2 (NAT64): NAT64 flows are non-cacheable (mod.rs:3420 comment), so they only
  hit the slow-path site (forward_request:215 via 3444), per packet. Reflecting
  the original inbound frame yields a reply in the SOURCE's family (v6 forward →
  ICMPv6 to the v6 source). Correct, but v2 should say so — it is the one case
  with no cache amortization, so the #2472 bucket matters most there.
- N3 (backscatter): the shared `GeneratedErrorReason::Reject` bucket now also
  gates output-filter reject. Under a reject-everything output filter on a
  line-rate transit flow, output and input/policy reject compete for the same
  bucket. Acceptable (all are "Reject" backscatter and should be jointly capped),
  but v2 open-question 5 should be answered "shared bucket is intended," not left
  open.
- N4 (tests): the two existing tests at cos_classify_tests.rs:1424/1477 assert
  `selection.drop` on discard/reject; both keep passing (drop unchanged) — extend
  to assert the new `reject` discriminator (reject term → reject=true; discard →
  reject=false). Good fail-on-revert.
- N5 (M11): correct that issue-history.md is generated (`/sync-history`) and #3608
  existing resolves M11; no hand-edit. Confirmed no manual doc row is needed.

## What the implementation MUST get right (if READY)
The `reject` discriminator must be set ONLY from `FilterAction::Reject` on the
OUTPUT-filter result, never from `policer_drop` or `Discard`, and the synthesis
branch must fire ONLY on a live transit frame at the TWO real sites. Everything
else (budget, bucket, classify, fail-closed, reflect-pre-NAT) is inherited
correctly from the existing interface.
