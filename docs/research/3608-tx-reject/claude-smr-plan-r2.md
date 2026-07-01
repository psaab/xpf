# Claude SMR — converged plan review r2 (#3608)

Reviewer: Claude SMR (in-conversation, hostile). Base: origin/master `a2c524281`.

## Verdict: PLAN-DEFER — recommend option (c) (commit-time warning) now; keep
#3608 open with option (a) as the deferred design-of-record. This is a
self-correction from my r1 (READY-WITH-REVISIONS).

## Why I converged from r1-READY to r2-DEFER

My r1 leaned READY on the premise that option (a) was "low marginal cost — the
machinery exists, only 2 live sites." Codex and AGY (both DEFER) surfaced five
costs I under-weighted; re-checking each against source, they hold:

1. **API boundary is real plumbing, not a one-liner (Codex #2).**
   `PendingForwardRequest` carries `flow_key: Option<SessionKey>`
   (`types/tx.rs:73-84`), but `enqueue_filter_reject_reply` requires
   `flow: &SessionFlow` (`reject_reply.rs:70-78`), and the helper is `pub(super)`
   in `poll_descriptor`. Reusing it from the slow-path dispatch sites means
   reconstructing a `SessionFlow` from a `SessionKey` and widening the helper's
   module visibility (or hoisting it). My r1 "reuse the existing interface as-is"
   was wrong about the call boundary.

2. **The borrow pattern is NOT proven by #2301 (Codex #3).** The #2301/#2328 PTB
   block builds an OWNED `Vec` and enqueues AFTER the ingress borrow ends
   (`ingress_area` is a raw ptr, not a live UMEM slice held across the
   `tx_pipeline` mutation). My r1 claim that #2301 "proves the split-borrow" was
   overstated — reflection would need an owned-frame copy first. Feasible, but not
   the free precedent I implied.

3. **Reflection source-address is an unresolved PRODUCT decision (Codex #4, AGY,
   my r1-B3).** TCP reject SPOOFS the original destination as the RST source
   (`frame/tcp.rs:555-627`); ICMP sources from the ingress-iface primary
   (`icmp.rs:541-560`). Whether an OUTPUT-filter reject should inherit
   policy-reject's TCP spoofing (vs a firewall-sourced rejection) is a product
   call that must be made BEFORE code, not inherited by accident.

4. **Shared Reject limiter caps aggregate, not fairness (Codex #5, AGY N3).** One
   `GeneratedErrorReason::Reject` bucket (`reject_reply.rs:167-179`,
   `icmp_ratelimit.rs` 1000/s) gates policy + input + (proposed) output reject. A
   reject-everything OUTPUT filter on a line-rate transit flow would starve
   policy/input reject diagnostics. This is arguably its own follow-up
   (per-source or per-interface reject budget) and a prerequisite for (a).

5. **Pre-existing NAT-tuple output-filter mismatch (AGY N1).** `forward_request.rs
   :175` evaluates the egress output filter on the PRE-NAT ingress `forward_key`;
   Junos evaluates output filters on post-NAT egress headers (for NAT64 the v4
   egress filter sees the v6 key — a full mismatch). This is a PRE-EXISTING bug
   orthogonal to reject-vs-drop; but it means active reject in NAT cases would
   fire on a match set that already diverges from Junos — reducing the parity
   value that justifies (a). Deserves its own issue.

Given the action is **Medium** severity (the silent drop ALREADY enforces the
security boundary — only the courtesy RST/ICMP is missing) and is a diagnostic
niche, these five costs push it under the value bar for now. My r1 site-map
correction (only 2 live sites; `dispatch/mod.rs:136` is dead — Codex #1, AGY #1)
stands and is folded into v2.

## Recommendation

- **Ship option (c) now:** a commit-time WARNING (not a reject) that an interface
  `filter output ... then reject` degrades to a drop the userspace dataplane
  cannot actively reject, naming interface/unit/filter/term. Hook:
  `pkg/config/compiler_validate_warn.go`, mirroring the #3445 lo0-mirror-modifier
  and #3295 no-catch-all warn-not-reject precedents; warn-only on BOTH strict and
  lenient paths (#1960 no-brick); EXCLUDE lo0/host-bound (#2521/#3445 already
  actively reject there). This is small, low-risk, and makes the gap
  operator-visible immediately.
- **Keep #3608 open** with option (a) as the deferred design-of-record, gated on:
  (i) demand justifying the hot-path touch, (ii) a decision on reflection
  source-address semantics (#4/product), (iii) a fairness/budget answer for the
  shared reject limiter (own follow-up), and (iv) resolution of the pre-existing
  NAT-tuple output-filter evaluation (own issue).

## Converged with Codex (DEFER-c) and AGY (DEFER-c). 3-of-3 on PLAN-DEFER.
