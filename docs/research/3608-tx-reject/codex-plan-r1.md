# Codex — hostile plan review r1 (#3608), verbatim

VERDICT: **PLAN-DEFER, option (c) commit-time warning. Keep #3608 open; do NOT
implement option (a).**

Blocking objections (all with file:line):

1. The "three drop sites" claim is FALSE — the deferred-dispatch drop at
   `tx/dispatch/mod.rs:135-138` only runs when `!request.cos_tx_selection_resolved`,
   but production builders set it TRUE (`forward_request.rs:232`, `icmp.rs:268`,
   `poll_descriptor/mod.rs:1998`); `tx/dispatch/cos.rs:141-143` says that path may
   run AFTER the UMEM frame was recycled → not a live-original-frame site.
2. Site 2 lacks helper inputs — `PendingForwardRequest` carries
   `flow_key: Option<SessionKey>` (`types/tx.rs:73-84`), NOT `&SessionFlow`, but
   `enqueue_filter_reject_reply` requires `flow: &SessionFlow`
   (`reject_reply.rs:70-78`); that helper is `pub(super)` in poll_descriptor
   (`reject_reply.rs:70`) — tx/dispatch cannot call it as-is.
3. The #2301 PTB precedent does NOT prove the proposed borrow pattern (dispatch
   stores `ingress_area` as a raw ptr, builds an OWNED Vec `ptb_reply`, enqueues
   after the borrow ends — not holding a UMEM slice while mutating
   `ingress_binding.tx_pipeline`).
4. Reflection semantics assumed not proven — TCP reject deliberately SPOOFS the
   original dest as RST source (`frame/tcp.rs:555-571/596-608/621-627`); non-TCP
   ICMP uses ingress-iface primary addr (`icmp.rs:541-560`). Plan doesn't prove
   OUTPUT-filter reject should inherit policy-reject TCP spoofing vs
   firewall-sourced rejection.
5. Shared Reject limiter caps AGGREGATE not fairness (`reject_reply.rs:167-179`
   shares one bucket policy+filter; `icmp_ratelimit.rs` global-per-reason 1000/s)
   → a reject-everything output filter starves policy/input reject diagnostics.

Non-blocking: Site 1 (`flow_cache_hit.rs:65-87`) has the original frame but is the
hot established arm; Site 3 needs an Option-API change (`poll_descriptor/mod.rs:
1057/3444`, `flow_cache_hit.rs:402`) broader than the plan admits.

ACTION: converge on PLAN-DEFER with option (c) (commit-time warning that
OUTPUT-filter `then reject` is realized as a drop the dataplane cannot actively
reject — mirror the #3445 warn-not-silent-noop precedent). Address objection 5 as
a separate follow-up (shared reject-bucket starvation).
