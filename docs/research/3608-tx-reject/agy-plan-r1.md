# AGY — hostile plan review r1 (#3608), verbatim

VERDICT: **PLAN-DEFER (Option c)**

Blocking objections:

1. Unreachable Drop Site 2: `userspace-dp/src/afxdp/tx/dispatch/mod.rs:136`. In
   production every `PendingForwardRequest` is built with
   `cos_tx_selection_resolved = true` (`forward_request.rs:232`, `icmp.rs:268`,
   `poll_descriptor/mod.rs:1998`), so `pending_forward_needs_cos_tx_selection`
   (`dispatch/cos.rs:165`) always returns false — the `cos.drop` block at
   `dispatch/mod.rs:136` is dead code. Any packet matching a drop/reject filter is
   already filtered out (None/recycled) at build time (`forward_request.rs:215` /
   `flow_cache_hit.rs:181`), so no packet with `cos.drop == true` ever reaches
   dispatch.

2. Policer-Drop vs Reject bug: `poll_descriptor/flow_cache_hit.rs:181` and
   `tx/cos_classify.rs:412`. Checking `cached_descriptor.tx_selection.reject`
   inside a drop branch (where `tx_selection.drop || policer_action.drop` is true)
   will incorrectly fire a reject reply when a flow matches a terminal Reject but
   is discarded by a transient/fall-through three-color policer
   (`policer_action.drop` true while `tx_selection.reject` still true). Logic must
   explicitly gate on `!policer_action.drop` (cached) and `!output_result.policer_
   drop` (runtime); the plan overlooks this.

Non-blocking concerns:

1. NAT/egress-filter parity mismatch: `forward_request.rs:175` and
   `tx/cos_classify.rs:384-388`. Junos evaluates egress output filters on post-NAT
   headers, but `forward_request.rs:175` passes the pre-NAT ingress session flow
   key to `resolve_cos_tx_selection_at`. For NAT64 the IPv4 egress filter is
   evaluated with the IPv6 ingress key — a full mismatch. Synthesizing reject on
   the pre-NAT frame inherits this architectural mismatch without achieving true
   Junos parity.

2. Complexity/value ratio: `forward_request.rs:215`. Evaluating reject where
   `tx_pipeline`/`counters` are unavailable forces refactoring
   `build_live_forward_request_from_frame`'s return type/params — violates the
   low-cost/low-risk bar for a diagnostic niche feature.
