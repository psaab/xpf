# AGY (Antigravity) — adversarial plan review r1 — #2238

Job: `adversarial-review-mqopeax8-qsducu` (succeeded). Read-only, grounded in
line references. Verdict: **PLAN NO** — one blocking finding, all other
challenges RESOLVED.

## [BLOCKING] A1 — Fail-Open Security Bypass on Internal Parse Failure (§6.2)

> The proposal to fail-open and emit replies unclassified if the byte parser
> fails is a security vulnerability. An egress output filter term (e.g.,
> discarding outbound ICMP to obscure topology) is a security boundary. Under
> this plan, if a malformed trigger packet induces a local ICMP reply that
> chokes the parser, the packet bypasses the egress discard filter and leaks
> out of the firewall.
> **Required Change:** Transition to fail-closed (drop packet) on any internal
> parse error. Observation maintained via `generated_reply_classify_parse_errors`.

**Disposition: APPLIED in plan r3 §6.2.** Converges with Codex-r1 Blocker 2.

## RESOLVED challenges (AGY verified against source)

- **Path B vs A vs C:** Path B lowest-risk. Path A risks transit-loop recursion
  / packet cycles by routing local replies into `PendingForwardRequest`. Path C
  duplicates filter eval across builders. Path B delegates to existing
  `frame/inspect.rs` helpers (`frame_l3_offset`, `parse_flow_ports`).
- **Embedded-ICMP NAT path deferral:** correct — it handles transit traffic;
  pulling it into this PR bleeds host-only changes into the forwarding loop.
  Track as sibling.
- **Output port-mirror deferral:** correct scope fence — verified `mirrors.go`
  + `mirror/mod.rs` only implement ingress-direction mirroring; egress mirror
  does not exist in the codebase.
- **Time Exceeded egress-ifindex correction:** same bug class, not scope creep
  (with `bind_ifindex` set the reply egresses a different interface; evaluating
  on `ingress_ident.ifindex` is the same classification defect).
- **ICMP ports=0 keying:** verified `parse_flow_ports` (inspect.rs:313-317)
  ALREADY sets ICMP destination port key to 0 on transit; the generated-reply
  keying aligns with existing behavior — no new regression surface.
- **Hot-path cost:** reject (`reject_reply.rs:22`) and SYN-cookie
  (`cookie_reply.rs:45`) are `#[cold] #[inline(never)]`; Time Exceeded fires
  only on TTL expiry. Transit loop register pressure unaffected.
- **HA/fabric:** generated replies are stateless + node-local; fabric TTL
  expiry explicitly ignored (`icmp.rs:6`); no new distributed state.
- **Go↔Rust wire-contract:** `protocol/tests.rs` wire-invariant specimens
  enforce Go/Rust snapshot sync; plan mandates `protocol_wire_v1.json` regen.

## Net

AGY independently confirmed every scope fence and the ICMP-port-0 claim against
source, and converged with Codex on the single fail-closed blocker. With r3's
§6.2 flip, AGY's only blocker is satisfied.
