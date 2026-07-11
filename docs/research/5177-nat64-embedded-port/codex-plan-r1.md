# Codex — hostile plan review, #5177 (plan r2)

Model: gpt-5 (codex-companion). Read-only adversarial audit. Session 019f51fa.
Task: try to BREAK the PLAN-KILL. Verdict below is verbatim Codex output.

## Summary of Codex disposition
- Item 1 (reachability): NO counter-path found — reverse NAT64 ICMP error is dropped; the scoped fix site is unreachable. KILL basis holds.
- Item 2 (forward datum): confirmed fresh per-error allocation (wrong datum).
- Item 3 (datum availability): EmbeddedIcmpMatch.original_src_port is the client port (both arms).
- Item 4 (KILL vs reframe): the scoped embedded-ICMP fix (NatDecision::default() request) is NOT repaired by the ordinary-reply carriage fix — scoped ask insufficient → supports KILL + larger follow-up.
- Item 5 (R-C): EXHAUSTIVELY PROVEN — ordinary reverse NAT64 TCP/UDP replies are ALSO broken (Nat64ReverseInfo lost at the PendingForwardRequest boundary); a small decision-derived repair exists for the ordinary-reply carriage; oversized reverse TCP additionally leaks as IPv4 via segmentation.
- Material plan corrections to fold into r3 (citation mislabels; upgrade the 'may be unreachable' hedge to 'exhaustively broken').

## Verbatim final verdict

Item 5 verdict: **ordinary reverse NAT64 TCP/UDP replies do not correctly translate in the current userspace production path.** Session/BIB state is built correctly, but `Nat64ReverseInfo` is lost at the `PendingForwardRequest` boundary. No alternate Rust/XDP translation path repairs it.

Verified:

- Forward NAT64 creates `nat64_info` from the original IPv6 endpoints at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2730-2782`. It stores that value on both forward and reverse `SessionMetadata` at `:3003-3010` and `:3280-3286`.
- The reverse decision is correctly generated with `NatDecision::reverse` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3216-3223`; the IPv4 reverse key handles both TCP and UDP at `:3238-3275`; the reverse session is installed and published to the XDP session map at `:3322-3368`.
- Lazy reverse-session repair also preserves the metadata: `resolve_flow_session_decision` invokes the forward-NAT lookup/repair at `userspace-dp/src/afxdp/session_glue/mod.rs:1151-1230`, while `build_reverse_session_from_forward_match` copies `forward_match.metadata.nat64_reverse` and reverses the decision at `userspace-dp/src/afxdp/shared_ops.rs:668-734`.
- HA import likewise reconstructs real NAT64 session metadata at `userspace-dp/src/server/helpers.rs:475-505` and `:529-567`. Thus local, lazy, and synced session state are not the missing link.
- The kernel shim does not translate NAT64. A published live session stores only the redirect action at `userspace-dp/src/afxdp/bpf_map/mod.rs:68-95`; the XDP shim reconstructs the key and reads that action at `userspace-xdp/src/lib.rs:1427-1437`, then redirects the packet to AF_XDP at `:584-645` and `:670-724`.
- NAT64 is deliberately excluded from the flow cache at `userspace-dp/src/afxdp/flow_cache.rs:321-329`, so ordinary replies necessarily return to the generic request path.
- All three production `PendingForwardRequest` literals set `nat64_reverse: None`:

  - Normal live forwarding: `userspace-dp/src/afxdp/forward_request.rs:288-302`.
  - Embedded-ICMP prebuilt forwarding: `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2537-2557`.
  - Generated time-exceeded forwarding: `userspace-dp/src/afxdp/icmp.rs:257-281`.

  No assignment to `request.nat64_reverse` exists afterward.
- Dispatch sees `decision.nat.nat64` at `userspace-dp/src/afxdp/tx/dispatch/mod.rs:674-678`; its only production calls to `build_nat64_forwarded_frame` pass `request.nat64_reverse.as_ref()` at `:772-779` and `:1100-1107`. The AF_INET branch immediately requires that value at `userspace-dp/src/afxdp/frame/mod.rs:289-292`, so it returns `None`.
- Build failure enables slow-path fallback at `userspace-dp/src/afxdp/tx/dispatch/mod.rs:880-882` and `:1201-1203`. That is not a hidden NAT64 translator: it calls `extract_l3_packet_with_nat` at `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:199-211`, which chooses same-family `apply_nat_ipv4` for AF_INET at `:379-398`. `apply_nat_ipv4` discards IPv6 rewrite addresses at `userspace-dp/src/afxdp/frame/mod.rs:896-905` while still rewriting TCP/UDP ports at `:961-968`; the resulting still-IPv4 bytes are written unchanged to the TUN at `userspace-dp/src/slowpath.rs:433-446` and `:461-467`.

Inferred from those verified transitions: absent an external, unrepresented kernel NAT64 facility, the client cannot receive the intended IPv6 reply; the Rust production path emits no IPv6 packet.

A small repair is viable:

- For an ordinary reverse session, `Nat64ReverseInfo` is redundant in the pending request. `NatDecision::reverse` sets `rewrite_src = original_dst`, `rewrite_dst = original_src`, and preserves `nat64` at `userspace-dp/src/nat/mod.rs:106-120`.
- The local reverse call passes the original IPv6 flow endpoints at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:3216-3223`; the lazy/synced path passes the original forward key endpoints at `userspace-dp/src/afxdp/shared_ops.rs:725-733`.
- Those are exactly the addresses the frame builder currently obtains as `info.orig_dst_v6` and `info.orig_src_v6` at `userspace-dp/src/afxdp/frame/mod.rs:310-318`.

Therefore a small AF_INET builder repair can derive `src_v6`/`dst_v6` from `decision.nat.rewrite_src`/`rewrite_dst`, eliminating the ordinary-reply dependency on `request.nat64_reverse`. This does not by itself repair the scoped embedded-ICMP path, whose request uses `NatDecision::default()`.

Additional hostile-path result:

- Oversized TCP is not a working bypass. Segmentation runs before the NAT64 builder at `userspace-dp/src/afxdp/tx/dispatch/mod.rs:541-591`, and its admission predicate has no NAT64 exclusion at `:1458-1502`. The segment builder chooses EtherType/family from ingress metadata and applies same-family IPv4 NAT at `userspace-dp/src/afxdp/frame/tcp_segmentation.rs:145-148` and `:195-217`. Consequently an oversized reverse NAT64 TCP reply can be transmitted as IPv4 rather than translated to IPv6. UDP always reaches the failing NAT64 builder.

Plan corrections:

- The plan’s “may be broadly unreachable / not exhaustively proven” qualification at `docs/research/5177-nat64-embedded-port/plan.md:123-128` can be upgraded: normal TCP/UDP reverse translation is exhaustively broken at the request-carriage boundary.
- The constructor citations at `docs/research/5177-nat64-embedded-port/plan.md:117-121` and `:305` are materially mislabeled. `poll_descriptor/mod.rs:2380`, `:5701`, `:5865`, `worker/loop_body/mod.rs:1483`, and `forwarding/mod.rs:804` are `SessionMetadata` fields, several in test-only helpers—not `PendingForwardRequest` constructors. The actual production constructors are the three listed above.
- The plan overstates the prerequisite’s size at `docs/research/5177-nat64-embedded-port/plan.md:209-212` and `:284-286`: current behavior is broken, but the ordinary-reply carriage issue has a small decision-derived repair.
- Reverse fragment association is not an alternate path: the production install stores `reverse: None` at `userspace-dp/src/afxdp/poll_descriptor/mod.rs:90-95`, and the only consult rejects AF_INET and discards `_reverse` at `:98-122`.
- `reverse_deterministic_v6` exists at `userspace-dp/src/nat/allocator.rs:372-387`, but call-site enumeration found only tests, not a production reverse translator.

Searches performed: all `PendingForwardRequest {` literals; every `nat64_reverse` occurrence and assignment; all callers of `build_nat64_forwarded_frame`, `build_nat64_v4_to_v6_frame`, `translate_v4_to_v6`, and `write_v4_to_v6_into`; all `frag_assoc` installs/lookups; `reverse_deterministic_v6` cross-references; and the complete userspace-XDP source for NAT64/session handling.
