# Hostile plan reviewer B (independent Claude) — r1 — #2117

VERDICT: **PLAN-KILL CORRECT**

The port-22-only "no RST" behavior is fully and solely explained by the test
config's input firewall filter, not by any defect in the #2089 reject path.
Tried to resurrect every alternative bug hypothesis; all failed.

Findings (each from a personally-opened file):

1. Input filter IS on the untrust ingress. `test/incus/xpf-test.conf:20-27`.
2. `block-ssh` discards TCP/22 and 22 is the ONLY discarded TCP port.
   `xpf-test.conf:404-413`; 8080 only in DNAT (341/348).
3. `discard` is silent by design. `userspace-dp/src/filter/mod.rs:31-41`.
4. Input filter runs BEFORE the policy and short-circuits.
   `poll_descriptor/mod.rs:659-677`; reject site at L1758-1768.
5. The discard derivation for TCP/22 is real. `filter.rs:103-114` →
   `engine/eval.rs:450-480` → `evaluate_filter_ref_counted_v4` (`eval.rs:107-123`)
   → first matching term → `matching.rs:54` `dest_ports.matches(22)`.
6. Hypothesis "screen/SYN-cookie swallows :22" — REFUTED. `poll_stages.rs:
   240-327`; SynCookieChallenge emits a SYN-ACK (`mod.rs:214-226`), not silence;
   `check_land` requires src==dst (`screen/stateless.rs:19`).
7. Hypothesis "build_reject_rst_frame returns None for :22" — REFUTED.
   `frame/tcp.rs:352-373` + `tcp_segment_consumed_len:380-428` never read the
   dst port; test `reject_tcp_with_egress_enqueues_rst` uses dst_port 22 and
   asserts the RST IS enqueued (`reject_reply.rs:89,168-205`).
8. Hypothesis "TX budget / RST-storm guard hits :22" — REFUTED.
   `reject_reply.rs:33-49` budget gate + storm guard (`tcp.rs:355`) are
   port-agnostic; a SYN is never an inbound RST.
9. No port-22/SSH special-casing (only `"ssh" => "22"` normalizers
   `policy.rs:1169`, `filter/compiler.rs:447`).
10. MissingNeighbor / session-hit paths don't change the result; Go control
    plane wires the filter per-unit (`pkg/dataplane/userspace/interfaces.go:245`
    `FilterInputV4`), confirming the bind to ge-0/0/1.

Summary: every alternative bug hypothesis fails against source; the only
port-22-specific element in the entire config is the `block-ssh` term that
silently discards TCP/22 before the policy runs. The kill is correct; #2089's
reject path works; the port-22 RST is absent by design, not by bug.
