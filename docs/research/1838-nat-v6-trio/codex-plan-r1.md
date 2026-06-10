# Codex adversarial plan review — round 1

Task: codex-companion adversarial-review (flock'd, --wait), branch diff vs origin/master.
Verdict: needs-attention → PLAN-NEEDS-REVISION.

Findings (verbatim summary):

- [high] #1838 scope misses ICMPv6 embedded NAT reversal fixed-40 rewrites.
  icmp_embed/mod.rs:124-150 dispatches matching ext-aware (meta.l4_offset;
  XDP parser walks ext chains: userspace-xdp/src/lib.rs:1158-1208);
  poll_descriptor/mod.rs:867-919 builds NAT-reversed errors;
  icmp_embed/builders.rs:170-178 hardcodes icmp_offset=40 and
  emb_l4_offset=emb_ip_offset+40; icmp_embed/parse.rs:93-100 reads embedded
  proto at +6 and l4 at +40. Outer-ext errors are matched at the real offset
  then rewritten/checksummed at 40 — same valid ext-header corruption class.
  Recommendation: pull into #1838 scope, reuse an ext-aware walker for both
  outer and embedded headers, deterministic tests for both layers.

- [medium] #1840 matrix ignores same-port NAT residual divergence.
  apply_nat_port_rewrite adjusts only under old != new (frame/mod.rs:867-882);
  descriptor applies any nonzero delta (rewrite/ipv6.rs:66-81; same-port
  delta is 0xFFFF, pinned at prop_tests/rewrite.rs:500-526). Malformed v6
  UDP stored-0 × same-port NAT remains generic 0x0000 vs descriptor 0xFFFF
  after the planned family gate. Recommendation: specify a no-op port-NAT
  parity rule + deterministic test.

Open-question answers: Q1 keep meta-led precedence (no bad producer found);
Q2 include recompute rider if recompute touched; Q3 delete dead trio;
Q4 file fragment NAT separately with a pin; Q5 fold segmentation fix,
arithmetic right; Q6 adjust-for-parity defensible subject to same-port
caveat; Q7 empty mask plausible for valid domain once same-port resolved.
