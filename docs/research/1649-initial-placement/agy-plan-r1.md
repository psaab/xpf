# AGY adversarial plan-review — #1649 r1

Job: adversarial-review-mpqehy8u-aywovr (succeeded).

## Verdict: PLAN-READY (the PLAN-KILL is correct)

## Summary of findings (condensed from verbatim output)

**Attack 1 — §5 reactive-is-a-re-steer airtight?** YES, airtight. No
ethtool/devlink/tc-flower/RSS-context primitive pre-commits a queue for a
wildcard accept before the ephemeral src-port is known:
- RSS contexts: within a context the NIC still Toeplitz-hashes the 5-tuple →
  same multinomial floor; dynamically re-weighting the indirection table
  re-hashes ALL active flows = bulk re-steer.
- tc-flower wildcard: action must be static (single queue/context); per-flow
  distinct-queue assignment requires matching the exact ephemeral 5-tuple =
  reactive.
- aRFS: reactive by construction (programs rule after recvmsg) = re-steer, fatal
  under AF_XDP queue-bound delivery.
- Symmetric Toeplitz: only RX/TX symmetry, not the N-into-M collision.

**Attack 2 — N≤M reachable by a non-reactive mechanism?** NO. Under any static
uniform hash, P(6 flows → 6 distinct queues) = 6!/6^6 ≈ 1.54%; 98.46% of the
time collisions produce the bimodal symptom. The 3.8% Phase-0 CoV is reachable
only by knowing the port map in advance (impossible for wildcard accepts) or by
reactive steering (a re-steer). Plan did NOT wrongly conflate with #1203's
within-queue wall — it explicitly distinguished them in §4.1.

**Attack 3 — empirical claims:** all verified.
- 1024-rule cap = driver `MLX5E_ETHTOOL_FLOW_SPEC_NUM`; #1203's "32k typical"
  applies to raw flow tables, not the ethtool ntuple interface.
- ~1.1ms/rule = synchronous firmware command round-trip (ETHTOOL_SRXCLSRLINS →
  CREATE_FLOW_TABLE_ENTRY) on ConnectX; fatal at real conn rate.
- RX-queue-N ⇒ worker-N: hardcoded queue-bound delivery; cross-queue redirect
  fails `xsk_rcv_check()` in net/xdp/xsk.c and silently strands packets.

**Attack 4 — salvageable opt-in?** NO. Hand-pinned exact-5-tuple = #1203 retread
(ephemeral-port dilemma + re-steer wall + no conntrack on target worker).
Coarse dst-port pinning can't resolve same-dst-port collisions and operators can
already do it with raw ethtool.

## Recommendation

Proceed with §9 PLAN-KILL deliverable (document the floor curve in
docs/fairness-regimes.md, cross-link issues). Closes #1649 permanently.

## Note on the residue counter-example

AGY's Attack 2 computes the static-hash unreachability (1.54% perfect spread)
which is the same multinomial argument that defeats Codex's masked-port-residue
counter-example for uncontrolled src-ports. AGY did not separately name masked
src-port-residue, but its static-hash math covers it: residue steering is a
static hash, subject to the same multinomial collision.
