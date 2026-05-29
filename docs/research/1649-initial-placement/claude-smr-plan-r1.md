# Claude SMR hostile plan-review — #1649 r1

Reviewing as an RSS / NIC-flow-steering / AF_XDP / Linux-kernel-networking
domain expert. Hostile pass, not synthesizer-by-default.

## Verdict: PLAN-NEEDS-WORK (the KILL is correct, but §6 is factually wrong and must be rewritten)

The plan reaches the right verdict (PLAN-KILL) for the right top-level reason,
but §6 ("Mechanism") contains a **false claim** that I confirmed false on the
hardware, and the kill rationale must be re-grounded on the mechanism that
actually exists rather than on a claim that no non-re-steer mechanism exists.

## Finding 1 (BLOCKING) — §6 is factually wrong; a non-reactive mechanism DOES exist

Plan §6 line 198-205 says the only non-re-steer ntuple use is dst-port/subnet
pre-partition, and that the same-dst-port iperf symptom "cannot pre-partition
without knowing src-port," concluding "No viable per-flow non-re-steer
mechanism exists." **This is false.** Masked **source-port-residue** ntuple
rules pre-partition the *future* src-port space without knowing the exact
ephemeral port. Confirmed on `loss:xpf-userspace-fw0` ge-0-0-2 (mlx5):

```
ethtool -N ge-0-0-2 flow-type tcp4 src-port 0 m 0xfff8 dst-port 5210 m 0x0000 action 0
  Added rule with ID 1023
  ... src-port {0..5} m 0xfff8 -> queue {0..5}  (6 rules, all accepted)
  Filter shows: Src port: 0 mask: 0xfff8  -> matches port & 0x0007 == 0
```

These six rules are installed ONCE at boot, before any SYN, and steer every
future flow by `src_port mod 8`. An established flow's src-port is fixed for
its lifetime, so its queue never changes — **this is genuinely not a re-steer**
and not reactive. Codex's round-1 counter-example is correct; §6 must be
rewritten to acknowledge this mechanism rather than deny its existence.

## Finding 2 (the actual kill, must become the spine of §7/§8) — residue steering does NOT beat the floor for uncontrolled src-ports

The reason to KILL is NOT "no mechanism exists" (§6 was wrong) — it is that the
residue mechanism **relocates the multinomial draw, it does not flatten it**,
for any workload that does not control its own src-ports.

`src_port mod 8` for N=6 flows with client-assigned ephemeral ports is a draw of
6 items into 8 residue classes (only 6 of which map to queues; residues 6,7 fall
through to default RSS). Monte-Carlo (200k trials):

```
P(6 flows all distinct residues, B=8) = 0.077   (7.7%)
Mean bucket-count CoV (port mod 8, 6 flows)     = 1.05
Mean bucket-count CoV (RSS uniform into 6)      = 0.87   <-- residue is WORSE
```

Residue steering is just a *different, worse hash* than the NIC's Toeplitz
(1 field vs 4-field Toeplitz; 8 classes for 6 queues wastes 2 classes). It beats
the floor ONLY when the *generator deliberately assigns distinct residues* via
`iperf3 --cport` — which is the Phase-0 3.8% result, a **controlled-harness
artifact**, not a production traffic fix. iperf3 defaults to ephemeral ports;
production clients always use ephemeral ports. So for the realistic flow mix the
mechanism cannot beat the floor, and can make it worse.

This is the airtight kill that survives Codex's counter-example: the mechanism
*exists* (Codex right) but *cannot beat the floor for realistic traffic* (the
multinomial math). AGY's round-1 independent computation reaches the same
1.54%-perfect-spread conclusion for the static-hash case.

## Finding 3 (verified, keep) — §5 reactive-is-a-re-steer holds for the per-5-tuple controller

The §5 argument is airtight against the *reactive exact-5-tuple* controller
(#1203's form): the SYN is RSS-placed before any exact rule can exist, so a
correction moves an established flow. I cross-checked the alternatives:
- aRFS is reactive by construction (programs the rule after recvmsg sees the
  flow) → moves an established flow → re-steer; fatal under AF_XDP queue-bound.
- RSS-context (`ethtool -X context`) dynamic-weight reshape re-hashes ALL active
  flows in the context (Toeplitz is static) → bulk re-steer.
- tc-flower wildcard action can only steer to a single queue/context, not assign
  distinct queues per flow without matching the exact ephemeral 5-tuple.
None falsify §5. But §5 only covers the *reactive* family; it does NOT cover the
*static residue* mechanism, which is why Finding 1/2 are needed.

## Finding 4 (verified) — empirical claims hold

- 1024-rule cap: confirmed by exhaustion probe ("Total 1024 rules", FAIL at
  insert 1004 after 21 pre-existing). AGY corroborates this is
  `MLX5E_ETHTOOL_FLOW_SPEC_NUM = 1024` in the driver, distinct from the raw
  steering-table capacity #1203 assumed.
- ~1.1ms/rule: weak as stated (subtracts an incus-exec fork baseline). It should
  NOT carry the kill (the kill is Finding 2). Reframe as "additionally, per-rule
  firmware cost is firmware-synchronous-command-bound (~1ms class) → fatal at
  real conn rates" as a *secondary* nail, not the load-bearing one.
- RX-queue-N ⇒ worker-N: confirmed (`lib.rs:371` rx_queue_index → binding.slot →
  XSK redirect; `lib.rs:1322` queue-bound physics). Tighten wording to
  "queue-bound deterministic binding" per Codex (HA slot layout could differ).

## Finding 5 — salvage check: no production-worthy opt-in

Operator hand-pinned exact-5-tuple rules = #1203 retread (reactive, can't know
ephemeral port, re-steer). A static residue/RSS-context "even-flow test mode"
is real but only helps controlled generators; it is a benchmark knob, not a
fairness feature, and the operator can already do it with raw `ethtool`. Not
worth a dataplane controller. Confirm KILL.

## Required revisions before convergence

1. **Rewrite §6**: acknowledge masked src-port-residue (and RSS-context) as a
   real non-reactive mechanism. Show the residue rules work on the NIC.
2. **Rewrite §7/§8 spine**: the kill is "residue steering relocates but does not
   flatten the multinomial for uncontrolled src-ports (CoV 1.05 > RSS 0.87);
   beats floor only for generator-controlled ports = harness artifact." Demote
   the ~1.1ms cost to a secondary nail.
3. **§10 table**: add the masked-port-residue row explicitly (currently absent),
   verdict "non-reactive + valid, but worse-than-RSS for uncontrolled ports."
4. **§9 floor-curve deliverable**: add a note that residue/static-hash steering
   is on the same multinomial floor (or worse), so the doc pre-empts the
   "but couldn't we just steer by port?" question.

With these the three reviewers converge on KILL. The verdict does not change;
the rationale must.
