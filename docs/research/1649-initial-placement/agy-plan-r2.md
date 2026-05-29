# AGY adversarial plan-review — #1649 r2 (confirmation)

Job: adversarial-review-mpqeu1la-c6tr50 (succeeded).

## Verdict: PLAN-READY (kill correct, rationale sound)

## §7.0 multinomial argument — confirmed airtight

AGY ran a 200k-trial Monte-Carlo on the workspace for N=6, M=6 across four
mapping strategies under randomized ephemeral ports:

| Mapping | Mean CoV (ddof=0) | P(perfect spread) | vs RSS floor |
|---------|-------------------|-------------------|--------------|
| Default RSS uniform | 0.8752 | 1.52% | baseline floor |
| Residue, 6/7 → RSS | 0.8736 | 1.55% | identical (no improvement) |
| Residue, 6/7 → Q0 | 0.9980 | 0.79% | worse |
| Residue, explicit 0..5,0,1 | 0.9268 | 1.07% | worse |

No static 1-field hash beats the 1.54% perfect-spread floor for uncontrolled
random ephemeral ports; the non-power-of-2 queue count (M=6) only degrades it.

## Controlled-harness exception — confirmed and correctly scoped

Sequential client ports (e.g. `iperf3 --cport` stepped) give distinct residues
mod 8: CoV ≈ 0.54, P(perfect spread) ≈ 20.11%. This is the only regime that
beats the floor, and the plan correctly classifies it as a controlled-harness
artifact, not production traffic (production clients randomize ports;
multi-client environments are uncoordinated). No code/controller required — an
operator running such a harness can configure residue rules with raw `ethtool`.

## No hole

r2 resolves the round-1 divergence: acknowledges the non-reactive mechanism
(§6), grounds the kill on the multinomial floor (§7.0), demotes the rule cost,
captures the floor curve in the §9 deliverable. Recommend PLAN-KILL.
