# Claude SMR plan-review — #1928 — round 1

**Verdict: PLAN-NEEDS-MINOR** — diagnosis is well-evidenced; Path 1 is the right
lead but hinges on a Phase-0 fact (does virtio 7.0 *negotiate + deliver* ZC).

## Diagnosis — solid (calibrated against the working cluster)
Confirmed the forwarding signals against the WORKING mlx5 loss cluster:
forwarding ⇒ nonzero `Unicast-sessions` + nonzero
`xpf_userspace_binding_tx_completions_total`. virtio shows 0 on both during
v4+v6 transit while `rx_xdp_redirects` climbs (926). (`rx_packets_total` is 0
even on the working cluster — a red herring; the plan should not lean on it.)
So: shim redirects, dataplane does not forward → copy-mode XSK delivery gap.
Diagnosis stands.

## Findings
- **F1 (the crux):** Path 1 assumes virtio negotiates ZC on 7.0 and then
  delivers. The deep-research established virtio RX-ZC exists ~6.11+, but
  "negotiates when asked" ≠ "delivers end-to-end." Phase 0 MUST force a ZC bind
  and confirm `tx_completions`/sessions go nonzero before committing to Path 1.
  Keep PLAN-KILL (virtio mgmt-only) as the honest fallback.
- **F2:** the git archaeology (fabric/generic origin of virtio→AUTO) reduces the
  risk that native-virtio ZC was deliberately avoided, but a reviewer should
  confirm no virtio ZC hang/regression is referenced elsewhere.
- **F3 (nit):** the plan should drop `rx_packets_total` as evidence and cite
  sessions + tx_completions as the forwarding signal (calibrated above).
- **F4:** if Path 2 (copy-mode fill-ring) is needed, the plan must locate where
  the fill ring is (or isn't) refilled per-tick for copy bindings — currently
  hand-waved.

## Bottom line
Phase-0-decides is the right structure. Lead Path 1 (small, mirrors the
non-virtio path), fall back to Path 2, PLAN-KILL to virtio-mgmt-only if neither.
PLAN-NEEDS-MINOR: fix F3 (evidence), tighten F1 (ZC-delivers gate) and F4
(copy-mode fill-ring locus) before PLAN-READY.
