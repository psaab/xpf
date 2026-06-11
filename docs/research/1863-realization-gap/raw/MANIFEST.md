# raw/ cell manifest (incident labels per plan §8; Codex r1 F6)

| Cell | Role | Build | Snap node (RG0 primary) | Label |
|------|------|-------|--------------------------|-------|
| base-r1-022731 | baseline re-anchor | gaff208a18 (==master tree) | fw1 | clean (warm-up rep; low sum) |
| base-r2-022807 | baseline re-anchor | gaff208a18 | fw1 | clean, DECISIVE |
| agg9-r1-022855 / agg9-r2-022931 | aggressor sweep | gaff208a18 | fw1 | clean, DECISIVE (kill-exit leg 2) |
| agg12-r1-023008 / agg12-r2-023044 | aggressor sweep | gaff208a18 | fw1 | clean |
| base-r3-033430 | post-redeploy baseline | g7b076ee2e | fw0 | clean, DECISIVE (cell-P control) |
| p6g-r1-033531 | cell P (6g buffer-size 4m VERIFIED applied) | g7b076ee2e | fw0 | clean, DECISIVE |
| p6g-r2-033607 | cell P rep 2 | g7b076ee2e | fw0 | TAINTED-corroborating: foreign SIGTERM restart of fw0 xpfd at 03:36:30 PDT mid-cell |
| p6g-r3-034534 | intended cell P rep 3 | g7b076ee2e | fw1 | MISLABELED-BASELINE: the buffer-size set never committed (foreign manual RG0 failover ~03:44 PDT hit the config-edit window) — counts as an extra clean baseline rep |
| s24-r1-033854 / s24-r2-033930 | stream-count perturbation | g7b076ee2e | fw0 (NON-primary after 03:40 — counters not authoritative; iperf numbers valid) | CONFOUNDED: 6g buffer-size still applied (failed revert), snap node secondary |
| s24-r3-034134 | stream-count clean rep | g7b076ee2e | fw1 | clean |
| unshaped-r1-034219 / unshaped-r2-034255 | C_phys(mix) bound | g7b076ee2e | fw1 (CoS deleted — no CoS counters by design) | clean, DECISIVE (kill-exit leg 3) |
| sanity-r1-034349 | post-restore sanity | g7b076ee2e | fw1 | clean (ran amid foreign failover ops; values in-band) |
| udp3g-r1-035126 / udp3g-r2-035202 | inelastic discriminator | g7b076ee2e | fw1 | clean, DECISIVE (§2.7) |
