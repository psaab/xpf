# #1880 plan review — Claude SMR, round 2 (HOSTILE)

Verdict on r2: PLAN-NEEDS-REVISION — I CONCUR with Codex r2 H1 and flag
that I missed it in my own r1 pass (I wrote "exactly status-quo parity"
for the degraded fallback without noticing the status quo's convergence
depends on the very FRR murder+restart Path A deletes). That is the
SMR-soft-pass pattern; logged.

Independent verification of the two r2 findings:
- H1 (bounded convergence): confirmed real. With Path A, vtysh -f
  fallback persistence is indefinite on an idle config — no restart, no
  next-commit guarantee. r3's single-flight primary-only retry
  (15s/30s/60s/5min, frr.conf as SSOT, reloadMu serialization,
  ErrNotFound straight to slow cadence, Prometheus gauge) bounds it and
  cannot regress a newer apply since the retry reloads the current file.
- M (process group): confirmed real — frr-reload.py shells out to vtysh
  repeatedly; Go kills only the direct child by default. r3's
  Setpgid + kill(-pgid) + fallback-after-Wait() closes it.
- Cleanup one-shot path: r3's bounded-convergence argument (deploy
  starts the new daemon seconds later; first ApplyFull full-diffs) is
  sound for the deploy flow; a manually-invoked `xpfd cleanup` with no
  subsequent daemon start leaves FRR running stale config with a loud
  log — acceptable and documented (the operator asked for teardown of a
  node being decommissioned or redeployed).

Verdict on r3 (as edited): PLAN-READY. Remaining items are
implementation-phase, covered by §7 gates.
