# #1863 implementation raw cells

All cells: loss userspace cluster, push, 12 streams/class, 30 s TCP,
runner = docs/research/1863-realization-gap/run-cell.sh (research
branch), under /tmp/xpf-cluster.lock with in-band version checks.

| Cell | Build | Role |
|------|-------|------|
| step0-r1/r2 | g96234c7d7 (master + Step-0 instrument) | Step-0 decision cells: per-worker requested-vs-granted; applied the registered rule -> claim-sampling loss dominant -> Path A-ii |
| fix24c-r1/r2/r3 | g75f5ed727 (instrument + A-ii carry; VERSION-PRE/POST pinned in one lock hold) | decisive small4+24g before/after |
| fix9c-r1/r2 | g75f5ed727 | small4+9g work-conservation gate |
| fixalone-r1 | g75f5ed727 | small4-alone regression guard |

Excluded (not evidence): fix24-r1/r2 ran UNSHAPED (post-deploy
NO-PRIMARY window broke the CoS apply); fix24-r1b/r2b/r3b ran on a
FOREIGN build (g1cc32cdf6 — another agent deployed over this PR's
build without the cluster lock between deploy and cells; caught by
the in-band version check). Both incidents motivated the
one-lock-hold + VERSION-PRE/POST protocol of the fix24c session.
