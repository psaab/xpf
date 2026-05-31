# #1693 Path C — reviewer task IDs

## Plan review round 1 (v1 @ a72ca9316)
- Codex r1: isolated foreground session `codex-1693-plan-r1-*`. Verdict
  PLAN-NEEDS-MAJOR — found the conditional shared-exact owner path
  (`cross_binding.rs:69` bail is `&& tx_owner_live.is_some()`; when
  `None`, routes via `owner_worker_id` at `:74/:126/:190`,
  `tx/drain/mod.rs:517-534`). Ratifies KILL once §3.A narrowed to
  "shared-exact with live per-worker TX binding." Confirmed 3g/6g ≥2.5G
  shared-exact; #761 leg stands; #1692 leg fair.
- AGY r1: job `adversarial-review-mptujtop-pcnmry`. Verdict
  PLAN-KILL-IS-WRONG (refuted absolute §3.A) BUT decision matrix:
  "symmetric worker bindings (loss cluster) ⇒ PLAN-KILL"; asymmetric
  ⇒ NEEDS-MAJOR. #761 leg "fatal blocker" (stands); #1692 leg fair;
  §5 experiment non-rescuing on symmetric clusters.
- Claude-SMR r1: in-conversation. Verified the conditional bail
  independently before reviewers returned; ratifies the v2 narrowing.

## Plan review round 2 (v2 — §3 narrowed to topology-conditional)
- Codex r2: (pending)
- AGY r2: (pending)
- Claude-SMR r2: (pending)
