# Codex infra-block documentation — #6751 (rounds 46-47)

Codex could not complete round 46 or 47: the weekly usage quota is
exhausted, with the stated reset at Aug 10th, 2026 6:57 AM. Two
documented attempts were made: the full round-46 review
(/tmp/codex-6751-r46.out — empty; /tmp/codex-6751-r46.log carries the
usage-limit error) and a minimal quota probe after a backoff
(/tmp/codex-6751-r46-probe.log, exit 1, same error).

Per the codex-infra-blocked exception in the standing rules
(feedback_codex_infra_must_retry): retries are documented above, and
convergence proceeds 2-of-3 (Claude SMR + AGY) — AGY alone is never
enough, but SMR + AGY together satisfy the exception. Codex completed
21 consecutive reviews (r1-r45); every one of its findings through r45
is folded and grep-verified in the final blob, and its r44/r45 reviews
explicitly verified the evidence/authority split as behaviorally sound
(sync_protocol.go:491, sync_rtflow_session_id_5212_test.go:64).
