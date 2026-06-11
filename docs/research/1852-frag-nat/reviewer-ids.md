# #1852 reviewer task IDs

Codex (GLOBALLY SERIALIZED via flock /tmp/xpf-codex.lock):

| Round | Task ID | Verdict |
|-------|---------|---------|
| r1 | task-mq8wfs3n-c5eg6a | PLAN-NEEDS-REVISION (HIGH port-write reachable; MED address-NAT, segmentation, defect-2 helper trap; LOW S5/A′) |
| r2 | task-mq8wsliq-uqsza3 | PLAN-NEEDS-REVISION (MED-HIGH SNAT alloc-leak pre-rewrite; MED defect-2 helper trap/v4 gap; LOW tunnel caller) |
| r3 | (pending) | |

AGY adversarial-review (result: /home/ps/.claude/plugins/data/gemini-abiswas97-gemini/state/jobs/<id>.result.md):

| Round | Job ID | Verdict |
|-------|--------|---------|
| r1 | adversarial-review-mq8whg97-ifovwq | PLAN-NEEDS-REVISION (shim partial-drop; pool-SNAT port-write reachable; defect-2 helper trap; "Proceed with Path A, do NOT kill") |
| r2 | adversarial-review-mq8wssym-b57kae | PLAN-NEEDS-REVISION (critical: helper change breaks GRE decap + tunnel local-origin fragment forwarding; segmentation gate placement confirmed correct) |
| r3 | (pending) | |

Claude SMR: `docs/research/1852-frag-nat/claude-smr-plan-r<N>.md`
- r1: PLAN-NEEDS-REVISION (F1 thread predicate; F2 confirm descriptor fall-back; F3 S5 no cross-fragment state; F4 free meta_flags bit; S9 own-guard nit)
- r2: PLAN-READY (PREMATURE — soft-pass, self-corrected in r3)
- r3: PLAN-READY (verifies the v3 helper-trap + SNAT-leak fixes; Q6 = user decision)
