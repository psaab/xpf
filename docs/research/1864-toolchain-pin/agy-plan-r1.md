# AGY adversarial plan review — #1864 r1

Job: adversarial-review-mq9axojw-2uci47 (Gemini / Antigravity)
Result: /home/ps/.claude/plugins/data/gemini-abiswas97-gemini/state/jobs/adversarial-review-mq9axojw-2uci47.result.md

## Verdict: PLAN-NEEDS-REVISION

Numbered findings (verbatim summary):

1. **Semantic Equivalence Verified (Option B)** — both rewrites in
   optionB.diff are equivalent across all input domains. Long-term
   risk: future LLVM passes might canonicalize the ternary back into
   the verifier-killing pattern → reinforces the need for the gates.
2. **Live Node Memory & Locked Page Hazard** — anonymous `dnat_table`
   (10M-entry hash) allocates the bucket array (~128 MB+) even when
   empty; `userspace_sessions` (262144, preallocated) also allocates
   upfront. On memory-constrained nodes the C2 verify-load could
   ENOMEM/OOM. Mitigation: mutate the CollectionSpec in-memory before
   the verify-only load to shrink MaxEntries of large hash maps to 1
   (verifier safety analysis does not depend on hash max_entries).
3. **CPU Starvation on Live Nodes** — a REJECT walk is ~17 s of 100%
   CPU; run the pre-flight under `nice -n 19` (and optionally taskset
   away from dataplane cores).
4. **Unsound toolchain & linker pin design** —
   a. omit of `rust-toolchain.toml` hurts IDE/rust-analyzer and manual
      cargo invocations (nightly features); add one in `userspace-xdp/`.
   b. `userspace-xdp/.cargo/config.toml:5` hardcodes
      `/home/ps/.cargo/bin/bpf-linker` (non-portable) — change to
      `linker = "bpf-linker"`. **Confirmed real by inspection.**
5. **Unprivileged Git-Commit Escape Path** — C1 soft-fail still lets a
   bad `.o` overwrite the tracked file. Mitigation: build/verify at a
   temp path; only install over the tracked artifact on PASS; on
   unverified builds leave the tracked file untouched and exit nonzero.
6. **PR Splitting Recommendation** — merge gates first, prove them on
   known-good/known-bad objects, then bump the artifact in a second PR.
