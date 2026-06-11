# AGY adversarial plan review — #1864 r2

Job: adversarial-review-mq9bmafk-47842g (Gemini / Antigravity)

## Verdict: PLAN-NEEDS-REVISION (minor — all r1 findings closed, single-PR approved)

### Part 1 — r1 findings: ALL 6 CONFIRMED CLOSED (quoted r2 text per finding).

### Part 2 — F6 re-judged: single PR APPROVED under fail-closed C1
("the C1 gate will fail-closed when compiling the bad source code,
proving the gate works ... prevents any intermediate state where the
Go binary embeds a mismatching or broken `.o`").

### Part 3 — new findings (r2):

7. **`nice -n 19` insufficiency on AF_XDP worker cores** — CFS still
   grants minimum-granularity timeslices (0.75-6 ms); at line rate
   that overflows NIC RX rings. Mitigation: `taskset` the verify walk
   onto housekeeping cores (away from workers).
8. **Fragile bash parse of `rust-toolchain.toml`** — quote/comment
   variations could yield empty/garbled channel and silently fall back
   unpinned. Mitigation: tolerant extraction + strict
   `nightly-YYYY-MM-DD` format validation, fail loudly.
9. **`XPF_SHIM_ALLOW_UNPINNED_INSTALL` commit escape** — an
   unpinned-but-verified `.o`, once installed locally, is committable.
   Mitigation: merge gate runs pinned `make generate` + asserts
   `git diff --exit-code pkg/dataplane/userspace_xdp_bpfel.o`
   (bit-for-bit reproducibility — empirically confirmed in this
   research: identical md5 across rebuilds and across checkout paths).

Note: MaxEntries=1 hash shrink assessed verifier-safe by AGY
(lookup-pointer rules independent of capacity).

All three foldable; folded into plan r3.
