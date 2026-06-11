# Claude SMR hostile plan review — #1864 r2

Re-review of plan r2 after folding Codex r1 (8) + AGY r1 (6) + SMR r1
(F1/F2). I hunted for NEW holes introduced by the revisions.

## Findings

### F1 (Should-fix, folded into r2 directly) — validate-before-shrink ordering

The r2 C2 text combined two requirements that conflict if naively
implemented: `validateUserspaceShimSpec` requires
`dnat_table.MaxEntries == userspaceShimMaxSessions` (10M,
loader_userspace_shim.go:151), while the AGY F2 mitigation shrinks
that same map to MaxEntries=1. Implemented in the wrong order, the
pre-flight would fail every PASS object with a drift error. Fixed in
the plan: validate the unmodified spec first, shrink after, load last.

### F2 (Note, folded) — C1 kernel-scope caveat made explicit

C1 verifies on the build box's kernel; the cluster runs a different
(newer) verifier. A local PASS is necessary, not sufficient — C2 on
the target node is the authoritative gate. The plan now states this
so nobody later "optimizes away" C2 as redundant with C1.

### F3 (Checked, holds) — MaxEntries=1 hash shrink is verifier-neutral

For BPF_MAP_TYPE_HASH, program safety analysis consumes key_size /
value_size (value-pointer bounds after `bpf_map_lookup_elem`) — not
max_entries. max_entries only sizes the runtime bucket array /
prealloc pool. Array maps are excluded from the shrink (their direct
value indexing semantics are entangled with map geometry); the two
big offenders (`dnat_table` 10M no-prealloc, `USERSPACE_SESSIONS`
262144 preallocated, lib.rs:332-336) are both hash maps.

### F4 (Checked, holds) — override env is not a new escape

`XPF_SHIM_ALLOW_UNPINNED_INSTALL=1` only bypasses the *pin* refusal;
the C1 verifier gate still applies to the install unconditionally. An
unpinned-but-verified object can be installed only deliberately, with
provenance printed; an unverified object can never be installed. The
two gates are independent, which is the correct lattice.

### F5 (Checked, holds) — bash parse of rust-toolchain.toml

Single-key extraction (`channel = "..."`) from a file this repo
controls; same risk class as the existing MAX_INTERFACES awk parse of
xpf_common.h (build-userspace-xdp.sh:28-33) with the same fail-loud
empty-check requirement. Phase 2 must include the empty-parse guard.

## Verdict

**PLAN-READY.** Root cause empirically proven (bisect + load-repro),
both fix layers validated by real BPF_PROG_LOAD, guards fail closed at
build and deploy, lenient-boot preserved, all r1 findings from three
reviewers closed with quoted revisions. Recommend Path D, single PR,
gates-first commit order.
