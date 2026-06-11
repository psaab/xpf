# Claude SMR hostile plan review — #1864 r1

Reviewer stance: adversarial domain SMR (BPF verifier, rustc/LLVM
codegen, build hardening, HA deploy safety). I tried to kill the plan
on the five §11 axes plus the gates.

## Findings

### F1 (Should-fix) — C1 ordering: verify BEFORE install, not after

Plan §4 C1: the gate "runs it after `install`" and on rejection "the
script restores the previous `.o`". Restore-after-clobber is a
needless failure mode (interrupted script, concurrent `go generate`,
restore step itself failing leaves the bad artifact in place — the
exact incident vector). The script must verify the candidate at the
cargo output path (`target/bpfel-unknown-none/release/libxpf_userspace_xdp.so`)
or a temp copy, and only `install` on PASS. The tracked `.o` is then
never transiently bad. Revision: reword C1 to verify-then-install.

### F2 (Should-fix) — bpf-linker pin needs an exact-match contract

`bpf-linker --version` → `bpf-linker 0.10.2` is the check, but the
plan should state the failure semantics: missing binary OR version
mismatch are both hard fails (today's script only checks existence,
build-userspace-xdp.sh:17-20). The linker embeds its own LLVM and is
an equal codegen input — half the toolchain identity. Plan §4 A
gestures at this; make it explicit in the revision.

### F3 (Verified, no action) — Option B equivalence re-derivation

- lib.rs:467: guard `now_ns < *last_heartbeat` short-circuits the
  underflow case; on the evaluated path `now_ns >= *last_heartbeat` ⇒
  `wrapping_sub == saturating_sub == exact`. Additionally robust: even
  if the guard were removed, a wrapped value is ≥ 2^63-ish and still
  `> timeout_ns` (max plausible timeout_ns = u32::MAX ms · 1e6 < 2^53).
  Equivalent for all inputs.
- lib.rs:484: `data_end > data ? data_end - data : 0` vs
  `saturating_sub`: case-equal on `>`, `==` (both 0), `<` (both 0).
  Equivalent for all inputs. Both operands are `usize` scalars, no
  pointer-provenance concern at the Rust level (already raw usizes).

### F4 (Verified, no action) — C2 cannot disturb the live collection

`loadRustUserspaceXDP()` returns a spec with no pinning (aya legacy
`maps` section carries no pinning attribute; pinning is applied
explicitly by `loadUserspaceShimObjectsOnce()` at
loader_userspace_shim.go:89-93 — which verify-dataplane must NOT
call). A bare `ebpf.NewCollection(spec)` creates anonymous maps +
loads the prog; nothing references `/sys/fs/bpf/xpf`; process exit
frees everything. Empirically exercised by tools-shimverify on this
host. The 10M-entry maps are BPF_F_NO_PREALLOC (empty = trivial).
Requirement carried to Phase 2: verify-dataplane must use a verify-only
path (plain NewCollection), never the production pinning path.

### F5 (Considered, rejected as kill) — same-PR `.o` regeneration

This is R2 and it is the incident operation. But shipping guards-only
first means master's tracked object still carries the un-fixed source
and the next regeneration (with the un-pinned flow on some box) is
still live ammunition until a second PR lands. The C1 PASS + parent
guarded-deploy smoke gate (§6) is exactly the protection the artifact
bump needs. Single PR is acceptable; split is not safer, just slower.

### F6 (Note) — gates' "wrong toolchain arm" is awkward but honest

Proving the refusal arm requires either an uninstalled pinned
toolchain (simulate via `RUSTUP_HOME` redirect or a bogus
`RUST_BPF_TOOLCHAIN`) — fine; or reverting B to re-trigger the 1M
blowup with the floating nightly — the preserved bad object plus the
verify-dataplane REJECT demo covers the same proof more cheaply. Both
arms remain provable; no change needed beyond F1's ordering.

### F7 (Note) — pin point: script env-default is correct

`rust-toolchain.toml` in the crate dir would silently govern any
`cargo` invocation in `userspace-dp`-style workflows and is overridden
by the script's explicit `+toolchain` anyway; the env-default keeps
exactly one authority (the build script) and one documented override
(`RUST_BPF_TOOLCHAIN`). Agree with §5.

## Verdict

**PLAN-READY (with F1 + F2 wording revisions — no architectural
change).** The root cause is proven, not hypothesized; both fix layers
were empirically validated in this worktree (bisect table §2, Option B
PASS on the failing nightly); the guard design fails builds/deploys
instead of dataplanes and respects lenient-boot. Recommend Path D.
