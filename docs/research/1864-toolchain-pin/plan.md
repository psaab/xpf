# #1864 — `make generate` produces a verifier-killing userspace-xdp shim: pin the BPF toolchain + add load guards

Revision: r1 (2026-06-11)
Branch: `research/1864-toolchain-pin`
Status: DRAFT — awaiting 3-way hostile plan review (Codex + AGY + Claude SMR)

## 1. Problem

`make generate` (→ `pkg/dataplane/build-userspace-xdp.sh`) rebuilds the
git-tracked, go:embed-ed `pkg/dataplane/userspace_xdp_bpfel.o` with
`cargo +${RUST_BPF_TOOLCHAIN:-nightly}` — i.e., **whatever `nightly` is
installed on the build box** — plus the locally-installed `bpf-linker`.
On 2026-06-10 a routine `make generate` produced an object that the
kernel BPF verifier rejects with `BPF program is too large. Processed
1000001 insn`; deploying the binary embedding it put **both** loss-cluster
nodes into config-only mode (no forwarding) until the tracked object
(md5 `58405bd24c690c027842eec778227c69`) was restored and redeployed.

Three compounding landmines:

1. `make generate` is the first documented Quick Start step, so any dev
   box reproduces the bad artifact silently; the failure only surfaces
   at deploy+load time, as a dead dataplane.
2. The `.o` is git-tracked: an innocent `git add -A` lands the
   cluster-killing artifact on master.
3. Nothing anywhere — build, CI, deploy, or daemon — verifier-checks
   the object before it replaces a live, working program.

## 2. Root cause — proven by local reproduction and toolchain bisect

All experiments run in this worktree on kernel 6.18.5 with a throwaway
cilium/ebpf harness (`tools-shimverify/`, same load path as production
`loadRustUserspaceXDP` → `ebpf.NewCollection`). `userspace-xdp/` source
and `Cargo.lock` unchanged since #1432 in every build below;
`bpf-linker 0.10.2` held constant (installed 2026-03-09).

| Toolchain (rustup dated nightly) | Result | Evidence |
|---|---|---|
| tracked object (built 2026-05-31) | **PASS**, 6632 xlated insns | baseline |
| `nightly-2026-03-08` | **PASS**, 6632 insns, xdp section `0xb3d0` — codegen identical to tracked object except one 2-insn branch-polarity swap | recovered the producing-toolchain era (local `nightly` dir dated from ~March until a `rustup update` on 2026-06-06) |
| `nightly-2026-05-01`, `-05-15`, `-05-23` | **PASS**, 6632 insns | stable codegen across 11 weeks |
| `nightly-2026-05-27` | **REJECT** — `Processed 1000001 insn`, identical signature to the incident | first bad |
| current `nightly` (1.98.0-nightly 8954863c8 2026-06-05) | **REJECT** — `max_states_per_insn 31, total_states 57464`; ~17 s of kernel CPU per failed load | the incident toolchain |
| `nightly-2025-06-01` (year-old) | **REJECT** — *different* failure: `invalid access to packet, R4 offset is outside of the packet` at 75 K insns | proves "any older nightly" is NOT safe either |

**Regression window: (`nightly-2026-05-23`, `nightly-2026-05-27`]** — an
upstream rustc/LLVM codegen change, not anything in this repo.

The codegen divergence is small and localized. Hash-normalized disasm
diff between good and bad objects (+7 static insns, 56,264 → 56,320 B)
shows the new compiler lowers `u64::saturating_sub` as
`sub` + overflow-test + **materialized boolean re-branch**
(`r4 = 1; if cond …; r4 = 0; if r4 != 0 goto …`) with extra
stack-spilled scalars and tail-duplicated blocks, where the old
compiler emitted a branch-minimal compare-then-subtract. The shim has
exactly two `saturating_sub` sites, both in the per-packet hot
prologue executed before every parse path:

- `userspace-xdp/src/lib.rs:467` — heartbeat staleness:
  `now_ns < *last_heartbeat || now_ns.saturating_sub(*last_heartbeat) > timeout_ns`
- `userspace-xdp/src/lib.rs:484` — `packet_len = data_end.saturating_sub(data)`

The spilled wide-`var_off` booleans give downstream branch states
distinct ids the verifier cannot prune; with ~5,750 static insns and
the IPv6 extension-header/option parse fan-out, the state walk blows
through the 1 M processed-insn cap (constant since kernel 5.2 —
**kernel-version-independent**, which is why local 6.18.5 reproduces
the 7.0 cluster failure exactly).

Confirmed source attribution by experiment: rewriting only those two
sites (see §4 Path B) makes the **current failing nightly** produce a
**PASS** object (6620 insns), and the older nightlies still PASS.

One more operationally relevant finding: `bpftool prog load` **cannot**
be the guard — aya emits a legacy `maps` ELF section that libbpf 1.0+
refuses (`legacy map definitions in 'maps' section are not supported`).
Any guard must load through cilium/ebpf, exactly like production.

## 3. Why this can recur (threat model)

- `rustup update` is routine hygiene; the floating `nightly` default
  guarantees eventual drift. It already silently changed under us once.
- The old-nightly failure mode (pkt-offset rejection) shows the safe
  set of toolchains is an *interval*, not a half-line — only an
  empirical verifier check defines membership.
- Future shim source changes can independently regress verifier cost
  even on the pinned toolchain (the legacy BPF tree hit this repeatedly
  — see CLAUDE.md BPF-verifier gotchas). A pin alone is insufficient;
  a verifier gate alone leaves `make generate` failing with no
  actionable remediation. Both are needed.

## 4. Paths

### Path A — pin the toolchain, fail loudly on mismatch

`build-userspace-xdp.sh`:

- `TOOLCHAIN="${RUST_BPF_TOOLCHAIN:-${PINNED}}"` where
  `PINNED=nightly-2026-05-23` (latest dated nightly verified to PASS
  with **both** the current source and the Path-B-patched source —
  maximal safety margin; bump deliberately, never implicitly).
- Refuse to build if `cargo +${TOOLCHAIN}` is unavailable, printing the
  exact `rustup toolchain install ${PINNED} --component rust-src` line.
- Record/check `bpf-linker --version` against a pinned expectation
  (`0.10.2`); mismatch ⇒ hard fail with install instructions
  (`cargo install bpf-linker --version 0.10.2 --locked`). bpf-linker
  embeds its own LLVM; it is as much a codegen input as rustc.
- Explicit `RUST_BPF_TOOLCHAIN=...` override still allowed (needed for
  bisects and pin bumps) — but the Path-C gate still applies.

### Path B — fix the source so reasonable compilers emit prunable code

Two-line change, **already verified in this research** (diff preserved
at `docs/research/1864-toolchain-pin/optionB.diff`):

- lib.rs:467: `saturating_sub` → `wrapping_sub`. Semantics identical:
  the short-circuit `now_ns < *last_heartbeat` clause already handles
  the underflow case, and even if evaluated, a wrapped huge value still
  compares `> timeout_ns` → same branch. No behavior change.
- lib.rs:484: `data_end.saturating_sub(data)` →
  `if data_end > data { data_end - data } else { 0 }`. Identical
  result for all inputs.

Verified matrix (this worktree): patched source PASSes on
`nightly-2026-03-08`, `-05-23`, **and the current failing nightly**
(6620 xlated insns). Cheap, real, and removes the single known
explosion trigger — but it cannot guarantee future toolchains stay
safe, so it does not replace A or C.

### Path C — verifier load guards (fail the build/deploy, never the dataplane)

- **C1 — build-time gate.** Productionize the research harness as a
  small Go command (`cmd/shimverify` or `tools/`-scoped) that loads the
  freshly-built object via `ebpf.NewCollection` (anonymous maps, no
  pinning, no attach) and exits nonzero with the verifier log tail on
  rejection. `build-userspace-xdp.sh` runs it after `install`:
  - with CAP_BPF/root available: gate is mandatory — rejection fails
    `make generate` loudly *before* the bad object can be committed,
    and the script restores the previous `.o` (or instructs
    `git checkout -- pkg/dataplane/userspace_xdp_bpfel.o`).
  - without privileges: print an UNMISSABLE warning that the object is
    UNVERIFIED plus the exact sudo command to verify. (Static insn
    counting is **not** a substitute — good and bad objects differ by
    7 static insns; only a real BPF_PROG_LOAD walk is honest.)
- **C2 — deploy-time pre-flight.** New `xpfd verify-dataplane`
  subcommand (pattern already exists: `version`, `cleanup` in
  `cmd/xpfd/main.go`): loads the **embedded** collection anonymously,
  prints PASS/REJECT + verifier tail, exits 0/nonzero. Verify-only
  load touches no pins and detaches nothing — an existing good loaded
  program keeps forwarding (lenient-boot doctrine intact; anonymous
  maps are freed on process exit). `deploy_vm()` in
  `test/incus/cluster-setup.sh` pushes the new binary to a temp path
  and runs `verify-dataplane` on the node **before** `systemctl stop
  xpfd`; failure aborts that node's deploy with the old daemon still
  running. This converts "cluster down" into "deploy refused".
- **C3 (cheap, optional) — root-gated Go test** in `pkg/dataplane`
  that loads the embedded object and skips without privileges, so any
  privileged CI/dev `make test` also catches a bad tracked artifact.

### Path D — recommended: B + A + C1 + C2 (+C3 if trivial) + docs

The issue title asks for pin + guard; B is verified-cheap and removes
the known trigger, so ship all three layers:

1. B makes current and pinned toolchains both produce passing objects.
2. A makes the build reproducible and refuses silent drift.
3. C makes any residual escape (future toolchain bump, future source
   regression, stale local bpf-linker) fail the build or the deploy
   instead of the dataplane.

## 5. Non-goals / out of scope

- No change to the runtime daemon load path semantics: config-only
  fallback on load failure stays (it is correct lenient-boot behavior
  for a node that is already mid-restart; the guard's job is to stop
  bad artifacts *before* that point).
- No CI infrastructure build-out beyond the root-gated test (the
  project has no privileged CI runner today; C1/C2 are where the
  enforcement lives).
- No attempt to upstream the rustc/LLVM regression report (worth doing
  separately; the window (05-23, 05-27] and the saturating-sub
  lowering diff are captured here for that purpose).
- No `rust-toolchain.toml` in `userspace-xdp/` — the build script's
  explicit `+${TOOLCHAIN}` overrides it anyway, and a toolchain file
  would also capture unrelated `cargo` invocations in that directory.
  (Reviewers: disagree if you think the file is the better pin point.)

## 6. Gates (Phase 2, all unmasked)

- `go build ./... && go vet ./... && make test` — full, no skips.
- `make generate` both arms proven in the PR:
  - correct toolchain (pinned, auto-checked): produces an object that
    passes C1 verification; record md5 + xlated insn count in the PR.
  - wrong toolchain (e.g. `RUST_BPF_TOOLCHAIN=nightly` with the
    current bad nightly **and Path B reverted locally** — or simulated
    missing toolchain): clean, actionable refusal; no bad `.o` left
    behind in the worktree.
- `xpfd verify-dataplane` demonstrated on both a PASS object and a
  REJECT object (the bad object from this research is preserved for
  the test).
- New tracked `.o` (regenerated with B + pinned toolchain) must PASS
  C1 locally AND be smoke-validated by the parent on the loss cluster
  (one guarded `make generate` + deploy cycle under the cluster lock)
  before merge. cargo gates (`fmt --check`, `clippy`, `test`) for the
  `userspace-xdp` crate since Rust source is touched.
- Performance: B touches the per-packet prologue. The rewritten
  expressions are branch-equivalent or cheaper (6620 vs 6632 xlated
  insns); parent smoke (line-rate iperf3 v4/v6) is the gate — any
  regression fails the PR.

## 7. Risks

- **R1: pinned nightly disappears from rustup mirrors.** Dated nightly
  components occasionally get GC'd upstream. Mitigation: the pin is
  one variable; bump procedure documented (build + C1 verify + commit
  new `.o` + record versions). C1 makes any bump safe.
- **R2: regenerating the tracked `.o` in the same PR.** The new object
  (B-patched source, pinned toolchain) replaces md5 `58405bd2…`. This
  is exactly the operation that caused the incident — mitigated by C1
  PASS locally + the parent's guarded deploy smoke before merge.
- **R3: C2 verify-load on a live node races the running program.**
  Verify-only load creates anonymous maps (incl. a 10 M-entry
  no-prealloc hash — same as production spec, trivial memory when
  empty) and never pins/attaches; the running collection is untouched.
  A REJECT walk costs ~17 s of one CPU on the node — acceptable for a
  deploy-time, once-per-push check.
- **R4: B is semantics-sensitive code review surface.** Both rewrites
  are proven-identical by case analysis (§4B) and the object diff;
  hostile review should re-derive both.
- **R5: sudo/CAP_BPF unavailable at build time** ⇒ C1 soft-fails to a
  warning. Residual risk accepted: C2 still blocks the deploy, and the
  privileged path is the documented default for artifact-regenerating
  PRs.

## 8. Blast radius

- `pkg/dataplane/build-userspace-xdp.sh` — pin + checks + C1 hook.
- `userspace-xdp/src/lib.rs` — 2-line B fix.
- `pkg/dataplane/userspace_xdp_bpfel.o` — regenerated (R2 above).
- `cmd/xpfd/main.go` (+ small helper in `pkg/dataplane`) — C2
  subcommand; reuses `loadRustUserspaceXDP()`.
- New small verifier-harness command (C1) + optional root-gated test.
- `test/incus/cluster-setup.sh` `deploy_vm()` — pre-flight hook.
- Docs: CLAUDE.md Quick Start, `pkg/dataplane/README.md`,
  `docs/engineering-style.md` gotcha entry.
- No control-plane, HA, CoS, or userspace-dp helper code touched.

## 9. Docs (same PR)

- CLAUDE.md Quick Start: state that `make build` does NOT require
  `make generate` unless `userspace-xdp/` source changed; the tracked
  `.o` is the deployable artifact.
- Recovery runbook (in `pkg/dataplane/README.md`): symptom string
  (`BPF program is too large`), recovery =
  `git checkout -- pkg/dataplane/userspace_xdp_bpfel.o && make build`
  + redeploy; pin-bump procedure.
- Engineering-style gotcha: BPF artifact regeneration requires the
  pinned toolchain + verifier gate; never commit a regenerated `.o`
  without a C1 PASS.

## 10. Deliverable

One PR (`Closes #1864`): Path D as above, with the verified evidence
from this research (optionB.diff, bisect table, harness) referenced.
Logical commits: (1) B source fix + regenerated verified `.o`;
(2) A pin + loud checks; (3) C1 harness + build hook; (4) C2
subcommand + deploy hook (+C3 test); (5) docs.

## 11. Decision asked of reviewers

PLAN-KILL is explicitly invited if you believe any of:

- the pin point is wrong (script env-default vs `rust-toolchain.toml`),
- B's semantic-equivalence argument has a hole,
- C2's verify-on-live-node is unsafe in a way §7/R3 misses,
- regenerating the tracked `.o` in this PR is unacceptable risk and
  the PR should ship guards-only first, artifact bump second,
- or the whole shape should instead be "stop tracking the `.o`, build
  it hermetically in CI" (rejected here for lack of privileged CI and
  because the embedded-artifact model is load-bearing for deploys —
  but argue it if you disagree).

Otherwise: PLAN-READY with the recommendation = Path D.
