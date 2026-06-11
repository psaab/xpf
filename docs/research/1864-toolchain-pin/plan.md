# #1864 — `make generate` produces a verifier-killing userspace-xdp shim: pin the BPF toolchain + add load guards

Revision: r2 (2026-06-11) — folds in AGY r1 findings 2-5, Claude SMR F1/F2
Branch: `research/1864-toolchain-pin`
Status: round 2 — awaiting 3-way convergence (Codex + AGY + Claude SMR)

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

Single source of truth: a new `userspace-xdp/rust-toolchain.toml`
pinning `channel = "nightly-2026-05-23"` (latest dated nightly
verified to PASS with **both** the current source and the
Path-B-patched source — maximal safety margin; bump deliberately,
never implicitly) with `components = ["rust-src"]`. This also fixes
rust-analyzer/IDE and ad-hoc `cargo` invocations in the crate dir
(AGY r1 F4a). `build-userspace-xdp.sh`:

- Parses the pin from `rust-toolchain.toml` (one authority);
  `TOOLCHAIN="${RUST_BPF_TOOLCHAIN:-<parsed pin>}"`. Explicit
  `RUST_BPF_TOOLCHAIN=...` override still allowed (needed for bisects
  and pin bumps) — the Path-C gate still applies either way. Because
  the script always passes an explicit `+${TOOLCHAIN}`, the override
  works even with the toolchain file present.
- Refuses to build if the resolved toolchain is unavailable, printing
  the exact `rustup toolchain install <pin> --component rust-src` line.
- Checks the **exact linker binary cargo will execute** (Codex r1 F2:
  today the script checks `${HOME}/.cargo/bin/bpf-linker` while
  `.cargo/config.toml` hardcodes an absolute `/home/ps/...` path — the
  check and the build can disagree). The fix: `.cargo/config.toml`
  becomes `linker = "bpf-linker"` (AGY r1 F4b — also removes the
  non-portable home path); the script resolves `bpf-linker` via the
  same PATH cargo will see (prepending `~/.cargo/bin` deterministically)
  and runs `--version` on **that resolved path**, requiring an exact
  match with the pinned expectation (`0.10.2`); missing binary OR
  version mismatch ⇒ hard fail with
  `cargo install bpf-linker --version 0.10.2 --locked` instructions
  (Claude SMR F2). bpf-linker embeds its own LLVM; it is as much a
  codegen input as rustc.
- **Override builds cannot silently update the tracked artifact**
  (Codex r1 F6): when `RUST_BPF_TOOLCHAIN` differs from the pin, the
  script builds and verifies but refuses the final install unless an
  explicit, grep-able `XPF_SHIM_ALLOW_UNPINNED_INSTALL=1` is also set,
  and prints the toolchain provenance either way. Bisects stay easy;
  accidental unpinned commits do not.

### Path B — fix the source so reasonable compilers emit prunable code

Two-line change, **already verified in this research** (diff preserved
at `docs/research/1864-toolchain-pin/optionB.diff`):

- lib.rs:467: `saturating_sub` → `wrapping_sub`. Semantics identical:
  the short-circuit `now_ns < *last_heartbeat` clause already handles
  the underflow case; on the evaluated path `now_ns >= *last_heartbeat`
  so `wrapping_sub == saturating_sub == exact`. No behavior change.
  (Codex r1 F7: the r1 "even if evaluated, a wrapped value still
  compares > timeout_ns" side-claim is removed — it only holds under
  domain assumptions; the short-circuit guard is the proof.)
- lib.rs:484: `data_end.saturating_sub(data)` →
  `if data_end > data { data_end - data } else { 0 }`. Identical
  result for all inputs.

Verified matrix (this worktree): patched source PASSes on
`nightly-2026-03-08`, `-05-23`, **and the current failing nightly**
(6620 xlated insns). Cheap, real, and removes the single known
explosion trigger — but it cannot guarantee future toolchains stay
safe, so it does not replace A or C.

### Path C — verifier load guards (fail the build/deploy, never the dataplane)

- **C1 — build-time gate, verify-then-install.** Productionize the
  research harness as a small Go command (`cmd/shimverify` or
  `tools/`-scoped) that loads a candidate object via
  `ebpf.NewCollection` (anonymous maps, no pinning, no attach) and
  exits nonzero with the verifier log tail on rejection.
  `build-userspace-xdp.sh` verifies the **candidate at the cargo
  output path** and only `install`s over the tracked
  `pkg/dataplane/userspace_xdp_bpfel.o` on PASS (Claude SMR F1 + AGY
  r1 F5 — the tracked artifact is never transiently bad, so there is
  no restore step to get wrong and no committable-escape window):
  - with CAP_BPF/root available (the script may attempt `sudo -n`
    for the verify step only): rejection fails `make generate` loudly,
    tracked `.o` untouched.
  - without privileges: the tracked `.o` is **not** updated; the
    candidate stays at the cargo output path; the script exits nonzero
    with the exact privileged command to verify+install. Regeneration
    *requires* verification — there is no unverified-install path.
    (Static insn counting is **not** a substitute — good and bad
    objects differ by 7 static insns; only a real BPF_PROG_LOAD walk
    is honest.)
- **C2 — deploy-time pre-flight.** New `xpfd verify-dataplane`
  subcommand (pattern already exists: `version`, `cleanup` in
  `cmd/xpfd/main.go`): loads the **embedded** collection anonymously,
  prints PASS/REJECT + verifier tail, exits 0/nonzero. **Hard
  invariant (Codex r1 F3): the verify path must NOT call
  `LoadUserspaceShim`/`loadUserspaceShimObjectsOnce` or anything that
  sets `PinByName`/`PinPath`/`MapReplacements`** — it is a dedicated
  verify-only function on a bare `ebpf.NewCollection`. It DOES run the
  non-mutating spec checks production runs
  (`validateUserspaceShimSpec`, loader_userspace_shim.go:138-162) so a
  PASS attests production-load viability, not just verifier acceptance
  (Codex r1 F4). Verify-only load touches no pins and detaches
  nothing — an existing good loaded program keeps forwarding
  (lenient-boot doctrine intact; anonymous maps are freed on process
  exit). Two live-node hardening measures
  (AGY r1 F2/F3): before loading, the verify path mutates the spec
  in-memory to shrink the large **hash** maps' MaxEntries to 1
  (`dnat_table` 10 M no-prealloc still allocates its bucket array
  ~128 MB+ even empty; `userspace_sessions` 262144 is preallocated —
  hash-map max_entries does not feed program safety analysis, so the
  verifier outcome is unchanged; array maps are left alone), and the
  deploy hook runs the subcommand under `nice -n 19` so a ~17 s REJECT
  walk cannot starve dataplane cores. `deploy_vm()` in
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
- (r1 stance reversed in r2 per AGY F4a:) `rust-toolchain.toml` IS now
  the pin's single source of truth — see Path A. The build script
  parses it rather than duplicating the version string.

## 6. Gates (Phase 2, all unmasked)

- `go build ./... && go vet ./... && make test` — full, no skips.
- `make generate` both arms proven in the PR:
  - correct toolchain (pinned, auto-checked): produces an object that
    passes C1 verification; record md5 + xlated insn count in the PR.
  - wrong/missing toolchain: clean, actionable refusal; no bad `.o`
    left behind in the worktree. Proven via (a) missing-pin simulation
    (bogus `RUSTUP_HOME` or uninstalled pin) and (b)
    `RUST_BPF_TOOLCHAIN` override **without**
    `XPF_SHIM_ALLOW_UNPINNED_INSTALL` ⇒ install refused with
    provenance printed (Codex r1 F6 — refusal semantics are the
    contract, not re-triggering the blowup; the preserved bad object
    already proves the REJECT arm of the verifier gate).
- `xpfd verify-dataplane` demonstrated on both a PASS object and a
  REJECT object (the bad object from this research is preserved for
  the test).
- **Deploy-ordering invariant reviewed explicitly (Codex r1 F5):** in
  the revised `deploy_vm()`, no `systemctl stop xpfd` and no
  `xpfd cleanup` may appear before the `verify-dataplane` pre-flight;
  the review checklist names this line ordering, since the current
  script's stop-clean-push ordering (cluster-setup.sh:668-682) is the
  exact incident shape.
- Cargo gates with the pinned toolchain and the build-script env
  (Codex r1 F8 — `lib.rs:81-84` requires `MAX_INTERFACES` via `env!`):
  `MAX_INTERFACES=$(awk ... bpf/headers/xpf_common.h)
  cargo +<pin> fmt --check / clippy --release / test` exactly as the
  PR documents them; gates must not be run against the floating
  `nightly`.
- New tracked `.o` (regenerated with B + pinned toolchain) must PASS
  C1 locally AND be smoke-validated by the parent on the loss cluster
  (one guarded `make generate` + deploy cycle under the cluster lock)
  before merge.
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
  Verify-only load creates anonymous maps and never pins/attaches; the
  running collection is untouched. Memory hazard from the 10 M-entry
  hash bucket array and the preallocated `userspace_sessions` is
  removed by the MaxEntries=1 spec shrink (§4 C2); CPU hazard from a
  ~17 s REJECT walk is bounded by `nice -n 19`. Residual: a PASS walk
  is seconds and once-per-push.
- **R4: B is semantics-sensitive code review surface.** Both rewrites
  are proven-identical by case analysis (§4B) and the object diff;
  hostile review should re-derive both.
- **R5: sudo/CAP_BPF unavailable at build time** ⇒ C1 fails closed
  (Codex r1 F1 + AGY r1 F5): the tracked `.o` is never updated without
  a verified PASS; the unprivileged arm exits nonzero with the
  candidate left at the cargo output path and exact instructions.
  Residual: an unprivileged box cannot regenerate the artifact at all
  — by design; C2 still independently blocks any escaped bad binary at
  deploy.

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
Logical commits, **gates first, artifact bump last** (Codex r1
closing condition: gates must fail closed and the regenerated object
must not sit ahead of the guard in bisect order): (1) C1 harness +
verify-then-install build hook; (2) A pin (rust-toolchain.toml +
script checks + .cargo/config.toml fix); (3) C2 subcommand + deploy
pre-flight (+C3 test); (4) B source fix + regenerated verified `.o`;
(5) docs.

## 11. Decision asked of reviewers

**Open question for round 2 (AGY F6 vs Codex/Claude SMR): one PR or
two?** AGY r1 recommends gates-first PR then a separate artifact-bump
PR. Codex r1 accepts same-PR regeneration "only if the gates fail
closed" and notes shipping the B source fix without the object would
be misleading (the binary embeds the `.o` — userspace_xdp_rust.go:11).
SMR position: single PR, commits ordered gates-first /
artifact-bump-last (§10), gate proven against the preserved bad object
within the PR, parent's guarded deploy smoke gating the merge. r2
adopts the single-PR fail-closed shape; AGY round 2 is asked to
re-judge with the fail-closed C1 (no unverified-install path) now in
the plan.

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
