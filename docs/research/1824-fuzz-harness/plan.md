# #1824 — proptest/fuzz harness for frame/inspect parse, NAT round-trip, state_writer encode

## 1. Status

DRAFT v1 — pending adversarial plan review (Claude SMR + Codex + AGY, research mode, no PR).

Worktree: `.claude/worktrees/research-1824-fuzz` @ `d30cfab84` (origin/master).
All file/line references below are to that SHA.

## 2. Issue framing

#1824 is the residue of two independent external reviews that both flagged the
same gap:

- **#1669 §12** — "Verified: zero `cargo fuzz` / `proptest` / `quickcheck`
  usage. Candidate targets: `frame/inspect.rs` (packet-parse fuzz),
  session-table install/lookup/delete property, NAT forward/reverse round-trip
  property, `state_writer.rs` serialization round-trip. Genuinely new,
  low-risk, high-value. `/research` to pick harness (cargo-fuzz vs proptest) +
  CI integration."
- **#1663 §3 ranks 4–8** — ranked test-gap list naming `state_writer.rs`
  (rank 4) and `tx/tcp_segmentation.rs` (rank 5) among the actionable seams.

This plan answers the harness-selection design question (proptest vs
cargo-fuzz vs both), gives a concrete per-surface property list, the harness
layout, and the CI/runtime budget — and corrects two factual premises in the
issue residue (see §4: `state_writer.rs` has no encode/decode pair; cargo-fuzz
is structurally blocked by the bin-only crate).

## 3. Honest scope/value framing

This is a **test-only** change: zero production code is touched, zero release
binary delta (dev-dependency only), zero hot-path impact. The value is not
throughput or latency; it is:

1. **Panic-freedom as a security property.** A panic in a worker poll thread
   kills the dataplane (forwarding stops on that queue). The parse functions
   in `frame/inspect.rs` run on every packet against attacker-controlled
   bytes. Today their bounds discipline is enforced only by 78 example-based
   tests in `frame/tests.rs` plus code review. A property test pins "no input
   of length 0..2048 with arbitrary metadata can panic" permanently — every
   future edit to the extension-header walk or the meta-led offset shortcuts
   is re-checked across hundreds of adversarial shapes per CI run.
2. **Fast-path/slow-path equivalence as a differential oracle.** The
   flow-cache descriptor rewrite (`frame/rewrite/ipv4.rs`, `ipv6.rs`, applied
   with precomputed `ip_csum_delta`/`l4_csum_delta` from
   `src/afxdp/checksum.rs:43`) *claims* byte-equivalence with the generic
   rewrite path (`rewrite/mod.rs` header: "Mirrors the byte-level rewrite
   semantics of the generic in-place rewrite"). That claim is currently
   enforced by nothing. Incremental-checksum bugs are the single most
   recurrent defect class in this codebase's history (one's-complement delta
   arithmetic, UDP zero-checksum special cases, 0xFFFF folding). A randomized
   differential test makes the equivalence claim executable.
3. **Reassembly identity for the TSO splitter.** `frame/tcp_segmentation.rs`
   and `tx/tcp_segmentation.rs` are near-duplicate implementations (the
   second is the UMEM-coupled twin). The pure one is property-testable today;
   drift between the twins is a real maintenance hazard (noted as follow-up,
   §10).

What this is **not**: it will not find deep stateful bugs (session table
lifecycle, HA sync ordering) — those need model-based stateful testing that
is explicitly out of scope (§10). It is also not coverage-guided fuzzing;
proptest explores randomly, not by branch feedback (§5.1 explains why that
trade is right for this crate today).

Expected size: ~3 new test files, ~600–900 LOC of test code, one
dev-dependency, ≤10s added `cargo test` wall-clock at the default case
counts.

*If reviewers conclude the bug-finding value is too small to justify the
churn and the new dependency, PLAN-KILL is an acceptable verdict.*

## 4. What's already shipped / corrected premises

### 4.1 Existing test infrastructure (verified at d30cfab84)

- `src/afxdp/frame/tests.rs` — 78 `#[test]`s, included via
  `#[cfg(test)] #[path = "tests.rs"] mod tests;` (frame/mod.rs:1301). Has
  reusable synthetic-packet builders: `build_ipv4_tcp_frame` (line 949),
  `build_icmp_echo_frame_v4`/`_vlan` (28/51), `build_ipv6_gre_frame` (79).
- `MmapArea::new(len)` (umem/mmap.rs:24, `pub(in crate::afxdp)`) works in
  unit tests via anonymous mmap — `frame/tests.rs:179` et al. already build
  UMEM-backed frames in-process. The descriptor rewrite path is therefore
  unit-testable today without AF_XDP sockets.
- `frame/tcp_tests.rs` (24 tests), `frame/headers_tests.rs` (20),
  `frame/checksum.rs` inline tests (13, incl. an existing
  `checksum16_complement_is_invariant` quasi-property at checksum.rs:691).
- `src/afxdp/test_fixtures.rs` — `ConfigSnapshot` fixtures
  (`forwarding_snapshot`, `native_gre_snapshot`) that produce a populated
  `ForwardingState` for decision-dependent tests.
- `tests/*.rs` integration tests (`fairness_eval_blackbox.rs` etc.) are
  black-box subprocess drivers; per the #547 plan v6 §3.5 contract they
  **cannot** import crate internals — "Cargo's tests/*.rs target physically
  cannot reach the binary's internal modules; that boundary is enforced by
  the compiler."
- Existing example-based serde round-trips: `main_tests.rs:906/1432`
  (`BindingCountersSnapshot`), `main_tests.rs:1276/1317/1355` (legacy +
  three-color + mirror `ConfigSnapshot` decode), and cross-language contract
  tests on the Go side (`pkg/dataplane/userspace/cold_path_status_test.go`
  embeds literal Rust-emitted JSON).

### 4.2 Premise correction A — `state_writer.rs` has no encode/decode pair

`src/state_writer.rs` (192 LOC) is an io_uring-backed **atomic file
persister** (`persist()` → temp file → `fsync` → `rename`), not a
serializer. The encode the issue residue points at is
`server/helpers.rs:784–806` `write_state()`: `serde_json::to_vec_pretty`
of `Payload { status: &ProcessStatus, snapshot: &Option<ConfigSnapshot> }`.
**Nothing in the Rust crate ever decodes that file back** — the consumer is
the Go control plane. So "decode(encode(x)) == x inside state_writer" is not
a property the code has. The honest replacements are in §5.3-S3; the
StateWriter mechanism itself gets one small deterministic durability test,
not a fuzz target.

### 4.3 Premise correction B — cargo-fuzz is structurally blocked

`userspace-dp` is a **bin-only crate** (no `src/lib.rs`; benches already had
to "reimplement the hot-path data shapes in this bin crate" per the
Cargo.toml bench comments). cargo-fuzz targets live in a separate
`fuzz/` crate that links the target **as a library dependency**. Every
candidate function is `pub(in crate::afxdp)` or `pub(crate)`. Adopting
cargo-fuzz therefore requires either (a) adding a lib target and re-exporting
internals — reversing the deliberate compiler-enforced encapsulation boundary
cited in the #547 plan, or (b) `#[cfg(fuzzing)]` visibility hacks plus a
nightly toolchain and corpus storage. Additionally there is **no CI lane to
host it**: this repo has no `.github/workflows/`; the test gate is
`make test` + `cargo test` run by agents/operators. A coverage-guided fuzz
lane would have no scheduled executor.

## 5. Concrete design

### 5.1 DESIGN QUESTION — proptest vs cargo-fuzz vs both

| | **A. proptest in-tree** (recommended) | **B. cargo-fuzz / libFuzzer** | **C. Both (A now, B follow-up)** |
|---|---|---|---|
| Access to `pub(in crate::afxdp)` fns | Yes — `#[cfg(test)]` modules are inside the crate | No — needs lib facade / visibility change | A part yes; B part blocked |
| Toolchain | stable (cargo 1.96 already in use) | nightly + `cargo-fuzz` install | stable + nightly |
| CI integration | runs inside existing `cargo test` gate; deterministic case counts; committed `proptest-regressions/` replay corpus | needs a new long-running lane + corpus storage; repo has **no** CI workflow infrastructure to host it | A inside `cargo test`; B unscheduled |
| Exploration | random + boundary-biased + shrinking | coverage-guided (strictly stronger at depth) | both |
| Release-binary impact | none (`[dev-dependencies]` don't link into release) | none (separate crate) | none |
| Structural change to production code | **zero** | lib target + re-exports (production-visible) | zero now, structural later |

**Recommendation: Option A**, with Option B explicitly **rejected for now**
(not deferred-as-promised): the marginal value of coverage-guided search over
boundary-biased random generation is real for deep parsers (ASN.1, TLS), but
the parsers here are shallow (≤6 extension-header iterations, fixed-offset
field reads, all already behind `get()`/length checks); the structural cost
(lib facade reversing an intentionally compiler-enforced boundary) plus the
missing CI home outweigh it. If a future lib split happens for other reasons,
re-evaluate via a fresh issue. This is *not* Option C — we do not pre-commit
to a fuzz follow-up nobody will schedule.

`proptest` enters as `[dev-dependencies] proptest = { version = "1",
default-features = false, features = ["std"] }` — drops the `fork`/`timeout`
features (process-forking test isolation) we don't need, trimming build-time
deps. No cargo feature gating is needed in our crate: dev-dependencies are
compiled only for test/bench profiles and cannot bloat
`cargo build --release` (the `make build-userspace-dp` artifact is unchanged
byte-for-byte except for nothing — it does not see the dep at all).

### 5.2 Harness layout

Follow the existing sibling-`*_tests.rs`-with-`#[path]` convention (e.g.
frame/mod.rs:1301):

```
userspace-dp/src/afxdp/frame/prop_inspect_tests.rs   # §5.3-S1 (parse)
userspace-dp/src/afxdp/frame/prop_rewrite_tests.rs   # §5.3-S2 (NAT)
userspace-dp/src/afxdp/frame/prop_segment_tests.rs   # §5.3-S4 (TSO)
userspace-dp/proptest-regressions/…                  # committed shrunk failures
```

included from `frame/mod.rs`:

```rust
#[cfg(all(test, not(miri)))]
#[path = "prop_inspect_tests.rs"]
mod prop_inspect_tests;
// … same for the other two
```

`not(miri)` because proptest's case loops are intractable under miri and the
project does run targeted `cargo +nightly miri test --bin` passes (#1755
lesson); the deterministic example tests keep miri coverage of the same fns.

The S3 snapshot/serde properties live in
`userspace-dp/src/prop_state_tests.rs` included from `main.rs` next to the
existing `main_tests.rs` include, same `cfg(all(test, not(miri)))` gate.

Shared strategies (tuple/packet generators) live in a
`#[cfg(test)] pub(in crate::afxdp) mod prop_strategies` block at the top of
`prop_inspect_tests.rs` and are reused by the other two frame files via
`super::prop_inspect_tests::prop_strategies` — no production module is
created for test plumbing.

Generator design (the part that determines whether these tests find
anything): two strategy families per surface —

- **`arb_garbage_frame()`** — `proptest::collection::vec(any::<u8>(),
  0..2048)` with a 25%-weighted prefix-mutation layer that stamps plausible
  EtherType/version/IHL bytes at offsets 12..15 so the generator doesn't
  waste 99% of cases failing the first length check. Plus an
  `arb_meta()` strategy producing `UserspaceDpMeta` with independently
  arbitrary `l3_offset`/`l4_offset`/`addr_family`/`protocol`/`pkt_len`
  (metadata is produced by the XDP shim but must be treated as semi-trusted
  — the parse fns already defend against inconsistent meta; the property
  pins that).
- **`arb_valid_packet()`** — wraps the existing builders
  (`build_ipv4_tcp_frame` etc.) over generated tuples: addrs from
  `any::<u32>()`/`any::<[u8;16]>()`, ports `any::<u16>()`, payload len
  `0..1600`, IHL ∈ {20, 24, 60}, optional VLAN tag, IPv6 with 0–2 extension
  headers (hop-by-hop/dest-opts) and optional fragment header. The v6
  ext-header generator is new (existing builders don't emit ext headers) and
  is the highest-value generator in the plan — the ext-header walk in
  `frame_l4_offset`/`packet_rel_l4_offset` (inspect.rs:44–137) is the most
  branch-dense parse code with zero current test coverage of AH (51) and
  fragment (44) arms.

### 5.3 Property list per surface

**S1 — frame/inspect parse** (`frame/inspect.rs`, plus `frame/tcp.rs`
flag readers reached through the same entry points):

| ID | Property | Inputs |
|----|----------|--------|
| P-I1 | No panic: `frame_l3_offset`, `frame_l4_offset`, `packet_rel_l4_offset(_and_protocol)`, `parse_flow_ports`, `parse_session_flow_from_bytes`, `parse_session_flow_from_frame`, `parse_ipv4_session_flow_from_frame`, `parse_packet_destination_from_frame`, `decode_frame_summary` return without panicking for ALL inputs | garbage frame × arbitrary meta |
| P-I2 | Bounds: every returned offset `o` satisfies `o <= frame.len()` and `l4 >= l3 >= 14`; `parse_flow_ports` only ever reads inside the slice (implied by P-I1 + `get()`, asserted explicitly on returns) | garbage frame × arbitrary meta |
| P-I3 | Offset consistency: `frame_l4_offset(f, af) == frame_l3_offset(f).and_then(\|l3\| packet_rel_l4_offset(&f[l3..], af).map(\|r\| l3+r))` | garbage + valid frames |
| P-I4 | Parse round-trip: for a synthesized valid packet from tuple T (v4/v6 × TCP/UDP/ICMP × VLAN × ext-headers), `parse_session_flow_from_bytes(frame, consistent_meta) == Some(flow(T))` and with zeroed/garbled meta the frame-led path recovers the same tuple | valid packets |
| P-I5 | Meta independence: for valid packets, the result with consistent meta equals the result with `l3_offset`/`l4_offset` zeroed (frame-led fallback agreement, inspect.rs:336–356 arbitration) | valid packets |

**S2 — NAT forward/reverse rewrite** (`apply_nat_ipv4`/`apply_nat_ipv6` +
`apply_nat_port_rewrite` in frame/mod.rs:696+/849+; descriptor path
`apply_rewrite_descriptor` in frame/rewrite/):

| ID | Property | Inputs |
|----|----------|--------|
| P-N1 | Round-trip identity: for valid v4/v6 TCP/UDP packets and NAT decision D (any non-empty subset of {src ip, dst ip, sport, dport} rewritten), `apply_nat(apply_nat(pkt, D), inverse(D)) == pkt` byte-for-byte (incl. IP + L4 checksums), where `inverse(D)` rewrites back to the original values. This is the issue's "NAT fwd∘rev == identity on the rewritten fields" stated on the actual unit the code exposes (`NatDecision` is direction-agnostic; the session-reverse-entry composition is out of scope, §10) | valid packets × arb NatDecision |
| P-N2 | Checksum validity oracle: after `apply_nat`, full recompute (`checksum16` over IP header; `checksum16_ipv4`/`checksum16_ipv6` pseudo-header over L4) matches the stored checksums — i.e. the incremental `adjust_l4_checksum_*` deltas equal ground truth. UDP/v4 zero-checksum packets stay zero (RFC 768); UDP/v6 and rewritten-UDP/v4 never end at 0x0000 | valid packets × arb NatDecision |
| P-N3 | **Differential, descriptor vs generic**: build the same valid TCP/UDP frame into two `MmapArea`s; apply the generic in-place path (`rewrite_forwarded_frame_in_place`) and the descriptor path (`apply_rewrite_descriptor` with `RewriteDescriptor` whose deltas come from `compute_l4_csum_delta` exactly as flow_cache.rs:339 builds them); assert the resulting frames are byte-identical and both pass `verify_built_frame_checksums` (frame/mod.rs:1120). Cases where the descriptor path declines (`None`: TTL≤1, port mismatch, nat64/nptv6) assert the generic path is the only writer | valid packets × arb NAT × arb TTL/ports |
| P-N4 | Payload immutability: bytes after the L4 header are untouched by either path | same |

**S3 — state encode (re-scoped per §4.2):**

| ID | Property | Inputs |
|----|----------|--------|
| P-W1 | Serde round-trip: `serde_json::from_*(serde_json::to_*(x)) == x` for proptest-generated `ConfigSnapshot` and `BindingCountersSnapshot` values (generated via small per-field strategies over the existing `test_fixtures.rs` shapes, not `derive(Arbitrary)` — no production derive changes). Generalizes the existing single-example round-trips at main_tests.rs:906/1432 | generated snapshots |
| P-W2 | Deterministic (non-prop) StateWriter durability test: `persist()` to a tempdir path → read-back equals payload; `temporary_path` never equals its input and stays in the same directory (state_writer.rs:183–192 extension edge cases: no extension, dotfile, multi-dot) | fixed examples |

P-W1/P-W2 are deliberately the smallest slice of this plan (~80 LOC). If
reviewers judge even that as ballast given the existing example tests and the
Go-side contract tests, dropping S3 entirely is a fine outcome — say so in
review rather than nodding it through.

**S4 — TCP segmentation** (`frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`,
pure: `&[u8] → Option<Vec<Vec<u8>>>`; needs only a fixture `ForwardingState`
for the MTU lookup and a `SessionDecision`):

| ID | Property | Inputs |
|----|----------|--------|
| P-T1 | No panic for garbage frames × arbitrary meta × fixture forwarding state | garbage |
| P-T2 | Reassembly identity: when `Some(segs)`, concatenating per-segment TCP payloads == original TCP payload | valid oversized TCP packets (payload 1×–4× MTU, MTU ∈ 1280..9216, TCP options 0..40B, v4 IHL 20..60) |
| P-T3 | Per-segment wellformedness: every segment ≤ eth_len+MTU; `seq_i == orig_seq.wrapping_add(cumulative_offset)` (incl. seq wrap near u32::MAX); PSH cleared on all but last; SYN/FIN/RST never present (precondition gate at :69 declines them — asserted as `None`); IP total-length/payload-length fields consistent; both checksums verify via `verify_built_frame_checksums`; segment count == `ceil(payload/segment_max)` | same |
| P-T4 | NAT composition: with a NAT decision in the `SessionDecision`, every segment carries the rewritten tuple and valid checksums (composes S2's oracle) | same × arb NAT |

The UMEM-coupled twin (`tx/tcp_segmentation.rs::…_into_prepared`) is **out of
scope** (needs a `BindingWorker` + tx_pipeline harness); the twin-drift risk
is recorded as a candidate follow-up in §10, not silently absorbed.

### 5.4 CI / runtime budget

- Config: every property uses an explicit
  `ProptestConfig { cases: N, max_shrink_iters: 4096, .. }`. N = 512 for
  cheap parse properties (P-I*), 256 for S2/S4 (packet build + dual rewrite +
  full-recompute oracle per case), 128 for P-N3 (two MmapAreas per case),
  64 for P-W1. Measured target: **≤10s added to `cargo test --release`
  wall-clock total**; if a property exceeds ~2s at these counts, the count is
  halved and the halving justified in the test header comment.
- Determinism: proptest's default RNG is deterministic per-seed with
  failure persistence; `proptest-regressions/**/*.txt` files are
  **committed** so every previously-found counterexample replays first on
  every future run (the actual regression-pinning mechanism). No
  time-dependent or env-dependent generation.
- Soak knob: `PROPTEST_CASES=100000 cargo test -p … prop_` documented in the
  test-file headers for operator-driven deep runs; never wired into any gate.
- Gates: the new tests run wherever `cargo test --manifest-path
  userspace-dp/Cargo.toml` already runs (the project's standard validation,
  e.g. /engineer Step gates). No new Make target, no new CI lane, no nightly.

## 6. Public API preservation

Zero production source changes. No visibility widening: all targets are
already reachable from `#[cfg(test)]` modules inside `crate::afxdp` (the
layout in §5.2 places files inside the same module tree, exactly like
`frame/tests.rs`). `Cargo.toml` gains one `[dev-dependencies]` line;
`Cargo.lock` gains proptest's dev-graph (compiled for tests only). The
release binary, the control protocol, and all module docs' behavioral
contracts are untouched. Docs: `userspace-dp/src/afxdp/frame/README.md`
gains a short "property tests" section describing the three prop files and
the regression-corpus convention (module-doc contract per CLAUDE.md).

## 7. Hidden invariants the change must preserve

- **No `cargo fmt` over existing files** (#1769 gotcha) — new files are
  formatted in isolation; includes in `frame/mod.rs`/`main.rs` are 3-line
  appends.
- **Miri lane stays green** — `cfg(all(test, not(miri)))` on all prop
  modules (§5.2); miri must not crawl proptest case loops.
- **`debug-log` feature build stays green** — P-N3 calls paths that contain
  `cfg!(feature = "debug-log")` checksum verification; tests must pass both
  with and without the feature (`make build-userspace-dp-debug-log` parity).
- **Test determinism under parallel `cargo test`** — no shared tempdir
  collisions (reuse the TempGuard pattern from `fairness_eval_blackbox.rs`
  for P-W2); no reliance on thread-local debug counters.
- **`unsafe` discipline** — P-N3 exercises `slice_mut_unchecked` through the
  same call shapes as production (via the public-ish entry fns), never adds
  new unsafe in test code beyond what existing tests already do.
- **proptest-regressions hygiene** — files are committed, never hand-edited,
  and reviewed like code (a deleted regression file silently unpins a bug).

## 8. Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression risk | **NONE** | test-only; release artifact bit-identical w.r.t. production code |
| Lifetime / borrow-checker risk | **LOW** | MmapArea differential test needs two areas to avoid aliasing `slice_mut_unchecked` views; pattern already exists in frame/tests.rs |
| Performance regression risk | **LOW** | bounded: +≤10s `cargo test`, + proptest dev-build time (~20–40s cold, cached thereafter). Hot path untouched |
| Architectural mismatch risk | **LOW–MED** | the one real hazard: properties that encode the *current* behavior of deliberately-lenient parsers (e.g. meta-vs-frame arbitration in inspect.rs:342–352) could calcify accidental semantics and produce false-red friction on future parser changes. Mitigation: P-I5/P-N3 assert *relations* (agreement, equivalence, identity), not absolute golden outputs; absolute assertions are confined to P-I4 round-trips on packets we synthesized ourselves |

Also honest: if a property finds a real panic/checksum bug during
implementation, that becomes a separate `bug` issue + fix PR sequenced before
the harness PR pins it (tests must land green; we don't commit xfail).

## 9. Test plan (for the harness PR itself)

1. `cargo build --manifest-path userspace-dp/Cargo.toml --release` — clean,
   and the release binary is unaffected (`cargo tree --edges normal` shows no
   proptest).
2. `cargo test --manifest-path userspace-dp/Cargo.toml --release` — full
   suite green; record before/after wall-clock to enforce the ≤10s budget.
3. `cargo test … --features debug-log` — green (P-N3 verification arm).
4. Mutation spot-check (manual, documented in PR): temporarily break one
   checksum delta (e.g. drop the `0xFEFF` TTL term in rewrite/ipv4.rs) and
   one bounds check, confirm P-N3/P-I1 actually fail, revert. This proves
   the oracle bites — the most common failure mode of property-test PRs is
   vacuous properties.
5. Standard repo gates: `make build`, `make test` (Go suite unaffected),
   `make audit-check`.
6. No smoke/cluster run needed (test-only, no dataplane artifact change) —
   consistent with the batch-smoke policy for non-runtime PRs.

## 10. Out of scope (explicitly)

- **cargo-fuzz / coverage-guided lane** — rejected for now (§5.1); revisit
  only if a lib split lands for independent reasons.
- **Session-table install/lookup/delete stateful property** (#1669 §12's
  third bullet) — needs proptest-state-machine or model-based testing
  against `SessionManager`; different harness class, different blast
  radius; file separately if wanted.
- **`tx/tcp_segmentation.rs::…_into_prepared`** and a differential test
  against its pure twin — blocked on a `BindingWorker`/tx_pipeline fixture;
  candidate follow-up issue.
- **NAT64/NPTv6 translation properties** (`nat64.rs`, `nptv6.rs`) — real
  candidates (NAT64 has its own checksum16 clones at nat64.rs:408+) but
  header-size-changing translation needs its own generator design; keep this
  PR reviewable.
- **icmp_embed builders** (#1663 rank 7), WG frame parsing (`frame/wg.rs`),
  GRE (`gre.rs`) — same harness pattern applies later; not in v1.
- **Cross-language Go↔Rust state-file contract fuzzing** — the existing
  embedded-JSON contract tests cover the schema; generating on one side and
  decoding on the other requires build orchestration out of proportion to
  the risk.

## 11. Open questions for adversarial review (PLAN-KILL invitable on each)

1. **Is the whole thing worth it?** 78+24+20+13 example tests already cover
   these files; the parse fns are short and `get()`-disciplined. If you
   believe random+shrinking adds ~nothing over the existing examples plus
   review discipline, say PLAN-KILL — "genuinely new" (the #1669 claim) is
   not the same as "genuinely valuable".
2. **Is P-N3 (descriptor-vs-generic differential) sound as specified?** The
   two paths intentionally differ in *when* they decline (descriptor declines
   on port mismatch/nat64/nptv6/TTL and falls back). Is "byte-identical when
   both succeed; assert decline conditions otherwise" the right contract, or
   does hidden legitimate divergence (e.g. UDP zero-checksum handling
   differences between rewrite/ipv4.rs:108–118 and the generic
   `adjust_l4_checksum_*` path) make the property unprovable-as-stated?
   Reviewers should check those two code paths' UDP-0 semantics specifically.
3. **Strategy realism**: does the 25%-stamped garbage generator actually
   reach the deep ext-header arms (AH/fragment), or do we need a dedicated
   structured-v6-ext-header strategy as the primary generator (and is 512
   cases enough to mean anything there)? Is there a measurement we should
   demand (e.g. `llvm-cov` over one prop run) before trusting the harness?
4. **S3 scope**: keep the ~80-LOC serde/persist slice, or drop it entirely
   given §4.2 (no Rust decoder; Go contract tests exist)? Keeping a
   misnamed surface alive just because the issue title names it is cargo
   culting; killing it changes the issue's deliverable list.
5. **proptest-regressions in-repo**: committed corpus files are the pinning
   mechanism but also accumulate; is the team willing to review/own them, or
   should we set `failure_persistence` to a custom path and rely on
   re-finding (weaker)?
6. **Module-include shape**: three sibling `prop_*_tests.rs` files in
   `frame/` (consistent with `*_tests.rs` convention) vs one
   `frame/prop_tests/` directory module (consistent with the module-dir
   refactor preference) — which does the repo's layout contract actually
   demand for *new* multi-file test additions?
