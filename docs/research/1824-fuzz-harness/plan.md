# #1824 — proptest/fuzz harness for frame/inspect parse, NAT round-trip, state_writer encode

## 1. Status

DRAFT v3 — post round-2 (Codex r2 PLAN-NEEDS-REVISION task-mq8evi7r-vd8x4k:
2 HIGH, both verified; AGY r2 PLAN-READY adversarial-review-mq8euds7-fy9qg1
but its Q1 "byte-equality provable" answer is refuted by Codex's
counterexample; Claude SMR r2 self-corrected — my "cannot construct a
divergence outside the excluded bytes" claim was wrong). v3 folds:

- **D3 (NEW, Codex r2 finding 1 + Claude blast-radius extension)**: the
  generic v6 NAT path assumes L4 at fixed offset 40 — port rewrite at
  `apply_nat_port_rewrite(packet, 40, …)` (frame/mod.rs:840–841) AND both
  checksum adjusters at `40usize.checked_add(delta)` (checksum.rs:490,
  516–517) — while the descriptor path parses real ext-header offsets
  (rewrite/ipv6.rs:35–41). On v6 + ext headers + NAT the generic path
  writes into extension-header bytes: a latent production defect, §10-D D3.
  ALL NAT-applying properties (P-N1..P-N4, P-T4) now generate v6 packets
  WITHOUT extension headers; ext-header packets remain in the read-only S1
  parse properties.
- **P-N3b corrected (Codex r2 finding 2)**: both paths write the Ethernet
  header in prep BEFORE TTL/port validation (frame/mod.rs:403/413 via
  mod.rs:581, rewrite/mod.rs:56), so "neither writes" was false; decline
  assertions now cover bytes from L3 onward only, with a note that the L2
  scribble on a declined frame is harmless in production (caller drops on
  `None`).

Prior round-1 folds (v2/v2.1) retained below in this section's history.

v1.1 folded SMR r1 F1–F5. v2 folds Codex r1 (1–6) + AGY r1 (1–4):
- **S3 DROPPED** (Codex 5 + AGY Q4 + SMR Q4 convergent): `ConfigSnapshot`
  has no `PartialEq` (protocol/snapshot.rs:182) so P-W1 doesn't even compile
  without a production derive change, the Rust crate has no decoder, and Go
  contract tests cover the schema. §5.3-S3 retained as a tombstone.
- **P-N3 re-specified** (Codex 1+2, AGY 1+2): `verify_built_frame_checksums`
  is v4-TCP-only (frame/mod.rs:1129–1131 early-returns `(true,true)` for
  everything else) → replaced by a test-local full-recompute oracle; byte
  equality now excludes L4 checksum bytes (two legitimate production
  divergences found by review: rewrite/ipv6.rs:98 canonicalizes 0→0xFFFF for
  ALL v6 protocols vs generic UDP/ICMPv6-only at checksum.rs:88; the
  family-ungated UDP `current == 0` bypass at frame/mod.rs:906); success
  property runs both paths with `expected_ports=None`; decline conditions
  moved to deterministic example tests.
- **P-N1 inverse(D)** (Codex 3, AGY 3): harness-defined same-packet undo,
  explicitly NOT `NatDecision::reverse` (nat/mod.rs:71–74 is reverse-flow).
- **Generator** (Codex 4, AGY 4): structured v6 ext-header chain strategy is
  the primary generator — forced routing(43)/AH(51)/fragment(44)/
  no-next-header(59), >6-header chains; llvm-cov spot-check during
  implementation.
- Layout switched to `frame/prop_tests/` directory module (Codex Q6 + AGY
  Q6); RNG-determinism wording fixed; cargo-fuzz "blocked" reworded to
  "not worth the facade/shims now".

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
requires a lib facade or visibility shims the bin-only crate deliberately
avoids).

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

Expected size: one new `frame/prop_tests/` directory module (~5 files,
~600–900 LOC of test code), one dev-dependency, ≤10s added `cargo test`
wall-clock at the default case counts.

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
plus the missing CI home outweigh it. Precision (Codex r1 finding 6):
"blocked" means *not worth the workarounds*, not impossible — a lib facade,
`#[cfg(fuzzing)]` visibility shims, or source-inclusion (`include!`) fuzz
targets are all technically feasible and all ugly enough to need their own
justification. If a future lib split happens for other reasons, re-evaluate
via a fresh issue. This is *not* Option C — we do not pre-commit to a fuzz
follow-up nobody will schedule.

`proptest` enters as `[dev-dependencies] proptest = { version = "1",
default-features = false, features = ["std"] }` — drops the `fork`/`timeout`
features (process-forking test isolation) we don't need, trimming build-time
deps. No cargo feature gating is needed in our crate: dev-dependencies are
compiled only for test/bench profiles and cannot bloat
`cargo build --release` (the `make build-userspace-dp` artifact is unchanged
byte-for-byte except for nothing — it does not see the dep at all).

### 5.2 Harness layout

Directory module under `frame/` (module-dir layout convention; ratified by
Codex r1 Q6 + AGY r1 Q6 over sibling flat files):

```
userspace-dp/src/afxdp/frame/prop_tests/mod.rs        # includes + ProptestConfig consts
userspace-dp/src/afxdp/frame/prop_tests/strategies.rs # shared generators (§ below)
userspace-dp/src/afxdp/frame/prop_tests/inspect.rs    # §5.3-S1 (parse)
userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs    # §5.3-S2 (NAT)
userspace-dp/src/afxdp/frame/prop_tests/oracle.rs     # full-recompute checksum oracle (§5.3-S2)
userspace-dp/src/afxdp/frame/prop_tests/segment.rs    # §5.3-S4 (TSO)
userspace-dp/proptest-regressions/…                   # committed shrunk failures
```

included from `frame/mod.rs`:

```rust
#[cfg(all(test, not(miri)))]
mod prop_tests;
```

`not(miri)` because proptest's case loops are intractable under miri and the
project does run targeted `cargo +nightly miri test --bin` passes (#1755
lesson); the deterministic example tests keep miri coverage of the same fns.

Shared strategies and the checksum oracle are private to `prop_tests/`
(`pub(super)` inside the directory module) — no production module is created
for test plumbing, and nothing leaks outside `frame/`.

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
  `0..1600`, IHL ∈ {20, 24, 60}, optional VLAN tag. **v6 variants used by
  any NAT-applying property (P-N1..P-N4, P-T4) carry NO extension headers**
  — the generic v6 NAT path hardcodes L4 at offset 40 (§10-D D3), so
  ext-header × NAT inputs are a known production divergence, not a property
  violation. Ext-header packets feed only the read-only S1 parse properties
  (and the P-N3b D3 pin example).
- **`arb_v6_ext_chain()`** — a dedicated *structured* IPv6 extension-header
  chain strategy, the primary generator for the v6 parse arms (Codex r1
  finding 4 + AGY r1 finding 4: stamped garbage will not reliably reach
  them). Generates chains drawn from {hop-by-hop(0), routing(43),
  dest-opts(60), AH(51), fragment(44), no-next-header(59)} with: forced-AH
  cases (the `(len+2)*4` arithmetic at inspect.rs:60–67 differs from the
  `(len+1)*8` options arithmetic), forced-fragment cases (fixed 8-byte
  advance, inspect.rs:68–75), chains **longer than 6** (the loop bound at
  inspect.rs:50 — pins the `Some(offset)` post-loop behavior), oversized
  hdr-ext-len values that walk past the buffer, and truncated chains. The
  ext-header walk is the most branch-dense parse code with zero current test
  coverage of the AH/fragment/no-next arms. Acceptance evidence during
  implementation: one `cargo llvm-cov` spot-run over the prop tests showing
  the 43/51/44/59 arms executed (documented in the PR, not wired into CI).

### 5.3 Property list per surface

**S1 — frame/inspect parse** (`frame/inspect.rs`, plus `frame/tcp.rs`
flag readers reached through the same entry points):

| ID | Property | Inputs |
|----|----------|--------|
| P-I1 | No panic: `frame_l3_offset`, `frame_l4_offset`, `packet_rel_l4_offset(_and_protocol)`, `parse_flow_ports`, `parse_session_flow_from_bytes`, `parse_session_flow_from_frame`, `parse_ipv4_session_flow_from_frame`, `parse_packet_destination_from_frame`, `decode_frame_summary` return without panicking for ALL inputs | garbage frame × arbitrary meta |
| P-I2 | Bounds: every returned offset `o` satisfies `o <= frame.len()` and `l4 >= l3 >= 14`; `parse_flow_ports` only ever reads inside the slice (implied by P-I1 + `get()`, asserted explicitly on returns) | garbage frame × arbitrary meta |
| P-I3 | Offset consistency: `frame_l4_offset(f, af) == frame_l3_offset(f).and_then(\|l3\| packet_rel_l4_offset(&f[l3..], af).map(\|r\| l3+r))` | garbage + valid frames |
| P-I4 | Parse round-trip: for a synthesized valid packet from tuple T (v4/v6 × TCP/UDP/ICMP × VLAN × ext-headers), `parse_session_flow_from_bytes(frame, consistent_meta) == Some(flow(T))` and with zeroed/garbled meta the frame-led path recovers the same tuple | valid packets |
| P-I5 | Meta independence: for valid packets **with generator-enforced `meta.protocol == frame[l3+9]` (v4) / final next-header (v6)**, the result with consistent meta equals the result with `l3_offset`/`l4_offset`/meta tuple zeroed (frame-led fallback agreement, inspect.rs:336–356 arbitration). The two paths source `protocol` differently — meta-led key uses `meta.protocol` (inspect.rs:329–334 → from_meta), v4 frame-led key uses `frame[l3+9]` (inspect.rs:614) — so the property only holds under that constraint; the inconsistent-protocol divergence is pinned by one deterministic example test documenting current arbitration behavior, not hidden by the generator | valid packets |

**S2 — NAT forward/reverse rewrite** (`apply_nat_ipv4`/`apply_nat_ipv6` +
`apply_nat_port_rewrite` in frame/mod.rs:696+/849+; descriptor path
`apply_rewrite_descriptor` in frame/rewrite/):

| ID | Property | Inputs |
|----|----------|--------|
| P-N1 | Round-trip identity **on non-checksum bytes**: for valid v4/v6 TCP/UDP packets and NAT decision D (any non-empty subset of {src ip, dst ip, sport, dport} rewritten), after `apply_nat(apply_nat(pkt, D), undo(D, pkt))` the addresses, ports, every other header field, and the payload are byte-identical to the original. **`undo` is a harness-defined same-packet inverse** — `NatDecision { rewrite_src: D.rewrite_src.map(\|_\| orig_src), rewrite_dst: D.rewrite_dst.map(\|_\| orig_dst), … }` — explicitly NOT `NatDecision::reverse` (nat/mod.rs:71–74), which builds the reverse-FLOW decision (src↔dst swapped) for reply packets and would corrupt a same-direction packet (Codex r1 finding 3, AGY r1 finding 3). **Checksum fields are excluded from byte comparison** — one's-complement zero has two encodings (0x0000/0xFFFF) and the code deliberately maps across them (rewrite/ipv4.rs:113–118, rewrite/ipv6.rs:96–98, generic UDP `keep_zero`); instead each hop's checksums must pass the P-N2 oracle ("valid before, valid after fwd, valid after undo"; v4 UDP zero-checksum stays zero across both hops). The session-level fwd/rev composition via `NatDecision::reverse` gets ONE deterministic example test (forward packet through D, synthesized reply through `D.reverse(...)`, assert the reply's rewritten tuple maps back to the original flow) — example, not property, because it needs a semantically-built reply packet | valid packets × arb NatDecision |
| P-N2 | Checksum validity oracle (`prop_tests/oracle.rs`): a test-local full recompute — `checksum16` over the IP header (v4), `checksum16_ipv4`/`checksum16_ipv6` pseudo-header over the L4 segment with checksum field zeroed — compared against stored values, treating 0x0000/0xFFFF as the defined-equal pair where the protocol permits both. **NOT** `verify_built_frame_checksums`: that helper early-returns `(true, true)` for everything except IPv4 TCP (frame/mod.rs:1129–1131 "Only handle IPv4 TCP for now") and would make the v6/UDP arms vacuous (Codex r1 finding 1). Asserts: incremental `adjust_l4_checksum_*` deltas equal ground truth; UDP/v4 zero-checksum stays zero (RFC 768); UDP/v6 stored checksum never 0x0000 | valid packets × arb NatDecision |
| P-N3 | **Differential, descriptor vs generic — success cases**: build the same valid TCP/UDP frame (TTL ≥ 2, v6 UDP checksum non-zero, **v6 WITHOUT extension headers** — the generic v6 NAT path hardcodes L4 at offset 40 (§10-D D3) so ext-header × NAT inputs diverge outside checksum bytes; they are excluded here and pinned by one deterministic D3 example documenting current behavior) into two `MmapArea`s; apply the generic path (`rewrite_forwarded_frame_in_place`) and the descriptor path (`apply_rewrite_descriptor`, deltas from `compute_l4_csum_delta` exactly as flow_cache.rs:339 builds them), both with `expected_ports = None` (the two paths check expected ports at different pipeline points — descriptor pre-NAT as a DMA-race guard at rewrite/ipv4.rs:36, generic post-NAT via `enforce_expected_ports` at frame/mod.rs:526 — so port-mismatch inputs are NOT differential-comparable; Codex r1 finding 2); assert both succeed and the frames are **byte-identical except ALL checksum fields (v4 IP header checksum + L4 checksum)**, with every checksum passing the P-N2 oracle. The L4 exclusion is forced by two review-discovered production divergences documented in §10-D (rewrite/ipv6.rs:98 canonicalizes 0→0xFFFF for ALL v6 protocols vs generic UDP/ICMPv6-only at checksum.rs:88; frame/mod.rs:906's UDP `current == 0` skip is not family-gated). The v4 IP-header exclusion is the RFC 1624 zero-representation ambiguity (SMR r2): both paths are incremental, but the descriptor folds `!old + rd.ip_csum_delta + 0xFEFF` in one pass (rewrite/ipv4.rs:79–91) while the generic chains three `checksum16_adjust` calls with intermediate refolds (checksum.rs:291–312); end-around-carry totals ≡ 0 (mod 0xFFFF) can surface as 0x0000 in one path and 0xFFFF in the other (~2⁻¹⁶ of inputs — exactly the kind of case shrinking gravitates to). Validity-oracle-on-both is strictly the right contract; byte-equality on checksum fields is not a property the code promises | valid packets × arb NAT |
| P-N3b | Decline conditions as **deterministic example tests**, not properties — asserting **bytes from the L3 offset onward are untouched** (NOT the whole frame: both paths write the Ethernet/VLAN header during `rewrite_prepare_eth*` BEFORE TTL/port validation — frame/mod.rs:403/413, called from mod.rs:581 and rewrite/mod.rs:56 — so a declined frame legitimately carries a rewritten L2 header; harmless in production because the caller drops the frame on `None`; Codex r2 finding 2): (a) TTL/hop-limit ≤ 1 → BOTH paths return `None` with L3+ untouched (the v1 claim "generic is the only writer" was wrong — frame/mod.rs:495 declines too); (b) descriptor port-mismatch (expected_ports set, frame differs) → descriptor `None`, L3+ untouched by it; (c) `rd.nat64`/`rd.nptv6` → descriptor `None` at rewrite/mod.rs:55 (before prep — frame fully untouched in this one case), and note the flow cache never builds descriptors for them anyway (`should_cache` gates at flow_cache.rs:223–224); (d) **D3 pin**: one v6+hop-by-hop+port-NAT example documenting that the generic path currently writes at offset 40 (ext-header bytes) — marked as pinning a defect, referencing the D3 issue | fixed examples |
| P-N4 | Payload immutability: bytes after the L4 header are untouched by either path | valid packets × arb NAT |

**S3 — state encode: DROPPED in v2** (Codex r1 finding 5 + AGY r1 Q4 + SMR
r1 Q4, unanimous). Three independent reasons: (1) §4.2 — the premise was
wrong; `state_writer.rs` is a persister, there is no Rust decode
counterpart; (2) the proposed `== x` round-trip does not even compile —
`ConfigSnapshot` derives `Clone, Debug, Serialize, Deserialize, Default`
with **no `PartialEq`** (protocol/snapshot.rs:182), and adding one for tests
would be a production-type change this plan forbids; (3) the schema is
already pinned by Go-side contract tests
(pkg/dataplane/userspace/cold_path_status_test.go) and the existing
example round-trips (main_tests.rs:906/1432). A plain `StateWriter::persist`
read-back unit test remains a legitimate ordinary-test follow-up outside
this harness's scope (§10). The convergence comment on #1824 must state that
the issue-title surface "state_writer encode" is descoped and why.

**S4 — TCP segmentation** (`frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`,
pure: `&[u8] → Option<Vec<Vec<u8>>>`; needs only a fixture `ForwardingState`
for the MTU lookup and a `SessionDecision`):

| ID | Property | Inputs |
|----|----------|--------|
| P-T1 | No panic for garbage frames × arbitrary meta × fixture forwarding state | garbage |
| P-T2 | Reassembly identity: when `Some(segs)`, concatenating per-segment TCP payloads == original TCP payload | valid oversized TCP packets (payload 1×–4× MTU, MTU ∈ 1280..9216, TCP options 0..40B, v4 IHL 20..60) |
| P-T3 | Per-segment wellformedness: every segment ≤ eth_len+MTU; `seq_i == orig_seq.wrapping_add(cumulative_offset)` (incl. seq wrap near u32::MAX); PSH cleared on all but last; SYN/FIN/RST never present (precondition gate at :69 declines them — asserted as `None`); IP total-length/payload-length fields consistent; per-segment IP + L4 checksums verify via the **P-N2 test-local oracle** (not `verify_built_frame_checksums` — v4-TCP-only, see S2); segment count == `ceil(payload/segment_max)` | same |
| P-T4 | NAT composition: with a NAT decision in the `SessionDecision`, every segment carries the rewritten tuple and valid checksums (composes S2's oracle). v6 inputs ext-header-free (the splitter calls `apply_nat_ipv6` which assumes L4 at 40 — same D3 constraint) | same × arb NAT |

The UMEM-coupled twin (`tx/tcp_segmentation.rs::…_into_prepared`) is **out of
scope** (needs a `BindingWorker` + tx_pipeline harness); the twin-drift risk
is recorded as a candidate follow-up in §10, not silently absorbed.

### 5.4 CI / runtime budget

- Config: every property uses an explicit
  `ProptestConfig { cases: N, max_shrink_iters: 4096, .. }`. N = 512 for
  cheap parse properties (P-I*), 256 for S2/S4 (packet build + dual rewrite +
  full-recompute oracle per case), 128 for P-N3 (two MmapAreas per case),
  Measured target: **≤10s added to `cargo test --release`
  wall-clock total**; if a property exceeds ~2s at these counts, the count is
  halved and the halving justified in the test header comment.
- Failure-path cost is different and unbounded-ish by design: a failing
  P-N3 case can spend `max_shrink_iters` × (2 mmaps + dual rewrite) ≈
  low minutes shrinking before it reports. That cost is paid only on a real
  counterexample (or a property bug) and buys a minimal repro; it is
  accepted, not hidden.
- Determinism, stated precisely (Codex r1 finding 6): **passing runs use a
  fresh random seed each run** — that is the point (continuous exploration);
  what is deterministic is (a) the committed
  `proptest-regressions/**/*.txt` corpus, replayed FIRST on every run, which
  is the actual regression-pinning mechanism, and (b) the fixed case counts.
  We do not fix the run seed. Generation logic itself is pure (no
  time/env-dependent strategies).
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
gains a short "property tests" section describing the `prop_tests/` module
and the regression-corpus convention (module-doc contract per CLAUDE.md).

## 7. Hidden invariants the change must preserve

- **No `cargo fmt` over existing files** (#1769 gotcha) — new files are
  formatted in isolation; includes in `frame/mod.rs`/`main.rs` are 3-line
  appends.
- **Miri lane stays green** — `cfg(all(test, not(miri)))` on all prop
  modules (§5.2); miri must not crawl proptest case loops.
- **`debug-log` feature build stays green** — P-N3 calls paths that contain
  `cfg!(feature = "debug-log")` checksum verification; tests must pass both
  with and without the feature (`make build-userspace-dp-debug-log` parity).
- **Test determinism under parallel `cargo test`** — no shared state across
  prop tests; no reliance on thread-local debug counters.
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
4b. Coverage spot-check (manual, documented in PR): one `cargo llvm-cov`
   run over the prop tests showing the IPv6 ext-header arms 43/51/44/59 in
   `frame_l4_offset`/`packet_rel_l4_offset` executed (Codex r1 finding 4 /
   AGY r1 Q3 acceptance evidence). Not wired into any gate.
5. Standard repo gates: `make build`, `make test` (Go suite unaffected),
   `make audit-check`.
6. No smoke/cluster run needed (test-only, no dataplane artifact change) —
   consistent with the batch-smoke policy for non-runtime PRs.

## 10. Out of scope (explicitly)

### §10-D — Review-discovered production divergences (documented, NOT fixed here)

Round-1 review surfaced two real behavioral divergences between the
descriptor fast path and the generic NAT path. This plan documents and
test-accommodates them (P-N3's checksum-byte exclusion); it does **not**
change production code. Each gets a small standalone issue filed at
implementation time so the divergences are owned, not buried in a test
comment:

- **D1 — v6 zero-checksum canonicalization scope**: rewrite/ipv6.rs:96–98
  maps a computed 0x0000 L4 checksum to 0xFFFF for ALL v6 protocols
  (including TCP), while the generic policy (`adjust_zero_checksum_illegal`,
  checksum.rs:85–90) canonicalizes only UDP/ICMPv6. Both encodings are valid
  one's-complement zero, so this is wire-harmless, but it breaks bit-exact
  path equivalence. (AGY r1 finding 1, Codex r1 finding 1.)
- **D2 — family-ungated UDP zero-checksum skip on port rewrite**:
  `adjust_l4_checksum_port` (frame/mod.rs:~906) skips the checksum update
  when `protocol == UDP && current == 0` without checking address family;
  the comment says "optional for IPv4 UDP" but v6 UDP (where 0 is
  malformed input) takes the same skip, while the descriptor path applies
  its delta. Only reachable on malformed input; the harness's valid-packet
  generators never emit v6 UDP checksum 0, and one deterministic example
  pins current behavior. (AGY r1 finding 2.)
- **D3 — generic v6 NAT path assumes L4 at fixed offset 40**: the worst of
  the three — affects VALID traffic, not just representation or malformed
  input. `apply_nat_ipv6` rewrites ports via
  `apply_nat_port_rewrite(packet, 40, protocol, nat)` (frame/mod.rs:840–841,
  comment "IPv6 header is always 40 bytes (no IHL)"), and both generic v6
  checksum adjusters compute `checksum_offset = 40usize.checked_add(delta)`
  (`adjust_l4_checksum_ipv6_words` checksum.rs:490,
  `adjust_l4_checksum_ipv6_addr_bytes` checksum.rs:516–517). The caller
  `rewrite_apply_v6` parses the REAL ext-header-aware `rel_l4`
  (frame/mod.rs:550–555) but only uses it for tuple restore — then hands the
  packet to the 40-assuming helpers. The descriptor path parses real offsets
  (rewrite/ipv6.rs:35–41). Consequence: a valid IPv6 packet with any
  extension header that takes the generic NAT path gets its first
  ext-header bytes overwritten (port rewrite) and/or a non-checksum word
  "adjusted". Reachability (does NAT66/SNAT-v6 traffic with ext headers
  reach this path in production?) is assessed in the filed issue, not here.
  (Codex r2 finding 1; blast radius extended to the checksum adjusters by
  Claude verification.)

### Deferred / rejected

- **cargo-fuzz / coverage-guided lane** — rejected for now (§5.1); revisit
  only if a lib split lands for independent reasons.
- **Session-table install/lookup/delete stateful property** (#1669 §12's
  third bullet) — needs proptest-state-machine or model-based testing
  against `SessionManager`; different harness class, different blast
  radius; file separately if wanted.
- **`tx/tcp_segmentation.rs::…_into_prepared`** and a differential test
  against its pure twin — blocked on a `BindingWorker`/tx_pipeline fixture;
  candidate follow-up issue.
- **S3 / state encode** — dropped in v2 (see §5.3-S3 tombstone); an
  ordinary `StateWriter::persist` read-back unit test is a legitimate
  follow-up outside this harness.
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

The convergence comment on #1824 must enumerate which #1669 §12 bullets this
plan does NOT deliver (session-table stateful property; cargo-fuzz lane) so
the umbrella residue stays honest (SMR r1 F5).

## 11. Open questions for adversarial review (PLAN-KILL invitable on each)

### Resolved in round 1 (all three reviewers)

- ~~Q1 worth it?~~ — Codex: "Worth it after revision for S1/S2/S4; not
  PLAN-KILL." AGY: "highly valuable… permanent regression guards." SMR:
  architecture sound. Resolved: proceed with S1/S2/S4.
- ~~Q2 P-N3 sound?~~ — No as v1.1-written; re-specified in v2 (success-only
  differential, expected_ports=None, L4-checksum bytes excluded, oracle
  replaced, declines → examples). D1/D2 divergences documented in §10-D.
- ~~Q3 generator reach?~~ — structured `arb_v6_ext_chain()` is primary;
  llvm-cov spot-check is acceptance evidence (§9 step 4b).
- ~~Q4 S3?~~ — dropped, unanimous (also: would not compile — no PartialEq).
- ~~Q5 regressions policy?~~ — commit them; RNG-determinism wording fixed;
  only minimal shrunk failures checked in.
- ~~Q6 layout?~~ — `frame/prop_tests/` directory module.

### Resolved in round 2

- ~~Q1 (r2) divergence outside excluded bytes?~~ — YES, Codex r2 constructed
  it: v6 ext-headers × port NAT (generic path hardcodes L4 at 40). Verified
  in source, blast radius extended to the checksum adjusters; recorded as
  §10-D D3; NAT-applying generators restricted to ext-header-free v6. AGY
  r2's contrary "provable, identical write helpers" answer was refuted by
  this counterexample.
- ~~Q2 frame-diff mask?~~ — Codex: add explicit mask (cheap, unambiguous);
  AGY: P-N1+P-N4 suffice. Resolution: implement P-N1/P-N3 comparisons via
  one shared explicit byte-mask helper in `prop_tests/oracle.rs` (Codex's
  position — it costs ~20 LOC and makes the excluded-byte set auditable).
- ~~Q3 D1/D2 document-and-file?~~ — both reviewers: yes, with Codex's
  condition that the new D3 class be excluded from P-N3 (done in v3).
- ~~Q4 budget?~~ — both: counts fine given structured ext-header weighting +
  llvm-cov spot-check.
- ~~Q5 kill?~~ — Codex: "Not PLAN-KILL overall"; AGY: "highly valuable".

### Open for round 3 (final convergence check)

1. Does v3 correctly and completely fold Codex r2's two findings (D3
   exclusion + L3+-only decline assertions)? Any remaining valid-input
   divergence inside the v3-restricted generator domain (v4 any-IHL,
   ext-header-free v6, TTL ≥ 2, valid checksums, `expected_ports=None`)?
2. Anything else blocking PLAN-READY? PLAN-KILL remains acceptable.
