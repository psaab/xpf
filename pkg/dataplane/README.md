# pkg/dataplane

> Deprecation notice (#1373): the legacy eBPF backend in this package is being
> retired in favor of the Rust AF_XDP userspace dataplane. Phase 1 updates
> active docs and migration targeting only; no BPF source, loader code, or
> bindings are removed in this phase.

Abstract dataplane interface plus the legacy eBPF backend. Compiles the typed
config from `pkg/config` into BPF-map entries (zones, policies, NAT,
filters, applications), attaches the 14 BPF programs (9 XDP + 5 TC), and
exposes session iteration to GC, the CLI, and the metrics surface.

Pluggable: the legacy eBPF backend registers through `RegisterBackend` for
the old `DataPlane` surface (DPDK retired #1525; removed in #1527/#1528).
Runtime backends register through `RegisterRuntimeBackend`; daemon startup now
selects `userspace.Boot()` directly for the default and explicit userspace
paths and falls through to `NewRuntimeDataPlane` for every other effective
type. Today the operator-facing cases on that branch are the explicit legacy
eBPF rollback and retired-DPDK sentinel; unknown/custom types still surface the
legacy factory's error path verbatim. During the #1381 migration, the userspace
runtime constructor returns `LegacyDataPlaneAdapter`: the userspace `Manager`
itself still does not implement the BPF-shaped `DataPlane`, but daemon status,
CLI, and cluster-sync callers that have not moved to domain interfaces still
receive a temporary compatibility handle.

DPDK retirement (#1525): the historical #1475 policy that retained DPDK as
a separately supported DPDK-build backend is no longer in force. The
`pkg/dataplane/dpdk` bridge, the `cmd/xpfd/main.go` blank registration
import, and the canary allowlist entries were removed in #1527/#1528. The
[`docs/pr/1373-retire-ebpf-dataplane/README.md`](../../docs/pr/1373-retire-ebpf-dataplane/README.md)
"DPDK Backend Retired (#1525)" section now describes the remaining
Phase 1 reject machinery (commit-time `ErrDPDKDataplaneRetired`,
`TypeDPDK` sentinel, runtime `ErrDPDKBackendRetired`) which is kept
for one release cycle to preserve the operator-friendly migration
message for stored-config rolling upgrade.

The userspace backend's status wire format is mirrored here for CLI/API
consumers. CoS queue status includes queue-scoped drain-phase counters so
operators can separate guarantee bytes, surplus bytes, and non-exact bytes
sent while exact queues were still backlogged.


### Proving the shim/userspace parity guards actually bind

`userspace-xdp/src/ipv6_ext_walk.rs` is guarded by
`test/mutation/shim-ext-parity-acceptance.sh`, not by `make test` alone. The
script mutates the walk across 16 mutation rows plus one negative control,
bracketed by a green baseline (row 0) and a post-restore recheck, and requires
the parity guards in
`userspace-dp/src/afxdp/frame/tests_shim_ext_parity.rs` to red on each edit. It
prints per-row accounting at the end, so the evidence quoted in a PR body is
checkable against the matrix rather than against a bare `PASS`.

One mutation per row, and one ARM per row where an edit applies to several: a
row that mutated the GENERIC and AUTH revalidation bases together scored RED on
either arm reding, so it could not support the claim about both that its label
made.

Rows 1-11 perturb an arm UNIFORMLY. Rows 12-15 are keyed on a SINGLE data value
— `+8` only at `HdrExtLen == 4`, `+4` only at AH `HdrExtLen == 2`, Fragment
advancing 7 only when `reserved != 0`, and the carried next-header UDP
propagated as TCP. Each changes real packet classification and each was GREEN
before the corpus gained its exhaustive dimension sweeps, because the corpus
sampled 5 of 256 generic declared lengths, 3 of 256 AUTH ones, one value of the
Fragment `reserved` byte, and declared TCP as the terminal in every single
chain. A uniform-mutation matrix cannot find that class; only closing the
dimension can. Row 16 is the same shape in a different axis — the post-advance
revalidation skipped only for Routing(43) — and was green while the generic
arm's eight next-header values shared one boundary witness between them.

Run it whenever you change that walk. `make test` tells you the guards are
green; it does not tell you they still bind, and this file has a history of the
difference mattering: an earlier build gate used `cargo build --release`, which
never compiles the `#[cfg(test)]`-only parity module, so a deliberate syntax
error produced `BUILD rc=0 TEST rc=101` and was scored as "the guard fired".

Two preflights run first and must themselves fail when broken — one proves the
build gate really compiles the file under test, one proves a filter matching
nothing is scored MISSING rather than `ok` (`cargo test` exits 0 on a filter that
matches no test).

The baseline is VERIFIED BEFORE IT IS CAPTURED, and an unverifiable baseline
ABORTS. Three ways that used to fail open, all reproduced:

* The gold copy was taken at the top of the script and git consulted 138 lines
  later, so on a tree git could not speak for, the mutation had already become
  the baseline. Replayed against an archive with no `.git`, the script printed
  `UNVERIFIED` and ran every row against a `(len+1)*8 -> (len+1)*16` mutation
  installed as "pristine", then "restored" it at the end.
* "Not a git work tree" was a WARNING. It is now `ABORT` — a harness whose whole
  subject is probes that report success without observing anything cannot make
  an exception of itself.
* `git diff` believes the INDEX for a path flagged `assume-unchanged` or
  `skip-worktree`, so it never stats the file. `git update-index
  --assume-unchanged` flipped `diff --quiet HEAD` from rc 1 to rc 0 with the
  mutation still on disk, and the check reported "matches git HEAD (index
  included)". The `ls-files -v` tag must now be `H`.

The comparison is against `HEAD`, index included; comparing against the index
alone let a STAGED mutation be captured as the pristine gold copy and restored
as such.

Scope of that check, precisely: exactly one path, `ipv6_ext_walk.rs`, because
that is the file the script overwrites. The guard tests and the negative
controls are NOT compared against git — they are covered behaviourally, by
row 0 (green on the unmutated tree) and the NEG-CTL row (a semantically null edit must
SURVIVE). Neither is a claim that the working tree matches `HEAD`.

The corpus builder also carries non-vacuity floors. The assertions that CONSUME
the corpus are of the form "this collection is empty" or "the loop visited every
(offset, case) pair", and both hold trivially on an empty corpus — the guards
that read the manifest's emitted facts, and both negative controls, do not
consume it and are unaffected. (The coverage half used to be
`compared == cases * offsets`, which was tautological: the counter incremented
inside the loops it claimed to measure, so any edit that skipped a case skipped
its increment too. It is now a visited set of `(l3, name)` pairs recorded AFTER
each comparison, checked against a cross product built independently from the
two inputs, plus a distinct-names assertion so the set cannot collapse two cases
into one.)

Those floors are named per SHAPE — per-arm boundary witness pairs, the
chain-length boundary, the next-header sweep, the long-chain shape, the L3
offsets, and each remaining named corpus BLOCK — and not as one size threshold,
because a size threshold did not bind:
a single `cases.len() >= 200` stood there while 256 of the ~310 cases came from
one homogeneous next-header sweep, so cutting the corpus down to that sweep AND
deleting the generic arm's post-advance bounds revalidation was measured to
leave all five tests `ok`.

Naming the shape is not enough either. The replacement floors counted CASES
SATISFYING A PREDICATE, and three of the five predicates had degenerate
satisfiers: a 40-byte packet declaring an arm "fails closed" without ever
reaching that arm's boundary, one `DestOpt(len=6)` header lands on the same
terminal offset as a seven-header chain, and a seven-byte buffer carries a
next-header byte neither walker ever classifies. So each floor now binds its
shape by CONSTRUCTION — the corpus must contain a locally rebuilt reference
buffer, byte for byte — and, where the shape is behavioural, by MEASUREMENT
with this crate's walker. The per-arm floor requires a WITNESS PAIR: the padded
twin must resolve the terminal at exactly the advance target (proving the
boundary was reached) and the tight twin, one byte shorter, must fail closed
(attributing the refusal to the length check). The tight twin's fail-closed is
the failure DEFAULT of the reference walker, so it is only attributable once the
twin is asserted to be the padded one minus exactly its last byte — otherwise a
generator that made the two differ in a header byte as well as in length would
satisfy the pair while isolating nothing.

"Per-arm" was also per-arm-MEMBER coverage of exactly one member. Eight
next-header values enter the shim's single GENERIC `match` arm and share its
advance and its post-advance revalidation, but only DestOpt had a boundary pair
— so a revalidation skipped when `protocol == ROUTING` was a fail-open of
precisely the shape that pair exists to catch, invisible to it, and invisible to
the 256-value sweep as well (those buffers carry 20 bytes of slack past the
advance target, and only a packet ENDING at or before the target can observe a
missing bounds check). Every generic member now carries a pair, and the check is
stated over EVERY ADVANCING ARM rather than over the arm the defect was found in
— naming GENERIC and stopping there would repeat the mistake one level up. The
membership is enumerated by asking the reference walker to classify all 256
next-header values: GENERIC has 8 members (0, 43, 60, 135, 139, 140, 253, 254),
AUTH exactly 1 (51), FRAGMENT exactly 1 (44), so GENERIC was the only arm that
could carry the defect — but that is an OUTPUT of the loop, not an assumption in
it, and a ninth value added to any advancing arm reds. `NoNextHeader` (59) and
the 244 terminal values are excluded on purpose: they neither read nor advance,
so there is no bound to weaken and a boundary pair would witness nothing; their
property is bound by the 256-value sweep and the classification negative
control. The acceptance matrix carries the one-member mutation as its own row.

**A witness pair is worth its error FAMILY, and no more.** The pair's derivation
— an error `a*l + b` vanishing at two distinct declared lengths is identically
zero — is a statement about errors AFFINE in the declared length, and nothing in
the corpus enforces that premise. `+ 8` only when `HdrExtLen == 4` is not
affine, is a real classification regression, and vanishes at both witnesses and
at every one of the 251 declared lengths the corpus did not sample. A seventh
floor therefore sweeps four dimensions COMPLETELY: generic declared lengths,
AUTH ones, all 256 values of the Fragment `reserved` byte (that arm has no
declared length, so a byte neither walker reads is the analogous hiding place),
and all 256 values of the next-header an extension header CARRIES. Presence is
not enough for the first three — 256 buffers that all fail closed would satisfy
it — so each value is also measured to resolve its terminal at that arm's own
advance target.

**One of those four is JOINT and three are MARGINAL, and the difference is part
of the claim.** A marginal sweep of A with B held fixed says nothing about an
error conditioned on A *and* B — the same shape, one level up, as the
non-affine error two witnesses could not see. 256⁴ is not enumerable, so the
design covers the four marginals plus the one pair the arm's own code makes
reachable: the generic sweep is joint over (entering next-header × declared
length), 8 × 256 = 2048 cases, because the entering value selects the `match`
arm while `opt[1]` feeds its advance. Explicitly NOT covered: (declared length ×
carried next-header), which is 256 × 256 = 65536 buffers of up to 2 KB and was
judged not worth the corpus; every 3-way combination; and an arm reached as a
LATER header, since every sweep case is a single extension header at offset 40.
An error keyed on `opt[0] == 17 && opt[1] == 4` survives this floor. What
measures whether that gap matters is the acceptance matrix, not a bigger corpus.

Nor do the five shape floors SUBSUME a coverage floor, which is what deleting
the old `handcrafted >= 40` count assumed. Between them they require ten
boundary buffers, the two chain-length twins and the two long chains — 14
hand-written cases before the 256-value sweep — so the intermediate chain
lengths, the varied declared lengths, the truncation block, the minimal per-arm
packets, the non-first fragments, the AH sweep and the #4517 Mobility cases
could all be deleted with every floor green. Measured: dropping the ten
varied-length HbH cases and the ten truncation cases takes the hand-written
count 55 -> 35, which the old count floor caught and none of the shape floors
does. A sixth floor now binds the BLOCKS themselves — each named category
rebuilt locally and required in the corpus in full, so deleting a category names
that category in the failure. Not restored as a count: the old threshold was
arbitrary, and a count has degenerate satisfiers.

The floors' reference buffers are built by `expect_chain`, deliberately NOT by
the corpus's own `chain` generator. Rebuilding with `chain` and then looking the
result up in a corpus `chain` produced is circular at the level of the
generator: making `chain` write TCP at byte 6 for every one-header input
collapses the 256-value sweep to a single distinct next-header value, no verdict
moves on either walker, and the floor still reports 256 present. The
cross-walker comparison catches a unilateral misclassification; it cannot catch
a common-mode change to the inputs both walkers are fed. The next-header floor
additionally reads back the value each corpus buffer CARRIES at byte 6 and
requires 256 distinct ones.

A floor is worth its predicate, never the prose beside it, so each one also
states what it does NOT cover. They stop a shape being deleted between
acceptance runs; they do not establish that the corpus is adequate, which is
what the matrix above measures.

The parity file also states, as a list rather than as an example, everything it
asserts about the shim rather than runs: `parse_l2`'s L3 offsets, `parse_ipv6`'s
arguments to the walk, `parse_l4`'s catch-all (which the `OverLimit` fold rests
on), and the manifest-to-object relationship. The shim crate is `#![no_std]`
over `aya-ebpf` and does not build for the host — `cargo build --target
x86_64-unknown-linux-gnu` fails with "unwinding panics are not supported without
std" — so its entry points cannot be executed from that test binary at all. An
accurate list of what is asserted is worth more than naming one item, which
reads as a claim that the rest are covered.

Note `ipv6_ext_walk.rs` is a hashed input of `userspace_xdp_manifest.json`, so
even a comment edit there requires `make generate` and trips
`TestUserspaceXDPShimObjectMatchesSourceManifest` until you do. That is why this
pointer lives here rather than in the file it describes.

## Shim artifact: pinned toolchain + verifier gates (#1864)

`userspace_xdp_bpfel.o` (the retained Rust AF_XDP shim, built from
`userspace-xdp/`) is **git-tracked and embedded into xpfd via
go:embed** — it is the deployable artifact. `make build` never needs
`make generate`; only regenerate when `userspace-xdp/` source changes.

Why this is guarded: on 2026-06-10 a `make generate` with a drifted
Rust nightly produced an object that exceeded the kernel verifier's
1M processed-insn cap (`BPF program is too large. Processed 1000001
insn`) and put BOTH HA cluster nodes into config-only mode. The
upstream rustc/LLVM change in (nightly-2026-05-23, nightly-2026-05-27]
altered `u64::saturating_sub` lowering in a way that defeats verifier
state pruning; a year-old nightly fails differently — the safe
toolchain set is an interval, so the build pins the toolchain AND
verifies every candidate empirically.

Guard layers (`build-userspace-xdp.sh`):

1. **Toolchain pin** — `userspace-xdp/rust-toolchain.toml` is the
   single source of truth (`channel = "nightly-YYYY-MM-DD"` +
   rust-src). The script parses it strictly (exactly one channel key
   in `[toolchain]`, format-validated) and refuses to build with a
   missing toolchain, printing the exact `rustup toolchain install`
   line. bpf-linker is version-pinned too (it embeds its own LLVM);
   the script version-checks the exact PATH-resolved binary cargo
   executes.
2. **Verify-then-install** — the cargo output is loaded through the
   real kernel verifier (`cmd/shimverify`: anonymous maps, no pins,
   no attach, plus the same `validateUserspaceShimSpec` checks the
   daemon runs) BEFORE the tracked `.o` is touched. REJECT or missing
   privileges (root / passwordless sudo) ⇒ tracked object untouched,
   nonzero exit, actionable message. There is no unverified-install
   path. `RUST_BPF_TOOLCHAIN=...` overrides the pin for bisects, but
   installing an unpinned object additionally requires
   `XPF_SHIM_ALLOW_UNPINNED_INSTALL=1`.
3. **Deploy pre-flight** — `xpfd verify-dataplane` runs the same
   verify-only load against the object embedded in the invoked
   binary (exit 0 PASS / 3 verifier REJECT / 1 other).
   `test/incus/cluster-setup.sh deploy_vm()` pushes the new binary to
   a temp path and runs this BEFORE stopping the old daemon — a
   REJECT refuses the deploy with the old dataplane still forwarding.

   The shared `validateUserspaceShimSpec` gate this runs also performs
   an **ABI compatibility check** (#5307): for every required pinned map
   it compares the embedded shim's `Type`, `KeySize`, `ValueSize`,
   `MaxEntries`, and `Flags` — the exact fields cilium/ebpf's
   `MapSpec.Compatible` flags with `ErrMapIncompatible` at load —
   against BOTH the Go-side expected shape (dnat_table and dnat_table_v6,
   from `userspaceShimSharedMapSpecs`) AND the RUNNING daemon's **live
   pinned maps** (read-only via `ebpf.LoadPinnedMap` + shape
   accessors). The ABI-checked inventory (`userspaceABICheckedPinnedMaps`)
   is the UNION of the shim-declared PinByName maps
   (`userspacePinnedShimMaps`) AND the Go-created/replaced shared maps
   (`userspaceShimSharedMapSpecs`) — deduplicated — matching the
   required-pins set (`userspaceRequiredShimPins`). Before #5484 it
   covered only the PinByName group, so state-bearing shared maps the
   shim does NOT declare — `sessions_v6`, `dnat_table_v6`, and the HA /
   per-CPU maps (`rg_active`, `ha_watchdog`, `session_id_gen`, the
   `*_counters`) — were never pre-flighted: an incompatible live pin for
   one of them passed a green pre-flight and then failed
   `ErrMapIncompatible` in `loadUserspaceShimSharedMaps` AFTER the old
   daemon was stopped, stranding the node. Because this runs while the
   old daemon is still up (its pins live), an ABI-incompatible map is
   now caught HERE and the deploy is refused — instead of the pre-#5307
   behavior where a green pre-flight let the deploy proceed, the old
   daemon was stopped, and the new daemon's `NewCollectionWithOptions`
   (or the shared-map load) then failed `ErrMapIncompatible`, stranding
   the node fail-closed (config-only). A map with no pin yet (fresh
   node / first load) skips the live-pin arm — only the expected-value
   checks apply, so a clean node never false-fails. The disposable
   counter map `userspace_fallback_stats` is intentionally excluded:
   `reconcileDisposableCollectionPin` resets it on an intended shape
   change (#4113), so ABI-checking it here would re-brick that upgrade.

   **Remediation message split (#5363):** the two ABI arms print
   *different* operator guidance because they diagnose different faults.
   An **embedded-vs-Go-SSOT drift** (`validateUserspaceShimSpecWith`
   expected-shape arms + `validateSharedMapExpectedABI` +
   the `userspace_bindings`/`userspace_ingress_ifaces` drift errors) means
   the embedded shim binary drifted from its Go-side source contract, so
   it prints `userspaceShimGenerateRemediation` — "Re-run `make
   generate-userspace-xdp`." A **live-pin mismatch**
   (`validateUserspaceShimLivePins`) is the OPPOSITE situation: it compares
   this build's embedded shim against the RUNNING (old) daemon's pinned
   map, so the pin is ALWAYS the stale side. The embedded shim is the
   intended, un-broken target, so `make generate` is the WRONG action;
   instead it prints `userspaceShimStalePinRemediation`, which directs the
   operator to unlink the ONE named pin
   (`docs/operations/userspace-shim-pin-recovery.md`) and then start xpfd. A
   rolling deploy cannot cross a genuine shim-map ABI change while the old
   pin is still present, because the new map can only be pinned after the
   stale one is released.

   **Whether a restart releases the pin is MODE-DEPENDENT**, and this text
   has been wrong in both directions (#6928). It first said "a reload"
   releases it — nothing does. It then said restarting NEVER releases it and
   only `xpfd cleanup` does — also false. A bpffs pin outlives the process
   that created it, so releasing it means UNLINKING it, which is `Cleanup()`
   in `loader.go` doing `os.RemoveAll(bpfPinPath)`. `Cleanup()` has TWO
   production callers: the `xpfd cleanup` subcommand (`cmd/xpfd/main.go`)
   **and** `Manager.Teardown`. `daemon_run_shutdown.go` calls `Teardown` on
   every NON-hitless shutdown ("HA shutdown: tearing down BPF state"), so on
   that path the pins are already gone and a plain restart suffices. Only a
   HITLESS shutdown takes `Manager.Close`, which preserves the pins
   deliberately — that is the path where a restart hits the identical
   refusal, mid-upgrade, with the dataplane down.

   `xpfd cleanup` also clears it, but it is a much broader hammer: it
   removes EVERY pinned dataplane map (sessions, DNAT, all compatibility
   state) and clears the FRR managed routes. Name the targeted unlink first.
   `TestCleanupProductionCallersMatchRemediation_6928` binds the reference set
   this paragraph describes, so it cannot drift again without a red test. Since
   #6743 `Manager.Teardown` reaches `Cleanup` INDIRECTLY, through the
   `teardownCleanupFn` seam var, so that test reports the var rather than
   `Teardown` and `TestTeardownInvokesTheCleanupSeam_6928` binds the half a
   function-value reference cannot: that Teardown still invokes it.

   **CPUMAP MaxEntries is CPU-sized, not a stale-pin signal (#5364):**
   `userspace_cpumap` is a `BPF_MAP_TYPE_CPUMAP`. The shim declares it as
   `CpuMap::with_max_entries(256, 0)` — a template MAX — but cilium/ebpf's
   `MapSpec.fixupMagicFields` clamps a CPUMAP's `MaxEntries` to
   `nr_possible_cpus` before it creates OR ABI-compares the map, so a fresh
   daemon ALWAYS pins it at `nr_possible_cpus` (16 on the loss VMs), never
   256. Because `MapSpec.Compatible` (the exact `ErrMapIncompatible` check
   this pre-flight predicts) runs the identical clamp, the real PinByName
   load compares `nr_possible_cpus == nr_possible_cpus` and succeeds. The
   pre-flight therefore resolves the reference `MaxEntries` through
   `livePinRefABI`, which applies the same clamp for a CPUMAP — so the old
   "`cpumap=16` pin vs embedded `cpumap=256` shim" diff (mischaracterized as
   a stale 16→256 ABI bump, which false-rejected EVERY rolling
   cluster-deploy) is no longer produced. The relaxation is scoped to the
   `MaxEntries` axis of the CPUMAP only: no other ABI-checked shim map is
   CPU-count-sized (per-CPU ARRAY/HASH maps keep their declared `MaxEntries`
   and replicate the VALUE per-CPU; XskMap keeps its declared size), so every
   other map keeps a strict `MaxEntries` check, and a genuine cpumap
   Type/KeySize/ValueSize/Flags break still yields the stale-pin
   remediation (`userspaceShimStalePinRemediation`). Since #6928 that
   constant is the TARGETED single-pin unlink plus a mode-dependent note
   on restart — NOT a "full reload". Nothing in the product reloads a
   bpffs pin: a pin outlives the process that made it, so "full-reload"
   was only ever a label for the constant, never an instruction an
   operator could follow.

   **Residual (documented, not caught here):** a *same-size* Go/Rust
   value **field reorder** — identical `KeySize`/`ValueSize`/`Type`/
   `Flags` but a different field layout — is invisible to this
   spec-level ABI comparison (and to `ErrMapIncompatible` itself). That
   class stays covered by the build-time kernel-verifier gate above +
   the cross-language struct-parity tests (`bpf/headers/*.h` vs the Go
   mirrors and the userspace-dp parity tests), NOT the deploy
   pre-flight.
4. **Tests** — root-gated `TestVerifyEmbeddedUserspaceShim` catches a
   bad tracked artifact in privileged `make test`;
   `TestVerifyUserspaceShimShrinkEquivalence` proves the verify-only
   hash-map MaxEntries shrink (memory hygiene for live-node
   pre-flights) never changes the verifier verdict, using the
   preserved incident object in `testdata/`. The #5364 cpumap
   CPU-count-clamp handling is covered by
   `TestCPUMapLivePinPossibleCPUAccepted` (a CPU-sized cpumap live pin is
   accepted, not false-rejected), `TestCPUMapLivePinGenuineBreakStillRejected`
   (a genuine cpumap ValueSize break is still rejected), and
   `TestNonCPUMapMaxEntriesStillStrict` (no other map's MaxEntries check is
   weakened).
5. **Source→object freshness gate (#4977)** — the four layers above bind
   the *toolchain* and the object's *verifier behavior*, but none proves
   the git-tracked `.o` corresponds to CURRENT `userspace-xdp/**` source.
   Because `make build` never runs `make generate` and `make test` never
   rebuilds the shim, a logic-only edit to the Rust source (a
   packet-steering or security fix) that is not followed by `make
   generate` + committing the regenerated `.o` would ship the STALE
   object while source review and `make test` stay green. The gate closes
   that gap:
   - `pkg/dataplane/userspace_xdp_manifest.json` records a SHA-256 of the
     tracked object AND of every freshness-relevant build input — every
     `userspace-xdp/src/**/*.rs`, `Cargo.toml`, `Cargo.lock`,
     `rust-toolchain.toml`, BOTH the crate-local `userspace-xdp/.cargo/
     config.toml` and the repo-root `.cargo/config.toml` (cargo loads
     ancestor configs, so a root-level BPF-target rustflags edit could
     change the object), `bpf/headers/xpf_common.h` (its `MAX_INTERFACES`
     `#define` is awk-extracted by the recipe and sizes the shim binding
     array + maps), and the `build-userspace-xdp.sh` recipe itself (it
     embeds the bpf-linker pin). The header is hashed directly so the gate
     is fail-CLOSED: the header->Go max_entries parity canary
     (`TestMaxInterfacesMatchesCHeader`) `t.Skip`s when the header is
     absent, so leaning on it alone left a hole. It deliberately EXCLUDES
     only cargo's `target/` (build artifacts) and `.gitignore`.
   - `build-userspace-xdp.sh` regenerates the manifest (via
     `cmd/shim-manifest` → `dataplane.WriteUserspaceXDPManifest`)
     immediately after the verifier-gated install, so the manifest stays
     in LOCKSTEP with the object it describes and can never record a
     source hash newer than the object that source produced.
   - `TestUserspaceXDPShimObjectMatchesSourceManifest` (a plain, non-root
     `make test` test) recomputes the manifest from the working tree and
     fails when it drifts — editing a shim source, adding a new `.rs`
     module, or swapping the `.o` without `make generate` all go RED with
     a message pointing back to `make generate`.
     `TestUserspaceXDPManifestCoversTrackedShimInputs` additionally guards
     the input SET so a manifest hand-edit cannot drop or invent entries.
6. **Verifier-headroom tripwire (#4555)** — every layer above is BINARY:
   the object loads or it does not. That is exactly how the shim came to
   sit at 990,796 of 1,000,000 processed insns (0.92% headroom) with all
   five gates green, until a routine change to the IPv6 extension-header
   walk hit the 1M wall and had to be redesigned around the budget. So
   `shimverify` now also reads the verifier's own accounting
   (`LogLevelStats` → `processed N insns (limit M)`) and refuses a
   candidate that LOADS but leaves less than
   `UserspaceShimMinVerifierHeadroomPct` (3%) unused.
   - **Exit codes**: `0` PASS (measured, above the floor), `3` verifier
     REJECT, `4` loads but below the floor, `5` loads but headroom could
     NOT be measured, `6` loads and INSTALLS with the gate overridden,
     `2` usage, `1` other. The recipe has an arm for each. An overridden
     run gets its own code rather than `0`, so a non-interactive caller
     can tell "measured and comfortably clear" from "we could not check,
     and someone had the variable exported" without parsing stderr.
   - **Unmeasurable is a failure, deliberately.** If the running kernel's
     log carries no recognisable stats line the floor cannot be applied,
     and passing there would switch the gate off at the one moment
     headroom is unknown — reproducing the blind spot it exists to close.
   - **Override**: `XPF_SHIM_ALLOW_LOW_HEADROOM=1` covers both refusals,
     mirroring `XPF_SHIM_ALLOW_UNPINNED_INSTALL`. It is threaded through
     the `sudo` hop explicitly (sudo scrubs the environment, so it would
     otherwise be a silent no-op). Consuming it prints a loud banner
     naming the object and the reason; a run that did NOT need it but has
     it set prints a staleness note, because the variable lives in the
     ambient environment and a value exported once would otherwise
     disarm the gate forever.
   - 3% is a tripwire, not a performance target: it says "the next change
     here will not fit" while there is still room to plan. The comparison
     is `<`, so an object leaving EXACTLY 3.00% passes;
     `TestShimverifyDecision` carries a `970000/1000000` fixture, the only
     one that distinguishes `<` from `<=`.
   - **The decision lives in ONE place.** `decide()` maps
     `(stats, override)` to the verdict, and `run()` only PRESENTS it —
     `main()` is `os.Exit(run(...))` and nothing else. Before that, `main`
     called `decide` and then independently REPEATED both predicates
     (`!stats.Measured()`, `headroom < floor`) to pick its branch and its
     `os.Exit`, so the unit-tested function was not the shipped gate:
     rewriting main's low-headroom predicate to `if false` left `go build`,
     `go vet` and the whole `cmd/shimverify` suite GREEN while a
     990796/1000000 object printed `LOW-HEADROOM ... headroom 0.92%` and
     exited **0**, which the recipe's `0) ;;` arm installs. `run` takes
     argv, both streams, the environment and the verifier as parameters, so
     `TestShimverifyRun` asserts the real exit status for every arm without
     a kernel, root, or an object.
   - **The recipe is matched as CODE, not as text.**
     `TestBuildRecipeHandlesShimverifyExitCodes` reads
     `build-userspace-xdp.sh` through a comment-stripping filter and
     requires the verifier invocation at the START of a code line, in BOTH
     branches of `run_verifier` (root and `sudo`). A plain
     `strings.Contains` was satisfied by the script's own prose: replacing
     the non-root invocation with
     `true # sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=..." ...` left the
     test green while a non-root `make generate` skipped verification
     entirely and installed through the `0)` arm — the unverified-install
     path this section says does not exist. The same filter (Rust flavour)
     backs `TestShimCarriesFragHdrSizeAssertion`, where
     `const _: () = assert!(true); // mem::size_of::<FragHdr>() == 8`
     used to satisfy the check.
     Of the two defences, the ANCHORING is what catches that mutation:
     measured, with the comment filter edited to strip nothing, the
     `true # sudo -n env ...` recipe still reds, because a line beginning
     `true` does not begin `sudo`. The filter's own worth is narrower —
     it stops a WHOLE-LINE comment satisfying a check — and narrower still
     for the plain `XPF_SHIM_ALLOW_LOW_HEADROOM` mention assertion, which
     the continuation lines of the recipe's multi-line `fail "..."`
     diagnostics satisfy (the filter is line-oriented and does not carry
     quote state across newlines). That assertion binds only that the
     override is NAMED somewhere outside a comment; the two start-of-line
     invocation checks are what bind the behaviour.

**Recovery runbook** (symptom: `load Rust xdp_userspace collection:
... BPF program is too large. Processed 1000001 insn`, daemon in
config-only mode):

```
git checkout -- pkg/dataplane/userspace_xdp_bpfel.o
make build
# redeploy; do NOT run make generate until the toolchain matches the pin
```

**Pin-bump procedure**: edit `userspace-xdp/rust-toolchain.toml` (and
`PINNED_BPF_LINKER_VERSION` in `build-userspace-xdp.sh` if bumping the
linker), run `make generate` (the verifier gate must PASS), commit the
regenerated `.o` together with the pin change, and require a clean
`git diff --exit-code pkg/dataplane/userspace_xdp_bpfel.o` after a
pinned re-run (builds are bit-for-bit reproducible for a given pin)
plus a cluster smoke before merge. `make generate` also refreshes
`userspace_xdp_manifest.json` in the same step (the recipe is a hashed
input, so a linker-pin bump moves the manifest too), so commit the
regenerated object and manifest together — the #4977 freshness gate
then stays green.

## Armed-state admission contract (#2114 A3)

`Manager.loaded` is an `atomic.Bool` admission bit, and every
`m.maps`/`m.programs` access in every method class goes through the
`m.mu`-scoped typed helper pair (`lookupMapLocked`/`lookupProgramLocked`,
which return the handle, a comma-ok `present` bit, and the under-lock
`registryState` classification). The shim loader publishes the registry
and the armed flag as ONE whole-batch critical section
(`publishShimRegistryLocked`: the program assignment, both map insert
loops, then `Store(true)` as the final in-hold step), so a reader
released from a lookup hold observes either the pre-arm state or the
fully populated armed registry — never a partial one, and never a
concurrent-map read/write against the populating Start.

The gate predicate is TWO-STATE on the unarmed side:

- **FRESH-unarmed** (`loaded == false` AND `m.maps` empty — a
  never-armed manager): class-1 (fallible, map-required) methods return
  the typed, `errors.Is`-compatible `ErrDataplaneNotArmed` at their
  first REQUIRED registry access, replacing master's per-map "not
  found" error (or, on the pre-#2114 concurrent path, a fatal
  concurrent-map throw). Class-2 neutral methods keep master's
  missing-map outcome byte-for-byte. Class-3 hybrids
  (`ClearNATRuleCounters`/`ClearGlobalCounters`/`ClearZoneCounters`/
  `ClearAllCounters`) keep their pinned side-effect-plus-legacy-outcome
  behavior and are UNGATED — `ClearAllCounters` composes through the
  ungated raw internals (`clearInterfaceCountersRaw` et al.) so the
  pinned legacy "interface_counters map not found" text survives in
  every state. Class-4 getters return nil (`NewEventSource` returns the
  typed error — its signature carries one).
- **RETAINED-unarmed** (`loaded == false` with a populated registry —
  an armed manager's `Close`, which keeps the pinned-map handles live
  for hitless restart, or a bootstrap-Teardown-retained manager): every
  class proceeds EXACTLY as master — retained reads report the retained
  registry, retained mutations reach the retained maps. The loaded-check
  set (`AttachXDP`/`AttachTC`/the `CompileConfig` path) keeps its own
  pre-registry rejection ("eBPF programs not loaded" / "dataplane not
  loaded") on BOTH unarmed states; the typed error never fires for
  them.
- `Close()` stores `loaded=false` at ENTRY (before the link-handle
  closes), which narrows the loaded-check set's admission window and
  advances the externally visible `IsLoaded()`/REST/gRPC
  `DataplaneLoaded` surface during the close window. The bit is an
  admission flag, NOT a lease — it cannot drain an in-flight operation,
  and no teardown/lifetime exclusion is claimed (cilium/ebpf documents
  close-in-use as unsafe).
- `Teardown()` (= `Close` + `Cleanup`) additionally CLEARS the
  `xdpLinks`/`tcLinks` membership maps: `Close` closed the Go handles
  and `Cleanup` unpinned and destroyed the kernel links, so the entries
  would otherwise point at dead handles for links that no longer exist,
  and a same-process re-Start (the commit-confirmed rollback →
  bootstrap-exit re-arm) would hit `AttachXDP`'s stale-membership
  "already attached" short-circuit — which `attachUserspaceShimXDP`
  deliberately swallows — and report success with no AF_XDP ingress
  (Codex PR #6743 r3-1). `Close` alone deliberately keeps the
  membership: its pinned links stay live in the kernel for hitless
  reuse, so the entries remain truthful there.
  `TestManagerTeardownClearsLinkMembership` pins both polarities.

Enforcement (all in `armed_gate_matrix_test.go` /
`armed_gate_legs_test.go`): the 159-method class manifest is
AST-verified for totality; the registry canary fails the build on any
raw `m.maps`/`m.programs` access outside the two helpers + the
publisher, with negatives covering package-wide/chained/pointer type
aliases, `var`-declared and fixpoint local aliases, multi-layer
parenthesized access, cross-object lock credit (a locked `*Manager`
parameter never covers the receiver's registry), closure-hidden locks,
method-value lock/unlock escapes, and helper method-value escapes; the
stale-checked callsite manifest pins all 135 helper callsites with
their outcome roles, and the per-callsite gate evidence only counts a
`registryFresh` comparison that evaluates THAT callsite's own binding
(the scan stops at the bound identifier's reassignment — the
`ClearNATPoolIPs` two-lookup reuse shape). The five-leg runtime oracle
(fresh outcomes, retained outcomes, blocked fresh-Start, blocked
retained-reStart, Close-window `IsLoaded`) plus the continuation legs
run under `make test-race-dp`; every blocking leg proves goroutine
arrival from the `muAcquireProbeHook` pre-lock seam (a signal before
the contended call can pass the silence window without the goroutine
ever reaching the mutex).

## Live-indirection primitives (#2114 / #6743 r6)

`live.go` carries the three things the daemon's `liveDataPlane` adapter
(`pkg/daemon/daemon_dp_live.go`) needs the consumers to share:

- `ErrNotPublished` — returned by every forwarder when the daemon's cell
  is empty AT CALL TIME. It is EXPORTED so `pkg/grpcapi` can map it to
  `codes.Unavailable` (the code its own `dp == nil || !IsLoaded()`
  pre-check already returns) rather than reporting daemon lifecycle state
  as `codes.Internal`.
- `LiveUnwrapper` / `Unwrap` — an adapter's method set is exactly its
  declared forwarders, so every OPTIONAL capability consumers reach by
  asserting on `any` is ERASED by it. `Unwrap` resolves to the backend
  published at the instant of the call, and returns nil once the daemon
  has disowned one — capability transparency WITHOUT resurrecting a
  disowned backend. It is the identity for a plain backend, so every
  non-daemon caller and every test is unaffected. The
  `LastApplyResultOf` / `SessionStoreOf` / `TelemetryOf` helpers resolve
  through it, as does each consumer package's `dpProbe()`.
- `Published` — the honest replacement for `dp != nil` at render sites:
  the adapter is permanently non-nil, so the field cannot answer "does a
  dataplane exist?".

### Counter-clear error propagation: what it does NOT cover

`clearPolicyCountersIn` / `clearFilterCountersIn` propagate their
`Map.Update` error (#6743 r4-F2), which fixes the discarded-error false
success. It does NOT fix the DETACHED-backend false success: `Teardown()`
closes only the link handles and `Cleanup` merely unpins, so a retained,
torn-down `Manager` still holds live FD-backed map objects and an
`Update` through them SUCCEEDS. A `clear` issued against a disowned
generation therefore still reports success while the live generation
keeps its counters. Detecting that needs a generation tag or lease on the
handle itself — **#6741**, not this wrapper.

## Apply ordering: attach → publish → detach (#5485)

`userspace.Manager.Compile` mutates kernel XDP/TC attachment state twice
per apply, and the two halves sit on opposite sides of the snapshot
publish. The ordering is load-bearing, not incidental:

1. **Attach** — `CompileUserspaceShim` installs the retained XDP shim on
   every candidate ingress in the NEW config. This has to happen BEFORE
   `apply_snapshot`: the helper cannot bind an AF_XDP socket to an
   interface that carries no shim, so there is no way to stage it later.
2. **Publish** — `applyCompiledSnapshot` programs the classifier maps and
   sends `apply_snapshot`. `m.lastSnapshot` — the authority every
   fail-closed path calls "the retained snapshot" — advances only on
   success, or on the deliberate deferred-publish branch, which advances
   it and returns nil while the status loop publishes later.
3. **Detach** — `syncInterfaceAttachments` removes XDP and TC from every
   ifindex the accepted snapshot no longer adjudicates. It runs at the
   ACCEPTANCE POINTS ONLY, immediately after each `m.lastSnapshot = snap`.

**Why the detach is last.** Until #5485 it ran before step 2, so any
failure in between left the kernel on the new interface set while the
control plane still reported the old one. That divergence is a policy
BYPASS, not merely an outage. Both pre-publish failure modes drive the
shim to `ctrl.Enabled=0` — `programBootstrapMapsLocked` programs it
disabled, and `publishSnapshotFailClosedLocked` disables it on the
same-plan path (#4959) — and a disabled ctrl DROPS transit on every
interface that still carries the shim, because
`degraded_ctrl_disabled_action` runs before the ingress-map test in
`userspace-xdp/src/lib.rs`. An interface that has already been detached
is outside that fail-closed surface entirely: with no XDP program and
`ip_forward=1` its traffic goes straight into the Linux stack,
unadjudicated by xpf, while the daemon reports the previous-good
snapshot as enforced.

**The transient the new ordering opens is strictly safe.** Between a
successful publish and the detach, an interface still carries the shim
while the applied snapshot no longer lists it. In both ctrl states that
is at least as strict as the detached state it precedes: an ifindex
absent from `userspace_ingress_ifaces` takes `cpumap_or_pass`, which is
the kernel path a detached interface would have taken anyway, and a
still-disabled ctrl drops its transit. Nothing in the window between the
old detach site and the publish reads the attachment set —
`entryProgramsLocked` (`maps_sync.go`) is the only other `XDPLinks()`
reader and it is status reporting — so moving the detach costs no
dependency.

**Consequence to expect on a failing apply:** an interface the operator
REMOVED from the config keeps its shim, and its transit stays dropped,
until an apply succeeds. That is the intended fail-closed retention —
the retained snapshot still lists the interface, so xpf still owns it.

Record-and-rollback (capture the detached set, re-attach on error) was
the considered alternative. It was rejected: it compensates for the
window instead of removing it, the re-attach itself can fail with no
second recovery, and `AttachXDP` does a fresh attach that reinitializes
mlx5 XSK buffer pools — churning the datapath on interfaces that were
never in question.

Guarded by `TestAttachmentsNotDetachedBeforePublish_5485` (behavioral: a
pre-publish failure retains both links) and
`TestDetachOnlyAfterSnapshotAccepted_5485` (structural: every
`syncInterfaceAttachments` call site is dominated by `m.lastSnapshot =
snap`, and there are two of them — one per acceptance path).

## Entry points

- `DataPlane` — `dataplane.go`. Legacy BPF-shaped interface kept for the
  legacy eBPF compiler and compatibility adapters (DPDK retired #1525). New
  daemon-facing code should not add methods here.
- DPDK backend deleted in #1528 (umbrella #1525). The `pkg/dataplane/dpdk`
  package no longer exists.
- `RuntimeDataPlane`, `ConfigSink`, `SessionStore`, `Telemetry`,
  `HAController`, and `LinkController` — `apply.go` and `session_store.go`.
  These are the split-domain interfaces used by daemon startup and runtime
  subsystems. `ConfigSink.ApplyConfig` is the daemon's apply-time
  compile/config entry point; userspace AF_XDP does not need to implement the
  legacy BPF-shaped `Compile` method just to receive committed config.
- `NewRuntimeDataPlane(dpType)` — `dataplane.go`. Runtime-domain constructor
  kept for the explicit legacy eBPF rollback, the retired-DPDK sentinel, and
  compatibility/test seams such as the userspace runtime registry round-trip.
  The daemon's default and explicit userspace boot path now goes through
  `userspace.Boot()` via `pkg/daemon/buildRuntimeDataPlane()`. The current
  userspace constructor still returns a compatibility adapter around
  `*userspace.Manager` until the remaining status/session-sync callers stop
  requiring `DataPlane`.
- `Manager` — `loader.go`. eBPF implementation.
- `New() *Manager` — `loader.go`.
- `Compile(cfg *config.Config) (*CompileResult, error)` — multi-phase
  lowering to BPF map entries. Phases live in `compiler.go`: zone IDs,
  screen profile IDs, **validate-before-mutate pre-pass**, zones, address
  book, applications, policies, NAT, static NAT, NAT64 prefixes, NPTv6,
  screen profiles, default policy, flow timeouts, firewall filters, flow
  config, port mirroring.
  - The pre-pass (`compiler_validate_4960.go`, #4960) re-runs the fallible
    HOST-PURE phases against a discarding dataplane BEFORE the zones phase
    performs the first destructive host netlink mutation, so a config that
    passes `commit check` but trips a later phase is REJECTED with nothing
    mutated instead of half-applied with no undo path. It can therefore fail
    the whole compile on its own. It is additive — every real phase keeps its
    position — but it does change WHICH error an operator sees when a config
    carries more than one fault. Precedence is the pre-pass ROW ORDER, because
    the pre-pass returns on the first failing row. An unknown screen-profile
    reference is now reported by a pre-pass row (`zone screen references`)
    sitting FIRST in the table, so it is the error an operator sees when a
    config carries it alongside any other pre-pass fault. It remains a
    zones-phase fault as well — #6894 hoisted `validateZoneScreenReferences`
    to the top of `compileZones`, so a caller reaching that phase without the
    pre-pass still rejects before any zone is programmed. The earlier wording
    ("no longer a zones-phase fault at all") described only the pre-pass half
    and read as though the zones-phase check had been removed. Read the order off `validationPhases` rather than trusting this
    sentence — the previous wording had the two the wrong way round. That file
    states what the pre-pass
    does and does not cover; the coverage table is not the whole compile.
  - **The pre-pass is only as good as the phases' own strictness** (#6894 r9,
    #4960). A row that ACCEPTS what the Rust helper later REJECTS puts the
    half-applied state back: the helper's rejection lands at
    `publishSnapshotFailClosedLocked`, after the zones phase has already
    created VLANs and reconciled addresses. NPTv6 was such a row —
    `compileNPTv6` warned and skipped an unparseable / length-mismatched /
    host-bits-set prefix while `Nptv6State::try_from_snapshots` rejects the
    WHOLE snapshot over it (`userspace-dp/src/nptv6.rs`, #2240/#4519). It now
    returns an error for those, so the same certain failure happens BEFORE the
    mutation. The error is scoped to rules the helper actually REFUSES, which is
    not the same as "Go cannot parse it" (#7077): Rust's `parse_prefix` takes a
    leading `+` on the mask (`u8::from_str`) where Go's `net.ParseCIDR` does not,
    so `fd00:9::/+48` is a Go parse error and a helper ACCEPT whose apply
    succeeds today. `nptv6HelperWouldInstall` mirrors the helper's grammar (drift
    is bound by a rustc-measured parity table) so that class keeps warn-and-skip;
    a skipped rule still reaches the helper because `buildNptv6Snapshots` copies
    the config strings independently. The error is also scoped to rules that
    actually reach the helper at all:
    `config.NPTv6ScopeUnsupported` is the shared predicate the snapshot builder
    uses to DROP a rule (#5818), and a dropped rule keeps the warn-and-skip
    disposition because today's apply succeeds without it. **Residual:** the
    helper also rejects OVERLAPPING NPTv6 prefixes (#2241) partitioned by zone
    scope (#5176); the pre-pass does not replicate that partitioning, so an
    overlap still fails post-mutation. Replicating it coarsely would REJECT
    configs the helper accepts, which is worse than the residual.
  - **No-brick note.** A pre-pass rejection cannot strand a boot or an HA
    peer-sync: `configstore.Store.Load` and `Store.SyncApply` compile through
    `pkg/config.compileTreeLenient` and never reach `pkg/dataplane.CompileConfig`
    at all. The config still loads with the warning `validateNPTv6Strict` emits
    on the tolerant path; what fails is the dataplane apply, which already
    failed at publish before this change.
- `CompileResult` — `compiler.go`. Zone/policy/NAT/app IDs, compiled
  policy-scheduler rule slots, and the per-interface networkd configs.
- Session iteration: `IterateSessions`, `BatchIterateSessions`,
  `IterateSessionsV6`, `BatchIterateSessionsV6`.
- Full-table clear (`clear security flow session all`): `ClearAllSessions`
  and `ClearAllSessionsChunked`. The table holds up to ~10M sessions per
  family, so the clear is both cooperative (yields between batches — #4719)
  and **bounded** (#5304): it collects at most `sessionClearSnapshotChunk`
  keys, deletes that chunk (+ its dynamic DNAT entries) via chunked
  `BPF_MAP_DELETE_BATCH`, then re-scans for the next chunk — peak key-slice
  memory is O(chunk), not O(table). Deleting every collected key before the
  next scan makes the loop converge (every key present at start is removed).
  `ClearAllSessionsChunked` invokes an optional per-chunk callback so the
  userspace wrapper (`userspace.Manager.ClearAllSessions`) can issue its
  authoritative Rust-helper delete on each bounded chunk instead of building
  a second full-table key snapshot of its own — the two coexisting full-table
  snapshots (wrapper v4+v6 + shim v4+v6 + DNAT lists) were the ~1 GB RSS spike
  that #5304 removed. In userspace mode the Rust helper is AUTHORITATIVE (it
  owns packet forwarding; the BPF table is a read model), so the wrapper's
  `ClearAllSessions` propagates a helper-delete IPC failure as a non-nil error
  rather than losing it in a log line (#5881): a failed authoritative
  revocation must not report success while the helper keeps forwarding under
  the "cleared" session. The bpf mirror's partial (v4, v6) counts are still
  returned alongside that error — the same non-atomic clear-all reporting
  contract the API handlers honor for a mid-clear mirror failure (#5882). A
  mirror-side error still takes precedence. The batch delete path
  (`BatchDeleteSessions{,V6}`) keeps the #5096 best-effort contract — the
  periodic session sync and GC delta reconcile a transient helper miss — so it
  discards the helper-delete error; only the operator clear-all propagates it.
- Session domain adapters: `SessionStoreOf`, `TelemetryOf`, and
  `NewDataPlaneSessionStore`. The generic `DataPlane` adapter preserves the
  batch-iteration fast path and centralizes cluster/GC companion ownership:
  cluster-synced forward installs create reverse and DNAT companions and roll
  back session writes if companion creation fails. Iteration callers that
  already have the session value must delete through `DeleteKnown*` or
  `DeleteBatchKnown*` so reverse/DNAT cleanup uses the authoritative
  iterator value, preserves persistent-NAT bindings, and keeps the batched
  map-delete fast path. `DeleteWithCompanions*` is retained for key-only
  HA delete messages.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`, `pkg/conntrack`.

## Dependencies

`appid`, `config`, `networkd`.

## BPF verifier and kernel constraints

These are the project's recurring traps. Read CLAUDE.md for the
authoritative list; quick recap:

- Branch merges lose packet range — re-read `ctx->data` / `ctx->data_end`
  after any branch.
- 512-byte combined stack across call frames — push large locals into
  scratch maps; mark big helpers `__noinline`.
- Variable-offset packet pointers lose range when `var_off` is wide
  (0xffff). Use a constant offset from a validated pointer.
- Mask `meta->l3_offset` (u16) with `& 0x3F` before packet-pointer
  arithmetic so the verifier can track the range (commit `66833c5`).
- `__u16` causes sign-extension (`smin=-32768`) — fails for packet-pointer
  math.
- Pointer bitwise OR is rejected (`if (sv4 || sv6)` where both are
  pointers triggers a compiler `|=` on pointer registers). Use separate
  null checks.
- xdp_zone fails the verifier on kernel 6.12 (NAT64 complexity); passes
  on 6.18+.

### IPv6 extension-header walk: the shim's budget is nearly spent (#4555)

The shim's `parse_ipv6` extension-header loop is fully unrolled, so every
iteration duplicates each arm body and its `read_bytes` range
re-validation. It is the single largest consumer of the 1M processed-insn
verifier cap, and the pre-#4555 shim sat at **990,796 of 1,000,000 — under
1% headroom**. Measured on the pinned toolchain via `cmd/shimverify`
(kernel 7.0), varying only `MAX_EXT_HDRS` and whether the generic arm
carries the full #4517 type set:

| `MAX_EXT_HDRS` | #4517 types (135/139/140/253/254) | verdict | processed insns |
|---|---|---|---|
| 6 | no (pre-#4555) | PASS | 990,796 |
| 6 | yes | PASS | 874,873 |
| 7 | no | **REJECT** | — |
| 7 | yes (current) | PASS | 947,188 |
| 8 | no | **REJECT** | — |
| 8 | yes | **REJECT** | 1,000,001 |

Two things to carry away:

- **8 is unreachable.** Do not "just bump it to match userspace" — the
  candidate does not load, and `make generate` fails closed at the #1864
  verify-then-install gate (the tracked `.o` is left untouched).
- **The bound and the type set are coupled.** Widening the generic arm to
  the full #4517 set is what makes bound 7 affordable: folding five more
  next-header values into one shared arm body prunes more verifier state
  than the five extra compares cost. Bound 7 with the narrow set is
  rejected; with the wide set it passes with 5.3% headroom.

**Parity relation.** `MAX_EXT_HDRS` (shim) and `MAX_IPV6_EXT_HEADERS`
(`userspace-dp/src/afxdp/frame/inspect.rs`) are ITERATION counts whose
loops exit differently, so they are deliberately NOT equal:

- the shim spends one iteration per extension header and exits by
  EXHAUSTION carrying the last declared next-header value straight into
  `parse_l4` (no post-loop over-limit check) — it resolves chains of up to
  `MAX_EXT_HDRS` extension headers;
- `walk_ipv6_ext_chain` needs one FURTHER iteration to return the terminal
  and folds exhaustion into the fail-closed `OverLimit` verdict
  (#2292/#4743) — it resolves up to `MAX_IPV6_EXT_HEADERS - 1`.

So the correct condition is `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1`
(7 and 8): both walkers resolve 0..=7 extension headers and both refuse 8
or more.

**The two mismatch directions are not symmetric.** Only shim-BELOW-userspace
is fail-closed: the shim's unresolved chain leaves the extension-header type
in `ParsedPacket::protocol` with `parse_l4`'s catch-all ports 0/0, so the
session key misses and the packet is redirected to userspace for full
policy — it costs that flow the XDP fast path permanently, nothing more.

That miss is **not** something the shim enforces. The shim probes a session
map userspace writes, so "the key cannot be present" is a claim about the
WRITERS, and #6923 found it false: `metadata_tuple_complete`
(`userspace-dp/src/afxdp/frame/inspect.rs`) accepted every non-TCP/UDP
metadata tuple, so the residual extension-header protocol with ports 0/0
became a `SessionFlow`. That made `flow.is_none()` false, which SKIPPED the
#4743 over-limit drop; an `application any` permit then matched a flow with
no ports to fail on, and the session was installed and published under
exactly the key the shim probes with. The unconditional over-limit refusal
was in fact conditional on policy, and after one packet the chain had a fast
path. Both writers now refuse an IPv6 key whose protocol is one the walk
traverses — the packet path in `metadata_tuple_complete`, and the HA import
in `build_synced_session_key`
(`userspace-dp/src/server/helpers/session_sync.rs`), because the session map
is global and the shim probes whatever row is present regardless of who
wrote it. The refused set is `ipv6_ext_header_is_traversable`, held equal to
the shim's own `eh_class` non-terminal set over all 256 values by
`refused_protocol_set_equals_the_shim_traversable_set`. **A third writer
into `USERSPACE_SESSIONS` must extend that refusal, or this paragraph goes
back to being false.**

Shim-ABOVE-userspace is the direction never to take: the shim would stamp a
full 5-tuple and `l4_offset` for a chain `walk_ipv6_ext_chain` refuses with
`OverLimit`, and hand that meta to consumers that trust it. Independently of
that argument, bound 8 does not load — see the table above.

**`parsed.protocol` is not only a session-key ingredient.** It also drives
pre-session dispatch that terminates in the shim: ESP and non-native GRE to
`cpumap_or_pass` (kernel XFRM / tunnel decap), WireGuard-to-firewall via
`wg_steer_to_kernel`, ICMPv6 NDP 133-137 via `pass_local_control`. Widening
the walked type set therefore re-routes packets between the XSK path and the
kernel path — `IPv6 → Mobility → ESP` reached userspace over XSK before
#4555 and now goes to the kernel stack, matching how `DestOpt → ESP` already
behaved and how userspace-dp classifies the same chain. On the userspace
side `meta.protocol` feeds NAT64 translation and L4 checksum recomputation
(`frame/mod.rs`), so walk agreement matters well beyond telemetry.

**How parity is enforced: the shim EMITS its facts (#4555).** The shim
cannot be executed by userspace-dp's tests — it is `no_std`, built for
`bpfel-unknown-none`. Four successive guards MODELLED it from source text
and every one leaked to a more ordinary edit: a substring test on the
advance arithmetic accepted an added `+ 8`; it also accepted a prepended
`if opt[1] == 0 { break; }` (which rejects the ordinary 8-byte
HbH/DestOpt); pinning whole arm bodies still ignored a statement inside the
loop but outside the `match`; pinning the TEXT `size_of::<FragHdr>()` did
not pin its VALUE; and the struct-layout resolver written to fix that
skipped a field hidden behind a COMMENT.

So the dependency is inverted, in two layers.

**Emitted facts, for the artifact.** `userspace-xdp` emits
`XPF_SHIM_FACTS` — a `#[used]` static whose fields rustc const-evaluates
from the real types and the real classifier: `MAX_EXT_HDRS`,
`size_of::<FragHdr>()`, and a 256-entry table produced by the same
`eh_class` function the walk dispatches on. It lands in its own
`.xpf_shim_facts` section (deliberately not `.rodata*`, which cilium/ebpf
would surface as a runtime map), costs **zero** verifier budget (measured:
947,188 insns with and without it), and `make generate` reads it back out
of the object (`ReadShimFactsFromObject`) into the `shim_facts` block of
`userspace_xdp_manifest.json`.

**The executed walk, for behaviour.** Three scalars cannot witness what the
walk DOES, and claiming otherwise was wrong: four edits to the shim — the
generic advance to `* 16`, the AH advance to `* 8`, a statement added
inside the loop but outside the `match`, and deleting the generic arm's
post-advance bounds revalidation — all left the fact comparison green,
because none of them changes `MAX_EXT_HDRS`, `FragHdr` or `eh_class`. So
the walk itself lives in `userspace-xdp/src/ipv6_ext_walk.rs`, a module
depending only on `core`, which `tests_shim_ext_parity.rs`
`#[path]`-includes and RUNS on a corpus of real chains alongside
`walk_ipv6_ext_chain`. Advance arithmetic, bounds revalidation and
resolvable chain length are compared outcomes, not source-text claims.

The two layers cover different things and both are needed. The corpus
proves the walk behaves identically **in the dimension the shim
represents**, which is narrower than "identically":
`walk_ipv6_ext_headers` returns `(offset, protocol)` and nothing else, so
the compared unit is terminal offset, terminal protocol, no-next-header
and fail-closed. Fragment state is not compared because the shim has none
to compare against. `walk_ipv6_ext_chain` additionally records the first
Fragment header's raw bytes and a non-first-fragment flag, and the shim's
blindness there is a real, OPEN divergence rather than an artefact of the
comparison: on `IPv6 || Fragment(frag_off != 0, next = TCP)` the shim
resolves `L4(48, TCP)` and `parse_l4` reads fragment PAYLOAD as a TCP
header, where this crate refuses those bytes. That is **#6704** —
pre-existing, not introduced by #4555, PINNED (not fixed) by
`shim_is_not_more_permissive`, and closable only by a shim behaviour
change with its own verifier cost. The emitted facts, meanwhile, travel
with the artifact so a consumer of a prebuilt object — the Debian
packaging path never compiles the shim crate — can check the walk's
constants without a Rust toolchain.

This also fixes a scope gap a compile-time assertion could not: an
assertion in the shim only runs when the shim crate is COMPILED, which the
Debian packaging path never does (`debian/rules` runs `make build`, and the
daemon embeds the tracked `.o`). Facts recorded in the manifest travel with
the artifact and are checkable wherever a prebuilt object is consumed.

No source-text check remains. The exhaustion semantics that make the shim
resolve `MAX_EXT_HDRS` headers were once argued to be unemittable — "a
shape, not a value" — and kept as a narrow source scan. Executing the walk
dissolves that: the corpus walks chains of 0..=10 extension headers and
compares verdicts, so the resolvable length is measured on both sides.

## SR-IOV / driver constraints

- iavf (VF) has no native XDP — generic mode only, ~16% CPU loss.
  i40e/ice on the PF have native XDP.
- `bpf_redirect_map` requires `ndo_xdp_xmit` on the target. Mixing native
  + generic interfaces in a redirect set silently drops.
- Workaround: per-interface `redirect_capable` flag in `bpf/xdp/xdp_forward.c`.
  Non-native interfaces fall back to `XDP_PASS` (kernel forwarding).
- The lab uses PF passthrough (i40e) on the WAN interface; all other
  interfaces are virtio with native XDP. Per-VF passthrough would need
  generic XDP and hit the iavf cliff.

## Flow export ownership

Flow export (NetFlow v9 / IPFIX) is owned by `pkg/flowexport` on the
**control plane**, driven by `pkg/logging.EventReader` SESSION_CLOSE
events. The userspace dataplane does NOT emit flow packets. The Rust
dataplane once carried a dead `FlowExporter` plus a write-only
`flow_export_config` field that emitted nothing; both were removed in
#2130. The Go→Rust `flow_export` snapshot wire field is retained as
reserved/ignored (the helper deserializes and drops it) to preserve the
#1977 decode-safety tests and avoid a wire-protocol break.

## Byte order

Use `binary.NativeEndian.Uint32(ip4)` for `__be32` BPF fields, **not**
`BigEndian`. cilium/ebpf serializes map values in native endian; the IP
bytes are already in network order on the wire.

## Arm-coverage proof (#5275, observe-only)

`armproof.go` computes whether the dataplane is genuinely armed for the
surfaces the current config requires. **It gates nothing.** It reports what a
gating build would have decided (`ArmCoverageReport.WouldGate`) so the
divergence rate can be measured across real deployments before the gate is ever
load-bearing — the eventual fix refuses to publish ownership, forwarding and
route/VIP advertisement until the proof passes.

Why a measurement phase: "armed" today is weaker than the proof.
`attachUserspaceShimXDP` treats a **native** XDP attach failure as a warning —
it detaches and re-attaches in generic (skb) mode, and only a *generic* failure
returns an error. A box therefore reports itself armed while running the whole
shim on the fallback path.

**Which stage this measures.** The plan's §5 takes the *final* proof after the
last mutation that can invalidate it — networkd, the RETH MAC link-cycle, and
the AF_XDP rebind / deferred-worker reapply. This proof runs inside
`CompileUserspaceShim`, i.e. at the **preliminary** attachment stage: it proves
the attach-point **inventory** and *reports* the program instance each tracked
`bpf_link` carries — it does **not** verify that instance is the shim's (see
the residual below) — and cannot see XSK binding readiness. The number it emits
is therefore the *preliminary-stage* divergence rate, a lower bound on the
gate's — not the gate's own rate.

Each surface resolves to exactly one of four kinds. The decisions below are
stated deliberately, not left to emerge from how the readback happens to be
written, because a later "tighten the proof" change would otherwise flip a
supported deployment to fail-closed with nobody intending it. Each is pinned by
a test in `armproof_5275_test.go`.

| Kind | Meaning |
|---|---|
| `direct` | A shim instance is attached here. **Native and generic both count.** |
| `delegated` | No attach is expected here by design; the **parent** covers it, and the parent is a required surface that itself classified `direct`. |
| `skipped` | The **compiler** declined to arm this surface and the compile still succeeded. A **third, distinct unknown**: neither proven covered nor proven forwarding-without-policy. `WouldGate` deliberately excludes it — see below. |
| `uncovered` | Nothing here and no proven delegate — including a failed readback, and a declined surface whose netdev was not proven down. |

- **Generic (skb-mode) counts as armed.** It still steers packets to
  userspace-dp and still enforces policy, at roughly 16% CPU overhead from the
  per-packet `sk_buff`. #5275 exists to prevent a *policy-free* kernel, and a
  fallback box is not policy-free. iavf SR-IOV VFs have no native XDP support at
  all, so this is a supported steady state — failing it closed would brick a
  supported deployment to prevent a condition that is not occurring.
- **The attach mode is read from the kernel, never from compile bookkeeping.**
  The native→generic fallback happens once and the resulting `m.xdpLinks` entry
  survives every later compile, so `AttachXDP` short-circuits on "already
  attached" and a per-compile record is empty from compile #2 onward while the
  box is still on skb-mode. Sourcing the flag from such a record would log "went
  native" on every commit after the first, on precisely the population this
  phase exists to count.
- **VLAN sub-interfaces are delegated, and the delegation is resolved.** Under
  the userspace shim a VLAN child is never attached (both attach loops skip it;
  it is recorded in `Manager.VlanSubInterfaces`) because the parent's XDP sees
  VLAN-tagged frames before kernel VLAN demuxing, and attaching the child breaks
  IPv6 NDP under generic-mode `XDP_PASS`. Policy is enforced — at a different
  attach point. A proof demanding an instance on every mapped attach point would
  fail every VLAN deployment; one that skipped VLAN children would pass a
  surface whose coverage was never checked. So the parent must be a **required**
  surface that itself classified `direct`, or the child reads as uncovered — a
  link that merely happens to be tracked is not enough, because an
  enabled→disabled commit leaves the old parent link in place while the parent
  is admin-DOWN and about to be torn down.
- **The delegate's `ParentIndex` is only read once the child is proven to be an
  802.1Q device.** vishvananda/netlink folds `IFLA_LINK` into
  `LinkAttrs.ParentIndex` in the *common* attribute loop, for every link kind —
  and what `IFLA_LINK` means is per-kind: a macvlan/ipvlan's lower device, a
  tunnel's bound device, and, the sharp one, a **veth's peer**, which for a
  cross-namespace pair is an ifindex in the *foreign* namespace that can
  numerically alias any local interface. Both branches that can make a child
  read as covered — the proven-down promotion to `skipped` and the delegation to
  a covered required parent — would then let an unrelated local interface answer
  for it, and both directions are **under**-counts that hide a live forwarding
  surface with no shim. It is reachable: `ensureVLANSubInterface` adopts *any*
  existing device named `<phys>.<vid>` without checking its kind, the ifindex is
  recorded as a delegated child, the userspace attach loop skips it, and the
  unmanaged sweep will not remove it because the name's prefix before `.` is a
  managed interface. So `coverDelegated` requires `Link.Type() == "vlan"`
  (`vlanLinkKind`) and otherwise reports `uncovered` with `Via` left zero —
  naming a bogus parent would repeat the same confusion in the log.
- **…and only once the parent is proven to be in THIS namespace.** The kind
  belt is necessary, not sufficient: a genuine 802.1Q device whose `real_dev`
  was left in another namespace keeps kind `"vlan"` and keeps a `ParentIndex`
  that now names an ifindex *over there*, aliasing local ifindexes just as
  freely. `coverDelegated` therefore also requires
  `LinkAttrs.NetNsID == netnsIDLocal` (`-1`). The kernel emits
  `IFLA_LINK_NETNSID` exactly when `link_net != dev_net`, and netlink seeds
  `-1` and overwrites it only from that attribute, so `-1` means "local
  parent". The test is `!= -1`, **not** `> 0`: a foreign parent's nsid is
  commonly **zero** (measured), and netlink parses the wire `s32` unsigned
  (`int(native.Uint32(...))`), so a wire `-1` arrives as `4294967295` — which
  `!= -1` still rejects, conservatively.
  - An earlier revision of this document claimed such an orphan is forced
    admin-DOWN, that `LinkSetUp` fails `ENETDOWN`, and that it is therefore not
    a live surface. **That was wrong**, and the experiment behind it only
    reproduced because it left the foreign `real_dev` DOWN. Re-measured: with
    the `real_dev` down, `LinkSetUp` does fail (rc=2, `ENETDOWN`, oper=down);
    bring it **up in its own namespace** and the orphan comes up
    (`up|broadcast|running`, oper=up) and forwards. `vlan_dev_open` refuses only
    while the `real_dev` is down.
- One limit is stated rather than assumed: the checks bind the *kind* and the
  parent's *namespace*, not the *configured* parent — an adopted VLAN stacked on
  a different local device delegates to that device, which stays honest because
  the parent's XDP really does see its tagged frames. The adoption itself is a
  separate production defect; these belts only stop the proof from laundering it
  into a covered count.
- **A surface the compiler declined to arm is not silently absent.**
  `compiler_iface.go` soft-skips **four** ways, each leaving the compile
  *successful* and the surface out of `pendingXDP`: the interface was not found,
  the VLAN child could not be created, the interface is administratively
  disabled, and — one frame up in `programZoneMaps` — the zone slot is nil. Each
  records an `UnarmedSurface`. The first three also emit a compiler-side `slog`
  line; the nil zone slot emits none, so the proof's own per-surface line is the
  only place it becomes visible.
  - `skipped` is **not** a claim that nothing forwards. It is the third unknown:
    the compiler did not look, so the proof cannot say. `WouldGate` excludes it
    because a clean `disable` is a legitimate operator action and folding every
    one into would-gate would swamp the measurement this phase exists to take.
    **The gating PR must decide** what a declined surface means to a gate; PR1
    only has to stop hiding it.
  - A VLAN child whose parent was declined and **proven down** inherits
    `skipped`, not `uncovered`. `compiler_iface.go` appends the child ~130 lines
    *above* the `isDisabled` check and never appends a disabled parent, so a
    clean `set interfaces ge-0-0-2 disable` leaves `ge-0-0-2.50` in the required
    set with its delegate outside it. Reading that as uncovered would drive
    would-gate on a legitimate operator action, on precisely the interface shape
    both reference deployments run (`reth0.50`/`reth0.80` on the loss cluster,
    VLAN 50 on the standalone VM) — an inflated baseline is the failure this
    phase exists to prevent. A VLAN device cannot pass traffic while its real
    device is DOWN, so a proven-down parent proves the child is not forwarding
    either. If the parent's `LinkSetDown` *failed*, the child rides a netdev that
    may still be up, zoned and XDP-less, so it stays `uncovered`.
  - The sharp case is promoted: a `disable` whose `netlink.LinkSetDown` fails
    (or whose link never resolved, so the down was never attempted) leaves the
    netdev up, still address-reconciled, still in a zone, still forwarded
    through, with no XDP — reported `uncovered`. `disabledSurfaceRecord` makes
    that judgement, split out so it is unit-testable; producing the condition
    needs `CAP_NET_ADMIN`, deciding what it *means* does not.
  - Absence is not assumed from an error nobody read. `net.InterfaceByName`
    reports a genuine absence and a netlink **dump failure** through the same
    `*net.OpError`; a dump failure proves nothing about whether the netdev
    exists, so `missingInterfaceRecord` treats a wrapped `syscall.Errno` as
    possibly-still-forwarding.
  - The nil zone slot is recorded at **zone** level (`zone:<name>`) and stays
    `skipped`: `zone.Interfaces` is precisely the deref the nil guard prevents,
    so its surfaces are unknowable there. It is an enumeration gap the
    measurement can now see — and it is reachable on the HA config-sync path,
    where the rate was previously biased optimistic.
  - One record per surface, keyed on `(Name, Ifindex)`. `mapZoneInterface` runs
    once per *zone reference* and the per-phys dedup sits below the skips, so an
    interface named by two zones would otherwise be counted twice; a repeat
    sighting never downgrades the classification. The key is why the record must
    name the **configured** surface: `mapZoneInterface` resolves `reth0.50` to
    its parent *before* the lookup, so filing a missing child under the parent's
    name folds every child of one absent parent — and the parent's own record —
    into a single entry, while a parent that resolves yields one record per
    surface. `missingInterfaceRecord` therefore takes the VLAN id and names
    `<parent>.<vid>`, keeping the parent in the reason.
- **`XDP_ATTACHED_MULTI` counts as generic.** It means programs are attached in
  more than one mode, and it is reachable — `attachUserspaceShimXDP` discards
  `DetachXDP`'s error on the native-fallback path. Reading it as native would
  undercount the slow-path population, the same direction as the defect that
  moved the flag to the kernel.
- **Residual: the program instance is reported, not verified.**
  `xdpLinkProgramID` accepts **any** readable program id. It does not compare
  it against `m.programs[m.XDPEntryProgram()]` — the program `AttachXDP`
  installs — and does not check `Info.XDP().Ifindex` against the ifindex being
  proved. A `direct` verdict therefore means *an instance exists here and this
  is its id*, not *the shim covers this surface*. It is sound today only by an
  invariant held **elsewhere**: every writer of `m.xdpLinks` installs
  `m.programs[m.XDPEntryProgram()]` (`AttachXDP`'s fresh attach and its
  pinned-link `Update` reuse, plus `swapXDPEntryProg`, which updates the links
  and only then renames the entry program), post-#1476 `m.programs` has a single
  shim writer with the legacy entry program never loaded, and nothing outside the
  package can reach a tracked link (`Program(name)` is a read-only getter;
  `m.xdpLinks` has no accessor). So a mismatch is not a state this tree can
  produce, and adding the comparison to a *diagnostic* would measure nothing
  while adding a new way to report a false `uncovered` — an unreadable expected
  program. **The gating PR must add it**: a build that withholds ownership,
  forwarding and route/VIP advertisement cannot rest its refusal on an invariant
  upheld by its callers, and it has to decide the direction this phase has no
  evidence for — whether an unreadable expected program fails closed. Plan
  §13/D1 carries the same split.

`CoverageUncovered` is deliberately the zero value: an unpopulated entry must
read as *not* covered, so a partially-built report can only ever be more
conservative.

**Observe-only, stated exactly.** The proof writes no Go state — not the
`Manager`, and not the `CompileResult` it is proving (link resolution uses the
non-memoising `peekLinkByIndex`, not `cachedLinkByIndex`). It does read live
kernel and bpf state, and the cost is per surface *kind* rather than uniform: a
`direct` surface with a tracked link costs one `RTM_GETLINK` for the attach mode
plus one bpf_link info call for the program identity, and nothing at all when no
link is tracked; a `delegated` surface costs at most one `RTM_GETLINK` to
resolve its parent and never a bpf_link call, because it reuses the parent's
already-computed classification; a declined surface is rendered from its
recorded struct and costs nothing.

**One summary line per compile, not per apply.** A single daemon apply compiles
twice on the RETH deferred-MAC path (`reapplyAfterDeferredMAC`), so the apply
generation is folded into the stage label (`stage=post-attach#7`) to keep the
two records apart. The summary line is emitted even when the proof enumerated
nothing, carrying `ran=true`: suppressing it would make "nothing to arm", "the
proof never ran" and "this build has no proof" identical in a log archive.
Beyond the summary, `uncovered` surfaces add one `WARN` each and `skipped`
surfaces one `INFO` each — a fully-covered box stays at the single line, and
the two levels are deliberate: `WARN` is the would-gate set, while a skip's
dominant member is a clean `disable`, so logging it at `WARN` would train
operators to ignore both.
