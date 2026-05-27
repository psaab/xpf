# #1561 — userspace-dp first-snapshot CoSBatch null deref on fresh VM boot

Status: **PLAN-KILLED v1** — 2/2 hostile-review verdicts concur.

- Codex task `task-mpni4rdg-285gk5` — PLAN-KILL (3m20s)
- AGY job `review-mpni517x-6yp34f` — PLAN-KILL

Both reviewers ratified the structural argument that a null Vec /
VecDeque drop receiver is a stack-local condition not reachable from
any ArcSwap publish race, and agreed that the three candidate fixes
(barrier, atomic publish, lazy init) do not target the observed
fingerprint. Both also endorsed PLAN-KILL plus a diagnostic-only
follow-up (install `systemd-coredump`, retain build-id, preserve
debuginfo) as the highest-EV next step. AGY added an explicit
counter-trace: an FFI stack clobber in `userspace-xdp` could zero
adjacent stack slots and produce exactly this fingerprint — which
none of the three publish-side candidates would fix.

Codex's caveat (preserved as record): `addr2line` symbol attribution
near tightly packed `drop_in_place` instantiations is approximate;
the "drop_in_place&lt;VecDeque&lt;TxRequest&gt;&gt;" identification
is plausible but not proven without a captured core. The diagnostic
follow-up must capture build-id, registers, crashing instruction
bytes, and ideally debuginfod access — not just install
`systemd-coredump`.

#1561 closed as "supervisor-respawn recovery per #925 is the
correct design at this layer; no production-code change without a
captured core." Issue link will reference this plan doc.

## Issue framing

`#1561` reports a non-deterministic null-pointer dereference at the
same fixed binary offset across 3–6 worker threads on a freshly booted
helper. `addr2line` resolves the offset to
`core::ptr::drop_in_place<xpf_userspace_dp::afxdp::cos::queue_service::CoSBatch>`.
The supervisor restarts the helper child after the segfault and the
subsequent snapshot install always succeeds — per the `#925` design
contract this currently recovers silently and the cluster reaches
`Takeover ready: yes` within seconds.

The crash predates the most recent userspace-dp churn:
`queue_service.rs` (where `CoSBatch` is defined) has had no commits
since `f0081b1f` (April 2026). It is **not** introduced by
`#1525/#1527/#1528/#1373` (DPDK / eBPF retirement chain) and is **not**
a blocker for any of those PRs per the explicit priority statement in
the issue body.

Bisect (agent `a4b4b8581f6b96e00`) walked the retirement-chain merge
window and returned NO-LOCALIZATION: the same binary hash that crashed
on Run 1 ran cleanly on Run 2.

## Honest scope / value framing

What this PR would have to do, if it were going to land, is one of:

- (a) Wait-for-publish barrier: workers spin-wait for a first complete
      CoS snapshot before they start polling `drain_shaped_tx`.
- (b) Atomic publish: collapse the per-`ArcSwap` `.store()` cascade in
      `Coordinator::refresh_cos_runtime_maps` (`coordinator/mod.rs:618-641`)
      into a single combined publish so workers cannot observe a
      mixed-generation snapshot.
- (c) Lazy init: workers start with empty CoS runtime state and only
      populate `cos_interfaces` once a non-empty publish is observed
      atomically.

The structural cost of each:

- (a) adds a startup-only spin loop (no steady-state cost) but couples
      worker startup to the coordinator's snapshot completion.
      A new failure mode appears: coordinator is delayed → workers
      block → operator sees `Takeover ready: no` for longer than
      today's ~250 ms helper restart.
- (b) collapses ~6 independent `ArcSwap<BTreeMap<...>>` slots into one
      `ArcSwap<CoSAggregate>`. **Hot-path** workers consult these slots
      individually per tick — the existing `load_arc_if_changed` +
      `Arc::ptr_eq` short-circuit (per `#1188`) is per-slot. Folding
      them into one aggregate forces every CoS shard rotation to
      invalidate the entire aggregate Arc, which dominates the win.
- (c) gates `cos_interfaces` non-emptiness on a separate flag and
      duplicates the (already-empty-by-construction) initial state
      logic. Adds branches on the per-tick drain path.

**At absolute scale** the win is: ~50 % reduction in
"helper-respawn-on-first-boot" events on a cold cluster. Each
respawn is roughly 250 ms of `Takeover ready: no`. The cluster is
already protected by VRRP failover and `#925`'s supervisor; no traffic
is lost. The win is operator-visibility cleanliness, not a correctness
or availability improvement.

**If reviewers conclude the perf/risk trade-off does not justify the
churn (i.e. that the #925 supervisor-respawn recovery is the right
design at this layer), PLAN-KILL is an acceptable verdict.** That is
the verdict this plan expects.

## What's already shipped / partially batched

- `#925` Phase 1 (`spawn_supervised_worker`) — catches Rust panics in
  worker threads and records them in `WorkerRuntimeAtomics.dead` plus
  `panic_slot`. **Does not catch SIGSEGV**: a real null deref kills
  the entire process. The Go-side helper supervisor in
  `pkg/dataplane/userspace/` is what restarts the process.
- `#1186` (`xpf_userspace_worker_dead` Prometheus gauge): operator
  visibility for the panic-catch path. Process-restart events are
  visible via `systemd`'s journald + the
  `userspace helper not enabled` reason string in
  `show chassis cluster status`.
- `#1188` (per-tick Arc refresh short-circuit): the `load() + ptr_eq +
  load_full()` pattern at `worker/loop_body/mod.rs:288-405`. Reduces
  the per-tick atomic-RMW cost of the existing per-slot ArcSwap
  consultation; any "combined publish" plan trades against this win.
- `#1318` early-exit on `should_enter_shaped_drain` — keeps idle
  workers from entering `drain_shaped_tx` at all, which is presumably
  the path leading to the segfaulting `drop_in_place<CoSBatch>` site.

## What we actually know about the crash

Anchored to the segfault evidence in
`docs/pr/1530-dpdk-final-validation/artifacts/run1-fw0-helper-race/fw0-helper-segfaults.log`:

```
[ 14.829224] xpf-userspace-w[879]: segfault at 0 ip <0x...32a4b6> sp ... error 4
[ 14.829561] xpf-userspace-w[884]: segfault at 0 ip <0x...32a4b6> sp ... error 4
[ 14.829754] xpf-userspace-w[880]: segfault at 0 ip <0x...32a4b6> sp ... error 4
[216.405295] xpf-userspace-w[1241]: segfault at 0 ip <0x...32a4b6> ...
[216.405342] xpf-userspace-w[1236]: segfault at 0 ip <0x...32a4b6> ...
[216.405639] xpf-userspace-w[1237]: segfault at 0 ip <0x...32a4b6> ...
```

The `error 4` (read fault, user-mode, not present) plus
`segfault at 0` indicates `mov 0x18(%rbx),%r14` with `%rbx == NULL`.
Six workers segfault simultaneously across two separate helper
lifetimes (different ASLR load addresses, same RIP offset).

The exact binary (sha256
`975f6fe3e740fd24d79c7ff195ba1e7f78ebd8ae6f94ce6dfec604836a17a448`)
is **not available on this host** — the cargo target dir was rebuilt
during the retirement chain, and no `xpf-userspace-dp` binary with
that sha exists under `/dev/shm/`, `/tmp/`, or any worktree
(`find / -name xpf-userspace-dp` confirms). Any new build will have
different offsets, so a clean
`objdump --disassemble-symbols=core::ptr::drop_in_place<...CoSBatch>`
on a current binary is the only path forward and we cannot match the
exact instruction stream of the crashing build.

### Crucial detail about the fingerprint

The original issue body's objdump excerpt shows:

```
32a4ad: pop %rbp
32a4ae: jmp *0x15749c(%rip)        # <_DYNAMIC+0x248>
32a4b4: mov 0x18(%rbx),%r14       <-- CRASH HERE
```

A `jmp *<got>` at `32a4ae` is a **tail call** (typical Rust release
build epilogue calling into a PLT slot — most likely `__rust_dealloc`
or an inlined `Vec::drop`'s free). Control never falls through after
a tail call. So **the instruction at `0x32a4b4` is not reachable from
the `32a4ae` jmp** — it belongs to the next function packed adjacently
in `.text`, almost certainly an inner-Drop glue (`drop_in_place::<VecDeque<TxRequest>>`
or similar) that `addr2line` happened to attribute to the surrounding
`drop_in_place<CoSBatch>` symbol because there is no separate symbol
boundary.

This means the surface-level fingerprint
`drop_in_place<CoSBatch>` is misleading. What is actually executing
at the crash IP is most likely one of:

- `drop_in_place::<VecDeque<TxRequest>>` (the `items` field's drop)
- `drop_in_place::<TxRequest>` (per-element drop)
- An inlined free-loop body in either of the above

The `%rbx` register is the conventional first-argument receiver after
the System V prologue (`mov %rdi, %rbx`). If %rbx is null entering
this inner drop, the inner pointer (`items.buf.ptr`, `items.head`,
etc.) is being passed in as null **by the caller** — i.e. the outer
CoSBatch from which `items` was extracted has had its `items` field
torn out and replaced with a zero-initialized stand-in, then the
outer drop walks the moved-from CoSBatch.

This is consistent with a panic-during-move scenario:
`submit_cos_batch` destructures `CoSBatch::Local { items, ... }` and
moves `items` into `submit_local()`. If `submit_local()` panics
before consuming `items`, Rust's unwind machinery may invoke
`drop_in_place` on the moved-from binding — but the `items` value
has already been moved and the slot is dropped via drop-flag
machinery in release builds is **statically eliminated**.

So the most likely scenario, given the fingerprint, is **not** a
torn-Arc publish but a **panic inside `submit_local()` / `submit_prepared()`
during the first drain pass** that unwinds across a partially-moved
CoSBatch and triggers drop on uninitialized memory. The first drain
pass after snapshot install is unusual in two ways:

1. `cos_interfaces` may have queues that the worker has not yet
   primed (priming happens lazily in `prime_cos_root_for_service`).
2. Inner `transmit_batch` consults `binding.xsk.tx_ring` which may
   not yet be wired if the binding ready check has not fired.

### What the bisect agent already established

- Multiple workers segfault simultaneously at the same offset, twice
  in a row, with different ASLR bases → **same machine-code site**,
  reached from multiple parallel call stacks.
- Same exact binary, second cold boot: clean run, no segfault.
- Issue does **not** reproduce on fw1 of the same cluster running the
  same image at the same boot epoch.
- The CoSBatch type itself has not been touched since April 2026
  (`f0081b1f`).

## Concrete design (three candidate fixes — all candidate for KILL)

### Candidate (a): startup barrier

```rust
// In worker_loop, after building cos_fast_interfaces:
loop {
    if validation.snapshot_installed
        && !cos_owner_live_by_queue.is_empty()
        && !cos_shared_root_leases.is_empty()
    {
        break;
    }
    if stop.load(Ordering::Relaxed) { return; }
    std::thread::sleep(Duration::from_millis(1));
    // reload all shared arcs
}
```

Costs:
- Adds startup latency of up to one publish-cycle (~10 ms).
- Couples worker readiness to coordinator readiness in a tighter way
  than the current "publish-then-spawn" sequence in
  `apply_snapshot` + `bringup`.
- Does **not** address the supposed root cause (panic during move),
  only delays the first drain pass.

### Candidate (b): atomic publish of CoS aggregate

Collapse `coordinator/mod.rs:618-641` to a single
`Arc<ArcSwap<CoSAggregate>>` swap. The aggregate would hold the six
maps (`owner_worker_by_queue`, `owner_live_by_queue`, `root_leases`,
`exact_backlogs`, `queue_leases`, `queue_vtime_floors`) as fields of
one struct. Workers do **one** `load_arc_if_changed` per tick instead
of six.

Costs:
- Defeats the `#1188` short-circuit win for the 5 of 6 slots that
  did not change on a given snapshot.
- Every per-binding-queue rotation invalidates the whole aggregate.
- Forces a full `build_worker_cos_fast_interfaces` rebuild on any
  CoS sub-state churn.
- Does **not** explain the null deref because the destination of the
  null `%rbx` is **not** an Arc field — it is the receiver of a Vec
  drop, which is owned by the local CoSBatch, not by any ArcSwap.

### Candidate (c): lazy `cos_interfaces` init

Workers start with empty `cos_interfaces`. `build_worker_cos_fast_interfaces`
returns an empty `FastMap` until **all** of the dependent shared
arcs have been observed non-empty in the same tick. Sentinel:
`(owner_live_by_queue, root_leases, queue_leases)` jointly non-empty.

Costs:
- Adds a one-shot branch on per-tick rebuild path.
- Does not target the actual fingerprint — the crash is in
  `Vec`/`VecDeque` drop within a CoSBatch on the worker's own stack,
  not in shared state.

## Why each candidate is suspect

None of the three explains the observed fingerprint. The fingerprint
points at a Vec/VecDeque drop receiver being null, which can only
happen if the CoSBatch was constructed with a null inner pointer or
if a panic during move caused drop glue to run on a partially-moved
value.

Candidates (a)–(c) all assume the bug is in the ArcSwap publish
ordering. The bisect agent already considered this and produced
NO-LOCALIZATION. The actual root cause is more likely:

- A use-after-move that the borrow checker does not catch because
  the move target is `pub(super) fn submit_local(... items: VecDeque<TxRequest>, ...)`
  and `items` is moved by value; **a panic inside `submit_local`
  before `items` is consumed** would invoke drop on a partially-moved
  CoSBatch — but Rust's release-mode codegen eliminates the drop
  flag and treats the move as definite, so the outer destructor
  never runs against the moved field.
- A genuine miscompile in the Rust toolchain (very unlikely; not
  reproducible after first boot).
- Memory corruption from an upstream FFI boundary (`xsk_ffi`,
  `userspace-xdp`) clobbering stack slots adjacent to the CoSBatch
  during init.

We cannot distinguish between these without a captured core dump
that has not been collected on either boot (systemd-coredump is not
installed on the test cluster).

## Public API preservation

For (b) only: `Coordinator::cos.*` accessors would have to change
shape from six independent `ArcSwap`s to one aggregate. Every call
site of `shared_cos_*` (the worker-loop function signature has six
parameters; `coordinator/reconcile/bringup.rs:206-211` clones all
six) would have to change. This is a non-trivial refactor that
touches the worker spawn boundary.

## Hidden invariants the change must preserve

- **Side-effect ordering**: the coordinator's `refresh_cos_runtime_maps`
  publishes `owner_worker_by_queue` **before** `owner_live_by_queue`
  so that workers reading "live" never reach a slot the "owner" map
  has not yet promoted. Any atomic-publish plan must preserve this.
- **`#1188` short-circuit semantics**: per-slot `load_arc_if_changed`
  must remain O(1) on the unchanged path.
- **HA sync portability**: CoS state is purely local; no HA sync
  contract changes.
- **Stale-handle hazards**: `cos_fast_interfaces` is cloned into each
  binding (line 423-424 of `worker/loop_body/mod.rs`) — any plan
  that defers initialization must re-publish before the first
  drain tick that observes any non-empty `pending_tx_local`.

## Risk assessment

| Risk class                                    | Level | Notes |
|-----------------------------------------------|-------|-------|
| Behavioral regression                         | HIGH  | Touches startup ordering; barrier candidates could deadlock if coordinator hangs. |
| Lifetime / borrow-checker shape               | LOW   | All proposals are `Arc`-shape preserving. |
| Performance regression                        | MEDIUM | (b) defeats `#1188`; (a) adds startup latency. |
| Architectural mismatch                        | HIGH  | All three candidates assume the bug is in ArcSwap publish; fingerprint suggests it is not. |

## Test plan (if landing)

- `cargo build --release` clean
- `cargo test --release` full suite (940+ tests)
- 5/5 named-test flake check on `cos_interfaces_rotate_during_publish`
  (new test exercising parallel `worker_loop` ArcSwap consumption
  during coordinator publish).
- Go suite: 30 packages pass.
- Smoke v4 + v6 × push + reverse × CoS-off + CoS-on on
  `loss:xpf-userspace-fw0/fw1`.
- **Targeted repro attempt**: 20× cold-boot loop of
  `incus restart loss:xpf-userspace-fw0` immediately followed by
  CoS-on push smoke. Pre-fix baseline: ~50 % helper-respawn rate.
  Post-fix gate: 0 helper-respawn across all 20.
- `systemd-coredump` installed on the test cluster so future
  reproductions yield real cores.

## Out of scope (explicitly)

- Catching SIGSEGV in-process (Rust does not give us this; signal
  handlers cannot safely re-enter the Rust runtime).
- Replacing the Go-side helper supervisor with anything fancier.
- Closing `#925` "no-respawn" criterion 1 — the current contract is
  silent recovery and the issue body explicitly does not propose
  changing that.

## Open questions for adversarial review

1. **Is the fingerprint actually `drop_in_place<CoSBatch>`?** The
   tail-call jmp at `0x32a4ae` suggests the crash IP at `0x32a4b4`
   belongs to a different inner-Drop function packed adjacently.
   Does the reviewer accept that addr2line's symbol attribution is
   approximate when symbols are tightly packed?

2. **Is the "50 % first-boot reproduction" claim reliable?** The
   issue cites 3 of 6 helper restarts on fw0 across two Runs of
   `#1530`, and 0 of 3 on fw1. With six data points this is a 50 %
   point estimate with a wide CI; the true rate could be 20–80 %.
   Does the reviewer believe this volume justifies the proposed
   churn?

3. **Does PLAN-KILL leave a real user-visible defect?** The
   supervisor restart is silent in `Takeover ready` output for
   ~250 ms. No traffic loss; no HA failover triggered (RG 0 stays
   on the secondary's peer; RG 1 fails to take over until restart
   completes, but the peer is already primary). The operator-facing
   degradation is one line in `show chassis cluster status` for a
   couple hundred milliseconds. Is this worth the structural risk
   of altering the ArcSwap publish path?

4. **Would a `core_pattern` change plus a release-mode binary with
   `-C debuginfo=2` give us a clean reproduction?** We could land a
   *diagnostic-only* PR that installs `systemd-coredump`, sets
   `coredumpctl` retention, and adds a test-cluster helper to
   capture cores on first-boot crashes. This is a smaller, safer
   change with strictly higher information value than any of (a)–(c).

5. **Is there a simpler defensive measure?** E.g., gate
   `drain_shaped_tx` on `validation.snapshot_installed`. Today only
   `classify_metadata` checks that flag. Adding the same check at
   the entry of `drain_shaped_tx` would short-circuit the entire
   suspect path until first snapshot — at the cost of one branch
   per drain tick. This is candidate (a-prime) and may be
   defensible if (a) is judged too heavy.

6. **What confidence do we have that any of (a)–(c) would actually
   fix the race?** None of them target a verified causal chain.
   Shipping any of them would be a hopeful guess.

## Expected verdict

Given:
- The race is structurally bounded (only first-boot, never recurring).
- The supervisor-respawn recovery is the explicit `#925` design
  contract.
- The retirement-chain explicitly de-blocks this issue.
- None of the candidate fixes target a verified causal chain.
- A diagnostic-only PR (Q4) is strictly higher EV.

**This plan expects PLAN-KILL × 2** (Codex + AGY), with the
follow-up being either:

- close `#1561` as "expected behavior per `#925` supervisor recovery"
  with the diagnosis recorded; or
- open a smaller diagnostic-only PR for `systemd-coredump` + a
  `core_pattern` test fixture (Q4 above) so the next reproduction
  yields a real core.
