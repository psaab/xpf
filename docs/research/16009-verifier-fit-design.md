# #16009 — verifier-fit design amendment

- **Status:** design/research only. This change proposes no production
  implementation and authorizes none.
- **Amends:** `docs/research/16009-host-screen-plan.md`. All worker
  semantics, C1–C35, map/mask meaning, 11 terminal-arm placement, and
  successor boundaries remain as landed. This amendment ranks bounded
  parser shapes and pre-registers a finite prototype/measurement order;
  it does not delete coverage or relax K1.
- **Source base:** worktree `wt-16009fit` at `a5cbd72c25` (plan text
  folded at `6c9098dcfb`, based on `6c27f54cf2`). The failure measurements
  below come from `wt-16009impl/docs/log/16009.md`, a dirty, unpushed
  implementation worktree rebased on `c10b3aa064`. That log is cited as
  measurement evidence only; none of its source changes are adopted.
- **Lane log location:** `docs/log/16009.md` is absent on this branch.
  The only local measured-failure record found is the dirty implementation
  worktree above, plus the parent record on issue #16009. The landed plan
  §12 directs a `docs/log/16009.md` update for implementation/landing
  commits, not for this research-only document. Accordingly this change
  adds this design document only.

---

## 1. Hard constraints carried forward

### K1 — unchanged

The source-base object measured **779,213 processed instructions** of
1,000,000 (22.0787% headroom; 15% floor) in
`pkg/dataplane/userspace_xdp_gate_verdict.json` at `6c27f54cf2`.
The landing ceiling remains **≤850,000 processed instructions**, floor
PASS, and `override_consumed: false`. `XPF_SHIM_ALLOW_LOW_HEADROOM`
(`cmd/shimverify/main.go:232ff`) MUST NOT be used to waive a reject or
low-headroom result. Only a complete-object measurement is K1 evidence.

### Invariants and semantics — unchanged

- `ParsedPacket` (`userspace-xdp/src/lib.rs:2148-2195`) and `ExtWalk`
  (`ipv6_ext_walk.rs:191-226`) gain **zero fields**. Keep
  `MAX_EXT_HDRS` (=7, `ipv6_ext_walk.rs:49`), walk advance/break rules,
  and `parse_l4` signatures unchanged.
- Keep one current packed per-packet word, with checked writes and a
  fail-closed read/write posture (plan K2); profile mask bits stay
  independent, including SYN+FIN/no-flag/FIN-without-ACK/WinNuke.
- Keep the outlined gate and invoke it only at the 11 selected terminal
  kernel-PASS arms. Do not gate transit, move either LAND call, change
  reason indices 21/22, or omit an arm.
- Preserve the worker's exact predicate/error split in landed-plan §§4–5:
  IPv4 malformed options are an extractor error even when a valid LSRR/
  SSRR is also present (`screen/extract.rs:224-241,258-299`); a second
  readable non-atomic IPv6 Fragment header is a separate parse error
  (`:357-365`); IPv4 tiny-declared flags and capture-unknown flags remain
  distinct; C22 remains an explicitly disclosed divergence. IPv6 tiny
  packets remain earlier `L3 PARSE_FAIL` controls (C18/C19), not host-screen
  parity.
- Every C-cell C1–C35 retains its existing meaning, including C21's
  duplicate notification, C23's 128 dual-stack TCP outcomes, and C18/C19/
  C22's explicit non-parity framing. No proposed shape reduces that set.

### One plan/implementation seam to resolve before coding

Landed-plan §5.2 says the extension walker stays map-free and that a
Routing callback observes `rh[2]` after full-header bounds validation.
The failed implementation instead made a generic observer whose BPF
callbacks touched `USERSPACE_SCREEN_SCRATCH` inside the walk; its generic
Routing arm read a three-byte prefix before the full-span revalidation.
The lane log records an `off=56` rejection for the original variable-length
Routing read, then an instruction-cap rejection after changing to a fixed
three-byte prefix. Therefore the callback contract does not yet identify a
measured verifier-fit BPF shape. This amendment keeps the host-witness
requirement but separates fact accumulation from map access, and requires
any routing-type read to be checked and associated with the already-validated
header span. Whether this resolves K1 is an experiment, not an assumption.

---

## 2. Existing precedents to reuse

1. **Per-CPU scratch laundering.** `userspace_v6frag_scratch` is a
   `PerCpuArray<u8>` at `userspace-xdp/src/lib.rs:603-604`. Its rationale
   at `:588-602` records the crucial verifier behavior: reading a second
   walk-derived value directly defeats state merging; an opaque map value
   restores merging, with the recorded historical comparison of direct
   consumption rejecting at 1,000,001 versus a laundered variant verifying.
   The current parser writes then reads the slot at `:2435-2462`, fail-closed
   on either operation.
2. **Do not widen packet/walk returns.** `ParsedPacket`'s own comment at
   `lib.rs:2150-2156` records that widening it by a `u16` relocated a packet
   read and rejected the object. The landed #16009 plan §3 records a prior
   `ExtWalk`/`ParsedPacket` widening that reached 1,000,001 and identifies
   downstream verifier-state multiplication as the reason not to revive it.
3. **Choose outlining per function.** `land_gate` is `#[inline(never)]`
   (`lib.rs:2605-2636`), as are other map-touching helpers at `:2647-2676,
   2738-2790`. By contrast, `parse_l4` is deliberately `#[inline(always)]`
   (`:2838-2900`): its comment records measured subprogram/inlined results
   of 795,764/497,050 at `a02e55248`. These precedents prohibit blanket
   "outline everything" or "inline everything" advice; every new boundary
   is measured.
4. **The checked-read idiom.** The IPv6 walker (`ipv6_ext_walk.rs:284-343`)
   uses a 2-byte generic-header read, derives the span, then revalidates the
   advanced extent; its Fragment arm reads all 8 bytes before extracting the
   word. `parse_ipv4` already checks an IHL-sized header at `lib.rs:2281`,
   then derives parser facts from scalar locals (`:2292-2355`). The TCP
   arms in `parse_l4` document the same verifier-sensitive pattern:
   "Span first (scalar), read second (packet)" and one dominating bound per
   read (`lib.rs:2916-2938,2951-2959`). New reads must use the same checked
   discipline; exact offsets that the verifier accepts remain to be measured.
5. **Pure host/BPF arithmetic.** `ipv4_len_gate.rs`, `ipv6_len_gate.rs`,
   and `land.rs` are pure `core`-only helpers with host twins. Keep TLV
   semantics and verdict arithmetic pure; keep packet reads in the parser
   where their checked bounds are available. The IPv6 walker is itself
   host-compiled and exercised on real buffers (`ipv6_ext_walk.rs` module
   comment and `userspace-dp` parity tests).

---

## 3. Failure matrix — measured, not an instruction estimate

The following results are from `wt-16009impl/docs/log/16009.md`, section
"Rebased K1 isolation — 2026-11-06", base `c10b3aa064`. The generation
command there set `XPF_SHIM_ALLOW_LOW_HEADROOM=0`; no result below consumed
an override.

| Shape actually measured in the dirty lane | Result | Processed instructions / states |
|---|---|---:|
| Pristine base | PASS; 22.0787% headroom; 70,787 slack to 850,000 | 779,213 |
| Sink-only parser slice | PASS; 24.44% headroom; 94,380 slack to 850,000 floor boundary | 755,620 |
| Complete candidate with the original IPv6 variable-length Routing-header read | REJECT, `invalid access to packet, off=56 size=1`; same class in no-gate diagnostic | 30,642 complete-candidate diagnostic; 30,223 no-gate diagnostic |
| Isolated IPv6 observer with original Routing-header slice | REJECT, `off=56 size=1`; 2,136 total states | 30,152 |
| IPv6 fixed three-byte-prefix variant | Access reject cleared; instruction-cap reject | 1,000,001; 63,606 states |
| IPv6 map-accumulating / out-of-line callback variants | Instruction-cap reject | 1,000,001; 61,589 / 61,135 states |
| Outlined generic walker | Link failure: bpf-linker did not support resulting stack arguments | n/a |
| IPv4 TLV/options scan atop sink | REJECT, `off=34 size=1`; 5,672 states | 101,057 |
| IPv4 static-dispatch checked-byte reader | REJECT: `R3 tried to subtract pointer from scalar` | 101,488; 5,673 states |
| IPv4 stack-copy variants | REJECT, `off=35 size=1` | 101,366 / 99,774 |
| IPv4 tiny-declared + post-L4 TCP-trip slice | REJECT: **528-byte combined stack across 3 calls** | 775,418; 47,384 states |

These are slice diagnostics, not K1 results except the pristine base.
The F1 sink pass shows that a checked per-CPU scratch mechanism is not by
itself the blocker. The other slices fail independently, through three
different observed outcomes: packet-access verification, instruction cap,
and combined stack. The lane log does **not** establish the exact source
of the `off=34`/`off=35` tracking failures or the reason the post-L4 slice
reached 528 bytes; the alternatives below do not treat those causes as
proven. In particular, the log gives no grounds for claiming that one
particular syntax, helper attribute, or instruction-count heuristic will
fix them.

---

## 4. IPv6 observer facts — three candidate shapes

All shapes must preserve these facts from the validated extension walk:
first non-atomic fragment word/data start, duplicate readable non-atomic
Fragment before the existing non-first break, and Routing type 0/1 only.
Atomic-header and governing-header rules stay unchanged. Host tests must
still observe the first/duplicate notification for C21 and the route type
for RH0/RH1/RH2 controls. `ExtWalk` remains unchanged.

The current `ExtWalk` output (`offset`, `protocol`,
`non_first_fragment`, `fragment_seen`, `exhausted`) contains neither a
Routing-header type nor a non-atomic Fragment count. It cannot, by itself,
distinguish RH0/RH1/RH2 or one versus two non-atomic Fragment headers.
Do not repurpose `offset`/`protocol` as packed facts: their existing values
are consumed by parser callers and their domains have no reserved encodings.
Those facts must be accumulated from validated bytes during the existing
walk or discovered by a second call to that same walker; copying its advance
logic into a parser-side walk would create a second, unguarded parity surface.

### V6-1 (rank 1): stack-only accumulator inside the existing walk, map I/O after return

**Shape.** Keep the current single traversal and existing `ExtWalk` return.
Pass a small stack accumulator for the facts to the generic walker/observer.
At the Fragment arm, derive the word and post-header offset from the already
validated 8-byte slice; at the generic Routing arm, capture the routing type
only through a checked read associated with the validated header span; set
the duplicate fact before the existing non-first break. Observer methods
only update the caller's scalar accumulator; no map pointer, map read/write,
fallible return, or packet pointer crosses a callback. After the walk returns,
`parse_ipv6` packs those facts and uses the checked scratch write from the
sink pattern. Host callers pass a recording accumulator and assert the same
facts. Do not add fields to `ExtWalk` or change walk advances/breaks.

**Why first.** It preserves one validated walk and avoids the measured
map-access-in-loop form while keeping BPF packet access and map I/O outside
callbacks where practical. It also lets the host witness test the same walk.
**Uncertainty.** The fixed-prefix observer already cleared the immediate
`off=56` failure but still hit 1,000,001; the lane did not measure this
stack-only accumulator with post-walk map I/O. A generic mutable accumulator
may still raise verifier states. It is a candidate, not a claim of fit.

### V6-2 (rank 2): reuse the existing v6-fragment laundering slot

**Shape.** Use V6-1's local accumulator, then store the packed fragment/
route/duplicate facts through the existing `userspace_v6frag_scratch`
slot and read the opaque value back after the walk. Do not create a second
per-CPU state channel for the v6 facts. This requires changing the slot's
value from `u8` to a word large enough for the plan's packed facts and
reusing that one per-CPU slot for the later gate read (including the IPv4
parser if this replaces, rather than supplements, `userspace_screen_scratch`).
The write/read failure behavior must be fail-closed; stale values must never
reach the gate. Preserve the existing non-first protocol-laundering decision
at `lib.rs:2435-2462` from the same fresh value.

**Why second.** It applies the proven opaque-state mechanism to the facts
that otherwise leave the walk, and avoids a second map/state fork. It is
ranked below V6-1 because it changes an existing map's value-size ABI and
the map lifecycle/retirement contract; those compatibility constraints
must be resolved before the prototype can be considered viable. The
measurement cannot waive them.

### V6-3 (rank 3): a second pass through the same walker, scalar-only observer

**Shape.** Keep the existing no-observer traversal as the sole producer of
`ExtWalk`; after it succeeds, call the same shared walker again with a
stack-only fact accumulator (V6-1), then perform one checked scratch write.
Do not copy extension advance arithmetic into `parse_ipv6`; host and BPF
still execute the same walker. The second pass records route/fragment facts
but never changes parse disposition, `ExtWalk`, or the first pass's
protocol/offset. Failure of either walk remains the existing fail-closed
parse path.

**Why third.** It completely separates the established parser walk state
from fact collection and is straightforward to compare against the first
pass's `ExtWalk`; however, it repeats a walk bounded by `MAX_EXT_HDRS=7`.
Its instruction cost could consume K1 headroom. Use only if V6-1 fails on
state shape and V6-2 is rejected for map ABI reasons, and measure it once.

**Rejected, not a fourth try:** another observer with map reads/writes in
each callback, another variable-length `rh` slice, and outlining the generic
walker are already measured rejects (§3). Do not repeat them under a new
name. A `#[inline(never)]` generic walker is not an option unless a separate
linkable signature is demonstrated; the recorded attempt did not link.

---

## 5. IPv4 options — three candidate shapes

The parser already bounds the IHL-sized header at `lib.rs:2281`; options
are the bytes `[20, IHL)` and at most 40 bytes. The result must match the
worker extractor's malformed-before/after-LSRR behavior and LSRR/SSRR
semantics (`screen/extract.rs:224-241,258-299`). The measured dynamic TLV
scan and checked-byte/stack-copy attempts (§3) are rejected evidence, not
starting templates.

### V4-1 (rank 1): fixed-offset selector with a bounded, unrolled TLV state machine

**Shape.** Retain the existing checked IHL slice. Implement the TLV state
machine with a maximum of 40 byte positions, but no packet/slice access at
a dynamic `pos`: each kind/length-byte access is a constant-offset arm
selected by `pos` (e.g. `match pos { 0 => options[20], 1 => options[21], … }`),
with the IHL-derived real option length checked before selecting an arm.
Unroll the 40 positions or use a compiler-visible constant-dispatch helper;
no hand-built pointer arithmetic. Maintain the worker's rules: EOOL ends
scan, NOP advances one, other kinds require a length byte and length ≥2,
LSRR/SSRR require length ≥3, and any overrun/short TLV marks malformed.
Malformed suppresses the source-route fact. The scan is pure over the
already-held slice; output only the two verdict scalars for the packed word.

**Why first.** It changes the access shape itself: the parser state may
advance `pos`, but each byte selection is a constant-offset arm rather than
a dynamically indexed packet slice. This is not established to fit; it is
the first bounded experiment because it preserves one scan and avoids more
packet reads. It must be checked for generated code size and exact host
parity before full-object assembly.

### V4-2 (rank 2): copy the validated IHL slice once, then scan only stack bytes

**Shape.** Bind the existing `read_bytes(data, data_end, l3_offset, ihl)`
result, copy its options portion into a zero-initialized 40-byte stack
buffer using the held slice, and run the same bounded TLV machine against
the stack buffer with `ihl - 20` as the actual length. Padding is never
parsed. No additional packet pointer arithmetic occurs in the scan. The
copy itself must not issue reads beyond the held `ihl` slice.

**Why second.** It cleanly separates verifier packet access from loop
indexing, but consumes stack and resembles the already-failed stack-copy
family (`off=35`). It is admissible only if its implementation differs in
the relevant way: one copy from the already-held IHL slice and stack-only
scan, not another sequence of packet reads. Kill it immediately if it
reproduces the `off=35` failure or exceeds stack limits.

### V4-3 (rank 3): separate malformed-list pass and route-sighting pass, both fixed-dispatch

**Shape.** Use the V4-1 constant-offset access scheme, but split it into
two bounded scans: first determine well-formedness and short-circuit on
malformed; only a clean list is scanned again for LSRR/SSRR. Both scans
share the same validated slice and constant-offset selector. No TLV
semantics are omitted; the second pass does not run on an invalid list.

**Why third.** It costs more code and repeats the bounded scan, so it is
not preferred over a single pass. It is a diagnostic fallback only if the
combined state for the one-pass machine is rejected but the fixed-offset
access itself is accepted; it tests whether combining the two output facts
is responsible. It must be abandoned if the packet-access failure persists,
since splitting semantic outputs cannot cure an access failure by itself.

**Already-rejected variants:** the measured dynamic TLV/options scan
(`off=34`), static-dispatch checked-byte reader (pointer/scalar failure),
and stack-copy variants (`off=35`) (§3). Do not rerun those unchanged.

---

## 6. TCP post-L4 stack pressure — three candidate shapes

The failed slice is specifically IPv4 tiny-declared plus post-L4 TCP-trip
computation, which the lane log measured at 528 bytes across three calls
(775,418 instructions). The log does not identify which local or frame
caused the maximum; do not claim a causal stack allocation without a new
stack report. Preserve `tcp_trip_syn_frag`, independent Q1 bits, C22's
capture-unknown suppression, and all C23 combinations.

### TCP-1 (rank 1): compute facts, write the packed word immediately before address materialization

**Shape.** Keep the parser-local computation from the landed plan, but
shorten its live range: after L4 returns validated `protocol`, `tcp_flags`,
ports, and fragment facts, compute the compact trip bits into the one
existing word and perform the checked scratch write immediately, before
reading/copying the source and destination addresses into their 16-byte
arrays (`parse_ipv4:2353-2362`; IPv6's corresponding post-L4 region is
`:2468-2522`). Do not carry a second `u64`/trip struct across `ParsedPacket`
construction. Keep tiny-declared and capture-unknown facts distinct. This
is a placement change only; host twin must still compare all C23 outcomes.

**Why first.** It introduces no new helper, return value, or packet read;
it tests whether the measured stack peak is sensitive to keeping the packed
word live alongside address construction. It does not assume that this is
the cause of the 528-byte report; the stack diagnostic decides.

### TCP-2 (rank 2): derive Q1 mask trips in the already-outlined terminal gate

**Shape.** Keep parser-produced scratch facts for geometry, tiny/error
states, and `tcp_trip_syn_frag` if that is needed for the existing word
contract. Compute the four ordinary Q1 facts in `host_screen_gate` from
fields already in `ParsedPacket` (`protocol`, `tcp_flags`, destination
port, `is_fragment`, and `tcp_flags_unknown`), before intersecting with
the zone's independent mask. A first TCP fragment is recognizable from
`is_fragment && protocol == PROTO_TCP`; a non-first fragment uses the
existing no-L4 sentinel, and `tcp_flags_unknown` suppresses flags whose
byte is unavailable. No struct field or packet read is added. Update the
pure host twin so C23 still exercises all 16 masks × 4 shapes per family
(128 results), and C22 remains the same documented divergence.

**Why second.** It moves four comparisons out of the inlined parser chain
and into a gate that the plan already outlines. It changes work placement,
not semantics, but may increase the outlined gate's own verifier state or
stack. This shape is valid only if source-level and host-twin checks confirm
that the sentinel/first-fragment and capture-unknown predicates exactly
preserve the worker oracle.

### TCP-3 (rank 3): one small outlined scalar helper, with an explicit stack report

**Shape.** Keep the fact location at the parser convergence but place the
small pure boolean-to-trip-mask calculation in one `#[inline(never)]`
helper taking only scalar locals and returning a compact `u8`/`u16` mask.
No packet pointers/slices, arrays, map references, callbacks, or new
`ParsedPacket` fields cross the boundary. Keep the checked scratch write
at the parser convergence. Confirm the helper links and capture the
verifier's per-function/combined stack report.

**Why third.** `land_gate` and other map-touching helpers show outlining
can isolate large shared work (`lib.rs:2605-2790`), but `parse_l4` proves
that a small helper can cost more when verified across multiple call
states (`:2838-2900`). This is therefore a measured fallback, not an
instruction-count or stack guarantee.

**Not a shape:** adding an arbitrary short-circuit branch alone. It can
reduce executed comparisons, but the measured failure is stack, and a
branch does not by itself reduce the verifier's maximum frame accounting.
It may be included in TCP-1 only if it improves the measured full-object
result without changing C23/C22 semantics.

---

## 7. Composite ranking

| Rank | Combination | Reason for rank |
|---|---|---|
| **1** | **V6-1 + V4-1 + TCP-1** | One walk, no map access inside callbacks, fixed-offset TLV selection, shortest TCP fact lifetime. This minimizes new packet reads and extra walks/functions while preserving all facts. None of its verifier outcomes are claimed in advance. |
| 2 | V6-2 + V4-1 + TCP-1 | Prefer if laundering is required and the existing map's value-size/lifecycle contract can be safely migrated; one per-CPU state channel rather than a second map. |
| 3 | V6-1 + V4-2 + TCP-2 | Stack-only v4 scan and moved Q1 computation; use only if the relevant isolated measurements pass and full semantic twins stay green. |
| 4 | V6-3 + V4-3 + TCP-3 | Repeated IPv6 walk, repeated IPv4 scan, and outlined TCP helper make this the most expensive combination; bounded fallback only. |

No ranking is evidence that a candidate meets K1. The rank-1 combination
is the first candidate to build after the arm-level prototypes; a lower
rank is selected only by the measured reason the prior shape failed
(access, instruction cap, link, or stack). Do not combine arbitrary
changes to hide which fact arm causes a rejection.

Do not introduce a BPF tail-call as a verifier workaround. The plan needs
one parsed verdict at the existing 11 terminal arms; a tail-call would add
a program/map/dispatch boundary and would have to transport the parsed
facts through per-CPU state, reintroducing the channel whose representation
is under test. No measured result in the lane log supports that extra
architecture. The only subprogram candidates here are ordinary outlined
functions (TCP-3 or the already-planned gate); the generic-walker outline
is an observed link failure (§3).

---

## 8. Bounded prototype and measurement protocol

Run only in detached scratch worktrees derived from the same base, never
in `wt-16009impl`; never install a generated object. Use the exact pinned
command recorded in the lane log:

```text
CARGO_TARGET_DIR=/var/worktrees/.cache/cargo-16009 \
TMPDIR=/var/worktrees/.cache/tmpdir GOTMPDIR=/wtgt \
GOCACHE=/var/worktrees/.cache/go-build \
XPF_SHIM_ALLOW_LOW_HEADROOM=0 make generate-userspace-xdp
```

Record source hash, object hash if generated, build digest, processed
instructions, floor/headroom/override fields, full verifier rejection
signature, per-function stack and combined-call stack, and which C-cell
host twins were exercised. Never treat a partial/slice build as K1 PASS.

### Exact order and cap

1. **Base control:** use the already-recorded same-base baseline
   779,213/1,000,000, floor PASS, override false. If the toolchain,
   build inputs, or source base differ, run one clean baseline first;
   a failed/mismatched control stops the experiment as environment drift.
2. **IPv6: up to 3 candidate attempts, in rank order:** V6-1 first. If it
   fails because of loop-state/instruction pressure (not packet-access
   bounds), try V6-2 if the value-size/lifecycle change is acceptable;
   otherwise try V6-3 once. If V6-2 is usable but fails, try V6-3 only
   when its second-pass shape addresses the recorded failure. If the
   routing-type read still fails packet-access verification, stop this arm:
   V6-2 and V6-3 retain the same validated routing-type read and cannot
   be counted as access fixes. Before each verifier run, run the host
   walk parity corpus for fragment governing/atomic/duplicate and
   RH0/RH1/RH2. Do not repeat the measured map-access-in-loop, unvalidated
   variable-length read, or generic-walker-outline forms.
3. **IPv4: up to 3 candidate attempts, in rank order:** V4-1; V4-2 only
   if V4-1's failure is access tracking and the held-slice/stack-only
   shape is materially distinct; V4-3 only if fixed-offset access is
   accepted but the one-pass state shape is rejected. Run host tests
   for LSRR/SSRR, malformed TLVs before and after a valid route, short
   lengths/overruns, EOOL/NOP, and malformed-option row-presence behavior
   before each verifier run.
4. **TCP: up to 3 candidate attempts:** TCP-1; if stack remains above
   512 bytes, TCP-2; if the outlined gate instead fails its own stack or
   instruction budget, TCP-3. Run the full host TCP matrix (C23's 128
   outcomes plus C22) before each verifier run.
5. **Complete candidates: at most 3 full-object builds.** Assemble the
   highest-ranked measured-viable candidate per arm and all unchanged
   plan features (mask map, gate, all 11 call sites, reason mirrors).
   Measure the complete object, then use the next already-prototyped
   shape only when the rejection signature identifies that arm. No
   previously rejected form may be tweaked outside its pre-registered
   shape. At most two re-compositions after the first are allowed.
6. **One final confirmation build** of the identical successful complete
   source hashes. K1 passes only if both complete builds report ≤850,000,
   floor PASS, and `override_consumed: false`; record the final object
   and source hashes in the prescribed artifacts when implementation is
   authorized. Run C1–C35 BPF tests and the dual-stack smoke only in the
   Class-R VM lane after K1 passes; the lane log records these were not
   examined on the workstation.

**Hard budget:** no more than **9 isolated shape attempts** (3 per fact
arm), **3 complete-object candidates**, and **1 identical-source final
confirmation**: **13 verifier runs maximum** (14 only if a new baseline is
required due to changed build inputs). A shape gets one isolated run; no
cosmetic retries, no open-ended attribute toggling, and no attempt is
repeated unless it is the predeclared final confirmation.

### Stop rule

Stop the prototype and return to architecture step 0 (the landed plan's
explicit re-plan point) when any of the following holds:

- all three predeclared shapes for any fact arm fail; or the only remaining
  alternatives require a struct/walk widening, a changed `MAX_EXT_HDRS`/
  advance/break rule, a second independently implemented parser walk, or
  missing/altered C-cell coverage;
- the 3-composition limit is exhausted without a complete object at
  ≤850,000, floor PASS, override false;
- any verifier run consumed the low-headroom override or the team proposes
  removing Q1/C23 coverage to make the count fit;
- a selected shape fails its host semantic twin, changes a C-cell result,
  or cannot link under the pinned toolchain.

The re-plan may consider the landed plan's named architecture alternatives
(including redirect-to-worker) and the plan's reviewed S7 route if Q1 is
explicitly removed. The experiment itself may not narrow scope, relabel a
partial object as K1, or continue with an unbounded fourth variant.

---

## 9. Recommendation

First prototype **V6-1 + V4-1 + TCP-1**, in that order, with no production
landing until the bounded sequence above selects a complete-object
candidate. If V6-1 fails specifically through state growth, measure V6-2
only after resolving its map value-size/lifecycle contract; V6-3 is the final
v6 fallback. If V4-1 fails on packet-access verification, measure the
materially distinct held-slice stack copy once, then stop that arm if it
fails. If V4-1 passes access but fails on the combined state shape, V4-3
is the one diagnostic alternative. If TCP-1 remains over the stack limit,
move only the four ordinary Q1 calculations into the existing outlined
gate (TCP-2), then measure TCP-3 once if necessary. The maximum work and
stop conditions in §8 are binding.

No production implementation, source modification outside this document,
verifier run, override, coverage change, or artifact generation is part of
this amendment.
