//! #5173: the packet's RX queue coordinate and the binding slot it resolves to,
//! in a module that compiles for the HOST as well as for `bpfel-unknown-none`.
//!
//! AF_XDP delivery is queue-bound: `xsk_rcv_check()` in `net/xdp/xsk.c` compares
//! BOTH `xs->dev != xdp->rxq->dev` and `xs->queue_id != xdp->rxq->queue_index`,
//! so a redirect to a socket bound to a different netdev or a different queue is
//! rejected and the packet dropped. The coordinate must therefore survive
//! unchanged between "which queue did this arrive on" and "which XSK do we
//! redirect to".
//!
//! WHY THIS IS A MODULE AND NOT A SET OF SOURCE CHECKS. The first attempt
//! asserted the invariant with tests that read the shim's source TEXT. Hostile
//! review escaped them twice with every guard green: by reducing the coordinate
//! at the CALL SITE, and by adding a raw fallback lookup in a DIFFERENT file,
//! which a file-scoped text check cannot see by construction. Source-spelling
//! tests are the wrong tool for a property that can be compiled or executed
//! instead — so the mapping moved here, where a host test RUNS it.
//!
//! WHAT IS ENFORCED, AND WHAT IS NOT — stated precisely, because the difference
//! is the whole point and because an earlier revision of this comment
//! overstated it:
//!
//!   - **Compile-time.** [`RawRxQueue`] wraps the coordinate with a PRIVATE
//!     field and implements no arithmetic. `queue % 2`, `queue & 3`, `queue >> 1`
//!     do not compile outside this module (E0369), and neither does the tuple
//!     constructor (E0423). A future author who genuinely needs to transform it
//!     must add a visible, reviewable accessor. That property holds only while
//!     the field stays private and no arithmetic impl exists, and BOTH are now
//!     bounded by the parity tests — a hostile round added an arithmetic impl
//!     plus a public field and nothing went red, which with one extra line
//!     reintroduced the defect with no `unsafe` marker anywhere in it.
//!   - **Executed.** [`binding_slot`] is host-compiled and RUN by the parity
//!     tests over both coordinate axes, so the mapping, the stride bound and
//!     the property that a slot never leaves its own interface's row are
//!     behavioural results rather than claims about text.
//!
//!     The axes are POWER-OF-TWO LADDERS — `2^k`, `2^k - 1` and `2^k + 1` for
//!     every representable k — and NOT the hand-picked spread an earlier
//!     revision of this comment described. That revision also got its own gap
//!     wrong in both directions: it named the only uncovered range as
//!     "ifindexes large enough for `ifindex * BINDING_QUEUES_PER_IFACE` to
//!     overflow `u32` (2^28 and up)", while the grid it described actually
//!     stopped at ifindex 65535 and at queue 63. That is not a rounding error
//!     in a comment, it is the whole defect: `& 0xffff` is the identity on
//!     every ifindex such a grid tests and `& 0x3f` is the identity on every
//!     queue it tests, so the largest value on each axis WAS the boundary of
//!     the mask that would walk through it. A hostile round added exactly those
//!     two masks to the two bodies below, compiled them, and left every guard
//!     green with a masking instruction in the emitted object.
//!
//!     A ladder has no such tell: the OR of the tested values is all-ones
//!     across the representable range, so a mask that clears ANY bit changes at
//!     least one tested result. The range that used to stop the
//!     interface-half axis — at or above 2^28, where the plain `u32` multiply
//!     overflowed and host and target genuinely disagreed (a debug host build
//!     PANICS while the release target WRAPS) — is closed by the checked
//!     multiply below: what overflowed now resolves to no slot, on both
//!     targets identically, so both executed axes run to `u32::MAX` and the
//!     ladder asserts the `None` above 2^28 - 1 exactly as it asserts exact
//!     slots below it. `(2^28 - 1) * BINDING_QUEUES_PER_IFACE + 15` is exactly
//!     `u32::MAX`, so that value is the largest addressable slot rather than
//!     a ceiling with a stated reason. A kernel interface index is an `int`
//!     and the shim gates on its ingress-interface map before reaching here;
//!     a wild value that clears that gate now fails closed as a clean miss
//!     instead of wrapping onto another row (#9900 F-150).
//!   - **Pinned as text — the BODIES, not only the signatures.** Widening an
//!     executed axis relocates a boundary; it does not remove one. So all three
//!     function bodies in this module — the constructor, the telemetry readback
//!     and [`binding_slot`] — are pinned token-for-token by the parity tests,
//!     exactly as the call sites in `lib.rs` already were. (Their symbol names
//!     are deliberately not spelled here: the parity tests pin how many times
//!     each is named in this crate, so prose that repeats one is a spurious
//!     RED.) That is what closes the class rather than moving
//!     it: a body is the one place an in-place arithmetic edit costs nothing
//!     else. It creates no binding, needs no dependency, spends no mention from
//!     the per-file tally and touches no pinned statement, which is why every
//!     other bound here was blind to it.
//!   - **NOT closed by a TYPE, and that list is not empty.** The constructor
//!     must accept a bare `u32`, because the value originates in an aya
//!     `XdpContext` that cannot cross into a `core`-only module. So (a) a
//!     reduction applied to the integer BEFORE it is wrapped still compiles,
//!     and (b) so does any construction of the wrapper that goes around the
//!     constructor entirely by fabricating it from raw bytes — a `transmute`,
//!     `mem::zeroed`, `MaybeUninit::assume_init`, a pointer read. (b) is a
//!     CLASS, not a symbol, and naming only `transmute` — as an earlier
//!     revision of this comment did — invites an audit that greps for one word
//!     and misses the rest; the field's visibility is irrelevant to all of
//!     them. A third residual is that [`binding_slot`] types the queue half of
//!     the index and not the ifindex half, so reducing the ifindex is never
//!     rejected by the type system.
//!
//!     What bounds all three is source, in the parity tests, and it is worth
//!     saying HOW because two obvious ways do not work. NOT by enumerating the
//!     fabrication symbols, which would always be one symbol behind. And NOT by
//!     matching the `let` + name token pair a shadow is usually spelled with:
//!     that is one binding FORM out of many, and a tuple pattern, a
//!     `let … else`, a `macro_rules!` body taking an `$n:ident` and a closure
//!     parameter each rebind without writing it — a hostile round drove a
//!     compiled defect through all four. What works is COUNTING, per file. The
//!     lookup statement is pinned so both coordinates must arrive under a fixed
//!     NAME, and the number of times each of those names appears in each file
//!     of the crate is pinned too. A binding written in this crate cannot exist
//!     without writing the name it binds, whatever form it takes, so every one
//!     of them moves that tally.
//!
//!     "Written in this crate" is a real qualifier and an earlier revision of
//!     this comment left it out. A PROC MACRO binds a name without writing it
//!     here: its expansion carries `Span::call_site()`, which resolves — and
//!     shadows — at the invocation. A hostile round built one outside the walked
//!     directory, invoked it with a single line naming neither coordinate, and
//!     the emitted object gained a mask on the queue index with every source
//!     bound green. Counting cannot see that, so the parity tests bound the
//!     ROUTE instead: this crate's `Cargo.toml` is pinned token-for-token and
//!     both cargo configs read for this build refuse `--extern`, `[patch]` and
//!     `[replace]`, so acquiring a proc macro IN TREE reds. That bounds
//!     acquisition and nothing more — the two dependencies already pinned (one
//!     of which is a proc-macro crate, since `#[xdp]` comes from it) are
//!     upstream code no test here reads, and a cargo config or `RUSTFLAGS`
//!     outside the repository is not source at all.
//!
//! The honest summary: the source-asserted surface cannot reach ZERO while the
//! coordinate originates in aya-dependent code. What remains is CONSERVATION —
//! a tally bounds occurrences, it classifies them only in part, so an author who
//! DELETES an existing use or line of prose can pay for a shadow and leave the
//! tally where it was. The two coordinates are in different positions and the
//! parity tests say so precisely rather than in the aggregate: for the queue
//! half every mention in the packet-path file is already inside a pinned
//! statement, so that name's budget there is spent; for the interface half free
//! mentions still exist outside the index path, and that is stated there as an
//! open residual rather than defended.
//!
//! **An earlier revision of the sentence above went on to say "so there is
//! nothing free to spend there", and that was FALSE — it treated a spent budget
//! for the two COUNTED names as a closed hole.** It is not one, because what a
//! tally bounds is which names are WRITTEN and how often, and what a statement
//! pin bounds is how the construction is SPELLED. Neither bounds what a THIRD
//! name inside that statement is BOUND TO. The demonstrated form attacks `ctx`:
//! shadow it a few statement-scope lines above the pinned construction with a
//! zeroed `xdp_md` carrying a masked queue index, restore it before
//! `bpf_xdp_adjust_meta` needs the real one, and the byte-identical pinned
//! statement reads the doctored struct. Measured on this tree: it builds, the
//! live kernel verifier PASSes, the emitted object gains a mask and LOSES the
//! stride guard, and every parity test stays green. The context binding is now
//! counted per file, and a `let`-rebinding of it is refused outright, which
//! closes the demonstrated forms — it does not close the class, because the
//! class is about what a name RESOLVES TO and every instrument here is about
//! what the source SAYS. (The refusal is why this paragraph writes "the context
//! binding" where it means the identifier: spelling `let` immediately before it
//! would trip the parity test on prose.)
//!
//! What the bounds can do, and now do, is make
//! every reintroduction of #5173 DEMONSTRATED in six hostile rounds either fail
//! to compile, fail a pinned token sequence — a statement, a signature, or this
//! crate's manifest — trip a refused build capability, or move a pinned tally.
//! Undemonstrated variants of the conservation escape are not covered, on
//! EITHER coordinate and on the context binding as well, and the parity tests
//! name the mentions that are still free.
//!
//! Nothing here may depend on `aya`, on a BPF map, or on `std` — that is what
//! keeps it host-compilable, and it is the whole point.

/// Queue stride of the flat binding array. The index is
/// `ifindex * BINDING_QUEUES_PER_IFACE + queue`, so this is the exclusive upper
/// bound on an addressable queue id: at or above it the index would land in the
/// NEXT ifindex's row. Mirrored by `bindingQueuesPerIface` in
/// `pkg/dataplane/userspace/maps_sync.go` and `BindingQueuesPerIface` in
/// `pkg/dataplane/constants.go`, both of which already refuse to publish a
/// higher queue id (#4894).
pub const BINDING_QUEUES_PER_IFACE: u32 = 16;

/// Capacity of the two maps keyed by `UserspaceBindingValue::slot`:
/// `userspace_heartbeat` and `userspace_xsk_map`.
///
/// This is a DIFFERENT axis from [`BINDING_QUEUES_PER_IFACE`] and from
/// `BINDING_ARRAY_MAX_ENTRIES`, and conflating them is the trap. The binding
/// ARRAY is addressed by the composed index `ifindex * BINDING_QUEUES_PER_IFACE
/// + queue`, so its capacity scales with the ifindex axis (`MAX_INTERFACES *
/// BINDING_QUEUES_PER_IFACE`). The heartbeat and XSK maps are addressed by
/// `binding.slot`, which the helper's planner assigns DENSELY — a plain counter
/// over the bindings it actually planned (`replan_bindings_from_candidates` in
/// `userspace-dp/src/server/helpers/planning.rs`). So this constant is a
/// ceiling on the TOTAL NUMBER OF BINDINGS, not on any ifindex or queue id.
///
/// It is 256x smaller than `BINDING_ARRAY_MAX_ENTRIES`. A bound checked against
/// the larger value therefore does NOT protect these two maps (#7497): a slot
/// admitted by it can still be unaddressable here.
///
/// The helper mirrors this as `MAX_BINDING_SLOTS` and REFUSES a plan that would
/// mint a slot at or above it, because the alternative is a failure at XSK
/// registration (`register_xsk_slot`, `userspace-dp/src/afxdp/bpf_map/ha.rs`)
/// which happens during bringup, after the previous bindings have been torn
/// down. Go pins the value against the compiled shim in
/// `validateUserspaceShimSpecWith` so the two spellings cannot drift silently.
pub const BINDING_SLOT_MAP_MAX_ENTRIES: u32 = 4096;

/// The packet's own RX queue index, as reported by the hardware.
///
/// The field is private and there are no arithmetic impls, so the coordinate
/// cannot be reduced, masked or shifted outside this module. That is the
/// compile-time half of the #5173 invariant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawRxQueue(u32);

impl RawRxQueue {
    /// The ONLY constructor reachable from `lib.rs`. Its single call site — the
    /// read of `(*ctx.ctx).rx_queue_index` — is pinned token-for-token by a
    /// repo-scoped check in the parity tests, because a reduction applied to
    /// the integer before it reaches here is one of the two escapes a newtype
    /// cannot prevent. (The other is going around this constructor altogether
    /// and fabricating the wrapper from raw bytes; no type prevents that, and
    /// the module comment above says how source bounds it.)
    #[inline(always)]
    pub fn from_ctx_field(rx_queue_index: u32) -> Self {
        RawRxQueue(rx_queue_index)
    }

    /// Read the coordinate back for TELEMETRY ONLY (`record_trace`).
    ///
    /// Deliberately not used to compute a binding index: `binding_slot` takes
    /// the wrapper, so the index path cannot be fed a bare integer that has
    /// been through arithmetic.
    #[inline(always)]
    pub fn for_trace(self) -> u32 {
        self.0
    }
}

/// Resolve the binding slot for a packet arriving on `rx_queue` of
/// `ingress_ifindex`, or `None` when the queue is outside the array's stride.
///
/// `None` is the correct answer for an out-of-stride queue and the ONLY correct
/// answer: clamping or reducing the coordinate back into range is the #5173
/// mis-steer in another form. The publish side already refuses such queue ids
/// (#4894); this is the matching read-side bound, required because
/// `rx_queue_index` comes from the hardware and nothing else clamps it.
///
/// What an out-of-stride read WOULD have done, recorded precisely because an
/// earlier comment got it wrong and the error propagated into review: it would
/// address row `(ifindex + q/16, q%16)`. If that row is empty the shim takes its
/// own binding-missing path and attempts no redirect. If it holds a live socket,
/// that socket is bound to a different netdev AND a different queue, so
/// `xsk_rcv_check()` returns `-EINVAL`, `xdp_redirect_map_err` is counted and
/// the driver discards — while the shim's last recorded trace stage stays
/// REDIRECT, making it a drop MIS-TRACED as having reached redirect. Neither
/// outcome is a cross-interface delivery.
///
/// An interface id at or above 2^28 would overflow the `u32` product; the
/// checked multiply resolves that to `None` instead of wrapping onto another
/// row (#9900 F-150). The caller treats it as a clean binding miss, same as
/// an out-of-stride queue.
#[inline(always)]
pub fn binding_slot(ingress_ifindex: u32, rx_queue: RawRxQueue) -> Option<u32> {
    if rx_queue.0 >= BINDING_QUEUES_PER_IFACE {
        return None;
    }
    ingress_ifindex
        .checked_mul(BINDING_QUEUES_PER_IFACE)?
        .checked_add(rx_queue.0)
}
