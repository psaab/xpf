//! The shim's IPv6 extension-header walk, in a module that compiles for the
//! HOST as well as for `bpfel-unknown-none`.
//!
//! #4555: this crate is `no_std` and built for the BPF target, so
//! userspace-dp's tests cannot link it. Four successive parity guards tried to
//! compensate by MODELLING this walk from its source text, and each leaked to a
//! more ordinary edit than the last (substring on the advance arithmetic, a
//! statement outside the `match`, a symbolic `size_of`, a comment hiding a
//! struct field). Replacing the model with three emitted scalars
//! (`MAX_EXT_HDRS`, `size_of::<FragHdr>()`, the class table) closed the
//! tautology but not the coverage: scalars cannot witness BEHAVIOUR, so an
//! altered advance, or a deleted bounds revalidation, left every parity test
//! green.
//!
//! So nothing here is modelled or re-described. Everything the walk needs is in
//! this file, it depends only on `core`, and userspace-dp's parity test pulls
//! THIS FILE in through a module-path attribute and runs it on real byte
//! buffers. Advance arithmetic, bounds revalidation and resolvable chain length
//! stop being claims about source text and become observable outcomes.
//!
//! That attribute is described rather than SPELLED, here and at the `lib.rs`
//! call site, and deliberately: #5173's confinement bound refuses the token
//! pair `[` `path` anywhere under `userspace-xdp/src`, because an attribute
//! that redirects a module pulls source in from outside the directory every
//! one of its other bounds walks. Prose tripping it is a spurious RED, so the
//! prose is worded around it. Do not re-spell it.
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on `std` —
//! that is what keeps it host-compilable, and it is the whole point.

use core::mem;

/// Iteration bound of the extension-header walk.
///
/// This is an ITERATION count, not a header count, and it differs by one from
/// userspace-dp's `MAX_IPV6_EXT_HEADERS` on purpose. This loop spends one
/// iteration per extension header and exits by EXHAUSTION carrying whatever
/// next-header value the last one declared — there is no post-loop over-limit
/// check, `protocol` flows straight into `parse_l4` — so a chain of up to
/// `MAX_EXT_HDRS` extension headers still resolves its L4.
/// `walk_ipv6_ext_chain` needs one FURTHER iteration to RETURN its terminal and
/// folds exhaustion into the fail-closed `OverLimit` verdict, so it resolves up
/// to `MAX_IPV6_EXT_HEADERS - 1`. The parity condition is therefore
/// `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1` (7 against 8): both resolve
/// 0..=7 headers and both refuse 8 or more. Setting this to 8 to "match" would
/// make the shim resolve chains userspace fails closed on — and it does not
/// pass the BPF verifier either.
pub const MAX_EXT_HDRS: usize = 7;

pub const NEXTHDR_HOP: u8 = 0;
pub const NEXTHDR_ROUTING: u8 = 43;
pub const NEXTHDR_FRAGMENT: u8 = 44;
pub const NEXTHDR_AUTH: u8 = 51;
pub const NEXTHDR_DEST: u8 = 60;
pub const NEXTHDR_NONE: u8 = 59;
// #4517/#4555: the remaining generic length-prefixed extension headers
// (byte 0 = next header, byte 1 = HdrExtLen in 8-octet units excluding the
// first 8 → advance `(HdrExtLen + 1) * 8`), matching the set userspace-dp's
// walker enumerates: 135 Mobility (RFC 6275 §6.1), 139 HIP (RFC 7401 §5.1),
// 140 Shim6 (RFC 5533 §5.1), 253/254 experimental (RFC 3692 / RFC 4727).
// ESP (50) is deliberately absent on BOTH sides: the payload is encrypted and
// the inner next-header unreadable, so stopping there is correct.
pub const NEXTHDR_MOBILITY: u8 = 135;
pub const NEXTHDR_HIP: u8 = 139;
pub const NEXTHDR_SHIM6: u8 = 140;
pub const NEXTHDR_EXP1: u8 = 253;
pub const NEXTHDR_EXP2: u8 = 254;

pub const EH_CLASS_TERMINAL: u8 = 0;
pub const EH_CLASS_GENERIC: u8 = 1;
pub const EH_CLASS_AUTH: u8 = 2;
pub const EH_CLASS_FRAGMENT: u8 = 3;
pub const EH_CLASS_NONEXT: u8 = 4;

/// The single classifier the walk dispatches on AND the emitted class table is
/// generated from, so the table can never describe a different set than the
/// walk actually treats specially.
#[inline(always)]
pub const fn eh_class(protocol: u8) -> u8 {
    match protocol {
        NEXTHDR_HOP
        | NEXTHDR_ROUTING
        | NEXTHDR_DEST
        | NEXTHDR_MOBILITY
        | NEXTHDR_HIP
        | NEXTHDR_SHIM6
        | NEXTHDR_EXP1
        | NEXTHDR_EXP2 => EH_CLASS_GENERIC,
        NEXTHDR_AUTH => EH_CLASS_AUTH,
        NEXTHDR_FRAGMENT => EH_CLASS_FRAGMENT,
        NEXTHDR_NONE => EH_CLASS_NONEXT,
        _ => EH_CLASS_TERMINAL,
    }
}

pub const fn eh_class_table() -> [u8; 256] {
    let mut table = [EH_CLASS_TERMINAL; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = eh_class(i as u8);
        i += 1;
    }
    table
}

/// IPv6 Fragment header. Fixed at 8 bytes by RFC 8200 §4.5, which is also what
/// userspace-dp's walker advances; the assertion below fails the build on any
/// layout change, and the size is emitted into the manifest so a consumer of a
/// prebuilt object can check it without compiling this crate.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FragHdr {
    pub nexthdr: u8,
    pub reserved: u8,
    pub frag_off: u16,
    pub identification: u32,
}

const _: () = assert!(
    mem::size_of::<FragHdr>() == 8,
    "FragHdr must stay 8 bytes: the IPv6 Fragment header is fixed at 8 (RFC 8200 §4.5) and \
     userspace-dp's walk_ipv6_ext_chain advances a literal 8"
);

/// Bounds-checked read of `len` bytes at `offset` from a raw packet window.
///
/// Both pointer additions are checked and the end is compared against
/// `data_end`, so a declared length that overruns the packet yields `None`
/// rather than a read past the buffer.
///
/// # Safety
/// `data..data_end` must describe a single readable region that outlives `'a`,
/// which is what the XDP context guarantees for `ctx->data`/`ctx->data_end`.
/// The host-side parity test upholds it by passing a live slice's own bounds.
///
/// #7174 C03: this is `unsafe` because it cannot be anything else. It
/// dereferences two caller-supplied `usize` values and hands back a slice whose
/// lifetime `'a` is UNCONSTRAINED — chosen by the caller, tied to no input — so
/// as a safe `fn` any safe code could pass arbitrary integers, or pick
/// `'static`, and obtain a dangling slice with no `unsafe` block anywhere. Every
/// call site in this crate passes real `ctx->data`/`ctx->data_end` bounds and is
/// sound, so this is defence in depth rather than a live defect; the point is
/// that the `# Safety` contract above was unenforceable while the signature said
/// `pub fn`, and a contract only prose carries is one a future caller can breach
/// without ever writing `unsafe`.
#[inline(always)]
pub unsafe fn read_bytes<'a>(
    data: usize,
    data_end: usize,
    offset: usize,
    len: usize,
) -> Option<&'a [u8]> {
    if data.checked_add(offset)?.checked_add(len)? > data_end {
        return None;
    }
    let ptr = (data + offset) as *const u8;
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// #7494: the value `parse_ipv4`/`parse_ipv6` substitute for the real upper-
/// layer protocol when the packet is a NON-FIRST fragment, i.e. when there is
/// no L4 header at the resolved offset to read. It routes the packet into
/// `parse_l4`'s existing unknown-protocol arm, which returns zeroed ports and
/// CANNOT fail.
///
/// It lives in this shared module, not in the shim, so that BOTH sides of the
/// boundary can assert about it: `tests_shim_ext_parity.rs` pulls this file in
/// by source path -- described, not spelled, per this module's own comment
/// above -- and can therefore check the value against userspace-dp's
/// `ipv6_ext_header_is_traversable` set, which no other location can see.
///
/// The value is NOT free to change. 253 and 254 are already load-bearing on
/// this same wire field -- they are members of the traversable set, which the
/// helper reads as "the shim gave up mid-chain" -- so a sentinel chosen as
/// "some high unused number" could silently reclassify every fragment. 255 is
/// IANA-Reserved and is a member of neither that set nor any protocol the shim
/// branches on.
pub const PROTO_FRAGMENT_NO_L4: u8 = 255;

/// The terminal an extension-header walk lands on, plus the fragment sighting
/// the caller needs to know whether the bytes THERE are an L4 header at all.
///
/// #6704: the walk used to return a bare `(offset, protocol)` and carry no
/// fragment state, because nothing in the shim consumed any. For a NON-FIRST
/// fragment the bytes at `offset` are PAYLOAD, not a TCP/UDP header, so a
/// caller that hands them to `parse_l4` synthesises a 5-tuple out of
/// attacker-influenced bytes. `non_first_fragment` is what lets the caller
/// decline instead.
#[derive(Clone, Copy)]
pub struct ExtWalk {
    /// Offset of the terminal — the first byte past the last walked header.
    pub offset: u16,
    /// The terminal next-header value.
    pub protocol: u8,
    /// Set when ANY Fragment header sighted along this walk carried non-zero
    /// fragment-offset bits (`& 0xFFF8`, RFC 8200 §4.5).
    ///
    /// ANY, not just the first, and that is the deliberate half. It mirrors
    /// `ExtChainWalk::non_first_fragment_offset_seen` in userspace-dp field
    /// for field, which is what the executable parity corpus compares. The
    /// SESSION chokepoint over there (`parse_session_flow_from_bytes` ->
    /// `frame_is_non_first_fragment` -> `ipv6_is_non_first_fragment`) reads
    /// only the FIRST recorded sighting, so on an RFC-8200-non-conformant
    /// DOUBLE-Fragment chain (first offset 0, second non-zero) this side is
    /// the STRICTER of the two. That residual disagreement is fail-closed by
    /// construction: the shim declines the L4, forms no session key, and the
    /// packet is redirected to userspace — the #4555 "loss of the fast path"
    /// cost, never a bypass. Do not "fix" it by switching this to the first
    /// sighting; that would make the shim the more permissive side, which is
    /// the direction this issue exists to close.
    pub non_first_fragment: bool,
}

/// Walk the extension-header chain from `first_protocol` at `offset`.
///
/// Returns the terminal the walk lands on, or `None` when a header is
/// truncated, a declared length overruns the packet, or an offset overflows —
/// the fail-closed outcomes, which propagate through `?` in `parse_ipv6` to
/// `XDP_DROP`.
///
/// Exhausting the loop is NOT an error here: it returns the last declared
/// next-header value, which will be an extension-header type. `parse_l4`'s
/// catch-all then yields ports 0/0 and the packet is redirected to userspace —
/// the fail-closed path for an over-limit chain.
///
/// #6923: that refusal rests on the session-key lookup MISSING, and the miss is
/// a property of the session MAP, which userspace writes — not of anything this
/// file can see. It holds only because BOTH writers refuse to mint
/// `(AF_INET6, <a next-header this walk traverses>, src, dst, 0, 0)`:
/// `metadata_tuple_complete` declines the tuple on the packet path, and
/// `build_synced_session_key` rejects it on the HA import path (both in
/// userspace-dp). Before #6923 the first of those accepted it, an
/// `application any` permit matched a flow with no ports to fail on, and the
/// installed key was published — so the next packet of the same chain HIT and
/// took the fast path. Do not restate this refusal as unconditional without
/// checking those two, and do not add a third writer without extending them.
///
/// Each arm's shape matters. The host-side parity corpus exercises them with
/// MINIMAL-length buffers as well as padded ones — a padded buffer cannot
/// observe a missing revalidation, because the walk lands inside the packet
/// either way. The cases that bind these arms are the ones whose packet ENDS at
/// or before the advance target:
/// the generic arm reads 2 bytes, advances `(HdrExtLen + 1) * 8` and
/// REVALIDATES the whole advanced span against `data_end`; AH advances
/// `(len + 2) * 4` (RFC 4302) and revalidates likewise; Fragment reads all 8
/// bytes before advancing by `size_of::<FragHdr>()`. Dropping a revalidation
/// would let a chain whose declared length runs past the packet resolve to an
/// L4 offset outside the buffer.
#[inline(always)]
pub fn walk_ipv6_ext_headers(
    data: usize,
    data_end: usize,
    l3_offset: u16,
    first_protocol: u8,
    start_offset: u16,
) -> Option<ExtWalk> {
    let mut protocol = first_protocol;
    let mut offset = start_offset;
    let mut non_first_fragment = false;
    for _ in 0..MAX_EXT_HDRS {
        match eh_class(protocol) {
            EH_CLASS_GENERIC => {
                let opt = unsafe { read_bytes(data, data_end, offset as usize, 2) }?;
                protocol = opt[0];
                offset = offset.checked_add(((opt[1] as u16) + 1) * 8)?;
                unsafe { read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                ) }?;
            }
            EH_CLASS_AUTH => {
                let opt = unsafe { read_bytes(data, data_end, offset as usize, 2) }?;
                protocol = opt[0];
                offset = offset.checked_add(((opt[1] as u16) + 2) * 4)?;
                unsafe { read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                ) }?;
            }
            EH_CLASS_FRAGMENT => {
                let frag = unsafe { read_bytes(data, data_end, offset as usize, 8) }?;
                // #6704/#13959: all 8 bytes were already read for the advance, so the
                // offset test is two of them and a mask. RFC 8200 §4.5 puts the
                // 13-bit fragment offset in the upper bits of bytes 2..4; a
                // non-zero offset means every byte the walk lands on after this
                // header is PAYLOAD of an earlier datagram, not an L4 header.
                // Stop after this header: following its declared next-header would
                // interpret payload as extension headers, where an attacker can
                // choose an AH/DestOpts length that overruns the packet and make
                // the walk fail closed. The caller substitutes
                // PROTO_FRAGMENT_NO_L4 for this sighting, matching the sibling
                // screen and userspace walkers.
                let non_first_fragment_sighting =
                    (u16::from_be_bytes([frag[2], frag[3]]) & 0xFFF8) != 0;
                protocol = frag[0];
                offset = offset.checked_add(mem::size_of::<FragHdr>() as u16)?;
                if non_first_fragment_sighting {
                    non_first_fragment = true;
                    break;
                }
            }
            _ => break,
        }
    }
    Some(ExtWalk {
        offset,
        protocol,
        non_first_fragment,
    })
}
