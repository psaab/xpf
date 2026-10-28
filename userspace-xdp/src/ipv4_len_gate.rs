//! #9901 (F-075): the ingress IPv4 declared-length gate, in a module that
//! compiles for the HOST as well as for `bpfel-unknown-none`.
//!
//! The shim used to validate the IPv4 version and IHL only and never read the
//! total-length field, so a datagram lying about its length reached shim
//! classification and flow stamping before any declared-end discipline — the
//! L4 tuple was read from whatever bytes the capture held, including Ethernet
//! pad / slack past the declared datagram end. The XDP fast-path verdict
//! (session-map probe + redirect) computed from those bytes is the residual
//! this gate closes; userspace already bounds its own reads by the declared
//! end (#2361 family) once the packet reaches it.
//!
//! The gate itself is two pure functions with no packet reads in them: the
//! caller hands over the total-length and header-length values it already
//! holds (bytes 2..4 sit inside the 20-byte header slice the parser holds, so
//! consulting them costs the verifier nothing), and the gate answers whether
//! the declared length can cover the header plus how far L4 reads may go.
//!
//! Sharing: userspace-dp cannot link this crate (it targets BPF), so its
//! parity test compiles THIS FILE for the host and sweeps it against the
//! userspace extractor's own gate — the same arrangement
//! `ipv6_ext_walk.rs` uses, with its wording discipline (the confinement
//! bound refuses a module-path attribute token pair anywhere under this
//! directory, so that attribute is described rather than spelled here).
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on `std` —
//! that is what keeps it host-compilable, and it is the whole point.

/// Whether the declared total length can cover an `ihl_bytes`-long header.
///
/// A total length below the header length is impossible on the wire: the
/// header is part of the datagram the length counts. Both the shim parser
/// and the userspace extractor refuse such a frame outright. Equal is the
/// bare-header datagram (no L4 present at all), which is possible but
/// carries no tuple.
#[inline(always)]
pub fn ipv4_declared_len_covers_header(total_len: u16, ihl_bytes: usize) -> bool {
    (total_len as usize) >= ihl_bytes
}

/// How far past `l3_offset` L4 reads may go: the declared datagram end
/// (`l3_offset + total_len`), clamped to the captured bytes (`data_end`).
///
/// A lying-SHORT length truncates the readable window so slack/padding past
/// the declared end is never parsed as L4; a lying-LONG length is bounded by
/// the capture exactly as before. `saturating_add` keeps a hostile length
/// from wrapping the bound below the header.
#[inline(always)]
pub fn ipv4_declared_read_end(l3_offset: usize, total_len: u16, data_end: usize) -> usize {
    let declared_end = l3_offset.saturating_add(total_len as usize);
    if declared_end < data_end {
        declared_end
    } else {
        data_end
    }
}

/// #16009: whether the IPv4 options region of an already-validated
/// header carries an LSRR (131) or SSRR (137) source-route option —
/// the worker screen's `saw_ipv4_source_route` (#2973). `iph` is the
/// header slice the caller already holds (at least `ihl_bytes` long)
/// and `ihl_bytes` the validated header length. Mirrors the worker
/// extractor's TLV walk verdict for well-formed options: EOOL (0)
/// ends, NOP (1) is one byte, LSRR/SSRR sight on the kind byte. A
/// malformed tail (missing length byte, length < 2, overrun) stops
/// the scan without a sighting; the shim parser has already validated
/// the header length, and the worker fails closed on malformed
/// options at its own extractor — a shape the shim's parser drops
/// earlier is never consulted here.
#[inline(always)]
pub fn ipv4_has_source_route_option(iph: &[u8], ihl_bytes: usize) -> bool {
    if ihl_bytes <= 20 || iph.len() < ihl_bytes {
        return false;
    }
    let options = &iph[20..ihl_bytes];
    let mut pos = 0usize;
    while pos < options.len() {
        let kind = options[pos];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            pos += 1;
            continue;
        }
        if kind == 131 || kind == 137 {
            return true;
        }
        if pos + 1 >= options.len() {
            break;
        }
        let opt_len = options[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > options.len() {
            break;
        }
        pos += opt_len;
    }
    false
}
