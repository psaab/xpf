use super::*;

pub(in crate::afxdp) const GRE_FLAG_CHECKSUM: u16 = 0x8000;
const GRE_FLAG_ROUTING: u16 = 0x4000;
pub(in crate::afxdp) const GRE_FLAG_KEY: u16 = 0x2000;
pub(in crate::afxdp) const GRE_FLAG_SEQUENCE: u16 = 0x1000;
const GRE_VERSION_MASK: u16 = 0x0007;
const GRE_PROTO_IPV4: u16 = 0x0800;
const GRE_PROTO_IPV6: u16 = 0x86dd;

#[derive(Clone, Debug)]
pub(super) struct NativeGrePacket {
    pub(super) frame: Vec<u8>,
    pub(super) meta: UserspaceDpMeta,
}

fn parse_outer_addresses(frame: &[u8], meta: UserspaceDpMeta) -> Option<(IpAddr, IpAddr)> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 12],
                    frame[l3 + 13],
                    frame[l3 + 14],
                    frame[l3 + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 16],
                    frame[l3 + 17],
                    frame[l3 + 18],
                    frame[l3 + 19],
                )),
            ))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some((
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
                )),
            ))
        }
        _ => None,
    }
}

/// #2782: the byte slice over which a Checksum-Present GRE checksum is
/// computed — the GRE header through the end of the GRE payload. The
/// region is bounded by the OUTER IP length (IPv4 Total Length, IPv6
/// Payload Length) so trailing Ethernet min-frame padding is excluded:
/// the GRE checksum covers exactly the encapsulated octets, and folding
/// pad bytes in would spuriously fail valid frames. Returns `None` when
/// the outer header is truncated or its declared length lies outside the
/// captured frame (fail-closed — a truncated/lying header must not
/// over-read or pass an unvalidated frame).
/// #6748: the authoritative end of the OUTER IP datagram, in frame offsets.
///
/// IPv4 Total Length, or 40 + IPv6 Payload Length, both relative to
/// `meta.l3_offset`, and refused when the declaration runs past what was
/// actually captured. Nothing earlier in the path establishes this: `raw_frame`
/// is the AF_XDP descriptor length, `classify_metadata` validates
/// snapshot/config-gen/fib-gen/addr-family and performs no length validation at
/// all, and the XDP shim declares `tot_len`/`payload_len` in its header structs
/// but never reads either.
///
/// This computation used to live inside `gre_checksum_region` and be applied to
/// the CHECKSUM only. Its docstring said why — "so trailing Ethernet min-frame
/// padding is excluded" — while payload promotion was bounded by
/// `frame.len() - inner_offset` instead. The asymmetry is what made #6748 an
/// oversight rather than a design choice: checksummed GRE got an incidental
/// outer-length sanity check that non-checksummed GRE did not. Extracted here so
/// there is ONE notion of "outer end" for the checksum, the option-field skips
/// and the inner extraction, rather than a second, possibly divergent one.
pub(in crate::afxdp) fn outer_datagram_end(frame: &[u8], meta: UserspaceDpMeta) -> Option<usize> {
    let l3 = meta.l3_offset as usize;
    let end = match meta.addr_family as i32 {
        libc::AF_INET => {
            let total = u16::from_be_bytes([*frame.get(l3 + 2)?, *frame.get(l3 + 3)?]) as usize;
            l3.checked_add(total)?
        }
        libc::AF_INET6 => {
            let payload =
                u16::from_be_bytes([*frame.get(l3 + 4)?, *frame.get(l3 + 5)?]) as usize;
            l3.checked_add(40)?.checked_add(payload)?
        }
        _ => return None,
    };
    // A declaration longer than what we captured is refused rather than
    // clamped: clamping would silently accept a header that lies about its own
    // datagram, which is the same class of trust this function exists to remove.
    if end > frame.len() {
        return None;
    }
    Some(end)
}

fn gre_checksum_region<'a>(
    frame: &'a [u8],
    meta: UserspaceDpMeta,
    gre_offset: usize,
) -> Option<&'a [u8]> {
    let gre_region_end = outer_datagram_end(frame, meta)?;
    // The declared region must start at/after the GRE header.
    if gre_region_end < gre_offset {
        return None;
    }
    frame.get(gre_offset..gre_region_end)
}

pub(in crate::afxdp) fn packet_trimmed_len(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len == 0 || total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total_len = 40usize.checked_add(payload_len)?;
            if total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        _ => None,
    }
}

/// #2315: count of GRE-decap frames DROPPED because the outer header
/// carried a CE mark over an inner packet that was Not-ECT — the
/// "illegal" RFC 6040 §4.2 combination (a congested router CE-marked a
/// packet whose endpoints never negotiated ECN). Surfaced via
/// `coordinator/status.rs` as
/// `xpf_userspace_gre_decap_ecn_illegal_drops_total`. A nonzero value
/// means a misbehaving/misconfigured tunnel ingress copied ECT onto the
/// outer for traffic the inner endpoints did not mark, then the path
/// congested. RFC 6040 mandates a drop here (the alternative — clearing
/// the bogus CE — would silently hide the protocol violation).
pub(in crate::afxdp) static GRE_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);

/// #2317: count of WireGuard-decap inner packets DROPPED by the same
/// RFC 6040 §4.2 combine, for the WG path. Separate from the GRE
/// counter so the two tunnel families are independently observable.
/// Surfaced via `coordinator/status.rs` as
/// `xpf_userspace_wg_decap_ecn_illegal_drops_total`. The WG decap path
/// captures the outer ECN out-of-band (the kernel UDP socket strips the
/// outer IP header before userspace, so the bits arrive as `IP_RECVTOS`
/// / `IPV6_RECVTCLASS` ancillary data on `recvmsg` — see
/// `coordinator/wg_control/sock.rs`) and feeds it into the SAME
/// `apply_decap_ecn_combine` below. A nonzero value means a misbehaving
/// WG ingress / congested path CE-marked the outer of a Not-ECT inner.
pub(in crate::afxdp) static WG_DECAP_ECN_ILLEGAL_DROPS: AtomicU64 = AtomicU64::new(0);

/// #2331: count of native-GRE encap frames DROPPED because the fully
/// built outer datagram (outer IP + GRE header[+key] + inner packet)
/// exceeded the resolved transport/egress MTU while the IPv4 outer
/// carries DF=1 (the only outer the native encap builder emits — see
/// `encapsulate_native_gre_frame`). A DF-set outer larger than the path
/// MTU cannot be fragmented downstream and would be silently dropped by
/// the egress NIC or an intermediate router with no PMTUD signal back to
/// the inner source — a blackhole for every inner flow whose encapped
/// size exceeds the path MTU. We refuse to EMIT that frame (drop +
/// bump). Surfaced via `coordinator/status.rs` as
/// `xpf_userspace_gre_encap_df_oversize_drops_total`. A nonzero value
/// flags inner flows whose encapped size exceeds the tunnel path MTU —
/// most often a missing/too-high inner MSS clamp (`native_gre_tcp_mss`)
/// or a non-TCP inner (UDP/ICMP/ESP) with no segmentation lever.
///
/// PMTUD (ICMP Frag-Needed / PTB) signalling back to the inner source is
/// NOT generated at THIS site — it lives in the TX dispatcher
/// (`tx/dispatch/mod.rs`, #2330). For the case where a PTB is owed (the
/// inner is IPv4 DF or IPv6), the dispatcher's PRE-build
/// `post_transform_inner_mtu` decision fires first, builds the inner-source
/// PTB advertising the GRE inner MTU (the SAME `native_gre_inner_mtu` value
/// this guard's `tunnel_outer_mtu - outer_ip - gre` math reduces to), sets
/// `mtu_signalled`, and SKIPS the encap build — so this counter is NOT
/// bumped in that case (no double-drop / double-count). This drop+bump now
/// fires only for the residual case where no PTB is owed but the outer is
/// still oversized: a non-DF IPv4 inner (`ForwardOversizeNoDf`: no PTB, since
/// the sender permits fragmentation, but this dataplane does not fragment
/// before encapsulation, #9758) whose encapped outer exceeds the DF-set
/// transport MTU.
pub(in crate::afxdp) static GRE_ENCAP_DF_OVERSIZE_DROPS: AtomicU64 = AtomicU64::new(0);

/// #2782: count of native-GRE decap frames DROPPED because the
/// Checksum-Present (C) bit was set but the GRE checksum did not verify
/// (or the header/payload was too short to cover the checksummed
/// region). RFC 2784 §2.1 + RFC 2890: when C is set the 16-bit
/// Checksum field is the IP-style one's-complement checksum of the GRE
/// header AND the payload, computed with the Checksum field itself
/// zeroed; a 16-bit Reserved1 follows. A checksum-present peer (notably
/// a vSRX configured for GRE checksum) was previously blackholed
/// outright (`return None` before this field was even parsed) — an
/// uncounted, no-show-reason drop and a router-interop gap. We now skip
/// the 4-byte Checksum+Reserved1 field to locate the inner payload and
/// VALIDATE the checksum; a verified frame decaps normally, a corrupt
/// one is dropped HERE with a specific counter so the drop is
/// observable. Surfaced via `coordinator/status.rs` as
/// `xpf_userspace_gre_decap_checksum_invalid_drops_total`. A nonzero
/// value means a checksummed GRE peer is delivering frames the path
/// corrupted (or a header truncated past the checksum field).
pub(in crate::afxdp) static GRE_DECAP_CHECKSUM_INVALID_DROPS: AtomicU64 = AtomicU64::new(0);

/// Serialises the tests that OBSERVE `GRE_DECAP_CHECKSUM_INVALID_DROPS`.
///
/// #6891: the counter above is PROCESS-GLOBAL production state — it is read by
/// `coordinator::status` and exported as
/// `xpf_userspace_gre_decap_checksum_invalid_drops_total`. So it cannot be made
/// per-test (a `thread_local!` here would silently break the real counter);
/// the tests must be serialised against each other instead.
///
/// Two tests observe it and they race under a parallel `cargo test`:
/// `native_gre_decap_checksum_invalid_drops_and_counts` BUMPS it (it corrupts a
/// payload byte after sealing the checksum), while
/// `native_gre_decap_checksum_present_yields_inner_packet` asserts the counter
/// is UNCHANGED across a valid-checksum decap. Interleaved, the second reads the
/// first's increment and fails with `left: 1, right: 0`.
///
/// Measured at `021869e5f`: **29 of 30** parallel runs of
/// `cargo test --bins native_gre_decap_checksum` failed before this lock.
///
/// It stayed hidden because `make test-rust` pins `-- --test-threads=1`
/// (`Makefile`), adopted for the #6657 wedge — so the sanctioned gate is
/// structurally blind to it, and it only surfaces on a plain parallel
/// `cargo test`, which is exactly when a lane concludes "master is red".
///
/// **Any new test that can reach the `fetch_add` above must take this lock**,
/// including one that merely corrupts a GRE checksum incidentally.
///
/// Poison-tolerant (`into_inner`) so one failing test does not cascade into
/// every other holder reporting a lock error instead of its own assertion.
#[cfg(test)]
pub(in crate::afxdp) fn gre_checksum_counter_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// #6842: native-GRE frames REFUSED for decap because the GRE version
/// field was non-zero while the outer tuple named a configured GRE
/// tunnel endpoint.
///
/// GRE version is a *decap discriminator*, not a cosmetic field. RFC
/// 2784/2890 GRE is version 0. RFC 2637 (PPTP) "enhanced GRE" is
/// **version 1** and re-purposes the same 32 bits RFC 2890 defines as an
/// opaque Key:
///
/// ```text
///   RFC 2890 :  |            Key (32)                          |
///   RFC 2637 :  |  Payload Length (16)  |     Call ID (16)      |
/// ```
///
/// It also defines an Acknowledgment-Number field behind an `A` bit
/// (0x0080) that an RFC 2890 reader does not know about, so a
/// version-blind parse of a version-1 header lands the "inner packet"
/// pointer on attacker-chosen bytes. Refusing the frame at the version
/// check — BEFORE any Key read or offset arithmetic — is what keeps that
/// closed.
///
/// This is a REFUSAL, not a drop: `try_native_gre_decap_from_frame`
/// returns `None` and the frame continues on the ordinary
/// transit/host-inbound path. It is counted only when a GRE tunnel
/// endpoint is actually configured for the outer tuple, so ordinary
/// TRANSIT PPTP crossing the firewall — which is forwarded, not refused
/// — does not inflate it. Surfaced via `coordinator/status.rs` as
/// `xpf_userspace_gre_decap_unsupported_version_refusals_total`. A
/// nonzero value means a peer is offering PPTP/enhanced GRE to a
/// configured GRE tunnel endpoint; xpf has no PPTP ALG (see #6842) so
/// that traffic is not terminated here.
/// #8291: the cumulative store, reached through `ForwardingState` rather than a
/// process-global `static`.
///
/// `Clone` shares the inner `Arc`, exactly like `ZoneCounterStore` /
/// `FloodCounterStore` (#3651): cloning the forwarding state for a worker
/// publish and carrying it forward across config applies both keep the total
/// alive, and `forwarding_build::attach_carried_counters` does the carry at the
/// same call site as its two siblings so one cannot be dropped without the
/// others.
///
/// WHY THIS MOVED, since it is a production change made for test isolation and
/// a reader will reasonably ask. As a `static` it was one cell shared by every
/// test in the process, and `tests_gre_version_6842` asserts a THREE-ROW table
/// of which two rows are "must NOT count" — an UPPER bound, which a shared
/// global under concurrent writers cannot provide at all. The family failed 19
/// of 20 parallel runs. The alternatives were worse: a sink parameter on the
/// decap path (a hot-path precedent), an undetectable "only sound
/// single-threaded" dependency (libtest does not expose the effective thread
/// count, so no cell can check it), or relaxing the countable row to a lower
/// bound — which fixes only 1 of 3 rows, leaves the family at 3/20, and turns a
/// false RED into a false GREEN because `>=` cannot tell this test's refusal
/// from a sibling's.
///
/// Moving it costs nothing on any path: `note_unsupported_gre_version` already
/// takes `&ForwardingState`, and it is `#[cold] #[inline(never)]`.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct GreDecapCounters {
    unsupported_version_refusals: std::sync::Arc<AtomicU64>,
}

impl GreDecapCounters {
    /// Account one version refusal. The only mutator.
    pub(in crate::afxdp) fn note_unsupported_version_refusal(&self) {
        self.unsupported_version_refusals
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(in crate::afxdp) fn unsupported_version_refusals(&self) -> u64 {
        self.unsupported_version_refusals.load(Ordering::Relaxed)
    }
}

/// Cold-path bookkeeping for the version refusal above.
///
/// Only reached when the version field is non-zero, so it costs the
/// RFC 2784/2890 fast path nothing. Allocation-free: one hash lookup in
/// the existing `gre_decap_index` plus a relaxed increment.
///
/// The single condition is deliberate. An earlier shape early-returned on
/// a missing `gre_decap_index` row and THEN ran the kind re-check, which
/// reads as two guards but is one: `any()` over an empty candidate list is
/// already false, so the first return was unreachable-by-subsumption and a
/// mutation that deleted it changed no observable behaviour. Expressing
/// the gate once means each half of it has exactly one mutation that
/// reaches a test.
#[cold]
#[inline(never)]
fn note_unsupported_gre_version(frame: &[u8], meta: UserspaceDpMeta, forwarding: &ForwardingState) {
    let Some((outer_src, outer_dst)) = parse_outer_addresses(frame, meta) else {
        return;
    };
    let key = (meta.addr_family as i32, outer_dst, outer_src);
    // A refusal is only a refusal if the frame was OFFERED to a GRE tunnel
    // endpoint. Ordinary transit GRE/PPTP crossing the firewall reaches
    // this same `return None`, and counting it would make the metric a
    // traffic gauge instead of a fault signal. The kind test mirrors
    // `match_tunnel_endpoint` (#2327): only a GRE-mode row would ever have
    // decapped, at any version.
    let offered_to_gre_endpoint = forwarding
        .gre_decap_index
        .get(&key)
        .is_some_and(|candidates| {
            candidates.iter().any(|id| {
                forwarding
                    .tunnel_endpoints
                    .get(id)
                    .is_some_and(|endpoint| tunnel_mode_kind(&endpoint.mode) == TunnelKind::Gre)
            })
        });
    if !offered_to_gre_endpoint {
        return;
    }
    forwarding.gre_decap_counters.note_unsupported_version_refusal();
}

/// Read the inner IP packet's DSCP+ECN byte for outer-header
/// propagation on tunnel encap (#2303). Returns the full 8-bit
/// TOS / Traffic-Class value (DSCP in the high 6 bits, ECN in the
/// low 2 bits) so the encap site can copy it verbatim onto the
/// outer header:
///
///   - DSCP: uniform model (RFC 2983 §3) — the inner DSCP is mirrored
///     onto the outer so per-hop QoS classification survives the
///     tunnel.
///   - ECN: RFC 6040 normal-mode ingress — the inner ECN is COPIED to
///     the outer ECN field at ENCAP, so a CE mark applied by a
///     congested router on the OUTER path can later be combined back
///     into the inner ECN at DECAP (loss-free congestion signalling
///     instead of a fallback to loss-based control). The complementary
///     DECAP-side combine (outer ECN → inner ECN) is `decap_ecn_combine`
///     below, wired into `try_native_gre_decap_from_frame` (#2315). This
///     function is ENCAP-only — it just reads the byte to copy.
///
/// Reading the WHOLE byte (rather than masking to DSCP and re-shifting,
/// the `wg::dscp::tos_from_dscp` shape that clears ECN) is what makes
/// this RFC-6040-compliant: ECN must propagate, not be zeroed.
///
/// `packet` is the inner IP packet (L2 already stripped); `addr_family`
/// is the inner family. Returns `0` (the pre-#2303 behavior) when the
/// packet is too short to hold the byte, so a malformed inner never
/// produces an out-of-bounds read — it just falls back to a zero outer
/// TOS.
#[inline]
pub(in crate::afxdp) fn inner_tos_byte(packet: &[u8], addr_family: u8) -> u8 {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 TOS / DiffServ byte is octet 1.
            packet.get(1).copied().unwrap_or(0)
        }
        libc::AF_INET6 => {
            // IPv6 Traffic Class spans the low nibble of octet 0 and
            // the high nibble of octet 1: TC = (b0 << 4) | (b1 >> 4).
            match (packet.first(), packet.get(1)) {
                (Some(&b0), Some(&b1)) => (b0 << 4) | (b1 >> 4),
                _ => 0,
            }
        }
        _ => 0,
    }
}

/// Extract the 2-bit ECN field from an IP TOS / Traffic-Class byte.
/// ECN occupies the low 2 bits of the DiffServ octet:
///   00 = Not-ECT, 10 = ECT(0), 01 = ECT(1), 11 = CE.
#[inline]
fn ecn_of_tos(tos: u8) -> u8 {
    tos & 0x03
}

/// Read the OUTER IP header's 2-bit ECN field for the RFC 6040 §4.2
/// decap combine. `frame` is the full received frame; `meta.l3_offset`
/// is the outer IP header start; `meta.addr_family` is the OUTER family.
/// Returns `None` when the outer header is truncated (caller then skips
/// the combine — a malformed outer never mutates the inner).
#[inline]
// #8274: widened from private so the WireGuard worker decap stage can read the
// outer ECN bits the same way. It is the same read at the same offset; a second
// copy is the divergence `logical_ingress`'s module comment exists to prevent.
pub(in crate::afxdp) fn outer_ecn_bits(frame: &[u8], meta: UserspaceDpMeta) -> Option<u8> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        // IPv4: TOS/DiffServ is octet 1 of the outer header.
        libc::AF_INET => Some(ecn_of_tos(*frame.get(l3 + 1)?)),
        // IPv6: Traffic Class spans the low nibble of octet 0 and the
        // high nibble of octet 1; ECN is its low 2 bits — i.e. bits 2-3
        // of octet 1. TC = (b0 << 4) | (b1 >> 4); ECN = TC & 0x03 =
        // (b1 >> 4) & 0x03.
        libc::AF_INET6 => Some((*frame.get(l3 + 1)? >> 4) & 0x03),
        _ => None,
    }
}

/// Parse the inner IP packet's DESTINATION address (#1434 B1b). Used by
/// the WG transit-encap path to LPM-select the egress peer by inner-dst.
/// `packet` is the inner IP packet (L2 stripped); `addr_family` is the
/// inner family. Returns `None` when the packet is too short — a
/// malformed inner produces no peer selection and the frame is dropped.
#[inline]
pub(in crate::afxdp) fn inner_dst_ip(packet: &[u8], addr_family: u8) -> Option<IpAddr> {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 destination address is octets 16..20.
            let b: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(b)))
        }
        libc::AF_INET6 => {
            // IPv6 destination address is octets 24..40.
            let b: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// RFC 6040 §4.2 decapsulation outcome for a single (inner, outer) ECN
/// pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum DecapEcn {
    /// Leave the inner ECN field unchanged.
    Keep,
    /// Upgrade the inner ECN to CE (congestion experienced).
    SetCe,
    /// Illegal combination (outer CE over a Not-ECT inner) — drop the
    /// packet per RFC 6040 §4.2.
    Drop,
}

/// RFC 6040 §4.2 ECN combine. Given the ARRIVING inner ECN and the
/// ARRIVING outer ECN, decide how the inner ECN must change at decap.
///
/// Table (rows = inner, columns = outer):
///
/// | inner \ outer | Not-ECT(00) | ECT0(10) | ECT1(01) | CE(11) |
/// |---------------|-------------|----------|----------|--------|
/// | Not-ECT(00)   | Keep        | Keep     | Keep     | Drop   |
/// | ECT(0)(10)    | Keep        | Keep     | Keep*    | SetCe  |
/// | ECT(1)(01)    | Keep        | Keep     | Keep     | SetCe  |
/// | CE(11)        | Keep        | Keep     | Keep     | Keep   |
///
/// The only state change is: outer CE upgrades any ECN-capable, non-CE
/// inner to CE (the loss-free congestion signal this whole feature
/// exists for). The illegal outer=CE / inner=Not-ECT cell is a Drop.
/// Every other cell keeps the inner verbatim (so a Not-ECT or already-CE
/// inner is never touched, and the inner DSCP — which is authoritative
/// at decap — is never copied from the outer).
///
/// (* the §4.2 "MAY" cell — outer=ECT(1) over inner=ECT(0) — leaves the
/// receiver free to either keep the inner ECT(0) or upgrade it to
/// ECT(1); neither carries a congestion mark. We take the simpler
/// conformant choice and Keep the inner ECT(0). Linux's
/// `__INET_ECN_decapsulate` upgrades to ECT(1) instead; both are RFC
/// 6040 conformant.)
///
/// `inner_ecn` and `outer_ecn` are the 2-bit ECN values (low 2 bits).
#[inline]
pub(in crate::afxdp) fn decap_ecn_combine(inner_ecn: u8, outer_ecn: u8) -> DecapEcn {
    const NOT_ECT: u8 = 0b00;
    const ECT_1: u8 = 0b01;
    const ECT_0: u8 = 0b10;
    const CE: u8 = 0b11;
    match (inner_ecn & 0x03, outer_ecn & 0x03) {
        // Not-ECT inner: never carries a congestion mark. Outer CE is
        // the illegal combination — drop. Any other outer is ignored
        // (a Not-ECT endpoint cannot consume an ECN signal).
        (NOT_ECT, CE) => DecapEcn::Drop,
        (NOT_ECT, _) => DecapEcn::Keep,
        // CE inner already carries the strongest signal — nothing to do.
        (CE, _) => DecapEcn::Keep,
        // ECN-capable, non-CE inner: outer CE upgrades it to CE.
        (_, CE) => DecapEcn::SetCe,
        // §4.2 MAY: outer=ECT(1) over inner=ECT(0). RFC 6040 leaves this
        // cell a MAY — the receiver may keep the inner ECT(0) or upgrade
        // it to ECT(1); neither is a congestion mark. We take the simpler
        // conformant choice and Keep the inner ECT(0). (Linux's
        // `__INET_ECN_decapsulate` upgrades to ECT(1); both are
        // conformant. A codepoint upgrade would need a distinct SetEct1
        // outcome variant, which carries no congestion semantics and is
        // not worth the type complexity.)
        (ECT_0, ECT_1) => DecapEcn::Keep,
        // All remaining non-CE outer values leave an ECN-capable inner
        // unchanged.
        _ => DecapEcn::Keep,
    }
}

/// Apply the RFC 6040 §4.2 decap ECN combine IN PLACE to the inner IP
/// packet. `inner_packet` is the inner IP datagram (L2 already
/// stripped); `inner_family` is the inner family; `outer_ecn` is the
/// 2-bit outer ECN read from the (now-stripped) outer header.
///
/// Returns `true` to FORWARD (possibly after setting the inner CE bit)
/// and `false` to DROP (the illegal outer-CE / inner-Not-ECT combo, per
/// §4.2; the drop counter is bumped here).
///
/// When the inner ECN is upgraded to CE on an IPv4 inner, the IPv4
/// header checksum is recomputed (the TOS byte is covered by the IPv4
/// header checksum but NOT by the L4 checksum). IPv6 inners have no IP
/// header checksum, and the IPv6 Traffic Class is not covered by the L4
/// pseudo-header, so no checksum work is needed.
///
/// `illegal_drops` is the per-tunnel-family drop counter bumped on the
/// illegal §4.2 combination (GRE and WG keep independent counters,
/// #2315 / #2317), so this one body is shared by both decap paths.
#[inline]
pub(in crate::afxdp) fn apply_decap_ecn_combine(
    inner_packet: &mut [u8],
    inner_family: u8,
    outer_ecn: u8,
    illegal_drops: &AtomicU64,
) -> bool {
    match inner_family as i32 {
        libc::AF_INET => {
            // IPv4 TOS is octet 1; ECN is its low 2 bits.
            let Some(&tos) = inner_packet.get(1) else {
                // Too short to hold the byte — forward unchanged
                // (consistent with the encap-side short-packet fallback).
                return true;
            };
            match decap_ecn_combine(ecn_of_tos(tos), outer_ecn) {
                DecapEcn::Keep => true,
                DecapEcn::Drop => {
                    illegal_drops.fetch_add(1, Ordering::Relaxed);
                    false
                }
                DecapEcn::SetCe => {
                    // Set ECN = CE (low 2 bits) without disturbing DSCP.
                    inner_packet[1] = (tos & 0xFC) | 0x03;
                    recompute_ipv4_header_checksum(inner_packet);
                    true
                }
            }
        }
        libc::AF_INET6 => {
            // IPv6 ECN is bits 2-3 of octet 1 (low 2 bits of the
            // Traffic Class). Need octets 0 and 1 to read/write it.
            let Some(&b1) = inner_packet.get(1) else {
                return true;
            };
            let inner_ecn = (b1 >> 4) & 0x03;
            match decap_ecn_combine(inner_ecn, outer_ecn) {
                DecapEcn::Keep => true,
                DecapEcn::Drop => {
                    illegal_drops.fetch_add(1, Ordering::Relaxed);
                    false
                }
                DecapEcn::SetCe => {
                    // CE = 0b11 in the ECN slot = bits 2-3 of octet 1.
                    // Clear the existing ECN nibble-bits then set CE.
                    inner_packet[1] = (b1 & 0xCF) | (0x03 << 4);
                    // IPv6: no header checksum; TC not in the L4
                    // pseudo-header — nothing else to recompute.
                    true
                }
            }
        }
        _ => true,
    }
}

/// Recompute the IPv4 header checksum in place. `packet` starts at the
/// IPv4 header. The header length is taken from IHL (octet 0 low nibble,
/// in 32-bit words). A short or malformed header leaves the packet
/// unchanged. Used after the decap ECN combine mutates the TOS byte.
#[inline]
fn recompute_ipv4_header_checksum(packet: &mut [u8]) {
    let Some(&b0) = packet.first() else { return };
    let ihl = usize::from(b0 & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    // Zero the checksum field (octets 10-11) before recomputing.
    packet[10] = 0;
    packet[11] = 0;
    let cs = checksum16(&packet[..ihl]);
    packet[10..12].copy_from_slice(&cs.to_be_bytes());
}

fn gre_inner_family_and_proto(proto: u16) -> Option<(u8, u16)> {
    match proto {
        GRE_PROTO_IPV4 => Some((libc::AF_INET as u8, 0x0800)),
        GRE_PROTO_IPV6 => Some((libc::AF_INET6 as u8, 0x86dd)),
        _ => None,
    }
}

/// Match a received GRE (proto-47) outer tuple to a GRE-mode tunnel
/// endpoint.
///
/// #2327 (kind-segregation + O(N) fix): the lookup goes through
/// `gre_decap_index`, which only contains `mode == "gre"` / `"ip6gre"`
/// endpoints — so a GRE frame is NEVER decapped against a WireGuard or
/// any other non-GRE row even if the outer tuple/key happen to collide.
/// The index is keyed by the endpoint's own
/// `(outer_family, source, destination)`; a received frame mirrors it as
/// `(addr_family, outer_dst, outer_src)`. Each bucket is a small
/// candidate list so a duplicate outer tuple (a keyed and an unkeyed
/// endpoint, or distinct logical ifindexes) is disambiguated by the GRE
/// key here rather than resolved non-deterministically by a first-match
/// scan over the entire table. Defense-in-depth: each candidate's
/// `mode` is re-checked via `tunnel_mode_kind` so a future build-side
/// indexing bug can never surface a non-GRE row on this path.
fn match_tunnel_endpoint(
    forwarding: &ForwardingState,
    outer_family: i32,
    outer_src: IpAddr,
    outer_dst: IpAddr,
    key: u32,
    key_present: bool,
) -> Option<&TunnelEndpoint> {
    let candidates = forwarding
        .gre_decap_index
        .get(&(outer_family, outer_dst, outer_src))?;
    for id in candidates {
        let Some(endpoint) = forwarding.tunnel_endpoints.get(id) else {
            continue;
        };
        // Kind re-check (defense in depth): only GRE-mode rows decap as
        // GRE, regardless of what the index claims.
        if tunnel_mode_kind(&endpoint.mode) != TunnelKind::Gre {
            continue;
        }
        let key_ok = if endpoint.key == 0 {
            !key_present || key == 0
        } else {
            key_present && endpoint.key == key
        };
        if key_ok {
            return Some(endpoint);
        }
    }
    None
}

// #8274: widened from private for the WireGuard worker decap stage — the inner
// packet it hands to `build_logical_ingress_packet` needs exactly these three
// values, derived exactly this way.
pub(in crate::afxdp) fn parse_inner_protocol_and_offsets(
    packet: &[u8],
    addr_family: u8,
) -> Option<(u8, u16, u16)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let protocol = packet[9];
            let l4_offset = ihl as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    if packet.len() < ihl + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[ihl + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < ihl + tcp_len {
                        return None;
                    }
                    l4_offset + tcp_len as u16
                }
                // #2376: UDP (RFC 768) and ICMP (RFC 792) both have an
                // 8-byte minimum header. The inner packet was already
                // trimmed to its IP-declared total length
                // (`packet_trimmed_len`), so a short inner (e.g.
                // total_len = ihl + 2) survives to here. Unlike TCP
                // above, these arms previously advanced the payload
                // offset by 8 with NO bounds check, stamping
                // `l4_offset`/`payload_offset` from bytes that are not a
                // real L4 header and pointing `payload_offset` past the
                // packet end. Fail CLOSED (drop / no decap) when the
                // inner cannot contain the claimed L4 header.
                PROTO_UDP | PROTO_ICMP => {
                    if packet.len() < ihl + 8 {
                        return None;
                    }
                    l4_offset + 8
                }
                _ => l4_offset,
            };
            Some((protocol, l4_offset, payload_offset))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            // Use the extension-header-aware helper to get both the final L4
            // protocol and the correct offset. packet[6] may be an extension
            // header type, not the actual L4 protocol.
            //
            // #2292: `packet_rel_l4_offset_and_protocol` now fails CLOSED
            // (returns `None`) when the ext-header chain is still on an
            // extension header at the `MAX_IPV6_EXT_HEADERS` bound, so a
            // surrendered `protocol == 0` (unconsumed Hop-by-Hop) can no
            // longer reach this match. The `_` arm below additionally
            // DROPS any leftover ext-header / no-next-header sentinel
            // (Hop-by-Hop 0, Routing 43, AH 51, No-Next 59, Dest-Opts 60)
            // rather than forwarding it with the ext-header offset used as
            // a fake L4/payload offset — defense in depth so this caller
            // never forwards a packet whose L4 protocol it could not
            // resolve.
            let (l4_off, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
            let rel_l4 = l4_off as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    let l4 = rel_l4 as usize;
                    if packet.len() < l4 + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[l4 + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < l4 + tcp_len {
                        return None;
                    }
                    rel_l4 + tcp_len as u16
                }
                // #2376: mirror the IPv4 UDP/ICMP guard for the IPv6
                // inner. UDP (RFC 768) and ICMPv6 (RFC 4443) both have
                // an 8-byte minimum header. `rel_l4` is the offset of
                // the resolved L4 header within the (already
                // IP-declared-length-trimmed) inner packet; if the
                // packet ends before that header is complete, the
                // previous `rel_l4 + 8` stamped a payload offset past
                // the packet end from non-L4 bytes. Fail CLOSED.
                PROTO_UDP | PROTO_ICMPV6 => {
                    let l4 = rel_l4 as usize;
                    if packet.len() < l4 + 8 {
                        return None;
                    }
                    rel_l4 + 8
                }
                // #2292: an unresolved/extension-header protocol is a drop,
                // not a forward. 0/43/51/59/60 are IPv6 ext-header or
                // no-next-header sentinels, never a real inner L4.
                0 | 43 | 51 | 59 | 60 => return None,
                _ => rel_l4,
            };
            Some((protocol, rel_l4, payload_offset))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn packet_tcp_flags(packet: &[u8], _addr_family: u8, protocol: u8, rel_l4: u16) -> u8 {
    if protocol != PROTO_TCP {
        return 0;
    }
    let l4 = rel_l4 as usize;
    packet.get(l4 + 13).copied().unwrap_or_default()
}

pub(super) fn try_native_gre_decap_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<NativeGrePacket> {
    if meta.protocol != PROTO_GRE {
        return None;
    }
    let gre_offset = meta.l4_offset as usize;
    // #6748: everything below reads through `outer`, never `frame`. The outer
    // IP header's own declared length is the authoritative end of this
    // datagram; bytes after it are a trailer the sender appended, not part of
    // the packet the tunnel carries.
    //
    // Bounding by the FRAME length — which is what implementing this from its
    // title alone would produce — fixes nothing: `packet_trimmed_len` below
    // already keeps the inner extent inside the frame, and Ethernet min-frame
    // padding is already trimmed. The missing bound was against the outer
    // DATAGRAM. A peer that appends a trailer past it AND inflates the inner IP
    // Total Length to cover it had those out-of-datagram bytes promoted into
    // the decapsulated packet.
    let outer_end = outer_datagram_end(frame, meta)?;
    if outer_end < gre_offset {
        return None;
    }
    let outer = frame.get(..outer_end)?;
    let base = outer.get(gre_offset..gre_offset + 4)?;
    let flags_version = u16::from_be_bytes([base[0], base[1]]);
    // #6842: the version field gates EVERY read below. RFC 2784/2890 GRE
    // is version 0; RFC 2637 (PPTP) enhanced GRE is version 1 and splits
    // the same 32 bits into `Payload Length (16) | Call ID (16)`, with an
    // extra Acknowledgment-Number field behind an `A` bit (0x0080) that
    // the RFC 2890 field order below does not skip. Parsing a version-1
    // header with these rules therefore (a) reads a per-packet-varying
    // Payload Length as if it were a stable tunnel Key and (b) lands
    // `inner_offset` on the Acknowledgment Number — attacker-chosen bytes
    // that would be promoted as the decapsulated inner packet. Refuse
    // before any of it. `GRE_DECAP_UNSUPPORTED_VERSION_REFUSALS` records
    // the case where the outer tuple named a real GRE endpoint, so the
    // operator can see PPTP being offered to a tunnel xpf cannot
    // terminate (no PPTP ALG exists — #6842).
    if (flags_version & GRE_VERSION_MASK) != 0 {
        note_unsupported_gre_version(frame, meta, forwarding);
        return None;
    }
    // Source Route Entries (the Routing-Present R bit) are not parsed —
    // the variable SRE list has no fixed offset and is effectively dead
    // on the modern Internet. A routed GRE frame stays a drop.
    if (flags_version & GRE_FLAG_ROUTING) != 0 {
        return None;
    }
    let checksum_present = (flags_version & GRE_FLAG_CHECKSUM) != 0;
    let key_present = (flags_version & GRE_FLAG_KEY) != 0;
    let sequence_present = (flags_version & GRE_FLAG_SEQUENCE) != 0;
    let gre_proto = u16::from_be_bytes([base[2], base[3]]);
    let (inner_family, inner_eth_proto) = gre_inner_family_and_proto(gre_proto)?;

    let mut inner_offset = gre_offset + 4;
    // #2782: RFC 2890 fixed field order is Checksum+Reserved1, then Key,
    // then Sequence — the Checksum field (when present) is FIRST, right
    // after the flags/protocol word. Skip its 4 bytes (2-byte Checksum +
    // 2-byte Reserved1) to reach Key/Sequence and the inner payload, and
    // validate the checksum so a corrupt frame is a counted drop rather
    // than a silently-misforwarded one.
    if checksum_present {
        // The checksum covers the GRE header + payload. Bound that
        // region by the OUTER IP length so we do not fold trailing L2
        // padding (Ethernet min-frame pad) into the sum.
        let gre_region = gre_checksum_region(frame, meta, gre_offset)?;
        // IP one's-complement checksum of the whole GRE region (the
        // Checksum field is included as-is); a valid frame folds to 0.
        if checksum16(gre_region) != 0 {
            GRE_DECAP_CHECKSUM_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // Past the checksum/reserved field; bounds-check before advance.
        // #6748: bounded by the outer datagram, so an option field that would
        // only fit in a trailer is refused rather than parsed.
        outer.get(inner_offset..inner_offset + 4)?;
        inner_offset += 4;
    }
    let mut key = 0u32;
    if key_present {
        key = u32::from_be_bytes(
            <[u8; 4]>::try_from(outer.get(inner_offset..inner_offset + 4)?).ok()?,
        );
        inner_offset += 4;
    }
    if sequence_present {
        outer.get(inner_offset..inner_offset + 4)?;
        inner_offset += 4;
    }
    let inner_packet = outer.get(inner_offset..)?;
    let inner_len = packet_trimmed_len(inner_packet, inner_family)?;
    let inner_packet = &inner_packet[..inner_len];

    let (outer_src, outer_dst) = parse_outer_addresses(frame, meta)?;
    let endpoint = match_tunnel_endpoint(
        forwarding,
        meta.addr_family as i32,
        outer_src,
        outer_dst,
        key,
        key_present,
    )?;
    let (protocol, rel_l4_offset, payload_offset) =
        parse_inner_protocol_and_offsets(inner_packet, inner_family)?;

    // #7167: the synthesize / ECN-combine / reparse / logical-rebind tail now
    // lives in `logical_ingress::build_logical_ingress_packet` so WireGuard and
    // IPsec plaintext can be adjudicated by the SAME code rather than a second
    // copy of it. Everything above stays GRE-specific (outer parse, GRE key,
    // `match_tunnel_endpoint` filtered to TunnelKind::Gre).
    let (synthetic, inner_meta) = crate::afxdp::logical_ingress::build_logical_ingress_packet(
        forwarding,
        &crate::afxdp::logical_ingress::LogicalIngressParams {
            inner_packet,
            inner_family,
            inner_eth_proto,
            protocol,
            rel_l4_offset,
            payload_offset,
            logical_ifindex: endpoint.logical_ifindex,
            // GRE still has its outer IP header in `frame`, so it reads the
            // outer ECN bits here and hands them in.
            outer_ecn: outer_ecn_bits(frame, meta),
            ecn_illegal_drops: &GRE_DECAP_ECN_ILLEGAL_DROPS,
            // #2486: mark the inner packet GRE-decapped so the forward builder
            // selects the `tcp-mss gre-in` clamp value.
            meta_flags: GRE_DECAP_INGRESS_FLAG,
            rx_queue_index: meta.rx_queue_index,
            // GRE runs inside a worker on a received packet, so the attachment
            // generations are inherited from the triggering RX meta (#7167
            // invariant 5). A caller with no ingress meta has no such value.
            config_generation: meta.config_generation,
            fib_generation: meta.fib_generation,
        },
    )?;

    Some(NativeGrePacket {
        frame: synthetic,
        meta: inner_meta,
    })
}

/// #2331: the built native-GRE OUTER L3 datagram length for an
/// `inner_len`-byte inner packet — outer IP header + GRE header (incl.
/// the optional 4-byte key, already folded into `gre_len`) + inner. The
/// L2 Ethernet/VLAN header is deliberately EXCLUDED: the MTU budget is
/// the L3 payload limit, and this matches `native_gre_inner_mtu`
/// (forwarding/mod.rs), which subtracts exactly `outer_ip + gre` from
/// the transport MTU to derive the inner allowance. Pulled out so the
/// MTU arithmetic is unit-testable in isolation (mirrors wg.rs's
/// `wg_encapped_size`).
#[inline]
pub(in crate::afxdp) fn gre_encapped_outer_len(
    outer_ip_len: usize,
    gre_len: usize,
    inner_len: usize,
) -> usize {
    outer_ip_len + gre_len + inner_len
}

pub(super) fn encapsulate_native_gre_frame(
    inner_frame: &[u8],
    inner_meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let inner_meta = inner_meta.into();
    let endpoint = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)?;
    // #1873 (Codex code r2): refuse to encapsulate when the id's
    // owning netdev differs from the one recorded in the session's
    // stored resolution (egress_ifindex = logical_ifindex at resolve
    // time) — a re-owned id must fail the build (R-C gate drops the
    // frame), never encapsulate into the new owner.
    if decision.resolution.egress_ifindex > 0
        && endpoint.logical_ifindex != decision.resolution.egress_ifindex
    {
        return None;
    }
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;
    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let inner_l3 = match frame_l3_offset(inner_frame) {
        Some(offset) => offset,
        None => inner_meta.l3_offset as usize,
    };
    // #5381: borrow the inner packet directly out of `inner_frame` rather
    // than `.to_vec()`-ing it. Every use below is read-only
    // (`packet_trimmed_len`, `inner_tos_byte`, `.len()`, and as the
    // `copy_from_slice` SOURCE into the separately-allocated `out`), so the
    // heap copy was redundant — the frame is copied exactly once, into
    // `out`. `inner_frame` outlives the borrow and `out` is a distinct
    // allocation, so there is no aliasing.
    let inner_slice = inner_frame.get(inner_l3..)?;
    let inner_len = packet_trimmed_len(inner_slice, inner_meta.addr_family)?;
    let inner_packet = &inner_slice[..inner_len];
    // #2303: copy the inner DSCP+ECN onto the outer header (uniform
    // DSCP model + RFC 6040 ECN ingress copy) instead of hardcoding 0.
    let outer_tos = inner_tos_byte(inner_packet, inner_meta.addr_family);

    let key_words = if endpoint.key != 0 { 1 } else { 0 };
    let gre_len = 4 + key_words * 4;
    let outer_ip_len = match endpoint.outer_family {
        libc::AF_INET => 20,
        libc::AF_INET6 => 40,
        _ => return None,
    };

    // #2331: refuse to EMIT an oversized DF-set outer. The IPv4 outer
    // this builder writes always carries DF=1 (#1440), and the IPv6
    // outer cannot be fragmented in-path either — so an outer L3
    // datagram larger than the transport/egress MTU is a downstream
    // blackhole (NIC/router drop, no PMTUD back to the inner source).
    // Compare the built outer L3 length (outer IP + GRE[+key] + inner;
    // the L2 eth/VLAN header is NOT part of the MTU budget) against the
    // SAME resolved outer MTU the rest of the tunnel path uses
    // (`tunnel_outer_mtu`, #2300 SSOT — the real transport ifindex, not
    // the logical tunnel ifindex). The 4-byte GRE key, when present, is
    // already folded into `gre_len`, so a key-present endpoint's extra
    // 4 bytes are counted. Drop + bump rather than emit; PMTUD/PTB
    // signalling from this site is deferred to #2330 (see the
    // GRE_ENCAP_DF_OVERSIZE_DROPS doc comment, which is the authority on
    // the ordering: #2330 LANDED the signalling in the TX dispatcher, whose
    // pre-build post_transform_inner_mtu decision fires first and skips this
    // build whenever a PTB is owed. What reaches this drop is the residual
    // where none is owed -- a non-DF IPv4 inner (`ForwardOversizeNoDf`: the
    // sender permits fragmentation, but this dataplane does not fragment before
    // encapsulation, #9758) (#8942: "deferred" alone read as an outstanding gap).
    let outer_l3_len = gre_encapped_outer_len(outer_ip_len, gre_len, inner_packet.len());
    let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
    if outer_l3_len > outer_mtu {
        GRE_ENCAP_DF_OVERSIZE_DROPS.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let frame_len = outer_eth_len + outer_ip_len + gre_len + inner_packet.len();
    let mut out = vec![0u8; frame_len];
    write_eth_header_slice(
        out.get_mut(..outer_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        if endpoint.outer_family == libc::AF_INET {
            0x0800
        } else {
            0x86dd
        },
    )?;

    let outer_ip_start = outer_eth_len;
    let gre_start = outer_ip_start + outer_ip_len;
    let inner_start = gre_start + gre_len;
    out.get_mut(inner_start..)?
        .get_mut(..inner_packet.len())?
        .copy_from_slice(inner_packet);

    let gre_flags = if endpoint.key != 0 { GRE_FLAG_KEY } else { 0 };
    out[gre_start..gre_start + 2].copy_from_slice(&gre_flags.to_be_bytes());
    out[gre_start + 2..gre_start + 4].copy_from_slice(
        &(if inner_meta.addr_family as i32 == libc::AF_INET {
            GRE_PROTO_IPV4
        } else {
            GRE_PROTO_IPV6
        })
        .to_be_bytes(),
    );
    if endpoint.key != 0 {
        out[gre_start + 4..gre_start + 8].copy_from_slice(&endpoint.key.to_be_bytes());
    }

    match endpoint.outer_family {
        libc::AF_INET => {
            let src = match endpoint.source {
                IpAddr::V4(ip) => ip,
                _ => return None,
            };
            let dst = match endpoint.destination {
                IpAddr::V4(ip) => ip,
                _ => return None,
            };
            let total_len = u16::try_from(outer_ip_len + gre_len + inner_packet.len()).ok()?;
            // #1440: consolidated IPv4 outer builder. Sets DF=1
            // (RFC 791 §3.1 / RFC 6864 §3 compliance) and computes
            // the header checksum via the shared `checksum16`.
            // Wire-byte change vs the previous open-code:
            // ip[6..8] = 0x4000 (was 0x0000); IPv4 header checksum
            // recomputes accordingly.
            write_ipv4_header(
                out.get_mut(outer_ip_start..outer_ip_start + 20)?,
                src,
                dst,
                PROTO_GRE,
                outer_tos,
                endpoint.ttl,
                total_len,
            )?;
        }
        libc::AF_INET6 => {
            let src = match endpoint.source {
                IpAddr::V6(ip) => ip,
                _ => return None,
            };
            let dst = match endpoint.destination {
                IpAddr::V6(ip) => ip,
                _ => return None,
            };
            let payload_len = u16::try_from(gre_len + inner_packet.len()).ok()?;
            // #1440: consolidated IPv6 outer builder.
            write_ipv6_header(
                out.get_mut(outer_ip_start..outer_ip_start + 40)?,
                src,
                dst,
                PROTO_GRE,
                outer_tos,
                /* flow_label */ 0,
                endpoint.ttl,
                payload_len,
            )?;
        }
        _ => return None,
    }

    Some(out)
}
