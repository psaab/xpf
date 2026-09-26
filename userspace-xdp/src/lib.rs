#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, xdp_action, xdp_md},
    helpers::r#gen::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_xdp_adjust_meta},
    macros::{map, xdp},
    maps::{Array, CpuMap, HashMap, PerCpuArray, XskMap},
    programs::XdpContext,
};
use core::mem;

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 4;
const USERSPACE_BINDING_READY: u32 = 1;
const USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS: u32 = 5000;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const ETH_P_9100: u16 = 0x9100;
const ETH_P_9200: u16 = 0x9200;
const ETH_P_9300: u16 = 0x9300;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_GRE: u8 = 47;
const PROTO_ICMPV6: u8 = 58;
const GRE_PROTO_IPV4: u16 = 0x0800;
const GRE_PROTO_IPV6: u16 = 0x86dd;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
// The BPF-side symbol names retain FALLBACK for index/map compatibility. The
// Go/operator surface exposes these retained-shim actions as degraded-path
// counters.
const USERSPACE_FALLBACK_REASON_CTRL_DISABLED: u32 = 0;
const USERSPACE_FALLBACK_REASON_PARSE_FAIL: u32 = 1;
const USERSPACE_FALLBACK_REASON_BINDING_MISSING: u32 = 2;
const USERSPACE_FALLBACK_REASON_BINDING_NOT_READY: u32 = 3;
const USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING: u32 = 4;
const USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE: u32 = 5;
const USERSPACE_FALLBACK_REASON_ICMP: u32 = 6;
const USERSPACE_FALLBACK_REASON_EARLY_FILTER: u32 = 7;
const USERSPACE_FALLBACK_REASON_ADJUST_META: u32 = 8;
const USERSPACE_FALLBACK_REASON_META_BOUNDS: u32 = 9;
const USERSPACE_FALLBACK_REASON_REDIRECT_ERR: u32 = 10;
const USERSPACE_FALLBACK_REASON_INTERFACE_NAT_NO_SESSION: u32 = 11;
const USERSPACE_FALLBACK_REASON_NO_SESSION: u32 = 12;
const USERSPACE_FALLBACK_REASON_STRICT_DROP: u32 = 13;
const USERSPACE_FALLBACK_REASON_PASS_TO_KERNEL: u32 = 14;
const USERSPACE_FALLBACK_REASON_TRANSIT_DROP: u32 = 15;
const USERSPACE_FALLBACK_REASON_QINQ_DROP: u32 = 16;
const USERSPACE_FALLBACK_REASON_STAG_DROP: u32 = 17;
const USERSPACE_FALLBACK_REASON_MAX: u32 = 18;
const USERSPACE_CTRL_FLAG_CPUMAP: u32 = 1;
const USERSPACE_CTRL_FLAG_TRACE: u32 = 2;
const USERSPACE_CTRL_FLAG_NATIVE_GRE: u32 = 4;
const USERSPACE_CTRL_FLAG_STRICT: u32 = 8;
/// #1432 S2a: set iff at least one WireGuard tunnel is configured. The
/// per-packet WG steering branch is gated on this single flag bit (read
/// from the same `ctrl.flags` word the GRE/STRICT checks already use), so
/// when no WG tunnel exists the branch — including the `wg_listen_port`
/// memory load and the UDP / dst-port / local-destination tests — is
/// skipped entirely. A bare `wg_listen_port != 0` load+compare on every
/// packet measurably nudged the v6 best-effort path into non-zero
/// retransmits at line rate (the v4 path had headroom); gating on the
/// already-loaded flags word restores the true zero-cost-when-absent
/// property.
const USERSPACE_CTRL_FLAG_WG_RX: u32 = 16;
mod binding_index;
mod degraded_ndp;
mod early_filter;
mod gre_classify;
mod ipv4_len_gate;
mod ipv6_ext_walk;
mod ipv6_len_gate;
mod tunnel_frag;
mod wg_classify;
use binding_index::{
    BINDING_QUEUES_PER_IFACE, BINDING_SLOT_MAP_MAX_ENTRIES, RawRxQueue, binding_slot,
};
use gre_classify::{
    InnerSessionAction, OuterDestinationLocal, USERSPACE_SESSION_ACTION_PASS_TO_KERNEL,
    native_gre_inner_pass_steers_to_kernel_typed,
};
use ipv4_len_gate::{ipv4_declared_len_covers_header, ipv4_declared_read_end};
use ipv6_ext_walk::{
    EH_CLASS_TERMINAL, FragHdr, MAX_EXT_HDRS, PROTO_FRAGMENT_NO_L4, eh_class, eh_class_table,
    read_bytes,
};
use ipv6_len_gate::ipv6_declared_end;
use tunnel_frag::{
    degraded_interface_nat_esp_passes_to_kernel, interface_nat_tunnel_passes_to_kernel,
};
use wg_classify::{
    WG_STEERED_PORT_SET_MAX, wg_port_is_steered, wg_record_is_transport_data,
    wg_steer_to_kernel_on_port_match, wg_worker_claims_record,
};
// MAX_INTERFACES is threaded in from bpf/headers/xpf_common.h via the
// pkg/dataplane/build-userspace-xdp.sh wrapper, which does
// `export MAX_INTERFACES=$(awk ... xpf_common.h)` before `cargo build`.
// This ties the aya Array size to the C-side tx_ports DEVMAP cap so
// the two constants cannot drift (see issue #814).
const MAX_INTERFACES: u32 = match u32::from_str_radix(env!("MAX_INTERFACES"), 10) {
    Ok(v) => v,
    Err(_) => panic!("MAX_INTERFACES env var must be a u32 decimal literal"),
};
const BINDING_ARRAY_MAX_ENTRIES: u32 = MAX_INTERFACES * BINDING_QUEUES_PER_IFACE;
const USERSPACE_SHIM_MAX_DNAT_ENTRIES: u32 = 10_000_000;
const USERSPACE_TRACE_STAGE_RECEIVED: u32 = 1;
const USERSPACE_TRACE_STAGE_BINDING_MISSING: u32 = 2;
const USERSPACE_TRACE_STAGE_BINDING_NOT_READY: u32 = 3;
const USERSPACE_TRACE_STAGE_HEARTBEAT_MISSING: u32 = 4;
const USERSPACE_TRACE_STAGE_HEARTBEAT_STALE: u32 = 5;
const USERSPACE_TRACE_STAGE_ICMP_FALLBACK: u32 = 6;
const USERSPACE_TRACE_STAGE_EARLY_FILTER: u32 = 7;
const USERSPACE_TRACE_STAGE_INTERFACE_NAT_LOCAL: u32 = 8;
const USERSPACE_TRACE_STAGE_LOCAL_DESTINATION: u32 = 9;
const USERSPACE_TRACE_STAGE_REDIRECT: u32 = 10;
const USERSPACE_TRACE_STAGE_REDIRECT_ERR: u32 = 11;
const USERSPACE_TRACE_STAGE_NO_SESSION: u32 = 12;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceCtrl {
    enabled: u32,
    metadata_version: u32,
    workers: u32,
    queue_count: u32,
    flags: u32,
    // #9587: steered WireGuard listen-port SET. `wg_port_count` valid
    // entries in `wg_ports` below (0 = no WG tunnel, the WG_RX gate stays
    // off); the tail is zero-filled by the Go programmer and zero never
    // matches. Occupies the former `wg_listen_port` scalar slot plus 16
    // bytes; the Go mirror declares the fields in the same order
    // (TestUserspaceCtrlLayoutMatchesShim9587 pins both sides).
    wg_port_count: u32,
    wg_ports: [u16; WG_STEERED_PORT_SET_MAX],
    config_generation: u64,
    fib_generation: u32,
    heartbeat_timeout_ms: u32,
}

// #9587: the ctrl value grows 40 -> 56 with the set. The Go
// `userspaceCtrlValue` mirror, the pinned-map ValueSize (40 -> 56) and the
// loader fixtures move together; this assertion fails the BUILD on drift.
const _: [(); 56] = [(); mem::size_of::<UserspaceCtrl>()];

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceDpMeta {
    magic: u32,
    version: u16,
    length: u16,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    ingress_vlan_id: u16,
    ingress_pcp: u8,
    ingress_vlan_present: u8,
    ingress_zone: u16,
    routing_table: u32,
    l3_offset: u16,
    l4_offset: u16,
    payload_offset: u16,
    pkt_len: u16,
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    meta_flags: u8,
    dscp: u8,
    dscp_rewrite: u8,
    reserved: u16,
    flow_src_port: u16,
    flow_dst_port: u16,
    flow_src_addr: [u8; 16],
    flow_dst_addr: [u8; 16],
    config_generation: u64,
    fib_generation: u32,
    reserved2: u32,
}

const _: [(); 96] = [(); mem::size_of::<UserspaceDpMeta>()];
// #7464: the two facts #5192's accepted-residual decision RESTS on, neither of
// which anything asserted. Both are compile-time only and emit no code, so the
// tracked userspace_xdp_bpfel.o is unchanged.
//
// 1. The zero-copy path's alignment argument depends on this. The store site
//    calls `bpf_xdp_adjust_meta` with a negative
//    `meta_len = size_of::<UserspaceDpMeta>()`, so `data_meta = data - 96`, and
//    the whole "the UB is unreachable on the zero-copy fast path because that
//    path is in fact aligned" argument requires that offset to PRESERVE
//    8-alignment.
//
//    The size assertion above happens to imply it today. The implication was
//    nowhere stated, so growing the struct to 100 bytes and updating that
//    assertion to 100 — an ordinary, reviewable edit — would silently move the
//    UB from a generic-XDP portability concern onto the PRIMARY forwarding
//    path, with nothing failing. A check that fails to a value
//    indistinguishable from healthy.
const _: () = assert!(mem::size_of::<UserspaceDpMeta>() % 8 == 0);
// 2. The accepted residual is scoped to an 8-byte alignment demand, which comes
//    from `config_generation: u64`. The layout block pins the size and six
//    offsets and NO alignment, so a future field raising the demand past 8 would
//    widen the residual on every path with no signal. This is the assertion the
//    prior analysis noted was missing and did not add.
const _: () = assert!(mem::align_of::<UserspaceDpMeta>() == 8);
const _: [(); 18] = [(); mem::offset_of!(UserspaceDpMeta, ingress_pcp)];
const _: [(); 19] = [(); mem::offset_of!(UserspaceDpMeta, ingress_vlan_present)];
const _: [(); 20] = [(); mem::offset_of!(UserspaceDpMeta, ingress_zone)];
const _: [(); 24] = [(); mem::offset_of!(UserspaceDpMeta, routing_table)];
const _: [(); 36] = [(); mem::offset_of!(UserspaceDpMeta, addr_family)];
const _: [(); 40] = [(); mem::offset_of!(UserspaceDpMeta, dscp)];
const _: [(); 80] = [(); mem::offset_of!(UserspaceDpMeta, config_generation)];

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceBindingKey {
    ifindex: u32,
    queue_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceBindingValue {
    slot: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceLocalV6Key {
    addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DnatKeyV4 {
    protocol: u8,
    pad: [u8; 3],
    dst_ip: u32,
    dst_port: u16,
    pad2: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DnatValueV4 {
    new_dst_ip: u32,
    new_dst_port: u16,
    flags: u8,
    pad: u8,
}

// Mirrors `struct dnat_key_v6` / `struct dnat_value_v6` in
// bpf/headers/xpf_maps.h (24-byte key, 20-byte value). The v6 reverse-NAT
// table is the IPv6 analog of DNAT_TABLE: the userspace-dp helper publishes
// a (proto, snat_ip, snat_port) -> (orig_src, orig_src_port) entry for each
// SNAT66 flow so an inbound ICMPv6 error carried over a native-GRE tunnel
// (whose inner destination is the SNAT pool address) is steered to the
// helper for embedded-ICMP reverse-NAT (#2406).
#[repr(C)]
#[derive(Clone, Copy)]
struct DnatKeyV6 {
    protocol: u8,
    pad: [u8; 3],
    dst_ip: [u8; 16],
    dst_port: u16,
    from_zone: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DnatValueV6 {
    new_dst_ip: [u8; 16],
    new_dst_port: u16,
    flags: u8,
    pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceSessionKey {
    addr_family: u8,
    protocol: u8,
    pad: u16,
    src_port: u16,
    dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceTraceValue {
    seq: u64,
    stage: u32,
    reason: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    selected_queue: u32,
    slot: u32,
    vlan_id: u16,
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    flow_src_port: u16,
    flow_dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VlanHdr {
    tci: u16,
    encapsulated_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ipv6OptHdr {
    nexthdr: u8,
    hdrlen: u8,
}



#[repr(C)]
struct ShimFacts {
    magic: u32,
    version: u32,
    max_ext_hdrs: u32,
    frag_hdr_size: u32,
    eh_classes: [u8; 256],
}

// Deliberately NOT in `.rodata`: cilium/ebpf surfaces `.rodata*` sections
// as internal MAPS, so the facts would be created in the kernel on every
// load and would have to be added to the retained-collection allowlist.
// These are BUILD-TIME metadata read out of the ELF by `make generate`;
// the BPF programs never touch them. A section the loader does not
// recognise keeps them out of the collection entirely — zero runtime
// cost, no map, no allowlist entry.
#[unsafe(link_section = ".xpf_shim_facts")]
#[unsafe(no_mangle)]
#[used]
static XPF_SHIM_FACTS: ShimFacts = ShimFacts {
    magic: 0x5850_4646,
    version: 1,
    max_ext_hdrs: MAX_EXT_HDRS as u32,
    frag_hdr_size: mem::size_of::<FragHdr>() as u32,
    eh_classes: eh_class_table(),
};

#[map(name = "userspace_ctrl")]
static USERSPACE_CTRL: Array<UserspaceCtrl> = Array::with_max_entries(1, 0);

// Array indexed by (ifindex * BINDING_QUEUES_PER_IFACE + queue_id).
// Go manager populates entries; unoccupied entries have flags=0.
#[map(name = "userspace_bindings")]
static USERSPACE_BINDINGS: Array<UserspaceBindingValue> =
    Array::with_max_entries(BINDING_ARRAY_MAX_ENTRIES, 0);

// Keyed on kernel ifindex which can exceed MAX_INTERFACES on long-lived
// VMs (incus/k8s ifindex grows monotonically). HashMap tolerates sparse
// keys so updates never hit E2BIG regardless of ifindex magnitude. The
// max_entries is bumped to MAX_INTERFACES to keep a single knob on the
// ifindex axis across every dataplane map (see issue #814).
#[map(name = "userspace_ingress_ifaces")]
static USERSPACE_INGRESS_IFACES: HashMap<u32, u8> = HashMap::with_max_entries(MAX_INTERFACES, 0);

#[map(name = "userspace_heartbeat")]
static USERSPACE_HEARTBEAT: Array<u64> = Array::with_max_entries(BINDING_SLOT_MAP_MAX_ENTRIES, 0);

#[map(name = "userspace_xsk_map")]
static USERSPACE_XSK_MAP: XskMap = XskMap::with_max_entries(BINDING_SLOT_MAP_MAX_ENTRIES, 0);

#[map(name = "userspace_local_v4")]
static USERSPACE_LOCAL_V4: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_local_v6")]
static USERSPACE_LOCAL_V6: HashMap<UserspaceLocalV6Key, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_interface_nat_v4")]
static USERSPACE_INTERFACE_NAT_V4: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

#[map(name = "userspace_interface_nat_v6")]
static USERSPACE_INTERFACE_NAT_V6: HashMap<UserspaceLocalV6Key, u8> =
    HashMap::with_max_entries(8192, 0);

// NOTE: This map MUST be pinned/reused from the main eBPF pipeline's
// dnat_table so dynamic SNAT-return entries are visible here. The Go
// loader (pkg/dataplane/loader.go) must ensure the userspace XDP
// collection shares the same pinned dnat_table map fd.
#[map(name = "dnat_table")]
static DNAT_TABLE: HashMap<DnatKeyV4, DnatValueV4> =
    HashMap::with_max_entries(USERSPACE_SHIM_MAX_DNAT_ENTRIES, BPF_F_NO_PREALLOC);

// IPv6 reverse-NAT steering table. Shares the same pinned-map contract as
// DNAT_TABLE above: the Go loader / userspace-dp coordinator reuse the
// pinned dnat_table_v6 fd so SNAT66-return entries published by the helper
// are visible to this classify path (#2406).
#[map(name = "dnat_table_v6")]
static DNAT_TABLE_V6: HashMap<DnatKeyV6, DnatValueV6> =
    HashMap::with_max_entries(USERSPACE_SHIM_MAX_DNAT_ENTRIES, BPF_F_NO_PREALLOC);

#[map(name = "userspace_sessions")]
static USERSPACE_SESSIONS: HashMap<UserspaceSessionKey, u8> = HashMap::with_max_entries(262144, 0);

const USERSPACE_SESSION_ACTION_REDIRECT: u8 = 1;
// PASS_TO_KERNEL's action value is shared with the GRE classifier.

// Pinned-map compatibility exception: Go still reads this map name during
// mixed-version upgrades, but status/docs expose it as degraded_path_counters.
//
// #4113 (F13): PerCpuArray, NOT a shared Array. Native XDP runs one program
// instance per RX queue on distinct CPUs concurrently (loss cluster VFs = 6
// RX queues -> 6 CPUs). `incr_fallback_stat` does a non-atomic load/add/store
// RMW; on a shared Array two CPUs taking the same fallback branch in the same
// window both read v, compute v+1, store v+1 -> one increment LOST. A per-CPU
// array makes each increment CPU-local, so the non-atomic RMW is correct
// (matching the #45 per-CPU-counter lineage the retired eBPF pipeline used).
// The Go/helper readers SUM across CPUs (readDegradedPathStatsLocked,
// read_degraded_path_stats).
#[map(name = "userspace_fallback_stats")]
static USERSPACE_FALLBACK_STATS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(USERSPACE_FALLBACK_REASON_MAX, 0);

// #8249: a per-CPU scratch slot that LAUNDERS the IPv6 non-first-fragment
// sighting out of the extension-header walk's exit state.
//
// WHY A MAP AND NOT A FIELD. Reading a SECOND value out of the walk defeats
// the verifier's state merging at the loop exit: exit states that previously
// merged on equal `protocol` now differ in the fragment flag and cannot. That
// cost is multiplied by every stateful thing downstream, and it is why four
// consumption channels were rejected at the 1,000,000-insn cap. A map read is
// opaque to the verifier, so `protocol` depends on an unknown value instead of
// on the walk's exit state. Measured: consuming the flag directly REJECTS at
// 1,000,001; laundered it costs +298,128 and verifies.
//
// PER-CPU is required, not a preference. Native XDP runs one program instance
// per RX queue on distinct CPUs concurrently; a shared array would let one
// CPU's fragment flag decide another CPU's packet.
#[map(name = "userspace_v6frag_scratch")]
static USERSPACE_V6FRAG_SCRATCH: PerCpuArray<u8> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "userspace_trace")]
static USERSPACE_TRACE: HashMap<u32, UserspaceTraceValue> = HashMap::with_max_entries(1024, 0);

#[map(name = "userspace_cpumap")]
static USERSPACE_CPUMAP: CpuMap = CpuMap::with_max_entries(256, 0);

#[xdp]
pub fn xdp_userspace_prog(ctx: XdpContext) -> u32 {
    match try_xdp_userspace(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn try_xdp_userspace(ctx: &XdpContext) -> Result<u32, i64> {
    let ctrl = USERSPACE_CTRL.get(0).ok_or(0i64)?;
    if ctrl.enabled == 0 || ctrl.metadata_version != USERSPACE_META_VERSION as u32 {
        return degraded_ctrl_disabled_action(ctx, ctrl);
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some((eth_proto, vlan_id, vlan_pcp, vlan_present, outer_stag, l3_offset)) =
        parse_l2(data, data_end)
    else {
        return Ok(cpumap_or_pass(ctrl));
    };
    if eth_proto != ETH_P_IP && eth_proto != ETH_P_IPV6 {
        // #9888/#10657: a still-VLAN post-unwrap ethertype is nested or
        // legacy-tagged and this single-unwrap shim cannot adjudicate it
        // (see `is_vlan_tpid`). #5879 refuses QinQ configs, so there is no
        // stacked-VLAN identity to steer it by. Drop-and-count fail-closed
        // instead of the silent XDP_PASS below, which on a bridged port
        // forwards with no zone policy. Flat comparisons; no unwrap loop.
        //
        // Disclosed cost, not an oversight: a single legacy-TPID outer
        // (0x9100/0x9200/0x9300) may hide ARP/LLDP the shim never unwraps, so
        // this drops L2 the old code passed to the kernel on XDP-bound ports.
        // Passing a shape that cannot be parsed is the hole; dropping it is
        // the fail-closed posture.
        if is_vlan_tpid(eth_proto) {
            return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_QINQ_DROP);
        }
        // #10655: a SINGLE outer S-tag (0x88a8) is an explicit DROP, never
        // the XDP_PASS below. The kernel side is 802.1Q-only, so passing
        // it would hand an S-tag-domain frame to a stack with no S-tag
        // unit — and steering it would stamp (parent, VID) metadata the
        // workers resolve to the C-tag unit with the same VID: zone
        // confusion. There is no S-tag identity to steer by, so the fix
        // is a dedicated reason, not TPID-aware keying (which would only
        // relocate the alias). Ordered AFTER the QinQ check: a double
        // tag with an 88a8 outer is still qinq_drop, never stag_drop.
        if outer_stag {
            return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_STAG_DROP);
        }
        return Ok(pass_non_ip_l2_direct());
    }

    // #5173: this statement is pinned token-for-token by the parity tests, and
    // the name it binds is bounded twice over there — to exactly one `let`
    // binding, and to a fixed total number of mentions anywhere in the crate.
    // The second bound is what catches a rebinding spelled as a tuple pattern,
    // a `let … else`, a macro expansion or a parameter, none of which write the
    // token pair the first one matches. The interface coordinate stays a bare
    // u32 all the way into `binding_slot`, so unlike the queue coordinate
    // NOTHING rejects a reduction of it by type — pinning where it comes from,
    // bounding the name, and pinning how it is passed is the whole defence.
    let ingress_ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    // #8279: this test USED to sit below the L3 parse, and the parse's failure
    // arm is a DROP (`drop_degraded_transit`), so an ifindex this shim does not
    // adjudicate could still have its traffic dropped here. That is reachable:
    // the shim is attached to a strictly LARGER set than the ingress set (every
    // zoned netdev, tunnels included — `compiler_iface.go` puts tunnel ifindexes
    // in `st.xdpIfindexes`), and `syncInterfaceAttachments` only reconciles the
    // difference away at the two post-acceptance points, deliberately (#5485).
    // A tunnel netdev is raw L3 with NO Ethernet header, so `parse_l2` reads
    // bytes [12..14] — the IP SOURCE octets — as the ethertype; an inner source
    // in 8.0.0.0/16 reads as ETH_P_IP and the shifted `parse_ipv4` then fails
    // for 241 of the 256 possible values of the third source octet. The packet's
    // fate was therefore selectable by its own source address, on an interface
    // this shim has no authority over.
    //
    // Moved ABOVE the L3 parse so a non-adjudicated ifindex never reaches the
    // parser at all. This is also the property `manager_compile.go`'s #5485
    // rationale already claims ("an ifindex absent from userspace_ingress_ifaces
    // takes cpumap_or_pass") — the claim was true of every arm except the parse
    // failure, and is now true of all of them.
    //
    // Deliberately NOT hoisted above the non-IP arm directly above: ARP and LLDP
    // must keep taking `pass_non_ip_l2_direct` (a plain XDP_PASS) on EVERY
    // interface. Routing them through `cpumap_or_pass` instead would send them
    // to a remote CPU, which does not drive the local L2 state machine — see
    // that function's own comment. Placing the test here changes the fate of no
    // packet except the one this fixes.
    if unsafe { USERSPACE_INGRESS_IFACES.get(&ingress_ifindex) }.map_or(true, |v| *v == 0) {
        return Ok(cpumap_or_pass(ctrl));
    }

    // The separate S-tag RX-strip offload is tracked in #10915; this check sees only in-frame tags.
    // #10655: a single outer S-tag carrying IP is an explicit DROP, never
    // steered to the helper. Deliberately BELOW the #8279 ingress gate:
    // an ifindex this shim does not adjudicate still takes cpumap_or_pass
    // above, so this drop only ever fires on an adjudicated interface.
    // Below the non-IP guard eth_proto is IP-or-IPv6, so `outer_stag`
    // here is provably a SINGLE S-tag — a double tag's inner TPID took
    // the qinq_drop arm above instead (taxonomy pinned by
    // TestUserspaceXDPSTagOuterDoubleTagStaysQinQ_10655).
    if outer_stag {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_STAG_DROP);
    }

    let parsed = match eth_proto {
        ETH_P_IP => parse_ipv4(data, data_end, vlan_id, vlan_pcp, vlan_present, l3_offset),
        ETH_P_IPV6 => parse_ipv6(data, data_end, vlan_id, vlan_pcp, vlan_present, l3_offset),
        // Unreachable by construction — the guard above already returned for
        // every other ethertype. Kept because `eth_proto` is a bare u16 and the
        // match must be total, and because it names the SAME action the guard
        // takes, so a future edit that weakened the guard would not silently
        // change what a non-IP frame does here. That includes the #9888
        // nested-VLAN drop: without the mirror, weakening the guard would
        // silently re-PASS QinQ frames to the kernel. The #10655 single-S-tag
        // drop is mirrored for the same reason: without it, weakening the
        // guard would silently re-PASS S-tagged L2 to the kernel.
        _ => {
            if is_vlan_tpid(eth_proto) {
                return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_QINQ_DROP);
            }
            if outer_stag {
                return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_STAG_DROP);
            }
            return Ok(pass_non_ip_l2_direct());
        }
    };
    let Some(parsed) = parsed else {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_PARSE_FAIL);
    };
    let native_gre =
        parsed.protocol == PROTO_GRE && (ctrl.flags & USERSPACE_CTRL_FLAG_NATIVE_GRE) != 0;

    // #5173: wrap the coordinate at the ONE point it leaves the context, so
    // nothing downstream can reduce it — `RawRxQueue` has a private field and no
    // arithmetic impls. The repo-scoped checks in the parity tests pin that this
    // is the only construction site and that its argument is the context field.
    let rx_queue = RawRxQueue::from_ctx_field(unsafe { (*ctx.ctx).rx_queue_index });
    let rx_queue_index = rx_queue.for_trace();
    let selected_queue = rx_queue_index;
    record_trace(
        ctrl.flags,
        ingress_ifindex,
        rx_queue_index,
        selected_queue,
        u32::MAX,
        USERSPACE_TRACE_STAGE_RECEIVED,
        0,
        &parsed,
    );
    let binding =
        binding_slot(ingress_ifindex, rx_queue).and_then(|idx| USERSPACE_BINDINGS.get(idx));
    let binding = match binding {
        Some(b) if b.flags != 0 => b,
        _ => {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                u32::MAX,
                USERSPACE_TRACE_STAGE_BINDING_MISSING,
                USERSPACE_FALLBACK_REASON_BINDING_MISSING,
                &parsed,
            );
            if is_degraded_local_or_control(ctrl, data, data_end, &parsed) {
                return pass_local_control(ctrl, USERSPACE_FALLBACK_REASON_BINDING_MISSING);
            }
            return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_BINDING_MISSING);
        }
    };
    if (binding.flags & USERSPACE_BINDING_READY) == 0 {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_BINDING_NOT_READY,
            USERSPACE_FALLBACK_REASON_BINDING_NOT_READY,
            &parsed,
        );
        if is_degraded_local_or_control(ctrl, data, data_end, &parsed) {
            return pass_local_control(ctrl, USERSPACE_FALLBACK_REASON_BINDING_NOT_READY);
        }
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_BINDING_NOT_READY);
    }
    let last_heartbeat = USERSPACE_HEARTBEAT.get(binding.slot);
    let Some(last_heartbeat) = last_heartbeat else {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_HEARTBEAT_MISSING,
            USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING,
            &parsed,
        );
        if is_degraded_local_or_control(ctrl, data, data_end, &parsed) {
            return pass_local_control(ctrl, USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING);
        }
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_HEARTBEAT_MISSING);
    };
    let timeout_ms = if ctrl.heartbeat_timeout_ms == 0 {
        USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS
    } else {
        ctrl.heartbeat_timeout_ms
    };
    let timeout_ns = (timeout_ms as u64) * 1_000_000;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    // #1864: spelled as a guarded wrapping_sub, not saturating_sub. The
    // rustc/LLVM nightlies after 2026-05-23 lower saturating_sub into a
    // materialized-boolean re-branch that defeats BPF verifier state
    // pruning (the rebuilt object blew the 1M processed-insn cap and
    // took both cluster dataplanes down). Semantics are identical: the
    // short-circuit `<` clause handles the underflow case, and on the
    // evaluated path now_ns >= *last_heartbeat makes wrapping_sub exact.
    if now_ns < *last_heartbeat || now_ns.wrapping_sub(*last_heartbeat) > timeout_ns {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_HEARTBEAT_STALE,
            USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE,
            &parsed,
        );
        if is_degraded_local_or_control(ctrl, data, data_end, &parsed) {
            return pass_local_control(ctrl, USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE);
        }
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_HEARTBEAT_STALE);
    }

    // #1864: explicit compare instead of saturating_sub (same verifier
    // state-pruning hazard as the heartbeat check above; identical
    // result for all inputs).
    let packet_len = if data_end > data { data_end - data } else { 0 };
    // #304: ESP and non-native GRE used to be diverted to the kernel here
    // on a PROTOCOL-ONLY test with no destination predicate, so TRANSIT
    // ESP and transit non-native GRE — addressed to a host beyond this
    // firewall — were handed to the kernel forwarding path, where
    // ip_forward=1 and an all-accept nft ruleset forward them with no zone
    // policy evaluated at all. The kernel-termination cases (XFRM for ESP,
    // a kernel GRE device for non-native GRE) are preserved by the
    // local-destination and interface-NAT arms of the session-miss path
    // below, which are destination-qualified; a remote destination now
    // continues to the AF_XDP redirect and is adjudicated by the worker.
    // The DEGRADED path already demanded this (is_degraded_local_or_control
    // gates ESP on is_interface_nat_destination and GRE on native-GRE plus
    // an inner PASS_TO_KERNEL, and drops other transit), so the healthy
    // path was the weaker of the two.
    // #1432 S2a (#9587: set-valued): WireGuard. WG-to-firewall is
    // local-destination UDP on a steered listen port; steer it to the kernel
    // (the userspace control-thread UdpSocket reads it) via cpumap_or_pass —
    // the same path ESP/IPsec rides above. `is_local_destination` is
    // MANDATORY: a port-only match would shunt TRANSIT/DNAT UDP that happens
    // to use a steered port to the kernel, bypassing the userspace policy
    // engine.
    //
    // The whole block is gated on the WG_RX flag bit (read from the same
    // `ctrl.flags` word the GRE check just above already loaded), so when
    // no WG tunnel is configured NOTHING here runs — not the `wg_ports`
    // load, not the protocol/port/local-destination
    // tests. This keeps the non-WG datapath byte-for-byte on its prior
    // instruction path (the bare per-packet `wg_listen_port` load+compare
    // measurably regressed v6 best-effort retransmits at line rate).
    if (ctrl.flags & USERSPACE_CTRL_FLAG_WG_RX) != 0 && wg_steer_to_kernel(ctrl, &parsed) {
        return Ok(cpumap_or_pass(ctrl));
    }
    if should_fallback_early(&parsed) {
        record_trace(
            ctrl.flags,
            ingress_ifindex,
            rx_queue_index,
            selected_queue,
            binding.slot,
            USERSPACE_TRACE_STAGE_EARLY_FILTER,
            USERSPACE_FALLBACK_REASON_EARLY_FILTER,
            &parsed,
        );
        return pass_local_control(ctrl, USERSPACE_FALLBACK_REASON_EARLY_FILTER);
    }
    // #10640: NO unconditional ICMPv6 NDP (types 133-137) arm. One used to
    // sit here, handing every RS/RA/NS/NA/Redirect to the kernel on a
    // TYPE-ONLY test with no destination predicate, so NDP addressed to a
    // TRANSIT destination bypassed the userspace policy engine entirely
    // (the kernel forward path plus the armed fence's ingress-name pinhole
    // forwarded it with no zone policy — the same shape #304 closed for
    // ESP and non-native GRE). NDP still reaches the kernel through the
    // destination-qualified arms below: multicast NDP (solicited-node,
    // all-nodes, all-routers) via should_fallback_early's multicast arm
    // above, and unicast NDP to a firewall-local address via the
    // is_local_destination arm of the session-miss path. A remote
    // destination continues to the AF_XDP redirect and is adjudicated by
    // the worker.
    if !native_gre {
        match live_userspace_session_action(&parsed) {
            USERSPACE_SESSION_ACTION_REDIRECT => {
                // Session exists and stays on the userspace dataplane.
            }
            USERSPACE_SESSION_ACTION_PASS_TO_KERNEL => {
                // LOCAL DELIVERY: this is for packets destined to the firewall
                // itself (management SSH, control plane, etc.). NOT transit.
                // Safe in strict mode — local delivery must always work.
                record_trace(
                    ctrl.flags,
                    ingress_ifindex,
                    rx_queue_index,
                    selected_queue,
                    binding.slot,
                    USERSPACE_TRACE_STAGE_LOCAL_DESTINATION,
                    0,
                    &parsed,
                );
                incr_fallback_stat(USERSPACE_FALLBACK_REASON_PASS_TO_KERNEL);
                return Ok(cpumap_or_pass(ctrl));
            }
            _ => {
                // Session miss — run full checks for new connections.
                if is_icmp_to_interface_nat_local(&parsed) {
                    record_trace(
                        ctrl.flags,
                        ingress_ifindex,
                        rx_queue_index,
                        selected_queue,
                        binding.slot,
                        USERSPACE_TRACE_STAGE_INTERFACE_NAT_LOCAL,
                        0,
                        &parsed,
                    );
                    return Ok(cpumap_or_pass(ctrl));
                }
                // #8274 step 3: a WireGuard TRANSPORT-DATA record for a
                // configured local listener is NOT local delivery any more —
                // the worker decaps it and adjudicates the inner packet under
                // the tunnel's logical ingress zone. Everything else that is
                // locally destined still goes to the kernel exactly as before.
                //
                // This is the arm that made step 2 inert: the WireGuard arm
                // above had already stopped claiming type-4 records, and this
                // predicate caught them and returned the same
                // `cpumap_or_pass`. Declining here is what actually moves them
                // onto the AF_XDP redirect.
                let wg_worker_claim = (ctrl.flags & USERSPACE_CTRL_FLAG_WG_RX) != 0
                    && wg_worker_claims_record(
                        true,
                        parsed.protocol == PROTO_UDP
                            && wg_port_is_steered(
                                parsed.flow_dst_port,
                                &ctrl.wg_ports,
                                ctrl.wg_port_count,
                            ),
                        true,
                        parsed.udp_wg_transport_data,
                    );
                if is_local_destination(&parsed) && !wg_worker_claim {
                    record_trace(
                        ctrl.flags,
                        ingress_ifindex,
                        rx_queue_index,
                        selected_queue,
                        binding.slot,
                        USERSPACE_TRACE_STAGE_LOCAL_DESTINATION,
                        0,
                        &parsed,
                    );
                    return Ok(cpumap_or_pass(ctrl));
                }
                // Interface-NAT session miss: redirect to helper (XSK)
                // so the helper's reverse-NAT repair path can handle
                // reply packets for SNATed flows (#290).
                if is_interface_nat_destination(&parsed) {
                    // #304 kernel arm is keyed by the parsed upper-layer
                    // protocol. #7494 substitutes 255 on non-first fragments,
                    // so retain the wire protocol solely for this disposition
                    // and make ESP / non-native GRE tails follow their
                    // kernel-bound heads. Native GRE is userspace-owned; its
                    // tails and every non-tunnel miss stay on the helper path.
                    if interface_nat_tunnel_passes_to_kernel(
                        parsed.protocol,
                        parsed.wire_protocol,
                        (ctrl.flags & USERSPACE_CTRL_FLAG_NATIVE_GRE) != 0,
                    ) {
                        return Ok(cpumap_or_pass(ctrl));
                    }
                    incr_fallback_stat(USERSPACE_FALLBACK_REASON_INTERFACE_NAT_NO_SESSION);
                    // Fall through to XSK redirect below.
                }
                // Let all session misses through to the userspace dataplane.
                // The userspace DP will evaluate policy and either create a
                // session (new flow) or drop (stale non-SYN TCP / policy deny).
            }
        }
    } else {
        let inner_action = classify_native_gre_inner(data, data_end, &parsed);
        if inner_action == USERSPACE_SESSION_ACTION_PASS_TO_KERNEL
            && native_gre_inner_pass_steers_to_kernel_typed(
                OuterDestinationLocal::from_is_local_destination(is_local_destination(&parsed)),
                InnerSessionAction::from_classifier_action(inner_action),
            )
        {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                binding.slot,
                USERSPACE_TRACE_STAGE_LOCAL_DESTINATION,
                0,
                &parsed,
            );
            incr_fallback_stat(USERSPACE_FALLBACK_REASON_PASS_TO_KERNEL);
            return Ok(cpumap_or_pass(ctrl));
        }
    }
    let meta_len = mem::size_of::<UserspaceDpMeta>() as i32;
    let adjust_rc = unsafe { bpf_xdp_adjust_meta(ctx.ctx as *mut xdp_md, -meta_len) };
    if adjust_rc != 0 {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_ADJUST_META);
    }

    let meta_ptr = ctx.metadata() as *mut UserspaceDpMeta;
    if (meta_ptr as usize).saturating_add(mem::size_of::<UserspaceDpMeta>()) > ctx.metadata_end() {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_META_BOUNDS);
    }

    // #7176 (C179-019) ALIGNMENT: this is a plain aligned store through a
    // *mut UserspaceDpMeta (align_of == 8, from `config_generation: u64`),
    // while the consumer reads the same bytes back with `read_unaligned` and
    // documents that it makes no alignment assumption
    // (userspace-dp/src/afxdp/frame/inspect.rs). The two sides disagree on
    // paper. They do not disagree in practice HERE, and this records why.
    //
    // The invariant this store depends on:
    //     meta_ptr == xdp->data - size_of::<UserspaceDpMeta>()
    //     size_of::<UserspaceDpMeta>() == 96, align_of == 8, 96 % 8 == 0
    //   =>  meta_ptr % 8 == xdp->data % 8
    // So the ONLY variable is whether the driver hands us an 8-aligned
    // `xdp->data`. That is a kernel/driver property, not an xpf one.
    //
    // Measured on the shipped target (mlx5_core VF, AF_XDP native, kernel
    // 7.0.0-rc7+) with a kprobe on bpf_xdp_adjust_meta reading xdp_buff->data:
    // 5,989,142 samples, ALL of them `% 8 == 0`, zero in buckets 1-7, over
    // LAN->WAN v4 and v6 (ping + iperf3). The histogram was NOT broken down
    // by ingress path and no fabric traffic was deliberately driven, so the
    // generic-XDP fabric path is unrepresented or under-represented rather
    // than proven clean; its buffers come from an skb rather than a
    // page-aligned frame, so it is the one surface where the answer could
    // differ.
    //
    // The probe recorded its own total alongside the histogram, deliberately:
    // a kprobe that never fired and a pointer that never misaligned produce
    // the SAME empty histogram. The total (5,989,142, equal to the aligned
    // bucket) is what makes the zero in buckets 1-7 a measurement rather than
    // an absence of evidence.
    //
    // This says the invariant is CURRENTLY SATISFIED on this target. It does
    // NOT say the construct is sound: `ptr::write` to a misaligned pointer is
    // UB regardless of whether the hardware faults, and LLVM is entitled to
    // exploit that, so "x86 tolerates it" is a weaker guarantee than it reads
    // as. A driver whose `xdp->data` is not 8-aligned, or a target that faults
    // on misaligned stores, makes this a live bug rather than a latent one.
    //
    // The fix if that happens is `core::ptr::write_unaligned` here. It was
    // implemented and measured rather than estimated: the BPF backend lowers
    // it to a byte-wise copy costing +145 instructions and +1,152 bytes of
    // .xdp, which moves #1864 verifier headroom 19.86% -> 18.73% against a
    // 15.0% floor — roughly a quarter of the remaining margin. Cheap if the
    // counter ever fires; not worth prepaying while it does not. That delta
    // is attributable because a no-change rebuild of this object is
    // byte-identical (md5 f576dfef5644337fc6f614c35c4555e2): the control was
    // established before the comparison rather than assumed.
    //
    // Note for anyone tempted by a runtime alignment check: the verifier
    // rejects it. `R1 bitwise operator &= on pointer prohibited` — a BPF
    // program cannot observe a packet pointer's alignment at all, so neither
    // an in-band probe nor a check-and-refuse variant is implementable.
    // #8249: the store is OUTLINED. Its live values cost 72 bytes of the ENTRY
    // frame, and the entry frame is 80% of the 512-byte combined-stack budget
    // the GRE classification chain has to fit inside. See the function's own
    // header for the measurement.
    // `pkt_len` is stored here rather than passed, so the call fits BPF's
    // five-argument limit WITHOUT packing either interface coordinate into a
    // wider word. #5173 exists because nothing rejects a REDUCTION of
    // `ingress_ifindex` by type; a pack/unpack pair around it would be a new
    // place for exactly that, so the coordinates travel as their own bare u32
    // arguments and the cheap scalar is the one that moves.
    write_userspace_meta(meta_ptr, &parsed, ingress_ifindex, rx_queue_index, ctrl);
    // Stored AFTER the call, not passed into it, so the call fits BPF's
    // five-argument limit WITHOUT packing either interface coordinate into a
    // wider word. #5173 exists because nothing rejects a REDUCTION of that
    // coordinate by type, and a pack/unpack pair around it would be a new place
    // for exactly that — so the coordinates travel as their own bare u32
    // arguments and the cheap scalar is the one that moves. It is written
    // after rather than before because the callee's whole-struct store would
    // otherwise overwrite it.
    unsafe {
        core::ptr::addr_of_mut!((*meta_ptr).pkt_len)
            .write(packet_len.min(u16::MAX as usize) as u16);
    }

    record_trace(
        ctrl.flags,
        ingress_ifindex,
        rx_queue_index,
        selected_queue,
        binding.slot,
        USERSPACE_TRACE_STAGE_REDIRECT,
        0,
        &parsed,
    );
    match USERSPACE_XSK_MAP.redirect(binding.slot, 0) {
        Ok(action) => Ok(action),
        Err(_) => {
            record_trace(
                ctrl.flags,
                ingress_ifindex,
                rx_queue_index,
                selected_queue,
                binding.slot,
                USERSPACE_TRACE_STAGE_REDIRECT_ERR,
                USERSPACE_FALLBACK_REASON_REDIRECT_ERR,
                &parsed,
            );
            if is_interface_nat_destination(&parsed) {
                incr_fallback_stat(USERSPACE_FALLBACK_REASON_REDIRECT_ERR);
                return Ok(xdp_action::XDP_DROP);
            }
            drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_REDIRECT_ERR)
        }
    }
}

#[inline(never)]
/// #8249: write the per-packet metadata, OUTLINED out of the entry program.
///
/// WHY THIS IS NOT INLINE, and it is a stack-budget reason rather than a code
/// -size one. BPF's limit is 512 bytes COMBINED across a call path. On the
/// path that matters — the entry program into the native-GRE inner classifier —
/// master measured 504 of those 512:
///
///     entry 400 + dispatcher 0 + classify_native_gre_inner_ipv4 104 = 504
///
/// Eight bytes of margin. That is why four unrelated attempts to act on the GRE
/// region were all rejected with `combined stack size of N calls is too large`
/// while none of them reached an instruction cap (#8249): they did not have
/// four different problems, they had one.
///
/// Outlining this store moves its live values into THIS frame instead of the
/// entry's, taking the entry from 400 to 328 and the GRE path from 504 to 432.
///
/// MEASURED, not reasoned. Deleting the store entirely also gives 328, so 328
/// is the floor this move can reach. Writing the same fields one at a time
/// through the pointer — avoiding the 96-byte struct temporary — recovers only
/// EIGHT of the 72 bytes, which is what establishes that the cost is the live
/// values feeding the store rather than the temporary itself. That is also why
/// the scratch-map lever in CLAUDE.md would not have helped: over half the entry
/// frame is register SPILL slots, and there is no large named object to move
/// (`UserspaceDpMeta` is 96 bytes, `ParsedPacket` ~58).
///
/// `stack_margin_8249_test.go` pins the resulting margin so this cannot erode
/// silently back to the eight bytes it started at.
#[inline(never)]
fn write_userspace_meta(
    meta_ptr: *mut UserspaceDpMeta,
    parsed: &ParsedPacket,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    ctrl: &UserspaceCtrl,
) {
    unsafe {
        *meta_ptr = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex,
            rx_queue_index,
            ingress_vlan_id: parsed.vlan_id,
            ingress_pcp: parsed.vlan_pcp,
            ingress_vlan_present: parsed.vlan_present as u8,
            ingress_zone: 0,
            routing_table: 0,
            l3_offset: parsed.l3_offset,
            l4_offset: parsed.l4_offset,
            payload_offset: parsed.payload_offset,
            // Overwritten by the caller immediately after this store — see
            // the note at the call site for why it is not an argument.
            pkt_len: 0,
            addr_family: parsed.addr_family,
            protocol: parsed.protocol,
            tcp_flags: parsed.tcp_flags,
            meta_flags: 0,
            dscp: parsed.dscp,
            dscp_rewrite: 0xff,
            reserved: 0,
            flow_src_port: parsed.flow_src_port,
            flow_dst_port: parsed.flow_dst_port,
            flow_src_addr: parsed.src_addr,
            flow_dst_addr: parsed.dst_addr,
            config_generation: ctrl.config_generation,
            fib_generation: ctrl.fib_generation,
            reserved2: 0,
        };
    }
}

/// #8249: the inner-session lookup, shared by the v4 and v6 GRE classifiers.
///
/// Both built an identical 40-byte `UserspaceSessionKey` and read the SAME map
/// inline, so the verifier explored the key construction and the map read twice.
#[inline(never)]
fn session_action_for_key(key: &UserspaceSessionKey) -> u8 {
    unsafe { USERSPACE_SESSIONS.get(key).copied() }.unwrap_or(0)
}

fn classify_native_gre_inner(data: usize, data_end: usize, outer: &ParsedPacket) -> u8 {
    let gre_offset = outer.l4_offset as usize;
    let Some(gre) = (unsafe { read_bytes(data, data_end, gre_offset, 4) }) else {
        return 0;
    };
    if gre[0] != 0 || gre[1] != 0 {
        return 0;
    }
    let gre_proto = u16::from_be_bytes([gre[2], gre[3]]);
    let Some(inner_offset) = gre_offset.checked_add(4) else {
        return 0;
    };
    match gre_proto {
        GRE_PROTO_IPV4 => classify_native_gre_inner_ipv4(data, data_end, inner_offset),
        GRE_PROTO_IPV6 => classify_native_gre_inner_ipv6(data, data_end, inner_offset),
        _ => 0,
    }
}

#[inline(never)]
fn classify_native_gre_inner_ipv4(data: usize, data_end: usize, l3_offset: usize) -> u8 {
    let Some(iph) = (unsafe { read_bytes(data, data_end, l3_offset, 20) }) else {
        return 0;
    };
    let version_ihl = iph[0];
    if (version_ihl >> 4) != 4 {
        return 0;
    }
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return 0;
    }
    if unsafe { read_bytes(data, data_end, l3_offset, ihl) }.is_none() {
        return 0;
    }
    let protocol = iph[9];
    let mut key = UserspaceSessionKey {
        addr_family: AF_INET,
        protocol,
        pad: 0,
        src_port: 0,
        dst_port: 0,
        src_addr: [0; 16],
        dst_addr: [0; 16],
    };
    key.src_addr[..4].copy_from_slice(&iph[12..16]);
    key.dst_addr[..4].copy_from_slice(&iph[16..20]);
    // Use native-endian to match Go's binary.NativeEndian.Uint32() used
    // for BPF map keys (DNAT_TABLE, USERSPACE_INTERFACE_NAT_V4, USERSPACE_LOCAL_V4).
    let dst_v4 = u32::from_ne_bytes([iph[16], iph[17], iph[18], iph[19]]);
    let Some(l4_offset) = l3_offset.checked_add(ihl) else {
        return 0;
    };
    match protocol {
        PROTO_TCP => {
            let Some(tcp) = (unsafe { read_bytes(data, data_end, l4_offset, 14) }) else {
                return 0;
            };
            key.src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            key.dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        }
        PROTO_UDP => {
            let Some(udp) = (unsafe { read_bytes(data, data_end, l4_offset, 8) }) else {
                return 0;
            };
            key.src_port = u16::from_be_bytes([udp[0], udp[1]]);
            key.dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        }
        PROTO_ICMP => {
            let Some(icmp) = (unsafe { read_bytes(data, data_end, l4_offset, 8) }) else {
                return 0;
            };
            key.src_port = u16::from_be_bytes([icmp[4], icmp[5]]);
        }
        _ => {}
    }
    let action = session_action_for_key(&key);
    if action != 0 {
        return action;
    }
    // ICMP echo flows store the identifier in src_port in the userspace
    // session-key shape. Dynamic SNAT-return DNAT entries use that identifier
    // as the port key, so native GRE must use the same field here or the first
    // reply falls through to the kernel path.
    let dnat_port = if protocol == PROTO_ICMP {
        key.src_port
    } else {
        key.dst_port
    };
    if dnat_lookup_v4(protocol, dst_v4, dnat_port).is_some() {
        return USERSPACE_SESSION_ACTION_REDIRECT;
    }
    // Native GRE owns inner-packet delivery. When the inner destination is a
    // tunnel-local/control-plane address, passing the outer GRE packet to the
    // kernel no longer works once the kernel GRE device has been replaced by a
    // logical anchor. Keep these packets on the userspace dataplane instead.
    if unsafe { USERSPACE_INTERFACE_NAT_V4.get(&dst_v4) }.is_some() {
        return USERSPACE_SESSION_ACTION_REDIRECT;
    }
    if unsafe { USERSPACE_LOCAL_V4.get(&dst_v4) }.is_some() {
        return USERSPACE_SESSION_ACTION_REDIRECT;
    }
    0
}

#[inline(always)]
fn dnat_lookup_v4(protocol: u8, dst_ip: u32, dst_port: u16) -> Option<DnatValueV4> {
    let exact = DnatKeyV4 {
        protocol,
        pad: [0; 3],
        dst_ip,
        dst_port,
        pad2: 0,
    };
    if let Some(value) = unsafe { DNAT_TABLE.get(&exact).copied() } {
        return Some(value);
    }
    let wildcard = DnatKeyV4 {
        protocol,
        pad: [0; 3],
        dst_ip,
        dst_port: 0,
        pad2: 0,
    };
    unsafe { DNAT_TABLE.get(&wildcard).copied() }
}

// Exact-match only: an SNAT66-return entry always carries a concrete
// snat_port (publish_dnat_table_entry v6 arm writes `snat_port`), so the
// exact key is what hits for the #2406 PMTUD/traceroute case. The v4 path
// also probes a port-0 wildcard to catch port-less STATIC DNAT config, but
// the second HASH lookup pushed xdp_userspace_prog over the 1M-insn BPF
// verifier cap (#1864 complexity gate) when added to the v6 GRE-inner
// classify. Port-wildcard static-DNAT-v6 carried inside a native-GRE tunnel
// is not steered by this path; non-GRE DNAT-v6 is unaffected (it rides the
// binding redirect, not dnat_table). Kept #[inline(always)] so the single
// lookup folds into the caller without a separate BPF program symbol.
#[inline(always)]
fn dnat_lookup_v6(protocol: u8, dst_ip: &[u8; 16], dst_port: u16) -> Option<DnatValueV6> {
    let exact = DnatKeyV6 {
        protocol,
        pad: [0; 3],
        dst_ip: *dst_ip,
        dst_port,
        from_zone: 0,
    };
    unsafe { DNAT_TABLE_V6.get(&exact).copied() }
}

#[inline(never)]
fn classify_native_gre_inner_ipv6(data: usize, data_end: usize, l3_offset: usize) -> u8 {
    let Some(ip6) = (unsafe { read_bytes(data, data_end, l3_offset, 40) }) else {
        return 0;
    };
    if (ip6[0] >> 4) != 6 {
        return 0;
    }
    let protocol = ip6[6];
    // #6886: bail out unless the inner next-header is a genuine L4 TERMINAL.
    //
    // This used to hand-list `HOP | ROUTING | DEST | AUTH | FRAGMENT`, which
    // was the complete extension-header set when it was written and stopped
    // being complete when #4517 added Mobility (135), HIP (139), Shim6 (140)
    // and the two experimental values (253/254) to the walker. It also never
    // covered No-Next-Header (59). Those six fell through to `_ => {}` and
    // built a session key whose `protocol` field held an EXTENSION-HEADER
    // type — an identity the real L4 hides behind, not an L4 identity.
    //
    // `eh_class` is the shim's own single classifier: its doc says the walk
    // dispatches on it AND the emitted class table is generated from it, so it
    // cannot describe a different set than the walk treats specially.
    // Deferring to it is what stops this site drifting again the next time the
    // walker learns a type — which is exactly how it drifted the first time,
    // because #4517 swept the walker and not this shortcut.
    if eh_class(protocol) != EH_CLASS_TERMINAL {
        return 0;
    }
    let mut key = UserspaceSessionKey {
        addr_family: AF_INET6,
        protocol,
        pad: 0,
        src_port: 0,
        dst_port: 0,
        src_addr: [0; 16],
        dst_addr: [0; 16],
    };
    key.src_addr.copy_from_slice(&ip6[8..24]);
    key.dst_addr.copy_from_slice(&ip6[24..40]);
    let dst_key = UserspaceLocalV6Key { addr: key.dst_addr };
    let Some(l4_offset) = l3_offset.checked_add(40) else {
        return 0;
    };
    match protocol {
        PROTO_TCP => {
            let Some(tcp) = (unsafe { read_bytes(data, data_end, l4_offset, 14) }) else {
                return 0;
            };
            key.src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            key.dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        }
        PROTO_UDP => {
            let Some(udp) = (unsafe { read_bytes(data, data_end, l4_offset, 8) }) else {
                return 0;
            };
            key.src_port = u16::from_be_bytes([udp[0], udp[1]]);
            key.dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        }
        PROTO_ICMPV6 => {
            let Some(icmp) = (unsafe { read_bytes(data, data_end, l4_offset, 8) }) else {
                return 0;
            };
            key.src_port = u16::from_be_bytes([icmp[4], icmp[5]]);
        }
        _ => {}
    }
    let action = session_action_for_key(&key);
    if action != 0 {
        return action;
    }
    // SNAT66-return steering: an inbound ICMPv6 error (or reply) whose inner
    // destination is a SNAT66 pool address has no live session of its own.
    // The helper publishes the reverse mapping into dnat_table_v6; mirror the
    // v4 path so the GRE-inner classify steers it to userspace for embedded-
    // ICMP reverse-NAT (#2406). ICMPv6 echo flows key the dnat entry on the
    // identifier (stored in src_port), matching publish_dnat_table_entry.
    let dnat_port = if protocol == PROTO_ICMPV6 {
        key.src_port
    } else {
        key.dst_port
    };
    if dnat_lookup_v6(protocol, &key.dst_addr, dnat_port).is_some() {
        return USERSPACE_SESSION_ACTION_REDIRECT;
    }
    if unsafe { USERSPACE_INTERFACE_NAT_V6.get(&dst_key) }.is_some() {
        return USERSPACE_SESSION_ACTION_REDIRECT;
    }
    if unsafe { USERSPACE_LOCAL_V6.get(&dst_key) }.is_some() {
        return USERSPACE_SESSION_ACTION_REDIRECT;
    }
    0
}

fn degraded_ctrl_disabled_action(ctx: &XdpContext, ctrl: &UserspaceCtrl) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let Some((eth_proto, vlan_id, vlan_pcp, vlan_present, outer_stag, l3_offset)) =
        parse_l2(data, data_end)
    else {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_CTRL_DISABLED);
    };
    // #10655: a single outer S-tag (0x88a8) is an explicit DROP, on the IP
    // and non-IP degraded arms alike. This entry has no ingress-interface
    // test by design — it fails closed on all attached interfaces — so one
    // check above the match covers both. The `!is_vlan_tpid` guard keeps
    // the #9888 taxonomy: a double tag with an 88a8 outer still takes the
    // qinq_drop arm below, never stag_drop.
    if outer_stag && !is_vlan_tpid(eth_proto) {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_STAG_DROP);
    }
    let parsed = match eth_proto {
        ETH_P_IP => parse_ipv4(data, data_end, vlan_id, vlan_pcp, vlan_present, l3_offset),
        ETH_P_IPV6 => parse_ipv6(data, data_end, vlan_id, vlan_pcp, vlan_present, l3_offset),
        _ => {
            // #9888/#10657: same nested/legacy-TPID drop as the armed path
            // (see `is_vlan_tpid` for the fail-closed rationale, including
            // the disclosed legacy-outer cost).
            if is_vlan_tpid(eth_proto) {
                return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_QINQ_DROP);
            }
            return pass_non_ip_l2_control_direct(USERSPACE_FALLBACK_REASON_CTRL_DISABLED);
        }
    };
    let Some(parsed) = parsed else {
        return drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_CTRL_DISABLED);
    };
    if is_degraded_local_or_control(ctrl, data, data_end, &parsed) {
        return pass_local_control(ctrl, USERSPACE_FALLBACK_REASON_CTRL_DISABLED);
    }
    drop_degraded_transit(ctrl, USERSPACE_FALLBACK_REASON_CTRL_DISABLED)
}

fn pass_non_ip_l2_control_direct(reason: u32) -> Result<u32, i64> {
    incr_fallback_stat(reason);
    incr_fallback_stat(USERSPACE_FALLBACK_REASON_PASS_TO_KERNEL);
    Ok(pass_non_ip_l2_direct())
}

fn pass_non_ip_l2_direct() -> u32 {
    // Non-IP local L2 frames such as ARP and LLDP must go directly to the
    // kernel stack. cpumap redirect breaks ARP neighbor resolution because
    // the remote-CPU processing path does not drive the local L2 state machine.
    xdp_action::XDP_PASS
}

fn pass_local_control(ctrl: &UserspaceCtrl, reason: u32) -> Result<u32, i64> {
    incr_fallback_stat(reason);
    incr_fallback_stat(USERSPACE_FALLBACK_REASON_PASS_TO_KERNEL);
    Ok(cpumap_or_pass(ctrl))
}

#[inline(always)]
fn is_degraded_local_or_control(
    ctrl: &UserspaceCtrl,
    data: usize,
    data_end: usize,
    parsed: &ParsedPacket,
) -> bool {
    if should_fallback_early(parsed) {
        return true;
    }
    // #10863: NDP is local control only when its destination is local. The
    // early filter above already handles multicast and link-local NDP.
    if is_icmp_to_interface_nat_local(parsed) {
        return true;
    }
    let destination_is_local = is_local_destination(parsed);
    if parsed.protocol == PROTO_ICMPV6
        && degraded_ndp::is_local_ndp_control(parsed.icmp_type, destination_is_local)
    {
        return true;
    }
    if destination_is_local {
        return true;
    }
    if degraded_interface_nat_esp_passes_to_kernel(parsed.protocol, parsed.wire_protocol)
        && is_interface_nat_destination(parsed)
    {
        return true;
    }
    // #10651: the degraded twin of the healthy native-GRE arm's outer-local
    // gate. An inner PASS_TO_KERNEL hit must not kernel-forward a non-local
    // outer here either; the degraded path is cold, so the outer predicate
    // runs before the inner classify.
    if parsed.protocol == PROTO_GRE && (ctrl.flags & USERSPACE_CTRL_FLAG_NATIVE_GRE) != 0 {
        let outer_is_local = is_local_destination(parsed);
        return native_gre_inner_pass_steers_to_kernel_typed(
            OuterDestinationLocal::from_is_local_destination(outer_is_local),
            InnerSessionAction::from_classifier_action(classify_native_gre_inner(
                data, data_end, parsed,
            )),
        );
    }
    false
}

#[inline(always)]
fn is_strict_mode(ctrl: &UserspaceCtrl) -> bool {
    (ctrl.flags & USERSPACE_CTRL_FLAG_STRICT) != 0
}

fn drop_degraded_transit(ctrl: &UserspaceCtrl, reason: u32) -> Result<u32, i64> {
    incr_fallback_stat(reason);
    incr_fallback_stat(USERSPACE_FALLBACK_REASON_TRANSIT_DROP);
    if is_strict_mode(ctrl) {
        incr_fallback_stat(USERSPACE_FALLBACK_REASON_STRICT_DROP);
    }
    Ok(xdp_action::XDP_DROP)
}

fn incr_fallback_stat(reason: u32) {
    if reason >= USERSPACE_FALLBACK_REASON_MAX {
        return;
    }
    if let Some(ptr) = USERSPACE_FALLBACK_STATS.get_ptr_mut(reason) {
        unsafe {
            *ptr = (*ptr).saturating_add(1);
        }
    }
}

fn record_trace(
    ctrl_flags: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    selected_queue: u32,
    slot: u32,
    stage: u32,
    reason: u32,
    parsed: &ParsedPacket,
) {
    // #4113 (F7): gate the BPF map insert on the TRACE flag UNCONDITIONALLY.
    // The previous `forced` bypass ran a per-packet bpf_ktime_get_ns + avalanche
    // key compute + bpf_map_update_elem (per-bucket lock) for the EARLY_FILTER /
    // BINDING_MISSING stages even when tracing was OFF. That was reachable by
    // unauthenticated traffic aimed at well-known multicast/broadcast groups
    // (should_fallback_early) or during a transient config-reload unbind
    // (BINDING_MISSING) -> attacker-influenceable native-XDP hot-path
    // amplification. Degraded-path visibility for those stages is preserved by
    // the (F13 per-CPU) USERSPACE_FALLBACK_STATS counter, which the call sites
    // bump via incr_fallback_stat independently of this trace insert.
    if (ctrl_flags & USERSPACE_CTRL_FLAG_TRACE) == 0 {
        return;
    }
    if matches!(parsed.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return;
    }
    let value = UserspaceTraceValue {
        seq: unsafe { bpf_ktime_get_ns() },
        stage,
        reason,
        ingress_ifindex,
        rx_queue_index,
        selected_queue,
        slot,
        vlan_id: parsed.vlan_id,
        addr_family: parsed.addr_family,
        protocol: parsed.protocol,
        tcp_flags: parsed.tcp_flags,
        flow_src_port: parsed.flow_src_port,
        flow_dst_port: parsed.flow_dst_port,
        src_addr: parsed.src_addr,
        dst_addr: parsed.dst_addr,
    };
    // Keep the key in u32 for the BPF map, but avoid overlapping the two port
    // fields directly. Mix each component into a separate avalanche step so
    // distinct (src_port, dst_port) pairs do not alias trivially.
    let trace_key = ingress_ifindex.wrapping_mul(0x9e37_79b1).rotate_left(5)
        ^ ((((parsed.protocol as u32) << 16) | (parsed.flow_src_port as u32))
            .wrapping_mul(0x85eb_ca6b))
        ^ ((parsed.flow_dst_port as u32).wrapping_mul(0xc2b2_ae35));
    let _ = USERSPACE_TRACE.insert(&trace_key, &value, 0);
}

/// Deliver IP packets to the kernel via cpumap redirect when available on
/// zero-copy AF_XDP paths. Falls back to XDP_PASS when cpumap is not enabled.
fn cpumap_or_pass(ctrl: &UserspaceCtrl) -> u32 {
    if (ctrl.flags & USERSPACE_CTRL_FLAG_CPUMAP) != 0 {
        let cpu = unsafe { bpf_get_smp_processor_id() };
        if let Ok(action) = USERSPACE_CPUMAP.redirect(cpu, 0) {
            return action;
        }
    }
    xdp_action::XDP_PASS
}

#[derive(Clone, Copy)]
struct ParsedPacket {
    // #8274: is this UDP datagram's first payload byte the WireGuard
    // TRANSPORT-DATA message type? Classified in `parse_l4`, where the offset
    // is still a freshly-validated local. A `bool` and not the byte: widening
    // this struct by a `u16` relocated an unrelated packet read into a BPF
    // subprogram and the verifier rejected the object (see `wg_classify`).
    // False for a datagram with no readable payload byte and for every non-UDP
    // protocol.
    udp_wg_transport_data: bool,
    vlan_id: u16,
    vlan_pcp: u8,
    vlan_present: bool,
    l3_offset: u16,
    l4_offset: u16,
    payload_offset: u16,
    addr_family: u8,
    protocol: u8,
    // The IP header's real upper-layer protocol before #7494's non-first-
    // fragment sentinel substitution. Read only by the #10677 interface-NAT
    // tunnel disposition; session and L4 consumers keep using `protocol`.
    wire_protocol: u8,
    icmp_type: u8,
    tcp_flags: u8,
    flow_src_port: u16,
    flow_dst_port: u16,
    dscp: u8,
    src_addr: [u8; 16],
    dst_v4: u32,
    dst_addr: [u8; 16],
}

/// #9888: is this post-unwrap ethertype a VLAN tag protocol identifier?
///
/// `parse_l2` below unwraps exactly ONE 0x8100/0x88a8 tag (`if`, not `while`
/// — the single unwrap is deliberate verifier-cost control, and 0x9100 /
/// 0x9200 / 0x9300 are never unwrapped). So when dispatch sees one of these
/// five values it is NOT a first tag: 0x8100/0x88a8 here is an INNER tag
/// (the frame is double-tagged QinQ), and 0x9100/0x9200/0x9300 here is a
/// legacy outer tag or a legacy inner one. Either shape is unadjudicable —
/// #5879 refuses QinQ configs, so the dataplane has no stacked-VLAN identity
/// to steer it by — and must drop rather than take a non-IP XDP_PASS arm:
/// this interface is XDP-bound, so a passed frame matches the armed forward
/// fence's allowlist (#10302, pkg/nftables/transit_barrier.go) and forwards
/// — by MAC on bridged ports — with no zone verdict. (Pre-fence this read
/// "the kernel forward path that is deliberately open while armed" — #10642.)
/// Complete L2 headers only:
/// this predicate runs on a successful `parse_l2`, never on its `None` path.
///
/// NOTE the single-legacy-outer cost, stated plainly: the shim never unwraps
/// 0x9100/0x9200/0x9300, so such an outer may hide ARP/LLDP this drop now
/// denies the kernel on XDP-bound ports. Deliberate fail-closed trade-off,
/// not an oversight — passing an opaque shape unadjudicated on bridged
/// ports is the #9888 hole (#10657 extends it to 0x9200/0x9300, which took
/// the same silent PASS) — and #5879 already refuses to configure anything
/// behind such a tag.
#[inline(always)]
fn is_vlan_tpid(eth_proto: u16) -> bool {
    eth_proto == ETH_P_8021Q
        || eth_proto == ETH_P_8021AD
        || eth_proto == ETH_P_9100
        || eth_proto == ETH_P_9200
        || eth_proto == ETH_P_9300
}

fn parse_l2(data: usize, data_end: usize) -> Option<(u16, u16, u8, bool, bool, u16)> {
    let eth = unsafe { read_bytes(data, data_end, 0, 14) }?;
    let mut eth_proto = u16::from_be_bytes([eth[12], eth[13]]);
    let mut l3_offset = mem::size_of::<EthHdr>() as u16;
    let mut vlan_id = 0u16;
    let mut vlan_pcp = 0u8;
    let mut vlan_present = false;
    let mut outer_stag = false;

    if eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD {
        // #10655: record the OUTER TPID before the shared unwrap erases it.
        // The unwrap itself stays shared (single tag → l3+4 either way);
        // only the disposition differs, keyed on this bit by both callers.
        outer_stag = eth_proto == ETH_P_8021AD;
        let vlan = unsafe { read_bytes(data, data_end, l3_offset as usize, 4) }?;
        let tci = u16::from_be_bytes([vlan[0], vlan[1]]);
        vlan_id = tci & 0x0fff;
        vlan_pcp = ((tci >> 13) & 0x07) as u8;
        vlan_present = true;
        eth_proto = u16::from_be_bytes([vlan[2], vlan[3]]);
        l3_offset += mem::size_of::<VlanHdr>() as u16;
    }

    Some((eth_proto, vlan_id, vlan_pcp, vlan_present, outer_stag, l3_offset))
}

#[inline(always)]
fn parse_ipv4(
    data: usize,
    data_end: usize,
    vlan_id: u16,
    vlan_pcp: u8,
    vlan_present: bool,
    l3_offset: u16,
) -> Option<ParsedPacket> {
    let iph = unsafe { read_bytes(data, data_end, l3_offset as usize, 20) }?;
    let version_ihl = iph[0];
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    unsafe { read_bytes(data, data_end, l3_offset as usize, ihl) }?;
    // #9901 (F-075): the declared-length gate. Bytes 2..4 sit inside the
    // 20-byte header slice already held, so consulting them costs nothing.
    // A total length below the header length is impossible on the wire and
    // is refused outright; otherwise L4 reads are bounded by the declared
    // datagram end (`l4_end`, a pure scalar) so slack past it is never
    // parsed as a tuple. A lying-LONG length clamps to the capture exactly
    // as before. Every read below still runs against the REAL capture end:
    // the verifier proves packet bounds only against that value, so the
    // declared end is enforced with scalar pre-checks, never substituted
    // for it.
    let total_len = u16::from_be_bytes([iph[2], iph[3]]);
    if !ipv4_declared_len_covers_header(total_len, ihl) {
        return None;
    }
    let l4_end = ipv4_declared_read_end(l3_offset as usize, total_len, data_end);
    // #7494: a non-first fragment has no L4 header -- the bytes at the resolved
    // offset are payload. Substituting the sentinel routes it into parse_l4's
    // EXISTING unknown-protocol arm, which returns zeroed ports and cannot
    // fail. That closes both exposures at one site:
    //
    //   #1  no payload-derived tuple reaches live_userspace_session_action.
    //       The session lookup can never match -- the helper only ever installs
    //       real protocols -- so a fragment is a GUARANTEED MISS, deliberately,
    //       and falls through to the XSK redirect where the helper adjudicates.
    //   #5  parse_l4's TCP arm returns None when the payload byte it reads as a
    //       data-offset nibble is < 5, and the caller turns None into
    //       drop_degraded_transit. That made the DISPOSITION OF A FRAGMENT
    //       SELECTABLE BY ITS OWN PAYLOAD. The unknown-protocol arm cannot
    //       fail, so that drop disappears.
    //
    // A guard at the branch point CANNOT do this: parse_l4 runs here, inside
    // the parser, so #5's drop happens before any later consumer sees the
    // packet. That is why this is in the parser and not beside the session
    // lookup.
    let frag_field = u16::from_be_bytes([iph[6], iph[7]]);
    let non_first_fragment = (frag_field & 0x1FFF) != 0;
    let first_fragment = (frag_field & 0x2000) != 0 && !non_first_fragment;
    let mut protocol = if non_first_fragment {
        PROTO_FRAGMENT_NO_L4
    } else {
        iph[9]
    };
    let tos = iph[1];
    let l4_offset = l3_offset.checked_add(ihl as u16)?;
    // A first fragment's L4 header is legitimately PARTIAL (a minimum legal
    // first fragment carries 8 L4 bytes, below the TCP arm's 14-byte span),
    // so it takes the tuple-tolerant path: ports, plus flags when the
    // declared datagram covers them. When even the tuple falls outside the
    // declared end there is no L4 to stamp — punt to userspace under the
    // no-L4 marker via parse_l4's infallible unknown arm (userspace
    // re-derives fragment status from the header itself downstream) rather
    // than dropping a packet the slow path may still forward. A WHOLE packet
    // short of its L4 inside the declared end is malformed (its full headers
    // are covered by definition), so parse_l4's None still drops it.
    let (payload_offset, tcp_flags, flow_src_port, flow_dst_port, icmp_type, udp_wg_transport_data) =
        if first_fragment {
            match first_fragment_l4(data, data_end, l4_end, l4_offset, protocol) {
                Some(t) => t,
                None => {
                    protocol = PROTO_FRAGMENT_NO_L4;
                    parse_l4(data, data_end, l4_offset, protocol, data_end)?
                }
            }
        } else {
            parse_l4(data, data_end, l4_offset, protocol, l4_end)?
        };
    let src_bytes = unsafe { read_bytes(data, data_end, l3_offset as usize + 12, 4) }?;
    let dst_bytes = unsafe { read_bytes(data, data_end, l3_offset as usize + 16, 4) }?;
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(src_bytes);
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(dst_bytes);
    Some(ParsedPacket {
        vlan_id,
        vlan_pcp,
        vlan_present,
        l3_offset,
        l4_offset,
        payload_offset,
        udp_wg_transport_data,
        addr_family: AF_INET,
        protocol,
        wire_protocol: iph[9],
        icmp_type,
        tcp_flags,
        flow_src_port,
        flow_dst_port,
        dscp: tos >> 2,
        src_addr,
        dst_v4: u32::from_be_bytes([dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]]),
        dst_addr,
    })
}

#[inline(always)]
fn parse_ipv6(
    data: usize,
    data_end: usize,
    vlan_id: u16,
    vlan_pcp: u8,
    vlan_present: bool,
    l3_offset: u16,
) -> Option<ParsedPacket> {
    let ip6 = unsafe { read_bytes(data, data_end, l3_offset as usize, 40) }?;
    let version_priority = ip6[0];
    if (version_priority >> 4) != 6 {
        return None;
    }
    let protocol = ip6[6];
    let offset = l3_offset.checked_add(mem::size_of::<Ipv6Hdr>() as u16)?;

    // #4555: the shared walk, executed verbatim by userspace-dp's parity
    // corpus (`ipv6_ext_walk.rs` is pulled in there through a module-path
    // attribute — described, not spelled; see that file's module comment for
    // why — and driven on real buffers), so its advance arithmetic and bounds
    // revalidation are observed rather than asserted about the source text.
    let walk = ipv6_ext_walk::walk_ipv6_ext_headers(data, data_end, l3_offset, protocol, offset)?;
    let wire_protocol = walk.protocol;
    // #6704: `walk.non_first_fragment` is NOT consumed here yet, and that is a
    // measured decision rather than an oversight. Every shape that acts on it
    // — masking the parsed L4 values, forking the session block, gating the
    // ICMP-type steering, even a lone extra `is_local_destination` on the
    // fragment path — was REJECTED by the kernel verifier at 1,000,001
    // processed instructions against the 1,000,000 cap. Carrying the sighting
    // fits; consuming it does not fit until the shim buys headroom — and the
    // headroom to buy is measured against the 850,000 install-blocking ceiling
    // (`shimverify` exits 4 below the 15% floor, and the build recipe admits
    // only exit 0), NOT against the 1,000,000 cap. No absolute baseline is
    // quoted here on purpose: it moves with every shim change and rots without
    // anyone editing this comment. The successor issue carries the full matrix
    // and the current figure, dated to the commit it was measured at. What the
    // sighting buys today is that the fragment dimension is finally
    // COMPARABLE: userspace-dp's executable parity corpus
    // reads this field against its own `non_first_fragment_offset_seen`, which
    // was impossible while the walk returned a bare `(offset, protocol)`.
    // #7494/#8249: a non-first fragment carries no L4 header — the bytes at the
    // resolved offset are PAYLOAD. Substituting the sentinel routes it into
    // `parse_l4`'s existing unknown-protocol arm, which returns zeroed ports and
    // cannot fail, closing both v6 exposures at one site: no payload-derived
    // tuple can match a session, and the TCP arm's data-offset drop — a
    // disposition an off-path party selected by choosing a payload byte —
    // disappears. This is the v4 fix at `parse_ipv4`, finally affordable for v6.
    //
    // THE GATE IS NOT AN OPTIMISATION, it is what makes the cost acceptable. A
    // non-first fragment requires a Fragment extension header, and the header
    // chain starts at `ip6[6]`. If that is a terminal L4 protocol the packet has
    // NO extension headers, so it cannot be a fragment and the laundering is
    // skipped entirely. `ip6[6]` is a direct read of the fixed header, not a
    // walk result, so the gate itself costs no exit-state correlation. Ordinary
    // IPv6 — which is nearly all traffic — takes the left branch and pays
    // nothing.
    let protocol = if eh_class(ip6[6]) == EH_CLASS_TERMINAL {
        walk.protocol
    } else {
        // FAIL CLOSED. The slot outlives the packet, so a write we did not make
        // leaves the PREVIOUS packet's value in it on this CPU — and a stale
        // `true` would sentinel an ordinary flow into a zero-ported
        // unknown-protocol one. Both map operations are therefore checked, and
        // either failing is treated as "this may be a fragment": the sentinel
        // makes the packet a guaranteed session miss that falls through to the
        // AF_XDP redirect, where the full dataplane adjudicates it. That defers,
        // it does not drop.
        let wrote = if let Some(p) = USERSPACE_V6FRAG_SCRATCH.get_ptr_mut(0) {
            unsafe { *p = walk.non_first_fragment as u8 };
            true
        } else {
            false
        };
        let seen = unsafe { USERSPACE_V6FRAG_SCRATCH.get(0) }.copied();
        let non_first = match (wrote, seen) {
            (true, Some(v)) => v != 0,
            _ => true,
        };
        if non_first {
            PROTO_FRAGMENT_NO_L4
        } else {
            walk.protocol
        }
    };
    let offset = walk.offset;

    let flow_lbl0 = ip6[1];
    let dscp = ((version_priority & 0x0f) << 2) | (flow_lbl0 >> 6);
    let payload_len = u16::from_be_bytes([ip6[4], ip6[5]]);
    let (payload_offset, tcp_flags, flow_src_port, flow_dst_port, icmp_type, udp_wg_transport_data) =
        parse_l4(data, data_end, offset, protocol, data_end)?;
    // #10662: keep the capture-bound L4 parse EXACTLY as before. Passing a
    // declared bound through parse_l4 multiplied verifier states past the
    // kernel cap while the control build fit comfortably (dated figures in
    // #10998, not here: absolute counts rot every merge). This single
    // post-check compares only the consumed packet-relative L4 end; the
    // scalar truncation verdict never becomes a new packet bound or enters
    // the heavy parse.
    let declared_end = ipv6_declared_end(l3_offset as usize, payload_len);
    let l4_truncated = payload_offset as usize > declared_end;
    if l4_truncated {
        return None;
    }
    // #8249 EXPERIMENT: reuse the already-validated 40-byte header slice
    // instead of re-reading the addresses from the packet. `ip6` covers
    // [l3_offset, l3_offset+40) and the addresses live at +8 and +24 within it.
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&ip6[8..24]);
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&ip6[24..40]);
    Some(ParsedPacket {
        vlan_id,
        vlan_pcp,
        vlan_present,
        l3_offset,
        l4_offset: offset,
        payload_offset,
        udp_wg_transport_data,
        addr_family: AF_INET6,
        protocol,
        wire_protocol,
        icmp_type,
        tcp_flags,
        flow_src_port,
        flow_dst_port,
        dscp,
        src_addr,
        dst_v4: 0,
        dst_addr,
    })
}

/// #1432 S2a: decide whether an inbound packet is WireGuard-to-firewall
/// that must be steered to the kernel (the control-thread `UdpSocket`).
/// The single call site has already verified `ctrl.flags &
/// USERSPACE_CTRL_FLAG_WG_RX != 0` (a bit-test on the flags word already
/// loaded for the GRE/STRICT checks), so when no WG tunnel is configured
/// the non-WG datapath skips this entirely — it pays ONLY the flag
/// bit-test. The flag-gate, not the function boundary, is what makes the
/// path zero-cost: an earlier `#[inline(never)] #[cold]` variant emitted
/// this as a separate BPF program symbol (tripping the shim
/// program-allowlist canary), so it is a normal inlinable fn behind the
/// flag gate. `is_local_destination` is MANDATORY — a port-only match
/// would shunt transit/DNAT UDP on the WG port to the kernel, bypassing
/// the userspace policy engine.
fn wg_steer_to_kernel(ctrl: &UserspaceCtrl, pkt: &ParsedPacket) -> bool {
    // Order is load-bearing (#1432, #9587): the UDP test first, then the
    // bounded set scan (register compares), and `is_local_destination` LAST
    // (up to two BPF map lookups). Nothing below runs for a packet that is
    // not UDP to a steered port.
    if pkt.protocol != PROTO_UDP
        || !wg_port_is_steered(pkt.flow_dst_port, &ctrl.wg_ports, ctrl.wg_port_count)
    {
        return false;
    }
    // #8274 step 2: types 1/2/3 (handshake, cookie) keep going to the kernel —
    // the control thread owns the handshake state machine and there is nothing
    // in them for the dataplane to adjudicate. Type 4 (transport data) does
    // not, because its plaintext is what the firewall has to adjudicate. The
    // decision lives in `wg_classify` so a host test can EXECUTE it rather than
    // model it from source text; see that module for why.
    //
    // INERT until step 3 lands the worker decap stage. A type-4 record that is
    // no longer claimed here falls through to the session-miss path and is
    // matched by the SAME `is_local_destination` predicate a few arms down,
    // returning the SAME `cpumap_or_pass(ctrl)`. The only path on which the two
    // differ is a live userspace session on the OUTER 5-tuple
    // (`USERSPACE_SESSION_ACTION_REDIRECT`), and nothing installs one: the outer
    // UDP header is synthesized at frame-build time by `wg_encap_frame` under
    // the INNER flow's session, and the inbound direction reaches the kernel
    // without the worker ever adjudicating it.
    wg_steer_to_kernel_on_port_match(is_local_destination(pkt), pkt.udp_wg_transport_data)
}

fn should_fallback_early(pkt: &ParsedPacket) -> bool {
    // #304: ESP and non-native GRE are no longer diverted to the kernel
    // ahead of this function; they are classified here like any other
    // protocol and reach the kernel only through the destination-qualified
    // local-destination / interface-NAT arms of the session-miss path.
    // #10640: the verdict lives in `early_filter` (host-executed by the
    // userspace-dp regression test). IPv4 169.254/16 no longer passes
    // early: scope alone never made a destination local to this box, and
    // genuinely local link-local addresses still deliver via the
    // `is_local_destination` arm of the session-miss path.
    match pkt.addr_family {
        AF_INET => early_filter::ipv4_early_pass_to_kernel(pkt.dst_v4),
        AF_INET6 => early_filter::ipv6_early_pass_to_kernel(pkt.dst_addr),
        _ => true,
    }
}

fn is_local_destination(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => {
            if unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some() {
                return false;
            }
            unsafe { USERSPACE_LOCAL_V4.get(&pkt.dst_v4) }.is_some()
        }
        AF_INET6 => {
            let key = UserspaceLocalV6Key { addr: pkt.dst_addr };
            if unsafe { USERSPACE_INTERFACE_NAT_V6.get(&key) }.is_some() {
                return false;
            }
            unsafe { USERSPACE_LOCAL_V6.get(&key) }.is_some()
        }
        _ => true,
    }
}

fn is_icmp_to_interface_nat_local(pkt: &ParsedPacket) -> bool {
    match pkt.addr_family {
        AF_INET => {
            // Echo reply (0) must reach the kernel for locally-originated
            // pings, since the kernel matches replies to the ping process.
            // Echo request (8) is also allowed here so inbound requests to
            // interface-local/NAT destinations are delivered to the kernel.
            if pkt.protocol != PROTO_ICMP || (pkt.icmp_type != 8 && pkt.icmp_type != 0) {
                return false;
            }
            unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some()
        }
        AF_INET6 => {
            if pkt.protocol != PROTO_ICMPV6 || (pkt.icmp_type != 128 && pkt.icmp_type != 129) {
                return false;
            }
            unsafe { USERSPACE_INTERFACE_NAT_V6.get(&UserspaceLocalV6Key { addr: pkt.dst_addr }) }
                .is_some()
        }
        _ => false,
    }
}

fn is_interface_nat_destination(pkt: &ParsedPacket) -> bool {
    // ICMP errors (TTL Exceeded, Unreachable, etc.) to NAT addresses must NOT
    // be passed to the kernel — they need embedded-ICMP NAT reversal in the
    // userspace helper.  Return false so they fall through to XSK redirect.
    if pkt.protocol == PROTO_ICMP
        && (pkt.icmp_type == 3 || pkt.icmp_type == 11 || pkt.icmp_type == 4 || pkt.icmp_type == 12)
    {
        return false;
    }
    if pkt.protocol == PROTO_ICMPV6 && pkt.icmp_type >= 1 && pkt.icmp_type <= 4 {
        return false;
    }
    match pkt.addr_family {
        AF_INET => unsafe { USERSPACE_INTERFACE_NAT_V4.get(&pkt.dst_v4) }.is_some(),
        AF_INET6 => {
            unsafe { USERSPACE_INTERFACE_NAT_V6.get(&UserspaceLocalV6Key { addr: pkt.dst_addr }) }
                .is_some()
        }
        _ => false,
    }
}

fn live_userspace_session_action(pkt: &ParsedPacket) -> u8 {
    let key = UserspaceSessionKey {
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        pad: 0,
        src_port: pkt.flow_src_port,
        dst_port: pkt.flow_dst_port,
        src_addr: pkt.src_addr,
        dst_addr: pkt.dst_addr,
    };
    unsafe { USERSPACE_SESSIONS.get(&key).copied() }.unwrap_or(0)
}

fn is_connection_initiating(pkt: &ParsedPacket) -> bool {
    match pkt.protocol {
        PROTO_TCP => (pkt.tcp_flags & TCP_FLAG_SYN) != 0 && (pkt.tcp_flags & TCP_FLAG_ACK) == 0,
        PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6 => true,
        _ => true,
    }
}

/// #9901 (F-075): the L4 tuple for a FIRST fragment, whose L4 header is
/// legitimately partial. `declared_end` is the declared-datagram bound (a pure
/// scalar from `parse_ipv4`); every span is scalar-checked against it BEFORE
/// the corresponding read, which itself runs against the real capture end —
/// the verifier proves packet bounds only against that value.
///
/// TCP takes the tuple-tolerant shape: the 4 port bytes must be covered
/// (else None, and the caller punts under the no-L4 marker), while the flags
/// byte is read when covered and zero otherwise — a minimum legal first
/// fragment carries 8 L4 bytes, which names the tuple but not the flags.
/// Every other protocol runs the standard arms against the same declared
/// end (UDP's 8/9-byte and ICMP's 8-byte spans fit a minimum first fragment;
/// short of that the caller punts rather than dropping).
#[inline(always)]
fn first_fragment_l4(
    data: usize,
    data_end: usize,
    declared_end: usize,
    l4_offset: u16,
    protocol: u8,
) -> Option<(u16, u8, u16, u16, u8, bool)> {
    if protocol == PROTO_TCP {
        if declared_end < l4_offset as usize + 4 {
            return None;
        }
        let ports = unsafe { read_bytes(data, data_end, l4_offset as usize, 4) }?;
        let flags = if declared_end >= l4_offset as usize + 14 {
            unsafe { read_bytes(data, data_end, l4_offset as usize + 13, 1) }.map_or(0, |b| b[0])
        } else {
            0
        };
        return Some((
            l4_offset,
            flags,
            u16::from_be_bytes([ports[0], ports[1]]),
            u16::from_be_bytes([ports[2], ports[3]]),
            0,
            false,
        ));
    }
    parse_l4(data, data_end, l4_offset, protocol, declared_end)
}

/// #8249: `#[inline(always)]` is LOAD-BEARING for verifier headroom, not a
/// performance hint.
///
/// Without it LLVM emits `parse_l4` as a BPF SUBPROGRAM, and a BPF-to-BPF call
/// is verified once per distinct calling state. `parse_l4` is reached from
/// `parse_ipv4`, `parse_ipv6` and both GRE inner classifiers, so the callee's
/// protocol dispatch was being walked from every one of them. Measured on the
/// real kernel verifier (`make generate` -> `shimverify`, no
/// `XPF_SHIM_ALLOW_LOW_HEADROOM`):
///
/// Both figures measured at commit `a02e55248`, and quoted against the 15%
/// install-blocking floor (~850,000 processed insns) rather than the 1,000,000
/// kernel cap — a shape that fits under the cap can still be unshippable
/// (#8241).
///
/// | | processed insns | total_states | slack to the 15% floor |
/// |---|---:|---:|---:|
/// | subprogram, at `a02e55248` | 795,764 | 43,377 | 54,236 |
/// | inlined, at `a02e55248` | 497,050 | 25,509 | 352,950 |
///
/// 298,714 instructions and 41% of the verifier's states. Removing this
/// attribute does not fail a test — it silently spends a third of the object's
/// budget, which is how the shim reached 0.92% headroom before #4555.
///
/// It also answers a request rather than being an opportunistic saving. #8274
/// step 3 (worker WireGuard decap) spent ~110,000 insns and left this trend in
/// its PR body, measured at `dc9c9d801`: "master 31.38% -> step 2 23.20% ->
/// 20.42% ... two thirds of the margin is gone ... buy headroom back rather
/// than assume it is there". Re-measured at `a02e55248`, a descendant of
/// `dc9c9d801`, the 795,764 / 20.42% control above IS that figure, so this
/// change puts back more than all of what step 3 spent.
///
/// THE COST, so a later editor prices it before growing this function:
/// `#[inline(always)]` on a fn reached from FOUR call sites multiplies its code
/// by four. That is a large net win today only because the per-calling-state
/// re-verification it removes is worth far more than the duplication it adds.
/// Grow `parse_l4` and you pay 4x — re-measure before assuming the trade still
/// holds.
///
/// NOT IN TENSION with `classify_native_gre_inner*` two hundred lines up, which
/// are deliberately `#[inline(never)]`. They are the opposite shape: LARGE
/// (1,848 and 2,160 bytes) and reached from ONE call site each, so outlining
/// buys state isolation for a cold path and costs no repeated walk. `parse_l4`
/// is small and reached from four, so outlining bought nothing and paid four
/// walks. The lever is bidirectional; the shape decides the direction, and
/// "make them consistent" would be a regression whichever way it was applied.
///
/// A NOTE ON FIGURES HERE. Dated headroom measurements rot within days: this
/// file has carried four successive control figures inside a single issue's
/// lifetime, each stale by the next merge that touched the crate, because a
/// headroom number without the sha it was measured at is a trap. #8249 twice
/// sent someone to reason against a moved figure, which is most of what that
/// issue cost. State relationships that do not move instead: carrying fits,
/// consuming does not, and the install-blocking ceiling is the 15% floor, not
/// the 1M cap. The current dated measurement lives in #10998, not here.
/// `declared_end` (#9901, F-075) is the caller's bound on how far L4 reads
/// may go — the IPv4 declared-datagram end, a pure scalar. Every arm below
/// scalar-checks its span against it BEFORE reading; the reads themselves
/// run against the real capture end, which is the only value the verifier
/// proves packet bounds against. Callers with no declared bound (IPv6,
/// GRE-inner) pass `data_end`, which makes every check vacuous.
#[inline(always)]
fn parse_l4(
    data: usize,
    data_end: usize,
    l4_offset: u16,
    protocol: u8,
    declared_end: usize,
) -> Option<(u16, u8, u16, u16, u8, bool)> {
    match protocol {
        PROTO_TCP => {
            // Span first (scalar), read second (packet): the 14-byte span,
            // then the data-offset span once the byte is known.
            if declared_end < l4_offset as usize + 14 {
                return None;
            }
            let bytes = unsafe { read_bytes(data, data_end, l4_offset as usize, 14) }?;
            let data_offset = ((bytes[12] >> 4) as u16) * 4;
            if data_offset < 20 {
                return None;
            }
            if declared_end < l4_offset as usize + data_offset as usize {
                return None;
            }
            unsafe { read_bytes(data, data_end, l4_offset as usize, data_offset as usize) }?;
            Some((
                l4_offset.checked_add(data_offset)?,
                bytes[13],
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                0,
                false,
            ))
        }
        PROTO_UDP => {
            // #8274: the FIRST PAYLOAD BYTE is captured here, not downstream.
            // For a WireGuard datagram it is the message type, and the shim
            // needs it to decide whether the record is a handshake (kernel) or
            // transport data (worker). Reading it at `pkt.payload_offset` in
            // `wg_steer_to_kernel` was tried and the kernel verifier REJECTED
            // the object — that offset arrives through a `ParsedPacket` field
            // with a wide `var_off`, and neither a hand-rolled deref, nor
            // `read_bytes`, nor the documented narrowing mask made it
            // trackable. See `wg_classify` for the full record.
            //
            // TRY THE 9-BYTE READ FIRST AND RETURN FROM INSIDE IT. Splitting it
            // into "8-byte header read, then a second 9-byte read whose result
            // is merged with a constant" was ALSO rejected
            // (`invalid access to packet, off=0 size=1, r=0`): the two reads
            // share a base, and after the merge the 1-byte load is dominated by
            // the EIGHT-byte bound, which does not cover offset 8. This shape
            // gives each read exactly one dominating check — the "branch merges
            // lose packet range" hazard CLAUDE.md records, in its packet-read
            // form.
            //
            // The 8-byte fallback below is NOT dead: a zero-length UDP payload
            // is legal (a WireGuard keepalive is a type-4 record with an empty
            // payload, but plenty of other UDP has none at all), and it must
            // still parse and yield its ports.
            // #9901: the 9-byte fast path additionally requires the 9th byte
            // inside the DECLARED datagram — past it lies pad/slack, whose
            // value must not steer WireGuard classification. The scalar gate
            // wraps the read without merging packet checks, so the #8274
            // one-dominating-check-per-read shape is preserved.
            if declared_end >= l4_offset as usize + 9 {
                if let Some(b) = unsafe { read_bytes(data, data_end, l4_offset as usize, 9) } {
                    return Some((
                        l4_offset.checked_add(8)?,
                        0,
                        u16::from_be_bytes([b[0], b[1]]),
                        u16::from_be_bytes([b[2], b[3]]),
                        0,
                        wg_record_is_transport_data(Some(b[8])),
                    ));
                }
            } else if declared_end < l4_offset as usize + 8 {
                return None;
            }
            let bytes = unsafe { read_bytes(data, data_end, l4_offset as usize, 8) }?;
            Some((
                l4_offset.checked_add(8)?,
                0,
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                0,
                false,
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            if declared_end < l4_offset as usize + 8 {
                return None;
            }
            let bytes = unsafe { read_bytes(data, data_end, l4_offset as usize, 8) }?;
            Some((
                l4_offset.checked_add(8)?,
                0,
                u16::from_be_bytes([bytes[4], bytes[5]]),
                0,
                bytes[0],
                wg_record_is_transport_data(None),
            ))
        }
        _ => Some((l4_offset, 0, 0, 0, 0, false)),
    }
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
