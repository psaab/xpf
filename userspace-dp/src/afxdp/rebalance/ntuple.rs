// #1748: direct ethtool rxnfc ioctl module for exact-5-tuple ntuple flow
// steering. The rust-netlink `ethtool` crate does NOT expose
// rxnfc/flow-classification rules (only feature/coalesce/ring/channel/link/
// pause/FEC/timestamp), so flow rules are ioctl-only. This mirrors the
// `libc::ioctl`-on-AF_INET-SOCK_DGRAM pattern in `slowpath.rs`.
//
// UAPI layout asserted at compile time against the kernel `ethtool.h`
// (x86-64, C-verified offsets):
//   struct ethtool_rx_flow_spec = 168 B:
//     flow_type u32 @0; h_u union @4 (52 B); h_ext @56 (20 B);
//     m_u union @76 (52 B); m_ext @128 (20 B); pad @148 (4 B);
//     ring_cookie u64 @152; location u32 @160; trailing pad @164 (4 B).
//   struct ethtool_rxnfc = 192 B:
//     cmd u32 @0; flow_type u32 @4; data u64 @8; fs @16 (168 B);
//     rule_cnt/rss_context u32 @184; rule_locs [u32;0] flexible @188.
//
// NOTE: the #1748 plan §4.1 documented `rule_locs @192`; the C compiler
// places the zero-length flexible array at @188 (rule_cnt@184, no padding;
// sizeof rounds to 192 for u64 alignment). The compile-time asserts below
// pin the C-verified offsets, which are authoritative.

use std::io;
use std::mem::{offset_of, size_of};
use std::os::fd::AsRawFd;

/// `SIOCETHTOOL` — the ioctl request that carries every ethtool command.
const SIOCETHTOOL: libc::c_ulong = 0x8946;

/// ethtool command numbers (ethtool.h).
const ETHTOOL_GRXCLSRLALL: u32 = 0x0000_0030; // get all classification rule locations
const ETHTOOL_SRXCLSRLDEL: u32 = 0x0000_0031; // delete a classification rule
const ETHTOOL_SRXCLSRLINS: u32 = 0x0000_0032; // insert a classification rule
const ETHTOOL_GRXCLSRLCNT: u32 = 0x0000_0029; // get count of classification rules
const ETHTOOL_GRXCLSRULE: u32 = 0x0000_002e; // get a single classification rule

/// flow_type values (ethtool.h enum). 0x01 = TCP/IPv4 spec (`tcp_ip4_spec`);
/// the plan's "0x03" was SCTP_V4_FLOW — corrected here against the header.
const TCP_V4_FLOW: u32 = 0x01;
const UDP_V4_FLOW: u32 = 0x02;
const TCP_V6_FLOW: u32 = 0x05;
const UDP_V6_FLOW: u32 = 0x06;

/// Flag bit OR'd into the GRXCLSRLCNT `data` reply when the DRIVER manages
/// rule locations (auto-assign). ethtool(8) `rmgr_find_empty_slot` returns
/// early (lets the driver pick) when this is set. mlx5 does NOT set it — it
/// requires the caller to supply a concrete location — so for mlx5 we always
/// pick the slot ourselves (#1751).
const RX_CLS_LOC_SPECIAL: u32 = 0x8000_0000;
/// Fallback location-space depth (mlx5 `MAX_NUM_OF_ETHTOOL_RULES = BIT(10)`)
/// used only if GRXCLSRLALL returns `data == 0` (it normally returns the real
/// table size). Locations are in `[0, size)`.
const DEFAULT_RULE_TABLE_SIZE: u32 = 1024;

/// `struct ethtool_tcpip4_spec` (ethtool.h) — 16 B. Network-order fields.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EthtoolTcpip4Spec {
    ip4src: u32, // __be32
    ip4dst: u32, // __be32
    psrc: u16,   // __be16
    pdst: u16,   // __be16
    tos: u8,
    _pad: [u8; 3],
}
const _: () = assert!(size_of::<EthtoolTcpip4Spec>() == 16);

/// `struct ethtool_tcpip6_spec` (ethtool.h) — 40 B (32 addr + 2+2 ports + 1
/// tclass, padded to 4-byte alignment). Network-order fields.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EthtoolTcpip6Spec {
    ip6src: [u32; 4], // __be32[4]
    ip6dst: [u32; 4], // __be32[4]
    psrc: u16,        // __be16
    pdst: u16,        // __be16
    tclass: u8,
    _pad: [u8; 3],
}
const _: () = assert!(size_of::<EthtoolTcpip6Spec>() == 40);

/// `union ethtool_flow_union` — 52 B (`hdata[52]` is the largest member).
#[repr(C)]
#[derive(Clone, Copy)]
struct EthtoolFlowUnion {
    hdata: [u8; 52],
}
const _: () = assert!(size_of::<EthtoolFlowUnion>() == 52);

impl Default for EthtoolFlowUnion {
    fn default() -> Self {
        Self { hdata: [0u8; 52] }
    }
}

impl EthtoolFlowUnion {
    fn from_tcpip4(spec: EthtoolTcpip4Spec) -> Self {
        let mut u = Self::default();
        // SAFETY: EthtoolTcpip4Spec (16 B) <= 52 B and is plain-old-data.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &spec as *const _ as *const u8,
                size_of::<EthtoolTcpip4Spec>(),
            )
        };
        u.hdata[..bytes.len()].copy_from_slice(bytes);
        u
    }

    fn from_tcpip6(spec: EthtoolTcpip6Spec) -> Self {
        let mut u = Self::default();
        // SAFETY: EthtoolTcpip6Spec (36 B) <= 52 B and is plain-old-data.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &spec as *const _ as *const u8,
                size_of::<EthtoolTcpip6Spec>(),
            )
        };
        u.hdata[..bytes.len()].copy_from_slice(bytes);
        u
    }
}

/// `struct ethtool_flow_ext` — 20 B: padding[2] + h_dest[6] + vlan_etype[2]
/// + vlan_tci[2] + data[2*4].
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EthtoolFlowExt {
    padding: [u8; 2],
    h_dest: [u8; 6],
    vlan_etype: u16,
    vlan_tci: u16,
    data: [u32; 2],
}
const _: () = assert!(size_of::<EthtoolFlowExt>() == 20);

/// `struct ethtool_rx_flow_spec` — 168 B.
#[repr(C)]
#[derive(Clone, Copy)]
struct EthtoolRxFlowSpec {
    flow_type: u32,
    h_u: EthtoolFlowUnion,
    h_ext: EthtoolFlowExt,
    m_u: EthtoolFlowUnion,
    m_ext: EthtoolFlowExt,
    ring_cookie: u64,
    location: u32,
}
const _: () = assert!(size_of::<EthtoolRxFlowSpec>() == 168);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, flow_type) == 0);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, h_u) == 4);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, h_ext) == 56);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, m_u) == 76);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, m_ext) == 128);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, ring_cookie) == 152);
const _: () = assert!(offset_of!(EthtoolRxFlowSpec, location) == 160);

impl Default for EthtoolRxFlowSpec {
    fn default() -> Self {
        Self {
            flow_type: 0,
            h_u: EthtoolFlowUnion::default(),
            h_ext: EthtoolFlowExt::default(),
            m_u: EthtoolFlowUnion::default(),
            m_ext: EthtoolFlowExt::default(),
            ring_cookie: 0,
            location: 0,
        }
    }
}

/// `struct ethtool_rxnfc` — 192 B. `rule_locs` is a flexible array member
/// `[u32; 0]` at offset 188; for GRXCLSRLALL we over-allocate a trailing
/// buffer (see `list_rules`).
#[repr(C)]
#[derive(Clone, Copy)]
struct EthtoolRxnfc {
    cmd: u32,
    flow_type: u32,
    data: u64,
    fs: EthtoolRxFlowSpec,
    rule_cnt: u32, // union with rss_context
    rule_locs: [u32; 0],
}
const _: () = assert!(size_of::<EthtoolRxnfc>() == 192);
const _: () = assert!(offset_of!(EthtoolRxnfc, cmd) == 0);
const _: () = assert!(offset_of!(EthtoolRxnfc, flow_type) == 4);
const _: () = assert!(offset_of!(EthtoolRxnfc, data) == 8);
const _: () = assert!(offset_of!(EthtoolRxnfc, fs) == 16);
const _: () = assert!(offset_of!(EthtoolRxnfc, rule_cnt) == 184);
const _: () = assert!(offset_of!(EthtoolRxnfc, rule_locs) == 188);

impl Default for EthtoolRxnfc {
    fn default() -> Self {
        Self {
            cmd: 0,
            flow_type: 0,
            data: 0,
            fs: EthtoolRxFlowSpec::default(),
            rule_cnt: 0,
            rule_locs: [],
        }
    }
}

/// Union matching the kernel's `ifreq.ifr_ifru` payload. The union itself is
/// 24 bytes on x86_64 (dominated by `struct ifmap`'s 24-byte layout), making
/// `sizeof(struct ifreq)` = 16 (ifr_name) + 24 (union) = 40 bytes. We mirror
/// that union size so the kernel's `copy_from_user(sizeof(struct ifreq))` does
/// not read past our allocation. For SIOCETHTOOL only the `data` arm is used.
#[repr(C)]
union EthtoolIfru {
    /// The `ifr_data` arm: pointer to an ethtool command struct.
    ///
    /// # Safety
    /// When `data` is active, it must point to a valid, correctly-sized
    /// ethtool command struct (e.g. `EthtoolRxnfc`) that outlives the ioctl
    /// call. The caller is responsible for upholding this invariant.
    data: *mut libc::c_void,
    /// Padding arm: sizes the union to 24 bytes, matching `sizeof(struct ifmap)`
    /// on x86_64 (the largest arm of the kernel's `ifreq.ifr_ifru` union).
    _pad: [u8; 24],
}

/// `struct ifreq` carrying `ifr_data` = pointer to an ethtool command.
/// `sizeof(EthtoolIfreq)` == 40 bytes on x86_64 (IFNAMSIZ=16 + union=24),
/// matching the kernel ABI so `copy_from_user(sizeof(struct ifreq))` is safe.
#[repr(C)]
struct EthtoolIfreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifru: EthtoolIfru,
}

// Enforce the 40-byte ABI match on x86_64 (IFNAMSIZ=16 + ifru union=24).
// On other architectures the kernel's struct ifreq may differ; ntuple ioctl
// support is mlx5-specific and therefore x86_64-only in practice.
#[cfg(target_arch = "x86_64")]
const _: () = assert!(
    std::mem::size_of::<EthtoolIfreq>() == 40,
    "EthtoolIfreq must be 40 bytes (sizeof(struct ifreq) on x86_64)",
);

impl EthtoolIfreq {
    fn new(ifname: &str, data: *mut libc::c_void) -> io::Result<Self> {
        let bytes = ifname.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid interface name {ifname:?}"),
            ));
        }
        let mut ifr_name = [0 as libc::c_char; libc::IFNAMSIZ];
        for (idx, b) in bytes.iter().enumerate() {
            ifr_name[idx] = *b as libc::c_char;
        }
        Ok(Self { ifr_name, ifru: EthtoolIfru { data } })
    }
}

/// The L3/L4 protocol family of a steered flow, mapped to the ethtool
/// `flow_type` + the per-family spec encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowProto {
    Tcp4,
    Udp4,
    Tcp6,
    Udp6,
}

/// An exact 5-tuple to steer. Addresses/ports are in NETWORK byte order
/// (matching the kernel `__be32`/`__be16` fields — same convention as the
/// rest of userspace-dp's wire-order session keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlowSpec5Tuple {
    pub proto: FlowProto,
    /// IPv4: only `[0]` is used. IPv6: all four words, network order.
    pub src_ip: [u32; 4],
    pub dst_ip: [u32; 4],
    pub src_port: u16, // network order
    pub dst_port: u16, // network order
}

/// A successfully opened ethtool socket bound to one interface. The
/// controller constructs ONE of these per steered interface only when the
/// rebalance knob is enabled (default-OFF builds construct zero sockets).
pub(crate) struct NtupleSocket {
    sock: i32,
    ifname: String,
}

impl Drop for NtupleSocket {
    fn drop(&mut self) {
        if self.sock >= 0 {
            // SAFETY: sock is a valid fd we own; close once.
            unsafe { libc::close(self.sock) };
        }
    }
}

impl AsRawFd for NtupleSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.sock
    }
}

impl NtupleSocket {
    /// Open an AF_INET/SOCK_DGRAM control socket for ethtool ioctls on
    /// `ifname`. Mirrors `slowpath.rs::set_if_up`.
    pub(crate) fn open(ifname: &str) -> io::Result<Self> {
        // SAFETY: standard socket(2) call.
        let sock = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
        };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { sock, ifname: ifname.to_string() })
    }

    fn ioctl(&self, rxnfc: &mut EthtoolRxnfc) -> io::Result<()> {
        let mut ifr = EthtoolIfreq::new(
            &self.ifname,
            rxnfc as *mut EthtoolRxnfc as *mut libc::c_void,
        )?;
        // SAFETY: ifr.ifru.data points at a valid, correctly-sized rxnfc; the
        // kernel reads/writes only within sizeof(ethtool_rxnfc).
        let rc = unsafe { libc::ioctl(self.sock, SIOCETHTOOL, &mut ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Insert an exact-5-tuple rule steering the flow to `queue`. Returns the
    /// rule location it was installed at. Structured errno: `ENOSPC` when the
    /// location space is full, `EOPNOTSUPP` on a NIC that does not support flow
    /// steering.
    ///
    /// #1751 live BLOCKER — mlx5 does NOT auto-assign a location for
    /// `RX_CLS_LOC_ANY`: `mlx5e_ethtool_flow_replace` validates
    /// `fs.location < MAX_NUM_OF_ETHTOOL_RULES` (= 1024) and rejects
    /// `RX_CLS_LOC_ANY` (0xFFFF_FFFF >= 1024) as "flow is not valid" → -ENOSPC
    /// (confirmed in dmesg). ethtool(8) does NOT pass ANY to the driver either:
    /// its userspace rule manager (rxclass.c `rmgr_*`) reads the used-location
    /// set and picks a CONCRETE free location top-down (from `size-1`), sets
    /// `fs.location` to it, THEN issues SRXCLSRLINS. We mirror that here.
    pub(crate) fn insert_rule(
        &self,
        flow: &FlowSpec5Tuple,
        queue: u32,
    ) -> io::Result<u32> {
        // Read the table size + the currently-used locations (matches
        // ethtool rmgr_init: GRXCLSRLCNT then GRXCLSRLALL).
        let (size, used) = self.table_size_and_used_locations()?;
        let loc = find_empty_slot_top_down(size, &used).ok_or_else(|| {
            io::Error::from_raw_os_error(libc::ENOSPC)
        })?;
        let mut rxnfc = EthtoolRxnfc {
            cmd: ETHTOOL_SRXCLSRLINS,
            ..EthtoolRxnfc::default()
        };
        rxnfc.fs = build_flow_spec(flow, queue);
        // Supply the CONCRETE location (NOT RX_CLS_LOC_ANY) — the whole fix.
        rxnfc.fs.location = loc;
        self.ioctl(&mut rxnfc)?;
        // On return fs.location is the actual rule location (== loc for a
        // concrete request; re-read to be exact).
        Ok(rxnfc.fs.location)
    }

    /// Delete the rule at `loc`. Idempotent at the caller level: an `ENOENT`
    /// from the kernel (rule already gone) is mapped to Ok so reconcile/
    /// teardown never wedges on a missing rule.
    pub(crate) fn delete_rule(&self, loc: u32) -> io::Result<()> {
        let mut rxnfc = EthtoolRxnfc {
            cmd: ETHTOOL_SRXCLSRLDEL,
            ..EthtoolRxnfc::default()
        };
        rxnfc.fs.location = loc;
        match self.ioctl(&mut rxnfc) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Return the count of currently-defined classification rules. On return
    /// `rule_cnt` is the live count and `data` is the table size with the
    /// `RX_CLS_LOC_SPECIAL` flag set iff the driver manages rule locations.
    /// Matches ethtool(8) `rxclass_get_dev_info` (cmd=GRXCLSRLCNT, data=0 in).
    pub(crate) fn rule_count(&self) -> io::Result<u32> {
        Ok(self.rule_count_and_driver_select()?.0)
    }

    /// `(rule_cnt, driver_select)`. `driver_select` is true when the NIC driver
    /// manages rule locations (auto-assign) — in which case the GRXCLSRLALL
    /// location-list scan must be skipped (ethtool does the same).
    fn rule_count_and_driver_select(&self) -> io::Result<(u32, bool)> {
        let mut rxnfc = EthtoolRxnfc {
            cmd: ETHTOOL_GRXCLSRLCNT,
            ..EthtoolRxnfc::default()
        };
        // ethtool sets data=0 before the call; default() already zeroes it.
        self.ioctl(&mut rxnfc)?;
        let driver_select = (rxnfc.data as u32 & RX_CLS_LOC_SPECIAL) != 0;
        Ok((rxnfc.rule_cnt, driver_select))
    }

    /// List the locations of all currently-defined rules via
    /// `ETHTOOL_GRXCLSRLALL`. Returns just the used-location vector.
    pub(crate) fn list_locs(&self) -> io::Result<Vec<u32>> {
        Ok(self.table_size_and_used_locations()?.1)
    }

    /// `(table_size, used_locations)` — the location-space depth and the set of
    /// currently-occupied locations, read EXACTLY as ethtool(8) `rmgr_init`
    /// (rxclass.c): GRXCLSRLCNT for the live count, then GRXCLSRLALL which
    /// returns `data` = the table size and `rule_locs[0..count]` = the used
    /// locations.
    ///
    /// #1751 live BLOCKER — this MUST work on mlx5 (the earlier "driver-select
    /// skip" was the WRONG fix: mlx5 is NOT driver-select for inserts, so the
    /// userspace rule manager NEEDS the used-location set to pick a free slot).
    /// The original GRXCLSRLALL EINVAL was a setup bug, not a driver signal;
    /// the buffer/rule_cnt layout below matches ethtool byte-for-byte.
    pub(crate) fn table_size_and_used_locations(&self) -> io::Result<(u32, Vec<u32>)> {
        // Step 1: GRXCLSRLCNT for the count (matches rxclass_get_dev_info).
        let count = self.rule_count_and_driver_select()?.0;

        // Step 2: GRXCLSRLALL. Buffer layout matches ethtool(8)
        // `rxclass_rule_getall`/`rmgr_init` EXACTLY: `calloc(1,
        // sizeof(ethtool_rxnfc) + count*sizeof(u32))`. The kernel
        // `ethtool_rxnfc_copy_to_user` does TWO writes: the full
        // `size`=sizeof(ethtool_rxnfc)=192-byte struct over [0,192), THEN the
        // `count` u32 locations starting at `offsetof(rule_locs)`=188 (they
        // overlap [188,192)). Sizing to `sizeof(EthtoolRxnfc) + count*4`
        // guarantees the 192-byte struct write never runs off the end for the
        // count==0/1 edge, byte-for-byte matching ethtool. We READ each
        // location back from offset 188 (#1748 #7), and `data` carries the
        // table size on return.
        let locs_off = offset_of!(EthtoolRxnfc, rule_locs);
        let total = size_of::<EthtoolRxnfc>() + (count as usize) * size_of::<u32>();
        let mut buf = vec![0u8; total];
        {
            // SAFETY: buf is at least sizeof(EthtoolRxnfc); we initialize the
            // header fields in place.
            let hdr = buf.as_mut_ptr() as *mut EthtoolRxnfc;
            unsafe {
                (*hdr).cmd = ETHTOOL_GRXCLSRLALL;
                (*hdr).flow_type = 0;
                (*hdr).data = 0;
                (*hdr).fs = EthtoolRxFlowSpec::default();
                (*hdr).rule_cnt = count;
            }
        }
        let mut ifr = EthtoolIfreq::new(
            &self.ifname,
            buf.as_mut_ptr() as *mut libc::c_void,
        )?;
        // SAFETY: the kernel writes the header back plus `rule_cnt` u32s into
        // the trailing buffer we sized for exactly that.
        let rc = unsafe { libc::ioctl(self.sock, SIOCETHTOOL, &mut ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // On return: `data` = table size, `rule_cnt` = number of valid locs.
        let (size, returned) = {
            // SAFETY: header is still valid POD in buf.
            let hdr = buf.as_ptr() as *const EthtoolRxnfc;
            let size = unsafe { (*hdr).data } as u32;
            let returned = unsafe { (*hdr).rule_cnt }.min(count) as usize;
            (size, returned)
        };
        let mut used = Vec::with_capacity(returned);
        for i in 0..returned {
            let off = locs_off + i * size_of::<u32>();
            let bytes: [u8; 4] = buf[off..off + 4].try_into().unwrap();
            used.push(u32::from_ne_bytes(bytes));
        }
        Ok((size, used))
    }

    /// #1748 AGY minor: startup orphan reconcile. A crashed/killed daemon
    /// leaves its installed ntuple rules in the NIC's hardware rule table (HW
    /// state is not torn down on SIGKILL). On controller construction we
    /// enumerate every existing rule on the interface and delete it, so a fresh
    /// run does not accumulate stale rules from a previous run and never trips
    /// the rule-table cap with dead entries.
    ///
    /// NOTE: this clears ALL flow-classification rules on the interface. On the
    /// userspace-dp dataplane these VFs are daemon-owned; flow-steering ntuple
    /// rules are not independently operator-managed there (see CLAUDE.md loss
    /// cluster topology). Returns the number of rules removed.
    pub(crate) fn reconcile_orphans(&self) -> io::Result<usize> {
        let locs = self.list_locs()?;
        let mut removed = 0usize;
        for loc in locs {
            // delete_rule maps ENOENT -> Ok, so a rule that vanished between
            // the list and the delete is not an error.
            self.delete_rule(loc)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Read back a single installed rule's flow spec via `ETHTOOL_GRXCLSRULE`.
    /// Test-only readback used by `live_insert_list_delete_round_trip` to
    /// assert the canonical inverted-mask encoding (#1748 review #1).
    #[cfg(test)]
    pub(crate) fn get_rule(&self, loc: u32) -> io::Result<EthtoolRxFlowSpec> {
        let mut rxnfc = EthtoolRxnfc {
            cmd: ETHTOOL_GRXCLSRULE,
            ..EthtoolRxnfc::default()
        };
        rxnfc.fs.location = loc;
        self.ioctl(&mut rxnfc)?;
        Ok(rxnfc.fs)
    }
}

/// Build the `ethtool_rx_flow_spec` for an exact 5-tuple.
///
/// MASK POLARITY (#1748 live BLOCKER A — the kernel/driver INPUT mask is
/// DIRECT, NOT inverted). The `m_u` mask passed INTO ETHTOOL_SRXCLSRLINS uses
/// 1-bits to mean "match this bit": the mlx5 driver copies `m_u` verbatim into
/// the hardware match criteria and only matches a field when its mask is
/// non-zero (`net/.../en_fs_ethtool.c set_ip4/set_tcp`: `if (ip4src_m) {...}`),
/// and `validate_tcpudp4` REJECTS a non-zero TOS mask with -EINVAL
/// (`if (l4_mask->tos) return -EINVAL`). So for an exact 5-tuple match:
///   - ip4src/ip4dst masks = 0xffff_ffff (match every address bit)
///   - psrc/pdst masks     = 0xffff      (match every port bit)
///   - tos/tclass mask     = 0           (MUST be 0 or the driver EINVALs)
///
/// A previous round set these the opposite way (tuple masks 0, tos 0xff) after
/// MISREADING `ethtool -n` READBACK output: ethtool(8) DISPLAYS the stored mask
/// inverted (it prints the complement, so a stored all-ones match shows as
/// "0.0.0.0"), but the value the kernel READS from user space is the direct
/// mask. That inverted setup made every SRXCLSRLINS fail with EINVAL (tos mask
/// 0xff) on the live mlx5 VF. The `lo` round-trip unit test did not exercise
/// the mlx5 validate path so it could not catch it.
///
/// #1751: ethtool-compatible free-location picker. Mirrors `rxclass.c`
/// `rmgr_find_empty_slot`: scan from the TOP of the location space
/// (`size - 1`) downward and return the first location NOT in `used`. Top-down
/// is ethtool's order (lowest priority first), which is why a manual
/// `ethtool -N` on the empty table lands at 1023. Returns `None` only when
/// every location in `[0, size)` is occupied (caller maps to ENOSPC).
///
/// `size == 0` (a driver that did not report a table size) falls back to the
/// mlx5 `MAX_NUM_OF_ETHTOOL_RULES` depth. The used set is tiny (bounded by the
/// controller's `max_rules`, default 16), so a linear scan is trivially cheap.
pub(crate) fn find_empty_slot_top_down(size: u32, used: &[u32]) -> Option<u32> {
    let size = if size == 0 { DEFAULT_RULE_TABLE_SIZE } else { size };
    // RX_CLS_LOC_SPECIAL flag bits never appear in a returned concrete
    // location, but mask defensively so a stray flag can't make a `used`
    // entry miss-compare against a candidate.
    let is_used = |loc: u32| used.iter().any(|&u| (u & !RX_CLS_LOC_SPECIAL) == loc);
    (0..size).rev().find(|&loc| !is_used(loc))
}

/// `ring_cookie` carries the destination RX queue (must be < num_channels, or
/// the driver EINVALs). `location` is left 0 here and set to a CONCRETE free
/// slot by `insert_rule` (#1751 — mlx5 does NOT auto-assign RX_CLS_LOC_ANY).
fn build_flow_spec(flow: &FlowSpec5Tuple, queue: u32) -> EthtoolRxFlowSpec {
    let mut fs = EthtoolRxFlowSpec {
        ring_cookie: queue as u64,
        location: 0,
        ..EthtoolRxFlowSpec::default()
    };
    match flow.proto {
        FlowProto::Tcp4 | FlowProto::Udp4 => {
            fs.flow_type = if flow.proto == FlowProto::Tcp4 {
                TCP_V4_FLOW
            } else {
                UDP_V4_FLOW
            };
            let spec = EthtoolTcpip4Spec {
                ip4src: flow.src_ip[0],
                ip4dst: flow.dst_ip[0],
                psrc: flow.src_port,
                pdst: flow.dst_port,
                tos: 0,
                _pad: [0; 3],
            };
            fs.h_u = EthtoolFlowUnion::from_tcpip4(spec);
            // Exact match: all addr/port mask bits set (1 = match), tos mask 0
            // (a non-zero tos mask makes the mlx5 driver return -EINVAL).
            let mask = EthtoolTcpip4Spec {
                ip4src: 0xffff_ffff,
                ip4dst: 0xffff_ffff,
                psrc: 0xffff,
                pdst: 0xffff,
                tos: 0,
                _pad: [0; 3],
            };
            fs.m_u = EthtoolFlowUnion::from_tcpip4(mask);
        }
        FlowProto::Tcp6 | FlowProto::Udp6 => {
            fs.flow_type = if flow.proto == FlowProto::Tcp6 {
                TCP_V6_FLOW
            } else {
                UDP_V6_FLOW
            };
            let spec = EthtoolTcpip6Spec {
                ip6src: flow.src_ip,
                ip6dst: flow.dst_ip,
                psrc: flow.src_port,
                pdst: flow.dst_port,
                tclass: 0,
                _pad: [0; 3],
            };
            fs.h_u = EthtoolFlowUnion::from_tcpip6(spec);
            // Exact match: all addr/port mask bits set, tclass mask 0.
            let mask = EthtoolTcpip6Spec {
                ip6src: [0xffff_ffff; 4],
                ip6dst: [0xffff_ffff; 4],
                psrc: 0xffff,
                pdst: 0xffff,
                tclass: 0,
                _pad: [0; 3],
            };
            fs.m_u = EthtoolFlowUnion::from_tcpip6(mask);
        }
    }
    fs
}

#[cfg(test)]
#[path = "ntuple_tests.rs"]
mod tests;
