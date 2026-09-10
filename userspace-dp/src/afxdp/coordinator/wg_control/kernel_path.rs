//! #9594: the posture a WireGuard control thread applies to a TRANSPORT record
//! that reached it through the kernel rather than through the AF_XDP worker.
//!
//! Only the STEERED listen port's thread gets here — #9521 already drops every
//! other port's kernel-path transport (`WgKernelTransport::DropUnsteered`). For
//! the steered port the kernel path has two causes, and they need opposite
//! answers:
//!
//!   * the record arrived on an ingress the XDP shim does NOT adjudicate (#8274's
//!     stated residual, `docs/log/8274.md`). The TUN write is the only path there,
//!     so it is delivered exactly as before;
//!   * the record arrived on an ingress the shim DOES adjudicate. A healthy shim
//!     claims every steered-port transport record addressed to the firewall for
//!     the worker (`wg_worker_claims_record`), so reaching the kernel there means
//!     the shim took one of its degraded arms — ctrl disabled at helper start / an
//!     RG transition / a reth link cycle, binding missing or not ready, heartbeat
//!     missing or stale — and passed the record up as "local". Writing its
//!     plaintext to the TUN handed inner TRANSIT to the kernel's open forward hook
//!     while every other transit packet was being dropped.
//!
//! For the second case the thread applies the shim's OWN degraded posture to the
//! decapsulated packet: an inner packet addressed to the firewall itself is
//! delivered (it then meets the nftables `hook input` chains, as native
//! host-inbound does in these windows), and inner transit is dropped and counted
//! (`rx_degraded_transit_drops`). A blanket drop would cut management over the VPN
//! during failovers for no security gain; delivering everything is the bypass.
//!
//! Both questions are answered from the shim's own pinned maps rather than a
//! second derivation in the helper: `userspace_ingress_ifaces` (the set
//! `try_xdp_userspace` adjudicates) and `userspace_local_v4/v6` minus
//! `userspace_interface_nat_v4/v6` (`is_local_destination`, which Go fills
//! including the VRRP VIPs it reads from the kernel — addresses the helper's
//! snapshot-derived `local_v4` does not carry).
//!
//! An ingress the thread cannot place — no pktinfo cmsg, or an ifindex that is
//! neither in the ingress set nor a configured interface (a VRF master, if the
//! kernel reports one) — is treated as covered: that fails closed for transit
//! only, and still delivers traffic addressed to the firewall.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a kernel-path record entered, relative to the shim's adjudicated set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WgKernelPathIngress {
    /// In `userspace_ingress_ifaces`: reaching the kernel here means degraded.
    Covered,
    /// A configured interface the shim does not adjudicate (#8274's residual).
    Uncovered,
    /// Cannot be placed; handled as `Covered`.
    Unknown,
}

/// What the steered port's thread does with an authenticated record's plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WgKernelPathDisposition {
    Deliver,
    DropDegradedTransit,
}

/// The two questions the posture asks, behind a seam so the control loop can be
/// driven without bpffs.
pub(crate) trait WgKernelPathView {
    fn ingress(&self, ifindex: Option<u32>) -> WgKernelPathIngress;
    /// The shim's `is_local_destination`: a local address that is not an
    /// interface-mode NAT address.
    fn destination_is_local(&self, dst: IpAddr) -> bool;
}

pub(crate) fn kernel_path_disposition(
    ingress: WgKernelPathIngress,
    inner_is_local: bool,
) -> WgKernelPathDisposition {
    match ingress {
        WgKernelPathIngress::Uncovered => WgKernelPathDisposition::Deliver,
        WgKernelPathIngress::Covered | WgKernelPathIngress::Unknown => {
            if inner_is_local {
                WgKernelPathDisposition::Deliver
            } else {
                WgKernelPathDisposition::DropDegradedTransit
            }
        }
    }
}

/// The inner packet's destination, or `None` when it is not a parseable IPv4 or
/// IPv6 header — which the posture treats as not local (fail closed).
pub(crate) fn inner_destination(inner: &[u8]) -> Option<IpAddr> {
    match inner.first().map(|b| b >> 4) {
        Some(4) if inner.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            inner[16], inner[17], inner[18], inner[19],
        ))),
        Some(6) if inner.len() >= 40 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&inner[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

/// `in_ingress_set` is `None` when the shim's ingress set could not be read at
/// all — then nothing is known to be adjudicated, which is the uncovered case
/// (and `ShimMapsKernelPathView` says so once, loudly).
pub(crate) fn classify_ingress(
    ifindex: Option<u32>,
    in_ingress_set: Option<bool>,
    known_interface: bool,
) -> WgKernelPathIngress {
    if ifindex.is_none() {
        return WgKernelPathIngress::Unknown;
    }
    match in_ingress_set {
        None => WgKernelPathIngress::Uncovered,
        Some(true) => WgKernelPathIngress::Covered,
        Some(false) if known_interface => WgKernelPathIngress::Uncovered,
        Some(false) => WgKernelPathIngress::Unknown,
    }
}

/// The shim's `userspace_local_v4` / `userspace_interface_nat_v4` key:
/// `u32::from_ne_bytes` of the address octets (userspace-xdp `parse_ipv4`), which
/// is also what Go's native-endian map encoding writes.
pub(crate) fn shim_v4_key(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

/// The shim's `is_local_destination` rule on its two lookups: an interface-mode
/// NAT address is NOT local (its traffic takes the SNAT listener's worker path),
/// otherwise presence in the local map decides. One function so the bpffs view
/// and the test seam cannot disagree about the rule.
pub(crate) fn shim_is_local_destination(in_interface_nat: bool, in_local: bool) -> bool {
    !in_interface_nat && in_local
}

const INGRESS_IFACES_PIN: &str = "/sys/fs/bpf/xpf/userspace_ingress_ifaces";
const LOCAL_V4_PIN: &str = "/sys/fs/bpf/xpf/userspace_local_v4";
const LOCAL_V6_PIN: &str = "/sys/fs/bpf/xpf/userspace_local_v6";
const INTERFACE_NAT_V4_PIN: &str = "/sys/fs/bpf/xpf/userspace_interface_nat_v4";
const INTERFACE_NAT_V6_PIN: &str = "/sys/fs/bpf/xpf/userspace_interface_nat_v6";
const REOPEN_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

struct ShimMaps {
    ingress: crate::afxdp::bpf_map::OwnedFd,
    local_v4: crate::afxdp::bpf_map::OwnedFd,
    local_v6: crate::afxdp::bpf_map::OwnedFd,
    nat_v4: crate::afxdp::bpf_map::OwnedFd,
    nat_v6: crate::afxdp::bpf_map::OwnedFd,
}

impl ShimMaps {
    fn open() -> std::io::Result<Self> {
        use crate::afxdp::bpf_map::OwnedFd;
        Ok(Self {
            ingress: OwnedFd::open_bpf_map(INGRESS_IFACES_PIN)?,
            local_v4: OwnedFd::open_bpf_map(LOCAL_V4_PIN)?,
            local_v6: OwnedFd::open_bpf_map(LOCAL_V6_PIN)?,
            nat_v4: OwnedFd::open_bpf_map(INTERFACE_NAT_V4_PIN)?,
            nat_v6: OwnedFd::open_bpf_map(INTERFACE_NAT_V6_PIN)?,
        })
    }
}

/// `bpf_map_lookup_elem` into a one-byte value. `Ok(None)` is ENOENT.
fn lookup_u8<K>(fd: libc::c_int, key: &K) -> std::io::Result<Option<u8>> {
    let mut value = 0u8;
    // SAFETY: `key` points at a live K whose layout is the map's key layout
    // (u32 / [u8; 16]); `value` is a writable byte, the maps' value size.
    let rc = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            fd,
            key as *const K as *const libc::c_void,
            &mut value as *mut u8 as *mut libc::c_void,
        )
    };
    if rc == 0 {
        return Ok(Some(value));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(err)
    }
}

/// #9594 test seam: per-tunnel stand-ins for the shim's maps, consulted by
/// `ShimMapsKernelPathView` BEFORE bpffs. Keyed by tunnel name like
/// `TEST_WG_TUN_STANDINS`, so a cell configuring one tunnel cannot change what
/// another test's control thread sees.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestShimMaps9594 {
    pub(crate) ingress: std::collections::HashSet<u32>,
    pub(crate) local: std::collections::HashSet<IpAddr>,
    pub(crate) interface_nat: std::collections::HashSet<IpAddr>,
}

#[cfg(test)]
pub(crate) static TEST_SHIM_MAPS_9594: std::sync::Mutex<Vec<(String, TestShimMaps9594)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn test_shim_maps_9594(tunnel_name: &str) -> Option<TestShimMaps9594> {
    TEST_SHIM_MAPS_9594
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(name, _)| name == tunnel_name)
        .map(|(_, maps)| maps.clone())
}

/// The production view: the shim's pinned maps for coverage and locality, and
/// the runtime forwarding state for "is this a configured interface".
pub(crate) struct ShimMapsKernelPathView {
    tunnel_name: String,
    runtime: crate::afxdp::types::RuntimeViewReader,
    maps: std::cell::RefCell<Option<ShimMaps>>,
    last_open_attempt: std::cell::Cell<Option<std::time::Instant>>,
    warned_unreadable: std::cell::Cell<bool>,
}

impl ShimMapsKernelPathView {
    pub(crate) fn new(
        tunnel_name: String,
        runtime: crate::afxdp::types::RuntimeViewReader,
    ) -> Self {
        Self {
            tunnel_name,
            runtime,
            maps: std::cell::RefCell::new(None),
            last_open_attempt: std::cell::Cell::new(None),
            warned_unreadable: std::cell::Cell::new(false),
        }
    }

    fn with_maps<R>(&self, f: impl FnOnce(&ShimMaps) -> R) -> Option<R> {
        if self.maps.borrow().is_none() {
            let now = std::time::Instant::now();
            let due = self
                .last_open_attempt
                .get()
                .is_none_or(|at| now.duration_since(at) >= REOPEN_BACKOFF);
            if due {
                self.last_open_attempt.set(Some(now));
                match ShimMaps::open() {
                    Ok(maps) => *self.maps.borrow_mut() = Some(maps),
                    Err(err) => {
                        if !self.warned_unreadable.replace(true) {
                            eprintln!(
                                "xpf-wg: tun={} cannot read the XDP shim's ingress/local maps ({err}): \
                                 kernel-path transport is treated as arriving on an UNCOVERED ingress, \
                                 so the degraded-mode transit refusal (#9594) is INACTIVE until they open",
                                self.tunnel_name
                            );
                        }
                    }
                }
            }
        }
        self.maps.borrow().as_ref().map(f)
    }

    fn known_interface(&self, ifindex: u32) -> bool {
        i32::try_from(ifindex).is_ok_and(|i| {
            self.runtime
                .load()
                .forwarding()
                .ifindex_to_name
                .contains_key(&i)
        })
    }
}

impl WgKernelPathView for ShimMapsKernelPathView {
    fn ingress(&self, ifindex: Option<u32>) -> WgKernelPathIngress {
        let Some(idx) = ifindex else {
            return WgKernelPathIngress::Unknown;
        };
        #[cfg(test)]
        if let Some(maps) = test_shim_maps_9594(&self.tunnel_name) {
            return classify_ingress(ifindex, Some(maps.ingress.contains(&idx)), self.known_interface(idx));
        }
        let in_set = self
            .with_maps(|maps| lookup_u8(maps.ingress.fd, &idx))
            .map(|res| match res {
                Ok(value) => Some(value.is_some_and(|v| v != 0)),
                // A read error on an open map is not "not covered": fail closed.
                Err(_) => Some(true),
            })
            .flatten();
        classify_ingress(ifindex, in_set, self.known_interface(idx))
    }

    fn destination_is_local(&self, dst: IpAddr) -> bool {
        #[cfg(test)]
        if let Some(maps) = test_shim_maps_9594(&self.tunnel_name) {
            return shim_is_local_destination(
                maps.interface_nat.contains(&dst),
                maps.local.contains(&dst),
            );
        }
        self.with_maps(|maps| match dst {
            IpAddr::V4(v4) => {
                let key = shim_v4_key(v4);
                // A read error counts as "NAT" and as "not local": fail closed.
                shim_is_local_destination(
                    !matches!(lookup_u8(maps.nat_v4.fd, &key), Ok(None)),
                    matches!(lookup_u8(maps.local_v4.fd, &key), Ok(Some(_))),
                )
            }
            IpAddr::V6(v6) => {
                let key = v6.octets();
                shim_is_local_destination(
                    !matches!(lookup_u8(maps.nat_v6.fd, &key), Ok(None)),
                    matches!(lookup_u8(maps.local_v6.fd, &key), Ok(Some(_))),
                )
            }
        })
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_mirrors_the_shims_degraded_posture_9594() {
        use WgKernelPathDisposition::*;
        use WgKernelPathIngress::*;
        assert_eq!(kernel_path_disposition(Uncovered, false), Deliver, "#8274 residual: delivered");
        assert_eq!(kernel_path_disposition(Uncovered, true), Deliver);
        assert_eq!(kernel_path_disposition(Covered, false), DropDegradedTransit, "degraded transit");
        assert_eq!(kernel_path_disposition(Covered, true), Deliver, "degraded host-inbound");
        assert_eq!(kernel_path_disposition(Unknown, false), DropDegradedTransit, "fail closed");
        assert_eq!(kernel_path_disposition(Unknown, true), Deliver);
    }

    #[test]
    fn ingress_classification_9594() {
        use WgKernelPathIngress::*;
        assert_eq!(classify_ingress(None, Some(false), true), Unknown, "no pktinfo");
        assert_eq!(classify_ingress(Some(12), Some(true), true), Covered);
        assert_eq!(classify_ingress(Some(12), Some(true), false), Covered);
        assert_eq!(classify_ingress(Some(3), Some(false), true), Uncovered, "configured, not adjudicated");
        assert_eq!(classify_ingress(Some(99), Some(false), false), Unknown, "unplaceable");
        assert_eq!(classify_ingress(Some(3), None, false), Uncovered, "no shim set: nothing covered");
    }

    #[test]
    fn inner_destination_parses_both_families_and_refuses_short_headers_9594() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[16..20].copy_from_slice(&[203, 0, 113, 9]);
        assert_eq!(inner_destination(&v4), Some("203.0.113.9".parse().unwrap()));
        assert_eq!(inner_destination(&v4[..19]), None);
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[24..40].copy_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(inner_destination(&v6), Some("2001:db8::9".parse().unwrap()));
        assert_eq!(inner_destination(&v6[..39]), None);
        assert_eq!(inner_destination(&[0x10, 0, 0, 0]), None);
    }

    #[test]
    fn locality_excludes_interface_nat_like_the_shim_9594() {
        assert!(shim_is_local_destination(false, true), "a local address is local");
        assert!(
            !shim_is_local_destination(true, true),
            "an interface-mode NAT address is NOT local (userspace-xdp is_local_destination): \
             its records belong to the SNAT listener's worker path"
        );
        assert!(!shim_is_local_destination(false, false), "an unknown address is transit");
        assert!(!shim_is_local_destination(true, false));
    }

    #[test]
    fn v4_key_matches_the_shims_native_endian_parse_9594() {
        // userspace-xdp parse_ipv4: `u32::from_ne_bytes([iph[16], iph[17], iph[18], iph[19]])`.
        let addr = Ipv4Addr::new(172, 16, 80, 8);
        let iph_dst = [172u8, 16, 80, 8];
        assert_eq!(shim_v4_key(addr), u32::from_ne_bytes(iph_dst));
    }
}

/// #9594 test-only view: every ingress is uncovered, nothing is local — the
/// pre-#9594 behavior, used by `run_wg_control_loop`'s test wrapper so the older
/// loop cells keep observing what they were written against.
#[cfg(test)]
pub(crate) struct UncoveredKernelPathView;

#[cfg(test)]
impl WgKernelPathView for UncoveredKernelPathView {
    fn ingress(&self, _ifindex: Option<u32>) -> WgKernelPathIngress {
        WgKernelPathIngress::Uncovered
    }
    fn destination_is_local(&self, _dst: IpAddr) -> bool {
        false
    }
}
