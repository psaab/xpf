//! #9594: the posture a WireGuard control thread applies to a TRANSPORT record
//! that reached it through the kernel rather than through the AF_XDP worker.
//!
//! Only a STEERED port's thread gets here — #9521 already drops every
//! other port's kernel-path transport (`WgKernelTransport::DropUnsteered`,
//! set-valued since #9587). For a steered port the kernel path has two
//! causes, and both get the SAME local-vs-transit posture:
//!
//!   * the record arrived on an ingress the XDP shim does NOT adjudicate (#8274's
//!     stated residual, `docs/log/8274.md`, tightened for transit by #10527);
//!   * the record arrived on an ingress the shim DOES adjudicate. A healthy shim
//!     claims every steered-port transport record addressed to the firewall for
//!     the worker (`wg_worker_claims_record`), so reaching the kernel there means
//!     the shim took one of its degraded arms — ctrl disabled at helper start / an
//!     RG transition / a reth link cycle, binding missing or not ready, heartbeat
//!     missing or stale — and passed the record up as "local".
//!
//! In BOTH cases the thread applies the shim's OWN degraded posture to the
//! decapsulated packet: an inner packet addressed to the firewall itself is
//! delivered (it then meets the nftables `hook input` chains, as native
//! host-inbound does in these windows), and inner transit is dropped and counted
//! (`rx_degraded_transit_drops`). A blanket drop would cut management over the VPN
//! during failovers for no security gain. The transit refusal is defense-in-depth
//! with the armed forward fence (#10302), not a bypass closure: the wgN TUN is
//! never a fence pinhole — only tracked XDP links and the marked xpf-usp1 queue
//! are — so TUN-written transit would die at the forward hook anyway. Refusing it
//! here attributes and counts the drop to the tunnel instead of leaving it to the
//! fence. (#9594's "delivering everything is the bypass" predates the fence;
//! #10527 was graded against that open-hook wording — #10642.)
//!
//! Both questions are answered from the shim's own pinned maps rather than a
//! second derivation in the helper: `userspace_ingress_ifaces` (bit 0 marks the
//! set `try_xdp_userspace` adjudicates; bit 1 carries tagged-only VID-0 scope)
//! and `userspace_local_v4/v6` minus
//! `userspace_interface_nat_v4_domain`/`_v6_domain` (`is_local_destination`, which Go fills
//! including the VRRP VIPs it reads from the kernel — addresses the helper's
//! snapshot-derived `local_v4` does not carry).
//!
//! #14328: coverage and locality are DIFFERENT questions keyed on DIFFERENT
//! interfaces. Coverage asks where the OUTER datagram arrived, so it is keyed
//! on the outer socket's pktinfo `ingress_ifindex`. Locality asks whether the
//! INNER plaintext destination is firewall-local in the routing domain the
//! decapsulated packet enters, so it is keyed on the `wgN` tunnel's logical
//! ifindex (`spawned_logical_ifindex`) — never the outer ifindex. The two
//! interfaces routinely live in different routing instances (outer underlay in
//! the default instance, tunnel in a tenant instance), and conflating them
//! both drops genuinely-local host-inbound in the tunnel's domain and
//! misclassifies transit that merely coincides with an underlay-local address.
//! A no-pktinfo ingress is therefore unknown for COVERAGE and still gets the
//! same local-vs-transit disposition, because locality no longer depends on
//! the outer ifindex at all. A configured ingress whose shim map cannot be
//! read is classified as uncovered; if locality is unreadable too, the destination
//! lookup returns false and the packet fails closed rather than being written.

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
    /// The shim's `is_local_destination` for the INNER destination, resolved
    /// in the tunnel's routing domain (the second argument is the `wgN`
    /// logical ifindex, NOT the outer ingress ifindex). See the module doc.
    fn destination_is_local(&self, dst: IpAddr, tunnel_logical_ifindex: i32) -> bool;
}

/// #14328: resolve the LOCALITY domain for one inner destination: the routing
/// domain of the `wgN` tunnel's logical ifindex. The OUTER ingress ifindex is
/// never consulted: it names the underlay the ciphertext arrived on, not the
/// instance the plaintext enters.
///
/// Two sources, in a deliberate order. When `ingress_domains` carries a row
/// for the tunnel's logical ifindex, that row wins: it is the shim's own
/// per-ifindex domain (Go's `localAddressRoutingDomain`), and a row present
/// for the tunnel is an explicit statement about THIS interface. Otherwise
/// the runtime forwarding state answers (`synced_routing_domain_in` — the
/// tunnel row's `routing_domain`, the resolver the TUN-origin builder uses).
/// The map-first order is what makes the test seam able to state a tunnel
/// domain without a full forwarding fixture: the seam has no tunnel row in
/// the (default, single-instance) forwarding state, and asking forwarding
/// first would silently collapse every test domain to 0.
///
/// Production caveat: Go fills `ingress_domains` per ingress-adjudicated
/// ifindex and excludes tunnel interfaces from the adjudicated set, so a
/// production `wgN` row is normally ABSENT and the forwarding state is the
/// production authority — it carries the tunnel row's `routing_domain` for
/// every interface, tunnels included. The test seam is the one place a map
/// row for a tunnel ifindex exists.
pub(crate) fn tunnel_routing_domain(
    forwarding: &crate::afxdp::ForwardingState,
    tunnel_logical_ifindex: i32,
    ingress_domains: &std::collections::HashMap<u32, u32>,
) -> Option<u32> {
    if let Ok(idx) = u32::try_from(tunnel_logical_ifindex) {
        if let Some(domain) = ingress_domains.get(&idx) {
            return Some(*domain);
        }
    }
    crate::afxdp::coordinator::synced_routing_domain_in(forwarding, tunnel_logical_ifindex, 0)
}

pub(crate) fn kernel_path_disposition(
    ingress: WgKernelPathIngress,
    inner_is_local: bool,
) -> WgKernelPathDisposition {
    match ingress {
        WgKernelPathIngress::Uncovered
        | WgKernelPathIngress::Covered
        | WgKernelPathIngress::Unknown => {
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

/// The shim's `userspace_local_v4_domain` / `userspace_interface_nat_v4_domain` key:
/// `u32::from_be_bytes` of the address octets (#14323 — userspace-xdp
/// `parse_ipv4` / `ipv4_key`, matching Go's `binary.BigEndian.Uint32`
/// map writer). The pre-#14323 `from_ne_bytes` byte-reversed every
/// non-palindromic address on little-endian hosts.
pub(crate) fn shim_v4_key(addr: Ipv4Addr) -> u32 {
    u32::from_be_bytes(addr.octets())
}
#[repr(C)]
#[derive(Clone, Copy)]
struct ShimLocalV4Key {
    domain: u32,
    addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ShimLocalV6Key {
    domain: u32,
    addr: [u8; 16],
}

type ShimInterfaceNatV4Key = ShimLocalV4Key;
type ShimInterfaceNatV6Key = ShimLocalV6Key;

/// The shim's `is_local_destination` rule on its two lookups: an interface-mode
/// NAT address is NOT local (its traffic takes the SNAT listener's worker path),
/// otherwise presence in the local map decides. One function so the bpffs view
/// and the test seam cannot disagree about the rule.
pub(crate) fn shim_is_local_destination(in_interface_nat: bool, in_local: bool) -> bool {
    !in_interface_nat && in_local
}

const INGRESS_IFACES_PIN: &str = "/sys/fs/bpf/xpf/userspace_ingress_ifaces";
const INGRESS_DOMAINS_PIN: &str = "/sys/fs/bpf/xpf/userspace_ingress_domains";
const INGRESS_IFACE_FLAG_ADJUDICATED: u8 = 1;
const LOCAL_V4_PIN: &str = "/sys/fs/bpf/xpf/userspace_local_v4_domain";
const LOCAL_V6_PIN: &str = "/sys/fs/bpf/xpf/userspace_local_v6_domain";
const INTERFACE_NAT_V4_PIN: &str = "/sys/fs/bpf/xpf/userspace_interface_nat_v4_domain";
const INTERFACE_NAT_V6_PIN: &str = "/sys/fs/bpf/xpf/userspace_interface_nat_v6_domain";
const REOPEN_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
struct ShimMaps {
    ingress: crate::afxdp::bpf_map::OwnedFd,
    ingress_domains: crate::afxdp::bpf_map::OwnedFd,
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
            ingress_domains: OwnedFd::open_bpf_map(INGRESS_DOMAINS_PIN)?,
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
fn lookup_u32<K>(fd: libc::c_int, key: &K) -> std::io::Result<Option<u32>> {
    let mut value = 0u32;
    let rc = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            fd,
            key as *const K as *const libc::c_void,
            &mut value as *mut u32 as *mut libc::c_void,
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
///
/// #14323: `local` / `interface_nat` store the ENCODED map keys
/// (`shim_v4_key` for IPv4, octets for IPv6), not `IpAddr` — so a cell
/// populates them through `insert_local` / `insert_interface_nat`, which
/// route through the production encoding, and the test branch of
/// `destination_is_local` probes with the same encoded keys as the bpffs
/// branch. Storing `IpAddr` bypassed `shim_v4_key` entirely, so the seam
/// could not catch an endian regression.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct TestShimMaps9594 {
    pub(crate) ingress: std::collections::HashSet<u32>,
    pub(crate) local_v4: std::collections::HashSet<(u32, u32)>,
    pub(crate) local_v6: std::collections::HashSet<(u32, [u8; 16])>,
    pub(crate) interface_nat_v4: std::collections::HashSet<(u32, u32)>,
    pub(crate) interface_nat_v6: std::collections::HashSet<(u32, [u8; 16])>,
    pub(crate) ingress_domains: std::collections::HashMap<u32, u32>,
}

#[cfg(test)]
impl TestShimMaps9594 {
    pub(crate) fn insert_local(&mut self, domain: u32, dst: IpAddr) {
        match dst {
            IpAddr::V4(v4) => {
                self.local_v4.insert((domain, shim_v4_key(v4)));
            }
            IpAddr::V6(v6) => {
                self.local_v6.insert((domain, v6.octets()));
            }
        }
    }

    pub(crate) fn insert_interface_nat(&mut self, domain: u32, dst: IpAddr) {
        match dst {
            IpAddr::V4(v4) => {
                self.interface_nat_v4.insert((domain, shim_v4_key(v4)));
            }
            IpAddr::V6(v6) => {
                self.interface_nat_v6.insert((domain, v6.octets()));
            }
        }
    }
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
/// the runtime forwarding state for "is this a configured interface" and for
/// the tunnel's routing domain (#14328).
pub(crate) struct ShimMapsKernelPathView {
    tunnel_name: String,
    /// #14328: the `wgN` logical ifindex this tunnel was spawned with. The
    /// locality question is resolved in THIS interface's routing domain; the
    /// outer pktinfo ifindex only ever feeds `ingress`.
    tunnel_logical_ifindex: i32,
    runtime: crate::afxdp::types::RuntimeViewReader,
    maps: std::cell::RefCell<Option<ShimMaps>>,
    last_open_attempt: std::cell::Cell<Option<std::time::Instant>>,
    warned_unreadable: std::cell::Cell<bool>,
}

impl ShimMapsKernelPathView {
    pub(crate) fn new(
        tunnel_name: String,
        tunnel_logical_ifindex: i32,
        runtime: crate::afxdp::types::RuntimeViewReader,
    ) -> Self {
        Self {
            tunnel_name,
            tunnel_logical_ifindex,
            runtime,
            maps: std::cell::RefCell::new(None),
            last_open_attempt: std::cell::Cell::new(None),
            warned_unreadable: std::cell::Cell::new(false),
        }
    }

    /// #14328: the tunnel's routing domain from the published runtime view.
    /// `None` when the tunnel ifindex is non-positive (no logical identity to
    /// resolve) or, with routing instances configured, names no interface —
    /// the locality lookup then fails closed.
    fn tunnel_domain(&self) -> Option<u32> {
        if self.tunnel_logical_ifindex <= 0 {
            return None;
        }
        crate::afxdp::coordinator::synced_routing_domain_in(
            self.runtime.load().forwarding(),
            self.tunnel_logical_ifindex,
            0,
        )
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
                                 transit and unreadable-locality traffic fail closed (#10527)",
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
                Ok(value) => {
                    Some(value.is_some_and(|flags| flags & INGRESS_IFACE_FLAG_ADJUDICATED != 0))
                }
                // A read error on an open map is not "not covered": fail closed.
                Err(_) => Some(true),
            })
            .flatten();
        classify_ingress(ifindex, in_set, self.known_interface(idx))
    }

    fn destination_is_local(&self, dst: IpAddr, tunnel_logical_ifindex: i32) -> bool {
        // #14328: locality is a property of the INNER packet in the TUNNEL's
        // routing domain. The outer ingress ifindex (which `ingress` above
        // consumes for coverage) is deliberately not a parameter any more:
        // keying the local map on it queried the underlay's domain for a
        // plaintext destination, and `None` (no pktinfo) short-circuited to
        // transit even for firewall-local inner destinations. The tunnel
        // ifindex is taken from the call argument (the production caller
        // passes the same `spawned_logical_ifindex` this view was built
        // with), so the seam can be driven for any tunnel identity.
        #[cfg(test)]
        if let Some(maps) = test_shim_maps_9594(&self.tunnel_name) {
            let forwarding = self.runtime.load().forwarding().clone();
            let Some(domain) =
                tunnel_routing_domain(&forwarding, tunnel_logical_ifindex, &maps.ingress_domains)
            else {
                return false;
            };
            // #14323: probe with the same encoded keys as the bpffs branch
            // below, so the seam exercises shim_v4_key.
            return match dst {
                IpAddr::V4(v4) => {
                    let key = shim_v4_key(v4);
                    shim_is_local_destination(
                        maps.interface_nat_v4.contains(&(domain, key)),
                        maps.local_v4.contains(&(domain, key)),
                    )
                }
                IpAddr::V6(v6) => {
                    let key = v6.octets();
                    shim_is_local_destination(
                        maps.interface_nat_v6.contains(&(domain, key)),
                        maps.local_v6.contains(&(domain, key)),
                    )
                }
            };
        }
        let Some(domain) = self.tunnel_domain() else {
            return false;
        };
        self.with_maps(|maps| match dst {
            IpAddr::V4(v4) => {
                let key = shim_v4_key(v4);
                let local_key = ShimLocalV4Key { domain, addr: key };
                let nat_key = ShimInterfaceNatV4Key { domain, addr: key };
                shim_is_local_destination(
                    !matches!(lookup_u8(maps.nat_v4.fd, &nat_key), Ok(None)),
                    matches!(lookup_u8(maps.local_v4.fd, &local_key), Ok(Some(_))),
                )
            }
            IpAddr::V6(v6) => {
                let key = v6.octets();
                let local_key = ShimLocalV6Key { domain, addr: key };
                let nat_key = ShimInterfaceNatV6Key { domain, addr: key };
                shim_is_local_destination(
                    !matches!(lookup_u8(maps.nat_v6.fd, &nat_key), Ok(None)),
                    matches!(lookup_u8(maps.local_v6.fd, &local_key), Ok(Some(_))),
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
        assert_eq!(
            kernel_path_disposition(Uncovered, false),
            DropDegradedTransit,
            "#10527: uncovered transit is refused, not #8274-delivered"
        );
        assert_eq!(
            kernel_path_disposition(Uncovered, true),
            Deliver,
            "#10527: uncovered host-inbound still delivered"
        );
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
    fn unparseable_inner_fails_closed_for_uncovered_transit_10527() {
        let truncated = [0x10, 0, 0, 0];
        assert_eq!(inner_destination(&truncated), None);
        assert_eq!(
            kernel_path_disposition(
                WgKernelPathIngress::Uncovered,
                inner_destination(&truncated).is_some()
            ),
            WgKernelPathDisposition::DropDegradedTransit,
            "an unreadable inner destination must not be treated as local"
        );
    }

    #[test]
    fn unreadable_ingress_map_fails_closed_for_uncovered_transit_10527() {
        let ingress = classify_ingress(Some(3), None, false);
        assert_eq!(ingress, WgKernelPathIngress::Uncovered);
        assert_eq!(
            kernel_path_disposition(ingress, false),
            WgKernelPathDisposition::DropDegradedTransit,
            "an unreadable shim ingress map must refuse transit"
        );
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
    fn v4_key_matches_the_shims_big_endian_parse_14323() {
        // #14323 decisive regression: userspace-xdp parse_ipv4 stores
        // dst_v4 as u32::from_be_bytes of the header octets, and Go writes
        // the maps with binary.BigEndian.Uint32. 172.16.80.8 is
        // non-palindromic, so from_ne_bytes (0x0850_10ac) cannot pass.
        let addr = Ipv4Addr::new(172, 16, 80, 8);
        assert_eq!(shim_v4_key(addr), 0xac10_5008);
        assert_eq!(shim_v4_key(addr), u32::from_be_bytes(addr.octets()));
        // Palindromic control: byte-reversal-invariant, passes either way.
        assert_eq!(
            shim_v4_key(Ipv4Addr::new(10, 1, 1, 10)),
            u32::from_be_bytes([10, 1, 1, 10])
        );
    }

    #[test]
    fn test_seam_destination_is_local_uses_encoded_keys_14323() {
        // #14323: the seam must route through shim_v4_key. A local entry
        // for the byte-REVERSED address (8.80.16.172) must not make the
        // real destination (172.16.80.8) local, and vice versa.
        let mut maps = TestShimMaps9594::default();
        maps.ingress_domains.insert(7, 0);
        maps.insert_local(0, IpAddr::V4(Ipv4Addr::new(8, 80, 16, 172)));
        let reversed_only = ShimMapsKernelPathView::new(
            "seam-14323-reversed".to_string(),
            7,
            crate::afxdp::types::RuntimeViewChannel::default().reader(),
        );
        TEST_SHIM_MAPS_9594
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(("seam-14323-reversed".to_string(), maps));
        assert!(
            !reversed_only.destination_is_local(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)), 7),
            "byte-reversed local entry must not claim the real destination (#14323)"
        );
        assert!(
            reversed_only.destination_is_local(IpAddr::V4(Ipv4Addr::new(8, 80, 16, 172)), 7),
            "the stored local address itself must still resolve"
        );
        TEST_SHIM_MAPS_9594
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(name, _)| name != "seam-14323-reversed");
    }
    #[test]
    fn tunnel_routing_domain_resolution_14328() {
        // Forwarding authority: the tunnel row's routing_domain in the
        // published forwarding state, when no map row names the tunnel.
        let mut forwarding = crate::afxdp::ForwardingState::default();
        forwarding.has_routing_domains = true;
        forwarding.ifindex_to_routing_domain.insert(20, 2);
        let empty = std::collections::HashMap::new();
        assert_eq!(tunnel_routing_domain(&forwarding, 20, &empty), Some(2));
        // Unclaimed tunnel ifindex with instances configured: the forwarding
        // resolver reads it as the default domain, matching its contract.
        assert_eq!(tunnel_routing_domain(&forwarding, 99, &empty), Some(0));
        // Non-positive logical ifindex cannot be placed -> fail closed.
        assert_eq!(tunnel_routing_domain(&forwarding, 0, &empty), None);
        assert_eq!(tunnel_routing_domain(&forwarding, -1, &empty), None);
        // Single-instance node: domain 0 is the only domain that exists.
        let single = crate::afxdp::ForwardingState::default();
        assert_eq!(tunnel_routing_domain(&single, 20, &empty), Some(0));
        // A map row for the tunnel's own ifindex wins over the forwarding
        // state: it is the shim's explicit per-ifindex statement (and the
        // only way the test seam can state a tunnel domain — the seam's
        // forwarding state is the single-instance default). Production
        // tunnel rows are absent from the map, so this precedence never
        // fires there.
        let mut domains = std::collections::HashMap::new();
        domains.insert(20u32, 7u32);
        assert_eq!(tunnel_routing_domain(&forwarding, 20, &domains), Some(7));
        assert_eq!(tunnel_routing_domain(&single, 20, &domains), Some(7));
    }

    #[test]
    fn locality_uses_tunnel_domain_not_outer_ingress_14328() {
        // #14328 decisive regression, in the exact shape the issue prescribes:
        // outer ifindex 10 in outer_domain 1, wg0 logical ifindex 20 in
        // inner_domain 2, local address 2001:db8::1 present ONLY in domain 2.
        // The pre-fix view keyed locality on the OUTER ifindex (and returned
        // false for None), so both assertions below failed on master.
        const OUTER: u32 = 10;
        const TUNNEL: i32 = 20;
        const OUTER_DOMAIN: u32 = 1;
        const INNER_DOMAIN: u32 = 2;
        let dst: IpAddr = "2001:db8::1".parse().unwrap();
        let transit_dst: IpAddr = "2001:db8::2".parse().unwrap();
        {
            let mut seam = TEST_SHIM_MAPS_9594
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            seam.retain(|(name, _)| name != "wgt14328");
            let mut maps = TestShimMaps9594::default();
            maps.ingress_domains.insert(OUTER, OUTER_DOMAIN);
            maps.ingress_domains.insert(TUNNEL as u32, INNER_DOMAIN);
            // Present only in the OUTER domain: a transit inner destination
            // that coincides with an underlay-local address.
            maps.insert_local(OUTER_DOMAIN, transit_dst);
            maps.insert_local(INNER_DOMAIN, dst);
            seam.push(("wgt14328".to_string(), maps));
        }
        let view = ShimMapsKernelPathView::new(
            "wgt14328".to_string(),
            TUNNEL,
            crate::afxdp::types::RuntimeViewChannel::default().reader(),
        );
        assert!(
            view.destination_is_local(dst, TUNNEL),
            "inner dst local in the TUNNEL domain must be local even though \
             the outer ingress ifindex lives in a different routing domain"
        );
        // No-pktinfo parity: locality no longer takes the outer ifindex at
        // all, so the Unknown/no-pktinfo disposition sees the same answer.
        // (The pre-fix `destination_is_local(dst, None) == false` made
        // `kernel_path_disposition(Unknown, true)` unreachable.)
        assert!(
            view.destination_is_local(dst, TUNNEL),
            "repeated lookup (the no-pktinfo path passes the same tunnel key) stays local"
        );
        assert_eq!(
            kernel_path_disposition(
                WgKernelPathIngress::Unknown,
                view.destination_is_local(dst, TUNNEL)
            ),
            WgKernelPathDisposition::Deliver,
            "no-pktinfo host-inbound in the tunnel domain is delivered, not dropped as transit"
        );
        // False-local direction: a destination local only in the OUTER
        // domain is transit in the tunnel's domain and must NOT be local.
        assert!(
            !view.destination_is_local(transit_dst, TUNNEL),
            "an address local only in the outer underlay domain is transit in the tunnel domain"
        );
        // Transit in both domains stays transit (fail-closed preserved).
        let nowhere: IpAddr = "2001:db8::99".parse().unwrap();
        assert!(!view.destination_is_local(nowhere, TUNNEL));
        // A tunnel ifindex that cannot be placed fails closed.
        assert!(!view.destination_is_local(dst, 0));
        assert!(!view.destination_is_local(dst, -1));
        TEST_SHIM_MAPS_9594
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(name, _)| name != "wgt14328");
    }
}

/// #9594 test-only view: every ingress is uncovered, and no destination is
/// local. It is used by the legacy transport cell, which now pins the
/// #10527 uncovered-transit refusal; dedicated local-delivery cells use a
/// fixed posture view with an explicit local destination.
#[cfg(test)]
pub(crate) struct UncoveredKernelPathView;

#[cfg(test)]
impl WgKernelPathView for UncoveredKernelPathView {
    fn ingress(&self, _ifindex: Option<u32>) -> WgKernelPathIngress {
        WgKernelPathIngress::Uncovered
    }
    fn destination_is_local(&self, _dst: IpAddr, _tunnel_logical_ifindex: i32) -> bool {
        false
    }
}
