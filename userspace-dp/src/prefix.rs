use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefixV4 {
    network: u32,
    mask: u32,
    prefix_len: u8,
}

impl PrefixV4 {
    pub(crate) fn from_net(net: Ipv4Net) -> Self {
        let prefix_len = net.prefix_len();
        let mask = mask_v4(prefix_len);
        Self {
            network: u32::from(net.addr()) & mask,
            mask,
            prefix_len,
        }
    }

    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub(crate) fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    /// The IPv4 subnet-directed broadcast address of this prefix: the
    /// network address with an all-ones host part (`network | !mask`).
    /// RFC 1812 §4.3.2.7 — a router MUST NOT originate an ICMP error to a
    /// directed broadcast. For /31 (RFC 3021 point-to-point, no broadcast)
    /// and /32 (`network | !mask` == the host itself) the host-all-ones
    /// value is not a real broadcast; callers guard those prefix lengths
    /// before comparing (see `dest_is_directed_broadcast`).
    pub(crate) fn directed_broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | !self.mask)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefixV6 {
    network: u128,
    mask: u128,
    prefix_len: u8,
}

impl PrefixV6 {
    pub(crate) fn from_net(net: Ipv6Net) -> Self {
        let prefix_len = net.prefix_len();
        let mask = mask_v6(prefix_len);
        Self {
            network: u128::from(net.addr()) & mask,
            mask,
            prefix_len,
        }
    }

    /// #17067: build directly from a network address and length without
    /// an `IpNet` detour. The mask is applied here so callers cannot
    /// install host bits.
    pub(crate) fn from_addr_len(addr: Ipv6Addr, prefix_len: u8) -> Self {
        debug_assert!(prefix_len <= 128);
        let mask = mask_v6(prefix_len);
        Self {
            network: u128::from(addr) & mask,
            mask,
            prefix_len,
        }
    }

    pub(crate) fn contains(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) & self.mask) == self.network
    }

    pub(crate) fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub(crate) fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.network)
    }
}

/// #16128: family-generic prefix membership for the filter term-walk and the
/// source-NAT rule match. One generic `nets_match` (below) serves both callers
/// only because `except` stays EXPLICIT at every call site: filter passes its
/// per-direction `*_except` flag, NAT passes `false`. The two empty-set
/// answers are therefore preserved, not merged — see `nets_match`.
pub(crate) trait AddrPrefix {
    type Addr: Copy;
    fn contains(&self, ip: Self::Addr) -> bool;
}

impl AddrPrefix for PrefixV4 {
    type Addr = Ipv4Addr;
    #[inline(always)]
    fn contains(&self, ip: Ipv4Addr) -> bool {
        PrefixV4::contains(self, ip)
    }
}

impl AddrPrefix for PrefixV6 {
    type Addr = Ipv6Addr;
    #[inline(always)]
    fn contains(&self, ip: Ipv6Addr) -> bool {
        PrefixV6::contains(self, ip)
    }
}

/// #16128: shared prefix-set membership with EXPLICIT `except`.
///
/// - `constrained == false`: match any address; `except` is irrelevant (no
///   scope to invert).
/// - `constrained == true` but `nets` empty: return `except`. Filter relies
///   on both arms (#2400/#2506): positive empty = match NOTHING (fail closed),
///   `except` empty = match ALL (Junos "not in {}", incl. the cross-family
///   case where the other family's vec is empty). Source NAT passes
///   `except == false` unconditionally, so its empty set stays fail-closed
///   (#2398) — never merged into the filter's match-all arm.
/// - otherwise: membership XOR `except`.
#[inline(always)]
pub(crate) fn nets_match<P: AddrPrefix>(
    constrained: bool,
    except: bool,
    nets: &[P],
    ip: P::Addr,
) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return except;
    }
    nets.iter().any(|net| net.contains(ip)) ^ except
}

const fn mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

const fn mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_v4_matches_expected_addresses() {
        let prefix = PrefixV4::from_net("10.0.61.0/24".parse().expect("prefix"));
        assert!(prefix.contains("10.0.61.100".parse().expect("match")));
        assert!(!prefix.contains("10.0.62.100".parse().expect("mismatch")));
        assert_eq!(prefix.prefix_len(), 24);
    }

    #[test]
    fn prefix_v6_matches_expected_addresses() {
        let prefix = PrefixV6::from_net("2001:559:8585:80::/64".parse().expect("prefix"));
        assert!(prefix.contains("2001:559:8585:80::200".parse().expect("match")));
        assert!(!prefix.contains("2001:559:8585:81::200".parse().expect("mismatch")));
        assert_eq!(prefix.prefix_len(), 64);
    }
}
