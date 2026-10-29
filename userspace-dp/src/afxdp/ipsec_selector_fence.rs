//! Shape-based fence for cleartext transit covered by policy-based IPsec selectors.
//!
//! AF_XDP TX bypasses kernel XFRM, and the snapshot does not carry SA state.
//! Selector coverage is therefore compiled once from the configured IP shapes
//! and enforced independently of whether charon currently has an SA.

use crate::nat::NatDecision;
use crate::policy::SnapshotIntegrityError;
use crate::protocol::ConfigSnapshot;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AddressRange {
    family: AddressFamily,
    start: u128,
    end: u128,
}

impl AddressRange {
    fn contains(self, address: IpAddr) -> bool {
        match (self.family, address) {
            (AddressFamily::V4, IpAddr::V4(ip)) => {
                let value = u32::from(ip) as u128;
                (self.start..=self.end).contains(&value)
            }
            (AddressFamily::V6, IpAddr::V6(ip)) => {
                let value = u128::from(ip);
                (self.start..=self.end).contains(&value)
            }
            _ => false,
        }
    }

    fn overlaps(self, other: AddressRange) -> bool {
        self.family == other.family && self.start <= other.end && other.start <= self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectorPair {
    local: AddressRange,
    remote: AddressRange,
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct BindlessIpsecSelectorFence {
    enabled: bool,
    rows: Vec<SelectorPair>,
}

impl BindlessIpsecSelectorFence {
    pub(in crate::afxdp) fn from_snapshot(
        snapshot: &ConfigSnapshot,
    ) -> Result<Self, SnapshotIntegrityError> {
        let enabled = snapshot.bindless_selector_fence_enabled;
        let rows = &snapshot.bindless_selector_rows;
        if enabled != !rows.is_empty() {
            return Err(SnapshotIntegrityError::BindlessSelectorFenceMarkerMismatch {
                enabled,
                rows: rows.len(),
            });
        }
        if !enabled {
            return Ok(Self::default());
        }

        let mut compiled = Vec::with_capacity(rows.len());
        for row in rows {
            let Some(local) = parse_address_range(&row.local_ts) else {
                return Err(SnapshotIntegrityError::InvalidBindlessSelector {
                    local_ts: row.local_ts.clone(),
                    remote_ts: row.remote_ts.clone(),
                });
            };
            let Some(remote) = parse_address_range(&row.remote_ts) else {
                return Err(SnapshotIntegrityError::InvalidBindlessSelector {
                    local_ts: row.local_ts.clone(),
                    remote_ts: row.remote_ts.clone(),
                });
            };
            compiled.push(SelectorPair { local, remote });
        }
        Ok(Self {
            enabled,
            rows: compiled,
        })
    }

    #[inline]
    pub(in crate::afxdp) fn matches(&self, source: IpAddr, destination: IpAddr) -> bool {
        self.enabled
            && self.rows.iter().any(|row| {
                (row.local.contains(source) && row.remote.contains(destination))
                    || (row.remote.contains(source) && row.local.contains(destination))
            })
    }

    #[inline]
    pub(in crate::afxdp) fn matches_with_nat(
        &self,
        source: IpAddr,
        destination: IpAddr,
        nat: NatDecision,
    ) -> bool {
        let translated_source = nat.rewrite_src.unwrap_or(source);
        let translated_destination = nat.rewrite_dst.unwrap_or(destination);
        self.matches(source, destination)
            || self.matches(translated_source, translated_destination)
            || self.matches(source, translated_destination)
            || self.matches(translated_source, destination)
    }

    #[inline]
    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        !self.enabled || self.rows.is_empty()
    }

    /// #16537: O(selector rows) pool fence check without enumerating pool
    /// addresses. `pool_ranges` are the contiguous (start, end) spans of a
    /// source-NAT pool (or NAT64 pool); `base` is the pre-pool decision
    /// (DNAT/NPTv6-inbound dst rewrite). Returns true iff
    /// `matches_with_nat(source, destination, base.merge(candidate))`
    /// would be true for base alone, for some pool candidate, or for the
    /// cross terms. Each candidate only sets `rewrite_src`, so the four
    /// fence terms collapse to: base alone; (pool_addr, dst'); (src,
    /// dst'); (pool_addr, dst) where dst' is the translated destination.
    pub(in crate::afxdp) fn matches_with_pool_ranges(
        &self,
        source: IpAddr,
        destination: IpAddr,
        base: NatDecision,
        pool_ranges_v4: &[(std::net::Ipv4Addr, std::net::Ipv4Addr)],
        pool_ranges_v6: &[(std::net::Ipv6Addr, std::net::Ipv6Addr)],
    ) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.matches_with_nat(source, destination, base) {
            return true;
        }
        if pool_ranges_v4.is_empty() && pool_ranges_v6.is_empty() {
            return false;
        }
        let translated_destination = base.rewrite_dst.unwrap_or(destination);
        self.rows.iter().any(|row| {
            let pool_hits = |pool: AddressRange| {
                (row.local.overlaps(pool) && row.remote.contains(translated_destination))
                    || (row.remote.overlaps(pool) && row.local.contains(translated_destination))
                    || (row.local.overlaps(pool) && row.remote.contains(destination))
                    || (row.remote.overlaps(pool) && row.local.contains(destination))
            };
            pool_ranges_v4.iter().any(|&(start, end)| {
                pool_hits(AddressRange {
                    family: AddressFamily::V4,
                    start: u32::from(start) as u128,
                    end: u32::from(end) as u128,
                })
            }) || pool_ranges_v6.iter().any(|&(start, end)| {
                pool_hits(AddressRange {
                    family: AddressFamily::V6,
                    start: u128::from(start),
                    end: u128::from(end),
                })
            })
        })
    }
}

fn parse_address_range(value: &str) -> Option<AddressRange> {
    if let Some((start, end)) = value.split_once('-') {
        let start = parse_address(start)?;
        let end = parse_address(end)?;
        if start.family != end.family || start.start > end.start {
            return None;
        }
        return Some(AddressRange {
            family: start.family,
            start: start.start,
            end: end.start,
        });
    }

    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(address_range(address));
    }
    let network = value.parse::<IpNet>().ok()?;
    let address = network.addr();
    let prefix = network.prefix_len();
    let family = match address {
        IpAddr::V4(_) => AddressFamily::V4,
        IpAddr::V6(_) => AddressFamily::V6,
    };
    let (start, end) = match address {
        IpAddr::V4(ip) => {
            let width = 32u8;
            let mask = prefix_mask(width, prefix);
            let start = (u32::from(ip) & mask as u32) as u128;
            let host_mask = (u32::MAX as u128) ^ mask;
            (start, start | host_mask)
        }
        IpAddr::V6(ip) => {
            let mask = prefix_mask(128, prefix);
            let start = u128::from(ip) & mask;
            (start, start | !mask)
        }
    };
    Some(AddressRange { family, start, end })
}

fn prefix_mask(width: u8, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix == width {
        if width == 32 { u32::MAX as u128 } else { u128::MAX }
    } else if width == 32 {
        (u32::MAX << (width - prefix)) as u128
    } else {
        u128::MAX << (width - prefix)
    }
}

fn address_range(address: IpAddr) -> AddressRange {
    match address {
        IpAddr::V4(ip) => {
            let value = u32::from(ip) as u128;
            AddressRange {
                family: AddressFamily::V4,
                start: value,
                end: value,
            }
        }
        IpAddr::V6(ip) => {
            let value = u128::from(ip);
            AddressRange {
                family: AddressFamily::V6,
                start: value,
                end: value,
            }
        }
    }
}

fn parse_address(value: &str) -> Option<AddressRange> {
    value.parse::<IpAddr>().ok().map(address_range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::IpsecBindlessSelectorSnapshot;

    fn snapshot(enabled: bool, rows: Vec<IpsecBindlessSelectorSnapshot>) -> ConfigSnapshot {
        ConfigSnapshot {
            bindless_selector_fence_enabled: enabled,
            bindless_selector_rows: rows,
            ..ConfigSnapshot::default()
        }
    }

    fn row(local_ts: &str, remote_ts: &str) -> IpsecBindlessSelectorSnapshot {
        IpsecBindlessSelectorSnapshot {
            local_ts: local_ts.to_string(),
            remote_ts: remote_ts.to_string(),
        }
    }

    #[test]
    fn bindless_selector_fence_matches_prefixes_and_ranges_precisely() {
        let fence = BindlessIpsecSelectorFence::from_snapshot(&snapshot(
            true,
            vec![
                row("10.20.0.0/16", "198.51.100.10-198.51.100.20"),
                row("2001:db8:1::/48", "2001:db8:2::1"),
            ],
        ))
        .expect("valid selector snapshot");

        assert!(fence.matches(
            "10.20.4.5".parse().unwrap(),
            "198.51.100.15".parse().unwrap()
        ));
        assert!(fence.matches(
            "198.51.100.15".parse().unwrap(),
            "10.20.4.5".parse().unwrap()
        ));
        assert!(!fence.matches(
            "10.21.4.5".parse().unwrap(),
            "198.51.100.15".parse().unwrap()
        ));
        assert!(!fence.matches(
            "10.20.4.5".parse().unwrap(),
            "198.51.100.21".parse().unwrap()
        ));
        assert!(fence.matches(
            "2001:db8:1::5".parse().unwrap(),
            "2001:db8:2::1".parse().unwrap()
        ));
        assert!(!fence.matches(
            "2001:db8:1::5".parse().unwrap(),
            "2001:db8:2::2".parse().unwrap()
        ));
    }
    #[test]
    fn bindless_selector_snapshot_uses_go_wire_shape() {
        let snapshot = snapshot(
            true,
            vec![row("10.20.0.0/16", "198.51.100.0/24")],
        );
        let wire = serde_json::to_value(&snapshot).expect("serialize selector snapshot");
        assert_eq!(wire["bindless_selector_fence_enabled"], true);
        assert_eq!(
            wire["bindless_selector_rows"][0]["local_ts"],
            "10.20.0.0/16"
        );
        assert_eq!(
            wire["bindless_selector_rows"][0]["remote_ts"],
            "198.51.100.0/24"
        );

        let decoded: ConfigSnapshot =
            serde_json::from_value(wire).expect("decode selector snapshot");
        let fence = BindlessIpsecSelectorFence::from_snapshot(&decoded)
            .expect("compile decoded selector snapshot");
        assert!(fence.matches(
            "10.20.1.2".parse().unwrap(),
            "198.51.100.4".parse().unwrap()
        ));
    }


    #[test]
    fn bindless_selector_fence_stays_disabled_without_rows() {
        let fence = BindlessIpsecSelectorFence::from_snapshot(&snapshot(false, Vec::new()))
            .expect("disabled empty selector snapshot");
        assert!(!fence.matches(
            "10.20.4.5".parse().unwrap(),
            "198.51.100.15".parse().unwrap()
        ));
    }

    #[test]
    fn bindless_selector_fence_rejects_inconsistent_or_unparseable_rows() {
        assert!(matches!(
            BindlessIpsecSelectorFence::from_snapshot(&snapshot(false, vec![row(
                "10.20.0.0/16",
                "198.51.100.0/24"
            )])),
            Err(SnapshotIntegrityError::BindlessSelectorFenceMarkerMismatch { .. })
        ));
        assert!(matches!(
            BindlessIpsecSelectorFence::from_snapshot(&snapshot(
                true,
                vec![row("not-a-selector", "198.51.100.0/24")]
            )),
            Err(SnapshotIntegrityError::InvalidBindlessSelector { .. })
        ));
    }

    /// #12507: Go's `config.CIDRMaskHelperRefusesPadding` must name exactly
    /// the padded selectors this fence refuses: "/08" and "/032" compile, while
    /// "/008" and "/0032" fail the whole snapshot closed, which the Go
    /// snapshot stamp reports for a tolerantly loaded bind-less VPN.
    #[test]
    fn bindless_selector_padded_masks_match_go_refusal_predicate_12507() {
        let fence = BindlessIpsecSelectorFence::from_snapshot(&snapshot(
            true,
            vec![
                row("10.0.0.0/08", "192.0.2.0/24"),
                row("2001:db8:1::/048", "2001:db8:2::/032"),
            ],
        ))
        .expect("helper-supported padding must compile");
        assert!(fence.matches(
            "10.1.2.3".parse().unwrap(),
            "192.0.2.9".parse().unwrap()
        ));
        for (local, remote) in [
            ("10.0.0.0/008", "192.0.2.0/24"),
            ("2001:db8:1::/48", "2001:db8:2::/0032"),
        ] {
            assert!(
                matches!(
                    BindlessIpsecSelectorFence::from_snapshot(&snapshot(
                        true,
                        vec![row(local, remote)]
                    )),
                    Err(SnapshotIntegrityError::InvalidBindlessSelector { .. })
                ),
                "{local:?} -> {remote:?} must fail the snapshot closed"
            );
        }
    }

    #[test]
    fn bindless_selector_fence_matches_original_and_post_nat_tuples() {
        let fence = BindlessIpsecSelectorFence::from_snapshot(&snapshot(
            true,
            vec![row("203.0.113.7", "198.51.100.9")],
        ))
        .expect("valid selector snapshot");
        let nat = NatDecision {
            rewrite_src: Some("203.0.113.7".parse().unwrap()),
            rewrite_dst: None,
            ..NatDecision::default()
        };
        assert!(fence.matches_with_nat(
            "10.0.0.7".parse().unwrap(),
            "198.51.100.9".parse().unwrap(),
            nat
        ));
    }

    #[test]
    fn pool_range_fence_detects_interior_and_last_pool_addresses_16537() {
        let fence = BindlessIpsecSelectorFence::from_snapshot(&snapshot(
            true,
            vec![row("9.9.9.0/24", "203.0.113.11/32")],
        ))
        .expect("valid selector snapshot");
        let src: IpAddr = "10.0.0.7".parse().unwrap();
        let dst: IpAddr = "9.9.9.9".parse().unwrap();
        let ranges = [(
            "203.0.113.10".parse().unwrap(),
            "203.0.113.11".parse().unwrap(),
        )];
        assert!(fence.matches_with_pool_ranges(src, dst, NatDecision::default(), &ranges, &[]));
        let disjoint = [(
            "203.0.113.20".parse().unwrap(),
            "203.0.113.21".parse().unwrap(),
        )];
        assert!(!fence.matches_with_pool_ranges(src, dst, NatDecision::default(), &disjoint, &[]));
        assert!(!fence.matches_with_pool_ranges(src, "8.8.8.8".parse().unwrap(), NatDecision::default(), &ranges, &[]));
    }

    #[test]
    fn pool_range_fence_empty_fence_and_base_hit_16537() {
        let empty = BindlessIpsecSelectorFence::from_snapshot(&snapshot(false, Vec::new()))
            .expect("disabled fence");
        let src: IpAddr = "10.0.0.7".parse().unwrap();
        let dst: IpAddr = "9.9.9.9".parse().unwrap();
        let ranges = [(
            "203.0.113.10".parse().unwrap(),
            "203.0.113.11".parse().unwrap(),
        )];
        assert!(empty.is_empty());
        assert!(!empty.matches_with_pool_ranges(src, dst, NatDecision::default(), &ranges, &[]));
        let fence = BindlessIpsecSelectorFence::from_snapshot(&snapshot(
            true,
            vec![row("10.0.0.0/8", "198.51.100.0/24")],
        ))
        .expect("valid selector snapshot");
        let base = NatDecision {
            rewrite_dst: Some("198.51.100.9".parse().unwrap()),
            ..NatDecision::default()
        };
        assert!(fence.matches_with_pool_ranges(src, dst, base, &[], &[]));
    }
}
