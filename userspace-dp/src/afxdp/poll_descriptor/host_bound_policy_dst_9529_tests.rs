//! #9529: `host_bound_policy_dst` as a pure function — the translation rule every
//! host-bound gate shares. The descriptor cells in
//! `afxdp/tests_host_bound_post_dnat_9529.rs` bind the call sites; these pin the
//! rule itself, including the cross-family case a descriptor fixture cannot reach
//! cheaply.

use super::*;
use crate::session::SessionKey;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn flow(dst: IpAddr, dport: u16) -> SessionFlow {
    let src = match dst {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
    };
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: if dst.is_ipv4() {
                libc::AF_INET as u8
            } else {
                libc::AF_INET6 as u8
            },
            protocol: 6,
            src_ip: src,
            dst_ip: dst,
            src_port: 54321,
            dst_port: dport,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

#[test]
fn with_no_translation_the_wire_tuple_is_judged_9529() {
    let vip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    assert_eq!(
        host_bound_policy_dst(&flow(vip, 443), 443, None, None),
        (vip, 443),
        "direct-to-local traffic carries no translation and must be judged exactly as \
         before (#9529)"
    );
}

#[test]
fn a_same_family_translation_is_judged_post_translation_9529() {
    let f = flow(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443);
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    assert_eq!(
        host_bound_policy_dst(&f, 443, Some(local), Some(8080)),
        (local, 8080),
        "a DNAT to the firewall's own 10.0.61.1:8080 is judged on the tuple the listener \
         receives (#9529)"
    );
    assert_eq!(
        host_bound_policy_dst(&f, 443, Some(local), None),
        (local, 443),
        "an address-only translation keeps the wire port"
    );
}

#[test]
fn a_cross_family_translation_keeps_the_wire_address_9529() {
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x64, 0, 0, 0, 0, 1));
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    assert_eq!(
        host_bound_policy_dst(&flow(v6, 80), 80, Some(v4), Some(8080)),
        (v6, 8080),
        "a NAT64 target is a different address family from the packet, so the address \
         the policy is asked about stays the wire one; the port still follows the \
         translation (#9529)"
    );
    let same = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x64, 0, 0, 0, 0, 2));
    assert_eq!(
        host_bound_policy_dst(&flow(v6, 80), 80, Some(same), None).0,
        same,
        "control: a same-family v6 translation IS taken, so the guard is keyed on family \
         and not on v6 as such"
    );
}
