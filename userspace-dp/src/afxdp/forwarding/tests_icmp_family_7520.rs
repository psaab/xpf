// #7520: the global ICMP host-inbound accept was IP-FAMILY BLIND.
//
// `is_icmp_host_inbound_global_accept` switched on the protocol number alone.
// That arm returns early, BEFORE the zone lookup, so a match admits a packet
// the zone's `host-inbound-traffic` set never permitted — it is a fail-OPEN,
// not a fail-closed narrowing.
//
// The two crossed pairs:
//
//   IPv4 packet, protocol byte 58, type 1  -> took the ICMPv6 arm -> ADMITTED
//   IPv6 packet, next-header 1,   type 11  -> took the ICMPv4 arm -> ADMITTED
//
// The type numbers cannot disambiguate them, which is why the family must be
// part of the key: ICMPv6 destination-unreachable is type 1 and ICMPv4
// time-exceeded is type 11, and neither number is reserved to one family.
//
// #3171 and #3292 implemented the two halves of this admission and neither
// tested their COMPOSITION, which is where the defect lived.

use super::host_inbound::is_icmp_host_inbound_global_accept_for_test as accepts;

#[test]
fn crossed_family_pairs_are_not_globally_admitted_7520() {
    // IPv4 carrying the ICMPv6 protocol number, for every type the ICMPv6 arm
    // admits. Each one was a global admit before #7520.
    for t in [1u8, 2, 3, 4, 133, 134, 135, 136, 137] {
        assert!(
            !accepts(58, false, t),
            "an IPv4 packet with protocol 58 and type {t} was globally admitted as \
             ICMPv6. This returns before the zone lookup, so it bypasses the zone's \
             host-inbound set entirely — a fail-OPEN (#7520)"
        );
    }
    // IPv6 carrying the ICMPv4 protocol number, for every type the ICMPv4 arm
    // admits.
    for t in [3u8, 11, 12] {
        assert!(
            !accepts(1, true, t),
            "an IPv6 packet with next-header 1 and type {t} was globally admitted as \
             ICMPv4 (#7520)"
        );
    }
}

#[test]
fn matched_family_pairs_are_still_admitted_7520() {
    // THE OVER-REJECTION CONTROL, and it is the assertion that matters most:
    // #3171's whole point is that PMTUD, unreachable and traceroute-to-self
    // work on a zone that omits `ping`, and #3240's that v6 ND works on a zone
    // that scopes router-discovery. Narrowing this predicate too far breaks
    // path-MTU discovery on every configured zone — silently, as a black hole.
    for t in [3u8, 11, 12] {
        assert!(
            accepts(1, false, t),
            "ICMPv4 type {t} on IPv4 is no longer globally admitted; PMTUD / \
             unreachable / traceroute-to-self break on a zone that omits `ping` (#3171)"
        );
    }
    for t in [1u8, 2, 3, 4, 133, 134, 135, 136, 137] {
        assert!(
            accepts(58, true, t),
            "ICMPv6 type {t} on IPv6 is no longer globally admitted; v6 PMTUD and \
             the ND set break on a configured zone (#3171/#3240)"
        );
    }
}

#[test]
fn mld_types_are_not_global_nd_accepts_10859() {
    // MLD Query/Report/Done (130-132) and MLDv2 Report (143) are not ND
    // (133-137). Query traffic reaches the kernel via multicast early-pass;
    // reports are egress, so none belongs in this global INPUT exemption.
    for t in [130u8, 131, 132, 143] {
        assert!(
            !accepts(58, true, t),
            "ICMPv6 MLD type {t} must not bypass zone admission as a global ND accept"
        );
    }
}

#[test]
fn non_error_icmp_types_stay_gated_7520() {
    // Echo-request (v4 8, v6 128) and IPv4 router-advert/solicit (9/10) are
    // deliberately NOT in the global set — they stay gated on the `ping` and
    // `router-discovery` tokens. Without this, "matched pairs are admitted"
    // is satisfied by a predicate that admits every ICMP type.
    for (proto, is_v6, t) in [(1u8, false, 8u8), (1, false, 0), (1, false, 9), (1, false, 10),
                              (58, true, 128), (58, true, 129)] {
        assert!(
            !accepts(proto, is_v6, t),
            "proto {proto} is_v6={is_v6} type {t} is globally admitted; only the \
             ERROR/PMTUD and ND sets are exempt — echo and v4 router-discovery stay \
             gated on their zone tokens"
        );
    }
}

#[test]
fn non_icmp_protocols_are_never_globally_admitted_7520() {
    // The fall-through. A packet whose family the parser could not determine,
    // or an ordinary transport protocol, must stay gated on the zone set — the
    // `icmp_type` argument is the first L4 byte and means nothing here.
    for (proto, is_v6) in [(6u8, false), (6, true), (17, false), (17, true),
                           (0, false), (255, true), (47, false)] {
        for t in [0u8, 1, 3, 11, 128, 135] {
            assert!(
                !accepts(proto, is_v6, t),
                "protocol {proto} (is_v6={is_v6}) was globally admitted for first-L4-byte \
                 {t}; only ICMP/ICMPv6 have a global accept (#7520)"
            );
        }
    }
}
