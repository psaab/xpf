package dataplane

import "github.com/vishvananda/netlink"

// netdev_framing_8279.go carries the link-layer framing requirement for the
// retained AF_XDP shim.
//
// The shim's `parse_l2` (`userspace-xdp/src/lib.rs`) reads a 14-byte Ethernet
// header unconditionally — its only branch is the VLAN one, and there is no
// raw-L3 path. On a netdev whose frames carry NO Ethernet header, bytes
// [12..14] are therefore not an ethertype at all: on a bare IPv4 packet they
// are the first two octets of the SOURCE ADDRESS. So:
//
//   - a source in 8.0.0.0/16 reads as ETH_P_IP and the shim parses an IPv4
//     header 14 bytes into the real one — a misparse an attacker selects by
//     choosing the inner source address;
//   - a source in 134.221.0.0/16 does the same for ETH_P_IPV6;
//   - 129.0.0.0/16 and 136.168.0.0/16 take the VLAN branch and re-read the
//     ethertype four bytes further in.
//
// #8279 fixed the ORDERING half of this in the shim (the ingress-set test now
// precedes the L3 parse, so a non-adjudicated ifindex is never parsed). This
// file closes the other half at the source: a netdev that cannot carry an
// Ethernet header must not carry the shim AT ALL. That is the only fix that
// also covers the ctrl-DISABLED path, which never consults the ingress set by
// design — a disabled ctrl must fail closed on every attached interface — and
// therefore evaluates its local/control exemption against the misparse.
//
// WHY THE ENCAP TYPE AND NOT THE LINK KIND. Measured, because the two
// disagree on exactly the case that matters: a TUN and a TAP are BOTH
// `netlink.Link.Type() == "tuntap"`, and only the encap type separates them —
//
//	xpf8279t  kind=tuntap  EncapType="none"     (TUN: raw L3, no Ethernet header)
//	xpf8279p  kind=tuntap  EncapType="ether"    (TAP: Ethernet)
//
// Keying on the kind would have excluded the TAP too, and — worse — would have
// admitted nothing about the tunnel netdevs this exists for. Real NICs report
// "ether"; `lo` reports "loopback".
//
// WHICH NETDEVS THIS ACTUALLY REACHES. The shim's attach set is strictly
// LARGER than the userspace-ingress set: every zoned netdev enters
// `st.xdpIfindexes` below, tunnels included, and only the userspace manager's
// `syncInterfaceAttachments` reconciles the difference away — at the two
// POST-acceptance points, deliberately (#5485). On a userspace-dataplane box a
// tunnel is an anchor TUN (ARPHRD_NONE), and the base row of a canonically
// spelled WireGuard tunnel (`set interfaces wgN unit 0 tunnel mode wireguard`)
// is not even excluded from the ingress set. So the population is real and it
// is reachable through an ordinary config.

// ethernetEncapType is the `netlink.LinkAttrs.EncapType` value for an
// ARPHRD_ETHER link. Verified against a live kernel rather than transcribed:
// every physical NIC, VLAN, bond, reth and L2 IPVLAN reports exactly this.
const ethernetEncapType = "ether"

// netdevCarriesEthernetFraming reports whether frames on a netdev with this
// `netlink.LinkAttrs.EncapType` begin with a 14-byte Ethernet header.
//
// A POSITIVE requirement, deliberately: the shim is an Ethernet parser, so an
// encap type this function has never heard of must be refused rather than
// assumed compatible. An allowlist of known-bad values would admit every
// future one.
//
// The empty string is refused for the same reason. It is what a caller that
// could not resolve the link reports, and "I do not know the framing" is not a
// licence to attach an Ethernet parser.
func netdevCarriesEthernetFraming(encapType string) bool {
	return encapType == ethernetEncapType
}

// netdevFramingKnown reports the link-layer encap type and whether it could be
// determined at all.
//
// THE POLARITY HERE IS THE OPPOSITE OF THE PREDICATE'S, DELIBERATELY, and an
// earlier round of this change had it wrong. `netdevCarriesEthernetFraming`
// refuses an unknown encap type, which is right for a PREDICATE — the shim is
// an Ethernet parser and an unrecognised framing must not be assumed
// compatible. But the GATE below must not refuse on `known == false`, because
// the two failures are not symmetric:
//
//   - attaching to a netdev whose framing we could not read risks a misparse,
//     and only on the rare device class that is actually raw L3;
//   - REFUSING one guarantees the netdev is UP, zoned and carries no XDP at
//     all, so with ip_forward=1 its traffic is forwarded unadjudicated. That
//     is a certain security gap on what is almost always a healthy Ethernet
//     NIC whose netlink lookup failed transiently.
//
// So refusing on "could not determine" trades a POSSIBLE misparse on a rare
// device for a CERTAIN adjudication hole on a common one — the wrong way
// round. The gate therefore refuses only what it affirmatively knows is not
// Ethernet, and an unresolvable link keeps its pre-existing behaviour.
//
// This was not reasoned out in advance: TestRefusedVLANNeverEntersTheDelegated
// ChildSet_6916 went red on a fixture whose link does not resolve, and reading
// why is what surfaced the asymmetry.
func netdevFramingKnown(link netlink.Link, linkErr error) (string, bool) {
	if linkErr != nil || link == nil || link.Attrs() == nil {
		return "", false
	}
	return link.Attrs().EncapType, true
}

// nonEthernetSurfaceRecord classifies a zoned netdev the compiler declined to
// arm because its frames carry no Ethernet header.
//
// StillForwarding is TRUE and that is the point of the record. The netdev is
// UP and in a zone, and it now has no XDP program, so with ip_forward=1 its
// traffic goes into the Linux stack unadjudicated — the #5275 policy-free-
// router state. That is a REAL gap, deliberately chosen over the alternative
// (adjudicating a misparsed header, where the 5-tuple the policy engine sees
// is selected by the attacker's inner source address), and the operator is
// entitled to see it rather than have it traded silently.
func nonEthernetSurfaceRecord(name string, ifindex int, encapType string) UnarmedSurface {
	shown := encapType
	if shown == "" {
		shown = "unresolved"
	}
	return UnarmedSurface{
		Name:    name,
		Ifindex: ifindex,
		Reason: "link-layer type " + shown + " is not Ethernet — the XDP shim parses a " +
			"14-byte Ethernet header unconditionally, so attaching it here would read the " +
			"IP source octets as an ethertype (#8279); netdev is UP and zoned but has no " +
			"XDP, so its traffic is not adjudicated",
		StillForwarding: true,
	}
}
