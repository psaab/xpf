package routing

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// FRA_DSCP is the fib_rule attribute carrying a 6-bit DSCP selector.
//
// It is absent from github.com/vishvananda/netlink v1.3.1 AND from that
// project's upstream main/master, where Rule still exposes only `Tos` — so this
// is not a dependency-bump problem and the attribute has to be emitted here.
//
// The value is derived from the library's own enum rather than hardcoded to 25.
// The kernel's uapi order is ... FRA_SPORT_RANGE, FRA_DPORT_RANGE, FRA_DSCP, so
// FRA_DSCP is one past FRA_DPORT_RANGE. Deriving it means that if the library
// ever inserts an attribute earlier in the enum, this constant moves with it
// instead of silently addressing the wrong attribute.
//
// #7796: the kernel validates the legacy tos byte in fib_rule_hdr against
// IPTOS_TOS_MASK (0x1E) and rejects anything outside it. A DSCP shifted into a
// TOS byte (DSCP << 2) overflows that mask at DSCP >= 8, so every named DSCP
// except cs0/be returned EINVAL and took the whole commit down. FRA_DSCP carries
// the 6-bit value directly and is not masked.
const FRA_DSCP = nl.FRA_DPORT_RANGE + 1

// maxDSCP is the largest value the 6-bit DiffServ code point can hold.
const maxDSCP = 63

// dscpRuleOps is the production ruleOps. It embeds *netlink.Handle so RuleAdd /
// RuleDel / RuleList remain the library's implementations, and adds the
// operations the library cannot express: the DSCP selector below, and the
// #9819 l3mdev terminator in rule_l3mdev_linux.go.
type dscpRuleOps struct {
	*netlink.Handle
}

// RuleAddDSCP installs a policy-routing rule carrying a DSCP selector.
//
// The library's RuleAdd cannot be reused and then amended: netlink has no
// "add an attribute to the rule I just installed" operation, and the library
// exposes no hook into its request construction, so the request is built here.
//
// This deliberately MIRRORS the structure, attribute widths and ordering of
// netlink's own ruleHandle rather than inventing its own conventions — a
// hand-rolled second encoder is only safe while it stays recognisably the same
// shape as the one it stands in for. The differences are exactly two: the legacy
// tos byte is never written, and FRA_DSCP is appended.
//
// Selectors this encoder does not emit are REJECTED rather than ignored
// (rejectUnencodedRuleFields). Silently dropping a selector widens the installed
// rule, and a rule that steers more traffic than it was asked to is the failure
// this subsystem exists to prevent (#5117).
func (o dscpRuleOps) RuleAddDSCP(rule *netlink.Rule, dscp uint8) error {
	if rule == nil {
		return fmt.Errorf("dscp rule: nil rule")
	}
	if dscp > maxDSCP {
		return fmt.Errorf("dscp rule: dscp %d out of range (0-%d)", dscp, maxDSCP)
	}
	if err := rejectUnencodedRuleFields(rule); err != nil {
		return err
	}

	req := nl.NewNetlinkRequest(unix.RTM_NEWRULE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	native := nl.NativeEndian()

	msg := nl.NewRtMsg()
	msg.Family = unix.AF_INET
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = unix.RTN_UNICAST
	// msg.Tos stays 0. Writing the DSCP here is the #7796 defect.
	if rule.Family != 0 {
		msg.Family = uint8(rule.Family)
	}
	if rule.Table >= 0 && rule.Table < 256 {
		msg.Table = uint8(rule.Table)
	}

	// Address attributes are built BEFORE the header is added, because they
	// mutate the header's prefix lengths and family. The library does the same;
	// adding the header first and mutating it afterwards depends on AddData
	// retaining the pointer, which is not part of its contract.
	var dstFamily uint8
	var addrAttrs []*nl.RtAttr
	if rule.Dst != nil && rule.Dst.IP != nil {
		dstLen, _ := rule.Dst.Mask.Size()
		msg.Dst_len = uint8(dstLen)
		msg.Family = uint8(nl.GetIPFamily(rule.Dst.IP))
		dstFamily = msg.Family
		addrAttrs = append(addrAttrs, nl.NewRtAttr(unix.RTA_DST, ruleIPBytes(rule.Dst.IP, msg.Family)))
	}
	if rule.Src != nil && rule.Src.IP != nil {
		msg.Family = uint8(nl.GetIPFamily(rule.Src.IP))
		if dstFamily != 0 && dstFamily != msg.Family {
			return fmt.Errorf("dscp rule: source and destination are not the same IP family")
		}
		srcLen, _ := rule.Src.Mask.Size()
		msg.Src_len = uint8(srcLen)
		addrAttrs = append(addrAttrs, nl.NewRtAttr(unix.RTA_SRC, ruleIPBytes(rule.Src.IP, msg.Family)))
	}

	req.AddData(msg)
	for i := range addrAttrs {
		req.AddData(addrAttrs[i])
	}

	if rule.Priority >= 0 {
		req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(uint32(rule.Priority))))
	}
	if rule.Table >= 256 {
		req.AddData(nl.NewRtAttr(nl.FRA_TABLE, nl.Uint32Attr(uint32(rule.Table))))
	}
	if rule.IifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_IIFNAME, nl.ZeroTerminated(rule.IifName)))
	}
	if rule.OifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_OIFNAME, nl.ZeroTerminated(rule.OifName)))
	}
	if rule.IPProto > 0 {
		// 4 bytes, matching the library. The kernel policy is NLA_U8 and reads
		// the first byte, so a wider attribute is accepted; keeping the width
		// identical to netlink's own emit avoids a second convention.
		req.AddData(nl.NewRtAttr(nl.FRA_IP_PROTO, nl.Uint32Attr(uint32(rule.IPProto))))
	}
	if rule.Dport != nil {
		req.AddData(nl.NewRtAttr(nl.FRA_DPORT_RANGE, rulePortRangeBytes(native, rule.Dport)))
	}
	if rule.Sport != nil {
		req.AddData(nl.NewRtAttr(nl.FRA_SPORT_RANGE, rulePortRangeBytes(native, rule.Sport)))
	}

	// The selector this file exists for.
	req.AddData(nl.NewRtAttr(FRA_DSCP, nl.Uint8Attr(dscp)))

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// rejectUnencodedRuleFields fails closed on any Rule field this encoder does not
// emit, so an unhandled selector stops the install instead of widening the rule.
func rejectUnencodedRuleFields(rule *netlink.Rule) error {
	switch {
	case rule.Tos != 0:
		return fmt.Errorf("dscp rule: legacy tos selector must not be combined with a dscp selector (#7796)")
	case rule.Mark != 0 || rule.Mask != nil:
		return fmt.Errorf("dscp rule: fwmark selector is not encoded by this path")
	case rule.TunID != 0:
		return fmt.Errorf("dscp rule: tunnel-id selector is not encoded by this path")
	case rule.Flow > 0:
		return fmt.Errorf("dscp rule: flow selector is not encoded by this path")
	case rule.UIDRange != nil:
		return fmt.Errorf("dscp rule: uid-range selector is not encoded by this path")
	case rule.Invert:
		return fmt.Errorf("dscp rule: inverted rules are not encoded by this path")
	case rule.Goto > 0:
		return fmt.Errorf("dscp rule: goto action is not encoded by this path")
	}
	return nil
}

// ruleIPBytes returns the address in the width the message family expects. A
// 4-byte family must not carry a 16-byte v4-mapped address: the kernel reads the
// attribute by family, so the wrong width silently changes the prefix.
func ruleIPBytes(ip net.IP, family uint8) []byte {
	if family == unix.AF_INET {
		if v4 := ip.To4(); v4 != nil {
			return []byte(v4)
		}
	}
	return []byte(ip.To16())
}

// rulePortRangeBytes encodes FRA_SPORT_RANGE / FRA_DPORT_RANGE as the kernel
// reads them: two native-order u16s.
func rulePortRangeBytes(native interface {
	PutUint16([]byte, uint16)
}, r *netlink.RulePortRange) []byte {
	b := make([]byte, 4)
	native.PutUint16(b[0:2], r.Start)
	native.PutUint16(b[2:4], r.End)
	return b
}

// Compile-time proof the production ops satisfies the interface the rule
// managers are written against, so a signature drift fails here rather than at
// the single place the Manager is constructed.
var _ ruleOps = dscpRuleOps{}
