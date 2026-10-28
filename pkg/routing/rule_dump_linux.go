package routing

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// RuleRow is one decoded kernel fib-rule dump row: the netlink.Rule the
// library would decode from the same row, extended with the fields
// netlink v1.3.1's RuleListFiltered cannot represent.
//
// Type is fib_rule_hdr.action, carried on netlink.Rule itself (the
// library leaves it zero). The field netlink.Rule has no slot for at
// all — the FRA_DSCP selector (#7796) — is a sidecar field here, so
// one dump serves every readback consumer instead of each keeping its
// own partial decoder.
type RuleRow struct {
	netlink.Rule

	// DSCP is the FRA_DSCP selector value; DSCPSet distinguishes
	// "match DSCP 0" (iproute2 renders `dscp default`) from "no DSCP
	// selector", mirroring PBRRule.DSCPSet.
	DSCP    uint8
	DSCPSet bool
}

// RuleListFull dumps the kernel fib-rule table for family and decodes
// every row with full length validation.
//
// It exists because netlink v1.3.1's RuleList omits the fib-rule action
// (Rule.Type) and silently drops FRA_DSCP, and the two raw decoders
// that grew around that gap — the validating one formerly in
// pkg/daemon's DNS-rule file and the unvalidated one formerly in
// rule_dscp_linux.go — disagree on validation and on the FRA_IP_PROTO
// width. This is the single RTM_GETRULE dump site for the tree (#17078).
//
// Any dump, header, attribute or length failure is returned: callers
// reconcile or report against this readback, so a malformed row must
// fail the whole read rather than be half-decoded into a rule that
// steers (or fails to steer) traffic it was never asked about.
func RuleListFull(family int) ([]RuleRow, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	req.AddData(nl.NewIfInfomsg(family))
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil {
		return nil, err
	}
	rows := make([]RuleRow, 0, len(msgs))
	for _, m := range msgs {
		row, err := ruleRowFromDumpMessage(family, m)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// ruleRowFromDumpMessage decodes one RTM_NEWRULE dump row. It mirrors
// netlink v1.3.1's (Handle).RuleListFiltered decode — same defaults
// (NewRule, Priority reset to the kernel's 0), same attribute set, same
// &net.IPNet{IP, Mask} construction — and adds the three things the
// library cannot do: Rule.Type from fib_rule_hdr, length validation on
// every attribute (fixed-width attributes must match their kernel width
// exactly; the library slices [0:4]/[0:8] unchecked, silently truncating
// oversize values), and the FRA_DSCP sidecar. FRA_IP_PROTO is
// width-tolerant (1..4 bytes): the kernel emits it as u8 (#14971) while
// the library and its encoders emit 4 bytes.
func ruleRowFromDumpMessage(family int, raw []byte) (RuleRow, error) {
	var row RuleRow
	if len(raw) < unix.SizeofRtMsg {
		return row, fmt.Errorf("short family %d policy-rule message: %d bytes", family, len(raw))
	}
	msg := nl.DeserializeRtMsg(raw)
	attrRegion := raw[msg.Len():]
	// nl.ParseRouteAttr trusts each attribute's aligned length and
	// slices past the end of a truncated final attribute whose
	// padding is missing (v1.3.1 nl_linux.go), panicking instead of
	// returning its EINVAL path. Validate the walk here so a
	// truncated tail or sub-header residue fails closed like every other
	// malformed row.
	rest := attrRegion
	for len(rest) >= unix.SizeofRtAttr {
		alen := int(nl.NativeEndian().Uint16(rest[:2]))
		if alen < unix.SizeofRtAttr || alen > len(rest) {
			return row, fmt.Errorf("truncated policy-rule attribute in family %d: header claims %d bytes, %d remain", family, alen, len(rest))
		}
		aligned := (alen + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
		if aligned > len(rest) {
			return row, fmt.Errorf("truncated policy-rule attribute in family %d: header claims %d bytes, %d remain", family, alen, len(rest))
		}
		rest = rest[aligned:]
	}
	if len(rest) != 0 {
		return row, fmt.Errorf("truncated policy-rule attribute in family %d: %d trailing bytes remain", family, len(rest))
	}
	attrs, err := nl.ParseRouteAttr(attrRegion)
	if err != nil {
		return row, fmt.Errorf("parse family %d policy-rule attributes: %w", family, err)
	}
	native := nl.NativeEndian()
	rule := netlink.NewRule()
	rule.Priority = 0 // The default priority from kernel
	rule.Family = int(msg.Family)
	rule.Table = int(msg.Table)
	rule.Type = msg.Type
	rule.Invert = msg.Flags&netlink.FibRuleInvert != 0
	rule.Tos = uint(msg.Tos)
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.RTA_TABLE: // == nl.FRA_TABLE, the extended table id
			// The header Table is the low 8 bits; the extended
			// attribute carries the full table id when present.
			value, err := ruleDumpUint32(attr.Value, "table")
			if err != nil {
				return row, err
			}
			rule.Table = int(value)
		case nl.FRA_PRIORITY:
			value, err := ruleDumpUint32(attr.Value, "priority")
			if err != nil {
				return row, err
			}
			rule.Priority = int(value)
		case nl.FRA_DST:
			prefix, err := ruleDumpPrefix(attr.Value, msg.Dst_len)
			if err != nil {
				return row, fmt.Errorf("decode policy-rule destination in family %d: %w", family, err)
			}
			rule.Dst = prefix
		case nl.FRA_SRC:
			prefix, err := ruleDumpPrefix(attr.Value, msg.Src_len)
			if err != nil {
				return row, fmt.Errorf("decode policy-rule source in family %d: %w", family, err)
			}
			rule.Src = prefix
		case nl.FRA_FWMARK:
			value, err := ruleDumpUint32(attr.Value, "mark")
			if err != nil {
				return row, err
			}
			rule.Mark = value
		case nl.FRA_FWMASK:
			value, err := ruleDumpUint32(attr.Value, "mark mask")
			if err != nil {
				return row, err
			}
			rule.Mask = &value
		case nl.FRA_TUN_ID:
			if len(attr.Value) < 8 {
				return row, fmt.Errorf("short policy-rule tunnel id attribute in family %d", family)
			}
			if len(attr.Value) > 8 {
				return row, fmt.Errorf("oversize policy-rule tunnel id attribute length %d in family %d", len(attr.Value), family)
			}
			rule.TunID = uint(native.Uint64(attr.Value))
		case nl.FRA_IIFNAME:
			rule.IifName = ruleDumpIfName(attr.Value)
		case nl.FRA_OIFNAME:
			rule.OifName = ruleDumpIfName(attr.Value)
		case nl.FRA_SUPPRESS_PREFIXLEN:
			value, err := ruleDumpUint32(attr.Value, "suppress prefix length")
			if err != nil {
				return row, err
			}
			if value != ^uint32(0) {
				rule.SuppressPrefixlen = int(value)
			}
		case nl.FRA_SUPPRESS_IFGROUP:
			value, err := ruleDumpUint32(attr.Value, "suppress interface group")
			if err != nil {
				return row, err
			}
			if value != ^uint32(0) {
				rule.SuppressIfgroup = int(value)
			}
		case nl.FRA_FLOW:
			value, err := ruleDumpUint32(attr.Value, "flow")
			if err != nil {
				return row, err
			}
			rule.Flow = int(value)
		case nl.FRA_GOTO:
			value, err := ruleDumpUint32(attr.Value, "goto")
			if err != nil {
				return row, err
			}
			rule.Goto = int(value)
		case nl.FRA_IP_PROTO:
			// Kernel emits FRA_IP_PROTO as u8 (1 byte); a u32-only
			// decode only ever saw synthetic 4-byte fixtures.
			// Accept 1..4 bytes, fail closed on empty/oversize
			// (#14971).
			if len(attr.Value) < 1 || len(attr.Value) > 4 {
				return row, fmt.Errorf("invalid policy-rule IP protocol attribute length %d in family %d", len(attr.Value), family)
			}
			var protoBuf [4]byte
			copy(protoBuf[:], attr.Value)
			rule.IPProto = int(native.Uint32(protoBuf[:]))
		case nl.FRA_DPORT_RANGE:
			if len(attr.Value) < 4 {
				return row, fmt.Errorf("short policy-rule destination-port range in family %d", family)
			}
			if len(attr.Value) > 4 {
				return row, fmt.Errorf("oversize policy-rule destination-port range length %d in family %d", len(attr.Value), family)
			}
			rule.Dport = netlink.NewRulePortRange(native.Uint16(attr.Value[:2]), native.Uint16(attr.Value[2:4]))
		case nl.FRA_SPORT_RANGE:
			if len(attr.Value) < 4 {
				return row, fmt.Errorf("short policy-rule source-port range in family %d", family)
			}
			if len(attr.Value) > 4 {
				return row, fmt.Errorf("oversize policy-rule source-port range length %d in family %d", len(attr.Value), family)
			}
			rule.Sport = netlink.NewRulePortRange(native.Uint16(attr.Value[:2]), native.Uint16(attr.Value[2:4]))
		case nl.FRA_UID_RANGE:
			if len(attr.Value) < 8 {
				return row, fmt.Errorf("short policy-rule UID range in family %d", family)
			}
			if len(attr.Value) > 8 {
				return row, fmt.Errorf("oversize policy-rule UID range length %d in family %d", len(attr.Value), family)
			}
			rule.UIDRange = netlink.NewRuleUIDRange(native.Uint32(attr.Value[:4]), native.Uint32(attr.Value[4:8]))
		case nl.FRA_PROTOCOL:
			if len(attr.Value) < 1 {
				return row, fmt.Errorf("short policy-rule protocol attribute in family %d", family)
			}
			if len(attr.Value) > 1 {
				return row, fmt.Errorf("oversize policy-rule protocol attribute length %d in family %d", len(attr.Value), family)
			}
			rule.Protocol = attr.Value[0]
		case FRA_DSCP:
			if len(attr.Value) < 1 {
				return row, fmt.Errorf("short policy-rule DSCP attribute in family %d", family)
			}
			if len(attr.Value) > 1 {
				return row, fmt.Errorf("oversize policy-rule DSCP attribute length %d in family %d", len(attr.Value), family)
			}
			row.DSCP = attr.Value[0]
			row.DSCPSet = true
		}
	}
	row.Rule = *rule
	return row, nil
}

func ruleDumpPrefix(ip []byte, prefixLen uint8) (*net.IPNet, error) {
	if (len(ip) != net.IPv4len && len(ip) != net.IPv6len) || int(prefixLen) > 8*len(ip) {
		return nil, fmt.Errorf("invalid address length %d or prefix length %d", len(ip), prefixLen)
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(prefixLen), 8*len(ip))}, nil
}

func ruleDumpUint32(value []byte, name string) (uint32, error) {
	if len(value) < 4 {
		return 0, fmt.Errorf("short policy-rule %s attribute", name)
	}
	if len(value) > 4 {
		return 0, fmt.Errorf("oversize policy-rule %s attribute length %d", name, len(value))
	}
	return nl.NativeEndian().Uint32(value), nil
}

func ruleDumpIfName(value []byte) string {
	name := string(value)
	if len(name) > 0 && name[len(name)-1] == 0 {
		name = name[:len(name)-1]
	}
	return name
}
