package routing

import (
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// RuleAddL3mdevUnreachable installs `ip rule add pref <priority> l3mdev
// unreachable` for one family. This is the #9819 VRF miss terminator; see
// vrfMissTerminatorPriority.
//
// netlink v1.3.1's Rule has no l3mdev selector (FRA_L3MDEV), so, as with
// RuleAddDSCP, the request is built here. It mirrors the header fields of the
// library's ruleHandle. The rule's action travels in the header's type byte,
// which is fib_rule_hdr.action, and FRA_L3MDEV carries 1, as iproute2 sends it.
// No table is named: the l3mdev selector supplies the VRF's table at lookup
// time.
func (o dscpRuleOps) RuleAddL3mdevUnreachable(family, priority int) error {
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return fmt.Errorf("l3mdev rule: unsupported family %d", family)
	}
	if priority < 0 {
		return fmt.Errorf("l3mdev rule: negative priority %d", priority)
	}
	req := nl.NewNetlinkRequest(unix.RTM_NEWRULE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	msg := nl.NewRtMsg()
	msg.Family = uint8(family)
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = nl.FR_ACT_UNREACHABLE
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(uint32(priority))))
	req.AddData(nl.NewRtAttr(nl.FRA_L3MDEV, nl.Uint8Attr(1)))
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// Compile-time proof the production ops satisfies the terminator's interface.
var _ vrfMissTerminatorOps = dscpRuleOps{}
