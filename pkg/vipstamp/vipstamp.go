// Package vipstamp is the kernel half of xpf's direct-mode VIP ownership
// record (#18573): every RETH VIP the direct-VIP path installs carries
// IFA_PROTO = Proto, and Dump reads it back. pkg/daemon (the reconcile
// that installs and prunes) and pkg/dataplane/userspace (the snapshot
// builder that must not publish a leftover) share this one definition.
package vipstamp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// Direct-mode VIP ownership stamp.
//
// Direct VIP mode (private-RG election / no-reth-vrrp, the compiler
// default) used to derive BOTH its add set and its remove set from the
// active config at call time. Nothing recorded what had been installed,
// so a commit that renumbered a RETH unit (.10 -> .42) left the old
// address on the RG owner indefinitely: the add pass only adds the new
// set, the demotion pass only removes the new set, and the netlink
// address reconcile skips RETH netdevs entirely. The owner kept answering
// ARP for an address the config no longer had.
//
// Ownership is recorded IN THE KERNEL, on the address object itself, via
// IFA_PROTO (Linux 6.3+; the appliance floor is 6.18). Every direct-mode
// VIP xpf installs carries Proto. That is the registry, and
// it is not a shadow of the address table — it is a field OF the address
// table, so every removal path (a commit, a demotion, a link-cycle flush,
// an operator's `ip addr del`, the netdev being deleted) removes the
// ownership record together with the address. Nothing has to be hooked,
// and a later foreign install of the same address/prefix carries the
// installer's proto (0 for `ip addr add`, the DHCP client, networkd),
// never this one, so xpf never mistakes it for its own.
//
// The prune deletes ONLY stamped addresses. An unstamped address is
// foreign — a DHCP lease, a kernel link-local (IFAPROT_KERNEL_LL), the
// stable RETH link-local (managed by its own add/remove pair), another
// daemon's address — and is never touched, with one pre-existing
// exception kept unchanged: the non-owner still removes every address
// the CONFIG names as a VIP of the RG, stamped or not, because the
// config names it as the RG's (and a VIP installed by a pre-#18573 xpf
// carries no stamp).
const Proto uint8 = 0xbf

// IFAProto is IFA_PROTO (include/uapi/linux/if_addr.h). golang.org/x/sys
// v0.40 stops at IFA_TARGET_NETNSID (0xa), and vishvananda/netlink v1.3.1
// neither encodes nor decodes it, so both the stamped add and the
// ownership-reading dump are hand-built below (the #17078 RuleListFull
// precedent: one raw site for what the library cannot represent).
const IFAProto = 0xb

// Row is one decoded RTM_NEWADDR dump row: the fields the
// direct-VIP ownership planner needs, including IFA_PROTO.
type Row struct {
	LinkIndex int
	Prefix    netip.Prefix // address + prefix length, NOT masked
	Proto     uint8        // 0 when the kernel sent no IFA_PROTO
}

// Stamped reports whether xpf's direct-VIP path installed this address.
func (r Row) Stamped() bool { return r.Proto == Proto }

// Identity is the row's (address, prefix length) identity in the space
// config.AddressIdentitiesByNetdev and config.VRRPVIPIdentity use.
func (r Row) Identity() string { return config.PrefixIdentity(r.Prefix) }

// Leftover is THE stale-VIP predicate (#18573), shared by the direct-VIP
// reconcile (which deletes it) and the userspace snapshot builder (which
// never publishes it): the row carries xpf's stamp, and the config
// assigns no such address to the netdev it sits on. configured is
// config.AddressIdentitiesByNetdev. An unstamped row is never a
// leftover — xpf cannot tell it was ever its own.
func Leftover(r Row, netdev string, configured map[string]map[string]bool) bool {
	return r.Stamped() && netdev != "" && !configured[netdev][r.Identity()]
}

// Dump dumps every address on every link (both families) and
// decodes each row, including IFA_PROTO. Any execute error — including
// NLM_F_DUMP_INTR — or malformed row fails the whole read: the caller
// deletes addresses on the strength of this readback, so a half-decoded
// or inconsistent table must never drive a delete.
func Dump() ([]Row, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETADDR, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfAddrmsg(unix.AF_UNSPEC))
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWADDR)
	if err != nil {
		return nil, err
	}
	rows := make([]Row, 0, len(msgs))
	for _, m := range msgs {
		row, ok, err := ParseRow(m)
		if err != nil {
			return nil, err
		}
		if ok {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// ParseRow decodes one RTM_NEWADDR payload (ifaddrmsg + attrs).
// ok is false for a well-formed row of a family the planner does not
// handle. Address attributes must carry exactly the family's width and
// IFA_PROTO exactly one byte; anything else is an error, never a guess.
// The address is IFA_LOCAL when present, else IFA_ADDRESS — the kernel
// sends IPv4 as both (IFA_ADDRESS is the peer when they differ) and IPv6
// as IFA_ADDRESS alone, the same rule netlink v1.3.1's parseAddr uses.
func ParseRow(raw []byte) (Row, bool, error) {
	var row Row
	if len(raw) < unix.SizeofIfAddrmsg {
		return row, false, fmt.Errorf("short address dump row: %d bytes", len(raw))
	}
	msg := nl.DeserializeIfAddrmsg(raw)
	var width int
	switch msg.Family {
	case unix.AF_INET:
		width = net.IPv4len
	case unix.AF_INET6:
		width = net.IPv6len
	default:
		return row, false, nil
	}
	if int(msg.Prefixlen) > width*8 {
		return row, false, fmt.Errorf("address dump row: prefixlen %d exceeds family width", msg.Prefixlen)
	}
	attrs, err := nl.ParseRouteAttr(raw[unix.SizeofIfAddrmsg:])
	if err != nil {
		return row, false, fmt.Errorf("address dump row: %w", err)
	}
	var local, address []byte
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.IFA_LOCAL:
			if len(a.Value) != width {
				return row, false, fmt.Errorf("address dump row: IFA_LOCAL is %d bytes, want %d", len(a.Value), width)
			}
			local = a.Value
		case unix.IFA_ADDRESS:
			if len(a.Value) != width {
				return row, false, fmt.Errorf("address dump row: IFA_ADDRESS is %d bytes, want %d", len(a.Value), width)
			}
			address = a.Value
		case IFAProto:
			if len(a.Value) != 1 {
				return row, false, fmt.Errorf("address dump row: IFA_PROTO is %d bytes, want 1", len(a.Value))
			}
			row.Proto = a.Value[0]
		}
	}
	ipBytes := local
	if ipBytes == nil {
		ipBytes = address
	}
	if ipBytes == nil {
		return row, false, fmt.Errorf("address dump row on ifindex %d carries no address", msg.Index)
	}
	ip, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return row, false, fmt.Errorf("address dump row on ifindex %d: undecodable address", msg.Index)
	}
	row.LinkIndex = int(msg.Index)
	row.Prefix = netip.PrefixFrom(ip.Unmap(), int(msg.Prefixlen))
	return row, true, nil
}

// Add installs p on ifindex carrying Proto. With
// replace=false it is an exclusive create (EEXIST when present, exactly
// like netlink.AddrAdd); with replace=true it is CREATE|REPLACE, which on
// an existing address rewrites ifa_proto in place (IPv4
// inet_rtm_newaddr / IPv6 inet6_addr_modify) — the adoption of a VIP a
// pre-#18573 xpf installed unstamped. The encoding otherwise mirrors
// netlink v1.3.1 addrHandle for a plain Addr (IFA_LOCAL + IFA_ADDRESS,
// low flag byte in the header, IPv4 broadcast computed below /31), so a
// stamped VIP is bit-identical to the one the library used to install
// apart from IFA_PROTO. IPv6 VIPs carry IFA_F_NODAD as before.
func Add(ifindex int, p netip.Prefix, replace bool) error {
	flags := unix.NLM_F_CREATE | unix.NLM_F_ACK
	if replace {
		flags |= unix.NLM_F_REPLACE
	} else {
		flags |= unix.NLM_F_EXCL
	}
	req := nl.NewNetlinkRequest(unix.RTM_NEWADDR, flags)
	for _, d := range RequestData(ifindex, p) {
		req.AddData(d)
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// RequestData is the pure encoding half of Add, so
// the attribute set is checkable without a kernel.
func RequestData(ifindex int, p netip.Prefix) []nl.NetlinkRequestData {
	addr := p.Addr().Unmap()
	family := unix.AF_INET6
	ipBytes := addr.AsSlice()
	if addr.Is4() {
		family = unix.AF_INET
	}
	msg := nl.NewIfAddrmsg(family)
	msg.Index = uint32(ifindex)
	msg.Prefixlen = uint8(p.Bits())
	if family == unix.AF_INET6 {
		msg.Flags = unix.IFA_F_NODAD
	}
	data := []nl.NetlinkRequestData{
		msg,
		nl.NewRtAttr(unix.IFA_LOCAL, ipBytes),
		nl.NewRtAttr(unix.IFA_ADDRESS, ipBytes),
	}
	if family == unix.AF_INET && p.Bits() < 31 {
		mask := net.CIDRMask(p.Bits(), 32)
		brd := make([]byte, net.IPv4len)
		for i := range brd {
			brd[i] = ipBytes[i] | ^mask[i]
		}
		data = append(data, nl.NewRtAttr(unix.IFA_BROADCAST, brd))
	}
	data = append(data, nl.NewRtAttr(IFAProto, []byte{Proto}))
	return data
}

// Del deletes one dumped address by (ifindex, address, prefix).
// The kernel matches IPv4 on IFA_LOCAL + prefixlen + IFA_ADDRESS and IPv6
// on the address; no label is sent, so the label never narrows the match.
func Del(row Row) error {
	ip := net.IP(row.Prefix.Addr().AsSlice())
	bits := 128
	if row.Prefix.Addr().Is4() {
		bits = 32
	}
	return netlink.AddrDel(nil, &netlink.Addr{
		IPNet:     &net.IPNet{IP: ip, Mask: net.CIDRMask(row.Prefix.Bits(), bits)},
		LinkIndex: row.LinkIndex,
	})
}

// GoneErr reports the delete outcomes that mean "already absent":
// the address went (or its netdev did) between the dump and the delete.
func GoneErr(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENODEV)
}
