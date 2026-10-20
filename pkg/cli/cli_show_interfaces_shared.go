package cli

import (
	"net"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

// dhcpLease returns the current DHCP lease for a managed interface, if any.
// Consumed by `show interfaces` presenters when rendering DHCP-assigned
// addresses; returns nil when no DHCP client is wired or no lease exists.
// The lease is resolved via cfg.DHCPLeaseKey(physName, unitNum) — the
// daemon's actual key (LinuxIfName + ".VlanID" when > 0) — so Junos
// slash names and VLAN-tagged units match (#15724).
func (c *CLI) dhcpLease(cfg *config.Config, physName string, unitNum int, af dhcp.AddressFamily) *dhcp.Lease {
	if c.dhcp == nil || cfg == nil {
		return nil
	}
	key, ok := cfg.DHCPLeaseKey(physName, unitNum)
	if !ok {
		return nil
	}
	return c.dhcp.LeaseFor(key, af)
}

// rethMemberLinkState returns the admin/link ("up"/"down") state for a reth's
// physical member, best-effort from the kernel. When the device is absent (a
// peer-owned member, or a test host with no such netdev) admin stays "up" and
// only link is reported "down" — matching the terse handler (#4328).
func rethMemberLinkState(member string) (admin, link string) {
	admin, link = "up", "up"
	kernelIf := config.LinuxIfName(member)
	iface, err := net.InterfaceByName(kernelIf)
	if err != nil {
		return "up", "down"
	}
	if iface.Flags&net.FlagUp == 0 {
		admin = "down"
	}
	if data, err := os.ReadFile("/sys/class/net/" + kernelIf + "/operstate"); err == nil {
		if strings.TrimSpace(string(data)) != "up" {
			link = "down"
		}
	}
	return admin, link
}

// baseIfName strips a dotted unit suffix ("reth0.50" -> "reth0").
func baseIfName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}

// kernelToAuthoredMap builds a kernel-ifname -> authored-Junos-name reverse map
// from the active config. The netlink-driven detail / extensive / statistics
// presenters walk kernel netdevs ("ge-0-0-2"), but every `show interfaces`
// variant must render the SAME authored identity ("ge-0/0/2") the summary and
// terse paths already use, so the operator never sees one interface under two
// spellings (#4984). A managed interface maps to its config (authored) name; an
// unmanaged netdev is absent from the map and callers fall back to the kernel
// name unchanged (see authoredName).
func kernelToAuthoredMap(cfg *config.Config) map[string]string {
	m := make(map[string]string)
	if cfg == nil {
		return m
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		if ifc == nil { // #5068: tolerant/HA-sync path may carry a nil value
			continue
		}
		m[config.LinuxIfName(ifc.Name)] = ifc.Name
	}
	return m
}

// authoredName resolves a kernel ifname to its authored Junos name via the
// reverse map, returning the kernel name unchanged for an unmanaged device.
func authoredName(kernelToAuthored map[string]string, kernelName string) string {
	if a, ok := kernelToAuthored[kernelName]; ok {
		return a
	}
	return kernelName
}

// ifaceFilterMatches reports whether an operator-supplied `show interfaces
// <name> detail|extensive` filter selects a netdev. It accepts EITHER the
// authored Junos name ("ge-0/0/2") or the kernel dash-form name ("ge-0-0-2")
// so the two spellings are interchangeable on the command line and an authored
// filter no longer reports "not found" against a kernel-named netdev (#4984).
func ifaceFilterMatches(filter, kernelName, authored string) bool {
	return filter == kernelName ||
		filter == authored ||
		config.LinuxIfName(filter) == kernelName
}

// rethMemberAttrs returns the netlink attributes of a reth's physical member,
// best-effort. ok is false when the member device is absent (peer-owned or a
// test host) so callers render from config alone (#4328).
func rethMemberAttrs(member string) (attrs *netlink.LinkAttrs, ok bool) {
	link, err := netlink.LinkByName(config.LinuxIfName(member))
	if err != nil {
		return nil, false
	}
	return link.Attrs(), true
}
