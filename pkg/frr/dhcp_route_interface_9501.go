package frr

import (
	"log/slog"
	"net/netip"
)

// dhcpRouteInterface returns the interface qualifier to render for a DHCP-learned
// route, and whether the route must be dropped instead (#9501).
//
// The gateway and destination operands on that line are safe by construction:
// they come from netip.Addr / netip.Prefix String(). The interface operand is a
// plain string (config.DHCPLeaseIfName -> config.LinuxIfName, which only maps "/"
// to "-"), and the static-route renderer already belts exactly that operand
// class with validFRRInterfaceOperand. ValidateInterfaceName rejects whitespace
// at commit, so a bad name can only arrive through a tolerant load, HA peer sync
// or a rollback recompile, which is the population the static belt exists for.
//
// A token-unsafe interface is never rendered. With a routable gateway the route
// renders WITHOUT the qualifier, the same granularity as the static-route belt,
// which drops the operand and not the route. A link-local gateway cannot resolve
// without an interface, so that route is dropped instead of rendering a line FRR
// may refuse, since a refused line fails the whole managed reload.
func dhcpRouteInterface(dr DHCPRoute) (string, bool) {
	if dr.Interface == "" || validFRRInterfaceOperand(dr.Interface) {
		return dr.Interface, false
	}
	if gw, err := netip.ParseAddr(dr.Gateway); err == nil && gw.IsLinkLocalUnicast() {
		slog.Warn("frr: dropping a DHCP-learned route: its interface operand is not a single token "+
			"and its link-local gateway cannot resolve without one (#9501)",
			"gateway", dr.Gateway, "interface_len", len(dr.Interface))
		return "", true
	}
	slog.Warn("frr: rendering a DHCP-learned route without its interface qualifier: the interface "+
		"operand is not a single token (#9501)",
		"gateway", dr.Gateway, "interface_len", len(dr.Interface))
	return "", false
}
