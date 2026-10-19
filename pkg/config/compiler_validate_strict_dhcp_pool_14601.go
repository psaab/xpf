package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateDHCPPoolValuesStrict refuses, at commit / commit-check, a DHCP
// pool whose subnet, address-range, router or dns-server value Kea would
// refuse in the rendered config (#14601, finding Y13-01).
//
// Every pool renders as its own Kea subnet4/subnet6 entry with the pool
// string, the routers / domain-name-servers (v4) or dns-servers (v6)
// option-data emitted verbatim. Kea loads the file as one unit, so a single
// bad value — a subnet without a prefix length ("Invalid subnet syntax
// (prefix/len expected)"), a pool outside its subnet (Subnet::addPool
// throws BadValue, rethrown as DhcpConfigError), an unparseable pool
// ("Failed to parse pool"), or wrong-family data in an ipv4-address option
// — makes kea-dhcp4/kea-dhcp6 refuse the whole file and stop serving every
// pool of that family on the node, healthy pools included, while the commit
// itself printed `commit complete`. That is the #9785 outage reached
// through four more leaves: #9785 gated only the duplicate subnet, and its
// validator skips an unparseable subnet, so a mistyped subnet, range,
// router or resolver committed clean.
//
// The checks, per pool of each server (the server fixes the family):
//
//   - subnet: when present it must parse as a prefix (which requires the
//     "/len") and be of the server's family. ParsePrefix also rejects a
//     bare address, which is exactly Kea's no-/len refusal.
//   - address-range low/high: each present bound must parse, be of the
//     server's family, and — when the pool subnet parsed — lie inside the
//     masked subnet; when both bounds are present, low must not exceed
//     high. A one-sided range is not rendered by the Kea generators (they
//     require both bounds), but a present bound is still family-checked:
//     it is a committed leaf that would render the moment its sibling is
//     added, and the issue acceptance names it leaf by leaf.
//   - router: the v4 renderer emits it as the `routers` option; a present
//     value must be a valid IPv4 address. The v6 renderer emits no router
//     option at all (there is no such DHCPv6 option; routers come from
//     RA), so a v6 pool's router leaf is inert and is not gated.
//   - dns-server: every element must parse and be of the server's family.
//     The schema's ValidateIPAddress accepts either family, so the family
//     half is this gate's job; the parse half is repeated here because the
//     tolerant paths do not run SchemaValidate.
//
// A pool with no subnet is refused outright (#15029, A17-02): it renders
// "subnet": "" and Kea refuses the whole file, so the missing subnet is
// itself the Kea-refused value, not a separate incompleteness. The other
// leaves are still checked after this gate only when a subnet exists.
// Iteration is sorted so the first reported error is stable across runs.
func validateDHCPPoolValuesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(srv *DHCPLocalServerConfig, server string, wantV6 bool) error {
		if srv == nil {
			return nil
		}
		addrFamily := "IPv4"
		if wantV6 {
			addrFamily = "IPv6"
		}
		groupNames := make([]string, 0, len(srv.Groups))
		for name := range srv.Groups {
			groupNames = append(groupNames, name)
		}
		sort.Strings(groupNames)
		for _, gname := range groupNames {
			group := srv.Groups[gname]
			if group == nil {
				continue
			}
			for _, pool := range group.Pools {
				if pool == nil {
					continue
				}
				where := fmt.Sprintf("%s group %q pool %q", server, group.Name, pool.Name)

				// Subnet: required, prefix shape + family. The masked
				// prefix is kept for the range-containment checks below.
				// An empty subnet renders "subnet": "" which Kea refuses,
				// stopping every pool of the family (#15029).
				if pool.Subnet == "" {
					return fmt.Errorf("%s subnet is not set (a DHCP pool without a subnet renders an empty subnet, Kea refuses the whole config and stops serving every pool on the node)", where)
				}
				var prefix netip.Prefix
				havePrefix := false
				{
					p, err := netip.ParsePrefix(pool.Subnet)
					if err != nil {
						return fmt.Errorf("%s subnet %q is not a valid prefix with a prefix length (Kea refuses a subnet without one and stops serving every pool on the node)", where, pool.Subnet)
					}
					if wantV6 && !p.Addr().Is6() {
						return fmt.Errorf("%s subnet %q is not an IPv6 prefix (required under dhcpv6-local-server)", where, pool.Subnet)
					}
					if !wantV6 && !p.Addr().Is4() {
						return fmt.Errorf("%s subnet %q is not an IPv4 prefix (required under dhcp-local-server)", where, pool.Subnet)
					}
					prefix = p.Masked()
					havePrefix = true
				}

				// Address range: parse + family + containment + order.
				parseBound := func(leaf, raw string) (netip.Addr, error) {
					addr, err := netip.ParseAddr(raw)
					if err != nil {
						return netip.Addr{}, fmt.Errorf("%s %s %q is not a valid IP address", where, leaf, raw)
					}
					if wantV6 && !addr.Is6() {
						return netip.Addr{}, fmt.Errorf("%s %s %q is not an IPv6 address (required under dhcpv6-local-server)", where, leaf, raw)
					}
					if !wantV6 && !addr.Is4() {
						return netip.Addr{}, fmt.Errorf("%s %s %q is not an IPv4 address (required under dhcp-local-server)", where, leaf, raw)
					}
					if havePrefix && !prefix.Contains(addr) {
						return netip.Addr{}, fmt.Errorf("%s %s %q is outside the pool subnet %s (Kea refuses a pool outside its subnet and stops serving every pool on the node)", where, leaf, raw, pool.Subnet)
					}
					return addr, nil
				}
				var low, high netip.Addr
				haveLow, haveHigh := false, false
				if pool.RangeLow != "" {
					a, err := parseBound("address-range low", pool.RangeLow)
					if err != nil {
						return err
					}
					low, haveLow = a, true
				}
				if pool.RangeHigh != "" {
					a, err := parseBound("address-range high", pool.RangeHigh)
					if err != nil {
						return err
					}
					high, haveHigh = a, true
				}
				if haveLow && haveHigh && low.Compare(high) > 0 {
					return fmt.Errorf("%s address-range low %q is greater than address-range high %q (Kea refuses an inverted pool and stops serving every pool on the node)", where, pool.RangeLow, pool.RangeHigh)
				}
				// #15691: a one-sided range renders NO Kea pool (the
				// generators require both bounds), so the bound the
				// operator committed would silently serve nothing.
				// Refuse it at commit instead of letting it commit
				// clean and take effect only when its sibling is
				// later added.
				if haveLow != haveHigh {
					return fmt.Errorf("%s address-range requires both low and high bounds (only one is set; Kea renders no pool for a one-sided range, so the configured bound would silently serve nothing)", where)
				}

				// Router: v4 `routers` option only; the v6 renderer
				// emits no router option, so the leaf is inert there.
				if !wantV6 && pool.Router != "" {
					addr, err := netip.ParseAddr(pool.Router)
					if err != nil {
						return fmt.Errorf("%s router %q is not a valid IP address", where, pool.Router)
					}
					if !addr.Is4() {
						return fmt.Errorf("%s router %q is not an IPv4 address (required under dhcp-local-server)", where, pool.Router)
					}
				}

				// DNS servers: every element, parse + family.
				for _, dns := range pool.DNSServers {
					addr, err := netip.ParseAddr(dns)
					if err != nil {
						return fmt.Errorf("%s dns-server %q is not a valid IP address", where, dns)
					}
					if wantV6 && !addr.Is6() {
						return fmt.Errorf("%s dns-server %q is not an %s address (required under %s)", where, dns, addrFamily, server)
					}
					if !wantV6 && !addr.Is4() {
						return fmt.Errorf("%s dns-server %q is not an %s address (required under %s)", where, dns, addrFamily, server)
					}
				}
			}
		}
		return nil
	}
	if err := check(cfg.System.DHCPServer.DHCPLocalServer, "dhcp-local-server", false); err != nil {
		return err
	}
	return check(cfg.System.DHCPServer.DHCPv6LocalServer, "dhcpv6-local-server", true)
}
