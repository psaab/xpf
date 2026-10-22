// Source NAT pool address-set resolution for the operational
// `show/clear security flow session source-nat-pool <name>` filter
// (#1827 PR-3). The filter identifies sessions whose TRANSLATED source
// address was allocated from a named pool — the operator path for
// invalidating sessions pinned to a failed uplink after an
// ip-monitoring transition.
package config

import "net"

// SourceNATPoolNets resolves a named source NAT pool to the networks
// its translated addresses occupy. Pool address entries are CIDRs or
// bare IPs (compile time pre-expands "low to high" ranges into bare
// IPs); bare IPs become host routes. The second return is false when
// the pool does not exist, letting callers distinguish "unknown pool"
// (an operator error) from "pool with no parseable addresses" — an
// unknown pool must never degrade a filtered session-clear into an
// unfiltered clear-all.
func SourceNATPoolNets(nat *NATConfig, poolName string) ([]*net.IPNet, bool) {
	if nat == nil || nat.SourcePools == nil {
		return nil, false
	}
	pool, ok := nat.SourcePools[poolName]
	if !ok || pool == nil {
		return nil, false
	}
	addrs := make([]string, 0, len(pool.Addresses)+1)
	if pool.Address != "" {
		addrs = append(addrs, pool.Address)
	}
	addrs = append(addrs, pool.Addresses...)
	nets := make([]*net.IPNet, 0, len(addrs))
	for _, a := range addrs {
		if n := parsePoolAddr(a); n != nil {
			nets = append(nets, n)
		}
	}
	return nets, true
}

// parsePoolAddr parses a pool address entry — a CIDR or a bare IP
// (bare IPs become /32 or /128 host networks). Returns nil for
// unparseable entries.
//
// #15943 (H11-04): the prefix length is normalized first
// (NormalizeNATPrefixLen, #7481), so a tolerated spelling the NAT grammar
// accepts and installs (`/+32`, `/024`, `/0024`) parses to the same network
// as its canonical form instead of returning nil and silently skipping
// every overlap gate that consumes this helper. Without the normalization
// a canonical-equivalent overlap escaped admission while the dataplane
// installed the address.
func parsePoolAddr(addr string) *net.IPNet {
	addr = NormalizeNATPrefixLen(addr)
	if _, n, err := net.ParseCIDR(addr); err == nil {
		return n
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// IPInNets reports whether ip is contained in any of nets.
func IPInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
