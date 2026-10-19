package config

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// #15673 — native address-book value forms.
//
// Junos `address <name>` takes exactly one value form:
//   - a prefix (IP/CIDR) — stored in Address.Value (pre-existing);
//   - `range-address <low> { to { <high>; } }` (hierarchical) or
//     `range-address <low> to <high>` (flat) — expanded natively at compile
//     time via expandAddressRange into Address.ExpandedPrefixes;
//   - `wildcard-address <ip>/<wildcard-mask>` — the bits set in the wildcard
//     mask are "don't care"; the entry enforces the single prefix formed by
//     clearing those bits, with prefix length 32-popcount(wildcard) (v4) or
//     128-popcount (v6), stored in ExpandedPrefixes;
//   - `dns-name <fqdn> [ipv4-only|ipv6-only]` — modelled in Address.DNSName /
//     DNSFamily; the current resolution lives in Address.DNSAddresses and is
//     refreshed by the daemon (RefreshDNSAddressBooks). An unresolvable name
//     yields no usable prefixes (match-none, fail-closed), never an error.
//
// Unknown/future forms and any entry mixing a prefix with another form stay
// in UnimplementedForms (#9524) and are unusable.

// lookupAddressDNSName resolves fqdn to IP strings. It is a package var so
// tests can substitute a deterministic resolver without network access.
var lookupAddressDNSName = func(fqdn string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			out = append(out, a.IP.String())
		}
	}
	return out, nil
}

// dnsIPsToPrefixes converts resolved IPs to /32 or /128 CIDRs, applying the
// family filter, deduplicated and sorted for determinism.
func dnsIPsToPrefixes(ips []string, family string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		is4 := ip.To4() != nil
		if family == "ipv4-only" && !is4 {
			continue
		}
		if family == "ipv6-only" && is4 {
			continue
		}
		var p string
		if is4 {
			p = ip.To4().String() + "/32"
		} else {
			p = ip.String() + "/128"
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// resolveDNSAddressEntry (re)resolves one dns-name entry in place. Resolution
// failure leaves the entry with no usable prefixes (fail-closed).
func resolveDNSAddressEntry(a *Address) {
	if a == nil || a.DNSName == "" {
		return
	}
	ips, err := lookupAddressDNSName(a.DNSName)
	if err != nil {
		a.DNSAddresses = nil
		return
	}
	a.DNSAddresses = dnsIPsToPrefixes(ips, a.DNSFamily)
}

// RefreshDNSAddressBooks re-resolves every dns-name entry in the global and
// zone-local books. Called at compile time and periodically by the daemon so
// a changed DNS answer republishes through the normal snapshot path.
func RefreshDNSAddressBooks(cfg *Config) {
	if cfg == nil {
		return
	}
	refresh := func(b *AddressBook) {
		if b == nil {
			return
		}
		for _, a := range b.Addresses {
			resolveDNSAddressEntry(a)
		}
	}
	refresh(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			refresh(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			refresh(z.AddressBook)
		}
	}
}

// expandWildcardAddress converts `ip/wildcard-mask` (e.g.
// 10.1.2.3/255.0.255.0, where set mask bits are don't-care) to the single
// enforced prefix. Non-contiguous masks have no CIDR equivalent and are
// rejected so the caller records the form as unimplemented.
func expandWildcardAddress(spec string) (string, error) {
	ipStr, maskStr, ok := strings.Cut(spec, "/")
	if !ok {
		return "", fmt.Errorf("wildcard-address %q: missing wildcard mask", spec)
	}
	ip := net.ParseIP(ipStr)
	maskIP := net.ParseIP(maskStr)
	if ip == nil || maskIP == nil {
		return "", fmt.Errorf("wildcard-address %q: invalid address or mask", spec)
	}
	ip4, mask4 := ip.To4(), maskIP.To4()
	var ipB, maskB []byte
	if ip4 != nil && mask4 != nil {
		ipB, maskB = ip4, mask4
	} else {
		ipB, maskB = ip.To16(), maskIP.To16()
		if ipB == nil || maskB == nil {
			return "", fmt.Errorf("wildcard-address %q: family mismatch", spec)
		}
	}
	network := make([]byte, len(ipB))
	care := make([]byte, len(maskB))
	for i := range maskB {
		care[i] = ^maskB[i]
		network[i] = ipB[i] & care[i]
	}
	ones, maskBits := net.IPMask(care).Size()
	if maskBits == 0 {
		return "", fmt.Errorf("wildcard-address %q: non-contiguous wildcard mask has no CIDR equivalent", spec)
	}
	cidr := fmt.Sprintf("%s/%d", net.IP(network).String(), ones)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", fmt.Errorf("wildcard-address %q: %w", spec, err)
	}
	return cidr, nil
}

func popcountByte(b byte) int {
	n := 0
	for b != 0 {
		n += int(b & 1)
		b >>= 1
	}
	return n
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isAllOnes(b []byte) bool {
	for _, v := range b {
		if v != 0xff {
			return false
		}
	}
	return true
}

// applyRangeAddress records a range-address expansion on addr. Oversized or
// malformed ranges are recorded (OversizedRange / UnimplementedForms) rather
// than failing compilation, so the tolerant path stays bootable (#8814 shape).
func applyRangeAddress(addr *Address, low, high string) {
	noteAddressFormConflict(addr, "range-address")
	if low == "" || high == "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "range-address")
		return
	}
	expanded, err := expandAddressRange(low, high)
	if err != nil {
		addr.OversizedRange = fmt.Sprintf("%s to %s: %v", low, high, err)
		return
	}
	addr.ExpandedPrefixes = expanded
}

// applyWildcardAddress records a wildcard-address expansion on addr.
func applyWildcardAddress(addr *Address, spec string) {
	noteAddressFormConflict(addr, "wildcard-address")
	prefix, err := expandWildcardAddress(spec)
	if err != nil {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "wildcard-address")
		return
	}
	addr.ExpandedPrefixes = []string{prefix}
}

// applyDNSName records a dns-name form on addr and resolves it once.
func applyDNSName(addr *Address, fqdn, family string) {
	noteAddressFormConflict(addr, "dns-name")
	if fqdn == "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "dns-name")
		return
	}
	addr.DNSName = fqdn
	addr.DNSFamily = family
	resolveDNSAddressEntry(addr)
}

// noteAddressFormConflict records that a value form was authored on an
// entry already carrying a value (prefix, expansion, or dns-name). Junos
// takes exactly one form, so the combination is unimplemented as authored
// and must fail closed (#9524/#15673).
func noteAddressFormConflict(addr *Address, form string) {
	if addr.Value != "" || len(addr.ExpandedPrefixes) > 0 || addr.DNSName != "" || addr.OversizedRange != "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, form)
	}
}

// rangeKeys extracts (low, high) from a hierarchical range-address child's
// keys/children: `range-address <low> { to { <high>; } }` arrives as a node
// Keys=[range-address low] with child [to] -> child [high], or packed
// Keys=[range-address low to high].
func rangeKeys(sub *Node) (low, high string) {
	if len(sub.Keys) >= 2 {
		low = sub.Keys[1]
	}
	if len(sub.Keys) >= 4 && sub.Keys[2] == "to" {
		high = sub.Keys[3]
		return low, high
	}
	for _, c := range sub.Children {
		if c.Name() == "to" {
			if len(c.Keys) >= 2 {
				high = c.Keys[1]
			}
			for _, cc := range c.Children {
				if len(cc.Keys) >= 1 {
					high = cc.Keys[0]
				}
			}
		} else if len(c.Keys) >= 1 && high == "" {
			high = c.Keys[0]
		}
	}
	return low, high
}

// dnsKeys extracts (fqdn, family) from a dns-name node: flat
// Keys=[... dns-name fqdn [ipv4-only|ipv6-only]] tail, hierarchical child
// Keys=[dns-name fqdn] with optional [ipv4-only]/[ipv6-only] children or
// packed keys.
func dnsKeys(keys []string, children []*Node) (fqdn, family string) {
	if len(keys) >= 1 {
		fqdn = keys[0]
	}
	for _, k := range keys[1:] {
		if k == "ipv4-only" || k == "ipv6-only" {
			family = k
		}
	}
	for _, c := range children {
		n := c.Name()
		if n == "ipv4-only" || n == "ipv6-only" {
			family = n
		}
		if len(c.Keys) >= 1 && (c.Keys[0] == "ipv4-only" || c.Keys[0] == "ipv6-only") {
			family = c.Keys[0]
		}
	}
	return fqdn, family
}
