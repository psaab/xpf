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
//     time via expandAddressRangeToCIDRCover (minimal CIDR cover, #16563)
//     into Address.ExpandedPrefixes;
//   - `wildcard-address <ip>/<wildcard-mask>` — Junos polarity (#16544):
//     the bits set in the wildcard mask are compared (care bits); a 0 bit
//     is ignored ("don't care"). The entry enforces the single prefix
//     formed by masking with the mask itself, with prefix length
//     popcount(mask), stored in ExpandedPrefixes. Non-contiguous masks
//     have no single CIDR equivalent and stay unimplemented.
//   - `dns-name <fqdn> [ipv4-only|ipv6-only]` — modelled in Address.DNSName /
//     DNSFamily; the current resolution lives in Address.DNSAddresses and is
//     refreshed by the daemon (RefreshDNSAddressBooks). A lookup FAILURE
//     keeps the last good answer (stale-while-error, #16595, flagged by
//     DNSLookupFailed); a successful lookup with no usable address is
//     match-none (fail-closed). Neither is an error.
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

// SetLookupAddressDNSNameForTest substitutes the dns-name resolver and
// returns a restore func. It exists for tests in OTHER packages (the
// daemon's periodic-refresh regression, #15933) that drive the resolver
// through RefreshDNSAddressBooks without network access.
func SetLookupAddressDNSNameForTest(fn func(fqdn string) ([]string, error)) func() {
	orig := lookupAddressDNSName
	lookupAddressDNSName = fn
	return func() { lookupAddressDNSName = orig }
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

// resolveDNSAddressEntry (re)resolves one dns-name entry in place (#16595).
// A lookup error keeps the previous DNSAddresses (stale-while-error) and
// sets DNSLookupFailed, so a transient resolver outage does not discard
// the last answer. A successful lookup — even one yielding no addresses,
// or none in the entry's family — replaces the answer and clears the
// flag: "name has no addresses" stays distinct from "resolver failed".
func resolveDNSAddressEntry(a *Address) {
	if a == nil || a.DNSName == "" {
		return
	}
	ips, err := lookupAddressDNSName(a.DNSName)
	if err != nil {
		a.DNSLookupFailed = true
		return
	}
	a.DNSLookupFailed = false
	a.DNSAddresses = dnsIPsToPrefixes(ips, a.DNSFamily)
}

// DNSEntryLookupFailed reports whether a (possibly nested) address-book
// name's closure contains a dns-name entry whose latest resolution FAILED
// (#16595). Such an entry is runtime-empty, not statically unresolvable:
// consumers that would otherwise treat an empty expansion as a static
// shape (the strict commit gate, the junos-host projection) must not let
// a resolver outage veto them. An entry that resolved successfully to
// zero addresses is NOT lookup-failed. Cycle-safe; mirrors the closure
// walks of the strict resolver.
func (ab *AddressBook) DNSEntryLookupFailed(name string) bool {
	if ab == nil {
		return false
	}
	seen := map[string]bool{}
	var walk func(ref string) bool
	walk = func(ref string) bool {
		if seen[ref] {
			return false
		}
		seen[ref] = true
		if a, ok := ab.Addresses[ref]; ok && a != nil {
			return a.DNSName != "" && a.DNSLookupFailed
		}
		if set, ok := ab.AddressSets[ref]; ok && set != nil {
			for _, m := range set.Addresses {
				if walk(m) {
					return true
				}
			}
			for _, m := range set.AddressSets {
				if walk(m) {
					return true
				}
			}
		}
		return false
	}
	return walk(name)
}

// RefreshDNSAddressBooks re-resolves every dns-name entry in the global,
// named, and zone-local books. Called at compile time and periodically by
// the daemon so a changed DNS answer republishes through the normal snapshot
// path.
//
// It MUTATES cfg in place: every Address.DNSAddresses field is replaced.
// cfg MUST NOT be a published active config (#15933): a config handed out
// by configstore (ActiveConfig / ActiveSnapshot) is shared with concurrent
// applies and readers, so the daemon refresh path resolves into a private
// copy (CloneForDNSRefresh) and publishes through the apply lock instead of
// writing into the shared generation. Compile-time callers own their cfg
// exclusively, as do callers already holding the daemon apply semaphore.
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

// CloneForDNSRefresh returns a copy of cfg that shares everything with the
// original EXCEPT the mutable DNS-resolution state: every dns-name Address
// (global, named, and zone-local books, including the folded
// zone-local/<zone>/<name> copies in the global book) is a fresh *Address
// with its own DNSAddresses slice. RefreshDNSAddressBooks may therefore
// write into the clone without touching the published generation it was
// cloned from (#15933).
//
// The address maps themselves are copied (not aliased) wherever a cloned
// entry is installed, so a writer cannot add/remove entries in the
// original's maps through the clone. Non-DNS entries are shared —
// nothing in the refresh path mutates them. Cost is O(zones + named
// books + all address-book entries), not a deep copy of the whole
// config.
func (cfg *Config) CloneForDNSRefresh() *Config {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.Security.AddressBook = cloneBookForDNSRefresh(cfg.Security.AddressBook)
	if cfg.Security.NamedAddressBooks != nil {
		named := make(map[string]*NamedAddressBook, len(cfg.Security.NamedAddressBooks))
		for name, nb := range cfg.Security.NamedAddressBooks {
			if nb == nil {
				named[name] = nil
				continue
			}
			cp := *nb
			if cloned := cloneBookForDNSRefresh(&nb.AddressBook); cloned != nil {
				cp.AddressBook = *cloned
			}
			named[name] = &cp
		}
		out.Security.NamedAddressBooks = named
	}
	if cfg.Security.Zones != nil {
		zones := make(map[string]*ZoneConfig, len(cfg.Security.Zones))
		for name, z := range cfg.Security.Zones {
			if z == nil {
				zones[name] = nil
				continue
			}
			cp := *z
			cp.AddressBook = cloneBookForDNSRefresh(z.AddressBook)
			zones[name] = &cp
		}
		out.Security.Zones = zones
	}
	return &out
}

func cloneBookForDNSRefresh(b *AddressBook) *AddressBook {
	if b == nil {
		return nil
	}
	out := *b
	if b.Addresses != nil {
		addrs := make(map[string]*Address, len(b.Addresses))
		for name, a := range b.Addresses {
			if a != nil && a.DNSName != "" {
				cp := *a
				cp.DNSAddresses = append([]string(nil), a.DNSAddresses...)
				a = &cp
			}
			addrs[name] = a
		}
		out.Addresses = addrs
	}
	return &out
}

// expandWildcardAddress converts `ip/wildcard-mask` (Junos polarity:
// set mask bits are compared, 0 bits are ignored; e.g.
// 10.1.2.3/255.255.255.0 enforces 10.1.2.0/24) to the single enforced
// prefix. Non-contiguous masks have no CIDR equivalent and are rejected
// so the caller records the form as unimplemented.
func expandWildcardAddress(spec string) (string, error) {
	ipStr, maskStr, ok := strings.Cut(spec, "/")
	if !ok {
		return "", fmt.Errorf("wildcard-address %q: missing wildcard mask", spec)
	}
	if strings.Contains(maskStr, "/") {
		return "", fmt.Errorf("wildcard-address %q: invalid address or mask", spec)
	}
	ip := net.ParseIP(ipStr)
	maskIP := net.ParseIP(maskStr)
	if ip == nil || maskIP == nil {
		return "", fmt.Errorf("wildcard-address %q: invalid address or mask", spec)
	}
	ip4, mask4 := ip.To4(), maskIP.To4()
	var ipB, maskB []byte
	switch {
	case ip4 != nil && mask4 != nil:
		ipB, maskB = ip4, mask4
	case ip4 != nil || mask4 != nil:
		return "", fmt.Errorf("wildcard-address %q: family mismatch", spec)
	default:
		ipB, maskB = ip.To16(), maskIP.To16()
		if ipB == nil || maskB == nil {
			return "", fmt.Errorf("wildcard-address %q: family mismatch", spec)
		}
	}
	network := make([]byte, len(ipB))
	for i := range maskB {
		network[i] = ipB[i] & maskB[i]
	}
	ones, maskBits := net.IPMask(maskB).Size()
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

// applyRangeAddress records a range-address expansion on addr: the
// minimal CIDR cover of [low, high] (#16563), at most 62 IPv4 / 254
// IPv6 prefixes for any range, so no host-count cap applies here —
// the NAT-pool per-host cap stays on expandAddressRange's NAT and
// proxy-arp callers only. Malformed ranges (bad endpoint, non-host
// mask, mixed family, reversed) are recorded in OversizedRange
// rather than failing compilation, so the tolerant path stays
// bootable (#8814 shape); strict commit rejects the record.
func applyRangeAddress(addr *Address, low, high string) {
	noteAddressFormConflict(addr, "range-address")
	if low == "" || high == "" {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, "range-address")
		return
	}
	addr.RangeSpec = low + " to " + high
	expanded, err := expandAddressRangeToCIDRCover(low, high)
	if err != nil {
		addr.OversizedRange = fmt.Sprintf("%s to %s: %v", low, high, err)
		return
	}
	addr.ExpandedPrefixes = expanded
}

// applyWildcardAddress records a wildcard-address expansion on addr.
func applyWildcardAddress(addr *Address, spec string) {
	noteAddressFormConflict(addr, "wildcard-address")
	if spec != "" {
		addr.WildcardSpec = spec
	}
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
