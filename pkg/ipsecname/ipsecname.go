// Package ipsecname derives the swanctl SA names xpf renders for an IPsec VPN (#9624): its
// connection name and its child SA section names.
//
// It is the ONE derivation shared by the renderer (pkg/ipsec effectiveTrafficSelectors) and the
// commit-time SA-name collision gate (pkg/config), which cannot import pkg/ipsec. With both
// calling the same functions, what commit checks is what the renderer emits by construction.
package ipsecname

import (
	"fmt"
	"hash/fnv"
	"sort"

	"github.com/psaab/xpf/pkg/rendersafe"
)

// SwanctlValue is the render-side spelling of a name written into swanctl: C0 controls and DEL
// replaced by a space (#6469). The renderer runs every connection and child name through it.
func SwanctlValue(s string) string {
	return rendersafe.ReplaceControlBytes(s, ' ')
}

// ChildBase maps a traffic-selector name onto swanctl's child-section alphabet: every rune
// outside [A-Za-z0-9._-] becomes '-', and an empty result becomes "traffic-selector".
func ChildBase(name string) string {
	if name == "" {
		return "traffic-selector"
	}
	b := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.':
			b = append(b, r)
		default:
			b = append(b, '-')
		}
	}
	if len(b) == 0 {
		return "traffic-selector"
	}
	return string(b)
}

// Disambiguator returns a short, stable hash of an ORIGINAL selector name, used to make colliding
// child bases injective within one VPN (#5122). It is a deterministic pure function of the input
// (fnv-1a 64-bit, low 32 bits as 8 hex chars), so the same config renders the same names on every
// node, a prerequisite for HA config-sync and idempotent commits.
func Disambiguator(original string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(original))
	return fmt.Sprintf("%08x", uint32(h.Sum64()))
}

// ChildNames returns the child SA section name each traffic selector of VPN vpn renders as, keyed
// by selector name: `<vpn>-<base>`. Two selectors of the SAME VPN whose bases collide (#5122)
// each get `-<Disambiguator(original)>` appended, extended with "x" until unique; bases that do
// not collide are reserved first and never change. The result depends only on the names, not on
// the order they are passed in. It returns nil for a VPN with no selector, which renders a single
// child named vpn itself. The names are NOT yet SwanctlValue-spelled, matching the renderer.
//
// Uniqueness is guaranteed only WITHIN one VPN. Two VPNs can still render the same name (#9624),
// which is what the commit gate built on SANames rejects.
func ChildNames(vpn string, selectors []string) map[string]string {
	if len(selectors) == 0 {
		return nil
	}
	names := append([]string(nil), selectors...)
	sort.Strings(names)

	bases := make([]string, len(names))
	counts := make(map[string]int, len(names))
	for i, name := range names {
		bases[i] = ChildBase(name)
		counts[bases[i]]++
	}
	used := make(map[string]bool, len(names))
	for i := range names {
		if counts[bases[i]] == 1 {
			used[bases[i]] = true
		}
	}
	out := make(map[string]string, len(names))
	for i, name := range names {
		child := bases[i]
		if counts[bases[i]] > 1 {
			child = bases[i] + "-" + Disambiguator(name)
			for used[child] {
				child += "x"
			}
			used[child] = true
		}
		out[name] = vpn + "-" + child
	}
	return out
}

// SANames returns every SA name VPN vpn renders, spelled as swanctl sees them: its connection name
// and each child name, deduplicated and sorted. A VPN with no selector renders its connection and
// its single child under the same name, so it contributes that one name.
func SANames(vpn string, selectors []string) []string {
	set := map[string]bool{SwanctlValue(vpn): true}
	for _, child := range ChildNames(vpn, selectors) {
		set[SwanctlValue(child)] = true
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
