package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ZoneMemberDetailLines renders the Address / DHCPv4 / DHCPv6 detail lines
// for ONE zone-bound interface reference (a ZoneConfig.Interfaces entry), in
// the exact spelling the local-CLI and gRPC-text `show security zones detail`
// renderers print under that member's header line. Callers own the
// `    <member>:` header and the newline after each returned line, so the two
// surfaces share ONE renderer for this block and cannot drift (#12898).
//
// A zone binds a LOGICAL member such as "ge-0/0/0.0" or "reth0.50", but
// cfg.Interfaces.Interfaces is keyed by the BASE name ("ge-0/0/0" / "reth0").
// Keying the member directly is a guaranteed miss, so a correctly addressed
// member rendered with NO address lines — the #5325 CLI defect, whose gRPC
// twin survived until #12898. The member is split, the BASE resolved, and —
// when a unit was named — only THAT unit's lines rendered.
//
// Semantics (the #5325 CLI contract, pinned by the tests beside this file):
//   - unit-qualified member "base.N": unit N's lines only, never a sibling
//     unit's — a .0 binding must not show .50's address or DHCP state.
//   - BARE member "base": ALL units' lines, byte-identical to the
//     pre-#5325/#12898 behavior, which was already correct for this form.
//   - non-numeric or empty suffix ("base.foo", "base."): no unit filter; the
//     base's units render, matching the CLI spelling for spelling.
//   - unresolved base: nil — the caller's header line stands alone. Such a
//     member is fail-CLOSED for traffic (the daemon brings an unresolved zone
//     member DOWN), and an empty block reads as unresolved, not as success.
//   - nil-safety: the lookups route through LookupInterface / RangeUnits
//     (#5886/#5910), so a present-but-nil stanza or unit slot admitted by the
//     tolerant load / HA config-sync path (#3494/#5068) is skipped, never
//     dereferenced.
//
// Split semantics are the #5325/#4908 display contract (first dot + Atoi),
// deliberately NOT SplitInterfaceUnitRef: the #9821 declared-precedence
// splitter resolves alias corners differently, and this renderer's contract
// is byte-parity with the local CLI, not declared-name resolution.
func ZoneMemberDetailLines(cfg *Config, member string) []string {
	base := member
	wantUnit := -1
	if parts := strings.SplitN(member, ".", 2); len(parts) == 2 {
		base = parts[0]
		if u, err := strconv.Atoi(parts[1]); err == nil {
			wantUnit = u
		}
	}
	ifc, ok := LookupInterface(cfg, base)
	if !ok {
		return nil
	}
	var lines []string
	RangeUnits(ifc, func(_ int, unit *InterfaceUnit) {
		if wantUnit >= 0 && unit.Number != wantUnit {
			return
		}
		for _, addr := range unit.Addresses {
			lines = append(lines, fmt.Sprintf("      Address: %s", addr))
		}
		if unit.DHCP {
			lines = append(lines, "      DHCPv4: enabled")
		}
		if unit.DHCPv6 {
			lines = append(lines, "      DHCPv6: enabled")
		}
	})
	return lines
}
