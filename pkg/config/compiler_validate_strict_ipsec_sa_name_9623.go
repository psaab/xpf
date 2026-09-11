package config

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/termsafe"
)

// validateIPsecSANamesDisplaySafeStrict rejects an IPsec VPN name that swanctl and HA IPsec SA
// sync would spell differently (#9623).
//
// The VPN name reaches strongSwan RAW: it is the swanctl connection name, the child name of a
// VPN with no traffic selector, and the prefix of every other child
// (pkg/ipsec renderConfig / effectiveTrafficSelectors; the render-side sanitizeSwanctlValue
// replaces only C0 controls and DEL). But pkg/ipsec GetSAStatus display-sanitizes every
// SAStatus field once, at parse (#6584), with termsafe.SanitizeForDisplay, which ALSO escapes
// C1 control runes, the Unicode line and paragraph separators and invalid UTF-8 into literal
// backslash text. For such a name, ActiveConnectionNames publishes a different string over HA
// IPsec SA sync, and neither the peer's `swanctl --initiate --child` nor TerminateAllSAs'
// `swanctl --terminate --ike` matches it: on failover that tunnel is not re-initiated.
//
// termsafe.DisplaySafe is exactly the condition under which the display spelling equals the
// raw one, so it is the predicate here. C0 controls are also rejected by the #1798 free-text
// gate, which runs first. Traffic-selector names do not need the gate: sanitizeChildName maps
// every rune outside [A-Za-z0-9._-] to '-' before it reaches a child name.
func validateIPsecSANamesDisplaySafeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !termsafe.DisplaySafe(name) {
			return fmt.Errorf("security ipsec vpn %q: the name contains a control character, a "+
				"line or paragraph separator, or invalid UTF-8. It renders raw into swanctl, but "+
				"HA IPsec SA sync publishes a display-escaped copy, so on failover the peer could "+
				"never re-initiate or terminate this tunnel; rename the VPN", name)
		}
	}
	return nil
}
