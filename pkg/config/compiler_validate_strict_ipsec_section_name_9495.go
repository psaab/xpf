package config

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/ipsecname"
)

// validateIPsecSectionNamesStrict rejects an IPsec VPN name outside the swanctl section-name
// allowlist (#9495).
//
// The name is written raw as a swanctl section header: the connection, the child of a VPN with
// no traffic selector, the prefix of every other child, and the `ike-<name>` secret. Measured on
// the pinned strongSwan (docs/log/9495.md):
//   - `{`, `}`, `#`, `=`, `,`, `"`, `.` or whitespace makes the WHOLE file unparsable, so every
//     tunnel is lost, not only this one;
//   - `x { children { p { mode = transport } } } y` loads two connections, and the injected
//     setting is applied;
//   - `:` loads the tunnel under a different name (section inheritance);
//   - `%` and non-ASCII are refused.
//
// The rule is ipsecname.SectionSafe, an allowlist of ASCII letters, digits, '-' and '_'. The
// render belt in pkg/ipsec skips a name that still reaches it (ipsecname.SectionBreaking).
// Traffic-selector names need no gate here: ipsecname.ChildBase maps every other character,
// '.' included since #9495, to '-'.
func validateIPsecSectionNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ipsecname.SectionSafe(name) {
			continue
		}
		why := "contains a character outside letters, digits, '-' and '_'"
		if ipsecname.SectionBreaking(name) {
			why = "contains a character that breaks the swanctl section it is written into " +
				"(whitespace, '{', '}', '#', '=', ',', '\"', '.', '%', ':', a control byte or non-ASCII); " +
				"one such name can make strongSwan discard EVERY tunnel in the file, or inject settings into it"
		}
		return fmt.Errorf("security ipsec vpn %q: the name %s. It is written raw as a swanctl section "+
			"name; use only letters, digits, '-' and '_'", name, why)
	}
	return nil
}
