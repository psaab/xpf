package config

import (
	"fmt"
	"sort"
)

// validateIPsecPSKQualifierStrict rejects an IPsec pre-shared-key whose
// qualifier is neither `ascii-text` nor a well-formed `hexadecimal`
// value (#15027, A16-04).
//
// Before this gate the IKE-policy compiler never read the qualifier
// (Keys[1]): `pre-shared-key hexadecimal <hex>` stored the hex digits
// as an ASCII secret and rendered them quoted (`secret = "6162..."`),
// so strongSwan derived the ASCII bytes and could never match a peer
// holding the same Junos hex key (whose raw bytes are the hex-decoded
// value); the block spelling `pre-shared-key { hexadecimal ...; }`
// dropped the key entirely; and ANY qualifier word (`bogus <key>`) was
// silently accepted as an ASCII key. The compiler now classifies the
// qualifier (classifyPSKQualifier): a valid hexadecimal key records
// PSKHex and renders as `secret = 0x<hex>`; an unknown qualifier or a
// malformed hex value records PSKQualifierInvalidSpec, which this gate
// turns into a hard error on strict commit / commit-check and a
// warning on the tolerant load / peer-sync path (the pkg/ipsec render
// belt independently skips a hex-flagged VPN whose value is not valid
// hex, so a warned config never renders the digits as ASCII). The
// diagnostic deliberately does NOT echo the recorded spec when it is
// a malformed hex VALUE (that is key material); it names the policy /
// VPN and the fix instead.
func validateIPsecPSKQualifierStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec

	polNames := make([]string, 0, len(ipsec.IKEPolicies))
	for name := range ipsec.IKEPolicies {
		polNames = append(polNames, name)
	}
	sort.Strings(polNames)
	for _, name := range polNames {
		pol := ipsec.IKEPolicies[name]
		if pol == nil || pol.PSKQualifierInvalidSpec == "" {
			continue
		}
		if pol.PSKHex {
			return fmt.Errorf("security ike policy %q: pre-shared-key "+
				"hexadecimal value is not valid hexadecimal (must be "+
				"non-empty, even-length hex digits) — fix the key or "+
				"use ascii-text (#15027)", name)
		}
		return fmt.Errorf("security ike policy %q: unsupported "+
			"pre-shared-key qualifier %q (must be ascii-text or "+
			"hexadecimal) — the qualifier was previously ignored and "+
			"the value treated as an ASCII secret (#15027)",
			name, pol.PSKQualifierInvalidSpec)
	}

	vpnNames := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, name := range vpnNames {
		vpn := ipsec.VPNs[name]
		if vpn == nil || vpn.PSKQualifierInvalidSpec == "" {
			continue
		}
		if vpn.PSKHex {
			return fmt.Errorf("security ipsec vpn %q: pre-shared-key "+
				"hexadecimal value is not valid hexadecimal (must be "+
				"non-empty, even-length hex digits) — fix the key or "+
				"use ascii-text (#15027)", name)
		}
		return fmt.Errorf("security ipsec vpn %q: unsupported "+
			"pre-shared-key qualifier %q (must be ascii-text or "+
			"hexadecimal) — the qualifier was previously ignored and "+
			"the value treated as an ASCII secret (#15027)",
			name, vpn.PSKQualifierInvalidSpec)
	}
	return nil
}
