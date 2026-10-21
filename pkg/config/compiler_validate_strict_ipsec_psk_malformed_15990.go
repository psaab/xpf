package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateIPsecPSKJunos9Strict rejects an IPsec pre-shared-key that
// carries a malformed Junos `$9$` value (#15990).
//
// Before this gate a `$9$` PSK was never decoded at compile (IKE keys
// decode only at render, in pkg/ipsec normalizePSK), so ANY `$9$`
// value — garbage, or `$9$i`/`$9$!` which decode to zero bytes —
// committed strict-clean as long as the encoded form was non-empty;
// the render belt then either skipped the VPN (malformed) or, for the
// decode-to-empty shapes, stored decodedPSKs[name]="" and emitted
// `secret = ""`. The #14139 presence gate now tests the DECODED form
// (ipsecVPNEffPSK), so a decode-to-empty key is refused there as an
// absent credential; this gate refuses every OTHER malformed `$9$`
// shape by name, so the operator learns at commit — not from a skipped
// tunnel at apply — that the key must be re-entered. Hexadecimal keys
// (PSKHex) are not `$9$` values and are skipped; a `$9$`-looking hex
// value is caught by the #15027 qualifier gate instead.
//
// Strict on commit / commit-check; lenient on load / peer-sync (warn,
// blob kept — the pkg/ipsec render belt skips the VPN, so a warned
// config never emits a connection with an undecodable or empty
// secret). The diagnostic never echoes the key.
func validateIPsecPSKJunos9Strict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec

	malformed := func(s Secret, hex bool) bool {
		if hex {
			return false
		}
		raw := s.Reveal()
		if !strings.HasPrefix(raw, junos9Magic) {
			return false
		}
		_, err := DecodeJunos9Secret(raw)
		return err != nil
	}

	polNames := make([]string, 0, len(ipsec.IKEPolicies))
	for name := range ipsec.IKEPolicies {
		polNames = append(polNames, name)
	}
	sort.Strings(polNames)
	for _, name := range polNames {
		pol := ipsec.IKEPolicies[name]
		if pol == nil {
			continue
		}
		if malformed(pol.PSK, pol.PSKHex) {
			return fmt.Errorf("security ike policy %q: pre-shared-key "+
				"is a malformed Junos $9$ secret that cannot be decoded "+
				"(including one that decodes to an empty secret) — "+
				"re-enter the key in plaintext or as a valid $9$ value (#15990)", name)
		}
	}

	vpnNames := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, name := range vpnNames {
		vpn := ipsec.VPNs[name]
		if vpn == nil {
			continue
		}
		if malformed(vpn.PSK, vpn.PSKHex) {
			return fmt.Errorf("security ipsec vpn %q: pre-shared-key "+
				"is a malformed Junos $9$ secret that cannot be decoded "+
				"(including one that decodes to an empty secret) — "+
				"re-enter the key in plaintext or as a valid $9$ value (#15990)", name)
		}
	}
	return nil
}
