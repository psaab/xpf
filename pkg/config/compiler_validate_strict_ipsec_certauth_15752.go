package config

import (
	"fmt"
	"sort"
)

// validateIPsecCertAuthStrict enforces the #15752 (G18-02/03) cert-auth
// invariants the schema cannot express:
//
//   - a pubkey-authenticated VPN (effective auth via the gateway's
//     ike-policy proposals, mirroring ipsecVPNAuthNeedsPSK) must carry an
//     effective local certificate — gateway LocalCertificate, else the
//     ike-policy's (EffectiveLocalCertificate). A credential-less pubkey
//     connection renders `auth = pubkey` with no certs and charon picks
//     any loaded cert or fails IKE_AUTH.
//   - gateway local/remote-identity types must be known Junos types
//     (ikeIdentityTypes15752); an unknown type renders verbatim into
//     swanctl id and is parsed as IP/FQDN, not the intended identity.
//
// Returns (isCert, err) pairs internally; the exported shape mirrors the
// sibling gates: strict error, lenient warning at the call site, and the
// pkg/ipsec render belt skips a cert-less pubkey VPN.
func validateIPsecCertAuthStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
	// Identity-type gate (gateway sorted for determinism).
	gwNames := make([]string, 0, len(ipsec.Gateways))
	for name := range ipsec.Gateways {
		gwNames = append(gwNames, name)
	}
	sort.Strings(gwNames)
	for _, name := range gwNames {
		gw := ipsec.Gateways[name]
		if gw == nil {
			continue
		}
		for _, side := range []struct{ leaf, typ string }{
			{"local-identity", gw.LocalIDType},
			{"remote-identity", gw.RemoteIDType},
		} {
			if side.typ != "" && !ikeIdentityTypes15752[side.typ] {
				return fmt.Errorf("security ike gateway %q %s: unknown identity "+
					"type %q (want hostname, inet, inet6, key-id, "+
					"distinguished-name, or user-at-hostname) — the value "+
					"would render verbatim as a strongSwan IP/FQDN identity "+
					"(#15752)", name, side.leaf, side.typ)
			}
		}
	}
	// Pubkey-needs-cert gate (VPN sorted for determinism).
	names := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vpn := ipsec.VPNs[name]
		if vpn == nil {
			continue
		}
		var gw *IPsecGateway
		if g, ok := ipsec.Gateways[vpn.Gateway]; ok {
			gw = g
		}
		if ipsecVPNAuthNeedsPSK(ipsec, gw) {
			continue // psk (or undecided chain): PSK gates own it
		}
		// Distinguish "decided pubkey" from "undecided chain": only reject
		// when a resolved proposal actually says pubkey. NeedsPSK already
		// returns false for undecided; re-check resolved auth here.
		if !ipsecVPNAuthIsPubkey15752(ipsec, gw) {
			continue
		}
		if EffectiveLocalCertificate(ipsec, vpn, gw) == "" {
			return fmt.Errorf("security ipsec vpn %q: authentication-method is "+
				"public-key (pubkey) but no local-certificate is configured "+
				"(neither `security ike gateway %s local-certificate` nor "+
				"`security ike policy <pol> local-certificate` via its "+
				"gateway); the tunnel would render auth = pubkey with no "+
				"certs and strongSwan could select any loaded certificate "+
				"— configure a local-certificate (#15752)", name, vpn.Gateway)
		}
	}
	return nil
}

// ipsecVPNAuthIsPubkey15752 reports whether any resolved IKE proposal for
// the VPN's gateway chain carries a pubkey auth method. Mirrors the
// ipsecVPNAuthNeedsPSK walk (dangling entries skipped, #14689).
func ipsecVPNAuthIsPubkey15752(ipsec *IPsecConfig, gw *IPsecGateway) bool {
	if gw == nil || gw.IKEPolicy == "" {
		return false
	}
	pol, ok := ipsec.IKEPolicies[gw.IKEPolicy]
	if !ok || pol == nil {
		return false
	}
	for _, ref := range pol.Proposals {
		prop, ok := ipsec.IKEProposals[ref]
		if !ok || prop == nil {
			continue
		}
		if auth, known := ikeConnectionAuthMethod(prop.AuthMethod); known && auth == "pubkey" {
			return true
		}
	}
	return false
}
