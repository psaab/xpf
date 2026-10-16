package config

import (
	"fmt"
	"sort"
)

// validateIPsecPSKPresenceStrict rejects an IPsec VPN whose effective IKE
// authentication is pre-shared-key but whose effective secret is empty
// (#14139, D5-06).
//
// The effective secret mirrors the renderer's resolution in pkg/ipsec
// (vpn.PSK, then the IKE-policy PSK reached via the gateway): when both
// are empty, the renderer used to emit a live `auth = psk` connection with
// no matching secrets{} entry, leaving strongSwan to consult another
// VPN's secret whose identities overlap. Commit / commit-check hard-reject
// the missing credential so the operator gets a diagnostic naming where
// to configure the key; the tolerant load / peer-sync path downgrades to
// a warning and the pkg/ipsec render belt skips the VPN, so an
// already-persisted or peer-synced config still boots without the
// uncredentialed connection loading.
//
// The effective authentication mirrors resolveIKESettings: it defaults to
// PSK, and when the gateway names an ike-policy with defined proposals,
// the proposals' authentication-method decides. A chain that does not
// resolve (undefined policy/proposal, or a proposal the renderer would
// skip) leaves the VPN to the existing chain/DH/proposal gates and the
// renderer's per-VPN skips, so this gate does not pile onto a VPN that
// is already rejected or skipped for another reason. Pubkey
// (certificate) VPNs have no PSK by design and are never rejected here.
func validateIPsecPSKPresenceStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
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
		if ipsecVPNAuthNeedsPSK(ipsec, gw) && ipsecVPNEffPSK(ipsec, vpn, gw) == "" {
			return fmt.Errorf("security ipsec vpn %q: authentication-method is "+
				"pre-shared-keys but no pre-shared key is configured (neither "+
				"`security ipsec vpn %s pre-shared-key` nor the ike-policy "+
				"pre-shared-key via its gateway); the tunnel would render "+
				"with no secret of its own and strongSwan could select "+
				"another VPN's secret — configure a pre-shared-key (#14139)",
				name, name)
		}
	}
	return nil
}

// ipsecVPNEffPSK mirrors the renderer's effective-PSK resolution:
// the VPN's own key wins, then the IKE-policy key via the gateway.
func ipsecVPNEffPSK(ipsec *IPsecConfig, vpn *IPsecVPN, gw *IPsecGateway) string {
	if s := vpn.PSK.Reveal(); s != "" {
		return s
	}
	if gw != nil {
		if pol, ok := ipsec.IKEPolicies[gw.IKEPolicy]; ok && pol != nil {
			return pol.PSK.Reveal()
		}
	}
	return ""
}

// ipsecVPNAuthNeedsPSK reports whether the VPN's effective IKE
// authentication is pre-shared-key, mirroring resolveIKESettings: PSK by
// default; when the gateway's ike-policy has defined proposals, their
// (renderer-checked) authentication-method decides. A policy whose
// proposals do not resolve leaves the auth undecided here (false), so
// the chain gates and renderer skips own that VPN's diagnosis.
func ipsecVPNAuthNeedsPSK(ipsec *IPsecConfig, gw *IPsecGateway) bool {
	if gw == nil || gw.IKEPolicy == "" {
		return true
	}
	pol, ok := ipsec.IKEPolicies[gw.IKEPolicy]
	if !ok || pol == nil || len(pol.Proposals) == 0 {
		// Legacy direct-proposal fallback uses the PSK default.
		if _, isLegacy := ipsec.Proposals[gw.IKEPolicy]; isLegacy {
			return true
		}
		return false
	}
	for _, ref := range pol.Proposals {
		prop, ok := ipsec.IKEProposals[ref]
		if !ok || prop == nil {
			return false
		}
		auth, known := ikeConnectionAuthMethod(prop.AuthMethod)
		if !known {
			return false
		}
		return auth == "psk"
	}
	return false
}
