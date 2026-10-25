package config

import (
	"fmt"
	"net/netip"
	"sort"
)

// validateIPsecResponderIdentityStrict rejects a PSK-authenticated VPN
// whose peer cannot be scoped to a selector:
//
//   - its IKE gateway is responder-only (`dynamic` with no address,
//     rendering remote_addrs = %any) but carries neither a remote-identity
//     nor a `dynamic hostname` FQDN identity (#14591, Y09-04; #14590), or
//   - it has no gateway at all (vpn.Gateway == ""), so the renderer
//     resolves gw == nil and remote == "" (#15989): no gateway object
//     carries a peer address or identity to scope by, or
//   - its gateway (or inline endpoint) is addressed only by hostname
//     with no remote-identity (#16708): the hostname is a dial target,
//     never the identity the peer presents (#16680), so no peer selector
//     exists and the secret would be scoped by nothing (pre-#16708: by
//     the box-shared local owner alone, which every peer matches).
//
// Inline-endpoint VPNs (vpn.Gateway is a usable IP literal, gw == nil
// but remote != "") are NOT rejected: the peer address is the selector.
//
// A responder-only or gateway-less connection accepts an initiator from
// any address, so the only thing binding its PSK to the intended peer is
// the peer IKE identity: the renderer scopes the secret with an id
// selector for the configured remote-id (#3952) or the `dynamic
// hostname` FQDN (@FQDN, #14590). With neither there is nothing to scope
// by, the secret matches any peer (a lone "%any" selector), and
// strongSwan's key selection by the attacker-claimed IDi lets a holder
// of another VPN's PSK authenticate into this connection by claiming
// that site's identity. Commit / commit-check hard-reject the shape so
// the operator configures the identity / a gateway; the tolerant load /
// peer-sync path downgrades to a warning (lenientIPsecResponderIdentity,
// same warning prefix as #14591) and the pkg/ipsec render belt skips the
// VPN, so an already-persisted or peer-synced config still boots without
// the unscoped connection loading.
//
// Only VPN-referenced gateways are checked, sorted by VPN name for a
// deterministic first failure. Pubkey (certificate) VPNs authenticate by
// certificate rather than a shared secret and are never rejected here;
// the effective-auth determination mirrors validateIPsecPSKPresenceStrict.
func validateIPsecResponderIdentityStrict(cfg *Config) error {
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
		gw, ok := ipsec.Gateways[vpn.Gateway]
		// #15989: a VPN with no gateway (vpn.Gateway == "" ⇒ the
		// renderer resolves gw == nil, remote == "") has no peer
		// selector at all, so its PSK secret would carry only the
		// lone "%any" id. Inline endpoints are unaffected (below).
		if vpn.Gateway == "" {
			if ipsecVPNAuthNeedsPSK(ipsec, gw) {
				return fmt.Errorf("security ipsec vpn %q: no ike gateway "+
					"configured; its pre-shared key cannot be scoped to a "+
					"peer (rendered with no remote_addrs it would match any "+
					"peer identity, so a holder of another VPN's key could "+
					"authenticate into this tunnel by claiming that peer's "+
					"identity) — configure `security ike gateway <name>` "+
					"with an address, or set `security ipsec vpn %s ike "+
					"gateway <name-or-address>` (#15989)", name, name)
			}
			continue
		}
		if ok && gw != nil && gw.ResponderOnly && gw.RemoteIDValue == "" && gw.DynamicHostname == "" {
			if !ipsecVPNAuthNeedsPSK(ipsec, gw) {
				continue
			}
			return fmt.Errorf("security ipsec vpn %q: ike gateway %q is "+
				"responder-only (dynamic, remote_addrs = %%any) but has no "+
				"remote-identity or dynamic hostname; its pre-shared key "+
				"cannot be scoped to the peer, so a holder of another VPN's "+
				"key could authenticate into this tunnel by claiming that "+
				"peer's identity — configure `security ike gateway %s "+
				"remote-identity <type> <value>` (#14591)", name, vpn.Gateway, vpn.Gateway)
		}
		// #16708: a non-responder PSK VPN whose peer offers no identity
		// selector — a defined gateway addressed only by hostname (or an
		// inline hostname endpoint, gw == nil with a hostname remote) and
		// no remote-identity — has nothing to scope its secret by. The
		// hostname is a dial target, never the presented identity
		// (#16680); a mixed hostname+IP list keeps its IP selectors and
		// is unaffected, as are pubkey VPNs.
		if !ipsecVPNAuthNeedsPSK(ipsec, gw) {
			continue
		}
		if ok && gw != nil {
			if gw.ResponderOnly || gw.RemoteIDValue != "" || gw.DynamicHostname != "" || hasIPLiteralAddress(gw.Address) {
				continue
			}
			return fmt.Errorf("security ipsec vpn %q: ike gateway %q is "+
				"addressed by hostname %q with no remote-identity; its "+
				"pre-shared key cannot be scoped to the peer (a hostname "+
				"is a dial target, not the identity the peer presents), "+
				"so a holder of another VPN's key could authenticate "+
				"into this tunnel — configure `security ike gateway %s "+
				"remote-identity <type> <value>` or address the gateway "+
				"by IP literal (#16708)", name, vpn.Gateway, gw.Address, vpn.Gateway)
		}
		if !ok {
			// Inline endpoint (no gateway object): a usable IP literal
			// scopes the secret; a hostname alone does not.
			if hasIPLiteralAddress(vpn.Gateway) {
				continue
			}
			return fmt.Errorf("security ipsec vpn %q: inline gateway "+
				"endpoint %q is a hostname with no gateway object "+
				"carrying a remote-identity; its pre-shared key cannot "+
				"be scoped to the peer, so a holder of another VPN's "+
				"key could authenticate into this tunnel — configure "+
				"`security ike gateway <name>` with a remote-identity, "+
				"or use an IP-literal endpoint (#16708)", name, vpn.Gateway)
		}
	}
	return nil
}

// hasIPLiteralAddress reports whether a comma-separated endpoint list
// carries at least one IP-literal entry (the only entries that become
// PSK peer selectors, #16680/#16708).
func hasIPLiteralAddress(list string) bool {
	for _, addr := range SplitIPsecEndpointList(list) {
		if _, err := netip.ParseAddr(addr); err == nil {
			return true
		}
	}
	return false
}
