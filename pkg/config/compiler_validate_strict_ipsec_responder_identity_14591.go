package config

import (
	"fmt"
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
//     the box-shared local owner alone, which every peer matches), or
//   - any of those peer selectors is an ID_ANY spelling (#16845):
//     a gateway address / inline endpoint of 0.0.0.0 or :: (or a list
//     of only unspecified addresses), or a responder-only gateway whose
//     remote-identity is `inet 0.0.0.0` / `inet6 ::` / `*` / `%any`.
//     The empty-string checks below missed every non-empty wildcard:
//     IsAnyIPsecSelector / IsAnyIPsecRemoteIdentity /
//     HasDiscriminatingIPsecAddress are the shared discriminators.
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
		if ok && gw != nil && gw.ResponderOnly && !hasDiscriminatingRemoteIdentity(gw) && gw.DynamicHostname == "" {
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
		// (#16680); a mixed hostname+IP list needs a discriminating
		// remote-identity for every dial target (#17772); pubkey VPNs are
		// unaffected.
		if !ipsecVPNAuthNeedsPSK(ipsec, gw) {
			continue
		}
		if ok && gw != nil {
			if gw.ResponderOnly || hasDiscriminatingRemoteIdentity(gw) || gw.DynamicHostname != "" || HasDiscriminatingIPsecAddress(gw.Address) {
				continue
			}
			// #16845: an ID_ANY gateway address (0.0.0.0/::) or an
			// ID_ANY remote-identity (inet 0.0.0.0) discriminates no
			// peer either; name the actual defect when the authored
			// value is a wildcard rather than a hostname.
			if IsAnyIPsecSelector(firstEndpoint(gw.Address)) || IsAnyIPsecRemoteIdentity(gw.RemoteIDType, gw.RemoteIDValue) {
				return fmt.Errorf("security ipsec vpn %q: ike gateway %q "+
					"peer selector is an unspecified/wildcard address "+
					"or identity (0.0.0.0/::/%%any); its pre-shared key "+
					"cannot be scoped to the peer, so a holder of "+
					"another VPN's key could authenticate into this "+
					"tunnel — configure `security ike gateway %s "+
					"address <peer-ip>` or a discriminating "+
					"`remote-identity` (#16845)", name, vpn.Gateway, vpn.Gateway)
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
			if HasDiscriminatingIPsecAddress(vpn.Gateway) {
				continue
			}
			if IsAnyIPsecSelector(firstEndpoint(vpn.Gateway)) {
				return fmt.Errorf("security ipsec vpn %q: inline gateway "+
					"endpoint %q is an unspecified/wildcard address "+
					"(0.0.0.0/::/%%any); its pre-shared key cannot be "+
					"scoped to the peer, so a holder of another VPN's "+
					"key could authenticate into this tunnel — use a "+
					"peer IP-literal endpoint or configure `security "+
					"ike gateway <name>` with a discriminating "+
					"remote-identity (#16845)", name, vpn.Gateway)
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
	// #17772: peer-only selectors must not expose a different credential to
	// another connection. Compare complete effective peer selector sets
	// (including IP-address defaults) against configured local-identity or
	// the default local IP identity; diagnostics never expose PSK values.
	if conflicts := IPsecPSKIdentityConflicts(ipsec); len(conflicts) != 0 {
		c := conflicts[0]
		if c.Kind == "mixed-hostname-ip" {
			return fmt.Errorf("security ipsec vpn %q: ike gateway %q has mixed hostname/IP endpoints including %q but no discriminating remote-identity; peer-only PSK selectors cover IP literals, not the hostname's resolved peer identity — configure `security ike gateway %s remote-identity <type> <value>` (#17772)", c.VPN, c.Gateway, c.Identity, c.Gateway)
		}
		if c.Kind == "peer-selector-is-other-local-identity" {
			return fmt.Errorf("security ipsec vpn %q and %q: peer-only PSK selector %q on ike gateway %q equals the effective local identity %q on ike gateway %q (strongSwan: %s); distinct PSK connections with different effective keys must not share an owner identity — configure distinct gateway identities or local addresses (#17772)", c.VPN, c.OtherVPN, c.Identity, c.Gateway, c.OtherIdentity, c.OtherGateway, c.Rule)
		}
		return fmt.Errorf("security ipsec vpn %q and %q: peer-only PSK selector %q on ike gateway %q and selector %q on ike gateway %q are the same strongSwan identity (%s) but use different effective keys; configure distinct remote-identity values so each PSK is selectable only for its intended peer (#17772)", c.VPN, c.OtherVPN, c.Identity, c.Gateway, c.OtherIdentity, c.OtherGateway, c.Rule)
	}
	return nil
}

// hasDiscriminatingRemoteIdentity reports whether gw carries a
// remote-identity that discriminates a peer (#16845): present and not
// an ID_ANY spelling. An `inet 0.0.0.0` / `inet6 ::` / `*` / `%any`
// remote-identity scopes the secret to ID_ANY, exactly like no
// remote-identity at all.
func hasDiscriminatingRemoteIdentity(gw *IPsecGateway) bool {
	if gw == nil || gw.RemoteIDValue == "" {
		return false
	}
	return !IsAnyIPsecRemoteIdentity(gw.RemoteIDType, gw.RemoteIDValue)
}

// firstEndpoint returns the first element of a comma-separated endpoint
// list ("" for an empty list), for defect naming in error messages.
func firstEndpoint(list string) string {
	if parts := SplitIPsecEndpointList(list); len(parts) > 0 {
		return parts[0]
	}
	return ""
}
