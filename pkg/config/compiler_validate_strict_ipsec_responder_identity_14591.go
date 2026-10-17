package config

import (
	"fmt"
	"sort"
)

// validateIPsecResponderIdentityStrict rejects a PSK-authenticated VPN
// whose IKE gateway is responder-only (`dynamic` with no address,
// rendering remote_addrs = %any) but carries neither a remote-identity
// nor a `dynamic hostname` FQDN identity (#14591, Y09-04; #14590).
//
// A responder-only connection accepts an initiator from any address, so
// the only thing binding its PSK to the intended peer is the peer IKE
// identity: the renderer scopes the secret with an id selector for the
// configured remote-id (#3952) or the `dynamic hostname` FQDN (@FQDN,
// #14590). With neither there is nothing to scope by, the secret matches
// any peer, and strongSwan's key selection by the attacker-claimed IDi
// lets a holder of another VPN's PSK authenticate into this connection
// by claiming that site's identity. Commit / commit-check hard-reject
// the shape so the operator configures the identity; the tolerant load
// / peer-sync path downgrades to a warning and the pkg/ipsec render
// belt skips the VPN, so an already-persisted or peer-synced config
// still boots without the unscoped connection loading.
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
		if !ok || gw == nil || !gw.ResponderOnly || gw.RemoteIDValue != "" || gw.DynamicHostname != "" {
			continue
		}
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
	return nil
}
