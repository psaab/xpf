package config

import (
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
)

// IPsecPSKIdentityConflict describes a peer-only selector collision between
// distinct PSK connections, or a mixed hostname/IP endpoint list that cannot
// scope one PSK to every dial target without an explicit peer identity.
// AffectedVPNs is the complete set of VPN members of the involved connection
// groups so a tolerant renderer can fail closed without dropping siblings.
type IPsecPSKIdentityConflict struct {
	VPN          string
	OtherVPN     string
	Gateway      string
	OtherGateway string
	Identity     string
	Kind         string
	AffectedVPNs []string
}

type ipsecPSKIdentityGroup struct {
	key           string
	gateway       string
	members       []string
	psks          map[string]struct{}
	peerSelectors map[string]string
	localIdentity string
	mixedHostname string
}

// IPsecPSKIdentityConflicts finds cross-connection peer-identity collisions
// that would make strongSwan enumerate one PSK for another connection. The
// selectors mirror the renderer: explicit remote-identity, dynamic-hostname
// identity, or concrete IP gateway addresses. Configured local-identity is
// checked only against another connection's peer selector; local identities
// are never added to secret owners. Equal effective PSK sets under the same
// identity are one credential repeated, not a cross-key collision.
//
// Only VPN-referenced PSK connections with an effective key participate.
// VPNs sharing one named gateway are one IKE connection and are grouped
// before comparison, matching the renderer's gateway fold.
func IPsecPSKIdentityConflicts(ipsec *IPsecConfig) []IPsecPSKIdentityConflict {
	if ipsec == nil {
		return nil
	}

	groupsByKey := make(map[string]*ipsecPSKIdentityGroup)
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
		gw := ipsec.Gateways[vpn.Gateway]
		if !ipsecVPNAuthNeedsPSK(ipsec, gw) {
			continue
		}
		psk := ipsecVPNEffPSK(ipsec, vpn, gw)
		if psk == "" {
			continue
		}
		if ipsecVPNPSKIsHex(ipsec, vpn, gw) {
			if decoded, err := hex.DecodeString(psk); err == nil {
				psk = string(decoded)
			} else {
				psk = "invalid-hex:" + psk
			}
		}
		fingerprint := psk

		key := "vpn:" + name
		if gw != nil {
			key = "gateway:" + vpn.Gateway
		}
		group := groupsByKey[key]
		if group == nil {
			group = &ipsecPSKIdentityGroup{
				key:           key,
				gateway:       vpn.Gateway,
				psks:          make(map[string]struct{}),
				peerSelectors: make(map[string]string),
			}
			groupsByKey[key] = group
		}
		group.members = append(group.members, name)
		group.psks[fingerprint] = struct{}{}

		endpointList := vpn.Gateway
		if gw != nil {
			endpointList = gw.Address
			if gw.LocalIDValue != "" {
				group.localIdentity, _ = ipsecIKEIdentityKey(gw.LocalIDType, gw.LocalIDValue)
			}
		}
		if mixedHostname, mixed := ipsecMixedHostnameAndIP(endpointList); mixed &&
			(gw == nil || (!hasDiscriminatingRemoteIdentity(gw) && gw.DynamicHostname == "")) {
			if group.mixedHostname == "" {
				group.mixedHostname = mixedHostname
			}
		}
		ipsecForEachPSKPeerIdentity(endpointList, gw, func(identity, rendered string) {
			group.peerSelectors[identity] = rendered
		})
	}

	keys := make([]string, 0, len(groupsByKey))
	for key := range groupsByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	groups := make([]*ipsecPSKIdentityGroup, 0, len(keys))
	for _, key := range keys {
		group := groupsByKey[key]
		sort.Strings(group.members)
		groups = append(groups, group)
	}

	var conflicts []IPsecPSKIdentityConflict
	for _, group := range groups {
		if group.mixedHostname == "" {
			continue
		}
		conflicts = append(conflicts, IPsecPSKIdentityConflict{
			VPN:          group.members[0],
			Gateway:      group.gateway,
			Identity:     group.mixedHostname,
			Kind:         "mixed-hostname-ip",
			AffectedVPNs: append([]string(nil), group.members...),
		})
	}

	for i, a := range groups {
		for _, b := range groups[i+1:] {
			if a.key == b.key || ipsecPSKSetsEqual(a.psks, b.psks) {
				continue
			}
			conflict := IPsecPSKIdentityConflict{}
			for _, identity := range ipsecSortedIdentityKeys(a.peerSelectors) {
				rendered := a.peerSelectors[identity]
				if _, ok := b.peerSelectors[identity]; ok {
					conflict = ipsecPSKIdentityConflict(a, b, rendered, "shared-peer-selector")
					break
				}
				if identity == b.localIdentity {
					conflict = ipsecPSKIdentityConflict(a, b, rendered, "peer-selector-is-other-local-identity")
					break
				}
			}
			if conflict.Kind == "" {
				for _, identity := range ipsecSortedIdentityKeys(b.peerSelectors) {
					rendered := b.peerSelectors[identity]
					if identity == a.localIdentity {
						conflict = ipsecPSKIdentityConflict(b, a, rendered, "peer-selector-is-other-local-identity")
						break
					}
				}
			}
			if conflict.Kind != "" {
				conflicts = append(conflicts, conflict)
			}
		}
	}
	return conflicts
}

func ipsecPSKIdentityConflict(a, b *ipsecPSKIdentityGroup, identity, kind string) IPsecPSKIdentityConflict {
	affected := make([]string, 0, len(a.members)+len(b.members))
	affected = append(affected, a.members...)
	affected = append(affected, b.members...)
	sort.Strings(affected)
	return IPsecPSKIdentityConflict{
		VPN:          a.members[0],
		OtherVPN:     b.members[0],
		Gateway:      a.gateway,
		OtherGateway: b.gateway,
		Identity:     identity,
		Kind:         kind,
		AffectedVPNs: affected,
	}
}

func ipsecSortedIdentityKeys(selectors map[string]string) []string {
	keys := make([]string, 0, len(selectors))
	for identity := range selectors {
		keys = append(keys, identity)
	}
	sort.Strings(keys)
	return keys
}

func ipsecPSKSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for psk := range a {
		if _, ok := b[psk]; !ok {
			return false
		}
	}
	return true
}

func ipsecVPNPSKIsHex(ipsec *IPsecConfig, vpn *IPsecVPN, gw *IPsecGateway) bool {
	if vpn.PSK.Reveal() != "" {
		return vpn.PSKHex
	}
	if gw != nil {
		if policy, ok := ipsec.IKEPolicies[gw.IKEPolicy]; ok && policy != nil {
			return policy.PSKHex
		}
	}
	return false
}

// IPsecPSKPeerSelectors returns the ordered peer-only id selectors emitted
// for one secret. The collision validator and renderer use the same identity
// classification so selectors cannot drift between validation and output.
func IPsecPSKPeerSelectors(endpointList string, gw *IPsecGateway) []string {
	var selectors []string
	ipsecForEachPSKPeerIdentity(endpointList, gw, func(_, selector string) {
		selectors = append(selectors, selector)
	})
	return selectors
}

func ipsecForEachPSKPeerIdentity(endpointList string, gw *IPsecGateway, visit func(string, string)) {
	var seen map[string]bool
	add := func(identity, selector string) {
		if seen != nil && seen[identity] {
			return
		}
		if seen == nil {
			seen = make(map[string]bool)
		}
		seen[identity] = true
		visit(identity, selector)
	}
	addIdentity := func(idType, idValue string) {
		if idValue == "" || IsAnyIPsecRemoteIdentity(idType, idValue) {
			return
		}
		identity, selector := ipsecIKEIdentityKey(idType, idValue)
		add(identity, selector)
	}
	if gw != nil && hasDiscriminatingRemoteIdentity(gw) {
		addIdentity(gw.RemoteIDType, gw.RemoteIDValue)
		return
	}
	if gw != nil && gw.DynamicHostname != "" {
		addIdentity("hostname", gw.DynamicHostname)
		return
	}
	for _, endpoint := range SplitIPsecEndpointList(endpointList) {
		if IsAnyIPsecSelector(endpoint) {
			continue
		}
		addr, err := netip.ParseAddr(endpoint)
		if err != nil {
			continue
		}
		identity, _ := ipsecIKEIdentityKey("inet", addr.String())
		add(identity, strings.TrimSpace(endpoint))
	}
}

func ipsecIKEIdentityKey(idType, idValue string) (string, string) {
	value := strings.TrimSpace(idValue)
	switch idType {
	case "hostname", "fqdn":
		return "fqdn:" + strings.ToLower(value), "@" + idValue
	case "key-id":
		if decoded, err := hex.DecodeString(value); err == nil {
			return "key-id-hex:" + hex.EncodeToString(decoded), "@#" + idValue
		}
		return "key-id-literal:" + value, "@#" + idValue
	case "inet", "inet6":
		if addr, err := netip.ParseAddr(value); err == nil {
			if addr.Is4() {
				return "ipv4:" + addr.String(), idValue
			}
			return "ipv6:" + addr.String(), idValue
		}
	}
	return idType + ":" + value, idValue
}

func ipsecMixedHostnameAndIP(endpointList string) (string, bool) {
	hasIP := false
	hostname := ""
	for _, endpoint := range SplitIPsecEndpointList(endpointList) {
		if IsAnyIPsecSelector(endpoint) {
			continue
		}
		if _, err := netip.ParseAddr(endpoint); err == nil {
			hasIP = true
			continue
		}
		if IsUsableIPsecEndpoint(endpoint) && hostname == "" {
			hostname = endpoint
		}
	}
	return hostname, hasIP && hostname != ""
}
