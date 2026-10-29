package config

import (
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
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
	key             string
	gateway         string
	members         []string
	psks            map[string]struct{}
	peerSelectors   map[string]string
	localIdentities map[string]struct{}
	mixedHostname   string
}

// IPsecPSKIdentityConflicts finds cross-connection peer-identity collisions
// that would make strongSwan enumerate one PSK for another connection. The
// selectors mirror the renderer: explicit remote-identity, dynamic-hostname
// identity, or concrete IP gateway addresses. Configured local-identity, or
// the effective local IP address when none is configured, is checked only
// against another connection's peer selector; local identities are never
// added to secret owners. Equal effective PSK sets under the same
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
				key:             key,
				gateway:         vpn.Gateway,
				psks:            make(map[string]struct{}),
				peerSelectors:   make(map[string]string),
				localIdentities: make(map[string]struct{}),
			}
			groupsByKey[key] = group
		}
		group.members = append(group.members, name)
		group.psks[fingerprint] = struct{}{}

		endpointList := vpn.Gateway
		if gw != nil {
			endpointList = gw.Address
		}
		if gw != nil && gw.LocalIDValue != "" {
			identity, _ := ipsecIKEIdentityKey(gw.LocalIDType, gw.LocalIDValue)
			group.localIdentities[identity] = struct{}{}
		} else {
			localAddress := vpn.LocalAddr
			if localAddress == "" && gw != nil {
				localAddress = gw.LocalAddress
			}
			for _, endpoint := range SplitIPsecEndpointList(localAddress) {
				addr, err := netip.ParseAddr(strings.TrimSpace(endpoint))
				if err != nil {
					continue
				}
				identity, _ := ipsecIKEIdentityKey("inet", addr.String())
				group.localIdentities[identity] = struct{}{}
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
				if _, ok := b.localIdentities[identity]; ok {
					conflict = ipsecPSKIdentityConflict(a, b, rendered, "peer-selector-is-other-local-identity")
					break
				}
			}
			if conflict.Kind == "" {
				for _, identity := range ipsecSortedIdentityKeys(b.peerSelectors) {
					rendered := b.peerSelectors[identity]
					if _, ok := a.localIdentities[identity]; ok {
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
	case "user-at-hostname", "email", "rfc822":
		// strongSwan renders all three aliases as one RFC822 identity. Its
		// domain compares case-insensitively, while the local part remains
		// case-sensitive.
		if at := strings.LastIndex(value, "@"); at >= 0 {
			return "rfc822:" + value[:at] + "@" + cases.Fold().String(value[at+1:]), idValue
		}
		return "rfc822:" + value, idValue
	case "key-id":
		// swanctl's @# spelling decodes valid even-length hex; otherwise
		// strongSwan compares the literal bytes. Canonicalize both forms
		// through those effective bytes, including odd-length hex as text.
		identityBytes := []byte(idValue)
		if decoded, err := hex.DecodeString(idValue); err == nil {
			identityBytes = decoded
		}
		return "key-id-bytes:" + hex.EncodeToString(identityBytes), "@#" + idValue
	case "distinguished-name":
		if canonical, ok := ipsecCanonicalDNIdentity(value); ok {
			return "distinguished-name:" + canonical, idValue
		}
		// Malformed DN syntax falls back to exact raw matching;
		// never guess a normalized identity from a partial parse.
		return "distinguished-name:" + idValue, idValue
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

func ipsecCanonicalDNIdentity(value string) (string, bool) {
	rdns, ok := splitIPsecDNComponents(value, ',')
	if !ok || len(rdns) == 0 {
		return "", false
	}
	canonicalRDNs := make([]string, 0, len(rdns))
	for _, rawRDN := range rdns {
		avas, ok := splitIPsecDNComponents(rawRDN, '+')
		if !ok || len(avas) == 0 {
			return "", false
		}
		canonicalAVAs := make([]string, 0, len(avas))
		for _, rawAVA := range avas {
			eq, ok := indexUnescapedIPsecDNByte(rawAVA, '=')
			if !ok || eq <= 0 {
				return "", false
			}
			attribute := canonicalIPsecDNAttribute(trimUnescapedIPsecDNPadding(rawAVA[:eq]))
			if attribute == "" {
				return "", false
			}
			rawValue := trimUnescapedIPsecDNPadding(rawAVA[eq+1:])
			decoded, ok := decodeIPsecDNValue(rawValue)
			if !ok {
				return "", false
			}
			if ipsecDNAttributeCaseIgnore(attribute) {
				decoded = cases.Fold().String(strings.Join(strings.Fields(decoded), " "))
			}
			canonicalAVAs = append(canonicalAVAs, attribute+"="+strconv.Quote(decoded))
		}
		sort.Strings(canonicalAVAs)
		canonicalRDNs = append(canonicalRDNs, strings.Join(canonicalAVAs, "+"))
	}
	// Treat equivalent RDN orderings and multi-valued AVA orderings as
	// the same peer identity. Quoted values keep escaped separators from
	// becoming structural delimiters in this collision-only key.
	sort.Strings(canonicalRDNs)
	return strings.Join(canonicalRDNs, "/"), true
}

func splitIPsecDNComponents(value string, separator byte) ([]string, bool) {
	parts := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			if i+1 >= len(value) {
				return nil, false
			}
			i++
			continue
		}
		if value[i] == separator {
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	parts = append(parts, value[start:])
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return nil, false
		}
	}
	return parts, true
}

func indexUnescapedIPsecDNByte(value string, target byte) (int, bool) {
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			if i+1 >= len(value) {
				return -1, false
			}
			i++
			continue
		}
		if value[i] == target {
			return i, true
		}
	}
	return -1, false
}

func trimUnescapedIPsecDNPadding(value string) string {
	start, end := 0, len(value)
	for start < end {
		r, size := utf8.DecodeRuneInString(value[start:end])
		if !unicode.IsSpace(r) {
			break
		}
		start += size
	}
	for end > start {
		r, size := utf8.DecodeLastRuneInString(value[start:end])
		if !unicode.IsSpace(r) {
			break
		}
		slashes := 0
		for i := end - size - 1; i >= start && value[i] == '\\'; i-- {
			slashes++
		}
		if slashes%2 != 0 {
			break
		}
		end -= size
	}
	return value[start:end]
}

func decodeIPsecDNValue(value string) (string, bool) {
	var decoded strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '\\' {
			decoded.WriteByte(value[i])
			i++
			continue
		}
		if i+1 >= len(value) {
			return "", false
		}
		if i+2 < len(value) {
			if b, err := hex.DecodeString(value[i+1 : i+3]); err == nil {
				decoded.WriteByte(b[0])
				i += 3
				continue
			}
		}
		if !strings.ContainsRune(" \\\"#+,;<>\\=", rune(value[i+1])) {
			return "", false
		}
		decoded.WriteByte(value[i+1])
		i += 2
	}
	return decoded.String(), true
}

func canonicalIPsecDNAttribute(attribute string) string {
	attribute = strings.ToUpper(strings.TrimSpace(attribute))
	switch attribute {
	case "S":
		return "ST"
	case "E":
		return "EMAILADDRESS"
	case "2.5.4.3":
		return "CN"
	case "2.5.4.6":
		return "C"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.9":
		return "STREET"
	case "2.5.4.10":
		return "O"
	case "2.5.4.11":
		return "OU"
	case "1.2.840.113549.1.9.1":
		return "EMAILADDRESS"
	default:
		return attribute
	}
}

func ipsecDNAttributeCaseIgnore(attribute string) bool {
	switch attribute {
	case "CN", "O", "OU", "C", "L", "ST", "STREET", "EMAILADDRESS", "DC", "UID":
		return true
	default:
		return false
	}
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
