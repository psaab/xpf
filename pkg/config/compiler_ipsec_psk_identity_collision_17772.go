package config

import (
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
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

// FormatIPsecIdentity renders an IKE identity exactly as swanctl emits it.
// Both pkg/ipsec's formatIdentity wrapper and collision-key construction
// use this function so the comparison never drifts from the rendered owner.
func FormatIPsecIdentity(idType, idValue string) string {
	switch idType {
	case "hostname", "fqdn":
		return "@" + idValue
	case "key-id":
		// KEY_ID: @#<value>, decoded by strongSwan's chunk_from_hex().
		if idValue == "" {
			return ""
		}
		return "@#" + idValue
	default: // "distinguished-name", "inet", "inet6", "user-at-hostname", "email", etc.
		// DN as-is (contains '='); empty = cert-derived DN, caller omits id.
		return idValue
	}
}

func ipsecIKEIdentityKey(idType, idValue string) (string, string) {
	selector := FormatIPsecIdentity(idType, idValue)
	if selector == "" {
		return "", selector
	}
	// identification_create_from_string() tries DN syntax before the @ and
	// @# forms. A malformed DN falls back to a literal KEY_ID, so preserve
	// those bytes before considering any rendered prefix.
	if strings.Contains(selector, "=") {
		if canonical, ok := ipsecCanonicalDNIdentity(selector); ok {
			return "distinguished-name:" + canonical, selector
		}
		return ipsecKeyIDBytesKey([]byte(selector)), selector
	}
	if strings.HasPrefix(selector, "@#") {
		return ipsecKeyIDBytesKey(ipsecChunkFromHex(selector[2:])), selector
	}
	if strings.HasPrefix(selector, "@@") {
		return ipsecRFC822IdentityKey(selector[2:]), selector
	}
	if strings.HasPrefix(selector, "@") {
		return "fqdn:" + ipsecASCIILower(selector[1:]), selector
	}
	if strings.Contains(selector, "@") {
		return ipsecRFC822IdentityKey(selector), selector
	}
	if addr, err := netip.ParseAddr(selector); err == nil && addr.Zone() == "" {
		if addr.Is4() {
			return "ipv4:" + addr.String(), selector
		}
		return "ipv6:" + addr.String(), selector
	}
	if strings.Contains(selector, ":") {
		return ipsecKeyIDBytesKey([]byte(selector)), selector
	}
	// A bare, unadorned identity with no DN/RFC822/IP syntax is parsed by
	// strongSwan as an FQDN identity. Preserve its exact length and whitespace.
	return "fqdn:" + ipsecASCIILower(selector), selector
}

func ipsecRFC822IdentityKey(value string) string {
	return "rfc822:" + ipsecASCIILower(value)
}

func ipsecKeyIDBytesKey(value []byte) string {
	return "key-id-bytes:" + hex.EncodeToString(value)
}

// ipsecChunkFromHex mirrors strongSwan's chunk_from_hex() spelling: lowercase
// 0x and colons are ignored, invalid nibbles become zero, and odd values are
// left-padded with a zero nibble before bytewise identity comparison.
func ipsecChunkFromHex(value string) []byte {
	if strings.HasPrefix(value, "0x") {
		value = value[2:]
	}
	nibbleCount := 0
	for i := 0; i < len(value); i++ {
		if value[i] != ':' {
			nibbleCount++
		}
	}
	decoded := make([]byte, (nibbleCount+1)/2)
	i, out := 0, 0
	nextNibble := func() byte {
		for i < len(value) && value[i] == ':' {
			i++
		}
		nibble := ipsecHexNibble(value[i])
		i++
		return nibble
	}
	if nibbleCount%2 != 0 {
		decoded[out] = nextNibble()
		out++
	}
	for out < len(decoded) {
		decoded[out] = nextNibble()<<4 | nextNibble()
		out++
	}
	return decoded
}

func ipsecHexNibble(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10
	default:
		return 0
	}
}

func ipsecASCIILower(value string) string {
	var lowered []byte
	for i := 0; i < len(value); i++ {
		if value[i] >= 'A' && value[i] <= 'Z' {
			if lowered == nil {
				lowered = []byte(value)
			}
			lowered[i] += 'a' - 'A'
		}
	}
	if lowered == nil {
		return value
	}
	return string(lowered)
}

func ipsecCanonicalDNIdentity(value string) (string, bool) {
	separator := byte(',')
	if strings.HasPrefix(value, "/") {
		separator = '/'
		value = value[1:]
	}
	rawRDNs := strings.Split(value, string(separator))
	canonicalRDNs := make([]string, 0, len(rawRDNs))
	for _, rawRDN := range rawRDNs {
		eq := strings.IndexByte(rawRDN, '=')
		if eq < 0 {
			return "", false
		}
		attribute := canonicalIPsecDNAttribute(strings.Trim(rawRDN[:eq], " "))
		if attribute == "" {
			return "", false
		}
		dnValue := strings.TrimRight(strings.TrimLeft(rawRDN[eq+1:], " ="), " ")
		valueType := "printable"
		switch attribute {
		case "EMAILADDRESS", "UNSTRUCTUREDNAME":
			valueType = "ia5"
		default:
			if !ipsecIsPrintableString(dnValue) {
				valueType = "utf8"
			}
		}
		if valueType == "printable" || attribute == "EMAILADDRESS" {
			dnValue = ipsecASCIILower(dnValue)
		}
		canonicalRDNs = append(canonicalRDNs,
			attribute+":"+valueType+":"+strconv.Quote(dnValue))
	}
	// strongSwan matches individual RDNs independent of their order. Sorting
	// only these parsed values mirrors that behavior; '+' and backslash stay
	// ordinary value bytes because atodn() does not parse them specially.
	sort.Strings(canonicalRDNs)
	return strings.Join(canonicalRDNs, "/"), true
}

func canonicalIPsecDNAttribute(attribute string) string {
	upper := ipsecASCIIUpper(attribute)
	switch upper {
	case "ND", "UID", "DC", "CN", "SN", "SERIALNUMBER", "C", "L", "ST",
		"STREET", "O", "OU", "ORGANIZATIONIDENTIFIER", "T", "D",
		"POSTALADDRESS", "POSTALCODE", "N", "G", "I", "DNQUALIFIER",
		"DMDNAME", "PSEUDONYM", "ID", "TCGID":
		return upper
	case "E", "EMAIL", "EMAILADDRESS":
		return "EMAILADDRESS"
	case "EN", "EMPLOYEENUMBER":
		return "EMPLOYEENUMBER"
	case "UN", "UNSTRUCTUREDNAME":
		return "UNSTRUCTUREDNAME"
	case "UA", "UNSTRUCTUREDADDRESS":
		return "UNSTRUCTUREDADDRESS"
	default:
		return ""
	}
}

func ipsecASCIIUpper(value string) string {
	var upper []byte
	for i := 0; i < len(value); i++ {
		if value[i] >= 'a' && value[i] <= 'z' {
			if upper == nil {
				upper = []byte(value)
			}
			upper[i] -= 'a' - 'A'
		}
	}
	if upper == nil {
		return value
	}
	return string(upper)
}

func ipsecIsPrintableString(value string) bool {
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			strings.ContainsRune(" '()+,-./:=?", rune(char)) {
			continue
		}
		return false
	}
	return true
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
