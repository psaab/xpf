package config

import (
	"encoding/asn1"
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
	// Identity is the rendered selector on Gateway; OtherIdentity is the
	// rendered selector (peer selector or effective local identity) on
	// OtherGateway that strongSwan treats as the same owner, and Rule names
	// the equality rule that made them equal (#18428).
	Identity      string
	OtherIdentity string
	Rule          string
	Kind          string
	AffectedVPNs  []string
}

type ipsecPSKPeerSelector struct {
	identity ipsecIKEIdentity
	rendered string
}

type ipsecPSKIdentityGroup struct {
	key             string
	gateway         string
	members         []string
	psks            map[string]struct{}
	peerSelectors   []ipsecPSKPeerSelector
	localIdentities []ipsecPSKPeerSelector
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
				key:     key,
				gateway: vpn.Gateway,
				psks:    make(map[string]struct{}),
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
			identity, rendered := ipsecIKEIdentityKey(gw.LocalIDType, gw.LocalIDValue)
			group.localIdentities = append(group.localIdentities, ipsecPSKPeerSelector{identity: identity, rendered: rendered})
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
				identity, rendered := ipsecIKEIdentityKey("inet", addr.String())
				group.localIdentities = append(group.localIdentities, ipsecPSKPeerSelector{identity: identity, rendered: rendered})
			}
		}
		if mixedHostname, mixed := ipsecMixedHostnameAndIP(endpointList); mixed &&
			(gw == nil || (!hasDiscriminatingRemoteIdentity(gw) && gw.DynamicHostname == "")) {
			if group.mixedHostname == "" {
				group.mixedHostname = mixedHostname
			}
		}
		ipsecForEachPSKPeerIdentity(endpointList, gw, func(identity ipsecIKEIdentity, rendered string) {
			group.peerSelectors = append(group.peerSelectors, ipsecPSKPeerSelector{
				identity: identity,
				rendered: rendered,
			})
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
		sort.Slice(group.peerSelectors, func(i, j int) bool {
			return group.peerSelectors[i].rendered < group.peerSelectors[j].rendered
		})
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
			// #18428: strongSwan selects a secret through has_owner()
			// (mem_cred.c), lookup->matches(owner), and every matches_* is
			// type-strict except that an ID_ANY owner matches anything.
			// Peer selectors are owners: two collide when one presented
			// identity can select both (ipsecIdentitiesCollide). An effective
			// local identity is the `me` lookup of its own exchange: it
			// exposes another connection's secret when it selects that
			// connection's owner (ipsecLookupSelectsOwner). equals() is not
			// on the lookup path.
			conflict := IPsecPSKIdentityConflict{}
			for _, peer := range a.peerSelectors {
				for _, other := range b.peerSelectors {
					if rule, ok := ipsecIdentitiesCollide(peer.identity, other.identity); ok {
						conflict = ipsecPSKIdentityConflict(a, b, peer.rendered, other.rendered, rule, "shared-peer-selector")
						break
					}
				}
				if conflict.Kind != "" {
					break
				}
			}
			if conflict.Kind == "" {
				for _, peer := range a.peerSelectors {
					for _, local := range b.localIdentities {
						if rule, ok := ipsecLookupSelectsOwner(local.identity, peer.identity); ok {
							conflict = ipsecPSKIdentityConflict(a, b, peer.rendered, local.rendered, rule, "peer-selector-is-other-local-identity")
							break
						}
					}
					if conflict.Kind != "" {
						break
					}
				}
			}
			if conflict.Kind == "" {
				for _, peer := range b.peerSelectors {
					for _, local := range a.localIdentities {
						if rule, ok := ipsecLookupSelectsOwner(local.identity, peer.identity); ok {
							conflict = ipsecPSKIdentityConflict(b, a, peer.rendered, local.rendered, rule, "peer-selector-is-other-local-identity")
							break
						}
					}
					if conflict.Kind != "" {
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

func ipsecPSKIdentityConflict(a, b *ipsecPSKIdentityGroup, identity, otherIdentity, rule, kind string) IPsecPSKIdentityConflict {
	affected := make([]string, 0, len(a.members)+len(b.members))
	affected = append(affected, a.members...)
	affected = append(affected, b.members...)
	sort.Strings(affected)
	return IPsecPSKIdentityConflict{
		VPN:           a.members[0],
		OtherVPN:      b.members[0],
		Gateway:       a.gateway,
		OtherGateway:  b.gateway,
		Identity:      identity,
		OtherIdentity: otherIdentity,
		Rule:          rule,
		Kind:          kind,
		AffectedVPNs:  affected,
	}
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
	ipsecForEachPSKPeerIdentity(endpointList, gw, func(_ ipsecIKEIdentity, selector string) {
		selectors = append(selectors, selector)
	})
	return selectors
}

func ipsecForEachPSKPeerIdentity(endpointList string, gw *IPsecGateway, visit func(ipsecIKEIdentity, string)) {
	var seen map[string]struct{}
	add := func(identity ipsecIKEIdentity, selector string) {
		if seen != nil {
			if _, ok := seen[selector]; ok {
				return
			}
		}
		if seen == nil {
			seen = make(map[string]struct{})
		}
		seen[selector] = struct{}{}
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

type ipsecIKEIdentity struct {
	typeID   uint32
	encoding string
	rdns     []ipsecDNRDN
	dnValid  bool
}

func ipsecIKEIdentityKey(idType, idValue string) (ipsecIKEIdentity, string) {
	selector := FormatIPsecIdentity(idType, idValue)
	if selector == "" {
		return ipsecIKEIdentity{}, selector
	}
	if identity, ok := ipsecStrongSwanExplicitTypeIdentity(selector); ok {
		return identity, selector
	}
	if identity, ok := ipsecStrongSwanNumericTypeIdentity(selector); ok {
		return identity, selector
	}
	if strings.Contains(selector, "=") {
		if encoded, ok := ipsecEncodeTextualDN(selector); ok {
			return ipsecTypedIdentity(9, encoded), selector
		}
		return ipsecTypedIdentityString(11, selector), selector
	}
	if ipsecStrongSwanAnySelector(selector) {
		return ipsecIKEIdentity{typeID: 0}, selector
	}
	if strings.HasPrefix(selector, "@#") {
		return ipsecTypedIdentity(11, ipsecChunkFromHex(selector[2:])), selector
	}
	if strings.HasPrefix(selector, "@@") {
		return ipsecTypedIdentityString(3, selector[2:]), selector
	}
	if strings.HasPrefix(selector, "@") {
		return ipsecTypedIdentityString(2, selector[1:]), selector
	}
	if strings.Contains(selector, "@") {
		return ipsecTypedIdentityString(3, selector), selector
	}
	if prefix, err := netip.ParsePrefix(selector); err == nil {
		return ipsecSubnetIdentity(prefix), selector
	}
	if prefix, ok := ipsecStrongSwanUntypedSubnet(selector); ok {
		return ipsecSubnetIdentity(prefix), selector
	}
	if identity, ok := ipsecAddressRangeIdentity(selector); ok {
		return identity, selector
	}
	if addr, err := netip.ParseAddr(selector); err == nil && addr.Zone() == "" {
		typeID := uint32(1)
		if addr.Is6() {
			typeID = 5
		}
		return ipsecTypedIdentity(typeID, addr.AsSlice()), selector
	}
	if strings.Contains(selector, ":") {
		return ipsecTypedIdentityString(11, selector), selector
	}
	return ipsecTypedIdentityString(2, selector), selector
}

// ipsecStrongSwanAnySelector reports whether identification_create_from_string
// maps the rendered selector to ID_ANY (#18428). strongSwan tests these exact
// strings, after the type prefixes and the '=' (DN) branch and only for
// selectors without '@', so the declared xpf type does not matter whenever it
// renders the value unprefixed (inet, inet6, distinguished-name,
// user-at-hostname, ...). Near spellings such as "::0" or " 0.0.0.0" are NOT
// ID_ANY (an IPv6 address and an FQDN), and neither is "@0.0.0.0".
func ipsecStrongSwanAnySelector(selector string) bool {
	switch selector {
	case "", "%any", "%any6", "0.0.0.0", "*", "::", "0::0":
		return true
	}
	return false
}

var ipsecStrongSwanIdentityPrefixes = [...]struct {
	text   string
	typeID uint32
	class  string
}{
	{"ipv4:", 1, ""},
	{"ipv6:", 5, ""},
	{"ipv4net:", 4, ""},
	{"ipv6net:", 6, ""},
	{"ipv4range:", 7, ""},
	{"ipv6range:", 8, ""},
	{"rfc822:", 3, ""},
	{"email:", 3, ""},
	{"userfqdn:", 3, ""},
	{"fqdn:", 2, ""},
	{"dns:", 2, ""},
	{"asn1dn:", 9, ""},
	{"asn1gn:", 10, ""},
	{"xmppaddr:", 10, "xmppaddr"},
	{"keyid:", 11, ""},
	{"uri:", 201, ""},
}

func ipsecStrongSwanExplicitTypeIdentity(selector string) (ipsecIKEIdentity, bool) {
	for _, prefix := range ipsecStrongSwanIdentityPrefixes {
		if !ipsecASCIIHasPrefix(selector, prefix.text) {
			continue
		}
		value := selector[len(prefix.text):]
		var encoded []byte
		if strings.HasPrefix(value, "#") {
			encoded = ipsecChunkFromHex(value[1:])
		} else {
			encoded = []byte(value)
		}
		if prefix.class == "xmppaddr" {
			encoded = ipsecXMPPGeneralName(encoded)
		}
		return ipsecTypedIdentity(prefix.typeID, encoded), true
	}
	return ipsecIKEIdentity{}, false
}

func ipsecStrongSwanNumericTypeIdentity(selector string) (ipsecIKEIdentity, bool) {
	if !strings.HasPrefix(selector, "{") {
		return ipsecIKEIdentity{}, false
	}
	close := strings.IndexByte(selector, '}')
	if close < 1 || close+1 >= len(selector) || selector[close+1] != ':' {
		return ipsecIKEIdentity{}, false
	}
	var typeID uint32
	if close > 1 {
		parsedTypeID, ok := ipsecParseStrtoul32(selector[1:close])
		if !ok {
			return ipsecIKEIdentity{}, false
		}
		typeID = parsedTypeID
	}
	value := selector[close+2:]
	if strings.HasPrefix(value, "#") {
		return ipsecTypedIdentity(typeID, ipsecChunkFromHex(value[1:])), true
	}
	return ipsecTypedIdentity(typeID, []byte(value)), true
}

func ipsecParseStrtoul32(value string) (uint32, bool) {
	i := 0
	for i < len(value) && strings.ContainsRune(" \t\n\v\f\r", rune(value[i])) {
		i++
	}
	negative := false
	if i < len(value) && (value[i] == '+' || value[i] == '-') {
		negative = value[i] == '-'
		i++
	}
	base := uint64(10)
	if i < len(value) && value[i] == '0' {
		base = 8
		if i+1 < len(value) && (value[i+1] == 'x' || value[i+1] == 'X') {
			base = 16
			i += 2
		}
	}
	start := i
	var number uint64
	for i < len(value) {
		char := value[i]
		digit := uint64(255)
		switch {
		case char >= '0' && char <= '9':
			digit = uint64(char - '0')
		case char >= 'a' && char <= 'f':
			digit = uint64(char-'a') + 10
		case char >= 'A' && char <= 'F':
			digit = uint64(char-'A') + 10
		default:
			break
		}
		if digit >= base {
			break
		}
		if number > (^uint64(0)-digit)/base {
			return 0, false
		}
		number = number*base + digit
		i++
	}
	if i == start || i != len(value) {
		return 0, false
	}
	if negative {
		number = 0 - number
	}
	return uint32(number), true
}

func ipsecTypedIdentity(typeID uint32, value []byte) ipsecIKEIdentity {
	identity := ipsecIKEIdentity{typeID: typeID, encoding: string(value)}
	if typeID == 9 || (len(value) > 0 && value[0] == 0x30) {
		// Type-9 left operands interpret any right identity's raw encoding as a DN.
		identity.rdns, identity.dnValid = ipsecParseDNEncoding(value)
	}
	return identity
}

func ipsecTypedIdentityString(typeID uint32, value string) ipsecIKEIdentity {
	identity := ipsecIKEIdentity{typeID: typeID, encoding: value}
	if typeID == 9 || (len(value) > 0 && value[0] == 0x30) {
		// Keep normal text encodings zero-copy; only parse possible DN bytes.
		identity.rdns, identity.dnValid = ipsecParseDNEncoding([]byte(value))
	}
	return identity
}

func (identity ipsecIKEIdentity) equals(other ipsecIKEIdentity) bool {
	if identity.typeID == 9 {
		return ipsecDNIdentityEqual(identity, other)
	}
	if identity.typeID != other.typeID {
		return false
	}
	switch identity.typeID {
	case 0:
		return true
	case 2, 3:
		if strings.IndexByte(identity.encoding, 0) >= 0 || strings.IndexByte(other.encoding, 0) >= 0 {
			return false
		}
		return ipsecASCIIEqualFold(identity.encoding, other.encoding)
	default:
		return identity.encoding == other.encoding
	}
}

// ipsecIdentitiesCollide reports whether one presented identity could select
// the secrets of both a and b, and names the rule that made them one owner
// (#18428). strongSwan selects a PSK through has_owner() in mem_cred.c:
// lookup->matches(owner) for each configured owner. Every matches_* is
// type-strict (matches_binary, matches_string, matches_dn_internal,
// matches_range return ID_MATCH_NONE unless both identities have the same
// type), except that an ID_ANY owner returns ID_MATCH_ANY for any lookup. So
// two owners collide only when their strongSwan types (parsed from the
// RENDERED selectors, which the key already carries) are equal and they
// compare equal, or when either is ID_ANY. equals() is directional only for a
// type-9 left operand against another type, which this type gate excludes,
// so the same-type test is symmetric. A DN whose DER equals a KEY_ID's bytes
// is NOT a collision: matches() never crosses the types (oracle-confirmed).
func ipsecIdentitiesCollide(a, b ipsecIKEIdentity) (string, bool) {
	if a.typeID == 0 || b.typeID == 0 {
		return "ID_ANY owner matches every identity", true
	}
	if a.typeID == b.typeID && a.equals(b) {
		return ipsecIdentityEqualityRule(a, b), true
	}
	return "", false
}

// ipsecLookupSelectsOwner reports whether lookup, used as the `me` identity of
// has_owner(), selects a secret owned by owner: lookup->matches(owner). It is
// ipsecIdentitiesCollide's rule with the operand roles fixed. An ID_ANY owner
// matches every lookup, but matches_any() makes an ID_ANY LOOKUP match only an
// ID_ANY owner. An effective local identity is ID_ANY when it is spelled as a
// wildcard or comes from an unspecified local address (`local-address
// 0.0.0.0` / `::`); charon then presents its real source address, which
// commit cannot know, so such a local identity selects no peer selector.
func ipsecLookupSelectsOwner(lookup, owner ipsecIKEIdentity) (string, bool) {
	if owner.typeID == 0 {
		return "ID_ANY owner matches every identity", true
	}
	if lookup.typeID == 0 {
		return "", false
	}
	return ipsecIdentitiesCollide(lookup, owner)
}

// ipsecIdentityEqualityRule describes why left.equals(right) holds for two
// identities of the same strongSwan type.
func ipsecIdentityEqualityRule(left, right ipsecIKEIdentity) string {
	switch left.typeID {
	case 9:
		if left.encoding == right.encoding {
			return "identical DN encoding"
		}
		return "DN equality (same RDNs; PrintableString/emailAddress case-insensitive)"
	case 2:
		if left.encoding == right.encoding {
			return "identical FQDN"
		}
		return "FQDN case-insensitive"
	case 3:
		if left.encoding == right.encoding {
			return "identical RFC822 address"
		}
		return "RFC822 case-insensitive (whole address, including the local part)"
	default:
		return "identical " + ipsecIdentityTypeName(left.typeID) + " encoding"
	}
}

// ipsecIdentityTypeName names a strongSwan id_type_t value for diagnostics.
func ipsecIdentityTypeName(typeID uint32) string {
	switch typeID {
	case 0:
		return "ID_ANY"
	case 1:
		return "IPV4_ADDR"
	case 2:
		return "FQDN"
	case 3:
		return "RFC822"
	case 4:
		return "IPV4_ADDR_SUBNET"
	case 5:
		return "IPV6_ADDR"
	case 6:
		return "IPV6_ADDR_SUBNET"
	case 7:
		return "IPV4_ADDR_RANGE"
	case 8:
		return "IPV6_ADDR_RANGE"
	case 9:
		return "DN"
	case 10:
		return "GENERAL_NAME"
	case 11:
		return "KEY_ID"
	case 201:
		return "URI"
	default:
		return "identity type " + strconv.FormatInt(int64(int32(typeID)), 10)
	}
}

func ipsecASCIIEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		left, right := a[i], b[i]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}

func ipsecASCIIEqualFoldUntilNUL(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		left, right := a[i], b[i]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
		if left == 0 {
			return true
		}
	}
	return true
}

func ipsecASCIIHasPrefix(value, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		char := value[i]
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		if char != prefix[i] {
			return false
		}
	}
	return true
}

func ipsecSubnetIdentity(prefix netip.Prefix) ipsecIKEIdentity {
	prefix = prefix.Masked()
	address := prefix.Addr()
	typeID := uint32(4)
	if address.Is6() {
		typeID = 6
	}
	encoding := address.AsSlice()
	mask := make([]byte, len(encoding))
	for bit := 0; bit < prefix.Bits(); bit++ {
		mask[bit/8] |= 1 << (7 - uint(bit%8))
	}
	encoding = append(encoding, mask...)
	return ipsecTypedIdentity(typeID, encoding)
}
func ipsecStrongSwanUntypedSubnet(value string) (netip.Prefix, bool) {
	addressValue, prefixValue, ok := strings.Cut(value, "/")
	if !ok {
		return netip.Prefix{}, false
	}
	address, err := netip.ParseAddr(addressValue)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, false
	}
	bits := ipsecStrtolDecimalPrefix(prefixValue)
	if bits < 0 || bits > int32(address.BitLen()) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, int(bits)), true
}

// ipsecStrtolDecimalPrefix mirrors strtol(..., 10) followed by strongSwan's
// signed 32-bit prefix-length conversion. It accepts a signed decimal prefix,
// ignores trailing bytes, treats no digits as zero, and uses strtol's
// saturating 64-bit overflow result before narrowing.
func ipsecStrtolDecimalPrefix(value string) int32 {
	index := 0
	for index < len(value) {
		switch value[index] {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			index++
		default:
			goto whitespaceDone
		}
	}

whitespaceDone:
	numberStart := index
	if index < len(value) && (value[index] == '+' || value[index] == '-') {
		index++
	}
	digitsStart := index
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	if index == digitsStart {
		return 0
	}
	number, _ := strconv.ParseInt(value[numberStart:index], 10, 64)
	return int32(number)
}

func ipsecAddressRangeIdentity(value string) (ipsecIKEIdentity, bool) {
	first, second, ok := strings.Cut(value, "-")
	if !ok {
		return ipsecIKEIdentity{}, false
	}
	start, err := netip.ParseAddr(first)
	if err != nil || start.Zone() != "" {
		return ipsecIKEIdentity{}, false
	}
	end, err := netip.ParseAddr(second)
	if err != nil || end.Zone() != "" || start.Is4() != end.Is4() || start.Compare(end) > 0 {
		return ipsecIKEIdentity{}, false
	}
	typeID := uint32(7)
	if !start.Is4() {
		typeID = 8
	}
	startBytes, endBytes := start.AsSlice(), end.AsSlice()
	encoded := make([]byte, len(startBytes)+len(endBytes))
	copy(encoded, startBytes)
	copy(encoded[len(startBytes):], endBytes)
	return ipsecTypedIdentity(typeID, encoded), true
}

func ipsecXMPPGeneralName(value []byte) []byte {
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x05}
	utf8 := ipsecDERWrap(0x0c, value)
	otherNameValue := ipsecDERWrap(0xa0, utf8)
	return ipsecDERWrap(0xa0, append(oid, otherNameValue...))
}

// ipsecChunkFromHex mirrors chunk_from_hex(): it sizes after removing every
// colon, then fills bytes from the right while skipping at most one colon
// before each low nibble.
func ipsecChunkFromHex(value string) []byte {
	if len(value) > 1 && value[0] == '0' && value[1] == 'x' {
		value = value[2:]
	}
	nibbleCount := len(value)
	for i := 0; i < len(value); i++ {
		if value[i] == ':' {
			nibbleCount--
		}
	}
	odd := nibbleCount%2 != 0
	if odd {
		nibbleCount++
	}
	decoded := make([]byte, nibbleCount/2)
	position := len(value)
	next := func() (byte, bool) {
		if position == 0 {
			return 0, false
		}
		position--
		return value[position], true
	}
	for i := len(decoded) - 1; i >= 0; i-- {
		nibble, ok := next()
		if ok && nibble == ':' {
			nibble, ok = next()
		}
		if ok {
			decoded[i] = ipsecHexNibble(nibble)
		}
		if i > 0 || !odd {
			nibble, ok = next()
			if ok {
				decoded[i] |= ipsecHexNibble(nibble) << 4
			}
		}
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

type ipsecDNAttribute struct {
	oid      string
	valueTag byte
}

type ipsecDNRDN struct {
	oid   string
	tag   byte
	value string
}

func ipsecEncodeTextualDN(value string) ([]byte, bool) {
	const (
		searchOID = iota
		readOID
		searchName
		readName
	)
	state := searchOID
	var separator byte
	oidStart, nameStart := 0, 0
	var attribute ipsecDNAttribute
	var rdns []byte
	rdnCount := 0
	appendRDN := func(name string) bool {
		if rdnCount == 20 {
			return false
		}
		tag := attribute.valueTag
		if tag == 0x13 && !ipsecIsPrintableString(name) {
			tag = 0x0c
		}
		oid := ipsecDERWrap(0x06, []byte(attribute.oid))
		valueDER := ipsecDERWrap(tag, []byte(name))
		sequence := ipsecDERWrap(0x30, append(oid, valueDER...))
		rdns = append(rdns, ipsecDERWrap(0x31, sequence)...)
		rdnCount++
		return true
	}
	for i := 0; i <= len(value); i++ {
		var char byte
		if i < len(value) {
			char = value[i]
		}
		switch state {
		case searchOID:
			if separator == 0 && char == '/' {
				separator = '/'
				continue
			}
			if char != ' ' && char != 0 {
				if separator == 0 {
					separator = ','
				}
				oidStart = i
				state = readOID
			}
		case readOID:
			if char != ' ' && char != '=' {
				continue
			}
			var ok bool
			attribute, ok = ipsecDNAttributeFor(value[oidStart:i])
			if !ok {
				return nil, false
			}
			state = searchName
		case searchName:
			if char == ' ' || char == '=' {
				continue
			}
			if char != separator && char != 0 {
				nameStart = i
				state = readName
				continue
			}
			if !appendRDN("") {
				return nil, false
			}
			state = searchOID
		case readName:
			if char != separator && char != 0 {
				continue
			}
			end := i
			for end > nameStart && value[end-1] == ' ' {
				end--
			}
			if !appendRDN(value[nameStart:end]) {
				return nil, false
			}
			state = searchOID
		}
	}
	if state == readOID {
		return nil, false
	}
	return ipsecDERWrap(0x30, rdns), true
}

func ipsecDNAttributeFor(attribute string) (ipsecDNAttribute, bool) {
	printable := byte(0x13)
	ia5 := byte(0x16)
	switch ipsecASCIILower(attribute) {
	case "nd":
		return ipsecDNAttribute{"\x82\x06\x01\x0a\x07\x14", printable}, true
	case "uid":
		return ipsecDNAttribute{"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x01", printable}, true
	case "dc":
		return ipsecDNAttribute{"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19", printable}, true
	case "cn":
		return ipsecDNAttribute{"\x55\x04\x03", printable}, true
	case "sn":
		return ipsecDNAttribute{"\x55\x04\x04", printable}, true
	case "serialnumber":
		return ipsecDNAttribute{"\x55\x04\x05", printable}, true
	case "c":
		return ipsecDNAttribute{"\x55\x04\x06", printable}, true
	case "l":
		return ipsecDNAttribute{"\x55\x04\x07", printable}, true
	case "st":
		return ipsecDNAttribute{"\x55\x04\x08", printable}, true
	case "street":
		return ipsecDNAttribute{"\x55\x04\x09", printable}, true
	case "o":
		return ipsecDNAttribute{"\x55\x04\x0a", printable}, true
	case "ou":
		return ipsecDNAttribute{"\x55\x04\x0b", printable}, true
	case "organizationidentifier":
		return ipsecDNAttribute{"\x55\x04\x61", printable}, true
	case "t":
		return ipsecDNAttribute{"\x55\x04\x0c", printable}, true
	case "d":
		return ipsecDNAttribute{"\x55\x04\x0d", printable}, true
	case "postaladdress":
		return ipsecDNAttribute{"\x55\x04\x10", printable}, true
	case "postalcode":
		return ipsecDNAttribute{"\x55\x04\x11", printable}, true
	case "n":
		return ipsecDNAttribute{"\x55\x04\x29", printable}, true
	case "g":
		return ipsecDNAttribute{"\x55\x04\x2a", printable}, true
	case "i":
		return ipsecDNAttribute{"\x55\x04\x2b", printable}, true
	case "dnqualifier":
		return ipsecDNAttribute{"\x55\x04\x2e", printable}, true
	case "dmdname":
		return ipsecDNAttribute{"\x55\x04\x36", printable}, true
	case "pseudonym":
		return ipsecDNAttribute{"\x55\x04\x41", printable}, true
	case "id":
		return ipsecDNAttribute{"\x55\x04\x2d", printable}, true
	case "en", "employeenumber":
		return ipsecDNAttribute{"\x60\x86\x48\x01\x86\xf8\x42\x03\x01\x03", printable}, true
	case "e", "email", "emailaddress":
		return ipsecDNAttribute{"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01", ia5}, true
	case "un", "unstructuredname":
		return ipsecDNAttribute{"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x02", ia5}, true
	case "ua", "unstructuredaddress":
		return ipsecDNAttribute{"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x08", printable}, true
	case "tcgid":
		return ipsecDNAttribute{"\x2b\x06\x01\x04\x01\x89\x31\x01\x01\x02\x02\x4b", printable}, true
	default:
		return ipsecDNAttribute{}, false
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

func ipsecDNIdentityEqual(a, b ipsecIKEIdentity) bool {
	if len(a.encoding) != len(b.encoding) {
		return false
	}
	if a.encoding == b.encoding {
		return true
	}
	if !a.dnValid || !b.dnValid || len(a.rdns) == 0 || len(a.rdns) != len(b.rdns) {
		return false
	}
	// compare_dn() declares a match only when both enumerators END at the end
	// of their DN. asn1_unwrap's chunk_skip returns chunk_empty (NULL ptr) for
	// an empty value at the very end, so a DN whose LAST attribute value is
	// empty never matches structurally — only byte-identically (above).
	// `CN=Peer, O=` therefore differs from `CN=peer, O=` (oracle-confirmed).
	if len(a.rdns[len(a.rdns)-1].value) == 0 || len(b.rdns[len(b.rdns)-1].value) == 0 {
		return false
	}
	const emailAddressOID = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01"
	for i := range a.rdns {
		x, y := a.rdns[i], b.rdns[i]
		if x.oid != y.oid || len(x.value) != len(y.value) {
			return false
		}
		if x.tag == y.tag && (x.tag == 0x13 || (x.tag == 0x16 && x.oid == emailAddressOID)) {
			if !ipsecASCIIEqualFoldUntilNUL(x.value, y.value) {
				return false
			}
		} else if x.value != y.value {
			return false
		}
	}
	return true
}

func ipsecParseDNEncoding(encoded []byte) ([]ipsecDNRDN, bool) {
	sequence, rest, ok := ipsecReadASN1Raw(encoded)
	if !ok || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, false
	}
	sets := sequence.Bytes
	var rdns []ipsecDNRDN
	for len(sets) > 0 {
		set, remainder, ok := ipsecReadASN1Raw(sets)
		if !ok || set.Class != 0 || set.Tag != 17 || !set.IsCompound {
			return nil, false
		}
		sequences := set.Bytes
		if len(sequences) == 0 {
			return nil, false
		}
		for len(sequences) > 0 {
			rdn, remainder, ok := ipsecReadASN1Raw(sequences)
			if !ok || rdn.Class != 0 || rdn.Tag != 16 || !rdn.IsCompound {
				return nil, false
			}
			oid, content, ok := ipsecReadASN1Raw(rdn.Bytes)
			if !ok || oid.Class != 0 || oid.Tag != 6 || oid.IsCompound {
				return nil, false
			}
			value, content, ok := ipsecReadASN1RawValue(content)
			if !ok || len(content) != 0 {
				return nil, false
			}
			tag := byte(value.Tag)
			if value.Class != 0 {
				tag |= byte(value.Class << 6)
			}
			if value.IsCompound {
				tag |= 0x20
			}
			rdns = append(rdns, ipsecDNRDN{
				oid:   string(oid.Bytes),
				tag:   tag,
				value: string(value.Bytes),
			})
			sequences = remainder
		}
		sets = remainder
	}
	return rdns, true
}

func ipsecReadASN1Raw(encoded []byte) (asn1.RawValue, []byte, bool) {
	return ipsecReadASN1RawWithHighTag(encoded, true)
}

// strongSwan's atodn reads a value tag as one raw octet; 0x1f is tag 31,
// not the start of a multi-octet identifier.
func ipsecReadASN1RawValue(encoded []byte) (asn1.RawValue, []byte, bool) {
	return ipsecReadASN1RawWithHighTag(encoded, false)
}

// strongSwan accepts nonminimal BER long-form lengths, including leading zeros,
// but bounds the length field to eight octets and the value to available input.
func ipsecReadASN1RawWithHighTag(encoded []byte, parseHighTag bool) (asn1.RawValue, []byte, bool) {
	if len(encoded) < 2 {
		return asn1.RawValue{}, nil, false
	}
	identifier := encoded[0]
	tag := int(identifier & 0x1f)
	index := 1
	if parseHighTag && tag == 0x1f {
		tag = 0
		for {
			if index >= len(encoded) {
				return asn1.RawValue{}, nil, false
			}
			next := encoded[index]
			index++
			maxInt := int(^uint(0) >> 1)
			if tag > (maxInt-int(next&0x7f))/128 {
				return asn1.RawValue{}, nil, false
			}
			tag = tag*128 + int(next&0x7f)
			if next&0x80 == 0 {
				break
			}
		}
		if tag < 31 {
			return asn1.RawValue{}, nil, false
		}
	}
	if index >= len(encoded) {
		return asn1.RawValue{}, nil, false
	}
	firstLength := encoded[index]
	index++
	var length uint64
	if firstLength&0x80 == 0 {
		length = uint64(firstLength)
	} else {
		lengthBytes := int(firstLength & 0x7f)
		if lengthBytes == 0 || lengthBytes > 8 || lengthBytes > len(encoded)-index {
			return asn1.RawValue{}, nil, false
		}
		for i := 0; i < lengthBytes; i++ {
			length = length<<8 | uint64(encoded[index+i])
		}
		index += lengthBytes
	}
	if length > uint64(len(encoded)-index) {
		return asn1.RawValue{}, nil, false
	}
	end := index + int(length)
	return asn1.RawValue{
		Class:      int(identifier >> 6),
		Tag:        tag,
		IsCompound: identifier&0x20 != 0,
		Bytes:      encoded[index:end],
		FullBytes:  encoded[:end],
	}, encoded[end:], true
}

func ipsecDERWrap(tag byte, content []byte) []byte {
	length := len(content)
	lengthBytes := 0
	if length >= 128 {
		for size := length; size > 0; size >>= 8 {
			lengthBytes++
		}
	}
	headerLength := 2 + lengthBytes
	encoded := make([]byte, headerLength+length)
	encoded[0] = tag
	if lengthBytes == 0 {
		encoded[1] = byte(length)
	} else {
		encoded[1] = 0x80 | byte(lengthBytes)
		for i := 0; i < lengthBytes; i++ {
			encoded[2+i] = byte(length >> (8 * (lengthBytes - 1 - i)))
		}
	}
	copy(encoded[headerLength:], content)
	return encoded
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
