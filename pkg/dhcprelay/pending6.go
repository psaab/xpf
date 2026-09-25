package dhcprelay

import (
	"encoding/binary"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// RFC 8415 recommends DUIDs no longer than 128 octets. The fixed-width key
// keeps lookup allocation-free and bounded; a request with a longer DUID is
// not sent upstream because its reply could not be bound safely.
const pending6MaxDUIDSize = 128

// pending6Key binds a DHCPv6 server reply to the client transaction relayed
// upstream. IA type distinguishes IA_NA, IA_TA, and IA_PD even when IAIDs match.
type pending6Key struct {
	xid     dhcpv6.TransactionID
	duid    [pending6MaxDUIDSize]byte
	duidLen uint8
	iaType  uint16
	iaid    [4]byte
}

// pending6KeyFor extracts only values the DHCPv6 server is required to echo:
// the transaction ID, Client Identifier, and the first IAID/type in stable
// sorted order. The sorted IA choice avoids binding to option order, which a
// server may change while retaining the same transaction identity. Messages
// with no IA use type 0 and a zero IAID (e.g. Information-request).
func pending6KeyFor(packet dhcpv6.DHCPv6) (pending6Key, bool) {
	if packet == nil {
		return pending6Key{}, false
	}
	msg, err := packet.GetInnerMessage()
	if err != nil || msg == nil {
		return pending6Key{}, false
	}
	key := pending6Key{xid: msg.TransactionID}
	if id := msg.Options.ClientID(); id != nil {
		n, ok := copyPending6DUID(&key.duid, id)
		if !ok {
			return pending6Key{}, false
		}
		key.duidLen = n
	}

	foundIA := false
	for _, option := range msg.Options.Options {
		var code uint16
		var iaid [4]byte
		switch ia := option.(type) {
		case *dhcpv6.OptIANA:
			code, iaid = uint16(dhcpv6.OptionIANA), ia.IaId
		case *dhcpv6.OptIATA:
			code, iaid = uint16(dhcpv6.OptionIATA), ia.IaId
		case *dhcpv6.OptIAPD:
			code, iaid = uint16(dhcpv6.OptionIAPD), ia.IaId
		default:
			continue
		}
		if !foundIA || code < key.iaType || code == key.iaType && pending6IAIDLess(iaid, key.iaid) {
			key.iaType, key.iaid = code, iaid
			foundIA = true
		}
	}
	return key, true
}

func pending6IAIDLess(a, b [4]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// copyPending6DUID serializes the library's parsed DUID types directly into
// fixed key storage, avoiding a temporary slice on every relayed packet.
func copyPending6DUID(dst *[pending6MaxDUIDSize]byte, id dhcpv6.DUID) (uint8, bool) {
	var typ uint16
	var hwType uint16
	var enterprise uint32
	var data []byte
	var timestamp uint32
	switch duid := id.(type) {
	case *dhcpv6.DUIDLLT:
		if duid == nil {
			return 0, false
		}
		typ, hwType, timestamp, data = uint16(duid.DUIDType()), uint16(duid.HWType), duid.Time, duid.LinkLayerAddr
		if 8+len(data) > len(dst) {
			return 0, false
		}
		binary.BigEndian.PutUint16(dst[0:2], typ)
		binary.BigEndian.PutUint16(dst[2:4], hwType)
		binary.BigEndian.PutUint32(dst[4:8], timestamp)
		return uint8(8 + copy(dst[8:], data)), true
	case *dhcpv6.DUIDLL:
		if duid == nil {
			return 0, false
		}
		typ, hwType, data = uint16(duid.DUIDType()), uint16(duid.HWType), duid.LinkLayerAddr
		if 4+len(data) > len(dst) {
			return 0, false
		}
		binary.BigEndian.PutUint16(dst[0:2], typ)
		binary.BigEndian.PutUint16(dst[2:4], hwType)
		return uint8(4 + copy(dst[4:], data)), true
	case *dhcpv6.DUIDEN:
		if duid == nil {
			return 0, false
		}
		typ, enterprise, data = uint16(duid.DUIDType()), duid.EnterpriseNumber, duid.EnterpriseIdentifier
		if 6+len(data) > len(dst) {
			return 0, false
		}
		binary.BigEndian.PutUint16(dst[0:2], typ)
		binary.BigEndian.PutUint32(dst[2:6], enterprise)
		return uint8(6 + copy(dst[6:], data)), true
	case *dhcpv6.DUIDUUID:
		if duid == nil {
			return 0, false
		}
		typ = uint16(duid.DUIDType())
		binary.BigEndian.PutUint16(dst[0:2], typ)
		copy(dst[2:18], duid.UUID[:])
		return 18, true
	case *dhcpv6.DUIDOpaque:
		if duid == nil {
			return 0, false
		}
		typ, data = uint16(duid.DUIDType()), duid.Data
		if 2+len(data) > len(dst) {
			return 0, false
		}
		binary.BigEndian.PutUint16(dst[0:2], typ)
		return uint8(2 + copy(dst[2:], data)), true
	default:
		// Preserve support for custom DUID implementations. The library's
		// parser produces one of the concrete types handled above.
		wire := id.ToBytes()
		if len(wire) > len(dst) {
			return 0, false
		}
		return uint8(copy(dst[:], wire)), true
	}
}
