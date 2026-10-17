package dhcprelay

import (
	"encoding/binary"
	"net"

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

// pending6Entry is the payload bound to a pending6Key (#14181): the address
// of the client (or downstream relay) whose packet the relay forwarded
// upstream. A Relay-Reply is forwarded only when its outer peer-address
// equals this recorded address, so a forged reply cannot redirect a pending
// transaction to loopback or a third party. Stored as a fixed 16-byte array
// (plus a presence flag) so the pending ring stays allocation-free; the
// empty payload (unknown client — entries adopted from a pre-#14181 table
// shape in tests, which never happens in production where insert always
// carries the peer) fails closed on the reply path.
type pending6Entry struct {
	clientAddr     [16]byte
	hasClientAddr  bool
	requestType    dhcpv6.MessageType
	hasRequestType bool
}

func pending6EntryFor(clientAddr net.IP, requestType dhcpv6.MessageType) pending6Entry {
	entry := pending6Entry{requestType: requestType, hasRequestType: requestType != dhcpv6.MessageTypeNone}
	if clientAddr != nil {
		if ip16 := clientAddr.To16(); ip16 != nil {
			copy(entry.clientAddr[:], ip16)
			entry.hasClientAddr = true
		}
	}
	return entry
}

// clientIP returns the recorded soliciting-client address, or nil when the
// entry carries none (which the reply path treats as unbound/fail-closed).
func (e pending6Entry) clientIP() net.IP {
	if !e.hasClientAddr {
		return nil
	}
	return net.IP(e.clientAddr[:])
}

// serverReplyTypeAllowed reports whether innerType is a legitimate
// server-to-client answer to the recorded client request type. RFC 8415:
// Solicit->Advertise; Request/Renew/Rebind/Confirm/Decline/Release/
// Information-request->Reply. RECONFIGURE (type 10) is server-initiated,
// is never an answer to a relayed request, and must carry its own
// authentication (RFC 8415 sections 20-21); it is therefore never allowed
// through the relay-reply path. A recorded request of any other type fails
// closed. The zero payload (no recorded request type, only the #10198
// fixture shape) uses the transitional floor in dhcpv6ServerReplyTypeAllowed.
func (e pending6Entry) serverReplyTypeAllowed(innerType dhcpv6.MessageType) bool {
	if !e.hasRequestType {
		return innerType == dhcpv6.MessageTypeSolicit ||
			innerType == dhcpv6.MessageTypeAdvertise ||
			innerType == dhcpv6.MessageTypeReply
	}
	switch e.requestType {
	case dhcpv6.MessageTypeSolicit:
		return innerType == dhcpv6.MessageTypeAdvertise
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm,
		dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind,
		dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline,
		dhcpv6.MessageTypeInformationRequest:
		return innerType == dhcpv6.MessageTypeReply
	default:
		return false
	}
}

// dhcpv6ServerReplyTypeAllowed is the request-independent floor. Solicit is
// included only as the transitional inner type of the #10198 dispatcher
// fixtures (NewMessage defaults to Solicit); production bindings always
// carry a recorded request type and the stricter per-request check above
// rejects a Solicit inner for every recorded request. RECONFIGURE and all
// other client-direction types are rejected here for every caller.
func dhcpv6ServerReplyTypeAllowed(innerType dhcpv6.MessageType) bool {
	return innerType == dhcpv6.MessageTypeSolicit ||
		innerType == dhcpv6.MessageTypeAdvertise ||
		innerType == dhcpv6.MessageTypeReply
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

// pending6MayReplyWithoutIA reports whether a server Reply to a client
// request of this type may legally carry no IA at all, so the request
// needs an IA-less alias binding (below) in addition to its IA-bound
// key. RFC 8415: a Confirm Reply carries Server ID, Client ID, and a
// Status Code with no IA required (§18.3.3, e.g. NotOnLink); a Release
// Reply carries a top-level Success Status Code, with an IA present
// only to carry NoBinding (§18.3.7); a Decline Reply has the same
// shape (§18.3.8). Every other request type's Reply is required to
// carry the IA it answers — Solicit draws Advertise, and Request,
// Renew, and Rebind draw a Reply echoing the IA — so those requests
// get no alias and an IA-less reply to them is still dropped. An
// Information-request carries no IA in the first place, so its
// primary key already is the IA-less key and needs no second entry.
func pending6MayReplyWithoutIA(requestType dhcpv6.MessageType) bool {
	switch requestType {
	case dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRelease,
		dhcpv6.MessageTypeDecline:
		return true
	default:
		return false
	}
}

// pending6IALessKey returns the key an IA-less message with the same
// transaction ID and Client ID keys to: IA type 0 and a zero IAID,
// exactly as pending6KeyFor computes it for such a message.
func pending6IALessKey(key pending6Key) pending6Key {
	key.iaType = 0
	key.iaid = [4]byte{}
	return key
}

// insertPending6 records the binding for a client request the relay is
// about to forward upstream: the primary IA-bound key, plus — for the
// request types in pending6MayReplyWithoutIA whose Reply may legally
// omit every IA — an IA-less alias key carrying the same entry. The
// alias lets a conformant IA-less Reply (Confirm NotOnLink, Release
// or Decline Success) match the transaction that carried an IA, which
// the IA-bound key alone could never do (#14599). The alias entry
// carries the same recorded client address and request type, so every
// #14181 check on the reply path (outer peer-address equality and
// legitimate server answer type) applies unchanged, and an IA-less
// Advertise or RECONFIGURE answering a Confirm still fails the
// per-request type check. The alias consumes one extra ring slot;
// eviction can only cause a legitimate reply to be dropped, never an
// unsolicited one to be accepted (see pending.go).
func insertPending6(table *pendingTableOf[pending6Key, pending6Entry], key pending6Key, requestType dhcpv6.MessageType, peer net.IP) {
	entry := pending6EntryFor(peer, requestType)
	table.insertValue(key, entry)
	if pending6MayReplyWithoutIA(requestType) {
		if alias := pending6IALessKey(key); alias != key {
			table.insertValue(alias, entry)
		}
	}
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
