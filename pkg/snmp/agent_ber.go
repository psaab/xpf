package snmp

import (
	"encoding/binary"
	"fmt"
	"math"
)

// --- ASN.1 BER codec + OID helpers ---
//
// Pure, Agent-independent SNMP wire primitives: BER tag-length-value
// encode/decode, the Counter32/Gauge32/Counter64/TimeTicks/OID/integer
// encoders, the PDU field decoder, and the OID comparison helpers.
// Extracted verbatim from agent.go (#5661 modularity cohort).

// maxOIDSubIdentifier is the upper bound RFC 2578 §7.1.3 puts on an OID
// sub-identifier: "the value range for each sub-identifier is 0..4294967295",
// i.e. an unsigned 32-bit integer.
//
// #9133: the codec modelled sub-identifiers as a platform-width SIGNED `int`
// with no bound at all, and every consequence followed from that one modelling
// choice rather than from three separate defects:
//
//   - `berDecodeOID` accumulated `val = (val << 7) | int(data[i]&0x7f)` over an
//     unbounded continuation run, so a crafted GET with ten continuation octets
//     (70 bits) returned a NEGATIVE component with NO error;
//   - `berEncodeSubID`'s `if val < 0x80 { return []byte{byte(val)} }` is true
//     for every negative value, so re-encoding such a component emitted a lone
//     continuation octet — malformed BER the agent's OWN decoder rejects
//     ("ber: OID sub-identifier truncated"). `echoVarbinds` puts the REQUEST
//     OIDs into the response, so a crafted request made the agent emit a reply
//     it could not itself parse;
//   - `oidCompare` compares components with a signed `<`, so a huge sub-id
//     sorted BEFORE 1 and a GETNEXT from it restarted at the top of the subtree.
//
// Bounding the DECODER is what fixes all three: an out-of-range component can
// no longer enter the OID list from the wire, so the encoder's guard below and
// `oidCompare`'s signed comparison are both operating on 0..4294967295 and are
// correct as written. `oidCompare` is therefore deliberately unchanged — it was
// the least load-bearing of the three sites, and rewriting it would have left
// the actual entry point open.
const maxOIDSubIdentifier = math.MaxUint32

// Compile-time guard for the SECOND half of the title: "platform-width".
// Components are carried as `[]int`, so `int` must be able to hold
// maxOIDSubIdentifier for the carry to be lossless. This constant expression is
// negative — and a uint constant overflow, i.e. a compile error — on a platform
// whose `int` is 32 bits. xpf builds for amd64/arm64 only; if a 32-bit target
// is ever added, this fails to build rather than silently wrapping every large
// sub-identifier negative, which is #9133 restored by the back door.
const _ uint = uint(^uint(0)>>1) - maxOIDSubIdentifier

// oidHasPrefix checks if oid starts with prefix.
func oidHasPrefix(oid, prefix []int) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}
	return true
}

// berEncodeCounter32 encodes a Counter32 value (unsigned 32-bit).
func berEncodeCounter32(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	// Strip leading zeros but keep at least one byte.
	// If high bit set, prepend zero for unsigned.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf
}

// berEncodeGauge32 encodes a Gauge32 value (unsigned 32-bit).
func berEncodeGauge32(val uint32) []byte {
	return berEncodeCounter32(val) // same encoding
}

// berEncodeCounter64 encodes a Counter64 value (unsigned 64-bit).
func berEncodeCounter64(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	// Strip leading zeros but keep at least one byte.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	// If high bit set, prepend zero for unsigned representation.
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf
}

// --- BER encoding helpers ---

// tagTimeTicks is the ASN.1 application tag for TimeTicks (hundredths of a second).
const tagTimeTicks = 0x43

// berEncodeTLV encodes a tag-length-value triplet.
func berEncodeTLV(tag byte, value []byte) []byte {
	length := len(value)
	var buf []byte
	buf = append(buf, tag)
	buf = append(buf, berEncodeLength(length)...)
	buf = append(buf, value...)
	return buf
}

// berEncodeLength encodes a BER length field.
func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Multi-byte length.
	var lenBytes []byte
	l := length
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...)
}

// berEncodeIntegerTLV encodes an integer as a complete TLV.
func berEncodeIntegerTLV(val int) []byte {
	return berEncodeTLV(tagInteger, berEncodeIntegerValue(val))
}

// berEncodeIntegerValue encodes an integer value (without tag/length).
func berEncodeIntegerValue(val int) []byte {
	if val == 0 {
		return []byte{0}
	}

	// Convert to big-endian bytes with proper sign handling.
	var bytes []byte
	if val > 0 {
		for v := val; v > 0; v >>= 8 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
		}
		// If high bit set, prepend a zero byte (positive number must not look negative).
		if bytes[0]&0x80 != 0 {
			bytes = append([]byte{0}, bytes...)
		}
	} else {
		// Negative: two's complement encoding.
		for v := val; v < -1; v >>= 8 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			bytes = append([]byte{0xff}, bytes...)
		}
	}
	return bytes
}

// berEncodeTimeTicks encodes a TimeTicks value (unsigned 32-bit integer).
func berEncodeTimeTicks(hundredths int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(hundredths))
	// Strip leading zeros but keep at least one byte.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	// TimeTicks is an unsigned APPLICATION integer: if the most-significant
	// content octet has its high bit set, prepend a 0x00 so the value is not
	// misdecoded as a negative signed INTEGER. This mirrors berEncodeCounter32 /
	// berEncodeGauge32 / berEncodeCounter64; without it a sysUpTime or v1/v2
	// link-trap timestamp at >= 0x80000000 hundredths (~248.5 days of uptime)
	// encodes as non-canonical/negative BER that strict managers reject (#4924).
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0x00}, buf...)
	}
	return buf
}

// berEncodeOID encodes an OID value (without tag/length). Returns nil — the
// existing "not encodable" signal, already used for an OID with fewer than two
// components — when any component past the first two is outside RFC 2578's
// 0..4294967295 (#9133).
//
// Reachability, stated precisely rather than assumed: with berDecodeOID bounded
// this guard cannot fire on a wire-sourced OID, so it is defence in depth
// against an internal bug, not the fix. It matters anyway because the
// alternative is silent: berEncodeSubID's old first branch turned a negative
// component into a lone continuation octet, and nothing downstream could tell
// that apart from a real encoding.
//
// The first two components are deliberately NOT bounded here. X.690 §8.19.4
// folds them into one octet, and berDecodeOID reconstructs them as
// `data[0]/40` and `data[0]%40` — which for a first octet above 0x77 yields a
// first arc above 2, technically invalid ASN.1 that nonetheless round-trips
// byte-for-byte. Rejecting it would replace a faithful echo of the client's own
// OID with an empty one, which is worse for the client and is not what #9133 is
// about.
func berEncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	// First two components are combined: first*40 + second.
	var encoded []byte
	encoded = append(encoded, byte(oid[0]*40+oid[1]))
	for i := 2; i < len(oid); i++ {
		if oid[i] < 0 || uint64(oid[i]) > maxOIDSubIdentifier {
			return nil
		}
		encoded = append(encoded, berEncodeSubID(uint32(oid[i]))...)
	}
	return encoded
}

// berEncodeSubID encodes a single OID sub-identifier using base-128 encoding.
//
// #9133: the parameter is `uint32`, RFC 2578's actual sub-identifier type, so
// the out-of-range case is UNREPRESENTABLE at the call rather than checked
// inside. The old `int` parameter's `val < 0x80` fast path was true for every
// negative value and returned `byte(val)` — 0xFF for -1 — a lone continuation
// octet with no terminator.
func berEncodeSubID(val uint32) []byte {
	if val < 0x80 {
		return []byte{byte(val)}
	}
	var bytes []byte
	for v := val; v > 0; v >>= 7 {
		bytes = append([]byte{byte(v & 0x7f)}, bytes...)
	}
	// Set high bit on all but the last byte.
	for i := 0; i < len(bytes)-1; i++ {
		bytes[i] |= 0x80
	}
	return bytes
}

// berEncodeValue encodes a value with the given tag.
func berEncodeValue(tag byte, value []byte) []byte {
	return berEncodeTLV(tag, value)
}

// encodeVarbind encodes one varbind as SEQUENCE { name OID, value } and
// appends it to dst (#17055). This is the sole varbind SEQUENCE wrap in the
// package: buildResponseVersion, buildV3Response, buildReportPDU /
// buildV3Discovery and both trap builders all go through it (traps build a
// []varbind first), so a varbind-encoding change lands in exactly one place.
//
// Exception tags (noSuchObject / noSuchInstance / endOfMibView) carry a nil
// value by definition; encodeVarbind preserves that even if the caller left
// a stray value on the varbind.
func encodeVarbind(dst []byte, vb varbind) []byte {
	body := berEncodeTLV(tagObjectIdentifier, berEncodeOID(vb.oid))
	if vb.tag == tagNoSuchObject || vb.tag == tagNoSuchInstance || vb.tag == tagEndOfMibView {
		body = append(body, berEncodeTLV(vb.tag, nil)...)
	} else {
		body = append(body, berEncodeValue(vb.tag, vb.value)...)
	}
	return append(dst, berEncodeTLV(tagSequence, body)...)
}

// encodeVarbindList encodes vbs as the varbind-list SEQUENCE (SEQUENCE OF
// VarBind) appended to nothing — it returns the complete list TLV.
func encodeVarbindList(vbs []varbind) []byte {
	var list []byte
	for _, vb := range vbs {
		list = encodeVarbind(list, vb)
	}
	return berEncodeTLV(tagSequence, list)
}

// encodePDU encodes a PDU whose body is request-id / error-status /
// error-index / varbind-list (GetResponse and Report share this shape,
// RFC 3416 §3) under the given PDU tag.
func encodePDU(tag byte, reqID, errStatus, errIndex int, vbList []byte) []byte {
	pduBody := berEncodeIntegerTLV(reqID)
	pduBody = append(pduBody, berEncodeIntegerTLV(errStatus)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(errIndex)...)
	pduBody = append(pduBody, vbList...)
	return berEncodeTLV(tag, pduBody)
}

// --- BER decoding helpers ---

// berDecodeHeader decodes a BER TLV header, returning the tag, the value bytes, and any error.
func berDecodeHeader(data []byte) (byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: data too short")
	}
	tag := data[0]
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return 0, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return 0, nil, fmt.Errorf("ber: value truncated (need %d, have %d)", headerLen+length, len(data))
	}
	return tag, data[headerLen : headerLen+length], nil
}

// berDecodeLength decodes a BER length field.
// Returns the length value and the number of bytes consumed.
func berDecodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("ber: empty length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, fmt.Errorf("ber: unsupported length encoding (%d bytes)", numBytes)
	}
	if len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("ber: length bytes truncated")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

// berDecodeInteger decodes a BER INTEGER, returning the value and remaining bytes.
func berDecodeInteger(data []byte) (int, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: integer too short")
	}
	if data[0] != tagInteger {
		return 0, nil, fmt.Errorf("ber: expected INTEGER (0x02), got 0x%02x", data[0])
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return 0, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return 0, nil, fmt.Errorf("ber: integer value truncated")
	}
	valBytes := data[headerLen : headerLen+length]
	val := 0
	// Sign-extend from first byte.
	if len(valBytes) > 0 && valBytes[0]&0x80 != 0 {
		val = -1
	}
	for _, b := range valBytes {
		val = (val << 8) | int(b)
	}
	return val, data[headerLen+length:], nil
}

// berDecodeOctetString decodes a BER OCTET STRING, returning the value and remaining bytes.
func berDecodeOctetString(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("ber: octet string too short")
	}
	if data[0] != tagOctetString {
		return nil, nil, fmt.Errorf("ber: expected OCTET STRING (0x04), got 0x%02x", data[0])
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return nil, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return nil, nil, fmt.Errorf("ber: octet string truncated")
	}
	return data[headerLen : headerLen+length], data[headerLen+length:], nil
}

// berDecodeOID decodes the raw bytes of a BER-encoded OID value into integer
// components.
//
// #9133: the accumulator is `uint64` and is bounded by RFC 2578's
// maxOIDSubIdentifier BEFORE each shift, so a sub-identifier that would exceed
// the standard's range is an ERROR rather than a silently wrapped value. This
// is the entry point that makes the whole family safe: no out-of-range
// component can reach berEncodeSubID or oidCompare from the wire.
//
// The bound also terminates an unbounded continuation run: five significant
// octets already exceed 32 bits, so any longer run is rejected at the octet
// that overflows rather than accumulating for as long as the PDU is.
func berDecodeOID(data []byte) ([]int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ber: empty OID")
	}
	// First byte encodes first two components: first = byte/40, second = byte%40.
	oid := []int{int(data[0]) / 40, int(data[0]) % 40}
	i := 1
	for i < len(data) {
		var val uint64
		for {
			if i >= len(data) {
				return nil, fmt.Errorf("ber: OID sub-identifier truncated")
			}
			// Checked BEFORE the shift: the pre-shift bound leaves val below
			// 2^25, so the shift itself can never overflow the accumulator —
			// no reasoning about the accumulator's width is required.
			if val > maxOIDSubIdentifier>>7 {
				return nil, fmt.Errorf(
					"ber: OID sub-identifier exceeds the RFC 2578 maximum (%d)",
					uint64(maxOIDSubIdentifier))
			}
			val = (val << 7) | uint64(data[i]&0x7f)
			if data[i]&0x80 == 0 {
				i++
				break
			}
			i++
		}
		oid = append(oid, int(val))
	}
	return oid, nil
}

// decodePDUFields decodes the common PDU fields: request-id, error-status/non-repeaters,
// error-index/max-repetitions, and the varbind list of OIDs.
func decodePDUFields(data []byte) (requestID int, field2 int, field3 int, oids [][]int, err error) {
	// request-id
	requestID, rest, err := berDecodeInteger(data)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("request-id: %w", err)
	}

	// error-status or non-repeaters
	field2, rest, err = berDecodeInteger(rest)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("field2: %w", err)
	}

	// error-index or max-repetitions
	field3, rest, err = berDecodeInteger(rest)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("field3: %w", err)
	}

	// varbind list (SEQUENCE of SEQUENCE).
	if len(rest) == 0 {
		return requestID, field2, field3, nil, nil
	}
	tag, vbListBody, err := berDecodeHeader(rest)
	if err != nil || tag != tagSequence {
		return 0, 0, 0, nil, fmt.Errorf("varbind list: not a SEQUENCE")
	}

	// Decode each varbind (SEQUENCE { OID, value }).
	//
	// #9333: a varbind this loop cannot decode is an ERROR, not something to
	// skip. It used to `continue` past five malformed shapes and `break` out of
	// a sixth, so the handler received a SHORTER OID list than the client sent
	// and answered `noError` with it. MEASURED: a two-varbind v1 GET with one
	// undecodable OID returned a response carrying ONE varbind, indistinguishable
	// from a request that only ever asked for one.
	//
	// That violates RFC 1157 §4.1.2 — the GetResponse's variable-bindings must
	// name the same variables the request did — and a manager that pairs values
	// to requests BY POSITION, which is the normal implementation, then reads the
	// wrong value for every varbind after the dropped one.
	//
	// Discarding the whole PDU is what BOTH standards prescribe for a message
	// that cannot be parsed (RFC 1157 §4.1, RFC 3416 §4.1), and it is what this
	// function ALREADY does for a malformed request-id, error-status,
	// error-index or varbind-list header — every caller turns an error here into
	// a dropped datagram. The six varbind arms were the only inconsistent ones.
	//
	// NOT changed, and asserted by TestWireVarbindByteFloors_6551: a varbind
	// carrying NO value TLV at all (`SEQUENCE { OID }`, 5 bytes) is still
	// accepted and its OID still delivered. It is well-formed — it reaches none
	// of the arms below — and #6551's densest-packing bound depends on it.
	remaining := vbListBody
	for len(remaining) > 0 {
		tag, vbBody, err := berDecodeHeader(remaining)
		if err != nil || tag != tagSequence {
			return 0, 0, 0, nil, fmt.Errorf("varbind: not a SEQUENCE")
		}
		// Advance past this varbind in the remaining buffer.
		vbTotalLen := berEncodedLen(remaining)
		if vbTotalLen <= 0 || vbTotalLen > len(remaining) {
			// UNREACHABLE, by construction rather than by inspection — and the
			// mutation matrix says so: reverting this to its original `break`
			// kills no cell, because no input reaches it.
			//
			// The proof is that `berDecodeHeader` (called above, on this same
			// slice) and `berEncodedLen` compute the SAME quantity from the SAME
			// bytes, and the header's check is strictly stronger. If the header
			// succeeded then len(remaining) >= 2, berDecodeLength succeeded, and
			// 1+lenBytes+length <= len(remaining) — which is exactly
			// berEncodedLen's return, so it is >= 2 and <= len(remaining).
			//
			// It is nonetheless an ERROR rather than the original `break`,
			// because the two functions are only equivalent while they stay in
			// lockstep. A `break` degrades silently if they ever diverge — it
			// drops this varbind AND every one after it, so the response is
			// short by an arbitrary number — and an error degrades into the
			// discard the rest of this loop already performs. Same cost, and the
			// failure mode is the one the rest of #9333 is about.
			return 0, 0, 0, nil, fmt.Errorf(
				"varbind: unreadable length (encoded len %d, %d bytes remain)",
				vbTotalLen, len(remaining))
		}
		remaining = remaining[vbTotalLen:]

		// Decode OID from varbind body.
		if len(vbBody) < 2 {
			return 0, 0, 0, nil, fmt.Errorf("varbind: body too short (%d bytes)", len(vbBody))
		}
		if vbBody[0] != tagObjectIdentifier {
			return 0, 0, 0, nil, fmt.Errorf(
				"varbind: first element is tag 0x%02x, not an OBJECT IDENTIFIER (0x%02x)",
				vbBody[0], tagObjectIdentifier)
		}
		oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
		if err != nil {
			return 0, 0, 0, nil, fmt.Errorf("varbind: OID length: %w", err)
		}
		oidHeaderLen := 1 + oidLenBytes
		if oidHeaderLen+oidLen > len(vbBody) {
			return 0, 0, 0, nil, fmt.Errorf(
				"varbind: OID value truncated (need %d, have %d)",
				oidHeaderLen+oidLen, len(vbBody))
		}
		oid, err := berDecodeOID(vbBody[oidHeaderLen : oidHeaderLen+oidLen])
		if err != nil {
			return 0, 0, 0, nil, fmt.Errorf("varbind: OID: %w", err)
		}
		oids = append(oids, oid)
	}

	return requestID, field2, field3, oids, nil
}

// berEncodedLen returns the total encoded length of a BER TLV at the start of data.
func berEncodedLen(data []byte) int {
	if len(data) < 2 {
		return -1
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return -1
	}
	return 1 + lenBytes + length
}

// --- OID comparison helpers ---

// oidEqual returns true if two OIDs are identical.
func oidEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// oidCompare compares two OIDs lexicographically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func oidCompare(a, b []int) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
