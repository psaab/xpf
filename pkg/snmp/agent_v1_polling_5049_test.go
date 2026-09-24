package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5049: the request-dispatch switch handled only v2c (version 1) and v3
// (version 3); the version-0 (SNMPv1) case fell through to the "unsupported
// version" default and returned nil, so the agent emitted v1 traps
// (buildLinkTrapV1) but silently dropped every v1 GET/GETNEXT/SET poll — a
// legacy v1 manager timed out and saw the device as down. These tests exercise
// the v1 request path end to end and assert the v1 response rules (RFC 1157 /
// RFC 2089): noSuchName on a missing/unresolvable name, a 1-based error-index,
// echoed request varbinds with NO per-varbind exception value, and no v2-only
// Counter64 on the wire. They are RED on revert: stash the agent.go dispatch
// case + handlers and every "expect a response" assertion below gets nil.

// --- v1 request/response test helpers (self-contained: they use only symbols
// that predate #5049, so this file still compiles when the production change is
// stashed for the RED-on-revert proof, and each test then fails with a nil
// response rather than a build error). ---

// buildV1Request builds an SNMPv1 message (version field 0) carrying the given
// request PDU (GET 0xa0 / GETNEXT 0xa1 / SET 0xa3) over a list of OIDs, each
// with a NULL value, exactly as a v1 manager encodes a request.
func buildV1Request(pduTag byte, community string, requestID int, oids [][]int) []byte {
	var vbList []byte
	for _, oid := range oids {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
		valBytes := berEncodeTLV(tagNull, nil)
		vbList = append(vbList, berEncodeTLV(tagSequence, append(oidBytes, valBytes...))...)
	}
	vbListEnc := berEncodeTLV(tagSequence, vbList)

	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // error-status (0 in a request)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // error-index  (0 in a request)
	pduBody = append(pduBody, vbListEnc...)
	pdu := berEncodeTLV(pduTag, pduBody)

	msg := berEncodeIntegerTLV(snmpVersion1) // version field 0
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

// v1VB is a fully-decoded response varbind: OID, value tag, and value bytes, so
// a test can assert the exact type on the wire (crucially: never Counter64, and
// never an exception tag) and the returned value.
type v1VB struct {
	oid []int
	tag byte
	val []byte
}

// decodeV1Response walks a v1 GetResponse to completion, asserting the message
// version field is 0 (a v1 response, not v2c), and returns the error-status,
// error-index, and every decoded varbind.
func decodeV1Response(t *testing.T, resp []byte) (errStatus, errIndex int, vbs []v1VB) {
	t.Helper()
	tag, body, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: outer SEQUENCE: tag=0x%02x err=%v", tag, err)
	}
	version, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	if version != snmpVersion1 {
		t.Fatalf("resp: version = %d, want %d (v1)", version, snmpVersion1)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("resp: community: %v", err)
	}
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil || pduTag != pduGetResponse {
		t.Fatalf("resp: PDU header tag=0x%02x err=%v (want GetResponse 0x%02x)", pduTag, err, pduGetResponse)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	errStatus, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	errIndex, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	return errStatus, errIndex, decodeV1Varbinds(t, pduRest)
}

// decodeV1Varbinds decodes every varbind (OID + value tag + value bytes) in an
// encoded varbind-list SEQUENCE.
func decodeV1Varbinds(t *testing.T, vbListTLV []byte) []v1VB {
	t.Helper()
	tag, vbListBody, err := berDecodeHeader(vbListTLV)
	if err != nil || tag != tagSequence {
		t.Fatalf("varbind list: not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	var vbs []v1VB
	remaining := vbListBody
	for len(remaining) > 0 {
		vbTotal := berEncodedLen(remaining)
		if vbTotal <= 0 || vbTotal > len(remaining) {
			t.Fatalf("varbind: bad length %d", vbTotal)
		}
		vbTag, vbBody, err := berDecodeHeader(remaining)
		if err != nil || vbTag != tagSequence {
			t.Fatalf("varbind: not a SEQUENCE (tag=0x%02x err=%v)", vbTag, err)
		}
		remaining = remaining[vbTotal:]

		// OID (first element).
		if len(vbBody) < 2 || vbBody[0] != tagObjectIdentifier {
			t.Fatalf("varbind: first element not an OID")
		}
		oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
		if err != nil {
			t.Fatalf("varbind: OID length: %v", err)
		}
		oidStart := 1 + oidLenBytes
		oid, err := berDecodeOID(vbBody[oidStart : oidStart+oidLen])
		if err != nil {
			t.Fatalf("varbind: OID decode: %v", err)
		}

		// Value (second element): capture its tag and content bytes.
		valTLV := vbBody[oidStart+oidLen:]
		valTag, valBody, err := berDecodeHeader(valTLV)
		if err != nil {
			t.Fatalf("varbind: value header: %v", err)
		}
		vbs = append(vbs, v1VB{oid: oid, tag: valTag, val: valBody})
	}
	return vbs
}

func oidsEqualT(a, b []int) bool {
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

// v1TestIfData is one interface with populated ifTable + ifXTable columns,
// including the four Counter64 high-capacity columns (ifHCInOctets 6,
// ifHCInUcastPkts 7, ifHCOutOctets 10, ifHCOutUcastPkts 11) a v1 walk must step
// over.
func v1TestIfData() []IfData {
	return []IfData{{
		IfIndex:          1,
		IfDescr:          "ge-0-0-0",
		IfType:           6,
		IfMtu:            1500,
		IfSpeed:          1000000000,
		AdminStatus:      1,
		OperStatus:       1,
		InOctets:         12345,
		OutOctets:        67890,
		IfName:           "ge-0-0-0",
		InMulticastPkts:  10,
		InBroadcastPkts:  20,
		OutMulticastPkts: 30,
		OutBroadcastPkts: 40,
		HCInOctets:       18000000000000000000, // Counter64
		HCInUcastPkts:    17000000000000000000, // Counter64
		HCOutOctets:      16000000000000000000, // Counter64
		HCOutUcastPkts:   15000000000000000000, // Counter64
		IfHighSpeed:      1000,
		IfAlias:          "uplink",
	}}
}

func v1Agent() *Agent {
	a := NewAgent(&config.SNMPConfig{
		Description: "xpf v1 test",
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(v1TestIfData)
	return a
}

// TestV1Get_KnownOID_ReturnsValue: a v1 GET of a known OID (sysDescr) returns a
// v1 GET-RESPONSE (version 0) carrying the value, not nil/timeout.
func TestV1Get_KnownOID_ReturnsValue(t *testing.T) {
	a := v1Agent()
	req := buildV1Request(pduGetRequest, "public", 1, [][]int{oidSysDescr})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("v1 GET of sysDescr returned nil — v1 polling dropped (#5049)")
	}
	errStatus, errIndex, vbs := decodeV1Response(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError (%d)", errStatus, errNoError)
	}
	if errIndex != 0 {
		t.Fatalf("error-index = %d, want 0 on success", errIndex)
	}
	if len(vbs) != 1 {
		t.Fatalf("got %d varbinds, want 1", len(vbs))
	}
	if !oidsEqualT(vbs[0].oid, oidSysDescr) {
		t.Fatalf("varbind OID = %v, want sysDescr %v", vbs[0].oid, oidSysDescr)
	}
	if vbs[0].tag != tagOctetString {
		t.Fatalf("sysDescr value tag = 0x%02x, want OctetString 0x%02x", vbs[0].tag, tagOctetString)
	}
	if string(vbs[0].val) != "xpf v1 test" {
		t.Fatalf("sysDescr value = %q, want %q", string(vbs[0].val), "xpf v1 test")
	}
}

// TestV1GetNext_WalksAndSkipsCounter64: a v1 GETNEXT walk from before the MIB
// start steps lexicographically through every served object, STEPS OVER all
// four Counter64 columns (RFC 2089 — v1 cannot carry Counter64), never emits a
// Counter64 tag or an exception tag, and finally terminates with noSuchName at
// the end of the MIB view.
func TestV1GetNext_WalksAndSkipsCounter64(t *testing.T) {
	a := v1Agent()

	// ifXTable Counter64 columns (must be skipped in a v1 walk).
	c64cols := map[int]bool{6: true, 7: true, 10: true, 11: true}
	isIfXCounter64 := func(oid []int) bool {
		if len(oid) != len(oidIfXTablePrefix)+2 {
			return false
		}
		for i := range oidIfXTablePrefix {
			if oid[i] != oidIfXTablePrefix[i] {
				return false
			}
		}
		return c64cols[oid[len(oidIfXTablePrefix)]]
	}

	// Start below sysDescr so the first GETNEXT lands on the first served OID.
	cur := []int{1, 3, 6, 1, 2, 1, 1, 1}
	var walked [][]int
	sawGauge64Col := false // did we walk PAST the Counter64 region to ifHighSpeed?
	for steps := 0; steps < 200; steps++ {
		req := buildV1Request(pduGetNextRequest, "public", 100+steps, [][]int{cur})
		resp := a.handlePacket(req)
		if resp == nil {
			t.Fatalf("v1 GETNEXT step %d returned nil (#5049)", steps)
		}
		errStatus, errIndex, vbs := decodeV1Response(t, resp)
		if errStatus == errNoSuchName {
			// End of MIB view: v1 signals it as noSuchName, index of the OID.
			if errIndex != 1 {
				t.Fatalf("end-of-MIB error-index = %d, want 1", errIndex)
			}
			if len(vbs) != 1 {
				t.Fatalf("end-of-MIB echo must carry the 1 request varbind, got %d", len(vbs))
			}
			// The echoed varbind is the request OID with a NULL value — NOT an
			// endOfMibView (0x82) or any other exception tag.
			if vbs[0].tag != tagNull {
				t.Fatalf("end-of-MIB echo value tag = 0x%02x, want NULL 0x%02x (no v2 exception in v1)", vbs[0].tag, tagNull)
			}
			if !oidsEqualT(vbs[0].oid, cur) {
				t.Fatalf("end-of-MIB echo OID = %v, want the request OID %v", vbs[0].oid, cur)
			}
			if !sawGauge64Col {
				t.Fatal("walk ended before reaching ifHighSpeed — the Counter64 region was not traversed")
			}
			return // success
		}
		if errStatus != errNoError {
			t.Fatalf("GETNEXT step %d error-status = %d, want noError", steps, errStatus)
		}
		if len(vbs) != 1 {
			t.Fatalf("GETNEXT step %d: got %d varbinds, want 1", steps, len(vbs))
		}
		got := vbs[0]

		// v1 rule 1: no Counter64 tag ever on the wire.
		if got.tag == tagCounter64 {
			t.Fatalf("GETNEXT returned a Counter64 value (tag 0x%02x) at OID %v — forbidden in v1", got.tag, got.oid)
		}
		// v1 rule 2: no exception tags.
		if got.tag == tagNoSuchObject || got.tag == tagNoSuchInstance || got.tag == tagEndOfMibView {
			t.Fatalf("GETNEXT returned a v2 exception tag 0x%02x at OID %v — forbidden in v1", got.tag, got.oid)
		}
		// v1 rule 3: the walk stepped OVER every Counter64 column (never named).
		if isIfXCounter64(got.oid) {
			t.Fatalf("GETNEXT landed ON a Counter64 column OID %v — must be skipped in v1", got.oid)
		}
		// Strictly increasing.
		if len(walked) > 0 && oidCompare(got.oid, walked[len(walked)-1]) <= 0 {
			t.Fatalf("GETNEXT not strictly increasing: %v after %v", got.oid, walked[len(walked)-1])
		}
		// ifHighSpeed (ifXTable col 15) sits AFTER the Counter64 columns; seeing
		// it proves the walk crossed the Counter64 region by skipping it.
		if len(got.oid) == len(oidIfXTablePrefix)+2 && got.oid[len(oidIfXTablePrefix)] == 15 {
			sawGauge64Col = true
		}
		walked = append(walked, got.oid)
		cur = got.oid
	}
	t.Fatal("v1 GETNEXT walk did not terminate within 200 steps")
}

// TestV1Get_UnknownOID_NoSuchName: a v1 GET where one requested OID is
// unresolvable fails the whole PDU with noSuchName, the 1-based error-index of
// the offending varbind, and the request varbinds echoed with NULL values (no
// per-varbind exception value).
func TestV1Get_UnknownOID_NoSuchName(t *testing.T) {
	a := v1Agent()
	unknown := []int{1, 3, 6, 1, 4, 1, 99999, 42, 0} // not served
	oids := [][]int{oidSysDescr, unknown, oidSysUpTime}
	req := buildV1Request(pduGetRequest, "public", 7, oids)
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("v1 GET returned nil (#5049)")
	}
	errStatus, errIndex, vbs := decodeV1Response(t, resp)
	if errStatus != errNoSuchName {
		t.Fatalf("error-status = %d, want noSuchName (%d)", errStatus, errNoSuchName)
	}
	if errIndex != 2 {
		t.Fatalf("error-index = %d, want 2 (the unknown OID is the 2nd varbind)", errIndex)
	}
	if len(vbs) != len(oids) {
		t.Fatalf("echoed %d varbinds, want %d (the request varbinds)", len(vbs), len(oids))
	}
	for i, vb := range vbs {
		if !oidsEqualT(vb.oid, oids[i]) {
			t.Fatalf("echo varbind %d OID = %v, want %v", i, vb.oid, oids[i])
		}
		// No exception value and no Counter64 — v1 echoes NULLs.
		if vb.tag != tagNull {
			t.Fatalf("echo varbind %d tag = 0x%02x, want NULL 0x%02x (no exception value in v1)", i, vb.tag, tagNull)
		}
	}
}

// TestV1Get_Counter64Node_NoSuchName: a direct v1 GET of a Counter64-typed node
// (ifHCInOctets, ifXTable col 6) is not representable in v1, so it returns
// noSuchName — never a Counter64 on the wire (RFC 2089).
func TestV1Get_Counter64Node_NoSuchName(t *testing.T) {
	a := v1Agent()
	hcInOctets := append(append([]int{}, oidIfXTablePrefix...), 6, 1) // col 6, ifIndex 1
	req := buildV1Request(pduGetRequest, "public", 9, [][]int{hcInOctets})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("v1 GET of a Counter64 node returned nil (#5049)")
	}
	errStatus, errIndex, vbs := decodeV1Response(t, resp)
	if errStatus != errNoSuchName {
		t.Fatalf("error-status = %d, want noSuchName (%d) for a Counter64 GET", errStatus, errNoSuchName)
	}
	if errIndex != 1 {
		t.Fatalf("error-index = %d, want 1", errIndex)
	}
	if len(vbs) != 1 {
		t.Fatalf("got %d varbinds, want 1", len(vbs))
	}
	if vbs[0].tag == tagCounter64 {
		t.Fatalf("v1 GET of a Counter64 node put a Counter64 (tag 0x%02x) on the wire — forbidden", vbs[0].tag)
	}
	if vbs[0].tag != tagNull {
		t.Fatalf("Counter64 GET echo tag = 0x%02x, want NULL 0x%02x", vbs[0].tag, tagNull)
	}
}

// TestV1_SourceAllowlistEnforced: the v1 path enforces the SAME community
// `clients` source-IP allowlist (#4289) as v2c — a query from a non-permitted
// source is dropped (nil), a query from a permitted source is served.
func TestV1_SourceAllowlistEnforced(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"scoped": {
				Name:          "scoped",
				Authorization: "read-only",
				Clients:       []config.SNMPClient{{Prefix: "10.0.0.0/24"}},
			},
		},
	})
	req := buildV1Request(pduGetRequest, "scoped", 1, [][]int{oidSysDescr})

	if resp := a.handlePacketFrom(req, snmpSource10687("10.0.0.9")); resp == nil {
		t.Fatal("v1 GET from a permitted source (10.0.0.9) was dropped; want a response")
	}
	if resp := a.handlePacketFrom(req, snmpSource10687("192.0.2.5")); resp != nil {
		t.Fatal("v1 GET from a non-permitted source (192.0.2.5) was answered; source allowlist not enforced")
	}
}

// TestV1_UnknownCommunityDropped: an unknown community is dropped on the v1
// path exactly as on v2c (no response).
func TestV1_UnknownCommunityDropped(t *testing.T) {
	a := v1Agent()
	req := buildV1Request(pduGetRequest, "wrong-community", 1, [][]int{oidSysDescr})
	if resp := a.handlePacket(req); resp != nil {
		t.Fatal("v1 GET with an unknown community was answered; want no response")
	}
}

// TestV1_MalformedRejected: a truncated/malformed v1 packet is rejected (nil),
// the same as v2c — the shared outer-SEQUENCE / version / PDU BER guards apply.
func TestV1_MalformedRejected(t *testing.T) {
	a := v1Agent()
	good := buildV1Request(pduGetRequest, "public", 1, [][]int{oidSysDescr})

	// Truncated packet: keep the outer header but chop the body.
	truncated := good[:len(good)/2]
	if resp := a.handlePacket(truncated); resp != nil {
		t.Fatal("malformed (truncated) v1 packet was answered; want no response")
	}

	// Garbage that is not a SEQUENCE at all.
	if resp := a.handlePacket([]byte{0x01, 0x02, 0x03}); resp != nil {
		t.Fatal("non-SEQUENCE v1 garbage was answered; want no response")
	}
}

// TestV1Get_OversizedReturnsTooBig: a v1 GET naming many long-valued OIDs would
// encode a response larger than maxPacketSize. Like v2c, it is size-bounded —
// replaced with tooBig + an empty varbind list, never emitted over-size (shared
// boundGetResponseVersion). RED-on-revert: with v1 dropped, resp is nil.
func TestV1Get_OversizedReturnsTooBig(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(60) })

	req := buildV1Request(pduGetRequest, "public", 1, ifDescrOIDs(60))
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("v1 GET returned nil (#5049)")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("v1 GET response %d bytes exceeds maxPacketSize %d (size cap not applied)", len(resp), maxPacketSize)
	}
	errStatus, _, vbs := decodeV1Response(t, resp)
	if errStatus != errTooBig {
		t.Fatalf("error-status = %d, want tooBig (%d) for an oversized v1 GET", errStatus, errTooBig)
	}
	if len(vbs) != 0 {
		t.Fatalf("tooBig response must carry an empty varbind list, got %d varbinds", len(vbs))
	}
}

// TestV1Set_NoSuchName: the agent serves only read-only objects and v1 lacks
// the noAccess/notWritable statuses v2c uses; per RFC 2089 both map to
// noSuchName. A v1 SET (read-only community, or read-write with no writable
// object) returns noSuchName with error-index 1 and the request varbinds echoed.
func TestV1Set_NoSuchName(t *testing.T) {
	// read-only community.
	a := v1Agent()
	req := buildV1Request(pduSetRequest, "public", 1, [][]int{oidSysContact})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("v1 SET returned nil (#5049)")
	}
	errStatus, errIndex, vbs := decodeV1Response(t, resp)
	if errStatus != errNoSuchName {
		t.Fatalf("v1 SET (read-only) error-status = %d, want noSuchName (%d)", errStatus, errNoSuchName)
	}
	if errIndex != 1 {
		t.Fatalf("v1 SET error-index = %d, want 1", errIndex)
	}
	if len(vbs) != 1 || !oidsEqualT(vbs[0].oid, oidSysContact) || vbs[0].tag != tagNull {
		t.Fatalf("v1 SET must echo the request varbind as NULL; got %+v", vbs)
	}

	// read-write community: still noSuchName (no writable object exists), never
	// a v2-only notWritable(17)/noAccess(6).
	arw := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})
	arw.SetIfDataFn(v1TestIfData)
	reqRW := buildV1Request(pduSetRequest, "private", 2, [][]int{oidSysContact})
	respRW := arw.handlePacket(reqRW)
	if respRW == nil {
		t.Fatal("v1 SET (read-write) returned nil (#5049)")
	}
	errStatusRW, _, _ := decodeV1Response(t, respRW)
	if errStatusRW != errNoSuchName {
		t.Fatalf("v1 SET (read-write) error-status = %d, want noSuchName (%d)", errStatusRW, errNoSuchName)
	}
}
