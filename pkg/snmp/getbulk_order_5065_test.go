package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5065: GETBULK must emit repeater varbinds repetition-major (RFC 3416
// §4.2.3), not column-major, and an exhausted repeater column must keep
// emitting endOfMibView in its own grid cell. Covered for both v2c and v3.

// oneIfData returns a single deterministic interface so the GETNEXT walk order
// over the static system group + ifTable + ifXTable is fully predictable.
func oneIfData() []IfData {
	return []IfData{{
		IfIndex:     1,
		IfDescr:     "ge-0-0-0",
		IfType:      6,
		IfMtu:       1500,
		IfSpeed:     1000000000,
		AdminStatus: 1,
		OperStatus:  1,
		IfName:      "ge-0-0-0",
		IfAlias:     "uplink",
		IfHighSpeed: 1000,
	}}
}

type decodedVB struct {
	oid    []int
	valTag byte
}

// decodeVarbindsFull decodes every varbind in an encoded varbind-list SEQUENCE,
// returning both the OID and the value's BER tag so a test can distinguish a
// real value from an endOfMibView (0x82) exception.
func decodeVarbindsFull(t *testing.T, vbListTLV []byte) []decodedVB {
	t.Helper()
	tag, vbListBody, err := berDecodeHeader(vbListTLV)
	if err != nil || tag != tagSequence {
		t.Fatalf("varbind list: not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	var out []decodedVB
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
		valTLV := vbBody[oidStart+oidLen:]
		if len(valTLV) < 1 {
			t.Fatalf("varbind: missing value TLV")
		}
		// Exactly two elements (#17055): the value TLV must consume the
		// remainder of the varbind body — a stray third element (the
		// stray-element mutant class) is malformed VarBind ::= SEQUENCE
		// { name, value } and must fail here, not be silently ignored.
		if n := berEncodedLen(valTLV); n != len(valTLV) {
			t.Fatalf("varbind: value TLV consumes %d of %d remaining bytes (stray element in varbind SEQUENCE)", n, len(valTLV))
		}
		out = append(out, decodedVB{oid: oid, valTag: valTLV[0]})
		remaining = remaining[vbTotal:]
	}
	return out
}

// v2cResponseVBList walks a v2c GetResponse to its varbind-list TLV bytes.
func v2cResponseVBList(t *testing.T, resp []byte) (errStatus int, vbList []byte) {
	t.Helper()
	tag, body, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("resp: community: %v", err)
	}
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil || pduTag != pduGetResponse {
		t.Fatalf("resp: PDU header tag=0x%02x err=%v", pduTag, err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	errStatus, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	return errStatus, pduRest
}

// v3ResponseVBList walks an authNoPriv v3 GetResponse to its varbind-list TLV.
func v3ResponseVBList(t *testing.T, resp []byte) (errStatus int, vbList []byte) {
	t.Helper()
	tag, msgBody, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(msgBody) // version
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	hdrLen := berEncodedLen(rest) // msgGlobalData SEQUENCE
	if hdrLen <= 0 || hdrLen >= len(rest) {
		t.Fatalf("resp: msgGlobalData length error")
	}
	rest = rest[hdrLen:]
	_, rest, err = berDecodeOctetString(rest) // msgSecurityParameters
	if err != nil {
		t.Fatalf("resp: secParams: %v", err)
	}
	tag, scopedBody, err := berDecodeHeader(rest) // scopedPDU SEQUENCE (plaintext)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: scopedPDU SEQUENCE: %v", err)
	}
	_, scopedRest, err := berDecodeOctetString(scopedBody) // contextEngineID
	if err != nil {
		t.Fatalf("resp: contextEngineID: %v", err)
	}
	_, scopedRest, err = berDecodeOctetString(scopedRest) // contextName
	if err != nil {
		t.Fatalf("resp: contextName: %v", err)
	}
	pduTag, pduBody, err := berDecodeHeader(scopedRest)
	if err != nil || pduTag != pduGetResponse {
		t.Fatalf("resp: PDU tag=0x%02x err=%v", pduTag, err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	errStatus, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	return errStatus, pduRest
}

func oidsEqual(a, b []int) bool {
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

func assertVBOID(t *testing.T, vbs []decodedVB, idx int, want []int) {
	t.Helper()
	if idx >= len(vbs) {
		t.Fatalf("varbind[%d] missing (only %d varbinds)", idx, len(vbs))
	}
	if !oidsEqual(vbs[idx].oid, want) {
		t.Fatalf("varbind[%d].oid = %v, want %v (wrong GETBULK order)", idx, vbs[idx].oid, want)
	}
}

// The two repeater columns and the interleaved OIDs a correct (repetition-major)
// GETBULK over one interface must produce, R=2 M=2:
//
//	col A start = sysDescr    -> A1 sysObjectID, A2 sysUpTime
//	col B start = sysLocation -> B1 ifNumber,    B2 ifTable.ifIndex.1
//
// repetition-major order: A1, B1, A2, B2.
// column-major (the #5065 bug): A1, A2, B1, B2 — index 1/2 swap and FAIL.
var (
	ifTableCol1Idx1 = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1}
	ifXTableCol15I1 = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15, 1}
	ifXTableCol18I1 = []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 1}
)

func assertRepetitionMajorR2M2(t *testing.T, vbs []decodedVB) {
	t.Helper()
	if len(vbs) != 4 {
		t.Fatalf("got %d varbinds, want 4 (R=2 x M=2)", len(vbs))
	}
	assertVBOID(t, vbs, 0, oidSysObjectID) // A1
	assertVBOID(t, vbs, 1, oidIfNumber)    // B1 — buggy column-major puts sysUpTime here
	assertVBOID(t, vbs, 2, oidSysUpTime)   // A2 — buggy column-major puts ifNumber here
	assertVBOID(t, vbs, 3, ifTableCol1Idx1)
}

func TestGetBulkRepetitionMajor_V2c_5065(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(oneIfData)

	req := buildV2cGetBulkRequest("public", 1, 0, 2, [][]int{oidSysDescr, oidSysLocation})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, vbList := v2cResponseVBList(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	assertRepetitionMajorR2M2(t, decodeVarbindsFull(t, vbList))
}

func TestGetBulkRepetitionMajor_V3_5065(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, oneIfData())

	req := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
		4096, 0, 2, [][]int{oidSysDescr, oidSysLocation})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, vbList := v3ResponseVBList(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	assertRepetitionMajorR2M2(t, decodeVarbindsFull(t, vbList))
}

// assertExhaustedColumnR2M3 checks the RFC 3416 §4.2.3 grid when one repeater
// column runs off the end of the MIB before the repetitions are exhausted:
//
//	col A start = sysDescr        -> A1 sysObjectID, A2 sysUpTime, A3 sysContact
//	col B start = ifXTable.15.1   -> B1 ifXTable.18.1 (the LAST OID),
//	                                 B2 endOfMibView@.18.1, B3 endOfMibView@.18.1
//
// repetition-major grid (6 cells): A1,B1,A2,B2,A3,B3. The exhausted column keeps
// its own cell filled with endOfMibView. The pre-#5065 code broke out of the
// column-B loop on first exhaustion and emitted only 5 column-major varbinds.
func assertExhaustedColumnR2M3(t *testing.T, vbs []decodedVB) {
	t.Helper()
	if len(vbs) != 6 {
		t.Fatalf("got %d varbinds, want 6 (R=2 x M=3, exhausted column keeps its cells)", len(vbs))
	}
	assertVBOID(t, vbs, 0, oidSysObjectID)
	assertVBOID(t, vbs, 1, ifXTableCol18I1)
	if vbs[1].valTag == tagEndOfMibView {
		t.Fatalf("varbind[1] is endOfMibView; the last real OID should carry a value")
	}
	assertVBOID(t, vbs, 2, oidSysUpTime)
	assertVBOID(t, vbs, 3, ifXTableCol18I1)
	if vbs[3].valTag != tagEndOfMibView {
		t.Fatalf("varbind[3].valTag = 0x%02x, want endOfMibView (0x82) in the exhausted column's cell", vbs[3].valTag)
	}
	assertVBOID(t, vbs, 4, oidSysContact)
	assertVBOID(t, vbs, 5, ifXTableCol18I1)
	if vbs[5].valTag != tagEndOfMibView {
		t.Fatalf("varbind[5].valTag = 0x%02x, want endOfMibView (0x82) placeholder in the exhausted column's later cell", vbs[5].valTag)
	}
}

func TestGetBulkExhaustedColumnEndOfMibView_V2c_5065(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(oneIfData)

	req := buildV2cGetBulkRequest("public", 1, 0, 3, [][]int{oidSysDescr, ifXTableCol15I1})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, vbList := v2cResponseVBList(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	assertExhaustedColumnR2M3(t, decodeVarbindsFull(t, vbList))
}

func TestGetBulkExhaustedColumnEndOfMibView_V3_5065(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, oneIfData())

	req := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
		4096, 0, 3, [][]int{oidSysDescr, ifXTableCol15I1})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, vbList := v3ResponseVBList(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	assertExhaustedColumnR2M3(t, decodeVarbindsFull(t, vbList))
}

// TestGetBulkThreeRepeaters_V2c_5065 exercises R=3 M=2 to make the column-major
// vs repetition-major distinction unambiguous across three columns.
//
//	col A start = sysDescr    -> A1 sysObjectID, A2 sysUpTime
//	col B start = sysUpTime   -> B1 sysContact,  B2 sysName
//	col C start = sysLocation -> C1 ifNumber,    C2 ifTable.1.1
//
// repetition-major: A1,B1,C1,A2,B2,C2.
func TestGetBulkThreeRepeaters_V2c_5065(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(oneIfData)

	req := buildV2cGetBulkRequest("public", 1, 0, 2,
		[][]int{oidSysDescr, oidSysUpTime, oidSysLocation})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	errStatus, vbList := v2cResponseVBList(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	vbs := decodeVarbindsFull(t, vbList)
	if len(vbs) != 6 {
		t.Fatalf("got %d varbinds, want 6 (R=3 x M=2)", len(vbs))
	}
	assertVBOID(t, vbs, 0, oidSysObjectID) // A1
	assertVBOID(t, vbs, 1, oidSysContact)  // B1
	assertVBOID(t, vbs, 2, oidIfNumber)    // C1
	assertVBOID(t, vbs, 3, oidSysUpTime)   // A2
	assertVBOID(t, vbs, 4, oidSysName)     // B2
	assertVBOID(t, vbs, 5, ifTableCol1Idx1)
}
