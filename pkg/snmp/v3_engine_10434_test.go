package snmp

import (
	"bytes"
	"crypto/hmac"
	"testing"
)

// usmStatsUnknownEngineIDsOID10434 is the RFC 3414 Report OID
// (1.3.6.1.6.3.15.1.1.4.0) a manager expects when it addresses the wrong
// authoritative engine. Kept test-local under a distinct name so the fix is
// free to introduce a package-level var without a redeclaration clash.
var usmStatsUnknownEngineIDsOID10434 = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}

// foreignEngineID10434 returns an engine ID that differs from local in the
// last octet. Same length, so the gate must compare content, not length.
func foreignEngineID10434(local []byte) []byte {
	out := append([]byte{}, local...)
	out[len(out)-1] ^= 0xFF
	return out
}

// buildV3SplitEngineRequest10434 builds an authNoPriv GetRequest carrying
// distinct USM msgAuthoritativeEngineID and scopedPDU contextEngineID values,
// so the two gates can be driven independently. HMAC is computed with authKey
// (localized against the agent's LOCAL engine ID) over the exact wire bytes,
// so a request naming a foreign engine still passes verifyAuth/timeliness and
// only the engine gate can reject it.
func buildV3SplitEngineRequest10434(t *testing.T, authProto, userName string, usmEngineID, contextEngineID, authKey []byte, msgFlags byte, boots, tm int, contextName []byte, oid []int) []byte {
	t.Helper()
	hashFn, _ := authHashFunc(authProto)
	if hashFn == nil {
		t.Fatalf("unknown auth proto %q", authProto)
	}
	truncLen := authTruncLen(authProto)

	authPlaceholder := make([]byte, truncLen)
	usmFields := berEncodeTLV(tagOctetString, usmEngineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(boots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(tm)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(11)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlags})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	scopedBody := berEncodeTLV(tagOctetString, contextEngineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, contextName)...)
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	vb = append(vb, berEncodeTLV(tagNull, nil)...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(77)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	scopedBody = append(scopedBody, berEncodeTLV(pduGetRequest, pduBody)...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	start, end, ok := usmAuthParamsRange(wholeMsg)
	if !ok || end-start != truncLen {
		t.Fatalf("usmAuthParamsRange failed on built request (ok=%v len=%d)", ok, end-start)
	}
	mac := hmac.New(hashFn, authKey)
	mac.Write(wholeMsg)
	computed := mac.Sum(nil)[:truncLen]
	copy(wholeMsg[start:end], computed)
	return wholeMsg
}

// assertV3ReportEncoding10434 verifies the RFC wire-level properties of a
// discovery/Report response: it is a Report PDU and its outgoing msgFlags
// clear reportableFlag (0x04).
func assertV3ReportEncoding10434(t *testing.T, resp []byte) {
	t.Helper()
	tag, msgBody, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("unknown-engine response: outer SEQUENCE decode failed: %v", err)
	}
	_, rest, err := berDecodeInteger(msgBody) // version
	if err != nil {
		t.Fatalf("unknown-engine response: version decode failed: %v", err)
	}
	hdrTag, hdrBody, err := berDecodeHeader(rest)
	if err != nil || hdrTag != tagSequence {
		t.Fatalf("unknown-engine response: header decode failed: %v", err)
	}
	_, hdrRest, err := berDecodeInteger(hdrBody) // msgID
	if err != nil {
		t.Fatalf("unknown-engine response: msgID decode failed: %v", err)
	}
	_, hdrRest, err = berDecodeInteger(hdrRest) // msgMaxSize
	if err != nil {
		t.Fatalf("unknown-engine response: msgMaxSize decode failed: %v", err)
	}
	flags, _, err := berDecodeOctetString(hdrRest)
	if err != nil || len(flags) != 1 {
		t.Fatalf("unknown-engine response: msgFlags decode failed: %v", err)
	}
	if flags[0]&msgFlagReportable != 0 {
		t.Fatalf("unknown-engine response: reportableFlag is set in response flags 0x%02x", flags[0])
	}

	headerLen := berEncodedLen(rest)
	if headerLen <= 0 || headerLen >= len(rest) {
		t.Fatalf("unknown-engine response: header length %d invalid", headerLen)
	}
	_, afterSec, err := berDecodeOctetString(rest[headerLen:])
	if err != nil {
		t.Fatalf("unknown-engine response: security parameters decode failed: %v", err)
	}
	scopedTag, scopedBody, err := berDecodeHeader(afterSec)
	if err != nil || scopedTag != tagSequence {
		t.Fatalf("unknown-engine response: scopedPDU decode failed: %v", err)
	}
	_, scopedRest, err := berDecodeOctetString(scopedBody) // contextEngineID
	if err != nil {
		t.Fatalf("unknown-engine response: contextEngineID decode failed: %v", err)
	}
	_, scopedRest, err = berDecodeOctetString(scopedRest) // contextName
	if err != nil {
		t.Fatalf("unknown-engine response: contextName decode failed: %v", err)
	}
	pduTag, _, err := berDecodeHeader(scopedRest)
	if err != nil || pduTag != 0xa8 {
		t.Fatalf("unknown-engine response: PDU tag 0x%02x, want Report 0xa8 (err=%v)", pduTag, err)
	}
}

// TestV3ForeignMsgEngineRejected_10434: an authenticated request carrying valid
// USM credentials but a FOREIGN msgAuthoritativeEngineID must be rejected with
// the standard usmStatsUnknownEngineIDs Report, not answered from the local MIB
// view. fail-on-revert: ignoring reqEngineID serves sysDescr -> red.
func TestV3ForeignMsgEngineRejected_10434(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	foreign := foreignEngineID10434(engineID)
	pkt := buildV3SplitEngineRequest10434(t, "sha", "tuser", foreign, engineID, authKey, msgFlagAuth|msgFlagReportable, 5, 1000, nil, oidSysDescr)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("foreign msgEngine request: got nil response, want usmStatsUnknownEngineIDs Report")
	}
	if bytes.Contains(resp, []byte("xpf stateful firewall")) {
		t.Fatal("foreign msgEngine request: answered from local MIB view, want unknown-engine Report")
	}
	if !bytes.Contains(resp, berEncodeOID(usmStatsUnknownEngineIDsOID10434)) {
		t.Fatal("foreign msgEngine request: response missing usmStatsUnknownEngineIDs Report OID")
	}
	assertV3ReportEncoding10434(t, resp)
}

// TestV3ForeignMsgEngineNotReportableDropped_10434 verifies the RFC 3414/3412
// reportable-flag guard: a foreign authoritative engine must not receive a
// reflected Report when the request clears msgFlagReportable.
func TestV3ForeignMsgEngineNotReportableDropped_10434(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	foreign := foreignEngineID10434(engineID)
	pkt := buildV3SplitEngineRequest10434(t, "sha", "tuser", foreign, engineID, authKey, msgFlagAuth, 5, 1000, nil, oidSysDescr)
	a.lastPacket = pkt

	if resp := driveV3(t, a, pkt); resp != nil {
		t.Fatalf("foreign non-reportable request: got %d-byte response, want drop", len(resp))
	}
}

// TestV3ForeignContextEngineEmptyView_10434: a request with the local USM
// engine but a FOREIGN contextEngineID and default contextName must NOT be
// served local MIB data; it gets the empty-view noSuchInstance exception, the
// same behavior as a non-default contextName.
func TestV3ForeignContextEngineEmptyView_10434(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	foreign := foreignEngineID10434(engineID)
	pkt := buildV3SplitEngineRequest10434(t, "sha", "tuser", engineID, foreign, authKey, msgFlagAuth|msgFlagReportable, 5, 1000, nil, oidSysDescr)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("foreign contextEngine request: got nil response (should be empty-view, not dropped)")
	}
	if bytes.Contains(resp, []byte("xpf stateful firewall")) {
		t.Fatal("foreign contextEngine request: leaked default-context sysDescr value")
	}
	if !bytes.Contains(resp, []byte{tagNoSuchInstance, 0x00}) {
		t.Fatal("foreign contextEngine request: response missing noSuchInstance exception")
	}
}

// TestV3LocalEnginesAccepted_10434 is the positive control: local USM engine +
// local context engine + default context still returns the sysDescr value.
func TestV3LocalEnginesAccepted_10434(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	pkt := buildV3SplitEngineRequest10434(t, "sha", "tuser", engineID, engineID, authKey, msgFlagAuth|msgFlagReportable, 5, 1000, nil, oidSysDescr)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("local-engine request: got nil response")
	}
	if !bytes.Contains(resp, []byte("xpf stateful firewall")) {
		t.Fatal("local-engine request: response missing sysDescr value")
	}
}

// TestV3DiscoveryUnaffected_10434 is the discovery control: the empty-user
// engine-ID discovery exchange must keep returning the
// usmStatsUnknownEngineIDs Report.
func TestV3DiscoveryUnaffected_10434(t *testing.T) {
	a, _, _ := newTimelinessAgent(t, 4, 100)
	buildProbe := func(msgFlags byte) []byte {
		usmFields := berEncodeTLV(tagOctetString, nil)
		usmFields = append(usmFields, berEncodeIntegerTLV(0)...)
		usmFields = append(usmFields, berEncodeIntegerTLV(0)...)
		usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...)
		usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...)
		usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...)
		usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

		hdr := berEncodeIntegerTLV(1)
		hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
		hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlags})...)
		hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
		hdrSeq := berEncodeTLV(tagSequence, hdr)

		scopedBody := berEncodeTLV(tagOctetString, nil)
		scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
		scopedBody = append(scopedBody, berEncodeTLV(pduGetRequest, nil)...)
		scopedPDU := berEncodeTLV(tagSequence, scopedBody)

		msgBody := berEncodeIntegerTLV(snmpVersion3)
		msgBody = append(msgBody, hdrSeq...)
		msgBody = append(msgBody, usmOctet...)
		msgBody = append(msgBody, scopedPDU...)
		return berEncodeTLV(tagSequence, msgBody)
	}

	pkt := buildProbe(msgFlagReportable)
	a.lastPacket = pkt
	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("discovery probe returned nil; handshake broken")
	}
	if !bytes.Contains(resp, berEncodeOID(usmStatsUnknownEngineIDsOID10434)) {
		t.Fatal("discovery response missing usmStatsUnknownEngineIDs report")
	}
	assertV3ReportEncoding10434(t, resp)

	nonReportable := buildProbe(0)
	a.lastPacket = nonReportable
	if resp := driveV3(t, a, nonReportable); resp != nil {
		t.Fatalf("non-reportable discovery probe: got %d-byte response, want drop", len(resp))
	}
}
