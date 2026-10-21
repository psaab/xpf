package snmp

import (
	"crypto/hmac"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildV3AuthSetPacket constructs a complete SNMPv3 authNoPriv SET request for
// a single OID with a NULL value, authenticated with the given user's key. It
// mirrors buildV3AuthPacket but emits a pduSetRequest (0xA3) carrying one
// varbind so handleV3Packet's SET branch runs end to end (decodePDUFields must
// see at least one OID for the agent to set errIdx and build a response).
func buildV3AuthSetPacket(t *testing.T, authProto, userName string, engineID, authKey []byte, oid []int) []byte {
	t.Helper()

	hashFn, _ := authHashFunc(authProto)
	if hashFn == nil {
		t.Fatalf("unknown auth proto %q", authProto)
	}
	truncLen := authTruncLen(authProto)

	// USM security parameters with a zeroed authParams placeholder.
	authPlaceholder := make([]byte, truncLen)
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(1)...) // engineBoots
	usmFields = append(usmFields, berEncodeIntegerTLV(2)...) // engineTime
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams (empty)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Global header (msgID, maxSize, flags=auth, securityModel=USM).
	hdr := berEncodeIntegerTLV(42)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// SET PDU: request-id, error-status(0), error-index(0), varbind-list.
	oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	valBytes := berEncodeTLV(tagNull, nil)
	vb := berEncodeTLV(tagSequence, append(oidBytes, valBytes...))
	vbList := berEncodeTLV(tagSequence, vb)
	pduBody := berEncodeIntegerTLV(101) // request-id
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	setPDU := berEncodeTLV(pduSetRequest, pduBody)

	// Scoped PDU (plaintext) — contextEngineID, contextName, SET PDU.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	scopedBody = append(scopedBody, setPDU...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Assemble the whole message.
	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	// Locate the authParams field (still zeroed), compute the HMAC over the
	// zeroed-placeholder form, then splice it in — exactly as a conformant
	// manager would so verifyAuth accepts the request.
	start, end, ok := usmAuthParamsRange(wholeMsg)
	if !ok {
		t.Fatalf("usmAuthParamsRange failed on freshly built SET packet")
	}
	mac := hmac.New(hashFn, authKey)
	mac.Write(wholeMsg)
	computed := mac.Sum(nil)
	if len(computed) > truncLen {
		computed = computed[:truncLen]
	}
	copy(wholeMsg[start:end], computed)
	return wholeMsg
}

// decodeV3ResponseErrorStatus walks an SNMPv3 authNoPriv GetResponse and
// returns its PDU error-status. The response carries a plaintext scopedPDU
// (no priv), so the walk is: outer SEQUENCE -> version -> msgGlobalData
// SEQUENCE -> msgSecurityParameters OCTET STRING -> scopedPDU SEQUENCE ->
// contextEngineID, contextName, responsePDU -> request-id -> error-status.
func decodeV3ResponseErrorStatus(t *testing.T, resp []byte) int {
	t.Helper()

	tag, msgBody, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("v3 response: not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	// version
	_, rest, err := berDecodeInteger(msgBody)
	if err != nil {
		t.Fatalf("v3 response: decode version: %v", err)
	}
	// msgGlobalData header SEQUENCE — skip the whole TLV.
	hdrLen := berEncodedLen(rest)
	if hdrLen <= 0 || hdrLen > len(rest) {
		t.Fatalf("v3 response: bad msgGlobalData length %d", hdrLen)
	}
	rest = rest[hdrLen:]
	// msgSecurityParameters OCTET STRING — skip past it.
	_, afterSec, err := berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("v3 response: decode securityParameters: %v", err)
	}
	// scopedPDU SEQUENCE (plaintext for authNoPriv).
	tag, scopedBody, err := berDecodeHeader(afterSec)
	if err != nil || tag != tagSequence {
		t.Fatalf("v3 response: scopedPDU not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	// contextEngineID, contextName.
	_, scopedRest, err := berDecodeOctetString(scopedBody)
	if err != nil {
		t.Fatalf("v3 response: decode contextEngineID: %v", err)
	}
	_, scopedRest, err = berDecodeOctetString(scopedRest)
	if err != nil {
		t.Fatalf("v3 response: decode contextName: %v", err)
	}
	// response PDU.
	pduTag, pduBody, err := berDecodeHeader(scopedRest)
	if err != nil {
		t.Fatalf("v3 response: decode PDU header: %v", err)
	}
	if pduTag != pduGetResponse {
		t.Fatalf("v3 response: PDU tag = 0x%02x, want GetResponse (0x%02x)", pduTag, pduGetResponse)
	}
	// request-id, error-status.
	_, pduRest, err := berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("v3 response: decode request-id: %v", err)
	}
	errStatus, _, err := berDecodeInteger(pduRest)
	if err != nil {
		t.Fatalf("v3 response: decode error-status: %v", err)
	}
	return errStatus
}

// TestV3SetRequest_NotWritable verifies that an authenticated SNMPv3 SET is
// refused with notWritable (Codex review Low for #2008). The agent exposes no
// writable objects and SNMPv3 USM carries no read-write authorization in this
// config, so every SET must be uniformly refused — not silently dropped — so a
// manager sees the standard error-status rather than a timeout.
//
// The packet is authenticated end to end (real HMAC), so it exercises the SET
// branch of handleV3Packet after verifyAuth, not an early auth-failure drop.
func TestV3SetRequest_NotWritable(t *testing.T) {
	const (
		userName = "admin"
		authPW   = "the-auth-password-1234"
		authPro  = "sha"
	)

	// Use a writable temp boots path so engineBoots is a fresh 1 (matching the
	// packet's engineBoots) and the timeliness gate passes — the default
	// /var/lib/xpf path is unwritable under test and now fails closed by
	// pinning to the ceiling (#2649), which is exercised separately.
	bootsPath := filepath.Join(t.TempDir(), "snmp-engineboots")
	a := NewAgentWithBootsPath(&config.SNMPConfig{
		V3Users: map[string]*config.SNMPv3User{
			userName: {Name: userName, AuthProtocol: authPro, AuthPassword: config.NewSecret(authPW)},
		},
	}, bootsPath)

	// Derive the localized auth key against the agent's engine ID so the
	// packet authenticates against the live user table.
	hashFn, hashLen := authHashFunc(authPro)
	authKey := passwordToKey(authPW, a.engineID, hashFn, hashLen)
	if authKey == nil {
		t.Fatal("passwordToKey returned nil")
	}

	pkt := buildV3AuthSetPacket(t, authPro, userName, a.engineID, authKey, oidSysContact)
	resp := a.handlePacket(pkt)
	if resp == nil {
		t.Fatal("authenticated v3 SET produced no response (was dropped); want a notWritable response")
	}
	if got := decodeV3ResponseErrorStatus(t, resp); got != errNotWritable {
		t.Errorf("v3 SET error-status = %d, want notWritable (%d)", got, errNotWritable)
	}
}
