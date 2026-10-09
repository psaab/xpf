package snmp

import (
	"bytes"
	"crypto/hmac"
	"testing"
)

// buildV3SetRequestMulti builds a complete SNMPv3 authNoPriv SET request for a
// LIST of OIDs (each with a NULL value) with a selectable advertised
// msgMaxSize. It mirrors buildV3GetBulkRequest's USM framing but emits a
// pduSetRequest (0xA3) so handleV3Packet's SET branch runs end to end with a
// manager-advertised receive limit. The default (empty) context is addressed.
func buildV3SetRequestMulti(t *testing.T, authProto, userName string, engineID, authKey []byte,
	boots, tm, msgMaxSize int, oids [][]int) []byte {
	t.Helper()
	return buildV3SetRequestMultiCtx(t, authProto, userName, engineID, authKey, boots, tm, msgMaxSize, nil, oids)
}

// buildV3SetRequestMultiCtx is buildV3SetRequestMulti with an explicit
// contextName so the fallback-size path can be exercised with an overlong
// echoed context.
func buildV3SetRequestMultiCtx(t *testing.T, authProto, userName string, engineID, authKey []byte,
	boots, tm, msgMaxSize int, contextName []byte, oids [][]int) []byte {
	t.Helper()
	hashFn, _ := authHashFunc(authProto)
	if hashFn == nil {
		t.Fatalf("unknown auth proto %q", authProto)
	}
	truncLen := authTruncLen(authProto)

	authPlaceholder := make([]byte, truncLen)
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(boots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(tm)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(11)
	hdr = append(hdr, berEncodeIntegerTLV(msgMaxSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	var vbList []byte
	for _, oid := range oids {
		vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
		vb = append(vb, berEncodeTLV(tagNull, nil)...)
		vbList = append(vbList, berEncodeTLV(tagSequence, vb)...)
	}
	vbListEnc := berEncodeTLV(tagSequence, vbList)

	pduBody := berEncodeIntegerTLV(77)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // error-status
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // error-index
	pduBody = append(pduBody, vbListEnc...)

	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, contextName)...) // addressed context, echoed in response
	scopedBody = append(scopedBody, berEncodeTLV(pduSetRequest, pduBody)...)
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
	copy(wholeMsg[start:end], mac.Sum(nil)[:truncLen])
	return wholeMsg
}

// setTestOIDs returns n distinct sysContact-family OIDs for multi-OID SET
// requests. Each encodes to a ~14-byte echoed varbind in the response.
func setTestOIDs(n int) [][]int {
	oids := make([][]int, 0, n)
	for i := 1; i <= n; i++ {
		oids = append(oids, []int{1, 3, 6, 1, 2, 1, 1, 4, i})
	}
	return oids
}

// TestV3Set_OversizedReturnsTooBig (#12147): an authenticated v3 SET that
// advertises the 484-byte floor while naming enough OIDs that the echoed
// notWritable response would exceed it must be replaced with tooBig + an empty
// varbind list (RFC 3416 §4.2.5) — never emitted over-size. fail-on-revert:
// return the notWritable echo directly (no bound) and this response exceeds
// 484 bytes with error-status notWritable.
func TestV3Set_OversizedReturnsTooBig(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, nil)

	oids := setTestOIDs(48)
	req := buildV3SetRequestMulti(t, "sha", "alice", engineID, authKey, boots, tm, minMsgMaxSize, oids)
	if len(req) > maxPacketSize {
		t.Fatalf("test setup: SET request %d bytes exceeds maxPacketSize %d; reduce OID count", len(req), maxPacketSize)
	}
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > minMsgMaxSize {
		t.Fatalf("SET response %d bytes exceeds advertised msgMaxSize %d (size cap not applied)", len(resp), minMsgMaxSize)
	}
	errStatus, got := v3ResponseErrorStatus(t, resp)
	if errStatus != errTooBig {
		t.Fatalf("error-status = %d, want tooBig (%d) for an oversized SET", errStatus, errTooBig)
	}
	if len(got) != 0 {
		t.Fatalf("tooBig response must carry an empty varbind list, got %d varbinds", len(got))
	}
}

// TestV3Set_SmallUnchanged (#12147): a small SET that fits within the
// advertised msgMaxSize keeps its existing behavior — refused with
// notWritable (the agent exposes no writable objects) with all requested OIDs
// echoed. The size bound must not disturb this path.
func TestV3Set_SmallUnchanged(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, nil)

	oids := setTestOIDs(2)
	req := buildV3SetRequestMulti(t, "sha", "alice", engineID, authKey, boots, tm, minMsgMaxSize, oids)
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > minMsgMaxSize {
		t.Fatalf("small SET response %d bytes unexpectedly exceeds msgMaxSize %d", len(resp), minMsgMaxSize)
	}
	errStatus, got := v3ResponseErrorStatus(t, resp)
	if errStatus != errNotWritable {
		t.Fatalf("error-status = %d, want notWritable (%d) for a small SET", errStatus, errNotWritable)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 echoed varbinds for a 2-OID SET, got %d", len(got))
	}
}

// TestV3Set_OversizedFallbackDropped (#12147, Astra R1): an accepted SET whose
// echoed contextName alone prevents even the empty-binding tooBig fallback
// from fitting must be dropped (RFC 3416 §4.2.5), never transmitted
// over-size. Repro: authenticated SHA/authNoPriv SET, 48 OIDs, 1024-byte
// contextName, msgMaxSize=484 — the 1168-byte tooBig fallback must NOT be
// transmitted. fail-on-revert: return the fallback without a recheck and this
// test observes a non-nil, over-cap response.
func TestV3Set_OversizedFallbackDropped(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, nil)

	ctx := bytes.Repeat([]byte{'C'}, 1024)
	oids := setTestOIDs(48)
	req := buildV3SetRequestMultiCtx(t, "sha", "alice", engineID, authKey, boots, tm, minMsgMaxSize, ctx, oids)
	if len(req) > maxPacketSize {
		t.Fatalf("test setup: SET request %d bytes exceeds maxPacketSize %d", len(req), maxPacketSize)
	}
	user := a.snapshotV3User("alice")
	fallback := a.buildV3Response(11, msgFlagAuth, user, ctx, 77, errTooBig, 0, nil)
	if len(fallback) <= minMsgMaxSize {
		t.Fatalf("test setup: tooBig fallback is %d bytes, want > msgMaxSize %d", len(fallback), minMsgMaxSize)
	}

	if resp := a.handlePacket(req); resp != nil {
		t.Fatalf("oversized tooBig fallback transmitted: %d bytes > msgMaxSize %d; must be dropped (RFC 3416 §4.2.5)", len(resp), minMsgMaxSize)
	}
	start, end, ok := usmAuthParamsRange(req)
	if !ok || !a.verifyAuth(user, req[start:end]) {
		t.Fatal("test setup: SET request must pass authenticated SHA validation")
	}
}
