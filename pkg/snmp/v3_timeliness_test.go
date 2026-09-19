package snmp

import (
	"bytes"
	"crypto/hmac"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nowMinus returns a time secs seconds in the past, so an Agent.startTime set
// to it makes engineTime() return approximately secs.
func nowMinus(secs int) time.Time {
	return time.Now().Add(-time.Duration(secs) * time.Second)
}

// buildV3TimedRequest builds a complete SNMPv3 authNoPriv GetRequest carrying
// the given msgAuthoritativeEngineBoots/Time, signed with authKey. It returns
// the on-wire bytes. The PDU is an empty GetRequest (the agent serves it and
// returns a GetResponse on acceptance, or a Report on a timeliness failure).
func buildV3TimedRequest(t *testing.T, authProto, userName string, engineID, authKey []byte, boots, tm int) []byte {
	return buildV3TimedRequestWithFlags(t, authProto, userName, engineID, authKey, msgFlagAuth|msgFlagReportable, boots, tm)
}

func buildV3TimedRequestWithFlags(t *testing.T, authProto, userName string, engineID, authKey []byte, msgFlags byte, boots, tm int) []byte {
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

	hdr := berEncodeIntegerTLV(7)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlags})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// scopedPDU: contextEngineID, contextName, empty GetRequest PDU.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	// GetRequest PDU body: request-id, error-status, error-index, empty vblist.
	pduBody := berEncodeIntegerTLV(99)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeTLV(tagSequence, nil)...)
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

// newTimelinessAgent builds an agent with a single authNoPriv user, a fixed
// engineID, a controlled engineBoots, and a startTime offset so engineTime()
// returns approximately wantTime. It returns the agent, engineID, and authKey.
func newTimelinessAgent(t *testing.T, boots, wantTime int) (*Agent, []byte, []byte) {
	t.Helper()
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xDE, 0xAD, 0xBE, 0xEF}
	authProto := "sha"
	hashFn, hashLen := authHashFunc(authProto)
	authKey := passwordToKey("timeliness-pw-123456", engineID, hashFn, hashLen)

	a := &Agent{
		engineID:    engineID,
		engineBoots: boots,
		v3Users:     map[string]*usmUser{},
		// startTime in the past so engineTime() ~= wantTime.
		startTime: nowMinus(wantTime),
	}
	a.v3Users["tuser"] = &usmUser{name: "tuser", authProto: authProto, authKey: authKey}
	return a, engineID, authKey
}

// classifyV3Response reports whether a response is a Report PDU carrying the
// usmStatsNotInTimeWindows OID ("report"), an ordinary GetResponse
// ("response"), or something else ("other"/"nil").
func classifyV3Response(t *testing.T, resp []byte) string {
	t.Helper()
	if resp == nil {
		return "nil"
	}
	if bytes.Contains(resp, berEncodeOID(usmStatsNotInTimeWindows)) {
		return "report"
	}
	// A GetResponse PDU tag (0xa2) appears in the scopedPDU.
	if bytes.IndexByte(resp, byte(pduGetResponse)) >= 0 {
		return "response"
	}
	return "other"
}

// TestTimeliness_InWindowAccepted verifies that an authenticated request with
// the correct boots and a timestamp inside the ±150s window is accepted and
// produces a data GetResponse (not a timeliness report).
func TestTimeliness_InWindowAccepted(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	// Request time within 150s of our time (~1000).
	pkt := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 5, 1050)
	a.lastPacket = pkt

	// handleV3Packet consumes the message body after the version integer; mirror
	// handlePacket's decode of the outer SEQUENCE + version.
	resp := driveV3(t, a, pkt)
	if got := classifyV3Response(t, resp); got != "response" {
		t.Fatalf("in-window request: got %q response, want a data GetResponse", got)
	}
}

// TestTimeliness_StaleRejected is the core replay test: a captured request
// whose engineTime is far outside the window (a replay long after capture) is
// rejected with usmStatsNotInTimeWindows, NOT served. fail-on-revert: removing
// the checkTimeliness call makes this request classify as "response".
func TestTimeliness_StaleRejected(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	// Replay: the captured request's time is 151s behind our clock.
	pkt := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 5, 849)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if got := classifyV3Response(t, resp); got != "report" {
		t.Fatalf("stale replay: got %q, want a usmStatsNotInTimeWindows report (replay must be rejected)", got)
	}
	assertV3ReportEncoding10434(t, resp)
}

// TestTimeliness_NonReportableDropped_10434 verifies that an authenticated
// stale request with reportableFlag clear is dropped rather than reflected
// with a Report response.
func TestTimeliness_NonReportableDropped_10434(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	pkt := buildV3TimedRequestWithFlags(t, "sha", "tuser", engineID, authKey,
		msgFlagAuth, 5, 849)
	a.lastPacket = pkt

	if resp := driveV3(t, a, pkt); resp != nil {
		t.Fatalf("non-reportable stale request: got %d-byte response, want drop", len(resp))
	}
}

// TestTimeliness_FutureRejected covers a request whose engineTime is far in the
// future (clock skew / crafted) — also outside the window.
func TestTimeliness_FutureRejected(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	pkt := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 5, 1200) // +200s
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if got := classifyV3Response(t, resp); got != "report" {
		t.Fatalf("future request: got %q, want a not-in-time-window report", got)
	}
}

// TestTimeliness_WrongBootsRejected covers the post-restart replay vector: the
// captured request carries the pre-restart boots value, which no longer matches
// our (incremented) boots, so it is rejected even if the time happens to align.
func TestTimeliness_WrongBootsRejected(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 6, 1000)                    // we are now boots=6
	pkt := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 5, 1000) // captured at boots=5
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if got := classifyV3Response(t, resp); got != "report" {
		t.Fatalf("wrong-boots request: got %q, want a not-in-time-window report", got)
	}
}

// TestTimeliness_Boundary checks the exact ±150s boundary: 150s is in-window,
// 151s is out.
func TestTimeliness_Boundary(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 3, 5000)

	in := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 3, 5000-usmTimeWindow)
	a.lastPacket = in
	if got := classifyV3Response(t, driveV3(t, a, in)); got != "response" {
		t.Fatalf("at -150s boundary: got %q, want accepted response", got)
	}

	out := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 3, 5000-usmTimeWindow-1)
	a.lastPacket = out
	if got := classifyV3Response(t, driveV3(t, a, out)); got != "report" {
		t.Fatalf("at -151s boundary: got %q, want rejected report", got)
	}
}

// TestTimeliness_DiscoveryStillWorks verifies the engineID discovery handshake
// (empty userName) is unaffected by the timeliness gate and still returns a
// usmStatsUnknownEngineIDs report so a manager can learn our boots/time.
func TestTimeliness_DiscoveryStillWorks(t *testing.T) {
	a, _, _ := newTimelinessAgent(t, 4, 100)
	// Discovery probe: empty userName, no auth.
	usmFields := berEncodeTLV(tagOctetString, nil) // unknown engineID
	usmFields = append(usmFields, berEncodeIntegerTLV(0)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(0)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // empty userName
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(1)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagReportable})...)
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
	pkt := berEncodeTLV(tagSequence, msgBody)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("discovery probe returned nil; handshake broken")
	}
	unknownEngineIDs := berEncodeOID([]int{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0})
	if !bytes.Contains(resp, unknownEngineIDs) {
		t.Fatal("discovery response missing usmStatsUnknownEngineIDs report")
	}
}

// driveV3 strips the outer SEQUENCE + version (as handlePacket does) and calls
// handleV3Packet, the unit under test.
func driveV3(t *testing.T, a *Agent, pkt []byte) []byte {
	t.Helper()
	tag, msgBody, err := berDecodeHeader(pkt)
	if err != nil || tag != tagSequence {
		t.Fatalf("driveV3: outer SEQUENCE decode failed: %v", err)
	}
	_, rest, err := berDecodeInteger(msgBody) // version
	if err != nil {
		t.Fatalf("driveV3: version decode failed: %v", err)
	}
	return a.handleV3Packet(rest)
}

// --- engineBoots persistence tests ---

// TestEngineBootsPersistAcrossRestart asserts the persisted counter advances
// 1 -> 2 -> 3 across successive agent constructions sharing one state file,
// rather than resetting to 1 each start. fail-on-revert: hard-coding
// engineBoots = 1 in initEngine makes the second/third assertions fail.
func TestEngineBootsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snmp-engineboots")

	for i, want := range []int{1, 2, 3} {
		a := NewAgentWithBootsPath(nil, path)
		if a.engineBoots != want {
			t.Fatalf("restart %d: engineBoots = %d, want %d", i, a.engineBoots, want)
		}
		// The persisted file must hold the value we just used.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("restart %d: read state: %v", i, err)
		}
		got, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatalf("restart %d: parse state %q: %v", i, data, err)
		}
		if got != want {
			t.Fatalf("restart %d: persisted boots = %d, want %d", i, got, want)
		}
	}
}

// TestEngineBootsFirstBootMissingFile confirms a missing state file yields
// boots = 1 (first boot) and creates the file.
func TestEngineBootsFirstBootMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "snmp-engineboots")

	a := NewAgentWithBootsPath(nil, path)
	if a.engineBoots != 1 {
		t.Fatalf("first boot: engineBoots = %d, want 1", a.engineBoots)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first boot: state file not created: %v", err)
	}
}

// TestEngineBootsCorruptFailsClosed confirms an unparseable counter does NOT
// silently reset to a low, replayable value but pins engineBoots to the RFC
// ceiling (#2649). RFC 3414 §2.2 requires engineBoots to be monotonic; a reset
// to 1 with the same deterministic engineID re-opens the replay window for a
// captured prior-epoch request. At the ceiling checkTimeliness rejects every
// authenticated request, forcing re-discovery — fail closed, not fail open.
//
// fail-on-revert: restoring the old `boots = 1` reset makes both assertions
// fail (engineBoots becomes 1, and checkTimeliness would no longer reject).
func TestEngineBootsCorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snmp-engineboots")
	if err := os.WriteFile(path, []byte("not-a-number"), 0o644); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	a := NewAgentWithBootsPath(nil, path)
	if a.engineBoots == 1 {
		t.Fatal("corrupt state: engineBoots reset to 1 (fail-open replay window) — must pin to ceiling")
	}
	if a.engineBoots != engineBootsMax {
		t.Fatalf("corrupt state: engineBoots = %d, want ceiling %d (fail-closed)", a.engineBoots, engineBootsMax)
	}
	// At the ceiling every authenticated request is rejected (§3.2 step 7),
	// so no replayed prior-epoch packet can be timely.
	if a.checkTimeliness(a.engineBoots, a.engineTime()) {
		t.Fatal("corrupt state pinned to ceiling must reject all authenticated requests")
	}
}

// TestEngineBootsCeilingDoesNotWrap confirms a persisted value at the ceiling
// does NOT wrap back to 1 on the next start (which would re-open the replay
// window) but stays pinned at the ceiling (#2649).
//
// fail-on-revert: the old `boots = 1` reset wraps a ceiling-valued file to 1.
func TestEngineBootsCeilingDoesNotWrap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snmp-engineboots")
	if err := os.WriteFile(path, []byte(strconv.Itoa(engineBootsMax)+"\n"), 0o644); err != nil {
		t.Fatalf("seed ceiling file: %v", err)
	}
	a := NewAgentWithBootsPath(nil, path)
	if a.engineBoots != engineBootsMax {
		t.Fatalf("ceiling state: engineBoots = %d, want ceiling %d (no wrap to 1)", a.engineBoots, engineBootsMax)
	}
}

// TestEngineBootsPersistFailureFailsClosed confirms that when the boots value
// cannot be durably persisted (unwritable state directory), the agent pins to
// the ceiling for this run rather than serving with an unpersisted low value
// that the next start would reuse as a stale (replayable) epoch (#2649).
//
// fail-on-revert: dropping the persist-failure ceiling pin makes engineBoots
// stay at the low prev+1 value, failing this assertion.
func TestEngineBootsPersistFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// Make the parent a regular file so MkdirAllDurable/WriteFileDurable under
	// it cannot succeed, forcing the durable-write failure path.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	path := filepath.Join(blocker, "subdir", "snmp-engineboots")
	a := NewAgentWithBootsPath(nil, path)
	if a.engineBoots != engineBootsMax {
		t.Fatalf("persist failure: engineBoots = %d, want ceiling %d (fail-closed)", a.engineBoots, engineBootsMax)
	}
}

// TestCheckTimeliness_CeilingRejects confirms a boots counter at the RFC
// ceiling rejects every authenticated request (RFC 3414 §3.2).
func TestCheckTimeliness_CeilingRejects(t *testing.T) {
	a := &Agent{engineBoots: engineBootsMax, startTime: nowMinus(100)}
	if a.checkTimeliness(engineBootsMax, 100) {
		t.Fatal("at engineBoots ceiling, checkTimeliness must reject all requests")
	}
}
