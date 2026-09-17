package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

const (
	snmpVersion3 = 3 // version field for SNMPv3

	// USM security model (RFC 3414).
	usmSecurityModel = 3

	// SNMPv3 message flags.
	msgFlagAuth   = 0x01
	msgFlagPriv   = 0x02
	msgFlagReport = 0x04

	// Auth HMAC truncation lengths (RFC 3414, RFC 7860).
	hmacMD5Len    = 12
	hmacSHA1Len   = 12
	hmacSHA256Len = 24
)

// usmUser holds precomputed key material for a USM user.
type usmUser struct {
	name      string
	authProto string // "md5", "sha", "sha256"
	authKey   []byte
	privProto string // "des", "aes128"
	privKey   []byte
}

// initV3Users builds USM user entries from a.cfg at agent construction,
// localizing passwords with the engine ID. It is the startup-only seam;
// commit-time reconfigure goes through UpdateConfig -> deriveV3Users.
func (a *Agent) initV3Users() {
	a.v3Users = a.deriveV3Users(a.cfg)
}

// deriveV3Users builds the USM user table from cfg, localizing each user's
// auth/priv passwords against the agent's engine ID. It does NOT touch agent
// state, so UpdateConfig can compute the new table before taking cfgMu and
// swap it in atomically. Returns nil when no v3 users are configured.
func (a *Agent) deriveV3Users(cfg *config.SNMPConfig) map[string]*usmUser {
	if cfg == nil || len(cfg.V3Users) == 0 {
		return nil
	}
	users := make(map[string]*usmUser, len(cfg.V3Users))
	for _, cu := range cfg.V3Users {
		u := &usmUser{name: cu.Name, authProto: cu.AuthProtocol, privProto: cu.PrivProtocol}
		hashFn, hashLen := authHashFunc(cu.AuthProtocol)
		if hashFn != nil && cu.AuthPassword != "" {
			u.authKey = passwordToKey(cu.AuthPassword.Reveal(), a.engineID, hashFn, hashLen)
		}
		if hashFn != nil && cu.PrivPassword != "" {
			u.privKey = passwordToKey(cu.PrivPassword.Reveal(), a.engineID, hashFn, hashLen)
		}
		users[cu.Name] = u
	}
	return users
}

// authHashFunc returns the hash constructor and key length for an auth protocol.
func authHashFunc(proto string) (func() hash.Hash, int) {
	switch proto {
	case "md5":
		return md5.New, md5.Size
	case "sha":
		return sha1.New, sha1.Size
	case "sha256":
		return sha256.New, sha256.Size
	default:
		return nil, 0
	}
}

// authTruncLen returns the HMAC truncation length for an auth protocol.
func authTruncLen(proto string) int {
	switch proto {
	case "md5":
		return hmacMD5Len
	case "sha":
		return hmacSHA1Len
	case "sha256":
		return hmacSHA256Len
	default:
		return 12
	}
}

// passwordToKey derives a localized key from a password per RFC 3414 section A.2.
func passwordToKey(password string, engineID []byte, hashNew func() hash.Hash, hashLen int) []byte {
	h := hashNew()
	pw := []byte(password)
	pLen := len(pw)
	if pLen == 0 {
		return nil
	}
	// Step 1: Generate Ku by hashing password repeated to >= 1MB.
	count := 0
	for count < 1048576 {
		var buf [64]byte
		for i := range buf {
			buf[i] = pw[(count+i)%pLen]
		}
		h.Write(buf[:])
		count += 64
	}
	ku := h.Sum(nil)

	// Step 2: Localize Ku with engineID: Kul = HASH(Ku || engineID || Ku).
	h.Reset()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	kul := h.Sum(nil)
	if len(kul) > hashLen {
		kul = kul[:hashLen]
	}
	return kul
}

// handleV3Packet processes an SNMPv3 message. Returns response bytes or nil.
func (a *Agent) handleV3Packet(msgBody []byte) []byte {
	// Decode HeaderData (SEQUENCE: msgID, msgMaxSize, msgFlags, msgSecurityModel).
	tag, headerBody, err := berDecodeHeader(msgBody)
	if err != nil || tag != tagSequence {
		slog.Debug("SNMPv3: invalid header SEQUENCE")
		return nil
	}

	msgID, rest, err := berDecodeInteger(headerBody)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode msgID")
		return nil
	}
	msgMaxSize, rest, err := berDecodeInteger(rest) // msgMaxSize
	if err != nil {
		slog.Debug("SNMPv3: failed to decode msgMaxSize")
		return nil
	}
	flagsBytes, rest, err := berDecodeOctetString(rest)
	if err != nil || len(flagsBytes) < 1 {
		slog.Debug("SNMPv3: failed to decode msgFlags")
		return nil
	}
	msgFlags := flagsBytes[0]

	// Reject the invalid noAuthPriv security level (RFC 3414 §5): the only
	// defined levels are noAuthNoPriv, authNoPriv, and authPriv. A message that
	// requests privacy without authentication (msgFlagPriv set, msgFlagAuth
	// clear) is malformed — an encrypted PDU MUST be authenticated. Drop it
	// BEFORE the auth/decrypt path below so its scopedPDU is never decrypted or
	// executed; doing the decrypt with the auth check skipped would let a sender
	// who can supply a decryptable PDU bypass HMAC/timeliness verification. We
	// drop rather than emit a report because, with no authentication, we cannot
	// produce an authenticated reply at the requested security level and an
	// unauthenticated report would itself be unverifiable.
	if msgFlags&msgFlagPriv != 0 && msgFlags&msgFlagAuth == 0 {
		slog.Debug("SNMPv3: invalid security level (noAuthPriv not supported), dropping")
		return nil
	}

	secModel, _, err := berDecodeInteger(rest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode securityModel")
		return nil
	}
	if secModel != usmSecurityModel {
		slog.Debug("SNMPv3: unsupported security model", "model", secModel)
		return nil
	}

	// Advance past the header in msgBody.
	headerTotalLen := berEncodedLen(msgBody)
	if headerTotalLen <= 0 || headerTotalLen >= len(msgBody) {
		slog.Debug("SNMPv3: header length error")
		return nil
	}
	afterHeader := msgBody[headerTotalLen:]

	// Decode USM Security Parameters (OCTET STRING wrapping a SEQUENCE).
	secParamsRaw, afterSecParams, err := berDecodeOctetString(afterHeader)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode security parameters")
		return nil
	}

	// Parse USM SEQUENCE inside the octet string.
	tag, usmBody, err := berDecodeHeader(secParamsRaw)
	if err != nil || tag != tagSequence {
		slog.Debug("SNMPv3: invalid USM SEQUENCE")
		return nil
	}

	// USM fields: engineID, engineBoots, engineTime, userName, authParams, privParams.
	_, usmRest, err := berDecodeOctetString(usmBody) // reqEngineID
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineID")
		return nil
	}
	reqBoots, usmRest, err := berDecodeInteger(usmRest) // engineBoots
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineBoots")
		return nil
	}
	reqTime, usmRest, err := berDecodeInteger(usmRest) // engineTime
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineTime")
		return nil
	}
	userNameBytes, usmRest, err := berDecodeOctetString(usmRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode userName")
		return nil
	}
	authParams, usmRest, err := berDecodeOctetString(usmRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode authParams")
		return nil
	}
	privParams, _, err := berDecodeOctetString(usmRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode privParams")
		return nil
	}

	userName := string(userNameBytes)

	// Discovery: empty userName means engine ID discovery.
	if userName == "" {
		return a.buildV3Discovery(msgID)
	}

	// Lookup user (under cfgMu so a commit-time UpdateConfig can't race the
	// USM user-table swap mid-request).
	user := a.snapshotV3User(userName)
	if user == nil {
		slog.Debug("SNMPv3: unknown user", "user", userName)
		return nil
	}

	// Enforce the per-user minimum security level (RFC 3414 §3.1
	// usmUserSecurityLevel). The message flags are the REQUEST's chosen level,
	// not a policy the sender may lower: a user configured with an auth key MUST
	// authenticate, and a user configured with a privacy key MUST use authPriv.
	// Without this floor a request can clear msgFlags (noAuthNoPriv) while naming
	// an authPriv user, and BOTH gates below — HMAC verification (gated on
	// msgFlagAuth) and decryption (gated on msgFlagPriv) — are skipped, so the
	// agent would decode and answer the scopedPDU in plaintext without the
	// configured password. That is an authentication + confidentiality bypass:
	// usernames are not secret, so knowing the name would suffice to read device
	// identity and interface inventory/counters and to re-open the
	// unauthenticated GETBULK CPU path. Drop under-leveled requests before
	// decoding the scoped PDU. We drop rather than emit a report because we
	// cannot produce an authenticated reply at a level the sender declined and an
	// unauthenticated report would itself be unverifiable. (noAuthPriv — priv
	// without auth — is already rejected above.)
	// #9155: THE FLOOR IS KEYED ON CONFIGURED INTENT, NOT ON DERIVED KEY
	// PRESENCE, and that distinction is the whole defect. See
	// usmUserServableAtLevel9155 for the reasoning and the table that drives it.
	if reason := usmUserServableAtLevel9155(user, msgFlags); reason != "" {
		slog.Debug("SNMPv3: refusing request", "user", userName, "reason", reason)
		return nil
	}

	// Verify authentication if required.
	if msgFlags&msgFlagAuth != 0 {
		if user.authKey == nil {
			slog.Debug("SNMPv3: user has no auth key", "user", userName)
			return nil
		}
		if !a.verifyAuth(user, authParams) {
			slog.Debug("SNMPv3: authentication failed", "user", userName)
			return nil
		}

		// USM timeliness window (RFC 3414 §3.2). Authentication proves the
		// sender holds the key; the time window proves the message is fresh.
		// Without it an on-path attacker can replay a captured authenticated
		// PDU. As the authoritative engine we check the request's boots/time
		// against our own clock and reply with usmStatsNotInTimeWindows on a
		// stale/future/wrong-boots request, which also lets a manager whose
		// cached boots/time drifted (e.g. across our restart) resynchronize.
		if !a.checkTimeliness(reqBoots, reqTime) {
			slog.Debug("SNMPv3: not in time window",
				"user", userName, "req_boots", reqBoots, "req_time", reqTime,
				"our_boots", a.engineBoots, "our_time", a.engineTime())
			return a.buildV3TimelinessReport(msgID, msgFlags, user)
		}
	}

	// Decode scoped PDU (possibly encrypted).
	var scopedPDUBody []byte
	if msgFlags&msgFlagPriv != 0 {
		encData, _, err := berDecodeOctetString(afterSecParams)
		if err != nil {
			slog.Debug("SNMPv3: failed to decode encrypted PDU")
			return nil
		}
		decrypted := a.decryptPDU(user, privParams, encData, reqBoots, reqTime)
		if decrypted == nil {
			slog.Debug("SNMPv3: decryption failed", "user", userName)
			return nil
		}
		// Decrypted data is a scopedPDU SEQUENCE.
		tag, body, err := berDecodeHeader(decrypted)
		if err != nil || tag != tagSequence {
			slog.Debug("SNMPv3: invalid decrypted scopedPDU")
			return nil
		}
		scopedPDUBody = body
	} else {
		tag, body, err := berDecodeHeader(afterSecParams)
		if err != nil || tag != tagSequence {
			slog.Debug("SNMPv3: invalid scopedPDU")
			return nil
		}
		scopedPDUBody = body
	}

	// Parse scopedPDU: contextEngineID, contextName, PDU.
	_, scopedRest, err := berDecodeOctetString(scopedPDUBody) // contextEngineID
	if err != nil {
		slog.Debug("SNMPv3: failed to decode contextEngineID")
		return nil
	}
	contextName, scopedRest, err := berDecodeOctetString(scopedRest) // contextName
	if err != nil {
		slog.Debug("SNMPv3: failed to decode contextName")
		return nil
	}

	// Context gating (RFC 3412 §4.1, RFC 3413 §3). This agent serves a single
	// MIB view in the default context (empty contextName). It does NOT model
	// per-VRF/routing-instance context views, so a request naming a non-default
	// context must NOT be answered with default-context data — that would be an
	// information-exposure / operator-confusion bug (#2611). Per RFC 3413, an
	// unknown context yields no matching MIB objects: Get returns
	// noSuchObject for unknown objects and noSuchInstance for missing
	// instances; GetNext/GetBulk return endOfMibView for every varbind.
	// The requested contextName is echoed back in the response so the manager
	// sees which context it addressed. The empty (default) context continues to
	// be served exactly as before.
	defaultContext := len(contextName) == 0
	echoContext := contextName

	// Decode PDU.
	pduTag, pduBody, err := berDecodeHeader(scopedRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode PDU")
		return nil
	}

	if !defaultContext {
		slog.Debug("SNMPv3: non-default context not served, returning empty view",
			"user", userName, "context", string(contextName))
	}

	var respVarbinds []varbind
	var requestID int

	// One interface snapshot for the whole PDU (#4013): the GET/GETNEXT/GETBULK
	// cases below walk the ifTable/ifXTable through findNextOIDSnap /
	// getOIDValueSnap so the netlink LinkList happens at most once per request
	// instead of twice per returned varbind.
	snap := a.newIfSnapshot()

	switch pduTag {
	case pduGetRequest:
		var oids [][]int
		requestID, _, _, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		for _, oid := range oids {
			if !defaultContext {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: oidAbsenceTag(oid)})
				continue
			}
			val, valTag := a.getOIDValueSnap(oid, snap)
			if val == nil {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: valTag})
			} else {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: valTag, value: val})
			}
		}

	case pduGetNextRequest:
		var oids [][]int
		requestID, _, _, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		for _, oid := range oids {
			if !defaultContext {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: tagEndOfMibView})
				continue
			}
			nextOID := a.findNextOIDSnap(oid, snap)
			if nextOID == nil {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: tagEndOfMibView})
			} else {
				val, valTag := a.getOIDValueSnap(nextOID, snap)
				respVarbinds = append(respVarbinds, varbind{oid: nextOID, tag: valTag, value: val})
			}
		}

	case pduGetBulkRequest:
		var oids [][]int
		var nonRepeaters, maxRepetitions int
		requestID, nonRepeaters, maxRepetitions, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		if nonRepeaters < 0 {
			nonRepeaters = 0
		}
		if maxRepetitions < 0 {
			maxRepetitions = 0
		}
		if maxRepetitions > 100 {
			maxRepetitions = 100
		}
		if !defaultContext {
			// Non-default context: no MIB view exists, so every requested OID
			// yields endOfMibView. One varbind per OID matches what a manager
			// expects from an empty view and avoids walking the default MIB.
			for _, oid := range oids {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: tagEndOfMibView})
			}
			break
		}
		// Bound the response to the effective maximum size (RFC 3416 §4.2.3):
		// the smaller of the manager's advertised msgMaxSize and our own
		// maxPacketSize, with msgMaxSize clamped up to the RFC floor.
		maxSize := effectiveMaxSize(msgMaxSize)

		// Repetition-major, per-column-cursor GETBULK order (RFC 3416 §4.2.3),
		// shared verbatim with the v2c handler so both paths encode identically
		// (#5065). The same ceiling bounds the grid expansion itself (#6551) so
		// the repeaters*maxRepetitions MIB walk never outruns what the response
		// can carry — on v3 an unbounded grid is worse than on v2c, because
		// every trimToFit rebuild re-runs USM framing/HMAC/encryption over it.
		respVarbinds = a.buildBulkVarbinds(oids, nonRepeaters, maxRepetitions, snap, maxSize)

		// Trim trailing varbinds until the fully-encoded message (USM +
		// scopedPDU, including any auth/priv overhead) fits; the manager
		// continues the walk from the last returned OID. Only if nothing fits
		// do we return tooBig with an empty varbind list rather than emit an
		// oversized datagram.
		resp, ok := trimToFit(respVarbinds, maxSize, func(vbs []varbind) []byte {
			return a.buildV3Response(msgID, msgFlags, user, echoContext, requestID, errNoError, 0, vbs)
		})
		if !ok {
			return a.buildV3Response(msgID, msgFlags, user, echoContext, requestID, errTooBig, 0, nil)
		}
		return resp

	case pduSetRequest:
		// The agent exposes no writable objects; refuse SET with notWritable
		// rather than silently dropping the request. SNMPv3 access control is
		// per-USM-user and carries no read-write authorization in this config,
		// so every SET is refused uniformly.
		var oids [][]int
		requestID, _, _, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		for _, oid := range oids {
			respVarbinds = append(respVarbinds, varbind{oid: oid, tag: tagNull})
		}
		errIdx := 0
		if len(oids) > 0 {
			errIdx = 1
		}
		return a.buildV3Response(msgID, msgFlags, user, echoContext, requestID, errNotWritable, errIdx, respVarbinds)

	default:
		slog.Debug("SNMPv3: unsupported PDU type", "type", pduTag)
		return nil
	}

	// Bound the GET/GETNEXT response to the effective maximum size, matching
	// the GETBULK cap above (#4918). GET/GETNEXT carry a fixed 1:1
	// varbind-per-request-OID contract that cannot be trimmed, so an oversized
	// response is replaced with tooBig + an empty varbind list (RFC 3416
	// §4.2.1/§4.2.2) rather than emitting an over-size datagram — the v3
	// residual of #2612, which bounded only GETBULK.
	resp := a.buildV3Response(msgID, msgFlags, user, echoContext, requestID, errNoError, 0, respVarbinds)
	if len(resp) > effectiveMaxSize(msgMaxSize) {
		return a.buildV3Response(msgID, msgFlags, user, echoContext, requestID, errTooBig, 0, nil)
	}
	return resp
}

// verifyAuth checks the HMAC authentication of a v3 message.
func (a *Agent) verifyAuth(user *usmUser, receivedMAC []byte) bool {
	hashFn, _ := authHashFunc(user.authProto)
	if hashFn == nil {
		return false
	}
	truncLen := authTruncLen(user.authProto)
	if len(receivedMAC) != truncLen {
		return false
	}

	// Build a copy of the whole packet with authParams zeroed.
	pkt := make([]byte, len(a.lastPacket))
	copy(pkt, a.lastPacket)
	zeroAuthParams(pkt)

	mac := hmac.New(hashFn, user.authKey)
	mac.Write(pkt)
	computed := mac.Sum(nil)
	if len(computed) > truncLen {
		computed = computed[:truncLen]
	}
	return hmac.Equal(computed, receivedMAC)
}

// zeroAuthParams blanks the USM msgAuthenticationParameters value in a raw
// SNMPv3 packet (in place) before HMAC recomputation, per RFC 3414 §6.3.1.
//
// It locates authParams by its POSITION in the parsed USM
// security-parameters SEQUENCE (#1710), not by a length heuristic. The
// previous implementation scanned for the first non-zero OCTET STRING whose
// BER length matched the HMAC truncation length, which mistakenly zeroed
// msgUserName (a 12- or 24-char username collides with truncLen) or a
// truncLen-byte msgAuthoritativeEngineID instead of authParams, locking the
// user out of SNMPv3. If the packet is not a well-formed v3 USM message the
// function is a no-op, so HMAC then runs over the unmodified copy and
// verifyAuth fails closed.
func zeroAuthParams(pkt []byte) {
	start, end, ok := usmAuthParamsRange(pkt)
	if !ok {
		return
	}
	for j := start; j < end; j++ {
		pkt[j] = 0
	}
}

// usmAuthParamsRange walks the SNMPv3 message in pkt to the USM
// msgAuthenticationParameters field and returns the [start,end) byte range
// of its OCTET STRING value within pkt. ok is true only when the message is
// well-formed all the way through the sixth USM field (msgPrivacyParameters),
// matching the parse requirements of handleV3Packet; ok=true therefore means
// "the USM sequence parsed cleanly and authParams is locatable."
//
// The field is found by RFC 3414 position — engineID, boots, time,
// msgUserName, msgAuthenticationParameters, msgPrivacyParameters — so a
// username or engineID whose length happens to equal the HMAC truncation
// length is never mistaken for authParams.
//
// Every descent decodes the child TLV from its parent's bounded value slice
// (returned by berDecodeHeader/berDecodeOctetString), never from a raw
// pkt[cursor:] window, so a nested length cannot escape its enclosing
// SEQUENCE/OCTET STRING: an over-running length makes the bounded decode
// return an error and ok=false. The absolute cursor into pkt is advanced by
// the byte counts the bounded decode consumed.
func usmAuthParamsRange(pkt []byte) (start, end int, ok bool) {
	// Outer message SEQUENCE.
	tag, msgBody, err := berDecodeHeader(pkt)
	if err != nil || tag != tagSequence {
		return 0, 0, false
	}
	// base = absolute offset of msgBody[0] within pkt = the outer SEQUENCE's
	// TLV header length. berEncodedLen(pkt) is header+value and len(msgBody)
	// is value, so their difference is the header length — independent of
	// whether the outer SEQUENCE fills the whole datagram.
	outerHdr := berEncodedLen(pkt) - len(msgBody)
	if outerHdr < 0 {
		return 0, 0, false
	}
	base := outerHdr

	// version INTEGER.
	cur := msgBody
	off, ok := advancePastTLV(cur, tagInteger)
	if !ok {
		return 0, 0, false
	}
	base += off
	cur = cur[off:]

	// msgGlobalData header SEQUENCE.
	off, ok = advancePastTLV(cur, tagSequence)
	if !ok {
		return 0, 0, false
	}
	base += off
	cur = cur[off:]

	// msgSecurityParameters OCTET STRING wrapping the USM SEQUENCE.
	secParams, _, err := berDecodeOctetString(cur)
	if err != nil {
		return 0, 0, false
	}
	// Absolute offset of the OCTET STRING value (the USM bytes) within pkt:
	// the value sits after this OCTET STRING's TLV header.
	usmHdrLen := berEncodedLen(cur) - len(secParams)
	if usmHdrLen < 0 {
		return 0, 0, false
	}
	usmBase := base + usmHdrLen

	// USM SEQUENCE.
	tag, usmBody, err := berDecodeHeader(secParams)
	if err != nil || tag != tagSequence {
		return 0, 0, false
	}
	usmSeqHdr := berEncodedLen(secParams) - len(usmBody)
	if usmSeqHdr < 0 {
		return 0, 0, false
	}
	usmBodyBase := usmBase + usmSeqHdr

	// USM fields by position: engineID, boots, time, userName, authParams.
	f := usmBody
	fbase := usmBodyBase

	// msgAuthoritativeEngineID OCTET STRING.
	off, ok = advancePastTLV(f, tagOctetString)
	if !ok {
		return 0, 0, false
	}
	fbase += off
	f = f[off:]

	// msgAuthoritativeEngineBoots INTEGER.
	off, ok = advancePastTLV(f, tagInteger)
	if !ok {
		return 0, 0, false
	}
	fbase += off
	f = f[off:]

	// msgAuthoritativeEngineTime INTEGER.
	off, ok = advancePastTLV(f, tagInteger)
	if !ok {
		return 0, 0, false
	}
	fbase += off
	f = f[off:]

	// msgUserName OCTET STRING.
	off, ok = advancePastTLV(f, tagOctetString)
	if !ok {
		return 0, 0, false
	}
	fbase += off
	f = f[off:]

	// msgAuthenticationParameters OCTET STRING — the field to blank.
	authVal, afterAuth, err := berDecodeOctetString(f)
	if err != nil {
		return 0, 0, false
	}
	authHdrLen := berEncodedLen(f) - len(authVal)
	if authHdrLen < 0 {
		return 0, 0, false
	}
	start = fbase + authHdrLen
	end = start + len(authVal)
	if start < 0 || end > len(pkt) || start > end {
		return 0, 0, false
	}

	// msgPrivacyParameters OCTET STRING — parse to confirm well-formedness
	// (matches handleV3Packet, which requires privParams to decode).
	if _, _, err := berDecodeOctetString(afterAuth); err != nil {
		return 0, 0, false
	}

	return start, end, true
}

// advancePastTLV decodes one TLV of the expected tag from the bounded slice
// data and returns the number of bytes it occupies (header + value), so the
// caller can advance both its slice and an absolute cursor in lockstep. ok is
// false if the tag does not match or the TLV is malformed/truncated relative
// to data's bounds.
func advancePastTLV(data []byte, expectTag byte) (consumed int, ok bool) {
	if len(data) == 0 || data[0] != expectTag {
		return 0, false
	}
	tag, _, err := berDecodeHeader(data)
	if err != nil || tag != expectTag {
		return 0, false
	}
	n := berEncodedLen(data)
	if n <= 0 || n > len(data) {
		return 0, false
	}
	return n, true
}

// decryptPDU decrypts an encrypted scopedPDU using the user's privacy key.
//
// boots/time are the msgAuthoritativeEngineBoots/Time carried in the request's
// USM parameters (reqBoots/reqTime) — NOT our local clock. RFC 3826 §3.1.2.1
// requires the AES-128-CFB IV to be built from the authoritative engine
// boots/time AS CARRIED IN THE MESSAGE: that is the value the sender used to
// derive the IV when it encrypted, having learned our boots/time via discovery.
// checkTimeliness has already run and (for an authenticated request) bounded
// reqBoots == a.engineBoots and reqTime within ±150s of a.engineTime(), but
// reqTime can still differ from our CURRENT engineTime() by up to the window —
// so using the local clock here would build the wrong IV and silently corrupt
// the plaintext. DES derives its IV from privParams alone, so boots/time are
// unused for DES.
func (a *Agent) decryptPDU(user *usmUser, privParams, encData []byte, boots, time int) []byte {
	if user.privKey == nil {
		return nil
	}
	switch user.privProto {
	case "des":
		return decryptDES(user.privKey, privParams, encData)
	case "aes128":
		return decryptAES128(user.privKey, privParams, encData, boots, time)
	default:
		return nil
	}
}

// decryptDES decrypts data using DES-CBC per RFC 3414 section 8.
func decryptDES(privKey, privParams, data []byte) []byte {
	if len(privKey) < 16 || len(privParams) != 8 || len(data) == 0 || len(data)%8 != 0 {
		return nil
	}
	desKey := privKey[:8]
	preIV := privKey[8:16]
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = preIV[i] ^ privParams[i]
	}
	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil
	}
	plaintext := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, data)
	return plaintext
}

// decryptAES128 decrypts data using AES-128-CFB per RFC 3826.
func decryptAES128(privKey, privParams, data []byte, boots, time int) []byte {
	if len(privKey) < 16 || len(privParams) != 8 || len(data) == 0 {
		return nil
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(time))
	copy(iv[8:16], privParams)
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil
	}
	plaintext := make([]byte, len(data))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, data)
	return plaintext
}

// randRead is the entropy source that SEEDS the SNMPv3 privacy salt counter
// (Agent.nextPrivSalt) once, at first use. It is a package variable so tests can
// inject an RNG failure and assert the encrypt path fails closed. It defaults to
// crypto/rand.Read. RFC 3826 §3.3 requires the salt counter to start from an
// arbitrary boot-time value; a good seed makes that start unpredictable so the
// derived cipher IVs are not predictable from message one. Per RFC 3826 the
// counter is then INCREMENTED (not re-drawn) for each message, so randRead is
// consulted only for the seed — the salt path MUST fail closed if that seed draw
// fails (no unpredictable start ⇒ refuse to emit a PDU, RFC 3414 §8.2.1).
var randRead = rand.Read

// nextPrivSalt returns the next 8-octet SNMPv3 privacy salt
// (msgPrivacyParameters) as a big-endian monotonic counter value. The counter is
// seeded ONCE from crypto/rand (via the randRead seam) at first use — an
// arbitrary boot-time starting point per RFC 3826 §3.3 — and incremented
// atomically thereafter, so every salt within an engine boot is distinct and no
// cipher IV is reused (RFC 3826 §3.1.2.1 AES, RFC 3414 §8.1.1.1 DES). It fails
// closed if the one-time seed draw cannot obtain entropy: without a good seed
// there is no unpredictable start, so encryptPDU drops the response rather than
// emit a predictable salt (RFC 3414 §8.2.1). Once seeded, a later RNG outage does
// NOT block encryption — fresh entropy per message is neither required nor drawn,
// exactly the RFC 3826 counter model. Safe for concurrent callers: the seed runs
// under privSaltMu once, and each allocation is a single atomic increment.
func (a *Agent) nextPrivSalt() ([]byte, error) {
	if !a.privSaltSeeded.Load() {
		a.privSaltMu.Lock()
		if !a.privSaltSeeded.Load() {
			var seed [8]byte
			if _, err := randRead(seed[:]); err != nil {
				a.privSaltMu.Unlock()
				return nil, fmt.Errorf("snmpv3: seed privacy salt counter: %w", err)
			}
			a.privSalt.Store(binary.BigEndian.Uint64(seed[:]))
			a.privSaltSeeded.Store(true)
		}
		a.privSaltMu.Unlock()
	}
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, a.privSalt.Add(1))
	return salt, nil
}

// encryptPDU encrypts a scopedPDU using the user's privacy key. It returns an
// error (rather than silently downgrading) when a securely-encrypted PDU cannot
// be produced — most importantly when the RNG fails to generate the per-message
// privacy salt — so the caller can fail closed.
func (a *Agent) encryptPDU(user *usmUser, scopedPDU []byte) ([]byte, []byte, error) {
	if user.privKey == nil {
		return nil, nil, fmt.Errorf("snmpv3: user %q has no privacy key", user.name)
	}
	// Allocate a unique per-message privacy salt from the monotonic counter
	// (RFC 3826 §3.3 / RFC 3414 §8.1.1.1). Fails closed if the one-time seed
	// draw could not obtain entropy — the caller drops the response rather than
	// emit a predictable salt (RFC 3414 §8.2.1).
	salt, err := a.nextPrivSalt()
	if err != nil {
		return nil, nil, err
	}
	switch user.privProto {
	case "des":
		// RFC 3414 §8.1.1.1 RECOMMENDS the DES privacy salt be
		// snmpEngineBoots(4) || local-integer(4) (big-endian) so the DES-CBC IV
		// (key-derived preIV XOR salt) is DETERMINISTICALLY unique across a
		// REBOOT: a fresh boot advances the high 32 salt bytes regardless of
		// where the monotonic counter re-randomizes its start. Overlay
		// engineBoots onto the counter's high 32 bits; keep the counter's low 32
		// bits (salt[4:8]) as the per-message local-integer. That low half still
		// increments monotonically per PDU and repeats only every 2^32 messages,
		// so within-boot IV uniqueness is preserved for 2^32 PDUs — this does NOT
		// reopen #5032 (that defect was birthday-bound random salts; the counter
		// model is unchanged). The overlaid salt is what we build the IV from AND
		// what we return as privParams: the wire salt MUST equal the IV salt or
		// the manager's decryptDES rebuilds a different IV and decodes garbage.
		//
		// The AES path is intentionally left with the raw counter — encryptAES128
		// embeds engineBoots in its own IV (boots||time||salt), so its cross-boot
		// uniqueness is already deterministic without touching the salt.
		desSalt := make([]byte, 8)
		copy(desSalt, salt)
		binary.BigEndian.PutUint32(desSalt[0:4], uint32(a.engineBoots))
		enc, err := encryptDES(user.privKey, scopedPDU, desSalt)
		if err != nil {
			return nil, nil, err
		}
		return enc, desSalt, nil
	case "aes128":
		enc, err := encryptAES128(user.privKey, scopedPDU, salt, a.engineBoots, a.engineTime())
		if err != nil {
			return nil, nil, err
		}
		return enc, salt, nil
	default:
		return nil, nil, fmt.Errorf("snmpv3: unsupported privacy protocol %q", user.privProto)
	}
}

// encryptDES encrypts data using DES-CBC per RFC 3414 §8.1.1.1. The caller
// supplies the 8-octet privacy salt (msgPrivacyParameters); the CBC IV is the
// key-derived pre-IV XORed with that salt. RFC 3414 §8.1.1.1 RECOMMENDS the salt
// be snmpEngineBoots(4) || local-integer(4) (big-endian): encryptPDU builds it
// as engineBoots(4) || counter32(4), where counter32 is the low half of the
// monotonic Agent.nextPrivSalt counter. The engineBoots prefix makes the IV
// deterministically unique across a reboot; the counter32 makes it distinct for
// each of up to 2^32 messages within a boot, so DES-CBC never repeats
// first-block structure (RFC 3414 §8.2.1). The salt is returned to the wire
// unchanged as privParams by the caller so the receiver rebuilds the same IV.
func encryptDES(privKey, data, salt []byte) ([]byte, error) {
	if len(privKey) < 16 {
		return nil, fmt.Errorf("snmpv3: DES privacy key too short: %d bytes", len(privKey))
	}
	if len(salt) != 8 {
		return nil, fmt.Errorf("snmpv3: DES privacy salt must be 8 bytes, got %d", len(salt))
	}
	desKey := privKey[:8]
	preIV := privKey[8:16]
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = preIV[i] ^ salt[i]
	}
	// Pad to DES block size.
	if pad := 8 - (len(data) % 8); pad < 8 {
		data = append(data, make([]byte, pad)...)
	}
	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil, fmt.Errorf("snmpv3: DES cipher init: %w", err)
	}
	encrypted := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, data)
	return encrypted, nil
}

// encryptAES128 encrypts data using AES-128-CFB per RFC 3826 §3.1.2.1. The
// caller supplies the 8-octet privacy salt; the 128-bit IV is
// boots(4) || time(4) || salt(8). RFC 3826 §3.3 requires the salt to change for
// each message — the agent allocates it from a monotonic counter
// (Agent.nextPrivSalt) so the low 64 IV bits never repeat within a (boots,time),
// avoiding CFB IV reuse (which would leak plaintext XORs, RFC 3414 §8.2.1). The
// salt is returned to the wire unchanged as privParams by the caller.
func encryptAES128(privKey, data, salt []byte, boots, time int) ([]byte, error) {
	if len(privKey) < 16 {
		return nil, fmt.Errorf("snmpv3: AES128 privacy key too short: %d bytes", len(privKey))
	}
	if len(salt) != 8 {
		return nil, fmt.Errorf("snmpv3: AES128 privacy salt must be 8 bytes, got %d", len(salt))
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(time))
	copy(iv[8:16], salt)
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil, fmt.Errorf("snmpv3: AES128 cipher init: %w", err)
	}
	encrypted := make([]byte, len(data))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encrypted, data)
	return encrypted, nil
}

// computeAuth computes the HMAC for a v3 message (with auth params zeroed in the message).
func computeAuth(user *usmUser, wholeMsg []byte) []byte {
	hashFn, _ := authHashFunc(user.authProto)
	if hashFn == nil {
		return nil
	}
	truncLen := authTruncLen(user.authProto)
	mac := hmac.New(hashFn, user.authKey)
	mac.Write(wholeMsg)
	result := mac.Sum(nil)
	if len(result) > truncLen {
		result = result[:truncLen]
	}
	return result
}

// buildV3Discovery builds a discovery response (report) with our engine ID.
func (a *Agent) buildV3Discovery(msgID int) []byte {
	// USM security parameters.
	usmFields := berEncodeTLV(tagOctetString, a.engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineBoots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineTime())...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // userName
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // authParams
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Header.
	hdr := berEncodeIntegerTLV(msgID)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagReport})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// Report PDU with usmStatsUnknownEngineIDs (1.3.6.1.6.3.15.1.1.4.0).
	reportOID := []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(reportOID))
	vb = append(vb, berEncodeTLV(tagCounter32, berEncodeCounter32(0))...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(0)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	reportPDU := berEncodeTLV(0xa8, pduBody) // Report PDU tag

	scopedBody := berEncodeTLV(tagOctetString, a.engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	scopedBody = append(scopedBody, reportPDU...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Assemble full message.
	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	return berEncodeTLV(tagSequence, msgBody)
}

// usmStatsNotInTimeWindows is the RFC 3414 §3.2 / §5 report OID
// (1.3.6.1.6.3.15.1.1.2.0) the authoritative engine returns when an
// authenticated request falls outside the timeliness window.
var usmStatsNotInTimeWindows = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0}

// buildV3TimelinessReport builds an authenticated Report PDU carrying
// usmStatsNotInTimeWindows and the agent's CURRENT engineBoots/engineTime, so a
// manager whose cached authoritative boots/time is stale (the legitimate
// not-in-time-window case, e.g. after our restart bumped engineBoots) can
// resynchronize and retry. The report is authenticated (RFC 3414 §3.2 requires
// the not-in-time-window report be sent at the request's security level) but
// never encrypted — it carries no MIB data. A replayed request gets this report
// instead of a data response, so the replay yields nothing useful.
func (a *Agent) buildV3TimelinessReport(msgID int, reqFlags byte, user *usmUser) []byte {
	reportPDU := a.buildReportPDU(usmStatsNotInTimeWindows)

	scopedBody := berEncodeTLV(tagOctetString, a.engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...) // contextName
	scopedBody = append(scopedBody, reportPDU...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Reports are sent authNoPriv (no encryption) regardless of the request's
	// priv flag — they carry no sensitive MIB data.
	respFlags := reqFlags & msgFlagAuth

	truncLen := authTruncLen(user.authProto)
	var authPlaceholder []byte
	if respFlags&msgFlagAuth != 0 && user.authKey != nil {
		authPlaceholder = make([]byte, truncLen)
	}

	usmFields := berEncodeTLV(tagOctetString, a.engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineBoots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineTime())...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(user.name))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(msgID)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{respFlags | msgFlagReport})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	if respFlags&msgFlagAuth != 0 && user.authKey != nil {
		if authMAC := computeAuth(user, wholeMsg); authMAC != nil {
			insertAuthMAC(wholeMsg, authMAC, truncLen)
		}
	}
	return wholeMsg
}

// buildReportPDU encodes a Report PDU (tag 0xa8) with a single varbind whose
// OID is the supplied usmStats counter and whose value is Counter32(0). The
// varbind value is informational — the OID identifies the error to the manager.
func (a *Agent) buildReportPDU(statsOID []int) []byte {
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(statsOID))
	vb = append(vb, berEncodeTLV(tagCounter32, berEncodeCounter32(0))...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(0) // request-id
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	return berEncodeTLV(0xa8, pduBody) // Report PDU tag
}

// buildV3Response builds an authenticated (and optionally encrypted) SNMPv3
// response. contextName is the contextName echoed back into the scopedPDU; it
// is the value decoded from the request (empty for the default context), so the
// manager sees the response is bound to the context it addressed (RFC 3412
// §4.1). The agent serves data only in the default (empty) context — non-default
// contexts are gated to an empty view by the caller — but the response still
// echoes the requested contextName.
func (a *Agent) buildV3Response(msgID int, reqFlags byte, user *usmUser,
	contextName []byte, requestID, errorStatus, errorIndex int, vbs []varbind) []byte {

	// Build varbind list.
	var vbListBytes []byte
	for _, vb := range vbs {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(vb.oid))
		var valBytes []byte
		if vb.tag == tagNoSuchObject || vb.tag == tagNoSuchInstance || vb.tag == tagEndOfMibView {
			valBytes = berEncodeTLV(vb.tag, nil)
		} else {
			valBytes = berEncodeValue(vb.tag, vb.value)
		}
		vbListBytes = append(vbListBytes, berEncodeTLV(tagSequence, append(oidBytes, valBytes...))...)
	}
	vbListEncoded := berEncodeTLV(tagSequence, vbListBytes)

	// Build response PDU.
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorStatus)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorIndex)...)
	pduBody = append(pduBody, vbListEncoded...)
	responsePDU := berEncodeTLV(pduGetResponse, pduBody)

	// Build scopedPDU. contextEngineID is our engineID (we are the authoritative
	// engine); contextName echoes the requested context (empty = default).
	scopedBody := berEncodeTLV(tagOctetString, a.engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, contextName)...) // contextName
	scopedBody = append(scopedBody, responsePDU...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Determine response flags.
	respFlags := reqFlags & (msgFlagAuth | msgFlagPriv)

	// Handle encryption.
	var scopedPDUEncoded []byte
	var privParamsVal []byte
	if respFlags&msgFlagPriv != 0 && user.privKey != nil {
		enc, pp, err := a.encryptPDU(user, scopedPDU)
		if err != nil {
			// Fail closed (RFC 3414 §8.2.1): the manager requested privacy but
			// we could not produce a securely-encrypted PDU — most importantly
			// when the RNG failed to generate the unpredictable per-message
			// privacy salt. Never downgrade to a plaintext response and never
			// send a PDU built from a zero/predictable salt. Returning nil here
			// drops the response (handleV3Packet nil == no datagram), so no
			// scopedPDU ever leaves the agent in the clear or with a weak IV.
			slog.Warn("SNMPv3: privacy encryption failed, dropping response",
				"user", user.name, "err", err)
			return nil
		}
		scopedPDUEncoded = berEncodeTLV(tagOctetString, enc)
		privParamsVal = pp
	} else {
		respFlags &^= msgFlagPriv
		scopedPDUEncoded = scopedPDU
	}

	// Auth params placeholder.
	truncLen := authTruncLen(user.authProto)
	var authPlaceholder []byte
	if respFlags&msgFlagAuth != 0 && user.authKey != nil {
		authPlaceholder = make([]byte, truncLen)
	}

	// USM security parameters.
	usmFields := berEncodeTLV(tagOctetString, a.engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineBoots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineTime())...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(user.name))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, privParamsVal)...)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Header.
	hdr := berEncodeIntegerTLV(msgID)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{respFlags})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// Assemble full message.
	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDUEncoded...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	// Compute and insert auth HMAC.
	if respFlags&msgFlagAuth != 0 && user.authKey != nil {
		// wholeMsg currently has zeroed auth placeholder — compute HMAC over it.
		authMAC := computeAuth(user, wholeMsg)
		if authMAC != nil {
			insertAuthMAC(wholeMsg, authMAC, truncLen)
		}
	}

	return wholeMsg
}

// insertAuthMAC writes the computed HMAC into the USM
// msgAuthenticationParameters field of a freshly built SNMPv3 response.
//
// It locates the field by USM position via usmAuthParamsRange (the same
// positional locator zeroAuthParams uses) rather than scanning for the first
// all-zero OCTET STRING of length truncLen. The old heuristic could land on
// an earlier all-zero field of the same length -- e.g. an all-zero
// truncLen-byte engineID or username -- and corrupt it instead of the
// authParams placeholder (the response-path sibling of #1710). The
// end-start == len(authMAC) check guards against writing a MAC of the wrong
// length into a mismatched slot.
func insertAuthMAC(pkt, authMAC []byte, truncLen int) {
	start, end, ok := usmAuthParamsRange(pkt)
	if !ok || end-start != truncLen || end-start != len(authMAC) {
		return
	}
	copy(pkt[start:end], authMAC)
}

// V3UserInfo returns user info for display (without passwords).
func V3UserInfo(users map[string]*config.SNMPv3User) []V3UserDisplay {
	var result []V3UserDisplay
	for _, u := range users {
		result = append(result, V3UserDisplay{
			Name:      u.Name,
			AuthProto: u.AuthProtocol,
			PrivProto: u.PrivProtocol,
		})
	}
	return result
}

// V3UserDisplay holds user info for display purposes.
type V3UserDisplay struct {
	Name      string
	AuthProto string
	PrivProto string
}

// usmUserServableAtLevel9155 reports why a request must be refused, or "" when
// it may proceed.
//
// #9155: the floor used to read `user.authKey != nil` / `user.privKey != nil`.
// A key is derived only from a password, and BOTH keys are derived with the
// AUTH hash function -- so any configuration that named a protocol but produced
// no key had NO FLOOR AT ALL and was answered at whatever level the request
// asked for. Two ordinary commits reach that state (an unrecognised protocol
// spelling, and privacy without authentication), and a config persisted before
// those commit gates existed reaches it through Store.Load regardless.
//
// So a key-derivation FAILURE degraded to clear. Keyed on the configured
// protocol it fails closed instead.
//
// EXTRACTED RATHER THAN LEFT INLINE, and the reason is a measurement. Inline,
// the two "configured but no key" arms SURVIVED mutation: with the flags set,
// the downstream auth check and decryptPDU already refuse, so nothing could
// observe the difference and a mutant deleting them killed no cell. They are
// not decoration -- they are the only place that says WHICH user and WHICH
// protocol, and a silent drop is the shape an operator cannot diagnose -- but a
// guard whose rejected input cannot be driven is a guard nobody can check.
// Pulled out as a pure function, every arm is drivable and the mutants die.
//
// The commit gates in pkg/config are not redundant with this: they tell the
// operator at commit time, and this refuses to serve a config already on disk
// or arriving by peer sync, which no commit gate can reach.
func usmUserServableAtLevel9155(user *usmUser, msgFlags byte) string {
	if user == nil {
		return "unknown user"
	}
	if user.authProto != "" {
		if msgFlags&msgFlagAuth == 0 {
			return "request below user minimum security level (auth required)"
		}
		if user.authKey == nil {
			return "user names an authentication protocol but has no derived key"
		}
	}
	if user.privProto != "" {
		if msgFlags&msgFlagPriv == 0 {
			return "request below user minimum security level (priv required)"
		}
		if user.privKey == nil {
			return "user names a privacy protocol but has no derived key"
		}
	}
	return ""
}
