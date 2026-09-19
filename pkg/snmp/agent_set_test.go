package snmp

import (
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildV2cSetRequest constructs a minimal SNMP v2c SET request packet for a
// single OID with a null value. It mirrors buildResponse but emits a
// pduSetRequest PDU so the agent's SET path can be exercised end to end.
func buildV2cSetRequest(community string, requestID int, oid []int) []byte {
	// Single varbind: SEQUENCE { OID, NULL }.
	oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	valBytes := berEncodeTLV(tagNull, nil)
	vb := berEncodeTLV(tagSequence, append(oidBytes, valBytes...))
	vbList := berEncodeTLV(tagSequence, vb)

	// PDU body: request-id, error-status(0), error-index(0), varbind-list.
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	pdu := berEncodeTLV(pduSetRequest, pduBody)

	// Message: version(v2c), community, PDU.
	msg := berEncodeIntegerTLV(snmpVersion2c)
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

// decodeResponseErrorStatus parses a SNMP v2c GetResponse packet and returns
// its error-status field. It walks SEQUENCE -> version -> community -> PDU ->
// request-id -> error-status.
func decodeResponseErrorStatus(t *testing.T, resp []byte) int {
	t.Helper()
	tag, body, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("response: not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	// version
	_, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("response: decode version: %v", err)
	}
	// community
	_, rest, err = berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("response: decode community: %v", err)
	}
	// PDU
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("response: decode PDU header: %v", err)
	}
	if pduTag != pduGetResponse {
		t.Fatalf("response: PDU tag = 0x%02x, want GetResponse (0x%02x)", pduTag, pduGetResponse)
	}
	// request-id
	_, pduRest, err := berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("response: decode request-id: %v", err)
	}
	// error-status
	errStatus, _, err := berDecodeInteger(pduRest)
	if err != nil {
		t.Fatalf("response: decode error-status: %v", err)
	}
	return errStatus
}

// TestSetRequest_ReadOnlyCommunityDenied verifies that a SET request from a
// read-only community is rejected with noAccess. This is the authorization
// gate added for issue #2008 H17: prior to the fix the agent had no SET
// handler at all (the default case dropped the PDU and returned nil), so a
// read-only community's configured authorization was never enforced.
//
// Mutation check: if communityCanWrite always returned true (gate removed),
// a read-only SET would be answered with notWritable like a read-write SET,
// and this test would fail on the errNoAccess assertion.
func TestSetRequest_ReadOnlyCommunityDenied(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	pkt := buildV2cSetRequest("public", 7, oidSysContact)
	resp := a.handlePacket(pkt)
	if resp == nil {
		t.Fatal("SET from read-only community produced no response (PDU was dropped)")
	}
	if got := decodeResponseErrorStatus(t, resp); got != errNoAccess {
		t.Errorf("read-only SET error-status = %d, want noAccess (%d)", got, errNoAccess)
	}
}

// TestSetRequest_ReadWriteCommunityPassesGate verifies that a read-write
// community is NOT denied at the authorization gate. The agent exposes no
// writable objects, so the write itself is refused with notWritable rather
// than noAccess. The distinction (notWritable != noAccess) is exactly what
// the authorization gate produces; removing the gate would yield noAccess for
// both communities (failing the read-only test) or notWritable for both
// (failing nothing here but failing the read-only test's noAccess assertion).
func TestSetRequest_ReadWriteCommunityPassesGate(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})

	pkt := buildV2cSetRequest("private", 9, oidSysContact)
	resp := a.handlePacket(pkt)
	if resp == nil {
		t.Fatal("SET from read-write community produced no response")
	}
	got := decodeResponseErrorStatus(t, resp)
	if got == errNoAccess {
		t.Errorf("read-write SET was denied at authorization gate (noAccess); "+
			"authorization read-write must pass the gate, got error-status %d", got)
	}
	if got != errNotWritable {
		t.Errorf("read-write SET error-status = %d, want notWritable (%d)", got, errNotWritable)
	}
}

// TestSetRequest_UnknownCommunityDropped verifies that a SET from an
// unconfigured community is dropped (no response), matching the read path's
// silent-drop behavior for invalid communities.
func TestSetRequest_UnknownCommunityDropped(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-write"},
		},
	})

	pkt := buildV2cSetRequest("nope", 3, oidSysContact)
	if resp := a.handlePacket(pkt); resp != nil {
		t.Errorf("SET from unknown community should be dropped, got %d-byte response", len(resp))
	}
}

// TestUpdateConfig_AuthorizationDowngradeEnforced is the gating regression for
// issue #2008 H17 / PR #2009: the SNMP agent is created once at daemon startup
// and keeps serving on UDP/161; the daemon's applyConfigLocked must call
// Agent.UpdateConfig on commit so a community that is downgraded read-write ->
// read-only takes effect on the live agent. Before the reconcile call the agent
// served from a stale community map, so a SET that should now be denied with
// noAccess would still pass the authorization gate (notWritable).
//
// Mutation check: if the UpdateConfig call is removed from applyConfigLocked
// (or UpdateConfig is made a no-op), the agent keeps its read-write community
// and the post-reconcile SET returns notWritable, failing the noAccess
// assertion below. This test exercises UpdateConfig directly (the daemon apply
// path is covered by the daemon package), so it fails if UpdateConfig does not
// swap the live config.
func TestUpdateConfig_AuthorizationDowngradeEnforced(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-write"},
		},
	})

	// Sanity: while read-write, the SET passes the authorization gate and is
	// refused only by the no-writable-object rule (notWritable).
	resp := a.handlePacket(buildV2cSetRequest("private", 1, oidSysContact))
	if resp == nil {
		t.Fatal("pre-reconcile read-write SET produced no response")
	}
	if got := decodeResponseErrorStatus(t, resp); got != errNotWritable {
		t.Fatalf("pre-reconcile read-write SET error-status = %d, want notWritable (%d)", got, errNotWritable)
	}

	// Simulate a commit that downgrades the community to read-only.
	a.UpdateConfig(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"private": {Name: "private", Authorization: "read-only"},
		},
	})

	// The live agent must now deny the SET at the authorization gate.
	resp = a.handlePacket(buildV2cSetRequest("private", 2, oidSysContact))
	if resp == nil {
		t.Fatal("post-reconcile read-only SET produced no response (PDU dropped)")
	}
	if got := decodeResponseErrorStatus(t, resp); got != errNoAccess {
		t.Errorf("post-reconcile read-only SET error-status = %d, want noAccess (%d); "+
			"UpdateConfig did not swap the live authorization config", got, errNoAccess)
	}
}

// TestUpdateConfig_CommunityDeletionEnforced verifies that deleting a community
// on commit makes a subsequent SET from that (now-unknown) community be dropped
// silently, matching the read-path behavior for unknown communities. Before the
// reconcile, the agent would still recognize the deleted community.
func TestUpdateConfig_CommunityDeletionEnforced(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"gone": {Name: "gone", Authorization: "read-write"},
		},
	})

	// Commit that removes the community entirely.
	a.UpdateConfig(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{},
	})

	if resp := a.handlePacket(buildV2cSetRequest("gone", 5, oidSysContact)); resp != nil {
		t.Errorf("SET from deleted community should be dropped, got %d-byte response", len(resp))
	}
}

// TestUpdateConfig_NilConfigSafe verifies that reconciling to a nil SNMP config
// (the operator removed the whole `snmp` stanza) does not panic and disables
// the agent's authorization surface: every v2c request is then dropped because
// no community is configured.
func TestUpdateConfig_NilConfigSafe(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	a.UpdateConfig(nil)

	if resp := a.handlePacket(buildV2cSetRequest("public", 6, oidSysContact)); resp != nil {
		t.Errorf("after nil reconcile, SET should be dropped (no community), got %d-byte response", len(resp))
	}
}

// TestUpdateConfig_RaceWithServe exercises the reconcile-vs-serve path: one
// goroutine repeatedly calls UpdateConfig (swapping the community map and the
// USM user table) while another repeatedly drives requests through
// handlePacket. With -race this fails if the cfg/v3Users reads on the serving
// path are not synchronized with the UpdateConfig swap (the data race the
// cfgMu RWMutex closes). Run under: go test -race ./pkg/snmp/.
func TestUpdateConfig_RaceWithServe(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
		V3Users: map[string]*config.SNMPv3User{
			"admin": {Name: "admin", AuthProtocol: "sha", AuthPassword: "pw-pw-pw-pw-pw"},
		},
	})

	const iters = 500
	var wg sync.WaitGroup

	// Writer: alternate the live config between two shapes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rw := &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-write"},
			},
			V3Users: map[string]*config.SNMPv3User{
				"admin": {Name: "admin", AuthProtocol: "md5", AuthPassword: "other-pw-1234"},
			},
		}
		ro := &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only"},
			},
		}
		for i := 0; i < iters; i++ {
			if i%2 == 0 {
				a.UpdateConfig(rw)
			} else {
				a.UpdateConfig(ro)
			}
		}
	}()

	// Reader: drive v2c GET, v2c SET, and a v3 discovery through the agent.
	getPkt := buildV2cGetRequest("public", 1, oidSysContact)
	setPkt := buildV2cSetRequest("public", 2, oidSysContact)
	v3Disc := buildV3DiscoveryRequest()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = a.handlePacket(getPkt)
			_ = a.handlePacket(setPkt)
			_ = a.handlePacket(v3Disc)
		}
	}()

	wg.Wait()
}

// buildV2cGetRequest builds a minimal v2c GET for one OID (helper for the race
// test; the SET helper already lives above).
func buildV2cGetRequest(community string, requestID int, oid []int) []byte {
	oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	valBytes := berEncodeTLV(tagNull, nil)
	vb := berEncodeTLV(tagSequence, append(oidBytes, valBytes...))
	vbList := berEncodeTLV(tagSequence, vb)
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	pdu := berEncodeTLV(pduGetRequest, pduBody)
	msg := berEncodeIntegerTLV(snmpVersion2c)
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

// buildV3DiscoveryRequest builds a v3 engine-ID discovery message (empty
// userName) that exercises the v3 entry in handlePacket without needing an
// authenticated packet.
func buildV3DiscoveryRequest() []byte {
	usmFields := berEncodeTLV(tagOctetString, nil) // engineID (empty -> discovery)
	usmFields = append(usmFields, berEncodeIntegerTLV(0)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(0)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // userName (empty)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // authParams
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(7)
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
	return berEncodeTLV(tagSequence, msgBody)
}

// TestSETAuthorized_MatchesLiveHandlerGate verifies that the exported
// SETAuthorized observation matches what the actual SET handler decides against
// the live config — across an UpdateConfig downgrade. This makes SETAuthorized
// a faithful proxy for the live SET access-control gate, which the daemon
// package's reconcile-wiring test relies on (it cannot reach the unexported
// handlePacket / packet builders). For each community state the two must agree:
// SETAuthorized == (handleSet did NOT return noAccess).
func TestSETAuthorized_MatchesLiveHandlerGate(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"c": {Name: "c", Authorization: "read-write"},
		},
	})

	check := func(stage string, wantAuthorized bool) {
		t.Helper()
		gotAuthorized := a.SETAuthorized("c")
		if gotAuthorized != wantAuthorized {
			t.Fatalf("%s: SETAuthorized(c) = %v, want %v", stage, gotAuthorized, wantAuthorized)
		}
		resp := a.handlePacket(buildV2cSetRequest("c", 1, oidSysContact))
		if resp == nil {
			t.Fatalf("%s: SET produced no response", stage)
		}
		handlerAllowed := decodeResponseErrorStatus(t, resp) != errNoAccess
		if handlerAllowed != gotAuthorized {
			t.Fatalf("%s: live handler allowed=%v but SETAuthorized=%v (proxy diverged from gate)",
				stage, handlerAllowed, gotAuthorized)
		}
	}

	check("read-write", true)

	a.UpdateConfig(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"c": {Name: "c", Authorization: "read-only"},
		},
	})
	check("downgraded-read-only", false)

	if a.SETAuthorized("missing") {
		t.Error("SETAuthorized(missing) = true, want false for unknown community")
	}
}

// TestGetCommunity_Authorization verifies getCommunity returns the community
// struct with its authorization level intact, the lookup that backs the SET
// access-control gate.
func TestGetCommunity_Authorization(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"ro": {Name: "ro", Authorization: "read-only"},
			"rw": {Name: "rw", Authorization: "read-write"},
		},
	})

	if c := a.getCommunity("ro"); c == nil || communityCanWrite(c) {
		t.Errorf("getCommunity(ro): want non-nil read-only, communityCanWrite=%v", communityCanWrite(c))
	}
	if c := a.getCommunity("rw"); c == nil || !communityCanWrite(c) {
		t.Errorf("getCommunity(rw): want non-nil read-write, communityCanWrite=%v", communityCanWrite(c))
	}
	if c := a.getCommunity("missing"); c != nil {
		t.Errorf("getCommunity(missing) = %v, want nil", c)
	}
}
