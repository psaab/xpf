package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildLinkTrap_LinkDown(t *testing.T) {
	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only"},
			},
		},
		startTime: time.Now().Add(-10 * time.Second),
	}

	pkt := agent.buildLinkTrap("public", false, 5, "trust0", true)
	if len(pkt) == 0 {
		t.Fatal("empty trap packet")
	}

	// Decode outer SEQUENCE.
	tag, body, err := berDecodeHeader(pkt)
	if err != nil {
		t.Fatalf("decode outer sequence: %v", err)
	}
	if tag != tagSequence {
		t.Fatalf("expected SEQUENCE tag 0x30, got 0x%02x", tag)
	}

	// Decode version.
	version, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if version != snmpVersion2c {
		t.Fatalf("expected version %d, got %d", snmpVersion2c, version)
	}

	// Decode community.
	community, rest, err := berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("decode community: %v", err)
	}
	if string(community) != "public" {
		t.Fatalf("expected community 'public', got '%s'", community)
	}

	// Decode PDU header.
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("decode PDU header: %v", err)
	}
	if pduTag != pduSNMPv2Trap {
		t.Fatalf("expected PDU tag 0xa7, got 0x%02x", pduTag)
	}

	// Decode request-id, error-status, error-index.
	_, pduBody, err = berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("decode request-id: %v", err)
	}

	errStatus, pduBody, err := berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("decode error-status: %v", err)
	}
	if errStatus != 0 {
		t.Fatalf("expected error-status 0, got %d", errStatus)
	}

	errIdx, pduBody, err := berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("decode error-index: %v", err)
	}
	if errIdx != 0 {
		t.Fatalf("expected error-index 0, got %d", errIdx)
	}

	// Decode varbind list.
	vbTag, vbListBody, err := berDecodeHeader(pduBody)
	if err != nil {
		t.Fatalf("decode varbind list: %v", err)
	}
	if vbTag != tagSequence {
		t.Fatalf("expected varbind list SEQUENCE, got 0x%02x", vbTag)
	}

	// Count varbinds (each is a SEQUENCE).
	count := 0
	remaining := vbListBody
	for len(remaining) > 0 {
		totalLen := berEncodedLen(remaining)
		if totalLen <= 0 || totalLen > len(remaining) {
			break
		}
		remaining = remaining[totalLen:]
		count++
	}
	if count != 6 {
		t.Fatalf("expected 6 varbinds, got %d", count)
	}
}

func TestBuildLinkTrap_LinkUp(t *testing.T) {
	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"secret": {Name: "secret", Authorization: "read-only"},
			},
		},
		startTime: time.Now().Add(-60 * time.Second),
	}

	pkt := agent.buildLinkTrap("secret", true, 2, "wan0", true)
	if len(pkt) == 0 {
		t.Fatal("empty trap packet")
	}

	// Verify community is "secret".
	_, body, _ := berDecodeHeader(pkt)
	_, rest, _ := berDecodeInteger(body) // version
	community, rest, _ := berDecodeOctetString(rest)
	if string(community) != "secret" {
		t.Fatalf("expected community 'secret', got '%s'", community)
	}

	// Verify PDU tag.
	pduTag, _, err := berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("decode PDU: %v", err)
	}
	if pduTag != pduSNMPv2Trap {
		t.Fatalf("expected PDU tag 0xa7, got 0x%02x", pduTag)
	}
}

func TestSendLinkTraps_NoConfig(t *testing.T) {
	agent := &Agent{
		cfg:       nil,
		startTime: time.Now(),
	}
	// Should not panic with nil config.
	agent.NotifyLinkDown(1, "eth0", true)
	agent.NotifyLinkUp(1, "eth0", true)
}

func TestSendLinkTraps_NoTrapGroups(t *testing.T) {
	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public"},
			},
			TrapGroups: map[string]*config.SNMPTrapGroup{},
		},
		startTime: time.Now(),
	}
	// Should return immediately (no targets).
	agent.NotifyLinkDown(1, "eth0", true)
	agent.NotifyLinkUp(1, "eth0", true)
}

func TestSendLinkTraps_WithTarget(t *testing.T) {
	// Start a UDP listener to receive traps.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()

	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"test": {Name: "test", Authorization: "read-only"},
			},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"managers": {
					Name:    "managers",
					Targets: []string{addr},
				},
			},
		},
		startTime: time.Now(),
	}

	// Send a linkDown trap.
	agent.NotifyLinkDown(3, "dmz0", true)

	// Read the received packet.
	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read trap: %v", err)
	}

	// Verify it's a valid SNMP packet.
	tag, body, err := berDecodeHeader(buf[:n])
	if err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	if tag != tagSequence {
		t.Fatalf("expected SEQUENCE, got 0x%02x", tag)
	}

	version, _, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if version != snmpVersion2c {
		t.Fatalf("expected v2c, got %d", version)
	}
}

func TestTrapVarbindOIDs(t *testing.T) {
	agent := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"c": {Name: "c"},
			},
		},
		startTime: time.Now(),
	}

	pkt := agent.buildLinkTrap("c", false, 7, "tunnel0", true)

	// Navigate to varbind list.
	_, body, _ := berDecodeHeader(pkt)
	_, rest, _ := berDecodeInteger(body)
	_, rest, _ = berDecodeOctetString(rest)
	_, pduBody, _ := berDecodeHeader(rest)
	_, pduBody, _ = berDecodeInteger(pduBody) // request-id
	_, pduBody, _ = berDecodeInteger(pduBody) // error-status
	_, pduBody, _ = berDecodeInteger(pduBody) // error-index
	_, vbList, _ := berDecodeHeader(pduBody)  // varbind list

	// Extract first varbind OID: should be sysUpTime.0
	_, vb1Body, _ := berDecodeHeader(vbList)
	oid1Raw := extractVarbindOID(t, vb1Body)
	if !oidEqual(oid1Raw, oidSysUpTime) {
		t.Errorf("varbind 1 OID = %v, want sysUpTime.0 %v", oid1Raw, oidSysUpTime)
	}

	// Advance past first varbind.
	vb1Len := berEncodedLen(vbList)
	vbList = vbList[vb1Len:]

	// Second varbind OID: should be snmpTrapOID.0
	_, vb2Body, _ := berDecodeHeader(vbList)
	oid2Raw := extractVarbindOID(t, vb2Body)
	if !oidEqual(oid2Raw, oidSnmpTrapOID) {
		t.Errorf("varbind 2 OID = %v, want snmpTrapOID.0 %v", oid2Raw, oidSnmpTrapOID)
	}
}

func extractVarbindOID(t *testing.T, vbBody []byte) []int {
	t.Helper()
	if len(vbBody) < 2 || vbBody[0] != tagObjectIdentifier {
		t.Fatal("varbind does not start with OID")
	}
	oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
	if err != nil {
		t.Fatalf("decode OID length: %v", err)
	}
	headerLen := 1 + oidLenBytes
	oid, err := berDecodeOID(vbBody[headerLen : headerLen+oidLen])
	if err != nil {
		t.Fatalf("decode OID: %v", err)
	}
	return oid
}
