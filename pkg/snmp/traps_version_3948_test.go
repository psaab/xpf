package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// decodeTrapVersionAndPDU walks an SNMP trap message down to its PDU and
// returns the message version field and the PDU tag.
func decodeTrapVersionAndPDU(t *testing.T, pkt []byte) (version int, pduTag byte) {
	t.Helper()
	tag, body, err := berDecodeHeader(pkt)
	if err != nil || tag != tagSequence {
		t.Fatalf("outer SEQUENCE: tag=0x%02x err=%v", tag, err)
	}
	version, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("decode community: %v", err)
	}
	pduTag, _, err = berDecodeHeader(rest)
	if err != nil {
		t.Fatalf("decode PDU header: %v", err)
	}
	return version, pduTag
}

// TestBuildLinkTrapV1_Structure verifies the SNMPv1 Trap-PDU shape (#3948):
// version field 0, PDU tag 0xa4, the snmpTraps enterprise OID, the correct
// generic-trap code (2=linkDown, 3=linkUp), specific-trap 0, and 4 varbinds
// (ifIndex, ifAdminStatus, ifOperStatus, ifDescr — sysUpTime.0/snmpTrapOID.0
// are NOT repeated as varbinds in v1; #16778).
func TestBuildLinkTrapV1_Structure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		linkUp      bool
		wantGeneric int
	}{
		{"linkDown", false, genericTrapLinkDown},
		{"linkUp", true, genericTrapLinkUp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{startTime: time.Now().Add(-30 * time.Second)}
			pkt := a.buildLinkTrapV1WithUptime("public", "", tc.linkUp, 5, "ge-0-0-0", int(time.Since(a.startTime).Milliseconds()/10), true)

			version, pduTag := decodeTrapVersionAndPDU(t, pkt)
			if version != snmpVersion1 {
				t.Fatalf("version = %d, want %d (v1)", version, snmpVersion1)
			}
			if pduTag != pduSNMPv1Trap {
				t.Fatalf("PDU tag = 0x%02x, want 0x%02x (v1 Trap-PDU)", pduTag, pduSNMPv1Trap)
			}

			// Re-walk to the PDU body to inspect the v1-specific fields.
			_, body, _ := berDecodeHeader(pkt)
			_, rest, _ := berDecodeInteger(body)    // version
			_, rest, _ = berDecodeOctetString(rest) // community
			_, pduBody, _ := berDecodeHeader(rest)  // Trap-PDU body

			// enterprise OID == snmpTraps
			entTag, entVal, err := berDecodeHeader(pduBody)
			if err != nil || entTag != tagObjectIdentifier {
				t.Fatalf("enterprise: tag=0x%02x err=%v", entTag, err)
			}
			entOID, err := berDecodeOID(entVal)
			if err != nil {
				t.Fatalf("decode enterprise OID: %v", err)
			}
			if !oidEqual(entOID, oidSnmpTraps) {
				t.Fatalf("enterprise OID = %v, want snmpTraps %v", entOID, oidSnmpTraps)
			}
			pduBody = pduBody[berEncodedLen(pduBody):]

			// agent-addr: IpAddress (tag 0x40)
			addrTag, addrVal, err := berDecodeHeader(pduBody)
			if err != nil || addrTag != tagIPAddress {
				t.Fatalf("agent-addr: tag=0x%02x err=%v", addrTag, err)
			}
			if len(addrVal) != 4 {
				t.Fatalf("agent-addr length = %d, want 4", len(addrVal))
			}
			pduBody = pduBody[berEncodedLen(pduBody):]

			// generic-trap
			generic, pduBody2, err := berDecodeInteger(pduBody)
			if err != nil {
				t.Fatalf("generic-trap: %v", err)
			}
			if generic != tc.wantGeneric {
				t.Fatalf("generic-trap = %d, want %d", generic, tc.wantGeneric)
			}

			// specific-trap == 0
			specific, pduBody3, err := berDecodeInteger(pduBody2)
			if err != nil {
				t.Fatalf("specific-trap: %v", err)
			}
			if specific != 0 {
				t.Fatalf("specific-trap = %d, want 0", specific)
			}

			// time-stamp: TimeTicks (tag 0x43)
			tsTag, _, err := berDecodeHeader(pduBody3)
			if err != nil || tsTag != tagTimeTicks {
				t.Fatalf("time-stamp: tag=0x%02x err=%v", tsTag, err)
			}
			pduBody3 = pduBody3[berEncodedLen(pduBody3):]

			// varbind list: 4 varbinds (#16778 OBJECTS order + trailing ifDescr)
			vbTag, vbList, err := berDecodeHeader(pduBody3)
			if err != nil || vbTag != tagSequence {
				t.Fatalf("varbind list: tag=0x%02x err=%v", vbTag, err)
			}
			count := 0
			for len(vbList) > 0 {
				n := berEncodedLen(vbList)
				if n <= 0 || n > len(vbList) {
					break
				}
				vbList = vbList[n:]
				count++
			}
			if count != 4 {
				t.Fatalf("v1 varbind count = %d, want 4", count)
			}
		})
	}
}

// recvTrapVersions enqueues a link trap for a trap group with the given version
// and returns the (version, pduTag) of every UDP packet the agent emits.
func recvTrapVersions(t *testing.T, groupVersion string, want int) [][2]int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()

	a := &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only"},
			},
			TrapGroups: map[string]*config.SNMPTrapGroup{
				"managers": {Name: "managers", Targets: []string{addr}, Version: groupVersion},
			},
		},
		startTime: time.Now().Add(-10 * time.Second),
	}
	a.NotifyLinkDown(3, "ge-0-0-1", true)

	var got [][2]int
	buf := make([]byte, 4096)
	for i := 0; i < want; i++ {
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read trap %d/%d (version=%q): %v", i+1, want, groupVersion, err)
		}
		v, tag := decodeTrapVersionAndPDU(t, append([]byte(nil), buf[:n]...))
		got = append(got, [2]int{v, int(tag)})
	}
	return got
}

// TestSendLinkTraps_VersionV1_EmitsV1 is the config->emit RED-on-revert guard.
// A trap group configured `version v1` must put an SNMPv1 Trap-PDU (version
// field 0, PDU tag 0xa4) on the wire. Before the fix sendLinkTraps built a v2c
// trap regardless of the group version, so this receives version 1 / tag 0xa7
// and fails.
func TestSendLinkTraps_VersionV1_EmitsV1(t *testing.T) {
	got := recvTrapVersions(t, "v1", 1)
	if got[0][0] != snmpVersion1 || byte(got[0][1]) != pduSNMPv1Trap {
		t.Fatalf("version v1 group emitted version=%d pduTag=0x%02x, want version=%d pduTag=0x%02x",
			got[0][0], got[0][1], snmpVersion1, pduSNMPv1Trap)
	}
}

// TestSendLinkTraps_VersionV2_EmitsV2c confirms `version v2` stays v2c.
func TestSendLinkTraps_VersionV2_EmitsV2c(t *testing.T) {
	got := recvTrapVersions(t, "v2", 1)
	if got[0][0] != snmpVersion2c || byte(got[0][1]) != pduSNMPv2Trap {
		t.Fatalf("version v2 group emitted version=%d pduTag=0x%02x, want version=%d pduTag=0x%02x",
			got[0][0], got[0][1], snmpVersion2c, pduSNMPv2Trap)
	}
}

// TestSendLinkTraps_VersionUnspecified_EmitsV2c confirms the unspecified
// (empty) version defaults to v2c — the pre-#3948 behavior is preserved for
// groups that never set a version.
func TestSendLinkTraps_VersionUnspecified_EmitsV2c(t *testing.T) {
	got := recvTrapVersions(t, "", 1)
	if got[0][0] != snmpVersion2c || byte(got[0][1]) != pduSNMPv2Trap {
		t.Fatalf("unspecified version emitted version=%d pduTag=0x%02x, want v2c version=%d pduTag=0x%02x",
			got[0][0], got[0][1], snmpVersion2c, pduSNMPv2Trap)
	}
}

// TestSendLinkTraps_VersionAll_EmitsBoth confirms `version all` puts BOTH a v1
// and a v2c trap on the wire (Junos semantics).
func TestSendLinkTraps_VersionAll_EmitsBoth(t *testing.T) {
	got := recvTrapVersions(t, "all", 2)
	sawV1, sawV2c := false, false
	for _, g := range got {
		switch {
		case g[0] == snmpVersion1 && byte(g[1]) == pduSNMPv1Trap:
			sawV1 = true
		case g[0] == snmpVersion2c && byte(g[1]) == pduSNMPv2Trap:
			sawV2c = true
		}
	}
	if !sawV1 || !sawV2c {
		t.Fatalf("version all: sawV1=%v sawV2c=%v (packets=%v), want both", sawV1, sawV2c, got)
	}
}

// TestTrapKindsForVersion17066 pins the sole version dispatch (#17066).
// Before this, buildLinkTrapsForVersion switched on v1/all but its only
// production callers passed "v2" or a version sendLinkTraps had already
// routed away, so its v1/all arms were dead while tests and the README
// treated them as the dispatch. Mutating trapKindsForVersion (e.g. swapping
// the v1/all returns) must redden this cell.
func TestTrapKindsForVersion17066(t *testing.T) {
	cases := []struct {
		version string
		v1, v2c bool
	}{
		{"v1", true, false},
		{"all", true, true},
		{"v2", false, true},
		{"", false, true},
		{"bogus", false, true},
	}
	for _, tc := range cases {
		v1, v2c := trapKindsForVersion(tc.version)
		if v1 != tc.v1 || v2c != tc.v2c {
			t.Errorf("trapKindsForVersion(%q) = (%v, %v), want (%v, %v)", tc.version, v1, v2c, tc.v1, tc.v2c)
		}
	}
}
