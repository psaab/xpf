package snmp

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16180: the v1 and v2c handlers previously duplicated the fail-closed
// community admission head (BER community decode -> getCommunity lookup ->
// AllowsSource enforcement, with the #4302 no-secret logging discipline).
// communityGate is the single extracted head both handlers now share; the
// handlers and their per-varbind PDU behaviour are NOT merged (#5049), and
// v3 never passes through the gate.
//
// These tests drive the DIFFERENTIAL acceptance check: the same admission
// outcomes must hold on both the v1 and v2c wire paths — accepted
// community, wrong community, allowlist allowed/denied, malformed
// community field — and denial logs must contain no community secret on
// either path. The source-denied known_community=true log is asserted here
// for the first time (only the unknown-community arm had #4302 coverage).
//
// Decisive against extraction-introduced divergence: revert communityGate
// to skip getCommunity (admit any community) or to skip AllowsSource and
// the wrong-community / denied-source rows on BOTH versions answer; revert
// it to always deny and the accepted / allowed rows on both versions drop.

// gatePacket builds a GET request for oidSysDescr in the wire format of the
// named version ("v1" version field 0, "v2c" version field 1).
func gatePacket(version, community string, rid int) []byte {
	if version == "v1" {
		return buildV1Request(pduGetRequest, community, rid, [][]int{oidSysDescr})
	}
	return buildV2cGetRequest(community, rid, oidSysDescr)
}

func gateAgent(clients []config.SNMPClient) *Agent {
	return NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"scoped": {
				Name:          "scoped",
				Authorization: "read-only",
				Clients:       clients,
			},
			"open": {Name: "open", Authorization: "read-only"},
		},
	})
}

var gateVersions = []string{"v1", "v2c"}

// Accepted community, unscoped: served on both versions from any source.
func TestCommunityGate_DifferentialAccepted(t *testing.T) {
	for _, v := range gateVersions {
		a := gateAgent(nil)
		pkt := gatePacket(v, "open", 16180)
		if resp := a.handlePacketFrom(pkt, net.ParseIP("192.0.2.5")); resp == nil {
			t.Fatalf("%s: GET with accepted unscoped community was dropped; want a response", v)
		}
	}
}

// Wrong community: dropped on both versions.
func TestCommunityGate_DifferentialWrongCommunity(t *testing.T) {
	for _, v := range gateVersions {
		a := gateAgent(nil)
		pkt := gatePacket(v, "not-a-community", 16181)
		if resp := a.handlePacketFrom(pkt, net.ParseIP("10.0.0.9")); resp != nil {
			t.Fatalf("%s: GET with wrong community was answered; want no response", v)
		}
	}
}

// Scoped community: allowed source served, denied source dropped, on both
// versions — the #4289 lockstep arm.
func TestCommunityGate_DifferentialAllowlist(t *testing.T) {
	clients := []config.SNMPClient{{Prefix: "10.0.0.0/24"}}
	for _, v := range gateVersions {
		a := gateAgent(clients)
		pkt := gatePacket(v, "scoped", 16182)
		if resp := a.handlePacketFrom(pkt, snmpSource10687("10.0.0.9")); resp == nil {
			t.Fatalf("%s: GET from allowlisted source (10.0.0.9 in 10.0.0.0/24) was dropped; want a response", v)
		}
		if resp := a.handlePacketFrom(pkt, snmpSource10687("192.0.2.5")); resp != nil {
			t.Fatalf("%s: GET from non-allowlisted source (192.0.2.5) was answered; want no response (fail-open)", v)
		}
	}
}

// Truncated community field: the BER decode arm of the gate drops the
// packet on both versions. Built by truncating a well-formed request
// inside its community field (the bytes right after the version integer).
func TestCommunityGate_DifferentialMalformedCommunity(t *testing.T) {
	for _, v := range gateVersions {
		a := gateAgent(nil)
		good := gatePacket(v, "open", 16183)
		// Keep outer header + version + only 2 bytes of the community
		// TLV, so berDecodeOctetString fails inside the gate.
		_, msgBody, err := berDecodeHeader(good)
		if err != nil {
			t.Fatalf("%s: decode own request: %v", v, err)
		}
		_, afterVersion, err := berDecodeInteger(msgBody)
		if err != nil {
			t.Fatalf("%s: decode own version: %v", v, err)
		}
		keep := len(good) - len(afterVersion) + 2
		if keep >= len(good) {
			t.Fatalf("%s: test bug: keep=%d not truncating len=%d", v, keep, len(good))
		}
		if resp := a.handlePacket(good[:keep]); resp != nil {
			t.Fatalf("%s: packet with truncated community field was answered; want no response", v)
		}
	}
}

// Direct gate contract: success returns the raw community bytes, the
// resolved community, and the remainder positioned at the PDU; every
// failure mode returns all-nil so callers drop without serving.
func TestCommunityGate_DirectContract(t *testing.T) {
	a := gateAgent([]config.SNMPClient{{Prefix: "10.0.0.0/24"}})

	rest := berEncodeTLV(tagOctetString, []byte("scoped"))
	rest = append(rest, 0xA0, 0x00) // fake PDU header bytes as remainder
	community, comm, pduRest := a.communityGate(rest, snmpSource10687("10.0.0.9"))
	if string(community) != "scoped" || comm == nil || comm.Name != "scoped" {
		t.Fatalf("gate success: community=%q comm=%v, want scoped/scoped", community, comm)
	}
	if len(pduRest) != 2 || pduRest[0] != 0xA0 {
		t.Fatalf("gate success: pduRest=%v, want the 2 remainder bytes", pduRest)
	}

	for name, tc := range map[string]struct {
		rest []byte
		src  net.IP
	}{
		"undecodable community": {[]byte{0x04}, nil},
		"unknown community": {
			berEncodeTLV(tagOctetString, []byte("nope")), nil,
		},
		"denied source": {
			berEncodeTLV(tagOctetString, []byte("scoped")),
			snmpSource10687("192.0.2.5"),
		},
	} {
		community, comm, pduRest := a.communityGate(tc.rest, tc.src)
		if community != nil || comm != nil || pduRest != nil {
			t.Fatalf("gate %s: got (%q, %v, %v), want all nil (fail-closed)", name, community, comm, pduRest)
		}
	}

	// Nil srcIP disables the source check (AllowsSource semantics preserved):
	// the scoped community is admitted when no source is known.
	if _, comm, _ := a.communityGate(berEncodeTLV(tagOctetString, []byte("scoped")), nil); comm == nil {
		t.Fatal("gate with nil srcIP denied a scoped community; want admission (source check disabled)")
	}
}

// Denial logs on BOTH versions must name the source and the
// known_community discrimination, and must never contain the community
// secret — for the unknown-community arm (#4302) and, newly covered here,
// the source-denied arm (#4289).
func TestCommunityGate_DenialLogsNoSecretEitherVersion(t *testing.T) {
	clients := []config.SNMPClient{{Prefix: "10.0.0.0/24"}}
	for _, v := range gateVersions {
		a := gateAgent(clients)

		const unknownSecret = "s3cr3t-unknown-16180"
		out := captureDebugLog(t, func() {
			pkt := gatePacket(v, unknownSecret, 16184)
			if resp := a.handlePacketFrom(pkt, net.ParseIP("198.51.100.7")); resp != nil {
				t.Fatalf("%s: unknown-community GET was answered", v)
			}
		})
		if !strings.Contains(out, "SNMP: invalid community") || !strings.Contains(out, "known_community=false") {
			t.Fatalf("%s: unknown-community log missing expected line/flag: %q", v, out)
		}
		if strings.Contains(out, unknownSecret) {
			t.Fatalf("%s: unknown-community log LEAKED the secret: %q", v, out)
		}
		if !strings.Contains(out, "198.51.100.7") {
			t.Fatalf("%s: unknown-community log should record the source; got: %q", v, out)
		}

		const deniedSecret = "scoped"
		out = captureDebugLog(t, func() {
			pkt := gatePacket(v, deniedSecret, 16185)
			if resp := a.handlePacketFrom(pkt, net.ParseIP("192.0.2.5")); resp != nil {
				t.Fatalf("%s: source-denied GET was answered", v)
			}
		})
		if !strings.Contains(out, "SNMP: source not permitted for community") || !strings.Contains(out, "known_community=true") {
			t.Fatalf("%s: source-denied log missing expected line/flag: %q", v, out)
		}
		if strings.Contains(out, deniedSecret) {
			t.Fatalf("%s: source-denied log LEAKED the community name: %q", v, out)
		}
		if !strings.Contains(out, "192.0.2.5") {
			t.Fatalf("%s: source-denied log should record the source; got: %q", v, out)
		}
	}
}

// v3 traffic is unaffected by the gate: a v3 request arrives through the
// version-3 dispatch (USM, no community) and is still served/denied by the
// USM rules. Here a properly authenticated v3 GET through handlePacketFrom
// — the same entry the v1/v2c gate hangs off — must be answered.
func TestCommunityGate_V3Unaffected(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	pkt := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, 5, 1000)
	a.lastPacket = pkt
	if resp := a.handlePacketFrom(pkt, net.ParseIP("192.0.2.5")); resp == nil {
		t.Fatal("authenticated v3 GET through handlePacketFrom was dropped; v3 must not pass through the community gate")
	}
}
