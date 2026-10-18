package cluster

import (
	"strings"
	"testing"
)

// #14704 (gemini D14-02): marshalHeartbeatBody wrote a monitor's NameLen as
// uint8(len(nameBytes)) and the monitor count as uint8(numMon) with no
// <=255 guard, while groups (maxHeartbeatGroups, #4434) and the software
// version (maxHeartbeatSoftwareVersionSize) were clamped in the same
// function. A name longer than 255 bytes wrapped its length byte
// (260 -> 4) and more than 255 monitors wrapped the count byte
// (260 -> 4). The receiver trusts both bytes, so it parsed monitor payload
// as the version trailer and never reached the "XPFE" echo trailer:
// SoftwareVersion / HAProtocolVersion were poisoned and the echoed
// heartbeat session/sequence were lost, silently degrading echo-lease
// freshness in handlePeerHeartbeat.
//
// FAIL-ON-REVERT: drop the monitor name/count caps in marshalHeartbeatBody
// and the oversize-name cell decodes a 4-byte "aaaa" monitor with garbage
// version and no echo, while the oversize-count cell decodes 4 monitors
// instead of 255.

func heartbeat14704Packet(monitors []HeartbeatMonitor) *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:                1,
		ClusterID:             42,
		Groups:                []HeartbeatGroup{{GroupID: 1, Priority: 200, Weight: 255, State: 1}},
		Monitors:              monitors,
		SoftwareVersion:       "25.4R1.9",
		HAProtocolVersion:     CurrentHAProtocolVersion,
		HeartbeatSession:      0x1111222233334444,
		HeartbeatSequence:     77,
		PeerHeartbeatSession:  0x5555666677778888,
		PeerHeartbeatSequence: 88,
	}
}

func assert14704TrailerIntact(t *testing.T, got *HeartbeatPacket, wantMonitors int) {
	t.Helper()
	if len(got.Monitors) != wantMonitors {
		t.Fatalf("decoded %d monitors, want %d: %+v", len(got.Monitors), wantMonitors, got.Monitors)
	}
	if got.SoftwareVersion != "25.4R1.9" {
		t.Errorf("SoftwareVersion = %q, want %q (version trailer desynced by monitor section)", got.SoftwareVersion, "25.4R1.9")
	}
	if got.HAProtocolVersion != CurrentHAProtocolVersion {
		t.Errorf("HAProtocolVersion = %d, want %d", got.HAProtocolVersion, CurrentHAProtocolVersion)
	}
	if got.HeartbeatSession != 0x1111222233334444 || got.HeartbeatSequence != 77 {
		t.Errorf("echo trailer lost: session=%#x sequence=%d, want 0x1111222233334444/77",
			got.HeartbeatSession, got.HeartbeatSequence)
	}
	if got.PeerHeartbeatSession != 0x5555666677778888 || got.PeerHeartbeatSequence != 88 {
		t.Errorf("echo trailer lost: peer session=%#x peer sequence=%d, want 0x5555666677778888/88",
			got.PeerHeartbeatSession, got.PeerHeartbeatSequence)
	}
	// Groups are parsed before monitors and must survive regardless.
	if len(got.Groups) != 1 || got.Groups[0].GroupID != 1 {
		t.Errorf("groups desynced: %+v", got.Groups)
	}
}

func TestMarshalHeartbeatOversizeMonitorNameSkipped_14704(t *testing.T) {
	oversize := strings.Repeat("a", 260)
	pkt := heartbeat14704Packet([]HeartbeatMonitor{
		{RGID: 1, Weight: 255, Up: true, Interface: oversize},
		{RGID: 1, Weight: 128, Up: true, Interface: "ge-0/0/0"},
	})
	data := MarshalHeartbeat(pkt)
	if len(data) > maxHeartbeatSize {
		t.Fatalf("marshal produced %d bytes, exceeds %d", len(data), maxHeartbeatSize)
	}
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat failed: %v", err)
	}
	// The oversize monitor must be omitted entirely — never written with a
	// wrapped (260 -> 4) NameLen — and the following monitor must survive.
	assert14704TrailerIntact(t, got, 1)
	if got.Monitors[0].Interface != "ge-0/0/0" {
		t.Errorf("monitor 0 interface = %q (len %d), want %q; oversize name was truncated/wrapped onto the wire",
			got.Monitors[0].Interface, len(got.Monitors[0].Interface), "ge-0/0/0")
	}
}

func TestMarshalHeartbeatOversizeMonitorNameAlone_14704(t *testing.T) {
	// Exactly 256 bytes is the NameLen wrap boundary (uint8(256) == 0).
	pkt := heartbeat14704Packet([]HeartbeatMonitor{
		{RGID: 1, Weight: 255, Up: true, Interface: strings.Repeat("b", 256)},
	})
	got, err := UnmarshalHeartbeat(MarshalHeartbeat(pkt))
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat failed: %v", err)
	}
	assert14704TrailerIntact(t, got, 0)
}

func TestMarshalHeartbeatMonitorCountCapped_14704(t *testing.T) {
	monitors := make([]HeartbeatMonitor, 260)
	for i := range monitors {
		monitors[i] = HeartbeatMonitor{RGID: 1, Weight: 10, Up: true, Interface: "x"}
	}
	pkt := heartbeat14704Packet(monitors)
	data := MarshalHeartbeat(pkt)
	// NumMonitors byte follows header + 1 group entry.
	monCountOff := heartbeatHeaderSize + heartbeatGroupSize
	if data[monCountOff] != 255 {
		t.Fatalf("NumMonitors byte = %d, want capped 255 (260 must not wrap to 4)", data[monCountOff])
	}
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat failed: %v", err)
	}
	assert14704TrailerIntact(t, got, 255)
}

func TestMarshalHeartbeatMonitorWireLimitsBoundary_14704(t *testing.T) {
	// Controls: exactly at the uint8 limits must round-trip verbatim.
	name255 := strings.Repeat("n", 255)
	pkt := heartbeat14704Packet([]HeartbeatMonitor{
		{RGID: 1, Weight: 255, Up: true, Interface: name255},
	})
	got, err := UnmarshalHeartbeat(MarshalHeartbeat(pkt))
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat (255-byte name) failed: %v", err)
	}
	assert14704TrailerIntact(t, got, 1)
	if got.Monitors[0].Interface != name255 {
		t.Errorf("255-byte name round-tripped as %d bytes, want 255", len(got.Monitors[0].Interface))
	}

	monitors := make([]HeartbeatMonitor, 255)
	for i := range monitors {
		monitors[i] = HeartbeatMonitor{RGID: 1, Weight: 10, Up: i%2 == 0, Interface: "x"}
	}
	got, err = UnmarshalHeartbeat(MarshalHeartbeat(heartbeat14704Packet(monitors)))
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat (255 monitors) failed: %v", err)
	}
	assert14704TrailerIntact(t, got, 255)
}
