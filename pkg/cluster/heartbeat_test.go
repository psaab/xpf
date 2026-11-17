package cluster

import (
	"fmt"
	"testing"
)

func TestMarshalUnmarshalHeartbeat(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         42,
		SoftwareVersion:   "xpf-test-1",
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 1, Priority: 150, Weight: 100, State: uint8(StateSecondary)},
		},
	}

	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.NodeID != 1 {
		t.Errorf("NodeID = %d, want 1", got.NodeID)
	}
	if got.ClusterID != 42 {
		t.Errorf("ClusterID = %d, want 42", got.ClusterID)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(got.Groups))
	}
	if got.Groups[0].GroupID != 0 || got.Groups[0].Priority != 200 || got.Groups[0].Weight != 255 {
		t.Errorf("group 0 = %+v", got.Groups[0])
	}
	if got.Groups[0].State != uint8(StatePrimary) {
		t.Errorf("group 0 state = %d, want %d", got.Groups[0].State, StatePrimary)
	}
	if got.Groups[1].GroupID != 1 || got.Groups[1].Priority != 150 || got.Groups[1].Weight != 100 {
		t.Errorf("group 1 = %+v", got.Groups[1])
	}
	if got.Groups[1].State != uint8(StateSecondary) {
		t.Errorf("group 1 state = %d, want %d", got.Groups[1].State, StateSecondary)
	}
	if got.SoftwareVersion != "xpf-test-1" {
		t.Errorf("software version = %q, want xpf-test-1", got.SoftwareVersion)
	}
	if got.HAProtocolVersion != CurrentHAProtocolVersion {
		t.Errorf("ha protocol version = %d, want %d", got.HAProtocolVersion, CurrentHAProtocolVersion)
	}
}

func TestMarshalUnmarshalHeartbeat_NoGroups(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
	}
	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Groups) != 0 {
		t.Errorf("groups = %d, want 0", len(got.Groups))
	}
	if got.HAProtocolVersion != LegacyHAProtocolVersion {
		t.Errorf("ha protocol version = %d, want legacy %d", got.HAProtocolVersion, LegacyHAProtocolVersion)
	}
}

func TestUnmarshalHeartbeat_TooShort(t *testing.T) {
	_, err := UnmarshalHeartbeat([]byte{0x42, 0x50})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestUnmarshalHeartbeat_BadMagic(t *testing.T) {
	data := make([]byte, heartbeatHeaderSize)
	copy(data[0:4], "DEAD")
	data[4] = heartbeatVersion
	_, err := UnmarshalHeartbeat(data)
	if err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestUnmarshalHeartbeat_BadVersion(t *testing.T) {
	data := make([]byte, heartbeatHeaderSize)
	copy(data[0:4], heartbeatMagic)
	data[4] = 99 // bad version
	_, err := UnmarshalHeartbeat(data)
	if err == nil {
		t.Error("expected error for bad version")
	}
}

func TestUnmarshalHeartbeat_Truncated(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: 1},
		},
	}
	data := MarshalHeartbeat(pkt)
	// Truncate the group data.
	_, err := UnmarshalHeartbeat(data[:heartbeatHeaderSize+2])
	if err == nil {
		t.Error("expected error for truncated group data")
	}
}

func TestMarshalHeartbeat_Size(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: 1},
			{GroupID: 1, Priority: 100, Weight: 200, State: 0},
		},
	}
	data := MarshalHeartbeat(pkt)
	expected := heartbeatHeaderSize + 2*heartbeatGroupSize + 1 + 1 + 2 // +1 NumMonitors, +1 version length, +2 HA protocol version
	if len(data) != expected {
		t.Errorf("size = %d, want %d", len(data), expected)
	}
}

func TestHandlePeerHeartbeat(t *testing.T) {
	m := NewManager(0, 1)
	m.SetSoftwareVersion("local-test")
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)
	// Drain initial election event.
	recvEvent19161(t, m.Events(), "the next event")

	// Simulate peer heartbeat.
	pkt := &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         1,
		SoftwareVersion:   "peer-test",
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.PeerAlive() {
		t.Error("peer should be alive after heartbeat")
	}
	if m.PeerNodeID() != 1 {
		t.Errorf("peer node ID = %d, want 1", m.PeerNodeID())
	}

	peerGroups := m.PeerGroupStates()
	if pg, ok := peerGroups[0]; !ok {
		t.Error("peer group 0 not found")
	} else if pg.Priority != 100 {
		t.Errorf("peer group 0 priority = %d, want 100", pg.Priority)
	}
	if mismatch, local, peer := m.HAProtocolVersionMismatch(); mismatch || local != CurrentHAProtocolVersion || peer != CurrentHAProtocolVersion {
		t.Fatalf("ha protocol mismatch = %v local=%d peer=%d, want false/%d/%d", mismatch, local, peer, CurrentHAProtocolVersion, CurrentHAProtocolVersion)
	}
}

func TestHandlePeerTimeout(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	// First set peer alive.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.PeerAlive() {
		t.Fatal("peer should be alive")
	}

	// Simulate timeout.
	m.handlePeerTimeout()

	if m.PeerAlive() {
		t.Error("peer should not be alive after timeout")
	}
	peerGroups := m.PeerGroupStates()
	if len(peerGroups) != 0 {
		t.Errorf("peer groups should be cleared, got %d", len(peerGroups))
	}
}

func TestMarshalUnmarshalHeartbeat_WithMonitors(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 1, Weight: 255, Up: true, Interface: "ge-0/0/0"},
			{RGID: 1, Weight: 255, Up: false, Interface: "ge-0/0/1"},
			{RGID: 2, Weight: 128, Up: true, Interface: "ge-0/0/2"},
		},
	}

	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(got.Groups))
	}
	if len(got.Monitors) != 3 {
		t.Fatalf("monitors = %d, want 3", len(got.Monitors))
	}

	// Check first monitor.
	if got.Monitors[0].RGID != 1 || got.Monitors[0].Weight != 255 || !got.Monitors[0].Up || got.Monitors[0].Interface != "ge-0/0/0" {
		t.Errorf("monitor 0 = %+v", got.Monitors[0])
	}
	// Check second monitor (down).
	if got.Monitors[1].Up {
		t.Error("monitor 1 should be down")
	}
	if got.Monitors[1].Interface != "ge-0/0/1" {
		t.Errorf("monitor 1 interface = %q, want ge-0/0/1", got.Monitors[1].Interface)
	}
	// Check third monitor.
	if got.Monitors[2].RGID != 2 || got.Monitors[2].Weight != 128 {
		t.Errorf("monitor 2 = %+v", got.Monitors[2])
	}
}

func TestMarshalUnmarshalHeartbeat_NoMonitors_BackwardsCompat(t *testing.T) {
	// Simulate an old-format packet (no monitor section) — manually build.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 5,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 200, State: uint8(StateSecondary)},
		},
	}
	// Marshal will include empty monitor section (NumMonitors=0).
	data := MarshalHeartbeat(pkt)
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Monitors) != 0 {
		t.Errorf("monitors = %d, want 0", len(got.Monitors))
	}

	// Also test with truly old-format data (no monitor bytes at all).
	oldSize := heartbeatHeaderSize + 1*heartbeatGroupSize
	oldData := data[:oldSize]
	got2, err := UnmarshalHeartbeat(oldData)
	if err != nil {
		t.Fatalf("unmarshal old format: %v", err)
	}
	if len(got2.Monitors) != 0 {
		t.Errorf("monitors from old format = %d, want 0", len(got2.Monitors))
	}
	if len(got2.Groups) != 1 {
		t.Errorf("groups from old format = %d, want 1", len(got2.Groups))
	}
	if got2.SoftwareVersion != "" {
		t.Errorf("software version from old format = %q, want empty", got2.SoftwareVersion)
	}
	if got2.HAProtocolVersion != LegacyHAProtocolVersion {
		t.Errorf("ha protocol version from old format = %d, want %d", got2.HAProtocolVersion, LegacyHAProtocolVersion)
	}
}

func TestUnmarshalHeartbeat_TruncatedMonitor(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:          0,
		ClusterID:       1,
		SoftwareVersion: "peer-build",
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 1, Weight: 255, Up: true, Interface: "ge-0/0/0"},
			{RGID: 1, Weight: 128, Up: false, Interface: "ge-0/0/1"},
		},
	}
	data := MarshalHeartbeat(pkt)

	// Truncate in the middle of the second monitor entry — first monitor
	// and RG state should still be returned without error.
	// The full first monitor ends at: header(9) + 1*group(5) + numMon(1) + mon0(4+8) = 27.
	// Truncate at 29 so the second monitor header is partially there.
	truncAt := heartbeatHeaderSize + 1*heartbeatGroupSize + 1 + (4 + len("ge-0/0/0")) + 2
	got, err := UnmarshalHeartbeat(data[:truncAt])
	if err != nil {
		t.Fatalf("unexpected error for truncated monitor: %v", err)
	}
	if len(got.Groups) != 1 {
		t.Errorf("groups = %d, want 1", len(got.Groups))
	}
	if got.Groups[0].Priority != 200 {
		t.Errorf("group 0 priority = %d, want 200", got.Groups[0].Priority)
	}
	if len(got.Monitors) != 1 {
		t.Errorf("monitors = %d, want 1 (second was truncated)", len(got.Monitors))
	}
	if len(got.Monitors) > 0 && got.Monitors[0].Interface != "ge-0/0/0" {
		t.Errorf("monitor 0 interface = %q, want ge-0/0/0", got.Monitors[0].Interface)
	}
	if got.SoftwareVersion != "" {
		t.Errorf("software version = %q, want empty after truncated monitor section", got.SoftwareVersion)
	}
}

func TestUnmarshalHeartbeat_TruncatedMonitorName(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Monitors: []HeartbeatMonitor{
			{RGID: 1, Weight: 255, Up: true, Interface: "ge-0/0/0"},
		},
	}
	data := MarshalHeartbeat(pkt)
	// Truncate inside the name — should return 0 monitors, no error.
	truncAt := heartbeatHeaderSize + 1 + 4 + 2 // header + numMon + monHeader + partialName
	got, err := UnmarshalHeartbeat(data[:truncAt])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Monitors) != 0 {
		t.Errorf("monitors = %d, want 0 (name was truncated)", len(got.Monitors))
	}
}

func TestMarshalHeartbeat_LargeMonitorPayload_RGPreserved(t *testing.T) {
	// Build a packet with many monitors that would exceed the old 512-byte
	// limit. RG group state must always be preserved.
	pkt := &HeartbeatPacket{
		NodeID:          0,
		ClusterID:       1,
		SoftwareVersion: "peer-build",
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 1, Priority: 150, Weight: 100, State: uint8(StateSecondary)},
		},
	}
	// Each monitor with a 20-char interface name takes 4+20 = 24 bytes.
	// 80 monitors × 24 bytes = 1920 bytes just for monitors (+ header, groups, numMon).
	// This exceeds maxHeartbeatSize (1472) and forces truncation.
	for i := 0; i < 80; i++ {
		name := fmt.Sprintf("ge-0/0/%02d-longname__", i)
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID: 0, Weight: 255, Up: true, Interface: name,
		})
	}

	data := MarshalHeartbeat(pkt)
	if len(data) > maxHeartbeatSize {
		t.Fatalf("marshal produced %d bytes, exceeds maxHeartbeatSize %d", len(data), maxHeartbeatSize)
	}
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SoftwareVersion != "peer-build" {
		t.Fatalf("software version = %q, want peer-build", got.SoftwareVersion)
	}
	if got.HAProtocolVersion != LegacyHAProtocolVersion {
		t.Fatalf("ha protocol version = %d, want %d", got.HAProtocolVersion, LegacyHAProtocolVersion)
	}

	// RG groups must be intact.
	if len(got.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(got.Groups))
	}
	if got.Groups[0].Priority != 200 {
		t.Errorf("group 0 priority = %d, want 200", got.Groups[0].Priority)
	}
	if got.Groups[1].Priority != 150 {
		t.Errorf("group 1 priority = %d, want 150", got.Groups[1].Priority)
	}

	// Some monitors should be present (but fewer than 80 due to truncation).
	if len(got.Monitors) == 0 {
		t.Error("expected at least some monitors")
	}
	if len(got.Monitors) >= 80 {
		t.Errorf("expected monitors to be truncated, got all %d", len(got.Monitors))
	}
	t.Logf("fit %d/%d monitors in %d bytes", len(got.Monitors), 80, len(data))
}

func TestMarshalHeartbeat_CapsAtMaxSize(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	// Add enough monitors to blow past the limit.
	for i := 0; i < 200; i++ {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID: 0, Weight: 255, Up: true, Interface: fmt.Sprintf("interface-%d", i),
		})
	}
	data := MarshalHeartbeat(pkt)
	if len(data) > maxHeartbeatSize {
		t.Errorf("marshal output %d bytes exceeds cap %d", len(data), maxHeartbeatSize)
	}
}

func TestPeerMonitorStatuses(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	// No peer monitors initially.
	if pm := m.PeerMonitorStatuses(); pm != nil {
		t.Errorf("expected nil peer monitors, got %d", len(pm))
	}

	// Simulate peer heartbeat with monitors.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
		Monitors: []HeartbeatMonitor{
			{RGID: 0, Weight: 255, Up: true, Interface: "ge-7/0/0"},
			{RGID: 0, Weight: 255, Up: false, Interface: "ge-7/0/1"},
		},
	}
	m.handlePeerHeartbeat(pkt)

	pm := m.PeerMonitorStatuses()
	if len(pm) != 2 {
		t.Fatalf("peer monitors = %d, want 2", len(pm))
	}
	if pm[0].Interface != "ge-7/0/0" || !pm[0].Up {
		t.Errorf("peer monitor 0 = %+v", pm[0])
	}
	if pm[1].Interface != "ge-7/0/1" || pm[1].Up {
		t.Errorf("peer monitor 1 = %+v", pm[1])
	}

	// After timeout, peer monitors should be cleared.
	m.handlePeerTimeout()
	if pm := m.PeerMonitorStatuses(); pm != nil {
		t.Errorf("expected nil after timeout, got %d", len(pm))
	}
}

func TestBuildHeartbeat(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, true, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)

	pkt := m.buildHeartbeat()
	if pkt.NodeID != 0 {
		t.Errorf("NodeID = %d, want 0", pkt.NodeID)
	}
	if pkt.ClusterID != 1 {
		t.Errorf("ClusterID = %d, want 1", pkt.ClusterID)
	}
	if pkt.HAProtocolVersion != CurrentHAProtocolVersion {
		t.Errorf("HAProtocolVersion = %d, want %d", pkt.HAProtocolVersion, CurrentHAProtocolVersion)
	}
	if len(pkt.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(pkt.Groups))
	}
}

func TestHandlePeerHeartbeat_LegacyHeartbeatDefaultsProtocolCompatibility(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100, 1: 200}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})

	mismatch, local, peer := m.HAProtocolVersionMismatch()
	if local != CurrentHAProtocolVersion {
		t.Fatalf("local ha protocol version = %d, want %d", local, CurrentHAProtocolVersion)
	}
	if peer != LegacyHAProtocolVersion {
		t.Fatalf("peer ha protocol version = %d, want %d", peer, LegacyHAProtocolVersion)
	}
	wantMismatch := CurrentHAProtocolVersion != LegacyHAProtocolVersion
	if mismatch != wantMismatch {
		t.Fatalf("ha protocol mismatch = %v, want %v (local=%d peer=%d)", mismatch, wantMismatch, local, peer)
	}
}

func TestUnmarshalHeartbeat_TruncatedVersionTrailerDoesNotParseHAProtocol(t *testing.T) {
	pkt := &HeartbeatPacket{
		NodeID:            1,
		ClusterID:         5,
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 200, State: uint8(StateSecondary)},
		},
	}
	data := MarshalHeartbeat(pkt)

	// Remove the last HA protocol byte so the version trailer is incomplete.
	got, err := UnmarshalHeartbeat(data[:len(data)-1])
	if err != nil {
		t.Fatalf("unmarshal truncated trailer: %v", err)
	}
	if got.SoftwareVersion != "" {
		t.Fatalf("software version = %q, want empty", got.SoftwareVersion)
	}
	if got.HAProtocolVersion != LegacyHAProtocolVersion {
		t.Fatalf("ha protocol version = %d, want legacy default %d", got.HAProtocolVersion, LegacyHAProtocolVersion)
	}
}
