package userspace

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestBuildInjectPacketRequestEmitOnWireCarriesTuple(t *testing.T) {
	req, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip":   "172.16.80.200",
		"emit-on-wire":     "true",
		"source-ip":        "172.16.80.8",
		"source-port":      "4660",
		"destination-port": "0",
		"protocol":         "icmp",
	}, ProcessStatus{
		LastSnapshotGeneration:           11,
		LastFIBGeneration:                12,
		InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion,
	})
	if err != nil {
		t.Fatalf("BuildInjectPacketRequest: %v", err)
	}
	if req.TupleMetadataVersion != InjectPacketTupleProtocolVersion {
		t.Fatalf("TupleMetadataVersion = %d, want %d", req.TupleMetadataVersion, InjectPacketTupleProtocolVersion)
	}
	if req.AddrFamily != uint8(syscall.AF_INET) {
		t.Fatalf("AddrFamily = %d, want AF_INET", req.AddrFamily)
	}
	if req.Protocol != 1 {
		t.Fatalf("Protocol = %d, want ICMP", req.Protocol)
	}
	if req.SourceIP != "172.16.80.8" || req.DestinationIP != "172.16.80.200" {
		t.Fatalf("tuple IPs = %s -> %s", req.SourceIP, req.DestinationIP)
	}
	if req.SourcePort == nil || *req.SourcePort != 4660 {
		t.Fatalf("SourcePort = %v, want 4660", req.SourcePort)
	}
	if req.DestinationPort == nil || *req.DestinationPort != 0 {
		t.Fatalf("DestinationPort = %v, want 0", req.DestinationPort)
	}
}

func TestBuildInjectPacketRequestEmitOnWireFailsClosedWithoutHelperTupleProtocol(t *testing.T) {
	_, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip": "172.16.80.200",
		"emit-on-wire":   "true",
		"source-ip":      "172.16.80.8",
	}, ProcessStatus{})
	if err == nil {
		t.Fatal("BuildInjectPacketRequest succeeded without helper tuple protocol")
	}
	if !strings.Contains(err.Error(), "helper inject tuple protocol version") {
		t.Fatalf("error = %v, want tuple protocol failure", err)
	}
}

func TestBuildInjectPacketRequestEmitOnWireRequiresSourceIP(t *testing.T) {
	_, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip": "172.16.80.200",
		"emit-on-wire":   "true",
	}, ProcessStatus{InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion})
	if err == nil {
		t.Fatal("BuildInjectPacketRequest succeeded without source-ip")
	}
	if !strings.Contains(err.Error(), "requires source-ip") {
		t.Fatalf("error = %v, want source-ip failure", err)
	}
}

func TestBuildInjectPacketRequestEmitOnWireRejectsUnsupportedProtocol(t *testing.T) {
	_, err := BuildInjectPacketRequest(7, "valid", map[string]string{
		"destination-ip": "172.16.80.200",
		"emit-on-wire":   "true",
		"source-ip":      "172.16.80.8",
		"protocol":       "tcp",
	}, ProcessStatus{InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion})
	if err == nil {
		t.Fatal("BuildInjectPacketRequest succeeded with tcp protocol")
	}
	if !strings.Contains(err.Error(), "invalid protocol") {
		t.Fatalf("error = %v, want invalid protocol failure", err)
	}
}

func TestInjectPacketEmitOnWireFailsClosedBeforeHelperIPCWithoutTupleProtocol(t *testing.T) {
	port := uint16(7)
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.inner = nil
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = "/tmp/xpf-test-inject-packet-must-not-dial.sock"
	m.lastStatus = ProcessStatus{}

	_, err = m.InjectPacket(InjectPacketRequest{
		Slot:                 7,
		PacketLength:         128,
		AddrFamily:           uint8(syscall.AF_INET),
		Protocol:             1,
		MetadataValid:        true,
		DestinationIP:        "172.16.80.200",
		EmitOnWire:           true,
		TupleMetadataVersion: InjectPacketTupleProtocolVersion,
		SourceIP:             "172.16.80.8",
		SourcePort:           &port,
		DestinationPort:      &port,
	})
	if err == nil {
		t.Fatal("InjectPacket succeeded without helper tuple protocol")
	}
	if !strings.Contains(err.Error(), "helper inject tuple protocol version") {
		t.Fatalf("error = %v, want helper tuple protocol failure", err)
	}
}

func TestInjectPacketEmitOnWireRejectsLegacyRemoteRequestMetadata(t *testing.T) {
	port := uint16(7)
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.inner = nil
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = "/tmp/xpf-test-inject-packet-must-not-dial.sock"
	m.lastStatus = ProcessStatus{
		InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion,
	}

	_, err = m.InjectPacket(InjectPacketRequest{
		Slot:            7,
		PacketLength:    128,
		AddrFamily:      uint8(syscall.AF_INET),
		Protocol:        1,
		MetadataValid:   true,
		DestinationIP:   "172.16.80.200",
		EmitOnWire:      true,
		SourceIP:        "172.16.80.8",
		SourcePort:      &port,
		DestinationPort: &port,
	})
	if err == nil {
		t.Fatal("InjectPacket succeeded with legacy remote emit-on-wire metadata")
	}
	if !strings.Contains(err.Error(), "request requires tuple metadata version") {
		t.Fatalf("error = %v, want request tuple metadata failure", err)
	}
}
