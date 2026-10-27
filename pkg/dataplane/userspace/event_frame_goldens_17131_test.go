package userspace

// #17131: cross-language golden frames produced by the real Rust encoders
// (userspace-dp/src/event_stream/codec/goldens.rs, regenerated with
// XPF_WRITE_GOLDEN=1). Each file under testdata/event_frames/ is one full
// event-stream frame (16-byte header + payload). This test decodes each
// specimen through the production decoders and asserts the non-default
// specimen values, so moving any one offset in the Rust encoders (with the
// Rust pins updated) reds this test instead of silently mislabelling
// syslog/NetFlow fields.
//
// The pre-existing #9412 golden (testdata/session_update_frame_9412.hex)
// keeps its own pin in session_update_frame_9412_test.go.

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

func readGoldenFrame17131(t *testing.T, name string) (frame []byte, payload []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "event_frames", name+".hex"))
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with XPF_WRITE_GOLDEN=1 in the Rust golden test)", name, err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("golden %s is not hex: %v", name, err)
	}
	if len(b) < EventFrameHeaderSize {
		t.Fatalf("golden %s too short: %d bytes", name, len(b))
	}
	if n := binary.LittleEndian.Uint32(b[0:4]); int(n) != len(b)-EventFrameHeaderSize {
		t.Fatalf("golden %s payload length %d does not match %d bytes after header", name, n, len(b)-EventFrameHeaderSize)
	}
	return b, b[EventFrameHeaderSize:]
}

func TestEventFrameGoldensDecode17131(t *testing.T) {
	t.Run("session_update", func(t *testing.T) {
		frame, payload := readGoldenFrame17131(t, "session_update")
		if frame[4] != EventTypeSessionUpdate {
			t.Fatalf("frame type = %d, want SessionUpdate (%d)", frame[4], EventTypeSessionUpdate)
		}
		if seq := binary.LittleEndian.Uint64(frame[8:16]); seq != 1713101 {
			t.Fatalf("header seq = %d, want 1713101", seq)
		}
		d, ok := decodeSessionEvent(payload)
		if !ok {
			t.Fatal("decodeSessionEvent rejected golden session_update")
		}
		if d.AddrFamily != 2 || d.Protocol != 6 || d.SrcPort != 12345 || d.DstPort != 80 {
			t.Fatalf("tuple = af %d proto %d %d->%d, want 2/6 12345->80", d.AddrFamily, d.Protocol, d.SrcPort, d.DstPort)
		}
		if got := [4]byte(d.SrcAddr[:4]); got != [4]byte{10, 0, 1, 100} {
			t.Fatalf("SrcAddr = %v, want 10.0.1.100", got)
		}
		if got := [4]byte(d.DstAddr[:4]); got != [4]byte{10, 0, 2, 200} {
			t.Fatalf("DstAddr = %v, want 10.0.2.200", got)
		}
		if got := [4]byte(d.NATSrcAddr[:4]); got != [4]byte{10, 0, 2, 10} {
			t.Fatalf("NATSrcAddr = %v, want 10.0.2.10", got)
		}
		if got := [4]byte(d.NATDstAddr[:4]); got != [4]byte{10, 0, 2, 20} {
			t.Fatalf("NATDstAddr = %v, want 10.0.2.20", got)
		}
		if d.NATSrcPort != 40000 || d.NATDstPort != 40001 {
			t.Fatalf("NAT ports = %d/%d, want 40000/40001", d.NATSrcPort, d.NATDstPort)
		}
		if d.OwnerRGID != 40002 || d.EgressIfindex != 70003 || d.TXIfindex != 70004 {
			t.Fatalf("identity ints = rg %d egress %d tx %d, want 40002/70003/70004", d.OwnerRGID, d.EgressIfindex, d.TXIfindex)
		}
		if d.TunnelEndpointID != 513 || d.TXVLANID != 4094 {
			t.Fatalf("tunnel/vlan = %d/%d, want 513/4094", d.TunnelEndpointID, d.TXVLANID)
		}
		if !d.FabricRedirect || !d.FabricIngress || !d.LogSessionInit || !d.LogSessionClose {
			t.Fatalf("flags fabricRedirect=%v fabricIngress=%v logInit=%v logClose=%v, want all true (is_reverse has no Go decode leg)",
				d.FabricRedirect, d.FabricIngress, d.LogSessionInit, d.LogSessionClose)
		}
		if d.IngressZoneID != 301 || d.EgressZoneID != 1001 {
			t.Fatalf("zones = %d/%d, want 301/1001", d.IngressZoneID, d.EgressZoneID)
		}
		if d.PolicyID != 777001 || d.PolicyCounterIdx != 888002 || d.AppTimeout != 90 {
			t.Fatalf("policy = id %d counter %d timeout %d, want 777001/888002/90", d.PolicyID, d.PolicyCounterIdx, d.AppTimeout)
		}
		if d.RTFlowSessionID != 0x5EED1713 {
			t.Fatalf("RTFlowSessionID = %#x, want 0x5eed1713", d.RTFlowSessionID)
		}
		if d.TunnelDiscriminator != (uint64(1)<<32 | 0x0BADF00D) {
			t.Fatalf("TunnelDiscriminator = %#x, want Keyed(0x0badf00d) wire tag", d.TunnelDiscriminator)
		}
		if d.RoutingDomain != 77 {
			t.Fatalf("RoutingDomain = %d, want 77", d.RoutingDomain)
		}
		if d.TCPCloseClass != 2 {
			t.Fatalf("TCPCloseClass = %d, want 2", d.TCPCloseClass)
		}
		if d.InstallTableDomain != 525590 || d.InstallTableCheck != 3318534811 {
			t.Fatalf("install table = (%d,%d), want (525590,3318534811)", d.InstallTableDomain, d.InstallTableCheck)
		}
		if !d.SourceNatICMPValid || d.SourceNatICMPType != 13 || d.SourceNatICMPCode != 7 {
			t.Fatalf("SourceNatICMP = valid %v %d/%d, want true 13/7", d.SourceNatICMPValid, d.SourceNatICMPType, d.SourceNatICMPCode)
		}
		if d.IngressIfindex != 424242 || d.IngressVLANID != 2345 {
			t.Fatalf("ingress identity = %d vlan %d, want 424242/2345", d.IngressIfindex, d.IngressVLANID)
		}
		if d.PolicyRuleID != "golden-rule-17131" {
			t.Fatalf("PolicyRuleID = %q, want golden-rule-17131", d.PolicyRuleID)
		}
		if d.TCPHandshakeState != 3 {
			t.Fatalf("TCPHandshakeState = %d, want 3", d.TCPHandshakeState)
		}
		if d.SourceNatProvenance != 2 {
			t.Fatalf("SourceNatProvenance = %d, want 2 (static)", d.SourceNatProvenance)
		}
		if d.PptpCallIDs != 0x1122334455667788 {
			t.Fatalf("PptpCallIDs = %#x, want 0x1122334455667788", d.PptpCallIDs)
		}
		if d.NatScopeIfindex != -12345 {
			t.Fatalf("NatScopeIfindex = %d, want -12345", d.NatScopeIfindex)
		}
		if d.FwdPackets != 111111 || d.RevPackets != 222222 {
			t.Fatalf("packets = fwd %d rev %d, want 111111/222222", d.FwdPackets, d.RevPackets)
		}
		if d.NeighborMACBin != [6]byte{0xaa, 0x17, 0x13, 0x31, 0x00, 0x01} || d.SrcMACBin != [6]byte{0x11, 0x17, 0x13, 0x31, 0x00, 0x02} {
			t.Fatalf("MACs = neighbor %v src %v", d.NeighborMACBin, d.SrcMACBin)
		}
	})

	t.Run("session_close_v4", func(t *testing.T) {
		frame, payload := readGoldenFrame17131(t, "session_close_v4")
		if frame[4] != EventTypeSessionClose {
			t.Fatalf("frame type = %d, want SessionClose (%d)", frame[4], EventTypeSessionClose)
		}
		d, ok := decodeSessionCloseEvent(payload)
		if !ok {
			t.Fatal("decodeSessionCloseEvent rejected golden session_close_v4")
		}
		if d.AddrFamily != 2 || d.Protocol != 6 || d.SrcPort != 23456 || d.DstPort != 443 {
			t.Fatalf("tuple = af %d proto %d %d->%d, want 2/6 23456->443", d.AddrFamily, d.Protocol, d.SrcPort, d.DstPort)
		}
		if got := [4]byte(d.SrcAddr[:4]); got != [4]byte{10, 7, 7, 7} {
			t.Fatalf("SrcAddr = %v, want 10.7.7.7", got)
		}
		if got := [4]byte(d.DstAddr[:4]); got != [4]byte{172, 31, 7, 7} {
			t.Fatalf("DstAddr = %v, want 172.31.7.7", got)
		}
		if d.OwnerRGID != 40001 {
			t.Fatalf("OwnerRGID = %d, want 40001", d.OwnerRGID)
		}
		if !d.FabricRedirect || !d.FabricIngress {
			t.Fatalf("flags fabricRedirect=%v fabricIngress=%v, want both true", d.FabricRedirect, d.FabricIngress)
		}
		if d.IngressZoneID != 301 || d.EgressZoneID != 1001 {
			t.Fatalf("zones = %d/%d, want 301/1001", d.IngressZoneID, d.EgressZoneID)
		}
		if d.TunnelDiscriminator != (uint64(1)<<32 | 0x00C0FFEE) {
			t.Fatalf("TunnelDiscriminator = %#x, want Keyed(0x00c0ffee) wire tag", d.TunnelDiscriminator)
		}
		if d.RoutingDomain != 88 {
			t.Fatalf("RoutingDomain = %d, want 88", d.RoutingDomain)
		}
		if !d.PurgeRetirement {
			t.Fatal("PurgeRetirement = false, want true")
		}
		if d.IngressIfindex != 424243 || d.IngressVLANID != 2346 {
			t.Fatalf("ingress identity = %d vlan %d, want 424243/2346", d.IngressIfindex, d.IngressVLANID)
		}
	})

	t.Run("session_close_v6", func(t *testing.T) {
		frame, payload := readGoldenFrame17131(t, "session_close_v6")
		if frame[4] != EventTypeSessionClose {
			t.Fatalf("frame type = %d, want SessionClose (%d)", frame[4], EventTypeSessionClose)
		}
		d, ok := decodeSessionCloseEvent(payload)
		if !ok {
			t.Fatal("decodeSessionCloseEvent rejected golden session_close_v6")
		}
		if d.AddrFamily != 10 || d.Protocol != 17 || d.SrcPort != 5353 || d.DstPort != 53 {
			t.Fatalf("tuple = af %d proto %d %d->%d, want 10/17 5353->53", d.AddrFamily, d.Protocol, d.SrcPort, d.DstPort)
		}
		wantSrc := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x17, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		wantDst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x17, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		if d.SrcAddr != wantSrc || d.DstAddr != wantDst {
			t.Fatalf("addrs = src %v dst %v", d.SrcAddr, d.DstAddr)
		}
		if d.OwnerRGID != -7 {
			t.Fatalf("OwnerRGID = %d, want -7", d.OwnerRGID)
		}
		if d.FabricRedirect || !d.FabricIngress {
			t.Fatalf("flags fabricRedirect=%v fabricIngress=%v, want false/true", d.FabricRedirect, d.FabricIngress)
		}
		if d.IngressZoneID != 302 || d.EgressZoneID != 1002 {
			t.Fatalf("zones = %d/%d, want 302/1002", d.IngressZoneID, d.EgressZoneID)
		}
		if d.TunnelDiscriminator != 2 {
			t.Fatalf("TunnelDiscriminator = %d, want 2 (Unkeyed wire tag)", d.TunnelDiscriminator)
		}
		if d.RoutingDomain != 89 {
			t.Fatalf("RoutingDomain = %d, want 89", d.RoutingDomain)
		}
		if d.PurgeRetirement {
			t.Fatal("PurgeRetirement = true, want false")
		}
		if d.IngressIfindex != 70001 || d.IngressVLANID != 4094 {
			t.Fatalf("ingress identity = %d vlan %d, want 70001/4094", d.IngressIfindex, d.IngressVLANID)
		}
	})

	t.Run("rt_flow_close", func(t *testing.T) {
		frame, payload := readGoldenFrame17131(t, "rt_flow_close")
		if frame[4] != EventFrameTypeSessionClose {
			t.Fatalf("frame type = %d, want RT_FLOW SessionClose (%d)", frame[4], EventFrameTypeSessionClose)
		}
		rec, ok := decodeDataplaneEventPayload(payload)
		if !ok {
			t.Fatal("decodeDataplaneEventPayload rejected golden rt_flow_close")
		}
		assertRTFlowCloseGolden17131(t, rec)
	})

	t.Run("rt_flow_create", func(t *testing.T) {
		frame, payload := readGoldenFrame17131(t, "rt_flow_create")
		if frame[4] != EventFrameTypeSessionCreate {
			t.Fatalf("frame type = %d, want RT_FLOW SessionCreate (%d)", frame[4], EventFrameTypeSessionCreate)
		}
		rec, ok := decodeDataplaneEventPayload(payload)
		if !ok {
			t.Fatal("decodeDataplaneEventPayload rejected golden rt_flow_create")
		}
		if rec.Type != "SESSION_OPEN" {
			t.Fatalf("Type = %q, want SESSION_OPEN", rec.Type)
		}
		if rec.SrcAddr != "10.0.3.102:23456" || rec.DstAddr != "172.16.81.200:443" {
			t.Fatalf("addrs = %q -> %q", rec.SrcAddr, rec.DstAddr)
		}
		if rec.ProtocolNum != 6 || rec.Protocol != "TCP" {
			t.Fatalf("protocol = %d/%q, want 6/TCP", rec.ProtocolNum, rec.Protocol)
		}
		if rec.PolicyID != 42042 {
			t.Fatalf("PolicyID = %d, want 42042 ([44:48] on a create)", rec.PolicyID)
		}
		if rec.InZone != 303 || rec.OutZone != 1003 {
			t.Fatalf("zones = %d/%d, want 303/1003", rec.InZone, rec.OutZone)
		}
		if rec.NATSrcAddr != "172.16.81.8:40001" || rec.NATDstAddr != "203.0.113.100:9443" {
			t.Fatalf("NAT addrs = %q / %q", rec.NATSrcAddr, rec.NATDstAddr)
		}
		if rec.IngressIfindex != 77077 || rec.EgressIfindex != 88088 {
			t.Fatalf("ifindexes = ingress %d egress %d, want 77077/88088", rec.IngressIfindex, rec.EgressIfindex)
		}
		if rec.SessionID != 0x1122334455667788 {
			t.Fatalf("SessionID = %#x, want 0x1122334455667788", rec.SessionID)
		}
		if !rec.Time.Equal(time.Unix(0, 1700000123456789012)) {
			t.Fatalf("Time = %v, want admission instant 1700000123456789012ns", rec.Time)
		}
	})

	t.Run("dataplane_event", func(t *testing.T) {
		frame, payload := readGoldenFrame17131(t, "dataplane_event")
		if frame[4] != EventFrameTypePolicyDeny {
			t.Fatalf("frame type = %d, want PolicyDeny (%d)", frame[4], EventFrameTypePolicyDeny)
		}
		rec, ok := decodeDataplaneEventPayload(payload)
		if !ok {
			t.Fatal("decodeDataplaneEventPayload rejected golden dataplane_event")
		}
		if rec.Type != "POLICY_DENY" {
			t.Fatalf("Type = %q, want POLICY_DENY", rec.Type)
		}
		if rec.SrcAddr != "[2001:db8:1:2:3:4:5:6]:5353" || rec.DstAddr != "[2001:db8:6:5:4:3:2:1]:53" {
			t.Fatalf("addrs = %q -> %q", rec.SrcAddr, rec.DstAddr)
		}
		if rec.ProtocolNum != 17 || rec.Protocol != "UDP" {
			t.Fatalf("protocol = %d/%q, want 17/UDP", rec.ProtocolNum, rec.Protocol)
		}
		if rec.Action != "deny" {
			t.Fatalf("Action = %q, want deny", rec.Action)
		}
		if rec.PolicyID != 101101 || rec.RuleID != 101101 {
			t.Fatalf("PolicyID/RuleID = %d/%d, want 101101/101101 (stamped deny duplicates policy into rule)", rec.PolicyID, rec.RuleID)
		}
		if rec.OwnerRGID != -3 {
			t.Fatalf("OwnerRGID = %d, want -3", rec.OwnerRGID)
		}
		if rec.InZone != 301 || rec.OutZone != 1001 {
			t.Fatalf("zones = %d/%d, want 301/1001", rec.InZone, rec.OutZone)
		}
		if rec.IngressIfindex != 77077 {
			t.Fatalf("IngressIfindex = %d, want 77077", rec.IngressIfindex)
		}
		if !rec.Time.Equal(time.Unix(0, 1700000999000000000)) {
			t.Fatalf("Time = %v, want 1700000999000000000ns", rec.Time)
		}
		// Explicit uncovered-risk pins: DecodeRawEventRecord does not
		// surface Reason/AppID/Generation for a deny.
		_ = logging.EventRecord{}
	})
}

func assertRTFlowCloseGolden17131(t *testing.T, rec logging.EventRecord) {
	t.Helper()
	if rec.Type != "SESSION_CLOSE" {
		t.Fatalf("Type = %q, want SESSION_CLOSE", rec.Type)
	}
	if rec.SrcAddr != "10.0.1.102:12345" || rec.DstAddr != "172.16.80.200:443" {
		t.Fatalf("addrs = %q -> %q", rec.SrcAddr, rec.DstAddr)
	}
	if rec.ProtocolNum != 6 || rec.Protocol != "TCP" {
		t.Fatalf("protocol = %d/%q, want 6/TCP", rec.ProtocolNum, rec.Protocol)
	}
	if rec.Created != 1700000000 || rec.CreatedNanos != 123456789 {
		t.Fatalf("created = %d nanos %d, want 1700000000/123456789", rec.Created, rec.CreatedNanos)
	}
	if rec.PolicyID != 88088 {
		t.Fatalf("PolicyID = %d, want 88088 ([136:140] on a close)", rec.PolicyID)
	}
	if rec.InZone != 301 || rec.OutZone != 1001 {
		t.Fatalf("zones = %d/%d, want 301/1001", rec.InZone, rec.OutZone)
	}
	if rec.SessionPkts != 1111111 || rec.SessionBytes != 222333444 || rec.RevSessionPkts != 44444 || rec.RevSessionBytes != 55666777 {
		t.Fatalf("volume = fwd %d/%d rev %d/%d, want 1111111/222333444/44444/55666777",
			rec.SessionPkts, rec.SessionBytes, rec.RevSessionPkts, rec.RevSessionBytes)
	}
	if rec.NATSrcAddr != "172.16.80.8:40000" || rec.NATDstAddr != "203.0.113.99:8443" {
		t.Fatalf("NAT addrs = %q / %q", rec.NATSrcAddr, rec.NATDstAddr)
	}
	if rec.IngressIfindex != 42042 || rec.EgressIfindex != 9009 {
		t.Fatalf("ifindexes = ingress %d egress %d, want 42042/9009", rec.IngressIfindex, rec.EgressIfindex)
	}
	if rec.TOS != 0xB8 || rec.TCPControlBits != 0x13 {
		t.Fatalf("CoS = tos %#x tcp %#x, want 0xb8/0x13", rec.TOS, rec.TCPControlBits)
	}
	if rec.SessionID != 0xA1B2C3D4E5F60708 {
		t.Fatalf("SessionID = %#x, want 0xa1b2c3d4e5f60708", rec.SessionID)
	}
	if rec.CloseReason != "TCP RST" {
		t.Fatalf("CloseReason = %q, want TCP RST", rec.CloseReason)
	}
	if !rec.Time.Equal(time.Unix(0, 1700000123000000000)) {
		t.Fatalf("Time = %v, want close instant 1700000123000000000ns", rec.Time)
	}
}
