package cluster

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildGratuitousARP_Reply(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("10.0.1.10").To4()

	pkt := buildGratuitousARP(mac, ip, 2) // ARP Reply

	if len(pkt) != 42 {
		t.Fatalf("packet length = %d, want 42", len(pkt))
	}

	// Ethernet destination: broadcast.
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xff {
			t.Errorf("dst MAC[%d] = 0x%02x, want 0xff", i, pkt[i])
		}
	}

	// Ethernet source: our MAC.
	for i := 0; i < 6; i++ {
		if pkt[6+i] != mac[i] {
			t.Errorf("src MAC[%d] = 0x%02x, want 0x%02x", i, pkt[6+i], mac[i])
		}
	}

	// EtherType: ARP.
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != unix.ETH_P_ARP {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", etherType, unix.ETH_P_ARP)
	}

	// ARP hardware type: Ethernet (1).
	hwType := binary.BigEndian.Uint16(pkt[14:16])
	if hwType != 1 {
		t.Errorf("hardware type = %d, want 1", hwType)
	}

	// ARP protocol type: IPv4.
	protoType := binary.BigEndian.Uint16(pkt[16:18])
	if protoType != 0x0800 {
		t.Errorf("protocol type = 0x%04x, want 0x0800", protoType)
	}

	// Hardware/protocol address lengths.
	if pkt[18] != 6 {
		t.Errorf("hw addr len = %d, want 6", pkt[18])
	}
	if pkt[19] != 4 {
		t.Errorf("proto addr len = %d, want 4", pkt[19])
	}

	// Opcode: ARP reply (2).
	opcode := binary.BigEndian.Uint16(pkt[20:22])
	if opcode != 2 {
		t.Errorf("opcode = %d, want 2 (reply)", opcode)
	}

	// Sender hardware address = our MAC.
	for i := 0; i < 6; i++ {
		if pkt[22+i] != mac[i] {
			t.Errorf("sender MAC[%d] = 0x%02x, want 0x%02x", i, pkt[22+i], mac[i])
		}
	}

	// Sender protocol address = our IP.
	for i := 0; i < 4; i++ {
		if pkt[28+i] != ip[i] {
			t.Errorf("sender IP[%d] = %d, want %d", i, pkt[28+i], ip[i])
		}
	}

	// Target hardware address: broadcast (for GARP Reply).
	for i := 0; i < 6; i++ {
		if pkt[32+i] != 0xff {
			t.Errorf("target MAC[%d] = 0x%02x, want 0xff", i, pkt[32+i])
		}
	}

	// Target protocol address = our IP (GARP).
	for i := 0; i < 4; i++ {
		if pkt[38+i] != ip[i] {
			t.Errorf("target IP[%d] = %d, want %d", i, pkt[38+i], ip[i])
		}
	}
}

func TestBuildGratuitousARP_Request(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("10.0.1.10").To4()

	pkt := buildGratuitousARP(mac, ip, 1) // ARP Request

	if len(pkt) != 42 {
		t.Fatalf("packet length = %d, want 42", len(pkt))
	}

	// Opcode: ARP request (1).
	opcode := binary.BigEndian.Uint16(pkt[20:22])
	if opcode != 1 {
		t.Errorf("opcode = %d, want 1 (request)", opcode)
	}

	// Target hardware address: zero (for GARP Request).
	for i := 0; i < 6; i++ {
		if pkt[32+i] != 0x00 {
			t.Errorf("target MAC[%d] = 0x%02x, want 0x00", i, pkt[32+i])
		}
	}

	// Target protocol address = our IP (GARP).
	for i := 0; i < 4; i++ {
		if pkt[38+i] != ip[i] {
			t.Errorf("target IP[%d] = %d, want %d", i, pkt[38+i], ip[i])
		}
	}
}

func TestHtons(t *testing.T) {
	// htons should convert host-endian to network (big-endian).
	result := htons(0x0806)
	// Verify it round-trips: reading it back as big-endian gives 0x0806.
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, result)
	val := binary.BigEndian.Uint16(b)
	if val != 0x0806 {
		t.Errorf("htons(0x0806) round-trip = 0x%04x, want 0x0806", val)
	}
}

func TestSendGratuitousARP_IPv6Rejected(t *testing.T) {
	err := SendGratuitousARP("lo", net.ParseIP("::1"), 1)
	if err == nil {
		t.Error("expected error for IPv6 address")
	}
}

func TestSendGratuitousIPv6_IPv4Rejected(t *testing.T) {
	err := SendGratuitousIPv6("lo", net.ParseIP("10.0.1.1"), 1)
	if err == nil {
		t.Error("expected error for IPv4 address")
	}
}

// TestSendARPProbe_EmitsExplicitSender proves the crafted ARP Request uses
// the senderIP passed by the caller as the ARP sender protocol address
// (pkt[28:32]), NOT the interface's own address. This is the #2152 fix: the
// VRRP failover probe must carry the VIP as sender so the gateway re-binds
// VIP -> our MAC. The test is non-tautological — pre-fix, SendARPProbe
// ignored any passed sender and self-resolved to the interface primary, so
// this assertion (sender field == the VIP we passed, which is NOT an address
// of "lo") would fail.
func TestSendARPProbe_EmitsExplicitSender(t *testing.T) {
	const vip = "10.0.0.100" // a VRRP VIP — deliberately NOT an address of lo
	const gw = "10.0.0.1"    // the gateway target

	var captured []byte
	orig := arpProbeSend
	arpProbeSend = func(_ *net.Interface, pkt []byte) error {
		captured = append([]byte(nil), pkt...)
		return nil
	}
	defer func() { arpProbeSend = orig }()

	if err := SendARPProbe("lo", net.ParseIP(vip), net.ParseIP(gw)); err != nil {
		t.Fatalf("SendARPProbe returned error: %v", err)
	}
	if len(captured) != 42 {
		t.Fatalf("captured frame length = %d, want 42", len(captured))
	}

	// ARP sender protocol address is at pkt[28:32]; it MUST equal the VIP.
	gotSender := net.IP(captured[28:32]).String()
	if gotSender != vip {
		t.Errorf("ARP sender IP = %s, want VIP %s (probe used wrong sender)", gotSender, vip)
	}
	// Sanity: the target protocol address (pkt[38:42]) is the gateway.
	gotTarget := net.IP(captured[38:42]).String()
	if gotTarget != gw {
		t.Errorf("ARP target IP = %s, want gateway %s", gotTarget, gw)
	}
	// Opcode (pkt[20:22]) must be ARP Request (1).
	if op := binary.BigEndian.Uint16(captured[20:22]); op != 1 {
		t.Errorf("opcode = %d, want 1 (request)", op)
	}
}

func TestSendARPProbe_RejectsIPv6Sender(t *testing.T) {
	err := SendARPProbe("lo", net.ParseIP("2001:db8::1"), net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Error("expected error for IPv6 sender")
	}
}

func TestSendARPProbe_RejectsIPv6Target(t *testing.T) {
	err := SendARPProbe("lo", net.ParseIP("10.0.0.100"), net.ParseIP("2001:db8::1"))
	if err == nil {
		t.Error("expected error for IPv6 target")
	}
}

// TestPrimaryIPv4_SkipsLinkLocal verifies PrimaryIPv4 preserves the
// pre-#2152 self-resolved-sender behavior used by the neighbor-table
// reprobe path: it returns a non-link-local IPv4 and never a 169.254.x.x
// address. Loopback carries 127.0.0.1 (and no 169.254.x.x), so on a normal
// host it resolves to 127.0.0.1.
func TestPrimaryIPv4_SkipsLinkLocal(t *testing.T) {
	ip, err := PrimaryIPv4("lo")
	if err != nil {
		t.Skipf("lo has no usable IPv4 in this environment: %v", err)
	}
	if ip4 := ip.To4(); ip4 == nil {
		t.Fatalf("PrimaryIPv4 returned non-IPv4: %v", ip)
	} else if ip4[0] == 169 && ip4[1] == 254 {
		t.Errorf("PrimaryIPv4 returned link-local %v, want non-link-local", ip)
	}
}

func TestBuildUnsolicitedNA(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("2001:db8::1")

	pkt := buildUnsolicitedNA(mac, ip, ip)

	if len(pkt) != 86 {
		t.Fatalf("packet length = %d, want 86", len(pkt))
	}

	// Ethernet destination: IPv6 all-nodes multicast MAC.
	wantDstMAC := []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	for i := 0; i < 6; i++ {
		if pkt[i] != wantDstMAC[i] {
			t.Errorf("dst MAC[%d] = 0x%02x, want 0x%02x", i, pkt[i], wantDstMAC[i])
		}
	}

	// Ethernet source: our MAC.
	for i := 0; i < 6; i++ {
		if pkt[6+i] != mac[i] {
			t.Errorf("src MAC[%d] = 0x%02x, want 0x%02x", i, pkt[6+i], mac[i])
		}
	}

	// EtherType: IPv6.
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != unix.ETH_P_IPV6 {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", etherType, unix.ETH_P_IPV6)
	}

	// IPv6 version.
	if pkt[14]>>4 != 6 {
		t.Errorf("IPv6 version = %d, want 6", pkt[14]>>4)
	}

	// IPv6 payload length: 32 (24 NA + 8 TLLA option).
	payloadLen := binary.BigEndian.Uint16(pkt[18:20])
	if payloadLen != 32 {
		t.Errorf("payload length = %d, want 32", payloadLen)
	}

	// Next header: ICMPv6 (58).
	if pkt[20] != 58 {
		t.Errorf("next header = %d, want 58 (ICMPv6)", pkt[20])
	}

	// Hop limit: 255.
	if pkt[21] != 255 {
		t.Errorf("hop limit = %d, want 255", pkt[21])
	}

	// Source IP: our IPv6 address.
	srcIP := net.IP(pkt[22:38])
	if !srcIP.Equal(ip) {
		t.Errorf("source IP = %s, want %s", srcIP, ip)
	}

	// Destination: ff02::1.
	dstIP := net.IP(pkt[38:54])
	wantDst := net.ParseIP("ff02::1")
	if !dstIP.Equal(wantDst) {
		t.Errorf("destination IP = %s, want %s", dstIP, wantDst)
	}

	// ICMPv6 type: 136 (Neighbor Advertisement).
	if pkt[54] != 136 {
		t.Errorf("ICMPv6 type = %d, want 136", pkt[54])
	}

	// ICMPv6 code: 0.
	if pkt[55] != 0 {
		t.Errorf("ICMPv6 code = %d, want 0", pkt[55])
	}

	// Flags: Router=1 + Override=1 (0xA0).
	if pkt[58] != 0xA0 {
		t.Errorf("NA flags = 0x%02x, want 0xA0 (Router+Override)", pkt[58])
	}

	// Target address: our IPv6 address.
	targetIP := net.IP(pkt[62:78])
	if !targetIP.Equal(ip) {
		t.Errorf("target IP = %s, want %s", targetIP, ip)
	}

	// TLLA option: type=2, length=1.
	if pkt[78] != 2 {
		t.Errorf("TLLA option type = %d, want 2", pkt[78])
	}
	if pkt[79] != 1 {
		t.Errorf("TLLA option length = %d, want 1", pkt[79])
	}

	// TLLA option: our MAC.
	for i := 0; i < 6; i++ {
		if pkt[80+i] != mac[i] {
			t.Errorf("TLLA MAC[%d] = 0x%02x, want 0x%02x", i, pkt[80+i], mac[i])
		}
	}

	// Verify checksum is non-zero (computed).
	csum := binary.BigEndian.Uint16(pkt[56:58])
	if csum == 0 {
		t.Error("ICMPv6 checksum should be non-zero")
	}
}
func TestBuildUnsolicitedProxyNASeparatesSourceFromTarget(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	source := net.ParseIP("fe80::1234")
	target := net.ParseIP("2001:db8::7")

	pkt := buildUnsolicitedNA(mac, source, target)
	if got := net.IP(pkt[22:38]); !got.Equal(source) {
		t.Errorf("IPv6 source = %s, want assigned interface source %s", got, source)
	}
	if got := net.IP(pkt[62:78]); !got.Equal(target) {
		t.Errorf("NA target = %s, want proxy target %s", got, target)
	}
	// This daemon is a forwarding router; R=1 describes the sender, not the
	// proxied target. Override=1 replaces the stale neighbor binding and
	// Solicited=0 is required for this multicast announcement.
	if pkt[58] != 0xA0 {
		t.Errorf("NA flags = 0x%02x, want Router+Override and no Solicited flag (0xA0)", pkt[58])
	}

	original := binary.BigEndian.Uint16(pkt[56:58])
	pkt[56], pkt[57] = 0, 0
	if got := icmpv6Checksum(pkt[22:38], pkt[38:54], pkt[54:86]); got != original {
		t.Errorf("checksum = 0x%04x, recomputed with distinct source/target = 0x%04x", original, got)
	}
}

func TestProbeIPv6SourcePrefersGlobal(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
	}
	got := probeIPv6Source(addrs)
	want := net.ParseIP("2001:db8::10")
	if got == nil || !got.Equal(want) {
		t.Fatalf("probeIPv6Source() = %v, want %v", got, want)
	}
}

func TestProbeIPv6SourceFallsBackToLinkLocal(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1234"), Mask: net.CIDRMask(64, 128)},
	}
	got := probeIPv6Source(addrs)
	want := net.ParseIP("fe80::1234")
	if got == nil || !got.Equal(want) {
		t.Fatalf("probeIPv6Source() = %v, want %v", got, want)
	}
}

func TestProbeIPv6SourceRejectsIPv4Only(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
	}
	if got := probeIPv6Source(addrs); got != nil {
		t.Fatalf("probeIPv6Source() = %v, want nil", got)
	}
}

func TestICMPv6Checksum(t *testing.T) {
	// Build a known packet and verify checksum validates.
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("2001:db8::1")
	pkt := buildUnsolicitedNA(mac, ip, ip)

	// Extract the checksum that was written.
	originalCsum := binary.BigEndian.Uint16(pkt[56:58])

	// Zero the checksum field and recompute.
	pkt[56] = 0
	pkt[57] = 0
	recomputed := icmpv6Checksum(pkt[22:38], pkt[38:54], pkt[54:86])
	if recomputed != originalCsum {
		t.Errorf("recomputed checksum 0x%04x != original 0x%04x", recomputed, originalCsum)
	}
}
