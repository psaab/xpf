package snmp

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #10687: a dual-stack UDP socket reports a real IPv4 datagram as a 16-byte
// mapped address on some platforms. Normalize that kernel representation at
// ingress, while the allowlist itself keeps explicit 16-byte mapped identities
// separate from IPv4 sources.
func TestDualStackIPv4PeerRemainsAllowed10687(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	local := listener.LocalAddr().(*net.UDPAddr)
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: local.Port})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}

	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var packet [1]byte
	if _, peer, err := listener.ReadFromUDP(packet[:]); err != nil {
		t.Fatal(err)
	} else {
		source := sourceIPForUDP(peer)
		if len(source) != net.IPv4len || !source.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("normalized dual-stack peer = %v (len %d), want IPv4 127.0.0.1", source, len(source))
		}

		a := NewAgent(&config.SNMPConfig{Communities: map[string]*config.SNMPCommunity{
			"scoped": {
				Name:          "scoped",
				Authorization: "read-only",
				Clients:       []config.SNMPClient{{Prefix: "127.0.0.0/8"}},
			},
		}})
		if resp := a.handlePacketFrom(buildV2cGetRequest("scoped", 10687, oidSysDescr), source); resp == nil {
			t.Fatal("real IPv4 peer from a dual-stack socket was denied by its IPv4 clients entry")
		}
	}
}

func TestMappedIPv6SourceCannotUseIPv4Client10687(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Communities: map[string]*config.SNMPCommunity{
		"scoped": {
			Name:          "scoped",
			Authorization: "read-only",
			Clients:       []config.SNMPClient{{Prefix: "10.0.0.0/24"}},
		},
	}})
	pkt := buildV2cGetRequest("scoped", 10688, oidSysDescr)

	if resp := a.handlePacketFrom(pkt, snmpSource10687("10.0.0.9")); resp == nil {
		t.Fatal("canonical IPv4 source inside the clients prefix was denied")
	}
	if resp := a.handlePacketFrom(pkt, net.ParseIP("::ffff:10.0.0.9")); resp != nil {
		t.Fatal("16-byte mapped IPv6 source was served by an IPv4 clients prefix")
	}
}

func snmpSource10687(s string) net.IP {
	ip := net.ParseIP(s)
	if ip != nil && !strings.Contains(s, ":") {
		return ip.To4()
	}
	return ip
}
