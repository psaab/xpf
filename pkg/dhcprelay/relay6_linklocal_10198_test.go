package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/psaab/xpf/pkg/config"
)

// RFC 8415 §19.1.1 permits a link-local Relay-Forw link-address when no
// GUA/ULA exists, with Interface-Id required when the link-address cannot
// identify the return link (#10198).

func TestSelectDHCPv6LinkAddressFallback10198(t *testing.T) {
	gua := net.ParseIP("2001:db8:1::1")
	ula := net.ParseIP("fd00::1")
	ll := net.ParseIP("fe80::1")
	v4 := net.ParseIP("192.0.2.1")
	cases := []struct {
		name  string
		addrs []net.IP
		want  net.IP
	}{
		{"gua first", []net.IP{gua, ula, ll}, gua},
		{"first global remains preferred", []net.IP{ll, ula, gua}, ula},
		{"ula beats link-local", []net.IP{ll, ula}, ula},
		{"ula beats link-local reversed", []net.IP{ula, ll}, ula},
		{"link-local-only fallback", []net.IP{ll}, ll},
		{"link-local among unusable", []net.IP{v4, net.IPv6unspecified, net.ParseIP("ff02::1"), net.ParseIP("::1"), ll}, ll},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectDHCPv6LinkAddress(tc.addrs)
			if err != nil {
				t.Fatalf("selectDHCPv6LinkAddress(%v) error: %v", tc.addrs, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("selectDHCPv6LinkAddress(%v) = %v, want %v", tc.addrs, got, tc.want)
			}
		})
	}
	if _, err := selectDHCPv6LinkAddress(nil); err == nil {
		t.Fatal("empty address list must return an error")
	}
	if _, err := selectDHCPv6LinkAddress([]net.IP{v4, net.IPv6unspecified}); err == nil {
		t.Fatal("IPv4/unspecified-only list must return an error")
	}
}

func TestBuildRelayForwardV6LinkLocalRequiresInterfaceID10198(t *testing.T) {
	linkLocal := net.ParseIP("fe80::1")
	peer := net.ParseIP("fe80::2")

	forward, err := buildRelayForwardV6(newDHCPV6TestMessage(t), linkLocal, peer, []byte("ge-0/0/0.0"))
	if err != nil {
		t.Fatalf("direct link-local Relay-Forw with Interface-ID: %v", err)
	}
	if !forward.LinkAddr.Equal(linkLocal) {
		t.Fatalf("link-address = %v, want %v", forward.LinkAddr, linkLocal)
	}
	if got := string(forward.Options.InterfaceID()); got != "ge-0/0/0.0" {
		t.Fatalf("Interface-ID = %q, want authored interface", got)
	}

	if _, err := buildRelayForwardV6(newDHCPV6TestMessage(t), linkLocal, peer, nil); err == nil {
		t.Fatal("direct link-local Relay-Forw without Interface-ID must be rejected")
	}

	nested, err := dhcpv6.EncapsulateRelay(newDHCPV6TestMessage(t), dhcpv6.MessageTypeRelayForward, linkLocal, peer)
	if err != nil {
		t.Fatalf("EncapsulateRelay: %v", err)
	}
	if _, err := buildRelayForwardV6(nested, linkLocal, peer, []byte("ge-0/0/0.0")); err == nil {
		t.Fatal("nested link-local Relay-Forw must stay rejected even with Interface-ID")
	}

	if _, err := buildRelayForwardV6(newDHCPV6TestMessage(t), net.ParseIP("2001:db8:1::1"), peer, nil); err != nil {
		t.Fatalf("direct GUA Relay-Forw without Interface-ID must keep working: %v", err)
	}
}

func TestDHCPV6LinkLocalOnlyRelaysForward10198(t *testing.T) {
	client := newFakeDHCPV6Conn()
	server := newFakeConn()
	m := NewManager()
	m.v6.resolveLink = func(string) (net.IP, error) { return net.ParseIP("fe80::1"), nil }
	m.v6.newConn = func(_ context.Context, name string, _ net.IP) (dhcpV6Sockets, error) {
		client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort, Zone: name}
		client.iface = &net.Interface{Name: name, Index: 1}
		client.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		if err := client.JoinGroup(client.iface, client.group); err != nil {
			return dhcpV6Sockets{}, err
		}
		return dhcpV6Sockets{client: client, server: server, iface: client.iface, group: client.group}, nil
	}
	m.SetMasterGate(func(string) bool { return true })
	m.Apply(context.Background(), &config.DHCPRelayConfig{V6: &config.DHCPRelayV6Config{
		ServerGroups: map[string]*config.DHCPRelayV6ServerGroup{
			"sg6": {Name: "sg6", Servers: []string{"2001:db8::5"}},
		},
		Groups: map[string]*config.DHCPRelayV6Group{
			"g6": {Name: "g6", Interfaces: []string{"ge-0/0/0.0"}, ActiveServerGroup: "sg6"},
		},
	}})
	defer m.Stop()
	client.push(newDHCPV6TestMessage(t).ToBytes())
	deadline := time.Now().Add(time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() != 1 {
		t.Fatalf("link-local-only relay forwarded %d requests, want 1", server.writeCount())
	}
	forward, err := dhcpv6.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("parse forwarded request: %v", err)
	}
	relay := forward.(*dhcpv6.RelayMessage)
	if !relay.LinkAddr.Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("Relay-Forw link-address = %v, want fe80::1", relay.LinkAddr)
	}
	if got := string(relay.Options.InterfaceID()); got != "ge-0/0/0.0" {
		t.Fatalf("Relay-Forw Interface-ID = %q, want ge-0/0/0.0", got)
	}
}

func TestDHCPV6UpstreamBindAddrIgnoresLinkLocalIdentity10198(t *testing.T) {
	linkAddr := net.ParseIP("fe80::1")
	if !linkAddr.IsLinkLocalUnicast() {
		t.Fatalf("test link-address %v is not link-local", linkAddr)
	}
	got := dhcpV6UpstreamBindAddr()
	want := (&net.UDPAddr{IP: net.IPv6unspecified, Port: dhcpv6RelayPort}).String()
	if got != want {
		t.Fatalf("upstream bind address for link-local Relay-Forw = %q, want %q", got, want)
	}
	resolved, err := net.ResolveUDPAddr("udp6", got)
	if err != nil {
		t.Fatalf("resolve upstream bind address %q: %v", got, err)
	}
	if !resolved.IP.IsUnspecified() || resolved.Port != dhcpv6RelayPort {
		t.Fatalf("resolved upstream bind address = %v, want [::]:%d", resolved, dhcpv6RelayPort)
	}
}
