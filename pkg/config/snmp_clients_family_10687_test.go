package config

import (
	"net"
	"strings"
	"testing"
)

// #10687: net.IPNet.Contains treats IPv4-mapped 16-byte sources as IPv4. A
// community's IPv4 clients entry must not authorize that distinct 16-byte IPv6
// source representation. RED-on-revert: removing the source/network family
// check makes the mapped rows below pass through net.IPNet.Contains.
func TestSNMPClientSourceFamilyStrict10687(t *testing.T) {
	v4 := func(s string) net.IP { return net.ParseIP(s).To4() }
	mapped := net.ParseIP("::ffff:10.0.0.9")

	cases := []struct {
		name   string
		prefix string
		source net.IP
		want   bool
	}{
		{name: "IPv4 client admits canonical IPv4 source", prefix: "10.0.0.0/24", source: v4("10.0.0.9"), want: true},
		{name: "IPv4 client denies mapped IPv6 source", prefix: "10.0.0.0/24", source: mapped, want: false},
		{name: "IPv4 default route denies mapped IPv6 source", prefix: "0.0.0.0/0", source: mapped, want: false},
		{name: "IPv6 client admits IPv6 source", prefix: "2001:db8::/32", source: net.ParseIP("2001:db8::9"), want: true},
		{name: "IPv6 client denies IPv4 source", prefix: "2001:db8::/32", source: v4("10.0.0.9"), want: false},
		{name: "IPv6 default route admits mapped IPv6 source", prefix: "::/0", source: mapped, want: true},
		{name: "IPv6 default route denies IPv4 source", prefix: "::/0", source: v4("10.0.0.9"), want: false},
	}

	for _, compiled := range []bool{false, true} {
		mode := "uncompiled"
		if compiled {
			mode = "compiled"
		}
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				c := &SNMPCommunity{Clients: []SNMPClient{{Prefix: tc.prefix}}}
				if compiled {
					c.clientNets = compileClientNets(c.Clients)
				}
				if got := c.AllowsSource(tc.source); got != tc.want {
					t.Errorf("AllowsSource(%s, source len %d) = %v, want %v", tc.prefix, len(tc.source), got, tc.want)
				}
			})
		}
	}
}

func snmpClientTestSource10687(s string) net.IP {
	ip := net.ParseIP(s)
	if ip != nil && !strings.Contains(s, ":") {
		return ip.To4()
	}
	return ip
}
