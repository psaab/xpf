package daemon

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #15078 (A47-01): a stream to an IPv6 collector whose source-interface is
// dual-stack bound the IPv4 primary (inet wins PrimaryAddress at compile
// time) and failed to dial for the life of the config. The apply must
// resolve the source against the collector's family on BOTH the
// per-stream and the global source-interface arms.
//
// FAIL-ON-REVERT: family-blind resolution binds 10.0.1.20 for the IPv6
// collector cells below, so they go RED (the UDP cell additionally fails
// construction: a v4 source cannot dial a v6 collector).

func syslogFamilyCfg15078(host, perStreamIface, globalIface, proto string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			100: {
				Number:           100,
				Addresses:        []string{"10.0.1.20/24", "2001:db8:1::20/64"},
				PrimaryAddress:   "10.0.1.20/24",
				PreferredAddress: "10.0.1.20/24",
			},
		}},
	}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.SourceInterface = globalIface
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:            "audit",
			Host:            host,
			Port:            514,
			Transport:       config.SyslogTransport{Protocol: proto},
			SourceInterface: perStreamIface,
		},
	}
	return cfg
}

func TestApplySyslogConfigCollectorFamily15078(t *testing.T) {
	for _, tc := range []struct {
		name           string
		host           string
		perStreamIface string
		globalIface    string
		want           string
	}{
		{"ipv6 collector via per-stream source-interface", "2001:db8:9::1", "reth1.100", "", "2001:db8:1::20"},
		{"ipv6 collector via global source-interface", "2001:db8:9::1", "", "reth1.100", "2001:db8:1::20"},
		{"ipv4 collector control via per-stream source-interface", "192.0.2.1", "reth1.100", "", "10.0.1.20"},
		{"ipv4 collector control via global source-interface", "192.0.2.1", "", "reth1.100", "10.0.1.20"},
		{"hostname collector keeps legacy primary", "collector.example.net", "reth1.100", "", "10.0.1.20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			er := logging.NewEventReader(nil, nil)
			cfg := syslogFamilyCfg15078(tc.host, tc.perStreamIface, tc.globalIface, "tcp")
			d := &Daemon{}
			d.applySyslogConfig(er, cfg)
			clients := er.SyslogClients()
			if len(clients) != 1 {
				t.Fatalf("expected 1 syslog client after apply, got %d", len(clients))
			}
			defer clients[0].Close()
			if got := clients[0].SourceAddr(); got != tc.want {
				t.Errorf("daemon apply bound source %q, want %q (#15078)", got, tc.want)
			}
		})
	}
}

// Acceptance probe: an IPv6 UDP stream with `source-interface lo` must be
// installed and deliver. Pre-fix the resolver returned 127.0.0.1, the UDP
// dial to the v6 collector failed, and the stream was skipped entirely.
func TestApplySyslogConfigIPv6CollectorDeliversViaLo15078(t *testing.T) {
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:            "audit",
			Host:            "::1",
			Port:            port,
			Transport:       config.SyslogTransport{Protocol: "udp"},
			SourceInterface: "lo",
		},
	}
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)

	clients := er.SyslogClients()
	if len(clients) != 1 {
		t.Fatalf("IPv6 collector via source-interface lo installed %d clients, want 1 "+
			"(pre-fix the v4 source failed the v6 dial and the stream was skipped, #15078)", len(clients))
	}
	defer clients[0].Close()
	if got := clients[0].SourceAddr(); got != "::1" {
		t.Fatalf("bound source = %q, want ::1 (#15078)", got)
	}
	if err := clients[0].Send(logging.SyslogInfo, "family-probe-15078"); err != nil {
		t.Fatalf("Send to IPv6 collector: %v", err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no datagram delivered to the IPv6 collector: %v (#15078)", err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "family-probe-15078") {
		t.Errorf("delivered datagram %q does not carry the probe message", got)
	}
}

// IPv4 control for the probe above: unchanged delivery via lo.
func TestApplySyslogConfigIPv4CollectorDeliversViaLo15078(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no IPv4 loopback: %v", err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:            "audit",
			Host:            "127.0.0.1",
			Port:            port,
			Transport:       config.SyslogTransport{Protocol: "udp"},
			SourceInterface: "lo",
		},
	}
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)

	clients := er.SyslogClients()
	if len(clients) != 1 {
		t.Fatalf("IPv4 control installed %d clients, want 1", len(clients))
	}
	defer clients[0].Close()
	if got := clients[0].SourceAddr(); got != "127.0.0.1" {
		t.Fatalf("bound source = %q, want 127.0.0.1 (control)", got)
	}
	if err := clients[0].Send(logging.SyslogInfo, "family-control-15078"); err != nil {
		t.Fatalf("Send to IPv4 collector: %v", err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := pc.ReadFrom(buf); err != nil {
		t.Fatalf("no datagram delivered to the IPv4 collector (control): %v", err)
	}
}
