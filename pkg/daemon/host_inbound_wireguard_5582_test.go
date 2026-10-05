package daemon

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInboundWireGuardTestConfig extends the restricted-zone fixture
// (hostInboundTestConfig: wan = host-inbound { ssh; ping; } on reth0.50, a
// RESTRICTED zone with a v4+v6 static address) with a passive WireGuard
// listener: a wg0 tunnel, Mode="wireguard", listen-port 51820, one peer with NO
// endpoint (responder-only). The wan address is where the outer WG transport
// arrives; the shim steers UDP/51820 to the kernel, so the host-inbound filter
// must admit it or the fresh handshake is dropped by wan's catch-all (#5582).
func hostInboundWireGuardTestConfig() *config.Config {
	cfg := hostInboundTestConfig()
	// #11574: WG transport admission follows the outer source's owner zone.
	cfg.Interfaces.Interfaces["wg0"] = &config.InterfaceConfig{
		Name: "wg0",
		Tunnel: &config.TunnelConfig{
			Name:         "wg0",
			Mode:         "wireguard",
			Source:       "172.16.50.8",
			WgListenPort: 51820,
			WgPeers: []config.WgPeerConfig{
				// Responder-only: no Endpoint -> passive listener (the #5582 case).
				{PublicKeyHex: strings.Repeat("b2", 32),
					AllowedIPs: []string{"10.9.0.0/24"}},
			},
		},
	}
	cfg.Security.Zones["lan"].Interfaces = append(cfg.Security.Zones["lan"].Interfaces, "wg0")
	return cfg
}

// TestHostInboundFilterAdmitsWireGuardListenPort is the #5582 fail-on-revert
// proof, re-scoped by #11574. Although the WireGuard tunnel is logically in lan,
// its outer source address belongs to wan, so only wan ingress may reach that
// listener on a uniquely wan-owned destination address.
func TestHostInboundFilterAdmitsWireGuardListenPort(t *testing.T) {
	cfg := hostInboundWireGuardTestConfig()
	wgPorts := cfg.WireGuardListenPorts()
	if len(wgPorts) != 1 || wgPorts[0] != 51820 {
		t.Fatalf("WireGuardListenPorts() = %v, want [51820]", wgPorts)
	}
	views := buildAndCheckViews(t, cfg)
	wgZones := hostInboundWireGuardZonePorts(cfg, views)
	if len(wgZones) != 1 || len(wgZones["wan"]) != 1 || wgZones["wan"][0] != 51820 {
		t.Fatalf("hostInboundWireGuardZonePorts() = %v, want map[wan:[51820]]", wgZones)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, wgZones, true)

	// Scoped accepts (v4+v6) inside wan's section.
	for _, want := range []string{
		"ip daddr 172.16.50.8 udp dport 51820 accept",
		"ip6 daddr 2001:db8:50::8 udp dport 51820 accept",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload missing scoped WG admission %q\n---\n%s", want, payload)
		}
	}
	// No bare accept anywhere.
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, "udp dport") && strings.Contains(line, "51820") && !strings.Contains(line, "daddr") {
			t.Fatalf("bare WG accept leaked: %s\n---\n%s", line, payload)
		}
	}

	// The scoped accept must precede the wan v4 catch-all drop.
	wanDropV4 := hiDrop("ip", "172.16.50.8", "wan")
	idxAccept := strings.Index(payload, "udp dport 51820 accept")
	idxDrop := strings.Index(payload, wanDropV4)
	if idxDrop < 0 {
		t.Fatalf("payload missing wan v4 catch-all drop %q\n---\n%s", wanDropV4, payload)
	}
	if idxAccept < 0 || idxAccept > idxDrop {
		t.Errorf("WG accept must precede the wan v4 catch-all drop so a fresh "+
			"handshake is admitted:\n%s", payload)
	}

	// Restricted-default posture preserved: the wan catch-all drop still exists
	// (both families), and an unlisted service (telnet tcp/23) is NOT admitted.
	if !strings.Contains(payload, hiDrop("ip6", "2001:db8:50::8", "wan")) {
		t.Errorf("wan v6 catch-all drop must remain (restricted posture):\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 23") {
		t.Errorf("WG admission must not widen the zone to other services (telnet leaked):\n%s", payload)
	}
}

// TestHostInboundWireGuardPortGuardPrecedesAnyService verifies that a globally
// selected WG port cannot use an any-service zone's broad host admission to
// reach another zone's address or arrive on a non-owner ingress.
func TestHostInboundWireGuardPortGuardPrecedesAnyService(t *testing.T) {
	cfg := hostInboundWireGuardTestConfig()
	cfg.Security.Zones["wan"].HostInboundTraffic.SystemServices = []string{"any-service"}
	cfg.Security.Zones["lan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"any-service"}}
	views := buildAndCheckViews(t, cfg)
	ports := hostInboundWireGuardZonePorts(cfg, views)
	if len(ports["wan"]) != 1 || ports["wan"][0] != 51820 || len(ports["lan"]) != 0 {
		t.Fatalf("WG transport-zone ports = %v, want only wan:[51820]", ports)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, ports, true)

	var wanIngress, lanIngress []string
	for _, view := range views {
		switch view.Zone {
		case "wan":
			wanIngress = view.IngressNetdevs
		case "lan":
			lanIngress = view.IngressNetdevs
		}
	}
	if len(wanIngress) == 0 || len(lanIngress) == 0 {
		t.Fatalf("fixture ingress scopes missing: wan=%v lan=%v", wanIngress, lanIngress)
	}
	allowed := "iifname " + nftIifnameSet(wanIngress) + " ip daddr 172.16.50.8 udp dport 51820 accept"
	if !strings.Contains(payload, allowed) {
		t.Fatalf("same-zone outer-source admission missing %q:\n%s", allowed, payload)
	}
	lanDrop := "ip daddr 10.0.61.1 udp dport 51820 counter name \"" +
		xnft.HostInboundDenyCounterName("lan", "ip") + "\" drop"
	dropAt := strings.Index(payload, lanDrop)
	if dropAt < 0 {
		t.Fatalf("selected WG port to lan-owned address lacks its counted guard %q:\n%s", lanDrop, payload)
	}
	broadLanAccept := "iifname " + nftIifnameSet(lanIngress) + " ip daddr "
	acceptAt := strings.Index(payload, broadLanAccept)
	replyAt := strings.Index(payload, "ct state established,related ct direction reply accept")
	if acceptAt < 0 || dropAt > acceptAt || replyAt < 0 || dropAt > replyAt {
		t.Fatalf("WG guard must precede stateful and any-service accepts (drop=%d reply=%d accept=%d):\n%s", dropAt, replyAt, acceptAt, payload)
	}
	if strings.Contains(payload, "iifname "+nftIifnameSet(lanIngress)+" ip daddr 10.0.61.1 udp dport 51820 accept") {
		t.Fatalf("WG listener bound to wan's outer source must not admit from lan ingress:\n%s", payload)
	}
}

// TestHostInboundWireGuardMultiPortAdmissionPins9016 restores the #9016
// multi-listener pin through the current owner-zone derivation rather than a
// caller-supplied global map: both configured ports belong to wan's source
// address, while lan ingress, lan-owned destinations, and an unconfigured port
// remain denied.
func TestHostInboundWireGuardMultiPortAdmissionPins9016(t *testing.T) {
	cfg := hostInboundWireGuardTestConfig()
	cfg.Interfaces.Interfaces["wg1"] = &config.InterfaceConfig{
		Name: "wg1",
		Tunnel: &config.TunnelConfig{
			Name:         "wg1",
			Mode:         "wireguard",
			Source:       "172.16.50.8",
			WgListenPort: 51821,
		},
	}
	cfg.Security.Zones["lan"].Interfaces = append(cfg.Security.Zones["lan"].Interfaces, "wg1")
	ports := cfg.WireGuardListenPorts()
	if len(ports) != 2 || ports[0] != 51820 || ports[1] != 51821 {
		t.Fatalf("WireGuardListenPorts() = %v, want [51820 51821]", ports)
	}
	views := buildAndCheckViews(t, cfg)
	zonePorts := hostInboundWireGuardZonePorts(cfg, views)
	if len(zonePorts["wan"]) != 2 || zonePorts["wan"][0] != 51820 || zonePorts["wan"][1] != 51821 {
		t.Fatalf("source-owner ports = %v, want wan:[51820 51821]", zonePorts)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, zonePorts, true)

	var wanIngress, lanIngress []string
	for _, view := range views {
		switch view.Zone {
		case "wan":
			wanIngress = view.IngressNetdevs
		case "lan":
			lanIngress = view.IngressNetdevs
		}
	}
	if len(wanIngress) == 0 || len(lanIngress) == 0 {
		t.Fatalf("fixture ingress scopes missing: wan=%v lan=%v", wanIngress, lanIngress)
	}
	portSet := "{ 51820, 51821 }"
	allowed := "iifname " + nftIifnameSet(wanIngress) +
		" ip daddr 172.16.50.8 udp dport " + portSet + " accept"
	if !strings.Contains(payload, allowed) {
		t.Fatalf("both source-owned listener ports must be admitted only on wan ingress; missing %q:\n%s", allowed, payload)
	}
	wrongIngressDrop := "iifname != " + nftIifnameSet(wanIngress) +
		" ip daddr 172.16.50.8 udp dport " + portSet + " counter name \"" +
		xnft.HostInboundDenyCounterName("wan", "ip") + "\" drop"
	if !strings.Contains(payload, wrongIngressDrop) {
		t.Fatalf("wrong-zone ingress lacks the counted two-port drop %q:\n%s", wrongIngressDrop, payload)
	}
	if strings.Contains(payload, "iifname "+nftIifnameSet(lanIngress)+
		" ip daddr 172.16.50.8 udp dport "+portSet+" accept") {
		t.Fatalf("lan ingress must not admit wan-owned listener ports:\n%s", payload)
	}
	if !strings.Contains(payload, "udp dport "+portSet+" counter name \""+
		xnft.HostInboundDenyCounterName("lan", "ip")+"\" drop") {
		t.Fatalf("lan-owned destinations lack a two-port mismatch drop:\n%s", payload)
	}
	if strings.Contains(payload, "udp dport 51822") {
		t.Fatalf("unconfigured WG port leaked into host-inbound policy:\n%s", payload)
	}
}

// TestHostInboundFilterWireGuardPayloadParses runs the EXACT payload carrying
// the #5582 WireGuard accept (both the single-port and the multi-port anonymous
// set forms) through the appliance nft binary, so the emitted
// `udp dport <spec> accept` is validated against real nft syntax — not just
// asserted as a substring. Mirrors TestHostInboundFilterIdentResetPayloadParses:
// a `syntax error` fails; a netlink/permission error (no CAP_NET_ADMIN) after a
// clean parse is a pass; nft absent skips.
func TestHostInboundFilterWireGuardPayloadParses(t *testing.T) {
	nftPath := findNft()
	if nftPath == "" {
		t.Skip("nft not found; substring coverage in TestHostInboundFilterAdmitsWireGuardListenPort")
	}
	for _, tc := range []struct {
		name  string
		zones map[string][]uint16
		want  string
	}{
		{"single", map[string][]uint16{"wan": {51820}}, "udp dport 51820 accept"},
		{"set", map[string][]uint16{"wan": {51820, 51821}}, "udp dport { 51820, 51821 } accept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostInboundWireGuardTestConfig()
			views := buildAndCheckViews(t, cfg)
			payload := buildHostInboundFilterPayload(views, nil, nil, nil, tc.zones, true)
			if !strings.Contains(payload, tc.want) {
				t.Fatalf("payload missing %q:\n%s", tc.want, payload)
			}
			cmd := exec.Command(nftPath, "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(payload)
			out, err := cmd.CombinedOutput()
			if err == nil {
				return
			}
			if strings.Contains(string(out), "syntax error") {
				t.Fatalf("nft -c rejected the WireGuard host-inbound payload:\n%s\npayload:\n%s", out, payload)
			}
			t.Logf("nft -c parsed the payload; non-syntax error (expected without CAP_NET_ADMIN): %v\n%s", err, out)
		})
	}
}

// TestHostInboundFilterNoWireGuardNoAccept proves the negative: with NO
// WireGuard configured (wgListenPorts empty), no WG accept is emitted, so the
// restricted-default posture is bit-identical to the pre-#5582 payload.
func TestHostInboundFilterNoWireGuardNoAccept(t *testing.T) {
	cfg := hostInboundTestConfig()
	if ports := cfg.WireGuardListenPorts(); len(ports) != 0 {
		t.Fatalf("fixture unexpectedly has WG ports: %v", ports)
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	if strings.Contains(payload, "udp dport") && strings.Contains(payload, "51820") {
		t.Errorf("no WG accept must be emitted when WireGuard is unconfigured:\n%s", payload)
	}
}

// TestHostInboundSourceLessWireGuardFailsClosed12119 restores the original
// #5582 source-less listener shape as an explicit regression: compile remains
// compatible but emits no serving-zone admission, so the selected port is
// visibly dropped until a tunnel source is configured.
func TestHostInboundSourceLessWireGuardFailsClosed12119(t *testing.T) {
	cfg := hostInboundWireGuardTestConfig()
	cfg.Interfaces.Interfaces["wg0"].Tunnel.Source = ""
	views := buildAndCheckViews(t, cfg)
	ports := hostInboundWireGuardZonePorts(cfg, views)
	if len(ports[""]) != 1 || ports[""][0] != 51820 {
		t.Fatalf("source-less listener sentinel ports = %v, want empty-zone [51820]", ports)
	}
	if len(ports["wan"]) != 0 {
		t.Fatalf("source-less listener must not be attributed to wan: %v", ports)
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, ports, true)
	if !strings.Contains(payload, "udp dport 51820") {
		t.Fatalf("source-less selected listener must have an explicit mismatch drop:\n%s", payload)
	}
	if strings.Contains(payload, "udp dport 51820 accept") {
		t.Fatalf("source-less listener must not be admitted in any zone:\n%s", payload)
	}
}
