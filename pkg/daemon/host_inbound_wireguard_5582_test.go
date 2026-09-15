package daemon

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
	cfg.Interfaces.Interfaces["wg0"] = &config.InterfaceConfig{
		Name: "wg0",
		Tunnel: &config.TunnelConfig{
			Name:         "wg0",
			Mode:         "wireguard",
			WgListenPort: 51820,
			WgPeers: []config.WgPeerConfig{
				// Responder-only: no Endpoint -> passive listener (the #5582 case).
				{PublicKeyHex: "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
					AllowedIPs: []string{"10.9.0.0/24"}},
			},
		},
	}
	return cfg
}

// TestHostInboundFilterAdmitsWireGuardListenPort is the #5582 fail-on-revert
// proof. With a WireGuard listener configured, buildHostInboundFilterPayload
// emits a coarse `udp dport <listen-port> accept` on the input hook, admitting a
// fresh passive handshake (conntrack NEW) to a RESTRICTED zoned address that
// would otherwise hit the per-zone catch-all drop. The WG accept precedes the
// wan catch-all drop, so the handshake to the wan address:51820 is admitted, not
// dropped. Reverting the emitHostInboundWireGuardAccept emission removes the
// accept -> a NEW WG handshake falls to the drop -> this goes RED.
func TestHostInboundFilterAdmitsWireGuardListenPort(t *testing.T) {
	cfg := hostInboundWireGuardTestConfig()
	wgPorts := cfg.WireGuardListenPorts()
	if len(wgPorts) != 1 || wgPorts[0] != 51820 {
		t.Fatalf("WireGuardListenPorts() = %v, want [51820]", wgPorts)
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, wgPorts, true)

	wgAccept := "udp dport 51820 accept"
	if !strings.Contains(payload, wgAccept) {
		t.Fatalf("payload missing WireGuard listen-port admission %q\n---\n%s", wgAccept, payload)
	}

	// The WG accept must precede the wan v4 catch-all drop: a NEW inbound
	// handshake to the wan address on 51820 is admitted, not dropped.
	wanDropV4 := hiDrop("ip", "172.16.50.8", "wan")
	idxAccept := strings.Index(payload, wgAccept)
	idxDrop := strings.Index(payload, wanDropV4)
	if idxDrop < 0 {
		t.Fatalf("payload missing wan v4 catch-all drop %q\n---\n%s", wanDropV4, payload)
	}
	if idxAccept < 0 || idxAccept > idxDrop {
		t.Errorf("WG accept must precede the wan v4 catch-all drop so a fresh "+
			"handshake is admitted:\n%s", payload)
	}

	// Restricted-default posture preserved: the wan catch-all drop still exists
	// (both families), and an unlisted service (telnet tcp/23) is NOT admitted —
	// only the WG port was opened.
	if !strings.Contains(payload, hiDrop("ip6", "2001:db8:50::8", "wan")) {
		t.Errorf("wan v6 catch-all drop must remain (restricted posture):\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 23") {
		t.Errorf("WG admission must not widen the zone to other services (telnet leaked):\n%s", payload)
	}
	// Only ONE WG accept rule is emitted (a single coarse global rule), not one
	// per zone/family.
	if n := strings.Count(payload, wgAccept); n != 1 {
		t.Errorf("expected exactly one global WG accept rule, got %d:\n%s", n, payload)
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
		ports []uint16
		want  string
	}{
		{"single", []uint16{51820}, "udp dport 51820 accept"},
		{"set", []uint16{51820, 51821}, "udp dport { 51820, 51821 } accept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostInboundWireGuardTestConfig()
			views := buildAndCheckViews(t, cfg)
			payload := buildHostInboundFilterPayload(views, nil, nil, nil, tc.ports, true)
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
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, cfg.WireGuardListenPorts(), true)
	if strings.Contains(payload, "udp dport") && strings.Contains(payload, "51820") {
		t.Errorf("no WG accept must be emitted when WireGuard is unconfigured:\n%s", payload)
	}
}
