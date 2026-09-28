package daemon

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/webmgmt"
)

// webmgmt_port_contract_5715_test.go is the #5715 cross-package contract: the
// web-management LISTENER bind ports (derived by resolveAPIBinds from a
// web-management config) must EQUAL the host-inbound service-catalog admit ports
// for the `http` / `https` tokens (config.HostInboundServiceMatch, the Go SSOT
// the nft kernel mirror renders and the Rust classifier parity-tracks).
//
// Before #5715 the listener bound 8080/8443 while the catalog admitted 80/443,
// so a zoned interface configured with least-privilege `system-services https`
// admitted an unused TCP/443 socket and DROPPED the real TCP/8443 listener. Both
// sides now derive from the pkg/webmgmt SSOT (HTTPPort=80 / HTTPSPort=443).

// hostInboundTCPPort returns the single TCP admit port the host-inbound catalog
// grants for token in family, failing if the token does not map to exactly one
// single-port TCP match (the http/https contract shape).
func hostInboundTCPPort(t *testing.T, token, family string) uint16 {
	t.Helper()
	ms := config.HostInboundServiceMatch(token, family)
	if len(ms) != 1 {
		t.Fatalf("HostInboundServiceMatch(%q,%q) returned %d matches, want exactly 1", token, family, len(ms))
	}
	m := ms[0]
	if m.Proto != config.HostInboundProtoTCP {
		t.Fatalf("HostInboundServiceMatch(%q,%q) proto = %d, want TCP", token, family, m.Proto)
	}
	if len(m.Ports) != 1 || m.Ports[0].Lo != m.Ports[0].Hi {
		t.Fatalf("HostInboundServiceMatch(%q,%q) ports = %+v, want one single port", token, family, m.Ports)
	}
	return m.Ports[0].Lo
}

// listenerPort extracts the numeric port from a "host:port" listen address.
func listenerPort(t *testing.T, addr string) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return uint16(p)
}

// webmgmtTestAuth builds a resolver-usable credential snapshot: compiled
// verifiers, a known class, and a future expiry are all required for it to
// survive resolveAPIBinds.
func webmgmtTestAuth(t *testing.T) *config.APIAuthConfig {
	t.Helper()
	verifier, err := config.HashAPIAuthSecret("0123456789abcdef-webmgmt-test")
	if err != nil {
		t.Fatalf("HashAPIAuthSecret: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	return &config.APIAuthConfig{
		DefaultClass:     "read-only",
		DefaultExpiresAt: expires,
		Users: []*config.APIAuthUser{{
			Username:  "admin",
			Password:  config.Secret(verifier),
			Class:     "read-only",
			ExpiresAt: expires,
		}},
	}
}

// webmgmtCfg builds a web-management config for the requested bind legs. When
// withAuth is true, it supplies a usable credential; resolveAPIBinds disables
// the clear HTTP leg in that case and retains the authenticated HTTPS bind.
func webmgmtCfg(t *testing.T, http, https bool, iface string, withAuth bool) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	wm := &config.WebManagementConfig{}
	if http {
		wm.HTTP = true
		wm.HTTPInterface = iface
	}
	if https {
		wm.HTTPS = true
		wm.HTTPSInterface = iface
	}
	if withAuth {
		wm.APIAuth = webmgmtTestAuth(t)
	}
	cfg.System.Services = &config.SystemServicesConfig{WebManagement: wm}
	return cfg
}

// TestWebMgmtListenerMatchesHostInboundAdmit_5715 is the load-bearing #5715
// contract test.
//
// FAIL-ON-REVERT: restore the old listener port (bind 8080/8443 instead of the
// webmgmt SSOT 80/443) and the derived listener port no longer equals the
// host-inbound admit port — every assertion below goes RED. Likewise, changing
// only the catalog (config.HostInboundServiceMatch) breaks the equality.
func TestWebMgmtListenerMatchesHostInboundAdmit_5715(t *testing.T) {
	// The test uses no credentials: the non-loopback addresses are correctly
	// clamped, but the canonical HTTP/HTTPS ports must remain 80/443.
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		if kernelName == "ge-0-0-0" {
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)}}, nil
		}
		return nil, nil
	}

	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, webmgmtCfg(t, true, true, "ge-0/0/0.0", false))

	httpBind := listenerPort(t, apiCfg.Addr)
	httpsBind := listenerPort(t, apiCfg.HTTPSAddr)

	// (1) listener == catalog admit, per family, for http and https.
	for _, fam := range []string{"ip", "ip6"} {
		if admit := hostInboundTCPPort(t, "http", fam); httpBind != admit {
			t.Errorf("[%s] HTTP listener binds :%d but host-inbound admits :%d — contract broken", fam, httpBind, admit)
		}
		if admit := hostInboundTCPPort(t, "https", fam); httpsBind != admit {
			t.Errorf("[%s] HTTPS listener binds :%d but host-inbound admits :%d — contract broken", fam, httpsBind, admit)
		}
	}
	// (2) both sides equal the webmgmt SSOT constants.
	if httpBind != webmgmt.HTTPPort {
		t.Errorf("HTTP listener :%d != webmgmt.HTTPPort %d", httpBind, webmgmt.HTTPPort)
	}
	if httpsBind != webmgmt.HTTPSPort {
		t.Errorf("HTTPS listener :%d != webmgmt.HTTPSPort %d", httpsBind, webmgmt.HTTPSPort)
	}
	// (3) the webapi-* aliases share the same admit ports (they are web-mgmt).
	if p := hostInboundTCPPort(t, "webapi-clear-text", "ip"); p != webmgmt.HTTPPort {
		t.Errorf("webapi-clear-text admits :%d, want %d", p, webmgmt.HTTPPort)
	}
	if p := hostInboundTCPPort(t, "webapi-ssl", "ip"); p != webmgmt.HTTPSPort {
		t.Errorf("webapi-ssl admits :%d, want %d", p, webmgmt.HTTPSPort)
	}
	// (4) negative control: the OLD listener ports are NOT what the catalog
	// admits (a lifeline guard — 8080/8443 must not be silently admitted).
	if webmgmt.HTTPPort == 8080 || webmgmt.HTTPSPort == 8443 {
		t.Fatalf("canonical ports regressed to the pre-#5715 8080/8443")
	}
}

// TestWebMgmtBindPortSelection_5715 pins the resolveAPIBinds port-selection
// cases the #5715 research spec enumerates: HTTP-only, HTTPS-only, both (v4/v6),
// no-stanza (diagnostic default retained), and api-auth-only (not moved to 80).
func TestWebMgmtBindPortSelection_5715(t *testing.T) {
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		switch kernelName {
		case "ge-0-0-0":
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)}}, nil
		case "ge-0-0-1":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)}}, nil
		}
		return nil, nil
	}

	t.Run("http-only binds 80", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, webmgmtCfg(t, true, false, "ge-0/0/0.0", false))
		if apiCfg.Addr != "127.0.0.1:80" {
			t.Errorf("http-only Addr = %q, want loopback with canonical port 80", apiCfg.Addr)
		}
		if apiCfg.TLS {
			t.Errorf("http-only must not enable TLS")
		}
	})

	t.Run("https-only binds 443 and disables clear HTTP when auth is configured", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, webmgmtCfg(t, false, true, "ge-0/0/0.0", true))
		if apiCfg.HTTPSAddr != "10.0.0.5:443" {
			t.Errorf("https-only HTTPSAddr = %q, want 10.0.0.5:443", apiCfg.HTTPSAddr)
		}
		if apiCfg.Addr != "" {
			t.Errorf("api-auth left clear HTTP enabled at %q, want it disabled", apiCfg.Addr)
		}
		if apiCfg.Auth == nil {
			t.Fatal("the valid HTTPS credential was dropped")
		}
	})

	t.Run("ipv6 HTTPS interface binds bracketed 443 with clear HTTP disabled", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, webmgmtCfg(t, false, true, "ge-0/0/1.0", true))
		if apiCfg.Addr != "" {
			t.Errorf("api-auth left clear HTTP enabled at %q, want it disabled", apiCfg.Addr)
		}
		if apiCfg.HTTPSAddr != "[2001:db8::5]:443" {
			t.Errorf("v6 HTTPS Addr = %q, want [2001:db8::5]:443", apiCfg.HTTPSAddr)
		}
	})

	t.Run("no web-management stanza keeps -api-addr default", func(t *testing.T) {
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, &config.Config{})
		if apiCfg.Addr != "127.0.0.1:8080" {
			t.Errorf("no-stanza Addr = %q, want the untouched diagnostic default 127.0.0.1:8080", apiCfg.Addr)
		}
		if apiCfg.TLS {
			t.Errorf("no-stanza must not enable HTTPS")
		}
	})

	t.Run("api-auth-only disables clear HTTP without moving it to port 80", func(t *testing.T) {
		cfg := &config.Config{System: config.SystemConfig{Services: &config.SystemServicesConfig{
			WebManagement: &config.WebManagementConfig{APIAuth: webmgmtTestAuth(t)},
		}}}
		d := &Daemon{}
		apiCfg := api.Config{Addr: "127.0.0.1:8080"}
		d.resolveAPIBinds(&apiCfg, cfg)
		if apiCfg.Addr != "" {
			t.Errorf("api-auth-only block left clear HTTP enabled at %q, want it disabled", apiCfg.Addr)
		}
		if apiCfg.Auth == nil {
			t.Fatal("the valid api-auth-only credential was dropped")
		}
	})
}
