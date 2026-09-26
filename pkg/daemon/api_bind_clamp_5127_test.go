package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
)

// TestResolveAPIBindsClampsWithoutWebManagement pins the #5127 fix: the #4047
// loopback fail-safe must clamp a non-loopback bind even when NO `system
// services web-management` stanza exists — the plain `--api-addr` path. Before
// the fix the clamp lived INSIDE the web-management block, so a config with no
// web-management (or a nil active config) skipped the clamp and bound the
// mutating REST/config API off-loopback UNAUTHENTICATED. resolveAPIBinds now
// runs the clamp on every path; reverting it (clamp back inside the
// web-management block) makes the no-web-management cases below FAIL.
func TestResolveAPIBindsClampsWithoutWebManagement(t *testing.T) {
	d := &Daemon{}
	cases := []struct {
		name     string
		cfg      *config.Config
		inAddr   string
		wantAddr string
	}{
		{"nil config off-loopback wildcard clamps", nil, "0.0.0.0:8080", "127.0.0.1:8080"},
		{"nil config routable v4 clamps", nil, "10.0.0.5:8080", "127.0.0.1:8080"},
		{"empty config (no web-management) clamps", &config.Config{}, "192.168.1.1:8080", "127.0.0.1:8080"},
		{"empty config v6 off-loopback clamps to v6 loopback", &config.Config{}, "[2001:db8::1]:8080", "[::1]:8080"},
		{"nil config default loopback untouched", nil, "127.0.0.1:8080", "127.0.0.1:8080"},
		{"empty config v6 loopback untouched", &config.Config{}, "[::1]:8080", "[::1]:8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			apiCfg := api.Config{Addr: c.inAddr}
			d.resolveAPIBinds(&apiCfg, c.cfg)
			if apiCfg.Addr != c.wantAddr {
				t.Fatalf("resolveAPIBinds Addr = %q, want %q", apiCfg.Addr, c.wantAddr)
			}
			if apiCfg.Auth != nil {
				t.Fatalf("Auth = %v, want nil (no web-management config)", apiCfg.Auth)
			}
		})
	}
}

// TestResolveAPIBindsClampsHTTPSWithoutWebManagement pins that the HTTPS
// listener is clamped on the no-web-management path too, so an off-loopback
// TLS bind (set by some future flag / default) cannot serve the mutating API
// unauthenticated either.
func TestResolveAPIBindsClampsHTTPSWithoutWebManagement(t *testing.T) {
	d := &Daemon{}
	apiCfg := api.Config{
		Addr:      "0.0.0.0:8080",
		TLS:       true,
		HTTPSAddr: "0.0.0.0:8443",
	}
	d.resolveAPIBinds(&apiCfg, nil)
	if apiCfg.Addr != "127.0.0.1:8080" {
		t.Fatalf("HTTP Addr = %q, want 127.0.0.1:8080", apiCfg.Addr)
	}
	if apiCfg.HTTPSAddr != "127.0.0.1:8443" {
		t.Fatalf("HTTPS Addr = %q, want 127.0.0.1:8443", apiCfg.HTTPSAddr)
	}
}

// TestResolveAPIBindsRespectsWebManagementAuth pins that an off-loopback bind
// WITH api-auth derived from a web-management stanza is preserved
// (authenticated off-loopback is allowed). It guards that the now-unconditional
// clamp still derives + respects web-management api-auth, and that the
// extraction of resolveAPIBinds kept the auth-derivation intact.
func TestResolveAPIBindsRespectsWebManagementAuth(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			APIAuth: &config.APIAuthConfig{
				Users: []*config.APIAuthUser{{Username: "admin", Password: config.Secret("secret")}},
			},
		},
	}
	apiCfg := api.Config{Addr: "10.0.0.5:8080"}
	d.resolveAPIBinds(&apiCfg, cfg)
	if apiCfg.Addr != "10.0.0.5:8080" {
		t.Fatalf("authenticated off-loopback Addr = %q, want it preserved", apiCfg.Addr)
	}
	if apiCfg.Auth == nil || apiCfg.Auth.Users["admin"] != "secret" {
		t.Fatalf("Auth = %+v, want derived from web-management api-auth", apiCfg.Auth)
	}
}

func TestResolveAPIBindsCarriesCustomTLSPaths(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			HTTPS:          true,
			TLSCertificate: "/etc/xpf/tls/management-chain.pem",
			TLSPrivateKey:  "/etc/xpf/tls/management-key.pem",
		},
	}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, cfg)
	if !apiCfg.TLS || apiCfg.TLSCertificate != cfg.System.Services.WebManagement.TLSCertificate ||
		apiCfg.TLSPrivateKey != cfg.System.Services.WebManagement.TLSPrivateKey {
		t.Fatalf("resolved TLS config = %+v, want the configured custom certificate/key paths", apiCfg)
	}
}
