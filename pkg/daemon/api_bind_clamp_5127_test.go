package daemon

import (
	"testing"
	"time"

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

// TestResolveAPIBindsDisablesClearHTTPWithAPIAuth_10826 pins the two-leg
// transport policy: auth credentials disable the HTTP leg while the configured
// HTTPS leg keeps the same hashed credential snapshot.
func TestResolveAPIBindsDisablesClearHTTPWithAPIAuth_10826(t *testing.T) {
	password, err := config.HashAPIAuthSecret("0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			HTTP:  true,
			HTTPS: true,
			APIAuth: &config.APIAuthConfig{
				DefaultClass:     "read-only",
				DefaultExpiresAt: expires,
				Users: []*config.APIAuthUser{{
					Username:  "admin",
					Password:  config.Secret(password),
					Class:     "read-only",
					ExpiresAt: expires,
				}},
			},
		},
	}
	apiCfg := api.Config{Addr: "10.0.0.5:8080"}
	d.resolveAPIBinds(&apiCfg, cfg)
	if apiCfg.Addr != "" {
		t.Fatalf("clear HTTP address = %q, want disabled when api-auth is configured", apiCfg.Addr)
	}
	if !apiCfg.TLS || apiCfg.HTTPSAddr != "127.0.0.1:443" {
		t.Fatalf("HTTPS leg = (TLS=%v Addr=%q), want configured HTTPS leg retained",
			apiCfg.TLS, apiCfg.HTTPSAddr)
	}
	if apiCfg.Auth == nil || apiCfg.Auth.Users["admin"] != password ||
		apiCfg.Auth.UserClasses["admin"] != "read-only" ||
		!apiCfg.Auth.UserExpires["admin"].Equal(expires) {
		t.Fatalf("Auth = %+v, want the hashed read-only credential derived for HTTPS", apiCfg.Auth)
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
