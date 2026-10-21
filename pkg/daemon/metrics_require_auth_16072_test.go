package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
)

// metrics_require_auth_16072_test.go pins the #16072 daemon wiring:
// resolveAPIBinds stamps the gate into both the AuthConfig snapshot and the
// api.Config, and the management reconciler publishes a gate-only toggle
// through ReplaceMetricsRequireAuth (addition immediate, removal only once
// every live leg is named by the committed config).
//
// FAIL-ON-REVERT: dropping the resolveAPIBinds stamp makes Auth nil-flagged;
// dropping the reconcile publish makes the LiveAuth assertions fail.

func TestResolveAPIBindsStampsMetricsGate16072(t *testing.T) {
	password, err := config.HashAPIAuthSecret("0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	mk := func(gate bool) *config.Config {
		cfg := &config.Config{}
		cfg.System.Services = &config.SystemServicesConfig{
			WebManagement: &config.WebManagementConfig{
				HTTPS: true,
				APIAuth: &config.APIAuthConfig{
					DefaultClass:       "read-only",
					DefaultExpiresAt:   expires,
					MetricsRequireAuth: gate,
					Users: []*config.APIAuthUser{{
						Username:  "admin",
						Password:  config.NewSecret(password),
						Class:     "read-only",
						ExpiresAt: expires,
					}},
				},
			},
		}
		return cfg
	}

	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, mk(true))
	if apiCfg.Auth == nil || !apiCfg.Auth.MetricsRequireAuth {
		t.Fatalf("Auth gate = %+v, want MetricsRequireAuth stamped into the snapshot", apiCfg.Auth)
	}
	if !apiCfg.MetricsRequireAuth {
		t.Fatal("api.Config.MetricsRequireAuth not stamped by resolveAPIBinds")
	}

	apiCfg2 := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg2, mk(false))
	if apiCfg2.Auth == nil || apiCfg2.Auth.MetricsRequireAuth || apiCfg2.MetricsRequireAuth {
		t.Fatalf("gate leaked without the leaf: Auth=%+v Cfg=%v", apiCfg2.Auth, apiCfg2.MetricsRequireAuth)
	}
}

// TestResolveAPIBindsGateSurvivesExpiredCredentials16072 is the fold
// witness at the daemon/API boundary: a gated config whose only
// credential has expired (ordinary lifecycle: bounded expiries, restart
// or re-apply after expiry) must keep the gate intent in
// api.Config.MetricsRequireAuth even though Auth is nil, and a server
// built from that config must fail /metrics closed while /health stays
// open.
//
// FAIL-ON-REVERT: stamping the Cfg-level gate only inside the
// usable-credential branch makes apiCfg.MetricsRequireAuth false here
// and the served /metrics returns 200.
func TestResolveAPIBindsGateSurvivesExpiredCredentials16072(t *testing.T) {
	password, err := config.HashAPIAuthSecret("0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Hour)
	cfg := &config.Config{}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			HTTPS: true,
			APIAuth: &config.APIAuthConfig{
				DefaultClass:       "read-only",
				DefaultExpiresAt:   expired,
				MetricsRequireAuth: true,
				Users: []*config.APIAuthUser{{
					Username:  "admin",
					Password:  config.NewSecret(password),
					Class:     "read-only",
					ExpiresAt: expired,
				}},
			},
		},
	}
	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, cfg)
	if apiCfg.Auth != nil {
		t.Fatalf("Auth = %+v, want nil (the only credential expired)", apiCfg.Auth)
	}
	if !apiCfg.MetricsRequireAuth {
		t.Fatal("gate intent was nil-dropped with the expired credential; /metrics would reopen")
	}
	if !apiCfg.TLS {
		t.Fatal("HTTPS leg lost while resolving the expired-credential config")
	}

	// End to end: the resolved config carries Auth=nil + gate on; a
	// server built from exactly that shape must retain the intent
	// (the served 401 half is pinned in pkg/api by
	// TestLoopbackMetricsGateSurvivesCredentialLoss16072).
	srv := api.NewServer(apiCfg)
	if !srv.MetricsGate() {
		t.Fatal("server dropped the gate intent from a nil-Auth resolved config; /metrics would reopen")
	}
	if srv.LiveAuth() != nil {
		t.Fatalf("LiveAuth = %+v, want nil for the expired-credential config", srv.LiveAuth())
	}
}

func TestMgmtMetricsGateOnlyToggle16072(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	creds := func() *api.AuthConfig {
		return &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	}
	boot := cfgFor(reg, "127.0.0.1:8080", false, "", creds())
	if err := m.startTo(ctx, boot); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if m.srv.LiveAuth() == nil || m.srv.LiveAuth().MetricsRequireAuth {
		t.Fatalf("boot LiveAuth = %+v, want ungated credentials", m.srv.LiveAuth())
	}

	// Gate-only ADDITION (same endpoint, same credentials): a tightening,
	// published by the same reconcile with no rebind.
	gated := cfgFor(reg, "127.0.0.1:8080", false, "", creds())
	gated.MetricsRequireAuth = true
	if err := m.reconcileTo(gated); err != nil {
		t.Fatalf("gate-add reconcile: %v", err)
	}
	if !m.srv.LiveAuth().MetricsRequireAuth || !m.srv.MetricsGate() {
		t.Fatal("gate-only addition was not published to the live snapshot/intent")
	}
	if m.cur.addr != "127.0.0.1:8080" {
		t.Fatalf("gate toggle rebound the listener: cur=%q", m.cur.addr)
	}

	// Gate-only REMOVAL on the converged endpoint: a loosening, published
	// once every live leg is named by the committed config (it is).
	ungated := cfgFor(reg, "127.0.0.1:8080", false, "", creds())
	if err := m.reconcileTo(ungated); err != nil {
		t.Fatalf("gate-remove reconcile: %v", err)
	}
	if m.srv.LiveAuth().MetricsRequireAuth || m.srv.MetricsGate() {
		t.Fatal("gate-only removal was not published on the converged endpoint")
	}

	// Fold witness at the reconciler: gate on with NO credentials at all
	// (every credential filtered) still publishes the intent, and its
	// removal still lands — neither is nil-dropped with the snapshot.
	gatedNil := cfgFor(reg, "127.0.0.1:8080", false, "", nil)
	gatedNil.MetricsRequireAuth = true
	if err := m.reconcileTo(gatedNil); err != nil {
		t.Fatalf("gate-add nil-auth reconcile: %v", err)
	}
	if !m.srv.MetricsGate() {
		t.Fatal("gate intent was nil-dropped when the credential snapshot went nil")
	}
	ungatedNil := cfgFor(reg, "127.0.0.1:8080", false, "", nil)
	if err := m.reconcileTo(ungatedNil); err != nil {
		t.Fatalf("gate-remove nil-auth reconcile: %v", err)
	}
	if m.srv.MetricsGate() {
		t.Fatal("gate removal was not published with a nil credential snapshot")
	}
}
