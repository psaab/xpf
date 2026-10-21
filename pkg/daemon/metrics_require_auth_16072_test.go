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
						Password:  config.Secret(password),
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
	if !m.srv.LiveAuth().MetricsRequireAuth {
		t.Fatal("gate-only addition was not published to the live snapshot")
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
	if m.srv.LiveAuth().MetricsRequireAuth {
		t.Fatal("gate-only removal was not published on the converged endpoint")
	}
}
