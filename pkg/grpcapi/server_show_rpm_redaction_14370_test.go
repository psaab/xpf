package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #14370: gRPC ShowText{Topic:"rpm"} rendered live ProbeResult.Target and
// (via writeRPMConfig -> rpm.WriteConfiguredTest) the configured
// test.Target verbatim, while the JSON surface redacts the same target
// via RPMTest.MarshalJSON. "rpm" is a PermView topic (authz_methods.go),
// so any view-only reader received the live credential.

const (
	grpcSecretUserinfo14370 = "TOKEN-USERINFO"
	grpcSecretQuery14370    = "TOKEN-QUERY"
	grpcTarget14370         = "https://user:" + grpcSecretUserinfo14370 + "@host/check?token=" + grpcSecretQuery14370
)

func assertGRPCRPMRedacted14370(t *testing.T, surface, out string) {
	t.Helper()
	for _, secret := range []string{grpcSecretUserinfo14370, grpcSecretQuery14370} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked credential %q:\n%s", surface, secret, out)
		}
	}
	for _, want := range []string{"https://", "host", "/check"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s must still contain %q:\n%s", surface, want, out)
		}
	}
}

func TestShowRPMLiveRedactsTarget14370(t *testing.T) {
	s := &Server{rpmResultsFn: func() []*rpm.ProbeResult {
		return []*rpm.ProbeResult{{
			ProbeName: "p1", TestName: "t1", ProbeType: "http-get",
			Target: grpcTarget14370, LastStatus: "pass",
		}}
	}}
	var buf strings.Builder
	s.showRPM(&buf)
	assertGRPCRPMRedacted14370(t, "gRPC ShowText rpm (live)", buf.String())
}

func TestWriteRPMConfigRedactsTarget14370(t *testing.T) {
	cfg := &config.Config{
		Services: config.ServicesConfig{
			RPM: &config.RPMConfig{
				Probes: map[string]*config.RPMProbe{
					"p1": {
						Name: "p1",
						Tests: map[string]*config.RPMTest{
							"t1": {Name: "t1", ProbeType: "http-get", Target: grpcTarget14370},
						},
					},
				},
			},
		},
	}
	var buf strings.Builder
	writeRPMConfig(&buf, cfg)
	assertGRPCRPMRedacted14370(t, "gRPC ShowText rpm (config-fallback)", buf.String())
}
