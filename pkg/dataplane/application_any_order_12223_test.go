package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12223 control: the application-list lowerer treats `any` as a wildcard,
// but the legacy compileApplications catalog prepass still rejects an
// accompanying undefined name rather than hiding it.
func TestCompileApplicationsRejectsUnknownBesideAny12223(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "p",
			Match: config.PolicyMatch{
				Applications: []string{"any", "no-such-app-12223"},
			},
			Action: config.PolicyPermit,
		}},
	}}

	err := compileApplications(discardingDataPlane{}, cfg, newValidationResult())
	if err == nil || !strings.Contains(err.Error(), `application "no-such-app-12223" not found`) {
		t.Fatalf("compileApplications error = %v, want missing-app prepass rejection", err)
	}
}
