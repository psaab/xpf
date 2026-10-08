package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12223 — FAIL-ON-REVERT: `any` must not short-circuit the validation of its
// siblings in a `match application` list. A defined application whose match the
// tolerant path partly dropped (here: a destination-port on icmp, which never
// matches, so the expansion refuses the reference) must poison the rule whether
// it is listed before or after `any`. Pre-fix [any, icmp-port] armed as
// match-any while [icmp-port, any] poisoned with the __unsupported__ sentinel.
func applAnyOrderCfg12223(apps []string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{
		"icmp-port": {Name: "icmp-port", Protocol: "icmp", DestinationPort: "80"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "p",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         apps,
			},
			Action: config.PolicyPermit,
		}},
	}}
	return cfg
}

func applAnyOrderLenientCfg12223(t *testing.T, apps []string) *config.Config {
	t.Helper()
	return lenientHier9571(t, policyText9525(
		`application icmp-port { protocol icmp; destination-port 80; }`,
		"["+strings.Join(apps, " ")+"]", "permit", "deny-all"))
}

func TestApplAnyListValidationIsOrderInsensitive12223(t *testing.T) {
	for _, apps := range [][]string{{"any", "icmp-port"}, {"icmp-port", "any"}} {
		cfg := applAnyOrderLenientCfg12223(t, apps)
		terms := wireTerms9525(t, cfg)
		if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
			t.Fatalf("apps=%v: the policy must lower to the __unsupported__ sentinel alone; wire terms: %+v", apps, terms)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) != 1 || !strings.Contains(reasons[0], `application "icmp-port"`) {
			t.Fatalf("apps=%v: want one mirror reason naming application \"icmp-port\"; got %q", apps, reasons)
		}
	}
}

// The [any, <nonexistent>] control: an undefined name stays the legacy
// compileApplications catalog prepass's to reject (application %q not found),
// so the lowerer keeps honoring `any` and must neither poison nor refuse.
func TestApplAnyBesideUnknownNameStaysMatchAll12223(t *testing.T) {
	cfg := applAnyOrderCfg12223([]string{"any", "no-such-app"})
	terms := wireTerms9525(t, cfg)
	if len(terms) != 0 {
		t.Fatalf("[any, no-such-app] must stay match-any; wire terms: %+v", terms)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("[any, no-such-app] must not be refused; reasons %q", reasons)
	}
}
