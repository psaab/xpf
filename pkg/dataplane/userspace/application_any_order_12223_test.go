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

func applAnyOrderLenientCfg12223(t *testing.T, application string, apps []string) *config.Config {
	t.Helper()
	return lenientHier9571(t, policyText9525(
		application,
		"["+strings.Join(apps, " ")+"]", "permit", "deny-all"))
}

func TestApplAnyListValidationIsOrderInsensitive12223(t *testing.T) {
	for _, apps := range [][]string{{"any", "icmp-port"}, {"icmp-port", "any"}} {
		cfg := applAnyOrderLenientCfg12223(t,
			`application icmp-port { protocol icmp; destination-port 80; }`, apps)
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

func TestApplAnyListRejects2124ClassesInBothOrders12223(t *testing.T) {
	tests := []struct {
		name        string
		application string
	}{
		{"zero destination port", `application bad { protocol tcp; destination-port 0; }`},
		{"out-of-range destination port", `application bad { protocol tcp; destination-port 70000; }`},
		{"inverted destination-port range", `application bad { protocol tcp; destination-port 5000-80; }`},
		{"out-of-range protocol number", `application bad { protocol 999; }`},
		{"unknown protocol name", `application bad { protocol nosuchproto; }`},
	}
	orders := []struct {
		name string
		apps []string
	}{
		{"wildcard first", []string{"any", "bad"}},
		{"application first", []string{"bad", "any"}},
	}
	for _, test := range tests {
		for _, order := range orders {
			t.Run(test.name+"/"+order.name, func(t *testing.T) {
				cfg := applAnyOrderLenientCfg12223(t, test.application, order.apps)
				terms := wireTerms9525(t, cfg)
				if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
					t.Fatalf("apps=%v: want the __unsupported__ sentinel; wire terms: %+v", order.apps, terms)
				}
				reasons := PolicyContentRejectionReasons(cfg, nil)
				if len(reasons) != 1 || !strings.Contains(reasons[0], `application "bad"`) {
					t.Fatalf("apps=%v: want one mirror reason naming application \"bad\"; got %q", order.apps, reasons)
				}
			})
		}
	}
}

// An undefined name is refused by per-reference userspace lowering in either
// order. The compiler prepass independently rejects the same missing name.
func TestApplAnyBesideUnknownNamePoisonsBothOrders12223(t *testing.T) {
	for _, apps := range [][]string{{"any", "no-such-app"}, {"no-such-app", "any"}} {
		cfg := applAnyOrderCfg12223(apps)
		terms := wireTerms9525(t, cfg)
		if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
			t.Fatalf("apps=%v: want the __unsupported__ sentinel; wire terms: %+v", apps, terms)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) != 1 || !strings.Contains(reasons[0], `application "no-such-app"`) {
			t.Fatalf("apps=%v: want one mirror reason naming application \"no-such-app\"; got %q", apps, reasons)
		}
	}
}
func TestApplAnyBesideUnexpandableSetPoisonsBothOrders12223(t *testing.T) {
	for _, apps := range [][]string{{"any", "bad-set"}, {"bad-set", "any"}} {
		cfg := applAnyOrderCfg12223(apps)
		cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
			"bad-set": {Name: "bad-set", Applications: []string{"no-such-member"}},
		}
		terms := wireTerms9525(t, cfg)
		if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
			t.Fatalf("apps=%v: want the __unsupported__ sentinel; wire terms: %+v", apps, terms)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) != 1 || !strings.Contains(reasons[0], `application "bad-set"`) {
			t.Fatalf("apps=%v: want one mirror reason naming application \"bad-set\"; got %q", apps, reasons)
		}
	}
}

func TestApplAnyBesideProtocollessAppPoisonsBothOrders12223(t *testing.T) {
	for _, apps := range [][]string{{"any", "bad"}, {"bad", "any"}} {
		cfg := applAnyOrderCfg12223(apps)
		cfg.Applications.Applications["bad"] = &config.Application{Name: "bad"}
		terms := wireTerms9525(t, cfg)
		if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
			t.Fatalf("apps=%v: want the __unsupported__ sentinel; wire terms: %+v", apps, terms)
		}
		reasons := PolicyContentRejectionReasons(cfg, nil)
		if len(reasons) != 1 || !strings.Contains(reasons[0], `application "bad"`) {
			t.Fatalf("apps=%v: want one mirror reason naming application \"bad\"; got %q", apps, reasons)
		}
	}
}
