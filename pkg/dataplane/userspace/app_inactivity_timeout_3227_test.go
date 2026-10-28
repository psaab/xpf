package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3227 — a custom application's `inactivity-timeout` must ride the userspace
// PolicyApplicationSnapshot so the dataplane can stamp it on the admitted
// session and the helper's expiry ages the session out on the app's idle timeout
// instead of the global per-protocol timeout. The legacy (retired-eBPF) map
// compiler wired the same per-app `appTimeout`, so this closes a userspace
// parity regression.

func appTimeoutCfg(apps map[string]*config.Application) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Applications.Applications = apps
	return cfg
}

func TestAppInactivityTimeoutCarriedToSnapshot(t *testing.T) {
	cfg := appTimeoutCfg(map[string]*config.Application{
		"short-web": {
			Name:              "short-web",
			Protocol:          "tcp",
			DestinationPort:   "443",
			InactivityTimeout: 30,
		},
	})
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"short-web"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(short-web) ok=false, want true")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].InactivityTimeout != 30 {
		t.Fatalf("short-web InactivityTimeout = %d, want 30", terms[0].InactivityTimeout)
	}
}

func TestAppNoInactivityTimeoutDefaultsToZero(t *testing.T) {
	// An application without an inactivity-timeout must carry 0 (the
	// use-global-timeout sentinel) — byte-identical to pre-#3227.
	cfg := appTimeoutCfg(map[string]*config.Application{
		"plain-web": {Name: "plain-web", Protocol: "tcp", DestinationPort: "80"},
	})
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"plain-web"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(plain-web) ok=false, want true")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].InactivityTimeout != 0 {
		t.Fatalf("plain-web InactivityTimeout = %d, want 0 (use-global sentinel)", terms[0].InactivityTimeout)
	}
	// And with the omitempty tag, a zero timeout must NOT appear on the wire,
	// keeping the snapshot byte-identical for the back-compat case.
	b, err := json.Marshal(terms[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m["inactivity_timeout"]; present {
		t.Fatalf("inactivity_timeout present on wire for a zero timeout: %s", b)
	}
}

// A clamped negative configured value collapses to 0 (use-global), never wraps.
func TestAppInactivityTimeoutNegativeClampsToZero(t *testing.T) {
	cfg := appTimeoutCfg(map[string]*config.Application{
		"weird": {Name: "weird", Protocol: "udp", DestinationPort: "53", InactivityTimeout: -5},
	})
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"weird"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(weird) ok=false, want true")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].InactivityTimeout != 0 {
		t.Fatalf("weird InactivityTimeout = %d, want 0 (clamped)", terms[0].InactivityTimeout)
	}
}
