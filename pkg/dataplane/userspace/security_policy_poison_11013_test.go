package userspace

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Fail-on-revert through both real tolerant ingress paths: Store.SyncApply and
// Store.Load must retain the poison, and snapshot lowering must not publish any
// of the widened direct permits without the reserved sentinel.
const policyPoisonStoreText11013 = `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
                policy next-term {
                    match { source-address any; destination-address any; application any; }
                    then { permit; next term; }
                }
                policy nested-term {
                    match { source-address any; destination-address any; application any; }
                    then { permit; }
                    term nested {
                        match { source-address 10.0.0.0/8; }
                        then { deny; }
                    }
                }
                policy session-options {
                    match { source-address any; destination-address any; application any; }
                    then { permit; }
                    session-options { inactivity-timeout 60; }
                }
        }
    }
}`

func findPolicyStore11013(t *testing.T, cfg *config.Config, name string) *config.Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol != nil && pol.Name == name {
				return pol
			}
		}
	}
	t.Fatalf("policy %q is missing", name)
	return nil
}

func assertPolicyPoisonSnapshot11013(t *testing.T, cfgWarnings []string, cfgPolicies []*config.Policy, snap *ConfigSnapshot) {
	t.Helper()
	poisoned := map[string]bool{}
	for _, pol := range cfgPolicies {
		if pol != nil && pol.LenientContentDropped {
			poisoned[pol.Name] = true
		}
	}
	for _, name := range []string{"next-term", "nested-term", "session-options"} {
		if !poisoned[name] {
			t.Errorf("policy %q was not marked LenientContentDropped", name)
		}
	}
	foundNextDiagnostic := false
	for _, warning := range cfgWarnings {
		if strings.Contains(warning, "#11013") && strings.Contains(warning, "next term") && strings.Contains(warning, `policy "next-term"`) {
			foundNextDiagnostic = true
		}
	}
	if !foundNextDiagnostic {
		t.Errorf("tolerant ingress has no named unsupported-then diagnostic: %v", cfgWarnings)
	}

	sentinelRules := map[string]bool{}
	for _, rule := range snap.Policies {
		for _, term := range rule.ApplicationTerms {
			if term.Protocol == unsupportedApplicationSentinel || term.Name == unsupportedApplicationSentinel {
				sentinelRules[rule.Name] = true
			}
		}
	}
	for _, name := range []string{"next-term", "nested-term", "session-options"} {
		if !sentinelRules[name] {
			t.Errorf("policy %q lowered without the __unsupported__ sentinel; snapshot would publish its direct permit", name)
		}
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Error("poisoned policies did not produce a snapshot content-rejection reason")
	}
}

func TestStoreSyncApplyAndLoadPoisonDroppedSecurityPolicyContent11013(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	synced := newConfigStore(t, path)
	cfg, err := synced.SyncApply(policyPoisonStoreText11013, nil)
	if err != nil {
		t.Fatalf("SyncApply refused the persisted policy fixture: %v", err)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("build snapshot after SyncApply: %v", err)
	}
	assertPolicyPoisonSnapshot11013(t, cfg.Warnings, []*config.Policy{
		findPolicyStore11013(t, cfg, "next-term"),
		findPolicyStore11013(t, cfg, "nested-term"),
		findPolicyStore11013(t, cfg, "session-options"),
	}, snap)

	booted := newConfigStore(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load refused the config persisted by SyncApply: %v", err)
	}
	loaded := booted.ActiveConfig()
	if loaded == nil {
		t.Fatal("Store.Load left ActiveConfig nil")
	}
	loadedSnap, err := buildSnapshot(loaded, config.UserspaceConfig{}, 2, 0)
	if err != nil {
		t.Fatalf("build snapshot after Store.Load: %v", err)
	}
	assertPolicyPoisonSnapshot11013(t, loaded.Warnings, []*config.Policy{
		findPolicyStore11013(t, loaded, "next-term"),
		findPolicyStore11013(t, loaded, "nested-term"),
		findPolicyStore11013(t, loaded, "session-options"),
	}, loadedSnap)
}
