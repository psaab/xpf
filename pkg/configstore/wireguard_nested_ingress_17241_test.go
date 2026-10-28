package configstore

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const nestedAllowedIPsConfig17241 = `interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key 00bedd4ed26623ab2f765d16af2dcba4f6dbe17c284a66c6494b48b823f4c654;
                peer 04d9dab116416940a490d8bab5d0dd921094f0a278dee3db867df8fbd2db6e16 {
                    allowed-ips {
                        10.0.0.0/8 {
                            192.168.0.0/16;
                        }
                    }
                }
            }
        }
    }
}`

const hierarchicalNestedAllowedIPsConfig17241 = `interfaces {
    wg0 {
        tunnel {
            mode wireguard;
            wireguard {
                listen-port 51820;
                private-key 00bedd4ed26623ab2f765d16af2dcba4f6dbe17c284a66c6494b48b823f4c654;
                peer {
                    04d9dab116416940a490d8bab5d0dd921094f0a278dee3db867df8fbd2db6e16 {
                        allowed-ips {
                            10.0.0.0/8 {
                                192.168.0.0/16;
                            }
                        }
                    }
                }
            }
        }
    }
}`

func parseNestedAllowedIPs17241(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(nestedAllowedIPsConfig17241).Parse()
	if len(errs) > 0 {
		t.Fatalf("nested allowed-ips fixture must parse: %v", errs[0])
	}
	return tree
}

func assertNestedAllowedIPsRefused17241(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("lenient ingress accepted nested allowed-ips; it would install a truncated config")
	}
	if !strings.Contains(err.Error(), "allowed-ips") || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("error must identify the nested allowed-ips refusal, got: %v", err)
	}
}

// Store.Load must refuse a previously persisted nested allowed-ips value
// rather than install a config whose nested prefix is silently dropped.
func TestLoadRefusesNestedAllowedIPs17241(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(parseNestedAllowedIPs17241(t), true); err != nil {
		t.Fatalf("persist nested allowed-ips fixture: %v", err)
	}

	booted := newTestStoreAt(t, path)
	err := booted.Load()
	assertNestedAllowedIPsRefused17241(t, err)
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Store.Load nested refusal must retain ErrConfigCompile classification, got: %v", err)
	}
	if cfg := booted.ActiveConfig(); cfg != nil {
		t.Fatalf("Store.Load installed a compiled config after refusing nested allowed-ips: %+v", cfg.Interfaces)
	}
}

// SyncApply must reject the same nested value before replacing active state.
func TestSyncApplyRefusesNestedAllowedIPs17241(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	baseline, err := s.SyncApply(`system { host-name baseline; }`, nil)
	if err != nil || baseline == nil {
		t.Fatalf("install control baseline: cfg=%v err=%v", baseline, err)
	}
	beforeSet := s.ShowActiveSet()
	beforeConfig := s.ActiveConfig()

	cfg, err := s.SyncApply(nestedAllowedIPsConfig17241, nil)
	assertNestedAllowedIPsRefused17241(t, err)
	if cfg != nil {
		t.Fatalf("SyncApply returned a compiled config after refusing nested allowed-ips: %+v", cfg.Interfaces)
	}
	if got := s.ActiveConfig(); got != beforeConfig {
		t.Fatalf("SyncApply replaced the active compiled config on refusal: before=%p after=%p", beforeConfig, got)
	}
	if got := s.ShowActiveSet(); got != beforeSet {
		t.Fatalf("SyncApply changed active config on refusal:\nbefore:\n%s\nafter:\n%s", beforeSet, got)
	}
}

// A tolerated non-typed schema error before the WireGuard stanza must not stop
// the collect walk from finding a later nested-list hard refusal.
func TestSyncApplyDoesNotLetPriorSchemaErrorHideNestedRefusal17241(t *testing.T) {
	const priorSchemaError = `security {
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  address-book {
   address local 10.0.0.9/32;
   adress-set grp { address local; }
  }
 } security-zone untrust; }
}`
	text := priorSchemaError + "\n" + hierarchicalNestedAllowedIPsConfig17241
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	tree, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("combined fixture must parse: %v", parseErrs[0])
	}
	firstErr := s.schemaValidateExpandedTree(tree)
	if firstErr == nil || config.IsTypedLeafSchemaError(firstErr) ||
		config.IsNestedListContentSchemaError(firstErr) || !strings.Contains(firstErr.Error(), "adress-set") {
		t.Fatalf("fixture must begin with a non-typed schema error on adress-set, got: %v", firstErr)
	}

	baseline, err := s.SyncApply(`system { host-name baseline; }`, nil)
	if err != nil || baseline == nil {
		t.Fatalf("install control baseline: cfg=%v err=%v", baseline, err)
	}
	cfg, err := s.SyncApply(text, nil)
	assertNestedAllowedIPsRefused17241(t, err)
	if err == nil || !strings.Contains(err.Error(), "adress-set") {
		t.Fatalf("reported error set must preserve the early adress-set schema error beside the nested refusal, got: %v", err)
	}
	if !config.IsNestedListContentSchemaError(err) {
		t.Fatalf("reported error set must classify as the nested-list refusal, got: %v", err)
	}
	if cfg != nil || s.ActiveConfig() != baseline {
		t.Fatalf("prior schema error must not hide nested refusal or replace active config: cfg=%v active=%p baseline=%p",
			cfg, s.ActiveConfig(), baseline)
	}
}

// The collect-all typed-leaf limit must not hide a later nested-list refusal.
func TestSyncApplyRefusesNestedAllowedIPsBeyondTypedErrorCap17241(t *testing.T) {
	var content strings.Builder
	content.WriteString("class-of-service { schedulers {")
	for i := range config.MaxCollectedTypedLeafViolations16012 + 1 {
		content.WriteString(fmt.Sprintf(" scheduler-%d { transmit-rate asd; }", i))
	}
	content.WriteString(" } }\n")
	content.WriteString(hierarchicalNestedAllowedIPsConfig17241)

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	baseline, err := s.SyncApply(`system { host-name baseline; }`, nil)
	if err != nil || baseline == nil {
		t.Fatalf("install control baseline: cfg=%v err=%v", baseline, err)
	}
	cfg, err := s.SyncApply(content.String(), nil)
	assertNestedAllowedIPsRefused17241(t, err)
	if cfg != nil || s.ActiveConfig() != baseline {
		t.Fatalf("over-cap SyncApply refusal must leave the baseline active: cfg=%v active=%p baseline=%p",
			cfg, s.ActiveConfig(), baseline)
	}
}

// The hard refusal is narrowly scoped: other typed-leaf schema errors still
// follow the existing tolerant-ingress policy.
func TestLenientIngressStillToleratesOtherTypedLeafErrors17241(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`class-of-service {
    schedulers {
        be {
            transmit-rate asd;
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("lenient ingress must continue tolerating unrelated typed-leaf errors: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config for a tolerated unrelated typed-leaf error")
	}
	for _, warning := range cfg.Warnings {
		if strings.HasPrefix(warning, config.ToleratedTypedLeafWarningPrefix+" ") {
			return
		}
	}
	t.Fatalf("tolerated unrelated typed-leaf error must remain visible as a warning: %v", cfg.Warnings)
}
