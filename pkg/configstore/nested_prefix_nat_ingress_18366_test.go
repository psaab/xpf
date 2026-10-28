package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSyncApplyRefusesNestedPrefixAndNATLeaves18366(t *testing.T) {
	cases := []struct {
		name, config, leaf string
	}{
		{
			name: "defined firewall prefix-list reference",
			leaf: "source-prefix-list",
			config: `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
}
firewall {
    family inet {
        filter f {
            term t {
                from {
                    source-prefix-list {
                        pl1 { unexpected { 10.0.0.0/8; } }
                    }
                }
                then accept;
            }
        }
    }
}`,
		},
		{
			name: "NAT source-address",
			leaf: "source-address",
			config: `security {
    zones { security-zone trust; security-zone untrust; }
    nat {
        source {
            rule-set rs {
                from zone trust;
                to zone untrust;
                rule r {
                    match {
                        source-address {
                            10.0.0.0/8 {
                                unexpected { 192.0.2.0/24; }
                            }
                        }
                    }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
			baseline, err := s.SyncApply(`system { host-name baseline; }`, nil)
			if err != nil || baseline == nil {
				t.Fatalf("install control baseline: cfg=%v err=%v", baseline, err)
			}
			beforeSet := s.ShowActiveSet()
			beforeConfig := s.ActiveConfig()

			cfg, err := s.SyncApply(tc.config, nil)
			if err == nil || !config.IsNestedListContentSchemaError(err) {
				t.Fatalf("SyncApply must hard-reject nested content under %s, got cfg=%v err=%v", tc.leaf, cfg, err)
			}
			if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), "nested content") {
				t.Fatalf("nested-content error %q must name %s", err, tc.leaf)
			}
			if cfg != nil {
				t.Fatalf("SyncApply returned a compiled config after refusal: %+v", cfg)
			}
			if got := s.ActiveConfig(); got != beforeConfig {
				t.Fatalf("SyncApply replaced active config after refusal: before=%p after=%p", beforeConfig, got)
			}
			if got := s.ShowActiveSet(); got != beforeSet {
				t.Fatalf("SyncApply changed active config after refusal:\nbefore:\n%s\nafter:\n%s", beforeSet, got)
			}
		})
	}
}
