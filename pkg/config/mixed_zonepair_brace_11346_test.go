package config

import (
	"strings"
	"testing"
)

func mixedZonePairBrace11346(addPolicyZone bool) string {
	zones := zones7523
	if addPolicyZone {
		zones = `zones { security-zone trust; security-zone untrust; security-zone policy; }`
	}
	return `security { ` + zones + ` policies {
    from-zone {
        trust {
            to-zone untrust {
                policy p1 { match { source-address any; destination-address any; application any; } then { permit; } }
            }
        }
    }
} }`
}

func TestMixedKeyedZonePairBracesAreRejectedSpecifically11346(t *testing.T) {
	_, err := compileText7523(t, mixedZonePairBrace11346(true))
	if err == nil {
		t.Fatal("the mixed from-zone container / keyed to-zone shape committed as trust->policy with zero policies")
	}
	for _, want := range []string{"mixed zone-pair", "from-zone trust", "to-zone untrust", "zero policies"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Errorf("strict diagnostic %q does not name %q", err, want)
		}
	}
}

func TestMixedKeyedZonePairBracesWarnSpecificallyOnTolerantLoad11346(t *testing.T) {
	for _, tc := range []struct {
		name          string
		addPolicyZone bool
	}{
		{name: "undefined-policy-zone", addPolicyZone: false},
		{name: "defined-policy-zone", addPolicyZone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(mustParseTree7523(t, mixedZonePairBrace11346(tc.addPolicyZone)))
			if err != nil {
				t.Fatalf("tolerant load must preserve boot availability: %v", err)
			}
			for _, want := range []string{"mixed zone-pair", "from-zone trust", "to-zone untrust"} {
				found := false
				for _, warning := range cfg.Warnings {
					if strings.Contains(strings.ToLower(warning), strings.ToLower(want)) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("tolerant warnings do not identify %q; got %v", want, cfg.Warnings)
				}
			}
		})
	}
}

func mustParseTree7523(t *testing.T, src string) *ConfigTree {
	t.Helper()
	p := NewParser(src)
	tree, err := p.Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tree
}
