package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9801, #9831: group expansion of zones written as leaves, through the strict
// commit gate and the lenient compile the boot and HA-sync loaders use.
func TestGroupMergeOfLeafZonesAtCommit9801(t *testing.T) {
	lenientJSON := func(t *testing.T, text string) string {
		t.Helper()
		tree, perrs := config.NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient: %v", err)
		}
		b, _ := json.Marshal(cfg.Security.Zones)
		return string(b)
	}
	t.Run("9801 screen group into a leaf zone", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone <*> { screen edge; } } } } } apply-groups G; security { screen { ids-option edge { icmp { ping-death; } } } zones { security-zone trust; } }`
		if _, err := CheckText(text, -1); err != nil {
			t.Errorf("strict: want a commit, got %v (#9801)", err)
		}
		if js := lenientJSON(t, text); !strings.Contains(js, `"ScreenProfile":"edge"`) {
			t.Errorf("lenient: zone trust lacks the group's screen: %s (#9801)", js)
		}
	})
	t.Run("9831 group zone beside an inline leaf zone", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone zga; } } } } apply-groups G; security { zones { security-zone trust; } }`
		if _, err := CheckText(text, -1); err != nil {
			t.Errorf("strict: want a commit, got %v (#9831)", err)
		}
		if js := lenientJSON(t, text); !strings.Contains(js, `"zga":{"Name":"zga"`) {
			t.Errorf("lenient: the group's zone zga is missing: %s (#9831)", js)
		}
	})
	t.Run("9831 group zone list beside an inline leaf zone is refused", func(t *testing.T) {
		const text = `groups { G { security { zones { security-zone [ zga zgb ]; } } } } apply-groups G; security { zones { security-zone trust; } }`
		const want = `only zone "zga" compiles, and "zgb" is dropped`
		if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("strict: want the #9656 refusal containing %q once the group's statement survives expansion, got %v (#9831)", want, err)
		}
	})
}
