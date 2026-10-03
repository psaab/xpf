package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestUnknownEnforcementZoneChildIsAbsentFromPublishedRows11575(t *testing.T) {
	text := `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 screen { ids-option safe { tcp { land; } } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  screen safe;
  screeen;
 } }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse config: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}

	oldBuildLinkSnapshot := buildLinkSnapshot
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 27, 1500, "02:00:00:00:00:27", nil
	}
	t.Cleanup(func() { buildLinkSnapshot = oldBuildLinkSnapshot })

	rows := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	foundUnit := false
	for _, row := range rows {
		if row.Name != "ge-0/0/0.0" {
			continue
		}
		foundUnit = true
		if row.Zone != "" {
			t.Fatalf("unbound zone leaked into InterfaceSnapshot: %+v", row)
		}
	}
	if !foundUnit {
		t.Fatalf("configured unit absent from interface rows: %+v", rows)
	}
	if screenRows := buildScreenSnapshots(cfg); len(screenRows) != 0 {
		t.Fatalf("poisoned zone published a healthy screen profile: %+v", screenRows)
	}
	if refs := buildScreenMissingProfileRefs(cfg); len(refs) != 0 {
		t.Fatalf("poisoned zone claimed a missing-profile state instead of no binding: %+v", refs)
	}
}
