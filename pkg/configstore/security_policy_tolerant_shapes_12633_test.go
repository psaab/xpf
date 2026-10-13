package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func loadShape12633(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse persisted #12633 shape: %v", errs)
	}
	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("write active config: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Store.Load must remain bootable: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Store.Load")
	}
	return active
}

func TestStoreLoadPoisonsTolerantZonePairShapes12633(t *testing.T) {
	deny := `policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`
	for _, tc := range []struct {
		name     string
		fromZone string
		want     string
	}{
		{"S9-direct-nested", `from-zone A { to-zone B { ` + deny + ` } }`, `from-zone "A"`},
		{"S10-mixed-child-keyed-to-zone", `from-zone { A { to-zone B { ` + deny + ` } } }`, "to-zone B"},
		{"S18-container-to-zone-policy", `from-zone { A { to-zone { ` + deny + ` } } }`, "`policy policy`"},
		{"S18-keyed-to-zone-policy", `from-zone A { to-zone { ` + deny + ` } }`, "#12633"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active := loadShape12633(t, securityPolicyShapeText12231(tc.fromZone))
			if len(active.Security.MalformedZonePairs) == 0 {
				t.Fatalf("Store.Load recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", active.Security.Policies)
			}
			if joined := strings.Join(active.Security.MalformedZonePairs, "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("Store.Load MalformedZonePairs %q does not contain %q", joined, tc.want)
			}
			if got := config.LenientDroppedPolicyLocator(active); got == "" {
				t.Fatal("Store.Load did not retain the snapshot poison carrier")
			}
			if warnings := strings.Join(active.Warnings, "\n"); !strings.Contains(warnings, "not enforced") || !strings.Contains(warnings, "snapshot is refused") {
				t.Fatalf("Store.Load warning does not surface fail-closed handling: %v", active.Warnings)
			}
		})
	}
}
