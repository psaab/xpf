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
		name            string
		fromZone        string
		wantRecord      string
		wantDestination string
	}{
		{"S9-direct-nested", `from-zone A { to-zone B { ` + deny + ` } }`, `from-zone "A"`, `to-zone B`},
		{"S10-mixed-child-keyed-to-zone", `from-zone { A to-zone B { ` + deny + ` } }`, `from-zone { A`, `to-zone B`},
		{"S18-container-to-zone-policy", `from-zone { A { to-zone { ` + deny + ` } } }`, `from-zone "A"`, "`policy policy`"},
		{"S18-keyed-to-zone-policy", `from-zone A { to-zone { ` + deny + ` } }`, `from-zone "A"`, "#12633"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active := loadShape12633(t, securityPolicyShapeText12231(tc.fromZone))
			if len(active.Security.MalformedZonePairs) == 0 {
				t.Fatalf("Store.Load recorded nothing in MalformedZonePairs; dropped deny would fail open (pairs=%v)", active.Security.Policies)
			}
			joined := strings.Join(active.Security.MalformedZonePairs, "\n")
			if !strings.Contains(joined, tc.wantRecord) || !strings.Contains(joined, tc.wantDestination) {
				t.Fatalf("Store.Load MalformedZonePairs %q does not name malformed pair via %q and %q", joined, tc.wantRecord, tc.wantDestination)
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

func TestStoreLoadPoisonsSetCommandPhantomZonePair12633(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security policies from-zone A policy p1 match source-address any",
		"set security policies from-zone A policy p1 match destination-address any",
		"set security policies from-zone A policy p1 match application any",
		"set security policies from-zone A policy p1 then deny",
		"set security policies global policy g-permit match source-address any",
		"set security policies global policy g-permit match destination-address any",
		"set security policies global policy g-permit match application any",
		"set security policies global policy g-permit then permit",
		"set security policies default-policy permit-all",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("write active SET1 config: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Store.Load must remain bootable: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Store.Load")
	}
	joined := strings.Join(active.Security.MalformedZonePairs, "\n")
	if !strings.Contains(joined, `from-zone "A"`) || !strings.Contains(joined, "`policy p1`") {
		t.Fatalf("Store.Load MalformedZonePairs %q does not identify phantom A->p1", joined)
	}
	if got := config.LenientDroppedPolicyLocator(active); got == "" {
		t.Fatal("Store.Load did not retain the SET1 snapshot poison carrier")
	}
	if warnings := strings.Join(active.Warnings, "\n"); !strings.Contains(warnings, "not enforced") || !strings.Contains(warnings, "snapshot is refused") {
		t.Fatalf("Store.Load warning does not surface fail-closed handling: %v", active.Warnings)
	}
	for _, pair := range active.Security.Policies {
		if pair.FromZone == "A" && pair.ToZone == "p1" {
			t.Fatalf("Store.Load installed phantom A->p1 pair: %+v", pair)
		}
	}
}
