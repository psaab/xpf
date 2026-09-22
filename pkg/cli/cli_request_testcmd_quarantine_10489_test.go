package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func quarantineTestZoneCLI10489(t *testing.T) *CLI {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(`security {
    zones {
        security-zone z174 { interfaces { ge-0/0/0.0; } }
        security-zone z214 { interfaces { ge-0/0/1.0; } }
    }
}`, nil); err != nil {
		t.Fatalf("SyncApply colliding zones: %v", err)
	}
	return &CLI{store: store}
}

func TestTestSecurityZoneQualifiesQuarantined10489(t *testing.T) {
	c := quarantineTestZoneCLI10489(t)
	out := captureStdout(t, func() {
		if err := c.testSecurityZone([]string{"interface", "ge-0/0/1.0"}); err != nil {
			t.Fatalf("testSecurityZone loser: %v", err)
		}
	})
	want := config.ZoneQuarantineTestZoneQualifierFor(config.StableZoneID("z214"), "z174")
	if !strings.Contains(out, "belongs to zone: z214") || !strings.Contains(out, want) {
		t.Fatalf("quarantined test-zone match missing qualifier %q:\n%s", want, out)
	}
	survivorOut := captureStdout(t, func() {
		if err := c.testSecurityZone([]string{"interface", "ge-0/0/0.0"}); err != nil {
			t.Fatalf("testSecurityZone survivor: %v", err)
		}
	})
	if strings.Contains(survivorOut, "quarantined") {
		t.Fatalf("survivor test-zone match falsely qualified:\n%s", survivorOut)
	}
}

func TestTestSecurityZoneSortedAndNilSafe10489(t *testing.T) {
	c := quarantineTestZoneCLI10489(t)
	cfg := c.store.ActiveConfig()
	cfg.Security.Zones["z214"].Interfaces = append(cfg.Security.Zones["z214"].Interfaces, "ge-0/0/0.0")
	cfg.Security.Zones["nilzone"] = nil
	for i := 0; i < 20; i++ {
		out := captureStdout(t, func() {
			if err := c.testSecurityZone([]string{"interface", "ge-0/0/0.0"}); err != nil {
				t.Fatalf("testSecurityZone duplicate: %v", err)
			}
		})
		if !strings.Contains(out, "belongs to zone: z174") {
			t.Fatalf("duplicate interface resolved nondeterministically (want sorted-first z174):\n%s", out)
		}
	}
}
