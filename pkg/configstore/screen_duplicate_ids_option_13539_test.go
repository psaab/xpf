package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const duplicateScreenIDsOption13539 = `security {
    screen {
        ids-option untrust-screen {
            tcp {
                land;
            }
        }
        ids-option untrust-screen {
            icmp {
                ping-death;
            }
        }
    }
}`

// #13539 acceptance: duplicate named screen profiles are rejected for a new
// operator commit, but tolerated with a warning on legacy/peer config ingress
// (#1960). Exercise configstore.CheckText, SyncApply, and a real Store.Load
// from persisted state rather than only the compiler's unit-level validators.
func TestDuplicateScreenIDsOptionIngress13539(t *testing.T) {
	if _, err := CheckText(duplicateScreenIDsOption13539, -1); err == nil ||
		!strings.Contains(err.Error(), "ids-option") ||
		!strings.Contains(err.Error(), "untrust-screen") {
		t.Fatalf("strict CheckText error = %v; want duplicate ids-option rejection", err)
	}

	path := filepath.Join(t.TempDir(), "config")
	peer := newTestStoreAt(t, path)
	compiled, err := peer.SyncApply(duplicateScreenIDsOption13539, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate an already-existing duplicate profile: %v", err)
	}
	assertDuplicateScreenWarning13539(t, compiled.Warnings)
	assertLastScreenProfile13539(t, compiled.Security.Screen["untrust-screen"])

	boot := newTestStoreAt(t, path)
	if err := boot.Load(); err != nil {
		t.Fatalf("Store.Load must boot the persisted duplicate profile: %v", err)
	}
	if boot.compiled == nil {
		t.Fatal("Store.Load left the compiled config nil")
	}
	assertDuplicateScreenWarning13539(t, boot.compiled.Warnings)
	assertLastScreenProfile13539(t, boot.compiled.Security.Screen["untrust-screen"])
}

func assertDuplicateScreenWarning13539(t *testing.T, warnings []string) {
	t.Helper()
	for _, warning := range warnings {
		if strings.Contains(warning, "ids-option") &&
			strings.Contains(warning, "untrust-screen") &&
			strings.Contains(warning, "5180") {
			return
		}
	}
	t.Fatalf("missing #5180 duplicate ids-option warning: %v", warnings)
}

func assertLastScreenProfile13539(t *testing.T, profile *config.ScreenProfile) {
	t.Helper()
	if profile == nil {
		t.Fatal("surviving screen profile missing")
	}
	// The tolerant path intentionally retains historical map-overwrite
	// behavior; the diagnostic, not a runtime semantic change, is the safety
	// contract for an already-persisted duplicate.
	if !profile.ICMP.PingDeath || profile.TCP.Land {
		t.Fatalf("tolerant profile should retain only the second ids-option block; got %+v", profile)
	}
}
