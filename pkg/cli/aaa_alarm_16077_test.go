package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16077 (MGMT-16): a tolerant AAA tree runs local-only auth; the lenient
// warning previously died with the boot-time log. Both local alarm
// surfaces must list it persistently from the active compiled config.

const aaaAlarmTree16077 = `system {
    host-name fw-aaa;
    radius-server 192.0.2.10 {
        secret aaa-secret-16077;
    }
}`

func TestAAAAlarmReachesLocalAlarmSurfaces16077(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "aaa.conf"))
	if _, err := store.SyncApply(aaaAlarmTree16077, nil); err != nil {
		t.Fatalf("tolerant SyncApply must not brick on AAA tree (#1960): %v", err)
	}
	cfg := store.ActiveConfig()
	alarms := config.UnimplementedAAAWarnings(cfg)
	if len(alarms) != 1 || !strings.Contains(alarms[0], "radius-server") {
		t.Fatalf("active AAA alarms = %v, want one radius-server line", alarms)
	}
	marker := alarms[0]
	if strings.Contains(marker, "aaa-secret-16077") {
		t.Fatalf("alarm leaked the AAA secret: %q", marker)
	}

	c := &CLI{store: store}
	system := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms: %v", err)
		}
	})
	if !strings.Contains(system, marker) || !strings.Contains(system, "1 active alarm(s):") {
		t.Fatalf("show system alarms omitted the AAA alarm %q:\n%s", marker, system)
	}

	detail := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail: %v", err)
		}
	})
	if !strings.Contains(detail, marker) {
		t.Fatalf("show security alarms detail omitted the AAA alarm %q:\n%s", marker, detail)
	}

	brief := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms"}); err != nil {
			t.Fatalf("show security alarms: %v", err)
		}
	})
	if strings.Contains(brief, marker) {
		t.Fatalf("non-detail security alarms leaked detail text:\n%s", brief)
	}
	if !strings.Contains(brief, "1 security alarm(s) currently active") {
		t.Fatalf("non-detail security alarms omitted the AAA count:\n%s", brief)
	}
}
