package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16077 (MGMT-16): the gRPC show surfaces must list the tolerated AAA
// local-only posture from the active compiled config, like the local CLI.

const aaaAlarmTree16077 = `system {
    host-name fw-aaa;
    radius-server 192.0.2.10 {
        secret aaa-secret-16077;
    }
}`

func TestAAAAlarmReachesGRPCAlarmSurfaces16077(t *testing.T) {
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

	s := &Server{store: store}
	var system strings.Builder
	s.showAlarms(&system)
	if !strings.Contains(system.String(), marker) || !strings.Contains(system.String(), "1 active alarm(s):") {
		t.Fatalf("gRPC show system alarms omitted the AAA alarm %q:\n%s", marker, system.String())
	}

	var detail strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms-detail", &detail)
	if !strings.Contains(detail.String(), marker) {
		t.Fatalf("gRPC show security alarms detail omitted the AAA alarm %q:\n%s", marker, detail.String())
	}

	var brief strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms", &brief)
	if strings.Contains(brief.String(), marker) {
		t.Fatalf("gRPC non-detail security alarms leaked detail text:\n%s", brief.String())
	}
	if !strings.Contains(brief.String(), "1 security alarm(s) currently active") {
		t.Fatalf("gRPC non-detail security alarms omitted the AAA count:\n%s", brief.String())
	}
}
