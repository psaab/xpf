package grpcapi

import (
	"strings"
	"testing"

	"context"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15175 (B18-04): gRPC text + structured peers of the CLI test in
// pkg/cli. Same two arms (audit vs drop) on every view, plus a
// CLI/gRPC agreement pin: both surfaces must carry the shared
// dpuserspace.ScreenAlarmModeLine wording verbatim.

func alarmCfg15175(audit bool) *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"p": {Name: "p", AlarmWithoutDrop: audit, TCP: config.TCPScreen{Land: true}},
		},
		Zones: map[string]*config.ZoneConfig{"untrust": {Name: "untrust", ScreenProfile: "p"}},
	}}
}

func TestGRPCScreenAlarmWithoutDrop15175(t *testing.T) {
	s := &Server{}
	render := map[string]func(cfg *config.Config) string{
		"showScreen": func(cfg *config.Config) string { var b strings.Builder; s.showScreen(cfg, &b); return b.String() },
		"ids-option": func(cfg *config.Config) string {
			var b strings.Builder
			_, _ = s.showScreenIDSOption(&pb.ShowTextRequest{Topic: "screen-ids-option:p"}, cfg, &b)
			return b.String()
		},
		"detail": func(cfg *config.Config) string {
			var b strings.Builder
			_, _ = s.showScreenIDSOptionDetail(&pb.ShowTextRequest{Topic: "screen-ids-option-detail:p"}, cfg, &b)
			return b.String()
		},
	}
	for name, fn := range render {
		audit, drop := fn(alarmCfg15175(true)), fn(alarmCfg15175(false))
		if !strings.Contains(audit, "Mode: alarm-without-drop") {
			t.Errorf("%s: audit arm missing mode line:\n%s", name, audit)
		}
		if strings.Contains(drop, "alarm-without-drop") || strings.Contains(drop, "alarm-only") {
			t.Errorf("%s: drop arm must not claim audit mode:\n%s", name, drop)
		}
		if name != "showScreen" && (!strings.Contains(audit, "alarm-only") || !strings.Contains(drop, "enabled")) {
			t.Errorf("%s: Value arms wrong audit=%q drop has enabled=%v", name, audit, strings.Contains(drop, "enabled"))
		}
	}
	// Structured GetScreen must carry the mode too.
	store := maximalScreenGRPCStore(t)
	store.ActiveConfig().Security.Screen["max"].AlarmWithoutDrop = true
	resp, err := (&Server{store: store}).GetScreen(context.Background(), &pb.GetScreenRequest{})
	if err != nil {
		t.Fatalf("GetScreen: %v", err)
	}
	found := false
	for _, si := range resp.Screens {
		if si.Name == "max" {
			found = si.GetAlarmWithoutDrop()
		}
	}
	if !found {
		t.Errorf("GetScreen max profile must carry alarm_without_drop=true: %+v", resp.Screens)
	}
}
