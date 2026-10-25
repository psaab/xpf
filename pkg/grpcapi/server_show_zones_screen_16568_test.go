package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16568: GetZones must expose screen_disposition and the gRPC text
// zones renderer must qualify undefined/inert profiles; enforcing
// control unchanged; detail must not list alarm-without-drop as enabled.

func zonesScreenServer16568(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"corp":  {Name: "corp", TCP: config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 500}}},
			"audit": {Name: "audit", AlarmWithoutDrop: true},
		},
		Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", ScreenProfile: "corp", Interfaces: []string{"ge-0/0/0.0"}},
			"inert": {Name: "inert", ScreenProfile: "audit", Interfaces: []string{"ge-0/0/1.0"}},
			"ghost": {Name: "ghost", ScreenProfile: "missing"},
		},
	}}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	store.SetCompiledForTesting(cfg)
	return &Server{store: store}
}

func TestGetZonesScreenDisposition16568(t *testing.T) {
	s := zonesScreenServer16568(t)
	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones: %v", err)
	}
	want := map[string]pb.ZoneScreenDisposition{
		"trust": pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_ENFORCING,
		"inert": pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_INERT,
		"ghost": pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_UNDEFINED,
	}
	for name, w := range want {
		if got := getGRPCZone(t, resp, name).ScreenDisposition; got != w {
			t.Errorf("%s: ScreenDisposition = %v, want %v", name, got, w)
		}
	}

	var buf strings.Builder
	s.showZonesDetail(s.store.ActiveConfig(), "", &buf)
	out := buf.String()
	if !strings.Contains(out, "  Screen: corp\n") {
		t.Errorf("enforcing control must stay bare:\n%s", out)
	}
	if !strings.Contains(out, "  Screen: audit [ENFORCES NOTHING — conservative default applies]\n") {
		t.Errorf("inert zone not qualified:\n%s", out)
	}
	if !strings.Contains(out, "  Screen: missing [UNDEFINED — conservative default applies]\n") {
		t.Errorf("undefined zone not qualified:\n%s", out)
	}
	if strings.Contains(out, "Enabled checks: alarm-without-drop") {
		t.Errorf("inert detail lists modifier as enabled check:\n%s", out)
	}
	if !strings.Contains(out, "Enabled checks: syn-flood(threshold:500)") {
		t.Errorf("enforcing inventory changed:\n%s", out)
	}
	// test-zone renderer twin: inert zone's interface carries qualifier.
	var tbuf strings.Builder
	if _, err := s.showTestZone(&pb.ShowTextRequest{Topic: "test-zone:interface=ge-0/0/1.0"}, s.store.ActiveConfig(), &tbuf); err != nil {
		t.Fatalf("showTestZone: %v", err)
	}
	if !strings.Contains(tbuf.String(), "Screen:      audit [ENFORCES NOTHING — conservative default applies]") {
		t.Errorf("test-zone inert not qualified:\n%s", tbuf.String())
	}
}
