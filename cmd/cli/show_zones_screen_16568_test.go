package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16568: remote `show security zones` must qualify undefined/inert
// profiles from the structured screen_disposition; UNKNOWN stays bare.

func TestShowZonesScreenQualifier16568(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
			{Name: "trust", ScreenProfile: "corp", ScreenDisposition: pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_ENFORCING},
			{Name: "inert", ScreenProfile: "audit", ScreenDisposition: pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_INERT},
			{Name: "ghost", ScreenProfile: "missing", ScreenDisposition: pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_UNDEFINED},
			{Name: "old", ScreenProfile: "legacy", ScreenDisposition: pb.ZoneScreenDisposition_ZONE_SCREEN_DISPOSITION_UNKNOWN},
		}},
		getPoliciesResp: &pb.GetPoliciesResponse{},
	}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.showZones(""); err != nil {
			t.Fatalf("showZones: %v", err)
		}
	})
	for _, want := range []string{
		"  Screen: corp\n",
		"  Screen: audit [ENFORCES NOTHING — conservative default applies]\n",
		"  Screen: missing [UNDEFINED — conservative default applies]\n",
		"  Screen: legacy\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}
