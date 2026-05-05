package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #653: server-side wrapper for `show services
// application-identification status`. After Copilot review #5
// on PR #1196 the actual rendering moved to `pkg/appid`'s
// shared `RenderStatus`; the full content tests live there
// (`pkg/appid/textrender_test.go`). This test is the
// thin-wrapper smoke: confirms the gRPC topic dispatches
// through to the shared renderer and produces the expected
// heading.
func TestShowApplicationIdentificationStatusDelegatesToSharedRenderer(t *testing.T) {
	cfg := &config.Config{
		Services: config.ServicesConfig{ApplicationIdentification: true},
	}
	var buf strings.Builder
	(&Server{}).showApplicationIdentificationStatus(cfg, &buf)
	out := buf.String()
	if !strings.Contains(out, "Application identification (AppID) status:") {
		t.Errorf("server-side delegate did not produce expected heading:\n%s", out)
	}
}
