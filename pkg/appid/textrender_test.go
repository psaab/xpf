package appid

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #653: shared renderer for `show services
// application-identification status`. Both the local CLI
// (`pkg/cli`) and the gRPC text-show surface (`pkg/grpcapi`)
// delegate here, so anything they previously asserted about
// the rendered text now belongs on this single test.

func TestRenderStatusEnabledShowsHonestContract(t *testing.T) {
	cfg := &config.Config{
		Services: config.ServicesConfig{ApplicationIdentification: true},
	}
	var buf strings.Builder
	RenderStatus(&buf, cfg)
	out := buf.String()
	for _, want := range []string{
		"Application identification (AppID) status:",
		"Configured:                  yes",
		"Engine implementation:        port + protocol matching only",
		"L7 DPI / signature engine:    not implemented",
		"Signature package:            not supported",
		"Operator note:",
		"It does NOT enable L7 DPI",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRenderStatusDisabledHasNoOperatorNote(t *testing.T) {
	cfg := &config.Config{}
	var buf strings.Builder
	RenderStatus(&buf, cfg)
	out := buf.String()
	if !strings.Contains(out, "Configured:                  no") {
		t.Errorf("missing disabled marker in output:\n%s", out)
	}
	if !strings.Contains(out, "port→name heuristic") {
		t.Errorf("missing fallback explanation:\n%s", out)
	}
	// The "Operator note:" block fires only when the knob is
	// enabled. Defense against accidentally rendering it always.
	if strings.Contains(out, "Operator note:") {
		t.Errorf("operator note block must not render when AppID disabled:\n%s", out)
	}
}

func TestRenderStatusNilConfigUsesNoActiveSentinel(t *testing.T) {
	var buf strings.Builder
	RenderStatus(&buf, nil)
	out := buf.String()
	if !strings.Contains(out, "Application identification (AppID) status:") {
		t.Errorf("missing heading on nil config:\n%s", out)
	}
	if !strings.Contains(out, "(no active configuration)") {
		t.Errorf("expected nil-config sentinel:\n%s", out)
	}
}
