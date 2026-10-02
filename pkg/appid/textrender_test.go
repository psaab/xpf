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

// #5196 (A3-b1-F5): the DISABLED-mode status text previously said
// sessions "fall back to a built-in port→name heuristic", omitting the
// user-defined-application tuple match that resolveTupleFallback
// (runtime.go) actually performs FIRST. The built-in fallbacks are
// consulted only when no user-defined application matches. This pins the
// documented order so the operator-facing text matches the runtime.
func TestRenderStatusDisabledDocumentsUserDefinedFallbackFirst(t *testing.T) {
	cfg := &config.Config{}
	var buf strings.Builder
	RenderStatus(&buf, cfg)
	out := buf.String()

	// The user-defined `applications` scan must be documented...
	userIdx := strings.Index(out, "user-defined")
	if userIdx < 0 {
		t.Fatalf("disabled fallback text must document the user-defined application scan:\n%s", out)
	}
	// ...as happening FIRST...
	if !strings.Contains(out, "scanned FIRST") {
		t.Fatalf("disabled fallback text must state user-defined apps are scanned first:\n%s", out)
	}
	// ...and the built-in heuristic only "when none match".
	if !strings.Contains(out, "only when") {
		t.Fatalf("disabled fallback text must state the built-in heuristic applies only when no user-defined app matches:\n%s", out)
	}
	// The user-defined step must precede the built-in heuristic mention,
	// matching resolveTupleFallback's actual order.
	builtinIdx := strings.Index(out, "built-in port→name heuristic")
	if builtinIdx < 0 {
		t.Fatalf("disabled fallback text must still mention the built-in heuristic:\n%s", out)
	}
	if userIdx > builtinIdx {
		t.Fatalf("user-defined scan must be documented before the built-in heuristic (order matches runtime):\n%s", out)
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

// #11829 [C-07]: the status text claimed same-tier ties are "broken by
// name", stale since #5296/#10722. Both the Go fallback
// (resolveTupleFallback: lowest assigned app_id) and
// docs/services-application-identification.md agree on lowest assigned
// app_id, so the operator-facing text must say the same.
func TestRenderStatusDocumentsAssignedIDTieBreak_11829(t *testing.T) {
	cfg := &config.Config{}
	var buf strings.Builder
	RenderStatus(&buf, cfg)
	out := buf.String()
	if !strings.Contains(out, "ties broken by lowest assigned app_id") {
		t.Errorf("status text must document lowest-assigned-app_id tie-break, got:\n%s", out)
	}
	if strings.Contains(out, "ties broken by name") {
		t.Errorf("status text still carries stale by-name tie-break wording:\n%s", out)
	}
}
