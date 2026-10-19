package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// renderALG7423 renders `show security alg` for cfg into a string.
func renderALG7423(t *testing.T, alg *config.ALGConfig) string {
	t.Helper()
	var b strings.Builder
	renderALG(&b, alg)
	return b.String()
}

// ghostALGs7423 are the ALG names the pre-#7423 CLI printed as hard-coded
// literals. Eight of them claimed "Enabled". None has any config leaf, any
// compiler path, or any dataplane consumer anywhere in this product.
// PPTP left this list in #15655: it now has a real config leaf, compiler
// path, and Rust ALG consumer, so it renders as a modeled row.
var ghostALGs7423 = []string{
	"H323", "MGCP", "MSRPC", "RTSP", "SCCP", "SUNRPC", "TALK",
	"REAL", "RSH", "SQL", "TRACEROUTE",
}

func TestShowALGDoesNotFabricateRows_7423(t *testing.T) {
	out := renderALG7423(t, &config.ALGConfig{})
	for _, ghost := range ghostALGs7423 {
		if strings.Contains(out, ghost) {
			t.Errorf("show security alg renders a row for %q, which does not "+
				"exist in this product:\n%s", ghost, out)
		}
	}
	for _, real := range []string{"DNS", "FTP", "SIP", "TFTP", "PPTP"} {
		if !strings.Contains(out, real) {
			t.Errorf("show security alg is missing the real ALG %q:\n%s", real, out)
		}
	}
}

// TestShowALGDoesNotClaimEnabled_7423 is the row-6 defect proper. "Enabled" is
// the specific word that made an operator believe an ALG was inspecting
// traffic. Nothing in the dataplane does data-channel pinholing, so no ALG may
// render as enabled.
func TestShowALGDoesNotClaimEnabled_7423(t *testing.T) {
	out := renderALG7423(t, &config.ALGConfig{})
	if strings.Contains(out, "Enabled") {
		t.Errorf("show security alg still claims an ALG is Enabled; no ALG in "+
			"this product does data-channel pinholing:\n%s", out)
	}
	if !strings.Contains(out, "session-tagged (no data-channel pinholing)") {
		t.Errorf("DNS/FTP/SIP should report what they actually do (tag the "+
			"session), got:\n%s", out)
	}
	// TFTP is weaker still: its wire bit has no consumer at all.
	if !strings.Contains(out, "TFTP     : configured (not enforced)") {
		t.Errorf("TFTP should be marked configured (not enforced), got:\n%s", out)
	}
}

// TestShowALGStillReportsDisable_7423 guards the accept direction: the four
// modeled ALGs are real config, and an operator who disables one must still
// see that. A fix that rendered every ALG as inert would pass the two tests
// above while destroying the surface's remaining value.
func TestShowALGStillReportsDisable_7423(t *testing.T) {
	out := renderALG7423(t, &config.ALGConfig{
		DNSDisable: true, FTPDisable: true, SIPDisable: true, TFTPDisable: true,
	})
	if n := strings.Count(out, "disabled"); n != 4 {
		t.Errorf("all four ALGs are disabled, want 4 %q rows, got %d:\n%s",
			"disabled", n, out)
	}
	if strings.Contains(out, "session-tagged") {
		t.Errorf("a disabled ALG must not report session-tagged:\n%s", out)
	}
}

// TestShowALGRendersConfiguredUnsupportedProtos_7423 is the other direction of
// row 6. `security alg h323` is ACCEPTED at commit and recorded in
// UnsupportedProtos (#4232), so it can be in the running config. Deleting the
// fabricated rows without this would make a configured stanza vanish from the
// surface an operator checks — trading a false positive for a false negative.
//
// The fixture carries a DUPLICATE (the compiler appends per `security {}`
// block, so repeats are real) because that is the smallest shape in which the
// dedup is observable.
func TestShowALGRendersConfiguredUnsupportedProtos_7423(t *testing.T) {
	out := renderALG7423(t, &config.ALGConfig{
		UnsupportedProtos: []string{"h323", "msrpc", "h323"},
	})
	if n := strings.Count(out, "H323"); n != 1 {
		t.Errorf("configured `alg h323` should render exactly one row (deduped "+
			"like the advisory), got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "H323     : configured (not implemented)") {
		t.Errorf("configured-but-unmodeled ALG must be marked not implemented:\n%s", out)
	}
	if !strings.Contains(out, "MSRPC    : configured (not implemented)") {
		t.Errorf("every unmodeled proto must render, not just the first:\n%s", out)
	}
	// It must not be confused with the four that ARE modeled.
	if strings.Contains(out, "H323     : session-tagged") {
		t.Errorf("an unmodeled ALG must not claim the modeled behaviour:\n%s", out)
	}
}
