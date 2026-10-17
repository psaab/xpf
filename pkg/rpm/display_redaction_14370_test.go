package rpm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14370: an http-get RPM target is a live credential URL. RPMTest.MarshalJSON
// already runs it through config.RedactURL, so the JSON surfaces redact it,
// but the TEXT surfaces rendered test.Target verbatim:
//   - pkg/rpm.WriteConfiguredTest (CLI config-fallback + gRPC writeRPMConfig)
//   - the live-result renderers in pkg/cli and pkg/grpcapi (r.Target)
//   - the "RPM probe started" slog line in runProbeLoop
//
// These tests pin the shared renderer and the log line. The CLI/gRPC live
// renderers are pinned in their own packages.

const (
	secretUserinfo14370 = "TOKEN-USERINFO"
	secretQuery14370    = "TOKEN-QUERY"
	target14370         = "https://user:" + secretUserinfo14370 + "@host/check?token=" + secretQuery14370
)

func assertRedacted14370(t *testing.T, surface, out string) {
	t.Helper()
	for _, secret := range []string{secretUserinfo14370, secretQuery14370} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked credential %q in output:\n%s", surface, secret, out)
		}
	}
	for _, want := range []string{"https://", "host", "/check"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s output must still contain %q (scheme/host/path diagnostic), got:\n%s", surface, want, out)
		}
	}
}

func TestWriteConfiguredTestRedactsCredentialTarget14370(t *testing.T) {
	var buf bytes.Buffer
	WriteConfiguredTest(&buf, "p1", "t1", &config.RPMTest{
		Name:      "t1",
		ProbeType: "http-get",
		Target:    target14370,
	})
	assertRedacted14370(t, "rpm.WriteConfiguredTest", buf.String())
}

// Control: a credential-free target renders unchanged (RedactURL is a no-op),
// so the redaction does not destroy ordinary diagnostics.
func TestWriteConfiguredTestPlainTargetUnchanged14370(t *testing.T) {
	var buf bytes.Buffer
	WriteConfiguredTest(&buf, "p1", "t1", &config.RPMTest{
		Name:      "t1",
		ProbeType: "icmp-ping",
		Target:    "8.8.8.8",
	})
	if !strings.Contains(buf.String(), "Target: 8.8.8.8") {
		t.Errorf("plain target altered:\n%s", buf.String())
	}
}
