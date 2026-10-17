package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/rpm"
)

// #14370: CLI `show services rpm` rendered the live ProbeResult.Target and
// the config-fallback test.Target verbatim. An http-get target is a live
// credential URL (JSON redacts it via RPMTest.MarshalJSON); the TEXT
// surface must run it through config.RedactURL.

const (
	cliSecretUserinfo14370 = "TOKEN-USERINFO"
	cliSecretQuery14370    = "TOKEN-QUERY"
	cliTarget14370         = "https://user:" + cliSecretUserinfo14370 + "@host/check?token=" + cliSecretQuery14370
)

func assertCLIRPMRedacted14370(t *testing.T, surface, out string) {
	t.Helper()
	for _, secret := range []string{cliSecretUserinfo14370, cliSecretQuery14370} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked credential %q:\n%s", surface, secret, out)
		}
	}
	for _, want := range []string{"https://", "host", "/check"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s must still contain %q:\n%s", surface, want, out)
		}
	}
}

func TestShowRPMProbeResultsLiveRedactsTarget14370(t *testing.T) {
	c := &CLI{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "config.conf")),
		rpmResultsFn: func() []*rpm.ProbeResult {
			return []*rpm.ProbeResult{{
				ProbeName: "p1", TestName: "t1", ProbeType: "http-get",
				Target: cliTarget14370, LastStatus: "pass",
			}}
		},
	}
	var callErr error
	out := captureStdout(t, func() { callErr = c.showRPMProbeResults() })
	if callErr != nil {
		t.Fatalf("showRPMProbeResults() error = %v", callErr)
	}
	assertCLIRPMRedacted14370(t, "CLI live rpm", out)
}

func TestShowRPMProbeResultsConfigFallbackRedactsTarget14370(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.conf"))
	_, err := store.SyncApply(`services {
    rpm {
        probe p1 {
            test t1 {
                probe-type http-get;
                target url "`+cliTarget14370+`";
            }
        }
    }
}
`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v", err)
	}
	c := &CLI{
		store: store,
		rpmResultsFn: func() []*rpm.ProbeResult {
			return []*rpm.ProbeResult{}
		},
	}
	var callErr error
	out := captureStdout(t, func() { callErr = c.showRPMProbeResults() })
	if callErr != nil {
		t.Fatalf("showRPMProbeResults() error = %v", callErr)
	}
	if !strings.Contains(out, "RPM Probe Configuration:") {
		t.Fatalf("expected config fallback, got:\n%s", out)
	}
	assertCLIRPMRedacted14370(t, "CLI config-fallback rpm", out)
}
