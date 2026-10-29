package rpm

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16642 (R3-A49-05): the ErrProbeSetup WARN in runSingleTestWithOptions
// logged the error verbatim ("err", err). For http-get that error wraps a
// *url.Error carrying the target URL: the full raw URL on a
// NewRequestWithContext parse failure, and the URL with only the password
// masked on a local-bind failure. A credential-bearing target therefore
// reached the journal in cleartext every test-interval — the same surface
// class #14370 fixed for the "RPM probe started" line.
//
// These tests drive the REAL probeHTTP legs through runSingleTest (no
// probeFn stub for the error itself) with a captured slog handler and
// assert the WARN line carries neither credential while scheme/host/path
// stay visible.

const (
	secretUserinfo16642 = "TOKEN-USERINFO"
	secretQuery16642    = "TOKEN-QUERY-16642"
)

func captureRPMSetupWarn16642(t *testing.T, test *config.RPMTest) string {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	m := New()
	m.results["p1/t1"] = &ProbeResult{
		ProbeName: "p1", TestName: "t1", ProbeType: "http-get",
		Target: test.Target, LastStatus: "pass",
	}
	m.runSingleTest(context.Background(), "p1", test, "p1/t1", 1, 0, 1)

	out := buf.String()
	if !strings.Contains(out, "RPM probe setup failed") {
		t.Fatalf("expected RPM probe setup WARN, got:\n%s", out)
	}
	return out
}

func assertSetupWarnRedacted16642(t *testing.T, surface, out string) {
	t.Helper()
	for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked credential %q in WARN line:\n%s", surface, secret, out)
		}
	}
	for _, want := range []string{"http", "host", "/check"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s WARN must still contain %q (scheme/host/path diagnostic), got:\n%s", surface, want, out)
		}
	}
}

// Leg A: NewRequest parse failure. The schemeless-canonicalized target has
// a space in the host, so canonicalizeHTTPTarget stays lenient (url.Parse
// error branch) and http.NewRequestWithContext fails — its *url.Error
// embeds the full raw URL.
func TestSetupWarnRedactsNewRequestURL16642(t *testing.T) {
	out := captureRPMSetupWarn16642(t, &config.RPMTest{
		Name: "t1", ProbeType: "http-get",
		Target: "user:" + secretUserinfo16642 + "@host exa mple/check?token=" + secretQuery16642,
	})
	// The canonicalized form is http://…; host is truncated at the space in
	// the raw URL, so only scheme + path fragments are checkable here.
	for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
		if strings.Contains(out, secret) {
			t.Errorf("leg A leaked credential %q in WARN line:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "http") {
		t.Errorf("leg A WARN must retain scheme diagnostic, got:\n%s", out)
	}
}

// Leg A (schemed form): a schemed target whose path escape is invalid
// survives canonicalize? No — url.Parse rejects %zz, so canonicalize
// itself errors. That error also embeds the raw target and must be
// redacted in the WARN line.
func TestSetupWarnRedactsCanonicalizeURL16642(t *testing.T) {
	out := captureRPMSetupWarn16642(t, &config.RPMTest{
		Name: "t1", ProbeType: "http-get",
		Target: "https://user:" + secretUserinfo16642 + "@host/check%zz?token=" + secretQuery16642,
	})
	assertSetupWarnRedacted16642(t, "canonicalize leg", out)
}

// Leg B: local-bind failure. The target is a valid credential URL but the
// configured source-address is not assigned locally, so client.Do fails
// at bind (EADDRNOTAVAIL) and probeHTTP re-wraps the *url.Error as
// ErrProbeSetup. net/http masks only the password in that error; the
// username and the query token remain in cleartext pre-fix.
func TestSetupWarnRedactsLocalBindURL16642(t *testing.T) {
	out := captureRPMSetupWarn16642(t, &config.RPMTest{
		Name: "t1", ProbeType: "http-get",
		Target:        "http://user:" + secretUserinfo16642 + "@127.0.0.1:9/check?token=" + secretQuery16642,
		SourceAddress: "192.0.2.77",
	})
	// Host is 127.0.0.1 here; check scheme/path plus credential absence.
	for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
		if strings.Contains(out, secret) {
			t.Errorf("leg B leaked credential %q in WARN line:\n%s", secret, out)
		}
	}
	for _, want := range []string{"http", "127.0.0.1", "/check"} {
		if !strings.Contains(out, want) {
			t.Errorf("leg B WARN must still contain %q, got:\n%s", want, out)
		}
	}
}

// The returned probe error itself (not only the WARN rendering) must not
// carry the credential: the WARN logs it, and any other consumer that
// formats it would leak the same way.
func TestProbeHTTPErrorsRedacted16642(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		name string
		test *config.RPMTest
	}{
		{"canonicalize", &config.RPMTest{Name: "t", ProbeType: "http-get",
			Target: "https://user:" + secretUserinfo16642 + "@host/check%zz?token=" + secretQuery16642}},
		{"local-bind", &config.RPMTest{Name: "t", ProbeType: "http-get",
			Target:        "http://user:" + secretUserinfo16642 + "@127.0.0.1:9/check?token=" + secretQuery16642,
			SourceAddress: "192.0.2.77"}},
		{"no-host", &config.RPMTest{Name: "t", ProbeType: "http-get",
			Target: "https://user:" + secretUserinfo16642 + "@:80/check?token=" + secretQuery16642}},
	} {
		_, err := m.probeHTTP(context.Background(), tc.test, probeSockOpts{})
		if !errors.Is(err, ErrProbeSetup) {
			t.Fatalf("%s: probeHTTP err = %v, want ErrProbeSetup", tc.name, err)
		}
		for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: probeHTTP error leaked credential %q: %v", tc.name, secret, err)
			}
		}
	}
}

// Control: a credential-free http-get setup failure keeps its diagnostic
// text (redaction is a no-op on a clean target), and a credential-free
// target's host/path remain visible in the WARN line.
func TestSetupWarnPlainTargetUnchanged16642(t *testing.T) {
	out := captureRPMSetupWarn16642(t, &config.RPMTest{
		Name: "t1", ProbeType: "http-get",
		Target: "https://host/check%zz",
	})
	if !strings.Contains(out, "host") || !strings.Contains(out, "/check") {
		t.Errorf("plain-target WARN lost diagnostic host/path:\n%s", out)
	}
	if strings.Contains(out, "<redacted>") {
		t.Errorf("plain-target WARN should be unchanged (no redaction marker):\n%s", out)
	}
}

// #17725: the missing-'@' typo. Schemeless `user:TOKEN/check?token=...`
// canonicalizes to `http://user:TOKEN/check?...`; url.Parse then fails with
// `invalid port ":TOKEN" after host`, whose quoted substring IS the
// credential. Returning ue.Err verbatim (the old urlParseErrClass16642)
// leaks it into ErrProbeSetup / the WARN line even though the adjacent
// RedactURL(target) renders `<redacted>` (secret.go host:port rule). The
// sanitized class must keep the error class ("invalid port") and drop the
// quoted payload entirely; neither token may survive on any surface.
func TestSetupWarnRedactsMissingAtInnerError17725(t *testing.T) {
	target := "user:" + secretUserinfo16642 + "/check?token=" + secretQuery16642

	// Returned error surface (probeHTTP path: canonicalize stays lenient,
	// NewRequest re-parse fails).
	m := New()
	_, err := m.probeHTTP(context.Background(), &config.RPMTest{
		Name: "t", ProbeType: "http-get", Target: target,
	}, probeSockOpts{})
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeHTTP err = %v, want ErrProbeSetup", err)
	}
	for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("probeHTTP error leaked credential %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("probeHTTP error must retain error class %q, got: %v", "invalid port", err)
	}
	if strings.Contains(err.Error(), `":`+secretUserinfo16642+`"`) {
		t.Errorf("probeHTTP error retained quoted credential-bearing port substring: %v", err)
	}

	// Direct canonicalize surface (schemed missing-'@' form reaches the
	// url.Parse error arm in canonicalizeHTTPTarget).
	_, cerr := canonicalizeHTTPTarget("http://" + target)
	if !errors.Is(cerr, ErrProbeSetup) {
		t.Fatalf("canonicalize err = %v, want ErrProbeSetup", cerr)
	}
	for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
		if strings.Contains(cerr.Error(), secret) {
			t.Errorf("canonicalize error leaked credential %q: %v", secret, cerr)
		}
	}
	if !strings.Contains(cerr.Error(), "invalid port") {
		t.Errorf("canonicalize error must retain error class %q, got: %v", "invalid port", cerr)
	}

	// Helper-level: the raw inner text must never pass through.
	_, parseErr := url.Parse("http://" + target)
	if parseErr == nil {
		t.Fatal("url.Parse unexpectedly accepted missing-@ target")
	}
	if got := urlParseErrClass16642(parseErr, "http://"+target); strings.Contains(got, secretUserinfo16642) || !strings.Contains(got, "invalid port") {
		t.Errorf("urlParseErrClass16642 = %q, want sanitized invalid-port class without credential", got)
	}

	// WARN surface through the real runSingleTest path.
	out := captureRPMSetupWarn16642(t, &config.RPMTest{
		Name: "t1", ProbeType: "http-get", Target: target,
	})
	for _, secret := range []string{secretUserinfo16642, secretQuery16642} {
		if strings.Contains(out, secret) {
			t.Errorf("WARN leaked credential %q in WARN line:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "invalid port") {
		t.Errorf("WARN must retain error class %q, got:\n%s", "invalid port", out)
	}
}
