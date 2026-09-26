package bootstrapshow

import (
	"bytes"
	"strings"
	"testing"
)

// render is a test helper: the rendering of one snapshot as a string.
func render(s Snapshot) string {
	var b bytes.Buffer
	Render(&b, s)
	return b.String()
}

// The six recorded statuses each render their own status token AND their own
// meaning. RED on revert: collapse two cases in explain() and the pair that
// collapsed reports the same meaning line.
func TestEveryStatusRendersItsOwnMeaning(t *testing.T) {
	cases := []struct{ status, wantToken string }{
		{StatusOK, "ok"},
		{StatusLoadedDB, "loaded-from-db"},
		{StatusNoConfig, "no-config"},
		{StatusPending, "credential-apply-pending"},
		{StatusCredentialFailed, "credential-apply-failed"},
		{StatusFailed, "import-failed"},
	}
	seen := map[string]string{}
	for _, c := range cases {
		out := render(Snapshot{Status: c.status})
		if !strings.Contains(out, "Status:   "+c.wantToken+"\n") {
			t.Errorf("status %q: rendered status token missing from:\n%s", c.status, out)
		}
		meaning := meaningLine(t, out)
		if meaning == "" {
			t.Fatalf("status %q: no Meaning line in:\n%s", c.status, out)
		}
		if prev, dup := seen[meaning]; dup {
			t.Errorf("statuses %q and %q render the SAME meaning %q — an operator "+
				"cannot tell them apart", prev, c.status, meaning)
		}
		seen[meaning] = c.status
	}
}

func TestCredentialApplyFailureExplainsPartialAccess(t *testing.T) {
	out := render(Snapshot{
		Status: StatusCredentialFailed,
		Error:  "host credential reconciliation failed; inspect the daemon journal",
		Failed: true,
	})
	if !strings.Contains(out, "configured access may be incomplete") {
		t.Fatalf("credential-apply-failed must explain that configured access may be incomplete:\n%s", out)
	}
	if strings.Contains(out, "NOT the one on the day-0 medium") {
		t.Fatalf("credential-apply-failed must not claim the imported config is absent:\n%s", out)
	}
}

func TestCredentialApplyPendingDoesNotShowFailureRemediation(t *testing.T) {
	out := render(Snapshot{Status: StatusPending})
	if !strings.Contains(out, "initial host-credential application is still running") {
		t.Fatalf("pending status must say credential application has not finished:\n%s", out)
	}
	if strings.Contains(out, "configured access may be incomplete") {
		t.Fatalf("pending status must not be rendered as a failure:\n%s", out)
	}
}
func TestFailedMeaningDoesNotAssumeTextConfigWasInstalled(t *testing.T) {
	out := render(Snapshot{
		Status: StatusFailed,
		Error:  "day-0 config REJECTED by commit-check",
		Failed: true,
	})
	meaning := meaningLine(t, out)
	if strings.Contains(meaning, "file was present") {
		t.Fatalf("a loader-rejected medium installs no xpf.conf, so import-failed "+
			"must not claim a text file was present:\n%s", out)
	}
	if !strings.Contains(meaning, "could NOT be applied") {
		t.Fatalf("import-failed must explain that a configuration could not be applied:\n%s", out)
	}
}

func meaningLine(t *testing.T, out string) string {
	t.Helper()
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "Meaning:") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// A status the renderer does not know must be REPORTED as unrecognized, not
// printed as though it were understood. This is what makes the daemon-side
// constant aliasing (pkg/daemon/daemon_health.go) checkable rather than a
// convention: a divergence surfaces to the operator instead of hiding.
func TestUnknownStatusIsReportedAsUnrecognized(t *testing.T) {
	out := render(Snapshot{Status: "some-future-state"})
	if !strings.Contains(out, "some-future-state") {
		t.Errorf("the unrecognized status value itself must still be shown:\n%s", out)
	}
	if !strings.Contains(out, "unrecognized status") {
		t.Errorf("an unknown status must be called out as unrecognized:\n%s", out)
	}
}

// The empty status (daemon has not reached the decision yet) must not render
// as an empty field — the operator would read a blank as "nothing wrong".
func TestUnrecordedStatusIsNamed(t *testing.T) {
	out := render(Snapshot{})
	if !strings.Contains(out, "not-recorded") {
		t.Errorf("an unrecorded outcome must be NAMED, not blank:\n%s", out)
	}
	if strings.Contains(out, "Status:   \n") {
		t.Errorf("blank status field rendered:\n%s", out)
	}
}

// The failure REASON is the entire point of the command: /health withholds it
// (#5031, unauthenticated), so if this surface drops it too the operator has
// no in-band way to learn why the day-0 config did not apply.
func TestFailedRendersTheErrorDetailAndRemediation(t *testing.T) {
	const detail = `parse error at line 12: unknown statement "dataplane-type"`
	// 1755792000 == 2025-08-21 16:00:00 UTC. Pinned so the rendering is
	// asserted in UTC regardless of the test host's TZ.
	out := render(Snapshot{Status: StatusFailed, Error: detail, Failed: true, UnixSec: 1755792000})
	if !strings.Contains(out, detail) {
		t.Errorf("import-failed must render the error detail (the whole point of "+
			"the command; /health cannot carry it):\n%s", out)
	}
	if !strings.Contains(out, "lifeline-safe bootstrap state") {
		t.Errorf("import-failed must tell the operator what state the box is in:\n%s", out)
	}
	if !strings.Contains(out, "2025-08-21 16:00:00 UTC") {
		t.Errorf("a recorded timestamp must be rendered in UTC:\n%s", out)
	}
}

// The remediation block is gated on Failed, not on Error being non-empty. A
// non-failure must never be dressed up as one.
func TestNonFailureNeverShowsRemediation(t *testing.T) {
	for _, s := range []Snapshot{
		{Status: StatusOK, UnixSec: 1755792000},
		{Status: StatusNoConfig, UnixSec: 1755792000},
		{Status: StatusLoadedDB, UnixSec: 1755792000},
		{Status: StatusPending, UnixSec: 1755792000},
	} {
		out := render(s)
		if strings.Contains(out, "lifeline-safe bootstrap state") {
			t.Errorf("status %q is not a failure but rendered the failure "+
				"remediation:\n%s", s.Status, out)
		}
	}
}

// A snapshot with no recorded time must not render a 1970 timestamp as if the
// outcome had been recorded at the epoch.
func TestZeroTimestampIsOmittedNotRenderedAsEpoch(t *testing.T) {
	out := render(Snapshot{Status: StatusOK})
	if strings.Contains(out, "1970") {
		t.Errorf("an unset UnixSec must be omitted, not rendered as the epoch:\n%s", out)
	}
	if strings.Contains(out, "Recorded:") {
		t.Errorf("no Recorded line should appear without a timestamp:\n%s", out)
	}
}
