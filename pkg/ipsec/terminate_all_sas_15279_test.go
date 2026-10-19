package ipsec

import (
	"errors"
	"strings"
	"testing"
)

// NOTE on the seam: TerminateAllSAs lists SAs through listSAsForTerminate
// (the Manager's sc/scSplit seams, like TerminateConnection #15194), not
// the package-level runSwanctlSplit GetSAStatus uses. On pristine master
// it used GetSAStatus + the package-level runSwanctl and ignored the
// Manager seams, so these cells could not even present live SAs to it
// (a revert therefore fails with the real swanctl binary missing rather
// than reaching the terminate loop); the partial-failure assertion below
// is the one that pins the #15279 error-swallowing mechanism once the
// seam routing is in place.
// #15279 (D04-03): TerminateAllSAs logged and skipped each failed
// `swanctl --terminate --ike` and returned (count, nil). The CLI printed
// "Cleared N IPsec SA(s)" and the gRPC ipsec-sa-clear action returned
// success while the SAs the operator meant to kill kept forwarding.
// The failing arm must return a non-nil joined error naming the
// connections whose terminate failed, keeping the successful count;
// the success arm is unchanged.
//
// These cells drive TerminateAllSAs through the Manager swanctl seam
// (swanctlRecorder: listSAs presents live SAs, terminateErr programs a
// per-connection --terminate failure).

// RED core: one of three terminates fails. The count keeps the two
// successes, the error is non-nil and names only the failed connection,
// and every connection is still attempted.
func TestTerminateAllSAsPartialFailure15279(t *testing.T) {
	rec := &swanctlRecorder{
		listSAs:      liveSA("site-a", "site-b", "site-c"),
		terminateErr: map[string]error{"site-b": errors.New("charon refused")},
	}
	m := newRecordingManager(t, rec)

	count, err := m.TerminateAllSAs()
	if err == nil {
		t.Fatalf("#15279: TerminateAllSAs with a failed terminate must return non-nil error, got (count=%d, nil); the failed SA would keep forwarding behind a success status", count)
	}
	if count != 2 {
		t.Fatalf("#15279: count must keep the successful terminates, got %d, want 2", count)
	}
	if !strings.Contains(err.Error(), "site-b") {
		t.Fatalf("#15279: error must name the failed connection site-b, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "site-a") || strings.Contains(err.Error(), "site-c") {
		t.Fatalf("#15279: error must not name successfully terminated connections, got %q", err.Error())
	}
	got := rec.terminateCalls()
	if len(got) != 3 {
		t.Fatalf("#15279: every SA must still be attempted, terminate calls = %v", got)
	}
}

// RED core, all-fail arm: count is 0 and the joined error names every
// failed connection.
func TestTerminateAllSAsAllFail15279(t *testing.T) {
	boom := errors.New("charon refused")
	rec := &swanctlRecorder{
		listSAs:      liveSA("site-a", "site-b"),
		terminateErr: map[string]error{"site-a": boom, "site-b": boom},
	}
	m := newRecordingManager(t, rec)

	count, err := m.TerminateAllSAs()
	if err == nil {
		t.Fatalf("#15279: all terminates failing must return non-nil error, got (count=%d, nil)", count)
	}
	if count != 0 {
		t.Fatalf("#15279: count = %d, want 0", count)
	}
	for _, name := range []string{"site-a", "site-b"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("#15279: joined error must name %s, got %q", name, err.Error())
		}
	}
}

// CONTROL: every terminate succeeds — count and nil error unchanged.
func TestTerminateAllSAsAllSucceed15279(t *testing.T) {
	rec := &swanctlRecorder{listSAs: liveSA("site-a", "site-b")}
	m := newRecordingManager(t, rec)

	count, err := m.TerminateAllSAs()
	if err != nil {
		t.Fatalf("CONTROL: all-success TerminateAllSAs must return nil error, got %v", err)
	}
	if count != 2 {
		t.Fatalf("CONTROL: count = %d, want 2", count)
	}
}

// CONTROL: no live SAs — (0, nil), nothing terminated.
func TestTerminateAllSAsNoSAs15279(t *testing.T) {
	rec := &swanctlRecorder{listSAs: ""}
	m := newRecordingManager(t, rec)

	count, err := m.TerminateAllSAs()
	if err != nil || count != 0 {
		t.Fatalf("CONTROL: no SAs must return (0, nil), got (%d, %v)", count, err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("CONTROL: no SAs, no terminates expected, got %v", got)
	}
}

// CONTROL: a failed --list-sas still propagates as (0, err) — the caller
// must not report a clear it never attempted.
func TestTerminateAllSAsListFails15279(t *testing.T) {
	rec := &swanctlRecorder{listErr: errors.New("vici unreachable")}
	m := newRecordingManager(t, rec)

	count, err := m.TerminateAllSAs()
	if err == nil || count != 0 {
		t.Fatalf("CONTROL: list failure must return (0, non-nil), got (%d, %v)", count, err)
	}
}
