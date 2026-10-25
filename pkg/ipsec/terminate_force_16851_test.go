package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16851 (R3-B02-01): the fail-closed teardown on the commit and Clear paths
// called `swanctl --terminate --ike <conn>` with no --force. When the peer
// of a removed or changed connection does not answer the INFORMATIONAL
// DELETE, swanctl blocks until the 15 s swanctlTimeout kills it: the commit
// holds applySem for 15 s per such connection and returns a teardown-debt
// error, while charon keeps the IKE_SA in DELETING with its CHILD_SA and
// kernel XFRM states installed until the retransmits run out (~165 s at
// defaults) or the next commit discharges the debt. The accepted fix passes
// --force in terminateIKE: the connection is no longer authorized, so no
// ack is needed. The mutation control in the issue shows the same cell
// completing in ~100 ms with 0 xfrm states once --force is present.
//
// These tests pin the ARGUMENT, not just the fact of a terminate: the seam
// doubles record every invocation, and the graceful (unforced) shape fails
// every RED cell below. Note swanctlRecorder.run/terminateCalls now only
// recognize the forced shape for the commit path, so reverting --force in
// terminateIKE makes the pre-existing terminate suites go RED as well.
//
// Sibling decisions recorded here so they are not regressed silently:
//   - TerminateAllSAs (operator `clear ipsec sa`, ike.go) deliberately stays
//     GRACEFUL: it is not a de-authorization, and its caller reports
//     per-SA failure to the operator (#15279). TestTerminateAllStaysGraceful
//     pins that it must NOT gain --force from this fix.
//   - InitiateConnection gains `--timeout <s>`: without it swanctl waits
//     for the negotiation to settle, so an unresponsive peer rides the
//     15 s swanctlTimeout on the commit re-initiate path and on the HA
//     failover path.

// forcedTerminateCalls returns the raw forced terminate invocations from
// rec for conn, in order.
func forcedTerminateCalls(rec *swanctlRecorder, conn string) [][]string {
	var out [][]string
	for _, c := range rec.calls {
		if len(c) == 4 && c[0] == "--terminate" && c[1] == "--ike" && c[2] == conn && c[3] == "--force" {
			out = append(out, c)
		}
	}
	return out
}

// gracefulTerminateCalls returns any terminate invocation that lacks
// --force, in any position — the defect shape this issue removes from the
// commit/Clear paths. (TerminateConnection/#15194 already forces, so a
// graceful call anywhere in these commit-driven cells is the bug.)
func gracefulTerminateCalls(rec *swanctlRecorder) [][]string {
	var out [][]string
	for _, c := range rec.calls {
		if len(c) == 0 || c[0] != "--terminate" {
			continue
		}
		forced := false
		for _, a := range c {
			if a == "--force" {
				forced = true
			}
		}
		if !forced {
			out = append(out, c)
		}
	}
	return out
}

// RED core (defect cell, commit path): deleting a VPN whose peer does not
// answer must issue `swanctl --terminate --ike <conn> --force`, never the
// graceful form. Pre-fix the recorded call is exactly
// [--terminate --ike site-a] → both assertions fail.
func TestDeleteVPNForcesTerminate16851(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a", "site-b")
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}
	if got := forcedTerminateCalls(rec, "site-a"); len(got) != 1 {
		t.Fatalf("deleted conn must be force-terminated exactly once, got forced=%v calls=%v", got, rec.calls)
	}
	if got := gracefulTerminateCalls(rec); len(got) != 0 {
		t.Fatalf("commit path must never issue a graceful terminate (#16851), got %v", got)
	}
}

// RED core (Clear path): deleting the last VPN / Manager.Clear must force
// too — factory reset (clearIPsecForReset) inherits this path and aborts on
// its error while an unresponsive peer holds the SA.
func TestClearForcesTerminate16851(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := forcedTerminateCalls(rec, "site-a"); len(got) != 1 {
		t.Fatalf("Clear must force-terminate the removed conn exactly once, got forced=%v calls=%v", got, rec.calls)
	}
	if got := gracefulTerminateCalls(rec); len(got) != 0 {
		t.Fatalf("Clear path must never issue a graceful terminate (#16851), got %v", got)
	}
	// Direct Apply(nil) (delete-last-VPN commit) reaches the same teardown.
	rec2 := &swanctlRecorder{}
	m2 := newRecordingManager(t, rec2)
	if err := m2.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec2.listSAs = liveSA("site-a")
	if err := m2.Apply(nil); err != nil {
		t.Fatalf("clear Apply: %v", err)
	}
	if got := forcedTerminateCalls(rec2, "site-a"); len(got) != 1 {
		t.Fatalf("delete-last-VPN commit must force-terminate exactly once, got forced=%v calls=%v", got, rec2.calls)
	}
	if got := gracefulTerminateCalls(rec2); len(got) != 0 {
		t.Fatalf("delete-last-VPN commit must never issue a graceful terminate (#16851), got %v", got)
	}
}

// RED core (changed/rotation cell): a same-name security change (PSK
// rotation of a suspected-compromised peer is the #10878 case) must force
// the stale SA out and only then re-initiate with a bounded --timeout.
func TestChangedVPNForcesTerminateAndBoundsInitiate16851(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	old := vpnCfg("site-a")
	old.VPNs["site-a"].EstablishTunnels = "immediately"
	if err := m.Apply(old); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")
	changed := vpnCfg("site-a")
	changed.VPNs["site-a"].EstablishTunnels = "immediately"
	changed.VPNs["site-a"].PSK = config.NewSecret("rotated-secret")
	if err := m.Apply(changed); err != nil {
		t.Fatalf("changed Apply: %v", err)
	}
	if got := forcedTerminateCalls(rec, "site-a"); len(got) != 1 {
		t.Fatalf("changed conn must be force-terminated exactly once, got forced=%v calls=%v", got, rec.calls)
	}
	if got := gracefulTerminateCalls(rec); len(got) != 0 {
		t.Fatalf("changed-conn teardown must never be graceful (#16851), got %v", got)
	}
	if got := boundedInitiateCalls(rec); len(got) != 1 || got[0][2] != "site-a" {
		t.Fatalf("changed conn must be re-initiated once with --timeout, got %v (calls %v)", got, rec.calls)
	}
}

// boundedInitiateCalls returns initiate invocations carrying a --timeout
// argument with a positive value.
func boundedInitiateCalls(rec *swanctlRecorder) [][]string {
	var out [][]string
	for _, c := range rec.calls {
		if len(c) == 5 && c[0] == "--initiate" && c[1] == "--child" && c[3] == "--timeout" && c[4] != "" && c[4] != "0" {
			out = append(out, c)
		}
	}
	return out
}

// RED core (fallback arm): when --list-sas fails, terminateRemovedConns
// falls back to an unconditional terminate of each removed name; that
// fallback rides the same terminateIKE and must force as well.
func TestListSAsFallbackForcesTerminate16851(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listErr = errListFailed
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}
	if got := forcedTerminateCalls(rec, "site-a"); len(got) != 1 {
		t.Fatalf("fallback terminate must be forced exactly once, got forced=%v calls=%v", got, rec.calls)
	}
	if got := gracefulTerminateCalls(rec); len(got) != 0 {
		t.Fatalf("fallback terminate must never be graceful (#16851), got %v", got)
	}
}

// CONTROL (positive/control cell unchanged): the surviving connection is
// never terminated, forced or otherwise, and a connection with no live SA
// stays a clean no-op — --force must not widen the teardown set.
func TestForceDoesNotWidenTeardown16851(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	// Only site-b is live; site-a was deleted but has no SA.
	rec.listSAs = liveSA("site-b")
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}
	for _, c := range rec.calls {
		if len(c) > 0 && c[0] == "--terminate" {
			t.Fatalf("no terminate expected when the deleted conn has no live SA, got call %v (all %v)", c, rec.calls)
		}
	}
	if got := forcedTerminateCalls(rec, "site-b"); len(got) != 0 {
		t.Fatalf("surviving conn must never be terminated, got %v", got)
	}
}

// CONTROL (sibling deliberately unchanged): TerminateAllSAs, the operator
// `clear ipsec sa` path, stays GRACEFUL. It is not a de-authorization; a
// forced kill there would change the operator-visible contract pinned by
// #15279 (attempt every SA, report each failure) for a path whose stall is
// bounded by the same 15 s swanctlTimeout and reported, not silently held
// under applySem. If this test fails because someone "fixed" it too, that
// scope decision needs its own issue, not this one.
func TestTerminateAllStaysGraceful16851(t *testing.T) {
	rec := &swanctlRecorder{listSAs: liveSA("site-a", "site-b")}
	m := newRecordingManager(t, rec)
	count, err := m.TerminateAllSAs()
	if err != nil {
		t.Fatalf("TerminateAllSAs: %v", err)
	}
	if count != 2 {
		t.Fatalf("TerminateAllSAs count = %d, want 2", count)
	}
	var graceful, forced int
	for _, c := range rec.calls {
		if len(c) == 0 || c[0] != "--terminate" {
			continue
		}
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "--force") {
			forced++
		} else {
			graceful++
		}
	}
	if forced != 0 || graceful != 2 {
		t.Fatalf("TerminateAllSAs must stay graceful (#16851 scope): forced=%d graceful=%d calls=%v", forced, graceful, rec.calls)
	}
}

// RED core (initiate sibling): InitiateConnection must pass a --timeout so
// swanctl detaches instead of waiting out the negotiation (and, on an
// unresponsive peer, the 15 s swanctlTimeout kill). Pre-fix the recorded
// call is exactly [--initiate --child <name>] → this fails.
func TestInitiateConnectionBoundsWait16851(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.InitiateConnection("site-a"); err != nil {
		t.Fatalf("InitiateConnection: %v", err)
	}
	if got := boundedInitiateCalls(rec); len(got) != 1 {
		t.Fatalf("InitiateConnection must issue exactly one --initiate --child site-a --timeout <s>, got %v (calls %v)", got, rec.calls)
	}
	for _, c := range rec.calls {
		if len(c) > 0 && c[0] == "--initiate" && len(c) != 5 {
			t.Fatalf("unbounded initiate must not be issued (#16851), got %v", c)
		}
	}
}
