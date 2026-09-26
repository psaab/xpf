package ipsec

import (
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3941: deleting an IPsec VPN and committing must actively TERMINATE the
// deleted connection's live IKE/child SAs, not just unload its config via
// `swanctl --load-all`. Config unload leaves the established SAs forwarding
// until rekey/lifetime expiry — a removed VPN (compromised peer,
// decommissioned site) that keeps carrying traffic is a security gap.
//
// These tests drive Manager.Apply against a recording swanctl exec seam and
// assert that a `swanctl --terminate --ike <conn>` is issued for a deleted
// connection that has a live SA, and only for that connection.

// swanctlRecorder is a swanctl exec double. It records every invocation and
// returns a programmable `--list-sas` body so a test can present live SAs.
type swanctlRecorder struct {
	calls   [][]string
	listSAs string // body returned for `swanctl --list-sas`
	listErr error  // error returned for `swanctl --list-sas` (nil = ok)
	// terminateErr programs a per-connection failure for
	// `swanctl --terminate --ike <name>`; a name absent from the map (the
	// zero value, nil map) terminates successfully. Used by the #6542
	// teardown-debt tests.
	terminateErr map[string]error
}

func (r *swanctlRecorder) run(args ...string) ([]byte, error) {
	r.calls = append(r.calls, args)
	if len(args) > 0 && args[0] == "--list-sas" {
		return []byte(r.listSAs), r.listErr
	}
	if len(args) == 3 && args[0] == "--terminate" && args[1] == "--ike" {
		if err := r.terminateErr[args[2]]; err != nil {
			return []byte("terminate failed"), err
		}
	}
	return nil, nil
}

// terminateCalls returns the connection names passed to
// `swanctl --terminate --ike <name>`.
func (r *swanctlRecorder) terminateCalls() []string {
	var names []string
	for _, c := range r.calls {
		if len(c) == 3 && c[0] == "--terminate" && c[1] == "--ike" {
			names = append(names, c[2])
		}
	}
	return names
}

// initiateCalls returns the child names passed to `swanctl --initiate`.
func (r *swanctlRecorder) initiateCalls() []string {
	var names []string
	for _, c := range r.calls {
		if len(c) == 3 && c[0] == "--initiate" && c[1] == "--child" {
			names = append(names, c[2])
		}
	}
	return names
}

func (r *swanctlRecorder) sawListSAs() bool {
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "--list-sas" {
			return true
		}
	}
	return false
}

// newRecordingManager builds a Manager writing to a temp swanctl dir and
// routing every swanctl shell-out through rec.
func newRecordingManager(t *testing.T, rec *swanctlRecorder) *Manager {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = rec.run
	return m
}

// vpnCfg builds an IPsecConfig whose VPNs each name a stable direct peer IP
// plus PSK, so removing another VPN does not change a survivor's fingerprint.
func vpnCfg(names ...string) *config.IPsecConfig {
	vpns := make(map[string]*config.IPsecVPN, len(names))
	for _, n := range names {
		peerOctet := 0
		for _, r := range n {
			peerOctet = (peerOctet*31 + int(r)) % 254
		}
		vpns[n] = &config.IPsecVPN{
			LocalAddr: "10.0.1.1",
			Gateway:   "10.0.2." + strconv.Itoa(peerOctet+1),
			PSK:       config.Secret("secret-" + n),
		}
	}
	return &config.IPsecConfig{
		VPNs:      vpns,
		Proposals: map[string]*config.IPsecProposal{},
	}
}

// liveSA renders a minimal but parseable `swanctl --list-sas` body for a set
// of established connections.
func liveSA(conns ...string) string {
	var b strings.Builder
	for i, c := range conns {
		b.WriteString(c)
		b.WriteString(": #")
		b.WriteByte(byte('1' + i))
		b.WriteString(", ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r\n")
		b.WriteString("  local  '10.0.1.1' @ 10.0.1.1[500]\n")
		b.WriteString("  remote '10.0.2.1' @ 10.0.2.1[500]\n")
		b.WriteString("  " + c + ": #")
		b.WriteByte(byte('1' + i))
		b.WriteString(", reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128\n")
		b.WriteString("    installed 42s ago, rekeying in 3358s, expires in 3918s\n")
	}
	return b.String()
}

// TestDeleteVPNTerminatesLiveSA is the RED-on-revert core: deleting a VPN
// that has an active SA issues `swanctl --terminate --ike <conn>` for the
// removed connection. Reverting the fix (drop the terminateRemovedConns call)
// makes terminateCalls empty → this fails.
func TestDeleteVPNTerminatesLiveSA(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	// Baseline: two VPNs up. No prior config → nothing removed.
	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("initial Apply must not terminate anything, got %v", got)
	}
	if rec.sawListSAs() {
		t.Fatalf("initial Apply must not query SAs (nothing removed)")
	}

	// Both connections have live SAs; operator deletes site-a.
	rec.listSAs = liveSA("site-a", "site-b")
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}

	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("expected exactly one terminate for the deleted conn "+
			"site-a, got %v", got)
	}
	// The surviving connection must NOT be terminated.
	for _, n := range got {
		if n == "site-b" {
			t.Fatalf("terminated the surviving connection site-b")
		}
	}
}

// TestDeleteLastVPNTerminatesLiveSA covers the Clear() path: deleting the
// only VPN drives Apply → clearConfig, which must still terminate the deleted
// connection's live SA.
func TestDeleteLastVPNTerminatesLiveSA(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	rec.listSAs = liveSA("site-a")
	if err := m.Apply(nil); err != nil { // remove every VPN
		t.Fatalf("clear Apply: %v", err)
	}

	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("expected terminate for deleted conn site-a on clear, got %v", got)
	}
}

// TestDeleteVPNNoActiveSAIsNoOp: deleting a VPN that has no live SA issues no
// terminate — a clean no-op.
func TestDeleteVPNNoActiveSAIsNoOp(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	// site-a is deleted but no SA is established (empty --list-sas body).
	rec.listSAs = ""
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}

	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("deleting a VPN with no active SA must not terminate, got %v", got)
	}
	// It is allowed (and expected) to have queried live SAs to make that
	// decision, but it must never have issued a --terminate.
}

// TestAddingVPNDoesNotTerminate: adding a new VPN leaves existing SAs in
// place and does not query the live-SA list when no connection departed or
// changed.
func TestAddingVPNDoesNotTerminate(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")

	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("add Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("adding a VPN must not terminate, got %v", got)
	}
	if rec.sawListSAs() {
		t.Fatalf("adding a VPN must not query SAs (nothing removed or changed)")
	}
}

// TestChangedVPNSecurityTerminatesAndReinitiatesLiveSA proves a same-name
// PSK rotation and narrowed traffic selector evict the established SA and
// negotiate a replacement using the newly loaded settings.
func TestChangedVPNSecurityTerminatesAndReinitiatesLiveSA(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	old := vpnCfg("site-a")
	old.VPNs["site-a"].LocalID = "10.10.0.0/24"
	old.VPNs["site-a"].RemoteID = "10.20.0.0/24"
	if err := m.Apply(old); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	rec.listSAs = liveSA("site-a")
	changed := vpnCfg("site-a")
	changed.VPNs["site-a"].PSK = config.Secret("rotated-secret")
	changed.VPNs["site-a"].LocalID = "10.10.0.0/25"
	changed.VPNs["site-a"].RemoteID = "10.20.0.0/24"
	if err := m.Apply(changed); err != nil {
		t.Fatalf("changed Apply: %v", err)
	}

	if got := rec.terminateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("same-name security change must terminate the old IKE SA, got %v", got)
	}
	if got := rec.initiateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("live changed connection must be reinitiated with its new settings, got %v", got)
	}
	terminateAt, initiateAt := -1, -1
	for i, call := range rec.calls {
		if len(call) == 3 && call[0] == "--terminate" && call[1] == "--ike" {
			terminateAt = i
		}
		if len(call) == 3 && call[0] == "--initiate" && call[1] == "--child" {
			initiateAt = i
		}
	}
	if terminateAt < 0 || initiateAt < 0 || terminateAt >= initiateAt {
		t.Fatalf("replacement must be initiated after stale SA termination, got calls %v", rec.calls)
	}
}

// TestTrafficSelectorOnlyChangeTerminatesAndReinitiatesLiveSA proves a
// selector change by itself invalidates an established connection.
func TestTrafficSelectorOnlyChangeTerminatesAndReinitiatesLiveSA(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	old := vpnCfg("site-a")
	old.VPNs["site-a"].LocalID = "10.10.0.0/24"
	old.VPNs["site-a"].RemoteID = "10.20.0.0/24"
	if err := m.Apply(old); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	rec.listSAs = liveSA("site-a")
	changed := vpnCfg("site-a")
	changed.VPNs["site-a"].LocalID = "10.10.0.0/25"
	changed.VPNs["site-a"].RemoteID = "10.20.0.0/24"
	if err := m.Apply(changed); err != nil {
		t.Fatalf("selector-only Apply: %v", err)
	}

	if got := rec.terminateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("selector change must terminate the old IKE SA, got %v", got)
	}
	if got := rec.initiateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("selector change must reinitiate the live connection, got %v", got)
	}
}

// TestUnchangedRenderedContentDoesNotFlap proves repeated and cosmetic-only
// applies leave an established connection alone.
func TestUnchangedRenderedContentDoesNotFlap(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.calls = nil
	rec.listSAs = liveSA("site-a")

	cosmetic := vpnCfg("site-a")
	cosmetic.VPNs["site-a"].Name = "display-only"
	if err := m.Apply(cosmetic); err != nil {
		t.Fatalf("cosmetic-only Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("non-rendered VPN name must not terminate an SA, got %v", got)
	}
	if got := rec.initiateCalls(); len(got) != 0 {
		t.Fatalf("non-rendered VPN name must not trigger renegotiation, got %v", got)
	}
	if rec.sawListSAs() {
		t.Fatal("identical rendered connection content must not query live SAs")
	}
}

func TestChangedVPNTerminateDebtIsRetried(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	old := vpnCfg("site-a")
	if err := m.Apply(old); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSA("site-a")
	rec.terminateErr = map[string]error{"site-a": errTerminate}
	changed := vpnCfg("site-a")
	changed.VPNs["site-a"].PSK = config.Secret("rotated-secret")
	if err := m.Apply(changed); err == nil {
		t.Fatal("changed Apply must report a failed stale-SA termination")
	}
	if got := rec.initiateCalls(); len(got) != 0 {
		t.Fatalf("failed termination must not start a replacement, got %v", got)
	}

	rec.terminateErr = nil
	if err := m.Apply(changed); err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 2 || got[1] != "site-a" {
		t.Fatalf("changed-connection teardown debt must be retried, got %v", got)
	}
	if got := rec.initiateCalls(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("successful retry must reinitiate the changed connection, got %v", got)
	}
}

// TestDeleteVPNListSAsErrorFallsBackToUnconditionalTerminate: if the live-SA
// query fails, the deleted connection is still terminated (idempotently) so a
// straggler SA is not left forwarding.
func TestDeleteVPNListSAsErrorFallsBackToUnconditionalTerminate(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)

	if err := m.Apply(vpnCfg("site-a", "site-b")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}

	rec.listErr = errListFailed
	if err := m.Apply(vpnCfg("site-b")); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}

	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("expected fallback terminate for deleted conn site-a, got %v", got)
	}
}

type listFailedErr struct{}

func (listFailedErr) Error() string { return "list-sas failed" }

var errListFailed = listFailedErr{}
