// #15194 (D04-02): the belt half at the ipsec.Manager level. A stale local
// IKE SA with the same name makes charon refuse `swanctl --initiate --child`
// with "not establishing CHILD_SA ... due to existing duplicate". The
// manager's TerminateConnection must issue `swanctl --terminate --ike
// <conn> --force` for the connection that owns the named child, so the
// daemon takeover path can clear the duplicate before initiating.

package ipsec

import (
	"strings"
	"testing"
)

// RED core: TerminateConnection(vpn-rg1-child) must terminate the IKE
// connection that owns that child (here the gateway-named connection), with
// --force, and terminate nothing else.
func TestTerminateConnectionClearsNamedSA15194(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	// Since #15024 the IKE connection is gateway-named; the child carries
	// the VPN/selector name the daemon hands around.
	rec.listSAs = liveSAForVPN("vpn-rg1", "gw-rg1") + liveSA("vpn-rg2")

	if err := m.TerminateConnection("vpn-rg1"); err != nil {
		t.Fatalf("TerminateConnection: %v", err)
	}
	var term [][]string
	for _, c := range rec.calls {
		if len(c) > 0 && c[0] == "--terminate" {
			term = append(term, c)
		}
	}
	if len(term) != 1 {
		t.Fatalf("#15194: TerminateConnection must issue exactly one --terminate, got %v (all calls %v)", term, rec.calls)
	}
	got := strings.Join(term[0], " ")
	if !strings.Contains(got, "--ike gw-rg1") || !strings.Contains(got, "--force") {
		t.Fatalf("#15194: terminate must be `swanctl --terminate --ike gw-rg1 --force` (the IKE conn owning child vpn-rg1), got %q", got)
	}
}

// CONTROL: with no live SA matching the name, TerminateConnection is a
// clean no-op (terminate of a non-existent SA is not an error to surface).
func TestTerminateConnectionNoLiveSA15194(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	rec.listSAs = liveSA("vpn-rg2")

	if err := m.TerminateConnection("vpn-rg1"); err != nil {
		t.Fatalf("TerminateConnection with no matching live SA must be nil, got %v", err)
	}
	for _, c := range rec.calls {
		if len(c) > 0 && c[0] == "--terminate" {
			t.Fatalf("#15194: no live SA for vpn-rg1, so nothing may be terminated; got %v", c)
		}
	}
}
