package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16057 fold (producer side): two same-zone units of one interface-level
// GRE tunnel share one netdev (ifindex 30), and their authored per-unit
// host-inbound overrides spell the SAME services in REVERSED order. The
// producer resolves each unit's effective tokens per unit name and stamps
// them without sorting (lowerDedup preserves first-seen order), so the
// two snapshot rows legitimately carry differently-ordered slices for one
// effective set. The Rust dispute comparison must read those as ONE set —
// the classifier is order-insensitive — or it installs the deny sentinel
// on an ordinary, equal configuration.
//
// This test pins the producer half of that contract: both unit rows are
// stamped configured, on the shared ifindex, with token slices whose
// canonical signatures (config.CanonicalHostInboundTokenSigExcept, the
// shared SSOT) are EQUAL while the raw slices differ in order. If a
// future producer change canonicalises order itself, the raw-order
// precondition below fails loudly and this test should be revisited
// rather than silently passing as a tautology.
func TestSharedIfindexReorderedUnitOverridesShareOneSignature_16057(t *testing.T) {
	lines := []string{
		"set interfaces gr-0/0/0 tunnel source 10.0.61.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.61.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.1.1/30",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.255.2.1/30",
		"set security zones security-zone sfmix interfaces gr-0/0/0.0",
		"set security zones security-zone sfmix interfaces gr-0/0/0.1",
		"set security zones security-zone sfmix host-inbound-traffic system-services ssh",
		"set security zones security-zone sfmix host-inbound-traffic system-services https",
		"set security zones security-zone sfmix interfaces gr-0/0/0.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone sfmix interfaces gr-0/0/0.0 host-inbound-traffic system-services https",
		"set security zones security-zone sfmix interfaces gr-0/0/0.1 host-inbound-traffic system-services https",
		"set security zones security-zone sfmix interfaces gr-0/0/0.1 host-inbound-traffic system-services ssh",
	}
	_, snaps := buildSnapshotsFromSet6722(t, lines, map[string]int{"gr-0-0-0": 30}, nil)

	unit0 := snapByName6722(t, snaps, "gr-0/0/0.0")
	unit1 := snapByName6722(t, snaps, "gr-0/0/0.1")
	for _, u := range []InterfaceSnapshot{unit0, unit1} {
		if u.Ifindex != 30 {
			t.Fatalf("%s ifindex = %d, want the shared tunnel netdev 30", u.Name, u.Ifindex)
		}
		if !u.HostInboundConfigured {
			t.Fatalf("%s carries no host-inbound override stamp: %+v", u.Name, u)
		}
	}
	if len(unit0.HostInboundSystemServices) < 2 || len(unit1.HostInboundSystemServices) < 2 {
		t.Fatalf("precondition: both units must carry both services, got %v / %v",
			unit0.HostInboundSystemServices, unit1.HostInboundSystemServices)
	}
	sameOrder := len(unit0.HostInboundSystemServices) == len(unit1.HostInboundSystemServices)
	if sameOrder {
		for i := range unit0.HostInboundSystemServices {
			if unit0.HostInboundSystemServices[i] != unit1.HostInboundSystemServices[i] {
				sameOrder = false
				break
			}
		}
	}
	if sameOrder {
		t.Fatalf("precondition: producer now stamps identical order %v on both units; "+
			"the reversed-order shape this test exists to pin no longer reaches the wire",
			unit0.HostInboundSystemServices)
	}
	sig0 := config.CanonicalHostInboundTokenSigExcept(
		unit0.HostInboundSystemServices, unit0.HostInboundProtocols, unit0.HostInboundProtocolsExcept)
	sig1 := config.CanonicalHostInboundTokenSigExcept(
		unit1.HostInboundSystemServices, unit1.HostInboundProtocols, unit1.HostInboundProtocolsExcept)
	if sig0 != sig1 {
		t.Errorf("canonical signatures differ for set-equal units: %q vs %q "+
			"(services %v / %v) — the Rust dispute comparison would deny both",
			sig0, sig1, unit0.HostInboundSystemServices, unit1.HostInboundSystemServices)
	}
}
