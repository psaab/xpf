package vrrp

import (
	"net"
	"testing"
)

// #9914 F-120: UpdateRGPriority is the one writer that bypassed
// clampConfigPriority, and the sink narrows with uint8(priority): 256 aliases
// to 0, which IS the resign value, so a priority update would read as a
// resignation. Latent: current callers pass only 100/200.
//
// FAIL-ON-REVERT: remove the clampConfigPriority call at the top of
// UpdateRGPriority and the out-of-range rows store the raw value again.
func TestUpdateRGPriorityClampsToWireDomain_9914(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	reth := newInstance(Instance{Interface: "reth0", GroupID: 101, Priority: 100},
		&net.Interface{Name: "reth0", Index: 8}, m.eventCh, nil)
	m.instances[instanceKey{iface: "reth0", groupID: 101}] = reth

	for _, tc := range []struct {
		name string
		in   int
		want int
	}{
		// THE DEFECT. 256 narrows to uint8 0 on the wire — the RFC 5798
		// resignation beacon — while the state machine believes itself the
		// most preferred candidate.
		{"256 saturates to 254, never the resign alias", 256, 254},
		{"large value saturates to 254", 300, 254},
		// Below range floors to 1, never 0: installing the resignation
		// sentinel from config would be the bug rather than a bound.
		{"zero floors to 1, never resign", 0, 1},
		{"negative floors to 1", -5, 1},
		// An explicit 255 is the address owner and passes through untouched.
		{"address owner passes through", 255, 255},
		// REFERENCE ARM: in-range values must be byte-identical, including
		// the values production callers actually pass (100/200).
		{"secondary stays", 100, 100},
		{"primary stays", 200, 200},
		{"floor stays", 1, 1},
		{"ceiling stays", 254, 254},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m.UpdateRGPriority(1, tc.in)
			got := reth.cfg.Priority
			if got != tc.want {
				t.Errorf("UpdateRGPriority(1, %d) stored %d, want %d",
					tc.in, got, tc.want)
			}
			if w := uint8(got); w == 0 {
				t.Errorf("UpdateRGPriority(1, %d) stored %d, which narrows to "+
					"wire priority 0 (resign) — the clamp must make that "+
					"narrowing a no-op", tc.in, got)
			}
		})
	}
}
