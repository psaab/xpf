package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15202: Junos `remove-private` strips the private-AS run at the head
// (most-recently-prepended end) of the advertised AS path even when a
// public AS follows it, so the FRR spelling must be
// `remove-private-AS all`. The bare FRR spelling strips only an
// all-private path and leaks the private ASNs of a mixed
// private-then-public path upstream.
func TestRenderBGPRemovePrivateAll15202(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.4", PeerAS: 65002, RemovePrivateAS: true, FamilyInet: true},
			{Address: "2001:db8::4", PeerAS: 65002, RemovePrivateAS: true, FamilyInet6: true},
			{Address: "10.0.0.5", PeerAS: 65001, RemovePrivateAS: true, FamilyInet: true},
			{Address: "10.0.0.6", PeerAS: 65002, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)

	for _, want := range []string{
		"neighbor 10.0.0.4 remove-private-AS all\n",
		"neighbor 2001:db8::4 remove-private-AS all\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing Junos-equivalent render %q:\n%s", want, got)
		}
	}
	// Residual FRR/Junos differences must be documented, and the iBGP
	// omission belt (#14585) and non-flag neighbours are unchanged.
	if strings.Contains(got, "remove-private-AS\n") {
		t.Errorf("bare (all-private-only) spelling must not be emitted:\n%s", got)
	}
	if strings.Contains(got, "neighbor 10.0.0.5 remove-private-AS") {
		t.Errorf("iBGP neighbor must keep the #14585 omission:\n%s", got)
	}
	if strings.Contains(got, "neighbor 10.0.0.6 remove-private-AS") {
		t.Errorf("neighbor without remove-private must not gain the flag:\n%s", got)
	}

	// The rendered `all` spelling must be accepted by the local FRR
	// grammar, with an invalid-keyword control proving the parse reads
	// the file.
	vtysh := frrVtyshBinary12185(t)
	if output, err := validateRenderedRouting11417(t, vtysh, got); err != nil {
		t.Fatalf("FRR vtysh grammar rejected the rendered config: %v\n%s\nconfig:\n%s", err, output, got)
	}
	const invalid = "xpf-invalid-15202-command"
	output, err := validateRenderedRouting11417(t, vtysh, got+invalid+"\n")
	if err == nil || !strings.Contains(string(output), invalid) {
		t.Fatalf("FRR vtysh did not reject the invalid config control: %v\n%s", err, output)
	}
}
