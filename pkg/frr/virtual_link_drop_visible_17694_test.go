package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17694: the HA filter keeps a virtual link when its transit area has any
// enabled interface, but the renderer drops it when the sole transit
// interface was omitted for a failed authentication gate (tolerant keyless
// MD5). That drop must stay fail-closed — ospfd refuses a non-ABR VL — and
// become operator-visible: the renderer warning must name the VL and the
// reason its transit area was not emitted, and must agree with HA
// retention (the HA-kept VL that the renderer now drops is not lost
// silently).
//
// FAIL-ON-REVERT: drop the #17694 reason/HA attributes from the
// #16631 drop warning in renderOSPF16125 and this cell fails while the
// VL remains (correctly) unrendered.

func TestVirtualLinkDroppedKeylessMD5TransitVisible17694(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	m := New()
	// Tolerant keyless-MD5 transit area: the transit interface is present
	// and enabled (HA would keep the VL) but is omitted by the #14388
	// MD5 gate, so no `ip ospf area 0.0.0.1` is emitted.
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
		{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0", AuthType: "md5"}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
	}}

	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)

	// Fail-closed is preserved: neither the VL stanza nor the
	// unauthenticated transit interface block reaches ospfd.
	if strings.Contains(got, "virtual-link") {
		t.Fatalf("virtual-link rendered despite keyless-MD5 transit omission:\n%s", got)
	}
	if strings.Contains(got, " ip ospf area 0.0.0.1\n") {
		t.Fatalf("keyless-MD5 transit interface activated:\n%s", got)
	}

	// The underlying interface omission must remain visible on its own.
	logsStr := logs.String()
	if !strings.Contains(logsStr, "no renderable MD5 key (#14388)") {
		t.Fatalf("keyless-MD5 interface omission warn missing:\n%s", logsStr)
	}

	// The VL drop must name the virtual link and the reason, and state
	// the HA-retention disagreement so an operator debugging a missing
	// VL looks at the renderer, not at HA.
	for _, want := range []string{
		"omitting an OSPF virtual-link whose transit area renders no interface (#16631)",
		`neighbor=10.0.0.2`,
		`transit_area=0.0.0.1`,
		"reason=transit-area-not-emitted",
		"ha_kept=true",
		`transit_interface_present=true`,
		"auth_rejected=true",
	} {
		if !strings.Contains(logsStr, want) {
			t.Errorf("VL drop warn missing %q:\n%s", want, logsStr)
		}
	}
}

// Control: a transit area with a renderable interface keeps its VL and
// emits no #17694 drop warning; a dropped VL whose transit area simply
// has no interface must not claim HA/auth disagreement.
func TestVirtualLinkDropReasonControls17694(t *testing.T) {
	capture := func(ospf *config.OSPFConfig) (string, string) {
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		defer slog.SetDefault(previous)
		got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
		return got, logs.String()
	}

	// Strict-shaped control: valid MD5 transit renders, VL kept, silent.
	got, logsStr := capture(&config.OSPFConfig{Areas: []*config.OSPFArea{
		{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{
			{Name: "ge-0/0/0.0", AuthType: "md5", AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 1, Key: config.NewSecret("17694-key")}}}},
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
	}})
	if !strings.Contains(got, "area 0.0.0.1 virtual-link 10.0.0.2\n") {
		t.Fatalf("valid-MD5 virtual-link missing:\n%s", got)
	}
	if strings.Contains(logsStr, "ha_kept=") {
		t.Errorf("kept VL emitted a drop warning:\n%s", logsStr)
	}

	// Absent-transit control: dropped, but no HA-retention claim.
	got, logsStr = capture(&config.OSPFConfig{Areas: []*config.OSPFArea{
		{ID: "0.0.0.1", VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"}}},
		{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/0.0"}}},
	}})
	if strings.Contains(got, "virtual-link") {
		t.Fatalf("interfaceless VL rendered:\n%s", got)
	}
	if !strings.Contains(logsStr, "reason=transit-area-not-emitted") {
		t.Errorf("interfaceless drop warn missing reason:\n%s", logsStr)
	}
	if strings.Contains(logsStr, "ha_kept=true") {
		t.Errorf("interfaceless drop wrongly claims HA kept it:\n%s", logsStr)
	}
	if strings.Contains(logsStr, "auth_rejected=true") {
		t.Errorf("interfaceless drop wrongly claims auth rejection:\n%s", logsStr)
	}
}
