package daemon

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #15066 A35-01: a single correctly bound route-based VPN must stage a
// normal four-class divert generation, not a box-wide QuarantineAll.
// buildIpsecCaptureQueuePlan appends every valid tunnel's ifindex to
// plan.Quarantine.CandidateIfindices; previously finalize left those
// candidates in place when no quarantine reason existed and both
// ipsecCaptureDivertSpecWithQuarantine and normalizeIpsecQuarantineSpec
// read a non-empty candidate list as a quarantine request.

func stubValidLink15066(t *testing.T, index int) {
	t.Helper()
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		if name == "st0.0" {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}, nil
		}
		return nil, errors.New("missing link")
	}
}

func TestIpsecCaptureValidSingleVPNDoesNotQuarantine15066(t *testing.T) {
	stubValidLink15066(t, 41)
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"good": {BindInterface: "st0.0"},
	}
	plan, err := buildIpsecCaptureQueuePlan(cfg, 7)
	if err != nil {
		t.Fatalf("queue plan: %v", err)
	}
	if plan.Quarantine.QuarantineAll {
		t.Fatalf("valid single VPN quarantined: %+v", plan.Quarantine)
	}
	if len(plan.Quarantine.CandidateIfindices) != 0 {
		t.Fatalf("valid single VPN retained quarantine candidates %v, want none when not quarantined", plan.Quarantine.CandidateIfindices)
	}
	if len(plan.Keys) != 4 {
		t.Fatalf("valid single VPN keys = %d, want 4 classes", len(plan.Keys))
	}

	// The divert-spec seam must yield the four divert rules, not quarantine.
	handles := make([]ipsecQueueHandle, 0, len(plan.Keys))
	for i, key := range plan.Keys {
		handles = append(handles, ipsecQueueHandle{Number: uint16(1001 + i), Epoch: 9, Key: key})
	}
	spec, err := ipsecCaptureDivertSpecWithQuarantine(handles, plan.Quarantine)
	if err != nil {
		t.Fatalf("divert spec with quarantine: %v", err)
	}
	if spec.QuarantineAll {
		t.Fatalf("valid single VPN divert spec quarantined: %+v", spec)
	}
	if len(spec.InetForward) != 1 || len(spec.InetInput) != 1 || len(spec.BridgeForward) != 1 || len(spec.BridgeInput) != 1 {
		t.Fatalf("valid single VPN divert spec = %+v, want one rule in each of four classes", spec)
	}
	if len(spec.CandidateIfindices) != 0 {
		t.Fatalf("valid divert spec retained candidates %v", spec.CandidateIfindices)
	}
}

// Control: a genuine quarantine reason alongside a valid candidate must
// still quarantine and retain the candidate for the deny rules.
func TestIpsecCaptureQuarantineReasonRetainsCandidates15066(t *testing.T) {
	stubValidLink15066(t, 41)
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"bad-bind": {BindInterface: "not-an-xfrmi"},
		"good":     {BindInterface: "st0.0"},
	}
	plan, err := buildIpsecCaptureQueuePlan(cfg, 7)
	if err != nil {
		t.Fatalf("queue plan: %v", err)
	}
	if !plan.Quarantine.QuarantineAll {
		t.Fatalf("bad-bind plan not quarantined: %+v", plan.Quarantine)
	}
	if plan.Quarantine.QuarantineReasonMask&xnft.IpsecQuarantineMaskIFIDUnderivable == 0 {
		t.Fatalf("bad-bind quarantine mask = 0x%x, want IFID_UNDERIVABLE", plan.Quarantine.QuarantineReasonMask)
	}
	if len(plan.Quarantine.CandidateIfindices) != 1 || plan.Quarantine.CandidateIfindices[0] != 41 {
		t.Fatalf("quarantined candidates = %v, want [41]", plan.Quarantine.CandidateIfindices)
	}
	spec, err := ipsecCaptureDivertSpecWithQuarantine(nil, plan.Quarantine)
	if err != nil {
		t.Fatalf("quarantine divert spec: %v", err)
	}
	if !spec.QuarantineAll || len(spec.CandidateIfindices) != 1 {
		t.Fatalf("quarantine divert spec = %+v, want QuarantineAll with [41]", spec)
	}
}
