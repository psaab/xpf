package daemon

import (
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #14974 D32-01 daemon-side scoping: the divert spec for a VRF-enslaved
// st0.0 must carry its VRF master so the nft rule can match iifname=master +
// sdifname=st0.0; the host-input fence overlay for an enslaved xfrmi must be
// scoped to the tunnel slave, not the bare VRF master.

func vrfHandles14974() []ipsecQueueHandle {
	classes := []struct {
		family ipsecQueueFamily
		hook   ipsecQueueHook
	}{
		{ipsecFamilyInet, ipsecHookForward},
		{ipsecFamilyInet, ipsecHookInput},
		{ipsecFamilyBridge, ipsecHookForward},
		{ipsecFamilyBridge, ipsecHookInput},
	}
	handles := make([]ipsecQueueHandle, 0, len(classes))
	for i, c := range classes {
		handles = append(handles, ipsecQueueHandle{
			Number: uint16(2401 + i),
			Epoch:  3,
			Key: ipsecQueueKey{
				Generation: 5,
				Family:     c.family,
				Hook:       c.hook,
				Owner:      "vpn-a",
				STN:        "st0.0",
				Ifindex:    11,
				Master:     "vrf-blue",
			},
		})
	}
	return handles
}

func TestIpsecCaptureDivertSpecVRFEnslaved14974(t *testing.T) {
	spec, err := ipsecCaptureDivertSpec(vrfHandles14974())
	if err != nil {
		t.Fatalf("divert spec: %v", err)
	}
	if spec.QuarantineAll {
		t.Fatalf("enslaved tunnel was quarantined instead of captured: %+v", spec)
	}
	for name, rules := range map[string][]xnft.IpsecDivertRule{
		"inet-forward": spec.InetForward, "inet-input": spec.InetInput,
		"bridge-forward": spec.BridgeForward, "bridge-input": spec.BridgeInput,
	} {
		if len(rules) != 1 {
			t.Fatalf("%s = %d rules, want 1", name, len(rules))
		}
		if rules[0].Ifname != "st0.0" || rules[0].Master != "vrf-blue" {
			t.Fatalf("%s rule = %+v, want Ifname=st0.0 Master=vrf-blue (iifname-only rule never matches enslaved ingress)", name, rules[0])
		}
	}
	masters := ipsecDivertSpecMasters9506(spec)
	if len(masters) == 0 {
		t.Fatal("divert fence masters empty")
	}
	for _, m := range masters {
		if m != "st0.0" {
			t.Fatalf("divert fence masters = %v, want only st0.0 (tunnel slave, not vrf-blue)", masters)
		}
	}
	plain := vrfHandles14974()
	for i := range plain {
		plain[i].Key.Master = ""
		plain[i].Key.STN = "st0"
	}
	spec2, err := ipsecCaptureDivertSpec(plain)
	if err != nil {
		t.Fatalf("plain divert spec: %v", err)
	}
	if len(spec2.InetInput) != 1 || spec2.InetInput[0].Ifname != "st0" || spec2.InetInput[0].Master != "" {
		t.Fatalf("plain rule = %+v, want Ifname=st0 Master empty", spec2.InetInput)
	}
}

func TestIpsecCaptureQueuePlanResolvesVRFMaster14974(t *testing.T) {
	origLink := ipsecCaptureLinkByName
	origFence := ipsecFenceLinkByIndex
	t.Cleanup(func() { ipsecCaptureLinkByName = origLink; ipsecFenceLinkByIndex = origFence })
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 11, MasterIndex: 22}}, nil
	}
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue", Index: index}}, nil
	}
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{"vpn-a": {BindInterface: "st0.0"}}
	plan, err := buildIpsecCaptureQueuePlan(cfg, 5)
	if err != nil {
		t.Fatalf("queue plan: %v", err)
	}
	if plan.Quarantine.QuarantineAll {
		t.Fatalf("enslaved tunnel quarantined: %+v", plan.Quarantine)
	}
	if len(plan.Keys) != 4 {
		t.Fatalf("keys = %d, want 4 classes", len(plan.Keys))
	}
	for _, k := range plan.Keys {
		if k.Master != "vrf-blue" {
			t.Fatalf("key %+v Master = %q, want vrf-blue", k, k.Master)
		}
	}
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		return nil, netlink.LinkNotFoundError{}
	}
	plan2, err := buildIpsecCaptureQueuePlan(cfg, 5)
	if err != nil {
		t.Fatalf("queue plan2: %v", err)
	}
	if !plan2.Quarantine.QuarantineAll || len(plan2.Keys) != 0 {
		t.Fatalf("unresolvable master plan = keys %d quarantine %v, want quarantine with no keys", len(plan2.Keys), plan2.Quarantine.QuarantineAll)
	}
}

func TestIpsecHostInputFenceOverlayVRFScoped14974(t *testing.T) {
	old := ipsecFenceLinkByIndex
	t.Cleanup(func() { ipsecFenceLinkByIndex = old })
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		if index == 22 {
			return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue", Index: 22}}, nil
		}
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "unknown", Index: index}}, nil
	}
	d := &Daemon{}
	permit := &permitRecord{
		watchGeneration: 7,
		permitEpoch:     9,
		closeRequestSeq: 11,
		state:           ipsecPermitClosing,
		closeRequestKey: ipsecCloseRequestKey{
			Ready:           ipsecReadyUnsafe,
			WatchGeneration: 7,
			Tuples: []ipsecTopologyTuple{
				{Kind: "xfrmi", Ifindex: 11, MasterIndex: 22, Name: "st0.0"},
				{Kind: "xfrmi", Ifindex: 12, MasterIndex: 0, Name: "st1"},
			},
		},
	}
	overlay, err := d.ipsecHostInputFenceOverlayForPermit(permit)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	if overlay == nil {
		t.Fatal("overlay nil")
	}
	if len(overlay.MasterSet) != 1 || overlay.MasterSet[0] != "st1" {
		t.Fatalf("overlay MasterSet = %v, want [st1] only (vrf-blue must not be a bare master)", overlay.MasterSet)
	}
	if len(overlay.SlaveSet) != 1 || overlay.SlaveSet[0] != "st0.0" {
		t.Fatalf("overlay SlaveSet = %v, want [st0.0]", overlay.SlaveSet)
	}
	if len(overlay.MasterSlavePairs) != 1 || overlay.MasterSlavePairs[0] != (xnft.HostInputFencePair{Master: "vrf-blue", Slave: "st0.0"}) {
		t.Fatalf("overlay pairs = %v, want [{vrf-blue st0.0}]", overlay.MasterSlavePairs)
	}
	payload := buildHostInboundFilterPayloadWithOverlay(nil, nil, nil, nil, nil, true, overlay, nil, nil, dhcpBackstopLists{})
	if !strings.Contains(payload, `iifname "vrf-blue" meta sdifname "st0.0"`) {
		t.Fatalf("text oracle lacks slave-scoped fence drop:\n%s", payload)
	}
	if strings.Contains(payload, `iifname { "vrf-blue" }`) || strings.Contains(payload, `iifname "vrf-blue" counter`) {
		t.Fatalf("text oracle still drops bare VRF master:\n%s", payload)
	}
	if !strings.Contains(payload, `"st1"`) {
		t.Fatalf("text oracle lost unenslaved st1 fence:\n%s", payload)
	}
}
