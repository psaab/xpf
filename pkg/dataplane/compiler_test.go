package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type policyScheduleSlotTestDP struct {
	DataPlane

	rules []PolicyRule
}

func (d *policyScheduleSlotTestDP) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error {
	return nil
}

func (d *policyScheduleSlotTestDP) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	d.rules = append(d.rules, rule)
	return nil
}

func (d *policyScheduleSlotTestDP) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {}

func TestCompilePoliciesRecordsExpandedPolicyScheduleSlots(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{
			{
				Name:   "plain",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
			},
			{
				Name:          "scheduled",
				SchedulerName: "workhours",
				Action:        config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"app-a", "app-b"},
				},
			},
		},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:          "global-scheduled",
		SchedulerName: "night",
		Action:        config.PolicyPermit,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"app-c", "app-d"},
		},
	}}
	result := &CompileResult{
		ZoneIDs: map[string]uint16{
			"trust":   1,
			"untrust": 2,
		},
		AppIDs: map[string]uint32{
			"app-a": 1,
			"app-b": 2,
			"app-c": 3,
			"app-d": 4,
		},
	}
	dp := &policyScheduleSlotTestDP{}

	if err := compilePolicies(dp, cfg, result); err != nil {
		t.Fatalf("compilePolicies: %v", err)
	}

	want := []PolicyScheduleRuleSlot{
		{PolicySetID: 0, RuleIndex: 1, RuleID: 1, PolicyName: "scheduled", SchedulerName: "workhours"},
		{PolicySetID: 0, RuleIndex: 2, RuleID: 2, PolicyName: "scheduled", SchedulerName: "workhours"},
		{PolicySetID: 1, RuleIndex: 0, RuleID: MaxRulesPerPolicy, PolicyName: "global-scheduled", SchedulerName: "night"},
		{PolicySetID: 1, RuleIndex: 1, RuleID: MaxRulesPerPolicy + 1, PolicyName: "global-scheduled", SchedulerName: "night"},
	}
	if len(result.PolicyScheduleRuleSlots) != len(want) {
		t.Fatalf("got %d slots, want %d: %#v", len(result.PolicyScheduleRuleSlots), len(want), result.PolicyScheduleRuleSlots)
	}
	for i := range want {
		if got := result.PolicyScheduleRuleSlots[i]; got != want[i] {
			t.Fatalf("slot %d = %#v, want %#v", i, got, want[i])
		}
	}
	if len(dp.rules) != 5 {
		t.Fatalf("compiled %d policy rules, want 5", len(dp.rules))
	}
}

func TestExpandFilterTermNegateFlags(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"rfc1918": {
			Name:     "rfc1918",
			Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		"bogons": {
			Name:     "bogons",
			Prefixes: []string{"192.168.0.0/16"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "negate-test",
		Action: "accept",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "rfc1918", Except: true},
		},
		DestPrefixLists: []config.PrefixListRef{
			{Name: "bogons", Except: false},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists, nil)
	// Source: 2 prefixes (except) × Dest: 1 prefix (normal) = 2 rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	for i, r := range rules {
		// Source should have SrcAddr + SrcNegate
		if r.MatchFlags&FilterMatchSrcAddr == 0 {
			t.Errorf("rule %d: missing FilterMatchSrcAddr", i)
		}
		if r.MatchFlags&FilterMatchSrcNegate == 0 {
			t.Errorf("rule %d: missing FilterMatchSrcNegate for except prefix-list", i)
		}
		// Destination should have DstAddr but NOT DstNegate
		if r.MatchFlags&FilterMatchDstAddr == 0 {
			t.Errorf("rule %d: missing FilterMatchDstAddr", i)
		}
		if r.MatchFlags&FilterMatchDstNegate != 0 {
			t.Errorf("rule %d: unexpected FilterMatchDstNegate for non-except prefix-list", i)
		}
	}
}

func TestExpandFilterTermDstNegate(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"private": {
			Name:     "private",
			Prefixes: []string{"10.0.0.0/8"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "dst-negate-test",
		Action: "discard",
		DestPrefixLists: []config.PrefixListRef{
			{Name: "private", Except: true},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists, nil)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchDstAddr == 0 {
		t.Error("missing FilterMatchDstAddr")
	}
	if r.MatchFlags&FilterMatchDstNegate == 0 {
		t.Error("missing FilterMatchDstNegate for except prefix-list")
	}
	if r.MatchFlags&FilterMatchSrcAddr != 0 {
		t.Error("unexpected FilterMatchSrcAddr for term with no source")
	}
	if r.Action != FilterActionDiscard {
		t.Errorf("expected discard action, got %d", r.Action)
	}
}

func TestExpandFilterTermNoNegateWithoutExcept(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"allowed": {
			Name:     "allowed",
			Prefixes: []string{"10.0.1.0/24"},
		},
	}

	term := &config.FirewallFilterTerm{
		Name:   "no-negate",
		Action: "accept",
		SourcePrefixLists: []config.PrefixListRef{
			{Name: "allowed", Except: false},
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, prefixLists, nil)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchSrcAddr == 0 {
		t.Error("missing FilterMatchSrcAddr")
	}
	if r.MatchFlags&FilterMatchSrcNegate != 0 {
		t.Error("unexpected FilterMatchSrcNegate for non-except prefix-list")
	}
	if r.MatchFlags&FilterMatchDstNegate != 0 {
		t.Error("unexpected FilterMatchDstNegate")
	}
}

func TestResolveInterfaceRefXFRMUnit(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"st0": {
					Name: "st0",
					Units: map[int]*config.InterfaceUnit{
						1: {
							Addresses: []string{"10.0.0.1/30"},
						},
					},
				},
			},
		},
	}

	physName, cfgName, unitNum, vlanID := resolveInterfaceRef("st0.1", cfg)
	if physName != "st0.1" {
		t.Fatalf("physName = %q, want st0.1", physName)
	}
	if cfgName != "st0" {
		t.Fatalf("cfgName = %q, want st0", cfgName)
	}
	if unitNum != 1 {
		t.Fatalf("unitNum = %d, want 1", unitNum)
	}
	if vlanID != 0 {
		t.Fatalf("vlanID = %d, want 0", vlanID)
	}
}

func TestIsConfiguredVLANSubInterface(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"trust0": {
					Name:        "trust0",
					VlanTagging: true,
					Units: map[int]*config.InterfaceUnit{
						100: {VlanID: 100},
					},
				},
				"st0": {
					Name: "st0",
					Units: map[int]*config.InterfaceUnit{
						1: {},
					},
				},
			},
		},
	}

	if !isConfiguredVLANSubInterface("trust0.100", cfg) {
		t.Fatal("trust0.100 should be treated as a configured VLAN sub-interface")
	}
	if isConfiguredVLANSubInterface("st0.1", cfg) {
		t.Fatal("st0.1 must not be treated as a VLAN sub-interface")
	}
}

func TestExpandFilterTermFlexMatch(t *testing.T) {
	term := &config.FirewallFilterTerm{
		Name:   "flex-test",
		Action: "discard",
		FlexMatch: &config.FlexMatchConfig{
			MatchStart: "layer-3",
			ByteOffset: 9,
			BitLength:  8,
			Value:      0x11,
			Mask:       0xFF,
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, nil, nil)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.MatchFlags&FilterMatchFlex == 0 {
		t.Error("missing FilterMatchFlex flag")
	}
	if r.FlexOffset != 9 {
		t.Errorf("FlexOffset = %d, want 9", r.FlexOffset)
	}
	if r.FlexLength != 1 { // 8 bits / 8 = 1 byte
		t.Errorf("FlexLength = %d, want 1", r.FlexLength)
	}
	if r.FlexValue != 0x11 {
		t.Errorf("FlexValue = 0x%x, want 0x11", r.FlexValue)
	}
	if r.FlexMask != 0xFF {
		t.Errorf("FlexMask = 0x%x, want 0xFF", r.FlexMask)
	}
	if r.Action != FilterActionDiscard {
		t.Errorf("Action = %d, want discard", r.Action)
	}
}

func TestExpandFilterTermPolicerAndFlex(t *testing.T) {
	policerIDs := map[string]uint32{"my-pol": 1}
	term := &config.FirewallFilterTerm{
		Name:    "combo",
		Action:  "accept",
		Policer: "my-pol",
		FlexMatch: &config.FlexMatchConfig{
			MatchStart: "layer-3",
			ByteOffset: 12,
			BitLength:  32,
			Value:      0x0a000000,
			Mask:       0xff000000,
		},
	}

	rules := expandFilterTerm(term, AFInet, nil, nil, policerIDs)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r := rules[0]
	if r.PolicerID != 1 {
		t.Errorf("PolicerID = %d, want 1", r.PolicerID)
	}
	if r.MatchFlags&FilterMatchFlex == 0 {
		t.Error("missing FilterMatchFlex flag")
	}
	if r.FlexOffset != 12 {
		t.Errorf("FlexOffset = %d, want 12", r.FlexOffset)
	}
}

func TestParseSpeed(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"auto", ""},
		{"Auto", ""},
		{"10m", "10"},
		{"100m", "100"},
		{"1g", "1000"},
		{"1G", "1000"},
		{"2.5g", "2500"},
		{"5g", "5000"},
		{"10g", "10000"},
		{"25g", "25000"},
		{"40g", "40000"},
		{"100g", "100000"},
		{"1000", "1000"},   // raw Mbps
		{"10000", "10000"}, // raw Mbps
		{"bogus", ""},
		{"  1g  ", "1000"}, // whitespace trimmed
	}
	for _, tt := range tests {
		got := parseSpeed(tt.input)
		if got != tt.want {
			t.Errorf("parseSpeed(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseDuplex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"full", "full"},
		{"Full", "full"},
		{"FULL", "full"},
		{"half", "half"},
		{"Half", "half"},
		{"", ""},
		{"auto", ""},
		{"bogus", ""},
		{"  full  ", "full"}, // whitespace trimmed
	}
	for _, tt := range tests {
		got := parseDuplex(tt.input)
		if got != tt.want {
			t.Errorf("parseDuplex(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBuildScreenConfig(t *testing.T) {
	tests := []struct {
		name   string
		sf     *config.SynFloodConfig
		expect ScreenConfig
	}{
		{
			name: "attack threshold only",
			sf: &config.SynFloodConfig{
				AttackThreshold: 1000,
			},
			expect: ScreenConfig{
				Flags:          ScreenSynFlood,
				SynFloodThresh: 1000,
			},
		},
		{
			name: "all thresholds and timeout",
			sf: &config.SynFloodConfig{
				AttackThreshold:      5000,
				SourceThreshold:      100,
				DestinationThreshold: 200,
				Timeout:              10,
			},
			expect: ScreenConfig{
				Flags:             ScreenSynFlood,
				SynFloodThresh:    5000,
				SynFloodSrcThresh: 100,
				SynFloodDstThresh: 200,
				SynFloodTimeout:   10,
			},
		},
		{
			name: "zero source/dest thresholds omitted",
			sf: &config.SynFloodConfig{
				AttackThreshold: 2000,
				Timeout:         5,
			},
			expect: ScreenConfig{
				Flags:           ScreenSynFlood,
				SynFloodThresh:  2000,
				SynFloodTimeout: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &config.ScreenProfile{
				TCP: config.TCPScreen{SynFlood: tt.sf},
			}
			sc := buildScreenConfig(profile, false)

			if sc != tt.expect {
				t.Errorf("got %+v, want %+v", sc, tt.expect)
			}
		})
	}
}

func TestHostInboundRouterDiscoveryFlag(t *testing.T) {
	// Verify router-discovery maps to the correct flag bit.
	flag, ok := HostInboundProtocolFlags["router-discovery"]
	if !ok {
		t.Fatal("router-discovery not in HostInboundProtocolFlags")
	}
	if flag != HostInboundRouterDiscovery {
		t.Errorf("flag = 0x%x, want 0x%x", flag, HostInboundRouterDiscovery)
	}
	// Verify it's bit 20.
	if flag != (1 << 20) {
		t.Errorf("flag = 0x%x, want 1<<20 = 0x%x", flag, uint32(1<<20))
	}
}

func TestHostInboundAllowlistLogic(t *testing.T) {
	// Verify the three-way semantics used in xdp_forward / dpdk forward:
	//   flags == 0            → not configured, allow all
	//   flags == HostInboundAll → explicit "all", allow all
	//   flags != 0 && != All  → allowlist active, deny unknown (flag==0)

	// shouldDeny mirrors the BPF enforcement logic.
	shouldDeny := func(zoneFlags, pktFlag uint32) bool {
		if zoneFlags == 0 {
			return false // not configured
		}
		if zoneFlags == HostInboundAll {
			return false // explicit all
		}
		return pktFlag == 0 || (zoneFlags&pktFlag) == 0
	}

	tests := []struct {
		name      string
		zoneFlags uint32
		pktFlag   uint32
		wantDeny  bool
	}{
		{"not-configured allows anything", 0, 0, false},
		{"not-configured allows known", 0, HostInboundSSH, false},
		{"all allows unknown", HostInboundAll, 0, false},
		{"all allows known", HostInboundAll, HostInboundSSH, false},
		{"allowlist denies unknown", HostInboundSSH | HostInboundPing, 0, true},
		{"allowlist allows enabled", HostInboundSSH | HostInboundPing, HostInboundSSH, false},
		{"allowlist denies disabled", HostInboundSSH | HostInboundPing, HostInboundHTTP, true},
		{"single-service denies unknown", HostInboundPing, 0, true},
		{"single-service allows match", HostInboundPing, HostInboundPing, false},
		{"icmp-errors pass any allowlist", HostInboundPing, HostInboundAll, false},
		{"icmp-errors pass single-service", HostInboundSSH, HostInboundAll, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldDeny(tt.zoneFlags, tt.pktFlag)
			if got != tt.wantDeny {
				t.Errorf("shouldDeny(0x%x, 0x%x) = %v, want %v",
					tt.zoneFlags, tt.pktFlag, got, tt.wantDeny)
			}
		})
	}
}

func TestAppPortsFromSpec(t *testing.T) {
	tests := []struct {
		spec string
		want []int
	}{
		{"", nil},
		{"80", []int{80}},
		{"8080-8083", []int{8080, 8081, 8082, 8083}},
		{"443-443", []int{443}},
	}
	for _, tt := range tests {
		got := appPortsFromSpec(tt.spec)
		if len(got) != len(tt.want) {
			t.Errorf("appPortsFromSpec(%q) len = %d, want %d", tt.spec, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("appPortsFromSpec(%q)[%d] = %d, want %d", tt.spec, i, got[i], tt.want[i])
			}
		}
	}
}

func TestResolvePortName(t *testing.T) {
	tests := []struct {
		name string
		want uint16
	}{
		{"ssh", 22},
		{"SSH", 22},
		{"https", 443},
		{"domain", 53},
		{"dns", 53},
		{"ftp", 21},
		{"ftp-data", 20},
		{"bgp", 179},
		{"snmp", 161},
		{"snmptrap", 162},
		{"syslog", 514},
		{"ike", 500},
		{"80", 80},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := resolvePortName(tt.name)
		if got != tt.want {
			t.Errorf("resolvePortName(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestResolvePortRangeNamed(t *testing.T) {
	lo, hi := resolvePortRange("ssh")
	if lo != 22 || hi != 22 {
		t.Errorf("resolvePortRange(ssh) = (%d, %d), want (22, 22)", lo, hi)
	}
	lo, hi = resolvePortRange("1024-65535")
	if lo != 1024 || hi != 65535 {
		t.Errorf("resolvePortRange(1024-65535) = (%d, %d), want (1024, 65535)", lo, hi)
	}
}

func TestRethConfigAddrs(t *testing.T) {
	ifCfg := &config.InterfaceConfig{
		RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{
			0: {
				Addresses: []string{
					"172.16.50.10/24",
					"2001:db8::10/64",
				},
			},
		},
	}

	v4, v6 := rethConfigAddrs(ifCfg)
	if len(v4) != 1 {
		t.Fatalf("v4 count = %d, want 1", len(v4))
	}
	if !v4[0].Equal(net.ParseIP("172.16.50.10").To4()) {
		t.Errorf("v4[0] = %s, want 172.16.50.10", v4[0])
	}
	if len(v6) != 1 {
		t.Fatalf("v6 count = %d, want 1", len(v6))
	}
	if !v6[0].Equal(net.ParseIP("2001:db8::10")) {
		t.Errorf("v6[0] = %s, want 2001:db8::10", v6[0])
	}
}

func TestRethConfigAddrsMultiUnit(t *testing.T) {
	ifCfg := &config.InterfaceConfig{
		RedundancyGroup: 2,
		Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"10.0.1.1/24"}},
			1: {Addresses: []string{"10.0.2.1/24", "fe80::1/64"}}, // link-local, not global
		},
	}

	v4, v6 := rethConfigAddrs(ifCfg)
	if len(v4) != 2 {
		t.Fatalf("v4 count = %d, want 2", len(v4))
	}
	// fe80::1 is link-local, should be skipped
	if len(v6) != 0 {
		t.Errorf("v6 count = %d, want 0 (link-local skipped)", len(v6))
	}
}

func TestRethConfigAddrsEmpty(t *testing.T) {
	ifCfg := &config.InterfaceConfig{
		RedundancyGroup: 1,
		Units:           map[int]*config.InterfaceUnit{},
	}

	v4, v6 := rethConfigAddrs(ifCfg)
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("expected no addresses, got v4=%d v6=%d", len(v4), len(v6))
	}
}

func TestLo0FilterIDResolution(t *testing.T) {
	// Verify that lo0 filter names are resolved to numeric IDs
	// and that the sentinel value is used when no filter is configured.

	result := &CompileResult{
		Lo0FilterV4: 0xFFFFFFFF, // sentinel: no filter
		Lo0FilterV6: 0xFFFFFFFF,
	}

	// Simulate filter ID assignment (what compileFirewallFilters does)
	filterIDs := map[string]uint32{
		"inet:mgmt-v4":  5,
		"inet6:mgmt-v6": 8,
	}

	// Resolve lo0 filter names to IDs
	cfg := &config.Config{
		System: config.SystemConfig{
			Lo0FilterInputV4: "mgmt-v4",
			Lo0FilterInputV6: "mgmt-v6",
		},
	}
	if cfg.System.Lo0FilterInputV4 != "" {
		if fid, ok := filterIDs["inet:"+cfg.System.Lo0FilterInputV4]; ok {
			result.Lo0FilterV4 = fid
		}
	}
	if cfg.System.Lo0FilterInputV6 != "" {
		if fid, ok := filterIDs["inet6:"+cfg.System.Lo0FilterInputV6]; ok {
			result.Lo0FilterV6 = fid
		}
	}

	if result.Lo0FilterV4 != 5 {
		t.Errorf("Lo0FilterV4 = %d, want 5", result.Lo0FilterV4)
	}
	if result.Lo0FilterV6 != 8 {
		t.Errorf("Lo0FilterV6 = %d, want 8", result.Lo0FilterV6)
	}

	// Verify uint32 → uint16 conversion for BPF flow_config
	var fc FlowConfigValue
	if result.Lo0FilterV4 != 0xFFFFFFFF {
		fc.Lo0FilterV4 = uint16(result.Lo0FilterV4)
	} else {
		fc.Lo0FilterV4 = Lo0FilterNone
	}
	if result.Lo0FilterV6 != 0xFFFFFFFF {
		fc.Lo0FilterV6 = uint16(result.Lo0FilterV6)
	} else {
		fc.Lo0FilterV6 = Lo0FilterNone
	}

	if fc.Lo0FilterV4 != 5 {
		t.Errorf("FlowConfig Lo0FilterV4 = %d, want 5", fc.Lo0FilterV4)
	}
	if fc.Lo0FilterV6 != 8 {
		t.Errorf("FlowConfig Lo0FilterV6 = %d, want 8", fc.Lo0FilterV6)
	}
}

func TestLo0FilterIDSentinel(t *testing.T) {
	// When no lo0 filter is configured, the sentinel 0xFFFF must be used
	result := &CompileResult{
		Lo0FilterV4: 0xFFFFFFFF,
		Lo0FilterV6: 0xFFFFFFFF,
	}

	var fc FlowConfigValue
	if result.Lo0FilterV4 != 0xFFFFFFFF {
		fc.Lo0FilterV4 = uint16(result.Lo0FilterV4)
	} else {
		fc.Lo0FilterV4 = Lo0FilterNone
	}
	if result.Lo0FilterV6 != 0xFFFFFFFF {
		fc.Lo0FilterV6 = uint16(result.Lo0FilterV6)
	} else {
		fc.Lo0FilterV6 = Lo0FilterNone
	}

	if fc.Lo0FilterV4 != Lo0FilterNone {
		t.Errorf("Lo0FilterV4 = 0x%04x, want 0x%04x (none)", fc.Lo0FilterV4, Lo0FilterNone)
	}
	if fc.Lo0FilterV6 != Lo0FilterNone {
		t.Errorf("Lo0FilterV6 = 0x%04x, want 0x%04x (none)", fc.Lo0FilterV6, Lo0FilterNone)
	}
}

func TestLo0FilterMissingFilterName(t *testing.T) {
	// If a referenced filter doesn't exist, the sentinel must be preserved
	result := &CompileResult{
		Lo0FilterV4: 0xFFFFFFFF,
		Lo0FilterV6: 0xFFFFFFFF,
	}

	filterIDs := map[string]uint32{
		"inet:some-other-filter": 3,
	}

	cfg := &config.Config{
		System: config.SystemConfig{
			Lo0FilterInputV4: "nonexistent-filter",
		},
	}
	if cfg.System.Lo0FilterInputV4 != "" {
		if fid, ok := filterIDs["inet:"+cfg.System.Lo0FilterInputV4]; ok {
			result.Lo0FilterV4 = fid
		}
	}

	// Should remain sentinel since filter wasn't found
	if result.Lo0FilterV4 != 0xFFFFFFFF {
		t.Errorf("Lo0FilterV4 = 0x%08x, want 0xFFFFFFFF (unresolved)", result.Lo0FilterV4)
	}

	var fc FlowConfigValue
	if result.Lo0FilterV4 != 0xFFFFFFFF {
		fc.Lo0FilterV4 = uint16(result.Lo0FilterV4)
	} else {
		fc.Lo0FilterV4 = Lo0FilterNone
	}
	if fc.Lo0FilterV4 != Lo0FilterNone {
		t.Errorf("FlowConfig Lo0FilterV4 = 0x%04x, want 0x%04x (none)", fc.Lo0FilterV4, Lo0FilterNone)
	}
}

func TestGREPerformanceAcceleration(t *testing.T) {
	// Verify that GREPerformanceAcceleration config maps to GREAccel=1
	// in the BPF FlowConfigValue struct.
	flow := config.FlowConfig{
		GREPerformanceAcceleration: true,
	}

	var fc FlowConfigValue
	if flow.GREPerformanceAcceleration {
		fc.GREAccel = 1
	}
	if fc.GREAccel != 1 {
		t.Errorf("GREAccel = %d, want 1", fc.GREAccel)
	}

	// Disabled case
	flow2 := config.FlowConfig{
		GREPerformanceAcceleration: false,
	}
	var fc2 FlowConfigValue
	if flow2.GREPerformanceAcceleration {
		fc2.GREAccel = 1
	}
	if fc2.GREAccel != 0 {
		t.Errorf("GREAccel = %d, want 0", fc2.GREAccel)
	}
}
