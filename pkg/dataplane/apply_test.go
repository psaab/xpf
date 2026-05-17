package dataplane

import (
	"context"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/networkd"
)

func TestApplyResultFromCompileResultCarriesDisplayMetadata(t *testing.T) {
	compileResult := &CompileResult{
		ZoneIDs: map[string]uint16{
			"trust": 1,
		},
		ManagedInterfaces: []networkd.InterfaceConfig{
			{Name: "xe-0/0/0"},
		},
		FilterIDs: map[string]uint32{
			"inet:edge-in": 3,
		},
		FilterSpans: map[string]FilterCounterSpan{
			"inet:edge-in": {FilterID: 3, RuleStart: 42, RuleCount: 7},
		},
		NATCounterIDs: map[string]uint16{
			"srcnat/rule-a": 9,
		},
		PoolIDs: map[string]uint8{
			"snat-pool": 2,
		},
		PolicyNames: map[uint32]string{
			100: "trust/untrust/allow-all",
		},
		AppNames: map[uint16]string{
			5: "junos-http",
		},
		PolicyScheduleRuleSlots: []PolicyScheduleRuleSlot{
			{PolicySetID: 1, RuleIndex: 0, RuleID: 100, PolicyName: "allow-all", SchedulerName: "biz-hours"},
		},
	}

	result := ApplyResultFromCompileResult(compileResult)
	if result == nil {
		t.Fatal("ApplyResultFromCompileResult returned nil")
	}
	if got := result.FilterIDs["inet:edge-in"]; got != 3 {
		t.Fatalf("FilterIDs[inet:edge-in] = %d, want 3", got)
	}
	if got := result.FilterSpans["inet:edge-in"]; got != (FilterCounterSpan{FilterID: 3, RuleStart: 42, RuleCount: 7}) {
		t.Fatalf("FilterSpans[inet:edge-in] = %+v", got)
	}
	if got := result.NATCounterIDs["srcnat/rule-a"]; got != 9 {
		t.Fatalf("NATCounterIDs[srcnat/rule-a] = %d, want 9", got)
	}
	if !result.Capabilities.ForwardingSupported {
		t.Fatal("Capabilities.ForwardingSupported = false, want true")
	}
	if got := result.PoolIDs["snat-pool"]; got != 2 {
		t.Fatalf("PoolIDs[snat-pool] = %d, want 2", got)
	}
	if got := result.PolicyNames[100]; got != "trust/untrust/allow-all" {
		t.Fatalf("PolicyNames[100] = %q, want trust/untrust/allow-all", got)
	}
	if got := result.AppNames[5]; got != "junos-http" {
		t.Fatalf("AppNames[5] = %q, want junos-http", got)
	}
	if n := len(result.PolicyScheduleRuleSlots); n != 1 {
		t.Fatalf("PolicyScheduleRuleSlots len = %d, want 1", n)
	}
	if got := result.PolicyScheduleRuleSlots[0].PolicyName; got != "allow-all" {
		t.Fatalf("PolicyScheduleRuleSlots[0].PolicyName = %q, want allow-all", got)
	}

	// Mutate source — verify ApplyResult has independent copies.
	compileResult.FilterIDs["inet:edge-in"] = 99
	compileResult.FilterSpans["inet:edge-in"] = FilterCounterSpan{}
	compileResult.NATCounterIDs["srcnat/rule-a"] = 99
	compileResult.PoolIDs["snat-pool"] = 99
	compileResult.PolicyNames[100] = "mutated"
	compileResult.AppNames[5] = "mutated"
	compileResult.PolicyScheduleRuleSlots[0].PolicyName = "mutated"
	if got := result.FilterIDs["inet:edge-in"]; got != 3 {
		t.Fatalf("FilterIDs was not copied, got %d", got)
	}
	if got := result.FilterSpans["inet:edge-in"].RuleStart; got != 42 {
		t.Fatalf("FilterSpans was not copied, RuleStart = %d", got)
	}
	if got := result.NATCounterIDs["srcnat/rule-a"]; got != 9 {
		t.Fatalf("NATCounterIDs was not copied, got %d", got)
	}
	if got := result.PoolIDs["snat-pool"]; got != 2 {
		t.Fatalf("PoolIDs was not copied, got %d", got)
	}
	if got := result.PolicyNames[100]; got != "trust/untrust/allow-all" {
		t.Fatalf("PolicyNames was not copied, got %q", got)
	}
	if got := result.AppNames[5]; got != "junos-http" {
		t.Fatalf("AppNames was not copied, got %q", got)
	}
	if got := result.PolicyScheduleRuleSlots[0].PolicyName; got != "allow-all" {
		t.Fatalf("PolicyScheduleRuleSlots was not copied, got %q", got)
	}

	clone := result.Clone()
	clone.PolicyScheduleRuleSlots[0].PolicyName = "clone-mutated"
	if got := result.PolicyScheduleRuleSlots[0].PolicyName; got != "allow-all" {
		t.Fatalf("Clone shared PolicyScheduleRuleSlots backing array, original PolicyName = %q", got)
	}
}

func TestRuntimeDataPlaneContractStaysSmallAndBackendNeutral(t *testing.T) {
	typ := reflect.TypeOf((*RuntimeDataPlane)(nil)).Elem()
	if got := typ.NumMethod(); got > 15 {
		t.Fatalf("RuntimeDataPlane has %d methods, want <= 15", got)
	}

	forbidden := map[string]bool{
		"AttachXDP":                 true,
		"AttachTC":                  true,
		"Map":                       true,
		"SetZone":                   true,
		"SetPolicyRule":             true,
		"SetSNATRule":               true,
		"SetDNATEntry":              true,
		"ClearDNATStatic":           true,
		"DeleteStaleIfaceZone":      true,
		"ReadFilterConfig":          true,
		"LastCompileResult":         true,
		"UpdatePolicyScheduleState": true,
	}
	for name := range forbidden {
		if _, ok := typ.MethodByName(name); ok {
			t.Fatalf("RuntimeDataPlane exposes BPF-shaped method %s", name)
		}
	}
}

func TestApplyConfigHonorsCanceledContextBeforeCompile(t *testing.T) {
	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := m.ApplyConfig(ctx, nil); err != context.Canceled {
		t.Fatalf("ApplyConfig canceled error = %v, want context.Canceled", err)
	}
	if got := m.LastApplyResult(); got != nil {
		t.Fatalf("LastApplyResult after canceled apply = %+v, want nil", got)
	}
}
