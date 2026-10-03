package config

import (
	"fmt"
	"strings"
	"testing"
)

type threeColorPolicerLeaf11827 struct {
	mode       string
	name       string
	validValue string
	overflow   string
}

// CIR/CBS each appear in both modes, so the schema has seven leaf
// declarations even though there are five distinct token names.
var threeColorPolicerLeaves11827 = []threeColorPolicerLeaf11827{
	{mode: "single-rate", name: "committed-information-rate", validValue: "1.5m", overflow: "1e309"},
	{mode: "single-rate", name: "committed-burst-size", validValue: "1500", overflow: "18446744073709551616"},
	{mode: "single-rate", name: "excess-burst-size", validValue: "15k", overflow: "18446744073709551616"},
	{mode: "two-rate", name: "committed-information-rate", validValue: "1.5m", overflow: "1e309"},
	{mode: "two-rate", name: "committed-burst-size", validValue: "1500", overflow: "18446744073709551616"},
	{mode: "two-rate", name: "peak-information-rate", validValue: "1.5m", overflow: "1e309"},
	{mode: "two-rate", name: "peak-burst-size", validValue: "15k", overflow: "18446744073709551616"},
}

func threeColorPolicerSet11827(mode, leaf, value string) string {
	set := fmt.Sprintf("set firewall three-color-policer p1 %s %s", mode, leaf)
	if value != "" {
		set += " " + value
	}
	return set
}

func TestThreeColorPolicerTypedLeafDiagnostics11827(t *testing.T) {
	for _, leaf := range threeColorPolicerLeaves11827 {
		t.Run(leaf.mode+"/"+leaf.name, func(t *testing.T) {
			invalid := []struct {
				name  string
				value string
				want  string
			}{
				{name: "missing", want: "missing value"},
				{name: "garbage", value: "not-a-value", want: "not a valid"},
				{name: "overflow", value: leaf.overflow, want: "out of range"},
				{name: "zero", value: "0", want: "at least"},
			}
			var messages []string
			for _, tc := range invalid {
				t.Run(tc.name, func(t *testing.T) {
					tree := flatTreeFromSets(t, threeColorPolicerSet11827(leaf.mode, leaf.name, tc.value))
					err := SchemaValidate(tree, nil)
					if err == nil {
						t.Fatalf("SchemaValidate accepted %s %q", leaf.name, tc.value)
					}
					message := err.Error()
					wantPath := "firewall three-color-policer p1 " + leaf.mode + " " + leaf.name
					if !strings.Contains(message, wantPath) {
						t.Errorf("diagnostic %q does not name leaf path %q", message, wantPath)
					}
					if !strings.Contains(strings.ToLower(message), tc.want) {
						t.Errorf("diagnostic %q does not distinguish %s input", message, tc.name)
					}
					messages = append(messages, message)
				})
			}
			for i := range messages {
				for j := i + 1; j < len(messages); j++ {
					if messages[i] == messages[j] {
						t.Errorf("distinct invalid inputs produced the same diagnostic: %q", messages[i])
					}
				}
			}
		})
	}
}

func TestThreeColorPolicerTypedLeavesAcceptValidValues11827(t *testing.T) {
	for _, leaf := range threeColorPolicerLeaves11827 {
		t.Run(leaf.mode+"/"+leaf.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, threeColorPolicerSet11827(leaf.mode, leaf.name, leaf.validValue))
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid %s value %q: %v", leaf.name, leaf.validValue, err)
			}
		})
	}
}

func TestThreeColorPolicerTypedLeavesPreserveJunosForms11827(t *testing.T) {
	sets := []string{
		"set firewall three-color-policer single single-rate committed-information-rate 1.5m",
		"set firewall three-color-policer single single-rate committed-burst-size 1000",
		"set firewall three-color-policer single single-rate excess-burst-size 2k",
		"set firewall three-color-policer dual two-rate committed-information-rate 1m",
		"set firewall three-color-policer dual two-rate committed-burst-size 1500",
		"set firewall three-color-policer dual two-rate peak-information-rate 1.5m",
		"set firewall three-color-policer dual two-rate peak-burst-size 15k",
	}
	tree := flatTreeFromSets(t, sets...)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected Junos decimal-rate or bare-byte forms: %v", err)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compilation rejected Junos decimal-rate or bare-byte forms: %v", err)
	}
}
