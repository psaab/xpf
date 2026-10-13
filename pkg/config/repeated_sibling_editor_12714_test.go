package config

import (
	"testing"
)

// #12714: Set/Delete/Deactivate/Activate must target the repeated sibling
// semantics the compiler observes. These tests pin interface inet DHCP,
// inet6 DHCPv6-client, forwarding-options sampling, group-body precedence,
// and the no-twin behavior when setting an existing DHCP container.

func tree12714(t *testing.T, input string) *ConfigTree {
	t.Helper()
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func compileTree12714(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func must12714(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// --- dhcp (family inet) ---

func dhcpOptions12714(cfg *Config) *DHCPInetOptions {
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		return nil
	}
	return ifc.Units[0].DHCPOptions
}

func TestEditorParityDHCP12714(t *testing.T) {
	input := `interfaces { ge-0/0/0 { unit 0 { family inet {
		dhcp { lease-time 3600; retransmission-attempt 4; }
		dhcp { lease-time 7200; retransmission-attempt 5; force-discover; }
	} } } }`
	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "dhcp"}

	tree := tree12714(t, input)
	if got := dhcpOptions12714(compileTree12714(t, tree)); got == nil || got.LeaseTime != 7200 {
		t.Fatalf("precondition lease-time = %+v, want last-wins 7200", got)
	}
	must12714(t, tree.SetPath(append(append([]string(nil), path...), "lease-time", "1800")))
	if got := dhcpOptions12714(compileTree12714(t, tree)); got == nil || got.LeaseTime != 1800 {
		t.Errorf("after set lease-time = %+v, want 1800 (edit must land on last sibling)", got)
	}

	tree = tree12714(t, input)
	must12714(t, tree.DeletePath(append(append([]string(nil), path...), "lease-time")))
	if got := dhcpOptions12714(compileTree12714(t, tree)); got == nil || got.LeaseTime != 0 {
		t.Errorf("after delete lease-time = %+v, want no remaining lease-time", got)
	}

	tree = tree12714(t, input)
	must12714(t, tree.DeletePath(path))
	if got := dhcpOptions12714(compileTree12714(t, tree)); got != nil {
		t.Errorf("after bare delete dhcp options = %+v, want nil (all siblings removed)", got)
	}

	tree = tree12714(t, input)
	must12714(t, tree.DeactivatePath(path))
	if got := dhcpOptions12714(compileTree12714(t, tree)); got != nil {
		t.Errorf("after deactivate dhcp options = %+v, want nil (all siblings inactive)", got)
	}
	must12714(t, tree.ActivatePath(path))
	if got := dhcpOptions12714(compileTree12714(t, tree)); got == nil || got.LeaseTime != 7200 {
		t.Errorf("after activate dhcp lease-time = %+v, want 7200", got)
	}
}

// --- dhcpv6-client (family inet6) ---

func dhcpv6Client12714(cfg *Config) *DHCPv6ClientConfig {
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		return nil
	}
	return ifc.Units[0].DHCPv6Client
}

func TestEditorParityDHCPv6Client12714(t *testing.T) {
	input := `interfaces { ge-0/0/0 { unit 0 { family inet6 {
		dhcpv6-client { client-type stateful; }
		dhcpv6-client { client-type stateless; client-ia-type ia-na; }
	} } } }`
	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet6", "dhcpv6-client"}

	tree := tree12714(t, input)
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got == nil || got.ClientType != "stateless" {
		t.Fatalf("precondition client-type = %+v, want last-wins stateless", got)
	}
	must12714(t, tree.SetPath(append(append([]string(nil), path...), "client-type", "autoconfig")))
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got == nil || got.ClientType != "autoconfig" {
		t.Errorf("after set client-type = %+v, want autoconfig", got)
	}

	tree = tree12714(t, input)
	must12714(t, tree.DeletePath(append(append([]string(nil), path...), "client-type")))
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got == nil || got.ClientType != "" {
		t.Errorf("after delete client-type = %+v, want no remaining client-type", got)
	}

	tree = tree12714(t, input)
	if err := tree.DeletePath(path); err != nil {
		t.Fatal(err)
	}
	if got := dhcpv6Client12714(compileTree12714(t, tree)); got != nil {
		t.Errorf("after bare delete dhcpv6-client = %+v, want nil", got)
	}
}

// --- forwarding-options sampling ---

func samplingInstance12714(cfg *Config, name string) *SamplingInstance {
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	return cfg.ForwardingOptions.Sampling.Instances[name]
}

func samplingRateNodes12714(tree *ConfigTree, instance string) []*Node {
	var rates []*Node
	var descendants func([]*Node)
	descendants = func(nodes []*Node) {
		for _, n := range nodes {
			if len(n.Keys) > 0 && n.Keys[0] == "rate" {
				rates = append(rates, n)
			}
			descendants(n.Children)
		}
	}
	var walk func([]*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if len(n.Keys) == 2 && n.Keys[0] == "instance" && n.Keys[1] == instance && !n.IsLeaf {
				descendants(n.Children)
			}
			walk(n.Children)
		}
	}
	walk(tree.Children)
	return rates
}

func TestEditorParitySampling12714(t *testing.T) {
	input := `forwarding-options {
		sampling { instance i1 { input { rate 100; } } instance i2 { input { rate 200; } } }
		sampling { instance i2 { input { rate 300; } } instance i3 { input { rate 400; } } }
	}`
	sampPath := []string{"forwarding-options", "sampling"}

	tree := tree12714(t, input)
	if got := samplingInstance12714(compileTree12714(t, tree), "i2"); got == nil || got.InputRate != 300 {
		t.Fatalf("precondition i2 = %+v, want last-container rate 300", got)
	}
	// Set on an instance present in both containers edits the last one.
	must12714(t, tree.SetPath([]string{"forwarding-options", "sampling", "instance", "i2", "input", "rate", "500"}))
	if got := samplingInstance12714(compileTree12714(t, tree), "i2"); got == nil || got.InputRate != 500 {
		t.Errorf("after set i2 rate = %+v, want 500", got)
	}
	// Set on an instance present only in the first container appends to the
	// last container (which shadows the first at compile).
	must12714(t, tree.SetPath([]string{"forwarding-options", "sampling", "instance", "i1", "input", "rate", "150"}))
	if got := samplingInstance12714(compileTree12714(t, tree), "i1"); got == nil || got.InputRate != 150 {
		t.Errorf("after set i1 rate = %+v, want 150", got)
	}
	// A brand-new instance lands in the last container; exactly one i4 results.
	must12714(t, tree.SetPath([]string{"forwarding-options", "sampling", "instance", "i4", "input", "rate", "600"}))
	cfg := compileTree12714(t, tree)
	if got := samplingInstance12714(cfg, "i4"); got == nil || got.InputRate != 600 {
		t.Errorf("after set new i4 = %+v, want rate 600", got)
	}
	if n := len(cfg.ForwardingOptions.Sampling.Instances); n != 4 {
		t.Errorf("instances = %d, want exactly 4 (i1..i4)", n)
	}

	// Bare delete of the sampling container removes every sibling.
	tree = tree12714(t, input)
	must12714(t, tree.DeletePath(sampPath))
	if cfg := compileTree12714(t, tree); cfg.ForwardingOptions.Sampling != nil && len(cfg.ForwardingOptions.Sampling.Instances) != 0 {
		t.Errorf("after bare delete sampling instances remain: %+v", cfg.ForwardingOptions.Sampling)
	}

	// Deactivate/activate toggle every sibling.
	tree = tree12714(t, input)
	must12714(t, tree.DeactivatePath(sampPath))
	if cfg := compileTree12714(t, tree); cfg.ForwardingOptions.Sampling != nil && len(cfg.ForwardingOptions.Sampling.Instances) != 0 {
		t.Errorf("after deactivate sampling instances remain: %+v", cfg.ForwardingOptions.Sampling)
	}
	must12714(t, tree.ActivatePath(sampPath))
	if got := samplingInstance12714(compileTree12714(t, tree), "i3"); got == nil || got.InputRate != 400 {
		t.Errorf("after activate i3 = %+v, want rate 400", got)
	}
	// Deep delete descends through instance/input across both sampling siblings.
	tree = tree12714(t, input)
	must12714(t, tree.DeletePath([]string{
		"forwarding-options", "sampling", "instance", "i2", "input", "rate",
	}))
	if got := samplingInstance12714(compileTree12714(t, tree), "i2"); got == nil || got.InputRate != 0 {
		t.Errorf("after deep delete i2 = %+v, want instance with default rate 0", got)
	}
	if got := samplingRateNodes12714(tree, "i2"); len(got) != 0 {
		t.Errorf("deep delete left %d i2 rate nodes", len(got))
	}
	if got := samplingInstance12714(compileTree12714(t, tree), "i1"); got == nil || got.InputRate != 100 {
		t.Errorf("deep delete changed unrelated i1: %+v", got)
	}

	// Deep deactivate/activate traverses the same nested path across siblings.
	tree = tree12714(t, input)
	deepRate := []string{"forwarding-options", "sampling", "instance", "i2", "input", "rate"}
	must12714(t, tree.DeactivatePath(deepRate))
	if got := samplingInstance12714(compileTree12714(t, tree), "i2"); got == nil || got.InputRate != 0 {
		t.Errorf("after deep deactivate i2 = %+v, want 0 with both rates inactive", got)
	}
	rates := samplingRateNodes12714(tree, "i2")
	if len(rates) != 2 || !rates[0].Inactive || !rates[1].Inactive {
		t.Errorf("deep deactivate rate nodes = %+v, want both siblings inactive", rates)
	}
	must12714(t, tree.ActivatePath(deepRate))
	if got := samplingInstance12714(compileTree12714(t, tree), "i2"); got == nil || got.InputRate != 300 {
		t.Errorf("after deep activate i2 = %+v, want 300", got)
	}
	rates = samplingRateNodes12714(tree, "i2")
	if len(rates) != 2 || rates[0].Inactive || rates[1].Inactive {
		t.Errorf("deep activate rate nodes = %+v, want both siblings active", rates)
	}

	tree = tree12714(t, input)
	if err := tree.DeletePath([]string{
		"forwarding-options", "sampling", "instance", "i2", "input", "rate", "999",
	}); err == nil {
		t.Error("deep delete of absent rate value succeeded")
	}
	if got := samplingInstance12714(compileTree12714(t, tree), "i2"); got == nil || got.InputRate != 300 {
		t.Errorf("failed deep delete mutated i2: %+v", got)
	}

}

// --- group-body parity (first-wins inside groups, mirroring #12508) ---

func TestEditorParityGroupsDHCP12714(t *testing.T) {
	input := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet {
		dhcp { lease-time 3600; }
		dhcp { lease-time 7200; }
	} } } } } }
	interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
	apply-groups G;`
	path := []string{"groups", "G", "interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "dhcp", "lease-time", "1800"}
	tree := tree12714(t, input)
	if got := dhcpOptions12714(compileTree12714(t, tree)); got == nil || got.LeaseTime != 3600 {
		t.Fatalf("precondition group-expanded lease-time = %+v, want first-wins 3600", got)
	}
	must12714(t, tree.SetPath(path))
	if got := dhcpOptions12714(compileTree12714(t, tree)); got == nil || got.LeaseTime != 1800 {
		t.Errorf("after group set lease-time = %+v, want 1800 (group first-wins target)", got)
	}
}

// --- container-level set into a repeated container must not twin ---

func TestEditorParityContainerSetNoTwin12714(t *testing.T) {
	input := `interfaces { ge-0/0/0 { unit 0 { family inet {
		dhcp { lease-time 3600; }
		dhcp { lease-time 7200; }
	} } } }`
	tree := tree12714(t, input)
	// Setting a new leaf under the repeated container must edit the last
	// sibling, not create a third dhcp block.
	must12714(t, tree.SetPath([]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "dhcp", "force-discover"}))
	got := dhcpOptions12714(compileTree12714(t, tree))
	if got == nil || !got.ForceDiscover {
		t.Errorf("after set force-discover options = %+v, want ForceDiscover true", got)
	}
	// Count dhcp siblings in the tree: must remain 2.
	count := 0
	var walk func(ns []*Node)
	walk = func(ns []*Node) {
		for _, n := range ns {
			if n.Name() == "dhcp" {
				count++
			}
			walk(n.Children)
		}
	}
	walk(tree.Children)
	if count != 2 {
		t.Errorf("dhcp sibling count = %d, want 2 (no twinning)", count)
	}
}
