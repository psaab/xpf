package config

import (
	"fmt"
	"strings"
	"testing"
)

func bridgeDomainTree16792(t *testing.T, names ...string) *ConfigTree {
	t.Helper()
	var text strings.Builder
	text.WriteString("bridge-domains {\n")
	for _, name := range names {
		fmt.Fprintf(&text, "    %s { vlan-id-list 100; }\n", name)
	}
	text.WriteString("}\n")
	tree, errs := NewParser(text.String()).Parse()
	if len(errs) > 0 {
		t.Fatalf("bridge-domain fixture must parse: %v\n%s", errs, text.String())
	}
	return tree
}

// TestBridgeDomainKernelNameStrictRejection16792: L2-only domains whose
// br-<name> exceeds IFNAMSIZ (or has ':') must reject at strict compile.
// RED pre-fix: customer-vlan-100 compiled nil.
func TestBridgeDomainKernelNameStrictRejection16792(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"customer-vlan-100", []string{"br-customer-vlan-100", "20 bytes", "IFNAMSIZ", "#16792"}},
		{`"ééééééé"`, []string{"17 bytes", "IFNAMSIZ"}},
		{"bad:name", []string{"br-bad:name", "dev_valid_name", "0x3a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := bridgeDomainTree16792(t, tc.name)
			for _, compiler := range []struct {
				name string
				run  func(*ConfigTree) error
			}{
				{"CompileConfig", func(tr *ConfigTree) error { _, err := CompileConfig(tr); return err }},
				{"CompileConfigForNode", func(tr *ConfigTree) error { _, err := CompileConfigForNode(tr, 0); return err }},
			} {
				err := compiler.run(tree)
				if err == nil {
					t.Fatalf("%s accepted bridge-domain %q; derived br- name must reject", compiler.name, tc.name)
				}
				for _, part := range tc.want {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("error %q missing %q", err, part)
					}
				}
			}
			if err := ValidateBridgeDomainName(tc.name); err == nil {
				t.Errorf("ValidateBridgeDomainName(%q) = nil, want rejection", tc.name)
			}
		})
	}
}

func TestBridgeDomainKernelNameExactLimitAccepted16792(t *testing.T) {
	const name = "abcdefghijkl" // 12 bytes; br- + 12 = 15
	if dev, reason := bridgeDomainBridgeDeviceNameIssue(name); reason != "" || len(bridgeDevicePrefix+name) != maxLinuxIfNameLen {
		t.Fatalf("boundary %q dev=%q reason=%q want 15 valid", name, dev, reason)
	}
	tree := bridgeDomainTree16792(t, name)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("12-byte name must commit: %v", err)
	}
	if len(cfg.BridgeDomains) != 1 || cfg.BridgeDomains[0].Name != name {
		t.Fatalf("domains=%+v want %q", cfg.BridgeDomains, name)
	}
	if err := ValidateBridgeDomainName(name); err != nil {
		t.Fatalf("ValidateBridgeDomainName boundary: %v", err)
	}
	// 13-byte name is first over limit.
	if _, err := CompileConfig(bridgeDomainTree16792(t, "abcdefghijklm")); err == nil {
		t.Fatal("13-byte name must reject")
	}
}

func TestBridgeDomainKernelNameASTUnion16792(t *testing.T) {
	tree := setTree11391(t,
		"set groups g1 bridge-domains customer-vlan-100 vlan-id-list 100",
		"set apply-groups g1",
	)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "customer-vlan-100") {
		t.Fatalf("applied-group long name must reject, got %v", err)
	}
	tree2 := setTree11391(t,
		"set groups node0 bridge-domains customer-vlan-100 vlan-id-list 100",
		`set apply-groups "${node}"`,
	)
	for _, run := range []func(*ConfigTree) error{
		func(tr *ConfigTree) error { _, err := CompileConfig(tr); return err },
		func(tr *ConfigTree) error { _, err := CompileConfigForNode(tr, 0); return err },
		func(tr *ConfigTree) error { _, err := CompileConfigForNode(tr, 1); return err },
	} {
		if err := run(tree2); err == nil || !strings.Contains(err.Error(), "IFNAMSIZ") {
			t.Fatalf("node-group long name must reject, got %v", err)
		}
	}
}

func TestBridgeDomainKernelNameQuarantinedLenient16792(t *testing.T) {
	tree := bridgeDomainTree16792(t, "customer-vlan-100", "bad:name", "bd0")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if len(cfg.BridgeDomains) != 1 || cfg.BridgeDomains[0].Name != "bd0" {
		t.Fatalf("active=%+v want only bd0", cfg.BridgeDomains)
	}
	if len(cfg.QuarantinedBridgeDomains) != 2 {
		t.Fatalf("quarantined=%+v want 2", cfg.QuarantinedBridgeDomains)
	}
	for _, want := range []string{"customer-vlan-100", "bad:name"} {
		found := false
		for _, q := range cfg.QuarantinedBridgeDomains {
			if q.Name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q not quarantined", want)
		}
		warnFound := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, want) && strings.Contains(w, "QUARANTINED") && strings.Contains(w, "#16792") {
				warnFound = true
			}
		}
		if !warnFound {
			t.Errorf("no quarantine warning for %q: %v", want, cfg.Warnings)
		}
	}
}

// Issue probe: full config with member interface.
func TestBridgeDomainL2OnlyProbe16792(t *testing.T) {
	tree := parseSetCommands(t,
		"set bridge-domains customer-vlan-100 vlan-id-list 100",
		"set bridge-domains customer-vlan-100 interface ge-0/0/1.100",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("L2-only probe must reject at strict compile")
	}
	treeOK := parseSetCommands(t,
		"set bridge-domains abcdefghijkl vlan-id-list 100",
		"set bridge-domains abcdefghijkl interface ge-0/0/1.100",
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
	)
	if _, err := CompileConfig(treeOK); err != nil {
		t.Fatalf("12-byte probe must commit: %v", err)
	}
}
