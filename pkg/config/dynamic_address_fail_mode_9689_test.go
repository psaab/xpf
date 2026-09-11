package config

import "testing"

// TestDynamicAddressFailModeCompiles9689: `profile fail-mode` reaches the
// compiled binding, and an omitted leaf leaves the default (retain).
func TestDynamicAddressFailModeCompiles9689(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security dynamic-address feed-server partners url http://example.test/partners",
		"set security dynamic-address address-name allow-partners profile feed-name partners",
		"set security dynamic-address address-name allow-partners profile fail-mode drop",
		"set security dynamic-address address-name deny-threats profile feed-name partners",
	})
	if b := cfg.Security.DynamicAddress.AddressBindings["allow-partners"]; b == nil || b.FailMode != "drop" {
		t.Fatalf("allow-partners compiled as %+v, want FailMode drop", b)
	}
	if b := cfg.Security.DynamicAddress.AddressBindings["deny-threats"]; b == nil || b.FailMode != "" {
		t.Fatalf("deny-threats compiled as %+v, want the default (empty) FailMode", b)
	}
}

// TestDynamicAddressFailModeRejectsUnknownValue9689: the commit gate refuses a
// fail-mode outside retain|drop, and accepts both valid values.
func TestDynamicAddressFailModeRejectsUnknownValue9689(t *testing.T) {
	base := []string{
		"set security dynamic-address feed-server partners url http://example.test/partners",
		"set security dynamic-address address-name allow-partners profile feed-name partners",
	}
	for _, v := range []string{"retain", "drop"} {
		tree := buildTreeFromSet(t, append(append([]string(nil), base...), "set security dynamic-address address-name allow-partners profile fail-mode "+v))
		if err := SchemaValidate(tree, nil); err != nil {
			t.Errorf("fail-mode %s rejected: %v", v, err)
		}
	}
	tree := buildTreeFromSet(t, append(append([]string(nil), base...), "set security dynamic-address address-name allow-partners profile fail-mode sometimes"))
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("fail-mode sometimes was accepted; the commit gate must refuse it")
	}
}

// TestDynamicAddressFailModeSurvivesOneLineSpellings9689: every one-line
// spelling keeps fail-mode, including the compact `profile fail-mode drop;` form
// the #2419 normalizer folds. The flat set line nests it under feed-name, and the
// braced one-line block packs both leaves onto one node. The strict walk refuses
// both, so the loss would only reach a node through a persisted config or an HA
// sync, which is why the lenient compile is what is asserted.
func TestDynamicAddressFailModeSurvivesOneLineSpellings9689(t *testing.T) {
	flat := buildTreeFromSet(t, []string{
		"set security dynamic-address feed-server partners url http://example.test/partners",
		"set security dynamic-address address-name allow-partners profile feed-name partners fail-mode drop",
	})
	braced, err := NewParser(`security { dynamic-address { feed-server partners { url http://example.test/partners; } address-name allow-partners { profile { feed-name partners fail-mode drop; } } } }`).Parse()
	if err != nil {
		t.Fatalf("parse braced: %v", err)
	}
	compact, err := NewParser(`security { dynamic-address { feed-server partners { url http://example.test/partners; } address-name allow-partners { profile feed-name partners; profile fail-mode drop; } } }`).Parse()
	if err != nil {
		t.Fatalf("parse compact: %v", err)
	}
	for name, tree := range map[string]*ConfigTree{"flat": flat, "braced": braced, "compact": compact} {
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("%s: lenient compile: %v", name, err)
		}
		b := cfg.Security.DynamicAddress.AddressBindings["allow-partners"]
		if b == nil || len(b.FeedNames) != 1 || b.FeedNames[0] != "partners" || b.FailMode != "drop" {
			t.Errorf("%s one-line spelling compiled as %+v, want feed partners and fail-mode drop", name, b)
		}
	}
}
