package config

import (
	"strings"
	"testing"
)

// #13119 completes D1-15: malformed args on the presence-only flag must be
// rejected by the schema/strict compile path, not merely dropped while
// leaving a poisoned zone in the compiled config.
// #13119 (D1-15 residual): #13097 made `compileZones` poison the zone on
// `tcp-rst disable;`, but D1-15 requires rejection at commit/schema
// validation: `SchemaValidate` declares `tcp-rst` as an unvalidated args:0
// leaf (schema_security.go) and `CompileConfig` accepted the malformed
// statement (only `UnknownZoneChildren`, not `DroppedEnforcementChild`,
// drives the strict unknown-child gate). This test pins the strict path.
func TestZoneTCPRstMalformedRejectedStrict13119(t *testing.T) {
	malformed := []string{
		"security { zones { security-zone trust { tcp-rst disable; } } }",
		"security { zones { security-zone trust { tcp-rst no; } } }",
		"security { zones { security-zone trust { tcp-rst false; } } }",
		"security { zones { security-zone trust { tcp-rst { disable; } } } }",
	}
	for _, text := range malformed {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse %q: %v", text, perrs)
		}
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("%q: SchemaValidate must reject malformed tcp-rst at commit", text)
		} else if !strings.Contains(err.Error(), "tcp-rst") {
			t.Fatalf("%q: SchemaValidate error must name tcp-rst, got %v", text, err)
		}

		tree2, perrs := NewParser(text).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse %q: %v", text, perrs)
		}
		if _, err := CompileConfig(tree2); err == nil {
			t.Fatalf("%q: CompileConfig must reject malformed tcp-rst at strict commit", text)
		} else if !strings.Contains(err.Error(), "tcp-rst") {
			t.Fatalf("%q: CompileConfig error must name tcp-rst, got %v", text, err)
		}
	}

	// Flat-set spelling must reject too.
	flat := &ConfigTree{}
	for _, cmd := range []string{"set security zones security-zone trust tcp-rst disable"} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := flat.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	if err := SchemaValidate(flat, nil); err == nil {
		t.Fatal("flat-set `tcp-rst disable` must be rejected by SchemaValidate")
	}
	if _, err := CompileConfig(flat); err == nil {
		t.Fatal("flat-set `tcp-rst disable` must be rejected by CompileConfig")
	}

	// Control: bare tcp-rst; still validates, compiles, and enables.
	good, perrs := NewParser("security { zones { security-zone trust { tcp-rst; } } }").Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse control: %v", perrs)
	}
	if err := SchemaValidate(good, nil); err != nil {
		t.Fatalf("bare tcp-rst must pass SchemaValidate: %v", err)
	}
	cfg, err := CompileConfig(good)
	if err != nil {
		t.Fatalf("bare tcp-rst must compile: %v", err)
	}
	if !cfg.Security.Zones["trust"].TCPRst {
		t.Fatal("bare tcp-rst must still set TCPRst")
	}

	// Tolerant path (#1960): a persisted malformed tcp-rst still boots,
	// warns, and does NOT enable TCP RST (fail-closed).
	for _, text := range malformed {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse %q: %v", text, perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("%q: tolerant compile must not brick boot: %v", text, err)
		}
		zone := cfg.Security.Zones["trust"]
		if zone == nil {
			t.Fatalf("%q: tolerant zone missing", text)
		}
		if zone.TCPRst {
			t.Fatalf("%q: tolerant path must not enable TCPRst from malformed statement", text)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "tcp-rst") {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q: tolerant path must warn naming tcp-rst, warnings=%v", text, cfg.Warnings)
		}
	}
}
