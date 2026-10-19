package config

import (
	"strings"
	"testing"
)

// #15138: `protocols { lldp { interface { disable; } } }` (and the
// `interface { ge-0/0/1; }` / `interface { ge-0/0/1 { disable; } }`
// spellings) panicked compileProtocols with
// "slice bounds out of range [2:1]".
//
// The block spellings carry Keys=["interface"] with the would-be name
// (or a bare disable) nested as a child. nodeVal falls back to that
// child's name, so compileProtocols treated "disable"/"ge-0/0/1" as an
// interface name and then sliced child.Keys[2:] on a 1-key node. The
// panic is reachable on every ingress that compiles: strict commit /
// commit-check, the authenticated load-override path, the tolerant
// Store.Load boot path, and the HA SyncApply path — with no recover
// above any of them, so xpfd exited.
//
// FAIL-ON-REVERT: restoring the nodeVal-based read (or the unguarded
// Keys[2:] slice) reintroduces the panic and these tests fail with it.
// A bare `len(child.Keys) > 2` guard around only the slice would stop
// the panic but silently compile a phantom interface named "disable"
// (or "ge-0/0/1" with no stated properties) — the strict-reject /
// lenient-drop assertions below reject that fix too.

var lldpNamelessBlockForms15138 = []struct {
	name string
	text string
}{
	{"bare disable block", `protocols { lldp { interface { disable; } } }`},
	{"bare name block", `protocols { lldp { interface { ge-0/0/1; } } }`},
	{"bare name with disable block", `protocols { lldp { interface { ge-0/0/1 { disable; } } } }`},
}

func TestLLDPNamelessInterfaceBlockDoesNotPanicStrict15138(t *testing.T) {
	for _, tc := range lldpNamelessBlockForms15138 {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseLLDP14616(t, tc.text)
			cfg, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict CompileConfig accepted nameless %q; compiled LLDP = %+v, want rejection", tc.text, cfg.Protocols.LLDP)
			}
			if !strings.Contains(err.Error(), "interface name is required") {
				t.Fatalf("strict CompileConfig error = %v, want naming the missing interface name", err)
			}
			if cfg != nil {
				t.Fatalf("strict CompileConfig returned a config alongside the rejection: %+v", cfg)
			}
		})
	}
}

func TestLLDPNamelessInterfaceBlockLenientWarnsAndDrops15138(t *testing.T) {
	for _, tc := range lldpNamelessBlockForms15138 {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseLLDP14616(t, tc.text)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfigLenient must not brick on %q: %v", tc.text, err)
			}
			if cfg == nil || cfg.Protocols.LLDP == nil {
				t.Fatalf("lenient %q: LLDP is nil", tc.text)
			}
			if len(cfg.Protocols.LLDP.Interfaces) != 0 {
				t.Fatalf("lenient %q compiled phantom interfaces %+v, want the nameless entry dropped", tc.text, cfg.Protocols.LLDP.Interfaces)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "interface name is required") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient %q warnings = %v, want one naming the missing interface name", tc.text, cfg.Warnings)
			}
		})
	}
}

// The store probe: the compiler consumes the apply-groups-expanded
// tree on the store paths, and the census test
// TestNoSchemaPathPanicsOnTheBlockForm_7568 must stay green with these
// spellings present in the schema walk. Pin the exact census behaviour
// for the LLDP path: compiling the block spelling under recover must
// not panic (a rejection is fine).
func TestLLDPBlockFormCensusProbe15138(t *testing.T) {
	for _, tc := range lldpNamelessBlockForms15138 {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("CompileConfig panicked on %q: %v", tc.text, r)
				}
			}()
			tree := parseLLDP14616(t, tc.text)
			_, _ = CompileConfig(tree)
			_, _ = CompileConfigLenient(tree)
		})
	}
}

// Named controls through the same code path must be untouched: the
// named block, packed, and plain spellings compile exactly as before.
func TestLLDPNamedInterfaceControlsStillCompile15138(t *testing.T) {
	for _, tc := range []struct {
		name    string
		text    string
		disable bool
	}{
		{"named block disable", `protocols { lldp { interface ge-0/0/0 { disable; } } }`, true},
		{"named packed disable", `protocols { lldp { interface ge-0/0/0 disable; } }`, true},
		{"named plain", `protocols { lldp { interface ge-0/0/0; } }`, false},
		{"named block plain", `protocols { lldp { interface ge-0/0/0 { } } }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lldp := compiledLLDP14616(t, tc.text)
			if len(lldp.Interfaces) != 1 {
				t.Fatalf("interfaces = %+v, want one", lldp.Interfaces)
			}
			if lldp.Interfaces[0].Name != "ge-0/0/0" || lldp.Interfaces[0].Disable != tc.disable {
				t.Fatalf("interface = %+v, want {ge-0/0/0 %v}", lldp.Interfaces[0], tc.disable)
			}
		})
	}
	// Flat-set named controls.
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set protocols lldp interface ge-0/0/0",
		"set protocols lldp interface ge-0/0/1 disable",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected flat named controls: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig flat named controls: %v", err)
	}
	if got := cfg.Protocols.LLDP.Interfaces; len(got) != 2 || got[0].Name != "ge-0/0/0" || got[0].Disable || got[1].Name != "ge-0/0/1" || !got[1].Disable {
		t.Fatalf("flat named controls = %+v, want [{ge-0/0/0 false} {ge-0/0/1 true}]", got)
	}
}
