package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue 8882: a typo'd TOP-LEVEL stanza committed clean and silently discarded
// everything under it.
//
//	securty { zones { security-zone z1 { } } }   compiles clean, zones=0
//
// Not one leaf -- the whole stanza. The keyword resolves to no schema node, so
// the walk never descends and nothing reports it.
//
// WHY THIS IS NOT setSchema.closedWorld, which is the obvious fix and is wrong.
// The closed-world flag INHERITS (`childClosed := closed || childSchema.closedWorld`),
// so arming it at the root closes every subtree below it, and the schema does
// configs: the pre-#10078 census had 9 of 10 rejected --
//
//	chassis cluster redundancy-group 1 interface-monitor
//	system services dhcp-local-server group <g> pool
//	interfaces <if> unit 0 family inet6 dhcpv6
//	security flow tcp-mss all-tcp (historical; admitted by #10078's
//	opaque tcp-mss boundary)
//
// That pre-#10078 figure represented an operational blackout on the commit
// path. The gate closes exactly ONE level and inherits nothing.

func schemaCheck8882(t *testing.T, text string) error {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
	}
	cfg, _ := CompileConfigLenient(tree)
	tree2, _ := NewParser(text).Parse()
	return SchemaValidate(tree2, cfg)
}

func TestUnknownTopLevelStanzaIsRejected8882(t *testing.T) {
	for _, c := range []struct{ name, text string }{
		{"typo'd stanza", `securty { zones { security-zone z1 { } } }`},
		{"unmodeled stanza", `quantum-firewall { enable; }`},
	} {
		err := schemaCheck8882(t, c.text)
		if err == nil {
			t.Errorf("%s: accepted. Everything under an unrecognised root keyword is "+
				"silently discarded, so a clean commit hides the loss of a whole stanza", c.name)
			continue
		}
		if !strings.Contains(err.Error(), "securty") && !strings.Contains(err.Error(), "quantum-firewall") {
			t.Errorf("%s: rejected, but not for the stanza keyword — a different complaint would "+
				"pass this cell while leaving the defect open: %v", c.name, err)
		}
	}
}

// The gate must close exactly ONE level. If it ever starts inheriting, this
// cell reds -- and it is the cheap early warning for the blackout measured
// above, since a deep unmodeled keyword is exactly what the shipped configs
// carry.
func TestTopLevelGateDoesNotInherit8882(t *testing.T) {
	for _, c := range []struct{ name, text string }{
		{"unmodeled child of a real stanza", `interfaces { intfce { unit 0 { family inet { address 192.0.2.1/32; } } } }`},
		{"the shape shipped configs carry", `chassis { cluster { redundancy-group 1 { interface-monitor ge-0/0/0 weight 255; } } }`},
	} {
		if err := schemaCheck8882(t, c.text); err != nil {
			t.Errorf("%s: REJECTED by the top-level gate. It must close one level and inherit "+
				"nothing — the schema does not model every depth, and closing the whole tree "+
				"rejects 9 of the 10 shipped configs: %v", c.name, err)
		}
	}
}

// NON-VACUITY: a real stanza must still be accepted, and must still deliver its
// contents. A gate that rejected everything would satisfy the cells above.
func TestRealTopLevelStanzaStillCompiles8882(t *testing.T) {
	const text = `security { zones { security-zone z1 { } } }`
	if err := schemaCheck8882(t, text); err != nil {
		t.Fatalf("a real stanza was rejected: %v", err)
	}
	tree, _ := NewParser(text).Parse()
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.Security.Zones) != 1 {
		t.Fatalf("got %d zones, want 1 — the cell above would pass against an empty config",
			len(cfg.Security.Zones))
	}
}

// Every shipped and example config must still pass the gate. The control file
// makes a clean sweep a finding rather than a broken harness.
func TestShippedConfigsPassTopLevelGate8882(t *testing.T) {
	var files []string
	for _, g := range []string{"../../docs/*.conf", "../../examples/deploy/*.conf", "../../test/incus/*.conf"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no shipped configs found — this cell would pass vacuously")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		tree, perrs := NewParser(string(b)).Parse()
		if len(perrs) > 0 {
			continue
		}
		cfg, _ := CompileConfigLenient(tree)
		tree2, _ := NewParser(string(b)).Parse()
		if err := SchemaValidate(tree2, cfg); err != nil {
			t.Errorf("%s no longer validates: %v", filepath.Base(f), err)
		}
	}
	// POSITIVE CONTROL.
	ctl := filepath.Join(t.TempDir(), "ctl.conf")
	if err := os.WriteFile(ctl, []byte("securty { zones { } }"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(ctl)
	tree, _ := NewParser(string(b)).Parse()
	cfg, _ := CompileConfigLenient(tree)
	tree2, _ := NewParser(string(b)).Parse()
	if err := SchemaValidate(tree2, cfg); err == nil {
		t.Fatal("the control config was accepted — this sweep cannot report a rejection, " +
			"so the shipped results above mean nothing")
	}
}
