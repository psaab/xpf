package config

import (
	"strings"
	"testing"
)

// #16003 — `apply-groups-except <typo>` silently no-oped on every path: the
// intended exclusion removed nothing and no diagnostic said so. The fix keeps
// the no-op (never an error — a shared cluster config may exclude a group only
// the peer defines) but warns once per distinct unresolved LITERAL name on
// every compile path. Dynamic `${...}` names stay silent.

func exceptWarnings16003(cfg *Config) []string {
	return warningsMentioning(cfg, "#16003")
}

func TestApplyGroupsExceptUnresolvedLiteralWarnsOnce16003(t *testing.T) {
	src := `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except NOPE; apply-groups-except [ NOPE ALSO-MISSING ]; domain-name example.com; }
security { zones { apply-groups-except NOPE; } }`
	cfg := compile9422(t, parseHierText(t, src))
	if cfg.System.HostName != "FROM-GROUP" {
		t.Fatalf("unresolved exclusion must remain a no-op, HostName=%q", cfg.System.HostName)
	}
	got := exceptWarnings16003(cfg)
	if len(got) != 2 {
		t.Fatalf("want exactly 2 distinct unresolved warnings (NOPE once, ALSO-MISSING once), got %v", cfg.Warnings)
	}
	if !strings.Contains(got[0], `"ALSO-MISSING"`) || !strings.Contains(got[1], `"NOPE"`) {
		t.Fatalf("warnings must be sorted by name, got %v", got)
	}
	// Tolerant path warns identically and still compiles.
	lenient, err := CompileConfigLenient(parseHierText(t, src))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if got := exceptWarnings16003(lenient); len(got) != 2 {
		t.Fatalf("lenient path must warn the same 2 names, got %v", lenient.Warnings)
	}
	// Node path warns identically.
	node, err := CompileConfigForNode(parseHierText(t, src), 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode: %v", err)
	}
	if got := exceptWarnings16003(node); len(got) != 2 {
		t.Fatalf("node path must warn the same 2 names, got %v", node.Warnings)
	}
}

func TestApplyGroupsExceptDefinedAndDynamicSilent16003(t *testing.T) {
	// Defined name (all spellings) + dynamic ${node} resolved to a defined
	// group: no warning, exclusion still honoured.
	src := `groups { G { system { host-name FROM-GROUP; } } node0 { system { host-name FROM-NODE0; } } }
apply-groups G;
system { apply-groups-except G; apply-groups-except "${node}"; domain-name example.com; }`
	cfg, err := CompileConfigForNode(parseHierText(t, src), 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode: %v", err)
	}
	if cfg.System.HostName != "" {
		t.Fatalf("defined exclusion broken, HostName=%q", cfg.System.HostName)
	}
	if got := exceptWarnings16003(cfg); len(got) != 0 {
		t.Fatalf("defined/dynamic exclusions must not warn, got %v", got)
	}
	// Generic compile: ${node} resolves via the node0 fallback to node0 (defined).
	generic := compile9422(t, parseHierText(t, src))
	if got := exceptWarnings16003(generic); len(got) != 0 {
		t.Fatalf("generic compile must resolve ${node} before judging, got %v", generic.Warnings)
	}
	// Unresolved DYNAMIC name stays silent: the peer's view may define it.
	dyn := `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except "${node}"; domain-name example.com; }`
	dcfg, err := CompileConfigForNode(parseHierText(t, dyn), 1)
	if err != nil {
		t.Fatalf("CompileConfigForNode(1): %v", err)
	}
	if dcfg.System.HostName != "FROM-GROUP" {
		t.Fatalf("dynamic unresolved exclusion must be a no-op, HostName=%q", dcfg.System.HostName)
	}
	if got := exceptWarnings16003(dcfg); len(got) != 0 {
		t.Fatalf("dynamic unresolved name must stay silent, got %v", dcfg.Warnings)
	}
	// A different variable never resolves on any node: still silent.
	other := `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except "${peer}"; domain-name example.com; }`
	ocfg := compile9422(t, parseHierText(t, other))
	if got := exceptWarnings16003(ocfg); len(got) != 0 {
		t.Fatalf("unresolved ${peer} must stay silent, got %v", ocfg.Warnings)
	}
	// Bare statement carries no name: silent, still compiles.
	bare := compile9422(t, parseHierText(t, `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except; domain-name example.com; }`))
	if got := exceptWarnings16003(bare); len(got) != 0 {
		t.Fatalf("bare apply-groups-except must not warn, got %v", bare.Warnings)
	}
}

func TestApplyGroupsExceptBlockFormUnresolved16003(t *testing.T) {
	cfg := compile9422(t, parseHierText(t, `groups { G { system { host-name FROM-GROUP; } } }
apply-groups G;
system { apply-groups-except { NOPE; G; } domain-name example.com; }`))
	if cfg.System.HostName != "" {
		t.Fatalf("block form: defined G must still be excluded, HostName=%q", cfg.System.HostName)
	}
	got := exceptWarnings16003(cfg)
	if len(got) != 1 || !strings.Contains(got[0], `"NOPE"`) {
		t.Fatalf("block form must warn only NOPE once, got %v", cfg.Warnings)
	}
}

// Packed group leaf (`target apply-groups-except TYPO;`): the exclusion rides
// the leaf's Keys tail and is materialized only during G's merge (#9862). The
// diagnostic must see it without inventing exclusions for tails expansion
// drops. Positive control: the same packed leaf naming the DEFINED H vetoes
// H with no warning.
func TestApplyGroupsExceptPackedTailUnresolved16003(t *testing.T) {
	build := func(except string) string {
		return `groups {
  G { services { rpm { probe P { test T { target apply-groups-except ` + except + `; } } } } }
  H { services { rpm { probe P { test T { target { address 10.9.9.9; } } } } } }
}
apply-groups [ G H ];
services { rpm { probe P { test T { target { url http://x/; } } } } }`
	}
	typo := compile9422(t, parseHierText(t, build("TYPO")))
	if got := exceptWarnings16003(typo); len(got) != 1 || !strings.Contains(got[0], `"TYPO"`) {
		t.Fatalf("packed-tail typo must warn once, got %v", typo.Warnings)
	}
	defined := compile9422(t, parseHierText(t, build("H")))
	if got := exceptWarnings16003(defined); len(got) != 0 {
		t.Fatalf("packed-tail defined H must not warn, got %v", defined.Warnings)
	}
}
