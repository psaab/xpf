package config

import (
	"strings"
	"testing"
)

// #13106 (D1-01): nested host-inbound exclusions were silently dropped.
//
// `all { ssh except; }` nests the exclusion inside the `all` value block.
// The old hostInboundExceptParts walker treated any non-`except` child
// (`ssh except;`) as "not a host-inbound value" and skipped it, so the
// operator's exclusion vanished and `all` stayed fully open — fail-open
// on both the strict commit gate and SchemaValidate, since the schema
// leaf for system-services/protocols has children:nil and never descends.
//
// The fix records such nested non-except children as a new third return
// value (`nested`) that parseHostInboundNode folds into UnknownChildren
// (fail-closed plumbing: strict commit rejects, tolerant load warns and
// keeps the stanza), and — as defence in depth — SchemaValidate descends
// into the same grammar. Nested `X { except; }` blocks carrying exactly
// one plain `except;` child remain the supported #10292 subblock form
// and must keep compiling.

func nestedExcept13106(t *testing.T, inner string, interfaceScope bool) *ConfigTree {
	t.Helper()
	zoneBody := `host-inbound-traffic { ` + inner + ` }`
	if interfaceScope {
		zoneBody = `interfaces { ge-0/0/0.0 { host-inbound-traffic { ` + inner + ` } } }`
	}
	prefix := ""
	if interfaceScope {
		prefix = `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } } `
	}
	tree, errs := NewParser(prefix + `security { zones { security-zone trust { ` + zoneBody + ` } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// TestNestedHostInboundExceptRejected13106 is the RED-on-revert guard:
// reverting hostInboundExceptParts' nested recording (or the
// parseHostInboundNode/SchemaValidate wiring) makes the nested cells
// compile clean again — SystemServices=[all] with ssh admitted.
func TestNestedHostInboundExceptRejected13106(t *testing.T) {
	cases := []struct {
		name           string
		inner          string
		wantStrict     string
		wantValue      string
		interfaceScope bool
	}{
		{
			name:       "system-services nested except under all",
			inner:      `system-services { all { ssh except; } }`,
			wantStrict: "ssh",
			wantValue:  "all",
		},
		{
			name:       "protocols nested except under all",
			inner:      `protocols { all { ospf except; } }`,
			wantStrict: "ospf",
			wantValue:  "all",
		},
		{
			name:       "system-services nested except-keyed child under ssh",
			inner:      `system-services { http; ssh { except; bogus; } }`,
			wantStrict: "except",
			wantValue:  "ssh",
		},
		{
			name:       "protocols nested bogus child under ospf",
			inner:      `protocols { ospf { bogus; } }`,
			wantStrict: "bogus",
			wantValue:  "ospf",
		},
		{
			name:           "per-interface nested child",
			inner:          `system-services { all { ssh except; } }`,
			wantStrict:     "ssh",
			wantValue:      "all",
			interfaceScope: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := nestedExcept13106(t, tc.inner, tc.interfaceScope)

			// Schema gate must not stay silent on the nested shape.
			if err := SchemaValidate(tree, nil); err == nil ||
				!strings.Contains(err.Error(), tc.wantStrict) {
				t.Fatalf("SchemaValidate = %v, want error naming %q", err, tc.wantStrict)
			}
			// Strict compile gate: hard reject naming the nested token.
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), tc.wantStrict) {
				t.Fatalf("strict CompileConfig = %v, want error naming %q", err, tc.wantStrict)
			}
			// Tolerant path: boots (#1960), warns naming the token, and
			// fails closed — the poisoned value must not survive.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			if !hasWarning(cfg.Warnings, tc.wantStrict) {
				t.Fatalf("lenient warnings %v do not name nested token %q", cfg.Warnings, tc.wantStrict)
			}
			hib := cfg.Security.Zones["trust"].HostInboundTraffic
			if tc.interfaceScope {
				hib = cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
			}
			if hib == nil {
				t.Fatal("lenient compile dropped the host-inbound stanza")
			}
			for _, tok := range append(append([]string{}, hib.SystemServices...), hib.Protocols...) {
				if tok == tc.wantValue {
					t.Fatalf("tolerant load retained poisoned value %q in services=%v protocols=%v (fail-open)", tok, hib.SystemServices, hib.Protocols)
				}
			}
		})
	}
}

// TestHostInboundNestedSubblockShapesStillBind13106 pins the supported
// shapes the fix must NOT break: the #10292 `X { except; }` subblock,
// the sibling flat-tail exclusion, and a plain list.
func TestHostInboundNestedSubblockShapesStillBind13106(t *testing.T) {
	hier := nestedExcept13106(t, `system-services { all; ssh { except; } }`, false)
	if err := SchemaValidate(hier, nil); err != nil {
		t.Fatalf("SchemaValidate rejected supported subblock: %v", err)
	}
	cfg, err := CompileConfig(hier)
	if err != nil {
		t.Fatalf("strict CompileConfig rejected supported subblock: %v", err)
	}
	hib := cfg.Security.Zones["trust"].HostInboundTraffic
	for _, tok := range hib.SystemServices {
		if tok == "ssh" || tok == "all" {
			t.Fatalf("supported ssh { except; } form kept %q in %v", tok, hib.SystemServices)
		}
	}
	if len(hib.SystemServices) == 0 {
		t.Fatal("supported subblock expanded to no services")
	}

	plain := nestedExcept13106(t, `system-services { ssh; ping; } protocols { ospf; }`, false)
	if _, err := CompileConfig(plain); err != nil {
		t.Fatalf("plain list rejected: %v", err)
	}
}
