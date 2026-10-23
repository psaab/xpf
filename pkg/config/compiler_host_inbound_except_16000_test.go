package config

import (
	"strings"
	"testing"
)

// #16000 (EX-2-residual): an unrecognized `except` operand warned on the
// tolerant path but left the full admit in force. `all; sh except` (a typo
// for `ssh`) compiled leniently to the entire `all` expansion PLUS the stray
// `sh` token, so ssh stayed admitted — warning-without-poison, the T1 class.
// Strict already rejects the operand by name (it survives in the positive
// token list); the tolerant path must now fail closed: every recognized
// admission in the affected dimension is cleared, while the unrecognized
// operand token itself stays (it admits nothing) so both the strict gate
// and the tolerant warning keep naming it.
//
// FAIL-ON-REVERT: drop the unknown-operand poison in parseHostInboundNode
// (and its merge/cross-scope counterparts) and the tolerant cells below
// re-admit ssh/ospf.

func hostInbound16000(t *testing.T, text string) *HostInboundTraffic {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v (tolerant load must still boot)", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || zone.HostInboundTraffic == nil {
		t.Fatal("compiled trust zone has no host-inbound-traffic stanza")
	}
	return zone.HostInboundTraffic
}

func TestHostInbound16000UnknownExceptOperandPoisonsDimension(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	cases := []struct {
		name  string
		inner string
	}{
		{"services-all-typo", `system-services { all; sh except; }`},
		{"services-any-service-typo", `system-services { any-service; sh except; }`},
		{"services-subblock-typo", `system-services { all; sh { except; } }`},
		{"protocols-all-typo", `protocols { all; ospff except; }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInbound16000(t, prefix+tc.inner+suffix)
			for _, svc := range got.SystemServices {
				// `any-service` may stay as the inert full-admit marker the
				// #12054 gate diagnoses; it must not admit anything while an
				// unknown operand poisons the dimension, and no other
				// recognized token may survive.
				if svc == "any-service" && tc.name == "services-any-service-typo" {
					continue
				}
				if KnownHostInboundSystemServices[svc] {
					t.Fatalf("system-services = %v, recognized token %q survived the poison (full admit retained)", got.SystemServices, svc)
				}
			}
		})
	}
}

func TestHostInbound16000UnknownExceptStrictRejectsByName(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	cases := []struct {
		name, inner, want string
	}{
		{"services", `system-services { all; sh except; }`, "sh"},
		{"protocols", `protocols { all; ospff except; }`, "ospff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(prefix + tc.inner + suffix).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "not a recognized") {
				t.Fatalf("strict error = %v, want unknown-token diagnostic naming %q", err, tc.want)
			}
		})
	}
}

func TestHostInbound16000KnownExceptStillSubtracts(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	got := hostInbound16000(t, prefix+`system-services { all; ssh except; }`+suffix)
	if len(got.SystemServices) == 0 {
		t.Fatal("known ssh exclusion poisoned the whole dimension; want all-minus-ssh")
	}
	for _, svc := range got.SystemServices {
		if svc == "ssh" {
			t.Fatalf("known exclusion regressed: ssh still admitted in %v", got.SystemServices)
		}
	}
	protos := hostInbound16000(t, prefix+`protocols { all; ospf except; }`+suffix)
	if len(protos.Protocols) == 0 {
		t.Fatal("known ospf exclusion poisoned the whole dimension; want all-minus-ospf")
	}
	for _, p := range protos.Protocols {
		if p == "ospf" {
			t.Fatalf("known exclusion regressed: ospf still admitted in %v", protos.Protocols)
		}
	}
}

// The tolerant warning must survive the poison: the operator still learns
// which operand was unrecognized, even though the dimension now denies.
func TestHostInbound16000TolerantWarningNamesUnknownOperand(t *testing.T) {
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { all; sh except; }
	} } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `"sh"`) && strings.Contains(w, "not a recognized system-service") {
			return
		}
	}
	t.Fatalf("tolerant warnings do not name the unknown operand sh: %v", cfg.Warnings)
}

// A poisoned dimension must stay poisoned when a sibling stanza merges onto
// it: re-filtering must not resurrect the full admit from the sibling's
// positive `all`.
func TestHostInbound16000PoisonSurvivesRepeatedBlockMerge(t *testing.T) {
	tree, errs := NewParser(`security { zones { security-zone trust {
		host-inbound-traffic { system-services { all; } }
		host-inbound-traffic { system-services { sh except; } }
	} } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	got := cfg.Security.Zones["trust"].HostInboundTraffic
	if got == nil {
		t.Fatal("no host-inbound stanza")
	}
	for _, svc := range got.SystemServices {
		if KnownHostInboundSystemServices[svc] {
			t.Fatalf("merged system-services = %v, recognized token %q survived (unknown except must poison the merged dimension)", got.SystemServices, svc)
		}
	}
}

// Per-interface scope carries the same grammar and must poison identically.
func TestHostInbound16000InterfaceScopePoisons(t *testing.T) {
	tree, errs := NewParser(`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
		security { zones { security-zone trust { interfaces { ge-0/0/0.0 { host-inbound-traffic {
		system-services { all; sh except; }
	} } } } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	hib := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
	if hib == nil {
		t.Fatal("no per-interface host-inbound stanza")
	}
	for _, svc := range hib.SystemServices {
		if KnownHostInboundSystemServices[svc] {
			t.Fatalf("per-interface system-services = %v, recognized token %q survived the poison", hib.SystemServices, svc)
		}
	}
}
