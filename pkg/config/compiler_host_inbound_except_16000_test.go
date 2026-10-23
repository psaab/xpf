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
			if strings.HasPrefix(tc.name, "protocols") {
				for _, p := range got.Protocols {
					if KnownHostInboundProtocols[hostInboundEffectiveToken(p)] {
						t.Fatalf("protocols = %v, recognized token %q survived the poison", got.Protocols, p)
					}
				}
				return
			}
			for _, svc := range got.SystemServices {
				// `any-service` may stay as the inert full-admit marker the
				// #12054 gate diagnoses; it must not admit anything while an
				// unknown operand poisons the dimension, and no other
				// recognized token may survive.
				if svc == "any-service" && tc.name == "services-any-service-typo" {
					continue
				}
				if KnownHostInboundSystemServices[hostInboundEffectiveToken(svc)] {
					t.Fatalf("system-services = %v, recognized token %q survived the poison (full admit retained)", got.SystemServices, svc)
				}
			}
		})
	}
}

// Review fold (Opus): a whitespace-padded `" any-service "` token is
// recognized by enforcement (HostInboundFullAdmitService trims) but was
// NOT recognized by the poison keep-decision, so it survived and trimmed
// into a live full admit downstream. The poison must decide on the
// normalized effective token. FAIL-ON-REVERT: drop the TrimSpace in
// hostInboundEffectiveToken / the poison helpers and the padded token
// survives again.
func TestHostInbound16000PaddedAnyServiceDoesNotSurvivePoison(t *testing.T) {
	poisoned := poisonUnknownExceptDimension(
		[]string{" any-service ", "sh"}, []string{"sh"}, KnownHostInboundSystemServices)
	for _, tok := range poisoned {
		if HostInboundFullAdmitService(tok) {
			t.Fatalf("padded full-admit token survived poison: %q in %q", tok, poisoned)
		}
		if KnownHostInboundSystemServices[hostInboundEffectiveToken(tok)] {
			t.Fatalf("recognized token %q survived poison: %q", tok, poisoned)
		}
	}
	// Padded known operand is NOT unknown: `" SSH "` except under `all`
	// must subtract at compile time — asserted on compiled semantics
	// (ssh NOT admitted), not on the helper's return value. Before the
	// filter normalized its excluded tokens, the padded operand built no
	// exclusion and ssh stayed in the `all` expansion.
	paddedTree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { all; " SSH " except; }
	} } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	paddedCfg, err := CompileConfigLenient(paddedTree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	paddedHIB := paddedCfg.Security.Zones["trust"].HostInboundTraffic
	if len(paddedHIB.SystemServices) == 0 {
		t.Fatal("padded known exclusion poisoned the dimension; want all-minus-ssh")
	}
	for _, tok := range paddedHIB.SystemServices {
		if hostInboundEffectiveToken(tok) == "ssh" {
			t.Fatalf("padded \" SSH \" except left ssh admitted: %q", paddedHIB.SystemServices)
		}
		for _, m := range HostInboundServiceMatch(tok, "ip") {
			for _, em := range HostInboundServiceMatch("ssh", "ip") {
				if !m.Reject && !em.Reject && m.Proto == em.Proto {
					for _, p := range m.Ports {
						for _, ep := range em.Ports {
							if p == ep {
								t.Fatalf("token %q still admits ssh tuple %v/%d", tok, m.Proto, p)
							}
						}
					}
				}
			}
		}
	}
	// Same for protocols: padded `" OSPF "` except must remove ospf.
	protoTree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		protocols { all; " OSPF " except; }
	} } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	protoCfg, err := CompileConfigLenient(protoTree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	for _, tok := range protoCfg.Security.Zones["trust"].HostInboundTraffic.Protocols {
		if hostInboundEffectiveToken(tok) == "ospf" {
			t.Fatalf("padded \" OSPF \" except left ospf admitted: %q", protoCfg.Security.Zones["trust"].HostInboundTraffic.Protocols)
		}
	}
	// End-to-end through the merged view: a padded any-service contributor
	// unioned with an unknown-except contributor admits nothing.
	merged := MergeHostInboundTraffic(
		&HostInboundTraffic{SystemServices: []string{" any-service "}},
		&HostInboundTraffic{SystemServices: []string{"sh"}, systemServicesExcept: []string{"sh"}},
	)
	for _, tok := range merged.SystemServices {
		if HostInboundFullAdmitService(tok) {
			t.Fatalf("merged view retained full admit %q: %q", tok, merged.SystemServices)
		}
	}
	// Quoted padded spelling through the real parser: tolerant compile
	// must not retain a full admit.
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { " any-service "; sh except; }
	} } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	for _, tok := range cfg.Security.Zones["trust"].HostInboundTraffic.SystemServices {
		if HostInboundFullAdmitService(tok) {
			t.Fatalf("tolerant compile retained full admit %q", tok)
		}
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
