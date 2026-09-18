package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9878 + #10078 — closed-world arms on the security grammar.
//
// #9878 arms `security zones` and `security policies`, so typos under either
// subtree fail closed instead of silently dropping a stanza while `show
// configuration` still displays it. `from-zone` inherits the policies arm
// (childClosed propagation in walkSchemaNode); no separate flag is needed.
//
// #10078 completes the sibling-level arm on `security` itself. A typo of a
// modeled top-level keyword (`policie` for `policies`) now fails closed too.
// Compiler-owned heterogeneous tails remain explicit opaque boundaries:
// `security flow tcp-mss all-tcp` is a valid value grammar per #1979 and is
// validated by its dedicated controls rather than by invented child keywords.
//
// Each rejection cell is RED with the relevant arm reverted (open-world
// silent-accept) and GREEN with the arm present.
func cwSecurity9878Set(bodyLines ...string) []string {
	out := []string{}
	for _, l := range bodyLines {
		out = append(out, "set security "+l)
	}
	return out
}

func TestClosedWorldSecurity9878_TypoRejected(t *testing.T) {
	for _, tc := range []struct{ line, bad string }{
		{"policies frum-zone trust to-zone untrust policy p1 then permit", "frum-zone"},
		{"policies from-zone trust to-zone untrust policy p1 mach source-address any", "mach"},
		{"zones security-zone trust interfces ge-0/0/0", "interfces"},
		{"zones security-zone trust host-inbound-traffic system-servces ssh", "system-servces"},
	} {
		tree := buildTree(t, cwSecurity9878Set(tc.line))
		err := SchemaValidate(tree, nil)
		if err == nil {
			t.Fatalf("typo %q must be rejected at commit, not silently dropped", tc.line)
		}
		if !strings.Contains(err.Error(), tc.bad) || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("error must name the typo %q and the closed-world subtree, got: %v", tc.bad, err)
		}
	}
}

// TestClosedWorldSecurity9878_MidKeywordRejected (spark-F1): the `to-zone`
// middle keyword of a from-zone stanza is structural, not a value — the
// compiler reads Keys[1],Keys[3] and ignores Keys[2], so `to-zon`
// committed clean pre-fix while the operator misspelled the pair. Both the
// flat-set packed shape and the hierarchical nested shape are rejected
// naming the token; the correctly-spelled nested shape still commits.
func TestClosedWorldSecurity9878_MidKeywordRejected(t *testing.T) {
	flat := buildTree(t, cwSecurity9878Set(
		"policies from-zone trust to-zon untrust policy p1 then permit",
	))
	if err := SchemaValidate(flat, nil); err == nil {
		t.Fatal("flat `to-zon` must be rejected at commit, not silently accepted")
	} else if !strings.Contains(err.Error(), "to-zon") {
		t.Fatalf("flat rejection must name the typo token, got: %v", err)
	}
	hierText := `security {
    policies {
        from-zone trust to-zon untrust {
            policy p1 {
                then permit;
            }
        }
    }
}`
	hier, perrs := NewParser(hierText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical fixture does not parse: %v", perrs)
	}
	if err := SchemaValidate(hier, nil); err == nil {
		t.Fatal("hierarchical nested `to-zon` must be rejected at commit, not silently accepted")
	} else if !strings.Contains(err.Error(), "to-zon") {
		t.Fatalf("hierarchical rejection must name the typo token, got: %v", err)
	}
	// Control: the correctly-spelled nested shape still commits.
	okText := `security {
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                then permit;
            }
        }
    }
}`
	ok, perrs := NewParser(okText).Parse()
	if len(perrs) > 0 {
		t.Fatalf("control fixture does not parse: %v", perrs)
	}
	if err := SchemaValidate(ok, nil); err != nil {
		t.Fatalf("correctly-spelled nested from-zone must commit clean, got: %v", err)
	}
}

// TestClosedWorldSecurity9878_AcceptsValid proves no false-reject: every
// modeled zones/policies leaf still commits clean under closed-world,
// including the shapes most likely to collide with the gate — wildcard
// interface names, multi-value list leaves, block-form valued leaves, and
// the default-policy valued leaf.
func TestClosedWorldSecurity9878_AcceptsValid(t *testing.T) {
	valid := [][]string{
		{
			"policies from-zone trust to-zone untrust policy p1 match source-address any",
			"policies from-zone trust to-zone untrust policy p1 match destination-address any",
			"policies from-zone trust to-zone untrust policy p1 match application any",
			"policies from-zone trust to-zone untrust policy p1 then permit",
		},
		{
			"policies global policy gp1 match source-address any",
			"policies global policy gp1 match destination-address any",
			"policies global policy gp1 match application any",
			"policies global policy gp1 then deny",
		},
		{
			"policies default-policy deny-all",
		},
		{
			"zones security-zone trust interfaces ge-0/0/0",
			"zones security-zone trust host-inbound-traffic system-services ssh",
			"zones security-zone trust host-inbound-traffic protocols ping",
			"zones security-zone trust description edge-zone",
			"zones security-zone trust tcp-rst",
			"zones security-zone trust screen ids-opt1",
			"zones security-zone trust address-book address web 10.0.5.0/24",
			"zones security-zone trust address-book address-set grp address web",
			"zones security-zone trust address-book address-set outer address-set grp",
		},
		{
			"zones security-zone trust interfaces ge-0/0/1 host-inbound-traffic system-services ssh",
		},
		{
			// Bare `interfaces <if>`: zone membership only, no body.
			"zones security-zone dmz interfaces ge-0/0/2",
		},
		{
			"policies policy-rematch extensive",
			"policies default-policy-log session-init",
			"policies default-policy-log [ session-init session-close ]",
		},
		{
			"policies from-zone trust to-zone untrust policy p2 match source-address-excluded",
			"policies from-zone trust to-zone untrust policy p2 match destination-address-excluded",
			"policies from-zone trust to-zone untrust policy p2 match source-address any",
			"policies from-zone trust to-zone untrust policy p2 match destination-address any",
			"policies from-zone trust to-zone untrust policy p2 match application any",
			"policies from-zone trust to-zone untrust policy p2 then deny log session-init",
			"policies from-zone trust to-zone untrust policy p2 then deny count",
			"policies from-zone trust to-zone untrust policy p2 scheduler-name sched1",
			"policies from-zone trust to-zone untrust policy p2 description pair-policy",
		},
		{
			"policies global policy gp2 match from-zone trust",
			"policies global policy gp2 match to-zone untrust",
			"policies global policy gp2 match source-address any",
			"policies global policy gp2 match destination-address any",
			"policies global policy gp2 match application any",
			"policies global policy gp2 then log session-init",
			"policies global policy gp2 then count",
			"policies global policy gp2 scheduler-name sched1",
		},
	}
	for _, stanza := range valid {
		tree := buildTree(t, cwSecurity9878Set(stanza...))
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("valid zones/policies stanza %q must commit clean under closed-world, got: %v", stanza, err)
		}
	}
}

// TestClosedWorldSecurity9878_HierarchicalShapes: the typo cells above are
// flat-set only (buildTree). The hierarchical (braced) spelling must reject
// typos too — a gate that only closed one serialization would leave the
// other open — and must accept the blockValue + nested-container shapes.
func TestClosedWorldSecurity9878_HierarchicalShapes(t *testing.T) {
	parse := func(text string) *ConfigTree {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse: %v", perrs)
		}
		return tree
	}
	for _, tc := range []struct{ name, text, bad string }{
		{"frum-zone", `security { policies { frum-zone trust to-zone untrust { policy p1 { then permit; } } } }`, "frum-zone"},
		{"interfces", `security { zones { security-zone trust { interfces ge-0/0/0; } } }`, "interfces"},
		{"match-typo", `security { policies { from-zone trust to-zone untrust { policy p1 { mach { source-address any; } then permit; } } } }`, "mach"},
	} {
		if err := SchemaValidate(parse(tc.text), nil); err == nil {
			t.Fatalf("hierarchical typo %q must be rejected at commit", tc.name)
		} else if !strings.Contains(err.Error(), tc.bad) {
			t.Fatalf("hierarchical rejection must name %q, got: %v", tc.bad, err)
		}
	}
	// Valid hierarchical shapes: default-policy blockValue, nested
	// zone/policy containers, address-book nesting.
	validHier := `security {
    policies {
        default-policy { deny-all; }
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then permit;
            }
        }
    }
    zones {
        security-zone trust {
            interfaces ge-0/0/0;
            host-inbound-traffic { system-services { ssh; } }
            address-book { address web 10.0.5.0/24; }
        }
    }
}`
	if err := SchemaValidate(parse(validHier), nil); err != nil {
		t.Fatalf("valid hierarchical zones/policies must commit clean, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_PolicieRejected pins the security-level arm:
// `policie` is a sibling-level typo of `policies`, so the #9878 subtree arms
// could not catch it. Both flat-set and hierarchical forms must now reject it
// naming the authored token. Reverting the security arm makes this RED.
func TestClosedWorldSecurity10078_PolicieRejected(t *testing.T) {
	flat := buildTree(t, cwSecurity9878Set(
		"policie from-zone trust to-zone untrust policy p1 then permit",
	))
	if err := SchemaValidate(flat, nil); err == nil {
		t.Fatal("flat `policie` must be rejected at the security boundary")
	} else if !strings.Contains(err.Error(), "policie") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("flat rejection must name `policie` and closed-world, got: %v", err)
	}
	hier, perrs := NewParser(`security { policie { from-zone trust to-zone untrust { policy p1 { then permit; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical fixture does not parse: %v", perrs)
	}
	if err := SchemaValidate(hier, nil); err == nil {
		t.Fatal("hierarchical `policie` must be rejected at the security boundary")
	} else if !strings.Contains(err.Error(), "policie") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("hierarchical rejection must name `policie` and closed-world, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_TCPMSSOpaqueGrammar pins the #1979 exception.
// The security-level arm must still accept the shipped `all-tcp` grammar in
// both AST shapes, while the modeled kind list rejects a typo kind. Reverting
// either the kind modeling or the opaque-tail boundary makes one half RED.
func TestClosedWorldSecurity10078_TCPMSSOpaqueGrammar(t *testing.T) {
	flat := buildTree(t, []string{"set security flow tcp-mss all-tcp 1350"})
	if err := SchemaValidate(flat, nil); err != nil {
		t.Fatalf("flat all-tcp MSS must survive the security arm: %v", err)
	}
	cfg, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("flat all-tcp MSS must compile: %v", err)
	}
	if got := cfg.Security.Flow.TCPMSSAllTCP; got != 1350 {
		t.Fatalf("flat all-tcp MSS compiled as %d, want 1350", got)
	}

	hier, perrs := NewParser(`security { flow { tcp-mss { all-tcp { mss 1360; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical all-tcp fixture does not parse: %v", perrs)
	}
	if err := SchemaValidate(hier, nil); err != nil {
		t.Fatalf("hierarchical all-tcp MSS must survive the security arm: %v", err)
	}
	cfg, err = CompileConfig(hier)
	if err != nil {
		t.Fatalf("hierarchical all-tcp MSS must compile: %v", err)
	}
	if got := cfg.Security.Flow.TCPMSSAllTCP; got != 1360 {
		t.Fatalf("hierarchical all-tcp MSS compiled as %d, want 1360", got)
	}

	bad := buildTree(t, []string{"set security flow tcp-mss all-tpc 1350"})
	if err := SchemaValidate(bad, nil); err == nil {
		t.Fatal("misspelled tcp-mss kind must be rejected by the security arm")
	} else if !strings.Contains(err.Error(), "all-tpc") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("tcp-mss kind rejection must name all-tpc and closed-world, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_PackedLogRunExpansion pins the compiler/schema
// parity for SetPath's nested packed stream shape. `expandFlatRun` hoists the
// valid category sibling before the closed-world walk; a misspelled sibling
// must remain visible and reject rather than pass through an opaque port leaf.
func TestClosedWorldSecurity10078_PackedLogRunExpansion(t *testing.T) {
	valid := buildTree(t, []string{
		"set security log stream s1 port 5514 category policy",
	})
	if err := SchemaValidate(valid, nil); err != nil {
		t.Fatalf("valid packed stream run must survive the security arm: %v", err)
	}
	bad := buildTree(t, []string{
		"set security log stream s1 port 5514 categroy policy",
	})
	if err := SchemaValidate(bad, nil); err == nil {
		t.Fatal("misspelled packed stream sibling must be rejected under closed-world")
	} else if !strings.Contains(err.Error(), "categroy") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("packed stream rejection must name categroy and closed-world, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_PackedDestinationPortArity ensures the
// address-plus-port Junos suffix consumes exactly the declared port value.
// A trailing token must return to the pool-level schema walk and be rejected,
// rather than being absorbed into the address leaf and overwritten by the
// compiler's packed-address scanner.
func TestClosedWorldSecurity10078_PackedDestinationPortArity(t *testing.T) {
	valid := buildTree(t, []string{
		"set security nat destination pool p1 address 192.0.2.1 port 80",
	})
	if err := SchemaValidate(valid, nil); err != nil {
		t.Fatalf("valid packed destination port must survive the security arm: %v", err)
	}
	bad := buildTree(t, []string{
		"set security nat destination pool p1 address 192.0.2.1 port 80 192.0.2.2",
	})
	if err := SchemaValidate(bad, nil); err == nil {
		t.Fatal("trailing token after packed destination port must be rejected")
	} else if !strings.Contains(err.Error(), "192.0.2.2") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("trailing-token rejection must name 192.0.2.2 and closed-world, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_PoolUtilizationAlarmGrammar pins the #2079
// compiler-read source-NAT alarm under the inherited security boundary. The
// distinct 80/55 pair proves the clear value is preserved rather than replaced
// by the raise-only default, and a misspelled leaf must fail closed.
func TestClosedWorldSecurity10078_PoolUtilizationAlarmGrammar(t *testing.T) {
	valid := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 80 clear-threshold 55",
	})
	if err := SchemaValidate(valid, nil); err != nil {
		t.Fatalf("valid pool-utilization-alarm must survive the security arm: %v", err)
	}
	cfg, err := CompileConfig(valid)
	if err != nil {
		t.Fatalf("valid pool-utilization-alarm must compile: %v", err)
	}
	a := cfg.Security.NAT.PoolUtilizationAlarm
	if a == nil || a.RaiseThreshold != 80 || a.ClearThreshold != 55 {
		t.Fatalf("alarm thresholds were not preserved: %+v", a)
	}
	bad := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 80 clear-threshhold 55",
	})
	if err := SchemaValidate(bad, nil); err == nil {
		t.Fatal("misspelled pool-utilization-alarm leaf must be rejected")
	} else if !strings.Contains(err.Error(), "clear-threshhold") {
		t.Fatalf("alarm typo rejection must name the token, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_DirectIPsecVPNLeaves pins the direct VPN
// spelling alongside the existing nested `ike` form. Both leaves are read by
// compileIPsec, so the direct shape must commit and a typo must fail closed.
func TestClosedWorldSecurity10078_DirectIPsecVPNLeaves(t *testing.T) {
	valid := buildTree(t, []string{
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec policy esp-pol proposal-set standard",
		"set security ipsec vpn tun1 gateway gw1 ipsec-policy esp-pol",
	})
	if err := SchemaValidate(valid, nil); err != nil {
		t.Fatalf("direct gateway/ipsec-policy leaves must survive the security arm: %v", err)
	}
	cfg, err := CompileConfig(valid)
	if err != nil {
		t.Fatalf("direct gateway/ipsec-policy leaves must compile strictly: %v", err)
	}
	vpn := cfg.Security.IPsec.VPNs["tun1"]
	if vpn == nil || vpn.Gateway != "gw1" || vpn.IPsecPolicy != "esp-pol" {
		t.Fatalf("direct VPN leaves were not preserved: %+v", vpn)
	}

	hier, perrs := NewParser(`security {
    ike { gateway gw1 { address 192.0.2.1; } }
    ipsec {
        proposal esp-p1 {
            protocol esp;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm hmac-sha-256-128;
        }
        policy esp-pol { proposals esp-p1; }
        vpn tun1 gateway gw1 ipsec-policy esp-pol;
    }
}`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical direct VPN fixture does not parse: %v", perrs)
	}
	if err := SchemaValidate(hier, nil); err != nil {
		t.Fatalf("hierarchical direct VPN leaves must survive the security arm: %v", err)
	}
	hcfg, err := CompileConfig(hier)
	if err != nil {
		t.Fatalf("hierarchical direct gateway/ipsec-policy leaves must compile strictly: %v", err)
	}
	hvpn := hcfg.Security.IPsec.VPNs["tun1"]
	if hvpn == nil || hvpn.Gateway != "gw1" || hvpn.IPsecPolicy != "esp-pol" {
		t.Fatalf("hierarchical direct VPN leaves were not preserved: %+v", hvpn)
	}

	bad := buildTree(t, []string{
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec policy esp-pol proposal-set standard",
		"set security ipsec vpn tun1 gateway gw1 ipsec-policie esp-pol",
	})
	if err := SchemaValidate(bad, nil); err == nil {
		t.Fatal("misspelled direct ipsec-policy leaf must be rejected")
	} else if !strings.Contains(err.Error(), "ipsec-policie") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("direct VPN typo rejection must name the token and closed-world boundary, got: %v", err)
	}
}

// TestClosedWorldSecurity10078_CompletionPinsSubtrees verifies the same
// modeled keywords drive config-mode completion. This keeps the closed-world
// inventory and the user-facing schema surface from drifting apart.
func TestClosedWorldSecurity10078_CompletionPinsSubtrees(t *testing.T) {
	flow := CompleteSetPathWithValues([]string{"security", "flow", "tcp-mss"}, nil)
	for _, want := range []string{"all-tcp", "gre-in", "gre-out", "ipsec-vpn"} {
		if !containsCompletionName(flow, want) {
			t.Fatalf("flow tcp-mss completion missing %q: %v", want, completionNames(flow))
		}
	}
	alg := CompleteSetPathWithValues([]string{"security", "alg", "d"}, nil)
	if !containsCompletionName(alg, "dns") {
		t.Fatalf("ALG class completion missing dns: %v", completionNames(alg))
	}
	ike := CompleteSetPathWithValues([]string{"security", "ike", "proposal", "p1", "a"}, nil)
	for _, want := range []string{"authentication-method", "authentication-algorithm"} {
		if !containsCompletionName(ike, want) {
			t.Fatalf("IKE proposal completion missing %q: %v", want, completionNames(ike))
		}
	}
}

// TestClosedWorldSecurity9878_LenientDoesNotBrick binds only the
// downgrade FUNCTION (CompileConfigLenient must not error on the typo) —
// it deliberately does NOT bind the Store.Load/SyncApply ingress, which
// lives in pkg/configstore and is bound there by
// TestLoadToleratesSecurityTypo_9878 (a pkg/config cell alone would stay
// green while a change that made Load schema-validate bricked booting
// nodes — the ipip_no_brick_4785 argument). #1960.
func TestClosedWorldSecurity9878_LenientDoesNotBrick(t *testing.T) {
	typoTree := buildTree(t, cwSecurity9878Set("policies frum-zone trust to-zone untrust policy p1 then permit"))
	if err := SchemaValidate(typoTree, nil); err == nil {
		t.Fatal("precondition: strict SchemaValidate must reject the typo")
	}
	if _, err := CompileConfigLenient(typoTree); err != nil {
		t.Fatalf("the lenient load/peer-sync path must not brick on a closed-world typo (#1960); got: %v", err)
	}
}

// TestClosedWorldSecurity9878_ShippedConfigsStillCommit sweeps every
// shipped and example config through strict SchemaValidate: the arm must
// not false-reject any production grammar (the #8882 lesson — a gate that
// rejects everything satisfies the typo cells above).
//
// NO SILENT SKIPS (GPT-2/spark-F7): every globbed file must validate — a
// read failure, a parse failure, or a validation failure is a sweep
// failure, and checked!=len(files) fails. A sweep that logs green on a
// partial population is the vacuous-pass this harness exists to prevent.
// The positive control walks the SAME file path (temp file + NewParser),
// not the buildTree unit path, so it proves the sweep itself can report.
func TestClosedWorldSecurity9878_ShippedConfigsStillCommit(t *testing.T) {
	var files []string
	for _, g := range []string{"../../docs/*.conf", "../../examples/deploy/*.conf", "../../test/incus/*.conf"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no shipped configs found — this sweep would pass vacuously")
	}
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("%s unreadable, sweep cannot certify it: %v", filepath.Base(f), err)
			continue
		}
		tree, perrs := NewParser(string(b)).Parse()
		if len(perrs) > 0 {
			t.Errorf("%s does not parse, sweep cannot certify it: %v", filepath.Base(f), perrs)
			continue
		}
		cfg, _ := CompileConfigLenient(tree)
		tree2, _ := NewParser(string(b)).Parse()
		if err := SchemaValidate(tree2, cfg); err != nil {
			t.Errorf("%s no longer validates: %v", filepath.Base(f), err)
			continue
		}
		checked++
	}
	if checked != len(files) {
		t.Fatalf("sweep certified %d of %d shipped/example configs — partial green is failure", checked, len(files))
	}
	t.Logf("swept %d/%d shipped/example configs, all validate", checked, len(files))
	// POSITIVE CONTROL through the same file path: a typo config written
	// to a temp file and parsed with NewParser must still reject, or the
	// sweep above cannot report one.
	ctlPath := filepath.Join(t.TempDir(), "ctl-frum-zone.conf")
	if err := os.WriteFile(ctlPath, []byte("security {\n policies {\n frum-zone trust to-zone untrust {\n policy p1 {\n then permit;\n }\n }\n }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cb, _ := os.ReadFile(ctlPath)
	ctl, perrs := NewParser(string(cb)).Parse()
	if len(perrs) > 0 {
		t.Fatalf("control file does not parse — the control proves nothing: %v", perrs)
	}
	if err := SchemaValidate(ctl, nil); err == nil {
		t.Fatal("the control typo was accepted through the file path — this sweep cannot report a rejection")
	}
}
