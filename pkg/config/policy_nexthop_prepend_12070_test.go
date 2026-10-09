package config

import (
	"strings"
	"testing"
)

// #12070 RED-before: `then next-hop` accepts FRR-invalid operands at
// commit-check. Junos `next-hop (address | discard | next-table table-name |
// peer-address | reject | self)` values `discard`, `reject`, and
// `next-table` are valid Junos that this tree renders as
// `set ip next-hop <tok>` — a line FRR's `set ip next-hop A.B.C.D$addr`
// grammar rejects at the vtysh MARK pass, failing the whole frr-reload. A
// malformed IPv4 literal (`10.0.0.300`) fails the same way. Base has no
// valueType/validator on the leaf (schema_routing.go), so every bad token
// below commits green → RED until the gate lands.
func TestPolicyThenNextHop_SchemaGate_12070(t *testing.T) {
	base := "set policy-options policy-statement P term t1 "
	bad := []string{"discard", "reject", "next-table", "10.0.0.300", "not-an-ip", "1.2.3", "2001:db8::garbage", "0.0.0.0", "0.1.2.3", "127.0.0.1", "::", "::1", "fe80::1", "ff02::1", "224.0.0.1"}
	good := []string{"192.0.2.1", "10.0.0.1", "2001:db8::1", "169.254.1.1", "240.0.0.1", "255.255.255.255", "::ffff:192.0.2.1", "peer-address", "self"}

	for _, v := range bad {
		tree := flatTreeFromSets(t, base+"then next-hop "+v)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("then next-hop %q: expected SchemaValidate to reject, got nil", v)
		}
	}
	for _, v := range good {
		tree := flatTreeFromSets(t, base+"then next-hop "+v)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("then next-hop %q: expected SchemaValidate to accept, got %v", v, err)
		}
	}
}

func TestPolicyThenNextHop_ExclusionErrorNamesReason_12070(t *testing.T) {
	base := "set policy-options policy-statement P term t1 then next-hop "
	for _, tc := range []struct {
		address string
		reason  string
	}{
		{"127.0.0.1", "loopback"},
		{"0.1.2.3", "IPv4 0/8"},
		{"224.0.0.1", "multicast"},
		{"fe80::1", "IPv6 link-local"},
		{"0.0.0.0", "unspecified"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			tree := flatTreeFromSets(t, base+tc.address)
			err := SchemaValidate(tree, nil)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("SchemaValidate error = %v, want reason %q", err, tc.reason)
			}
		})
	}
}

// #12070 RED-before: `then as-path-prepend` accepts non-ASN tokens at
// commit-check. FRR's `set as-path prepend ASNUM...` grammar takes AS
// numbers only; `65001 abc` renders verbatim and fails the reload. The
// leaf is multi:true so EVERY token is validated (bracketed and repeated
// spellings included). Base has no validator → RED until the gate lands.
func TestPolicyThenASPathPrepend_SchemaGate_12070(t *testing.T) {
	base := "set policy-options policy-statement P term t1 "
	bad := []string{
		"then as-path-prepend abc",
		"then as-path-prepend 0",
		"then as-path-prepend 4294967296",
		"then as-path-prepend 65001.5",
		"then as-path-prepend 1.10",
		"then as-path-prepend [ 65001 abc ]",
		"then as-path-prepend [ 65001 0 ]",
		"then as-path-prepend 065001",
		"then as-path-prepend 00001",
		"then as-path-prepend [ 65001 065001 ]",
		"then as-path-prepend [ 65001 00001 ]",
	}
	good := []string{
		"then as-path-prepend 1",
		"then as-path-prepend 65001",
		"then as-path-prepend 4294967295",
		"then as-path-prepend [ 65001 65001 ]",
	}

	for _, c := range bad {
		tree := flatTreeFromSets(t, base+c)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("%q: expected SchemaValidate to reject, got nil", c)
		}
	}
	for _, c := range good {
		tree := flatTreeFromSets(t, base+c)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("%q: expected SchemaValidate to accept, got %v", c, err)
		}
	}
}

// #12070: SchemaValidate is the strict commit-check gate; rejection must
// identify the path and offending value rather than defer failure to FRR.
func TestPolicyThenNextHopPrepend_RejectionNamesValue_12070(t *testing.T) {
	base := "set policy-options policy-statement P term t1 "
	for _, tc := range []struct{ set, leaf, value string }{
		{base + "then next-hop discard", "next-hop", "discard"},
		{base + "then next-hop 10.0.0.300", "next-hop", "10.0.0.300"},
		{base + "then as-path-prepend 65001 abc", "as-path-prepend", "abc"},
	} {
		err := SchemaValidate(buildTreeFromSet(t, []string{tc.set}), nil)
		if err == nil {
			t.Fatalf("%q: expected SchemaValidate to reject, got nil", tc.set)
		}
		for _, want := range []string{"P", "t1", tc.leaf, tc.value} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%q: schema error %q must name %q", tc.set, err.Error(), want)
			}
		}
	}
}

// #12070: valid operands keep compiling strict — the gate must not
// over-reject working configs.
func TestPolicyThenNextHopPrepend_ValidCompiles_12070(t *testing.T) {
	base := "set policy-options policy-statement P term t1 "
	tree := buildTreeFromSet(t, []string{
		base + "then next-hop 192.0.2.1",
		"set policy-options policy-statement P term t2 then next-hop 2001:db8::1",
		"set policy-options policy-statement P term t3 then next-hop peer-address",
		"set policy-options policy-statement P term t4 then next-hop self",
		"set policy-options policy-statement P term t5 then as-path-prepend 65001",
		"set policy-options policy-statement P term t6 then as-path-prepend [ 65001 65001 ]",
		"set policy-options policy-statement P term t7 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected valid operands: %v", err)
	}
}

func TestPolicyThenASPathPrepend_QuotedMultiASN_12070(t *testing.T) {
	text := `policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then {
                as-path-prepend "65001 65001";
                accept;
            }
        }
    }
}`
	tree, parseErrs := NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected the documented quoted multi-ASN form: %v", err)
	}
	compiled, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected the documented quoted multi-ASN form: %v", err)
	}
	wantASNs(t, "quoted ASPathPrepend", compiled.PolicyOptions.PolicyStatements["P"].Terms[0].ASPathPrepend, []string{"65001", "65001"})
}

func TestPolicyThenASPathPrepend_BlockChildChecksEveryOperand_12070(t *testing.T) {
	text := `policy-options {
    policy-statement P {
        term t1 {
            then {
                as-path-prepend {
                    65001 bad;
                }
                accept;
            }
        }
    }
}`
	tree, parseErrs := NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	err := SchemaValidate(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("SchemaValidate error = %v, want rejection naming second compiler-consumed operand %q", err, "bad")
	}
}

// TestPolicyThenOperandsLenientRegistrationAndCompile_12070 pins the #1960
// no-brick half of the compiled #12070 gate. Persisted compact and term-line
// operands that strict commit refuses must remain bootable on tolerant loads,
// with the downgrade visible to operators.
//
// RED-on-revert: removing lenientPolicyThenOperands from lenientCompileOpts
// makes CompileConfigLenient reject these configs instead of warning.
func TestPolicyThenOperandsLenientRegistrationAndCompile_12070(t *testing.T) {
	if !lenientCompileOpts().lenientPolicyThenOperands {
		t.Fatal("lenientPolicyThenOperands is not registered in lenientCompileOpts")
	}
	for _, tc := range []struct {
		name, text, bad string
	}{
		{
			name: "compact next-hop",
			text: `policy-options { policy-statement P { term t { then accept next-hop discard; } } }`,
			bad:  "discard",
		},
		{
			name: "compact next-hop extra operand",
			text: `policy-options { policy-statement P { term t { then accept next-hop 192.0.2.1 192.0.2.2; } } }`,
			bad:  "192.0.2.2",
		},
		{
			name: "term-line prepend",
			text: `policy-options { policy-statement P { term t then accept as-path-prepend 65001 abc; } }`,
			bad:  "abc",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrs := NewParser(tc.text).Parse()
			if len(parseErrs) > 0 {
				t.Fatalf("parse: %v", parseErrs[0])
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict CompileConfig accepted the invalid policy operand")
			}
			compiled, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected the existing invalid operand: %v", err)
			}
			found := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "policy then operand (downgraded to warning on tolerant path)") &&
					strings.Contains(warning, tc.bad) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("CompileConfigLenient warnings %q do not include downgraded operand %q",
					compiled.Warnings, tc.bad)
			}
		})
	}
}
