package config

import (
	"strings"
	"testing"
)

// #10293: interface `family inet/inet6` filter LISTS, uRPF, and policer binds
// commit clean and bind nothing.
//
// compileInterfaces reads ONLY `filter input|output` (single names) under the
// family node (compiler_interfaces.go); Junos `filter input-list/output-list`,
// `rpf-check`, and `policer input/output` parse-accept and are silently
// dropped — on every interface including lo0, which compiles through the same
// loop. No dataplane consumer exists for any of them, so the honest answer is
// a strict reject naming the knob (the #6178 vlan-map honesty-gate doctrine),
// not silent acceptance.
//
// Fail-on-revert: delete the gate and every Test*Rejected* cell below goes RED
// (CompileConfig returns nil).

func mustReject10293(t *testing.T, tree *ConfigTree, knob string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("interface %s committed cleanly, but nothing binds it — the operator believes a filter list / uRPF / policer is enforced when it is silently dropped", knob)
	}
	if !strings.Contains(err.Error(), "#10293") {
		t.Fatalf("reject error %q does not name the #10293 gate", err.Error())
	}
	if !strings.Contains(err.Error(), knob) {
		t.Fatalf("reject error %q does not name the offending knob %q", err.Error(), knob)
	}
}

func filterListFixture10293() []string {
	return []string{
		"set firewall family inet filter f1 term t1 then accept",
		"set firewall family inet filter f2 term t1 then accept",
		"set firewall family inet6 filter f6 term t1 then accept",
	}
}

func TestInterfaceFilterInputListRejected10293(t *testing.T) {
	base := filterListFixture10293()
	flat := append(append([]string{}, base...),
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input-list f1",
	)
	mustReject10293(t, flatTreeFromSets(t, flat...), "input-list")

	hier := hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                filter {
                    input-list [ f1 f2 ];
                }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`)
	mustReject10293(t, hier, "input-list")

	v6 := append(append([]string{}, base...),
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter input-list f6",
	)
	mustReject10293(t, flatTreeFromSets(t, v6...), "input-list")
}

func TestInterfaceFilterMultiValueSingularRejected10293(t *testing.T) {
	tests := []struct {
		name string
		src  string
		knob string
	}{
		{
			name: "input bracket",
			knob: "filter input",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter { input [ f1 f2 ]; }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "input block",
			knob: "filter input",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter { input { f1; f2; } }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "output bracket",
			knob: "filter output",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter { output [ f1 f2 ]; }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "output block",
			knob: "filter output",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter { output { f1; f2; } }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "inet6 input bracket",
			knob: "filter input",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 {
                filter { input [ f1 f2 ]; }
            }
        }
    }
}
firewall {
    family inet6 {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "input packed block values",
			knob: "filter input",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter { input { f1 f2; } }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "output packed block values",
			knob: "filter output",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter { output { f1 f2; } }
            }
        }
    }
}
firewall {
    family inet {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
		{
			name: "inet6 input packed block values",
			knob: "filter input",
			src: `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 {
                filter { input { f1 f2; } }
            }
        }
    }
}
firewall {
    family inet6 {
        filter f1 { term t1 { then accept; } }
        filter f2 { term t1 { then accept; } }
    }
}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mustReject10293(t, hierTree(t, tc.src), tc.knob)
		})
	}
	t.Run("input packed tail", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set firewall family inet filter f1 term t1 then accept",
			"set firewall family inet filter f2 term t1 then accept",
			"set interfaces ge-0/0/0 unit 0 family inet filter input f1 f2",
		)
		mustReject10293(t, tree, "filter input")
	})
	t.Run("lenient input bracket", func(t *testing.T) {
		cfg, err := CompileConfigLenient(hierTree(t, tests[0].src))
		if err != nil {
			t.Fatalf("lenient multi-value filter must not brick: %v", err)
		}
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, "#10293") &&
				strings.Contains(warning, "filter input") {
				return
			}
		}
		t.Fatalf("lenient multi-value filter must warn #10293, got %q", cfg.Warnings)
	})
	for _, tc := range []struct {
		name   string
		src    string
		input  string
		output string
	}{
		{
			name:  "input single-child block",
			src:   strings.Replace(tests[1].src, "input { f1; f2; }", "input { f1; }", 1),
			input: "f1",
		},
		{
			name:   "output single-child block",
			src:    strings.Replace(tests[3].src, "output { f1; f2; }", "output { f1; }", 1),
			output: "f1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(hierTree(t, tc.src))
			if err != nil {
				t.Fatalf("single-child filter binding must remain valid: %v", err)
			}
			u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
			if u.FilterInputV4 != tc.input || u.FilterOutputV4 != tc.output {
				t.Fatalf("single-child binding drifted: got input=%q output=%q, want input=%q output=%q",
					u.FilterInputV4, u.FilterOutputV4, tc.input, tc.output)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#10293") {
					t.Fatalf("single-child binding must not warn #10293: %q", warning)
				}
			}
		})
	}
}

func TestInterfaceFilterOutputListRejected10293(t *testing.T) {
	base := filterListFixture10293()
	flat := append(append([]string{}, base...),
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter output-list f1",
	)
	mustReject10293(t, flatTreeFromSets(t, flat...), "output-list")

	v6 := append(append([]string{}, base...),
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter output-list f6",
	)
	mustReject10293(t, flatTreeFromSets(t, v6...), "output-list")
}

func TestInterfaceRpfCheckRejected10293(t *testing.T) {
	flat := flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet rpf-check",
	)
	mustReject10293(t, flat, "rpf-check")

	hier := hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                rpf-check {
                    mode loose;
                }
            }
        }
    }
}`)
	mustReject10293(t, hier, "rpf-check")
}

func TestInterfacePolicerBindRejected10293(t *testing.T) {
	in := flatTreeFromSets(t,
		"set firewall policer p1 then discard",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet policer input p1",
	)
	mustReject10293(t, in, "policer")

	out := flatTreeFromSets(t,
		"set firewall policer p1 then discard",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet policer output p1",
	)
	mustReject10293(t, out, "policer")

	hier := hierTree(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 {
                address 2001:db8::1/64;
                policer {
                    input p1;
                    output p1;
                }
            }
        }
    }
}
firewall {
    policer p1 { then discard; }
}`)
	mustReject10293(t, hier, "policer")
}

func TestLo0FilterInputListRejected10293(t *testing.T) {
	// lo0 compiles through the same compileInterfaces loop (it is an ordinary
	// interface under cfg.Interfaces.Interfaces["lo0"]), so the host-bound
	// filter hook needs the same honesty.
	tree := flatTreeFromSets(t,
		"set firewall family inet filter lo4 term t1 then accept",
		"set interfaces lo0 unit 0 family inet address 127.0.0.1/32",
		"set interfaces lo0 unit 0 family inet filter input-list lo4",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("lo0 filter input-list committed cleanly, but nothing binds it")
	}
	if !strings.Contains(err.Error(), "#10293") || !strings.Contains(err.Error(), "lo0") {
		t.Fatalf("reject error %q must name the #10293 gate and lo0", err.Error())
	}
}

func TestInterfaceFilterInputOutputStillCommit10293(t *testing.T) {
	// The negative control: single-name `filter input|output` and sampling
	// are real consumers and must keep committing with no #10293 diagnostic.
	tree := flatTreeFromSets(t,
		"set firewall family inet filter in4 term t1 then accept",
		"set firewall family inet filter out4 term t1 then accept",
		"set firewall family inet6 filter in6 term t1 then accept",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input in4",
		"set interfaces ge-0/0/0 unit 0 family inet filter output out4",
		"set interfaces ge-0/0/0 unit 0 family inet sampling input",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter input in6",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("single-name filter input/output must still commit: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10293") {
			t.Fatalf("supported filter input/output must not warn #10293, got %q", w)
		}
	}
	u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if u.FilterInputV4 != "in4" || u.FilterOutputV4 != "out4" || u.FilterInputV6 != "in6" {
		t.Fatalf("single-name bindings lost: %+v", u)
	}
}

func TestInterfaceFilterListLenientWarnsNoBrick10293(t *testing.T) {
	// #1960: the tolerant load / peer-sync path downgrades to a warning so a
	// config an older binary silently accepted still boots.
	tree := flatTreeFromSets(t,
		"set firewall family inet filter f1 term t1 then accept",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input-list f1",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must not brick on input-list: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10293") && strings.Contains(w, "input-list") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient path must warn #10293 naming input-list, got %q", cfg.Warnings)
	}
}
