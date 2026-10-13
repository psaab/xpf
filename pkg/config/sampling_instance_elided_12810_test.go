package config

import "testing"

// #12810: a fully brace-elided sampling-instance tail was never compiled.
// `sampling { instance i2 input rate 100; }` packed the whole tail
// [input rate 100] onto the instance node's Keys; compileSampling reads
// only children (FindChild("input") / FindChildren("family")), so the
// instance compiled with rate 0 and no families on a clean commit. An
// elided instance in a later repeated `sampling` container also
// overwrote an earlier braced instance of the same name with that
// empty shell (last-sibling-wins, #12595).
//
// Doctrine (repo precedents): a brace-elided spelling of a legitimate
// config COMPILES like its braced twin — #12596 admitted
// ("sampling","input"/"output") for interface sampling and #8690
// family 3 admitted ("sampling","instance"), ("input","rate"),
// ("output","flow-server") etc. for forwarding-options. Strict-reject
// is reserved for spellings whose braced twin is itself rejected.
// The fix admits the missing links under `instance` (input, family)
// plus packedStatements on the instance node so a multi-statement
// elided tail splits instead of swallowing its later statements.

func samplingInstance12810(t *testing.T, text, name string) *SamplingInstance {
	t.Helper()
	cfg := compileText(t, text)
	if cfg == nil || cfg.ForwardingOptions.Sampling == nil {
		t.Fatalf("no sampling config compiled for %q", text)
	}
	inst, ok := cfg.ForwardingOptions.Sampling.Instances[name]
	if !ok {
		t.Fatalf("instance %q absent for %q (have %v)", name, text, cfg.ForwardingOptions.Sampling.Instances)
	}
	return inst
}

func TestElidedSamplingInstanceTail12810(t *testing.T) {
	cases := []struct {
		name string
		text string
		inst string
		rate int
		inet bool
	}{
		{"braced control",
			"forwarding-options { sampling { instance i2 { input { rate 100; } } } }", "i2", 100, false},
		{"fully elided single instance",
			"forwarding-options { sampling { instance i2 input rate 100; } }", "i2", 100, false},
		{"elided tail after braced sibling",
			"forwarding-options { sampling { instance i1 { input { rate 50; } } instance i2 input rate 100; } }", "i2", 100, false},
		{"elided family inet inline-jflow",
			"forwarding-options { sampling { instance i2 family inet output inline-jflow; } }", "i2", 0, true},
		{"elided family inet6 flow-server",
			"forwarding-options { sampling { instance i2 family inet6 output flow-server 10.0.0.1 port 2055; } }", "i2", 0, false},
		{"elided multi-statement tail rate and family",
			"forwarding-options { sampling { instance i2 input rate 100 family inet output inline-jflow; } }", "i2", 100, true},
		{"fully elided from forwarding-options",
			"forwarding-options sampling instance i2 input rate 100;", "i2", 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := samplingInstance12810(t, tc.text, tc.inst)
			if inst.InputRate != tc.rate {
				t.Errorf("rate = %d, want %d for %q", inst.InputRate, tc.rate, tc.text)
			}
			if tc.inet {
				if inst.FamilyInet == nil || !inst.FamilyInet.InlineJflow {
					t.Errorf("family inet inline-jflow missing for %q: %+v", tc.text, inst.FamilyInet)
				}
			}
			if tc.name == "elided family inet6 flow-server" {
				if inst.FamilyInet6 == nil || len(inst.FamilyInet6.FlowServers) != 1 ||
					inst.FamilyInet6.FlowServers[0].Address != "10.0.0.1" ||
					inst.FamilyInet6.FlowServers[0].Port != 2055 {
					t.Errorf("family inet6 flow-server wrong for %q: %+v", tc.text, inst.FamilyInet6)
				}
			}
		})
	}
}

// The clobber half of #12810: an elided instance in a later repeated
// sampling container must not erase an earlier braced instance — it
// compiles its own tail, exactly like the braced last-sibling-wins
// spelling (#12595/#9023 merge semantics keep author order).
func TestElidedSamplingInstanceDoesNotClobber12810(t *testing.T) {
	text := "forwarding-options { sampling { instance i2 { input { rate 100; } } } " +
		"sampling { instance i2 input rate 200; } }"
	inst := samplingInstance12810(t, text, "i2")
	if inst.InputRate != 200 {
		t.Errorf("rate = %d, want 200 (elided later sibling compiles, not empty clobber) for %q", inst.InputRate, text)
	}
	// Reverse order: braced later sibling still wins over elided earlier.
	text2 := "forwarding-options { sampling { instance i2 input rate 200; } " +
		"sampling { instance i2 { input { rate 100; } } } }"
	inst2 := samplingInstance12810(t, text2, "i2")
	if inst2.InputRate != 100 {
		t.Errorf("rate = %d, want 100 for %q", inst2.InputRate, text2)
	}
}

// Explicit rate 0 is the documented sample-all sentinel and must stay
// 0 in both spellings; an instance with no input at all also stays 0.
func TestElidedSamplingInstanceExplicitZero12810(t *testing.T) {
	for _, text := range []string{
		"forwarding-options { sampling { instance i2 { input { rate 0; } } } }",
		"forwarding-options { sampling { instance i2 input rate 0; } }",
		"forwarding-options { sampling { instance i2 { } } }",
	} {
		inst := samplingInstance12810(t, text, "i2")
		if inst.InputRate != 0 {
			t.Errorf("rate = %d, want 0 for %q", inst.InputRate, text)
		}
	}
}
func TestElidedSamplingInstanceBoundsAndEmpty12810(t *testing.T) {
	maxRate := samplingInstance12810(t,
		"forwarding-options { sampling { instance i2 input rate 4294967295; } }", "i2")
	if maxRate.InputRate != 4294967295 {
		t.Errorf("maximum valid rate = %d, want 4294967295", maxRate.InputRate)
	}

	cfg := compileText(t, "forwarding-options { sampling { } }")
	if cfg == nil {
		t.Fatal("empty sampling container did not compile")
	}
	if cfg.ForwardingOptions.Sampling != nil &&
		len(cfg.ForwardingOptions.Sampling.Instances) != 0 {
		t.Errorf("empty sampling container produced instances: %v",
			cfg.ForwardingOptions.Sampling.Instances)
	}
}
