package config

import (
	"strings"
	"testing"
)

// #15650: repeated forwarding-options / port-mirroring / instance / input /
// output stanzas must merge. Hierarchical split
// `instance span1 {input}` + `instance span1 {output}` previously compiled
// strict to "no ingress interfaces" (second block's fresh mi replaced first),
// and repeated port-mirroring blocks dropped the first.
// RED-on-base, GREEN after find-or-create merging + FindChildren iteration.

func hierTree15650(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return tree
}

func strictCompile15650(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig strict: %v", err)
	}
	return cfg
}

func TestPortMirroringSplitHierarchicalMerges15650(t *testing.T) {
	// Two port-mirroring blocks inside one forwarding-options, same instance
	// split input/output, plus a second forwarding-options root with another
	// instance. All must survive merged.
	text := `forwarding-options {
    port-mirroring {
        instance span1 {
            input {
                rate 10;
                ingress {
                    interface ge-0/0/0.0;
                }
            }
        }
    }
    port-mirroring {
        instance span1 {
            output {
                interface ge-0/0/1.0;
            }
        }
        instance span2 {
            input {
                ingress {
                    interface ge-0/0/2.0;
                }
            }
            output {
                interface ge-0/0/3.0;
            }
        }
    }
}
forwarding-options {
    port-mirroring {
        instance span1 {
            input {
                ingress {
                    interface ge-0/0/4.0;
                }
            }
        }
    }
}`
	cfg := strictCompile15650(t, hierTree15650(t, text))
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil {
		t.Fatal("PortMirroring nil")
	}
	span1 := pm.Instances["span1"]
	if span1 == nil {
		t.Fatal("span1 missing")
	}
	if span1.InputRate != 10 {
		t.Errorf("span1 rate=%d want 10", span1.InputRate)
	}
	if len(span1.Input) != 2 || span1.Input[0] != "ge-0/0/0.0" || span1.Input[1] != "ge-0/0/4.0" {
		t.Errorf("span1 input=%v want [ge-0/0/0.0 ge-0/0/4.0]", span1.Input)
	}
	if span1.Output != "ge-0/0/1.0" {
		t.Errorf("span1 output=%q want ge-0/0/1.0", span1.Output)
	}
	span2 := pm.Instances["span2"]
	if span2 == nil || len(span2.Input) != 1 || span2.Output != "ge-0/0/3.0" {
		t.Errorf("span2=%+v want input ge-0/0/2.0 output ge-0/0/3.0", span2)
	}
}

func TestPortMirroringSplitInputOutputChildren15650(t *testing.T) {
	// Repeated input / output children inside a single instance block.
	text := `forwarding-options {
    port-mirroring {
        instance span1 {
            input { ingress { interface ge-0/0/0.0; } }
            input { rate 7; ingress { interface ge-0/0/1.0; } }
            output { interface ge-0/0/2.0; }
        }
    }
}`
	cfg := strictCompile15650(t, hierTree15650(t, text))
	inst := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if inst == nil {
		t.Fatal("span1 missing")
	}
	if inst.InputRate != 7 || len(inst.Input) != 2 || inst.Output != "ge-0/0/2.0" {
		t.Errorf("inst=%+v want rate7 inputs2 output ge-0/0/2.0", inst)
	}
}

func TestPortMirroringSplitLenientMerges15650(t *testing.T) {
	// Lenient load must also merge, not drop first stanza.
	text := `forwarding-options {
    port-mirroring {
        instance span1 { input { ingress { interface ge-0/0/0.0; } } }
    }
    port-mirroring {
        instance span1 { output { interface ge-0/0/1.0; } }
    }
}`
	tree := hierTree15650(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	inst := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if inst == nil || len(inst.Input) != 1 || inst.Output != "ge-0/0/1.0" {
		t.Fatalf("lenient merged inst=%+v", inst)
	}
	// No misleading zero-ingress warning for merged instance.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no ingress") && strings.Contains(w, "span1") {
			t.Errorf("unexpected zero-ingress warning after merge: %s", w)
		}
	}
}

func TestPortMirroringOutputFirstAcrossRoots15650(t *testing.T) {
	// Output fragment arrives before any ingress, in an earlier root: the
	// zero-ingress gate must fire only on the final merged instance.
	text := `forwarding-options {
    port-mirroring {
        instance span1 { output { interface ge-0/0/1.0; } }
    }
}
forwarding-options {
    port-mirroring {
        instance span1 { input { ingress { interface ge-0/0/0.0; } } }
    }
}`
	cfg := strictCompile15650(t, hierTree15650(t, text))
	inst := cfg.ForwardingOptions.PortMirroring.Instances["span1"]
	if inst == nil || len(inst.Input) != 1 || inst.Output != "ge-0/0/1.0" {
		t.Fatalf("inst=%+v want input+output merged", inst)
	}
}

func TestPortMirroringDuplicateIngressAcrossSplitStillRejected15650(t *testing.T) {
	// Merging must not bypass duplicate-ingress gate.
	text := `forwarding-options {
    port-mirroring {
        instance span1 { input { ingress { interface ge-0/0/0.0; } } output { interface ge-0/0/1.0; } }
        instance span1 { input { ingress { interface ge-0/0/0.0; } } }
    }
}`
	tree := hierTree15650(t, text)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "duplicate ingress") {
		t.Fatalf("err=%v want duplicate ingress reject", err)
	}
}
