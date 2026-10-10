package config

import (
	"strings"
	"testing"
)

func toZoneLessFromZoneTree12231(t *testing.T) *ConfigTree {
	t.Helper()
	const text = `security {
    zones { security-zone A; security-zone B; }
    policies {
        from-zone {
            A {
                policy p1 {
                    match { source-address any; destination-address any; application any; }
                    then { deny; }
                }
            }
        }
        global {
            policy g-permit {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        default-policy permit-all;
    }
}`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse to-zone-less policy tree: %v", errs)
	}
	return tree
}

func TestToZoneLessFromZoneTolerantCompilePoisons12231(t *testing.T) {
	cfg, err := CompileConfigLenient(toZoneLessFromZoneTree12231(t))
	if err != nil {
		t.Fatalf("tolerant compile must remain bootable: %v", err)
	}
	if len(cfg.Security.Policies) != 0 {
		t.Fatalf("to-zone-less context compiled %d zone pairs, want none", len(cfg.Security.Policies))
	}
	if len(cfg.Security.MalformedZonePairs) != 1 {
		t.Fatalf("MalformedZonePairs = %q, want one missing-to-zone context", cfg.Security.MalformedZonePairs)
	}
	if diagnostic := cfg.Security.MalformedZonePairs[0]; !strings.Contains(diagnostic, `from-zone "A"`) || !strings.Contains(diagnostic, "no to-zone") {
		t.Fatalf("missing-to-zone diagnostic is not specific: %q", diagnostic)
	}
	if got := LenientDroppedPolicyLocator(cfg); got == "" {
		t.Fatal("tolerant compile did not add the poison carrier; the dropped deny could fall through to permit-all")
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "not enforced") || !strings.Contains(warnings, "snapshot is refused") {
		t.Fatalf("tolerant warning must explain the dropped context and snapshot refusal: %v", cfg.Warnings)
	}
}

func TestToZoneLessFromZoneBareCompileRejects12231(t *testing.T) {
	_, err := CompileConfig(toZoneLessFromZoneTree12231(t))
	if err == nil {
		t.Fatal("bare CompileConfig accepted a from-zone context without any to-zone")
	}
	if !strings.Contains(err.Error(), "#12231") || !strings.Contains(err.Error(), "no to-zone") {
		t.Fatalf("bare CompileConfig error does not identify the missing-to-zone context: %v", err)
	}
}

func TestInactiveToZoneLessFromZoneIsNotRecorded12231(t *testing.T) {
	const text = `security {
    zones { security-zone A; }
    policies {
        from-zone {
            A {
                inactive: policy parked { then { deny; } }
            }
        }
    }
}`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse inactive policy tree: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("inactive policy must remain ignored: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 0 || LenientDroppedPolicyLocator(cfg) != "" {
		t.Fatalf("pruned inactive policy caused missing-to-zone poison: malformed=%q poison=%q",
			cfg.Security.MalformedZonePairs, LenientDroppedPolicyLocator(cfg))
	}
}
