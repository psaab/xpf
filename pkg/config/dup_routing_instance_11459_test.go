package config

import (
	"strings"
	"testing"
)

func TestCompileConfigMergesConflictingDuplicateRoutingInstances11459(t *testing.T) {
	const text = `routing-instances {
    A {
        instance-type virtual-router;
        routing-options {
            static { route 10.0.1.0/24 next-hop 192.0.2.1; }
        }
    }
    A {
        instance-type forwarding;
        routing-options {
            static { route 10.0.2.0/24 next-hop 192.0.2.2; }
        }
    }
}`
	tree, parseErrors := NewParser(text).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse duplicate routing instances: %v", parseErrors[0])
	}
	assertMerged := func(label string, cfg *Config) {
		t.Helper()
		if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].InstanceType != "forwarding" {
			t.Fatalf("%s compile = %+v; want one instance with last-authored type forwarding",
				label, cfg.RoutingInstances)
		}
		wantRoutes := map[string]bool{"10.0.1.0/24": true, "10.0.2.0/24": true}
		for _, route := range cfg.RoutingInstances[0].StaticRoutes {
			delete(wantRoutes, route.Destination)
		}
		if len(wantRoutes) != 0 {
			t.Fatalf("%s compile lost RI static routes %v; merged routes=%+v",
				label, wantRoutes, cfg.RoutingInstances[0].StaticRoutes)
		}
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, "duplicate routing-instance definition") &&
				strings.Contains(warning, "#11459") {
				return
			}
		}
		t.Fatalf("%s compile did not announce its deterministic RI merge: %v", label, cfg.Warnings)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig: %v", err)
	}
	assertMerged("strict", cfg)
	nodeCfg, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("strict node compile: %v", err)
	}
	assertMerged("strict node", nodeCfg)
}

func TestCompileConfigLenientMergesConflictingDuplicateRoutingInstances11459(t *testing.T) {
	const text = `routing-instances {
    A {
        instance-type virtual-router;
        routing-options {
            static { route 10.0.1.0/24 next-hop 192.0.2.1; }
        }
    }
}
routing-instances {
    A {
        instance-type forwarding;
        routing-options {
            static { route 10.0.2.0/24 next-hop 192.0.2.2; }
        }
    }
}`
	tree, parseErrors := NewParser(text).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse duplicate routing instances: %v", parseErrors[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].InstanceType != "forwarding" {
		t.Fatalf("lenient compile = %+v; want one instance with last-authored type forwarding",
			cfg.RoutingInstances)
	}
	wantRoutes := map[string]bool{"10.0.1.0/24": true, "10.0.2.0/24": true}
	for _, route := range cfg.RoutingInstances[0].StaticRoutes {
		delete(wantRoutes, route.Destination)
	}
	if len(wantRoutes) != 0 {
		t.Fatalf("lenient merge lost RI static routes %v; merged routes=%+v",
			wantRoutes, cfg.RoutingInstances[0].StaticRoutes)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "duplicate routing-instance definition") &&
			strings.Contains(warning, "#11459") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("lenient merge was not announced as a deterministic RI merge: %v", cfg.Warnings)
	}
}
func TestDuplicateRoutingInstanceNamedProtocolsGetsNamedWarning12043(t *testing.T) {
	const text = `routing-instances {
    protocols { instance-type virtual-router; }
    protocols { instance-type virtual-router; }
}`
	tree, parseErrors := NewParser(text).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse duplicate routing instances: %v", parseErrors[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	namedWarning, unnamedWarning := false, false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "duplicate routing-instance definition `protocols`") {
			namedWarning = true
		}
		if strings.Contains(warning, "duplicate unnamed") {
			unnamedWarning = true
		}
	}
	if !namedWarning {
		t.Fatalf("duplicate VRF named protocols did not get the named-instance diagnostic: %v", cfg.Warnings)
	}
	if unnamedWarning {
		t.Errorf("duplicate VRF named protocols was misclassified as an unnamed merge: %v", cfg.Warnings)
	}
}

func TestSpacedRoutingInstanceMergeWarningsKeepTheirKind12123(t *testing.T) {
	unnamedCases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "routing-options",
			text: `routing-instances {
    "a b" {
        instance-type virtual-router;
        routing-options { static { route 10.20.0.0/16 { next-hop 192.0.2.1; } } }
        routing-options { static { route 192.0.2.0/24 { next-hop 192.0.2.2; } } }
    }
}`,
			want: "duplicate unnamed `routing-options` containers under " +
				"routing-instances \"a b\" were merged in source order (#12043)",
		},
		{
			name: "protocols",
			text: `routing-instances {
    "a b" {
        instance-type virtual-router;
        protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }
        protocols { ospf { area 0.0.0.1 { interface ge-0/0/1.0; } } }
    }
}`,
			want: "duplicate unnamed `protocols` containers under " +
				"routing-instances \"a b\" were merged in source order (#12043)",
		},
	}
	for _, tc := range unnamedCases {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErrors := NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse spaced routing-instance merge: %v", parseErrors[0])
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "duplicate routing-instance definition") {
					t.Fatalf("unnamed %s case emitted misclassified named warning %q "+
						"(want only the unnamed-kind warning)", tc.name, warning)
				}
				if warning == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("warnings = %v, want unnamed warning %q", cfg.Warnings, tc.want)
			}
		})
	}

	const named = `routing-instances {
    "a b routing-options" { instance-type virtual-router; }
    "a b routing-options" { instance-type virtual-router; }
}`
	tree, parseErrors := NewParser(named).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse spaced named routing-instance fold: %v", parseErrors[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile named routing-instance fold: %v", err)
	}
	namedWarning := "duplicate routing-instance definition `\"a b routing-options\"` was merged into one typed instance in source order (#11459/#9023)"
	foundNamed := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "duplicate unnamed") {
			t.Fatalf("named control emitted misclassified unnamed warning %q "+
				"(want only the named-kind warning)", warning)
		}
		if warning == namedWarning {
			foundNamed = true
		}
	}
	if !foundNamed {
		t.Fatalf("warnings = %v, want named-instance warning %q", cfg.Warnings, namedWarning)
	}
}
