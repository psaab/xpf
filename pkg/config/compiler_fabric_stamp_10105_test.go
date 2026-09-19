package config

import (
	"strings"
	"testing"
)

func compileFabricStamp10105(t *testing.T, commands []string, compile func(*ConfigTree) (*Config, error)) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := compile(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func hasFabricStamp10105Warning(cfg *Config) bool {
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "fabric zone stamp (#10105)") {
			return true
		}
	}
	return false
}

var fabricStampCluster10105 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"set chassis cluster fabric-interface fab0",
}

func TestFabricStampSharedSegmentAdvisoryOnConfiguredFabric10105(t *testing.T) {
	cfg := compileFabricStamp10105(t, fabricStampCluster10105, CompileConfig)
	if !hasFabricStamp10105Warning(cfg) {
		t.Fatalf("configured fabric must emit the #10105 private-L2 advisory; warnings=%v", cfg.Warnings)
	}
}

func TestFabricStampSharedSegmentAdvisoryAbsentWithoutFabric10105(t *testing.T) {
	commands := append([]string(nil), fabricStampCluster10105[:3]...)
	cfg := compileFabricStamp10105(t, commands, CompileConfig)
	if hasFabricStamp10105Warning(cfg) {
		t.Fatalf("a cluster without a fabric link must not emit the #10105 advisory; warnings=%v", cfg.Warnings)
	}
}

func TestFabricStampSharedSegmentAdvisoryIsNotRepeatedOnTolerantLoad10105(t *testing.T) {
	cfg := compileFabricStamp10105(t, fabricStampCluster10105, CompileConfigLenient)
	if hasFabricStamp10105Warning(cfg) {
		t.Fatalf("tolerant load must not repeat the commit-time #10105 advisory; warnings=%v", cfg.Warnings)
	}
}

func TestFabricStampAdvisoryDoesNotFollowAuthKeyOption10105(t *testing.T) {
	// The stamp advisory has its own tolerant-path suppression flag. A caller
	// that only relaxes the unrelated cluster-auth gate must still receive the
	// deployment warning.
	cfg := compileFabricStamp10105(t, fabricStampCluster10105, func(tree *ConfigTree) (*Config, error) {
		return compileConfigWithOpts(tree, compileOpts{lenientClusterAuthKey: true})
	})
	if !hasFabricStamp10105Warning(cfg) {
		t.Fatalf("relaxing only the auth-key gate must not suppress the #10105 advisory; warnings=%v", cfg.Warnings)
	}
}
