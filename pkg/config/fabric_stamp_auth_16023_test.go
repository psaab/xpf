package config

import (
	"strings"
	"testing"
)

// #16023: the require-authenticated opt-in and the per-link attestation
// compile, round-trip through schema, and warn when the requirement has
// no authenticated link to honour stamps on.

func compile16023(t *testing.T, commands []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", command, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

var cluster16023 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"set chassis cluster fabric-interface fab0",
}

func TestRequireAuthenticatedFabricStampsCompiles16023(t *testing.T) {
	cfg := compile16023(t, append(append([]string{}, cluster16023...),
		"set security flow require-authenticated-fabric-stamps",
		"set chassis cluster fabric-interface-authenticated",
	))
	if !cfg.Security.Flow.RequireAuthenticatedFabricStamps {
		t.Fatal("require-authenticated-fabric-stamps must compile true")
	}
	if !cfg.Chassis.Cluster.FabricLinkAuthenticated {
		t.Fatal("fabric-interface-authenticated must compile true")
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "16023") {
			t.Fatalf("attested config must not warn #16023; got %q", w)
		}
	}
}

func TestRequireAuthenticatedWithoutAttestationWarns16023(t *testing.T) {
	cfg := compile16023(t, append(append([]string{}, cluster16023...),
		"set security flow require-authenticated-fabric-stamps",
	))
	if cfg.Chassis.Cluster.FabricLinkAuthenticated {
		t.Fatal("fixture must be unattested")
	}
	found := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "require-authenticated-fabric-stamps") && strings.Contains(w, "16023") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unattested require must warn; warnings=%v", ValidateConfig(cfg))
	}
	plain := compile16023(t, cluster16023)
	for _, w := range ValidateConfig(plain) {
		if strings.Contains(w, "16023") {
			t.Fatalf("plain config must not warn #16023; got %q", w)
		}
	}
}

func TestFabric1AttestationCompiles16023(t *testing.T) {
	cfg := compile16023(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"set chassis cluster fabric-interface fab0",
		"set chassis cluster fabric1-interface fab1",
		"set chassis cluster fabric1-interface-authenticated",
		"set security flow require-authenticated-fabric-stamps",
	})
	if !cfg.Chassis.Cluster.Fabric1LinkAuthenticated {
		t.Fatal("fabric1-interface-authenticated must compile true")
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "16023") {
			t.Fatalf("fab1-attested config must not warn #16023; got %q", w)
		}
	}
}
