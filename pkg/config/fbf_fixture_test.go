package config

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestFBFTwoUpstreamFixtureCompiles keeps the #1827 PR-2 two-upstream
// lab fixture (test/incus/fbf-two-upstream-config.set) compiling: every
// set line must parse (ParseSetCommand + SetPath), schema-validate, and
// the merged candidate must pass CompileConfig with the FBF composition
// intact. The fixture is what the smoke harness
// (test/incus/test-fbf-steering.sh) load-merges onto the live cluster
// config — a fixture that no longer compiles must fail CI, not the
// smoke run.
func TestFBFTwoUpstreamFixtureCompiles(t *testing.T) {
	f, err := os.Open("../../test/incus/fbf-two-upstream-config.set")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatal("fixture contains no set lines")
	}

	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("schema validation: %v", err)
	}

	var fbf *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ISP-B" {
			fbf = ri
		}
	}
	if fbf == nil || fbf.InstanceType != "forwarding" {
		t.Fatalf("ISP-B forwarding instance not compiled: %+v", fbf)
	}
	if len(fbf.StaticRoutes) != 1 || len(fbf.Inet6StaticRoutes) != 1 {
		t.Fatalf("ISP-B statics = v4 %+v / v6 %+v, want one each",
			fbf.StaticRoutes, fbf.Inet6StaticRoutes)
	}

	v4 := cfg.Firewall.FiltersInet["fbf-steer"]
	if v4 == nil || len(v4.Terms) != 2 || v4.Terms[0].RoutingInstance != "ISP-B" ||
		v4.Terms[0].Count != "fbf-isp-b" ||
		len(v4.Terms[0].DSCPs) != 1 || v4.Terms[0].DSCPs[0] != "af31" {
		t.Fatalf("fbf-steer = %+v", v4)
	}
	v6 := cfg.Firewall.FiltersInet6["fbf-steer6"]
	if v6 == nil || len(v6.Terms) != 2 || v6.Terms[0].RoutingInstance != "ISP-B" {
		t.Fatalf("fbf-steer6 = %+v", v6)
	}

	reth1 := cfg.Interfaces.Interfaces["reth1"]
	if reth1 == nil || reth1.Units[0] == nil ||
		reth1.Units[0].FilterInputV4 != "fbf-steer" ||
		reth1.Units[0].FilterInputV6 != "fbf-steer6" {
		t.Fatalf("reth1 unit 0 filter bindings missing: %+v", reth1)
	}

	pol := cfg.Services.IPMonitoring.Policies["fbf-fallback"]
	if pol == nil || pol.MatchRPMProbe != "FBF-ISP-B" || len(pol.PreferredRoutes) != 1 {
		t.Fatalf("fbf-fallback policy = %+v", pol)
	}
	if pr := pol.PreferredRoutes[0]; pr.RoutingInstance != "ISP-B" ||
		pr.Destination != "0.0.0.0/0" || pr.NextHop != "172.16.50.1" {
		t.Fatalf("fbf-fallback preferred-route = %+v", pr)
	}
}
