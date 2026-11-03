package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	packedTailDrop18771   = `interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } }`
	packedTailBraced18771 = `interfaces { ge-0/0/0 { unit 0 { family inet6 { dad-disable; } } } }`
)

// The same-pair control was independently measured on the base before the
// gate existed: priority is DROP, authentication-type is diagnostic-only
// PARTIAL, and the duplicate priority occurrence is typed+diagnostic CLEAN.
const (
	packedTailMixedDrop18771    = `interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24 vrrp-group 1 priority 100; } } } }`
	packedTailMixedPartial18771 = `interfaces { ge-0/0/1 { unit 0 { family inet { address 192.0.2.2/24 vrrp-group 1 authentication-type simple; } } } }`
	packedTailMixedClean18771   = `interfaces { ge-0/0/2 { unit 0 { family inet { address 192.0.2.3/24 vrrp-group 1 priority 100; address 192.0.2.3/24 { vrrp-group 1 { priority 100; } } } } } }`
)

func packedTailCompile18771(t *testing.T, text string, opts compileOpts, nodeID *int) (*Config, error) {
	t.Helper()
	opts.packedTailGateEligible18771 = true
	return compileTree(parseHierText(t, text), opts, nodeID)
}

func packedTailMustCompile18771(t *testing.T, text string, opts compileOpts, nodeID *int) *Config {
	t.Helper()
	cfg, err := packedTailCompile18771(t, text, opts, nodeID)
	if err != nil {
		t.Fatalf("eligible compile: %v", err)
	}
	return cfg
}

func packedTailVerdicts18771(cfg *Config) (out []string) {
	if cfg == nil {
		return nil
	}
	for _, d := range cfg.Diagnostics {
		if d.Gate != "packedTailGate18771" {
			continue
		}
		fields := strings.Fields(d.Prose)
		if len(fields) > 1 {
			out = append(out, fields[1])
		}
	}
	return out
}

func packedTailDiagnosticText18771(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	var b strings.Builder
	for _, d := range cfg.Diagnostics {
		if d.Gate == "packedTailGate18771" {
			b.WriteString(d.Prose + "\n")
		}
	}
	return b.String()
}

func packedTailAssertVerdicts18771(t *testing.T, cfg *Config, want ...string) {
	t.Helper()
	got := packedTailVerdicts18771(cfg)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("verdicts = %v, want %v\ndiagnostics:\n%s", got, want, packedTailDiagnosticText18771(cfg))
	}
	for _, d := range cfg.Diagnostics {
		if d.Gate != "packedTailGate18771" {
			continue
		}
		found := false
		for _, w := range cfg.Warnings {
			if w == d.Prose {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("typed diagnostic has no byte-identical warning: %+v", d)
		}
	}
}

func packedTailPrepare18771(t *testing.T, text string, opts compileOpts, nodeID *int) (*Config, *packedTailGateRun18771) {
	t.Helper()
	opts.packedTailGateEligible18771 = true
	run := newPackedTailGateRun18771(opts, nodeID)
	working := parseHierText(t, text).cloneForExpansion()
	if _, err := HashAPIAuthSecrets(working); err != nil {
		t.Fatalf("hash API-auth secrets: %v", err)
	}
	normalizeCompactStanzasWithPackedTailGate18771(working, run)
	normalizeImplicitInetFilters9899(working)
	mergeDuplicateBlocks9023(working)
	if opts.lenientDuplicatePolicyNames {
		mergeDuplicateNamedInstances(working)
	}
	packedTailGateSnapshotPoint18771(working, run)
	if nodeID == nil {
		if _, err := working.ExpandGroupsNodeFallback15031(true); err != nil {
			t.Fatalf("expand generic groups: %v", err)
		}
	} else {
		if err := working.ExpandGroupsWithVarsTagged(map[string]string{"node": fmt.Sprintf("node%d", *nodeID)}); err != nil {
			t.Fatalf("expand node groups: %v", err)
		}
	}
	observePackedTailGateEffective18771(working, run)
	original := parseHierText(t, text)
	cfg, err := compileTree(original, packedTailGateTwinOpts18771(opts), nodeID)
	if err != nil {
		t.Fatalf("baseline compile: %v", err)
	}
	return cfg, run
}

func packedTailCaptureLogs18771(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestPackedTailGate18771Cell01HookProvenanceGroups(t *testing.T) {
	const applied = `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } } apply-groups g;`
	cfg := packedTailMustCompile18771(t, applied, strictCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, cfg, "DROP")
	_, appliedRun := packedTailPrepare18771(t, applied, strictCompileOpts(), nil)
	for _, source := range appliedRun.sources18771 {
		if len(source.groupLocalPath18771) == 0 || len(source.keyIdentity18771) == 0 || source.tailSpan18771 == 0 || source.inheritedFrom18771 != "g" {
			t.Fatal("applied-group source handle lost path, identity, tail span, or group provenance")
		}
	}

	const unused = `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } } system { host-name unused; }`
	packedTailAssertVerdicts18771(t, packedTailMustCompile18771(t, unused, strictCompileOpts(), nil))

	const fanout = `groups { g { interfaces { <*> { unit 0 { family inet6 dad-disable; } } } } }
apply-groups g;
interfaces { ge-0/0/0 { unit 0; } ge-0/0/1 { unit 0; } }
`
	cfg = packedTailMustCompile18771(t, fanout, lenientCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, cfg, "SKIPPED-PROVENANCE", "SKIPPED-PROVENANCE")
	if strings.Contains(packedTailDiagnosticText18771(cfg), "DROP") || strings.Contains(packedTailDiagnosticText18771(cfg), "PARTIAL") || strings.Contains(packedTailDiagnosticText18771(cfg), "CLEAN") {
		t.Fatal("fan-out occurrence was independently adjudicated")
	}

	const nodes = `groups {
 node0 { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } }
 node1 { interfaces { ge-0/0/1 { unit 0 { family inet6 dad-disable; } } } }
}
apply-groups "${node}";
`
	generic := packedTailMustCompile18771(t, nodes, strictCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, generic, "DROP")
	if !strings.Contains(strings.Join(generic.Warnings, "\n"), "default node0 context") {
		t.Fatal("generic node0 fallback diagnostic missing")
	}
	node := 1
	nodeCfg := packedTailMustCompile18771(t, nodes, strictCompileOpts(), &node)
	packedTailAssertVerdicts18771(t, nodeCfg, "DROP")
	if strings.Contains(strings.Join(nodeCfg.Warnings, "\n"), "default node0 context") {
		t.Fatal("node-aware compile used generic fallback")
	}
	if packedTailDiagnosticText18771(generic) == packedTailDiagnosticText18771(nodeCfg) {
		t.Fatal("generic and node-aware views did not retain distinct source locators")
	}

	const inlineMerge = `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } }
apply-groups g;
interfaces { ge-0/0/0 { unit 0 { family inet6 { mtu 1500; } } } }
`
	packedTailAssertVerdicts18771(t, packedTailMustCompile18771(t, inlineMerge, strictCompileOpts(), nil), "CLEAN")
}

func TestPackedTailGate18771Cell02TwinFidelityDerivedContext(t *testing.T) {
	primary := "persisted-primary"
	accepted := &clusterAcceptedKeys16858{primary: "persisted-primary", additional: "additional"}
	initial := currentClusterOpts(nil)
	initial.currentClusterPrimary16025 = &primary
	initial.currentClusterAccepted16858 = accepted
	initial.judgePlaceholders18744 = true
	initial.physicalInterfaces = map[string]bool{"derived": true}
	initial.zoneQuarantineNames = []string{"derived"}
	derivedNode := 99
	initial.nodeID = &derivedNode
	initial.igpIdentityExcused16810 = true
	twin := packedTailGateTwinOpts18771(initial)
	if twin.packedTailGateEligible18771 || !twin.skipPackedTailGate18771 {
		t.Fatalf("twin tuple = (%v,%v), want (false,true)", twin.packedTailGateEligible18771, twin.skipPackedTailGate18771)
	}
	if twin.physicalInterfaces != nil || twin.zoneQuarantineNames != nil || twin.nodeID != nil || twin.igpIdentityExcused16810 {
		t.Fatal("derived compile context was carried into twin")
	}
	initialPolicy, twinPolicy := initial, twin
	for _, o := range []*compileOpts{&initialPolicy, &twinPolicy} {
		o.physicalInterfaces = nil
		o.zoneQuarantineNames = nil
		o.nodeID = nil
		o.igpIdentityExcused16810 = false
		o.packedTailGateEligible18771 = false
		o.skipPackedTailGate18771 = false
	}
	if !reflect.DeepEqual(initialPolicy, twinPolicy) {
		t.Fatal("caller-set initial compile policy changed across twin entry")
	}

	node := 0
	o, run := packedTailPrepare18771(t, packedTailDrop18771, strictCompileOpts(), &node)
	if len(run.sources18771) != 1 {
		t.Fatalf("sources = %d, want 1", len(run.sources18771))
	}
	var id uint64
	for id = range run.sources18771 {
	}
	bTree, err := packedTailGateRewriteTwin18771(run.snapshot18771, id, true)
	if err != nil {
		t.Fatalf("rewrite B: %v", err)
	}
	bracedCfg, err := compileTree(bTree, packedTailGateTwinOpts18771(run.initialOpts18771), &node)
	if err != nil {
		t.Fatalf("compile B: %v", err)
	}
	publicB, err := CompileConfigForNode(parseHierText(t, packedTailBraced18771), node)
	if err != nil {
		t.Fatalf("public genuinely-braced compile: %v", err)
	}
	if ConfigFingerprint(bracedCfg) != ConfigFingerprint(publicB) || !packedTailGateDiagEqual18771(bracedCfg, publicB) {
		t.Fatal("B_i differs from independently parsed genuinely braced source")
	}
	rTree, err := packedTailGateRewriteTwin18771(run.snapshot18771, id, false)
	if err != nil {
		t.Fatalf("rewrite R: %v", err)
	}
	r, err := compileTree(rTree, packedTailGateTwinOpts18771(run.initialOpts18771), &node)
	if err != nil {
		t.Fatalf("compile R: %v", err)
	}
	for name, cfg := range map[string]*Config{"B": bracedCfg, "R": r} {
		if !reflect.DeepEqual(o.PhysicalInterfaces, cfg.PhysicalInterfaces) || !reflect.DeepEqual(o.ZoneQuarantineNames, cfg.ZoneQuarantineNames) {
			t.Errorf("%s recomputed derived context differs", name)
		}
		if o.Chassis.Cluster != nil && cfg.Chassis.Cluster != nil && o.Chassis.Cluster.NodeID != cfg.Chassis.Cluster.NodeID {
			t.Errorf("%s stamped node id differs", name)
		}
	}

	const groupSource = `groups {
 node0 { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } }
 node1 { system { host-name peer; } }
}
apply-groups "${node}";
system { apply-groups-except UNDEFINED18771; }
`
	_, groupRun := packedTailPrepare18771(t, groupSource, strictCompileOpts(), nil)
	for id := range groupRun.sources18771 {
		tree, err := packedTailGateRewriteTwin18771(groupRun.snapshot18771, id, true)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := compileTree(tree, packedTailGateTwinOpts18771(groupRun.initialOpts18771), nil)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(joined, "default node0 context") || !strings.Contains(joined, "UNDEFINED18771") {
			t.Fatalf("node fallback / unresolved-except diagnostics not rerun: %v", cfg.Warnings)
		}
	}

	const nested = `system { domain-search { example.com { x; } } }`
	_, nestedRun := packedTailPrepare18771(t, packedTailDrop18771, strictCompileOpts(), nil)
	for id := range nestedRun.sources18771 {
		tree, err := packedTailGateRewriteTwin18771(nestedRun.snapshot18771, id, true)
		if err != nil {
			t.Fatal(err)
		}
		tree.Children = append(tree.Children, parseHierText(t, nested).Children...)
		if _, err := compileTree(tree, packedTailGateTwinOpts18771(nestedRun.initialOpts18771), nil); err == nil {
			t.Fatal("twin did not rerun findNestedMultiValueContentError / compileTree gates")
		}
	}
}

func TestPackedTailGate18771Cell03SnapshotPlacement(t *testing.T) {
	const source = `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } }
apply-groups g;
security { flow { tcp-session no-syn-check; } }
`
	_, run := packedTailPrepare18771(t, source, strictCompileOpts(), nil)
	if run.snapshotCount18771 != 1 {
		t.Fatalf("snapshot hook count = %d, want 1", run.snapshotCount18771)
	}
	if run.snapshot18771 == nil || run.snapshot18771.FindChild("groups") == nil {
		t.Fatal("snapshot lost pre-expansion group definitions")
	}
	if len(run.sources18771) == 0 {
		t.Fatal("snapshot lost declined packed tail")
	}
	var admitted bool
	var walk func([]*Node)
	walk = func(ns []*Node) {
		for _, n := range ns {
			if len(n.Keys) == 1 && n.Keys[0] == "no-syn-check" {
				admitted = true
			}
			walk(n.Children)
		}
	}
	walk(run.snapshot18771.Children)
	if !admitted {
		t.Fatal("already-admitted tail was not production-normalized before snapshot")
	}

	raw, err := os.ReadFile("compiler.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "func compileTree(tree *ConfigTree")
	end := strings.Index(text[start:], "func CompileConfigForNode(")
	body := text[start : start+end]
	snap := strings.Index(body, "packedTailGateSnapshotPoint18771(tree, gate)")
	if snap < 0 || strings.Count(body, "packedTailGateSnapshotPoint18771(tree, gate)") != 1 {
		t.Fatal("compileTree must call the named snapshot hook exactly once")
	}
	before := []string{"normalizeCompactStanzasWithPackedTailGate18771(tree, gate)", "normalizeImplicitInetFilters9899(tree)", "mergeDuplicateBlocks9023(tree)", "merged, foldWidened, directActionConflicts = mergeDuplicateNamedInstances(tree)"}
	pos := 0
	for _, token := range before {
		i := strings.Index(body[pos:], token)
		if i < 0 {
			t.Fatalf("missing pass %q before snapshot", token)
		}
		if pos+i > snap {
			t.Fatalf("pass %q moved after snapshot", token)
		}
		pos += i + len(token)
	}
	if tunnel := strings.Index(body, "validateTunnelEndpointIDCollisionAST("); tunnel < 0 || snap > tunnel {
		t.Fatal("snapshot moved past tunnel collision gate")
	}
}

func TestPackedTailGate18771Cell04PerSiteCausality(t *testing.T) {
	const ha = `chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-18771-long; node 0; reth-count 2; no-private-rg-election;
 redundancy-group 0 { node 0 priority 200; node 1 priority 100; }
 redundancy-group 1 { node 0 priority 200; node 1 priority 100; } } }
interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } }
`
	cfg := packedTailMustCompile18771(t, ha, lenientCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, cfg, "CLEAN", "CLEAN", "CLEAN", "CLEAN", "DROP")

	const two = `interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } ge-0/0/1 { unit 0 { family inet6 dad-disable; } } }`
	packedTailAssertVerdicts18771(t, packedTailMustCompile18771(t, two, strictCompileOpts(), nil), "DROP", "DROP")

	mixed := packedTailMixedDrop18771 + "\n" + packedTailMixedPartial18771 + "\n" + packedTailMixedClean18771
	packedTailAssertVerdicts18771(t, packedTailMustCompile18771(t, mixed, lenientCompileOpts(), nil), "DROP", "PARTIAL", "CLEAN")
}

func TestPackedTailGate18771Cell05Determinism(t *testing.T) {
	paths := []string{"../../docs/ha-cluster-userspace.conf"}
	matches, err := filepath.Glob("../../test/incus/*.conf")
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, matches...)
	if len(matches) == 0 {
		t.Fatal("no test/incus configs measured")
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var first *Config
		for range 2 {
			cfg := packedTailMustCompile18771(t, string(raw), lenientCompileOpts(), nil)
			if first == nil {
				first = cfg
				continue
			}
			if ConfigFingerprint(first) != ConfigFingerprint(cfg) || !reflect.DeepEqual(first.Warnings, cfg.Warnings) || !reflect.DeepEqual(first.Diagnostics, cfg.Diagnostics) {
				t.Fatalf("%s is nondeterministic across repeated compiles", path)
			}
		}
	}

	const secret = "DISTINCTIVE-18771-SECRET"
	api := `system { services { web-management { api-auth { expires 2099-01-01; user admin { password "` + secret + `"; } api-key machine-generated-key-alpha; } } } }
` + packedTailDrop18771
	o, run := packedTailPrepare18771(t, api, lenientCompileOpts(), nil)
	if !run.snapshotIdempotent18771 {
		t.Fatal("lenient three-pass snapshot was not idempotent")
	}
	for id := range run.sources18771 {
		for _, brace := range []bool{true, false} {
			tree, err := packedTailGateRewriteTwin18771(run.snapshot18771, id, brace)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(packedTailVerifiers18771(run.snapshot18771), packedTailVerifiers18771(tree)) {
				t.Fatal("pre-hashed API-auth verifier changed across twin")
			}
		}
	}
	start := time.Now()
	findings := run.adjudicate18771(o)
	if len(findings) == 0 || run.twinCompilations18771 != 2 {
		t.Fatalf("findings=%d twins=%d, want 1/2", len(findings), run.twinCompilations18771)
	}
	t.Logf("measured full-twin cost: %d compilations in %s; no nondeterministic fields normalized", run.twinCompilations18771, time.Since(start))

	const duplicates = `security { policies { global { policy p { then permit; } policy p { then reject; } } } }
` + packedTailDrop18771
	_, dupRun := packedTailPrepare18771(t, duplicates, lenientCompileOpts(), nil)
	if !dupRun.snapshotIdempotent18771 {
		t.Fatal("lenient duplicate-named-instance fold was not idempotent")
	}
	dupRun.snapshotIdempotent18771 = false
	got := dupRun.adjudicate18771(o)
	for _, f := range got {
		if f.verdict18771 != "INDETERMINATE" {
			t.Fatalf("non-idempotent verdict = %s, want INDETERMINATE", f.verdict18771)
		}
	}

	_, strictRun := packedTailPrepare18771(t, packedTailDrop18771, strictCompileOpts(), nil)
	if !strictRun.snapshotIdempotent18771 {
		t.Fatal("strict two-pass snapshot was not idempotent")
	}
}

func packedTailVerifiers18771(tree *ConfigTree) (out []string) {
	var walk func([]*Node)
	walk = func(ns []*Node) {
		for _, n := range ns {
			for _, k := range n.Keys {
				if strings.HasPrefix(k, "$2") {
					out = append(out, k)
				}
			}
			walk(n.Children)
		}
	}
	walk(tree.Children)
	return out
}

func packedTailCensusSource18771(s compactSite) (string, string, bool) {
	siteKey := strings.Join(s.container, " ") + " " + s.leaf
	if len(s.container) < 2 {
		return siteKey, "", false
	}
	parent := s.container[:len(s.container)-1]
	stanza := s.container[len(s.container)-1]
	ctx := contextForStanza(parent, stanza)
	pre := preambleFor(parent, stanza)
	rendered := renderInstanceNames(s.container)
	ctx = renderScaffold(ctx, s.container, rendered)
	pre = renderScaffold(pre, s.container, rendered)
	parent = rendered[:len(rendered)-1]
	stanza = rendered[len(rendered)-1]
	if len(rendered) < 2 || strings.TrimSpace(ctx) != "" {
		return siteKey, "", false
	}
	var value string
	if !s.flag {
		var ok bool
		value, _, ok = compactCensusPair(s)
		if !ok {
			return siteKey, "", false
		}
	}
	outerParent := rendered[:len(rendered)-2]
	outer := rendered[len(rendered)-2]
	ctx2 := renderScaffold(contextForStanza(s.container[:len(s.container)-2], s.container[len(s.container)-2]), s.container, rendered)
	text := pre + nest(outerParent, ctx2+outer+" "+stanza+" "+s.leaf+" "+value+";")
	if s.flag {
		text = pre + nest(outerParent, ctx2+outer+" "+stanza+" "+s.leaf+";")
	}
	return siteKey, text, true
}

func packedTailAllCensusSources18771(t *testing.T) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, site := range collectCompactSites() {
		key, text, ok := packedTailCensusSource18771(site)
		if ok {
			out[key] = text
		}
	}
	if len(out) == 0 {
		t.Fatal("empty independent two-level census fixture set")
	}
	return out
}

func TestPackedTailGate18771Cell06FixedCensusManifest(t *testing.T) {
	raw, err := os.ReadFile("testdata/packed_tail_gate_18771.txt")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := packedTailAllCensusSources18771(t)
	fixtures["inline-drop"] = packedTailDrop18771
	fixtures["same-pair-mixed"] = packedTailMixedDrop18771 + "\n" + packedTailMixedPartial18771 + "\n" + packedTailMixedClean18771
	fixtures["applied-group"] = `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } } apply-groups g;`
	fixtures["fanout"] = `groups { g { interfaces { <*> { unit 0 { family inet6 dad-disable; } } } } } apply-groups g; interfaces { ge-0/0/0 { unit 0; } ge-0/0/1 { unit 0; } }`
	fixtures["already-admitted"] = `security { flow { tcp-session no-syn-check; } }`
	fixtures["strict-refused"] = `security { flow { tcp-session strict-syn-check; tcp-session no-syn-check; } }`
	fixtures["unclassified"] = packedTailMixedDrop18771
	fixtures["schema-unreached"] = `system { host-name example extra; }`
	fixtures["scope-true-declines"] = `security { zones { security-zone trust { address-book address a1 10.0.0.1/32 address a2 10.0.0.2/32 { address-set s1 address a1; } } } }`
	fixtures["scope-true-stranding"] = `security { zones { security-zone a { } security-zone b { } security-zone c { } security-zone d { } } policies from-zone a to-zone b { policy p { match { source-address any; destination-address any; application any; } then { permit; } } } from-zone c to-zone d { policy p { match { source-address any; destination-address any; application any; } then { permit; } } } }`
	fixtures["scope-true-leaf-decline"] = `security { zones { security-zone trust description hello { interfaces { ge-0/0/0.0; } } } } interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`
	fixtures["unused-group"] = `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } } system { host-name unused; }`
	seen := map[string]bool{}
	for lineNo, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("line %d: got %d fields", lineNo, len(fields))
		}
		kind, name, view, want := fields[0], fields[1], fields[2], fields[3]
		text := fixtures[name]
		if text == "" {
			t.Fatalf("line %d: unknown fixture %q", lineNo, name)
		}
		if seen[name] {
			t.Fatalf("line %d: duplicate fixture row %q", lineNo, name)
		}
		seen[name] = true
		opts := strictCompileOpts()
		if view == "lenient" {
			opts = lenientCompileOpts()
		} else if view != "strict" {
			t.Fatalf("line %d: bad view", lineNo)
		}
		cfg, err := packedTailCompile18771(t, text, opts, nil)
		if want == "ERROR" {
			if err == nil {
				t.Errorf("%s: wanted strict refusal", name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: compile: %v", name, err)
			continue
		}
		got := "NONE"
		if verdicts := packedTailVerdicts18771(cfg); len(verdicts) > 0 {
			counts := map[string]int{}
			for _, v := range verdicts {
				counts[v]++
			}
			order := []string{"DROP", "PARTIAL", "CLEAN", "INDETERMINATE", "SKIPPED-PROVENANCE", "SKIPPED-CAP"}
			var parts []string
			for _, v := range order {
				if counts[v] > 0 {
					parts = append(parts, v+":"+strconv.Itoa(counts[v]))
				}
			}
			got = strings.Join(parts, ",")
		}
		if kind == "OUT" && want == "NONE" && got != "NONE" {
			t.Errorf("%s: out-of-scope rows produced %s", name, got)
		} else if got != want {
			t.Errorf("%s: verdicts = %s, want %s", name, got, want)
		}
	}
	if len(seen) == 0 {
		t.Fatal("fixed manifest has no runtime rows")
	}
}

func TestPackedTailGate18771Cell07TypedDiagnosticClassification(t *testing.T) {
	o := &Config{System: SystemConfig{HostName: "same"}}
	b := &Config{System: SystemConfig{HostName: "different"}}
	r := &Config{System: SystemConfig{HostName: "same"}}
	if got := classifyPackedTailGate18771(o, b, r); got != "DROP" {
		t.Fatalf("classification = %s, want DROP", got)
	}
	bWarn := &Config{System: SystemConfig{HostName: "same"}, Warnings: []string{"warning-only"}}
	if got := classifyPackedTailGate18771(o, bWarn, r); got != "PARTIAL" {
		t.Fatalf("diagnostic-only B = %s, want PARTIAL", got)
	}
	rWarn := &Config{System: SystemConfig{HostName: "same"}, Warnings: []string{"removed-diagnostic"}}
	if got := classifyPackedTailGate18771(o, b, rWarn); got != "PARTIAL" {
		t.Fatalf("diagnostic-only R = %s, want PARTIAL", got)
	}
	if got := classifyPackedTailGate18771(o, o, o); got != "CLEAN" {
		t.Fatalf("typed-equivalent = %s, want CLEAN", got)
	}

	tagged := &Config{Warnings: []string{"gate prose"}, Diagnostics: []Diagnostic{{Gate: "packedTailGate18771", Prose: "gate prose"}}}
	if !packedTailGateDiagEqual18771(tagged, &Config{}) {
		t.Fatal("tagged gate diagnostic was not excluded symmetrically")
	}
	untagged := &Config{Warnings: []string{"mentions packedTailGate18771"}, Diagnostics: []Diagnostic{{Gate: "other", Prose: "mentions packedTailGate18771"}}}
	if packedTailGateDiagEqual18771(untagged, &Config{}) {
		t.Fatal("untagged diagnostic was excluded by prose substring")
	}
	packedTailAssertVerdicts18771(t, packedTailMustCompile18771(t, packedTailMixedPartial18771, lenientCompileOpts(), nil), "PARTIAL")
}

func TestPackedTailGate18771Cell08PhaseEligibilityAndReentrancy(t *testing.T) {
	if packedTailGateEnforce18771 {
		t.Fatal("phase one must remain report-only")
	}
	strict := packedTailMustCompile18771(t, packedTailDrop18771, strictCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, strict, "DROP")
	packedTailAssertVerdicts18771(t, packedTailMustCompile18771(t, packedTailDrop18771, lenientCompileOpts(), nil), "DROP")

	for name, compile := range map[string]func() (*Config, error){
		"direct-strict":        func() (*Config, error) { return CompileConfig(parseHierText(t, packedTailDrop18771)) },
		"direct-lenient":       func() (*Config, error) { return CompileConfigLenient(parseHierText(t, packedTailDrop18771)) },
		"display-lenient-node": func() (*Config, error) { return CompileConfigForNodeLenient(parseHierText(t, packedTailDrop18771), 0) },
		"daemon-strict-node":   func() (*Config, error) { return CompileConfigForNode(parseHierText(t, packedTailDrop18771), 0) },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := compile()
			if err != nil {
				t.Fatal(err)
			}
			packedTailAssertVerdicts18771(t, cfg)
		})
	}

	const igp = `groups {
 node0 { protocols { ospf { router-id 10.0.0.1; } } }
 node1 { protocols { ospf { router-id 10.0.0.2; } } }
}
apply-groups "${node}";
` + packedTailDrop18771
	logs := packedTailCaptureLogs18771(t)
	cfg := packedTailMustCompile18771(t, igp, strictCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, cfg, "DROP")
	if got := strings.Count(logs.String(), "packedTailGate18771"); got != 1 {
		t.Fatalf("gated log lines = %d, want 1 (nested IGP added twins/logs)", got)
	}

	logs = packedTailCaptureLogs18771(t)
	multi := packedTailMustCompile18771(t, packedTailDrop18771+"\n"+strings.ReplaceAll(packedTailDrop18771, "ge-0/0/0", "ge-0/0/1"), strictCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, multi, "DROP", "DROP")
	if got := strings.Count(logs.String(), "packedTailGate18771"); got != 2 {
		t.Fatalf("recursive/nested twins produced %d gate log lines, want 2", got)
	}

	opts := strictCompileOpts()
	opts.packedTailGateEligible18771 = true
	twin := packedTailGateTwinOpts18771(opts)
	if twin.packedTailGateEligible18771 || !twin.skipPackedTailGate18771 {
		t.Fatalf("half-stamped twin tuple (%v,%v)", twin.packedTailGateEligible18771, twin.skipPackedTailGate18771)
	}
}

func TestPackedTailGate18771Cell09HAReadTailAndSecrets(t *testing.T) {
	const secret = "DISTINCTIVE-18771-SECRET"
	text := `chassis { cluster { cluster-id 1; authentication-key test-cluster-psk-18771-long; node 0; reth-count 2; no-private-rg-election;
 redundancy-group 0 { node 0 priority 200; node 1 priority 100; }
 redundancy-group 1 { node 0 priority 200; node 1 priority 100; } } }
system { services { web-management { api-auth { expires 2099-01-01; user admin { password "` + secret + `"; } api-key machine-generated-key-alpha; } } } }
` + packedTailDrop18771
	logs := packedTailCaptureLogs18771(t)
	cfg := packedTailMustCompile18771(t, text, strictCompileOpts(), nil)
	diag := packedTailDiagnosticText18771(cfg)
	for _, line := range strings.Split(diag, "\n") {
		if strings.Contains(line, "node/priority") && strings.Contains(line, "DROP") {
			t.Fatal("shipped HA node/priority read tail was called DROP")
		}
	}
	for _, surface := range []string{diag, strings.Join(cfg.Warnings, "\n"), logs.String()} {
		if strings.Contains(surface, secret) || strings.Contains(surface, strconv.Quote(secret)) {
			t.Fatal("raw or quoted API-auth secret reached warning/log output")
		}
	}
}

func TestPackedTailGate18771Cell10BoundsAndMutants(t *testing.T) {
	makeSites := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "interfaces { ge-0/0/%d { unit 0 { family inet6 dad-disable; } } }\n", i)
		}
		return b.String()
	}
	cfg := packedTailMustCompile18771(t, makeSites(32), strictCompileOpts(), nil)
	if got := len(packedTailVerdicts18771(cfg)); got != 32 {
		t.Fatalf("32-site adjudication findings = %d, want 32", got)
	}
	cfg = packedTailMustCompile18771(t, makeSites(33), strictCompileOpts(), nil)
	packedTailAssertVerdicts18771(t, cfg, "SKIPPED-CAP")

	run := newPackedTailGateRun18771(strictCompileOpts(), nil)
	run.snapshot18771 = &ConfigTree{}
	if findings := run.adjudicate18771(&Config{}); len(findings) != 0 || run.twinCompilations18771 != 0 {
		t.Fatalf("empty recorder ran %d twins", run.twinCompilations18771)
	}

	o := &Config{System: SystemConfig{HostName: "same"}}
	b := &Config{System: SystemConfig{HostName: "different"}}
	r := &Config{System: SystemConfig{HostName: "same"}}
	if classifyPackedTailGate18771(o, b, r) != "DROP" {
		t.Fatal("comparator-always-equal mutant survives DROP control")
	}
	if classifyPackedTailGate18771(o, o, o) != "CLEAN" {
		t.Fatal("comparator-never-equal mutant survives CLEAN control")
	}
	warn := &Config{System: SystemConfig{HostName: "same"}, Warnings: []string{"diagnostic"}}
	if classifyPackedTailGate18771(o, warn, r) != "PARTIAL" {
		t.Fatal("typed-equality/diagnostic-equality conflation survives")
	}
}
