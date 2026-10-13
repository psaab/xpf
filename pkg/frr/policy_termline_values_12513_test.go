package frr

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

const communityLists12513 = "community L1 members 65001:1; community L2 members 65001:2; "

// renderTermLine12513 commits text through the real strict gate and renders
// its policy-options.
func renderTermLine12513(t *testing.T, text string) (*config.Config, string) {
	t.Helper()
	cfg, err := configstore.CheckText(text, -1)
	if err != nil {
		t.Fatalf("CheckText rejected %q: %v", text, err)
	}
	return cfg, (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&cfg.PolicyOptions)
}

// routeMapSeq12513 returns the rendered `route-map P ... <seq>` block.
func routeMapSeq12513(rendered, seq string) string {
	for _, block := range strings.SplitAfter(rendered, "exit\n") {
		if i := strings.Index(block, "route-map P "); i >= 0 {
			header, _, _ := strings.Cut(block[i:], "\n")
			if strings.HasSuffix(header, " "+seq) {
				return block[i:]
			}
		}
	}
	return ""
}

// FAIL-ON-REVERT (#12513): a committed term-line value must reach the FRR
// route-map as its exact `set` clause, a bracketed community list as every
// member, and a chain as every clause. Reverting the dispatch renders
// `permit 10 / on-match next` with no `set` line for every row.
func TestPolicyTermLineValuesRender12513(t *testing.T) {
	for _, tc := range []struct {
		name, then string
		want       []string
		forbid     []string
	}{
		{name: "local-preference", then: "local-preference 200", want: []string{" set local-preference 200\n", " on-match next\n"}},
		{name: "metric", then: "metric 10", want: []string{" set metric 10\n"}},
		{name: "metric-type", then: "metric-type 1", want: []string{" set metric-type type-1\n"}},
		{name: "origin", then: "origin igp", want: []string{" set origin igp\n"}},
		{name: "community add", then: "community add 65001:100", want: []string{" set community 65001:100 additive\n"}},
		{name: "community add list", then: "community add [ 65001:1 65001:2 ]", want: []string{" set community 65001:1 65001:2 additive\n"}},
		{name: "community set list", then: "community set [ 65001:1 65001:2 ]", want: []string{" set community 65001:1 65001:2\n"}},
		{
			name: "community delete list", then: "community delete [ L1 L2 ]",
			want: []string{" set comm-list L1 delete\n", " set comm-list L2 delete\n"},
		},
		{
			name: "chained actions", then: "community add 65001:100 local-preference 200 accept",
			want:   []string{"route-map P permit 10\n", " set local-preference 200\n", " set community 65001:100 additive\n"},
			forbid: []string{" on-match next\n"},
		},
		{
			// Disclosed behavior change: base rejected this at commit and
			// rendered `deny 10` on tolerant paths; it now matches the block
			// spelling.
			name: "value then next policy", then: "local-preference 200 next policy",
			want: []string{"route-map P permit 10\n", " set local-preference 200\n", " on-match goto "},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, rendered := renderTermLine12513(t, "policy-options { "+communityLists12513+
				"policy-statement P { term t then "+tc.then+"; term u then accept; } }")
			seq := routeMapSeq12513(rendered, "10")
			for _, want := range tc.want {
				if !strings.Contains(seq, want) {
					t.Errorf("route-map P 10 lacks %q:\n%s", want, rendered)
				}
			}
			for _, forbid := range tc.forbid {
				if strings.Contains(seq, forbid) {
					t.Errorf("route-map P 10 has %q:\n%s", forbid, rendered)
				}
			}
		})
	}
}

// FAIL-ON-REVERT (#12513): `then load-balance` has no route-map clause; its
// FRR consumer is resolveECMP, which turns the forwarding-table export policy
// into the IGP `maximum-paths 64` line and, for consistent-hash, the kernel
// L4 hash flip. Reverting the dispatch leaves LoadBalance empty, so neither
// happens.
func TestPolicyTermLineLoadBalanceDrivesECMP12513(t *testing.T) {
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
	}
	for _, tc := range []struct {
		value          string
		consistentHash bool
	}{
		{"per-packet", false},
		{"consistent-hash", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			cfg, _ := renderTermLine12513(t, "routing-options { forwarding-table { export P; } } "+
				"policy-options { policy-statement P { term t then load-balance "+tc.value+"; } }")
			fc := &FullConfig{
				ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
				PolicyOptions:         &cfg.PolicyOptions,
			}
			paths := resolveECMP(fc)
			if paths != 64 || fc.ConsistentHash != tc.consistentHash {
				t.Fatalf("resolveECMP = (%d, consistent-hash %v), want (64, %v)", paths, fc.ConsistentHash, tc.consistentHash)
			}
			if got := New().generateProtocols(ospf, nil, nil, nil, nil, "", paths, nil, nil); !strings.Contains(got, " maximum-paths 64\n") {
				t.Fatalf("router ospf lacks maximum-paths 64:\n%s", got)
			}
		})
	}
}

// TestPolicyThenInvalidOperandsCommitCheck12513 runs the real strict commit
// gate (CheckText) over packed `then` tails the schema walk skips. Each row
// must be refused naming the policy, term, leaf, and value. RED before the
// fold: CheckText accepted every row, and the renderer turned the numeric
// ones into `set local-preference 4294967296`, `set metric -1`, and similar
// lines that FRR rejects or reads as a relative change.
func TestPolicyThenInvalidOperandsCommitCheck12513(t *testing.T) {
	for _, tc := range []struct{ then, leaf, value string }{
		{"metric 4294967296", "metric", "4294967296"},
		{"metric -1", "metric", "-1"},
		{"local-preference 4294967296", "local-preference", "4294967296"},
		{"local-preference -1", "local-preference", "-1"},
		{"local-preference accept", "local-preference", "accept"},
		{"metric-type 3", "metric-type", "3"},
		{"origin bogus", "origin", "bogus"},
		{"origin accept", "origin", "accept"},
		{"origin reject", "origin", "reject"},
		{"community add [ 65001:1 reject ]", "community", "reject"},
	} {
		for _, format := range []string{
			"policy-options { policy-statement P { term t then %s; } }",
			"policy-options { policy-statement P { term t then accept %s; } }",
			"policy-options { policy-statement P { term t { then accept %s; } } }",
		} {
			text := strings.Replace(format, "%s", tc.then, 1)
			t.Run(text, func(t *testing.T) {
				_, err := configstore.CheckText(text, -1)
				if err == nil {
					t.Fatal("CheckText accepted the invalid operand")
				}
				for _, want := range []string{`policy-statement "P"`, `term "t"`, "then " + tc.leaf + ":", `invalid value "` + tc.value + `"`} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("CheckText error %q does not contain %q", err.Error(), want)
					}
				}
			})
		}
	}
	// Disclosed behavior change: the term-line value used to be dropped, so an
	// undefined community name committed; it now meets the #12069 gate.
	if _, err := configstore.CheckText("policy-options { policy-statement P { term t then community add UNDEFINED; } }", -1); err == nil ||
		!strings.Contains(err.Error(), "UNDEFINED") {
		t.Fatalf("term-line `then community add UNDEFINED` must fail the #12069 gate, got %v", err)
	}
}

// TestPolicyThenInvalidOperandsTolerantRender12513 pins the #1960 no-brick
// half: CompileConfigLenient and Store.SyncApply accept persisted invalid
// operands with the downgrade warning, the renderer omits the clause, and an
// action or match word in the operand slot keeps the meaning it had before
// #12513 (an eaten `reject` would turn the deny into a fall-through permit;
// an eaten `protocol` would drop the match). RED before the fold: the
// keyword rows rendered `permit 10 / on-match next` and lost the match, and
// the numeric rows rendered the invalid `set` line without a warning.
func TestPolicyThenInvalidOperandsTolerantRender12513(t *testing.T) {
	for _, tc := range []struct {
		name, term, bad string
		want, forbid    []string
	}{
		{name: "local-preference overflow", term: "term t then local-preference 4294967296;", bad: "4294967296",
			want: []string{"route-map P permit 10\n"}, forbid: []string{" set local-preference"}},
		{name: "metric negative", term: "term t then metric -1;", bad: "-1",
			want: []string{"route-map P permit 10\n"}, forbid: []string{" set metric"}},
		{name: "compact accept local-preference overflow", term: "term t { then accept local-preference 4294967296; }", bad: "4294967296",
			want: []string{"route-map P permit 10\n"}, forbid: []string{" set local-preference"}},
		{name: "origin reject stays deny", term: "term t then origin reject;", bad: "reject",
			want: []string{"route-map P deny 10\n"}, forbid: []string{"route-map P permit 10\n", " set origin"}},
		{name: "local-preference reject stays deny", term: "term t then local-preference reject;", bad: "reject",
			want: []string{"route-map P deny 10\n"}, forbid: []string{"route-map P permit 10\n"}},
		{name: "metric-type reject stays deny", term: "term t then metric-type reject;", bad: "reject",
			want: []string{"route-map P deny 10\n"}, forbid: []string{"route-map P permit 10\n"}},
		{name: "load-balance reject stays deny", term: "term t then load-balance reject;", bad: "reject",
			want: []string{"route-map P deny 10\n"}, forbid: []string{"route-map P permit 10\n"}},
		{name: "community add reject stays deny", term: "term t then community add reject;", bad: "reject",
			want: []string{"route-map P deny 10\n"}, forbid: []string{"route-map P permit 10\n"}},
		{name: "bracketed reject stays deny", term: "term t then community add [ 65001:1 reject ];", bad: "reject",
			want: []string{"route-map P deny 10\n"}, forbid: []string{"route-map P permit 10\n"}},
		{name: "origin accept stays terminal", term: "term t then origin accept;", bad: "accept",
			want: []string{"route-map P permit 10\n"}, forbid: []string{" on-match next\n", " set origin"}},
		{name: "origin protocol keeps the match", term: "term t then origin protocol static accept;", bad: "protocol",
			want: []string{"route-map P permit 10\n", " match source-protocol static\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "policy-options { policy-statement P { " + tc.term + " term u then accept; } }"
			tree, parseErrors := config.NewParser(text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse: %v", parseErrors)
			}
			lenient, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected the persisted operand: %v", err)
			}
			store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
			if err != nil {
				t.Fatalf("create config store: %v", err)
			}
			synced, err := store.SyncApply(text, nil)
			if err != nil {
				t.Fatalf("SyncApply rejected the persisted operand: %v", err)
			}
			for path, cfg := range map[string]*config.Config{"CompileConfigLenient": lenient, "SyncApply": synced} {
				warned := false
				for _, warning := range cfg.Warnings {
					warned = warned || strings.Contains(warning, "policy then operand (downgraded to warning on tolerant path)") &&
						strings.Contains(warning, `invalid value "`+tc.bad+`"`)
				}
				if !warned {
					t.Errorf("%s warnings %q lack the downgraded operand %q", path, cfg.Warnings, tc.bad)
				}
				seq := routeMapSeq12513((&Manager{frrConf: "/dev/null"}).generatePolicyOptions(&cfg.PolicyOptions), "10")
				for _, want := range tc.want {
					if !strings.Contains(seq, want) {
						t.Errorf("%s route-map P 10 lacks %q:\n%s", path, want, seq)
					}
				}
				for _, forbid := range tc.forbid {
					if strings.Contains(seq, forbid) {
						t.Errorf("%s route-map P 10 has %q:\n%s", path, forbid, seq)
					}
				}
			}
		})
	}
}

// FAIL-ON-REVERT (#12513): the renderer belt omits a local-preference or
// metric outside FRR's u32 operand however it reached the compiled config,
// and keeps the 0 and 4294967295 boundaries.
func TestPolicyThenOutOfRangeLocalPrefMetricOmitted12513(t *testing.T) {
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"P": {Name: "P", Terms: []*config.PolicyTerm{
			{Name: "over", Action: "accept", LocalPreference: 4294967296, HasLocalPreference: true, Metric: 4294967296, HasMetric: true},
			{Name: "negative", Action: "accept", LocalPreference: -1, HasLocalPreference: true, Metric: -1, HasMetric: true},
			{Name: "bounds", Action: "accept", LocalPreference: 4294967295, HasLocalPreference: true, HasMetric: true},
		}},
	}}
	got := (&Manager{frrConf: "/dev/null"}).generatePolicyOptions(po)
	for _, forbid := range []string{"4294967296", " set local-preference -1\n", " set metric -1\n"} {
		if strings.Contains(got, forbid) {
			t.Errorf("rendered out-of-range %q:\n%s", forbid, got)
		}
	}
	for _, want := range []string{" set local-preference 4294967295\n", " set metric 0\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("dropped the in-range %q:\n%s", want, got)
		}
	}
}
