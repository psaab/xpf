package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11833 ([C-12]): an entryless `classifiers inet-precedence <name>` is recorded
// in INetPrecedenceClassifiers (names list, compiler_class_of_service.go:323)
// but has no entry in INetPrecedenceClassifierDefs (map, only populated when
// len(Entries) > 0 at :363). It commits, binds, and completes, yet the
// renderer iterated Defs only, so `show` omitted it unfiltered and reported
// "No matches" by name — a show-vs-commit contradiction.
//
// These cells pin the real compiler-emitted shape (names entry, nil Defs map)
// and require the renderer to show it. Renderer-side fix only: tree.go is
// EE-owned and MUST NOT be touched.
func cosCfgEntryless11833(names ...string) *config.Config {
	return &config.Config{ClassOfService: &config.ClassOfServiceConfig{
		INetPrecedenceClassifiers: names,
	}}
}

func compileEntrylessINetPrecedence11833(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand("set class-of-service classifiers inet-precedence empty-cl")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// Compile the exact entryless stanza, then prove the resulting config survives
// both operational selection paths.
func TestCompiledEntrylessINetPrecedenceShownUnfilteredAndByName_11833(t *testing.T) {
	cfg := compileEntrylessINetPrecedence11833(t)
	cos := cfg.ClassOfService
	if cos == nil || len(cos.INetPrecedenceClassifiers) != 1 || cos.INetPrecedenceClassifiers[0] != "empty-cl" {
		t.Fatalf("compiled classifier names = %#v, want [empty-cl]", cos)
	}
	if cos.INetPrecedenceClassifierDefs["empty-cl"] != nil {
		t.Fatalf("entryless classifier unexpectedly has a Defs entry: %#v", cos.INetPrecedenceClassifierDefs["empty-cl"])
	}
	for _, tc := range []struct {
		name       string
		nameFilter string
	}{
		{name: "unfiltered"},
		{name: "by-name", nameFilter: "empty-cl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := FormatCoSClassifiers(cfg, tc.nameFilter, "")
			if !strings.Contains(out, "Classifier: empty-cl, Code point type: inet-precedence") {
				t.Fatalf("compiled entryless classifier missing from %s show:\n%s", tc.name, out)
			}
			if !strings.Contains(out, "No entries configured") {
				t.Errorf("entryless classifier lacks explicit empty-entry status:\n%s", out)
			}
		})
	}
}

func TestEntrylessINetPrecedenceShownUnfiltered_11833(t *testing.T) {
	out := FormatCoSClassifiers(cosCfgEntryless11833("empty-cl"), "", "")
	if strings.Contains(out, "No class-of-service classifiers configured") {
		t.Fatalf("entryless inet-precedence classifier rendered as unconfigured (#11833):\n%s", out)
	}
	for _, want := range []string{"empty-cl", "inet-precedence"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

func TestEntrylessINetPrecedenceShownByName_11833(t *testing.T) {
	out := FormatCoSClassifiers(cosCfgEntryless11833("empty-cl"), "empty-cl", "")
	if strings.Contains(out, "No class-of-service classifier matches") {
		t.Fatalf("entryless inet-precedence classifier not found by name (#11833):\n%s", out)
	}
	if !strings.Contains(out, "empty-cl") {
		t.Errorf("by-name output does not mention %q:\n%s", "empty-cl", out)
	}
}

func TestEntrylessINetPrecedenceTypeFilter_11833(t *testing.T) {
	cfg := cosCfgEntryless11833("empty-cl")
	if out := FormatCoSClassifiers(cfg, "", "inet-precedence"); !strings.Contains(out, "empty-cl") {
		t.Errorf("type filter `inet-precedence` matched no entryless classifier:\n%s", out)
	}
	if out := FormatCoSClassifiers(cfg, "", "dscp"); strings.Contains(out, "empty-cl") {
		t.Errorf("type filter `dscp` returned an inet-precedence classifier:\n%s", out)
	}
}

// The compiler records the name in BOTH the names list and (when entries
// exist) the Defs map, so a union iteration must dedup: one header, not two.
func TestINetPrecedenceNoDuplicateWhenNamedAndDefined_11833(t *testing.T) {
	cfg := &config.Config{ClassOfService: &config.ClassOfServiceConfig{
		INetPrecedenceClassifiers: []string{"prec-cl"},
		INetPrecedenceClassifierDefs: map[string]*config.CoSINetPrecedenceClassifier{
			"prec-cl": {Name: "prec-cl", Entries: []*config.CoSINetPrecedenceClassifierEntry{
				{ForwardingClass: "voice", LossPriority: "low", Precedences: []uint8{5}},
			}},
		},
	}}
	out := FormatCoSClassifiers(cfg, "", "")
	if got := strings.Count(out, "Classifier: prec-cl"); got != 1 {
		t.Errorf("expected exactly one `Classifier: prec-cl` header, got %d:\n%s", got, out)
	}
}

// The names slice preserves config-file order; the renderer must sort so
// output is stable regardless of file order.
func TestEntrylessINetPrecedenceSorted_11833(t *testing.T) {
	out := FormatCoSClassifiers(cosCfgEntryless11833("zulu-cl", "alpha-cl"), "", "")
	ia, iz := strings.Index(out, "alpha-cl"), strings.Index(out, "zulu-cl")
	if ia < 0 || iz < 0 {
		t.Fatalf("both entryless names must render:\n%s", out)
	}
	if ia > iz {
		t.Errorf("entryless names not sorted (alpha must precede zulu):\n%s", out)
	}
}
