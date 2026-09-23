package userspace

// #10587 freshness gate: generated rows carry the exact snapshot produced by
// the Go userspace builder. policymatch independently consumes the rows and
// compares Match with Rust's stamped verdict.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const generatedSeedManifestPath10587 = "../../../testdata/policy_generated_corpus/seed_manifest.json"

type generatedSnapshotRow10587 struct {
	ID             string          `json:"id"`
	ConfigSetLines []string        `json:"config_set_lines"`
	Snapshot       json.RawMessage `json:"snapshot"`
}

func generatedRowsDir10587() string {
	if dir := os.Getenv("XPF_POLICY_ROWS_DIR"); dir != "" {
		return dir
	}
	return "../../../testdata/policy_generated_corpus/rows"
}

func generatedSnapshotRows10587(t *testing.T) []generatedSnapshotRow10587 {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(generatedRowsDir10587(), "*.json"))
	if err != nil {
		t.Fatalf("glob generated rows: %v", err)
	}
	sort.Strings(paths)
	rows := make([]generatedSnapshotRow10587, 0, len(paths))
	for _, path := range paths {
		blob, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var row generatedSnapshotRow10587
		if err := json.Unmarshal(blob, &row); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(row.Snapshot) == 0 || string(row.Snapshot) == "null" {
			t.Fatalf("row %s has no Go-built snapshot", row.ID)
		}
		if row.ID == "" || row.ID != strings.TrimSuffix(filepath.Base(path), ".json") {
			t.Fatalf("row %s has unstable/missing ID for %s", row.ID, path)
		}
		rows = append(rows, row)
	}
	return rows
}

type generatedSeedManifest10587 struct {
	SchemaVersion int      `json:"schema_version"`
	IDs           []string `json:"ids"`
}

func generatedSeedManifestIDs10587(t *testing.T) []string {
	t.Helper()
	blob, err := os.ReadFile(generatedSeedManifestPath10587)
	if err != nil {
		t.Fatalf("read seed_manifest.json: %v", err)
	}
	var manifest generatedSeedManifest10587
	if err := json.Unmarshal(blob, &manifest); err != nil {
		t.Fatalf("seed_manifest.json is invalid JSON: %v", err)
	}
	if manifest.SchemaVersion != 1 || len(manifest.IDs) != 48 {
		t.Fatalf("seed_manifest.json has schema %d and %d IDs, want schema 1 and exactly 48",
			manifest.SchemaVersion, len(manifest.IDs))
	}
	return manifest.IDs
}

func assertGeneratedSnapshotCoverage10587(t *testing.T, rows []generatedSnapshotRow10587) {
	t.Helper()
	if len(rows) < 48 {
		t.Fatalf("generated policy row contract collapsed to %d (want >=48)", len(rows))
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		seen[row.ID] = true
	}
	for _, id := range generatedSeedManifestIDs10587(t) {
		if !seen[id] {
			t.Fatalf("generated policy row contract is missing committed seed %q", id)
		}
	}
}

func buildGeneratedSnapshot10587(t *testing.T, row generatedSnapshotRow10587) policyCorpusSnapshot9167 {
	t.Helper()
	tr := &config.ConfigTree{}
	for _, line := range row.ConfigSetLines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("row %s: parse %q: %v", row.ID, line, err)
		}
		if err := tr.SetPath(path); err != nil {
			t.Fatalf("row %s: set %q: %v", row.ID, line, err)
		}
	}
	cfg, err := config.CompileConfig(tr)
	if err != nil {
		t.Fatalf("row %s: strict compile: %v", row.ID, err)
	}
	rules, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("row %s: build policy snapshot: %v", row.ID, err)
	}
	books, _, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatalf("row %s: build address-book snapshot: %v", row.ID, err)
	}
	return policyCorpusSnapshot9167{
		DefaultPolicy: policyActionString(cfg.Security.DefaultPolicy),
		Rules:         rules,
		Zones:         buildZoneSnapshots(cfg),
		AddressBooks:  books,
	}
}

func TestPolicyGeneratedGoSnapshotsAreFresh10587(t *testing.T) {
	rows := generatedSnapshotRows10587(t)
	assertGeneratedSnapshotCoverage10587(t, rows)
	if os.Getenv("XPF_POLICY_ROWS_DIR") == "" && len(rows) != 48 {
		t.Fatalf("committed generated policy row contract has %d rows, want exactly 48", len(rows))
	}
	for _, row := range rows {
		t.Run(row.ID, func(t *testing.T) {
			var committed policyCorpusSnapshot9167
			if err := json.Unmarshal(row.Snapshot, &committed); err != nil {
				t.Fatalf("row %s snapshot JSON: %v", row.ID, err)
			}
			want := buildGeneratedSnapshot10587(t, row)
			committedCanonical, err := json.Marshal(committed)
			if err != nil {
				t.Fatalf("row %s canonicalize committed snapshot: %v", row.ID, err)
			}
			freshCanonical, err := json.Marshal(want)
			if err != nil {
				t.Fatalf("row %s canonicalize fresh snapshot: %v", row.ID, err)
			}
			if bytes.Equal(committedCanonical, freshCanonical) {
				return
			}
			if os.Getenv("XPF_UPDATE_POLICY_ROWS") == "1" {
				fresh, err := json.MarshalIndent(want, "", "  ")
				if err != nil {
					t.Fatalf("row %s marshal fresh snapshot: %v", row.ID, err)
				}
				fresh = append(fresh, '\n')
				path := filepath.Join(generatedRowsDir10587(), row.ID+".json")
				blob, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("row %s read for update: %v", row.ID, err)
				}
				var raw map[string]json.RawMessage
				if err := json.Unmarshal(blob, &raw); err != nil {
					t.Fatalf("row %s decode for update: %v", row.ID, err)
				}
				raw["snapshot"] = fresh
				updated, err := json.MarshalIndent(raw, "", "  ")
				if err != nil {
					t.Fatalf("row %s marshal updated row: %v", row.ID, err)
				}
				if err := os.WriteFile(path, append(updated, '\n'), 0o644); err != nil {
					t.Fatalf("row %s update snapshot: %v", row.ID, err)
				}
				return
			}
			got, _ := json.MarshalIndent(committed, "", "  ")
			fresh, _ := json.MarshalIndent(want, "", "  ")
			t.Fatalf("row %s snapshot is stale relative to production builder\ncommitted:\n%s\nfresh:\n%s", row.ID, got, fresh)
		})
	}
}

func TestPolicyGeneratedRustHalfRegistered10587(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	policy, err := os.ReadFile(filepath.Join(root, "userspace-dp", "src", "policy.rs"))
	if err != nil {
		t.Fatalf("read policy.rs: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^#\[cfg\(test\)\]\n(?:(?://[^\n]*|#\[[^\n]*\])\n)*#\[path = "policy_prop_tests/mod\.rs"\]\nmod policy_prop_tests;$`)
	if !decl.Match(policy) {
		t.Fatal("policy.rs no longer declares the cfg(test) #10587 Rust property module")
	}
	module, err := os.ReadFile(filepath.Join(root, "userspace-dp", "src", "policy_prop_tests", "mod.rs"))
	if err != nil {
		t.Fatalf("read policy property module: %v", err)
	}
	names := []string{
		"policy_generated_seed_rows_are_fresh_and_emittable_10587",
		"p1_determinism_totality_10587",
		"p1_generated_config_totality_10587",
		"p2_first_match_wins_10587",
		"p3_tier_precedence_10587",
		"p4_scope_soundness_10587",
		"p5_address_families_exclusions_10587",
		"p6_application_port_icmp_frag_10587",
		"p7_fragment_associated_deny_10587",
		"p8_unknown_zone_gates_10587",
		"p9_default_posture_independence_10587",
		"p10_content_reject_refusal_10587",
		"p11_policy_id_agreement_10587",
	}
	expected := make(map[string]bool, len(names))
	for _, name := range names {
		expected[name] = true
		testDecl := regexp.MustCompile(`(?m)^[ \t]*#\[test\]\r?\n(?:[ \t]*(?://[^\r\n]*|#\[[^\r\n]*\])\r?\n)*[ \t]*fn ` +
			regexp.QuoteMeta(name) + `\s*\(`)
		if !testDecl.Match(module) {
			t.Fatalf("Rust property is not registered as #[test]: %s", name)
		}
	}
	fnDecl := regexp.MustCompile(`(?m)^[ \t]*fn[ \t]+([A-Za-z0-9_]+_10587)[ \t]*\(`)
	actual := make(map[string]bool)
	for _, match := range fnDecl.FindAllSubmatch(module, -1) {
		actual[string(match[1])] = true
	}
	if len(actual) != len(expected) {
		t.Fatalf("Rust #10587 declaration set has %d functions, want exactly %d: got=%v want=%v",
			len(actual), len(expected), actual, expected)
	}
	for name := range actual {
		if !expected[name] {
			t.Fatalf("Rust #10587 declaration is not pinned: %s", name)
		}
	}
}
