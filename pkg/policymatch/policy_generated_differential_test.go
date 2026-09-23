package policymatch

// #10587 — generated-config/packet agreement consumer.
//
// Rust is the only generator and computes rust_verdict from the production
// PolicyState parser/evaluator. This test independently compiles every row's
// set-lines with the strict Go compiler and drives Match. No Go generator or
// expectation-only oracle is used here.
//
// Normal CI consumes the committed seed rows (48 pure-agreement rows at land).
// Operators can point the test at an emitted directory with
// XPF_POLICY_ROWS_DIR. The Rust module honors PROPTEST_CASES for soak runs;
// record the effective cases, rows, and disagreement count. Any disagreement
// is a bug, never a new allowlist.
import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const (
	policyGeneratedCorpusDir10587   = "../../testdata/policy_generated_corpus"
	policyGeneratedRowsDir10587     = "../../testdata/policy_generated_corpus/rows"
	policyGeneratedBoundaryDir10587 = "../../testdata/policy_generated_corpus/boundaries"
	policyGeneratedManifest10587    = "../../testdata/policy_generated_corpus/seed_manifest.json"
)

type generatedPolicyManifest10587 struct {
	SchemaVersion int      `json:"schema_version"`
	IDs           []string `json:"ids"`
}

type generatedPolicyQuery10587 struct {
	FromZone  string `json:"from_zone"`
	ToZone    string `json:"to_zone"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Frag      bool   `json:"frag"`
	L4Present bool   `json:"l4_present"`
	ICMPType  *uint8 `json:"icmp_type"`
	ICMPCode  *uint8 `json:"icmp_code"`
}

type generatedPolicyVerdict10587 struct {
	Action                 string `json:"action"`
	Matched                bool   `json:"matched"`
	DefaultUsed            bool   `json:"default_used"`
	UnsupportedTupleFamily bool   `json:"unsupported_tuple_family"`
	PolicyName             string `json:"policy_name"`
	PolicyID               uint32 `json:"policy_id"`
}

type generatedPolicyRow10587 struct {
	SchemaVersion  int                          `json:"schema_version"`
	ID             string                       `json:"id"`
	SourceCase     string                       `json:"source_case"`
	ConfigSetLines []string                     `json:"config_set_lines"`
	Query          generatedPolicyQuery10587    `json:"query"`
	GoVerdict      *generatedPolicyVerdict10587 `json:"go_verdict,omitempty"`
	RustVerdict    generatedPolicyVerdict10587  `json:"rust_verdict"`
	Snapshot       json.RawMessage              `json:"snapshot"`
}

type generatedPolicyAggregate10587 struct {
	SchemaVersion int                       `json:"schema_version"`
	Note          string                    `json:"_note"`
	Rows          []generatedPolicyRow10587 `json:"rows"`
}

type generatedPolicyDivergences10587 struct {
	Divergences []struct {
		ID string `json:"id"`
	} `json:"divergences"`
}

func generatedRowsDir10587() string {
	if dir := os.Getenv("XPF_POLICY_ROWS_DIR"); dir != "" {
		return dir
	}
	return policyGeneratedRowsDir10587
}

func readGeneratedRows10587(t *testing.T, dir string) []generatedPolicyRow10587 {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("generated row glob %s: %v", dir, err)
	}
	sort.Strings(paths)
	var rows []generatedPolicyRow10587
	for _, path := range paths {
		if filepath.Base(path) == "index.json" {
			continue
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read generated row %s: %v", path, err)
		}
		var row generatedPolicyRow10587
		if err := json.Unmarshal(blob, &row); err != nil {
			t.Fatalf("generated row %s is invalid JSON: %v", path, err)
		}
		if len(row.Snapshot) == 0 || string(row.Snapshot) == "null" {
			t.Fatalf("generated row %s has no production snapshot", path)
		}
		if row.ID == "" || row.ID != strings.TrimSuffix(filepath.Base(path), ".json") {
			t.Fatalf("generated row %s has unstable/missing id %q", path, row.ID)
		}
		rows = append(rows, row)
	}
	return rows
}

func generatedSeedManifestIDs10587(t *testing.T) []string {
	t.Helper()
	blob, err := os.ReadFile(policyGeneratedManifest10587)
	if err != nil {
		t.Fatalf("read seed_manifest.json: %v", err)
	}
	var manifest generatedPolicyManifest10587
	if err := json.Unmarshal(blob, &manifest); err != nil {
		t.Fatalf("seed_manifest.json is invalid JSON: %v", err)
	}
	if manifest.SchemaVersion != 1 {
		t.Fatalf("seed_manifest.json schema = %d, want 1", manifest.SchemaVersion)
	}
	if len(manifest.IDs) != 48 {
		t.Fatalf("seed_manifest.json has %d IDs, want exactly 48", len(manifest.IDs))
	}
	return manifest.IDs
}

func assertGeneratedSeedCoverage10587(t *testing.T, rows []generatedPolicyRow10587) {
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

func canonicalGeneratedJSON10587(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("canonicalize generated snapshot: %v", err)
	}
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal canonical generated snapshot: %v", err)
	}
	return out
}

func normalizeGeneratedRow10587(t *testing.T, row generatedPolicyRow10587) generatedPolicyRow10587 {
	t.Helper()
	row.Snapshot = canonicalGeneratedJSON10587(t, row.Snapshot)
	return row
}

func generatedConfig10587(t *testing.T, row generatedPolicyRow10587) *config.Config {
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
	return cfg
}

func generatedQuery10587(t *testing.T, q generatedPolicyQuery10587) Query {
	t.Helper()
	src := net.ParseIP(q.SrcIP)
	dst := net.ParseIP(q.DstIP)
	if src == nil || dst == nil {
		t.Fatalf("generated query has invalid concrete IPs: %q -> %q", q.SrcIP, q.DstIP)
	}
	if q.Frag && q.L4Present {
		t.Fatalf("generated query marks a fragment with l4_present=true")
	}
	return Query{
		FromZone:         q.FromZone,
		ToZone:           q.ToZone,
		SrcIP:            src,
		DstIP:            dst,
		SrcFamily:        config.NATAddrFamily(q.SrcIP),
		DstFamily:        config.NATAddrFamily(q.DstIP),
		Protocol:         q.Protocol,
		SrcPort:          q.SrcPort,
		DstPort:          q.DstPort,
		ICMPType:         q.ICMPType,
		ICMPCode:         q.ICMPCode,
		NonFirstFragment: q.Frag,
	}
}

func generatedVerdictFromGo10587(res Result) generatedPolicyVerdict10587 {
	policyName := ""
	policyID := uint32(0)
	if res.Matched {
		policyName = res.PolicyName
		policyID = res.PolicyID
	}
	return generatedPolicyVerdict10587{
		Action:                 policyActionName9167(res.Action),
		Matched:                res.Matched,
		DefaultUsed:            res.DefaultUsed,
		UnsupportedTupleFamily: res.UnsupportedTupleFamily,
		PolicyName:             policyName,
		PolicyID:               policyID,
	}
}

func compareGeneratedVerdicts10587(t *testing.T, row generatedPolicyRow10587, got generatedPolicyVerdict10587) {
	t.Helper()
	if row.GoVerdict != nil && !reflect.DeepEqual(*row.GoVerdict, got) {
		t.Errorf("row %s: Go seed verdict changed: got %+v want %+v", row.ID, got, *row.GoVerdict)
	}
	if !reflect.DeepEqual(got, row.RustVerdict) {
		t.Errorf("row %s: Go/Rust disagreement: go=%+v rust=%+v", row.ID, got, row.RustVerdict)
	}
}

func TestPolicyGeneratedDifferential10587(t *testing.T) {
	rows := readGeneratedRows10587(t, generatedRowsDir10587())
	assertGeneratedSeedCoverage10587(t, rows)
	if os.Getenv("XPF_POLICY_ROWS_DIR") == "" && len(rows) != 48 {
		t.Fatalf("committed generated policy row contract has %d rows, want exactly 48", len(rows))
	}
	for _, row := range rows {
		if row.SchemaVersion != 1 {
			t.Fatalf("row %s has unsupported schema %d", row.ID, row.SchemaVersion)
		}
		t.Run(row.ID, func(t *testing.T) {
			cfg := generatedConfig10587(t, row)
			res := Match(cfg, generatedQuery10587(t, row.Query))
			if res.ContentRejected {
				t.Fatalf("row %s unexpectedly content-rejected: %v", row.ID, res.ContentRejectionReasons)
			}
			compareGeneratedVerdicts10587(t, row, generatedVerdictFromGo10587(res))
		})
	}
}

// Cross-family tuples are rejected by the Go forwarding contract before policy
// matching. They deliberately live outside rows/*.json: there is no Rust
// policy-evaluator classification to compare against, so this named boundary
// is tested as its own contract rather than hidden behind an allowlist.
func TestPolicyGeneratedUnsupportedTupleBoundary10587(t *testing.T) {
	rows := readGeneratedRows10587(t, policyGeneratedBoundaryDir10587)
	if len(rows) != 1 || rows[0].ID != "cross-family-v4-to-v6" {
		t.Fatalf("unsupported-tuple boundary corpus drifted: %+v", rows)
	}
	row := rows[0]
	cfg := generatedConfig10587(t, row)
	res := Match(cfg, generatedQuery10587(t, row.Query))
	if res.ContentRejected {
		t.Fatalf("boundary row unexpectedly content-rejected: %v", res.ContentRejectionReasons)
	}
	got := generatedVerdictFromGo10587(res)
	if row.GoVerdict == nil || !reflect.DeepEqual(*row.GoVerdict, got) {
		t.Fatalf("boundary row Go outcome changed: got %+v want %+v", got, row.GoVerdict)
	}
	if !res.UnsupportedTupleFamily {
		t.Fatalf("cross-family boundary lost UnsupportedTupleFamily classification")
	}
}

// This is the consumer-side freshness gate. The userspace package has the
// production snapshot builder and performs the stronger config->snapshot check;
// this gate catches a row directory edited without rebuilding the Rust
// aggregate, and ensures every row remains strict-committable in this package.
func TestPolicyGeneratedSeedIsFresh10587(t *testing.T) {
	if os.Getenv("XPF_POLICY_ROWS_DIR") != "" {
		t.Skip("emitted rows are an operator differential input, not committed seed state")
	}
	rows := readGeneratedRows10587(t, policyGeneratedRowsDir10587)
	assertGeneratedSeedCoverage10587(t, rows)
	if len(rows) != 48 {
		t.Fatalf("committed generated policy row contract has %d rows, want exactly 48", len(rows))
	}
	blob, err := os.ReadFile(filepath.Join(policyGeneratedCorpusDir10587, "seed_rows.json"))
	if err != nil {
		t.Fatalf("read seed_rows.json: %v", err)
	}
	var aggregate generatedPolicyAggregate10587
	if err := json.Unmarshal(blob, &aggregate); err != nil {
		t.Fatalf("seed_rows.json is invalid JSON: %v", err)
	}
	if aggregate.SchemaVersion != 1 || len(aggregate.Rows) != 48 {
		t.Fatalf("seed_rows.json has schema %d and %d rows, want schema 1 and exactly 48",
			aggregate.SchemaVersion, len(aggregate.Rows))
	}
	if len(rows) != len(aggregate.Rows) {
		t.Fatalf("seed_rows.json has %d rows but rows/ has %d", len(aggregate.Rows), len(rows))
	}
	for i := range rows {
		got := normalizeGeneratedRow10587(t, rows[i])
		want := normalizeGeneratedRow10587(t, aggregate.Rows[i])
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed_rows.json is stale relative to rows/*.json at index %d; rerun the aggregate assembly step", i)
		}
	}
	for _, row := range rows {
		_ = generatedConfig10587(t, row)
	}
	var allow generatedPolicyDivergences10587
	allowBlob, err := os.ReadFile(filepath.Join(policyGeneratedCorpusDir10587, "known_divergences.json"))
	if err != nil {
		t.Fatalf("read known_divergences.json: %v", err)
	}
	if err := json.Unmarshal(allowBlob, &allow); err != nil {
		t.Fatalf("known_divergences.json is invalid JSON: %v", err)
	}
	if len(allow.Divergences) != 0 {
		t.Fatalf("known_divergences.json must be empty at land; got %d entries", len(allow.Divergences))
	}
}

// P10 Go-led refusal pin: an unrepresentable application is a config-wide
// content rejection, not a fabricated policy verdict. This is a separate
// application-axis pin from Rust's address-sentinel refusal property.
func TestPolicyGeneratedContentRejectRefusal10587(t *testing.T) {
	row := generatedPolicyRow10587{
		ID: "content-reject", ConfigSetLines: []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone untrust interfaces ge-0/0/1.0",
			"set security policies default-policy deny-all",
			"set security policies from-zone trust to-zone untrust policy bad match source-address any",
			"set security policies from-zone trust to-zone untrust policy bad match destination-address any",
			"set security policies from-zone trust to-zone untrust policy bad match application missing-app",
			"set security policies from-zone trust to-zone untrust policy bad then permit",
		},
	}
	tr := &config.ConfigTree{}
	for _, line := range row.ConfigSetLines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("content-reject parse %q: %v", line, err)
		}
		if err := tr.SetPath(path); err != nil {
			t.Fatalf("content-reject set %q: %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tr)
	if err != nil {
		t.Fatalf("content-reject lenient compile: %v", err)
	}
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		SrcFamily: config.NATAddrFamily("10.0.1.5"),
		DstFamily: config.NATAddrFamily("10.0.2.5"),
		Protocol:  "tcp", SrcPort: 1234, DstPort: 80,
	})
	if !res.ContentRejected {
		t.Fatalf("Match did not surface ContentRejected: %+v", res)
	}
	if res.Matched || res.DefaultUsed || res.HostInboundUnmatched {
		t.Fatalf("ContentRejected must not fabricate Matched/DefaultUsed/HostInboundUnmatched: %+v", res)
	}
	if res.DisplayAction() != ContentRejectedActionString {
		t.Fatalf("DisplayAction() = %q, want ContentRejectedActionString", res.DisplayAction())
	}
	reasons := strings.Join(res.ContentRejectionReasons, " | ")
	if !strings.Contains(reasons, "trust->untrust/bad") || !strings.Contains(reasons, "missing-app") {
		t.Fatalf("content rejection reasons %q do not name the offending policy/application", reasons)
	}
}
