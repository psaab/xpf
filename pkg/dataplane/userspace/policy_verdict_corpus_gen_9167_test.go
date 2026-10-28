package userspace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9167 — the SNAPSHOT half of the shared policy-verdict corpus.
//
// The Rust enforcer evaluates a SNAPSHOT; the Go simulator evaluates a CONFIG.
// So the corpus carries the config (authored, in testdata/policy_verdict_corpus.txt)
// and this generator emits the snapshot Go would put on the wire for it, into a
// COMMITTED file the Rust test reads.
//
// WHAT THE GENERATOR DELIBERATELY DOES NOT EMIT: the queries and their expected
// verdicts. Those reach Rust by Rust parsing the corpus TEXT itself. If Go
// transcribed the expectation column into the JSON, the oracle would arrive at
// the Rust side THROUGH Go, and a Go misreading would be invisible — the exact
// shape of dependence this issue exists to remove. The snapshot has to come from
// Go because Go builds it in production; the expectation does not.
//
// THE HONEST BOUND, stated because it is the one thing this differential cannot
// see. The snapshot handed to Rust is built by Go's snapshot BUILDER, so that
// builder is shared input to both sides. It is not a blind spot for the tier
// walk — Go's simulator reads the CONFIG, not the snapshot, so a builder that
// drops or mangles a rule makes the two sides disagree with each other and with
// the corpus — but a builder defect that the corpus expectation was ALSO written
// to match would be invisible. That is why the expectation column is authored
// from the Junos semantics rather than transcribed from a run.

const (
	policyCorpusTextPath9167 = "../../../testdata/policy_verdict_corpus.txt"
	policyCorpusSnapPath9167 = "../../../testdata/policy_verdict_corpus_snapshots.json"
)

type policyCorpusSnapshot9167 struct {
	DefaultPolicy string                `json:"default_policy"`
	Rules         []PolicyRuleSnapshot  `json:"rules,omitempty"`
	Zones         []ZoneSnapshot        `json:"zones,omitempty"`
	AddressBooks  []AddressBookSnapshot `json:"address_books,omitempty"`
}

type policyCorpusSnapshotFile9167 struct {
	Note  string                              `json:"_note"`
	Cases map[string]policyCorpusSnapshot9167 `json:"cases"`
}

// corpusCase9167 is one generator-side case: its config lines plus the
// #17077 case-level inputs (lenient flag, feed overlay) the snapshot builder
// needs. The query grammar is deliberately not parsed here — the generator
// has no business seeing the expectations.
type corpusCase9167 struct {
	SetLines    []string
	Lenient     bool
	FeedOverlay map[string][]string
}

// corpusCaseSetLines9167 reads ONLY what this generator needs: the case names,
// their config lines, and the #17077 `lenient` flag / `feed` overlay lines.
func corpusCaseSetLines9167(t *testing.T) map[string]corpusCase9167 {
	t.Helper()
	f, err := os.Open(policyCorpusTextPath9167)
	if err != nil {
		t.Fatalf("#9167: the shared corpus is unreadable: %v", err)
	}
	defer f.Close()
	out := map[string]corpusCase9167{}
	var name string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "case "):
			rest := strings.TrimSpace(line[5:])
			name = rest
			cc := corpusCase9167{}
			if f := strings.Fields(rest); len(f) == 2 && f[1] == "lenient" {
				name, cc.Lenient = f[0], true
			}
			out[name] = cc
		case line == "end":
			name = ""
		case strings.HasPrefix(line, "set ") && name != "":
			cc := out[name]
			cc.SetLines = append(cc.SetLines, line)
			out[name] = cc
		case strings.HasPrefix(line, "feed ") && name != "":
			rest := strings.TrimSpace(line[5:])
			feedName, rhs, ok := strings.Cut(rest, "=")
			if !ok || feedName == "" {
				t.Fatalf("#9167: bad feed line %q", line)
			}
			cc := out[name]
			if cc.FeedOverlay == nil {
				cc.FeedOverlay = map[string][]string{}
			}
			var prefixes []string
			if rhs != "" {
				prefixes = strings.Split(rhs, ",")
			}
			cc.FeedOverlay[feedName] = prefixes
			out[name] = cc
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("#9167: reading the corpus: %v", err)
	}
	return out
}

func buildCorpusSnapshots9167(t *testing.T) policyCorpusSnapshotFile9167 {
	t.Helper()
	cases := corpusCaseSetLines9167(t)
	if len(cases) == 0 {
		t.Fatal("#9167: the corpus yielded no cases; the generator would emit an empty file " +
			"and the Rust half would assert nothing")
	}
	out := policyCorpusSnapshotFile9167{
		Note: "GENERATED from testdata/policy_verdict_corpus.txt by " +
			"TestPolicyVerdictCorpusSnapshotsAreFresh9167 (UPDATE_9167=1). Do not hand-edit: " +
			"it is the snapshot Go puts on the wire, and the Rust half of the #9167 " +
			"differential reads it. The EXPECTED VERDICTS are NOT here on purpose — Rust " +
			"reads those from the corpus text directly.",
		Cases: map[string]policyCorpusSnapshot9167{},
	}
	for name, cc := range cases {
		tr := &config.ConfigTree{}
		for _, l := range cc.SetLines {
			p, err := config.ParseSetCommand(l)
			if err != nil {
				t.Fatalf("case %q: parse %q: %v", name, l, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("case %q: setpath %q: %v", name, l, err)
			}
		}
		compile := config.CompileConfig
		if cc.Lenient {
			compile = config.CompileConfigLenient
		}
		cfg, err := compile(tr)
		if err != nil {
			t.Fatalf("case %q: the corpus config does not compile (lenient=%v): %v", name, cc.Lenient, err)
		}
		books, nameToID, err := buildAddressBookTableWithFeeds(cfg, cc.FeedOverlay)
		if err != nil {
			t.Fatalf("case %q: address book: %v", name, err)
		}
		rules, err := buildPolicySnapshotsWithAddressBook(cfg, nil, cc.FeedOverlay, nameToID)
		if err != nil {
			t.Fatalf("case %q: policy snapshot: %v", name, err)
		}
		zones := buildZoneSnapshots(cfg)
		if cc.Lenient {
			// #17077: emit the post-quarantine snapshot the dataplane
			// actually receives (builder.go runs quarantineCollidingZones
			// before publishing): the quarantined zone and its policies
			// are absent, so the Rust half enforces the same posture the
			// Go simulator's zoneKnown gate reports.
			snap := &ConfigSnapshot{Zones: zones, Policies: rules, Config: cfg}
			quarantineCollidingZones(snap)
			zones, rules = snap.Zones, snap.Policies
		}
		out.Cases[name] = policyCorpusSnapshot9167{
			DefaultPolicy: policyActionString(cfg.Security.DefaultPolicy),
			Rules:         rules,
			Zones:         zones,
			AddressBooks:  books,
		}
	}
	return out
}

// TestPolicyVerdictCorpusSnapshotsAreFresh9167 keeps the committed snapshot file
// in step with the corpus text.
//
// Without it the two halves of the differential could silently describe
// different configs: a corpus case edited here and a stale snapshot there, with
// the Rust side asserting the OLD config against the NEW expectation. That
// failure would look like a Go/Rust disagreement and send the reader hunting a
// drift that is not there.
//
// Regenerate with `UPDATE_9167=1 go test ./pkg/dataplane/userspace/ -run 9167`.
func TestPolicyVerdictCorpusSnapshotsAreFresh9167(t *testing.T) {
	built := buildCorpusSnapshots9167(t)
	blob, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob = append(blob, '\n')

	if os.Getenv("UPDATE_9167") != "" {
		if err := os.WriteFile(policyCorpusSnapPath9167, blob, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("#9167: regenerated %s (%d cases)", policyCorpusSnapPath9167, len(built.Cases))
		return
	}

	want, err := os.ReadFile(policyCorpusSnapPath9167)
	if err != nil {
		t.Fatalf("#9167: the committed snapshot file is unreadable (%v). Regenerate with "+
			"UPDATE_9167=1; the Rust half of the differential reads it and cannot run "+
			"without it.", err)
	}
	if string(want) != string(blob) {
		t.Errorf("#9167: %s is STALE relative to the corpus text.\n"+
			"Regenerate with UPDATE_9167=1.\n\n"+
			"This matters more than an ordinary golden file: the Rust half asserts the "+
			"corpus's EXPECTED VERDICTS against the config in THIS file. If the two "+
			"describe different configs, Rust fails against an expectation that was never "+
			"written for it, and the failure reads like a Go/Rust drift that does not exist.",
			policyCorpusSnapPath9167)
	}
}

// TestPolicyCorpusSnapshotMirrorsTheWireShape9167 keeps the fixture's WIRE SHAPE
// tied to the real producer's, so the fixture cannot become more well-formed
// than production.
//
// The corpus differential is only as honest as the snapshot it hands Rust. If
// this wrapper's tags drifted from ConfigSnapshot's -- dropping `,omitempty` so
// it emits `null`, or production dropping `,omitempty` so IT emits `null` -- the
// fixture and the real wire would describe different shapes, and the Rust half
// would be exercising a decode path production never takes (or skipping one it
// does). Measured: that drift is how the first generated file came to carry
// `"address_books": null`, which production cannot send.
//
// FAIL-ON-REVERT: remove `,omitempty` from any of the three wrapper fields, or
// from the matching ConfigSnapshot field, and this cell reds naming the field.
func TestPolicyCorpusSnapshotMirrorsTheWireShape9167(t *testing.T) {
	prod := reflect.TypeOf(ConfigSnapshot{})
	mine := reflect.TypeOf(policyCorpusSnapshot9167{})
	for _, pair := range []struct{ prodField, mineField string }{
		{"Zones", "Zones"},
		{"Policies", "Rules"},
		{"AddressBooks", "AddressBooks"},
	} {
		pf, ok := prod.FieldByName(pair.prodField)
		if !ok {
			t.Fatalf("ConfigSnapshot has no field %q; the wire shape this cell pins has moved",
				pair.prodField)
		}
		mf, ok := mine.FieldByName(pair.mineField)
		if !ok {
			t.Fatalf("the corpus wrapper has no field %q", pair.mineField)
		}
		if pf.Type != mf.Type {
			t.Errorf("#9167: element type differs for %s: production %v, fixture %v",
				pair.prodField, pf.Type, mf.Type)
		}
		pOmit := strings.Contains(pf.Tag.Get("json"), ",omitempty")
		mOmit := strings.Contains(mf.Tag.Get("json"), ",omitempty")
		if pOmit != mOmit {
			t.Errorf("#9167: WIRE SHAPE DRIFT on %s: production `,omitempty`=%v, fixture "+
				"`,omitempty`=%v. With them different, an empty list is an ABSENT key on one side "+
				"and `null` on the other, so the Rust half decodes a shape production never sends.",
				pair.prodField, pOmit, mOmit)
		}
	}
}

// TestPolicyVerdictCorpusRustHalfIsRegistered9167 binds the WIRING of the Rust
// half of the differential, which nothing on the Rust side can do.
//
// The Rust half is a `#[path]` test module declared in policy.rs. Delete that
// declaration and `cargo test` stays GREEN: the module is simply not compiled,
// the corpus is asserted in Go alone, and the one-sided oracle #9167 exists to
// remove is back while every suite passes. A test cannot notice its own absence,
// so the declaration is pinned from here, beside the generator that feeds it.
// The include_str! paths are pinned too: a Rust half reading some other file
// would pass just as silently.
func TestPolicyVerdictCorpusRustHalfIsRegistered9167(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	policyRS, err := os.ReadFile(filepath.Join(root, "userspace-dp", "src", "policy.rs"))
	if err != nil {
		t.Fatalf("read policy.rs: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^#\[cfg\(test\)\]\n(?:(?://[^\n]*|#\[[^\n]*\])\n)*#\[path = "policy_verdict_corpus_9167\.rs"\]\nmod policy_verdict_corpus_9167;$`)
	if !decl.Match(policyRS) {
		t.Fatalf("#9167: userspace-dp/src/policy.rs no longer declares the Rust half of the " +
			"policy-verdict corpus differential (`#[cfg(test)] #[path = \"policy_verdict_corpus_9167.rs\"] " +
			"mod policy_verdict_corpus_9167;`). Without it cargo test stays green while the corpus is " +
			"asserted in Go only, which is the unverified simulator this differential replaced")
	}
	half, err := os.ReadFile(filepath.Join(root, "userspace-dp", "src", "policy_verdict_corpus_9167.rs"))
	if err != nil {
		t.Fatalf("read the Rust half: %v", err)
	}
	for _, want := range []string{
		`include_str!("../../testdata/policy_verdict_corpus.txt")`,
		`include_str!("../../testdata/policy_verdict_corpus_snapshots.json")`,
		"#[test]\nfn policy_verdict_corpus_differential_9167()",
	} {
		if !bytes.Contains(half, []byte(want)) {
			t.Errorf("#9167: the Rust half no longer contains %q, so it is not asserting the shared corpus", want)
		}
	}
}
