package configstore

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// syslog_facility_lenient_6844_test.go -- #6844.
//
// #6844 added a commit-time gate on the `system syslog <dest> <facility>` key.
// The claim that makes that safe is the #1319/#1960 split: SchemaValidate is
// strict ONLY on the operator-driven commit path, and Store.compileTreeLenient
// downgrades a violation to a WARNING on the tolerant Load / SyncApply ingress —
// so a config an older binary accepted still BOOTS.
//
// That claim was asserted in a PR body and in comments, and proved nowhere. A
// daemon-side test named itself "IsLoadReachable" while calling ordinary
// config.CompileConfig, so a regression that routed Load through STRICT
// compilation — or made compileTreeLenient return schema errors — would have
// left every cell green while blackout-booting a node on upgrade.
//
// This drives the real Store.Load.

// TestLoadToleratesAnInjectableSyslogFacility_6844 is the #1960 proof.
//
// The config below is one an older binary accepted: it carries a facility the
// #6844 gate now rejects. Loading it must SUCCEED, because refusing would leave
// an upgraded node with no active config — an operational blackout — over a
// value the compiler still compiles the same way it always did.
func TestLoadToleratesAnInjectableSyslogFacility_6844(t *testing.T) {
	dir := t.TempDir()

	const src = "system {\n  host-name box;\n  syslog {\n    file audit {\n" +
		"      \"daemon;*.* /tmp/pwn\" info;\n    }\n  }\n}\n"
	tree, errs := config.NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}

	// PRECONDITION, or this test proves nothing: the STRICT gate must actually
	// reject this value. If it stops rejecting, the tolerance below is vacuous
	// — it would be tolerating something nothing objects to.
	if _, err := config.CompileConfig(tree); err != nil {
		t.Fatalf("precondition: the compiler rejected the value, so this is no longer "+
			"a schema-layer question: %v", err)
	}
	if err := config.SchemaValidate(tree); err == nil {
		t.Fatal("precondition: SchemaValidate ACCEPTS the injectable facility, so the " +
			"#6844 gate is gone and this test tolerates a value nothing rejects")
	}

	db, err := NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("older-binary-1.0")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	st, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Load(); err != nil {
		t.Fatalf("Store.Load REJECTED a previously-committed config over the #6844 "+
			"facility gate: %v\n"+
			"The tolerant ingress must downgrade a typed-leaf violation to a warning "+
			"(#1319), or an upgraded node boots with no active config and an upgraded "+
			"standby alarm-loops HA config sync (#1960).", err)
	}
	if st.ActiveConfig() == nil {
		t.Fatal("Load succeeded but promoted no config; the node has no active " +
			"configuration, which is the blackout this split exists to prevent")
	}

	// And the value survived unchanged: the tolerant path warns, it does not
	// silently rewrite. The render belt is what keeps it off disk.
	files := st.ActiveConfig().System.Syslog.Files
	if len(files) != 1 || len(files[0].Selectors) != 1 ||
		files[0].Selectors[0].Facility != "daemon;*.* /tmp/pwn" {
		t.Errorf("loaded facility = %+v, want the verbatim value — the tolerant path "+
			"must warn, not rewrite", files)
	}
}

// TestCommitRejectsAnInjectableSyslogFacility_6844 is the paired half.
//
// Without it, "Load tolerates it" is satisfied by a build where NOTHING rejects
// the value anywhere, which is the pre-#6844 state. The two together say what
// the split actually claims: strict at commit, tolerant on load.
func TestCommitRejectsAnInjectableSyslogFacility_6844(t *testing.T) {
	st := newTestStore(t)
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	const src = "system {\n  host-name box;\n  syslog {\n    file audit {\n" +
		"      \"daemon;*.* /tmp/pwn\" info;\n    }\n  }\n}\n"
	if err := st.LoadOverride(src); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := st.CommitCheck(); err == nil {
		t.Fatal("commit-check ACCEPTED an injectable syslog facility. The operator is " +
			"told nothing and their configuration silently does not do what it says " +
			"(#6844) — the whole point of the gate.")
	}
}
