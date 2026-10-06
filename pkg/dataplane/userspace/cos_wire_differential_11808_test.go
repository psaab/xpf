package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const cosWireFixture11808 = "protocol_wire_cos_v1.json"

func compileCoSWireFixture11808(t *testing.T) *config.Config {
	t.Helper()
	commands := []string{
		"set system dataplane-type userspace",
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 1 bulk-data",
		"set class-of-service forwarding-classes queue 5 voice",
		// DSCP 46 is deliberately assigned to bulk first and voice second.
		// Rust's classifier table uses source-order last-wins semantics.
		"set class-of-service classifiers dscp edge-dscp forwarding-class bulk-data loss-priority low code-points [ 10 46 ]",
		"set class-of-service classifiers dscp edge-dscp forwarding-class voice loss-priority high code-points 46",
		"set class-of-service classifiers dscp edge-dscp forwarding-class voice loss-priority medium-high code-points 48",
		// Undefined FC input is committable on the tolerant path but must not
		// cross the Go snapshot boundary.
		"set class-of-service classifiers dscp edge-dscp forwarding-class missing-class loss-priority high code-points 50",
		"set class-of-service rewrite-rules dscp edge-rewrite forwarding-class best-effort loss-priority low code-point 1",
		"set class-of-service rewrite-rules dscp edge-rewrite forwarding-class bulk-data loss-priority low code-point 11",
		"set class-of-service rewrite-rules dscp edge-rewrite forwarding-class voice loss-priority high code-point 55",
		"set class-of-service rewrite-rules dscp edge-rewrite forwarding-class voice loss-priority medium-high code-point 54",
		"set class-of-service rewrite-rules dscp edge-rewrite forwarding-class missing-class loss-priority high code-point 60",
		"set class-of-service schedulers be-scheduler priority low",
		"set class-of-service schedulers bulk-scheduler priority low",
		"set class-of-service scheduler-maps edge-map forwarding-class best-effort scheduler be-scheduler",
		"set class-of-service scheduler-maps edge-map forwarding-class bulk-data scheduler bulk-scheduler",
		// The dangling scheduler is preserved for the Rust safe-default path.
		"set class-of-service scheduler-maps edge-map forwarding-class voice scheduler missing-scheduler",
		// Undefined forwarding classes are skipped rather than sent to Rust.
		"set class-of-service scheduler-maps edge-map forwarding-class missing-class scheduler be-scheduler",
	}

	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func decodeCoSWireValue11808(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode fixture value %s: %v", raw, err)
	}
	return value
}

func TestCoSConfigSnapshotWireDifferential11808(t *testing.T) {
	cfg := compileCoSWireFixture11808(t)
	snapshot := buildClassOfServiceSnapshot(cfg)
	if snapshot == nil {
		t.Fatal("compiled CoS config produced no class-of-service snapshot")
	}

	if len(snapshot.DSCPClassifiers) != 1 ||
		len(snapshot.DSCPRewriteRules) != 1 ||
		len(snapshot.SchedulerMaps) != 1 {
		t.Fatalf("compiled CoS snapshot lacks the expected classifier/rewrite/map: %+v", snapshot)
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal CoS snapshot: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("decode Go CoS wire: %v", err)
	}

	fixturePath := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures", cosWireFixture11808)
	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", fixturePath, err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode %s: %v", fixturePath, err)
	}
	var expected map[string]json.RawMessage
	if err := json.Unmarshal(fixture["populated_snapshot"], &expected); err != nil {
		t.Fatalf("decode populated CoS fixture: %v", err)
	}

	// Compare every populated wire array exactly, including list order. The
	// fixture also carries an explicit all-empty Rust DTO specimen; Go's
	// omitempty omissions from the populated wire shape are asserted below.
	for _, field := range []string{
		"forwarding_classes",
		"dscp_classifiers",
		"dscp_rewrite_rules",
		"schedulers",
		"scheduler_maps",
	} {
		want, ok := expected[field]
		if !ok {
			t.Fatalf("fixture populated_snapshot lacks %q", field)
		}
		actual, ok := got[field]
		if !ok {
			t.Fatalf("Go CoS wire omits populated field %q", field)
		}
		if !reflect.DeepEqual(decodeCoSWireValue11808(t, actual), decodeCoSWireValue11808(t, want)) {
			t.Errorf("Go CoS wire %s differs from Rust-consumed fixture:\n got %s\nwant %s", field, actual, want)
		}
	}
	var emptySnapshot map[string]json.RawMessage
	if err := json.Unmarshal(fixture["empty_snapshot"], &emptySnapshot); err != nil {
		t.Fatalf("decode empty CoS fixture: %v", err)
	}
	for _, field := range []string{
		"forwarding_classes",
		"dscp_classifiers",
		"ieee8021_classifiers",
		"inet_precedence_classifiers",
		"dscp_rewrite_rules",
		"scheduler_maps",
		"schedulers",
	} {
		empty, ok := emptySnapshot[field]
		if !ok || !reflect.DeepEqual(decodeCoSWireValue11808(t, empty), []any{}) {
			t.Fatalf("empty_snapshot %s = %s, want explicit empty array", field, empty)
		}
	}
	for _, field := range []string{"ieee8021_classifiers", "inet_precedence_classifiers"} {
		if _, ok := expected[field]; ok {
			t.Errorf("populated fixture unexpectedly contains empty %s; Go wire omits it", field)
		}
		if _, ok := got[field]; ok {
			t.Errorf("Go CoS wire unexpectedly emitted empty %s despite omitempty", field)
		}
	}

	// Pin Go's compile-to-snapshot treatment of dangling references. The
	// undefined FC entries are absent; the undefined scheduler reference is
	// retained so Rust can preserve the queue with its safe scheduler default.
	classifier := snapshot.DSCPClassifiers[0]
	for _, entry := range classifier.Entries {
		if entry.ForwardingClass == "missing-class" {
			t.Fatal("undefined forwarding-class classifier entry crossed the wire")
		}
	}
	for _, entry := range snapshot.DSCPRewriteRules[0].Entries {
		if entry.ForwardingClass == "missing-class" {
			t.Fatal("undefined forwarding-class rewrite entry crossed the wire")
		}
	}
	var sawUndefinedScheduler, sawUndefinedClass bool
	for _, entry := range snapshot.SchedulerMaps[0].Entries {
		sawUndefinedScheduler = sawUndefinedScheduler ||
			(entry.ForwardingClass == "voice" && entry.Scheduler == "missing-scheduler")
		sawUndefinedClass = sawUndefinedClass || entry.ForwardingClass == "missing-class"
	}
	if !sawUndefinedScheduler {
		t.Fatal("undefined scheduler reference was not retained for Rust safe-default handling")
	}
	if sawUndefinedClass {
		t.Fatal("undefined forwarding-class scheduler-map entry crossed the wire")
	}

	// The duplicate is deliberate and ordered: the last DSCP 46 classifier
	// entry is voice/high, the winner Rust must use for queue and LP verdicts.
	var dscp46 []CoSDSCPClassifierEntrySnapshot
	for _, entry := range classifier.Entries {
		for _, dscp := range entry.DSCPValues {
			if dscp == 46 {
				dscp46 = append(dscp46, entry)
				break
			}
		}
	}
	if len(dscp46) != 2 ||
		dscp46[0].ForwardingClass != "bulk-data" || dscp46[0].LossPriority != "low" ||
		dscp46[1].ForwardingClass != "voice" || dscp46[1].LossPriority != "high" {
		t.Fatalf("DSCP 46 duplicate entries = %+v, want ordered bulk-data/low then voice/high", dscp46)
	}
}
