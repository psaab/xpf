package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #11503: decode the populated Rust status specimen and carry its distinct
// cause values through the real userspace-status Prometheus collection path.
func TestRustUnzonedPolicyDenialsReachPrometheus11503(t *testing.T) {
	fixture := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures", "protocol_wire_v1.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read Rust protocol fixture %s: %v", fixture, err)
	}
	var specimens map[string]json.RawMessage
	if err := json.Unmarshal(raw, &specimens); err != nil {
		t.Fatalf("decode Rust protocol fixture: %v", err)
	}
	var status dpuserspace.ProcessStatus
	if specimen, ok := specimens["process_status_unzoned_policy_denials"]; !ok {
		t.Fatal("Rust protocol fixture has no populated unzoned-denial ProcessStatus specimen")
	} else if err := json.Unmarshal(specimen, &status); err != nil {
		t.Fatalf("decode Rust ProcessStatus specimen: %v", err)
	}

	collector := newCollector(&Server{})
	ch := make(chan prometheus.Metric)
	go func() {
		collector.collectUserspaceStatus(ch, &status)
		close(ch)
	}()
	var got []prometheus.Metric
	for metric := range ch {
		got = append(got, metric)
	}
	assertCounterClose(t, got, collector.userspaceUnzonedIngressDenied, nil, 107)
	assertCounterClose(t, got, collector.userspaceUnzonedEgressDenied, nil, 211)
}
