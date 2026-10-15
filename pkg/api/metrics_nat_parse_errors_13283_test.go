package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #13283 (D3-08): NAT reconcile parse errors counted in the helper must
// reach Prometheus as xpf_userspace_nat_parse_errors_total. Driving the
// real Collect (not the emitter) proves the wiring; RED pre-fix because
// ProcessStatus has no NATParseErrorsTotal field and no series exists.
func TestNATParseErrorsReachScrape13283(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		status:  dpuserspace.ProcessStatus{NATParseErrorsTotal: 7},
	}
	c := newCollector(srv)
	ch := make(chan prometheus.Metric, 4096)
	done := make(chan struct{})
	found := -1.0
	go func() {
		defer close(done)
		for m := range ch {
			var pbm dto.Metric
			if err := m.Write(&pbm); err != nil {
				continue
			}
			if strings.Contains(m.Desc().String(), `"xpf_userspace_nat_parse_errors_total"`) {
				found = pbm.GetCounter().GetValue()
			}
		}
	}()
	c.Collect(ch)
	close(ch)
	<-done
	if found != 7 {
		t.Fatalf("xpf_userspace_nat_parse_errors_total = %v, want 7", found)
	}
}

func TestNATParseErrorsStatusJSON13283(t *testing.T) {
	input := dpuserspace.ProcessStatus{NATParseErrorsTotal: 17}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["nat_parse_errors_total"]) != "17" {
		t.Fatalf("nat_parse_errors_total = %s, want 17", fields["nat_parse_errors_total"])
	}
	var output dpuserspace.ProcessStatus
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	if output.NATParseErrorsTotal != 17 {
		t.Fatalf("decoded NATParseErrorsTotal = %d, want 17", output.NATParseErrorsTotal)
	}
}
