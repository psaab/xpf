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

// #13283 (D3-08): parse/validation failures must retain their NAT builder
// type from the helper through ProcessStatus and the Prometheus scrape.
func TestNATParseErrorsReachScrape13283(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{
			SourceNATParseErrors:      7,
			DestinationNATParseErrors: 11,
			StaticNATParseErrors:      13,
		},
	}
	c := newCollector(srv)
	ch := make(chan prometheus.Metric, 4096)
	done := make(chan struct{})
	found := make(map[string]float64)
	go func() {
		defer close(done)
		for m := range ch {
			var pbm dto.Metric
			if err := m.Write(&pbm); err != nil {
				continue
			}
			if strings.Contains(m.Desc().String(), `"xpf_userspace_nat_parse_errors_total"`) {
				kind := ""
				for _, label := range pbm.GetLabel() {
					if label.GetName() == "type" {
						kind = label.GetValue()
						break
					}
				}
				found[kind] = pbm.GetCounter().GetValue()
			}
		}
	}()
	c.Collect(ch)
	close(ch)
	<-done
	for kind, want := range map[string]float64{"source": 7, "destination": 11, "static": 13} {
		if found[kind] != want {
			t.Errorf("xpf_userspace_nat_parse_errors_total{type=%q} = %v, want %v", kind, found[kind], want)
		}
	}
}

func TestNATParseErrorsStatusJSON13283(t *testing.T) {
	input := dpuserspace.ProcessStatus{
		SourceNATParseErrors:      17,
		DestinationNATParseErrors: 19,
		StaticNATParseErrors:      23,
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"source_nat_parse_errors":      "17",
		"destination_nat_parse_errors": "19",
		"static_nat_parse_errors":      "23",
	} {
		if string(fields[key]) != want {
			t.Errorf("%s = %s, want %s", key, fields[key], want)
		}
	}
	var output dpuserspace.ProcessStatus
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	if output.SourceNATParseErrors != 17 ||
		output.DestinationNATParseErrors != 19 ||
		output.StaticNATParseErrors != 23 {
		t.Fatalf("decoded NAT parse counts = (%d, %d, %d), want (17, 19, 23)",
			output.SourceNATParseErrors, output.DestinationNATParseErrors, output.StaticNATParseErrors)
	}
}
