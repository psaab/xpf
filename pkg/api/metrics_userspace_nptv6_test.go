package api

import (
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"testing"
)

func TestEmitUserspaceNptv6Metrics(t *testing.T) {
	c := &xpfCollector{
		userspaceNptv6TranslationsTotal: prometheus.NewDesc(
			"xpf_userspace_nptv6_translations_total", "test", []string{"direction"}, nil),
		userspaceNptv6UntranslatableDrops: prometheus.NewDesc(
			"xpf_userspace_nptv6_untranslatable_drops_total", "test", nil, nil),
	}
	status := dpuserspace.ProcessStatus{
		Nptv6InboundTranslations:  7,
		Nptv6OutboundTranslations: 11,
		Nptv6UntranslatableDrops:  3,
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal process status: %v", err)
	}
	var decoded dpuserspace.ProcessStatus
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal process status: %v", err)
	}
	if decoded.Nptv6InboundTranslations != status.Nptv6InboundTranslations ||
		decoded.Nptv6OutboundTranslations != status.Nptv6OutboundTranslations ||
		decoded.Nptv6UntranslatableDrops != status.Nptv6UntranslatableDrops {
		t.Fatalf("NPTv6 status wire roundtrip = %+v, want %+v", decoded, status)
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.emitUserspaceNptv6(ch, status)
		close(ch)
	}()
	directions := map[string]float64{}
	var untranslatable float64
	metrics := 0
	for metric := range ch {
		metrics++
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Counter == nil {
			t.Fatalf("metric %s is not a counter", metric.Desc())
		}
		direction := ""
		for _, label := range pb.Label {
			if label.GetName() == "direction" {
				direction = label.GetValue()
			}
		}
		if direction != "" {
			directions[direction] = pb.Counter.GetValue()
		} else {
			untranslatable = pb.Counter.GetValue()
		}
	}
	if metrics != 3 {
		t.Fatalf("got %d metrics, want 3", metrics)
	}
	if directions["inbound"] != 7 || directions["outbound"] != 11 {
		t.Errorf("translation directions = %#v, want inbound=7, outbound=11", directions)
	}
	if untranslatable != 3 {
		t.Errorf("untranslatable drops = %v, want 3", untranslatable)
	}
}
