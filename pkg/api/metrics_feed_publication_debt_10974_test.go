package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/feeds"
)

func TestFeedPublicationDebtMetric10974(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	collector := newCollector(&Server{
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threat-feed": {PublicationDebt: true},
			}
		},
	})
	if err := reg.Register(collector); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather collector: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "xpf_feed_publication_debt" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if len(metric.GetLabel()) == 1 && metric.GetLabel()[0].GetName() == "feed" && metric.GetLabel()[0].GetValue() == "threat-feed" &&
				metric.GetGauge().GetValue() == 1 {
				return
			}
		}
	}
	t.Fatal("scrape did not emit xpf_feed_publication_debt{feed=\"threat-feed\"}=1")
}
