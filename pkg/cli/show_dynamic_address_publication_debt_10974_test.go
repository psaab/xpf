package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

func TestShowDynamicAddressReportsPublicationDebt10974(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
		"threats": {Name: "threats", FeedName: "threat-feed", URL: "https://feeds.example/list"},
	}
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"threat-list": {Name: "threat-list", FeedNames: []string{"threat-feed"}},
	}
	runtime := map[string]feeds.FeedInfo{
		"threat-feed": {
			Prefixes: 1, Hash: "installed-hash", PublishedHash: "previous-hash",
			HasPublished: true, PublicationDebt: true,
		},
	}
	var output strings.Builder
	renderDynamicAddress(&output, cfg, runtime)
	got := output.String()
	for _, want := range []string{
		"PUBLICATION-DEBT: installed snapshot sha256=installed-hash was not confirmed applied",
		"last published sha256=previous-hash",
		"Enforced: indeterminate: feed publication debt for threat-feed",
		"dataplane may still enforce the previous-good snapshot",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("dynamic-address show lacks %q:\n%s", want, got)
		}
	}
}
