package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

// TestRenderDynamicAddressAgreesWithEnforcement9689: the show surface reports
// the hold interval as applied, a hold drop, and per binding what is enforced.
func TestRenderDynamicAddressAgreesWithEnforcement9689(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
		"partner-feed": {Name: "partner-feed", URL: "http://example.test/p"},
		"threat-feed":  {Name: "threat-feed", URL: "http://example.test/t", HoldInterval: 600},
	}
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"allow-partners": {Name: "allow-partners", FeedNames: []string{"partner-feed"}, FailMode: "drop"},
		"deny-threats":   {Name: "deny-threats", FeedNames: []string{"partner-feed"}},
		"current":        {Name: "current", FeedNames: []string{"threat-feed"}},
	}
	runtime := map[string]feeds.FeedInfo{
		"partner-feed": {HoldDropped: true},
		"threat-feed":  {Prefixes: 3, LastFetch: time.Now()},
	}
	var b strings.Builder
	renderDynamicAddress(&b, cfg, runtime)
	out := b.String()
	for _, want := range []string{
		"Hold interval:   none (last-good set retained indefinitely)",
		"Hold interval:   600 seconds, then the last-good set is dropped",
		"HOLD-DROPPED",
		"allow-partners: feeds partner-feed, fail-mode drop",
		"1 feed(s) dropped by hold-interval, publishing the other 0 feed(s)' prefixes (fail-mode drop)",
		"deny-threats: feeds partner-feed, fail-mode retain",
		"under fail-mode retain, so policies referencing this name are rejected",
		"current: feeds threat-feed, fail-mode retain",
		"Enforced: current prefixes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "7200") {
		t.Errorf("show still prints a 7200s hold default that nothing applies:\n%s", out)
	}
}
