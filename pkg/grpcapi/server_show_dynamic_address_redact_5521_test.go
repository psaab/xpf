package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

// TestShowDynamicAddressRedactsFeedURLCredentials pins #5521: the
// `show security dynamic-address` render must route each feed's URL through
// config.RedactURL so embedded basic-auth userinfo (https://user:token@host)
// and query-string credentials (?apikey=secret) are NOT disclosed to a
// read-only management client (or any command-output log / support bundle).
//
// RED-on-revert: replace config.RedactURL(feed.URL) with feed.URL in
// server_show_security_text.go and the raw "s3cr3t-token" / "sup3r-secret"
// substrings reappear in the output — this test then fails.
func TestShowDynamicAddressRedactsFeedURLCredentials(t *testing.T) {
	const (
		userInfoToken = "s3cr3t-token"
		queryToken    = "sup3r-secret"
	)
	cfg := &config.Config{}
	cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
		"tenant-feed": {
			Name: "tenant-feed",
			URL:  "https://user:" + userInfoToken + "@feeds.example.com/blocklist?apikey=" + queryToken,
		},
	}

	s := &Server{}
	var buf strings.Builder
	s.showDynamicAddress(cfg, &buf)
	out := buf.String()

	// The embedded credentials must not appear anywhere in the operator-visible
	// render.
	if strings.Contains(out, userInfoToken) {
		t.Errorf("basic-auth userinfo token %q leaked into show output:\n%s", userInfoToken, out)
	}
	if strings.Contains(out, queryToken) {
		t.Errorf("query-string credential %q leaked into show output:\n%s", queryToken, out)
	}

	// The non-credential structure (scheme + host + path) must still be shown so
	// the operator can identify the feed.
	if !strings.Contains(out, "feeds.example.com") {
		t.Errorf("redacted URL dropped the host; operator can no longer identify the feed:\n%s", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("expected redaction sentinel <redacted> in output:\n%s", out)
	}
	// The feed name label must survive unchanged.
	if !strings.Contains(out, "Feed server: tenant-feed") {
		t.Errorf("feed-server name label missing from output:\n%s", out)
	}
}

func TestShowDynamicAddressReportsShrinkRefusal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DynamicAddress.FeedServers = map[string]*config.FeedServer{
		"threat": {Name: "threat", URL: "https://feeds.example/list"},
	}
	s := &Server{
		feedsFn: func() map[string]feeds.FeedInfo {
			return map[string]feeds.FeedInfo{
				"threat": {
					Prefixes: 100, Hash: "installedhash", ShrinkRefused: true, ShrinkRefusalCount: 3,
					ShrinkRefusalID: 9, ShrinkCandidateHash: "candidatehash", ShrinkBaselineHash: "installedhash",
					ShrinkCandidateOldCount: 100, ShrinkCandidateNewCount: 49,
					ShrinkCandidateReason: "cumulative high-water shrink",
					ShrinkAckHash:         "candidatehash", ShrinkAckBaselineHash: "installedhash",
					ShrinkAckReason:        "provider confirmed",
					ShrinkGuardMinOldCount: 32, ShrinkGuardMinRetainPercent: 50,
					ShrinkGuardMinDrop:        16,
					ShrinkGuardHighWaterCount: 100, ShrinkGuardHighWaterHash: "highwaterhash",
					ShrinkAckPending: true, ShrinkAckActor: "operator=alice",
				},
			}
		},
	}
	var buf strings.Builder
	s.showDynamicAddress(cfg, &buf)
	out := buf.String()
	for _, want := range []string{
		"Shrink guard: high-water >= 32 prefixes; refuse candidates below 50% of baseline with a drop of at least 16",
		"Content churn guard: installed >= 32 prefixes; refuse below 50% exact-prefix overlap",
		"Shrink refusals: 3",
		"Shrink high-water baseline: 100 prefixes sha256=highwaterhash",
		"SHRINK-HELD: candidate 49 prefixes vs guard baseline 100; refusal #9; candidate_sha256=candidatehash baseline_sha256=installedhash",
		"Guard reason: cumulative high-water shrink",
		"SHRINK-ACKED: exact candidate #9 awaiting next fetch",
		"Acked candidate_sha256=candidatehash baseline_sha256=installedhash by operator=alice; reason: \"provider confirmed\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dynamic-address show lacks %q:\n%s", want, out)
		}
	}
}
