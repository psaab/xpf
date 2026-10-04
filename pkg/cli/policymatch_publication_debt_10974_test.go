package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/feeds"
)

// TestPolicySimulatorRefusesToCertifyUnpublishedFeedContent10974 proves the
// CLI simulator reports an indeterminate result when a policy evaluation
// consults feed content whose apply was rejected.
func TestPolicySimulatorRefusesToCertifyUnpublishedFeedContent10974(t *testing.T) {
	c := newFeedPolicyCLI(t)
	c.feedOverlayFn = func() map[string][]string {
		return map[string][]string{"bad-actors": {"203.0.113.0/24"}}
	}
	c.feedsFn = func() map[string]feeds.FeedInfo {
		return map[string]feeds.FeedInfo{
			"bad-actors": {
				Hash: "installed-hash", PublishedHash: "previous-hash",
				HasPublished: true, PublicationDebt: true,
			},
		}
	}
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	args := []string{"from-zone", "untrust", "to-zone", "trust", "source-ip", "203.0.113.7"}
	out := captureStdout(t, func() {
		if err := c.showMatchPolicies(cfg, args); err != nil {
			t.Fatalf("showMatchPolicies error = %v", err)
		}
	})
	if !strings.Contains(out, "feed publication debt:") || !strings.Contains(out, "bad-actors") {
		t.Fatalf("simulator did not identify unpublished feed debt:\n%s", out)
	}
	if strings.Contains(out, "Matching policy") || strings.Contains(out, "No matching policy") {
		t.Fatalf("simulator certified a verdict from unpublished feed content:\n%s", out)
	}
}
