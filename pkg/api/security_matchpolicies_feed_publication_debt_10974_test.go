package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/feeds"
)

func TestMatchPoliciesRESTReportsPublicationDebt10974(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address bad-actors 198.51.100.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone untrust to-zone trust {
            policy block-feed {
                match { source-address bad-actors; destination-address any; application any; }
                then { deny; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	s := &Server{store: store}
	s.feedOverlayFn = func() map[string][]string {
		return map[string][]string{"bad-actors": {"203.0.113.0/24"}}
	}
	s.feedsFn = func() map[string]feeds.FeedInfo {
		return map[string]feeds.FeedInfo{
			"bad-actors": {PublicationDebt: true},
		}
	}
	q := url.Values{
		"from_zone": {"untrust"},
		"to_zone":   {"trust"},
		"src_ip":    {"203.0.113.7"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/match?"+q.Encode(), nil)
	s.matchPoliciesHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var envelope struct {
		Success bool                `json:"success"`
		Data    MatchPoliciesResult `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rr.Body.String())
	}
	if !envelope.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if envelope.Data.Matched || !strings.Contains(envelope.Data.Action, "feed publication debt") {
		t.Fatalf("simulator certified an unpublished feed verdict: %+v", envelope.Data)
	}
	if !envelope.Data.FeedPublicationDebt || len(envelope.Data.FeedPublicationDebtFeeds) != 1 || envelope.Data.FeedPublicationDebtFeeds[0] != "bad-actors" {
		t.Fatalf("publication debt fields = %+v", envelope.Data)
	}
}
