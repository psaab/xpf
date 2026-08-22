package ddns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCloudflareListRecordsPaginates pins #4909: listRecords must walk every
// page of the dns_records list. The pre-fix single GET returned only page 1, so
// an xpf-owned row past the first page was invisible — driving a duplicate
// create or a false "already absent" delete.
//
// RED on revert: restore the single unpaginated GET and listRecords returns
// only the first 100 rows, failing the full-count assertion.
func TestCloudflareListRecordsPaginates(t *testing.T) {
	const (
		token   = "tok-123"
		zoneID  = "ZONEID1"
		zone    = "example.net"
		name    = "host.example.net"
		total   = 250
		perPage = 100
	)

	// Build the full record set the API holds for name+type A.
	all := make([]cfRecord, total)
	for i := range all {
		all[i] = cfRecord{
			ID:      "rec" + strconv.Itoa(i),
			Type:    "A",
			Name:    name,
			Content: "203.0.113." + strconv.Itoa(i%256),
			TTL:     1,
		}
	}
	totalPages := (total + perPage - 1) / perPage

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "errors": []any{},
				"result": []cfZone{{ID: zoneID, Name: zone}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/"+zoneID+"/dns_records":
			q := r.URL.Query()
			page, _ := strconv.Atoi(q.Get("page"))
			if page < 1 {
				page = 1
			}
			pp, _ := strconv.Atoi(q.Get("per_page"))
			if pp <= 0 {
				pp = perPage
			}
			start := (page - 1) * pp
			end := start + pp
			if start > total {
				start = total
			}
			if end > total {
				end = total
			}
			out := all[start:end]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "errors": []any{},
				"result": out,
				"result_info": map[string]int{
					"page": page, "per_page": pp, "count": len(out),
					"total_count": total, "total_pages": totalPages,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret(token),
		Zone: zone, Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}

	recs, err := b.listRecords(context.Background(), zoneID, "A", name)
	if err != nil {
		t.Fatalf("listRecords: %v", err)
	}
	if len(recs) != total {
		t.Fatalf("listRecords returned %d rows, want all %d (pagination not followed)", len(recs), total)
	}
	// The final-page row (only reachable via pagination) must be present.
	last := "rec" + strconv.Itoa(total-1)
	found := false
	for _, r := range recs {
		if r.ID == last {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("last-page record %q missing; pagination stopped early", last)
	}
}

// TestCloudflareListRecordsErrorsOnPageCap pins #6218 item 5: hitting the
// hard 1000-page runaway guard must return a non-nil error rather than a
// Warn-and-silently-truncate. The ownership-scoped upsert/delete callers
// (UpsertLease / DeleteLease) trust listRecords to return EVERY row for a
// name+type — a truncated set could hide the row xpf owns and drive a
// duplicate create or a false "already absent" delete (the exact #4909
// hazard this function exists to close), so a page-cap hit must fail the
// cycle instead of acting on a partial list.
//
// RED on revert: restoring the Warn+`return all, nil` tail makes err nil
// here, failing the error assertion.
func TestCloudflareListRecordsErrorsOnPageCap(t *testing.T) {
	const (
		token  = "tok-123"
		zoneID = "ZONEID1"
		zone   = "example.net"
		name   = "host.example.net"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "errors": []any{},
				"result": []cfZone{{ID: zoneID, Name: zone}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/"+zoneID+"/dns_records":
			// Every page returns a full page of rows and OMITS result_info, so
			// the short-page fallback never fires and the loop must run to the
			// hard maxPages cap (1000) before it can stop.
			q := r.URL.Query()
			page, _ := strconv.Atoi(q.Get("page"))
			out := make([]cfRecord, 100)
			for i := range out {
				out[i] = cfRecord{
					ID:      "rec-p" + strconv.Itoa(page) + "-" + strconv.Itoa(i),
					Type:    "A",
					Name:    name,
					Content: "203.0.113.1",
					TTL:     1,
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "errors": []any{},
				"result": out,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret(token),
		Zone: zone, Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}

	_, err = b.listRecords(context.Background(), zoneID, "A", name)
	if err == nil {
		t.Fatal("listRecords: want a non-nil error on hitting the page cap, got nil")
	}
}
