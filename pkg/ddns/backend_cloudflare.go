package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_cloudflare.go: the Cloudflare API DDNS backend (#2691 P3, plan
// §5.2). Authenticates with an API TOKEN (Authorization: Bearer) and publishes a
// single A/AAAA record through the Cloudflare DNS API. The flow mirrors inadyn's
// `setup`+`request` model:
//
//  1. setup  — resolve the zone id from the configured zone name (GET /zones).
//  2. find   — GET /zones/{zid}/dns_records?type=&name= for the existing record.
//  3. update — PATCH the existing record's content, OR POST a new record.
//
// Rate-limit discipline (plan §8.3): the Surface A engine only calls Upsert on a
// CHANGE or a forced-refresh, so a steady WAN address generates at most one
// Cloudflare update per forced-refresh interval — far under the ~1200 req/5min
// limit. A 429 is classified errHTTPRateLimited and the engine backs off.
//
// Implements the SAME DNSUpdater interface as rfc2136; the Surface A engine
// drives it identically.

// cloudflareAPIBase is the production API root. Overridable per-instance (the
// apiBase field) so httptest can point the backend at a mock server.
const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareBackend publishes a single record via the Cloudflare API.
type cloudflareBackend struct {
	name    string
	apiBase string
	token   string // revealed at construction; never logged
	zone    string // zone NAME (e.g. example.net); id resolved at update time
	client  *http.Client
}

// newCloudflareBackend resolves a provider-catalog entry into a live Cloudflare
// backend. A missing api-token or zone is a hard error so the manager falls back
// to no-op (logged) rather than issuing unauthenticated requests. A non-nil
// client is reused (the cached reconcile-path client, #2904); nil builds a
// fresh bound client.
func newCloudflareBackend(p *config.DDNSProvider, client *http.Client) (*cloudflareBackend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns cloudflare: nil provider")
	}
	token := p.APIToken.Reveal()
	if token == "" {
		return nil, fmt.Errorf("ddns cloudflare: provider %q has no api-token", p.Name)
	}
	if strings.TrimSpace(p.Zone) == "" {
		return nil, fmt.Errorf("ddns cloudflare: provider %q has no zone", p.Name)
	}
	base := cloudflareAPIBase
	if s := strings.TrimSpace(p.Server); s != "" {
		base = strings.TrimRight(s, "/")
	}
	// Bind the dial to the configured source-address/interface/VRF (#2846). A
	// malformed source-address is a hard error so we degrade to no-op rather than
	// publish from the wrong source. A cached client (#2904) is reused when the
	// reconcile path supplies one; nil builds a fresh bound client.
	client, err := ensureProviderHTTPClient(p, client)
	if err != nil {
		return nil, fmt.Errorf("ddns cloudflare: provider %q: %w", p.Name, err)
	}
	return &cloudflareBackend{
		name:    p.Name,
		apiBase: base,
		token:   token,
		zone:    strings.TrimSuffix(strings.TrimSpace(p.Zone), "."),
		client:  client,
	}, nil
}

// cfEnvelope is the common Cloudflare response envelope.
type cfEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []cfMessage     `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo cfResultInfo    `json:"result_info"`
}

// cfResultInfo carries Cloudflare's list pagination metadata. Absent on
// non-list endpoints (all fields zero), which listRecords treats as "single
// page" via its result-count fallback.
type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

type cfMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// cfErrors formats the envelope errors WITHOUT leaking the token (which is only
// ever in the request header, never echoed by Cloudflare).
func cfErrors(env cfEnvelope) string {
	if len(env.Errors) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		parts = append(parts, fmt.Sprintf("%d:%s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

// do issues an authenticated Cloudflare API request and decodes the envelope.
func (b *cloudflareBackend) do(ctx context.Context, method, path string, body any) (cfEnvelope, error) {
	var rdr *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return cfEnvelope{}, fmt.Errorf("ddns cloudflare: marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, b.apiBase+path, rdr)
	if err != nil {
		// SECURITY: apiBase comes from the `server` leaf UNPARSED, so %w would
		// print whatever credential it carries (#6545).
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: build request: %s", scrubURLError(err))
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, raw, err := doRequest(ctx, b.client, req)
	if err != nil {
		return cfEnvelope{}, err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: %s: %w", b.name, cerr)
	}
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: %s: decode response: %w", b.name, err)
	}
	if !env.Success {
		return env, fmt.Errorf("ddns cloudflare: %s: API error: %s", b.name, cfErrors(env))
	}
	return env, nil
}

// resolveZoneID fetches the zone id for the configured zone name (the setup step).
func (b *cloudflareBackend) resolveZoneID(ctx context.Context) (string, error) {
	q := url.Values{}
	q.Set("name", b.zone)
	env, err := b.do(ctx, http.MethodGet, "/zones?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var zones []cfZone
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("ddns cloudflare: %s: decode zones: %w", b.name, err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, b.zone) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("ddns cloudflare: %s: zone %q not found for this token", b.name, b.zone)
}

// listRecords returns ALL A/AAAA records Cloudflare holds for the FQDN+type.
// Returning the full set (rather than recs[0]) is the basis for both the
// upsert content-match and — critically — the ownership-scoped delete: a name
// can carry several records of one type, and recs[0] is an API-ordering
// artifact, not a statement of which row xpf owns (#2770).
func (b *cloudflareBackend) listRecords(ctx context.Context, zoneID, rtype, fqdn string) ([]cfRecord, error) {
	// Paginate (#4909). The dns_records list is paginated (default 100/page);
	// the pre-fix single GET returned only page 1, so a name+type carrying more
	// rows than one page hid xpf-owned rows past that page — driving a duplicate
	// create (owned row unseen) or a false "already absent" delete. Walk every
	// page until the API's result_info says we have them all, with a hard page
	// cap as a runaway guard.
	const (
		perPage  = 100
		maxPages = 1000 // 100k rows for one name+type — far beyond any real zone
	)
	var all []cfRecord
	name := strings.TrimSuffix(fqdn, ".")
	for page := 1; page <= maxPages; page++ {
		q := url.Values{}
		q.Set("type", rtype)
		q.Set("name", name)
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page))
		env, err := b.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var recs []cfRecord
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, fmt.Errorf("ddns cloudflare: %s: decode records: %w", b.name, err)
		}
		all = append(all, recs...)
		// Stop when the API reports the last page. Fall back to a short-page
		// heuristic when result_info is absent (a mock/older API omits it): a
		// page returning fewer than perPage rows is the last one.
		if ri := env.ResultInfo; ri.TotalPages > 0 {
			if page >= ri.TotalPages {
				return all, nil
			}
		} else if len(recs) < perPage {
			return all, nil
		}
	}
	// #6218 item 5: the pre-fix Warn-and-return-nil-error here silently
	// truncated the result set past the cap — the ownership-scoped
	// upsert/delete callers (below) trust listRecords to return EVERY row for
	// the name+type, so a truncated set could hide the row xpf actually owns
	// and drive a duplicate create or a false "already absent" delete (the
	// exact #4909 hazard this function exists to close). Fail loud instead:
	// both callers already propagate a non-nil error and skip the write this
	// cycle rather than acting on a partial list.
	return nil, fmt.Errorf("ddns cloudflare: %s: record list for %s type %s exceeded "+
		"%d pages (%d rows); refusing to act on a possibly-truncated list",
		b.name, name, rtype, maxPages, len(all))
}

// UpsertLease publishes the A/AAAA with a VALUE-SPECIFIC in-place replace
// (#3739): resolve zone id, list every A/AAAA at the name, and touch ONLY the
// row xpf owns — never a co-resident FOREIGN value at a shared name. recs[0] is
// an API-ordering artifact, not a statement of ownership (mirrors the
// content-scoped DELETE, #2770). The precedence is:
//
//  1. A row already carrying the NEW content → no write (idempotent re-publish;
//     extra ban-avoidance on top of the engine's change-detection).
//  2. Else a row carrying xpf's PREVIOUS published value (rec.PrevAddr) → PATCH
//     that row in place. This is the renumber of xpf's OWN record; the foreign
//     row (if any) is left untouched.
//  3. Else no xpf-owned row exists at this name → POST a NEW record. Any foreign
//     record at the name survives (never PATCH recs[0], which would rewrite a
//     foreign value to xpf's address — the #3739 H11 bug).
//
// Degenerate cases stay correct: a first publish (no prev, empty name) POSTs;
// a first publish onto a name that already carries only a foreign record also
// POSTs (coexist, do not clobber). If xpf's prior value is genuinely unknown
// (PrevAddr lost) on a renumber, a new row is POSTed and the old xpf row leaks —
// acceptable, and strictly better than clobbering a foreign record.
func (b *cloudflareBackend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	zoneID, err := b.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(rec.FQDN, ".")
	content := rec.Addr.Unmap().String()
	ttl := rec.TTL
	if ttl <= 0 {
		ttl = 1 // Cloudflare TTL=1 means "automatic".
	}
	recs, err := b.listRecords(ctx, zoneID, rec.ForwardType, name)
	if err != nil {
		return err
	}
	var prevContent string
	if rec.PrevAddr.IsValid() {
		prevContent = rec.PrevAddr.Unmap().String()
	}
	prevID := ""
	for _, r := range recs {
		if r.Content == content {
			// Already correct — no write.
			return nil
		}
		if prevContent != "" && r.Content == prevContent {
			prevID = r.ID
		}
	}
	payload := map[string]any{
		"type":    rec.ForwardType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
	}
	if prevID != "" {
		// Renumber xpf's OWN row in place — never a foreign row.
		_, err = b.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+prevID, payload)
		return err
	}
	// No xpf-owned row to update — create a new one alongside any foreign record.
	_, err = b.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload)
	return err
}

// DeleteLease removes the firewall's OWN A/AAAA from Cloudflare: resolve zone
// id, list every record for the FQDN+type, and DELETE only the rows whose
// content equals the owned address (rec.Addr.Unmap().String()).
//
// This honours the Surface A sole-delete-authority boundary
// (withdrawOwnedLocked re-derives the delete from the EXACT owned tuple): xpf
// never deletes a name+value it did not record. recs[0] is an API-ordering
// artifact, so a content-blind delete of the first match would clobber a value
// a human/automation later set on the same name (#2770). Multiple owned rows
// with the same content are all removed (not just the first). A record that is
// already gone — or where no row matches the owned content (ownership conflict)
// — is a success no-op: the wire is already in (or never reached) the desired
// state, and deleting a foreign value would itself be the bug.
func (b *cloudflareBackend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	zoneID, err := b.resolveZoneID(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(rec.FQDN, ".")
	owned := rec.Addr.Unmap().String()
	recs, err := b.listRecords(ctx, zoneID, rec.ForwardType, name)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Content != owned {
			continue
		}
		if _, err := b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}
