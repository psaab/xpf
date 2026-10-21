package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

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

	// created tracks the (zoneID, recordID) of rows THIS backend instance
	// POSTed, keyed "zoneID/id" (#16086 A10-16). It is the "self-created"
	// half of the withdraw ownership test for rows that predate the
	// comment tag or whose provider drops the comment: those rows are
	// untagged, so only this in-process memory proves xpf created them.
	// Losing it (restart, or a rebuilt backend — backends are resolved
	// per reconcile) demotes those rows to the legacy value-scoped
	// fallback in DeleteLease, WITH a warning; it can never promote a
	// foreign row.
	mu      sync.Mutex
	created map[string]struct{}
}

func (b *cloudflareBackend) trackCreated(zoneID, id string) {
	if id == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.created == nil {
		b.created = map[string]struct{}{}
	}
	b.created[zoneID+"/"+id] = struct{}{}
}

func (b *cloudflareBackend) selfCreated(zoneID, id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.created[zoneID+"/"+id]
	return ok
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
	Comment string `json:"comment"`
}

// cfOwnedComment is the Cloudflare record-comment tag xpf stamps on every
// record it CREATES (POST) — the only durable ownership proof Cloudflare
// offers: unlike Route 53's RRset, a Cloudflare row is individually
// addressable, and its free-form comment rides with the row (#16086 A10-16).
// A row xpf PATCHes is deliberately NOT re-tagged: xpf can only reach its
// own prior row or a same-content row via value equality, which is exactly
// the ambiguous case — claiming a foreign row by stamping it would repeat
// the withdraw bug on the publish side. DeleteLease therefore deletes a
// same-content row ONLY when it carries this tag or was created by this
// backend instance; an untagged same-content row is a legacy/foreign
// candidate handled by the logged value-scoped fallback (see DeleteLease).
const cfOwnedComment = "xpf-managed"

// cfOwnedByTag reports whether a Cloudflare row carries xpf's ownership tag.
func cfOwnedByTag(r cfRecord) bool { return r.Comment == cfOwnedComment }

// maxCFErrors bounds how many envelope errors are rendered. The array length is
// PROVIDER-CHOSEN, so without this the per-message cap is defeated by repetition
// (#6634): a body carrying ten thousand short errors is still an unbounded log
// line. Four is more than any real Cloudflare failure returns.
const maxCFErrors = 4

// cfErrors formats the envelope errors.
//
// The Cloudflare API token is only ever in the request header and is never
// echoed by Cloudflare, so it is not the exposure here. The MESSAGE is: it is
// chosen by the provider, and it was rendered verbatim with %s into an error the
// daemon logs and retains as the provider's lastErr. An API that answers "your
// request was invalid: <the request>" echoes our own update URL back, so the
// text is scrubbed and bounded on the way out (#6634), and the COUNT is bounded
// too — a per-item cap is not a bound when the provider picks the item count.
//
// The numeric Code is rendered as-is: an int cannot carry text.
func cfErrors(env cfEnvelope) string {
	if len(env.Errors) == 0 {
		return "unknown error"
	}
	shown := env.Errors
	extra := 0
	if len(shown) > maxCFErrors {
		extra = len(shown) - maxCFErrors
		shown = shown[:maxCFErrors]
	}
	parts := make([]string, 0, len(shown)+1)
	for _, e := range shown {
		parts = append(parts, fmt.Sprintf("%d:%s", e.Code, scrubProviderText(e.Message)))
	}
	if extra > 0 {
		parts = append(parts, fmt.Sprintf("[+%d more]", extra))
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
		// SECURITY (#6634): `raw` is a provider-chosen response body, and Go's
		// JSON decoder QUOTES the offending input back — an overflowing numeric
		// field yields "json: cannot unmarshal number 9876543210…" with the
		// complete provider-selected token in it. Withhold the decoder's text
		// the same way the Route 53 XML decode does; the prefix already says
		// which call failed.
		return cfEnvelope{}, fmt.Errorf("ddns cloudflare: %s: decode response: %s",
			b.name, scrubInnerError(err))
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
		// SECURITY (#6634): as in do() — the decoder quotes provider-chosen
		// input back, and env.Result came off the wire.
		return "", fmt.Errorf("ddns cloudflare: %s: decode zones: %s",
			b.name, scrubInnerError(err))
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
			// SECURITY (#6634): as in do() — the decoder quotes provider-chosen
			// input back, and env.Result came off the wire.
			return nil, fmt.Errorf("ddns cloudflare: %s: decode records: %s",
				b.name, scrubInnerError(err))
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
//  1. A PROVEN-owned row (comment-tagged, or created by this instance)
//     already carrying the NEW content with the desired TTL → no write to
//     the live row (idempotent re-publish), but xpf's stale PREVIOUS row
//     (if any) is still DELETEd (#10715). An UNTAGGED same-content row does
//     NOT satisfy this arm (#16086 A10-16): it may be a foreign publisher's
//     identical record, so xpf falls through and POSTs its own tagged row
//     to coexist with it (when no stale previous row needs renumbering).
//  2. A row carrying the NEW content with the WRONG TTL → PATCH that row in
//     place (#9067), then DELETE xpf's stale previous row if one survived
//     alongside (#10715). The PATCH payload carries no comment, so it never
//     claims a row by stamping it.
//  3. Else a row carrying xpf's PREVIOUS published value (rec.PrevAddr) → PATCH
//     that row in place. This is the renumber of xpf's OWN record; the foreign
//     row (if any) is left untouched.
//  4. Else no xpf-owned row exists at this name → POST a NEW record stamped
//     with the cfOwnedComment ownership tag and tracked as self-created. Any
//     foreign record at the name survives (never PATCH recs[0], which would
//     rewrite a foreign value to xpf's address — the #3739 H11 bug).
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
	prevSet := map[string]bool{}
	if rec.PrevAddr.IsValid() {
		prevSet[rec.PrevAddr.Unmap().String()] = true
	}
	for _, p := range rec.PrevAddrs {
		if p.IsValid() {
			prevSet[p.Unmap().String()] = true
		}
	}
	var prevIDs []string
	sameContentID := ""
	sameContentCorrect := false
	// A same-content row xpf can PROVE it owns (comment tag, or created by
	// this backend instance). Only a proven-owned row may satisfy the
	// idempotent no-write arm: an untagged same-content row may be a
	// foreign publisher's identical record (#16086 A10-16), and treating
	// it as ours both skips creating xpf's own tagged row and pairs with
	// an untagged withdraw fallback that would delete it.
	sameOwnedCorrect := false
	sameOwnedWrongTTL := false
	for _, r := range recs {
		if r.Content == content {
			if cfOwnedByTag(r) || b.selfCreated(zoneID, r.ID) {
				if r.TTL == ttl {
					sameOwnedCorrect = true
					continue
				}
				sameContentID = r.ID
				sameOwnedWrongTTL = true
				continue
			}
			if r.TTL == ttl {
				sameContentCorrect = true
				continue
			}
			if sameContentID == "" {
				sameContentID = r.ID
			}
			continue
		}
		if prevSet[r.Content] {
			prevIDs = append(prevIDs, r.ID)
		}
	}
	prevID := ""
	if len(prevIDs) > 0 {
		prevID = prevIDs[0]
	}
	payload := map[string]any{
		"type":    rec.ForwardType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
	}
	// postPayload stamps the ownership tag on CREATE only (see
	// cfOwnedComment). PATCHes reuse payload (no comment key), so a PATCH
	// never claims a row and never strips a genuine tag's ownership info.
	postPayload := map[string]any{
		"type":    rec.ForwardType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
		"comment": cfOwnedComment,
	}
	if sameOwnedCorrect {
		for _, id := range prevIDs {
			if _, err = b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil); err != nil {
				return err
			}
		}
		return nil
	}
	if !sameOwnedWrongTTL && sameContentCorrect && len(prevIDs) > 0 {
		// An untagged row already carries the new content AND xpf's stale
		// previous row survives (#10715 shape, untagged flavour): delete
		// the stale previous row(s), then fall through past the
		// same-content PATCH target (sameContentID cleared below) so the
		// POST arm creates xpf's own tagged row for the new value.
		for _, id := range prevIDs {
			if _, err = b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil); err != nil {
				return err
			}
		}
		prevIDs = nil
		prevID = ""
	}
	if !sameOwnedWrongTTL && sameContentCorrect {
		// The only same-content row is untagged and unproven: it may be a
		// foreign publisher's identical record (#16086). Do NOT adopt it
		// as proof of publish — fall through to POST xpf's own tagged
		// row so the records coexist and a later withdraw can tell them
		// apart.
		sameContentID = ""
	}
	targetID := prevID
	if sameContentID != "" {
		targetID = sameContentID
	}
	if targetID != "" {
		_, err = b.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+targetID, payload)
		if err != nil {
			return err
		}
		for _, id := range prevIDs {
			if id != targetID {
				if _, err = b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil); err != nil {
					return err
				}
			}
		}
		return err
	}
	env, err := b.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", postPayload)
	if err != nil {
		return err
	}
	var created cfRecord
	if len(env.Result) > 0 {
		_ = json.Unmarshal(env.Result, &created)
	}
	b.trackCreated(zoneID, created.ID)
	for _, id := range prevIDs {
		if _, err = b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil); err != nil {
			return err
		}
	}
	return nil
}

// DeleteLease removes the firewall's OWN A/AAAA from Cloudflare: resolve zone
// id, list every record for the FQDN+type, and DELETE only the rows xpf can
// prove it owns whose content equals the owned address
// (rec.Addr.Unmap().String()).
//
// OWNERSHIP (#16086 A10-16): content equality alone is NOT ownership — a
// foreign publisher can hold an identical name+type+value row (redundant
// appliances), and the pre-fix withdraw deleted EVERY same-content row,
// killing the victim's name until its forced refresh. A same-content row is
// deleted only when xpf can prove ownership: it carries the cfOwnedComment
// tag (stamped on CREATE), or this backend instance created it (tracked in
// b.created). Any other same-content row is left alone whenever a proven
// row exists.
//
// LEGACY VALUE-SCOPED FALLBACK, logged: when NO same-content row is provably
// xpf's — the steady state for records published before the tag existed (or
// after a restart dropped b.created before those records were re-tagged) —
// withdraw falls back to the pre-#16086 value-scoped delete (every
// same-content row) and warns. Skipping the delete instead would orphan
// xpf's own legacy record forever once local ownership is dropped. The
// fallback is therefore still value-scoped and can still delete a foreign
// same-content record; it exists only for untagged rows, fires loudly, and
// shrinks to zero as records are re-created with the tag. A row with a
// DIFFERENT value is never touched in either mode (#2770 ownership
// conflict = success no-op), honouring the Surface A sole-delete-authority
// boundary. Already-gone is likewise a success no-op.
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
	var proven, unproven []cfRecord
	for _, r := range recs {
		if r.Content != owned {
			continue
		}
		if cfOwnedByTag(r) || b.selfCreated(zoneID, r.ID) {
			proven = append(proven, r)
		} else {
			unproven = append(unproven, r)
		}
	}
	targets := proven
	if len(targets) == 0 && len(unproven) > 0 {
		slog.Warn("ddns cloudflare: withdrawing by value-scoped fallback; "+
			"no xpf-tagged record found, deleting every untagged same-content row "+
			"(legacy record published before ownership tagging, or a foreign "+
			"same-content record cannot be distinguished)",
			"provider", b.name, "fqdn", name, "type", rec.ForwardType,
			"addr", owned, "rows", len(unproven))
		targets = unproven
	}
	for _, r := range targets {
		if _, err := b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}
