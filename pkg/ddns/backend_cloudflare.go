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

type cloudflareBackend struct {
	name    string
	apiBase string
	token   string // revealed at construction; never logged
	zone    string // zone NAME (e.g. example.net); id resolved at update time
	client  *http.Client
	// ownerID is this backend's stable instance identity ("prov/<hex>",
	// see cfOwnerID); instanceTag is the full comment this instance
	// stamps and owns.
	ownerID     string
	instanceTag string
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
	ownerID := cfOwnerID(p)
	return &cloudflareBackend{
		name:        p.Name,
		apiBase:     base,
		token:       token,
		zone:        strings.TrimSuffix(strings.TrimSpace(p.Zone), "."),
		client:      client,
		ownerID:     ownerID,
		instanceTag: cfInstanceTag(ownerID),
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

// Cloudflare record-comment ownership (#16086 A10-16, folded per the
// PR #16114 hostile reviews).
//
// A record comment is the only durable per-row ownership proof Cloudflare
// offers: unlike a Route 53 RRset member, a Cloudflare row is individually
// addressable and its comment rides with the row. A bare product marker
// ("xpf-managed") is NOT ownership: every xpf instance stamps the same
// literal, so one xpf would adopt and withdraw another independent xpf's
// record. The comment therefore carries a STABLE PER-INSTANCE identity:
//
//	xpf-managed:<instance>     instance-owned (cfInstanceTagPrefix)
//	xpf-managed                legacy bare tag (pre-fold records)
//
// <instance> is "prov/<hex>" — an FNV-1a hash of the provider's stable
// endpoint identity (backendFingerprint: backend type + server/zone —
// credential-free, the same identity Surface A persists for endpoint
// change detection). It is deliberately NOT random per construction
// (backends are rebuilt every reconcile, so a random id would orphan
// every record xpf creates) and NOT per-process state. Two INDEPENDENT
// xpf instances have different providers/zones (different instance ids);
// a coordinated HA pair shares the committed provider config, hence the
// same id — which is correct, because the pair is one logical writer.
// Routers that deliberately share one provider identity ARE one owner by
// construction; that residual is documented, not silently assumed.
//
// Ownership test (cfOwnedByTag, b.ownsRow): a row is xpf-owned ONLY when
// its comment is exactly THIS instance's tag, or this backend instance
// created it in-process (b.created). A row tagged by a DIFFERENT instance,
// a bare legacy "xpf-managed" row, and an untagged row are all FOREIGN for
// ownership purposes: never adopted, never PATCHed, never silently
// deleted. Legacy rows (bare tag or untagged) are withdrawn only through
// the logged value-scoped fallback (see DeleteLease / deleteStalePrev).
const (
	cfLegacyComment       = "xpf-managed"
	cfInstanceTagPrefix   = "xpf-managed:"
	cfInstanceTagProvider = "prov/"
)

// cfOwnerID derives the stable per-instance identity for a provider
// catalog entry: "prov/" + the credential-free endpoint fingerprint.
func cfOwnerID(p *config.DDNSProvider) string {
	if p == nil {
		return cfInstanceTagProvider + "unknown"
	}
	return cfInstanceTagProvider + backendFingerprint(p)
}

// cfInstanceTag is the exact comment an instance stamps on CREATE.
func cfInstanceTag(ownerID string) string { return cfInstanceTagPrefix + ownerID }

// cfTagKind classifies a row's comment for ownership decisions.
type cfTagKind int

const (
	cfTagForeign  cfTagKind = iota // untagged, other-instance, or unrelated comment
	cfTagMine                      // exactly this instance's tag
	cfTagLegacy                    // bare pre-fold "xpf-managed"
	cfTagOtherXPF                  // another instance's "xpf-managed:..." tag
)

func (b *cloudflareBackend) tagKind(r cfRecord) cfTagKind {
	switch {
	case r.Comment == b.instanceTag:
		return cfTagMine
	case r.Comment == cfLegacyComment:
		return cfTagLegacy
	case strings.HasPrefix(r.Comment, cfInstanceTagPrefix):
		return cfTagOtherXPF
	default:
		return cfTagForeign
	}
}

// ownsRow reports whether this instance may treat the row as its own:
// its exact instance tag, or a row this backend instance created
// in-process. Legacy/other-instance/foreign rows are NOT owned.
func (b *cloudflareBackend) ownsRow(zoneID string, r cfRecord) bool {
	return b.tagKind(r) == cfTagMine || b.selfCreated(zoneID, r.ID)
}

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

// UpsertLease publishes the A/AAAA touching ONLY rows this instance owns
// (#3739, #16086 fold). Ownership is per-INSTANCE (see the tag comment
// above): a row is owned only when it carries this instance's tag or this
// backend instance created it. Every other row — untagged, legacy
// bare-tagged, another instance's, foreign — is never PATCHed and never
// silently deleted. Precedence:
//
//  1. An owned row already carrying the NEW content with the desired TTL
//     → no write to the live row (idempotent re-publish), but owned stale
//     PREVIOUS rows are still cleaned (#10715). Unowned rows never
//     satisfy this arm.
//  2. An owned row carrying the NEW content with the WRONG TTL → PATCH
//     that owned row in place (#9067). The PATCH payload carries no
//     comment, so it never claims a row by stamping it.
//  3. Else an owned row carrying xpf's PREVIOUS value → PATCH it in
//     place (renumber of xpf's own row).
//  4. Else → POST a NEW row stamped with this instance's tag and tracked
//     as self-created. Unowned rows at the name survive untouched,
//     including an unowned same-content row at any TTL (fold finding 2:
//     the wrong-TTL PATCH adoption is closed — xpf creates alongside).
//
// Stale previous-value cleanup (#10715) follows the SAME discipline:
// owned stale rows are DELETEd; unowned stale candidates are deleted
// only through deleteStalePrev's logged fallback, and only when no owned
// stale row exists (fold finding 3). A different-instance row is never a
// fallback candidate.
//
// Degenerate cases stay correct: a first publish (no prev, empty name)
// POSTs; a first publish onto a name carrying only foreign rows also
// POSTs (coexist, do not clobber). If xpf's prior value is genuinely
// unknown (PrevAddr lost) on a renumber, a new row is POSTed and the old
// xpf row leaks — acceptable, and strictly better than clobbering a
// foreign record.
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
	var (
		ownedSameCorrect bool // owned row, new content, desired TTL
		patchTarget      string
		staleOwned       []string
		staleUnowned     []cfRecord
	)
	var prevOwnedID string
	for _, r := range recs {
		owned := b.ownsRow(zoneID, r)
		if r.Content == content {
			if !owned {
				continue // never adopt/PATCH an unowned same-content row
			}
			if r.TTL == ttl {
				ownedSameCorrect = true
			} else if patchTarget == "" {
				patchTarget = r.ID
			}
			continue
		}
		if prevSet[r.Content] {
			if owned {
				staleOwned = append(staleOwned, r.ID)
				if prevOwnedID == "" {
					prevOwnedID = r.ID
				}
			} else {
				staleUnowned = append(staleUnowned, r)
			}
		}
	}
	payload := map[string]any{
		"type":    rec.ForwardType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
	}
	// postPayload stamps this instance's tag on CREATE only (see the tag
	// comment). PATCHes reuse payload (no comment key), so a PATCH never
	// claims a row and never strips a genuine tag's ownership info.
	postPayload := map[string]any{
		"type":    rec.ForwardType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
		"comment": b.instanceTag,
	}
	deleteOwned := func(ids []string, except string) error {
		for _, id := range ids {
			if id == except {
				continue
			}
			if _, err := b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil); err != nil {
				return err
			}
		}
		return nil
	}
	if ownedSameCorrect {
		if err := deleteOwned(staleOwned, ""); err != nil {
			return err
		}
		return b.deleteStalePrev(ctx, zoneID, name, rec, staleOwned, staleUnowned)
	}
	targetID := patchTarget
	if targetID == "" {
		targetID = prevOwnedID
	}
	if targetID != "" {
		if _, err := b.do(ctx, http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+targetID, payload); err != nil {
			return err
		}
		if err := deleteOwned(staleOwned, targetID); err != nil {
			return err
		}
		return b.deleteStalePrev(ctx, zoneID, name, rec, staleOwned, staleUnowned)
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
	if err := deleteOwned(staleOwned, ""); err != nil {
		return err
	}
	return b.deleteStalePrev(ctx, zoneID, name, rec, staleOwned, staleUnowned)
}

// deleteStalePrev applies the logged-fallback half of stale previous-value
// cleanup (#16086 fold finding 3). Owned stale rows are deleted by the
// caller; this handles only UNOWNED stale candidates, and only when no
// owned stale row existed: legacy (bare-tagged or untagged) candidates
// are then deleted by value WITH a warning — the same accepted fallback
// as DeleteLease, because skipping them would orphan xpf's legacy row.
// Rows tagged by a DIFFERENT instance are never fallback candidates:
// they survive even when no owned stale row exists.
func (b *cloudflareBackend) deleteStalePrev(ctx context.Context, zoneID, name string, rec LeaseDNSRecord, staleOwned []string, staleUnowned []cfRecord) error {
	if len(staleOwned) > 0 || len(staleUnowned) == 0 {
		return nil
	}
	var legacy []cfRecord
	for _, r := range staleUnowned {
		if b.tagKind(r) == cfTagOtherXPF {
			continue
		}
		legacy = append(legacy, r)
	}
	if len(legacy) == 0 {
		return nil
	}
	slog.Warn("ddns cloudflare: deleting stale previous-value record(s) by "+
		"value-scoped fallback; no xpf-instance-tagged stale row found "+
		"(legacy record published before instance tagging, or a foreign "+
		"same-value record cannot be distinguished)",
		"provider", b.name, "fqdn", name, "type", rec.ForwardType,
		"owner", b.ownerID, "rows", len(legacy))
	for _, r := range legacy {
		if _, err := b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}

// DeleteLease removes this instance's OWN A/AAAA from Cloudflare: resolve
// zone id, list every record for the FQDN+type, and DELETE only the rows
// this instance owns whose content equals the owned address
// (rec.Addr.Unmap().String()).
//
// OWNERSHIP (#16086 A10-16 + fold): content equality alone is NOT
// ownership, and neither is a bare product tag — another xpf instance's
// tagged row is FOREIGN here. A same-content row is deleted only when
// this instance owns it (exact instance tag, or created by this backend
// instance). Every other same-content row survives whenever an owned row
// exists, including a different instance's row.
//
// LEGACY VALUE-SCOPED FALLBACK, logged: when NO same-content row is
// owned by this instance and the candidates are only legacy (bare-tagged
// or untagged) rows — records published before instance tagging —
// withdraw falls back to the pre-#16086 value-scoped delete and warns.
// Skipping would orphan xpf's own legacy record forever once local
// ownership is dropped. The fallback never touches a different
// instance's tagged row, and never a DIFFERENT value (#2770 ownership
// conflict = success no-op), honouring the Surface A sole-delete-
// authority boundary. Already-gone is likewise a success no-op.
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
	var proven, legacy []cfRecord
	for _, r := range recs {
		if r.Content != owned {
			continue
		}
		if b.ownsRow(zoneID, r) {
			proven = append(proven, r)
		} else if b.tagKind(r) != cfTagOtherXPF {
			legacy = append(legacy, r)
		}
	}
	targets := proven
	if len(targets) == 0 && len(legacy) > 0 {
		slog.Warn("ddns cloudflare: withdrawing by value-scoped fallback; "+
			"no record owned by this instance found, deleting every legacy "+
			"same-content row (record published before instance tagging, or "+
			"a foreign same-content record cannot be distinguished)",
			"provider", b.name, "fqdn", name, "type", rec.ForwardType,
			"addr", owned, "owner", b.ownerID, "rows", len(legacy))
		targets = legacy
	}
	for _, r := range targets {
		if _, err := b.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil); err != nil {
			return err
		}
	}
	return nil
}
