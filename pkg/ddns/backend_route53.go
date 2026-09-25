package ddns

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// backend_route53.go: the AWS Route 53 DDNS backend (#2691 P3, plan §5.2). Uses
// SigV4-signed ChangeResourceRecordSets requests. Route 53 UPSERT/DELETE operate
// on a WHOLE RRset at name+type — there is no per-value add/remove — so both the
// publish and the withdraw are OWNERSHIP-SCOPED read-modify-writes (#5389):
// ListResourceRecordSets reads the live members, and the change touches ONLY
// xpf's own value (drop rec.PrevAddr, add rec.Addr on publish; strip rec.Addr on
// withdraw) while PRESERVING any co-resident FOREIGN A/AAAA a human or another
// appliance set at the same shared name. A bare single-value UPSERT (the pre-#5389
// path) would create-or-replace the entire RRset and silently delete those
// foreign members. See the read-modify-write concurrency caveat on UpsertLease.
//
// SigV4 is implemented in sigv4.go (a minimal signer — no AWS SDK dependency;
// plan §5.2 open question resolved toward the minimal signer since we sign ONE
// API shape). Rate-limit discipline (plan §8.3): Route 53 is 5 req/s/account;
// the engine's change-only + forced-refresh cadence keeps us far under that, and
// a 429/throttle classifies errHTTPRateLimited so the engine backs off.
//
// Implements the SAME DNSUpdater interface as rfc2136; the engine drives it
// identically.

// route53Endpoint is the Route 53 API host. Route 53 is a global service signed
// in us-east-1. Overridable per-instance (the endpoint field) for httptest.
const route53Endpoint = "https://route53.amazonaws.com"

// route53APIVersion is the Route 53 REST API version path prefix.
const route53APIVersion = "2013-04-01"

// route53Backend publishes a single record via Route 53 ChangeResourceRecordSets.
type route53Backend struct {
	name     string
	endpoint string
	zoneID   string
	creds    sigv4Credentials
	client   *http.Client
	now      func() time.Time
}

// newRoute53Backend resolves a provider-catalog entry into a live Route 53
// backend. Missing access key / secret / hosted-zone-id are hard errors so the
// manager falls back to no-op (logged) rather than issuing unsigned requests. A
// non-nil client is reused (the cached reconcile-path client, #2904); nil
// builds a fresh bound client.
func newRoute53Backend(p *config.DDNSProvider, client *http.Client) (*route53Backend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns route53: nil provider")
	}
	secret := p.AWSSecretAccessKey.Reveal()
	if p.AWSAccessKeyID == "" || secret == "" {
		return nil, fmt.Errorf("ddns route53: provider %q is missing aws-access-key / aws-secret-key", p.Name)
	}
	if strings.TrimSpace(p.HostedZoneID) == "" {
		return nil, fmt.Errorf("ddns route53: provider %q has no hosted-zone-id", p.Name)
	}
	region := strings.TrimSpace(p.AWSRegion)
	if region == "" {
		region = "us-east-1" // Route 53 is signed in us-east-1.
	}
	endpoint := route53Endpoint
	if s := strings.TrimSpace(p.Server); s != "" {
		endpoint = strings.TrimRight(s, "/")
	}
	// Bind the dial to the configured source-address/interface/VRF (#2846). A
	// cached client (#2904) is reused when supplied; nil builds a fresh one.
	client, err := ensureProviderHTTPClient(p, client)
	if err != nil {
		return nil, fmt.Errorf("ddns route53: provider %q: %w", p.Name, err)
	}
	return &route53Backend{
		name:     p.Name,
		endpoint: endpoint,
		zoneID:   normalizeHostedZoneID(p.HostedZoneID),
		creds: sigv4Credentials{
			accessKeyID:     p.AWSAccessKeyID,
			secretAccessKey: secret,
			region:          region,
			service:         "route53",
		},
		client: client,
		now:    time.Now,
	}, nil
}

// normalizeHostedZoneID strips the "/hostedzone/" prefix Route 53 sometimes
// reports so the operator can paste either form.
func normalizeHostedZoneID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "/hostedzone/")
	return id
}

// changeBatchXML is the ChangeResourceRecordSets request body.
type changeBatchXML struct {
	XMLName     xml.Name `xml:"https://route53.amazonaws.com/doc/2013-04-01/ ChangeResourceRecordSetsRequest"`
	ChangeBatch struct {
		Changes struct {
			Change []r53Change `xml:"Change"`
		} `xml:"Changes"`
	} `xml:"ChangeBatch"`
}

type r53Change struct {
	Action            string `xml:"Action"`
	ResourceRecordSet struct {
		Name            string `xml:"Name"`
		Type            string `xml:"Type"`
		TTL             int    `xml:"TTL"`
		ResourceRecords struct {
			ResourceRecord []struct {
				Value string `xml:"Value"`
			} `xml:"ResourceRecord"`
		} `xml:"ResourceRecords"`
	} `xml:"ResourceRecordSet"`
}

// r53ErrorXML is the Route 53 error response envelope.
type r53ErrorXML struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// listRRSetsXML is the ListResourceRecordSets response envelope. Only the
// fields the read-modify-write publish needs are decoded (name/type/ttl/values).
// The element namespace is deliberately NOT pinned in the tags so a plain
// local-name match decodes the Route 53 reply regardless of the xmlns prefix it
// carries.
type listRRSetsXML struct {
	ResourceRecordSets struct {
		ResourceRecordSet []struct {
			Name            string `xml:"Name"`
			Type            string `xml:"Type"`
			TTL             int    `xml:"TTL"`
			ResourceRecords struct {
				ResourceRecord []struct {
					Value string `xml:"Value"`
				} `xml:"ResourceRecord"`
			} `xml:"ResourceRecords"`
		} `xml:"ResourceRecordSet"`
	} `xml:"ResourceRecordSets"`
}

// r53LiveRRSet is the current state of the RRset at a (name, type), read back
// from Route 53 with ListResourceRecordSets. found is false when Route 53 holds
// no RRset at that name+type. values is the FULL member list — xpf's own value
// PLUS any FOREIGN co-resident values a human / another appliance set at the
// same shared name (a manually-managed round-robin member, another host's A).
type r53LiveRRSet struct {
	found  bool
	ttl    int
	values []string
}

// listRRSet reads the current RRset at name+type. ListResourceRecordSets returns
// record sets ordered from the (name, type) start point, so the exact match — if
// it exists — is the first set returned; maxitems=1 fetches just that one. We
// STILL filter on an exact name+type match so a non-existent RRset (for which
// Route 53 returns the lexically-next set) reads back as found=false rather than
// the backend adopting a neighbour's values.
func (b *route53Backend) listRRSet(ctx context.Context, name, rtype string) (r53LiveRRSet, error) {
	q := url.Values{}
	q.Set("name", strings.TrimSuffix(name, ".")+".")
	q.Set("type", rtype)
	q.Set("maxitems", "1")
	path := "/" + route53APIVersion + "/hostedzone/" + b.zoneID + "/rrset"
	req, err := http.NewRequest(http.MethodGet, b.endpoint+path+"?"+q.Encode(), nil)
	if err != nil {
		// SECURITY: endpoint comes from the `server` leaf UNPARSED, so %w would
		// print whatever credential it carries (#6545).
		return r53LiveRRSet{}, fmt.Errorf("ddns route53: build list request: %s", scrubURLError(err))
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")
	signRequest(req, b.creds, nil, b.now())

	code, raw, err := doRequest(ctx, b.client, req)
	if err != nil {
		return r53LiveRRSet{}, err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		var e r53ErrorXML
		if xml.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
			// SECURITY (#6634): Code and Message are decoded from a
			// PROVIDER-CHOSEN response body and were rendered verbatim with %s
			// into an error the daemon logs and retains as lastErr. Scrub and
			// bound both; an API that echoes the request back would otherwise
			// put our own credentialed update URL in the journal.
			return r53LiveRRSet{}, fmt.Errorf("ddns route53: %s: %s: %s: %w", b.name,
				scrubProviderText(e.Error.Code), scrubProviderText(e.Error.Message), cerr)
		}
		return r53LiveRRSet{}, fmt.Errorf("ddns route53: %s: %w", b.name, cerr)
	}
	var resp listRRSetsXML
	if err := xml.Unmarshal(raw, &resp); err != nil {
		// SECURITY: Go's XML decoder quotes provider-controlled declaration
		// values back in its error text, e.g.
		//   xml: unsupported version "<whatever the body said>"; only version
		//   1.0 is supported
		// and `raw` is a 2xx response body, so that string is entirely
		// attacker-chosen. A provider echoing our own update URL there puts the
		// credential into this error, which the daemon logs. Withhold it: the
		// prefix already says what failed, and the decoder's detail is not worth
		// a disclosure channel.
		return r53LiveRRSet{}, fmt.Errorf("ddns route53: %s: decode rrset list: %s",
			b.name, scrubInnerError(err))
	}
	want := strings.TrimSuffix(name, ".")
	for _, s := range resp.ResourceRecordSets.ResourceRecordSet {
		if !strings.EqualFold(strings.TrimSuffix(s.Name, "."), want) || !strings.EqualFold(s.Type, rtype) {
			continue
		}
		live := r53LiveRRSet{found: true, ttl: s.TTL}
		for _, rr := range s.ResourceRecords.ResourceRecord {
			if v := strings.TrimSpace(rr.Value); v != "" {
				live.values = append(live.values, v)
			}
		}
		return live, nil
	}
	return r53LiveRRSet{found: false}, nil
}

// buildChangeBatch builds a single-change ChangeResourceRecordSets body for the
// given action against an EXPLICIT value list. Route 53 UPSERT create-or-replaces
// the WHOLE RRset with exactly these values, so the caller passes the MERGED set
// (foreign members preserved) — never a bare single value, which would clobber a
// co-resident foreign A/AAAA (#5389). A DELETE must match the live RRset exactly
// (name, type, ttl, values).
func buildChangeBatch(action, name, rtype string, ttl int, values []string) ([]byte, error) {
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	var batch changeBatchXML
	var c r53Change
	c.Action = action
	c.ResourceRecordSet.Name = strings.TrimSuffix(name, ".") + "."
	c.ResourceRecordSet.Type = rtype
	c.ResourceRecordSet.TTL = ttl
	for _, v := range values {
		rr := struct {
			Value string `xml:"Value"`
		}{Value: v}
		c.ResourceRecordSet.ResourceRecords.ResourceRecord = append(
			c.ResourceRecordSet.ResourceRecords.ResourceRecord, rr)
	}
	batch.ChangeBatch.Changes.Change = []r53Change{c}
	out, err := xml.Marshal(&batch)
	if err != nil {
		return nil, fmt.Errorf("ddns route53: marshal change batch: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

// change issues a signed ChangeResourceRecordSets with the given action and the
// EXPLICIT value list. When the request fails, the parsed Route 53 error
// code/message (never the creds) is returned alongside the typed transport error
// so DELETE-path idempotency classification (r53DeleteAlreadyGone) can inspect
// the on-wire code/message.
func (b *route53Backend) change(ctx context.Context, action, name, rtype string, ttl int, values []string) (errCode, errMsg string, err error) {
	body, err := buildChangeBatch(action, name, rtype, ttl, values)
	if err != nil {
		return "", "", err
	}
	path := "/" + route53APIVersion + "/hostedzone/" + b.zoneID + "/rrset/"
	req, err := http.NewRequest(http.MethodPost, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		// SECURITY: endpoint comes from the `server` leaf UNPARSED, so %w would
		// print whatever credential it carries (#6545).
		return "", "", fmt.Errorf("ddns route53: build request: %s", scrubURLError(err))
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "xpf-ddns/1.0")
	signRequest(req, b.creds, body, b.now())

	code, raw, err := doRequest(ctx, b.client, req)
	if err != nil {
		return "", "", err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		// Surface the Route 53 error code/message when present (never the creds).
		var e r53ErrorXML
		if xml.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
			// SECURITY (#6634): the RENDER is scrubbed and bounded, the RETURNED
			// values are not. r53DeleteAlreadyGone classifies delete-idempotency
			// on the raw code/message ("but it was not found"), so scrubbing the
			// values would change a control decision, not just a log line — a
			// withheld token could turn an idempotent delete into a permanent
			// retry. Only what reaches the error text goes through the scrubber.
			return e.Error.Code, e.Error.Message, fmt.Errorf("ddns route53: %s: %s: %s: %w",
				b.name, scrubProviderText(e.Error.Code), scrubProviderText(e.Error.Message), cerr)
		}
		return "", "", fmt.Errorf("ddns route53: %s: %w", b.name, cerr)
	}
	return "", "", nil
}

// mergeUpsertValues computes the desired RRset member list for a publish: keep
// every CURRENT member EXCEPT xpf's own previously-published value (prevVal,
// LeaseDNSRecord.PrevAddr), then ensure xpf's new value (newVal) is present.
// Foreign co-resident members survive; xpf's own row is renumbered in place
// (drop prev, add new) instead of the whole set being replaced. Duplicates are
// collapsed (Route 53 rejects a duplicate value in one RRset). When prevVal is
// empty (first publish / prior value lost) the merge is ADDITIVE — it coexists
// with any foreign member; a genuinely-unknown prior xpf value leaks a stale row
// rather than clobbering a foreign one (mirrors the Cloudflare / RFC 2136 fix).

// canonicalRRValueKey9147 is the COMPARISON KEY for an RRset value: an IP is
// normalized through netip so two spellings of one address compare equal, and
// anything unparseable is kept verbatim.
//
// #9147: mergeUpsertValues, removeValue and sameValueSet compared raw strings,
// so an AAAA written expanded (`2001:0db8:0000:...:0001`) and the same address
// written compressed (`2001:db8::1`) were two different values. AWS's own
// "Supported DNS record types" page gives the AAAA example in the expanded form
// -- so an operator pre-seeding the FQDN by following that documentation
// produces a string that can never byte-equal what xpf writes, and
// mergeUpsertValues then puts BOTH into one ChangeBatch. Its own comment says
// "Route 53 rejects a duplicate value in one RRset", so that publish 400s on
// every tick and the record never converges.
//
// WHY THIS LANDS WITHOUT SETTLING THE EXTERNAL QUESTION. The issue is filed
// UNRESOLVED because whether Route 53 echoes AAAA values verbatim or
// normalized cannot be observed from inside the repo, and it gated the fix on
// that answer. The fix does not actually depend on it, for two reasons:
//
//   - Comparing IP VALUES byte-exactly is wrong on its face. Two spellings of
//     one address are one address, whatever any particular server echoes.
//   - THE REPO ALREADY HOLDS THIS POSITION. wireRRClaim (pkg/ddns/state.go)
//     normalizes rdata through netip "so the two ownership surfaces ... compare
//     EQUAL for the same address even if their textual forms differ (e.g. an
//     IPv6 address written expanded vs compressed)". That is this exact
//     argument, already made and already shipped, on a path that reaches the
//     same data. This one did not use it.
//
// If Route 53 does normalize on storage, this is INERT rather than wrong: every
// value read back is already canonical and the key equals the string. So the
// unmeasurable premise decides whether the defect is reachable today, not
// whether the comparison is correct.
//
// KEY-ONLY, deliberately. The normalized form is never emitted for a value xpf
// does not own: rewriting a foreign member's spelling on write-back would edit
// someone else's record to suit our comparison, which is the same
// sole-delete-authority boundary DeleteLease's doc comment draws. Output keeps
// the ORIGINAL string.
func canonicalRRValueKey9147(v string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
		return a.Unmap().String()
	}
	return v
}

func mergeUpsertValues(current []string, prevVal, newVal string) []string {
	out := make([]string, 0, len(current)+1)
	seen := make(map[string]struct{}, len(current)+1)
	add := func(v string) {
		if v == "" {
			return
		}
		// #9147: dedup on the canonical KEY, emit the ORIGINAL string.
		k := canonicalRRValueKey9147(v)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	prevKey := canonicalRRValueKey9147(prevVal)
	for _, v := range current {
		if prevVal != "" && canonicalRRValueKey9147(v) == prevKey {
			continue // drop xpf's OWN prior value (renumber in place)
		}
		add(v)
	}
	add(newVal)
	return out
}

// removeValue returns current without the owned value (all occurrences), and
// reports whether anything was removed.
func removeValue(current []string, owned string) (out []string, removed bool) {
	out = make([]string, 0, len(current))
	ownedKey := canonicalRRValueKey9147(owned)
	for _, v := range current {
		// #9147: match on the canonical key, so an owned value that AWS echoed
		// in a different spelling is still recognised as ours.
		if canonicalRRValueKey9147(v) == ownedKey {
			removed = true
			continue
		}
		out = append(out, v)
	}
	return out, removed
}

// sameValueSet reports whether a and b hold the same values (order-independent,
// de-duplicated) — the idempotency gate that skips a no-op UPSERT.
func sameValueSet(a, b []string) bool {
	// #9147: compare on canonical keys, or a no-op upsert whose only difference
	// is an address spelling is published every tick.
	sa := make(map[string]struct{}, len(a))
	for _, v := range a {
		sa[canonicalRRValueKey9147(v)] = struct{}{}
	}
	sb := make(map[string]struct{}, len(b))
	for _, v := range b {
		sb[canonicalRRValueKey9147(v)] = struct{}{}
	}
	if len(sa) != len(sb) {
		return false
	}
	for v := range sa {
		if _, ok := sb[v]; !ok {
			return false
		}
	}
	return true
}

// UpsertLease publishes xpf's A/AAAA with an OWNERSHIP-SCOPED read-modify-write
// (#5389). Route 53 UPSERT create-or-replaces the ENTIRE RRset at name+type, so
// a bare single-value UPSERT would delete any co-resident FOREIGN value (a
// manually-managed round-robin member, or another host's record at a shared
// FQDN). Instead: ListResourceRecordSets reads the live members, mergeUpsertValues
// drops ONLY xpf's own prior value (rec.PrevAddr) and adds xpf's new value while
// preserving every foreign member, and the MERGED set is UPSERTed. A live RRset
// already equal to the desired set is a no-op (idempotent re-publish / ban
// avoidance). When no RRset exists the merge is a plain create of xpf's value.
//
// Concurrency caveat: Route 53 has no compare-and-swap for
// ChangeResourceRecordSets, so this read-modify-write is not atomic — a foreign
// member added between the List and the UPSERT is not observed and would be
// lost. The Surface A per-RG HA gate makes xpf itself a single writer for the
// name; the residual race is a human/automation writing the SAME RRset within
// the ~one-request window, which is the same window the Cloudflare / RFC 2136
// value-specific fixes accept (#3739).
func (b *route53Backend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	name := strings.TrimSuffix(rec.FQDN, ".")
	newVal := rec.Addr.Unmap().String()
	live, err := b.listRRSet(ctx, name, rec.ForwardType)
	if err != nil {
		return err
	}
	var prevVal string
	if rec.PrevAddr.IsValid() {
		prevVal = rec.PrevAddr.Unmap().String()
	}
	desired := mergeUpsertValues(live.values, prevVal, newVal)
	ttl := rec.TTL
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	if live.found && live.ttl == ttl && sameValueSet(live.values, desired) {
		return nil // already in the desired state — no write.
	}
	_, _, err = b.change(ctx, "UPSERT", name, rec.ForwardType, ttl, desired)
	return err
}

// DeleteLease withdraws xpf's OWN A/AAAA while preserving co-resident foreign
// members (#5389, the withdraw arm of the value-specific fix). It reads the live
// RRset and removes ONLY xpf's owned value (rec.Addr):
//
//   - RRset absent → idempotent success (#2771): nothing to withdraw.
//   - xpf's value not present (a human/automation replaced it, or it was already
//     withdrawn) → idempotent no-op; deleting a FOREIGN value would itself be the
//     bug (the Surface A sole-delete-authority boundary).
//   - foreign members remain after removing xpf's value → UPSERT the reduced set
//     (drops ONLY xpf's value, keeps every foreign member), carrying the LIVE TTL.
//   - only xpf's value existed → DELETE the whole RRset. Route 53 requires the
//     DELETE to match the live RRset exactly (name, type, TTL, value), so the
//     LIVE TTL is carried, not the configured one.
//
// IDEMPOTENT delete (#2771) still applies to the whole-RRset DELETE: if the
// record raced to gone between the List and the DELETE, Route 53 rejects it with
// HTTP 400 InvalidChangeBatch "... but it was not found"; that is treated as
// success (nil) so Surface A's withdrawOwnedLocked drops ownership instead of
// wedging on a withdraw that can never converge. A genuine transient/auth/throttle
// failure (SignatureDoesNotMatch, 5xx, 429, …) still returns non-nil so the
// engine retries — only the already-gone case is swallowed.
func (b *route53Backend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	name := strings.TrimSuffix(rec.FQDN, ".")
	owned := rec.Addr.Unmap().String()
	live, err := b.listRRSet(ctx, name, rec.ForwardType)
	if err != nil {
		return err
	}
	if !live.found {
		return nil // already gone — idempotent (#2771).
	}
	remaining, removed := removeValue(live.values, owned)
	if !removed {
		return nil // xpf's value not present — ownership conflict / already gone.
	}
	if len(remaining) > 0 {
		// Foreign members remain — reduce the set, keep the foreign values.
		_, _, err = b.change(ctx, "UPSERT", name, rec.ForwardType, live.ttl, remaining)
		return err
	}
	// Only xpf's value existed — DELETE the whole RRset (exact live-TTL match).
	errCode, errMsg, err := b.change(ctx, "DELETE", name, rec.ForwardType, live.ttl, []string{owned})
	if err != nil && r53DeleteAlreadyGone(errCode, errMsg) {
		return nil
	}
	return err
}

// r53DeleteAlreadyGone reports whether a Route 53 DELETE failure means the
// target record set was already absent (an idempotent no-op), as opposed to a
// real failure that must be retried.
//
// Route 53 reports a delete of a non-existent record as a single envelope:
// HTTP 400, Code=InvalidChangeBatch, with a per-change message of the form
//
//	[Tried to delete resource record set [name='wan.example.net.', type='A']
//	 but it was not found]
//
// The Code alone (InvalidChangeBatch) is NOT sufficient — it also covers
// genuine batch errors (e.g. an UPSERT whose value collides, a missing hosted
// zone). We additionally require the exact delete-record shape — BOTH the
// "tried to delete resource record set" action marker AND the "but it was
// not found" outcome marker — so any other InvalidChangeBatch carrying a bare
// "not found" / "was not found" (foreign zone/record, malformed batch) keeps
// retrying / surfaces as a conflict instead of dropping ownership (#10727).
func r53DeleteAlreadyGone(code, msg string) bool {
	if !strings.EqualFold(strings.TrimSpace(code), "InvalidChangeBatch") {
		return false
	}
	m := strings.ToLower(msg)
	return strings.Contains(m, "tried to delete resource record set") &&
		strings.Contains(m, "but it was not found")
}
