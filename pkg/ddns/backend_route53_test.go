package ddns

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// backend_route53_test.go: mock-server tests driving the REAL Route 53 backend
// against a STATEFUL httptest fake that models Route 53's RRset semantics —
// ListResourceRecordSets (GET) reads the live member list, and
// ChangeResourceRecordSets (POST) UPSERT/DELETE create-or-replace / exact-match
// the WHOLE RRset. This lets the tests assert the #5389 ownership-scoped
// read-modify-write: a co-resident FOREIGN A/AAAA at a shared name must SURVIVE a
// publish AND a withdraw of xpf's own value. The SigV4 signature is validated
// structurally (Authorization present + well-formed; sigv4_test.go pins the
// cryptographic correctness).

// r53RRSetState is one RRset (shared TTL + member value list) in the fake zone.
type r53RRSetState struct {
	ttl    int
	values []string
}

// r53FakeAPI is a stateful in-memory Route 53 zone. Sets are keyed "name|type"
// with the name normalized WITHOUT a trailing dot.
type r53FakeAPI struct {
	t          *testing.T
	sets       map[string]*r53RRSetState
	lists      int
	upserts    int
	deletes    int
	lastAuth   string
	lastAmz    string
	changePath string
	lastBatch  changeBatchXML
}

func newR53FakeAPI(t *testing.T) *r53FakeAPI {
	return &r53FakeAPI{t: t, sets: map[string]*r53RRSetState{}}
}

func setKey(name, rtype string) string {
	return strings.TrimSuffix(name, ".") + "|" + rtype
}

// seedSet pre-populates an RRset (as if a human / another appliance created it).
func (f *r53FakeAPI) seedSet(name, rtype string, ttl int, values ...string) {
	f.sets[setKey(name, rtype)] = &r53RRSetState{ttl: ttl, values: append([]string(nil), values...)}
}

func (f *r53FakeAPI) values(name, rtype string) []string {
	if st, ok := f.sets[setKey(name, rtype)]; ok {
		return st.values
	}
	return nil
}

func (f *r53FakeAPI) has(name, rtype, value string) bool {
	for _, v := range f.values(name, rtype) {
		if v == value {
			return true
		}
	}
	return false
}

func (f *r53FakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodGet:
			f.lists++
			f.writeList(w, strings.TrimSuffix(r.URL.Query().Get("name"), "."), r.URL.Query().Get("type"))
		case http.MethodPost:
			f.changePath = r.URL.Path
			f.lastAmz = r.Header.Get("X-Amz-Date")
			f.applyChange(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// writeList returns a ListResourceRecordSetsResponse holding the exact RRset (or
// an empty set list when absent — the backend filters on exact name+type anyway).
func (f *r53FakeAPI) writeList(w http.ResponseWriter, name, rtype string) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets>`)
	if st, ok := f.sets[setKey(name, rtype)]; ok {
		sb.WriteString(`<ResourceRecordSet><Name>` + name + `.</Name><Type>` + rtype + `</Type><TTL>` + itoa(st.ttl) + `</TTL><ResourceRecords>`)
		for _, v := range st.values {
			sb.WriteString(`<ResourceRecord><Value>` + v + `</Value></ResourceRecord>`)
		}
		sb.WriteString(`</ResourceRecords></ResourceRecordSet>`)
	}
	sb.WriteString(`</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(sb.String()))
}

func (f *r53FakeAPI) applyChange(w http.ResponseWriter, r *http.Request) {
	var batch changeBatchXML
	body, _ := io.ReadAll(r.Body)
	if err := xml.Unmarshal(body, &batch); err != nil {
		f.t.Errorf("fake: unmarshal change batch: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.lastBatch = batch
	if len(batch.ChangeBatch.Changes.Change) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c := batch.ChangeBatch.Changes.Change[0]
	name := strings.TrimSuffix(c.ResourceRecordSet.Name, ".")
	rtype := c.ResourceRecordSet.Type
	key := setKey(name, rtype)
	var vals []string
	for _, rr := range c.ResourceRecordSet.ResourceRecords.ResourceRecord {
		vals = append(vals, rr.Value)
	}
	switch c.Action {
	case "UPSERT":
		f.upserts++
		f.sets[key] = &r53RRSetState{ttl: c.ResourceRecordSet.TTL, values: vals}
		f.writeChangeOK(w)
	case "DELETE":
		f.deletes++
		// Route 53 requires a DELETE to match the live RRset exactly.
		st, ok := f.sets[key]
		if !ok || st.ttl != c.ResourceRecordSet.TTL || !sameValueSet(st.values, vals) {
			f.writeNotFound(w, name, rtype)
			return
		}
		delete(f.sets, key)
		f.writeChangeOK(w)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *r53FakeAPI) writeChangeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(`<?xml version="1.0"?><ChangeResourceRecordSetsResponse>` +
		`<ChangeInfo><Id>/change/C1</Id><Status>PENDING</Status></ChangeInfo>` +
		`</ChangeResourceRecordSetsResponse>`))
}

func (f *r53FakeAPI) writeNotFound(w http.ResponseWriter, name, rtype string) {
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidChangeBatch</Code>` +
		`<Message>[Tried to delete resource record set [name='` + name + `.', type='` + rtype +
		`'] but it was not found]</Message></Error></ErrorResponse>`))
}

func newR53TestBackend(t *testing.T, srv *httptest.Server) *route53Backend {
	t.Helper()
	b, err := newRoute53Backend(&config.DDNSProvider{
		Name: "r53", Backend: "route53",
		AWSAccessKeyID: "AKIDEXAMPLE", AWSSecretAccessKey: config.Secret("secret-key"),
		AWSRegion: "us-east-1", HostedZoneID: "Z123ABC", Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newRoute53Backend: %v", err)
	}
	// Pin the clock so the signature is deterministic in-test.
	b.now = func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) }
	return b
}

func newR53FakeBackend(t *testing.T) (*route53Backend, *r53FakeAPI) {
	fake := newR53FakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return newR53TestBackend(t, srv), fake
}

func TestRoute53UpsertChangeBatch(t *testing.T) {
	b, fake := newR53FakeBackend(t)

	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	// A read (list) then exactly one create (upsert).
	if fake.lists != 1 || fake.upserts != 1 {
		t.Fatalf("expected 1 list + 1 upsert, got lists=%d upserts=%d", fake.lists, fake.upserts)
	}
	if !strings.HasPrefix(fake.changePath, "/2013-04-01/hostedzone/Z123ABC/rrset") {
		t.Fatalf("wrong API path: %q", fake.changePath)
	}
	if !strings.HasPrefix(fake.lastAuth, "AWS4-HMAC-SHA256 ") || !strings.Contains(fake.lastAuth, "Signature=") {
		t.Fatalf("missing/invalid SigV4 Authorization: %q", fake.lastAuth)
	}
	if fake.lastAmz == "" {
		t.Fatal("missing X-Amz-Date on the change request")
	}
	c := fake.lastBatch.ChangeBatch.Changes.Change[0]
	if c.Action != "UPSERT" {
		t.Fatalf("expected UPSERT, got %q", c.Action)
	}
	if c.ResourceRecordSet.Name != "wan.example.net." || c.ResourceRecordSet.Type != "A" {
		t.Fatalf("wrong rrset: name=%q type=%q", c.ResourceRecordSet.Name, c.ResourceRecordSet.Type)
	}
	rr := c.ResourceRecordSet.ResourceRecords.ResourceRecord
	if len(rr) != 1 || rr[0].Value != "203.0.113.5" {
		t.Fatalf("wrong rdata: %+v", rr)
	}
	if !fake.has("wan.example.net", "A", "203.0.113.5") {
		t.Fatalf("record not published: %v", fake.values("wan.example.net", "A"))
	}
}

// TestRoute53UpsertIdempotentNoWrite: re-publishing the SAME value onto an RRset
// that already carries exactly it must issue NO change (list-only). This is the
// ban-avoidance no-op on top of the engine's change-detection.
func TestRoute53UpsertIdempotentNoWrite(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	fake.seedSet("wan.example.net", "A", 300, "203.0.113.5")

	rec := hostRecord(t, "wan.example.net", "203.0.113.5")
	rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if fake.upserts != 0 {
		t.Fatalf("unchanged RRset must not be rewritten: upserts=%d", fake.upserts)
	}
}

// TestRoute53UpsertPreservesForeignRecord is the #5389 fail-on-revert for a FIRST
// publish onto a name that already carries a FOREIGN A (no xpf row, no PrevAddr).
// The read-modify-write must UPSERT the MERGED set (foreign + xpf) so the foreign
// value survives. Reverting UpsertLease to the pre-#5389 bare single-value UPSERT
// replaces the whole RRset with only xpf's value → the foreign A is clobbered →
// this goes RED.
func TestRoute53UpsertPreservesForeignRecord(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	const fqdn = "wan.example.net"
	fake.seedSet(fqdn, "A", 300, "198.51.100.20") // foreign, human-managed

	if err := b.UpsertLease(context.Background(), hostRecord(t, fqdn, "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if fake.upserts != 1 {
		t.Fatalf("expected exactly one UPSERT, got %d", fake.upserts)
	}
	// The change batch must carry BOTH values (merged set), not a bare single one.
	rr := fake.lastBatch.ChangeBatch.Changes.Change[0].ResourceRecordSet.ResourceRecords.ResourceRecord
	if len(rr) != 2 {
		t.Fatalf("UPSERT must carry the merged RRset (foreign + xpf), got %d values: %+v", len(rr), rr)
	}
	if !fake.has(fqdn, "A", "198.51.100.20") {
		t.Fatalf("FOREIGN A was clobbered on publish: %v", fake.values(fqdn, "A"))
	}
	if !fake.has(fqdn, "A", "203.0.113.5") {
		t.Fatalf("xpf's A was not published: %v", fake.values(fqdn, "A"))
	}
}

// TestRoute53RenumberPreservesForeign is the #5389 fail-on-revert for a RENUMBER
// on a SHARED name: the RRset carries a FOREIGN A plus xpf's own prior value. A
// publish of xpf's NEW address (PrevAddr = xpf's prior value) must drop ONLY
// xpf's prior value, add the new one, and keep the foreign member. Reverting to
// the bare single-value UPSERT destroys the foreign member → RED.
func TestRoute53RenumberPreservesForeign(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	const fqdn = "wan.example.net"
	fake.seedSet(fqdn, "A", 300, "198.51.100.20", "203.0.113.5") // foreign + xpf's prior

	rec := hostRecord(t, fqdn, "203.0.113.9")
	rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("UpsertLease renumber: %v", err)
	}
	if !fake.has(fqdn, "A", "198.51.100.20") {
		t.Fatalf("FOREIGN A was clobbered on renumber: %v", fake.values(fqdn, "A"))
	}
	if !fake.has(fqdn, "A", "203.0.113.9") {
		t.Fatalf("xpf's new A was not published: %v", fake.values(fqdn, "A"))
	}
	if fake.has(fqdn, "A", "203.0.113.5") {
		t.Fatalf("xpf's prior value was not renumbered away: %v", fake.values(fqdn, "A"))
	}
}

func TestRoute53DeleteAction(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	// xpf owns the whole RRset (single value).
	fake.seedSet("wan.example.net", "A", 300, "203.0.113.5")

	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	if fake.deletes != 1 {
		t.Fatalf("expected one DELETE, got %d", fake.deletes)
	}
	if c := fake.lastBatch.ChangeBatch.Changes.Change[0]; c.Action != "DELETE" {
		t.Fatalf("expected DELETE action, got %q", c.Action)
	}
	if _, ok := fake.sets[setKey("wan.example.net", "A")]; ok {
		t.Fatalf("RRset not removed: %v", fake.values("wan.example.net", "A"))
	}
}

// TestRoute53DeletePreservesForeign is the #5389 withdraw arm: withdrawing xpf's
// value from an RRset that ALSO holds a foreign value must UPSERT the reduced set
// (foreign kept, xpf dropped) — never DELETE the whole RRset, and never leave
// xpf's value behind. The pre-#5389 bare single-value DELETE fails "not found"
// against the multi-value RRset and is swallowed idempotent → xpf's value LEAKS
// (survives) → asserting xpf is GONE goes RED on revert.
func TestRoute53DeletePreservesForeign(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	const fqdn = "wan.example.net"
	fake.seedSet(fqdn, "A", 300, "198.51.100.20", "203.0.113.5") // foreign + xpf

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, "203.0.113.5")); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	if fake.deletes != 0 {
		t.Fatalf("must not DELETE a shared RRset, got deletes=%d", fake.deletes)
	}
	if fake.upserts != 1 {
		t.Fatalf("must UPSERT the reduced set, got upserts=%d", fake.upserts)
	}
	if !fake.has(fqdn, "A", "198.51.100.20") {
		t.Fatalf("FOREIGN A was clobbered on withdraw: %v", fake.values(fqdn, "A"))
	}
	if fake.has(fqdn, "A", "203.0.113.5") {
		t.Fatalf("xpf's own value leaked on withdraw: %v", fake.values(fqdn, "A"))
	}
}

// TestRoute53DeleteOwnershipConflictNoop: when the live RRset does NOT contain
// xpf's value (a human replaced it after xpf published), the withdraw is a no-op —
// xpf never deletes a value it did not record. No DELETE, no UPSERT.
func TestRoute53DeleteOwnershipConflictNoop(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	const fqdn = "wan.example.net"
	fake.seedSet(fqdn, "A", 300, "198.51.100.20") // only a foreign value

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, "203.0.113.5")); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	if fake.deletes != 0 || fake.upserts != 0 {
		t.Fatalf("ownership-conflict withdraw must be a no-op: deletes=%d upserts=%d", fake.deletes, fake.upserts)
	}
	if !fake.has(fqdn, "A", "198.51.100.20") {
		t.Fatalf("foreign value must survive an ownership-conflict withdraw: %v", fake.values(fqdn, "A"))
	}
}

func TestRoute53ErrorSurfacesCode(t *testing.T) {
	// The LIST (read) is the first request; a 403 there surfaces the Route 53
	// error code just as a change would.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>nope</Message></Error></ErrorResponse>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)
	err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
	if err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("expected the Route 53 error code surfaced, got %v", err)
	}
}

// TestRoute53DeleteAbsentIdempotent: withdrawing when the RRset is ALREADY GONE
// (the list finds nothing) is an idempotent success with NO DELETE issued, so
// Surface A drops ownership instead of wedging (#2771).
func TestRoute53DeleteAbsentIdempotent(t *testing.T) {
	b, fake := newR53FakeBackend(t)
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("absent DELETE must be idempotent success (nil), got %v", err)
	}
	if fake.deletes != 0 || fake.upserts != 0 {
		t.Fatalf("absent withdraw must issue no change: deletes=%d upserts=%d", fake.deletes, fake.upserts)
	}
}

// TestRoute53DeleteRacedGoneIdempotent is the #2771 fail-on-revert guard for the
// whole-RRset DELETE arm. The list finds xpf's sole-owned value, but the DELETE
// races another writer to gone → Route 53 returns HTTP 400 InvalidChangeBatch
// "... but it was not found". DeleteLease MUST treat that as idempotent success
// (nil). Reverting the idempotency makes the already-gone error propagate.
func TestRoute53DeleteRacedGoneIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">` +
				`<ResourceRecordSets><ResourceRecordSet><Name>wan.example.net.</Name><Type>A</Type><TTL>300</TTL>` +
				`<ResourceRecords><ResourceRecord><Value>203.0.113.5</Value></ResourceRecord></ResourceRecords>` +
				`</ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidChangeBatch</Code>` +
			`<Message>[Tried to delete resource record set [name='wan.example.net.', type='A'] but it was not found]</Message>` +
			`</Error></ErrorResponse>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("raced-gone DELETE must be idempotent success (nil), got %v", err)
	}
}

// TestRoute53DeleteGenuineErrorRetries asserts the idempotency does NOT
// over-swallow: a real failure on the whole-RRset DELETE (auth, throttle, or a
// non-"not found" InvalidChangeBatch) must STILL return non-nil so the engine
// keeps retrying. The list finds xpf's sole-owned value; the DELETE fails.
func TestRoute53DeleteGenuineErrorRetries(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		code, msg  string
		wantSubstr string
	}{
		{
			name: "auth", status: http.StatusForbidden,
			code: "SignatureDoesNotMatch", msg: "nope",
			wantSubstr: "SignatureDoesNotMatch",
		},
		{
			name: "throttle", status: http.StatusTooManyRequests,
			code: "Throttling", msg: "Rate exceeded",
			wantSubstr: "Throttling",
		},
		{
			// InvalidChangeBatch that is NOT an already-gone delete (a genuine
			// conflicting/malformed batch) must keep retrying / surface.
			name: "invalid-batch-not-gone", status: http.StatusBadRequest,
			code: "InvalidChangeBatch", msg: "[RRSet with DNS name ... is not permitted in zone]",
			wantSubstr: "InvalidChangeBatch",
		},
		{
			// #10727 A10-F3: a FOREIGN "not found" (missing hosted zone, not
			// the record) must keep retrying — the old bare-substring matcher
			// swallowed it and dropped ownership.
			name: "invalid-batch-foreign-zone-not-found", status: http.StatusBadRequest,
			code: "InvalidChangeBatch", msg: "Hosted zone 'Z1234567890' was not found",
			wantSubstr: "InvalidChangeBatch",
		},
		{
			name: "invalid-batch-bare-not-found", status: http.StatusBadRequest,
			code: "InvalidChangeBatch", msg: "NoSuchHostedZone: zone not found",
			wantSubstr: "InvalidChangeBatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/xml")
					_, _ = w.Write([]byte(`<?xml version="1.0"?><ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">` +
						`<ResourceRecordSets><ResourceRecordSet><Name>wan.example.net.</Name><Type>A</Type><TTL>300</TTL>` +
						`<ResourceRecords><ResourceRecord><Value>203.0.113.5</Value></ResourceRecord></ResourceRecords>` +
						`</ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`))
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>` +
					tc.code + `</Code><Message>` + tc.msg + `</Message></Error></ErrorResponse>`))
			}))
			defer srv.Close()
			b := newR53TestBackend(t, srv)
			err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
			if err == nil {
				t.Fatalf("genuine %s failure must NOT be swallowed (want non-nil)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("want error containing %q, got %v", tc.wantSubstr, err)
			}
		})
	}
}

// TestRoute53ListExactMatchOnly guards the list filter: when Route 53 returns a
// NEIGHBOURING set (the lexically-next name, not the requested one), listRRSet
// must treat the requested name as absent — so a first publish creates xpf's
// record rather than merging a stranger's values.
func TestRoute53ListExactMatchOnly(t *testing.T) {
	var upserts int
	var upsertVals []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Return a DIFFERENT name's set (as Route 53 does when the exact
			// name/type does not exist).
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">` +
				`<ResourceRecordSets><ResourceRecordSet><Name>zzz.example.net.</Name><Type>A</Type><TTL>300</TTL>` +
				`<ResourceRecords><ResourceRecord><Value>198.51.100.99</Value></ResourceRecord></ResourceRecords>` +
				`</ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>`))
			return
		}
		upserts++
		var batch changeBatchXML
		body, _ := io.ReadAll(r.Body)
		_ = xml.Unmarshal(body, &batch)
		for _, rr := range batch.ChangeBatch.Changes.Change[0].ResourceRecordSet.ResourceRecords.ResourceRecord {
			upsertVals = append(upsertVals, rr.Value)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ChangeResourceRecordSetsResponse/>`))
	}))
	defer srv.Close()
	b := newR53TestBackend(t, srv)
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if upserts != 1 || len(upsertVals) != 1 || upsertVals[0] != "203.0.113.5" {
		t.Fatalf("neighbour set must be ignored; want a clean create of xpf's value, got upserts=%d vals=%v", upserts, upsertVals)
	}
}

func TestRoute53MissingCredsConstructError(t *testing.T) {
	if _, err := newRoute53Backend(&config.DDNSProvider{Name: "r", Backend: "route53", HostedZoneID: "Z"}, nil); err == nil {
		t.Fatal("missing keys must error")
	}
	if _, err := newRoute53Backend(&config.DDNSProvider{Name: "r", Backend: "route53",
		AWSAccessKeyID: "A", AWSSecretAccessKey: config.Secret("s")}, nil); err == nil {
		t.Fatal("missing hosted-zone-id must error")
	}
}
