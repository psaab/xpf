package ddns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_cloudflare_test.go: mock-server tests driving the REAL Cloudflare
// backend through a stateful httptest fake of the Cloudflare API (zones lookup +
// dns_records find/create/update/delete). Asserts the Bearer auth, the
// zone-id-resolve→find→PATCH/POST flow, and the change-vs-create branch.

type cfFakeAPI struct {
	t        *testing.T
	token    string
	zoneName string
	zoneID   string
	// records keyed by id.
	records map[string]cfRecord
	// order is the record ids in insertion order, so the GET handler returns a
	// DETERMINISTIC list (real Cloudflare order is arbitrary, but a stable test
	// order lets a test fix which row is recs[0] — the ordering artifact the
	// value-specific #3739 fix must NOT rely on).
	order   []string
	nextID  int
	patched int
	posted  int
	deleted int
	sawAuth string
}

func newCFFakeAPI(t *testing.T) *cfFakeAPI {
	return &cfFakeAPI{
		t: t, token: "tok-123", zoneName: "example.net", zoneID: "ZONEID1",
		records: map[string]cfRecord{}, nextID: 1,
	}
}

func (f *cfFakeAPI) ok(w http.ResponseWriter, result any) {
	env := map[string]any{"success": true, "errors": []any{}, "result": result}
	_ = json.NewEncoder(w).Encode(env)
}

func (f *cfFakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.sawAuth = r.Header.Get("Authorization")
		if f.sawAuth != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false,
				"errors": []map[string]any{{"code": 9109, "message": "bad token"}}})
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") != f.zoneName {
				f.ok(w, []cfZone{})
				return
			}
			f.ok(w, []cfZone{{ID: f.zoneID, Name: f.zoneName}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/"+f.zoneID+"/dns_records":
			name := r.URL.Query().Get("name")
			rtype := r.URL.Query().Get("type")
			var out []cfRecord
			for _, id := range f.order {
				rec := f.records[id]
				if rec.Name == name && rec.Type == rtype {
					out = append(out, rec)
				}
			}
			f.ok(w, out)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/"+f.zoneID+"/dns_records":
			f.posted++
			var rec cfRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "rec" + itoa(f.nextID)
			f.nextID++
			f.records[rec.ID] = rec
			f.order = append(f.order, rec.ID)
			f.ok(w, rec)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/"):
			f.patched++
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/")
			var upd cfRecord
			_ = json.NewDecoder(r.Body).Decode(&upd)
			cur := f.records[id]
			cur.Content = upd.Content
			// #9067: apply the TTL too. The fake used to drop it, so a cell
			// asserting the propagated TTL would have measured the FAKE rather
			// than the backend — and would have failed even against a correct
			// fix. Real Cloudflare applies every field in the PATCH payload.
			if upd.TTL != 0 {
				cur.TTL = upd.TTL
			}
			f.records[id] = cur
			f.ok(w, cur)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/"):
			f.deleted++
			id := strings.TrimPrefix(r.URL.Path, "/zones/"+f.zoneID+"/dns_records/")
			delete(f.records, id)
			for i, oid := range f.order {
				if oid == id {
					f.order = append(f.order[:i], f.order[i+1:]...)
					break
				}
			}
			f.ok(w, map[string]string{"id": id})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newCFTestBackend(t *testing.T, srv *httptest.Server, fake *cfFakeAPI) *cloudflareBackend {
	t.Helper()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret(fake.token),
		Zone: fake.zoneName, Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}
	return b
}

func TestCloudflareCreateThenUpdate(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	// First publish → POST (create).
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("first publish must create: posted=%d patched=%d", fake.posted, fake.patched)
	}
	// Same address again → no write (content already correct).
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("noop: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("unchanged content must not write: posted=%d patched=%d", fake.posted, fake.patched)
	}
	// New address → PATCH (update existing). Production threads the previous
	// published value (rec.PrevAddr, #3739) so the renumber patches xpf's OWN
	// row in place rather than creating a second record. Without PrevAddr the
	// value-specific path would (correctly) POST a new row and leak the old one.
	renum := hostRecord(t, "wan.example.net", "203.0.113.9")
	renum.PrevAddr = netip.MustParseAddr("203.0.113.5")
	if err := b.UpsertLease(context.Background(), renum); err != nil {
		t.Fatalf("update: %v", err)
	}
	if fake.patched != 1 || fake.posted != 1 {
		t.Fatalf("address change must patch xpf's own row, not create: patched=%d posted=%d", fake.patched, fake.posted)
	}
	// Verify the live record content.
	var live cfRecord
	for _, r := range fake.records {
		live = r
	}
	if live.Content != "203.0.113.9" {
		t.Fatalf("record content not updated: %q", live.Content)
	}
}

// TestCloudflareRenumberPatchesOnlyOwnedRow is the #3739 H11 fail-on-revert for
// a RENUMBER on a SHARED name: the FQDN carries a FOREIGN A a human set plus
// xpf's own A. A publish of xpf's NEW address (with PrevAddr = xpf's prior value)
// must PATCH only xpf's own row and leave the foreign value intact. The fake
// returns records in insertion order and the foreign row is seeded FIRST, so
// recs[0] is the FOREIGN row: reverting UpsertLease to the old content-blind
// "PATCH recs[0]" rewrites the foreign value to xpf's address → this goes RED.
func TestCloudflareRenumberPatchesOnlyOwnedRow(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	// Foreign row FIRST (so it is recs[0]) + xpf's own prior value.
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")
	ownedA := fake.seedRecord("A", fqdn, "203.0.113.5")

	rec := hostRecord(t, fqdn, "203.0.113.9")
	rec.PrevAddr = netip.MustParseAddr("203.0.113.5") // xpf's prior value
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("renumber: %v", err)
	}
	// Exactly one PATCH (xpf's own row), no POST.
	if fake.patched != 1 || fake.posted != 0 {
		t.Fatalf("renumber must patch xpf's own row only: patched=%d posted=%d", fake.patched, fake.posted)
	}
	// xpf's row now carries the new value.
	if got := fake.records[ownedA].Content; got != "203.0.113.9" {
		t.Fatalf("xpf row not renumbered: content=%q", got)
	}
	// The FOREIGN value must survive untouched (the #3739 clobber).
	if got := fake.records[foreignA].Content; got != "198.51.100.20" {
		t.Fatalf("foreign A was clobbered on renumber: content=%q (want 198.51.100.20)", got)
	}
}
// TestCloudflareExistingNewValueRemovesStalePreviousRecord is the #10715
// fail-on-revert for a renumber whose new value already exists at Cloudflare.
// The previous value remains stale: both the exact-content no-op and the
// TTL-correction path must clean it up without touching a foreign record.
func TestCloudflareExistingNewValueRemovesStalePreviousRecord10715(t *testing.T) {
	for _, tc := range []struct {
		name       string
		liveTTL    int
		wantPatches int
	}{
		{name: "renumber with desired TTL", liveTTL: 300, wantPatches: 0},
		{name: "renumber with TTL-only correction", liveTTL: 3600, wantPatches: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newCFFakeAPI(t)
			srv := httptest.NewServer(fake.handler())
			defer srv.Close()
			b := newCFTestBackend(t, srv, fake)

			const fqdn = "wan.example.net"
			foreignID := fake.seedRecordTTL("A", fqdn, "198.51.100.20", 1800)
			newID := fake.seedRecordTTL("A", fqdn, "203.0.113.9", tc.liveTTL)
			oldID := fake.seedRecordTTL("A", fqdn, "203.0.113.5", 300)
			rec := hostRecordTTL(t, fqdn, "203.0.113.9", 300)
			rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
			if err := b.UpsertLease(context.Background(), rec); err != nil {
				t.Fatalf("renumber with existing new value: %v", err)
			}

			if fake.deleted != 1 {
				t.Fatalf("#10715: expected stale PrevAddr row to be deleted exactly once, deleted=%d", fake.deleted)
			}
			if fake.patched != tc.wantPatches || fake.posted != 0 {
				t.Fatalf("existing new value must be reused: patched=%d posted=%d, want patched=%d posted=0",
					fake.patched, fake.posted, tc.wantPatches)
			}
			if _, ok := fake.records[oldID]; ok {
				t.Fatal("#10715: stale PrevAddr row survived")
			}
			if got := fake.records[newID].TTL; got != 300 {
				t.Errorf("new-value row TTL=%d, want 300", got)
			}
			if got := fake.records[foreignID]; got.Content != "198.51.100.20" || got.TTL != 1800 {
				t.Errorf("foreign row changed: %+v", got)
			}
			if len(fake.records) != 2 {
				t.Errorf("expected only the foreign and new-value rows, got %d", len(fake.records))
			}
		})
	}
}


// TestCloudflareFirstPublishOntoForeignName is the #3739 H11 fail-on-revert for a
// FIRST publish onto a name that already carries only a FOREIGN A (no xpf row,
// no PrevAddr). The value-specific upsert must POST a new record and leave the
// foreign one intact. Reverting to the old "found → PATCH recs[0]" rewrites the
// sole (foreign) row to xpf's address → this goes RED (foreign clobbered, and a
// POST that should have happened did not).
func TestCloudflareFirstPublishOntoForeignName(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")

	// No PrevAddr — a genuine first publish onto a name a human already populated.
	if err := b.UpsertLease(context.Background(), hostRecord(t, fqdn, "203.0.113.9")); err != nil {
		t.Fatalf("first publish onto foreign name: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("first publish onto a foreign name must POST, not PATCH: posted=%d patched=%d", fake.posted, fake.patched)
	}
	// The foreign value must survive.
	if got := fake.records[foreignA].Content; got != "198.51.100.20" {
		t.Fatalf("foreign A was clobbered on first publish: content=%q (want 198.51.100.20)", got)
	}
	// xpf's new value now coexists.
	var haveNew bool
	for _, r := range fake.records {
		if r.Content == "203.0.113.9" {
			haveNew = true
		}
	}
	if !haveNew {
		t.Fatal("xpf's new A was not created alongside the foreign record")
	}
}

func TestCloudflareDelete(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	rec := hostRecord(t, "wan.example.net", "203.0.113.5")
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if fake.deleted != 1 || len(fake.records) != 0 {
		t.Fatalf("delete must remove the record: deleted=%d remaining=%d", fake.deleted, len(fake.records))
	}
	// Deleting an already-gone record is a success (no-op).
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

// seedRecord injects a record directly into the fake (bypassing POST) so a test
// can stage the multi-record / wrong-content states the real Cloudflare API can
// hold but the backend's own POST path would never create on its own.
// seedRecordTTL seeds a record WITH a TTL (#9067). seedRecord leaves TTL zero,
// which is fine for the content-only cells but useless for a TTL comparison: a
// foreign row at TTL 0 cannot show that xpf left its TTL alone.
func (f *cfFakeAPI) seedRecordTTL(rtype, name, content string, ttl int) string {
	id := f.seedRecord(rtype, name, content)
	rec := f.records[id]
	rec.TTL = ttl
	f.records[id] = rec
	return id
}

func (f *cfFakeAPI) seedRecord(rtype, name, content string) string {
	id := "seed" + itoa(f.nextID)
	f.nextID++
	f.records[id] = cfRecord{ID: id, Type: rtype, Name: name, Content: content}
	f.order = append(f.order, id)
	return id
}

// TestCloudflareDeleteAllOwnedRecords is the #2770 fail-on-revert: a name can
// carry MULTIPLE records of one type, several of which xpf owns. DeleteLease
// must issue a DELETE for EVERY row whose content equals the owned address,
// must NOT touch a row with foreign content, and must leave a record that
// merely shares the name+type but a different value untouched. If reverted to
// the first-only / content-blind delete this goes RED: either it leaves a
// second owned row behind (deleted < 2) or it clobbers the foreign value.
func TestCloudflareDeleteAllOwnedRecords(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const owned = "203.0.113.5"
	// Two owned rows (duplicate same-value A records) + one foreign value a
	// human set on the same name + an unrelated AAAA that must never be hit.
	ownedA := fake.seedRecord("A", fqdn, owned)
	ownedB := fake.seedRecord("A", fqdn, owned)
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")
	foreignAAAA := fake.seedRecord("AAAA", fqdn, "2001:db8::1")

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, owned)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// EVERY owned row deleted — not just the first.
	if fake.deleted != 2 {
		t.Fatalf("must delete every owned record, got deleted=%d", fake.deleted)
	}
	if _, ok := fake.records[ownedA]; ok {
		t.Fatalf("owned record A still present")
	}
	if _, ok := fake.records[ownedB]; ok {
		t.Fatalf("owned record B still present")
	}
	// The foreign value (human/automation set it later) must survive.
	if _, ok := fake.records[foreignA]; !ok {
		t.Fatalf("foreign A value was clobbered — ownership boundary violated")
	}
	if _, ok := fake.records[foreignAAAA]; !ok {
		t.Fatalf("unrelated AAAA was deleted")
	}
}

// TestCloudflareDeleteOwnershipConflict: the name has records of the right type
// but NONE match the owned content (a human replaced the value xpf published).
// DeleteLease must NOT delete a foreign value — it is a success no-op.
func TestCloudflareDeleteOwnershipConflict(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, "203.0.113.5")); err != nil {
		t.Fatalf("delete (no owned match): %v", err)
	}
	if fake.deleted != 0 {
		t.Fatalf("must not delete a foreign value, got deleted=%d", fake.deleted)
	}
	if _, ok := fake.records[foreignA]; !ok {
		t.Fatalf("foreign value was clobbered on ownership conflict")
	}
}

func TestCloudflareBadTokenIsAuthError(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.Secret("WRONG"),
		Zone: fake.zoneName, Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}
	err = b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5"))
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("bad token must be an auth error, got %v", err)
	}
}

func TestCloudflareMissingCredsConstructError(t *testing.T) {
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", Zone: "x"}, nil); err == nil {
		t.Fatal("missing api-token must error")
	}
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", APIToken: config.Secret("t")}, nil); err == nil {
		t.Fatal("missing zone must error")
	}
}

// hostRecordTTL is hostRecord with an explicit TTL, so a cell can vary the ONE
// field #9067 is about (#9067). The existing helper hard-codes 300 and every
// pre-#9067 cell used it, which is why the omission was untested in BOTH
// directions: no cell could distinguish a backend that compares TTL from one
// that ignores it.
func hostRecordTTL(t *testing.T, fqdn, addr string, ttl int) LeaseDNSRecord {
	t.Helper()
	rec, err := buildHostRecord(fqdn, netip.MustParseAddr(addr), ttl)
	if err != nil {
		t.Fatalf("buildHostRecord: %v", err)
	}
	return rec
}

// #9067: a TTL-only change must propagate.
//
// The pre-#9067 loop returned on a CONTENT match alone, so a TTL-only edit was
// never written — not delayed, NEVER. Every later refresh, including the
// operator's explicit `request system dynamic-dns update` force latch, re-entered
// the same early return. Route 53's sibling has always compared both
// (`live.found && live.ttl == ttl && sameValueSet(...)`), and `cfRecord.TTL` was
// already parsed here: the datum was available and simply unread.
//
// It is silent — no error, no warning, and `show` reports the CONFIGURED TTL —
// and the harm lands later: an operator who lowers TTL before a planned renumber
// gets no propagation, which is exactly what the shorter TTL was bought for.
func TestCloudflareTTLOnlyChangePropagates9067(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	if err := b.UpsertLease(context.Background(),
		hostRecordTTL(t, "wan.example.net", "203.0.113.5", 3600)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if fake.posted != 1 {
		t.Fatalf("fixture: first publish must create, posted=%d", fake.posted)
	}
	postedPatches := fake.patched

	// SAME address, DIFFERENT TTL — the operator lowering TTL before a renumber.
	if err := b.UpsertLease(context.Background(),
		hostRecordTTL(t, "wan.example.net", "203.0.113.5", 60)); err != nil {
		t.Fatalf("ttl-only change: %v", err)
	}
	if fake.patched == postedPatches {
		t.Fatalf("#9067: a TTL-only change issued NO write (patched=%d, posted=%d). "+
			"The backend returned on a content match alone, so the new TTL never "+
			"reaches the provider — and never will, because every later refresh "+
			"re-enters the same early return", fake.patched, fake.posted)
	}
	if fake.posted != 1 {
		t.Errorf("#9067: the TTL fix must PATCH the existing row, not POST a second "+
			"one (posted=%d). A duplicate at the same name is worse than the "+
			"un-propagated TTL it replaces", fake.posted)
	}

	// The live record must carry BOTH the address and the new TTL.
	var live cfRecord
	for _, r := range fake.records {
		live = r
	}
	if live.TTL != 60 {
		t.Errorf("#9067: live TTL = %d, want 60 — the write happened but did not "+
			"carry the new TTL", live.TTL)
	}
	if live.Content != "203.0.113.5" {
		t.Errorf("#9067: the TTL update must not disturb the content: %q", live.Content)
	}
	if len(fake.records) != 1 {
		t.Errorf("#9067: expected exactly one record at the name, got %d", len(fake.records))
	}
}

// CONTROL, and it is load-bearing: with content AND TTL both already correct the
// backend must still issue NO write. Without this a "fix" that simply deleted the
// early return would satisfy the cell above while writing on every single
// refresh — turning an idempotent no-op path into unconditional provider traffic
// (and, on a rate-limited API, into failures).
func TestCloudflareUnchangedContentAndTTLStillSkips9067(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	rec := hostRecordTTL(t, "wan.example.net", "203.0.113.5", 3600)
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	posted, patched := fake.posted, fake.patched

	for i := 0; i < 3; i++ {
		if err := b.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("noop refresh %d: %v", i, err)
		}
	}
	if fake.posted != posted || fake.patched != patched {
		t.Errorf("#9067: content and TTL both unchanged must issue NO write, got "+
			"posted %d->%d patched %d->%d. Deleting the early return instead of "+
			"widening it makes every refresh a write", posted, fake.posted, patched, fake.patched)
	}
}

// A TTL-only change on a SHARED name must still patch only xpf's own row — the
// #3739 H11 property, re-asserted for the new fall-through path. The foreign row
// is seeded FIRST so it is recs[0]: a fix that patched recs[0] would rewrite the
// foreign value.
func TestCloudflareTTLOnlyChangeLeavesForeignRowAlone9067(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	// A human's record at the same name, seeded first.
	fake.seedRecordTTL("A", "wan.example.net", "198.51.100.7", 300)
	if err := b.UpsertLease(context.Background(),
		hostRecordTTL(t, "wan.example.net", "203.0.113.5", 3600)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := b.UpsertLease(context.Background(),
		hostRecordTTL(t, "wan.example.net", "203.0.113.5", 60)); err != nil {
		t.Fatalf("ttl-only change: %v", err)
	}

	var foreign, own *cfRecord
	for id := range fake.records {
		r := fake.records[id]
		switch r.Content {
		case "198.51.100.7":
			foreign = &r
		case "203.0.113.5":
			own = &r
		}
	}
	if foreign == nil {
		t.Fatal("#9067: the FOREIGN row was destroyed by the TTL-only update")
	}
	if foreign.TTL != 300 {
		t.Errorf("#9067: the foreign row's TTL was rewritten to %d — xpf must "+
			"never touch a record it does not own", foreign.TTL)
	}
	if own == nil || own.TTL != 60 {
		t.Errorf("#9067: xpf's own row did not get the new TTL: %+v", own)
	}
}
