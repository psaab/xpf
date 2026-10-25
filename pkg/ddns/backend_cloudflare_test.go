package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
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
			body := mustReadBody(f.t, r)
			var upd cfRecord
			_ = json.Unmarshal(body, &upd)
			cur := f.records[id]
			cur.Content = upd.Content
			// #9067: apply the TTL too. The fake used to drop it, so a cell
			// asserting the propagated TTL would have measured the FAKE rather
			// than the backend — and would have failed even against a correct
			// fix. Real Cloudflare applies every field in the PATCH payload.
			if upd.TTL != 0 {
				cur.TTL = upd.TTL
			}
			// Apply a comment only when the payload carries the key: real
			// Cloudflare leaves the comment alone when it is absent, and the
			// backend's PATCH deliberately omits it (#16086 — a PATCH must
			// never claim a row by stamping it). Decoding into cfRecord
			// cannot distinguish absent from empty, so inspect the raw keys.
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(body, &raw)
			if _, ok := raw["comment"]; ok {
				cur.Comment = upd.Comment
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
		Name: "cf", Backend: "cloudflare", APIToken: config.NewSecret(fake.token),
		Zone: fake.zoneName, Server: srv.URL, InstallID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, nil)
	if err != nil {
		t.Fatalf("newCloudflareBackend: %v", err)
	}
	return b
}

// TestCloudflareSameZoneDifferentInstall16585 is the #16585 decisive
// cell: two independent installs publish into the SAME Cloudflare zone
// (same zone name, same API base, same token — the production shape).
// Pre-fix both derived the identical zone-hash tag, so install B's
// withdraw deleted install A's row. Post-fix the tags differ by the
// durable install-id, B POSTs its own row alongside A's, and B's
// withdraw leaves A's row untouched.
//
// FAIL-ON-REVERT: reverting cfOwnerID to the zone-hash-only form makes
// aTag == bTag, B adopts A's row (posted=0), and B's withdraw deletes
// A's row — every assertion below reds.
func TestCloudflareSameZoneDifferentInstall16585(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	mk := func(name, installID string) *cloudflareBackend {
		b, err := newCloudflareBackend(&config.DDNSProvider{
			Name: name, Backend: "cloudflare", APIToken: config.NewSecret(fake.token),
			Zone: fake.zoneName, Server: srv.URL, InstallID: installID,
		}, nil)
		if err != nil {
			t.Fatalf("backend %s: %v", name, err)
		}
		return b
	}
	a := mk("cf-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := mk("cf-b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if a.instanceTag == b.instanceTag {
		t.Fatalf("#16585: same-zone installs with different install-ids must derive different tags, both %q", a.instanceTag)
	}
	if !strings.HasPrefix(a.instanceTag, cfInstanceTagPrefix+cfInstanceTagInstall) {
		t.Fatalf("#16585: tag must carry the inst/ owner prefix, got %q", a.instanceTag)
	}

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	rec := hostRecord(t, fqdn, addr)

	// A publishes; exactly one row, stamped with A's tag.
	if err := a.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("A publish: %v", err)
	}
	if fake.posted != 1 || len(fake.records) != 1 {
		t.Fatalf("#16585: A publish must POST one row, posted=%d records=%d", fake.posted, len(fake.records))
	}
	var aID string
	for id, r := range fake.records {
		aID = id
		if r.Comment != a.instanceTag {
			t.Fatalf("#16585: A's row must carry A's tag, got %q want %q", r.Comment, a.instanceTag)
		}
	}

	// B publishes the same name+IP: it must NOT adopt A's row; it POSTs
	// its own tagged row alongside.
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("B publish: %v", err)
	}
	if fake.posted != 2 || fake.patched != 0 {
		t.Fatalf("#16585: B must POST its own row beside A's (posted=%d patched=%d); adopting A's row makes it B's withdraw target", fake.posted, fake.patched)
	}
	if got := fake.records[aID]; got.Comment != a.instanceTag {
		t.Fatalf("#16585: B's publish rewrote A's row: %+v", got)
	}

	// B withdraws: only B's row goes; A's row survives, no fallback.
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("B withdraw: %v", err)
	}
	if _, ok := fake.records[aID]; !ok {
		t.Fatal("#16585: B's withdraw deleted install A's record on the same zone")
	}
	if len(fake.records) != 1 || fake.deleted != 1 {
		t.Fatalf("#16585: B's withdraw must delete exactly its own row, records=%d deleted=%d", len(fake.records), fake.deleted)
	}
	if strings.Contains(logs.String(), "value-scoped fallback") {
		t.Fatalf("#16585: B's withdraw must not take the fallback, logs: %s", logs.String())
	}

	// A still owns its row: A's withdraw removes it.
	if err := a.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("A withdraw: %v", err)
	}
	if len(fake.records) != 0 || fake.deleted != 2 {
		t.Fatalf("#16585: A withdraw must remove the last row, records=%d deleted=%d", len(fake.records), fake.deleted)
	}
}

// TestCloudflareHAPairSharesInstall16585 pins the HA half of #16585:
// two backends built from the SAME provider (same committed
// install-id, as config-sync delivers to both peers) derive the SAME
// tag, so the peer that takes over owns the rows the first peer
// published — one logical writer.
func TestCloudflareHAPairSharesInstall16585(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	p := &config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", APIToken: config.NewSecret(fake.token),
		Zone: fake.zoneName, Server: srv.URL, InstallID: "cccccccccccccccccccccccccccccccc",
	}
	b1, err := newCloudflareBackend(p, nil)
	if err != nil {
		t.Fatalf("peer1: %v", err)
	}
	b2, err := newCloudflareBackend(p, nil)
	if err != nil {
		t.Fatalf("peer2: %v", err)
	}
	if b1.instanceTag != b2.instanceTag {
		t.Fatalf("#16585: HA peers sharing one install-id must share the tag: %q vs %q", b1.instanceTag, b2.instanceTag)
	}
	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	rec := hostRecord(t, fqdn, addr)
	if err := b1.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("peer1 publish: %v", err)
	}
	// Peer2 sees peer1's row as its own: republish is a no-write, and
	// peer2's withdraw removes it.
	if err := b2.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("peer2 republish: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("#16585: HA peer republish must be a no-write, posted=%d patched=%d", fake.posted, fake.patched)
	}
	if err := b2.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("peer2 withdraw: %v", err)
	}
	if len(fake.records) != 0 {
		t.Fatalf("#16585: HA peer withdraw must remove the shared row, records=%d", len(fake.records))
	}
}

// TestCloudflareLegacyZoneTagFallback16585 pins the #16585 legacy read:
// a row stamped with THIS endpoint's pre-#16585 zone-hash tag is legacy
// (value-scoped fallback only), while the same zone-hash shape for a
// DIFFERENT endpoint stays foreign and is never fallback-deleted.
func TestCloudflareLegacyZoneTagFallback16585(t *testing.T) {
	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"

	t.Run("own endpoint legacy tag uses logged fallback", func(t *testing.T) {
		logs := captureWarn16086(t)
		fake := newCFFakeAPI(t)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()
		b := newCFTestBackend(t, srv, fake)
		if b.legacyTag == b.instanceTag || b.legacyTag == "" {
			t.Fatalf("setup: legacy tag %q must differ from instance tag %q", b.legacyTag, b.instanceTag)
		}
		legacyID := fake.seedRecordComment("A", fqdn, addr, b.legacyTag)
		if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, addr)); err != nil {
			t.Fatalf("legacy withdraw: %v", err)
		}
		if _, ok := fake.records[legacyID]; ok {
			t.Fatal("#16585: own-endpoint zone-hash row must be withdrawn via the fallback, not orphaned")
		}
		if fake.deleted != 1 || !strings.Contains(logs.String(), "value-scoped fallback") {
			t.Fatalf("#16585: legacy fallback must delete once and warn, deleted=%d logs=%q", fake.deleted, logs.String())
		}
		// Legacy rows are never adopted on publish either: a fresh
		// publish beside a legacy same-content row POSTs its own row.
		fake2 := newCFFakeAPI(t)
		srv2 := httptest.NewServer(fake2.handler())
		defer srv2.Close()
		b2 := newCFTestBackend(t, srv2, fake2)
		legacyID2 := fake2.seedRecordComment("A", fqdn, addr, b2.legacyTag)
		if err := b2.UpsertLease(context.Background(), hostRecord(t, fqdn, addr)); err != nil {
			t.Fatalf("publish beside legacy row: %v", err)
		}
		if fake2.posted != 1 || fake2.patched != 0 {
			t.Fatalf("#16585: publish beside a legacy row must POST its own, posted=%d patched=%d", fake2.posted, fake2.patched)
		}
		if got := fake2.records[legacyID2]; got.Comment != b2.legacyTag {
			t.Fatalf("#16585: legacy row was claimed by publish: %+v", got)
		}
	})

	t.Run("other endpoint zone-hash tag stays foreign", func(t *testing.T) {
		captureWarn16086(t)
		fake := newCFFakeAPI(t)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()
		b := newCFTestBackend(t, srv, fake)
		other, err := newCloudflareBackend(&config.DDNSProvider{
			Name: "cf-other", Backend: "cloudflare", APIToken: config.NewSecret(fake.token),
			Zone: "other.example.net", Server: srv.URL, InstallID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		}, nil)
		if err != nil {
			t.Fatalf("other backend: %v", err)
		}
		otherID := fake.seedRecordComment("A", fqdn, addr, other.legacyTag)
		if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, addr)); err != nil {
			t.Fatalf("withdraw: %v", err)
		}
		if _, ok := fake.records[otherID]; !ok {
			t.Fatal("#16585: another endpoint's zone-hash row was fallback-deleted")
		}
		if fake.deleted != 0 {
			t.Fatalf("#16585: expected no deletes, deleted=%d", fake.deleted)
		}
	})
}

// TestEnsureInstallID16585 pins the minting contract: a valid id is
// kept verbatim (HA stability), an absent or malformed id is replaced
// with a fresh well-formed one, and two mints differ.
func TestEnsureInstallID16585(t *testing.T) {
	p := &config.DDNSProvider{InstallID: "dddddddddddddddddddddddddddddddd"}
	got, err := EnsureInstallID(p)
	if err != nil || got != p.InstallID {
		t.Fatalf("#16585: valid id must be kept, got %q err %v", got, err)
	}
	for _, bad := range []string{"", "not-hex", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "dddd"} {
		q := &config.DDNSProvider{InstallID: bad}
		id1, err := EnsureInstallID(q)
		if err != nil {
			t.Fatalf("mint for %q: %v", bad, err)
		}
		if !validInstallID(id1) || q.InstallID != id1 {
			t.Fatalf("#16585: minted id %q (stored %q) must be well-formed", id1, q.InstallID)
		}
		id2, err := EnsureInstallID(&config.DDNSProvider{})
		if err != nil {
			t.Fatalf("second mint: %v", err)
		}
		if id1 == id2 {
			t.Fatal("#16585: two mints must differ (per-install uniqueness)")
		}
	}
	if _, err := EnsureInstallID(nil); err == nil {
		t.Fatal("#16585: nil provider must error")
	}
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
	// Foreign row FIRST (so it is recs[0]) + xpf's own prior value. The
	// owned row is seeded with this instance's tag (#16086 fold): an
	// untagged prior row is no longer PATCHed by value — that adoption is
	// exactly what the fold closes.
	foreignA := fake.seedRecord("A", fqdn, "198.51.100.20")
	ownedA := fake.seedRecordComment("A", fqdn, "203.0.113.5", b.instanceTag)

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
// The new-value and stale rows are seeded TAGGED (#16086): this cell is
// about xpf's OWN rows. An UNTAGGED new-value row is the #16086 adoption
// case (xpf POSTs its own tagged row instead) and is covered there.
func TestCloudflareExistingNewValueRemovesStalePreviousRecord10715(t *testing.T) {
	for _, tc := range []struct {
		name        string
		liveTTL     int
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
			newID := fake.seedRecordTTLComment("A", fqdn, "203.0.113.9", tc.liveTTL, b.instanceTag)
			oldID := fake.seedRecordTTLComment("A", fqdn, "203.0.113.5", 300, b.instanceTag)
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

// seedRecordComment seeds a record carrying a comment (the ownership tag
// dimension #16086 adds); seedRecord/seedRecordTTL leave it empty.
func (f *cfFakeAPI) seedRecordComment(rtype, name, content, comment string) string {
	id := f.seedRecord(rtype, name, content)
	rec := f.records[id]
	rec.Comment = comment
	f.records[id] = rec
	return id
}

// seedRecordTTLComment seeds a tagged record WITH a TTL, so a cell can
// stage an xpf-owned row whose TTL alone varies (#9067/#10715 x #16086).
func (f *cfFakeAPI) seedRecordTTLComment(rtype, name, content string, ttl int, comment string) string {
	id := f.seedRecordTTL(rtype, name, content, ttl)
	rec := f.records[id]
	rec.Comment = comment
	f.records[id] = rec
	return id
}

// mustReadBody drains a fake-handler request body, failing the test on error.
func mustReadBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return body
}

// captureWarn16086 installs a WARN-level slog default writing to a buffer and
// restores the previous default on cleanup. Tests asserting on the rendered
// log must not run in parallel (process-global default).
func captureWarn16086(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestCloudflareDeleteAllOwnedRecords is the #2770 fail-on-revert, restated
// for #16086 tag ownership: a name can carry MULTIPLE records of one type,
// several of which xpf owns (tagged). DeleteLease must issue a DELETE for
// EVERY proven-owned row whose content equals the owned address, must NOT
// touch a row with foreign content, and must leave a record that merely
// shares the name+type but a different value untouched. If reverted to the
// first-only / content-blind delete this goes RED: either it leaves a
// second owned row behind (deleted < 2) or it clobbers the foreign value.
// (Untagged same-content rows are the legacy fallback — see the #16086
// tests below; they are deliberately NOT staged here.)
func TestCloudflareDeleteAllOwnedRecords(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const owned = "203.0.113.5"
	// Two xpf-owned (tagged) rows + one foreign value a human set on the
	// same name + an unrelated AAAA that must never be hit.
	ownedA := fake.seedRecordComment("A", fqdn, owned, b.instanceTag)
	ownedB := fake.seedRecordComment("A", fqdn, owned, b.instanceTag)
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
		Name: "cf", Backend: "cloudflare", APIToken: config.NewSecret("WRONG"),
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
	if _, err := newCloudflareBackend(&config.DDNSProvider{Name: "cf", Backend: "cloudflare", APIToken: config.NewSecret("t")}, nil); err == nil {
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
