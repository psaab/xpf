package ddns

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_cloudflare_foreign_withdraw_16086_test.go: the #16086 (A10-16)
// decisive regression — DDNS withdraw must not delete foreign same-content
// records — as folded per the PR #16114 hostile reviews.
//
// Mechanism: Cloudflare DeleteLease used content equality as the only
// ownership proof and deleted EVERY row with Content==owned. Two
// publishers of the same name+IP meant xpf's withdraw also deleted the
// foreign publisher's identical row. The first fix iteration stamped a
// product-wide "xpf-managed" tag; the reviews showed three holes:
//
//  1. A product-wide tag does not distinguish INDEPENDENT xpf instances:
//     instance B adopted and withdrew instance A's record.
//  2. An untagged same-content row at a DIFFERENT TTL was still PATCHed
//     (adopted), then withdraw-deleted via the fallback.
//  3. Upsert stale PrevAddr cleanup deleted by value with no ownership
//     check and no fallback warning.
//
// Folded fix: the comment carries a STABLE PER-INSTANCE identity
// ("xpf-managed:prov/<endpoint-fingerprint>", see cfOwnerID); adoption
// and PATCH require that exact instance tag (or a row this backend
// instance created in-process); a different instance's tagged row is
// foreign; stale-cleanup applies the same discipline with the logged
// fallback. HA peers sharing the committed provider config share the
// identity — one logical writer — by construction.
//
// Known limit (NEEDS_VALIDATION in the reviews, unchanged): the fake
// accepts a second record at identical name/type/content; whether the
// real Cloudflare API accepts that duplicate POST is not established
// here. If it rejects it, publish over a foreign identical row errors
// (visible, retried) rather than deleting anything.

// otherInstanceTag16086 builds the tag a DIFFERENT xpf instance would
// stamp (a different provider identity ⇒ a different fingerprint).
func otherInstanceTag16086(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf-other", Backend: "cloudflare",
		APIToken: config.NewSecret("tok-123"), Zone: "other.example.net",
		Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("other backend: %v", err)
	}
	if b.instanceTag == "" {
		t.Fatal("other backend has no instance tag")
	}
	return b.instanceTag
}

// TestCloudflareForeignSameContentSurvivesWithdraw16086 is the issue's
// decisive check: a foreign publisher holds an unmanaged (untagged) row
// at name+value; xpf publishes the same name+IP, then withdraws. The
// foreign row must SURVIVE, with no fallback warning.
func TestCloudflareForeignSameContentSurvivesWithdraw16086(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	foreignID := fake.seedRecordTTL("A", fqdn, addr, 300)

	rec := hostRecordTTL(t, fqdn, addr, 300)
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("publish onto foreign same-content row: %v", err)
	}
	if fake.posted != 1 {
		t.Fatalf("#16086: publish over an untagged same-content row must POST "+
			"xpf's own tagged row (posted=%d)", fake.posted)
	}
	if got := fake.records[foreignID]; got.Content != addr || strings.HasPrefix(got.Comment, cfInstanceTagPrefix) || got.Comment == cfLegacyComment {
		t.Fatalf("#16086: foreign row was claimed/rewritten by publish: %+v", got)
	}
	var ownID string
	for id, r := range fake.records {
		if id != foreignID && r.Content == addr {
			ownID = id
			if r.Comment != b.instanceTag {
				t.Fatalf("#16086: xpf's created row must carry THIS instance's tag, got %q want %q", r.Comment, b.instanceTag)
			}
		}
	}
	if ownID == "" {
		t.Fatal("#16086: xpf's own row missing after publish")
	}
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("#16086: republish with an owned row must not write: posted=%d patched=%d",
			fake.posted, fake.patched)
	}
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := fake.records[foreignID]; !ok {
		t.Fatal("#16086: withdraw deleted the FOREIGN same-content record")
	}
	if _, ok := fake.records[ownID]; ok {
		t.Fatal("#16086: withdraw left xpf's own tagged record behind")
	}
	if fake.deleted != 1 {
		t.Fatalf("#16086: withdraw must delete exactly xpf's own row, deleted=%d", fake.deleted)
	}
	if strings.Contains(logs.String(), "value-scoped fallback") {
		t.Fatalf("#16086: withdraw with an owned row must not take the fallback, logs: %s", logs.String())
	}
}

// TestCloudflareForeignWrongTTLSurvives16086 is fold finding 2: an
// untagged foreign row at the same content but a DIFFERENT TTL must not
// be PATCHed/adopted. xpf creates its own tagged row alongside; the
// foreign row keeps its TTL and survives publish + withdraw.
//
// FAIL-ON-REVERT: restoring the wrong-TTL PATCH target makes patched=1,
// posted=0 and the withdraw deletes the foreign row.
func TestCloudflareForeignWrongTTLSurvives16086(t *testing.T) {
	captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	foreignID := fake.seedRecordTTL("A", fqdn, addr, 3600) // wrong TTL, untagged

	rec := hostRecordTTL(t, fqdn, addr, 300)
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("publish over wrong-TTL foreign row: %v", err)
	}
	if fake.patched != 0 {
		t.Fatalf("#16086 fold: publish must NEVER PATCH an unowned row, patched=%d", fake.patched)
	}
	if fake.posted != 1 {
		t.Fatalf("#16086 fold: publish must POST its own tagged row alongside, posted=%d", fake.posted)
	}
	if got := fake.records[foreignID]; got.Content != addr || got.TTL != 3600 || got.Comment != "" {
		t.Fatalf("#16086 fold: foreign wrong-TTL row was modified: %+v", got)
	}
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := fake.records[foreignID]; !ok {
		t.Fatal("#16086 fold: withdraw deleted the foreign wrong-TTL record")
	}
	if got := fake.records[foreignID]; got.TTL != 3600 {
		t.Fatalf("#16086 fold: foreign row TTL changed: %+v", got)
	}
}

// TestCloudflareOtherInstanceRecordIsForeign16086 is fold finding 1: a
// record tagged by a DIFFERENT xpf instance (different provider
// identity) is foreign to this instance. This instance must not adopt
// it on publish (no-write arm), must not count it as proven on
// withdraw, and must never delete it — even via the fallback.
func TestCloudflareOtherInstanceRecordIsForeign16086(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)
	otherTag := otherInstanceTag16086(t, srv)
	if otherTag == b.instanceTag {
		t.Fatalf("test setup: other-instance tag %q must differ from own %q", otherTag, b.instanceTag)
	}

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	otherID := fake.seedRecordTTLComment("A", fqdn, addr, 300, otherTag)

	rec := hostRecordTTL(t, fqdn, addr, 300)
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("publish beside other-instance row: %v", err)
	}
	// Not adopted: this instance POSTs its own row instead of no-writing.
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("#16086 fold: publish beside another instance's row must POST own "+
			"row (posted=%d patched=%d); adopting it makes the other instance's "+
			"record this instance's withdraw target", fake.posted, fake.patched)
	}
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := fake.records[otherID]; !ok {
		t.Fatal("#16086 fold: withdraw deleted ANOTHER xpf instance's record")
	}
	if fake.deleted != 1 {
		t.Fatalf("#16086 fold: withdraw must delete only this instance's row, deleted=%d", fake.deleted)
	}
	if strings.Contains(logs.String(), "value-scoped fallback") {
		t.Fatalf("#16086 fold: no fallback may fire (or reach the other instance's "+
			"row) here, logs: %s", logs.String())
	}

	// Withdraw with ONLY the other instance's row present: still foreign.
	// No owned row, and the fallback must exclude other-instance rows, so
	// this is a no-op (the other instance still owns its record).
	fake2 := newCFFakeAPI(t)
	srv2 := httptest.NewServer(fake2.handler())
	defer srv2.Close()
	b2 := newCFTestBackend(t, srv2, fake2)
	other2 := fake2.seedRecordTTLComment("A", fqdn, addr, 300, otherTag)
	if err := b2.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("withdraw beside only other-instance row: %v", err)
	}
	if _, ok := fake2.records[other2]; !ok {
		t.Fatal("#16086 fold: fallback deleted another instance's sole record")
	}
	if fake2.deleted != 0 {
		t.Fatalf("#16086 fold: expected no deletes, deleted=%d", fake2.deleted)
	}
}

// TestCloudflareTaggedWithdrawLeavesUntaggedTwin16086: the provider
// reports this instance's tag (post-restart steady state — fresh backend,
// only the tag proves ownership). Withdraw deletes the tagged row and
// leaves the untagged foreign twin.
func TestCloudflareTaggedWithdrawLeavesUntaggedTwin16086(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	foreignID := fake.seedRecord("A", fqdn, addr)
	ownID := fake.seedRecordComment("A", fqdn, addr, b.instanceTag)

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, addr)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := fake.records[foreignID]; !ok {
		t.Fatal("#16086: withdraw deleted the untagged foreign twin")
	}
	if _, ok := fake.records[ownID]; ok {
		t.Fatal("#16086: withdraw left the tagged owned row behind")
	}
	if fake.deleted != 1 {
		t.Fatalf("#16086: withdraw must delete exactly the tagged row, deleted=%d", fake.deleted)
	}
	if strings.Contains(logs.String(), "value-scoped fallback") {
		t.Fatalf("#16086: tagged withdraw must not warn the fallback, logs: %s", logs.String())
	}
}

// TestCloudflareLegacyWithdrawValueScopedFallbackLogged16086 pins the
// documented fallback for BOTH legacy shapes — untagged and bare
// pre-fold "xpf-managed": with no instance-owned row, withdraw still
// deletes by value (else xpf's own legacy record orphans forever) and
// MUST warn.
func TestCloudflareLegacyWithdrawValueScopedFallbackLogged16086(t *testing.T) {
	for _, tc := range []struct {
		name    string
		comment string
	}{
		{name: "untagged legacy", comment: ""},
		{name: "bare-tag legacy", comment: cfLegacyComment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureWarn16086(t)
			fake := newCFFakeAPI(t)
			srv := httptest.NewServer(fake.handler())
			defer srv.Close()
			b := newCFTestBackend(t, srv, fake)

			const fqdn = "wan.example.net"
			const addr = "203.0.113.5"
			legacyID := fake.seedRecordComment("A", fqdn, addr, tc.comment)

			if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, addr)); err != nil {
				t.Fatalf("legacy withdraw: %v", err)
			}
			if _, ok := fake.records[legacyID]; ok {
				t.Fatal("#16086: legacy withdraw must still delete the row " +
					"(value-scoped fallback); skipping would orphan xpf's own record")
			}
			if fake.deleted != 1 {
				t.Fatalf("#16086: legacy fallback must delete the row, deleted=%d", fake.deleted)
			}
			if !strings.Contains(logs.String(), "value-scoped fallback") {
				t.Fatalf("#16086: legacy fallback MUST be logged, logs: %q", logs.String())
			}
		})
	}
}

// TestCloudflareStalePrevOwnership16086 is fold finding 3, across the
// prevIDs deletion arms:
//   - an untagged stale twin survives when an OWNED stale row exists
//     (cleanup deletes only the owned row, no fallback, no warning spam
//     beyond the owned path);
//   - a sole untagged stale row is deleted ONLY via the logged fallback;
//   - another instance's stale row is never a fallback candidate.
func TestCloudflareStalePrevOwnership16086(t *testing.T) {
	const fqdn = "wan.example.net"

	t.Run("untagged twin survives beside owned stale row", func(t *testing.T) {
		logs := captureWarn16086(t)
		fake := newCFFakeAPI(t)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()
		b := newCFTestBackend(t, srv, fake)

		// Tagged desired row already correct + owned stale row + untagged
		// foreign twin at the previous value.
		fake.seedRecordTTLComment("A", fqdn, "203.0.113.9", 300, b.instanceTag)
		ownedStale := fake.seedRecordTTLComment("A", fqdn, "203.0.113.5", 300, b.instanceTag)
		foreignStale := fake.seedRecordTTL("A", fqdn, "203.0.113.5", 300)

		rec := hostRecordTTL(t, fqdn, "203.0.113.9", 300)
		rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
		if err := b.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if _, ok := fake.records[ownedStale]; ok {
			t.Fatal("#10715: owned stale row must be cleaned")
		}
		if _, ok := fake.records[foreignStale]; !ok {
			t.Fatal("#16086 fold: untagged stale twin was deleted beside an owned stale row")
		}
		if fake.deleted != 1 {
			t.Fatalf("#16086 fold: only the owned stale row may be deleted, deleted=%d", fake.deleted)
		}
		if strings.Contains(logs.String(), "value-scoped fallback") {
			t.Fatalf("#16086 fold: owned cleanup must not warn the fallback, logs: %s", logs.String())
		}
	})

	t.Run("sole untagged stale row uses logged fallback", func(t *testing.T) {
		logs := captureWarn16086(t)
		fake := newCFFakeAPI(t)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()
		b := newCFTestBackend(t, srv, fake)

		fake.seedRecordTTLComment("A", fqdn, "203.0.113.9", 300, b.instanceTag)
		stale := fake.seedRecordTTL("A", fqdn, "203.0.113.5", 300)

		rec := hostRecordTTL(t, fqdn, "203.0.113.9", 300)
		rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
		if err := b.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if _, ok := fake.records[stale]; ok {
			t.Fatal("#16086 fold: sole legacy stale row must be cleaned via the fallback")
		}
		if !strings.Contains(logs.String(), "value-scoped fallback") {
			t.Fatalf("#16086 fold: stale fallback MUST be logged, logs: %q", logs.String())
		}
	})

	t.Run("other-instance stale row never fallback-deleted", func(t *testing.T) {
		captureWarn16086(t)
		fake := newCFFakeAPI(t)
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()
		b := newCFTestBackend(t, srv, fake)
		otherTag := otherInstanceTag16086(t, srv)

		fake.seedRecordTTLComment("A", fqdn, "203.0.113.9", 300, b.instanceTag)
		otherStale := fake.seedRecordTTLComment("A", fqdn, "203.0.113.5", 300, otherTag)

		rec := hostRecordTTL(t, fqdn, "203.0.113.9", 300)
		rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
		if err := b.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if _, ok := fake.records[otherStale]; !ok {
			t.Fatal("#16086 fold: another instance's stale row was fallback-deleted")
		}
		if fake.deleted != 0 {
			t.Fatalf("#16086 fold: expected no deletes, deleted=%d", fake.deleted)
		}
	})
}

// TestCloudflarePatchNeverClaimsRow16086: a PATCH of an OWNED row
// (renumber onto xpf's own prior value) must not change its comment —
// the payload carries no comment key at all.
func TestCloudflarePatchNeverClaimsRow16086(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	ownID := fake.seedRecordTTLComment("A", fqdn, "203.0.113.5", 300, b.instanceTag)

	rec := hostRecordTTL(t, fqdn, "203.0.113.9", 300)
	rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("renumber: %v", err)
	}
	if fake.patched != 1 {
		t.Fatalf("renumber must PATCH xpf's prior row, patched=%d", fake.patched)
	}
	if got := fake.records[ownID]; got.Comment != b.instanceTag {
		t.Fatalf("#16086: PATCH must preserve the owned row's tag untouched, got %q", got.Comment)
	}
}

// TestCloudflareInstanceTagStableAcrossBackends16086: the instance
// identity is stable per provider identity (not random per backend), so
// a rebuilt backend (every reconcile) still owns its records, while a
// different provider identity yields a different tag.
func TestCloudflareInstanceTagStableAcrossBackends16086(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b1 := newCFTestBackend(t, srv, fake)
	b2 := newCFTestBackend(t, srv, fake)
	if b1.instanceTag != b2.instanceTag {
		t.Fatalf("#16086 fold: instance tag must be stable across rebuilt backends: %q vs %q",
			b1.instanceTag, b2.instanceTag)
	}
	if !strings.HasPrefix(b1.instanceTag, cfInstanceTagPrefix) {
		t.Fatalf("#16086 fold: instance tag must carry the xpf-managed prefix: %q", b1.instanceTag)
	}
	other := otherInstanceTag16086(t, srv)
	if other == b1.instanceTag {
		t.Fatal("#16086 fold: a different provider identity must yield a different instance tag")
	}
}
