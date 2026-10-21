package ddns

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// backend_cloudflare_foreign_withdraw_16086_test.go: the #16086 (A10-16)
// decisive regression — DDNS withdraw must not delete foreign same-content
// records.
//
// Mechanism: Cloudflare DeleteLease used content equality as the only
// ownership proof and deleted EVERY row with Content==owned. Two publishers
// of the same name+IP (redundant appliances — the non-hostile case) meant
// xpf's withdraw also deleted the foreign publisher's identical row, and
// the victim's name died until its engine's forced refresh republished.
// Upsert compounded it: it ADOPTED an existing same-content row (the
// no-write arm), creating no row of its own, so the withdraw then deleted
// the adopted foreign row.
//
// Fix: xpf stamps cfOwnedComment on every record it CREATEs (POST) and
// tracks rows this backend instance created. Upsert's no-write arm now
// requires proven ownership; an untagged same-content row is not adopted —
// xpf POSTs its own tagged row alongside. DeleteLease deletes only
// proven-owned same-content rows, with a logged value-scoped fallback when
// NO same-content row is provably xpf's (legacy records published before
// tagging). Route 53 cannot do this at all (RRset members carry no
// provenance) — that limitation is documented on its DeleteLease.

// TestCloudflareForeignSameContentSurvivesWithdraw16086 is the issue's
// decisive check: a foreign publisher holds an unmanaged (untagged) row at
// name+value; xpf publishes the same name+IP (adopting it pre-fix), then
// xpf withdraws. The foreign row must SURVIVE, with no fallback warning
// (xpf has its own proven row to delete).
//
// FAIL-ON-REVERT: reverting UpsertLease's no-write arm to content-only (or
// DeleteLease to content-scoped) makes the foreign row the deleted one (or
// one of them): fake.deleted / the survival assertions go RED.
func TestCloudflareForeignSameContentSurvivesWithdraw16086(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	// The foreign publisher's row: same name+type+value, no xpf tag.
	foreignID := fake.seedRecordTTL("A", fqdn, addr, 300)

	rec := hostRecordTTL(t, fqdn, addr, 300)
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("publish onto foreign same-content row: %v", err)
	}
	// xpf must NOT have adopted the foreign row as proof of publish: it
	// creates its OWN tagged row, so the two coexist.
	if fake.posted != 1 {
		t.Fatalf("#16086: publish over an untagged same-content row must POST "+
			"xpf's own tagged row (posted=%d); adopting the foreign row leaves "+
			"the withdraw with nothing provably xpf's to delete", fake.posted)
	}
	if got := fake.records[foreignID]; got.Content != addr || got.Comment == cfOwnedComment {
		t.Fatalf("#16086: foreign row was claimed/rewritten by publish: %+v", got)
	}
	var ownID string
	for id, r := range fake.records {
		if id != foreignID && r.Content == addr {
			ownID = id
			if r.Comment != cfOwnedComment {
				t.Fatalf("#16086: xpf's created row must carry the ownership tag, got comment %q", r.Comment)
			}
		}
	}
	if ownID == "" {
		t.Fatal("#16086: xpf's own row missing after publish")
	}
	// A steady-state republish is still a no-op (proven-owned row present).
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if fake.posted != 1 || fake.patched != 0 {
		t.Fatalf("#16086: republish with a proven-owned row must not write: posted=%d patched=%d",
			fake.posted, fake.patched)
	}

	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, ok := fake.records[foreignID]; !ok {
		t.Fatal("#16086: withdraw deleted the FOREIGN same-content record — " +
			"the victim's name dies until its forced refresh (pre-fix behaviour)")
	}
	if _, ok := fake.records[ownID]; ok {
		t.Fatal("#16086: withdraw left xpf's own tagged record behind")
	}
	if fake.deleted != 1 {
		t.Fatalf("#16086: withdraw must delete exactly xpf's own row, deleted=%d", fake.deleted)
	}
	if strings.Contains(logs.String(), "value-scoped fallback") {
		t.Fatalf("#16086: withdraw with a proven-owned row must not take the "+
			"value-scoped fallback, logs: %s", logs.String())
	}
}

// TestCloudflareTaggedWithdrawLeavesUntaggedTwin16086: the provider reports
// the ownership tag (post-restart steady state — the backend instance is
// fresh, so only the tag, not the in-process created-set, can prove
// ownership). Withdraw deletes the tagged row and leaves the untagged
// foreign twin.
func TestCloudflareTaggedWithdrawLeavesUntaggedTwin16086(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	// Fresh backend: b.created is empty, the tag alone proves ownership.
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	foreignID := fake.seedRecord("A", fqdn, addr)
	ownID := fake.seedRecordComment("A", fqdn, addr, cfOwnedComment)

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
// documented fallback: with NO provably-owned same-content row (a record
// published before tagging existed), withdraw still deletes by value — the
// alternative orphans xpf's own legacy record forever — and it MUST warn so
// the residual foreign-same-content risk is operator-visible.
func TestCloudflareLegacyWithdrawValueScopedFallbackLogged16086(t *testing.T) {
	logs := captureWarn16086(t)
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	const addr = "203.0.113.5"
	legacyID := fake.seedRecord("A", fqdn, addr)

	if err := b.DeleteLease(context.Background(), hostRecord(t, fqdn, addr)); err != nil {
		t.Fatalf("legacy withdraw: %v", err)
	}
	if _, ok := fake.records[legacyID]; ok {
		t.Fatal("#16086: legacy untagged withdraw must still delete the row " +
			"(value-scoped fallback); skipping would orphan xpf's own record")
	}
	if fake.deleted != 1 {
		t.Fatalf("#16086: legacy fallback must delete the untagged row, deleted=%d", fake.deleted)
	}
	if !strings.Contains(logs.String(), "value-scoped fallback") {
		t.Fatalf("#16086: legacy fallback MUST be logged, logs: %q", logs.String())
	}
}

// TestCloudflarePatchNeverClaimsRow16086: a PATCH (renumber onto xpf's own
// prior value, or a TTL correction) must not stamp the ownership comment —
// the payload carries no comment key at all. If a PATCH ever claimed rows,
// the publish side would repeat the withdraw bug by tagging a row reached
// only through value equality.
func TestCloudflarePatchNeverClaimsRow16086(t *testing.T) {
	fake := newCFFakeAPI(t)
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	b := newCFTestBackend(t, srv, fake)

	const fqdn = "wan.example.net"
	ownID := fake.seedRecordTTL("A", fqdn, "203.0.113.5", 300)

	rec := hostRecordTTL(t, fqdn, "203.0.113.9", 300)
	rec.PrevAddr = netip.MustParseAddr("203.0.113.5")
	if err := b.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("renumber: %v", err)
	}
	if fake.patched != 1 {
		t.Fatalf("renumber must PATCH xpf's prior row, patched=%d", fake.patched)
	}
	if got := fake.records[ownID]; got.Comment != "" {
		t.Fatalf("#16086: PATCH claimed the row with comment %q; PATCH payloads "+
			"must carry no ownership tag", got.Comment)
	}
}
