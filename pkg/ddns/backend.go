package ddns

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
)

// backend.go (moved verbatim from pkg/dhcpserver/ddns_dns.go in #2691 P1a):
// the DNS-update backend interface (#1387 plan §4.4) plus the
// pure record-construction helpers (forward A/AAAA + reverse PTR name).
// Increment 1 ships the interface, the record model, and a fakeUpdater
// (see ddns_test.go) so the reconciler is fully unit-testable with no
// network or DNS dependency. The live rfc2136 backend is increment 2.

// LeaseDNSRecord is the forward+reverse record set the reconciler wants
// for one active lease. It is the unit both UpsertLease and DeleteLease
// operate on; a delete re-derives the SAME record from owned state so the
// backend only ever touches names this firewall created.
type LeaseDNSRecord struct {
	// FQDN is the forward name (already normalized + sanitized).
	FQDN string
	// Addr is the leased address.
	Addr netip.Addr
	// TTL is the record TTL in seconds.
	TTL int
	// ForwardType is "A" (v4) or "AAAA" (v6), derived from Addr.
	ForwardType string
	// PTRName is the reverse-zone name (in-addr.arpa / ip6.arpa).
	PTRName string
	// ClientID is the stable DHCP client identity (v4: client-id||hwaddr,
	// v6: DUID/IAID) the reconciler keys ownership on. It is the input to the
	// RFC 4701 DHCID digest computed by the live RFC 2136 backend under the
	// replace-owned conflict policy, so that an add only claims (and a delete
	// only removes) a name whose DHCID proves xpf created it. Empty when the
	// lease carried no stable identity (the backend then omits the DHCID and
	// falls back to the name-not-in-use prerequisite — it still never adopts a
	// pre-existing third-party RR). NOT part of the published forward/reverse
	// RR set; carried alongside it only to derive the ownership marker.
	ClientID string
	// PairedClientID is the client identity of the OPPOSITE family's
	// lease for the same device + FQDN in this reconcile pass, paired
	// by sameDeviceClient at desired-set build time (#14995). The
	// backend digests it (device-canonicalized) into the sibling
	// DHCID the cross-family add must prove on the wire. Empty when
	// no same-device sibling is desired this pass. Distinct from
	// SiblingClientID (the durable store sibling): PairedClientID
	// covers the FIRST pass, before any store row exists.
	PairedClientID string
	// PrevAddr is the PREVIOUS published rdata for a SELF-OWNED Surface A
	// record (#3739), threaded from publishLocked (seeded across a restart from
	// the durable store's AddrText). It lets a self-owned backend do a
	// VALUE-SPECIFIC in-place replace — touch ONLY xpf's own prior value and add
	// the new one — instead of clobbering the whole name / RRset, which would
	// destroy a co-resident FOREIGN A/AAAA at a shared name. Zero (invalid) on a
	// first publish or when the prior value is genuinely unknown; the backend
	// then does an ADDITIVE insert/create that coexists with any foreign record
	// (strictly better than clobbering it). Ignored on the DHCP-lease path (that
	// path re-derives the exact delete from the owned tuple + DHCID) and by
	// non-self-owned backends.
	PrevAddr netip.Addr
	// PrevAddrs is the full candidate cleanup set for a Surface A publish
	// recovering from an ambiguous prior publish (#15225 A40-02): the
	// confirmed prior AND the prior desired value whose wire outcome is
	// unknown. When set, it supersedes PrevAddr — every backend removes
	// every candidate != Addr. Empty on ordinary publishes (PrevAddr alone).
	PrevAddrs []netip.Addr
	// KeepForwardDHCID, when true on a DeleteLease, tells the replace-owned
	// RFC 2136 backend to delete the forward A/AAAA but NOT the shared RFC 4701
	// DHCID — because ANOTHER owned record still shares this FQDN+ClientID
	// (a dual-stack client whose A and AAAA carry one DHCID). Deleting the
	// shared DHCID on a partial dual-stack teardown would (1) leave the
	// surviving family's record DHCID-unprotected (a hijack window, RFC 4703)
	// and (2) make the eventual delete of the surviving record fail its
	// DHCID-match prerequisite — leaking it on the wire (#2700). The DHCID-match
	// PREREQUISITE is still sent (the delete stays ownership-guarded); only the
	// DHCID's removal from the zone is suppressed. The manager (deleteOwnedLocked)
	// sets this from a scan of the ownership store. Ignored on UpsertLease and by
	// non-replace-owned / no-DHCID delete paths. Defaults false (delete the
	// DHCID with the last record under the name — the pre-#2700 behaviour).
	KeepForwardDHCID bool
	// SiblingFamilyOwned, when true on a DeleteLease, tells the backend that
	// ANOTHER owned record shares this record's FQDN under the OPPOSITE address
	// family — a dual-stack same-name scope (#3738). It matters ONLY to a backend
	// whose sole withdraw verb is HOST-GRANULAR: DuckDNS `clear=true` ("if set to
	// true, the update will ignore all ip's and clear both your records" —
	// duckdns.org/spec.jsp) and dyndns2 `offline=YES` both take down the WHOLE
	// hostname (both the A and the AAAA). Firing that verb to withdraw ONE family
	// while its sibling is still live would blackhole the sibling — the sibling-
	// family availability bug. When this is set, such a backend does the LEAST-
	// DESTRUCTIVE thing: it SKIPS the wire delete (a logged no-op returning nil),
	// preserving the sibling; the withdrawn family's record is left in place
	// (stale) rather than the live sibling being taken down. The manager still
	// drops this family's ownership, so a subsequent full teardown (the LAST
	// family, no sibling left) fires the host-wide verb and cleans both — no
	// permanent orphan on teardown. Backends with a PER-FAMILY delete (rfc2136 /
	// cloudflare / route53 / bind) touch only the requested A/AAAA RRset and
	// IGNORE this flag on DeleteLease. Set by withdrawOwnedLocked from a scan of
	// the ownership store (same {provider, FQDN} under the opposite family).
	// Defaults false (single-family / full-teardown — the host-wide verb is
	// correct and issued).
	//
	// On UpsertLease the same flag carries the #14604 meaning (a DIFFERENT
	// predicate): the manager already owns a record at this forward name
	// under the opposite family (durable store, or this pass's write-ahead
	// intent for the sibling), so the name is xpf-owned, not foreign. The
	// RFC 2136 backend's skip-existing/strict-fail guard then stays
	// per-type (RRsetNotUsed) for that legitimate sibling publish instead
	// of refusing the second family with the name-level NameNotUsed guard.
	// Set by Manager.upsertLocked from its ownership scan — deliberately
	// NOT set anywhere on a DeleteLease-construction path for this meaning.
	SiblingFamilyOwned bool
	// SiblingClientID is the client identity of the manager-owned
	// opposite-family sibling record, threaded on UpsertLease only
	// (#14995). The RFC 2136 backend digests it into the sibling's
	// DHCID and requires that exact DHCID on the wire (RFC 2136
	// §2.4.2 value-dependent prerequisite) before it downgrades any
	// guard for a cross-family publish — so the store flag alone
	// never authorizes the claim, and a stale write-ahead intent
	// whose wire add never landed cannot hijack the name. Empty
	// means no proven sibling: every guard stays name-level.
	SiblingClientID string
}

// DNSUpdater is the pluggable DNS-update backend (plan §4.4). The
// reconciler holds one and never assumes a concrete implementation, so
// the live rfc2136 backend (increment 2), a future Kea-D2 shim, and the
// test fakeUpdater are interchangeable.
//
// Both methods MUST be idempotent: UpsertLease is called every reconcile
// for every still-active lease, and DeleteLease may be retried.
type DNSUpdater interface {
	UpsertLease(ctx context.Context, rec LeaseDNSRecord) error
	DeleteLease(ctx context.Context, rec LeaseDNSRecord) error
}

// nopUpdater is the no-op backend used when no live DNSUpdater is wired
// (increment 1 defers the live rfc2136 backend; NewManager substitutes
// this when nil is passed). Every call is a LOGGED no-op rather than a
// crash: a missing backend must never turn lease processing into a panic.
// Both methods return nil so the reconciler treats the (skipped) record as
// processed — it does NOT record ownership for an upsert that never reached
// a real backend (upsertLocked records ownership only on a nil-error return,
// and a no-op upsert that recorded ownership would let a later real backend
// believe it already published the record). To keep the never-publish/never-
// orphan invariants intact, the nopUpdater reports success so reconcile does
// not wedge, and the manager-level guard (see Manager.upsertLocked) is
// what keeps a no-op upsert from recording phantom ownership.
type nopUpdater struct{}

func (nopUpdater) UpsertLease(_ context.Context, rec LeaseDNSRecord) error {
	slog.Debug("ddns: no DNS backend wired; skipping upsert (no-op)",
		"fqdn", rec.FQDN, "addr", rec.Addr.String(), "type", rec.ForwardType)
	return nil
}

func (nopUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	slog.Debug("ddns: no DNS backend wired; skipping delete (no-op)",
		"fqdn", rec.FQDN, "addr", rec.Addr.String(), "type", rec.ForwardType)
	return nil
}

// isNopUpdater reports whether the manager has no live backend wired, so the
// reconciler can avoid recording phantom ownership for a no-op upsert.
func isNopUpdater(u DNSUpdater) bool {
	_, ok := u.(nopUpdater)
	return ok
}

// buildLeaseRecord constructs the forward+reverse record for an address +
// FQDN + TTL. ttl <= 0 falls back to defaultDDNSTTL. Returns an error for
// an invalid address so a malformed lease row never produces a record.
func buildLeaseRecord(fqdn, addr string, ttl int) (LeaseDNSRecord, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return LeaseDNSRecord{}, fmt.Errorf("ddns: invalid lease address %q: %w", addr, err)
	}
	a = a.Unmap()
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	rec := LeaseDNSRecord{
		FQDN:    fqdn,
		Addr:    a,
		TTL:     ttl,
		PTRName: reversePTRName(a),
	}
	if a.Is4() {
		rec.ForwardType = "A"
	} else {
		rec.ForwardType = "AAAA"
	}
	return rec, nil
}

// reversePTRName builds the reverse-DNS PTR name for an address.
//
// Byte-order note (plan §4.5): this is STRING manipulation on the textual
// address form, NOT the native-endian __be32 BPF-map convention. For IPv4
// the four decimal octets are reversed and suffixed .in-addr.arpa; for
// IPv6 the 32 nibbles (low-to-high) are reversed and suffixed .ip6.arpa.
// Deliberately independent of the dataplane byte-order habit — getting it
// "consistent with the map" would be wrong for DNS.
func reversePTRName(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		o := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", o[3], o[2], o[1], o[0])
	}
	b := a.As16()
	// 32 nibbles, least-significant first.
	var sb strings.Builder
	sb.Grow(len(b)*4 + len("ip6.arpa"))
	for i := len(b) - 1; i >= 0; i-- {
		lo := b[i] & 0x0f
		hi := b[i] >> 4
		fmt.Fprintf(&sb, "%x.%x.", lo, hi)
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}
