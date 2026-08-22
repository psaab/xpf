package ddns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// errDDNSStateCorrupt / errDDNSStateUnsupportedVersion classify a load failure
// of the ownership store so the manager can FAIL CLOSED rather than silently
// reset to an empty store (#2650). A corrupt or unknown-future-version store is
// the only authority for the records this firewall published; treating it as
// empty would (a) forget what we own — leaking previously-published records into
// authoritative DNS forever — and (b) let a later publish RE-CLAIM a name a peer
// owns, since the lost DHCID ownership records can no longer prove or deny our
// authorship. The reconciler refuses destructive AND additive ops while the load
// is unresolved (see Manager.degraded). These wrap with %w so the caller uses
// errors.Is to decide the degraded reason.
var (
	errDDNSStateCorrupt            = errors.New("ddns: ownership state file is corrupt")
	errDDNSStateUnsupportedVersion = errors.New("ddns: ownership state file has an unsupported version")
	// errDDNSStateTooLarge classifies an ownership file whose on-disk size
	// exceeds maxDDNSStateBytes (#5571, CWE-770 unbounded resource consumption).
	// It WRAPS errDDNSStateCorrupt so an over-bound file engages the EXACT
	// fail-closed posture the loader already uses for an unparseable/bad-version
	// file (quarantine aside + durable degraded marker via loadStateOrDegrade) —
	// an oversized/corrupt canonical file is no more trustworthy than a malformed
	// one. Keeping it a DISTINCT sentinel (matched separately with errors.Is) lets
	// a test prove the read was refused by the SIZE bound BEFORE buffering the
	// whole file, not merely by a JSON parse error after a full read.
	errDDNSStateTooLarge = fmt.Errorf("ddns: ownership state file exceeds the maximum size: %w", errDDNSStateCorrupt)
)

// state.go (moved verbatim from pkg/dhcpserver/ddns_state.go in #2691 P1a):
// the persistent ownership state store for #1387 DDNS — the
// PROTECTION BOUNDARY for the never-delete-a-record-xpf-did-not-create
// invariant (plan §4.2, §5 invariant 1, risk table "cardinal sin"). Every
// record this firewall publishes is recorded here with the EXACT
// (name, type, address) it wrote; the reconciler issues a delete only for
// an entry present in this store, re-deriving that exact tuple. Records
// not in the store are never touched.
//
// Persisted as JSON via fsatomic.WriteFileDurable (fsync-on-write): the
// reconciler is slow-path, so durability per write is affordable and the
// store must survive restart / failover to keep the boundary intact.
//
// DURABILITY CONTRACT (#2662): ownership of a published RR is durable BEFORE
// (or at) the wire add, never only after the whole reconcile pass. upsertLocked
// WRITE-AHEADs the ownership intent (PTRPending=true) and save()s it BEFORE
// calling UpsertLease, then confirms (clears PTRPending) with a second save
// after a fully-successful add. This closes the crash-after-add orphan window:
// a crash / kill / disk-full between the wire add and any later save finds the
// record already owned, so a later reconcile re-adds (idempotent) or a release
// deletes it (deleting a maybe-uncreated RR is safe — the #2648 DHCID-match /
// exact-RR delete prerequisite fails on a non-existent RR, a no-op). A refused
// add removes the pre-written intent (no phantom ownership); a failed pre-write
// suppresses the publish (record reported not safely owned). Deletes do not
// need write-ahead: a delete leaves "ownership without a live RR", which the
// idempotent re-delete on the next pass self-heals — never an orphaned live RR.

// defaultDDNSStatePath is the on-disk location of the ownership store.
const defaultDDNSStatePath = "/var/lib/xpf/dhcp-ddns-state.json"

// defaultDDNSTTL is the record TTL when the operator does not set one.
const defaultDDNSTTL = 300

// Family is the address family a scope/record applies to (#2691 P1b,
// plan §5.4). It is the FIRST and load-bearing ScopeKey axis: v4 and v6
// ownership/policy are INDEPENDENT (#2663), so a v4 conflict can never block
// a v6 publish, and the two families may target different domains / servers /
// TSIG keys / TTLs. The integer values mirror the engine's existing 4/6
// convention (ownedRecord.Family) so the scope and the record agree.
type Family int

const (
	// FamilyV4 is the IPv4 (A / in-addr.arpa) family.
	FamilyV4 Family = 4
	// FamilyV6 is the IPv6 (AAAA / ip6.arpa) family.
	FamilyV6 Family = 6
)

// familyOf maps the engine's int family (4/6) to a Family. Any other value
// (should not happen for a built record) maps to FamilyV4 as the safe
// default — the field is informational on the scope key, the record's own
// ForwardType/Address remain authoritative for the wire op.
func familyOf(f int) Family {
	if f == 6 {
		return FamilyV6
	}
	return FamilyV4
}

// ScopeKey is the unifying ownership/scope primitive (#2691 P1b, plan §5.4).
// It replaces the flat identity|address ownership key with a structured scope
// so the SAME firewall can independently own records across families,
// interfaces, routing-instances, and HA redundancy groups without collision:
//
//   - Family         — inet | inet6 (#2663: independent v4/v6 policy + ownership).
//   - Interface      — the bound interface (e.g. ge-0-0-2.50); "" = a global
//     lease policy not bound to a specific interface (today's Surface B).
//   - Unit           — the logical unit (sub-interface) the scope applies to.
//   - RoutingInstance — the VRF / routing-instance the update egresses from
//     (#2665 source binding selects the transport from this).
//   - RGOwner        — the redundancy-group id that owns this scope (#2664:
//     the per-RG HA writer gate keys on this; 0 = unscoped / standalone).
//   - PolicyID       — which provider/profile applies (P2/P3 catalog; "" today).
//   - FQDN           — the published forward name for a Surface A router record
//     (#2903). The published NAME is part of the scope IDENTITY for Surface A:
//     a scope owns exactly ONE record at a fixed FQDN, so changing the
//     configured hostname for a binding is a NEW scope (old name withdrawn,
//     new name published) rather than an in-place name overwrite that orphans
//     the old RR. It is EMPTY for the DHCP-lease path (Surface B), where the
//     published name is the client-supplied host part carried on the owned
//     record, not a per-scope identity — so a lease scope's key is unchanged
//     and the pre-#2903 on-disk shape for leases is preserved.
//
// ScopeKey is a comparable struct so it is usable directly as a map key. The
// zero value (FamilyV4-via-familyOf, all-empty) is the BACKWARD-COMPATIBLE
// global lease scope: an ownership record written before P1b (no scope fields
// on disk) decodes to a zero ScopeKey, and ownedRecordKey(zeroScope, id, addr)
// reproduces the EXACT pre-P1b "identity|address" key — so an old store loads
// and reconciles with no migration (plan §11 Q7: fail-open-to-existing).
type ScopeKey struct {
	Family          Family
	Interface       string
	Unit            int
	RoutingInstance string
	RGOwner         int
	PolicyID        string
	FQDN            string
}

// scopePrefix is the stable, deterministic textual encoding of a ScopeKey for
// the in-memory map key + the on-disk JSON sort order. The ZERO scope encodes
// to the EMPTY string, so ownedRecordKey(zeroScope, id, addr) == the pre-P1b
// "id|addr" key byte-for-byte: a pre-P1b store (no scope fields) loads and is
// reconciled identically (no migration, no churn). A NON-zero scope prefixes
// the key with its fields so two scopes for the same name+address never
// collide (the #2663 / #2664 requirement: a v4-scoped and a v6-scoped publish,
// or an RG0-owned and RG1-owned publish, of the same host are distinct owned
// records).
//
// FQDN (#2903) is appended ONLY when non-empty: a Surface B (DHCP-lease) scope
// leaves FQDN empty, so its prefix is byte-for-byte the pre-#2903 encoding and
// the on-disk lease store loads unchanged. A Surface A router scope sets FQDN,
// so the published NAME is part of the scope identity — changing the configured
// hostname yields a DIFFERENT prefix, which the reconciler treats as a new
// scope (old name withdrawn via the gone-from-config sweep, new name published)
// instead of an in-place name overwrite that would orphan the old RR.
func (s ScopeKey) scopePrefix() string {
	if s == (ScopeKey{}) {
		return ""
	}
	// Fixed field order; the family int (4/6) keeps it human-readable. The
	// terminating "#" separates the scope prefix from the identity|address
	// suffix so a scope value containing '|' cannot alias an identity.
	var sb strings.Builder
	fmt.Fprintf(&sb, "f%d/if=%s/u=%d/ri=%s/rg=%d/pid=%s",
		int(s.Family), s.Interface, s.Unit, s.RoutingInstance, s.RGOwner, s.PolicyID)
	// Append the FQDN axis only when set so an FQDN-less (lease) scope keeps its
	// pre-#2903 prefix byte-for-byte. "/fqdn=" cannot alias an earlier field
	// (pid is the last fixed field and the value cannot contain "/fqdn=").
	if s.FQDN != "" {
		fmt.Fprintf(&sb, "/fqdn=%s", s.FQDN)
	}
	sb.WriteByte('#')
	return sb.String()
}

// ownedRecord is the exact record set this firewall published for one
// owner identity. A delete re-derives precisely these fields; a mismatch
// (address moved, name changed) means the desired and owned differ and
// the reconciler must clean the OLD owned tuple before adding the new one.
type ownedRecord struct {
	Family      int    `json:"family"`       // 4 or 6
	Identity    string `json:"identity"`     // stable owner id (subnet+client/duid)
	SubnetID    string `json:"subnet_id"`    // pool/subnet metadata
	Address     string `json:"address"`      // textual leased address
	FQDN        string `json:"fqdn"`         // forward name published
	ForwardType string `json:"forward_type"` // "A" | "AAAA"
	PTRName     string `json:"ptr_name"`     // reverse name published
	TTL         int    `json:"ttl"`          // TTL written
	OwnerID     string `json:"owner_id"`     // deterministic node-stable watermark
	// ClientID is the RAW DHCP client identity (v4 client-id||hwaddr, v6
	// DUID/IAID) — the input to the RFC 4701 DHCID digest the live RFC 2136
	// backend writes under replace-owned. It is stored verbatim (NOT the
	// address-fallback identity used for keying) so a later delete recomputes
	// the SAME DHCID and the DHCID-match prerequisite proves xpf created the
	// record before it is removed. Empty when the lease had no stable
	// identity (the backend then publishes no DHCID and uses the
	// name-not-in-use add prerequisite instead). Omitted from older stores;
	// an absent value degrades to the no-DHCID path on delete (safe — the
	// exact-RR delete still only removes the firewall's own tuple).
	ClientID string `json:"client_id,omitempty"`
	// AddrText is the textual rdata (the published address) for a Surface A
	// router record (#2691 P2). Surface A keys ownership on {scope, fixed
	// identity, ""} so a scope owns exactly ONE record and an address change
	// REPLACES it in place (no stale old-address entry, never a withdraw-then-
	// add gap) — which means the keying Address field is "" and the actual
	// published address must be carried separately. The DHCP-lease path leaves
	// this empty (its Address field IS the rdata). Omitted from the JSON when
	// empty so a pre-P2 / lease store shape is unchanged.
	AddrText string `json:"addr_text,omitempty"`
	// PTRPending marks an ownership record whose forward A/AAAA was published
	// but whose reverse PTR add failed with a non-skippable (transient) error
	// (#2661). Ownership is still recorded so the live forward is tracked +
	// cleanable (never orphaned), and this flag tells the reconciler the PTR
	// is still owed: a record with PTRPending=true is NOT considered settled,
	// so the next reconcile re-runs UpsertLease (an idempotent forward re-add)
	// to re-attempt the PTR. Cleared once the PTR finally publishes. Omitted
	// from the JSON when false; an absent value (older stores, fully-published
	// records) degrades to "settled", the safe default.
	PTRPending bool `json:"ptr_pending,omitempty"`
	// BackendFingerprint is a STABLE, NON-SECRET fingerprint of the provider
	// backend ENDPOINT this record was published through (#3735): a hash of the
	// backend TYPE + server/host + zone + hosted-zone + region + generic URL
	// template, computed by backendFingerprint (surface_a.go). It carries NO
	// credentials (TSIGSecret / Password / APIToken / AWSSecretAccessKey are all
	// config.Secret and are deliberately excluded), so persisting it does NOT
	// reopen the #2053 plaintext-secret-on-disk disclosure class — nothing
	// sensitive is ever hashed in or written out.
	//
	// Its sole purpose is to make a provider IDENTITY change DETECTABLE so the
	// old record is not silently mishandled: a provider RENAME to a different
	// endpoint (H01), an in-place server/zone edit under the same provider name
	// (H02), or a removed-binding withdraw after a provider edit (H03). When the
	// stored fingerprint no longer matches the current provider's, the record was
	// published at a DIFFERENT endpoint than the one now configured for the same
	// scope/name — so it cannot be adopted-in-place, overwritten, or withdrawn
	// through the current catalog without either losing cleanup authority or
	// deleting at the WRONG endpoint. The reconciler then KEEPS ownership and
	// raises a loud operator alarm (auto-withdrawal of the old endpoint is
	// DEFERRED — the old creds are redacted config.Secret and the old endpoint is
	// usually decommissioned; see the pkg/ddns README + #3735). Omitted from the
	// JSON when empty; an absent value (a pre-#3735 store, or a nil-provider test)
	// degrades to "unknown" and is compared as "cannot determine a mismatch" —
	// never a false alarm.
	BackendFingerprint string `json:"backend_fingerprint,omitempty"`
	// PublishPending marks a Surface A ownership record whose DESIRED address was
	// durably written-ahead but whose wire publish has NOT yet been CONFIRMED
	// (#5285). The pre-#5285 Surface A publish persisted the desired address into
	// the SOLE ownership row BEFORE the provider I/O with no pending bit and no
	// retained prior value, so an abrupt CRASH between state.save and the wire add
	// left the store falsely reporting the new address as published (the in-process
	// rollback in publishLocked never ran): on restart the unchanged-owned skip
	// suppressed recovery, public DNS stayed at the OLD value while the appliance
	// reported the NEW one, and the old value's cleanup key was destroyed. With
	// PublishPending=true the record is NOT settled — its AddrText holds the DESIRED
	// value not yet on the wire and PriorAddrText retains the last CONFIRMED value —
	// so the next reconcile MUST re-run the provider I/O (it does not take the
	// unchanged-owned skip, see reconcileScopeLocked's pendingRecovery) and keeps the
	// prior value's cleanup key. Cleared by the confirm-save AFTER a successful wire
	// add. Mirrors the DHCP-lease path's PTRPending durable-pending idiom. DISTINCT
	// from #2662 (which persists the intent BEFORE the add to close the end-of-pass
	// orphan window, but writes the desired address as though confirmed): #5285 adds
	// the desired-vs-confirmed distinction so a crash in that same window cannot be
	// mistaken for a confirmed publish. Omitted from the JSON when false; an absent
	// value (a pre-#5285 store, a settled record) degrades to "settled", the safe
	// default.
	PublishPending bool `json:"publish_pending,omitempty"`
	// PriorAddrText is the last CONFIRMED published rdata, retained while
	// PublishPending is true (#5285). During crash recovery it is threaded to the
	// backend as the value-specific replace target (LeaseDNSRecord.PrevAddr) so the
	// self-owned in-place replace touches xpf's REAL live value — never the phantom
	// desired value that AddrText holds until the wire confirms — and so the stale
	// prior record is still cleanable/reclaimable (no misdirection, no lost cleanup
	// key). Released (set "") by the confirm-save once the wire add succeeds. Omitted
	// from the JSON when empty.
	PriorAddrText string `json:"prior_addr_text,omitempty"`
	// Scope is the ScopeKey this record belongs to (#2691 P1b, plan §5.4). It
	// is the per-family / per-interface / per-RG / per-routing-instance scope
	// the record was published under, so two scopes for the same name+address
	// (a v4 and a v6 publish, or an RG0-owned and RG1-owned publish) are
	// distinct owned entries. It is a POINTER so the JSON OMITS it entirely for
	// the zero (global lease) scope: a pre-P1b store has no "scope" key, which
	// decodes to a nil pointer, and a P1b global-scope record writes none
	// either — so the on-disk shape is unchanged for the existing Surface-B
	// path and there is no migration (plan §11 Q7: fail-open-to-existing). The
	// in-memory key uses scopeOf(r) which treats nil as the zero ScopeKey,
	// reproducing the pre-P1b "identity|address" key byte-for-byte.
	Scope *ScopeKey `json:"scope,omitempty"`
}

// scopeOf returns the record's scope as a value, treating a nil pointer (the
// zero/global lease scope, and every pre-P1b record) as the zero ScopeKey.
func (r ownedRecord) scopeOf() ScopeKey {
	if r.Scope == nil {
		return ScopeKey{}
	}
	return *r.Scope
}

// withScope returns r with its Scope set: a NON-zero scope is stored as a
// pointer; the zero scope clears it to nil so the JSON stays pre-P1b-clean and
// the in-memory key stays the global "identity|address" form.
func (r ownedRecord) withScope(s ScopeKey) ownedRecord {
	if s == (ScopeKey{}) {
		r.Scope = nil
		return r
	}
	sc := s
	r.Scope = &sc
	return r
}

// ownedRecordKey is the in-memory map key for an owned record: the record's
// SCOPE (#2691 P1b) plus a lease's stable identity plus its address, so the
// same client moving to a new address is a distinct entry (cleanup of the old
// address is explicit), AND the same identity+address published under two
// different scopes (e.g. a v4 vs v6 family, or an RG0 vs RG1 owner) are
// distinct entries that never collide. The ZERO scope yields the EXACT
// pre-P1b "identity|address" key (scopePrefix() == ""), so a pre-P1b store
// loads and reconciles unchanged.
func ownedRecordKey(scope ScopeKey, identity, address string) string {
	return scope.scopePrefix() + identity + "|" + address
}

// WireRRClaim identifies ONE forward DNS resource record that a DDNS ownership
// surface currently claims: the CANONICAL FQDN, the forward record type
// ("A"/"AAAA"), and the textual rdata (the published IP). Two owned records that
// produce an EQUAL WireRRClaim CO-OWN one wire RR — whether they are two DDNS
// scopes within ONE surface (the #5709 lease-vs-lease case) or one record from
// EACH of the two ownership surfaces (the Surface B DHCP lease store in Manager
// and the Surface A router/interface store in SurfaceAManager — the #5748
// cross-surface case). Because the reverse PTR derives deterministically from
// (FQDN, rdata), an equal forward claim implies an equal PTR RR, so matching the
// forward tuple captures both directions (#5709).
//
// It is the cross-surface interchange type: each manager publishes a LOCK-FREE
// snapshot of its own claims (Manager.WireRRClaims / SurfaceAManager.WireRRClaims,
// backed by an atomic.Pointer) that the OTHER surface's teardown guard consults
// WITHOUT taking the publisher's mutex. That lock-free read is what makes the
// two guards deadlock-free despite each holding its own manager's lock (#5748).
type WireRRClaim struct {
	FQDN        string // canonical form (dnsCanonicalFQDN)
	ForwardType string // "A" | "AAAA"
	Rdata       string // textual published address (the rdata)
}

// wireRRClaim builds a canonicalized WireRRClaim from a name, forward type, and
// textual rdata. The FQDN is DNS-canonicalized and the rdata is normalized
// through netip so the two ownership surfaces — whose rdata reaches this helper
// via DIFFERENT code paths (a Kea memfile string on the lease side, a
// netip-formatted AddrText on the Surface A side) — compare EQUAL for the same
// address even if their textual forms differ (e.g. an IPv6 address written
// expanded vs compressed). An unparseable rdata is kept verbatim (best effort —
// a stored address is normally well-formed). Empty rdata yields the zero-Rdata
// claim; callers skip records with no rdata (a rdata-less claim must never
// co-match another rdata-less one).
func wireRRClaim(fqdn, forwardType, rdata string) WireRRClaim {
	norm := rdata
	if a, err := netip.ParseAddr(rdata); err == nil {
		norm = a.Unmap().String()
	}
	return WireRRClaim{
		FQDN:        dnsCanonicalFQDN(fqdn),
		ForwardType: forwardType,
		Rdata:       norm,
	}
}

// ddnsState is the in-memory + on-disk ownership store. records is keyed
// by ownedRecordKey. It is NOT goroutine-safe on its own; the DDNS
// manager serializes all access under its own mutex.
type ddnsState struct {
	path    string
	records map[string]ownedRecord
	// writeFile is the durable-write seam. Production uses
	// fsatomic.WriteFileDurable (fsync-on-write); tests inject a recorder
	// that can fail/panic AFTER a DNS add to prove the crash-after-add
	// orphan window is closed (#2662). Nil selects the production path.
	writeFile func(path string, data []byte, perm os.FileMode) error
}

// ddnsStateFile is the serialized on-disk shape (a stable, sorted slice
// so the JSON diffs cleanly across reconciles).
type ddnsStateFile struct {
	Version int           `json:"version"`
	Records []ownedRecord `json:"records"`
}

const ddnsStateVersion = 1

// The read bound below (#5571, CWE-770) caps how much of the durable ownership
// file loadDDNSState will pull into memory BEFORE any JSON/version/semantic
// validation runs. Without it a single os.ReadFile of a very large canonical
// file — left by a prior crash, filesystem corruption, an administrative
// restore, or a future producer defect — drives input-proportional heap growth,
// GC pressure, or OOM during daemon STARTUP, exactly when the control plane must
// recover, and BEFORE the fail-closed corruption posture can engage. The bound
// is DERIVED (not a magic number) from the legitimate maximum ownership state:
//
//   maxDDNSStateBytes = maxDDNSStateRecords * maxDDNSStateRecordBytes + envelope
//
// so a legitimate store always loads while an oversized/corrupt one is refused
// before it is buffered whole.

// maxDDNSStateRecords is the generous legitimate ceiling on ownership records.
// The store carries at most one record per DDNS-published DHCP lease (Surface B)
// plus a handful of per-interface router records (Surface A), so its record
// count tracks the DHCP lease count. 65,536 is one ENTIRE /16 subnet fully
// leased with a DDNS record for every lease — already far beyond any realistic
// vSRX-class DDNS deployment (production stores hold tens to low thousands). It
// is the record-count anchor for the byte bound below, not an enforced count cap.
const maxDDNSStateRecords = 1 << 16 // 65,536

// maxDDNSStateRecordBytes is the generous per-record ceiling on the pretty-
// printed (2-space-indented, the save() format) JSON of one ownedRecord. A
// worst-case record with every optional field at its protocol maximum — FQDN
// 253, PTR name ~255, DUID-hex client-id ~260, identity/subnet/owner-id, a
// nested scope carrying its own 253-octet FQDN, the backend fingerprint — plus
// all JSON keys and indentation serializes to ~1.5 KiB; 2 KiB carries ~33%
// headroom so no legitimate record is ever over-counted.
const maxDDNSStateRecordBytes = 2 << 10 // 2 KiB

// maxDDNSStateBytes is the hard cap on the ownership file loadDDNSState will read
// into memory (#5571). It is maxDDNSStateRecords * maxDDNSStateRecordBytes plus a
// small envelope for the "version" field, the JSON array brackets, and top-level
// indentation. A file larger than this cannot be a legitimate store, so it is
// refused (classified errDDNSStateTooLarge -> fail-closed corrupt) before being
// buffered — converting an unbounded, input-proportional allocation into a
// bounded, constant one.
const maxDDNSStateBytes = maxDDNSStateRecords*maxDDNSStateRecordBytes + 4<<10 // 128 MiB + 4 KiB

// readBoundedStateFile reads the ownership store at path but REFUSES to buffer
// more than maxDDNSStateBytes (#5571, CWE-770). It opens the file and stats it
// first, rejecting an over-bound size BEFORE any allocation (so an arbitrarily
// large — GiB/TiB — corrupt file costs one stat, not a full read). It then reads
// through io.LimitReader(f, maxDDNSStateBytes+1) with a sentinel byte so a file
// that GREW after the stat, or whose stat size is unreliable (a pipe / special
// file), still cannot be buffered past the cap. An over-bound file returns an
// error wrapping errDDNSStateTooLarge (which wraps errDDNSStateCorrupt) so the
// caller fails closed and quarantines it exactly like an unparseable store. A
// not-exist error is returned verbatim (wrapping os.ErrNotExist) so the caller
// treats a missing file as a clean first-run empty store.
func readBoundedStateFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // includes os.ErrNotExist, classified by the caller
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil && fi.Size() > maxDDNSStateBytes {
		return nil, fmt.Errorf("ddns state %s size %d exceeds max %d bytes: %w",
			path, fi.Size(), maxDDNSStateBytes, errDDNSStateTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDDNSStateBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxDDNSStateBytes {
		return nil, fmt.Errorf("ddns state %s exceeds max %d bytes: %w",
			path, maxDDNSStateBytes, errDDNSStateTooLarge)
	}
	return data, nil
}

// loadDDNSState reads the ownership store from path. A missing file yields an
// empty store (first run, error nil). A CORRUPT or UNKNOWN-VERSION file is
// FAIL-CLOSED (#2650): the returned store is empty, but the returned error is
// non-nil and classifiable (errors.Is errDDNSStateCorrupt /
// errDDNSStateUnsupportedVersion) so the manager enters a DEGRADED state and
// refuses to publish or withdraw any record until the operator resolves it.
//
// Why fail closed, not fail open: this store is the ONLY authority for the
// records this firewall published and the DHCID ownership it can prove. Silently
// resetting to empty both forgets what we own (the cleanup half of the feature is
// lost — stale A/AAAA/PTR records leak into authoritative DNS forever) AND lets a
// later publish overwrite a record a PEER owns, because the lost ownership/DHCID
// state can no longer veto the re-claim. Returning the empty store keeps the
// manager constructible (the daemon still starts), but the non-nil error gates
// every reconcile op off until the state is trustworthy again.
//
// A read error other than not-exist (permission / IO) is also returned so the
// manager degrades — an unreadable store is no more trustworthy than a corrupt
// one — but it is NOT classified corrupt/unsupported (no quarantine: the bytes
// may be fine and re-readable, so do not move the file out from under a transient
// fault).
//
// The read is BOUNDED (#5571, CWE-770): an ownership file larger than
// maxDDNSStateBytes is refused BEFORE it is buffered whole (via
// readBoundedStateFile: an os.Stat pre-check plus an io.LimitReader sentinel) so
// a very large / corrupt canonical file cannot drive input-proportional heap
// growth or OOM during startup. Over-bound is classified errDDNSStateTooLarge —
// which wraps errDDNSStateCorrupt — so it engages the SAME fail-closed quarantine
// posture as an unparseable file.
func loadDDNSState(path string) (*ddnsState, error) {
	s := &ddnsState{path: path, records: map[string]ownedRecord{}}
	data, err := readBoundedStateFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		// An over-bound file is classified corrupt (errDDNSStateTooLarge wraps
		// errDDNSStateCorrupt) so the manager fails closed and quarantines it,
		// exactly like an unparseable store — a huge/corrupt canonical file is no
		// more trustworthy than a malformed one and must never be buffered whole
		// or acted on. Return it unwrapped so the classification survives.
		if errors.Is(err, errDDNSStateCorrupt) {
			return s, err
		}
		return s, fmt.Errorf("read ddns state %s: %w", path, err)
	}
	var f ddnsStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		// Corrupt store: return the empty store + a corrupt-classified error so
		// the manager fails closed (refuses all record ops) and quarantines the
		// bad file. We must NOT silently treat this as an empty trusted store:
		// that would forget every owned record (permanent stale-record leak) and
		// permit re-claiming a peer-owned name.
		return s, fmt.Errorf("parse ddns state %s: %w: %v", path, errDDNSStateCorrupt, err)
	}
	// Version validation: an unknown (future / unsupported) non-zero version is a
	// format we cannot safely decode — its records may carry a different tuple
	// shape, so trusting them could drive WRONG-tuple deletes, and ignoring them
	// loses ownership. Fail closed exactly like a corrupt store. Version 0 is
	// tolerated as a pre-versioning / zero-value store (the field was absent or
	// defaulted).
	if f.Version != 0 && f.Version != ddnsStateVersion {
		return s, fmt.Errorf("ddns state %s has version %d (want %d): %w",
			path, f.Version, ddnsStateVersion, errDDNSStateUnsupportedVersion)
	}
	// Semantic validation (#4909): valid-JSON, valid-version is NOT enough. A
	// record whose textual address does not parse is corrupt in a way the
	// reconciler cannot recover — deleteOwnedLocked cannot reconstruct the exact
	// wire RR, so it silently dropped the in-memory entry WITHOUT a wire delete
	// AND without persisting; the malformed record then reloaded on restart and
	// the stale DNS RR oscillated, uncleanable. Fail closed here (quarantine the
	// store, like a JSON-corrupt or bad-version file) so a malformed address is
	// never trusted or acted on.
	for _, r := range f.Records {
		if err := validOwnedRecordAddrs(r); err != nil {
			s.records = map[string]ownedRecord{}
			return s, fmt.Errorf("ddns state %s: %w: %v", path, errDDNSStateCorrupt, err)
		}
	}
	for _, r := range f.Records {
		s.records[ownedRecordKey(r.scopeOf(), r.Identity, r.Address)] = r
	}
	return s, nil
}

// validOwnedRecordAddrs reports whether an owned record's textual addresses are
// semantically well-formed. A record may legitimately carry an empty Address (a
// Surface A router record keys on {scope, identity, ""} and carries its rdata in
// AddrText) or an empty AddrText (a DHCP-lease record's rdata IS its Address),
// but any NON-EMPTY address field MUST parse as an IP: the published rdata is
// always an A/AAAA address, so an unparseable value is a corrupt record the
// reconciler cannot turn into a correct wire delete (#4909).
func validOwnedRecordAddrs(r ownedRecord) error {
	if r.Address != "" {
		if _, err := netip.ParseAddr(r.Address); err != nil {
			return fmt.Errorf("record %q address %q: %w", r.FQDN, r.Address, err)
		}
	}
	if r.AddrText != "" {
		if _, err := netip.ParseAddr(r.AddrText); err != nil {
			return fmt.Errorf("record %q addr_text %q: %w", r.FQDN, r.AddrText, err)
		}
	}
	return nil
}

// quarantineBadState moves a corrupt / unknown-version ownership file aside to a
// timestamped copy (path + ".corrupt-<RFC3339-ish>") so (a) the operator can
// inspect it and (b) a later save() does NOT overwrite the only forensic copy of
// the lost ownership records. It is best-effort: a quarantine failure is logged
// by the caller and does not change the fail-closed posture. Returns the
// quarantine path on success.
func quarantineBadState(path string, now time.Time) (string, error) {
	// Colons are filesystem-hostile; use a compact, sortable stamp.
	stamp := now.UTC().Format("20060102T150405Z")
	dst := fmt.Sprintf("%s.corrupt-%s", path, stamp)
	// #6218 item 6: os.Rename silently OVERWRITES an existing destination on
	// POSIX. The stamp's resolution is one wall-clock SECOND, so a second
	// quarantine event landing in the same second as an earlier one (a rapid
	// restart loop, or two callers racing) renamed straight over the first
	// quarantine file — destroying the only forensic copy of the FIRST
	// corruption this mechanism exists to preserve (docs at the top of this
	// function). Probe for a same-stamp collision and disambiguate with a
	// numeric suffix before renaming, so no quarantine attempt can clobber an
	// earlier one. maxAttempts is a sanity cap, not a real limit — a genuine
	// collision run this long is unreachable in practice.
	const maxAttempts = 1000
	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate := dst
		if attempt > 0 {
			candidate = fmt.Sprintf("%s.%d", dst, attempt)
		}
		if _, err := os.Lstat(candidate); err == nil {
			continue // candidate already taken; try the next suffix
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("quarantine ddns state %s -> %s: stat: %w", path, candidate, err)
		}
		if err := os.Rename(path, candidate); err != nil {
			return "", fmt.Errorf("quarantine ddns state %s -> %s: %w", path, candidate, err)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("quarantine ddns state %s: exhausted %d same-second suffixes", path, maxAttempts)
}

// degradedMarkerSuffix names the DURABLE fail-closed marker written beside the
// ownership store when a corrupt / unsupported-version file is quarantined
// (#4873). Its presence keeps the manager DEGRADED across restarts. Quarantine
// renames the only canonical file away, so without a durable marker the next
// boot would find no file, load an EMPTY store with a NIL error, and silently
// resume publish/withdraw with all prior ownership forgotten — the exact
// fail-open this closes (a previously-published A/AAAA/PTR can then leak into
// authoritative DNS forever, or a later publish can re-claim a peer-owned name
// with no DHCID ownership record left to veto it). The in-memory `degraded`
// flag alone does not survive the process. The manager stays degraded until an
// operator explicitly resolves it by removing this marker (after inspecting or
// importing the quarantined `.corrupt-*` copy).
const degradedMarkerSuffix = ".degraded"

func degradedMarkerPath(statePath string) string {
	return statePath + degradedMarkerSuffix
}

// readDegradedMarker reports whether a durable degraded marker exists for the
// ownership store at statePath and returns the recorded reason. A marker that
// exists but cannot be read is still treated as PRESENT (ok=true) with a
// generic reason — an unreadable fail-closed marker must never silently clear
// the fail-closed posture. Only a genuine not-exist yields ok=false.
func readDegradedMarker(statePath string) (reason string, ok bool) {
	data, err := os.ReadFile(degradedMarkerPath(statePath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false
		}
		return "ddns: ownership state degraded (marker present but unreadable: " + err.Error() + ")", true
	}
	reason = strings.TrimSpace(string(data))
	if reason == "" {
		reason = "ddns: ownership state degraded (persisted #4873 marker present)"
	}
	return reason, true
}

// writeDegradedMarker durably persists the fail-closed posture beside the
// ownership store (#4873) so it survives a restart after the corrupt file was
// quarantined away.
func writeDegradedMarker(statePath, reason string) error {
	if err := os.MkdirAll(dirOf(statePath), 0o755); err != nil {
		return fmt.Errorf("create ddns state dir for degraded marker: %w", err)
	}
	return fsatomic.WriteFileDurable(degradedMarkerPath(statePath), []byte(reason+"\n"), 0o600)
}

// save persists the store durably (fsync-on-write). Records are sorted by
// key for a deterministic file.
func (s *ddnsState) save() error {
	keys := make([]string, 0, len(s.records))
	for k := range s.records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	recs := make([]ownedRecord, 0, len(keys))
	for _, k := range keys {
		recs = append(recs, s.records[k])
	}
	data, err := json.MarshalIndent(ddnsStateFile{
		Version: ddnsStateVersion,
		Records: recs,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(s.path), 0o755); err != nil {
		return fmt.Errorf("create ddns state dir: %w", err)
	}
	if s.writeFile != nil {
		return s.writeFile(s.path, data, 0o600)
	}
	return fsatomic.WriteFileDurable(s.path, data, 0o600)
}

// put records ownership of a published record, keyed by its scope (#2691
// P1b) + identity + address.
func (s *ddnsState) put(r ownedRecord) {
	s.records[ownedRecordKey(r.scopeOf(), r.Identity, r.Address)] = r
}

// get returns the owned record for scope+identity+address, if any.
func (s *ddnsState) get(scope ScopeKey, identity, address string) (ownedRecord, bool) {
	r, ok := s.records[ownedRecordKey(scope, identity, address)]
	return r, ok
}

// delete removes an ownership entry (after a successful DNS delete), keyed by
// its scope + identity + address.
func (s *ddnsState) delete(scope ScopeKey, identity, address string) {
	delete(s.records, ownedRecordKey(scope, identity, address))
}

// all returns a stable-ordered copy of every owned record.
func (s *ddnsState) all() []ownedRecord {
	out := make([]ownedRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return ownedRecordKey(out[i].scopeOf(), out[i].Identity, out[i].Address) <
			ownedRecordKey(out[j].scopeOf(), out[j].Identity, out[j].Address)
	})
	return out
}

// dirOf is filepath.Dir without importing path/filepath here twice; kept
// local so the rest of the file reads cleanly.
func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}
