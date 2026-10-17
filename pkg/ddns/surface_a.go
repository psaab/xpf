package ddns

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a.go: the Surface A router/interface-address DDNS engine (#2691 P2,
// plan §2.1, §5.3, §5.5). Surface A publishes the firewall's OWN address — an
// interface/unit/family's learned WAN address (DHCP lease, static, netlink) —
// as a single A/AAAA record at a configured FQDN through an external DNS
// provider. It is the classic "dyndns client on the CPE" surface.
//
// REUSE, DO NOT FORK THE SPINE: Surface A drives the SAME Backend (DNSUpdater)
// interface, the SAME record construction (buildHostRecord → LeaseDNSRecord),
// the SAME RFC 2136 backend (newRFC2136Updater, with self-ownership semantics:
// no DHCID/ClientID, so sendAddOwned uses the name-not-in-use / refresh-owned
// prerequisite), the SAME ScopeKey ownership primitive (plan §5.4), and the
// SAME durable-fsync state store pattern (state.go ddnsState shape) — only the
// state FILE differs (interface-ddns-state.json, plan §5.5). The ONLY thing
// Surface A adds on top of the spine is the update ENGINE discipline the
// DHCP-lease reconciler does not need: per-scope change detection, a
// forced-refresh wire floor decoupled from the poll cadence, and flat error
// backoff (ban-avoidance) — the inadyn ideas #4/#7/#8 (plan §3.3/§5.5).
//
// HA (plan §5.6 / #2664): a router record on a reth/virtual interface is
// published only by the node that masters its scope's RG. The SurfaceAManager
// takes the SAME per-scope ScopeGate the lease reconciler does; a gated-out
// scope is stop-writing, never-withdraw (the peer RG master refreshes; a
// withdraw race would blackhole). A standalone (nil gate) always publishes.

// defaultSurfaceAStatePath is the on-disk location of the Surface A
// last-published / ownership store (plan §5.5). Distinct from the Surface B
// lease ownership store (defaultDDNSStatePath) so the two surfaces never
// collide on a record key and either can be reset independently.
const defaultSurfaceAStatePath = "/var/lib/xpf/interface-ddns-state.json"

// defaultForcedRefresh is the wire-update floor for an UNCHANGED address
// (inadyn idea #7, plan §5.5). The reconcile loop re-asserts desired state
// every 30s, but a wire UPDATE for an unchanged address fires at most once per
// forced-refresh interval — proving liveness to the provider / resisting record
// reaping without per-poll traffic. 24h matches the plan default.
const defaultForcedRefresh = 24 * time.Hour

// defaultErrorBackoffMax caps the per-scope error backoff (inadyn idea #8,
// flat — not exponential beyond the cap; plan §5.5). On a transient failure a
// scope backs off from the reconcile interval up to this cap so a failing
// provider is not hammered at the poll cadence (ban-avoidance).
const defaultErrorBackoffMax = time.Hour

// surfaceABaseBackoff is the first error-backoff step (the reconcile cadence).
// A scope that keeps failing doubles up to defaultErrorBackoffMax.
const surfaceABaseBackoff = 30 * time.Second

// AddressSource selects where an interface scope's current address is observed
// (plan §5.3). Ordered-fallback observation lives in the daemon's
// AddressObserver; this enum is the per-scope operator selection.
type AddressSource string

const (
	// AddressSourceInterface reads the address from the interface (netlink /
	// configured static) — the default. The firewall is the router, so it
	// usually knows its own public address directly (plan §7 fork 4).
	AddressSourceInterface AddressSource = "interface"
	// AddressSourceDHCP reads the address from the DHCP client lease
	// (pkg/dhcp.Manager.LeaseFor) — the authoritative learned WAN address.
	AddressSourceDHCP AddressSource = "dhcp"
)

// SurfaceAScope is the resolved, runtime-shaped configuration for ONE
// interface/unit/family Surface A binding (plan §5.9). It is derived from the
// per-interface `dynamic-dns` config + the referenced provider-catalog entry at
// reconcile time so the manager never holds a stale captured cfg.
type SurfaceAScope struct {
	// Key is the ownership/scope key (plan §5.4). For Surface A it is keyed on
	// {Family, Interface, Unit, RGOwner} — RoutingInstance/PolicyID round out
	// the transport + provider attribution. The interface+unit+family triple is
	// unique per binding.
	Key ScopeKey
	// FQDN is the forward name to publish (already an operator-supplied FQDN;
	// finalizeFQDN normalizes it against an empty zone so a dotted name is kept
	// verbatim, a bare label is published as-is).
	FQDN string
	// TTL is the record TTL in seconds (defaultDDNSTTL when unset).
	TTL int
	// Source selects the address-observation source for this scope.
	Source AddressSource
	// Provider is the resolved provider-catalog entry (backend + credentials +
	// transport binding) this scope publishes through.
	Provider *config.DDNSProvider
	// ForcedRefresh is the wire-update floor for an unchanged address; 0 ⇒
	// defaultForcedRefresh.
	ForcedRefresh time.Duration
	// ErrorBackoffMax caps the per-scope error backoff; 0 ⇒
	// defaultErrorBackoffMax.
	ErrorBackoffMax time.Duration
}

// effectiveKey returns the scope's ownership key with the published FQDN folded
// in (#2903). The published NAME is part of the Surface A scope identity, so the
// manager ALWAYS keys ownership/runtime/status on Key-with-FQDN regardless of
// whether the caller pre-populated Key.FQDN: a hostname change is then a NEW
// scope (old name withdrawn by the gone-from-config sweep, new name published)
// instead of an in-place name overwrite that orphans the old RR. SurfaceAScope.
// FQDN is authoritative; this folds it into the key so every manager lookup,
// the durable ownership record's stored Scope, and StatusViews agree.
func (s SurfaceAScope) effectiveKey() ScopeKey {
	k := s.Key
	k.FQDN = s.FQDN
	return k
}

// scopeID is the stable string id for a Surface A scope (its ScopeKey prefix),
// used as the map key in the manager's per-scope runtime state and the
// observation request. Two scopes with the same interface/unit but different
// families — or the same interface/unit/family but a DIFFERENT published FQDN
// (#2903) — are distinct.
func (s SurfaceAScope) scopeID() string { return s.effectiveKey().scopePrefix() }

// AddressObservation is the result of observing a scope's current address
// (plan §5.3). Addr.IsValid()==false means "no address right now" (the
// interface is down / has no lease for this family) — the engine withdraws a
// previously-published record for a scope that loses its address.
type AddressObservation struct {
	Addr   netip.Addr
	Source AddressSource
}

// AddressObserver observes the current address for a Surface A scope (plan
// §5.3). The daemon supplies it (it reads netlink / pkg/dhcp.LeaseFor). The
// engine never reads netlink/DHCP directly — keeping pkg/ddns free of those
// dependencies, exactly as the LeaseParser seam keeps it free of the Kea
// memfile parser. ok=false means the address could not be observed this cycle
// (transient) — the engine then leaves the scope untouched (no withdraw on a
// transient observation failure, the never-blackhole rule).
//
// ctx is the reconcile/pass context (#3736): the checkip address source
// performs a blocking external HTTP GET, and threading ctx lets that probe
// inherit the pass deadline and abort promptly on daemon shutdown instead of
// hanging up to its own fixed timeout. The engine invokes the observer with
// m.mu RELEASED (see reconcileScopeLocked) so a slow/black-holed checkip
// endpoint cannot block StatusViews/Stats or serialize other scopes.
type AddressObserver func(ctx context.Context, scope SurfaceAScope) (AddressObservation, bool)

// surfaceAState is the per-scope runtime engine state (plan §5.5): the
// last-published address + time (change-detection + forced-refresh) and the
// error-backoff schedule. It is kept in memory alongside the durable ownership
// record (the durable store proves ownership for cleanup; this drives the wire
// cadence). lastErr surfaces the last failure for observability.
// normalizeDDNSTTL resolves a configured TTL to the value actually published
// (#9067). `<= 0` means "unset" and resolves to defaultDDNSTTL, which is what
// every publish path already does inline. It exists so change-detection and the
// publish cannot disagree about what the TTL IS — two spellings of one
// normalisation is exactly how a comparison ends up checking a property the
// system does not act on.
func normalizeDDNSTTL(ttl int) int {
	if ttl <= 0 {
		return defaultDDNSTTL
	}
	return ttl
}

type surfaceAState struct {
	lastAddr netip.Addr
	// lastTTL is the TTL of the last SUCCESSFUL publish (#9067).
	//
	// Change detection compared only the address, so a TTL-ONLY edit was not a
	// change on ANY backend and nothing republished until the forced-refresh
	// floor — 24h by default. That is a delay rather than the permanent block
	// the Cloudflare early return was, but it defeats the same operator intent:
	// lowering TTL ahead of a planned renumber is bought precisely so the change
	// propagates SOON.
	//
	// Zero means "not yet published in this process". It is deliberately NOT
	// seeded by the restart re-adoption below: the durable store records the
	// published ADDRESS, not the TTL it was published with, so seeding a guess
	// would either suppress a genuine TTL change (if it guessed the new value)
	// or force a republish of every scope on every restart (if it guessed
	// wrong). Leaving it zero means the first post-restart reconcile of an
	// unchanged scope stays a counted skip, exactly as before, because the
	// comparison below is gated on a non-zero lastTTL.
	lastTTL       int
	lastPublished time.Time
	// nextEligible is the earliest time the scope may attempt a wire op again
	// after a failure (error backoff). Zero ⇒ eligible now.
	nextEligible time.Time
	backoff      time.Duration
	// backoffFromWithdraw records whether the armed backoff came from a failed
	// WITHDRAW (true) or a failed PUBLISH (false) (#4423 M03). The backoff window
	// gates only the wire op it was armed for: a publish-failure backoff must NOT
	// delay a newly-observed address-LOSS withdraw (leaving the record live at a
	// now-dead address is a blackhole), and a withdraw-failure backoff must not
	// delay re-publishing a recovered address. The op that fires re-arms its own
	// backoff on failure, so a persistently-failing wire op still backs off — no
	// hammering. Meaningless when nextEligible is zero.
	backoffFromWithdraw bool
	lastErr             string
	lastErrAt           time.Time
	// noBackend records that the most recent reconcile resolved the scope's
	// provider to the no-op backend (errSurfaceANoBackend — a half-configured
	// provider). Unlike lastErr it arms NO backoff (nothing was attempted on the
	// wire) and is cleared on the first successful publish. It drives the
	// SurfaceAStateUnpublished status row so a never-published scope is visible to
	// the operator instead of silently omitted (#2843).
	noBackend bool
	// withdrawUnsupported records that the scope's backend can NEVER perform a
	// withdraw (errGenericDeleteUnsupported — the generic HTTP backend has no
	// portable delete verb, #2772/#2811). Unlike a transient failure this arms NO
	// retry: re-attempting a structurally-unsupported delete on the backoff
	// cadence is pointless churn plus a recurring warn (#2813). The wire delete is
	// attempted at most once; a single warn is emitted; the scope KEEPS ownership
	// so the abandoned RR stays operator-visible. Both withdraw paths skip the
	// wire attempt while set. Cleared on a successful publish (the full rt reset)
	// and on restart (the runtime cache is rebuilt from the durable store, which
	// only seeds lastAddr), so a later provider change that adds a delete verb is
	// re-probed.
	withdrawUnsupported bool
}

// surfaceAOrphan records a DDNS record this node published at a PREVIOUS provider
// endpoint that a provider IDENTITY change has left stale and un-withdrawable
// through the current catalog (#3735). It is the durable-alarm payload behind the
// operator surfaces (Prometheus gauge + StatusViews row + slog.Warn): what name
// and address are stale, which provider owned it, and the old vs new endpoint
// fingerprint. Auto-withdrawal of the record is DEFERRED (the old endpoint's
// credentials are redacted config.Secret and the endpoint is usually
// decommissioned), so it is surfaced LOUDLY for MANUAL operator cleanup instead
// of being silently dropped (H01), overwritten (H02), or deleted at the wrong
// endpoint (H03).
type surfaceAOrphan struct {
	FQDN           string
	Address        string // the published rdata now stale at the old endpoint
	Provider       string // the owning PolicyID (provider name) at publish time
	Interface      string // the owning scope's interface
	Unit           int    // the owning scope's unit
	Family         int    // 4/6 — the owning scope's family (deterministic status sort)
	OldFingerprint string // the endpoint the record was published through
	NewFingerprint string // the current provider's endpoint ("" = provider gone)
	Reason         string // human-readable cause (one of orphanReason*)
	FirstSeen      time.Time
}

// orphanReason* are the operator-facing explanations attached to a surfaceAOrphan
// and its StatusViews row (#3735). They all resolve to the same required action:
// the old record must be cleaned up by hand.
const (
	orphanReasonProviderGone = "provider removed from catalog; old record stale at previous endpoint — manual cleanup required"

	orphanReasonEndpointChanged = "provider endpoint changed; old record stale at previous endpoint — manual cleanup required"

	orphanReasonEndpointChangedInPlace = "provider endpoint changed in place; old record stale at previous endpoint — manual cleanup required"
)

// Surface A scope status states for the operator view (#2843). A configured
// scope is rendered with exactly one of these so the operator sees every
// configured scope and its health, not only the successfully-owned ones.
const (
	// SurfaceAStatePublished — the scope has a durable ownership record (an RR
	// is published at the provider).
	SurfaceAStatePublished = "published"
	// SurfaceAStatePending — the scope is configured and has no ownership record
	// and no recorded error yet (never attempted, or skipped waiting on an
	// address observation / backoff window). Bring-up steady state.
	SurfaceAStatePending = "pending"
	// SurfaceAStateUnpublished — the scope is configured but cannot publish
	// because its provider resolved to the no-op backend (a half-configured
	// provider, errSurfaceANoBackend). Distinct from a transient error: nothing
	// is attempted on the wire and no backoff is armed.
	SurfaceAStateUnpublished = "unpublished"
	// SurfaceAStateError — the scope is configured and its last publish attempt
	// failed (provider/wire error); LastError/LastErrorAt carry the reason and
	// error backoff is armed.
	SurfaceAStateError = "error"
	// SurfaceAStateWithdrawPending — an ownership record exists for a scope that
	// is NO LONGER configured (the binding was removed); the next reconcile will
	// withdraw it. Surfaced so a wedged withdraw is visible, not silent.
	SurfaceAStateWithdrawPending = "withdraw-pending"
	// SurfaceAStateOrphaned — a record this node published at a PREVIOUS provider
	// endpoint that a provider identity change (rename to a different endpoint /
	// in-place server-zone edit / removed binding after an edit) left stale and
	// un-withdrawable through the current catalog (#3735). Ownership is KEPT and
	// the record is surfaced LOUDLY (LastError carries the manual-cleanup reason)
	// because auto-withdrawal is deferred (the old creds are redacted and the old
	// endpoint is usually gone). The operator must clean the stale record by hand.
	SurfaceAStateOrphaned = "orphaned"
	// SurfaceAStateInvalid — the binding is configured but STRUCTURALLY incomplete
	// so no scope can be built from it: it has no hostname, no provider, or names a
	// provider that is not in the catalog (#4423 M09). Such a binding never becomes
	// a reconcile scope (it cannot publish), so before this it vanished entirely
	// from the operator status surface even though the operator had typed it — the
	// commit warning was the only trace. The daemon now synthesizes an `invalid`
	// row (LastError carries the specific defect) so a broken binding stays visible
	// in `show system services dynamic-dns`.
	SurfaceAStateInvalid = "invalid"
)

// SurfaceAStatusView is a read-only projection of one Surface A scope's
// current publish state, for the operator surfaces (CLI/gRPC/REST). It exposes
// the scope's health State (#2843 — every CONFIGURED scope gets a row, not just
// the successfully-owned ones), what is currently published, the last-published
// time, and the last error.
type SurfaceAStatusView struct {
	Interface string
	Unit      int
	Family    int
	FQDN      string
	Provider  string
	State     string // one of the SurfaceAState* constants (#2843)
	// Published is the last CONFIRMED published address ("" = none confirmed).
	// It is NOT "what is live right now" when State is pending: see the #7423
	// note in StatusViews for why that is unknowable during a publish
	// write-ahead window (#5334).
	Published     string
	LastPublished time.Time
	LastError     string
	LastErrorAt   time.Time
}

// SurfaceAManager owns the Surface A reconcile + the per-scope last-published
// cache + ownership store (plan §5.5/§5.6). It is a SEPARATE manager from the
// DHCP-lease Manager (different ownership semantics — self-owned vs DHCID — and
// a different state file), but it drives the SAME Backend interface and the
// SAME record/scope/durability primitives.
//
// Lock discipline (#2778): m.mu guards ALL manager state — the durable store,
// the runtime cache, and the counters — but it is NEVER held across provider
// network I/O (UpsertLease/DeleteLease run with a 15s client timeout). A pass
// snapshots the exact intent under the lock (the resolved backend + record +
// the durably-written ownership write-ahead), RELEASES the lock to perform the
// wire op, then RE-ACQUIRES it to commit the result, re-validating that the
// scope's desired ownership has not changed while unlocked (the racing-op CAS).
// This keeps `show system services dynamic-dns`, metric scrapes, and other
// scopes responsive while one provider is slow or hung. The single-flight guard
// in the daemon (surfaceAReconcileInFlight) means two full passes never run
// concurrently, but StatusViews/Stats and any future caller must not block on
// provider I/O — hence the lock is released around every wire call.
type SurfaceAManager struct {
	mu    sync.Mutex
	state *ddnsState // durable ownership store (interface-ddns-state.json)

	// degraded fails the manager CLOSED when the ownership state file could not
	// be loaded (corrupt / unsupported-version / unreadable, #2971). It mirrors
	// the DHCP-lease Manager's #2650 posture: the durable store is the ONLY
	// authority for which router records this node published, so a load failure
	// must NOT be treated as "owns nothing" (fail-open) — that empty store would
	// re-publish every scope (overwriting a peer/manual owner, a write storm) and
	// permanently forget what to withdraw. While degraded, Reconcile is a
	// no-op-with-error: no publish, no withdraw, no save (the empty in-memory
	// store is never written, so a corrupt/quarantined file is preserved). A
	// MISSING file (first boot) is NOT degraded — it is a legitimately-empty
	// store, so a fresh (including standalone) node still publishes normally.
	degraded       bool
	degradedReason string

	// runtime is the per-scope engine state (change-detect / forced-refresh /
	// backoff), keyed by scopeID. NOT persisted: it is rebuilt on restart from
	// the durable store (seedFromStore) so a restart does not blast a redundant
	// update for an unchanged address (inadyn idea #5, plan §5.5).
	runtime map[string]*surfaceAState

	// orphans tracks records this node published at a PREVIOUS provider endpoint
	// that a provider identity change (rename to a different endpoint / in-place
	// server-zone edit / removed binding after an edit) has left stale and
	// un-withdrawable through the CURRENT catalog (#3735). It is keyed by
	// orphanKey (the owned record's scope prefix + FQDN + address) so a given
	// orphaned record contributes exactly one entry. It is the operator-visible
	// half of the fingerprint alarm: `xpf_ddns_surface_a_orphaned`, a distinct
	// `SurfaceAStateOrphaned` StatusViews row, and a single loud slog.Warn per
	// entry (noteOrphan is idempotent by key so it does not re-warn every sweep).
	//
	// It is NOT persisted: the H01/H03 orphans are re-derived every reconcile
	// from the durable owned record + the provider catalog (self-healing across
	// restart — the alarm re-fires once), while the H02 in-place-mutation orphan
	// is in-memory-until-restart because the OLD endpoint identity is intentionally
	// NOT persisted (persisting the old backend's creds to reach it is the
	// DEFERRED auto-cleanup half, blocked by the #2053 secret contract — see the
	// README). Auto-withdrawal of the orphaned record is DEFERRED; the alarm tells
	// the operator to clean it up by hand.
	orphans map[string]surfaceAOrphan

	// forceRefresh is the operator force-now latch (#3276): when set, the NEXT
	// reconcile pass treats every configured scope as refresh-due, re-asserting
	// the wire record even for an owned, unchanged address inside the
	// forced-refresh floor. It is the engine half of the `request system
	// dynamic-dns update` verb — a one-shot override of the change-detection +
	// forced-refresh skip, decoupled from the poll cadence (P2 #2717). The latch
	// is consumed by the first non-degraded pass (set false before Pass 1 runs)
	// so it forces exactly one publish, not a permanent re-assert storm. The
	// per-RG HA writer gate still applies — a gated-out scope is never published
	// even under force (only the RG owner writes, #2972). A degraded pass does
	// NOT consume the latch (it never publishes), so the force survives until the
	// state file is healthy.
	forceRefresh bool

	// newBackend resolves the live Backend for a provider at reconcile time
	// (resolve-per-Reconcile, plan §6 fork 1). When nil (tests injecting a fixed
	// backend) the static `backend` field is used for every scope.
	newBackend func(p *config.DDNSProvider, fqdn string, ttl int) (DNSUpdater, error)
	backend    DNSUpdater // static fallback / test injection

	// httpClients caches the hardened *http.Client (and its keep-alive
	// connection pool) per distinct provider source-binding so the HTTP backends
	// (dyndns2/cloudflare/route53/generic) reuse the pool across reconcile passes
	// instead of paying a full TCP+TLS handshake every ~30s pass (#2904). The
	// backend OBJECT is still rebuilt per pass (resolve-per-Reconcile, #2691); only
	// the expensive transport is reused. Keyed on the binding leaves, so a commit
	// that changes a binding resolves a fresh key and rebuilds the transport. Each
	// Reconcile pass reaps cache entries whose binding key is no longer referenced
	// by the committed config (#2956) — closing the superseded transport's idle
	// pool and dropping the entry — so the map stays bounded under binding churn.
	httpClients *httpClientCache

	// ifResolver maps a destination-interface Junos ref to the LOCAL node's
	// kernel device name for SO_BINDTODEVICE (#5070). It is refreshed at the
	// START of each Reconcile from the trailing resolver arg (the daemon threads
	// cfg.ResolveKernelIfName) and read by resolveBackend + CheckIPClient during
	// the same locked pass. Nil ⇒ the leaf slash-substitution fallback
	// (standalone tests); a routing-instance still resolves to vrf-<name>.
	ifResolver func(string) string

	now func() time.Time

	// counters (observability, plan §5.5).
	upsertOK   uint64
	upsertFail uint64
	deleteOK   uint64
	deleteFail uint64
	skipped    uint64 // unchanged-and-not-yet-forced skips
	backedOff  uint64 // scopes skipped this pass because still in error backoff
	// skippedNoBackend counts scopes skipped because the provider resolved to the
	// no-op backend (a half-configured HTTP provider whose constructor errored on
	// a missing credential — newSurfaceAHTTP degrades to nopUpdater{}). Such a
	// scope publishes NOTHING to any wire, so it must NOT count as an upsertOK,
	// must NOT write-ahead phantom ownership, and must NOT advance the
	// last-published cache — so it re-attempts every cycle once the operator adds
	// the credential (mirrors manager.go upsertLocked's skippedNoBackend, #2691
	// P3 review MAJOR).
	skippedNoBackend uint64
	// deleteCoowned counts wire deletes DEFERRED because the RR is still co-owned
	// by a Surface B DHCP lease scope (#5748 cross-surface arm of #5709, tie-break
	// #6015). UNLIKE the lease Manager (which is the sole suppression AUTHORITY and
	// drops its claim), Surface A is the NON-AUTHORITY: on a co-owned teardown it
	// does NOT drop its claim and does NOT issue the wire delete. It DEFERS — it
	// re-UPSERTs the RR (self-heal) and KEEPS its ownership claim, retrying the
	// teardown each pass until the lease authority releases (window-(b) fix: two
	// surfaces releasing the same co-owned RR in overlapping passes would orphan
	// it). So this counter tallies deferred passes, not one-shot suppressions.
	// Guarded by mu.
	deleteCoowned uint64

	// leaseCoowners, when non-nil, returns the wire-RR claims currently owned by
	// the SEPARATE Surface B DHCP lease surface (Manager.state.records, rdata in
	// Address). The daemon injects it (SetLeaseCoownerSource) so a Surface A
	// teardown suppresses a wire DELETE that would clobber a lease-owned identical
	// RR — the symmetric direction of the #5748 cross-surface guard. It is a
	// LOCK-FREE snapshot accessor (Manager.WireRRClaims, a bare atomic load); it
	// MUST NOT take Manager.mu, so withdrawOwnedLocked can call it while THIS
	// manager holds m.mu without a lock-order cycle. Lock order: m.mu (held) →
	// lock-free peer read (no peer mutex). Nil ⇒ no cross-surface suppression.
	leaseCoowners func() []WireRRClaim

	// wireRRClaims is the LOCK-FREE snapshot of the wire RRs THIS (Surface A)
	// surface currently owns, published for the lease Manager's teardown guard to
	// consult (#5748). Rebuilt under m.mu at the end of every non-degraded reconcile
	// pass and after load, read via WireRRClaims() with a bare atomic load — never
	// taking m.mu. Nil until the first rebuild.
	wireRRClaims atomic.Pointer[[]WireRRClaim]
}

// NewSurfaceAManager constructs the production Surface A manager (plan §5.5). It
// loads the durable ownership store from defaultSurfaceAStatePath. A corrupt /
// unsupported-version / unreadable store puts the manager into the FAIL-CLOSED
// degraded state (#2971, mirroring the DHCP-lease Manager's #2650 posture): the
// manager is still constructible (the daemon starts) but Reconcile refuses to
// publish or withdraw any record until the operator resolves the bad file
// (corrupt/unsupported files are quarantined aside). A MISSING file (first boot)
// is NOT degraded — a fresh node publishes normally. It resolves the live
// backend per provider at reconcile time (resolve-per-Reconcile): the RFC 2136
// dynamic-DNS UPDATE backend OR one of the HTTP providers — dyndns2, duckdns,
// cloudflare, route53, generic — all siblings behind the same DNSUpdater
// interface (see resolveSurfaceABackend). The runtime cache is seeded from the
// durable store so a restart does not republish an unchanged address.
func NewSurfaceAManager() *SurfaceAManager {
	st, degraded, reason := loadStateOrDegrade(defaultSurfaceAStatePath, time.Now)
	m := &SurfaceAManager{
		state:          st,
		degraded:       degraded,
		degradedReason: reason,
		runtime:        map[string]*surfaceAState{},
		orphans:        map[string]surfaceAOrphan{},
		httpClients:    newHTTPClientCache(),
		now:            time.Now,
	}
	// resolveBackend closes over the manager's per-binding HTTP client cache
	// (#2904) so every HTTP backend the reconcile path builds reuses the cached
	// transport/connection pool rather than allocating a fresh one each pass.
	m.newBackend = m.resolveBackend
	m.seedFromStore()
	// #5748: seed the cross-surface wire-RR claim snapshot from the loaded store so
	// the lease guard sees this surface's ownership from the first pass. Single-
	// threaded during construction.
	m.rebuildWireRRClaimsLocked()
	return m
}

// newSurfaceAManagerForTesting builds a manager with an in-memory state file
// path, an injected backend, and an injectable clock — no real /var/lib path,
// no network. Used by surface_a_test.go. It loads the durable store through the
// SAME loadStateOrDegrade gate as production (#2971), so a corrupt/unreadable
// state file at statePath drives the manager into the fail-closed degraded state
// in tests exactly as it would in production; a missing file (the common case)
// yields a clean empty store.
func newSurfaceAManagerForTesting(statePath string, backend DNSUpdater, now func() time.Time) *SurfaceAManager {
	nowFn := now
	if nowFn == nil {
		nowFn = time.Now
	}
	st, degraded, reason := loadStateOrDegrade(statePath, nowFn)
	m := &SurfaceAManager{
		state:          st,
		degraded:       degraded,
		degradedReason: reason,
		runtime:        map[string]*surfaceAState{},
		orphans:        map[string]surfaceAOrphan{},
		backend:        backend,
		now:            now,
	}
	m.seedFromStore()
	m.rebuildWireRRClaimsLocked() // #5748: seed the cross-surface claim snapshot
	return m
}

// productionSurfaceABackend resolves a provider-catalog entry into a live
// Backend (plan §5.2). The rfc2136 backend (P2) and the HTTP backends — dyndns2,
// cloudflare, route53, generic (P3) — are all siblings behind the SAME
// DNSUpdater interface, so the Surface A engine drives every one identically. A
// backend whose required fields are missing (or an unknown backend token)
// resolves to the no-op (logged) so a half-configured provider degrades safely
// at runtime instead of wedging — the commit warning already told the operator.
func productionSurfaceABackend(p *config.DDNSProvider, fqdn string, ttl int) (DNSUpdater, error) {
	return resolveSurfaceABackend(p, fqdn, ttl, nil)
}

// CheckIPClient returns the bound *http.Client a checkip probe should use for a
// provider, reusing the manager's cached per-binding client (#2904) so the
// ~30s checkip probe reuses the keep-alive connection pool instead of doing a
// full TCP+TLS handshake every reconcile pass. The bind-resolution error (a
// malformed source-address) is returned alongside the UNBOUND default client
// (fail-open, matching NewCheckIPClient); the probe is a transient observation,
// never a withdraw. When the cache is nil (a test manager) it falls back to
// building a fresh client.
func (m *SurfaceAManager) CheckIPClient(p *config.DDNSProvider) (*http.Client, error) {
	// #5070: resolve a destination-interface binding to the local node's kernel
	// device via the per-pass resolver (set at Reconcile start; the observer that
	// calls this runs inside that same locked pass). Nil ⇒ leaf fallback.
	if m.httpClients == nil {
		return newProviderHTTPClient(p, m.ifResolver)
	}
	return m.httpClients.clientFor(p, m.ifResolver)
}

// SetCheckIPRootCAsForTesting replaces the TLS trust roots on every client
// the manager's cache builds so tests can point a probe at an httptest TLS
// server. Test-only; not for production callers (production clients verify
// against the system trust store). Call BEFORE the first probe: clients
// already built keep their original roots.
func (m *SurfaceAManager) SetCheckIPRootCAsForTesting(pool *x509.CertPool) {
	if m.httpClients == nil {
		m.httpClients = newHTTPClientCache()
	}
	m.httpClients.rootCAs = pool
}

// resolveBackend is the manager-bound backend resolver (#2904). It is identical
// to productionSurfaceABackend except the HTTP backends are built with the
// manager's cached, per-binding *http.Client so the keep-alive connection pool
// is reused across reconcile passes instead of being rebuilt every pass.
func (m *SurfaceAManager) resolveBackend(p *config.DDNSProvider, fqdn string, ttl int) (DNSUpdater, error) {
	// #5070: thread the per-pass interface-name resolver so a destination-interface
	// binding resolves to the local node's kernel device before SO_BINDTODEVICE.
	return resolveSurfaceABackend(p, fqdn, ttl, m.httpClients, m.ifResolver)
}

// resolveSurfaceABackend resolves a provider-catalog entry into a live Backend.
// When clients is non-nil the HTTP backends reuse the cached per-binding client
// (#2904); when nil each HTTP backend builds its own client (the pre-#2904
// behaviour, used by productionSurfaceABackend's direct/test callers). A
// half-configured or unknown provider degrades to the no-op (logged) exactly as
// before.
func resolveSurfaceABackend(p *config.DDNSProvider, fqdn string, _ int, clients *httpClientCache, resolveIf ...func(string) string) (DNSUpdater, error) {
	if p == nil {
		return nopUpdater{}, nil
	}
	// httpClientFor pulls the cached bound client for this provider's binding
	// when a cache is present, else returns (nil, nil) so the backend constructor
	// builds — and fail-closes on — its own client via newProviderHTTPClient.
	//
	// FAIL-CLOSED on a cached-client source-bind error (#4437): clients.clientFor
	// returns the UNBOUND default client ALONGSIDE the bind-resolution error (a
	// malformed / unusable source-address). Earlier this path swallowed that
	// error, logged a warning, and threaded the unbound client into the backend —
	// so a provider that configured a `source-address` silently published from the
	// DEFAULT ROUTE (the wrong source / interface the operator explicitly
	// overrode). The error is now PROPAGATED, not swallowed: httpBackend turns it
	// into the no-op publisher (newSurfaceAHTTP) and the reconcile SKIPS the
	// publish — never a withdraw — exactly as the nil-cache path already does
	// (newProviderHTTPClient surfaces the same error from inside the constructor)
	// and as the checkip observer's CheckIPBound gate (#3733). A publish with a
	// configured source-address that cannot be honored is an error, not a silent
	// use-default.
	httpClientFor := func() (*http.Client, error) {
		if clients == nil {
			return nil, nil
		}
		return clients.clientFor(p, resolveIf...)
	}
	// httpBackend resolves the source-bound client FIRST (fail-closed on a bind
	// error) and only then builds the HTTP backend. Resolving the client before
	// the constructor is what keeps the unbound fail-open client from ever being
	// threaded in: on a bind error the constructor is never reached, so
	// newSurfaceAHTTP degrades to the no-op backend and the publish is skipped.
	httpBackend := func(build func(*http.Client) (DNSUpdater, error)) (DNSUpdater, error) {
		return newSurfaceAHTTP(p, func() (DNSUpdater, error) {
			cl, err := httpClientFor()
			if err != nil {
				return nil, fmt.Errorf("ddns surface-a: provider %q source bind "+
					"unusable; refusing to publish from the unbound default route: %w",
					p.Name, err)
			}
			return build(cl)
		})
	}
	switch p.Backend {
	case "rfc2136", "":
		if p.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		return newSurfaceARFC2136(p, fqdn, resolveIf...)
	case "dyndns2":
		return httpBackend(func(cl *http.Client) (DNSUpdater, error) { return newDyndns2Backend(p, cl) })
	case "duckdns":
		return httpBackend(func(cl *http.Client) (DNSUpdater, error) { return newDuckDNSBackend(p, cl) })
	case "cloudflare":
		return httpBackend(func(cl *http.Client) (DNSUpdater, error) { return newCloudflareBackend(p, cl) })
	case "route53":
		return httpBackend(func(cl *http.Client) (DNSUpdater, error) { return newRoute53Backend(p, cl) })
	case "generic":
		return httpBackend(func(cl *http.Client) (DNSUpdater, error) { return newGenericBackend(p, cl) })
	default:
		slog.Warn("ddns surface-a: unknown provider backend; publishing nothing",
			"provider", p.Name, "backend", p.Backend)
		return nopUpdater{}, nil
	}
}

// newSurfaceAHTTP adapts an HTTP-backend constructor to the
// productionSurfaceABackend contract: a construction error (missing credential /
// endpoint) degrades to the no-op (logged + the commit warning already fired)
// rather than failing the whole reconcile pass, matching the rfc2136 fail-open
// posture. The returned backend's UpsertLease/DeleteLease are then driven by the
// engine exactly like rfc2136.
func newSurfaceAHTTP(p *config.DDNSProvider, build func() (DNSUpdater, error)) (DNSUpdater, error) {
	u, err := build()
	if err != nil {
		slog.Warn("ddns surface-a: HTTP provider not usable; publishing nothing",
			"provider", p.Name, "backend", p.Backend, "err", err)
		return nopUpdater{}, nil
	}
	return u, nil
}

// newSurfaceARFC2136 builds the live RFC 2136 backend for a Surface A provider.
// It reuses the SAME rfc2136Updater the lease path uses, in SELF-OWNED mode:
// a router record has NO ClientID/DHCID (the firewall is the authoritative owner
// of its OWN configured FQDN), so the forward ADD is an atomic IN-PLACE REPLACE
// of our record type (rfc2136Updater.selfOwned → sendAddSelfOwned), NOT the
// lease path's name-not-in-use / DHCID-match prerequisite. This is what lets an
// address change and a forced-refresh of an EXISTING name succeed — without
// selfOwned, the no-DHCID lease path would REFUSE the pre-existing name and pin
// the record at its first address forever. The provider's transport binding
// (source-address / dest-interface / VRF) is honored via the shared
// resolveBindConfig→dialer path by reusing DHCPDynamicDNSConfig as the carrier.
func newSurfaceARFC2136(p *config.DDNSProvider, _ string, resolveIf ...func(string) string) (DNSUpdater, error) {
	if p == nil {
		return nil, errors.New("ddns surface-a: nil provider")
	}
	// Reuse the lease-path policy + config shape so the rfc2136 backend builds
	// identically (server, TSIG, source binding). conflict-policy is replace-
	// owned but the selfOwned flag (set below) overrides the forward-add path to
	// the in-place replace — the conflict-policy value only governs the unused
	// PTR path for a self record.
	pol := ddnsPolicy{
		domain:         "", // the FQDN is absolute; no domain suffixing
		conflictPolicy: "replace-owned",
		backend:        "rfc2136",
	}
	c := &config.DHCPDynamicDNSConfig{
		UpdateServer:         p.UpdateServer,
		TSIGKeyName:          p.TSIGKeyName,
		TSIGAlgorithm:        p.TSIGAlgorithm,
		TSIGSecret:           p.TSIGSecret,
		SourceAddress:        p.SourceAddress,
		DestinationInterface: p.DestinationInterface,
		RoutingInstance:      p.RoutingInstance,
	}
	u, err := newRFC2136Updater(pol, c, nil, nil, nil, resolveIf...)
	if err != nil {
		return nil, err
	}
	u.selfOwned = true
	return u, nil
}

// seedFromStore rebuilds the in-memory runtime cache from the durable ownership
// store (inadyn idea #5, plan §5.5): a restart must not blast a redundant
// update for an address that has not changed. Each owned record seeds BOTH
// lastAddr (so change-detection sees the unchanged address as unchanged) AND
// lastPublished, set to the restart instant, so the forced-refresh floor is
// measured from the restart: the FIRST post-restart reconcile of an unchanged
// record is a counted skip (no wire traffic) and the record re-asserts only
// once the forced-refresh interval elapses from the restart. Leaving
// lastPublished zero would make refreshDue immediately true and republish
// every owned scope on the first pass — a restart write-storm proportional to
// the scope count, the exact provider ban/rate-limit risk the cache exists to
// avoid (#3734/H04).
//
// The published rdata lives in AddrText for a Surface A router record; the
// keying Address field is "" (Surface A keys ownership on {scope, fixed
// identity, ""}, #2691 P2). Seed from AddrText and only fall back to the
// Address field for any legacy lease-shape entry that predates AddrText — a
// pre-fix restart parsed the empty Address, errored, and seeded NOTHING, which
// is exactly the storm this fixes. An unparseable/empty value seeds no runtime
// entry (the scope re-publishes on its first reconcile — safe). Caller need not
// hold the mutex (constructor-only).
func (m *SurfaceAManager) seedFromStore() {
	// Restart baseline for the forced-refresh floor. m.now is set by both
	// constructors before seedFromStore runs; the nil guard is defensive.
	var restart time.Time
	if m.now != nil {
		restart = m.now()
	}
	for _, r := range m.state.all() {
		text := r.AddrText
		if text == "" {
			text = r.Address
		}
		a, err := netip.ParseAddr(text)
		if err != nil {
			continue
		}
		m.runtime[r.scopeOf().scopePrefix()] = &surfaceAState{
			lastAddr:      a.Unmap(),
			lastPublished: restart,
		}
	}
}

// providerIO performs ONE provider network call (UpsertLease/DeleteLease) with
// m.mu RELEASED, then re-acquires the lock before returning (#2778). The caller
// MUST hold m.mu on entry and will hold it again on return. Releasing the lock
// around the (up-to-15s) wire op is the whole point: a slow or hung provider
// must not block StatusViews/Stats/other-scope reconcile work. The function is
// careful to re-acquire the lock even if fn panics, so the deferred Unlock in
// Reconcile stays balanced (a panicking backend would otherwise double-unlock).
func (m *SurfaceAManager) providerIO(fn func() error) error {
	m.mu.Unlock()
	defer m.mu.Lock()
	return fn()
}

// observeIO runs the per-scope address observation with m.mu RELEASED (#3736,
// the observation residual of #2778). For a checkip source the observer
// performs a blocking external HTTP GET (up to ~10s); holding the manager mutex
// across it would block StatusViews/Stats and serialize every OTHER scope's
// reconcile behind a slow/black-holed checkip endpoint — the exact lock
// discipline #2778 established for provider Upsert/Delete, which observation was
// left out of. The observation only READS external state (netlink / DHCP /
// HTTP), never manager state, so nothing under the lock is needed for the
// round-trip; the caller re-reads m.state/m.runtime after the lock is
// re-acquired before making any publish/withdraw decision. The daemon
// serializes reconcile passes (surfaceAReconcileInFlight), so no concurrent
// pass mutates m.runtime/m.state while the lock is dropped here — only the
// read-only StatusViews/Stats callers may run, which is the whole point.
// Panic-safe: the lock is re-acquired even if fn panics, keeping Reconcile's
// deferred Unlock balanced.
func (m *SurfaceAManager) observeIO(fn func()) {
	m.mu.Unlock()
	defer m.mu.Lock()
	fn()
}

// Reconcile drives one Surface A reconcile pass over the configured scopes
// (plan §5.5/§5.6). For each scope it: observes the current address; applies
// the per-RG HA gate; runs change-detection + forced-refresh + error backoff;
// and publishes/withdraws through the resolved Backend. A scope present in the
// durable store but ABSENT from `scopes` (binding removed from config) is
// WITHDRAWN (turn-off cleanup), provided this node may write its scope.
//
// gate is the SAME per-RG ScopeGate the lease reconciler uses (#2664). A nil
// gate (standalone) admits every scope. A gated-out scope is stop-writing,
// never-withdraw (the peer RG master refreshes it).
// resolveIf is the OPTIONAL committed-config Junos→kernel interface-name
// resolver (the daemon threads cfg.ResolveKernelIfName) used to resolve a
// destination-interface binding to the local node's real kernel device before
// SO_BINDTODEVICE (#5070). Omitted (tests) ⇒ the leaf slash-substitution
// fallback; a routing-instance still resolves to its vrf-<name> master.
func (m *SurfaceAManager) Reconcile(ctx context.Context, scopes []SurfaceAScope, observe AddressObserver, gate ScopeGate, catalog map[string]*config.DDNSProvider, resolveIf ...func(string) string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// #5748: republish this surface's wire-RR claim snapshot for the lease Manager's
	// teardown guard AFTER the pass mutates the store. Registered second so it runs
	// BEFORE the unlock (LIFO), still under m.mu. A degraded pass returns early with
	// an unchanged store, so the rebuild is a harmless nop.
	defer m.rebuildWireRRClaimsLocked()

	// #5070: refresh the per-pass interface-name resolver (read by resolveBackend
	// + CheckIPClient under this same lock).
	m.ifResolver = firstResolver(resolveIf)

	// FAIL CLOSED (#2971, mirroring the DHCP-lease #2650 gate): the ownership
	// state could not be loaded, so we cannot prove which router records this
	// node published. Acting now is unsafe — a publish could overwrite a
	// peer/manual owner (the lost ownership can no longer veto the re-claim) and
	// would re-publish EVERY configured scope every pass (a write storm), while a
	// withdraw has no trustworthy owned set to delete against. Refuse the whole
	// pass and DO NOT touch the state file: the empty in-memory store is never
	// saved, so the corrupt/quarantined file is preserved for the operator. A
	// standalone (nil gate) node fails closed the same way — losing the only
	// authority is no safer without a peer; a restart with the bad file
	// quarantined aside re-reads an absent (clean-empty) store and resumes
	// publishing.
	if m.degraded {
		return fmt.Errorf("ddns surface-a: reconcile suspended (state degraded): %s", m.degradedReason)
	}

	// Consume the operator force-now latch (#3276) for THIS pass: a force makes
	// every configured scope refresh-due so the RG owner re-asserts the wire
	// record even for an unchanged address inside the forced-refresh floor. The
	// latch is cleared before Pass 1 so it forces exactly one publish round; the
	// per-RG gate below still decides which scopes this node may actually write.
	force := m.forceRefresh
	m.forceRefresh = false

	now := m.now()
	var firstErr error
	noteErr := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}

	admit := func(s ScopeKey) bool {
		if gate == nil {
			return true
		}
		return gate(s)
	}

	// desired[scopeID] = the configured scope. Used to find owned records that
	// are no longer configured (withdraw), and to drive the per-scope publish.
	desired := map[string]SurfaceAScope{}
	for _, sc := range scopes {
		desired[sc.scopeID()] = sc
	}

	// Reap superseded HTTP transports (#2956): the per-binding client cache is
	// populated lazily by resolveBackend/CheckIPClient and keyed on the
	// source-binding tuple. A binding-leaf change keys a FRESH entry and the OLD
	// entry is never looked up again, but the cache outlives any single config, so
	// stale tuples (and their idle-connection pools) would accumulate for the
	// daemon lifetime. Compute the set of binding keys still referenced by this
	// pass — every configured scope's provider (the per-binding source-address
	// override is applied on the scope's provider copy) AND every catalog provider
	// (used by the removed-binding withdraw backend rebuild) plus the unbound
	// default — and drop any cached client whose key is gone. An active binding is
	// always in `live` so it is never closed.
	if m.httpClients != nil {
		live := make(map[string]struct{}, len(scopes)+len(catalog)+1)
		live[""] = struct{}{} // unbound default (nil provider / fail-open client)
		for _, sc := range scopes {
			live[bindCacheKey(sc.Provider)] = struct{}{}
		}
		for _, p := range catalog {
			live[bindCacheKey(p)] = struct{}{}
		}
		m.httpClients.reap(live)
	}

	// Pass 1 — publish / refresh / withdraw-on-address-loss each configured
	// scope.
	for _, sc := range scopes {
		if !admit(sc.Key) {
			// Per-RG gate closed: stop writing, never withdraw (plan §5.6). The
			// peer that masters this RG owns the refresh.
			slog.Debug("ddns surface-a: scope not writable from this node (per-RG gate closed); not publishing, not withdrawing",
				"fqdn", sc.FQDN, "rg", sc.Key.RGOwner, "iface", sc.Key.Interface)
			continue
		}
		noteErr(m.reconcileScopeLocked(ctx, sc, observe, now, force))
	}

	// liveByPolicy / liveByFP describe the {FQDN, AddrText} records a STILL-
	// CONFIGURED scope owns after Pass 1 — the exact name+rdata that is (or will
	// be) live at the provider — keyed by PROVIDER IDENTITY so the #2903 adoption
	// guard is provider-AWARE (#3735). A Pass 2 withdraw issues an EXACT-RR delete
	// (name+type+rdata), so withdrawing a record whose name+rdata equals a live RR
	// would REMOVE the live RR. The #2903 on-disk MIGRATION case (a pre-#2903 store
	// keyed under an FQDN-LESS scope prefix; the configured scope now keys under the
	// FQDN-bearing prefix — SAME provider, name and address) must therefore be
	// ADOPTED in place, not exact-RR deleted.
	//
	// The pre-#3735 guard keyed liveRR only on {FQDN, AddrText}, so it ALSO adopted
	// a genuine PROVIDER RENAME (prov-A → prov-B, same name+addr) — silently
	// dropping the old-provider ownership WITHOUT a wire delete and orphaning the
	// record at provider A (the codex-157 H01 bug). Keying on provider identity
	// closes that: an old record is adopted only when a still-configured record
	// with the SAME name+addr shares its PROVIDER NAME (the #2903 same-provider
	// migration — PolicyID is unchanged and present on both the FQDN-less and the
	// FQDN-bearing record) OR its non-empty backend FINGERPRINT (a pure rename to
	// the SAME endpoint — no real orphan exists, so no false alarm). A genuine
	// rename to a DIFFERENT endpoint matches neither axis, so it is no longer
	// silently adopted — it becomes a real withdraw candidate that the Pass-2
	// classifier turns into a KEEP-ownership + loud orphan alarm.
	liveByPolicy := make(map[string]struct{}, len(desired))
	liveByFP := make(map[string]struct{}, len(desired))
	for _, owned := range m.state.all() {
		osc := owned.scopeOf()
		if _, stillConfigured := desired[osc.scopePrefix()]; !stillConfigured {
			continue
		}
		liveByPolicy[osc.PolicyID+"\x00"+owned.FQDN+"\x00"+owned.AddrText] = struct{}{}
		if owned.BackendFingerprint != "" {
			liveByFP[owned.BackendFingerprint+"\x00"+owned.FQDN+"\x00"+owned.AddrText] = struct{}{}
		}
	}

	// Pass 2 — withdraw scopes whose binding was removed from config. A record
	// owned for a scope NOT in `desired` is withdrawn (turn-off cleanup), gated
	// by the same per-RG writer gate (never withdraw a scope this node does not
	// master). The live backend is REBUILT from the owned record's provider
	// attribution (scope.PolicyID → the provider catalog) — the same backend the
	// publish used — so the withdraw actually reaches the wire even though the
	// SurfaceAScope is gone (#2691 P2 MAJOR-2 fix: a removed-binding withdraw
	// MUST send a real DNS DELETE, not silently drop ownership and orphan the RR).
	for _, owned := range m.state.all() {
		osc := owned.scopeOf()
		sid := osc.scopePrefix()
		if _, stillConfigured := desired[sid]; stillConfigured {
			continue
		}
		if !admit(osc) {
			continue
		}
		// Provider-aware adopt-in-place (#2903 migration / same-endpoint rename,
		// #3735): the exact name+rdata is still owned by a configured scope with
		// the SAME provider identity (same PolicyID, or same non-empty endpoint
		// fingerprint). An exact-RR delete here would remove the just-published
		// live RR — adopt in place: drop the stale old-prefix ownership entry, no
		// wire delete, no orphan alarm.
		liveName := owned.FQDN + "\x00" + owned.AddrText
		_, adoptByPolicy := liveByPolicy[osc.PolicyID+"\x00"+liveName]
		_, adoptByFP := liveByFP[owned.BackendFingerprint+"\x00"+liveName]
		if adoptByPolicy || (owned.BackendFingerprint != "" && adoptByFP) {
			slog.Debug("ddns surface-a: stale-prefix ownership adopted by a configured same-provider scope; dropping without a wire delete",
				"fqdn", owned.FQDN, "addr", owned.AddrText, "provider", osc.PolicyID)
			m.state.delete(osc, owned.Identity, owned.Address)
			delete(m.runtime, sid)
			m.clearOrphan(owned)
			continue
		}
		// Per-scope error backoff for the gone-from-config withdraw (#2813): a
		// persistently-failing withdraw (a generic backend with no delete verb, or
		// a dyndns2/cloudflare/route53/rfc2136 delete that keeps erroring) must back
		// off its retry cadence instead of re-attempting — and warning — on every
		// 30s sweep. This reuses the SAME per-scope runtime backoff slot the publish
		// path arms (keyed by scopePrefix == sid); the runtime entry was seeded from
		// the durable store at startup (seedFromStore), so it usually already exists.
		// A scope is only ever a publish OR a withdraw candidate at one time (a
		// gone-from-config scope is absent from `desired` and never reaches Pass 1),
		// so a single shared backoff slot is correct — no withdraw-specific slot.
		rt := m.runtime[sid]
		if rt == nil {
			rt = &surfaceAState{}
			m.runtime[sid] = rt
		}
		if rt.withdrawUnsupported {
			// Terminal: the backend can never withdraw (#2813). Keep ownership (the
			// RR stays operator-visible) and do not re-attempt the wire delete.
			continue
		}
		// #3735: classify whether the record's ORIGINAL endpoint is reachable
		// through the current catalog BEFORE any backoff/withdraw. A provider that
		// is gone (H01: renamed to a different endpoint / removed) or whose endpoint
		// fingerprint no longer matches (H03: in-place server/zone edit) is
		// un-withdrawable — issuing a delete would either no-op or hit the WRONG
		// endpoint and false-success-drop ownership. KEEP ownership and raise a loud
		// operator alarm ONCE (noteOrphan is idempotent), never a wrong-endpoint
		// delete. Auto-withdrawal of the old record is DEFERRED (the old creds are
		// redacted config.Secret and the old endpoint is usually gone) — the alarm
		// tells the operator to clean it up by hand.
		backend, status, err := m.classifyOwnedBackend(owned, catalog)
		switch status {
		case ownedBackendProviderGone:
			m.noteOrphan(owned, "", orphanReasonProviderGone, now)
			continue
		case ownedBackendEndpointChanged:
			m.noteOrphan(owned, backendFingerprint(catalog[osc.PolicyID]), orphanReasonEndpointChanged, now)
			continue
		}
		if err != nil {
			m.recordScopeError(rt, owned.FQDN, 0, err, now, true)
			noteErr(err)
			continue
		}
		if !rt.nextEligible.IsZero() && now.Before(rt.nextEligible) && rt.backoffFromWithdraw {
			// Still inside a WITHDRAW-origin backoff window — skip the wire delete
			// this pass (a persistently-failing withdraw backs off). A PUBLISH-origin
			// backoff (a failed publish before the binding was removed) must NOT delay
			// this gone-from-config withdraw (#4423 M03) — the record should come down
			// promptly, and the withdraw re-arms its own backoff on failure.
			m.backedOff++
			slog.Debug("ddns surface-a: gone-from-config scope in withdraw backoff; skipping this pass",
				"fqdn", owned.FQDN, "next-eligible", rt.nextEligible)
			continue
		}
		noteErr(m.withdrawScopeLocked(ctx, owned, backend, rt, owned.FQDN, 0, now))
	}

	if err := m.state.save(); err != nil {
		slog.Warn("ddns surface-a: persist ownership state failed", "err", err)
		noteErr(err)
	}
	return firstErr
}

// reconcileScopeLocked is the per-scope engine (plan §5.5): observe → change
// detection → forced-refresh → error backoff → publish/withdraw. Caller holds
// m.mu.
func (m *SurfaceAManager) reconcileScopeLocked(ctx context.Context, sc SurfaceAScope, observe AddressObserver, now time.Time, force bool) error {
	sid := sc.scopeID()
	rt := m.runtime[sid]
	if rt == nil {
		rt = &surfaceAState{}
		m.runtime[sid] = rt
	}

	// Observe FIRST, before the error-backoff window is consulted (#4423 M03).
	// Observation is a cheap netlink/DHCP-lease read (or, for a checkip source, an
	// HTTP GET against the checkip endpoint — a DIFFERENT server than the DNS
	// provider the backoff protects), so running it every pass does not hammer the
	// backed-off provider. Observing first is what lets a newly-detected address
	// LOSS trigger a withdraw even while a prior PUBLISH failure is in its backoff
	// window: leaving the record live at a now-dead address for the whole backoff
	// (up to the cap) is a blackhole. The window is still honored PER WIRE OP below
	// (a publish-armed backoff gates publishing; a withdraw-armed backoff gates
	// withdrawing), and each op re-arms its own backoff on failure, so a
	// persistently-failing op still backs off — no hammering.
	//
	// The observe runs with m.mu RELEASED and the reconcile ctx threaded (#3736):
	// holding the mutex across a blocking checkip GET would block StatusViews/Stats
	// and serialize other scopes; ignoring ctx would hang shutdown behind an
	// in-flight probe.
	var (
		obs AddressObservation
		ok  bool
	)
	m.observeIO(func() { obs, ok = observe(ctx, sc) })
	if !ok {
		// Transient observation failure: leave the scope untouched (never
		// withdraw on a transient — the never-blackhole rule, plan §8.2).
		slog.Debug("ddns surface-a: address observation failed (transient); leaving scope untouched", "fqdn", sc.FQDN)
		return nil
	}

	// inBackoffWindow reports whether the scope is still inside an armed error
	// backoff. It is consulted per-intent below (#4423 M03) so one wire op's
	// backoff never delays the other.
	inBackoffWindow := !rt.nextEligible.IsZero() && now.Before(rt.nextEligible)

	if !obs.Addr.IsValid() {
		// The scope lost its address (interface down / lease gone). If we own a
		// record for it, withdraw it (the address really is gone — this is the
		// authoritative "no address", not a transient observation failure). We
		// still have the live SurfaceAScope here, so resolve its provider backend
		// directly — the withdraw reaches the wire (the address-loss half of the
		// #2691 P2 MAJOR-2 fix; backendForOwned is only needed for the gone-from-
		// config Pass 2 withdraw where the scope no longer exists).
		if owned, exists := m.state.get(sc.effectiveKey(), surfaceAIdentity, ""); exists {
			// Honor the backoff window ONLY when it was armed by a prior WITHDRAW
			// failure (#4423 M03): a persistently-failing withdraw still backs off,
			// but a PUBLISH-failure backoff must not delay this fresh address-loss
			// withdraw (that would keep the record live at a dead address for the
			// whole publish backoff — a blackhole).
			if inBackoffWindow && rt.backoffFromWithdraw {
				m.backedOff++
				slog.Debug("ddns surface-a: scope in withdraw backoff; skipping this pass",
					"fqdn", sc.FQDN, "next-eligible", rt.nextEligible)
				return nil
			}
			if rt.withdrawUnsupported {
				// Terminal: the resolved backend has no withdraw verb (#2813). Do not
				// re-attempt the wire delete every sweep — keep ownership (the RR is
				// operator-visible) and stay quiet (the single warn already fired).
				slog.Debug("ddns surface-a: withdraw unsupported by backend; not re-attempting (record kept)",
					"fqdn", sc.FQDN)
				return nil
			}
			backend, err := m.backendFor(sc)
			if err != nil {
				// Could not even build the backend: arm the SAME per-scope backoff the
				// publish path uses (#2813) so a persistent resolve failure backs off
				// instead of re-attempting (and warning) every 30s sweep. Tagged as a
				// withdraw-origin backoff so the withdraw-intent window check above
				// skips the next sweeps (#4423 M03).
				m.deleteFail++
				m.recordScopeError(rt, sc.FQDN, sc.ErrorBackoffMax, err, now, true)
				return err
			}
			// withdrawScopeLocked drives the delete under the shared backoff machinery:
			// success clears the scope state (the runtime entry is dropped), a transient
			// failure arms exponential backoff, an unsupported-verb failure is terminal.
			return m.withdrawScopeLocked(ctx, owned, backend, rt, sc.FQDN, sc.ErrorBackoffMax, now)
		}
		return nil
	}

	addr := obs.Addr.Unmap()

	// Honor the backoff window ONLY when it was armed by a prior PUBLISH failure
	// (#4423 M03): a persistently-failing publish still backs off (ban-avoidance),
	// but a WITHDRAW-failure backoff must not delay re-publishing a recovered
	// address. Placed before change-detection so a backed-off scope is counted as
	// a backed-off skip (not an unchanged skip), preserving the pre-#4423 counter
	// semantics of the removed top-of-function window check.
	if inBackoffWindow && !rt.backoffFromWithdraw {
		m.backedOff++
		slog.Debug("ddns surface-a: scope in publish backoff; skipping this pass",
			"fqdn", sc.FQDN, "next-eligible", rt.nextEligible)
		return nil
	}

	// Change detection + forced-refresh (inadyn ideas #4/#7): fire a wire
	// UPDATE when the address changed OR the forced-refresh floor elapsed since
	// the last successful publish. An unchanged address inside the floor is a
	// counted skip (no wire traffic).
	forced := sc.ForcedRefresh
	if forced <= 0 {
		forced = defaultForcedRefresh
	}
	changed := addr != rt.lastAddr
	// #9067: a TTL-only edit is a change too.
	//
	// Compared on the NORMALISED value, not the configured one. `sc.TTL <= 0`
	// means "use defaultDDNSTTL", and the publish path below normalises it that
	// way — so comparing the raw field would miss the explicit-to-unset edit
	// (e.g. 60 -> unset, which really does change the published TTL) while
	// reporting a spurious change for unset-to-explicit-default. Both sides go
	// through the same normalisation the wire op uses.
	//
	// Gated on a non-zero lastTTL so a scope re-adopted after restart (address
	// seeded from the durable store, TTL unknown) is not republished
	// spuriously — see surfaceAState.lastTTL.
	if rt.lastTTL != 0 && normalizeDDNSTTL(sc.TTL) != rt.lastTTL {
		changed = true
	}
	// Ownership is keyed on the scope INCLUDING the published FQDN (#2903), so a
	// hostname-only change (same address) yields a new effectiveKey for which no
	// record is owned yet → owned==false → the skip below does not fire and the
	// new name is published. The old name's record (under the previous FQDN's
	// scope key) is no longer in `desired`, so Reconcile Pass 2 withdraws it.
	ownedRec, owned := m.state.get(sc.effectiveKey(), surfaceAIdentity, "")
	// Durable crash recovery (#5285): a PENDING owned record — its desired AddrText
	// was write-ahead-saved but the wire add never CONFIRMED, because a crash struck
	// between state.save and the provider I/O — is NOT settled. The unchanged-owned
	// skip below MUST NOT suppress its recovery, or public DNS would stay at the OLD
	// value forever while the appliance falsely reported the new one (and the old
	// value's cleanup key would be lost). Force the scope refresh-due while pending
	// so publishLocked re-runs the wire op and converges the provider to the desired
	// value, threading the retained prior value as the replace/cleanup target. The
	// pending bit is cleared by publishLocked's confirm-save once the add succeeds.
	pendingRecovery := owned && ownedRec.PublishPending
	// force (#3276): the operator `request system dynamic-dns update` latch makes
	// the scope refresh-due regardless of the change-detection / forced-refresh
	// floor, so the owner re-asserts the wire record now.
	refreshDue := force || pendingRecovery || rt.lastPublished.IsZero() || now.Sub(rt.lastPublished) >= forced
	if owned && !changed && !refreshDue {
		m.skipped++
		slog.Debug("ddns surface-a: address unchanged and forced-refresh not due; skipping",
			"fqdn", sc.FQDN, "addr", addr.String())
		return nil
	}

	if err := m.publishLocked(ctx, sc, addr, now); err != nil {
		if errors.Is(err, errSurfaceANoBackend) {
			// No live backend (half-configured provider): nothing was attempted on
			// the wire. Do NOT arm error backoff and do NOT advance the
			// last-published cache — leave the publish cadence untouched so the scope
			// re-attempts every cycle once the operator adds the credential. Swallow
			// the sentinel (not a pass error). Record noBackend so the status surface
			// shows an "unpublished: no backend" row instead of omitting the scope
			// entirely (#2843).
			rt.noBackend = true
			rt.lastErr = err.Error()
			rt.lastErrAt = now
			return nil
		}
		if errors.Is(err, errSurfaceAPublishRaced) {
			// The wire add succeeded but a concurrent op changed the scope's
			// ownership while the lock was released for the I/O (#2778). Do NOT
			// advance the runtime cache to a value the live ownership no longer
			// agrees with, and do NOT arm backoff (the wire op worked). The next
			// reconcile converges the current desired state. Note: `rt` here may be
			// the entry a concurrent withdraw deleted from m.runtime — advancing it
			// would resurrect a stale map entry, so we swallow without touching rt.
			return nil
		}
		m.recordScopeError(rt, sc.FQDN, sc.ErrorBackoffMax, err, now, false)
		return err
	}
	// Success: clear backoff, update the last-published cache.
	rt.lastAddr = addr
	rt.lastTTL = normalizeDDNSTTL(sc.TTL) // #9067: store what was PUBLISHED
	rt.lastPublished = now
	rt.nextEligible = time.Time{}
	rt.backoff = 0
	rt.backoffFromWithdraw = false
	rt.lastErr = ""
	rt.lastErrAt = time.Time{}
	rt.noBackend = false
	rt.withdrawUnsupported = false
	return nil
}

// surfaceAIdentity is the fixed ownership "identity" for every Surface A record
// — a router record is keyed on its SCOPE + FQDN, not a client identity (there
// is no DHCP client). Using a constant identity keeps the ownedRecordKey shape
// shared with the lease store (scopePrefix + identity + "|" + address) while
// the scope (interface/unit/family) is the real discriminator. Address is "" in
// the key so a scope owns at most ONE record and an address change REPLACES it
// in place (no stale old-address entry, never a withdraw-then-add gap).
const surfaceAIdentity = "router-self"

// errSurfaceANoBackend is returned by publishLocked when the scope's provider
// resolved to the no-op backend (a half-configured HTTP provider). It is NOT a
// failure to back off on — nothing was attempted on the wire — and NOT a success
// (no ownership, no last-published advance). reconcileScopeLocked treats it as a
// counted no-backend skip that re-attempts next cycle (#2691 P3 review MAJOR).
var errSurfaceANoBackend = errors.New("ddns surface-a: no live backend for provider")

// errSurfaceAPublishRaced is returned by publishLocked when the wire add
// SUCCEEDED but a concurrent op changed the scope's owned record while the lock
// was released for the I/O (#2778). It is NOT a failure (the wire op worked, the
// counter advanced) and NOT a clean success for THIS desired state — the live
// ownership now reflects a newer intent. reconcileScopeLocked treats it as a
// no-op for the runtime cache (do not advance lastAddr/lastPublished, do not arm
// backoff); the next reconcile converges whatever the current desired state is.
var errSurfaceAPublishRaced = errors.New("ddns surface-a: publish raced a concurrent ownership change")

// publishLocked publishes the scope's record through the resolved Backend and
// records ownership write-ahead (the same durability discipline as the lease
// path, #2662). The ownership key fixes Address="" so a scope owns exactly one
// record: an address change REPLACES the rdata via the backend's atomic
// in-place self-owned replace (rfc2136Updater.sendAddSelfOwned: a single UPDATE
// that delete-RRsets our forward type then inserts the new rdata), never a
// withdraw-then-add that would blackhole.
//
// Lock discipline (#2778): the caller holds m.mu on entry and exit, but the
// lock is RELEASED around the wire UpsertLease (via providerIO) so a slow/hung
// provider cannot block other manager ops. Everything that touches manager
// state — backend/record construction, the ownership write-ahead + save, the
// counters, the last-published cache — happens UNDER the lock; only the wire
// call is unlocked. After the unlocked wire op the result is committed under
// the re-acquired lock with a racing-op re-validation: if a concurrent op
// changed the scope's owned record while we were unlocked, the stale wire
// result is NOT allowed to clobber the newer ownership (see below).
func (m *SurfaceAManager) publishLocked(ctx context.Context, sc SurfaceAScope, addr netip.Addr, now time.Time) error {
	backend, err := m.backendFor(sc)
	if err != nil {
		m.upsertFail++
		return err
	}
	if isNopUpdater(backend) {
		// The provider degraded to the no-op backend (a half-configured HTTP
		// provider whose constructor errored on a missing credential, e.g.
		// `backend cloudflare` with no api-token). Publishing NOTHING to any wire:
		// do NOT write-ahead ownership (it would be phantom — an RR that does not
		// exist), do NOT count an upsertOK (the counter would lie), and signal the
		// caller (errSurfaceANoBackend) so it leaves the last-published cache
		// untouched and re-attempts next cycle once the credential is added. This
		// mirrors manager.go upsertLocked's skippedNoBackend handling. The commit
		// warning already told the operator the provider is incomplete.
		m.skippedNoBackend++
		slog.Debug("ddns surface-a: provider resolved to no-op backend; skipping publish (no ownership, will re-attempt)",
			"fqdn", sc.FQDN, "provider", sc.Key.PolicyID)
		return errSurfaceANoBackend
	}
	ttl := sc.TTL
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	rec, err := buildHostRecord(sc.FQDN, addr, ttl)
	if err != nil {
		m.upsertFail++
		return err
	}

	// Ownership is keyed on the scope INCLUDING the published FQDN (#2903): a
	// hostname change is a NEW scope (no prevOwned here — the old name lives under
	// its own scope key and is withdrawn by Reconcile Pass 2), never an in-place
	// overwrite that would orphan the old RR.
	key := sc.effectiveKey()
	prevOwned, hadPrev := m.state.get(key, surfaceAIdentity, "")
	prevAddr := ""
	if hadPrev {
		if prevOwned.PublishPending {
			// The current durable row is a not-yet-confirmed PENDING write-ahead
			// (#5285): a prior crash struck between the write-ahead state.save and
			// the wire add, so its AddrText holds the DESIRED value that never
			// reached the wire. The value actually LIVE at the provider is the
			// retained CONFIRMED prior (PriorAddrText). Thread the prior so the
			// self-owned in-place replace targets xpf's real live value and cleans
			// the stale record — never the phantom desired value AddrText carries.
			prevAddr = prevOwned.PriorAddrText
		} else {
			// The previously-published rdata lives in AddrText for a Surface A
			// record (Address is the "" scope key, #2691 P2). Reading Address here
			// always yielded "" so the "replaced record address" renumber log below
			// never fired — a WAN renumber left no operational trace (#3734/M02).
			// Prefer AddrText; fall back to Address only for a legacy lease-shape
			// entry.
			prevAddr = prevOwned.AddrText
			if prevAddr == "" {
				prevAddr = prevOwned.Address
			}
		}
	}

	// Thread the previously-published rdata to the backend (#3739) so a
	// self-owned publish can do a VALUE-SPECIFIC in-place replace — touch only
	// xpf's own prior value, never a co-resident FOREIGN record at a shared
	// name. On a first publish (or a lost prior value) PrevAddr stays invalid and
	// the backend does an additive insert/create instead of clobbering the name.
	if prevAddr != "" {
		if pa, perr := netip.ParseAddr(prevAddr); perr == nil {
			rec.PrevAddr = pa.Unmap()
		}
	}

	// Non-secret backend fingerprint for this publish (#3735). Stored on the owned
	// record so a later provider identity change is detectable, and compared here
	// against the previous publish's fingerprint to catch an IN-PLACE provider
	// mutation (H02): the scope key {PolicyID, FQDN} is unchanged (server/zone/
	// creds are not in the key), so this scope is NEVER a Pass-2 withdraw candidate;
	// the republish would overwrite the same ownership key with the NEW endpoint and
	// silently orphan the record at the OLD endpoint. When the stored and current
	// fingerprints both resolve and differ, the old endpoint's record is stale and
	// un-withdrawable (the catalog now resolves this provider to the new endpoint),
	// so raise the SAME loud operator alarm instead of silently overwriting. We
	// still publish the new record (the operator wants it live at the new endpoint);
	// auto-withdrawal of the old one is DEFERRED (redacted creds / decommissioned
	// endpoint) — the alarm tells the operator to clean it up by hand.
	fp := backendFingerprint(sc.Provider)
	if hadPrev && prevOwned.BackendFingerprint != "" && fp != "" && prevOwned.BackendFingerprint != fp {
		m.noteOrphan(prevOwned, fp, orphanReasonEndpointChangedInPlace, now)
	}

	// Write-ahead the ownership intent BEFORE the wire add (#2662 + #5285): the
	// durable row records the DESIRED address as PENDING (PublishPending=true) and
	// RETAINS the last-confirmed value (PriorAddrText) until the wire add confirms.
	// This closes the save->wire crash window (#5285): a crash after this save but
	// before/inside the wire add leaves a PENDING record (never a false-confirmed
	// one), so restart recovery re-runs the provider I/O and still knows the prior
	// value's cleanup key. The confirm-save AFTER a successful wire add clears the
	// pending bit and releases the prior value (mirrors the DHCP-lease PTRPending
	// idiom). The in-process rollback below still handles a NON-crash wire failure.
	ow := ownedRecord{
		Family:             familyInt(addr),
		Identity:           surfaceAIdentity,
		Address:            "", // key on scope+FQDN; rdata lives in AddrText below
		FQDN:               rec.FQDN,
		ForwardType:        rec.ForwardType,
		PTRName:            "",
		TTL:                ttl,
		AddrText:           addr.String(),
		BackendFingerprint: fp,
		PublishPending:     true,     // #5285: desired, not yet confirmed on the wire
		PriorAddrText:      prevAddr, // #5285: last-confirmed value retained for replace + cleanup
	}.withScope(key)
	m.state.put(ow)
	if err := m.state.save(); err != nil {
		// Could not durably record ownership: do NOT publish. Roll back to the
		// previous durable state.
		if hadPrev {
			m.state.put(prevOwned)
		} else {
			m.state.delete(key, surfaceAIdentity, "")
		}
		m.upsertFail++
		return fmt.Errorf("ddns surface-a: cannot durably record ownership before publish: %w", err)
	}

	// Perform the wire UpsertLease with m.mu RELEASED (#2778): the 15s-timeout
	// provider call must not block StatusViews/Stats/other scopes. The ownership
	// write-ahead above is already durable, so a crash during the unlocked window
	// still finds the record owned and the next reconcile converges it.
	wireErr := m.providerIO(func() error { return backend.UpsertLease(ctx, rec) })

	// Re-acquired the lock. Re-validate that THIS publish's write-ahead is still
	// the live owned record before acting on the (possibly stale) wire result. A
	// concurrent op (a racing reconcile, a withdraw, a removed-binding cleanup)
	// could have replaced or deleted the ownership entry while we were unlocked;
	// if so, the newer state wins and we must NOT clobber it with a rollback or a
	// stale success — just report the wire outcome and let the next pass converge.
	cur, stillOwned := m.state.get(key, surfaceAIdentity, "")
	stale := !stillOwned || cur.AddrText != ow.AddrText
	if wireErr != nil {
		// Hard add failure: the record is NOT live with the new rdata. Restore
		// the previous durable ownership (the old address is still live) so we
		// do not claim an address we failed to publish. A conflict refusal
		// (name owned by another party) also lands here — Surface A does not
		// adopt a third party's name.
		//
		// Racing-op guard (#2778): only roll back if OUR write-ahead is still the
		// live entry. If a concurrent op already changed the owned record while we
		// were unlocked, rolling back to prevOwned would clobber the newer truth —
		// leave it alone and let the next reconcile converge.
		if !stale {
			if hadPrev {
				m.state.put(prevOwned)
			} else {
				m.state.delete(key, surfaceAIdentity, "")
			}
			_ = m.state.save()
		}
		m.upsertFail++
		if errors.Is(wireErr, errDDNSConflictRefused) {
			return fmt.Errorf("ddns surface-a: %s is owned by another party (refused): %w", rec.FQDN, wireErr)
		}
		return fmt.Errorf("ddns surface-a: publish %s %s=%s: %w", rec.ForwardType, rec.FQDN, addr, wireErr)
	}

	if stale {
		// The wire add succeeded, but a concurrent op changed the scope's desired
		// ownership while we were unlocked. The owned record now reflects the
		// newer intent (or the scope was withdrawn); count the successful wire op
		// for honesty but do NOT advance the (caller-owned) last-published cache
		// to a value the live ownership no longer agrees with — the next reconcile
		// reconciles the current desired state. Signal the caller via a sentinel
		// so it skips the lastAddr/lastPublished advance.
		m.upsertOK++
		slog.Debug("ddns surface-a: publish raced a concurrent ownership change; not advancing cache",
			"fqdn", rec.FQDN, "published", addr.String())
		return errSurfaceAPublishRaced
	}

	// Success. If the address CHANGED (replace), the self-owned add already
	// updated the rdata in place at the server (sendAddSelfOwned's atomic
	// delete-RRset + insert), so there is no separate withdraw of the old
	// address — the never-blackhole replace. Log the transition for observability.
	if prevAddr != "" && prevAddr != addr.String() {
		slog.Info("ddns surface-a: replaced record address",
			"fqdn", rec.FQDN, "old", prevAddr, "new", addr.String())
	} else if !hadPrev {
		slog.Info("ddns surface-a: published record", "fqdn", rec.FQDN, "addr", addr.String())
	}
	m.upsertOK++

	// CONFIRM the publish (#5285): the wire add SUCCEEDED, so mark the durable row
	// CONFIRMED — clear the pending bit, make the desired address the confirmed one,
	// and RELEASE the retained prior value (its cleanup key: the self-owned in-place
	// replace already took the old rdata down at the server). This confirm-save runs
	// AFTER the wire op, so a crash before it leaves the PENDING write-ahead intact
	// and recovery re-runs the idempotent wire add rather than false-confirming a
	// value that never reached the wire. A confirm-save failure is non-fatal: the
	// record is still durably owned via the pending write-ahead, so the next
	// reconcile re-runs the idempotent add to clear the flag (mirrors upsertLocked's
	// confirm posture).
	confirmed := ow
	confirmed.PublishPending = false
	confirmed.PriorAddrText = ""
	m.state.put(confirmed)
	if err := m.state.save(); err != nil {
		slog.Warn("ddns surface-a: cannot persist confirmed ownership after publish (record still owned via pending write-ahead)",
			"fqdn", rec.FQDN, "err", err)
	}
	return nil
}

// withdrawOwnedLocked removes the firewall's own record for an owned scope
// (binding removed, or address lost) through the GIVEN backend, then drops the
// ownership entry. Caller holds m.mu and is responsible for resolving the LIVE
// backend (Pass 1 from the live scope via backendFor, Pass 2 from the provider
// catalog via classifyOwnedBackend) so the delete actually reaches the wire — a nil/
// no-op backend would orphan the RR (#2691 P2 MAJOR-2). A delete is re-derived
// from the EXACT owned tuple (the sole-delete-authority boundary, shared with
// the lease path): Surface A never deletes a name it did not record.
//
// Delete-target selection (#5334): the wire delete must target the value ACTUALLY
// LIVE at the provider. For a SETTLED record that is unambiguously AddrText. For a
// crash-left PENDING record (#5285) which value is live is AMBIGUOUS — publishLocked
// has TWO crash windows and the persisted {AddrText=B, PriorAddrText=A} shape is
// byte-identical in both:
//   - Window 1: crash BETWEEN the durable write-ahead save and the wire add — B
//     never reached the provider, so the CONFIRMED prior A is still live.
//   - Window 2: crash AFTER a SUCCESSFUL wire add but BEFORE the confirm-save
//     clears the pending bit — sendAddSelfOwned atomically removed A and inserted
//     B, so B is live and A is gone.
//
// The pending bit cannot distinguish the windows, so withdrawing EITHER single
// value orphans the other window's live RR. Rather than guess one horn, a pending
// withdraw issues an exact-RR delete of BOTH candidate rdata (AddrText AND
// PriorAddrText, deduplicated). A value-specific exact-RR delete of a value that
// is NOT live is BENIGN (rfc2136 sendRemove maps NXRrset/NameError to success;
// host-granular DuckDNS/dyndns2 ignore the rdata and SiblingFamilyOwned already
// guards the live sibling), so the both-delete removes whichever value the crash
// left live and no-ops the other — the invariant holds regardless of the window.
//
// Observability honesty (#2691 P2 MINOR M1): the ownership entry is dropped only
// AFTER a successful wire delete; a failed delete increments deleteFail (not
// deleteOK) and leaves the entry so the next reconcile retries. A no-op backend
// (provider unresolvable) is treated as a FAILURE — it did NOT remove the RR, so
// it must not report success nor drop ownership (which would orphan the RR).
//
// Lock discipline (#2778): the caller holds m.mu on entry and exit, but the lock
// is RELEASED around the wire DeleteLease (via providerIO) so a slow/hung
// provider cannot block other manager ops. After the unlocked delete the
// ownership drop is committed under the re-acquired lock with a racing-op
// re-validation: the entry is dropped only if it is STILL the exact record we
// deleted (same scope+identity+address-text). If a concurrent publish re-asserted
// the scope with a different address while we were unlocked, we must NOT drop the
// newer ownership — that would orphan the freshly-published RR.
func (m *SurfaceAManager) withdrawOwnedLocked(ctx context.Context, owned ownedRecord, backend DNSUpdater) error {
	// #5334: the set of rdata to exact-RR delete. A SETTLED record yields just its
	// live AddrText; a crash-left PENDING record yields BOTH crash-window candidates
	// (AddrText and PriorAddrText) so the actually-live value is removed regardless
	// of which window the crash fell in (see the doc comment). Empties/unparseables
	// are dropped and duplicates coalesced.
	targets := m.withdrawTargets(owned)
	if len(targets) == 0 {
		// No parseable rdata to delete (should not happen for a Surface A record —
		// a settled record always carries a parseable AddrText). Drop the entry to
		// avoid wedging rather than issue a delete with a guessed address.
		slog.Warn("ddns surface-a: owned record has no parseable address; dropping entry",
			"fqdn", owned.FQDN, "addr", owned.AddrText, "prior", owned.PriorAddrText)
		m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
		delete(m.runtime, owned.scopeOf().scopePrefix())
		m.clearOrphan(owned)
		return nil
	}
	if isNopUpdater(backend) {
		// No live backend resolved (provider gone from the catalog): the RR
		// cannot be withdrawn. Do NOT claim success or drop ownership — leaving
		// the entry keeps the RR cleanable once the provider is reconfigured, and
		// keeps the deleteOK counter honest (#2691 P2 MINOR M1).
		m.deleteFail++
		slog.Warn("ddns surface-a: cannot withdraw record — no live backend for its provider; keeping ownership for retry",
			"fqdn", owned.FQDN, "addr", owned.AddrText, "provider", owned.scopeOf().PolicyID)
		return fmt.Errorf("ddns surface-a: no live backend to withdraw %s", owned.FQDN)
	}
	// #3738: whether a SIBLING family is still owned at this {provider, FQDN}. A
	// host-granular-withdraw backend (DuckDNS clear=true, dyndns2 offline=YES — both
	// take the WHOLE hostname down) uses this to SKIP its destructive verb so a
	// single-family withdraw does not blackhole the live sibling; per-family
	// backends (rfc2136/cloudflare/route53/bind) ignore it. Identical for every
	// candidate delete of this record (same family/FQDN/provider), so compute once.
	sibling := m.siblingFamilyOwnedLocked(owned)
	var firstErr error
	noteFirst := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	var deferredCoowned int // #6015: targets a DHCP lease still co-owns (defer + re-assert)
	var deleted int         // real wire deletes issued this pass
	for _, a := range targets {
		// #5748 + #6015 (cross-surface arm of #5709): if a Surface B DHCP lease
		// scope still co-owns THIS exact wire RR (canonical FQDN + forward type +
		// this rdata), Surface A must not issue the wire delete — that would clobber
		// the RR the lease surface still legitimately owns and refreshes (the #6012
		// caution). But it must also not suppress-and-RELEASE its own claim the way
		// the lease side does: that is the #6015 window-(b) mutual-suppression path.
		// If BOTH surfaces tear down the SAME co-owned RR in overlapping passes, each
		// reads the OTHER's pre-rebuild (end-of-pass) snapshot — still listing the RR
		// as owned — so if both released their claims the RR would be left on the
		// wire UNOWNED (orphaned).
		//
		// The deterministic tie-break (#6015): Surface B (the lease Manager) is the
		// SOLE SUPPRESSION AUTHORITY — it alone suppress-and-RELEASES a cross-surface
		// co-owned RR (unchanged from #6012, deleteOwnedLocked / wireRRSharedWithOther).
		// Surface A is the NON-AUTHORITY: it DEFERS — it RE-ASSERTS (re-UPSERTs) the
		// RR so a leaked RR self-heals, and KEEPS its ownership claim, retrying the
		// teardown on later passes. The real delete is deferred until the lease
		// authority has RELEASED its co-ownership (a later pass finds
		// leaseWireRRCoowner false for every target and deletes normally below).
		// Because B always releases first and A always defers-until-B-is-gone, exactly
		// ONE surface ever deletes a cross-surface co-owned RR — mutual suppression can
		// never orphan it, and A never clobbers B's still-owned record. The
		// leaseCoowners read is LOCK-FREE (no Manager.mu), so this is safe under m.mu.
		// #6755: pass THIS record's publish-time authority so a lease claim at a
		// DIFFERENT DNS endpoint no longer suppresses the delete.
		if m.leaseWireRRCoowner(owned.FQDN, owned.ForwardType, a.String(), owned.BackendFingerprint) {
			deferredCoowned++
			m.deleteCoowned++
			// Re-assert the RR (self-heal): re-UPSERT the exact owned RR so a leaked
			// co-owned record (e.g. the residual window-(a) sub-ms clobber) is
			// restored. Re-adding an identical RR is idempotent at the provider.
			if rec, err := buildHostRecord(owned.FQDN, a, owned.TTL); err == nil {
				noteFirst(m.providerIO(func() error { return backend.UpsertLease(ctx, rec) }))
			} else {
				noteFirst(err)
			}
			slog.Debug("ddns surface-a: cross-surface co-owned RR — deferring wire delete and "+
				"re-asserting; a DHCP lease scope still co-owns it (keeping claim until it releases)",
				"fqdn", owned.FQDN, "type", owned.ForwardType, "addr", a.String(),
				"provider", owned.scopeOf().PolicyID)
			continue
		}
		rec, err := buildHostRecord(owned.FQDN, a, owned.TTL)
		if err != nil {
			noteFirst(err)
			continue
		}
		rec.SiblingFamilyOwned = sibling
		// Wire DeleteLease with m.mu RELEASED (#2778): the 15s-timeout provider call
		// must not block StatusViews/Stats/other scopes. A delete of a non-live
		// candidate is a benign no-op (the backend maps not-found to success), so an
		// error here is a REAL provider failure.
		if err := m.providerIO(func() error { return backend.DeleteLease(ctx, rec) }); err != nil {
			noteFirst(err)
		} else {
			deleted++
		}
	}
	if firstErr != nil {
		// A candidate delete (or a deferred re-assert) failed with a real provider
		// error. Keep ownership so the next reconcile retries EVERY candidate (an
		// already-deleted one is a benign no-op) — a genuinely-live value is never
		// orphaned. The errGenericDeleteUnsupported sentinel is preserved (%w) so
		// withdrawScopeLocked marks the scope terminal instead of retrying a
		// structurally-unsupported verb.
		m.deleteFail++
		return fmt.Errorf("ddns surface-a: withdraw %s %s: %w", owned.ForwardType, owned.FQDN, firstErr)
	}
	// deleteOK counts a real wire withdraw. If every candidate was cross-surface
	// co-owned (deferred) nothing was deleted — do not inflate deleteOK; the
	// deleteCoowned counter already recorded the suppression.
	if deleted > 0 {
		m.deleteOK++
	}
	// #6015 deterministic tie-break: if ANY target is still cross-surface co-owned
	// by a DHCP lease, this record is a DEFERRED cross-surface teardown — KEEP the
	// ownership claim (do NOT drop it below) so the RR is never orphaned and Surface
	// A stays the deterministic last-claimant that deletes only once the lease
	// authority has released. rebuildWireRRClaimsLocked keeps advertising the claim
	// so the lease side still sees the co-ownership. A later pass, once the lease no
	// longer co-owns, falls through to the real delete + ownership release.
	//
	// Steady-state note (#6015): if a live DHCP lease legitimately co-owns this RR
	// indefinitely while A's own binding is permanently removed, A defers FOREVER —
	// it re-UPSERTs the identical RR and keeps its Scopes claim every reconcile pass
	// until the lease releases. That is correct (never orphan, never clobber) and
	// bounded to ~1 idempotent UPSERT per poll at DDNS cadence (not per-packet).
	if deferredCoowned > 0 {
		return nil
	}

	// Racing-op guard (#2778): drop ownership only if the live entry is STILL the
	// exact record we deleted. A concurrent publish could have re-asserted this
	// scope (new address) while we were unlocked; that publish re-wrote the owned
	// record (a different AddrText) and already drove its own wire add. Dropping
	// it here would orphan the freshly-published RR. Leave the newer entry; the
	// next reconcile converges it.
	cur, stillOwned := m.state.get(owned.scopeOf(), owned.Identity, owned.Address)
	if stillOwned && cur.AddrText != owned.AddrText {
		slog.Debug("ddns surface-a: withdraw raced a concurrent re-publish; keeping newer ownership",
			"fqdn", owned.FQDN, "withdrew", owned.AddrText, "current", cur.AddrText)
		return nil
	}
	m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
	delete(m.runtime, owned.scopeOf().scopePrefix())
	m.clearOrphan(owned)
	slog.Info("ddns surface-a: withdrew record",
		"fqdn", owned.FQDN, "addr", owned.AddrText, "candidates", len(targets))
	return nil
}

// withdrawTargets returns the deduplicated, parseable rdata an exact-RR withdraw
// must delete for an owned record (#5334). A SETTLED record yields exactly its
// live AddrText. A crash-left PENDING record (PublishPending=true) yields BOTH
// AddrText and PriorAddrText — the two crash-window candidates for "which value is
// live" (see withdrawOwnedLocked's doc comment) — so the both-delete removes
// whichever the crash left live and benign-no-ops the other. Empty and
// unparseable values are dropped (an unparseable stored rdata is logged and
// skipped, never guessed) and duplicates coalesced (a same-value pending record
// collapses to one delete). Caller holds m.mu.
func (m *SurfaceAManager) withdrawTargets(owned ownedRecord) []netip.Addr {
	texts := []string{owned.AddrText}
	if owned.PublishPending && owned.PriorAddrText != "" {
		texts = append(texts, owned.PriorAddrText)
	}
	out := make([]netip.Addr, 0, len(texts))
	seen := make(map[netip.Addr]struct{}, len(texts))
	for _, t := range texts {
		if t == "" {
			continue
		}
		a, err := netip.ParseAddr(t)
		if err != nil {
			slog.Warn("ddns surface-a: owned record has unparseable withdraw rdata; skipping that candidate",
				"fqdn", owned.FQDN, "addr", t, "err", err)
			continue
		}
		a = a.Unmap()
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

// SetLeaseCoownerSource injects the accessor the daemon wires so a Surface A
// teardown can consult the Surface B DHCP lease surface for a cross-surface
// wire-RR co-owner (#5748, symmetric direction). fn MUST be lock-free with respect
// to Manager.mu (it is Manager.WireRRClaims, a bare atomic load) so calling it
// under m.mu can never deadlock. Idempotent; nil clears it.
func (m *SurfaceAManager) SetLeaseCoownerSource(fn func() []WireRRClaim) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaseCoowners = fn
}

// WireRRClaims returns a LOCK-FREE snapshot of the wire RRs this (Surface A)
// surface currently owns, for the lease Manager's teardown guard to consult
// (#5748). It does a bare atomic load and NEVER takes m.mu, so a peer holding
// Manager.mu can call it with no lock-order cycle. Empty before the first rebuild.
func (m *SurfaceAManager) WireRRClaims() []WireRRClaim {
	if p := m.wireRRClaims.Load(); p != nil {
		return *p
	}
	return nil
}

// rebuildWireRRClaimsLocked recomputes this surface's published wire-RR claim
// snapshot from the durable store and publishes it atomically for the lease
// Manager's lock-free read (#5748). Caller holds m.mu. A Surface A record's rdata
// is its AddrText (with the legacy lease-shape Address fallback — the same
// precedence classifyOwnedBackend/withdrawTargets use); rdata-less rows are
// skipped. The snapshot is an immutable slice, replaced wholesale.
func (m *SurfaceAManager) rebuildWireRRClaimsLocked() {
	claims := make([]WireRRClaim, 0, len(m.state.records))
	for _, r := range m.state.records {
		rdata := r.AddrText
		if rdata == "" {
			rdata = r.Address // legacy lease-shape entry (pre-AddrText)
		}
		if rdata == "" {
			continue
		}
		// #6755: the record's own publish-time endpoint fingerprint. Stored on
		// the durable record since #3735 for the withdraw path, so no catalog
		// lookup is needed here and the authority is the one this record was
		// ACTUALLY published to, not whatever the catalog says today.
		claims = append(claims, wireRRClaim(r.FQDN, r.ForwardType, rdata, r.BackendFingerprint))
	}
	m.wireRRClaims.Store(&claims)
}

// leaseWireRRCoowner reports whether a Surface B DHCP lease scope still co-owns
// the wire RR (canonical FQDN + forward type + rdata) this Surface A teardown is
// about to delete (#5748). It reads the injected lease-claim snapshot LOCK-FREE
// (no Manager.mu), so it is safe to call while holding m.mu. Nil accessor ⇒ no
// cross-surface co-owner (pre-#5748 behavior). Caller holds m.mu.
func (m *SurfaceAManager) leaseWireRRCoowner(fqdn, forwardType, rdata, authority string) bool {
	if m.leaseCoowners == nil {
		return false
	}
	want := wireRRClaim(fqdn, forwardType, rdata, authority)
	for _, c := range m.leaseCoowners() {
		if c.coOwns(want) {
			return true
		}
	}
	return false
}

// siblingFamilyOwnedLocked reports whether ANOTHER owned record shares this
// record's published FQDN and provider under the OPPOSITE address family — the
// dual-stack same-name topology (#3738). A host-granular-withdraw backend
// (DuckDNS clear=true / dyndns2 offline=YES, which take the WHOLE hostname down)
// uses this to SUPPRESS its destructive verb so a single-family withdraw does
// not blackhole the still-live sibling. The match is on {PolicyID, FQDN,
// opposite Family}: the collateral-damage condition is precisely a co-located
// sibling at the SAME provider — a same-name record at a DIFFERENT provider is a
// different authoritative server the verb cannot touch, so it is not a sibling
// for this purpose. The record's own entry (same Family) is skipped, so it never
// self-matches. Caller holds m.mu.
func (m *SurfaceAManager) siblingFamilyOwnedLocked(owned ownedRecord) bool {
	osc := owned.scopeOf()
	fqdn := canonicalDDNSName(owned.FQDN)
	for _, r := range m.state.all() {
		if r.Family == owned.Family {
			continue
		}
		if r.scopeOf().PolicyID != osc.PolicyID {
			continue
		}
		if canonicalDDNSName(r.FQDN) == fqdn {
			return true
		}
	}
	return false
}

// canonicalDDNSName normalizes a published FQDN for equality comparison: trim
// surrounding whitespace, drop a single trailing dot, and lowercase (DNS names
// are case-insensitive). Used by the #3738 sibling-family scan so "Home.duckdns.org."
// and "home.duckdns.org" resolve to the same name.
func canonicalDDNSName(fqdn string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
}

// backendFor resolves the live Backend for a scope's provider (resolve-per-
// Reconcile). The static `backend` field (test injection) wins when set.
func (m *SurfaceAManager) backendFor(sc SurfaceAScope) (DNSUpdater, error) {
	if m.newBackend == nil {
		if m.backend != nil {
			return m.backend, nil
		}
		return nopUpdater{}, nil
	}
	return m.newBackend(sc.Provider, sc.FQDN, sc.TTL)
}

// backendFingerprint returns a STABLE, NON-SECRET fingerprint of a provider's
// backend ENDPOINT IDENTITY — the backend TYPE plus the server / zone /
// hosted-zone / region / generic URL template (#3735). It deliberately EXCLUDES
// every credential (TSIGSecret / Password / APIToken / AWSSecretAccessKey — all
// config.Secret) and every non-endpoint field, so persisting it on the durable
// ownedRecord does NOT reopen the #2053 plaintext-secret-on-disk class: no secret
// is ever hashed in or written out. A change in this fingerprint between the
// stored ownership and the current provider means the record was published at a
// DIFFERENT endpoint than the one now configured for the same scope/name — the
// H01/H02/H03 signal. Returns "" for a nil provider (fingerprint unknown —
// compared as "cannot determine a mismatch", never a false alarm). The empty
// backend token normalizes to "rfc2136" to match resolveSurfaceABackend's default
// so an explicit `backend rfc2136` and the implicit default share a fingerprint.
func backendFingerprint(p *config.DDNSProvider) string {
	if p == nil {
		return ""
	}
	backend := p.Backend
	if backend == "" {
		backend = "rfc2136" // resolveSurfaceABackend's default
	}
	return authorityFingerprint(
		backend,
		p.UpdateServer, // rfc2136 target
		p.Server,       // dyndns2 endpoint override
		p.Zone,         // cloudflare zone
		p.HostedZoneID, // route53 hosted zone
		p.AWSRegion,    // route53 region
		p.URLTemplate,  // generic endpoint template (%u/%p are placeholders, not live creds)
	)
}

// authorityFingerprint is the SHARED format behind every DDNS authority
// identity in this package (#6755). Both ownership surfaces derive their
// identity through it, so the two can never drift into hashing the same
// endpoint differently — a divergence here would silently make two records at
// one authority look like two authorities, which reverts #5748's cross-surface
// clobber protection.
//
// Length-prefixed, order-fixed and credential-free, so no pair of adjacent
// fields can alias across the boundary (a value cannot inject the separator)
// and no secret material participates.
//
// The Surface A provider catalog and the DHCP lease policy populate DIFFERENT
// subsets of these slots, and that is deliberate rather than a gap: `Zone`,
// `HostedZoneID`, `AWSRegion` and `URLTemplate` are backend-specific fields
// (Zone is documented as the CLOUDFLARE zone and is read only by
// backend_cloudflare.go), so an rfc2136 provider leaves them empty on BOTH
// sides. rfc2136 is the one backend the two surfaces share, and for it each
// side populates exactly `backend` + `updateServer` — so the same server hashes
// identically across surfaces, and a genuinely different backend or endpoint
// does not.
func authorityFingerprint(backend, updateServer, server, zone, hostedZoneID, awsRegion, urlTemplate string) string {
	var sb strings.Builder
	writeField := func(s string) { fmt.Fprintf(&sb, "%d:%s|", len(s), s) }
	writeField(backend)
	writeField(updateServer)
	writeField(server)
	writeField(zone)
	writeField(hostedZoneID)
	writeField(awsRegion)
	writeField(urlTemplate)
	h := fnv.New64a()
	_, _ = h.Write([]byte(sb.String()))
	return fmt.Sprintf("fp1-%016x", h.Sum64())
}

// leaseAuthorityFingerprint is the DHCP lease surface's authority identity,
// built through the same shared format so it is comparable with a Surface A
// record's stored BackendFingerprint (#6755).
//
// DHCPDynamicDNSConfig carries Backend and UpdateServer (documented as the
// rfc2136 host:port target) and no other endpoint-identifying field, so the
// remaining slots are empty — which is exactly what an rfc2136 Surface A
// provider produces. The TSIG material is deliberately NOT included: it is
// credential material, and two policies differing only in key would still be
// the same authority.
func leaseAuthorityFingerprint(c *config.DHCPDynamicDNSConfig) string {
	if c == nil {
		return ""
	}
	backend := c.Backend
	if backend == "" {
		backend = "rfc2136" // the lease surface's default, matching Surface A's
	}
	return authorityFingerprint(backend, c.UpdateServer, "", "", "", "", "")
}

// ownedBackendStatus classifies whether an owned record's ORIGINAL publish
// endpoint can be rebuilt from the CURRENT provider catalog for a withdraw
// (#3735). Only ownedBackendOK is safe to issue a wire delete against — the other
// two mean the old endpoint is unreachable through the current config, so a
// withdraw would either no-op (provider gone) or, worse, delete at the WRONG
// endpoint and false-success-drop ownership (endpoint changed).
type ownedBackendStatus int

const (
	// ownedBackendOK — the provider is present and its endpoint fingerprint still
	// matches (or one side is unknown, so no mismatch can be proven): the returned
	// backend reaches the record's original endpoint. Safe to withdraw.
	ownedBackendOK ownedBackendStatus = iota
	// ownedBackendProviderGone — the record's provider (scope.PolicyID) is no
	// longer in the catalog (H01: renamed/removed): the old endpoint cannot be
	// rebuilt (no server/creds), so the record is orphaned.
	ownedBackendProviderGone
	// ownedBackendEndpointChanged — the provider is present but its endpoint
	// fingerprint no longer matches the record's stored fingerprint (H03: an
	// in-place server/zone edit after the binding was removed): rebuilding from the
	// catalog reaches the NEW endpoint, so a withdraw there would delete at the
	// wrong place / no-op and false-success-drop ownership. The record is orphaned.
	ownedBackendEndpointChanged
)

// classifyOwnedBackend resolves the live backend for a WITHDRAW of an owned
// record whose binding is gone from config (#2691 P2 MAJOR-2), and classifies
// whether that backend actually reaches the record's ORIGINAL endpoint (#3735 —
// the provider-aware successor to the old backendForOwned). It REBUILDS the same
// backend the publish used by looking the owned record's provider (scope.PolicyID)
// up in the still-committed catalog and feeding it through newBackend — so a
// removed-binding withdraw sends a real DNS DELETE instead of orphaning the RR.
// The static `backend` field (test injection) always wins and is ownedBackendOK
// (a fixed test backend is the single endpoint). A missing provider is
// ownedBackendProviderGone; a present-but-fingerprint-mismatched provider is
// ownedBackendEndpointChanged — both keep ownership + alarm rather than issuing a
// wrong-endpoint delete / false-success drop.
func (m *SurfaceAManager) classifyOwnedBackend(owned ownedRecord, catalog map[string]*config.DDNSProvider) (DNSUpdater, ownedBackendStatus, error) {
	if m.backend != nil {
		return m.backend, ownedBackendOK, nil
	}
	if m.newBackend == nil {
		return nopUpdater{}, ownedBackendProviderGone, nil
	}
	policyID := owned.scopeOf().PolicyID
	prov := catalog[policyID]
	if prov == nil {
		// The provider was removed alongside the binding (or renamed to a new
		// name): no credentials/server to rebuild the backend, so the RR cannot be
		// withdrawn — orphaned.
		return nopUpdater{}, ownedBackendProviderGone, nil
	}
	// A provider identity change under the SAME name (H03) keeps the PolicyID but
	// points at a DIFFERENT endpoint. Compare the stored fingerprint with the
	// current provider's; a proven mismatch means the catalog no longer describes
	// the endpoint this record lives at, so a withdraw here would hit the wrong
	// server (or no-op and false-success-drop ownership). Both fingerprints must
	// be non-empty to prove a mismatch (an unknown/pre-#3735 fingerprint is never
	// a false alarm).
	if owned.BackendFingerprint != "" {
		if cur := backendFingerprint(prov); cur != "" && cur != owned.BackendFingerprint {
			return nopUpdater{}, ownedBackendEndpointChanged, nil
		}
	}
	b, err := m.newBackend(prov, owned.FQDN, owned.TTL)
	return b, ownedBackendOK, err
}

// orphanKey is the stable m.orphans map key for an owned record (#3735): its
// scope prefix + published name + address. A given orphaned record contributes
// exactly one entry regardless of how many reconcile passes re-observe it.
func orphanKey(owned ownedRecord) string {
	return owned.scopeOf().scopePrefix() + "|" + owned.FQDN + "|" + owned.AddrText
}

// noteOrphan records (once) that an owned record is stale at a PREVIOUS provider
// endpoint and cannot be withdrawn automatically (#3735), and emits a single loud
// operator alarm. It is idempotent by orphanKey so a re-derived orphan (every
// reconcile re-classifies the still-owned H01/H03 records) does not re-warn each
// sweep. newFP is the current provider's endpoint fingerprint ("" when the
// provider is gone from the catalog). Caller holds m.mu.
func (m *SurfaceAManager) noteOrphan(owned ownedRecord, newFP, reason string, now time.Time) {
	if m.orphans == nil {
		m.orphans = map[string]surfaceAOrphan{}
	}
	key := orphanKey(owned)
	if _, ok := m.orphans[key]; ok {
		return // already alarmed — do not re-warn every sweep
	}
	osc := owned.scopeOf()
	m.orphans[key] = surfaceAOrphan{
		FQDN:           owned.FQDN,
		Address:        owned.AddrText,
		Provider:       osc.PolicyID,
		Interface:      osc.Interface,
		Unit:           osc.Unit,
		Family:         int(osc.Family),
		OldFingerprint: owned.BackendFingerprint,
		NewFingerprint: newFP,
		Reason:         reason,
		FirstSeen:      now,
	}
	slog.Warn("ddns surface-a: provider identity changed; OLD record ORPHANED at the previous endpoint and cannot be withdrawn automatically — MANUAL CLEANUP REQUIRED",
		"fqdn", owned.FQDN, "addr", owned.AddrText, "provider", owned.scopeOf().PolicyID,
		"old-endpoint", owned.BackendFingerprint, "new-endpoint", newFP, "reason", reason)
}

// clearOrphan drops any orphan alarm for an owned record (#3735) — called when
// the record is cleanly adopted-in-place or withdrawn, so a later genuine
// re-orphan re-alarms. A delete on an absent key is a no-op.
func (m *SurfaceAManager) clearOrphan(owned ownedRecord) {
	delete(m.orphans, orphanKey(owned))
}

// recordScopeError records a failure on a scope and advances its flat error
// backoff (inadyn idea #8): nextEligible = now + backoff, doubling from
// surfaceABaseBackoff up to the cap. Surfaced via lastErr for observability.
//
// Shared by the publish AND both withdraw paths (#2813): a scope is only ever a
// publish OR a withdraw candidate at one time, so one per-scope backoff slot is
// correct. fqdn is for the log line; maxBackoff is the per-binding cap (0 ⇒ the
// package default, which is what the gone-from-config withdraw uses since its
// binding — and its configured cap — is gone). fromWithdraw tags which wire op
// armed the backoff (#4423 M03) so the window gates only that op and does not
// delay the OTHER op when the observed intent flips.
func (m *SurfaceAManager) recordScopeError(rt *surfaceAState, fqdn string, maxBackoff time.Duration, err error, now time.Time, fromWithdraw bool) {
	if maxBackoff <= 0 {
		maxBackoff = defaultErrorBackoffMax
	}
	if rt.backoff <= 0 {
		rt.backoff = surfaceABaseBackoff
	} else {
		rt.backoff *= 2
	}
	if rt.backoff > maxBackoff {
		rt.backoff = maxBackoff
	}
	rt.nextEligible = now.Add(rt.backoff)
	rt.backoffFromWithdraw = fromWithdraw
	rt.lastErr = err.Error()
	rt.lastErrAt = now
	rt.noBackend = false
	slog.Warn("ddns surface-a: scope DNS update failed; backing off",
		"fqdn", fqdn, "backoff", rt.backoff, "err", err)
}

// withdrawScopeLocked drives ONE withdraw of an owned record through `backend`
// under the SAME per-scope backoff machinery the publish path uses (#2813). The
// caller MUST have already passed the backoff-window / terminal checks (so this
// is invoked only when the scope is eligible to attempt the wire delete) and
// holds m.mu. Outcomes:
//
//   - success: withdrawOwnedLocked already dropped the durable ownership AND the
//     runtime entry, so the scope's error/backoff state is implicitly cleared;
//     return nil.
//   - errGenericDeleteUnsupported: the backend can NEVER withdraw (no portable
//     delete verb, #2772/#2811). Mark the scope terminal (a single warn, no
//     exponential-backoff churn) and SWALLOW the error so the reconcile pass does
//     not warn every sweep; ownership is kept (the RR stays operator-visible).
//   - any other (transient) failure: arm the shared exponential backoff and
//     RETURN the error so the pass reports it ONCE per eligible attempt — the
//     backoff window then skips the next sweeps, collapsing the per-sweep spam.
func (m *SurfaceAManager) withdrawScopeLocked(ctx context.Context, owned ownedRecord, backend DNSUpdater, rt *surfaceAState, fqdn string, maxBackoff time.Duration, now time.Time) error {
	err := m.withdrawOwnedLocked(ctx, owned, backend)
	if err == nil {
		return nil
	}
	if errors.Is(err, errGenericDeleteUnsupported) {
		m.markWithdrawUnsupported(rt, fqdn, now)
		return nil
	}
	m.recordScopeError(rt, fqdn, maxBackoff, err, now, true)
	return err
}

// markWithdrawUnsupported flags a scope whose backend has no withdraw verb so
// the withdraw is attempted at most once (#2813). It is idempotent — the single
// warn fires only on the first transition — and records the reason for the
// status surface. The scope KEEPS ownership; the abandoned RR stays
// operator-visible. The flag is cleared by a successful publish (the full rt
// reset) or a restart (the runtime cache is rebuilt from the durable store).
func (m *SurfaceAManager) markWithdrawUnsupported(rt *surfaceAState, fqdn string, now time.Time) {
	rt.lastErr = errGenericDeleteUnsupported.Error()
	rt.lastErrAt = now
	if rt.withdrawUnsupported {
		return
	}
	rt.withdrawUnsupported = true
	slog.Warn("ddns surface-a: backend has no withdraw verb; abandoning withdraw retries (record kept, operator-visible)",
		"fqdn", fqdn)
}

// StatusViews returns a stable-ordered snapshot of EVERY configured Surface A
// scope's current publish state for the operator surfaces (plan §5.5
// observability, #2843). It is the union of:
//
//   - every CONFIGURED scope (the `scopes` arg, materialized by the daemon from
//     the committed config) — so a scope that has NEVER successfully published
//     (no ownership record yet) or that errored (no-backend / provider failure /
//     wedged) still appears, with its State and reason. Before #2843 these were
//     silently omitted — the operator saw nothing for a broken bring-up scope.
//   - any ownership record for a scope NO LONGER configured — a withdraw is
//     pending; surfaced as withdraw-pending so a wedged teardown is visible.
//
// Each row merges the durable ownership store (what is published) with the
// in-memory runtime state (last-published time, last error, no-backend flag).
// Caller need not hold the mutex (the method takes it). A nil/empty `scopes`
// (no configured Surface A bindings) yields only the orphaned-ownership rows.
func (m *SurfaceAManager) StatusViews(scopes []SurfaceAScope) []SurfaceAStatusView {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]SurfaceAStatusView, 0, len(scopes)+len(m.state.records))
	// configured tracks which scope prefixes are covered by a configured-scope
	// row so the orphaned-ownership sweep below skips them.
	configured := make(map[string]struct{}, len(scopes))

	for _, sc := range scopes {
		sid := sc.scopeID()
		configured[sid] = struct{}{}
		v := SurfaceAStatusView{
			Interface: sc.Key.Interface,
			Unit:      sc.Key.Unit,
			Family:    int(sc.Key.Family),
			FQDN:      sc.FQDN,
			Provider:  sc.Key.PolicyID,
		}
		owned, isOwned := m.state.get(sc.effectiveKey(), surfaceAIdentity, "")
		if isOwned {
			// #7423 row 5: while PublishPending is true, AddrText holds the
			// DESIRED address — "the phantom desired value that AddrText holds
			// until the wire confirms", as PriorAddrText's own doc puts it.
			// Reporting AddrText as `Published` told the operator the new
			// address was live at exactly the moment it was not, which is the
			// same window the State below was mis-reporting.
			//
			// What this field means during a pending publish is deliberately
			// LAST CONFIRMED, not "what is live". Those differ, and the
			// difference is not knowable here: per the #5334 analysis in
			// README.md a pending record has the byte-identical shape for two
			// crash windows — one where the prior value is still live, one
			// where the new value already landed and only the confirm-save was
			// lost. `withdrawOwnedLocked` deletes BOTH candidates for exactly
			// this reason. So no single address in this column can be asserted
			// live; the honest pairing is the last value the system actually
			// confirmed, next to a State that says `pending`.
			//
			// PriorAddrText is used UNCONDITIONALLY when pending, including
			// when it is empty. An empty prior means a FIRST publish that has
			// not confirmed — nothing has ever been live at this name — and the
			// column renders "-". Falling back to AddrText there would
			// reintroduce the exact defect for the one case where the claim is
			// least supportable.
			v.Published = owned.AddrText
			if owned.PublishPending {
				v.Published = owned.PriorAddrText
			}
			if owned.FQDN != "" {
				v.FQDN = owned.FQDN
			}
		}
		rt := m.runtime[sid]
		if rt != nil {
			v.LastPublished = rt.lastPublished
			v.LastError = rt.lastErr
			v.LastErrorAt = rt.lastErrAt
		}
		switch {
		// #7423 row 5: ownership is not settlement. A record written ahead of
		// the wire add carries PublishPending=true, and its own type doc says
		// "with PublishPending=true the record is NOT settled" — yet this arm
		// consulted only `isOwned`, so after a crash in the write-ahead window
		// the operator read `published` for an address public DNS had never
		// served.
		//
		// This is deliberately a NARROWING of the owned arm rather than a
		// reordering of the switch. The obvious-looking fix — moving the
		// `lastErr` arm above `isOwned`, since the issue observes that owned
		// wins over it — would make a healthy settled scope that once hit a
		// transient error report `error` while its RR is live and correct. The
		// pending bit is what actually distinguishes the two cases, and it
		// covers the reported symptom too: a re-publish that keeps failing
		// leaves PublishPending=true (set by the write-ahead save at every
		// attempt, cleared only by the confirm-save), so such a scope now falls
		// through to `pending` on its own.
		case isOwned && !owned.PublishPending:
			v.State = SurfaceAStatePublished
		case isOwned && owned.PublishPending:
			// Desired, not confirmed. `pending` already means exactly this
			// elsewhere in this switch: configured, not settled on the wire.
			v.State = SurfaceAStatePending
		case rt != nil && rt.noBackend:
			v.State = SurfaceAStateUnpublished
		case rt != nil && rt.lastErr != "":
			v.State = SurfaceAStateError
		default:
			// Configured, not yet owned, no recorded error: never attempted, or
			// waiting on an address observation / backoff window.
			v.State = SurfaceAStatePending
		}
		out = append(out, v)
	}

	// Orphaned ownership: a record for a scope no longer configured. The next
	// reconcile (Pass 2) withdraws it; surface it as withdraw-pending so a wedged
	// teardown is not invisible. A record the reconciler has flagged as a #3735
	// provider-change ORPHAN (stale at a previous endpoint, un-withdrawable) is
	// covered by the dedicated orphan rows below instead — skip it here so it is
	// not double-listed as merely withdraw-pending.
	for _, r := range m.state.all() {
		sc := r.scopeOf()
		if _, ok := configured[sc.scopePrefix()]; ok {
			continue
		}
		if _, isOrphan := m.orphans[orphanKey(r)]; isOrphan {
			continue
		}
		v := SurfaceAStatusView{
			Interface: sc.Interface,
			Unit:      sc.Unit,
			Family:    int(sc.Family),
			FQDN:      r.FQDN,
			Provider:  sc.PolicyID,
			Published: r.AddrText,
			State:     SurfaceAStateWithdrawPending,
		}
		if rt := m.runtime[sc.scopePrefix()]; rt != nil {
			v.LastPublished = rt.lastPublished
			v.LastError = rt.lastErr
			v.LastErrorAt = rt.lastErrAt
		}
		out = append(out, v)
	}

	// #3735 orphan alarm rows: a record stale at a PREVIOUS provider endpoint that
	// a provider identity change (rename to a different endpoint / in-place
	// server-zone edit / removed binding after an edit) left un-withdrawable
	// through the current catalog. Ownership is KEPT; the row is the operator-
	// visible half of the alarm (LastError carries the manual-cleanup reason). It
	// is emitted for BOTH a gone-from-config record (H01/H03 — skipped above) and a
	// still-configured scope whose OLD endpoint was orphaned by an in-place mutation
	// (H02 — the healthy published row for the new endpoint also appears).
	for _, o := range m.orphans {
		out = append(out, SurfaceAStatusView{
			Interface:   o.Interface,
			Unit:        o.Unit,
			Family:      o.Family,
			FQDN:        o.FQDN,
			Provider:    o.Provider,
			Published:   o.Address,
			State:       SurfaceAStateOrphaned,
			LastError:   o.Reason,
			LastErrorAt: o.FirstSeen,
		})
	}

	SortSurfaceAStatusViews(out)
	return out
}

// SortSurfaceAStatusViews orders status rows by a TOTAL key so the operator
// surface (CLI/gRPC/REST) is byte-stable across calls (#4423 M11). The old
// comparator keyed only on {FQDN, Family}, which is NOT a total order over the
// rows: two rows can legitimately share an FQDN AND a family — e.g. the same
// hostname published from two interfaces/units, or a configured row plus a
// withdraw-pending / orphaned row for the same name+family under a different
// scope. On such a tie sort.Slice (not stable) left the order to the input/map
// iteration order, so `show system services dynamic-dns` flapped between calls
// and any golden-output test was non-deterministic. Extending the key to
// {FQDN, Family, Interface, Unit, Provider, State, Published} breaks every tie
// deterministically. Exported so the daemon re-sorts the combined engine +
// synthesized-invalid-binding row set (#4423 M09) with the identical ordering.
func SortSurfaceAStatusViews(out []SurfaceAStatusView) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.FQDN != b.FQDN {
			return a.FQDN < b.FQDN
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		if a.Unit != b.Unit {
			return a.Unit < b.Unit
		}
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.State != b.State {
			return a.State < b.State
		}
		return a.Published < b.Published
	})
}

// SurfaceAStats is the counter snapshot for `show` + Prometheus (plan §5.5).
type SurfaceAStats struct {
	Scopes           int
	UpsertOK         uint64
	UpsertFail       uint64
	DeleteOK         uint64
	DeleteFail       uint64
	Skipped          uint64
	BackedOff        uint64
	SkippedNoBackend uint64
	// DeleteCoowned is the count of wire deletes DEFERRED because the RR is still
	// co-owned by a Surface B DHCP lease scope (#5748, the cross-surface arm of the
	// #5709 co-ownership guard). Under the #6015 deterministic tie-break Surface A is
	// the NON-AUTHORITY: rather than suppress-and-release like the lease side, each
	// such pass DEFERS the delete, RE-ASSERTS the RR, and KEEPS the ownership claim
	// until the lease authority releases — so this counter tallies deferred passes,
	// not one-shot suppressions, and grows once per reconcile while the co-ownership
	// persists. A non-zero value is normal when Surface A and a DHCP lease
	// legitimately publish the same host/address.
	DeleteCoowned uint64
	// Orphaned is the count of records this node published at a PREVIOUS provider
	// endpoint that a provider identity change (rename / in-place mutation /
	// removed binding after an edit) left stale and un-withdrawable through the
	// current catalog (#3735). Each is surfaced as a SurfaceAStateOrphaned
	// StatusViews row and drives the `xpf_ddns_surface_a_orphaned` gauge. A
	// non-zero value means an old record needs MANUAL operator cleanup
	// (auto-withdrawal is deferred — the old creds are redacted and the old
	// endpoint is usually decommissioned).
	Orphaned int
	// Degraded is the FAIL-CLOSED alarm (#2971): the ownership state file could
	// not be loaded (corrupt / unsupported-version / unreadable), so Reconcile
	// refuses every publish/withdraw until the operator resolves it.
	Degraded bool
	// DegradedReason is a human-readable explanation of Degraded (the load error
	// plus the quarantine path of the bad file, if any). Empty when not degraded.
	DegradedReason string
}

// ForceRefresh arms the operator force-now latch (#3276): the NEXT reconcile
// pass re-asserts the wire record for every configured scope this node owns,
// bypassing the change-detection + forced-refresh skip (but NOT the per-RG HA
// writer gate — only the RG owner publishes). It is the engine half of the
// `request system dynamic-dns update` operator verb. The daemon arms the latch
// and then nudges an immediate reconcile pass; the latch is one-shot (consumed
// by the first non-degraded pass) so it forces exactly one publish round.
func (m *SurfaceAManager) ForceRefresh() {
	m.mu.Lock()
	m.forceRefresh = true
	m.mu.Unlock()
}

// Stats returns the current Surface A counters.
func (m *SurfaceAManager) Stats() SurfaceAStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SurfaceAStats{
		Scopes:           len(m.state.records),
		UpsertOK:         m.upsertOK,
		UpsertFail:       m.upsertFail,
		DeleteOK:         m.deleteOK,
		DeleteFail:       m.deleteFail,
		Skipped:          m.skipped,
		BackedOff:        m.backedOff,
		SkippedNoBackend: m.skippedNoBackend,
		DeleteCoowned:    m.deleteCoowned,
		Orphaned:         len(m.orphans),
		Degraded:         m.degraded,
		DegradedReason:   m.degradedReason,
	}
}

// buildHostRecord constructs the forward-only A/AAAA record for a Surface A
// router record (no PTR — Surface A publishes the firewall's forward name; PTR
// for the firewall's own address is an operator/ISP concern, not auto-managed).
// The FQDN is normalized against an EMPTY zone (finalizeFQDN keeps a dotted
// operator-supplied name verbatim, a bare label as-is) so an absolute name like
// wan.example.net is published exactly.
func buildHostRecord(fqdn string, addr netip.Addr, ttl int) (LeaseDNSRecord, error) {
	// Surface A operator FQDNs are ABSOLUTE (the operator picks the full name,
	// unlike the DHCP-lease path where the client picks the host part and the
	// firewall picks the zone). finalizeFQDN("",...) would reduce a dotted name
	// to its first label, which is wrong for "wan.example.net" — so use a
	// dotted-structure-preserving per-label sanitize instead.
	name := surfaceAName(fqdn)
	if name == "" {
		return LeaseDNSRecord{}, fmt.Errorf("ddns surface-a: hostname %q sanitizes to empty", fqdn)
	}
	a := addr.Unmap()
	if ttl <= 0 {
		ttl = defaultDDNSTTL
	}
	rec := LeaseDNSRecord{
		FQDN: name,
		Addr: a,
		TTL:  ttl,
	}
	if a.Is4() {
		rec.ForwardType = "A"
	} else if a.Is6() {
		rec.ForwardType = "AAAA"
	} else {
		return LeaseDNSRecord{}, fmt.Errorf("ddns surface-a: record %q has an unspecified address", fqdn)
	}
	return rec, nil
}

// surfaceAName normalizes an operator-supplied Surface A hostname. Unlike the
// DHCP-lease path (where the CLIENT supplies the name and the FIREWALL picks the
// zone), the OPERATOR supplies the full FQDN here, so the name is honored
// verbatim after a per-label LDH sanitize that preserves the dotted structure
// (so wan.example.net stays wan.example.net), trimming a trailing dot. An empty
// result ("" — the input had no usable label) is returned so the caller errors
// rather than publishing junk.
func surfaceAName(fqdn string) string {
	return sanitizeFQDN(fqdn)
}

// familyInt returns the engine family int (4/6) for an address.
func familyInt(a netip.Addr) int {
	if a.Unmap().Is4() {
		return 4
	}
	return 6
}
