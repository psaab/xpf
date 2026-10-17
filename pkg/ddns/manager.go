package ddns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// errDDNSNoBackendToWithdraw is returned by deleteOwnedLocked when an owned
// record must be withdrawn but only the no-op backend is wired (#2699). The
// wire RR was NOT removed and ownership is DELIBERATELY KEPT (so the record
// stays cleanable once a real backend is reconfigured), so the delete is
// reported as a failure rather than a silent ownership drop. reconcileOnceLocked
// treats it like any other delete error (the record is left in the store, its
// identity/address/FQDN are blocked from re-add this cycle, and a later
// reconcile retries) — but it is NOT a wire-level error, so it does not fail
// the whole reconcile pass: a turn-off / restart with no backend resolves to
// nop legitimately, and wedging the pass on it would be noise. The next
// reconcile that resolves a live backend (or the next-cycle withdraw guard
// supplying the prior live updater) performs the real withdraw.
var errDDNSNoBackendToWithdraw = errors.New("ddns: no live backend to withdraw owned record (ownership kept for retry)")

// manager.go (moved verbatim from pkg/dhcpserver/ddns.go in #2691 P1a): the
// DHCP dynamic-DNS manager + reconciler core (#1387, per
// docs/research/1387-dhcp-ddns/plan.md). This is the config-driven policy,
// the never-delete-non-owned ownership store, and the build-desired /
// diff-owned / transition reconcile algorithm driven through a pluggable
// DNSUpdater. The state-aware Kea-memfile lease parser stays in
// pkg/dhcpserver (ddns_leases.go) and is injected as a LeaseParser seam.
// Tests drive reconcileOnce directly with synthetic Leases and a fakeUpdater
// (zero network/DNS dependency).
//
// SHIPPED (no longer deferred):
//   - the LIVE rfc2136 DNSUpdater backend (#1387 inc-2; see
//     ddns_rfc2136.go) — records are published to and withdrawn from the
//     authoritative server over real RFC 2136 UPDATE;
//   - the always-on daemon reconcile loop with the HA writer gate
//     (pkg/daemon/daemon_ddns.go) — a node only publishes when it is the
//     cluster writer (standalone, or MASTER for >=1 redundancy group);
//   - Prometheus emission through pkg/api (the xpf_dhcp_ddns_* counters
//     are exported from Stats()).
//
// SHIPPED in #2691 P1b (this phase):
//   - ScopeKey on ownership records + per-family INDEPENDENT v4/v6 policy
//     (#2663): ReconcileScoped resolves a policy + backend PER FAMILY;
//   - per-RG HA writer gate (#2664): a ScopeGate/ScopeResolver gates the
//     publish decision PER redundancy-group (stop-writing-never-withdraw on a
//     partial demotion), wired from pkg/daemon (ddnsReconcileOptions);
//   - source / interface / VRF binding for the RFC 2136 update socket (#2665,
//     backend_bind.go).
//
// STILL DEFERRED:
//   - the Kea D2 backend (reserved enum; not in the image — bake.py);
//   - router/interface-address publish (Surface A) + the HTTP provider
//     backends (dyndns2/Cloudflare/Route53/generic) — the #2691 world-class
//     redesign phases P2-P3.
//
// When DynamicDNS is nil or disabled the manager does nothing except a
// one-time withdraw of any previously-owned records (turn-off cleanup) —
// net behaviour change for existing users is zero.

// Lease is the reconcile-relevant view of one active DHCP lease the engine
// consumes (#2691 P1a). It is the DDNS subset of the Kea-memfile lease record
// (pkg/dhcpserver.ddnsLease): the fields the reconciler keys ownership and
// naming on. The full memfile record (v6 lease-type / prefix-len fields used
// only by the lease-sync fallback) stays in pkg/dhcpserver; its parser
// converts each row into this struct at the LeaseParser boundary. Fields are
// a 1:1 copy of the previously-internal ddnsLease fields the reconciler read.
type Lease struct {
	Family     int    // 4 or 6
	Address    string // textual leased address
	Identity   string // v4: client-id||hwaddr ; v6: DUID/IAID
	SubnetID   string // pool/subnet metadata
	HostName   string // host-name option
	ClientFQDN string // client-supplied FQDN option (fqdn_fwd implied)
	// LeaseType is the v6 lease_type discriminator carried through the
	// LeaseParser boundary (#5072): it distinguishes an address binding (IA_NA
	// / IA_TA) from a delegated-prefix binding (IA_PD) so the reconciler never
	// coerces an IA_PD prefix base (e.g. 2001:db8:abcd::) into a host
	// A/AAAA/PTR. The ZERO value is LeaseTypeIANA (an address lease), so a v4
	// lease, a v6 lease with no lease_type column, and any Lease constructed
	// without setting this field are correctly treated as address-bearing.
	// The Kea-memfile adapter maps a PRESENT-but-unparseable / unknown column
	// to LeaseTypeUnknown so it is rejected fail-closed rather than guessed.
	LeaseType int
}

// v6 lease_type values carried on Lease.LeaseType. The address types mirror
// Kea's memfile column (0=IA_NA, 1=IA_TA, 2=IA_PD); LeaseTypeUnknown is a
// local sentinel the Kea-memfile adapter assigns when the column is present but
// unparseable. Only IA_NA / IA_TA are address-bearing and eligible for host DNS
// (#5072). IA_NA is 0 so it is the safe zero-value default.
const (
	LeaseTypeIANA    = 0  // identity association, non-temporary address
	LeaseTypeIATA    = 1  // identity association, temporary address
	LeaseTypeIAPD    = 2  // identity association, prefix delegation (NOT a host address)
	LeaseTypeUnknown = -1 // lease_type column present but unparseable / unrecognized
)

// isAddressLease reports whether the lease binds a host ADDRESS eligible for
// A/AAAA/PTR publication. This is an explicit ALLOWLIST: only IA_NA / IA_TA
// qualify. An IA_PD delegated-prefix base must never be published (authoritative
// DNS for a delegated network base is an info-disclosure / policy violation),
// and any unknown / unparseable type is rejected fail-closed (#5072).
func (l Lease) isAddressLease() bool {
	return l.LeaseType == LeaseTypeIANA || l.LeaseType == LeaseTypeIATA
}

// LeaseParser reads a family's (4 or 6) active leases from a Kea memfile path
// as of now. It is the seam through which pkg/dhcpserver's Kea-memfile parser
// feeds the engine (#2691 P1a). An error means the family's lease set is
// unreliable this cycle; the reconciler then marks the family untrusted and
// skips its destructive diff (the mass-delete fail-safe).
type LeaseParser func(path string, family int, now time.Time) ([]Lease, error)

// ddnsPolicy is the resolved, runtime-shaped DDNS configuration the
// reconciler consumes. It is derived from config.DHCPDynamicDNSConfig at
// reconcile time so the reconciler never holds a stale captured cfg
// (plan §5 invariant 1).
//
// #2691 P1b — one ddnsPolicy is resolved PER FAMILY (#2663 independent v4/v6
// policy). The v4 and v6 lease sets are now reconciled with their OWN policy +
// own backend, so a v4 conflict, a v4 backend failure, or a v4 turn-off can
// never affect v6 publishing (and vice-versa).
type ddnsPolicy struct {
	enabled        bool
	domain         string
	ttl            int
	hostnameSource string
	conflictPolicy string
	backend        string
	// authority is the credential-free fingerprint of this policy's DNS
	// endpoint (#6755), comparable with a Surface A record's stored
	// BackendFingerprint. Computed once here because ddnsPolicy is the resolved
	// runtime shape the reconciler carries; the raw config is not available at
	// claim-rebuild time.
	authority string
}

// ScopeGate decides whether THIS node may publish records for a given scope
// (#2691 P1b / #2664 the per-RG HA writer gate). It returns true when the
// scope is writable from here: standalone always true; in a cluster, true IFF
// the local node is the MASTER for scope.RGOwner. A nil gate (the standalone
// Reconcile entry point and existing tests) means "every scope is writable".
//
// FAIL-CLOSED CONTRACT (#2664): the daemon's gate returns FALSE for any scope
// whose RG ownership is uncertain (a lease whose address falls in no
// master-owned subnet, or whose RG cannot be attributed). A scope the gate
// rejects is NOT published — but it is also NOT withdrawn (stop-writing, never
// withdraw: the peer that became MASTER for that RG refreshes the record; a
// withdraw race would blackhole, plan §5.6 / risk R3). The reconciler enforces
// this by treating a gated-out OWNED record exactly like an untrusted family:
// it is left in the store, never deleted, and never re-published from here.
type ScopeGate func(ScopeKey) bool

// ScopeResolver attributes a lease to the redundancy group (and, in later
// phases, the interface/unit/routing-instance) that OWNS it (#2691 P1b). The
// daemon supplies it from the committed DHCP config: a lease address is mapped
// to its pool subnet → group → interface → redundancy-group (stable CIDR
// membership, NOT the per-render-unstable Kea subnet_id, plan §6 fork 2). It
// returns the scope's RG owner and ok=false when the lease cannot be attributed
// to any known scope — which the gate then treats as fail-closed (not
// published). A nil resolver (standalone / tests) yields the zero scope for the
// family (RGOwner 0), which a nil gate always admits.
type ScopeResolver func(l Lease) (ScopeKey, bool)

// ReconcileOptions carries the HA scope wiring for one reconcile pass (#2691
// P1b). All fields are optional; the zero value is the standalone behaviour
// (every scope writable, leases keyed by family only). The daemon populates
// Gate + Resolver so the per-RG writer gate and per-family/per-RG ownership
// scoping take effect.
type ReconcileOptions struct {
	// Gate is the per-scope HA writer gate (#2664). Nil ⇒ all scopes writable.
	Gate ScopeGate
	// Resolver attributes each lease to its owning scope (RG etc., #2664). Nil
	// ⇒ leases get the zero scope for their family (standalone Surface B).
	Resolver ScopeResolver
	// InterfaceResolver maps a destination-interface Junos ref to the LOCAL
	// node's kernel device name for SO_BINDTODEVICE (#5070). The daemon passes
	// cfg.ResolveKernelIfName (the SSOT resolver). Nil ⇒ the leaf
	// slash-substitution fallback (a routing-instance still resolves to its
	// vrf-<name> master via diagcmd.VRFDeviceName regardless).
	InterfaceResolver func(ref string) string
}

// policyFromConfig resolves a typed config block into a runtime policy,
// applying defaults. A nil or disabled block yields enabled=false.
func policyFromConfig(c *config.DHCPDynamicDNSConfig) ddnsPolicy {
	if c == nil {
		return ddnsPolicy{}
	}
	p := ddnsPolicy{
		enabled:        c.Enabled,
		domain:         c.Domain,
		ttl:            c.TTLSeconds,
		hostnameSource: c.HostnameSource,
		conflictPolicy: c.ConflictPolicy,
		backend:        c.Backend,
		authority:      leaseAuthorityFingerprint(c),
	}
	if p.ttl <= 0 {
		p.ttl = defaultDDNSTTL
	}
	if p.backend == "" {
		p.backend = "rfc2136"
	}
	if p.conflictPolicy == "" {
		p.conflictPolicy = "replace-owned"
	}
	return p
}

// validConflictPolicy reports whether p is one of the three conflict
// policies the RFC 2136 backend implements. The empty string is NOT
// valid here: policyFromConfig has already defaulted it to
// replace-owned, so any other value reaching the backend is an operator
// typo (e.g. skip-existng, none) that arrived via the tolerant load /
// peer-sync path, which downgrades the strict schema-enum reject to a
// warning (#1319/#1960). Such a value must fail closed on BOTH the add
// side (#14429) and the delete side (#14432), never fall through to an
// unguarded branch.
func validConflictPolicy(p string) bool {
	switch p {
	case "replace-owned", "skip-existing", "strict-fail":
		return true
	default:
		return false
	}
}

// Stats is the observable counter snapshot surfaced by `show` (and,
// since increment 2, the Prometheus collector). All counters are monotonic.
type Stats struct {
	Enabled    bool
	Backend    string
	UpsertOK   uint64
	UpsertFail uint64
	DeleteOK   uint64
	DeleteFail uint64
	// DeleteCoowned counts wire deletes SUPPRESSED because the exact wire RR
	// (same forward name + type + rdata) is still CO-OWNED by another DDNS scope
	// — e.g. a second redundancy group, or a per-interface and a global binding
	// resolving the same host to the same address (#5709). The departing scope's
	// ownership claim is released but the live RR is left in place for the
	// surviving scope; only the LAST claimant's teardown issues the real wire
	// delete. A monotonic counter: a non-zero, rising value is normal in
	// multi-scope deployments and means the cross-scope clobber was prevented.
	DeleteCoowned uint64
	SkippedNoName uint64
	// SkippedNonAddress counts leases skipped because they are not an
	// address-bearing lease type eligible for host DNS — an IA_PD
	// delegated-prefix binding or an unknown/unparseable v6 lease_type (#5072).
	// A prefix base must never be coerced into an A/AAAA/PTR record.
	SkippedNonAddress uint64
	SkippedNoBackend  uint64 // records skipped because no live backend is wired
	// SkippedPTRNotAuth counts reverse-zone PTR updates skipped because the
	// authoritative server returned NOTAUTH/REFUSED for the reverse zone —
	// a reverse zone we do not own (e.g. delegated to an ISP). The forward
	// A/AAAA add still succeeded; the lease's reconcile is not failed
	// (#1387 inc-2, plan §11 Q6).
	SkippedPTRNotAuth uint64
	// SkippedConflict counts adds skipped under conflict-policy skip-existing
	// because the exact RR already existed at the server (plan §4.1).
	SkippedConflict uint64
	// PTRDeferred counts upserts where the forward A/AAAA published but the
	// reverse PTR add failed with a non-skippable (transient) error: ownership
	// is recorded for the live forward (never orphaned) and the PTR is retried
	// on the next reconcile (#2661). It is a CUMULATIVE lifetime counter (every
	// deferral ever), NOT the count of records CURRENTLY pending — use
	// PTRPendingNow for the current gauge (#2708).
	PTRDeferred uint64
	// PTRPendingNow is the CURRENT count of owned records whose forward A/AAAA
	// is published but whose reverse PTR is still owed (ownedRecord.PTRPending,
	// #2708). Distinct from the cumulative PTRDeferred: this falls back to 0
	// once every pending PTR finally publishes, so it is the live "how many
	// records are half-published right now" gauge an operator watches for
	// recovery. Surfaced in `show ... dynamic-dns` and Prometheus.
	PTRPendingNow int
	// OrphanedBackendChange counts owned records whose backend/update-server
	// identity changed while the OLD endpoint was unreachable in-process (a daemon
	// restart lost the anchor), so the record could NOT be withdrawn through the
	// endpoint that published it (#5814). Ownership is KEPT and the record is never
	// deleted at the wrong endpoint; a non-zero value means DNS may be stale on the
	// old server and needs operator attention (mirrors the Surface A #3735 alarm).
	OrphanedBackendChange uint64
	// ReconcileOK / ReconcileFail count whole reconcile passes by outcome
	// (a pass is "fail" when at least one record op errored this cycle).
	ReconcileOK    uint64
	ReconcileFail  uint64
	OwnedRecords   int
	LastReconcile  time.Time
	LastReconcileN int // active leases seen on the last reconcile
	// Degraded is the FAIL-CLOSED alarm (#2650): the ownership state file could
	// not be loaded (corrupt JSON, an unsupported/future version, or an
	// unreadable file), so the manager cannot prove what records it owns. While
	// degraded the reconciler refuses BOTH to publish (it could overwrite a
	// peer-owned record) AND to withdraw/delete (it has lost the ownership it
	// would withdraw against). The operator must resolve the state file before
	// DDNS resumes. Surfaced in `show ... dynamic-dns` and Prometheus so the lost
	// cleanup authority is never silent.
	Degraded bool
	// DegradedReason is a human-readable explanation of Degraded (the load error
	// plus the quarantine path of the bad file, if any). Empty when not degraded.
	DegradedReason string
}

// Manager owns the DDNS reconcile loop and the ownership store. It is
// a SEPARATE type from the Kea Manager (plan §7) so the generation-
// ordered Kea applier is not perturbed.
type Manager struct {
	mu      sync.Mutex
	state   *ddnsState
	updater DNSUpdater

	// lastLiveUpdater retains the PREVIOUS reconcile's resolved LIVE backend per
	// family (#5814): [0]=v4, [1]=v6. On an IN-PROCESS backend-identity change
	// (update-server / zone / TSIG-key edit) the reconciler withdraws records that
	// were published through the OLD endpoint via this retained updater BEFORE
	// republishing on the newly-resolved one — so a server swap neither orphans
	// the old endpoint's record nor deletes at the wrong (new) endpoint. Kept per
	// family so a v4 change never routes v6 cleanup through v4's backend (#2663
	// independence). NOT persisted: an in-process anchor only. Across a daemon
	// restart it is nil, so the fingerprint-mismatch path keeps ownership + alarms
	// rather than deleting at the wrong endpoint (the Surface A #3735 posture).
	// Only advanced on the resolve-per-Reconcile path (newUpdater != nil); a
	// fixed-updater test never populates it. Guarded by mu.
	lastLiveUpdater [2]DNSUpdater

	// lastLiveFP is the ENDPOINT FINGERPRINT of the backend held in
	// lastLiveUpdater, advanced in LOCKSTEP with it (#5814). It is the load-
	// bearing guard against a WRONG-endpoint withdraw after a daemon restart: the
	// anchor updater alone is not enough, because after a restart the anchor is
	// re-seeded to the NEW backend on the first post-restart cycle, so a later
	// cycle would find a non-nil anchor that points at the NEW endpoint and could
	// misroute a delete for an OLD-endpoint record through it. The transition path
	// therefore withdraws through lastLiveUpdater ONLY when this fingerprint equals
	// the owned record's stored fingerprint — i.e. the anchor is PROVABLY the
	// endpoint that published the record. A mismatch (or an empty anchor) routes to
	// the keep-ownership + alarm orphan branch instead. Per family; guarded by mu.
	lastLiveFP [2]string

	// degraded fails the manager CLOSED when the ownership state file could not
	// be loaded (#2650): corrupt JSON, an unsupported/future version, or an
	// unreadable file. The loaded `state` is empty in this case, but it must NOT
	// be acted upon — an empty store would forget every owned record (permanent
	// stale-record leak) and let a publish re-claim a peer-owned name. While
	// degraded, ReconcileScoped is a no-op-with-error: no publish, no withdraw,
	// no save() (which would overwrite the on-disk file). Cleared only by a
	// successful reload (operator resolves/removes the bad file and restarts, or
	// the quarantine leaves a clean slate for a genuine first run). Guarded by mu.
	degraded       bool
	degradedReason string

	// forceNext is the operator force-now latch (#5710, the DHCP Surface-B half
	// of `request system dynamic-dns update`). When set, the NEXT non-degraded
	// reconcile pass re-asserts (re-upserts) every owned record whose desired
	// wire tuple is UNCHANGED — bypassing the change-detection short-circuit the
	// routine reconcile uses for efficiency — so an operator can repair a drifted
	// / manually-deleted wire RR. It does NOT bypass the per-RG HA writer gate
	// (only the RG owner publishes) and it is one-shot: consumed by the first
	// pass that actually runs (a degraded pass never publishes, so it does not
	// consume the latch). Mirrors SurfaceAManager.forceRefresh. Guarded by mu.
	forceNext bool

	// newUpdater resolves the live DNS-update backend from the policy +
	// config resolved at the start of each Reconcile (plan §6 fork 1:
	// resolve-per-Reconcile). When nil (tests that inject a fixed updater,
	// or the always-on idle-when-disabled production manager before its
	// first enabled reconcile) the manager uses the static `updater` field.
	// Resolving per cycle means a backend-config change at commit takes
	// effect on the next reconcile with no swap race and no stale capture;
	// it also lets ONE always-constructed manager serve both the disabled
	// (nopUpdater) and enabled (rfc2136Updater) states so enabled→disabled
	// still runs withdrawAllLocked through a live backend (plan §4.2).
	newUpdater func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error)

	// ifResolver maps a destination-interface Junos ref to the LOCAL node's
	// kernel device name for SO_BINDTODEVICE (#5070). It is refreshed at the
	// START of each ReconcileScoped from ReconcileOptions.InterfaceResolver (the
	// daemon threads cfg.ResolveKernelIfName), so a topology/commit change takes
	// effect next cycle. Read by the production newUpdater closure under m.mu
	// (set and read in the same locked pass). Nil ⇒ the leaf slash-substitution
	// fallback (standalone tests with no committed config).
	ifResolver func(string) string

	// nodeID is the deterministic-owner-id seed (plan §5 invariant 2):
	// the owner watermark is derived from the lease identity so EITHER HA
	// node computes the same value, keeping cleanup safe across failover.
	// The HA emission gating (the writer gate in pkg/daemon/daemon_ddns.go)
	// is live; the watermark is node-stable so a failed-over node can clean
	// up records its peer published.
	nodeID string

	// leaseParser reads a family's active-lease set from a Kea memfile path
	// (#2691 P1a). The Kea-memfile parser stays in pkg/dhcpserver
	// (ddns_leases.go — it is entangled with the lease-sync fallback), so the
	// caller injects it here, inverting the dependency: pkg/ddns defines the
	// Lease record + the engine; pkg/dhcpserver supplies the parser. The
	// reconciler treats a parser error for a family as "untrusted" and skips
	// that family's destructive diff (the mass-delete fail-safe). When nil,
	// every family reads empty + trusted (the spine has no leases of its own).
	leaseParser LeaseParser

	// lease file paths (overridable for tests). Passed to leaseParser per
	// reconcile and surfaced via DDNSLeasePaths for cross-package tests.
	leasePath4 string
	leasePath6 string

	// now is injectable for deterministic expiry tests.
	now func() time.Time

	// counters
	upsertOK          atomic.Uint64
	upsertFail        atomic.Uint64
	deleteOK          atomic.Uint64
	deleteFail        atomic.Uint64
	deleteCoowned     atomic.Uint64 // wire delete skipped: RR still co-owned by another scope (#5709)
	skippedNoName     atomic.Uint64
	skippedNonAddress atomic.Uint64 // leases skipped: IA_PD / non-address lease type (#5072)
	skippedNoBackend  atomic.Uint64 // upsert/delete skipped: no live backend wired
	skippedPTRNotAuth atomic.Uint64 // reverse-zone PTR skipped (NOTAUTH/REFUSED)
	skippedConflict   atomic.Uint64 // add skipped: exact RR already exists
	ptrDeferred       atomic.Uint64 // forward published, PTR add failed (retry next cycle)
	// orphanedBackendChange counts owned records whose backend/update-server
	// identity changed but whose OLD endpoint is not reachable in-process (a
	// daemon restart lost the in-process anchor), so the record could NOT be
	// withdrawn through the endpoint that published it (#5814). Ownership is KEPT
	// (with the old fingerprint) so cleanup authority survives and the record is
	// never deleted at the wrong endpoint; the reconciler does not republish that
	// exact tuple onto the new endpoint (which would overwrite the ownership key
	// and destroy the old cleanup key). A non-zero value means DNS may be stale on
	// the old server and needs operator attention (mirrors Surface A #3735).
	orphanedBackendChange atomic.Uint64
	reconcileOK           atomic.Uint64 // reconcile passes with no record-op error
	reconcileFail         atomic.Uint64 // reconcile passes with >=1 record-op error

	lastReconcile  atomic.Int64 // unix nanos
	lastReconcileN atomic.Int64

	// last resolved policy (for Stats()).
	lastPolicy atomic.Pointer[ddnsPolicy]

	// surfaceACoowners, when non-nil, returns the wire-RR claims currently owned
	// by the SEPARATE Surface A ownership surface (router/interface DDNS records,
	// whose rdata lives in AddrText not Address, in the SurfaceAManager store).
	// The daemon injects it (SetSurfaceACoownerSource) so this lease teardown can
	// suppress a wire DELETE that would clobber a Surface-A-owned identical RR —
	// the cross-surface arm of the #5709 co-ownership class (#5748). It is a
	// LOCK-FREE snapshot accessor (an atomic.Pointer load inside SurfaceAManager);
	// it MUST NOT take SurfaceAManager.mu, so wireRRSharedWithOther can call it
	// while THIS manager holds m.mu without any lock-order cycle. Lock order:
	// m.mu (held) → lock-free peer read (no peer mutex). Nil in tests / standalone
	// / a not-yet-wired boot ⇒ exactly the pre-#5748 Surface-B-only scan.
	surfaceACoowners func() []WireRRClaim

	// wireRRClaims is the LOCK-FREE snapshot of the wire RRs THIS (Surface B lease)
	// surface currently owns, published for the Surface A teardown guard to consult
	// symmetrically (#5748). Rebuilt under m.mu at the end of every non-degraded
	// reconcile pass and after load (rebuildWireRRClaimsLocked), and read via
	// WireRRClaims() with a bare atomic load — never taking m.mu — so the peer can
	// query it while holding SurfaceAManager.mu without a deadlock. Nil until the
	// first rebuild; WireRRClaims() then returns an empty slice.
	wireRRClaims atomic.Pointer[[]WireRRClaim]
}

// loadStateOrDegrade loads the ownership store and classifies a load failure
// into the fail-closed degraded posture (#2650). It always returns a usable
// (possibly empty) store so the manager is constructible — the daemon must still
// start — but on a corrupt / unsupported-version / unreadable store it returns
// degraded=true plus a reason, and the manager refuses every reconcile op until
// the operator resolves the file. A corrupt / unsupported-version file is
// QUARANTINED (renamed aside, timestamped) so the bad bytes are preserved for
// inspection and a later save() cannot clobber the only forensic copy. An
// unreadable file (permission / IO) is NOT quarantined — the bytes may be fine
// and re-readable, so it would be wrong to move the file under a transient fault.
func loadStateOrDegrade(path string, now func() time.Time) (st *ddnsState, degraded bool, reason string) {
	// #4873: honor a DURABLE degraded marker FIRST. Quarantine (below) renames
	// the corrupt canonical file away, so on the next boot a naive reload would
	// find no file, load an empty store with a nil error, and silently resume
	// publish/withdraw with all prior ownership forgotten (fail-open). While the
	// marker exists we stay degraded regardless of the canonical file's state,
	// until an operator explicitly removes the marker after repair/import. Still
	// load the store so the manager has a path-initialized (constructible)
	// handle; its contents are unused while every reconcile op is suspended.
	if mreason, ok := readDegradedMarker(path); ok {
		st, _ = loadDDNSState(path)
		slog.Error("ddns: FAILING CLOSED on a persisted degraded marker; publishing and "+
			"withdrawals are SUSPENDED until the operator removes it", "reason", mreason,
			"marker", degradedMarkerPath(path))
		return st, true, mreason
	}

	st, err := loadDDNSState(path)
	if err == nil {
		return st, false, ""
	}
	classified := errors.Is(err, errDDNSStateCorrupt) || errors.Is(err, errDDNSStateUnsupportedVersion)
	reason = err.Error()
	if classified {
		nowFn := now
		if nowFn == nil {
			nowFn = time.Now
		}
		if qp, qerr := quarantineBadState(path, nowFn()); qerr != nil {
			slog.Error("ddns: FAILING CLOSED on unloadable ownership state; quarantine of the bad file also failed",
				"err", err, "quarantine_err", qerr)
			reason += " (quarantine failed: " + qerr.Error() + ")"
		} else {
			slog.Error("ddns: FAILING CLOSED on unloadable ownership state; bad file quarantined; "+
				"publishing and withdrawals are SUSPENDED until the operator resolves it",
				"err", err, "quarantine", qp)
			reason += " (quarantined to " + qp + ")"
		}
		// Persist the fail-closed posture durably (#4873): quarantine just
		// removed the canonical file, so without this a restart would come up
		// clean-but-empty and resume as if it owns nothing. The marker keeps the
		// manager degraded across restarts until the operator resolves it.
		if werr := writeDegradedMarker(path, reason); werr != nil {
			slog.Error("ddns: could not persist the degraded marker; a RESTART may FAIL OPEN "+
				"(resume with empty ownership)", "err", werr, "marker", degradedMarkerPath(path))
			reason += " (degraded-marker write failed: " + werr.Error() + ")"
		}
	} else {
		slog.Error("ddns: FAILING CLOSED on unreadable ownership state; publishing and withdrawals "+
			"are SUSPENDED until the file is readable", "err", err)
	}
	return st, true, reason
}

// NewManager constructs a DDNS manager with the given lease parser, updater
// backend, and node id. The ownership store is loaded from
// defaultDDNSStatePath. A corrupt / unsupported-version / unreadable store puts
// the manager into the FAIL-CLOSED degraded state (#2650): it is constructible
// (the daemon still starts) but refuses to publish or withdraw any record until
// the operator resolves the bad file (quarantined aside). The parser is the
// LeaseParser seam (the Kea-memfile parser lives in pkg/dhcpserver — #2691 P1a);
// a nil parser means the manager reads no leases (every family trusted-empty).
func NewManager(parser LeaseParser, updater DNSUpdater, nodeID string) *Manager {
	st, degraded, reason := loadStateOrDegrade(defaultDDNSStatePath, time.Now)
	if updater == nil {
		// Increment 1 defers the live backend: a nil updater becomes a
		// logged no-op rather than a nil-pointer panic on first publish or
		// withdraw. The reconciler stays nil-safe end to end.
		slog.Info("ddns: no DNS-update backend wired; running in no-op mode " +
			"(record reconcile logged-and-skipped until a backend exists)")
		updater = nopUpdater{}
	}
	m := &Manager{
		state:          st,
		degraded:       degraded,
		degradedReason: reason,
		updater:        updater,
		nodeID:         nodeID,
		leaseParser:    parser,
		leasePath4:     "/var/lib/kea/kea-leases4.csv",
		leasePath6:     "/var/lib/kea/kea-leases6.csv",
		now:            time.Now,
	}
	// #5748: seed the cross-surface wire-RR claim snapshot from the loaded store so
	// the Surface A guard sees this surface's ownership from the very first pass
	// (before this manager's first reconcile). Construction is single-threaded.
	m.rebuildWireRRClaimsLocked()
	return m
}

// NewProductionManager constructs the always-on production manager
// (#1387 increment 2, plan §4.2). It is built UNCONDITIONALLY at daemon
// start regardless of whether DDNS is currently enabled, and resolves the
// live RFC 2136 backend from the policy at the START OF EACH Reconcile so a
// commit-time backend-config change takes effect on the next cycle, and so
// the SAME manager can withdraw records when DDNS is turned off (it always
// has a running loop). When the active config has no usable backend the
// manager resolves to the nopUpdater and keeps reconciling (idle). The parser
// is the Kea-memfile LeaseParser seam injected by pkg/dhcpserver (#2691 P1a).
func NewProductionManager(parser LeaseParser, nodeID string) *Manager {
	m := NewManager(parser, nopUpdater{}, nodeID)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		// Only the live rfc2136 backend is wired in inc-2 (kea-d2 reserved).
		if pol.backend != "rfc2136" {
			return nopUpdater{}, nil
		}
		if c == nil || c.UpdateServer == "" {
			// Enabled but nothing to update — stay no-op (the commit warning
			// already told the operator). Counts as no-backend skips.
			return nopUpdater{}, nil
		}
		return newRFC2136Updater(pol, c, nil,
			func() { m.skippedPTRNotAuth.Add(1) },
			func() { m.skippedConflict.Add(1) },
			m.ifResolver) // #5070: resolve dest-interface to the kernel device
	}
	return m
}

// newManagerForTesting builds a manager with an in-memory state store
// at statePath and injectable lease parser / paths / clock. Exported to other
// packages' tests via pkg/dhcpserver's test seam.
func newManagerForTesting(parser LeaseParser, updater DNSUpdater, statePath, leasePath4, leasePath6, nodeID string, now func() time.Time) *Manager {
	st, degraded, reason := loadStateOrDegrade(statePath, now)
	if updater == nil {
		updater = nopUpdater{}
	}
	m := &Manager{
		state:          st,
		degraded:       degraded,
		degradedReason: reason,
		updater:        updater,
		nodeID:         nodeID,
		leaseParser:    parser,
		leasePath4:     leasePath4,
		leasePath6:     leasePath6,
		now:            now,
	}
	m.rebuildWireRRClaimsLocked() // #5748: seed the cross-surface claim snapshot
	return m
}

// NewManagerForTesting builds a Manager with injectable lease parser, state +
// lease paths, clock, and a per-Reconcile updater factory. It is the exported
// seam OTHER packages' tests use (via pkg/dhcpserver.NewDDNSManagerForTesting)
// to drive the resolve-per-Reconcile manager without real /var/lib paths.
// updater is the fixed fallback used when newUpdater is nil; newUpdater, when
// non-nil, is the resolve-per-Reconcile factory (the policy is not exposed to
// the caller — only the raw config, matching the pre-#2691-P1a seam shape).
// Moved from pkg/dhcpserver/test_seams.go in #2691 P1a.
func NewManagerForTesting(
	parser LeaseParser,
	updater DNSUpdater,
	statePath, leasePath4, leasePath6, nodeID string,
	now func() time.Time,
	newUpdater func(c *config.DHCPDynamicDNSConfig) (DNSUpdater, error),
) *Manager {
	m := newManagerForTesting(parser, updater, statePath, leasePath4, leasePath6, nodeID, now)
	if newUpdater != nil {
		m.newUpdater = func(_ ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
			return newUpdater(c)
		}
	}
	return m
}

// ownerWatermark is the deterministic, node-stable owner id for a lease
// identity (plan §5 invariant 2). It is a hash of identity+address ONLY —
// the receiver's nodeID is DELIBERATELY NOT folded in — so EITHER HA node
// derives the SAME value for the same lease.
//
// Today this value is an INFORMATIONAL marker only (stored as the
// ownership record's OwnerID); it is NOT the delete-matching key. Record
// cleanup matches on identity+address plus the reconstructed RFC 4701
// DHCID, which is already node-independent, so OwnerID is never compared
// across nodes at present. Keeping the watermark node-independent is
// intentional regardless: it avoids surprises if a future phase ever does
// compare it across nodes (folding nodeID would make the two HA nodes
// disagree for the same lease). (#2691 P0 / #2667: the prior comment
// wrongly claimed nodeID was "folded in as a TXT-marker hint"; it never
// was — the code below is correct, the comment was stale.)
func (m *Manager) ownerWatermark(identity, address string) string {
	h := sha256.Sum256([]byte(identity + "|" + address))
	return "xpf-dhcp-ddns:" + hex.EncodeToString(h[:8])
}

// Reconcile resolves the policy from cfg and runs one reconcile pass over
// the current lease files. It is the production entry point; the always-on
// reconcile loop and the HA writer gate that call it are live in
// pkg/daemon/daemon_ddns.go. A nil/disabled policy is a no-op except for
// one-time cleanup of any previously-owned records when the feature is
// turned OFF (so disabling DDNS withdraws its records).
func (m *Manager) Reconcile(ctx context.Context, cfg *config.DHCPServerConfig) error {
	return m.ReconcileScoped(ctx, cfg, ReconcileOptions{})
}

// ForceRefresh arms the operator force-now latch (#5710): the NEXT non-degraded
// reconcile pass re-asserts (re-upserts) every owned DHCP DDNS record onto the
// wire even when its content is unchanged, bypassing the change-detection skip
// the routine reconcile uses for efficiency. It is the DHCP Surface-B half of
// the `request system dynamic-dns update` operator verb (mirroring
// SurfaceAManager.ForceRefresh). It does NOT bypass the per-RG HA writer gate —
// only the redundancy-group owner publishes — and it is one-shot (consumed by
// the first pass that runs), so it forces exactly one publish round. The daemon
// arms the latch and then nudges an immediate reconcile.
func (m *Manager) ForceRefresh() {
	m.mu.Lock()
	m.forceNext = true
	m.mu.Unlock()
}

// reconcileEnv is the per-pass, per-family resolved environment the reconcile
// algorithm + the upsert/delete helpers consume (#2691 P1b). It carries each
// family's INDEPENDENT policy + backend (#2663), plus the HA scope gate +
// resolver (#2664). The helpers select the family slice by a record's Family.
type reconcileEnv struct {
	pol     [2]ddnsPolicy // [0]=v4, [1]=v6
	updater [2]DNSUpdater // [0]=v4, [1]=v6 (resolve-per-Reconcile per family)
	gate    ScopeGate     // per-scope HA writer gate (#2664); nil ⇒ all writable
	res     ScopeResolver // lease→scope attribution (#2664); nil ⇒ zero scope
	// force re-asserts every UNCHANGED owned record on this pass (#5710 operator
	// force-now). It relaxes only the change-detection skip in Pass 1; the per-RG
	// HA writer gate still governs which scopes may be published.
	force bool
	// backendFP is each family's CURRENT backend/update-server ENDPOINT identity
	// fingerprint (#5814): a non-secret hash of the resolved rfc2136 endpoint
	// (backend type + update-server + TSIG key name/algorithm + transport bind).
	// It is STAMPED onto every desired ownedRecord published this pass and
	// COMPARED against a record's stored fingerprint so an in-process
	// update-server / zone / TSIG-key change is DETECTED (the content-only
	// recordsEqual shortcut cannot see it). Empty ("") when the family has no live
	// endpoint (disabled / no update-server / non-rfc2136 backend) or when the
	// backend is not resolve-per-Reconcile (a fixed-updater test) — an empty
	// fingerprint on EITHER side is treated as "cannot prove a change", never a
	// false transition. Only populated on the resolve-per-Reconcile path
	// (m.newUpdater != nil), so a fixed-updater test never transitions.
	backendFP [2]string
	// prevUpdater is each family's PREVIOUS-cycle live backend (#5814), retained
	// so a detected endpoint change withdraws the OLD-endpoint record through the
	// backend that PUBLISHED it — never the newly-resolved one (a delete sent to
	// the new server no-ops at best and, on a "successful" no-op, would falsely
	// drop ownership and orphan the record on the old server forever). Per family
	// so a v4 endpoint change never routes v6 cleanup through v4's backend (#2663
	// independence, #5814 design pt 7). Nil ⇒ the old endpoint is not reachable
	// in-process (first pass, or a daemon restart lost the anchor): the reconciler
	// then KEEPS ownership + alarms rather than deleting at the wrong endpoint.
	prevUpdater [2]DNSUpdater
	// prevFP is the ENDPOINT FINGERPRINT of prevUpdater per family (#5814),
	// carried in lockstep from Manager.lastLiveFP. The transition path uses
	// prevUpdater to withdraw an old-endpoint record ONLY when prevFP equals the
	// record's stored fingerprint — proof that prevUpdater is the SAME endpoint
	// that published it. Without this check a post-restart cycle whose anchor was
	// re-seeded to the NEW endpoint would misroute the withdraw through the new
	// (wrong) server, orphaning the old server's record and dropping ownership.
	prevFP [2]string
}

// famIdx maps an engine family int (4/6) to the [2] env slot.
func famIdx(family int) int {
	if family == 6 {
		return 1
	}
	return 0
}

// updaterFor returns the resolved backend for a record's family.
func (e *reconcileEnv) updaterFor(family int) DNSUpdater { return e.updater[famIdx(family)] }

// prevUpdaterFor returns the PREVIOUS-cycle live backend for a record's family
// (#5814), used to withdraw a record through the endpoint that published it when
// the current endpoint identity has changed. Nil when no in-process anchor is
// held (first pass / post-restart) — the caller must NOT fall back to the new
// endpoint's updater.
func (e *reconcileEnv) prevUpdaterFor(family int) DNSUpdater { return e.prevUpdater[famIdx(family)] }

// backendFPFor returns a family's current endpoint fingerprint (#5814).
func (e *reconcileEnv) backendFPFor(family int) string { return e.backendFP[famIdx(family)] }

// prevFPFor returns the endpoint fingerprint of the family's previous-cycle live
// backend (#5814) — the identity of prevUpdaterFor(family). "" when no anchor is
// held. Compared against an owned record's stored fingerprint to prove the anchor
// is the endpoint that published it before withdrawing through it.
func (e *reconcileEnv) prevFPFor(family int) string { return e.prevFP[famIdx(family)] }

// backendChangedForOwned reports whether an owned record was published through a
// DIFFERENT backend endpoint than the one now resolved for its family (#5814): a
// server / zone / TSIG-key change. BOTH fingerprints must be non-empty to prove a
// mismatch — an unknown fingerprint (a pre-#5814 store, a disabled family, or a
// fixed-updater test) is compared as "cannot determine a change" and never
// triggers a false transition.
func (e *reconcileEnv) backendChangedForOwned(owned ownedRecord) bool {
	cur := e.backendFPFor(owned.Family)
	return owned.BackendFingerprint != "" && cur != "" && owned.BackendFingerprint != cur
}

// polFor returns the resolved policy for a family.
func (e *reconcileEnv) polFor(family int) ddnsPolicy { return e.pol[famIdx(family)] }

// scopeAdmits reports whether THIS node may publish records for a scope under
// the gate (#2664). A nil gate admits everything (standalone). Fail-closed is
// the daemon's gate's responsibility (it returns false for an uncertain RG).
func (e *reconcileEnv) scopeAdmits(s ScopeKey) bool {
	if e.gate == nil {
		return true
	}
	return e.gate(s)
}

// scopeFor attributes a lease to its owning scope (#2664). With no resolver
// (standalone / tests) the scope is just the family — the zero-scope global
// lease path, byte-for-byte the pre-P1b ownership key. The resolver's ok=false
// (lease attributable to no known scope) returns the family-only scope with
// admit=false so the caller fail-closes (does not publish), without losing the
// family tag that keeps v4/v6 ownership independent.
func (e *reconcileEnv) scopeFor(l Lease) (scope ScopeKey, admit bool) {
	if e.res == nil {
		// Standalone / no-resolver: the ZERO scope for BOTH families — the
		// global lease key, byte-for-byte the pre-P1b "identity|address"
		// ownership key (no migration, no churn). A v4 and a v6 record never
		// collide on this key because their ADDRESSES differ (an address is
		// either v4 or v6), so the family need not be folded into the key here;
		// per-family POLICY independence (#2663) is delivered by the per-family
		// policy + backend resolution, not by the ownership key. The record's
		// own Family field stays authoritative for the wire op.
		return ScopeKey{}, e.scopeAdmits(ScopeKey{})
	}
	s, ok := e.res(l)
	if !ok {
		// Unattributable lease: fail-closed (#2664). Use a non-zero family-only
		// scope so the gated-out record cannot alias a real global-scope entry;
		// it is dropped (admit=false), so it is never stored anyway.
		return ScopeKey{Family: familyOf(l.Family)}, false
	}
	return s, e.scopeAdmits(s)
}

// ReconcileScoped is the per-family / per-scope reconcile entry point (#2691
// P1b). It resolves an INDEPENDENT policy + backend for the v4 and the v6
// family (#2663), tags every desired record with its ScopeKey (#2664), and
// applies the per-scope HA writer gate (opts.Gate / opts.Resolver). Reconcile
// is the nil-options (standalone, all-scopes-writable) wrapper.
func (m *Manager) ReconcileScoped(ctx context.Context, cfg *config.DHCPServerConfig, opts ReconcileOptions) error {
	var ddns4, ddns6 *config.DHCPDynamicDNSConfig
	if cfg != nil {
		ddns4 = cfg.DynamicDNS
		ddns6 = cfg.DynamicDNSv6
	}
	// BACKWARD COMPATIBILITY (#2663 + plan §5.9): a pre-P1b config carried a
	// SINGLE dynamic-dns block under ONE family that applied to BOTH families
	// (the reconciler walked both lease sets with one policy). To keep those
	// committed configs working byte-for-byte, when only ONE family's block is
	// present the OTHER family INHERITS it. The moment BOTH families set their
	// own block they are fully INDEPENDENT (the #2663 fix). This preserves the
	// single-family case AND delivers per-family independence for the two-block
	// case, with no silent loss of v6 publishing for existing single-block
	// configs.
	if ddns4 == nil && ddns6 != nil {
		ddns4 = ddns6
	} else if ddns6 == nil && ddns4 != nil {
		ddns6 = ddns4
	}
	pol4 := policyFromConfig(ddns4)
	pol6 := policyFromConfig(ddns6)
	// lastPolicy surfaces an aggregate for Stats(): enabled if EITHER family is
	// enabled; backend is the v4 backend when v4 is configured, else v6's.
	agg := pol4
	if !agg.enabled {
		agg = pol6
	}
	if ddns4 == nil && ddns6 != nil {
		agg = pol6
	}
	m.lastPolicy.Store(&agg)

	m.mu.Lock()
	defer m.mu.Unlock()
	// #5748: republish this surface's wire-RR claim snapshot for the Surface A
	// teardown guard AFTER the pass has mutated the store. Registered second so it
	// runs BEFORE the unlock (LIFO), i.e. still under m.mu. A degraded pass returns
	// early below with an unchanged (empty) store, so the rebuild is a harmless nop.
	defer m.rebuildWireRRClaimsLocked()

	// #5070: refresh the interface-name resolver for THIS pass so a
	// destination-interface binding resolves to the local node's real kernel
	// device before SO_BINDTODEVICE (read by the production newUpdater closure,
	// under this same lock). Nil (standalone tests) ⇒ the leaf fallback.
	m.ifResolver = opts.InterfaceResolver

	// FAIL CLOSED (#2650): the ownership state could not be loaded, so we cannot
	// prove what records this firewall owns. Doing ANYTHING here is unsafe — a
	// publish could overwrite a peer-owned name (lost DHCID veto) and a withdraw
	// has no trustworthy owned set to delete against. Refuse the whole pass
	// (counted as a reconcile failure for visibility) and DO NOT touch the state
	// file. The empty in-memory store is never acted upon, so no save() runs and
	// the quarantined bad file is preserved.
	if m.degraded {
		err := fmt.Errorf("ddns: reconcile suspended (state degraded): %s", m.degradedReason)
		m.recordReconcilePass(err)
		return err
	}

	// Consume the operator force-now latch (#5710) for THIS pass, AFTER the
	// degraded short-circuit above so a suspended (state-degraded) pass — which
	// never publishes — does not swallow the force. One-shot: cleared here so it
	// forces exactly one publish round; the per-RG HA gate below still governs
	// which scopes are written even under force.
	force := m.forceNext
	m.forceNext = false

	env := reconcileEnv{
		pol:     [2]ddnsPolicy{pol4, pol6},
		updater: [2]DNSUpdater{m.updater, m.updater},
		gate:    opts.Gate,
		res:     opts.Resolver,
		force:   force,
	}

	// Resolve each family's live backend from THIS cycle's policy (plan §6
	// fork 1: resolve-per-Reconcile, now PER FAMILY — #2663). A nil factory
	// keeps the static updater (tests inject a fixed fakeUpdater). A factory
	// error (bad TSIG / unusable policy) for one family falls back to that
	// family's no-op WITHOUT affecting the other family — independence (#2663).
	if m.newUpdater != nil {
		// #5814: this family's CURRENT endpoint identity fingerprint (stamped onto
		// every record published this pass) + the PREVIOUS cycle's per-family live
		// backend (to withdraw an old-endpoint record through the backend that
		// published it). Computed from the operator config BEFORE resolveFamily-
		// Updater runs (the production factory may rewrite c.UpdateServer to a lab
		// address; the fingerprint tracks the committed identity, not the dialed
		// one). Copy the anchor array (value semantics) before it is advanced below.
		env.backendFP[0] = dhcpBackendFingerprint(pol4, ddns4)
		env.backendFP[1] = dhcpBackendFingerprint(pol6, ddns6)
		env.prevUpdater = m.lastLiveUpdater
		// Carry the anchor's IDENTITY too (#5814): the transition path withdraws
		// through prevUpdater only when its fingerprint proves it is the endpoint
		// that published the owned record — otherwise (e.g. a post-restart anchor
		// re-seeded to the NEW endpoint) it orphans + alarms instead of misrouting.
		env.prevFP = m.lastLiveFP

		env.updater[0] = m.resolveFamilyUpdater(pol4, ddns4)
		env.updater[1] = m.resolveFamilyUpdater(pol6, ddns6)
		// Keep the LIVE-updater-for-withdraw guard, now per family: if a family
		// resolved to nop but still owns records (turn-off), keep the prior live
		// updater for THIS withdraw cycle so the backend that published also
		// withdraws (else the nop silently drops ownership, orphaning the live
		// RR — the same hazard the single-family path guards, plan §4.2).
		env.updater = m.applyWithdrawAnchors(env.updater)
		// Track a single representative live updater for the next-cycle
		// withdraw guard (m.updater is the "last live backend seen" anchor).
		if !isNopUpdater(env.updater[0]) {
			m.updater = env.updater[0]
		} else if !isNopUpdater(env.updater[1]) {
			m.updater = env.updater[1]
		}
		// #5814: advance the PER-FAMILY live-backend anchor + its fingerprint for
		// NEXT cycle's endpoint-change detection, in LOCKSTEP. Per family (not the
		// single m.updater) so a v6 endpoint change never withdraws through v4's
		// backend — the independence design pt 7 flags. A nop cycle PRESERVES both
		// so a transient factory error (or a one-cycle disable) does not erase the
		// anchor and misclassify the next live cycle as unreachable. Storing the
		// fingerprint ALONGSIDE the updater is what lets the transition path prove a
		// retained anchor is genuinely the endpoint that published a given record
		// (owned.BackendFingerprint == prevFP) before withdrawing through it —
		// closing the post-restart wrong-endpoint-delete gap.
		if !isNopUpdater(env.updater[0]) {
			m.lastLiveUpdater[0] = env.updater[0]
			m.lastLiveFP[0] = env.backendFP[0]
		}
		if !isNopUpdater(env.updater[1]) {
			m.lastLiveUpdater[1] = env.updater[1]
			m.lastLiveFP[1] = env.backendFP[1]
		}
	}

	now := m.now()
	untrusted := map[int]bool{}
	var leases []Lease
	var err4, err6 error

	// Per-family enable: a disabled family withdraws ITS OWN records only
	// (#2663 independence — disabling v4 must not touch v6). A family that is
	// enabled feeds its leases into the shared desired set.
	if pol4.enabled {
		l4, e4 := m.parseLeases(m.leasePath4, 4, now)
		err4 = e4
		if e4 != nil {
			slog.Warn("ddns: parse v4 leases failed; suppressing v4 deletes this cycle", "err", e4)
			untrusted[4] = true
		}
		leases = append(leases, l4...)
	} else {
		// v4 disabled: withdraw v4-owned records through the resolved v4
		// updater. Leaving v4 out of `leases` would make Pass 1 try to delete
		// every v4 record anyway, but routing the withdraw explicitly keeps the
		// family-scoped semantics clear and uses the v4 backend.
		untrusted[4] = false
	}
	if pol6.enabled {
		l6, e6 := m.parseLeases(m.leasePath6, 6, now)
		err6 = e6
		if e6 != nil {
			slog.Warn("ddns: parse v6 leases failed; suppressing v6 deletes this cycle", "err", e6)
			untrusted[6] = true
		}
		leases = append(leases, l6...)
	} else {
		untrusted[6] = false
	}

	// disabledFamilies tells the reconciler to WITHDRAW (delete-owned) a
	// family's records rather than skip them: a family that is not enabled has
	// no desired set, so Pass 1 deletes its owned records (turn-off cleanup),
	// while an ENABLED family with an unreadable CSV is untrusted (skip the
	// destructive diff). The two must not be conflated.
	disabled := map[int]bool{4: !pol4.enabled, 6: !pol6.enabled}

	recErr := m.reconcileOnceLocked(ctx, &env, leases, untrusted, disabled)
	passErr := recErr
	if passErr == nil {
		if err4 != nil {
			passErr = err4
		} else if err6 != nil {
			passErr = err6
		}
	}
	m.recordReconcilePass(passErr)
	return passErr
}

// resolveFamilyUpdater resolves one family's backend from its policy + config,
// falling back to the no-op (logged, counted) on a factory error so one
// family's malformed backend cannot wedge the loop or affect the other family.
func (m *Manager) resolveFamilyUpdater(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) DNSUpdater {
	up, err := m.newUpdater(pol, c)
	if err != nil {
		slog.Warn("ddns: cannot build DNS-update backend; staying no-op this cycle for this family", "err", err)
		return nopUpdater{}
	}
	return up
}

// familyOwnsRecords reports whether the ownership store holds any record of the
// given family — used to keep a live updater for a turn-off withdraw cycle.
func (m *Manager) familyOwnsRecords(family int) bool {
	for _, r := range m.state.records {
		if r.Family == family {
			return true
		}
	}
	return false
}

// desiredRecord is one entry of the reconcile desired set: the record a
// live lease wants owned for its scope+identity+address this pass.
type desiredRecord struct {
	rec  LeaseDNSRecord
	ow   ownedRecord
	seen bool
}

// dhcidSharedWithOther reports whether ANOTHER owned record (a different store
// key) shares the SAME RFC 4701 DHCID as `owned` — i.e. the same non-empty
// ClientID and the same canonical FQDN (#2700). The DHCID digest is
// SHA-256(client-identity || canonical-FQDN-in-wire-form) and folds in NEITHER
// the address NOR the family, so a dual-stack client (an A and an AAAA under
// one FQDN, same client identity) produces ONE shared DHCID across both
// records. When such a sibling exists, deleting one family's A/AAAA must keep
// the shared DHCID on the wire so the surviving family's record stays
// DHCID-protected and its eventual delete still satisfies the DHCID-match
// prerequisite — otherwise the survivor is left unprotected (a hijack window)
// and then leaks on the wire (its delete prereq fails). Records with an empty
// ClientID never wrote a DHCID (the delete takes the plain exact-RR path), so
// they are never siblings. Caller holds m.mu.
func (m *Manager) dhcidSharedWithOther(owned ownedRecord) bool {
	if owned.ClientID == "" {
		return false
	}
	ownedKey := ownedRecordKey(owned.scopeOf(), owned.Identity, owned.Address)
	ownedFQDN := dnsCanonicalFQDN(owned.FQDN)
	for k, r := range m.state.records {
		if k == ownedKey {
			continue
		}
		if r.ClientID == owned.ClientID && dnsCanonicalFQDN(r.FQDN) == ownedFQDN {
			return true
		}
	}
	return false
}

// crossTypeSiblingOwned reports whether the manager already owns a record
// at owned's canonical FQDN under the OPPOSITE address family (#14604).
// The sibling may be (a) a durable store record, or (b) a still-desired
// record whose write-ahead intent is already durable in this same pass
// (the write-ahead put that precedes every UpsertLease, #2662): Pass-2
// sibling evaluation runs one lease at a time, so relying on the store
// alone is enough only because upsertLocked writes each family's intent
// before its own wire add. The check is re-run per call, so sibling state
// is re-proven per cycle for the duration of the pass. Records are matched
// on the canonical FQDN and opposite family only, NOT on ClientID/Identity:
// production-shaped dual-stack producers never share an identity across
// families (cid:/mac: vs duid:), so an identity match would re-create the
// Y13-02/#14602 bug. A third record sharing only the FQDN under the SAME
// family/scope never sets the flag. PTR records are forward-type absent
// from this store, so they never match.
func (m *Manager) crossTypeSiblingOwned(owned ownedRecord) bool {
	ownedFQDN := dnsCanonicalFQDN(owned.FQDN)
	for _, r := range m.state.records {
		if r.Family == owned.Family {
			continue
		}
		if dnsCanonicalFQDN(r.FQDN) == ownedFQDN {
			return true
		}
	}
	return false
}

// dhcidStillWanted reports whether the desired set itself still wants a
// record that would compute the SAME RFC 4701 DHCID as `owned` (#14189).
// It is consulted ONLY by the Pass-1 move path (a still-wanted-differently
// delete whose replacement Pass 2 re-publishes this pass) — never by a
// genuine expiry / backend-transition withdraw — so the expiration
// semantics of dhcidSharedWithOther (scan the store only) are unchanged
// everywhere else. Caller holds m.mu.
func dhcidStillWanted(owned ownedRecord, want map[string]*desiredRecord) bool {
	if owned.ClientID == "" {
		return false
	}
	ownedFQDN := dnsCanonicalFQDN(owned.FQDN)
	for _, d := range want {
		if d.ow.ClientID == owned.ClientID && dnsCanonicalFQDN(d.ow.FQDN) == ownedFQDN {
			return true
		}
	}
	return false
}

// wireRRSharedWithOther reports whether ANOTHER owned record — a DIFFERENT store
// key, i.e. a different DDNS scope — publishes the SAME wire resource record as
// `owned`: the same forward name + type + rdata (canonical FQDN, ForwardType,
// and textual Address). Two DDNS scopes — e.g. two redundancy groups, or a
// per-interface binding and a global one — can legitimately resolve the same
// host to the same address and thus CO-OWN one wire RR; each keeps its own
// ownership row because the ScopeKey prefix makes the store keys distinct (#2691
// P1b). The reverse PTR is co-owned too: PTRName derives deterministically from
// Address and the PTR target is the FQDN, so an equal (FQDN, Address) implies an
// equal PTR RR — matching the forward tuple captures both directions (#5709).
//
// deleteOwnedLocked reconstructs the wire RR from (FQDN, ForwardType, Address)
// alone, so without this claim accounting one scope's teardown (lease expiry /
// config removal) would issue a wire DELETE that removes the RR the OTHER scope
// still legitimately owns and refreshes — silently clobbering a live record
// (codex-review-182 M36). When a co-owner exists the reconciler releases ONLY
// the departing scope's ownership claim and leaves the wire RR in place; the
// surviving scope, as the LAST claimant, issues the real wire delete when it in
// turn tears down. Address must be non-empty (a lease record's rdata is always
// its Address) so two rdata-less rows never falsely co-match. Caller holds m.mu.
//
// #5748: the scan is now surface-agnostic. Beyond the Surface B lease store
// (m.state.records) it also consults the SEPARATE Surface A ownership surface
// (router/interface DDNS records, rdata in AddrText not Address) through the
// injected surfaceACoowners accessor. A Surface A record and a Surface B lease
// can legitimately resolve the same host to the same address and thus co-own one
// wire RR; without the cross-surface arm a lease teardown would still issue a
// DELETE that clobbers a Surface-A-owned identical RR. The accessor is a
// LOCK-FREE snapshot read (see the field doc), so this runs while m.mu is held
// with no lock-order cycle. Nil accessor ⇒ pre-#5748 Surface-B-only behavior.
func (m *Manager) wireRRSharedWithOther(owned ownedRecord) bool {
	if owned.Address == "" {
		return false
	}
	ownedKey := ownedRecordKey(owned.scopeOf(), owned.Identity, owned.Address)
	ownedFQDN := dnsCanonicalFQDN(owned.FQDN)
	for k, r := range m.state.records {
		if k == ownedKey {
			continue
		}
		if r.Address == owned.Address &&
			r.ForwardType == owned.ForwardType &&
			dnsCanonicalFQDN(r.FQDN) == ownedFQDN {
			return true
		}
	}
	// Cross-surface (#5748): a Surface A router/interface record may co-own the
	// SAME wire RR (canonical FQDN + forward type + rdata). Its rdata lives in
	// AddrText, already normalized into the Rdata field of each WireRRClaim; build
	// the same canonical claim for this lease record and compare by value.
	if m.surfaceACoowners != nil {
		ownedClaim := wireRRClaim(owned.FQDN, owned.ForwardType, owned.Address, m.currentAuthorityLocked())
		for _, c := range m.surfaceACoowners() {
			if c.coOwns(ownedClaim) {
				return true
			}
		}
	}
	return false
}

// SetSurfaceACoownerSource injects the accessor the daemon wires so a lease
// teardown can consult the Surface A ownership surface for a cross-surface wire-RR
// co-owner (#5748). fn MUST be lock-free with respect to SurfaceAManager.mu (it is
// SurfaceAManager.WireRRClaims, a bare atomic load) so calling it under m.mu can
// never deadlock. Idempotent; nil clears it (restores Surface-B-only behavior).
func (m *Manager) SetSurfaceACoownerSource(fn func() []WireRRClaim) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.surfaceACoowners = fn
}

// WireRRClaims returns a LOCK-FREE snapshot of the wire RRs this (Surface B lease)
// surface currently owns, for the Surface A teardown guard to consult (#5748). It
// does a bare atomic load and NEVER takes m.mu, so a peer holding
// SurfaceAManager.mu can call it with no lock-order cycle. Returns an empty slice
// before the first rebuild.
func (m *Manager) WireRRClaims() []WireRRClaim {
	if p := m.wireRRClaims.Load(); p != nil {
		return *p
	}
	return nil
}

// rebuildWireRRClaimsLocked recomputes this surface's published wire-RR claim
// snapshot from the durable store and publishes it atomically for the peer's
// lock-free read (#5748). Caller holds m.mu. A lease record's rdata IS its
// Address; rdata-less rows are skipped (they can never co-own a wire RR). The
// snapshot is an immutable slice — replaced wholesale, never mutated in place.
// currentAuthorityLocked is this surface's DNS authority fingerprint (#6755),
// taken from the last resolved policy. Empty when no policy has resolved yet,
// which coOwns treats as unknown rather than as a different authority.
//
// The lease surface stamps its CURRENT authority rather than a per-record
// publish-time one, because ownedRecord carries no fingerprint field and adding
// one would be a durable-store change this fix does not otherwise need. The
// asymmetry with Surface A (which does store publish-time) is bounded: a policy
// whose endpoint changes republishes its records through the new endpoint, and
// until it does, an authority mismatch only ever makes coOwns MORE conservative
// about suppressing a delete on the Surface A side.
func (m *Manager) currentAuthorityLocked() string {
	if p := m.lastPolicy.Load(); p != nil {
		return p.authority
	}
	return ""
}

func (m *Manager) rebuildWireRRClaimsLocked() {
	claims := make([]WireRRClaim, 0, len(m.state.records))
	for _, r := range m.state.records {
		if r.Address == "" {
			continue
		}
		claims = append(claims, wireRRClaim(r.FQDN, r.ForwardType, r.Address, m.currentAuthorityLocked()))
	}
	m.wireRRClaims.Store(&claims)
}

// parseLeases reads a family's active leases via the injected LeaseParser
// (#2691 P1a). A nil parser (the spine constructed without a Kea-memfile
// parser) yields an empty, trusted lease set — identical to a healthy memfile
// with no active leases. The parser's error is propagated unchanged so the
// caller's untrusted-family fail-safe behaves exactly as before the extraction.
func (m *Manager) parseLeases(path string, family int, now time.Time) ([]Lease, error) {
	if m.leaseParser == nil {
		return nil, nil
	}
	return m.leaseParser(path, family, now)
}

// recordReconcilePass tallies a whole reconcile pass by outcome (plan §4.4
// reconcile_runs_total{result}). A nil err is an "ok" pass; a non-nil err
// (record-op failure or an unreadable lease family) is a "fail" pass.
func (m *Manager) recordReconcilePass(err error) {
	if err != nil {
		m.reconcileFail.Add(1)
		return
	}
	m.reconcileOK.Add(1)
}

// blockedName is the key of reconcileOnceLocked's Pass-1 -> Pass-2 name block:
// a forward name is blocked for the FAMILY whose delete failed, never for both
// (#8597 K50). A struct key makes the family un-forgeable by any name value.
type blockedName struct {
	family int
	fqdn   string
}

// reconcileOnceLocked is the pure reconcile algorithm (plan §4.5): build
// the desired DNS state from active leases, diff against owned state, and
// apply add / move / reassign / expire transitions — each reconciled
// against owned state so the never-delete-non-owned boundary holds. Caller
// holds m.mu. Exposed (unexported) so tests drive it with synthetic
// leases + a fakeUpdater.
// untrusted maps a lease family (4 or 6) to true when that family's lease
// CSV could not be read/parsed this cycle. The reconciler skips the
// destructive diff (deletes) for an untrusted family so a transient
// malformed lease file can never mass-delete that family's owned records.
// A nil map means all families are trusted.
func (m *Manager) reconcileOnceLocked(ctx context.Context, env *reconcileEnv, leases []Lease, untrusted, disabled map[int]bool) error {
	blockedIdentity := map[string]struct{}{}
	blockedAddress := map[string]struct{}{}
	// blockedFQDN is keyed by (family, name), NOT by name alone (#8597 K50).
	//
	// A failed Pass-1 delete leaves a live RR the reconciler believes it has
	// removed, so Pass 2 must not add a record that would CONFLICT with it.
	// Identity and address are already family-distinct in practice — a v4
	// identity is "cid:"/"mac:"-prefixed and a v6 one "duid:"-prefixed (the
	// no-identity fallback is "addr:"+address), and a v4 address text never
	// equals a v6 one — but a DUAL-STACK host publishes the SAME FQDN for its
	// A and its AAAA. Keyed on the bare name, a failed A delete therefore
	// suppressed that host's unrelated AAAA publish for the whole cycle:
	//
	//	seed:   A laptop.example.com -> 10.0.1.5
	//	cycle:  v4 lease moves to 10.0.1.9; a NEW v6 lease appears
	//	        the A delete fails -> blockedFQDN["laptop.example.com"]
	//	        => the AAAA add is skipped, though nothing about the failed
	//	           A delete can conflict with an AAAA
	//
	// The conflict this gate exists for is per RECORD TYPE, and the family
	// determines the type (A vs AAAA, and the PTR derives from the rdata), so
	// (family, name) is the axis. Dropping the name gate entirely is NOT the
	// fix: it is the only one of the three that covers a same-family
	// REASSIGNMENT — a different client taking over a name at a different
	// address matches neither the identity nor the address gate, and without
	// this gate Pass 2 publishes A name->new while A name->old is still live.
	// Both halves are pinned by cells in ddns_blocked_fqdn_family_8597_test.go.
	//
	// A struct key rather than a formatted string: the family cannot then be
	// forged by a name value, with no encoding argument to maintain (#8597 K49
	// is the same lesson one function over).
	blockedFQDN := map[blockedName]struct{}{}

	// gatedScope[scopePrefix] = true marks a scope this node may NOT publish
	// for (the per-RG HA writer gate is CLOSED for it, #2664). An owned record
	// in a gated scope is treated EXACTLY like an untrusted family in Pass 1:
	// it is NEVER deleted (stop-writing, never withdraw — the peer MASTER for
	// that RG refreshes it; a withdraw race would blackhole, plan §5.6) and
	// never re-published from here. Tracked by scope-prefix so the Pass-1
	// owned-record loop can ask "is this record's scope gated?" without a
	// resolver (the owned record carries its scope).
	gatedScope := map[string]bool{}

	// desired[key] = the record we want owned for that scope+identity+address.
	want := map[string]*desiredRecord{}
	// Reassignment (a new client taking over an address a different client
	// held) is cleaned by the owned-state delete pass below, NOT a separate
	// tracker: the old owner's (scope,identity,address) key is no longer in
	// `want` (the new client has a different identity), so Pass 1 deletes the
	// old owned record before Pass 2 adds the new one (delete-before-add on a
	// shared address; a failed delete blocks the add via the blocked maps).
	for _, l := range leases {
		pol := env.polFor(l.Family)
		source := hostnameSourceFor(&pol)
		// Only an address-bearing lease (IA_NA / IA_TA) may become an
		// A/AAAA/PTR record. Reject an IA_PD delegated-prefix base (and any
		// unknown/unparseable v6 lease type) BEFORE name/record derivation so
		// its prefix base is never coerced into a host address and published
		// (#5072). It is dropped from `want`, so any record mis-published for
		// it before this gate existed is withdrawn by the Pass-1 delete below.
		if !l.isAddressLease() {
			m.skippedNonAddress.Add(1)
			slog.Debug("ddns: skipping non-address lease (IA_PD / unknown lease type); "+
				"not publishing host DNS for a delegated-prefix base",
				"address", l.Address, "family", l.Family, "leaseType", l.LeaseType)
			continue
		}
		// Resolve the lease's scope + the per-RG HA gate decision (#2664). A
		// gated-out scope is recorded so Pass 1 protects its owned records from
		// deletion, and the desired record is NOT added (stop-writing).
		scope, admit := env.scopeFor(l)
		if !admit {
			gatedScope[scope.scopePrefix()] = true
			slog.Debug("ddns: scope not writable from this node (per-RG gate closed); "+
				"not publishing, not withdrawing",
				"address", l.Address, "rg", scope.RGOwner, "family", l.Family)
			continue
		}
		fqdn, err := deriveFQDN(l.HostName, l.ClientFQDN, l.Identity, pol.domain, source)
		if err != nil {
			m.skippedNoName.Add(1)
			slog.Debug("ddns: skipping lease with no publishable name",
				"address", l.Address, "err", err)
			continue
		}
		rec, err := buildLeaseRecord(fqdn, l.Address, pol.ttl)
		if err != nil {
			slog.Warn("ddns: skipping lease with invalid address", "err", err)
			continue
		}
		identity := l.Identity
		if identity == "" {
			// No stable identity: key ownership on the address alone so
			// reassignment still cleans (the address is the reverse key).
			identity = "addr:" + l.Address
		}
		// Carry the lease identity onto the published record so the live
		// backend can derive the RFC 4701 DHCID ownership marker. The
		// address-fallback identity ("addr:<addr>") is intentionally NOT a
		// DHCID source — only a real client identity proves ownership — so the
		// raw lease identity (possibly empty) is what the backend hashes.
		rec.ClientID = l.Identity
		ow := ownedRecord{
			Family:      l.Family,
			Identity:    identity,
			SubnetID:    l.SubnetID,
			Address:     l.Address,
			FQDN:        rec.FQDN,
			ForwardType: rec.ForwardType,
			PTRName:     rec.PTRName,
			TTL:         rec.TTL,
			OwnerID:     m.ownerWatermark(identity, l.Address),
			ClientID:    l.Identity,
			// #5814: stamp the CURRENT endpoint identity so a later reconcile can
			// detect an update-server / TSIG-key change and withdraw the old
			// endpoint's record through the backend that published it. Empty on the
			// fixed-updater path (env.backendFP unset) — no transition ever fires.
			BackendFingerprint: env.backendFPFor(l.Family),
		}.withScope(scope)
		want[ownedRecordKey(scope, identity, l.Address)] = &desiredRecord{rec: rec, ow: ow}
	}

	var firstErr error
	noteErr := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}

	// Pass 1 — expire / reassign: delete every owned record that is NOT
	// in the desired set, OR whose desired record set changed (address
	// moved, name changed). Cleaning before adding is what makes
	// reassignment safe (delete the old owner first).
	for _, owned := range m.state.all() {
		key := ownedRecordKey(owned.scopeOf(), owned.Identity, owned.Address)
		d, stillWanted := want[key]
		// #5814: the content-only recordsEqual shortcut MUST NOT settle a record
		// whose backend/update-server ENDPOINT changed — the DNS tuple is identical
		// but it now lives on the WRONG server. backendChangedForOwned forces the
		// fall-through to the transition path below (withdraw at the old endpoint,
		// republish at the new one). An unknown fingerprint on either side (pre-#5814
		// store, disabled family, fixed-updater test) reports "no change", so the
		// existing efficiency skip is preserved for every non-transition record.
		if stillWanted && recordsEqual(owned, d.ow) && !env.backendChangedForOwned(owned) {
			// The published forward/reverse tuple is unchanged. If the owned
			// record still owes its reverse PTR (#2661 partial success), leave it
			// owned (do NOT delete the live forward) but do NOT mark it settled —
			// fall through so Pass 2 re-runs the upsert and re-attempts the PTR
			// (the forward re-add is an idempotent no-op).
			//
			// Operator force-now (#5710): when env.force is set, also leave the
			// record UNSETTLED so Pass 2 re-upserts it onto the wire even though
			// the content is unchanged. This lets `request system dynamic-dns
			// update` repair a drifted / manually-deleted authoritative RR that
			// the routine change-detection skip would otherwise never re-publish.
			// The record is still not deleted (it IS wanted and equal), so force
			// only relaxes the efficiency skip — never the HA gate, which already
			// dropped gated scopes from `want`.
			if !owned.PTRPending && !env.force {
				d.seen = true // fully published; no add needed below
			}
			continue
		}
		// HA per-RG gate (#2664): if this owned record's scope is gated CLOSED
		// from this node (we are not the MASTER for its RG), STOP WRITING but
		// NEVER WITHDRAW — leave it in the store untouched. The peer that is
		// MASTER for that RG owns the refresh; a withdraw here would race the
		// peer and blackhole (plan §5.6 / risk R3). This is the load-bearing
		// #2664 invariant: a node that loses one RG must not delete that RG's
		// records.
		//
		// The gate is consulted DIRECTLY on the owned record's stored scope
		// (env.scopeAdmits), NOT only via gatedScope — which is populated solely
		// from leases present in THIS cycle's parsed set. On a STEADY-STATE
		// partial demotion the demoted RG's group is dropped from the narrowed
		// Kea config (filterDHCPConfigForMasterRGs) and its leases age out of the
		// memfile, so those leases vanish from the parsed set and gatedScope
		// never learns the demoted RG's prefix. Without re-asking the gate here,
		// Pass 1 would then see the demoted RG's owned record as "not wanted, not
		// gated, not untrusted, not disabled" and WITHDRAW it — the exact §5.6
		// blackhole the per-RG gate exists to prevent. Re-evaluating the SAME
		// gate the publish path consults keeps publish and withdraw in agreement:
		// a scope this node does not master is neither published nor withdrawn.
		// Standalone (nil gate) admits every scope ⇒ this guard is inert and
		// turn-off / expiry / reassignment withdrawal still works; a disabled
		// family's owned records are in scopes this node DOES master, so the gate
		// admits them and they are still withdrawn (turn-off cleanup unaffected).
		if gatedScope[owned.scopeOf().scopePrefix()] || !env.scopeAdmits(owned.scopeOf()) {
			if stillWanted {
				d.seen = true
			}
			continue
		}
		// Fail-safe (#1387 MAJOR-4): if this owned record's family had an
		// unreadable/partial lease CSV this cycle, its "expired" appearance
		// is untrustworthy — skip the delete entirely. Mark the record as
		// seen so the add pass does not re-publish it either; leave the
		// ownership entry intact for a later, trustworthy reconcile. A DISABLED
		// family (disabled[family]) is NOT untrusted — it has no desired set on
		// purpose, so its owned records SHOULD be withdrawn (turn-off cleanup),
		// so disabled does not protect from delete here.
		if untrusted[owned.Family] && !disabled[owned.Family] {
			if stillWanted {
				d.seen = true
			}
			continue
		}
		// Owned but not wanted (expired/released) OR wanted differently
		// (the desired pass below re-adds the new form). Delete only the
		// EXACT owned tuple — never anything not in the store.
		delUpdater := env.updaterFor(owned.Family)
		if env.backendChangedForOwned(owned) {
			// #5814: this record was published at a DIFFERENT endpoint than the one
			// now resolved for its family (an update-server / zone / TSIG-key
			// change). It MUST be withdrawn THROUGH the OLD endpoint — a delete sent
			// to the newly-resolved server no-ops at best and, on a "successful"
			// no-op, would falsely drop ownership and orphan the record on the old
			// server forever. Route the withdraw through the retained previous-cycle
			// backend for THIS family — but ONLY when its fingerprint PROVES it is
			// the endpoint that published this record; Pass 2 publishes the new form
			// on the new endpoint (delete-old-then-add-new).
			prev := env.prevUpdaterFor(owned.Family)
			if prev == nil || isNopUpdater(prev) || env.prevFPFor(owned.Family) != owned.BackendFingerprint {
				// The OLD endpoint is not reachable in-process, OR the retained
				// anchor is NOT the endpoint that published this record. The latter
				// is the post-restart trap (#5814 review): after a restart the anchor
				// is nil for one cycle (this branch, correctly), then the first
				// post-restart cycle re-seeds it to the NEW endpoint — so a naive
				// non-nil check would find a live anchor pointing at the WRONG server
				// and delete the old-endpoint record through it, orphaning the old
				// server's record and dropping ownership. The prevFP==owned
				// fingerprint gate blocks that: unless the anchor's identity matches
				// the record's, we treat the old endpoint as unreachable. Deleting at
				// the wrong endpoint or overwriting ownership would destroy the old
				// cleanup key and orphan the record with no authority to clean it.
				// KEEP ownership (with the old fingerprint), raise the alarm EVERY
				// cycle the mismatch persists (a cumulative counter — operators keep
				// seeing it, it never freezes), and do NOT republish this exact tuple
				// on the new endpoint this pass (that overwrite would clobber the old
				// fingerprint). A later reconcile with the old backend reachable, or
				// operator action, resolves it. Mirrors Surface A's deferred-
				// withdrawal posture on a lost old endpoint (#3735).
				m.orphanedBackendChange.Add(1)
				slog.Warn("ddns: backend/update-server identity changed but the OLD "+
					"endpoint is not reachable in-process; keeping ownership and NOT "+
					"deleting at the new endpoint (cleanup authority preserved; the "+
					"record may be stale on the old server — operator attention needed)",
					"fqdn", owned.FQDN, "address", owned.Address, "type", owned.ForwardType,
					"family", owned.Family)
				if stillWanted {
					d.seen = true // do not republish the same tuple onto the new endpoint
				}
				continue
			}
			delUpdater = prev
		}
		// #14189: this Pass-1 delete is a MOVE (not an expiry) iff the desired
		// set re-publishes the same FQDN+ClientID — hence the same DHCID —
		// this pass (Pass 2). The owned key embeds the address, so an IP
		// change makes stillWanted false even though the NAME is still
		// wanted; dhcidStillWanted is the move test. Keep the DHCID on the
		// wire for the replacement, or the re-add's RFC 4703 Attempt B loses
		// its ownership proof and refuses forever when any other RRset
		// coexists at the name. A genuine expiry (no matching desired
		// record) must NOT keep it — the name is being released.
		keepDHCID := dhcidStillWanted(owned, want)
		if err := m.deleteOwnedLocked(ctx, delUpdater, owned, keepDHCID); err != nil {
			// errDDNSNoBackendToWithdraw is a "kept ownership, no backend"
			// non-failure (#2699): the record stays owned + cleanable, but no
			// wire op was attempted, so it must NOT fail the reconcile pass (a
			// legitimate turn-off / restart with no backend resolves to nop).
			// Still BLOCK a re-add of the same tuple this cycle — the record is
			// still considered live/owned, not expired.
			if !errors.Is(err, errDDNSNoBackendToWithdraw) {
				noteErr(err)
			}
			blockedIdentity[owned.Identity] = struct{}{}
			blockedAddress[owned.Address] = struct{}{}
			blockedFQDN[blockedName{family: owned.Family, fqdn: owned.FQDN}] = struct{}{}
			// leave it in the store so a later reconcile retries the
			// delete (bounded by the loop cadence; never wedges).
			continue
		}
	}

	// Pass 2 — add / move: upsert every desired record not already owned
	// in its current exact form.
	for _, d := range want {
		if d.seen {
			continue
		}
		if _, blocked := blockedIdentity[d.ow.Identity]; blocked {
			continue
		}
		if _, blocked := blockedAddress[d.ow.Address]; blocked {
			continue
		}
		if _, blocked := blockedFQDN[blockedName{family: d.ow.Family, fqdn: d.ow.FQDN}]; blocked {
			continue
		}
		if err := m.upsertLocked(ctx, env.updaterFor(d.ow.Family), d.rec, d.ow); err != nil {
			noteErr(err)
			continue
		}
	}

	// End-of-pass durability backstop. Adds are already durable via the
	// per-record write-ahead in upsertLocked (#2662), so this no longer
	// covers the crash-after-add orphan window; it persists the ownership
	// REMOVALS done by deleteOwnedLocked in Pass 1 (a delete drops the
	// in-memory entry but does not self-save). A delete leaves "ownership
	// without a live RR", never an orphaned live RR — so the residual window
	// here is self-healing (a crash before this save replays the idempotent
	// re-delete next pass), not an orphan. The save is still issued so the
	// store converges promptly.
	if err := m.state.save(); err != nil {
		slog.Warn("ddns: persist ownership state failed", "err", err)
		noteErr(err)
	}
	m.lastReconcile.Store(m.now().UnixNano())
	m.lastReconcileN.Store(int64(len(leases)))
	return firstErr
}

// withdrawAllLocked deletes every owned record (feature disabled / config
// removed) so turning DDNS off cleans the operator's zone. Records that
// fail to delete stay in the store for a later retry. Caller holds m.mu.
func (m *Manager) withdrawAllLocked(ctx context.Context) error {
	owned := m.state.all()
	if len(owned) == 0 {
		return nil
	}
	var firstErr error
	for _, r := range owned {
		// errDDNSNoBackendToWithdraw (#2699) keeps ownership and is not a wire
		// failure: a withdraw-all with no live backend (DDNS disabled before a
		// real backend was ever resolved, or a restart that has not yet built
		// one) legitimately resolves to nop. Do NOT surface it — the records are
		// kept and a later reconcile with a live backend withdraws them.
		if err := m.deleteOwnedLocked(ctx, m.updater, r, false); err != nil &&
			!errors.Is(err, errDDNSNoBackendToWithdraw) && firstErr == nil {
			firstErr = err
		}
	}
	if err := m.state.save(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// providerIO performs ONE provider network call (UpsertLease/DeleteLease) with
// m.mu RELEASED, then re-acquires the lock before returning (#5006, mirroring
// SurfaceAManager.providerIO / #2778). The caller MUST hold m.mu on entry and
// will hold it again on return. Releasing the lock around the wire op — bounded
// by the ~5s DDNS reconcile timeout — is the whole point: a slow or hung
// authoritative RFC 2136 server must NOT block the telemetry/CLI readers
// Stats() / OwnedRecordViews() (`show system services dynamic-dns` + the
// Prometheus scrape both take m.mu). The daemon serializes reconcile passes
// (ddnsReconcileInFlight, pkg/daemon/daemon.go), so no concurrent pass mutates
// m.state while the lock is dropped here — only the read-only Stats() /
// OwnedRecordViews() callers may run, which is exactly what must be unblocked.
// The write-ahead ownership intent (upsertLocked) is persisted under the lock
// BEFORE this call and the wire result is recorded under the re-acquired lock
// AFTER it, so the durable store is never mutated concurrently. Panic-safe: the
// lock is re-acquired even if fn panics, keeping ReconcileScoped's deferred
// Unlock balanced (a panicking backend would otherwise double-unlock).
func (m *Manager) providerIO(fn func() error) error {
	m.mu.Unlock()
	defer m.mu.Lock()
	return fn()
}

// upsertLocked publishes a record and records ownership on success. With no
// live backend (nopUpdater), the upsert is a logged no-op AND ownership is
// deliberately NOT recorded: recording ownership for a record that never
// reached a real backend would (a) leave the store claiming records that do
// not exist in DNS and (b) cause a later real backend to skip them as
// "already owned". So the no-op path counts the skip and returns success
// (reconcile must not wedge) without mutating the ownership store.
//
// WRITE-AHEAD OWNERSHIP (#2662): the durable ownership record is persisted
// BEFORE the DNS add, not at the end of the reconcile pass. The previous
// shape (in-memory put per record, ONE state.save() after all I/O) left a
// per-PASS orphan window: a crash / kill / disk-full / WriteFileDurable
// failure after a successful DNS add but before the end-of-pass save left a
// LIVE DNS RR with NO durable ownership record — on restart the manager
// loaded the pre-add store and had no authority to ever clean that RR (the
// stale-record class #1387 set out to prevent). Write-ahead closes the
// window: the intent is durable BEFORE the wire add, so a crash anywhere
// after the add finds the ownership already recorded and a later reconcile
// re-adds (idempotent) or release deletes it. The pre-add intent carries
// PTRPending=true (the published tuple is not yet confirmed settled); a
// fully-successful add clears it via a confirm save. If the durable
// pre-write FAILS the add does NOT run and the record is reported "not
// safely owned" (the error is surfaced) — we never publish a RR we could not
// first record ownership for.
//
// REFUSED-ADD REMOVES THE INTENT (#2648 MAJOR-1 + #2662): a replace-owned /
// skip-existing add that REFUSES a name owned by another party returns
// errDDNSConflictRefused. The wire add did NOT happen, so the pre-written
// intent is phantom ownership and is REMOVED (delete + save) — leaving it
// would let a later release delete a record xpf did not create (for a
// no-identity lease, whose delete has no DHCID-match guard, that delete
// actually fires). Deleting an intent for a RR that was never created is
// safe: the #2648 DHCID-match / exact-RR delete prerequisite fails on a
// non-existent RR, so the wire delete is a harmless no-op.
func (m *Manager) upsertLocked(ctx context.Context, updater DNSUpdater, rec LeaseDNSRecord, ow ownedRecord) error {
	// #14604: a name already owned under the opposite address family
	// (durable store, or this pass's write-ahead intent for the sibling
	// put by an earlier Pass-2 upsert) is xpf-owned, not foreign — signal
	// the backend so its skip-existing/strict-fail guard stays per-type for
	// that legitimate sibling publish instead of refusing the second family.
	// The signal is recomputed from the store on every call and stamped
	// only on UpsertLease paths; DeleteLease callers never receive it.
	if m.crossTypeSiblingOwned(ow) {
		rec.SiblingFamilyOwned = true
	}
	if isNopUpdater(updater) {
		// No live backend: nothing is published, so record NO ownership and
		// do not write-ahead an intent (an intent for a record nopUpdater
		// never wrote would be phantom). Count the skip and return success so
		// the reconcile does not wedge.
		if err := updater.UpsertLease(ctx, rec); err != nil {
			m.upsertFail.Add(1)
			return err
		}
		m.skippedNoBackend.Add(1)
		return nil
	}

	// WRITE-AHEAD: persist the ownership intent durably BEFORE the wire add.
	// PTRPending=true until a fully-successful add confirms it; a crash after
	// the add (but before any confirm) therefore finds the record owned and
	// the next reconcile converges it.
	intent := ow
	intent.PTRPending = true
	m.state.put(intent)
	if err := m.state.save(); err != nil {
		// Could not durably record ownership: do NOT publish. Roll the
		// in-memory intent back so the store matches what is durable, surface
		// the failure as "record not safely owned", and let the next
		// reconcile retry.
		m.state.delete(intent.scopeOf(), intent.Identity, intent.Address)
		m.upsertFail.Add(1)
		slog.Warn("ddns: cannot durably record ownership before add; skipping publish",
			"fqdn", rec.FQDN, "err", err)
		return err
	}

	if err := m.providerIO(func() error { return updater.UpsertLease(ctx, rec) }); err != nil {
		// ORDER MATTERS (#2676): check errDDNSPTRPending BEFORE
		// errDDNSConflictRefused. errDDNSPTRPending is returned ONLY after the
		// forward A/AAAA add SUCCEEDED, so its presence proves the forward is
		// LIVE and ownership MUST be recorded — it must never fall into the
		// no-ownership (intent-removal) branch below. The backend (#2676) no
		// longer wraps a PTR-side conflict-refusal into a chain carrying BOTH
		// sentinels, but this defensive ordering guarantees a
		// forward-published error can never orphan the forward even if some
		// future path produces a chain with both sentinels.
		if errors.Is(err, errDDNSPTRPending) {
			// PARTIAL SUCCESS (#2661): the forward A/AAAA is LIVE in DNS but the
			// reverse PTR add failed with a non-skippable (transient) error. The
			// pre-written intent already records ownership with PTRPending=true,
			// which is exactly the state we want to keep — the next reconcile
			// re-runs UpsertLease (an idempotent forward re-add) and re-attempts
			// the still-missing PTR. The forward is durably owned (never
			// orphaned). The PTR failure is counted and logged so it is
			// observable; the reconcile pass is NOT failed (the forward succeeded
			// and the PTR retry converges on its own), the same non-fatal
			// treatment as a NOTAUTH skip. No re-save needed: the durable intent
			// already carries PTRPending=true.
			m.ptrDeferred.Add(1)
			slog.Warn("ddns: forward published but reverse PTR add failed; "+
				"ownership recorded with PTR pending for retry next cycle",
				"fqdn", rec.FQDN, "ptr", rec.PTRName, "err", err)
			m.upsertOK.Add(1)
			return nil
		}
		if errors.Is(err, errDDNSConflictRefused) {
			// Refused (name owned by another party): the FORWARD wire add did not
			// happen (errDDNSConflictRefused is propagated unwrapped by the
			// backend only from the forward add, and a PTR-side conflict-refusal
			// is now classified as a permanent skip that returns nil — #2676), so
			// REMOVE the pre-written intent (no phantom ownership) and persist the
			// removal. Count it as a conflict skip already done by the backend; do
			// not fail the reconcile pass.
			m.state.delete(intent.scopeOf(), intent.Identity, intent.Address)
			if serr := m.state.save(); serr != nil {
				// The intent is removed in memory but the removal is not durable.
				// Surface it so the pass is marked failed and retried; a stale
				// durable intent is safe (its delete is a no-op on a non-existent
				// RR) and self-heals on the next successful save.
				slog.Warn("ddns: cannot persist removal of refused-add intent",
					"fqdn", rec.FQDN, "err", serr)
				return serr
			}
			return nil
		}
		// Hard add failure: the wire add did not succeed. Remove the
		// pre-written intent so the store does not claim a record that is not
		// in DNS, and persist the removal so a later release cannot fire a
		// (no-op) delete against a non-existent RR forever. A save failure here
		// is non-fatal beyond the add error already returned: a stale durable
		// intent's delete is a harmless no-op and self-heals on the next save.
		m.state.delete(intent.scopeOf(), intent.Identity, intent.Address)
		if serr := m.state.save(); serr != nil {
			slog.Warn("ddns: cannot persist removal of failed-add intent",
				"fqdn", rec.FQDN, "err", serr)
		}
		m.upsertFail.Add(1)
		return err
	}

	// Fully-successful add: confirm by clearing PTRPending and persisting the
	// settled record. A confirm-save failure is non-fatal — the durable
	// intent (PTRPending=true) already owns the live record, so it is
	// cleanable; the only cost is the next reconcile re-running the idempotent
	// forward add to clear the pending flag.
	m.upsertOK.Add(1)
	ow.PTRPending = false
	m.state.put(ow)
	if err := m.state.save(); err != nil {
		slog.Warn("ddns: cannot persist settled ownership after add (record still owned via write-ahead intent)",
			"fqdn", rec.FQDN, "err", err)
	}
	return nil
}

// deleteOwnedLocked re-derives the EXACT record from owned state and
// deletes it, removing the ownership entry on success. This is the sole
// delete authority — it never constructs a delete from anything but the
// store, so a record xpf did not create can never be deleted.
//
// keepDHCIDForMove (#14189) is set ONLY by the Pass-1 move path when the
// desired set re-publishes the same FQDN+ClientID this pass: the shared
// DHCID must survive the old record's delete so the replacement's RFC 4703
// ownership proof (Attempt B) still holds. Every genuine-withdraw caller
// passes false.
func (m *Manager) deleteOwnedLocked(ctx context.Context, updater DNSUpdater, owned ownedRecord, keepDHCIDForMove bool) error {
	rec, err := buildLeaseRecord(owned.FQDN, owned.Address, owned.TTL)
	if err != nil {
		// The stored address no longer parses (a corrupt store now fails closed
		// at load, but keep this defensive). We cannot reconstruct the exact
		// wire RR, so a safe wire delete is impossible — do NOT issue a delete
		// with a guessed name. Drop the entry to avoid wedging, but PERSIST the
		// drop (#4909): without the save the malformed record reloaded on the
		// next restart and this same silent drop oscillated forever.
		slog.Warn("ddns: owned record has unparseable address; dropping entry (persisted)",
			"address", owned.Address, "err", err)
		m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
		if serr := m.state.save(); serr != nil {
			slog.Warn("ddns: cannot persist drop of unparseable-address record",
				"fqdn", owned.FQDN, "err", serr)
		}
		return nil
	}
	// #5709 (codex-review-182 M36): if another owned record — a DIFFERENT DDNS
	// scope — still CO-OWNS this exact wire RR (same forward name + type +
	// rdata, hence the same reverse PTR), do NOT issue the wire delete: it would
	// remove the RR the peer scope still legitimately owns and keeps fresh,
	// silently clobbering a live record. Release only THIS scope's ownership
	// claim and leave the wire RR in place; the surviving scope issues the real
	// delete when it in turn becomes the last claimant. This is the wire-RR
	// claim accounting the per-scope ownership store was missing. It runs BEFORE
	// the wire op and independent of the backend (a nop updater must not orphan
	// a co-owned RR either) — dropping a claim on a still-co-owned RR can never
	// leak a stale record, so it needs no write-ahead.
	if m.wireRRSharedWithOther(owned) {
		slog.Debug("ddns: skipping wire delete — RR still co-owned by another scope; "+
			"releasing this scope's claim only",
			"fqdn", owned.FQDN, "type", owned.ForwardType, "address", owned.Address,
			"scope", owned.scopeOf().scopePrefix())
		m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
		m.deleteCoowned.Add(1)
		return nil
	}
	// Force the stored forward type / PTR name (re-derived above should
	// match, but the store is authoritative for what was written).
	rec.ForwardType = owned.ForwardType
	rec.PTRName = owned.PTRName
	// Replay the EXACT client identity the record was published with so the
	// backend recomputes the same RFC 4701 DHCID — the delete prerequisite
	// then proves xpf owns the record before removing it.
	rec.ClientID = owned.ClientID
	// #2700: if ANOTHER owned record still shares this record's FQDN + ClientID
	// (a dual-stack client whose A and AAAA carry the SAME shared DHCID — the
	// DHCID digest folds in client-identity||FQDN, NOT the address, so both
	// families produce one DHCID), keep the shared DHCID on the wire so the
	// surviving family's record stays DHCID-protected (RFC 4703) and its later
	// delete still satisfies the DHCID-match prerequisite. Only when THIS is the
	// last owned record under the name is the DHCID removed with it.
	// #14189: keepDHCIDForMove extends the same keep to a same-pass MOVE whose
	// replacement (in the desired set, not yet in the store) shares the DHCID.
	rec.KeepForwardDHCID = m.dhcidSharedWithOther(owned) || keepDHCIDForMove
	if err := m.providerIO(func() error { return updater.DeleteLease(ctx, rec) }); err != nil {
		m.deleteFail.Add(1)
		return err
	}
	if isNopUpdater(updater) {
		// No live backend: the delete was a logged no-op — the wire RR (if any)
		// was NOT removed. KEEP the ownership entry so the record stays
		// cleanable once a real backend is reconfigured; do NOT drop it (#2699).
		//
		// The pre-#2699 path dropped ownership here, justified by the inc-1
		// invariant "nopUpdater never published, so there is nothing to orphan."
		// That invariant no longer holds: a real RFC 2136 backend now publishes
		// records (inc-2), and ownership can ONLY be recorded by a live backend
		// (upsertLocked's nop branch records NO ownership and write-aheads no
		// intent — manager.go upsertLocked). So any owned entry reaching this
		// path was published by a real backend; if the backend is later removed
		// (DDNS disabled / update-server cleared) OR the process restarts before
		// it resolves a live backend, dropping ownership would ORPHAN the live
		// A/AAAA/PTR/DHCID in the authoritative zone — xpf would forget the only
		// record that lets it ever clean them (the stale-record / split-ownership
		// class #1387 exists to prevent). Instead, treat the no-op delete as a
		// FAILURE (count deleteFail, surface the error) and KEEP ownership: a
		// later reconcile that resolves a live backend (the same family's backend
		// re-appears, or the next-cycle withdraw guard supplies the prior live
		// updater) withdraws it for real. This mirrors the Surface A precedent
		// (SurfaceAManager.withdrawOwnedLocked, surface_a.go) which already treats
		// a no-op backend as a delete failure rather than dropping ownership.
		m.skippedNoBackend.Add(1)
		m.deleteFail.Add(1)
		slog.Warn("ddns: cannot withdraw record — no live backend wired; "+
			"keeping ownership for retry (record stays cleanable)",
			"fqdn", owned.FQDN, "address", owned.Address, "type", owned.ForwardType)
		return errDDNSNoBackendToWithdraw
	}
	m.deleteOK.Add(1)
	m.state.delete(owned.scopeOf(), owned.Identity, owned.Address)
	return nil
}

// dhcpBackendFingerprint returns a STABLE, NON-SECRET fingerprint of the
// DHCP-lease (Surface B) rfc2136 endpoint IDENTITY for one family (#5814): the
// backend type + update-server + TSIG key NAME/algorithm + the transport bind
// (source address / destination interface / routing-instance). It is the Surface
// B analogue of surface_a.go's backendFingerprint and, like it, deliberately
// EXCLUDES every credential — TSIGSecret is a config.Secret and is NEVER hashed
// in or written out, so persisting this on the durable ownedRecord does NOT
// reopen the #2053 plaintext-secret-on-disk class.
//
// It returns "" (UNKNOWN — compared as "cannot prove a change", never a false
// transition) whenever the family has NO live endpoint: a nil/disabled config, a
// non-rfc2136 backend (kea-d2 is reserved-but-nop), or an empty update-server.
// That is EXACTLY the set of conditions under which NewProductionManager's
// factory resolves the nopUpdater, so a non-empty fingerprint corresponds
// one-to-one with a live resolved backend — a record's stored fingerprint and the
// per-family anchor updater that published it always agree.
func dhcpBackendFingerprint(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) string {
	if c == nil || !pol.enabled || pol.backend != "rfc2136" || c.UpdateServer == "" {
		return ""
	}
	// Length-prefixed, order-fixed, credential-free tuple so no pair of adjacent
	// fields can alias across the boundary (a value cannot inject the separator).
	var sb strings.Builder
	writeField := func(s string) { fmt.Fprintf(&sb, "%d:%s|", len(s), s) }
	writeField("rfc2136")              // backend type (only live Surface B backend)
	writeField(c.UpdateServer)         // authoritative server host[:port]
	writeField(c.TSIGKeyName)          // TSIG key NAME (identity, not the secret)
	writeField(c.TSIGAlgorithm)        // TSIG algorithm
	writeField(c.SourceAddress)        // transport: bound source IP
	writeField(c.DestinationInterface) // transport: SO_BINDTODEVICE target
	writeField(c.RoutingInstance)      // transport: VRF bind
	h := fnv.New64a()
	_, _ = h.Write([]byte(sb.String()))
	return fmt.Sprintf("fpb1-%016x", h.Sum64())
}

// recordsEqual reports whether two owned records describe the same
// published DNS state (name + type + address + ttl). Identity/subnet
// metadata changes alone do not require a DNS re-write.
func recordsEqual(a, b ownedRecord) bool {
	return a.FQDN == b.FQDN &&
		a.ForwardType == b.ForwardType &&
		a.Address == b.Address &&
		a.PTRName == b.PTRName &&
		a.TTL == b.TTL
}

// OwnedRecordView is a read-only projection of one owned record for
// `show ... dynamic-dns detail`. It deliberately omits the owner watermark
// (an internal hash) and exposes only the published tuple.
type OwnedRecordView struct {
	Family      int
	FQDN        string
	ForwardType string
	Address     string
	PTRName     string
	TTL         int
	// PTRPending is true when the forward A/AAAA is published but the reverse
	// PTR is still owed (a non-skippable PTR add failure, #2661). It surfaces
	// the half-published condition per record so an operator can distinguish a
	// settled record from one whose PTR is missing and watch it recover (#2708).
	PTRPending bool
}

// OwnedRecordViews returns a stable-ordered snapshot of the records this
// node currently owns (published into DNS). Used by the show command.
func (m *Manager) OwnedRecordViews() []OwnedRecordView {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.state.all()
	out := make([]OwnedRecordView, 0, len(all))
	for _, r := range all {
		out = append(out, OwnedRecordView{
			Family:      r.Family,
			FQDN:        r.FQDN,
			ForwardType: r.ForwardType,
			Address:     r.Address,
			PTRName:     r.PTRName,
			TTL:         r.TTL,
			PTRPending:  r.PTRPending,
		})
	}
	return out
}

// Stats returns the current observable counters for `show ... dynamic-dns`.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	n := len(m.state.records)
	pendingNow := 0
	for _, r := range m.state.records {
		if r.PTRPending {
			pendingNow++
		}
	}
	degraded := m.degraded
	degradedReason := m.degradedReason
	m.mu.Unlock()

	st := Stats{
		Degraded:              degraded,
		DegradedReason:        degradedReason,
		UpsertOK:              m.upsertOK.Load(),
		UpsertFail:            m.upsertFail.Load(),
		DeleteOK:              m.deleteOK.Load(),
		DeleteFail:            m.deleteFail.Load(),
		DeleteCoowned:         m.deleteCoowned.Load(),
		SkippedNoName:         m.skippedNoName.Load(),
		SkippedNonAddress:     m.skippedNonAddress.Load(),
		SkippedNoBackend:      m.skippedNoBackend.Load(),
		SkippedPTRNotAuth:     m.skippedPTRNotAuth.Load(),
		SkippedConflict:       m.skippedConflict.Load(),
		PTRDeferred:           m.ptrDeferred.Load(),
		PTRPendingNow:         pendingNow,
		OrphanedBackendChange: m.orphanedBackendChange.Load(),
		ReconcileOK:           m.reconcileOK.Load(),
		ReconcileFail:         m.reconcileFail.Load(),
		OwnedRecords:          n,
		LastReconcileN:        int(m.lastReconcileN.Load()),
	}
	if ns := m.lastReconcile.Load(); ns > 0 {
		st.LastReconcile = time.Unix(0, ns)
	}
	if p := m.lastPolicy.Load(); p != nil {
		st.Enabled = p.enabled
		st.Backend = p.backend
	}
	return st
}

// DDNSLeasePaths returns the manager's lease CSV paths so a cross-package
// test can write synthetic memfiles the reconcile loop will read. Moved
// verbatim from pkg/dhcpserver/test_seams.go in #2691 P1a (the method name is
// kept so pkg/daemon's tests need no change).
func (m *Manager) DDNSLeasePaths() (leasePath4, leasePath6 string) {
	return m.leasePath4, m.leasePath6
}

// OwnedForTesting reports whether the ownership store holds a record for the
// given identity+address IN ANY SCOPE. Test-only accessor for cross-package
// tests (the pkg/dhcpserver real-parser→engine integration tests) that
// previously reached into the unexported state store directly (#2691 P1a). It
// matches scope-agnostically (#2691 P1b) so the existing seam callers — which
// publish on the zero/global lease scope — keep working unchanged. Not for
// production use.
func (m *Manager) OwnedForTesting(identity, address string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.state.records {
		if r.Identity == identity && r.Address == address {
			return true
		}
	}
	return false
}

// OwnedKeysForTesting returns the identity|address keys of every owned record,
// for diagnostic assertions in cross-package tests. Test-only (#2691 P1a).
func (m *Manager) OwnedKeysForTesting() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.state.records))
	for k := range m.state.records {
		out = append(out, k)
	}
	return out
}
