package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// linkOps is the narrow netlink surface the interface domains
// (tunnel, xfrm, bond, reth) use for link/address lifecycle. Satisfied
// by *netlink.Handle in production; tests substitute a fake.
type linkOps interface {
	LinkByName(name string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetUp(netlink.Link) error
	LinkSetDown(netlink.Link) error
	LinkSetMaster(netlink.Link, netlink.Link) error
	LinkSetNoMaster(netlink.Link) error
	LinkSetMTU(netlink.Link, int) error
	LinkList() ([]netlink.Link, error)
	AddrAdd(netlink.Link, *netlink.Addr) error
	AddrDel(netlink.Link, *netlink.Addr) error
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
}

// vrfBinder is the cross-domain dependency tunnel apply needs to bind a
// tunnel interface to a routing-instance VRF. Satisfied by *vrfManager.
// BindInterfaceToVRF takes no lock, so calling it while holding the
// tunnel lock introduces no lock-ordering cycle (see vrf.go).
type vrfBinder interface {
	BindInterfaceToVRF(ifaceName, instanceName string) error
}

// TunnelStatus holds the status of a tunnel interface.
type TunnelStatus struct {
	Name        string
	Source      string
	Destination string
	State       string // "up" or "down"
	Addresses   []string
	// KeepaliveUp is tri-state (#1918): non-nil true/false when liveness is
	// KNOWN (probe succeeded/failed), and nil when EITHER no keepalive is
	// configured OR liveness is currently UNKNOWN (ProbeUnsupported —
	// hold-on-unknown). The two nil cases are distinguished by
	// KeepaliveInfo: "" → not configured; "unknown (...)" → configured but
	// liveness unknown.
	KeepaliveUp   *bool
	KeepaliveInfo string // human-readable keepalive status
}

// tunnelManager owns GRE/IPIP tunnel lifecycle and per-tunnel keepalive
// goroutines. The mu field replaces the tunnel slice of the former
// shared Manager.ifaceMu; keepalives belong to this domain (their only
// user is tunnel apply/clear), so mu protects both tunnels and the
// keepalives map as one cohesive critical section.
type tunnelLivenessChangeCallback func(tunnelName string, up bool)

type tunnelManager struct {
	ops       linkOps
	vrfBinder vrfBinder

	// prober performs the keepalive ICMP echo. nil → the production
	// icmpProber (lazily resolved by keepaliveProber). Tests inject a
	// deterministic fake (#1918).
	prober tunnelProber

	mu         sync.Mutex
	tunnels    []string                    // tunnels successfully applied this round (GetStatus source)
	keepalives map[string]*keepaliveRunner // tunnel name -> runner
	// livenessChange is atomically replaceable because the keepalive runner
	// reads it without taking the tunnel manager lock.
	livenessChange atomic.Pointer[tunnelLivenessChangeCallback]

	// linkGen is the per-tunnel monotonic generation counter (#1918 §6
	// Axis D, defense-in-depth recreate guard). The MAP structure is
	// mutated only under mu (by Apply, via bumpLinkGenLocked); the counter
	// values are *atomic.Uint64 so a keepalive runner can Load() them
	// lock-free at tick time without ever taking mu (AGY r5 deadlock
	// note). Apply bumps the counter on a tunnel link create/recreate so a
	// stale runner captured at the old generation drops its LinkSet*.
	linkGen map[string]*atomic.Uint64

	// Reconcile-in-place state (#1884). All lazily initialized by Apply.
	//
	// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
	// DESIRED set (plus names whose removal LinkDel failed, retained for
	// retry). The removal diff and the adoption decision both key off
	// this — NOT off the success-tracked t.tunnels, whose
	// failure-continue paths can leave a live kernel link untracked.
	ownedNames map[string]bool
	// appliedAddrs: per tunnel, the address set this manager itself
	// ensured (successful adds + present-and-wanted + link-local whose
	// stale-delete failed). Gates stale LINK-LOCAL deletion: a
	// configured fe80 we applied is removable; the kernel's autoconf
	// fe80 is never touched.
	appliedAddrs map[string]map[string]bool
	// appliedRI: per tunnel, the routing-instance whose VRF this
	// manager successfully bound — or directly OBSERVED as the link's
	// master for a step-0a `routing-instances <ri> interface` list
	// bind. Invariant (#1884 r6-r8): a claim is only ever written from
	// a successful bind or a master observation, never an intent.
	// Unbind on config-wants-none is identity-gated against
	// vrf-<claim>.
	appliedRI map[string]string
	// wgConfigured: WireGuard tunnel names configured at the LAST Apply
	// (plus names whose address prune left residual tracked addresses,
	// retained for retry). NEVER feeds the LinkDel removal loop — WG
	// links persist (#1432 S2a). Drives the WG address-prune-on-removal
	// diff (#1919): a WG tunnel removed from config keeps its persistent
	// wgN link but has the kernel addresses this manager applied pruned
	// away, so they no longer route. The link-itself diff still excludes
	// WG (the link is kept); this set exists solely so removal can find
	// the now-absent WG name and reconcile its addresses to empty.
	wgConfigured map[string]bool
}

// ensureReconcileStateLocked lazily initializes the reconcile maps so
// directly-constructed managers (tests, façade) need no constructor
// changes. Caller MUST hold mu.
func (t *tunnelManager) ensureReconcileStateLocked() {
	if t.ownedNames == nil {
		t.ownedNames = map[string]bool{}
	}
	if t.appliedAddrs == nil {
		t.appliedAddrs = map[string]map[string]bool{}
	}
	if t.appliedRI == nil {
		t.appliedRI = map[string]string{}
	}
	if t.wgConfigured == nil {
		t.wgConfigured = map[string]bool{}
	}
	if t.keepalives == nil {
		t.keepalives = map[string]*keepaliveRunner{}
	}
	if t.linkGen == nil {
		t.linkGen = map[string]*atomic.Uint64{}
	}
}

// linkGenForLocked returns the (lazily created) generation counter for a
// tunnel name. Caller MUST hold mu.
func (t *tunnelManager) linkGenForLocked(name string) *atomic.Uint64 {
	g, ok := t.linkGen[name]
	if !ok {
		g = &atomic.Uint64{}
		t.linkGen[name] = g
	}
	return g
}

// bumpLinkGenLocked advances a tunnel's generation token. Called by
// Apply whenever it CREATES or RECREATES the kernel link for a tunnel,
// so any keepalive runner still holding the previous generation drops
// its netlink op (#1918 §6 Axis D defense-in-depth). Caller MUST hold
// mu.
func (t *tunnelManager) bumpLinkGenLocked(name string) {
	t.linkGenForLocked(name).Add(1)
}

func (t *tunnelManager) setLivenessChangeCallback(callback func(tunnelName string, up bool)) {
	if callback == nil {
		t.livenessChange.Store(nil)
		return
	}
	typed := tunnelLivenessChangeCallback(callback)
	t.livenessChange.Store(&typed)
}

// Apply reconciles the kernel tunnel devices against the desired config
// WITHOUT the historical clear-all + delete-and-recreate (#1884): an
// untouched tunnel keeps its netdev (stable ifindex — no FRR route churn,
// no userspace-dp TUN-reader death per commit, see #1881), tunnels removed
// from config are deleted via a set-diff against the previous desired set,
// and a bounded LinkList sweep reaps untracked xpf tunnel orphans left by
// a daemon restart (#11443). A device is recreated only when the existing
// kernel link is genuinely incompatible. Keepalive probes (legacy
// non-anchor branch only) are reconciled by identity instead of being
// restarted every apply.
func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
	// mu is held across the WHOLE netlink+exec reconcile deliberately (not
	// just a small state-read section): the reconcile INTERLEAVES shared-map
	// reads/writes (ownedNames, appliedAddrs, appliedRI, wgConfigured,
	// tunnels) with the netlink LinkDel/LinkAdd it drives — per-tunnel
	// removal/adoption decisions are made FROM the maps and the failure
	// retries are written BACK into them, and every applyKernelTunnelLocked/
	// applyAnchorLocked/applyWireguardTunLocked helper requires the lock.
	// Two concurrent Apply/Clear calls would race both the maps AND the
	// kernel link state (double-delete, delete-during-recreate), so the wide
	// scope serializes them. There is no isolable critical section to narrow
	// to. GetStatus (below) is the counter-case that CAN narrow — it only
	// snapshots names under the lock, then probes netlink read-only unlocked.
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureReconcileStateLocked()

	// errs accumulates GENUINE reconcile failures (a removed tunnel's
	// LinkDel, and each per-tunnel apply's create/find/up/delete) so the
	// commit fails closed (#5355, sibling of the #5310 xfrmManager fix).
	// Before this Apply logged every such failure and returned nil
	// UNCONDITIONALLY — a GRE/tunnel LinkAdd/LinkSetUp/LinkDel failure
	// reported a SUCCESSFUL commit while the interface was absent (fail-open
	// false convergence). Tolerated idempotent conditions never append: a
	// still-present compatible tunnel is adopted in place (reuse, not a
	// LinkAdd), a delete of an already-gone tunnel is a no-op, and a
	// TRANSIENT lookup that only defers the reconcile retains+retries
	// without erroring. The #5354 tail-join in applyInterfaceReconcile
	// surfaces the returned error into the commit result.
	var errs []error

	desired := make(map[string]bool, len(tunnels))
	wgDesired := map[string]bool{}
	for _, tc := range tunnels {
		// WireGuard TUNs stay untracked/persistent (#1432 S2a, AGY
		// Hazard B) and are excluded from the removal diff.
		if tc.Mode == "wireguard" {
			wgDesired[tc.Name] = true
		} else {
			desired[tc.Name] = true
		}
	}
	// #11443: tracked diffs cannot see links left behind when xpfd was
	// down during a config removal. Re-scan only the xpf tunnel namespaces
	// and recognized kernel link types; all other or wrongly-typed links
	// remain untouched. Existing ownership state still drives the tracked
	// retry paths below, so this pass handles only previously-untracked
	// candidates.
	if links, err := t.ops.LinkList(); err != nil {
		slog.Warn("tunnel orphan reap: LinkList failed; retrying on next apply", "err", err)
	} else {
		for _, link := range links {
			if link == nil || link.Attrs() == nil {
				continue
			}
			name := link.Attrs().Name
			if desired[name] || wgDesired[name] ||
				t.ownedNames[name] || t.wgConfigured[name] {
				continue
			}
			isWireGuardName := strings.HasPrefix(name, "wg")
			isTunnelName := strings.HasPrefix(name, "gr-") || strings.HasPrefix(name, "ip-")
			if !isWireGuardName && !isTunnelName {
				continue
			}
			// A TUN cannot reveal whether its absent config used
			// mode=wireguard or an AnchorOnly GRE/IPIP endpoint. Keep every
			// persistent TUN (including gr-*/ip-* names) and prune addresses
			// instead; this avoids killing a live Rust WG attachment after a
			// restart while still removing connected routes from the FIB.
			if tun, ok := link.(*netlink.Tuntap); ok {
				if tun.Mode == netlink.TUNTAP_MODE_TUN {
					t.pruneOrphanTUNLocked(link, name)
				}
				continue
			}
			switch link.(type) {
			case *netlink.Gretun, *netlink.Iptun, *netlink.Ip6tnl:
				if err := t.ops.LinkDel(link); err != nil && !isLinkNotFound(err) {
					slog.Warn("tunnel orphan reap: LinkDel failed",
						"name", name, "err", err)
					errs = append(errs, fmt.Errorf("delete orphan tunnel %s: %w", name, err))
					continue
				}
				delete(t.appliedAddrs, name)
				delete(t.appliedRI, name)
				slog.Info("tunnel orphan reaped", "name", name)
			}
		}
	}

	// oldOwned is the ENTRY-TIME ownership snapshot — the adoption
	// authority for the per-tunnel loop below (#1884 r2 Codex F1: the
	// rewritten set would mark every desired tunnel "owned" and make
	// adoption unreachable). next starts as the desired set; removal
	// failures retain their names so the next Apply retries instead of
	// orphaning a live link (r2 Codex F5).
	oldOwned := t.ownedNames
	next := make(map[string]bool, len(desired))
	for name := range desired {
		next[name] = true
	}
	for name := range oldOwned {
		if desired[name] {
			continue
		}
		if wgDesired[name] {
			// Same-name non-WG→WG transition: this name is being (re)claimed
			// as a persistent WireGuard tunnel by the apply loop below. WG
			// links are intentionally untracked in ownedNames and must NEVER
			// be torn by the removal diff (#1432 S2a). Hand off WITHOUT
			// deleting the link AND WITHOUT retaining ownedNames — retaining
			// would leave the active WG link in ownedNames and let a later
			// Apply LinkDel it (Codex r3 inverse-handoff hole).
			//
			// PRESERVE appliedAddrs (Codex r4): applyWireguardTunLocked's
			// reconcile needs the applied set to gate LINK-LOCAL deletion —
			// a configured fe80 this manager applied as the anchor must be
			// deletable by the WG reconcile (it is absent from the new WG
			// desired set), not re-classified as foreign and leaked. This
			// mirrors the forward WG→non-WG handoff, which also keeps
			// appliedAddrs. PRESERVE appliedRI too (#5120): WG now reconciles
			// its VRF through the shared claim machinery, so a prior anchor
			// VRF claim must carry into applyWireguardTunLocked's reconcile —
			// a reused anchor TUN keeps its kernel master across the handoff,
			// and dropping the claim would leave an empty appliedRI that
			// skips the identity-gated unbind, stranding an anchor→WG-no-RI
			// device enslaved to the old VRF. (A GRE→WG handoff deletes and
			// recreates the link, so the fresh TUN has master==0 and the
			// carried claim self-clears in the reconcile.)
			t.stopKeepaliveLocked(name)
			continue
		}
		t.stopKeepaliveLocked(name)
		if link, err := t.ops.LinkByName(name); err == nil {
			if delErr := t.ops.LinkDel(link); delErr != nil {
				slog.Warn("failed to delete removed tunnel",
					"name", name, "err", delErr)
				next[name] = true // retain ownership; retry next apply
				// #5355: a genuine LinkDel failure leaves the removed
				// tunnel's device (and its addresses) live in the kernel —
				// fail the commit closed rather than report a clean removal.
				errs = append(errs, fmt.Errorf("delete removed tunnel %s: %w", name, delErr))
				continue
			}
			slog.Info("tunnel removed", "name", name)
		} else if !isLinkNotFound(err) {
			// Transient LinkByName error (EBUSY/netlink/timeout): we have
			// NOT proven the device gone and have NOT deleted it. Retain
			// ownership so the next Apply retries the LinkDel — dropping it
			// here would orphan a live link (and any stale addresses on it)
			// with no state left to clean it up. A genuine not-found falls
			// through to drop tracking. (#1919 r2 Codex: closes the
			// WG→non-WG-handoff + transient-removal leak chain; also hardens
			// the pre-existing GRE/anchor removal path against transient
			// lookup errors, mirroring the WG prune loop's isLinkNotFound
			// discipline below.)
			slog.Warn("failed to look up removed tunnel for deletion",
				"name", name, "err", err)
			next[name] = true
			continue
		}
		delete(t.appliedAddrs, name)
		delete(t.appliedRI, name)
	}
	t.ownedNames = next
	t.tunnels = nil // success-tracked (GetStatus); rebuilt below

	// WireGuard address-prune-on-removal diff (#1919). WG links persist
	// (#1432 S2a) and are deliberately excluded from `desired`/ownedNames
	// above, so the GRE removal loop never visits them and the per-tunnel
	// apply loop below only reconciles addresses for STILL-configured WG.
	// A WG tunnel removed from config therefore leaks the kernel addresses
	// this manager applied to its persistent wgN device. wgConfigured
	// records the WG names tracked at the last Apply; here we prune the
	// addresses of any that disappeared while KEEPING the link.
	// (wgDesired is computed once at the top of Apply.)
	oldWG := t.wgConfigured
	nextWG := make(map[string]bool, len(wgDesired))
	for name := range wgDesired {
		nextWG[name] = true
	}
	for name := range oldWG {
		if wgDesired[name] {
			continue // still configured as WG; reconciled by the apply loop below
		}
		if desired[name] {
			// Same-name WG→non-WG mode transition (e.g. wg0 reconfigured as
			// a GRE/anchor tunnel of the same name). The name is now owned by
			// the non-WG apply path, which reconciles its addresses itself
			// (reconcileLinkAddrsLocked deletes the stale WG addresses against
			// the new desired set). Running the WG prune here would race that
			// path and could delete the newly-configured non-WG address, or —
			// on a prune AddrDel retry — persist in nextWG and prune the
			// active tunnel on a later Apply (Codex r1 MAJOR). Hand ownership
			// to the non-WG path: drop from WG tracking, keep appliedAddrs so
			// the non-WG reconcile can still gate its link-locals correctly.
			continue
		}
		link, err := t.ops.LinkByName(name)
		if err != nil {
			if isLinkNotFound(err) {
				// Device genuinely gone (manual `ip link del`, or never
				// existed). Nothing to prune; drop tracking. The VRF binding
				// died with the device, so clear any claim too (#5120) —
				// there is nothing left to unbind.
				delete(t.appliedAddrs, name)
				delete(t.appliedRI, name)
			} else {
				// Transient lookup error (EBUSY/netlink/timeout): we cannot
				// conclude the device is clean. Retain the name AND its
				// tracked address set so the next Apply retries the prune —
				// dropping here would forget a still-leaked address forever
				// (#1919 r1 Codex/AGY MAJOR). The appliedRI claim is left
				// intact so the next Apply also retries the VRF unbind (#5120).
				slog.Warn("failed to look up wireguard tun for address prune",
					"name", name, "err", err)
				nextWG[name] = true
			}
			continue
		}
		failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
		// Identity-gated VRF unbind (#5120): the persistent wgN link is KEPT
		// (S2a), but a WG tunnel removed from config must not linger enslaved
		// to the VRF it last claimed. Mirror the RI-removal unbind in
		// reconcileVRFClaimLocked — retain the claim and retry on transient
		// failure.
		unbindRetry := t.unbindVRFClaimLocked(name, link)
		if retry || unbindRetry {
			// Could not prove the device clean (an AddrDel failed, AddrList
			// itself failed, or the VRF unbind hit a transient error). Carry
			// the residual address set forward (it gates link-local deletion
			// next pass) and retry next Apply. A retained appliedRI claim
			// (unbindRetry) is revisited on that retry.
			t.appliedAddrs[name] = failed
			nextWG[name] = true
			continue
		}
		// Proven clean: drop tracking so the next Apply is a no-op for this
		// name (idempotent — it is in neither wgDesired nor nextWG).
		delete(t.appliedAddrs, name)
	}
	t.wgConfigured = nextWG

	for _, tc := range tunnels {
		// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
		// delete-and-recreate on reload — that would flap wgN and destroy
		// its addresses + FRR routes every commit. applyWireguardTunLocked
		// reuses an existing wgN in place.
		if tc.Mode == "wireguard" {
			if err := t.applyWireguardTunLocked(tc); err != nil {
				slog.Warn("failed to apply wireguard tunnel",
					"name", tc.Name, "err", err)
				// #5355: surface the WG create/replace/bring-up failure so
				// the commit fails closed; the sentinel-driven ownedNames
				// re-retain below is orthogonal to the aggregation.
				errs = append(errs, fmt.Errorf("apply wireguard tunnel %s: %w", tc.Name, err))
				// Re-retain ownedNames ONLY when a stale NON-WG link remains
				// under this name (incompatible same-name link whose
				// replacement LinkDel failed — errWGIncompatibleLinkRetained).
				// The inverse-handoff guard above dropped the name from
				// ownedNames, and the WG prune path only touches addresses,
				// never the link, so without this the stale non-WG link would
				// be orphaned (Codex r5). A future Apply then retries the
				// non-WG cleanup (LinkDel on config-remove or WG re-replace).
				//
				// Do NOT re-retain on any OTHER error (transient lookup,
				// failed create): those either left no link or left a HEALTHY
				// persistent WG link, which must stay untracked — re-adding it
				// would let a later removal LinkDel the live wgN (#1432 S2a,
				// Codex r6 create-failure counterexample).
				if errors.Is(err, errWGIncompatibleLinkRetained) {
					t.ownedNames[tc.Name] = true
				}
			}
			continue
		}
		// Adoption = this manager did NOT own the name at the last
		// apply (daemon restart, wireguard→gre same-name flip, foreign
		// but compatible TUN). Decided from the entry-time snapshot for
		// BOTH the plain-reuse and the LinkAdd-EEXIST paths.
		adopting := !oldOwned[tc.Name]
		if tc.AnchorOnly {
			if err := t.applyAnchorLocked(tc, adopting); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := t.applyKernelTunnelLocked(tc); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// pruneOrphanTUNLocked keeps an untracked persistent TUN but removes its
// address-derived connected routes. On restart there is no safe way to
// distinguish configured link-local addresses from kernel autoconf ones,
// so pruneAppliedAddrsLocked retains that existing ownership gate.
func (t *tunnelManager) pruneOrphanTUNLocked(link netlink.Link, name string) {
	failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
	unbindRetry := t.unbindVRFClaimLocked(name, link)
	if retry || unbindRetry {
		t.appliedAddrs[name] = failed
		return
	}
	delete(t.appliedAddrs, name)
	delete(t.appliedRI, name)
}

// anchorReusable reports whether an existing link can serve as the
// userspace-dp TUN anchor in place (#1884 A.3): it must be a TUN (not
// TAP/dummy/gre), carry NO_PI (the Rust side opens IFF_TUN|IFF_NO_PI —
// userspace-dp/src/slowpath.rs; a PI-enabled foreign TUN would break
// attach where recreate heals it), and be persistent (a non-persistent
// TUN held alive only by a foreign fd would evaporate when that fd
// closes). Kernel readback reconstructs Mode/NO_PI/persist via
// IFLA_TUN_*; the obsolete ONE_QUEUE flag is not reported and not
// checked.
func anchorReusable(link netlink.Link) bool {
	tt, ok := link.(*netlink.Tuntap)
	if !ok || tt.Mode != netlink.TUNTAP_MODE_TUN {
		return false
	}
	if tt.Flags&netlink.TUNTAP_NO_PI == 0 {
		return false
	}
	return !tt.NonPersist
}

// applyAnchorLocked reconciles one AnchorOnly TUN device (the
// production userspace-dp path). Caller MUST hold mu.
//
// #4071: the #1918 keepalive engine now runs on the anchor path too. A
// configured `keepalive`/`keepalive-retry` on a GRE anchor tunnel starts
// the ICMP-echo prober whose down-action LinkSetDowns the anchor TUN on
// peer death — the Junos-faithful "gr-/st0 interface-down →
// route-withdrawal" semantic. The prober is dataplane-agnostic (raw ICMP
// over the underlay FIB), identical to the legacy branch's runner; only
// the START/STOP wiring differs. The keepalive is reconciled by identity
// exactly like applyKernelTunnelLocked: an unchanged runner is retained
// across applies (probe state survives commits), restarted on a config
// change, and stopped when keepalive is removed.
//
// #5355: returns a non-nil error on a GENUINE reconcile failure (the
// replace LinkDel, the create LinkAdd, or the finishTunnelLocked
// LinkSetUp) so Apply can aggregate it and fail the commit closed —
// mirroring xfrmManager.Apply (#5310). A plain reuse/adopt of an
// already-present compatible anchor is NOT a failure and returns nil.
func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) error {
	// Drain-before-recreate + linkGen bump (#1918 §6 Axis D F7, ported to
	// the anchor path in #4071). Decide up front whether this apply will
	// recreate the anchor TUN. If so, CANCEL + DRAIN any existing keepalive
	// runner BEFORE the LinkDel/LinkAdd and bump the generation, so no
	// stale runner tick can LinkSet* a recreated device that reused the
	// ifindex; linkGen is the lock-free defense-in-depth backstop. A
	// TRANSIENT lookup error is NOT a recreate: the LinkAdd-EEXIST fallback
	// below adopts a still-present TUN in place, so draining a live runner
	// then would needlessly reset probe state (mirrors the legacy branch's
	// transient-lookup discipline, TestApplyTransientLookupKeepsRunner).
	existing, lookupErr := t.ops.LinkByName(tc.Name)
	willRecreate := false
	switch {
	case lookupErr == nil:
		willRecreate = !anchorReusable(existing)
	case isLinkNotFound(lookupErr):
		willRecreate = true
	}
	if willRecreate {
		t.stopKeepaliveLocked(tc.Name)
		t.bumpLinkGenLocked(tc.Name)
	}

	var link netlink.Link
	created := false
	if lookupErr == nil {
		if anchorReusable(existing) {
			// Operate on the kernel-fetched link (real ifindex and
			// attributes), never a fresh ifindex-less struct (#1706).
			link = existing
			slog.Debug("tunnel anchor reused", "name", tc.Name)
		} else {
			slog.Info("replacing non-TUN tunnel anchor",
				"name", tc.Name, "type", existing.Type())
			if delErr := t.ops.LinkDel(existing); delErr != nil {
				slog.Warn("failed to replace tunnel anchor",
					"name", tc.Name, "err", delErr)
				return fmt.Errorf("replace tunnel anchor %s: %w", tc.Name, delErr)
			}
		}
	}
	if link == nil {
		anchor := &netlink.Tuntap{
			LinkAttrs:  netlink.LinkAttrs{Name: tc.Name},
			Mode:       netlink.TUNTAP_MODE_TUN,
			Flags:      netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
			Queues:     1,
			NonPersist: false,
		}
		if addErr := t.ops.LinkAdd(anchor); addErr != nil {
			// LinkAdd-EEXIST / transient-lookup race (#1706): exactly
			// ONE re-lookup; a compatible TUN is adopted via the
			// KERNEL-FETCHED link (its Fds is nil, so the
			// closeTuntapFiles below is skipped with it); anything else
			// fails this apply (no unbounded retry).
			existingAdopt, lkErr := t.ops.LinkByName(tc.Name)
			if lkErr != nil || !anchorReusable(existingAdopt) {
				slog.Warn("failed to create tunnel anchor",
					"name", tc.Name, "err", addErr)
				return fmt.Errorf("create tunnel anchor %s: %w", tc.Name, addErr)
			}
			slog.Info("tunnel anchor already exists as TUN, reusing",
				"name", tc.Name)
			link = existingAdopt
		} else {
			closeTuntapFiles(anchor.Fds)
			link = anchor
			created = true
			if tc.MTU > 0 {
				// TUNSETIFF may ignore LinkAttrs.MTU (#1432 Codex r4
				// precedent), and the compiler MTU stage restores only
				// ZONED interfaces — set explicitly so a configured MTU
				// on an unzoned tunnel is live too (#1884 r2/r4).
				if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
					slog.Warn("failed to set tunnel anchor mtu",
						"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
				}
			}
			slog.Info("tunnel anchor created", "name", tc.Name, "mode", "tun")
		}
	}
	// #4076: a genuine (re)create ALWAYS gets a fresh generation. The
	// up-front willRecreate block bumps for the CLASSIFIED recreate
	// (reusable-mismatch / not-found). But a TRANSIENT (non-not-found)
	// lookup error masks the recreate there — willRecreate stays false
	// because the switch has no `default` (unlike the legacy branch's
	// `default: return`) — while the device had actually VANISHED, so the
	// LinkAdd above SUCCEEDED and `created` is now true against a NEW
	// device. Bump the generation here so a keepalive runner still holding
	// the previous generation drops its netlink op (the lock-free gen
	// guard in keepaliveTick) before it can LinkSet* the fresh device in
	// the µs window before startKeepalive drains it. Guarded on
	// !willRecreate so the classified-recreate path (already bumped
	// up-front) is not double-bumped, and gated on `created` so a plain
	// reuse/adopt reconcile never needlessly bumps (no per-apply
	// re-resolve of a stable keepalive). fable-161 F-063 follow-up.
	if created && !willRecreate {
		t.bumpLinkGenLocked(tc.Name)
	}
	if !created {
		t.reconcileAnchorMTULocked(tc, link, adopting)
	}

	// Keepalive reconcile (#4071, mirroring applyKernelTunnelLocked's
	// #1884 A.7 identity reconcile). Retain an identity-unchanged runner
	// so probe state survives commits; the retained-and-DOWN case must
	// SKIP the LinkSetUp in finishTunnelLocked so the reconcile does not
	// fight a keepalive-down state — keepaliveLoop's down-transition is
	// gated on state.Up==true, so re-upping the link here would strand it
	// admin UP forever while probes keep failing. When willRecreate drained
	// the runner above, hasRunner is false → restartKA starts a fresh one.
	runner, hasRunner := t.keepalives[tc.Name]
	restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
	skipUp := false
	if tc.Keepalive > 0 && hasRunner && !restartKA {
		runner.state.mu.Lock()
		skipUp = !runner.state.Up
		runner.state.mu.Unlock()
	}

	finishErr := t.finishTunnelLocked(tc, link, skipUp, "tunnel anchor")

	if tc.Keepalive > 0 {
		if restartKA {
			// startKeepalive stops+drains any predecessor itself; runs
			// AFTER a recreate so the fresh runner probes the new device.
			// tc.Source is the probe bind endpoint (#1918 §5c).
			t.startKeepalive(tc.Name, tc.RoutingInstance, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
		}
	} else if hasRunner {
		t.stopKeepaliveLocked(tc.Name)
	}
	return finishErr
}

// reconcileAnchorMTULocked applies the #1884 MTU ownership rule to a
// reused/adopted anchor:
//   - tc.MTU > 0: the config value is reconciled on EVERY reuse. The
//     compiler stage restores MTU only through the zone interface
//     path, so an UNZONED tunnel's configured MTU has no other writer;
//     for zoned tunnels both writers derive the same value from the
//     same config and both guard with !=, so there is no fighting.
//   - tc.MTU == 0 && adopting: one-time normalization to the TUN
//     default 1500 — repairs the wireguard→gre same-name flip, where
//     the leftover WG device carries the reduced WG MTU that the
//     userspace snapshot would otherwise publish into tunnel
//     endpoints.
//   - tc.MTU == 0 && owned: never touched.
func (t *tunnelManager) reconcileAnchorMTULocked(tc *config.TunnelConfig, link netlink.Link, adopting bool) {
	want := 0
	switch {
	case tc.MTU > 0:
		want = tc.MTU
	case adopting:
		want = 1500
	default:
		return
	}
	if link.Attrs().MTU == want {
		return
	}
	if mtuErr := t.ops.LinkSetMTU(link, want); mtuErr != nil {
		slog.Warn("failed to set tunnel anchor mtu",
			"name", tc.Name, "mtu", want, "err", mtuErr)
		return
	}
	slog.Info("tunnel anchor mtu set", "name", tc.Name, "mtu", want)
}

// buildKernelTunnelLink constructs the desired netlink link for the
// legacy (non-anchor) kernel tunnel branch.
func buildKernelTunnelLink(tc *config.TunnelConfig, localIP, remoteIP net.IP, ttl uint8, isIPv6 bool) netlink.Link {
	switch tc.Mode {
	case "ipip":
		if isIPv6 {
			// IPIP over IPv6: use ip6tnl with IPPROTO_IPIP
			return &netlink.Ip6tnl{
				LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
				Local:     localIP,
				Remote:    remoteIP,
				Ttl:       ttl,
				Proto:     4, // IPPROTO_IPIP
			}
		}
		return &netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       ttl,
		}
	default: // "gre" or ""
		// Gretun.Type() auto-detects IPv6 → returns "ip6gre"
		greLink := &netlink.Gretun{
			LinkAttrs: netlink.LinkAttrs{Name: tc.Name},
			Local:     localIP,
			Remote:    remoteIP,
			Ttl:       ttl,
		}
		if tc.Key > 0 {
			greLink.IKey = tc.Key
			greLink.OKey = tc.Key
		}
		return greLink
	}
}

// ipEqual is net.IP.Equal with nil-tolerance. The kernel returns
// 4-byte v4 slices while net.ParseIP yields 16-byte forms — never
// compare these bytewise.
func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

// legacyTunnelMatches reports whether an existing kernel tunnel link
// already matches the desired one, comparing ONLY the config-driven
// attributes: concrete type + Type() string (catches v4↔v6 family
// flips — both "gre" and "ip6gre" deserialize to *Gretun with a
// family-derived Type()), endpoints, defaulted TTL, GRE keys, and the
// ip6tnl Proto. Kernel-populated or post-create-mutated fields (PMtu,
// Tos, flags, encap-limit — mutated by the `ip ... encaplimit none`
// exec) are deliberately NOT compared: a false "changed" verdict would
// silently restore the per-commit flap this code removes (#1884 A.6).
func legacyTunnelMatches(existing, desired netlink.Link) bool {
	switch d := desired.(type) {
	case *netlink.Gretun:
		e, ok := existing.(*netlink.Gretun)
		return ok && e.Type() == d.Type() &&
			ipEqual(e.Local, d.Local) && ipEqual(e.Remote, d.Remote) &&
			e.Ttl == d.Ttl && e.IKey == d.IKey && e.OKey == d.OKey
	case *netlink.Iptun:
		e, ok := existing.(*netlink.Iptun)
		return ok && ipEqual(e.Local, d.Local) &&
			ipEqual(e.Remote, d.Remote) && e.Ttl == d.Ttl
	case *netlink.Ip6tnl:
		e, ok := existing.(*netlink.Ip6tnl)
		return ok && ipEqual(e.Local, d.Local) &&
			ipEqual(e.Remote, d.Remote) && e.Ttl == d.Ttl &&
			e.Proto == d.Proto
	default:
		return false
	}
}

// applyKernelTunnelLocked reconciles one legacy (non-anchor) kernel
// GRE/IPIP tunnel device, reachable only via the standalone-CLI apply
// path (the daemon always sets AnchorOnly). Compare-then-decide:
// identical config-driven attrs reuse the device in place; any real
// change is a legitimate delete+recreate. Caller MUST hold mu.
// The legacy kernel GRE/IPIP device's lower-link selector is unset
// (`buildKernelTunnelLink` leaves `Link` zero), so its outer route
// lookup uses the main FIB. `tc.RoutingInstance` only VRF-binds the
// tunnel interface; keepalive probes on this path pass an empty
// transport instance to match the kernel's outer lookup.
//
// #5355: returns a non-nil error on a GENUINE reconcile failure (the
// replace LinkDel, the create LinkAdd, or the finishTunnelLocked
// LinkSetUp) so Apply can aggregate it and fail the commit closed. An
// invalid-endpoint config or a TRANSIENT lookup deferral is NOT a
// fail-closed condition — the former is a config error (warn), the
// latter self-heals on the next apply — so both return nil.
func (t *tunnelManager) applyKernelTunnelLocked(tc *config.TunnelConfig) error {
	localIP := net.ParseIP(tc.Source)
	remoteIP := net.ParseIP(tc.Destination)
	if localIP == nil || remoteIP == nil {
		slog.Warn("invalid tunnel endpoints",
			"name", tc.Name, "src", tc.Source, "dst", tc.Destination)
		return nil
	}

	ttl := tc.TTL
	if ttl == 0 {
		ttl = 64
	}
	isIPv6 := localIP.To4() == nil
	desired := buildKernelTunnelLink(tc, localIP, remoteIP, uint8(ttl), isIPv6)

	// #1918 §6 Axis D F7 — drain-before-recreate. Decide up front whether
	// this apply will recreate (delete + re-add) the kernel link. If so,
	// CANCEL + DRAIN any existing keepalive runner BEFORE the LinkDel /
	// LinkAdd, so no stale runner goroutine can be mid-LinkSet* while the
	// link is recreated and the kernel reuses its ifindex (the F7
	// counterexample). The drain is the real serializer; it already
	// existed inside startKeepalive but ran AFTER the recreate. After the
	// drain the old runner's goroutine has returned and cannot issue any
	// further LinkSet*. linkGen is the defense-in-depth backstop.
	//
	// A lookup error must be classified (Codex PR #1947 r1 HIGH): only a
	// genuine NOT-FOUND means "absent → create". Any OTHER lookup error
	// (EBUSY / transport hiccup) is TRANSIENT — it does NOT mean the link
	// is gone, so we must NOT drain the live keepalive runner and must NOT
	// fall through to a LinkAdd that would EEXIST. Abort and retry next
	// apply, exactly like a transient LinkDel failure below.
	willRecreate := false
	var existing netlink.Link
	e, lookupErr := t.ops.LinkByName(tc.Name)
	switch {
	case lookupErr == nil:
		existing = e
		willRecreate = !legacyTunnelMatches(e, desired)
	case isLinkNotFound(lookupErr):
		// Absent → the LinkAdd below is a (re)create.
		willRecreate = true
	default:
		// Transient lookup error: leave the runner and any live link
		// untouched; retry on the next apply. Not a fail-closed condition
		// (#5355) — the device state is unknown, not proven-broken, and
		// the next apply reconciles it.
		slog.Warn("tunnel lookup failed transiently; deferring apply",
			"name", tc.Name, "err", lookupErr)
		return nil
	}
	if willRecreate {
		// Drain the stale runner first; bump the generation so any runner
		// that somehow survives (future code paths) drops its netlink op.
		t.stopKeepaliveLocked(tc.Name)
		t.bumpLinkGenLocked(tc.Name)
	}

	var link netlink.Link
	created := false
	if existing != nil {
		if !willRecreate {
			link = existing // kernel-fetched, real ifindex (#1706)
			slog.Debug("tunnel reused", "name", tc.Name)
		} else {
			if delErr := t.ops.LinkDel(existing); delErr != nil {
				slog.Warn("failed to replace existing tunnel link",
					"name", tc.Name, "existing_type", existing.Type(), "err", delErr)
				// The recreate failed but the OLD link is still live. We
				// already drained its keepalive runner before the LinkDel
				// (F7 ordering). Restart it against the surviving link so a
				// transient LinkDel failure does not silently leave the
				// tunnel running with NO keepalive until the next successful
				// apply (Copilot PR #1947 r3). Safe because the link was NOT
				// recreated — the restarted runner captures the just-bumped
				// generation and probes the same device.
				if tc.Keepalive > 0 {
					t.startKeepalive(tc.Name, "", tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
				}
				return fmt.Errorf("replace tunnel %s: %w", tc.Name, delErr)
			}
			slog.Info("replaced tunnel link with changed parameters",
				"name", tc.Name, "existing_type", existing.Type())
		}
	}
	if link == nil {
		if addErr := t.ops.LinkAdd(desired); addErr != nil {
			slog.Warn("failed to create tunnel",
				"name", tc.Name, "mode", tc.Mode, "err", addErr)
			return fmt.Errorf("create tunnel %s: %w", tc.Name, addErr)
		}
		link = desired
		created = true

		// IPv6 GRE: disable encaplimit to avoid adding an IPv6
		// Destination Options extension header. Many transit networks
		// drop IPv6 packets with extension headers (RFC 7872). Runs
		// only on a real (re)create — it is a per-create device attr
		// and the 15s-bounded exec must not run per commit (#1884).
		if isIPv6 && (tc.Mode == "gre" || tc.Mode == "") {
			// Timeout-bounded (#1794/#1800): Apply runs under
			// applyConfigLocked's applySem (daemon_apply.go
			// ApplyTunnels), so a wedged `ip` would block every commit.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			ipCmd := exec.CommandContext(ctx, "ip", "link", "set", tc.Name,
				"type", "ip6gre", "encaplimit", "none")
			// WaitDelay caps the post-SIGKILL pipe-drain window.
			ipCmd.WaitDelay = 5 * time.Second
			out, err := ipCmd.CombinedOutput()
			cancel()
			if err != nil {
				slog.Warn("failed to set tunnel encaplimit",
					"name", tc.Name, "err", err, "output", string(out))
			}
		}
		if tc.MTU > 0 {
			if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
				slog.Warn("failed to set tunnel mtu",
					"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
			}
		}
		slog.Info("tunnel created", "name", tc.Name,
			"src", tc.Source, "dst", tc.Destination)
	} else if tc.MTU > 0 && link.Attrs().MTU != tc.MTU {
		// Config-owned MTU reconcile on reuse (#1884 r5). No
		// adoption-default normalization here: kernel GRE/IPIP devices
		// have protocol-specific default MTUs (1476/1462/...), not the
		// TUN 1500.
		if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
			slog.Warn("failed to set tunnel mtu",
				"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
		}
	}

	// Keepalive reconcile (#1884 A.7, LEGACY BRANCH ONLY — anchors
	// never run probes). Identity-unchanged runners are retained so
	// probe state survives commits; the retained-and-DOWN case must
	// skip LinkSetUp below: keepaliveLoop's down-transition is gated
	// on state.Up==true, so re-upping the link here would strand it
	// admin UP forever while probes keep failing (r1 Codex F1 + AGY
	// converged trace).
	runner, hasRunner := t.keepalives[tc.Name]
	restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
	skipUp := false
	if tc.Keepalive > 0 && hasRunner && !restartKA {
		runner.state.mu.Lock()
		skipUp = !runner.state.Up
		runner.state.mu.Unlock()
	}

	finishErr := t.finishTunnelLocked(tc, link, skipUp, "tunnel")

	if tc.Keepalive > 0 {
		if restartKA {
			// startKeepalive stops+drains any predecessor itself;
			// runs AFTER a recreate so the fresh runner probes the
			// new device. tc.Source is the bind endpoint (#1918 §5c).
			t.startKeepalive(tc.Name, "", tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
		}
	} else if hasRunner {
		t.stopKeepaliveLocked(tc.Name)
	}
	return finishErr
}

// finishTunnelLocked is the shared apply tail: admin-up (unless a
// retained keepalive runner holds the tunnel down), symmetric address
// reconciliation, VRF claim reconcile, and success tracking. Caller
// MUST hold mu; link is the kernel-fetched (or just-created) device.
//
// It returns a non-nil error only on a GENUINE bring-up failure (#5355):
// a LinkSetUp that fails leaves the tunnel device present but admin-DOWN,
// so the commit must fail closed rather than report a converged tunnel
// that carries no traffic. Address/VRF reconcile still run best-effort
// (they retain+retry their own state on transient failure) and are NOT
// folded into the fail-closed signal — matching the xfrmManager.Apply
// scope (#5310), which surfaces only create/find/up/delete link
// failures.
func (t *tunnelManager) finishTunnelLocked(tc *config.TunnelConfig, link netlink.Link, skipUp bool, kind string) error {
	var upErr error
	if skipUp {
		slog.Debug("skipping link up: keepalive holds tunnel down",
			"name", tc.Name)
	} else if err := t.ops.LinkSetUp(link); err != nil {
		slog.Warn("failed to bring up "+kind, "name", tc.Name, "err", err)
		upErr = fmt.Errorf("bring up %s %s: %w", kind, tc.Name, err)
	}
	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
	t.reconcileVRFClaimLocked(tc, link)
	t.tunnels = append(t.tunnels, tc.Name)
	return upErr
}

// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
// against the configured set: add configured-but-missing, delete
// present-but-unconfigured — EXCEPT link-local addresses, which are
// deleted only when this manager itself applied them (`applied`
// gate). The kernel's autoconf fe80 must never be deleted, while a
// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
// Codex F2; extended to the WG branch in #1905). applied == nil (the
// first apply for a link this manager has not tracked yet — restart
// adoption) means no link-local deletion at all.
//
// Returns the new applied set: successful adds + present-and-wanted +
// link-local addresses whose stale-delete FAILED (kept tracked so the
// next apply retries — r2 Codex F4).
func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
	want := make(map[string]bool, len(addrs))
	for _, addrStr := range addrs {
		addr, parseErr := netlink.ParseAddr(addrStr)
		if parseErr != nil {
			slog.Warn("invalid "+kind+" address",
				"name", name, "addr", addrStr, "err", parseErr)
			continue
		}
		want[addr.IPNet.String()] = true
	}
	newApplied := make(map[string]bool, len(want))
	existing := map[string]bool{}
	list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL)
	if listErr != nil {
		// Cannot enumerate: we cannot classify present addresses this pass,
		// so we delete nothing AND must NOT lose link-local OWNERSHIP. A
		// configured fe80 we previously applied that is absent from `want`
		// (mid-removal) would otherwise fall to the AddrAdd branch below
		// (returns EEXIST in real netlink), leave newApplied empty, and so
		// be re-classified as foreign on the next pass — permanently leaking
		// it on a later WG removal prune (Codex #1919 r1 MAJOR). Carry the
		// prior applied link-locals forward so the gate stays correct.
		// Non-link-local ownership is not gated by `applied`, so it need not
		// be preserved here.
		slog.Warn("failed to list "+kind+" addresses for reconcile",
			"name", name, "err", listErr)
		for key := range applied {
			if addr, err := netlink.ParseAddr(key); err == nil &&
				addr.IP != nil && addr.IP.IsLinkLocalUnicast() {
				newApplied[key] = true
			}
		}
	}
	if listErr == nil {
		for i := range list {
			a := list[i]
			key := a.IPNet.String()
			existing[key] = true
			if want[key] {
				continue
			}
			if a.IP == nil {
				// Defensive: the pre-#1884 WG block only deleted
				// addresses with a non-nil IP; keep that byte-identical
				// (and never delete something we cannot classify).
				continue
			}
			if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
				// Kernel-managed or foreign link-local: never delete.
				continue
			}
			if delErr := t.ops.AddrDel(link, &a); delErr != nil {
				slog.Warn("failed to remove stale "+kind+" address",
					"name", name, "addr", key, "err", delErr)
				if a.IP != nil && a.IP.IsLinkLocalUnicast() {
					newApplied[key] = true // retry next apply
				}
			} else {
				slog.Info("removed stale "+kind+" address",
					"name", name, "addr", key)
			}
		}
	}
	for _, addrStr := range addrs {
		addr, parseErr := netlink.ParseAddr(addrStr)
		if parseErr != nil {
			continue
		}
		key := addr.IPNet.String()
		if existing[key] {
			newApplied[key] = true
			continue
		}
		if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
			if errors.Is(addErr, unix.EEXIST) {
				// The address is already present — idempotent success, not a
				// failure. This is the common outcome after an AddrList
				// enumeration failure above (we could not see it in
				// `existing`, so it fell through to this add). Track it as
				// applied and log at Debug to avoid misleading Warn noise
				// (Copilot PR #1950).
				newApplied[key] = true
				slog.Debug("'"+kind+"' address already present",
					"name", name, "addr", addrStr)
			} else {
				slog.Warn("failed to add "+kind+" address",
					"name", name, "addr", addrStr, "err", addErr)
			}
		} else {
			newApplied[key] = true
		}
	}
	return newApplied
}

// pruneAppliedAddrsLocked deletes the addresses on a WG link being pruned
// (config-removal of a persistent wgN, #1919), KEEPING the link itself
// (#1432 S2a invariant — never LinkDel a wgN here). It deletes every
// present non-link-local address (the manager owns the device's
// non-link-local address set, identical to reconcileLinkAddrsLocked's
// steady-state semantics) plus configured/applied link-locals; the
// kernel autoconf / foreign fe80 is never touched (same gate as
// reconcileLinkAddrsLocked at the link-local check).
//
// It returns (failed, retry):
//   - failed: addresses whose AddrDel FAILED, across ALL families. This
//     is carried forward as the new appliedAddrs[name] so the link-local
//     gate stays correct on the retry pass.
//   - retry:  true when the device could NOT be proven clean this pass —
//     either an AddrDel failed OR AddrList itself failed. AddrList failure
//     means we cannot enumerate, hence cannot conclude clean, so we retry
//     unconditionally even when the prior applied set was empty (#1919 r2
//     Codex MAJOR: an empty applied with a real stale address must still
//     retry). The caller retains the name in wgConfigured on retry, NOT on
//     len(failed)>0 — decoupling enumerate-failed from delete-failed.
//
// Distinct from reconcileLinkAddrsLocked (left untouched, frozen #1884
// contract): that function only records a FAILED non-link-local delete
// when the address is link-local, so its return cannot drive a
// non-link-local retry signal (#1919 r1 MAJOR). This helper records every
// family's failed delete.
//
// Caller MUST hold mu.
func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) {
	list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		// Cannot enumerate ⇒ cannot conclude the device is clean. Keep the
		// existing tracked set (so the link-local gate stays correct next
		// pass) and signal retry unconditionally — even if applied is empty.
		slog.Warn("failed to list wireguard tun addresses for prune",
			"name", name, "err", err)
		return applied, true
	}
	failed := map[string]bool{}
	for i := range list {
		a := list[i]
		if a.IP == nil {
			continue // unclassifiable: never delete (parity with reconcile)
		}
		key := a.IPNet.String()
		if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
			continue // kernel autoconf / foreign link-local: never delete
		}
		if delErr := t.ops.AddrDel(link, &a); delErr != nil {
			slog.Warn("failed to prune wireguard tun address",
				"name", name, "addr", key, "err", delErr)
			failed[key] = true // ALL families (the #1919 r1 MAJOR fix)
		} else {
			slog.Info("pruned wireguard tun address (removed from config)",
				"name", name, "addr", key)
		}
	}
	return failed, len(failed) > 0
}

// reconcileVRFClaimLocked runs the #1884 A.5 ordered claim procedure.
// The claim invariant (r6-r8): t.appliedRI[name] is only ever written
// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
// link's master — never from intent — so the identity-gated unbind
// below can neither strand a master we own nor touch one we do not.
//
//  1. stanza RI nonempty: bind; on success claim = stanza RI (stanza
//     wins over a coexisting 0a list bind — today's effective apply
//     order); on failure fall through to observation.
//  2. stanza failed or empty, RIListMember nonempty: never unbind (0a
//     owns list binds — the VETO); claim transfers to the list RI only
//     when the observed master IS vrf-<RIListMember>, else the prior
//     claim is retained.
//  3. config wants no RI: identity-gated unbind of vrf-<claim>. Claim
//     clears on successful unbind / identity mismatch (master not
//     ours) / VRF device not-found (kernel already freed the slaves);
//     it is RETAINED on transient errors so the next apply retries.
//
// Caller MUST hold mu.
func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
	name := tc.Name
	if tc.RoutingInstance != "" {
		if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
			slog.Warn("failed to bind tunnel to VRF",
				"name", name, "vrf", tc.RoutingInstance, "err", err)
			// r7/r8: a FAILED bind must not blind-write the claim (the
			// kernel may still carry the previous master, or a 0a list
			// bind). Observation may take the claim; else retain.
			t.observeListClaimLocked(tc, link)
			return
		}
		t.appliedRI[name] = tc.RoutingInstance
		return
	}
	if tc.RIListMember != "" {
		// Unbind VETO: a stanza→list move must never strip the 0a
		// bind (r4 convergent counterexample).
		t.observeListClaimLocked(tc, link)
		return
	}

	// config wants no RI (step 3): identity-gated unbind of the prior
	// claim, shared with the WireGuard config-removal path (#5120).
	t.unbindVRFClaimLocked(name, link)
}

// unbindVRFClaimLocked runs the identity-gated unbind half of the #1884
// A.5 claim procedure for a tunnel whose desired routing-instance is now
// empty — either because the `routing-instance` stanza was removed from a
// still-configured tunnel (reconcileVRFClaimLocked step 3) or because the
// whole tunnel was removed and its persistent link is being reconciled
// (#5120, the WireGuard removal path — the wgN link is KEPT but must not
// linger enslaved to a VRF it should no longer be in). It clears the
// link's master to vrf-<claim> ONLY when the link's CURRENT master is
// OBSERVED to be that VRF device, so it can neither strand a master we own
// nor touch a foreign bind.
//
// The appliedRI claim clears on a successful unbind, on master==0 (already
// unbound), on an identity mismatch (master not ours), or when the VRF
// device is not-found (deleting a VRF frees its slaves). It is RETAINED —
// and the function returns retry=true — only on a TRANSIENT failure (a VRF
// lookup error other than not-found, or a LinkSetNoMaster error) so the
// caller re-runs the reconcile on the next Apply. Caller MUST hold mu.
func (t *tunnelManager) unbindVRFClaimLocked(name string, link netlink.Link) (retry bool) {
	claim := t.appliedRI[name]
	if claim == "" {
		return false
	}
	master := link.Attrs().MasterIndex
	if master == 0 {
		// Nothing is bound — whatever we once bound is already gone.
		delete(t.appliedRI, name)
		return false
	}
	vrf, err := t.ops.LinkByName("vrf-" + claim)
	if err != nil {
		if isLinkNotFound(err) {
			// The VRF device is gone; deleting a master frees its
			// slaves, so the current master cannot be ours.
			delete(t.appliedRI, name)
			return false
		}
		// Transient lookup error: retain the claim, retry next apply.
		return true
	}
	masterVRF, ok := vrf.(*netlink.Vrf)
	if !ok || masterVRF == nil || masterVRF.Attrs() == nil || masterVRF.Attrs().Index != master {
		// A same-name non-VRF link is not the claimed master either.
		delete(t.appliedRI, name)
		return false
	}
	if err := t.ops.LinkSetNoMaster(link); err != nil {
		slog.Warn("failed to unbind tunnel from VRF",
			"name", name, "vrf", claim, "err", err)
		return true // retain claim; retry next apply
	}
	slog.Info("tunnel unbound from routing-instance",
		"name", name, "vrf", claim)
	delete(t.appliedRI, name)
	return false
}

// observeListClaimLocked transfers the appliedRI claim to the
// routing-instance list member ONLY when the link's current master is
// OBSERVED to be that RI's VRF device (#1884 r6/r8: a blind transfer
// after a failed 0a bind would record an RI the kernel never took and
// later strand the real master on a mismatch-clear). On any
// non-observation the previous nonempty claim is retained. Caller MUST
// hold mu.
func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
	if tc.RIListMember == "" {
		return
	}
	master := link.Attrs().MasterIndex
	if master == 0 {
		return // 0a bind absent or failed: no observation, retain prior
	}
	vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
	if err != nil {
		return // retain prior claim
	}
	masterVRF, ok := vrf.(*netlink.Vrf)
	if ok && masterVRF != nil && masterVRF.Attrs() != nil && masterVRF.Attrs().Index == master {
		t.appliedRI[tc.Name] = tc.RIListMember
	}
}

// Clear removes all previously created tunnel interfaces.
func (t *tunnelManager) Clear() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.clearLocked()
}

// clearLocked is the lock-free body of Clear. Caller must hold mu.
// Apply no longer uses it (#1884 reconcile-in-place); it remains the
// explicit delete-everything path for ClearTunnels. It deletes the
// UNION of the success-tracked list and the ownership set: a
// per-tunnel apply failure leaves the name in ownedNames but not in
// t.tunnels (failure-continue before finishTunnelLocked), and the
// delete-everything contract must still cover that live link (Codex
// PR #1903 r1 MINOR).
func (t *tunnelManager) clearLocked() error {
	t.stopAllKeepalivesLocked()
	names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
	for _, name := range t.tunnels {
		names[name] = true
	}
	for name := range t.ownedNames {
		names[name] = true
	}
	var errs []error
	failed := map[string]bool{}
	for name := range names {
		link, err := t.ops.LinkByName(name)
		if err != nil {
			if isLinkNotFound(err) {
				continue // genuinely gone
			}
			// #7529: a transient lookup failure is not absence. Falling through
			// here dropped the name from ownedNames (it is rebuilt from
			// `failed` below), so a tunnel still present in the kernel became
			// untracked and no later Apply retried its delete — leaving a live
			// link with stale addresses and XFRM if_id state that xpf no longer
			// believes it owns. Same treatment as a failed LinkDel: retain
			// ownership and surface the error.
			slog.Warn("tunnel clear: link lookup failed, retaining ownership for retry",
				"name", name, "err", err)
			errs = append(errs, fmt.Errorf("lookup tunnel %s: %w", name, err))
			failed[name] = true
			continue
		}
		if err := t.ops.LinkDel(link); err != nil {
			// #4901: a failed LinkDel leaves the tunnel in the kernel. Retain
			// ownership so a post-Clear Apply's removal diff (which keys off
			// ownedNames) retries the delete instead of orphaning a live link
			// with stale addresses / XFRM if_id state, and surface the error.
			slog.Warn("failed to delete tunnel", "name", name, "err", err)
			errs = append(errs, fmt.Errorf("delete tunnel %s: %w", name, err))
			failed[name] = true
		} else {
			slog.Info("tunnel removed", "name", name)
		}
	}
	t.tunnels = nil
	// Reset the reconcile state with the devices: a post-Clear Apply
	// adopts whatever survives instead of trusting stale ownership.
	// #4901: EXCEPT the names whose LinkDel failed — retain their ownership so
	// the next Apply retries the delete rather than orphaning the link.
	if len(failed) > 0 {
		t.ownedNames = failed
	} else {
		t.ownedNames = nil
	}
	t.appliedAddrs = nil
	t.appliedRI = nil
	// Reset the WG-removal-prune tracking too (#1919). Clear does NOT delete
	// WG links (they are persistent and not in tunnels/ownedNames) — only the
	// tracking map is dropped so a post-Clear Apply re-adopts cleanly.
	//
	// #8996: whether Clear should ALSO flush WG addresses was deferred here to
	// #1434 for a long time and is now DECIDED: it must not, and the reason is
	// in the code beside this rather than a matter of taste. The link is kept
	// by #1432 S2a precisely because tearing one flaps the device and destroys
	// the live peer/session and the FRR routes over it. Flushing the ADDRESSES
	// destroys the connected route and the address that live session is using —
	// the same harm S2a exists to prevent, one level down — while leaving the
	// device up to imply it still works.
	//
	// Address hygiene on config REMOVAL is already handled, by a mechanism that
	// can tell removal from teardown: Apply's #1919 WG-removal diff prunes a WG
	// name that DISAPPEARED from config while keeping its link. Clear is not a
	// removal and must not borrow that behaviour.
	//
	// WHAT DROPPING THE MAP COSTS, so it is not rediscovered as a defect: a WG
	// tunnel removed from config ACROSS a Clear boundary is not in oldWG at the
	// next Apply, so the #1919 prune cannot see it. That is the SAME
	// restart-adoption limitation this manager already documents (a WG tunnel
	// removed while the daemon was DOWN is not in wgConfigured on the next
	// start) reached by a second route — the manager prunes only what it
	// tracked applying — rather than a new gap.
	//
	// Pinned by TestClearTunnelsKeepsWireguardAddresses8996.
	t.wgConfigured = nil
	// clearLocked drains every keepalive runner first
	// (stopAllKeepalivesLocked above), so no live runner holds a stale
	// linkGen pointer; dropping the map is safe and prevents removed names
	// from leaking generation counters (#1918).
	t.linkGen = nil
	return errors.Join(errs...)
}

// GetStatus returns the status of managed tunnel interfaces.
func (t *tunnelManager) GetStatus() ([]TunnelStatus, error) {
	// #848: snapshot tunnel names under mu, then iterate without the
	// lock so a long netlink probe can't block applyConfig.
	t.mu.Lock()
	names := append([]string(nil), t.tunnels...)
	t.mu.Unlock()

	var result []TunnelStatus
	for _, name := range names {
		ts := TunnelStatus{Name: name, State: "down"}

		link, err := t.ops.LinkByName(name)
		if err != nil {
			ts.State = "not found"
			result = append(result, ts)
			continue
		}

		if link.Attrs().Flags&net.FlagUp != 0 {
			ts.State = "up"
		}

		switch tun := link.(type) {
		case *netlink.Gretun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Iptun:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		case *netlink.Ip6tnl:
			ts.Source = tun.Local.String()
			ts.Destination = tun.Remote.String()
		}

		addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
		if err == nil {
			for _, a := range addrs {
				ts.Addresses = append(ts.Addresses, a.IPNet.String())
			}
		}

		// Add keepalive info.
		if ks := t.GetKeepaliveState(name); ks != nil {
			ks.mu.Lock()
			switch {
			case ks.Unknown:
				// Hold-on-unknown (#1918 §6 Axis C): the prober could not
				// verify liveness. KeepaliveUp stays nil ("liveness
				// unknown") — never reported up — and the info string tells
				// the operator why so they can fix the sysctl/caps. A
				// sustained transient unknown carries the escalated errno.
				ts.KeepaliveUp = nil
				switch {
				case ks.UnknownKind == UnsupportedTransient:
					ts.KeepaliveInfo = fmt.Sprintf(
						"unknown (%s; %d consecutive)",
						ks.UnknownErrno, ks.unknownStreak)
				case ks.UnknownErrno != "":
					// Structural with a captured reason (the real syscall/config
					// detail): show it so the operator can fix the root cause.
					ts.KeepaliveInfo = fmt.Sprintf(
						"unknown (ICMP probe unavailable: %s)", ks.UnknownErrno)
				default:
					ts.KeepaliveInfo = "unknown (ICMP probe unavailable)"
				}
			default:
				up := ks.Up
				ts.KeepaliveUp = &up
				if up {
					ts.KeepaliveInfo = fmt.Sprintf("up (interval %ds, %d retries)",
						ks.Interval, ks.MaxRetries)
				} else {
					ts.KeepaliveInfo = fmt.Sprintf("down (%d consecutive failures)",
						ks.Failures)
				}
			}
			ks.mu.Unlock()
		}

		result = append(result, ts)
	}
	return result, nil
}
