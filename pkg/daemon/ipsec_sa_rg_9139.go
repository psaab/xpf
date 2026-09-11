package daemon

// ipsec_sa_rg_9139.go — per-redundancy-group attribution for IPsec SA sync
// and re-initiation (#9139).
//
// THE DEFECT, and it is the shape #3764 already fixed once in this tree.
// advertiseIPsecSAOnce gated on IsLocalPrimary(0) and reinitiateIPsecSAs was
// wired only to applyRG0OwnershipTransition. Active/active is a supported
// configuration — docs/active-active-new-connections.md designs it and
// `make test-active-active` gates it — and in the asymmetric case (RG0 primary
// node 0, RG1 primary node 1, IPsec anchored on an RG1 reth) NEITHER half runs:
//
//   - node 1 holds the SAs and short-circuits at IsLocalPrimary(0), so it never
//     advertises;
//   - node 0 is RG0 primary, so it advertises its OWN set, which is empty, and
//     ipsecSASyncAdvertise suppresses a steady-empty set — nothing on the wire
//     either way;
//   - node 1 dies, node 0 takes RG1, and there is NO RG0 transition (node 0 was
//     already RG0 primary), so reinitiateIPsecSAs never fires — and the peer set
//     it would read is empty regardless.
//
// charon does not paper over it: pkg/ipsec/policy.go emits `start_action = start`
// ONLY for `establish-tunnels immediately`, so on the default setting the tunnel
// waits for the REMOTE peer to initiate. Every site-to-site VPN stays down until
// it does, with IPsecSASync configured and reporting healthy.
//
// #3764 in daemon_ipmon.go is the same defect on the ip-monitoring overlay and
// its comment describes the identical failure: "Keying on the lowest data RG
// alone suppressed the ENTIRE overlay on any node that was not primary for that
// lowest RG."
//
// WHY ATTRIBUTION IS NEEDED AND NOT JUST A WIDER GATE. Widening the advertise
// gate to IsLocalPrimaryAny() alone would make BOTH nodes advertise, and
// reinitiateIPsecSAs initiates the peer's WHOLE set. On a per-RG failover where
// the peer is still ALIVE and still owns another RG, taking RG1 would also
// initiate the tunnels the peer still holds on RG2 — a second IKE SA to the same
// remote from a different local address. Trading a missed re-initiation for a
// duplicate one is not a fix.
//
// The attribution below is deliberately evaluated at INITIATE time rather than
// at advertise time: it asks "does this node currently own the interface this
// connection would bind to", which is a local question with a local answer, and
// it needs no new wire field. It also tightens the pre-existing RG0 path, which
// initiated everything the peer advertised regardless of what this node owns.

import (
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// ipsecSANameIndex indexes the SA names a config's IPsec section renders
// (ipsec.BuildSANameIndex). Build it once per re-initiate pass: it renders the
// whole swanctl config, which is cheap once and wasteful per advertised name.
func ipsecSANameIndex(cfg *config.Config) ipsec.SANameIndex {
	if cfg == nil {
		return nil
	}
	return ipsec.BuildSANameIndex(&cfg.Security.IPsec)
}

// applyIPsecTracked applies cfg's IPsec section and records cfg as the generation HA
// IPsec attribution reads, at the moment strongSwan LOADED it (#9511).
//
// The record is made from inside the apply, through ipsec.Manager.ApplyGeneration.
// Loaded stores cfg right after the loaded connection set is promoted and BEFORE
// departed connections are torn down. That is the only correct point: Apply's error
// cannot say whether the reload succeeded (teardown debt, #6542, is returned after
// one), and a record made after the teardown would leave re-initiation, which does not
// hold applySem, attributing against the PREVIOUS generation for the whole teardown.
//
// FAILED-RELOAD WINDOW (#9511 stopgap). Written clears the record the moment the
// on-disk swanctl config changes, before the reload. If the reload then fails, charon
// keeps running the previous generation, but the NEW file stays on disk, and
// strongswan.service loads it on charon's own next start or reload (ExecStartPost and
// ExecReload run `swanctl --load-all`, Restart=on-abnormal). A record still naming the
// previous generation would then describe a config charon no longer runs, which is
// worse than master. With the record cleared, attribution stops trusting it. A render
// or write failure changes nothing on disk, so Written does not run and the previous
// record stays, still matching both the file and charon.
//
// GENERATION MARKER (#9641). The written file also names cfg's generation inside
// charon (ipsecApplyGeneration: the store's digest when cfg is its active config).
// While the record is empty, in this window or after an xpfd restart, attribution asks
// charon which generation it loaded and validates the answer against charon's loaded
// connections. When charon cannot tell, it falls back to the promoted config, the
// generation charon will load next (ipsec_loaded_generation_9641.go). The apply is
// bracketed (ipsecApplyActive, ipsecApplySeq) so a pass can tell that an apply
// overlapped it, and Written remembers the generation it put on disk
// (rememberWrittenIPsecGeneration) for a charon still running a tree the store has
// since dropped.
func (d *Daemon) applyIPsecTracked(cfg *config.Config) error {
	d.ipsecApplyActive.Add(1)
	d.ipsecApplySeq.Add(1)
	defer func() {
		d.ipsecApplySeq.Add(1)
		d.ipsecApplyActive.Add(-1)
	}()
	gen := d.ipsecApplyGeneration(cfg)
	return d.ipsec.ApplyGeneration(ipsec.PrepareConfig(cfg), gen, ipsec.ApplyHooks{
		Written: func() {
			d.ipsecLoadedCfg.Store(nil)
			d.rememberWrittenIPsecGeneration(gen, cfg)
		},
		Loaded: func() {
			d.ipsecLoadedCfg.Store(cfg)
			d.rememberLoadedIPsecGeneration(gen, cfg)
		},
	})
}

// ipsecAttributionConfig resolves the config one HA IPsec attribution pass reads, and
// records it as the latest resolution (ipsecAttribution):
//
//  1. the generation strongSwan has LOADED from this process (ipsecLoadedCfg, #9511);
//  2. with no record, the generation charon itself reports loaded, when this node
//     retains it, charon's loaded connections validate it and are provably not the
//     promoted config's, and no IPsec apply overlapped the pass
//     (ipsecStableMarkedGeneration, #9641);
//  3. otherwise the promoted config, which is what attribution read before #9641.
//
// The record comes first because it is exact whenever it is set: Written clears it as
// soon as a new file is on disk, so a record names the file charon loaded and would
// reload. Asking charon costs two swanctl calls, so it is kept for the states with no
// record: after an xpfd restart whose boot IPsec apply failed (charon still runs the
// previous process's generation), and in the failed-reload window.
//
// A name the loaded generation does not render is ROUTINE, not anomalous. It happens
// whenever the peer loaded a newer generation first (config-sync lag) or still
// reports an SA whose teardown is pending. Such a name keeps the pre-#9511 lookup and
// the RG 0 default rather than being dropped as an anomaly. A child strongSwan has not
// loaded cannot be initiated in any case, and that failure is logged by
// reinitiateIPsecSAs.
func (d *Daemon) ipsecAttributionConfig() *config.Config {
	cfg := d.ipsecLoadedCfg.Load()
	if cfg == nil {
		cfg = d.ipsecStableMarkedGeneration()
	}
	if cfg == nil {
		// An apply that finished during the pass may have recorded what charon loaded.
		cfg = d.ipsecLoadedCfg.Load()
	}
	if cfg == nil && d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	d.ipsecAttribution.Store(cfg)
	return cfg
}

// ipsecSAIndexCache pairs an SA name index with the attribution config it was
// built from.
type ipsecSAIndexCache struct {
	cfg *config.Config
	idx ipsec.SANameIndex
}

// cachedIPsecSANameIndex returns the SA name index for cfg, rebuilding it only
// when the attribution config (ipsecAttributionConfig) changed since the last build.
// Its sources are immutable snapshots: the store installs a new *config.Config on
// every promotion, applyIPsecTracked records the pointer it applied, and a generation
// charon names is compiled once and cached (retainedIPsecGeneration). So the pointer
// is the generation. A takeover wave runs one
// re-initiate pass per redundancy group; without the cache every pass would
// re-render every VPN, repeat the render's skip warnings, and repeat the
// collision warning below.
//
// Misses are serialised (ipsecSAIndexMu) and re-checked under the lock: the
// per-RG re-initiate goroutines of one takeover wave start together, and without
// it each would miss, render every VPN and log the same warning. A pass holding a
// config that is no longer current (isCurrentIPsecAttribution, which never asks
// charon) is answered but not installed, so it can neither overwrite the newer entry
// nor announce collisions for a config that is no longer active.
func (d *Daemon) cachedIPsecSANameIndex(cfg *config.Config) ipsec.SANameIndex {
	if cfg == nil {
		return nil
	}
	if c := d.ipsecSAIndex.Load(); c != nil && c.cfg == cfg {
		return c.idx
	}
	d.ipsecSAIndexMu.Lock()
	defer d.ipsecSAIndexMu.Unlock()
	if c := d.ipsecSAIndex.Load(); c != nil && c.cfg == cfg {
		return c.idx
	}
	idx := ipsecSANameIndex(cfg)
	if !d.isCurrentIPsecAttribution(cfg) {
		return idx
	}
	if coll := idx.Collisions(); len(coll) > 0 {
		slog.Warn("cluster: IPsec SA names rendered by more than one VPN; a name whose "+
			"candidates span several redundancy groups is re-initiated only by a node "+
			"that owns every one of them (and a declared RG0 for an unanchored candidate)",
			"collisions", coll)
	}
	d.ipsecSAIndex.Store(&ipsecSAIndexCache{cfg: cfg, idx: idx})
	return idx
}

// ipsecConnRedundancyGroups reports the redundancy groups that own the external
// interfaces of every VPN that could have produced an advertised SA name.
//
// connName is a name the PEER advertised, and the peer advertises SA names from
// ipsec.ActiveConnectionNames: CHILD SA names, not VPN names. idx maps the name
// back to the VPNs whose render produces it, and each VPN is walked vpn ->
// gateway -> external-interface -> reth -> redundant-ether-options
// redundancy-group (ipsecVPNRedundancyGroup).
//
// HISTORICAL, and wrong (#9511): this comment used to say "the swanctl connection
// name IS the VPN name (pkg/ipsec/policy.go renders `  <sanitized vpn name> {`)".
// That is true of the IKE section and false of the child sections the same file
// renders: a VPN with traffic-selector entries gets one child `<vpn>-<selector>`
// per selector and no child named `<vpn>`. The lookup was built on the comment,
// so every multi-selector VPN missed and fell to RG 0, and #9139's attribution
// was inert for exactly those VPNs. The name is deliberately NOT rewritten to the
// VPN name before it reaches here: reinitiateIPsecSAs hands the same name to
// `swanctl --initiate --child`, which needs the child (#9075, GEMINI-050-072).
//
// Usually one VPN renders a name and the answer is one group. When two renders
// collide every candidate's group is returned, and ownsIPsecConn requires all of
// them. A name no loaded VPN renders falls back to the pre-#9511 lookup by VPN
// name. A name that resolves to nothing, or to a VPN on no reth, is RG 0: the
// historical behaviour and the right default rather than a refusal, because
// before #9139 every peer-advertised name was re-initiated on the RG0 transition
// and refusing would silently STOP re-initiating tunnels that work today.
func ipsecConnRedundancyGroups(cfg *config.Config, idx ipsec.SANameIndex, connName string) []int {
	if cfg == nil || connName == "" {
		return []int{0}
	}
	var rgs []int
	for _, name := range idx.VPNs(connName) {
		rgs = appendRedundancyGroup(rgs, ipsecVPNRedundancyGroup(cfg, cfg.Security.IPsec.VPNs[name]))
	}
	if len(rgs) == 0 {
		return []int{ipsecVPNRedundancyGroup(cfg, lookupIPsecVPNByName(cfg, connName))}
	}
	sort.Ints(rgs)
	return rgs
}

func appendRedundancyGroup(rgs []int, rg int) []int {
	for _, have := range rgs {
		if have == rg {
			return rgs
		}
	}
	return append(rgs, rg)
}

// ipsecVPNRedundancyGroup reports the redundancy group owning the reth that a
// VPN's gateway external-interface names, or 0 when it resolves to no reth.
func ipsecVPNRedundancyGroup(cfg *config.Config, vpn *config.IPsecVPN) int {
	if vpn == nil || vpn.Gateway == "" {
		return 0
	}
	gw := cfg.Security.IPsec.Gateways[vpn.Gateway]
	if gw == nil || gw.ExternalIface == "" {
		return 0
	}
	base := gw.ExternalIface
	if i := strings.Index(base, "."); i > 0 {
		base = base[:i]
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return 0
	}
	return ifc.RedundancyGroup
}

// lookupIPsecVPNByName is the pre-#9511 lookup, kept only as the fallback for a
// name no loaded VPN renders: the configured VPN name, then a case-insensitive
// match on it.
func lookupIPsecVPNByName(cfg *config.Config, name string) *config.IPsecVPN {
	if vpn, ok := cfg.Security.IPsec.VPNs[name]; ok {
		return vpn
	}
	for vpnName, vpn := range cfg.Security.IPsec.VPNs {
		if vpn == nil {
			continue
		}
		if strings.EqualFold(vpnName, name) {
			return vpn
		}
	}
	return nil
}

// ownsIPsecConn reports whether this node is currently the primary for the
// redundancy group that owns the connection's external interface, i.e. whether
// this node holds the local address the IKE SA would bind to.
//
// A cluster-less daemon owns everything: the gate exists to prevent two CLUSTER
// nodes initiating the same tunnel, and there is no second node to collide with.
//
// A NAME WHOSE CANDIDATE VPNs SPAN MORE THAN ONE GROUP (#9511) is owned only when
// this node owns EVERY one of those groups. Initiating on a subset is a coin flip
// between the missed re-initiation and the duplicate SA #9139 exists to prevent,
// and `swanctl --initiate --child` cannot say which of the colliding children it
// would bring up anyway. For such a name RG0 must be DECLARED and held: the
// undeclared-RG0 fallback described below ("primary for anything") is not
// exclusive ownership, so it would let a node holding only RG1 initiate a name
// that may be the live peer's unanchored tunnel. Candidates that all share one
// group are not ambiguous for ownership and take the ordinary rule. The collision
// is logged once per attribution config (cachedIPsecSANameIndex).
//
// RG0 IS NOT NECESSARILY A DECLARED GROUP, and getting this wrong is a silent
// regression rather than a visible one. cluster.Manager.UpdateConfig creates a
// group only for an RG the config DECLARES, so on a config carrying
// `redundancy-group 1` and no `redundancy-group 0`, groups[0] does not exist and
// IsLocalPrimary(0) is permanently FALSE. Gating an unanchored connection on it
// there would mean never re-initiating it — worse than the pre-#9139 behaviour
// this change is supposed to extend. LocalGroupPrimary (#8640) exists precisely
// to tell "not primary" from "no such group", so an undeclared RG0 falls back to
// "primary for anything", which is the same question #3764 settled on for the
// ip-monitoring overlay.
//
// The fallback is NOT used when RG0 is declared (the shipped cluster configs
// declare it), nor for a name whose candidates span several groups (above),
// because there the honest answer is narrower: an unanchored tunnel
// binds an interface present on both nodes, so a node taking only a DATA RG
// while the peer keeps RG0 must not initiate it — the peer still has it.
func (d *Daemon) ownsIPsecConn(cfg *config.Config, idx ipsec.SANameIndex, connName string) bool {
	if d.cluster == nil {
		return true
	}
	rgs := ipsecConnRedundancyGroups(cfg, idx, connName)
	exclusive := len(rgs) > 1
	for _, rg := range rgs {
		if !d.ownsIPsecRedundancyGroup(rg, exclusive) {
			return false
		}
	}
	return true
}

// ownsIPsecRedundancyGroup reports whether this node holds rg for IPsec
// initiation. exclusive refuses the undeclared-RG0 "primary for anything"
// fallback, which cannot prove that the peer does not hold the tunnel.
func (d *Daemon) ownsIPsecRedundancyGroup(rg int, exclusive bool) bool {
	if rg != 0 {
		return d.cluster.IsLocalPrimary(rg)
	}
	if primary, known := d.cluster.LocalGroupPrimary(0); known {
		return primary
	}
	if exclusive {
		return false
	}
	return d.cluster.IsLocalPrimaryAny()
}
