// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// timeNowForRA is the clock for PD lifetime decay in buildRAConfigs;
// a var so tests could pin it, production is time.Now.
var timeNowForRA = time.Now

// buildRAConfigs merges static RA configs from the Junos config with
// PD-derived prefixes from DHCPv6 prefix delegation.
func (d *Daemon) buildRAConfigs(cfg *config.Config) []*config.RAInterfaceConfig {
	// #12533: per-RA-interface pin sets, unioned from every DHCPv6
	// client that targets the interface. Keyed by resolved kernel name
	// like raByIface below so the stamp lands on the merged config.
	pinsByRA := make(map[string][]string)
	if d.dhcp != nil {
		seenSrc := make(map[string]bool)
		for _, mapping := range d.dhcp.DelegatedPrefixesForRA() {
			if seenSrc[mapping.Interface] {
				continue
			}
			seenSrc[mapping.Interface] = true
			pins := d.dhcp.PinnedPrefixesForRA(mapping.Interface)
			if len(pins) == 0 {
				continue
			}
			key := cfg.ResolveKernelIfName(mapping.RAIface)
			for _, p := range pins {
				pinsByRA[key] = append(pinsByRA[key], p.String())
			}
		}
		for k := range pinsByRA {
			sort.Strings(pinsByRA[k])
		}
	}
	// #10856: every RA carries the box-wide configured-prefix set so the
	// sender can refuse a DELEGATED PIO that overlaps configured space.
	protectedPD := config.ConfiguredIPv6Prefixes(cfg)
	protectedPDStrings := make([]string, 0, len(protectedPD))
	for _, p := range protectedPD {
		protectedPDStrings = append(protectedPDStrings, p.String())
	}
	// Start with static RA configs from the configuration. Key the merge
	// map by the RESOLVED kernel name (#15058): a static RA authored as
	// ge-0/0/1.0 and a PD target authored as ge-0/0/1 (or vice versa) name
	// the same netdev once unit 0 collapses, so keying by the raw authored
	// string produced two configs for one netdev whose static options
	// ra.Apply's last-wins desired map then silently dropped. A resolved
	// collision between two distinct static entries keeps the first entry
	// (with a warning); ra.Apply refuses any residual duplicate outright.
	raByIface := make(map[string]*config.RAInterfaceConfig)
	var result []*config.RAInterfaceConfig
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra == nil {
			continue
		}
		clone := cloneRAInterfaceConfig(ra)
		key := cfg.ResolveKernelIfName(clone.Interface)
		if prev, dup := raByIface[key]; dup {
			slog.Warn("daemon: duplicate router-advertisement interfaces resolve to the same device; keeping the first",
				"interface", clone.Interface, "kept", prev.Interface, "device", key)
			continue
		}
		raByIface[key] = clone
		result = append(result, clone)
	}

	if d.dhcp != nil {
		// Merge PD-derived prefixes from DHCPv6 clients.
		for _, mapping := range d.dhcp.DelegatedPrefixesForRA() {
			subPrefix := dhcp.DeriveSubPrefix(mapping.Prefix, mapping.SubPrefLen)
			if !subPrefix.IsValid() {
				slog.Warn("DHCPv6 PD: invalid sub-prefix derivation",
					"delegated", mapping.Prefix, "sub_len", mapping.SubPrefLen)
				continue
			}

			pfx := &config.RAPrefix{
				Prefix:     subPrefix.String(),
				OnLink:     true,
				Autonomous: true,
				// #6587: mark the provenance so pkg/ra can apply a floor to a
				// DELEGATED prefix without breaking an operator-authored ::/0.
				Delegated: true,
				// #12533: separate pin provenance, from the decoder.
				Pinned: mapping.Pinned,
			}
			// #15057: carry the ABSOLUTE expiry (Obtained+granted) rather
			// than a decayed remaining value. The desired set then stays
			// byte-identical as wall time advances, so the 2s cluster
			// reconcile hash and ra.configEqual no longer churn every
			// second; pkg/ra buildRA computes the remaining lifetime at
			// send time. ValidLifetime/PreferredLife keep the granted
			// values as the no-expiry fallback (zero-obtained/test-seeded
			// and legacy hand-built prefixes). A mapping whose granted
			// valid lifetime is 0 (test-seeded, no clock) has no expiry:
			// leave lifetimes at 0, the sender default sentinel (#6531).
			if mapping.ValidLifetime > 0 {
				if _, remValid := mapping.RemainingLifetimes(timeNowForRA()); remValid <= 0 && !mapping.Obtained.IsZero() {
					continue
				}
				pfx.ValidLifetime = int(mapping.ValidLifetime.Seconds())
				pfx.PreferredLife = int(mapping.PreferredLifetime.Seconds())
				// #14606: the preferred lifetime is explicit, and 0 is
				// legal (deprecated, RFC 8415 §21.22) — whether granted
				// as 0 or decayed to 0 while valid remains. Record it so
				// pkg/ra does not conflate deprecated-0 with unset.
				pfx.PreferredLifeSet = true
				if exp := mapping.ExpiresAt(); !exp.IsZero() {
					pfx.ValidExpiresAt = exp.UnixNano()
				}
				if exp := mapping.PreferredExpiresAt(); !exp.IsZero() {
					pfx.PreferredExpiresAt = exp.UnixNano()
				}
			}

			key := cfg.ResolveKernelIfName(mapping.RAIface)
			if existing, ok := raByIface[key]; ok {
				// Append prefix to existing RA interface config.
				existing.Prefixes = append(existing.Prefixes, pfx)
			} else {
				// Create a new RA interface config for this downstream interface.
				ra := &config.RAInterfaceConfig{
					Interface: mapping.RAIface,
					Prefixes:  []*config.RAPrefix{pfx},
				}
				raByIface[key] = ra
				result = append(result, ra)
			}

			// Debug, not Info: buildRAConfigs is a pure builder now re-run on
			// every ~2s periodic cluster RA reconcile (reconcileClusterRAServices),
			// so this line would repeat per PD prefix every tick — per-poll-tick
			// Info spam the logging discipline forbids. The one-time operational
			// signal ("a PD prefix is being advertised") belongs on the actual
			// apply, which the reconcile's hash-gated Info already carries.
			slog.Debug("DHCPv6 PD: advertising prefix via RA",
				"prefix", subPrefix, "interface", mapping.RAIface,
				"delegated_from", mapping.Interface)
		}
	}

	// Detect explicitly configured link-local addresses on RA interfaces.
	// If a user configures e.g. fe80::face/64 on a RETH interface (or on a
	// VLAN subinterface), the RA sender should bind to that address instead
	// of auto-selecting a transient EUI-64 link-local.
	for _, ra := range result {
		// #10856: same slice for every interface — the protected set is
		// box-wide, and the sender treats it as read-only.
		ra.ProtectedPrefixes = protectedPDStrings
		// #12533: pin set for this RA interface only (union of its PD
		// clients' pins), resolved by kernel name.
		if pins, ok := pinsByRA[cfg.ResolveKernelIfName(ra.Interface)]; ok {
			ra.PinnedPrefixes = append([]string(nil), pins...)
		}
		ifc, ll := resolveRASourceLinkLocal(cfg, ra.Interface)
		if ifc == nil {
			continue
		}
		if ll != "" {
			ra.SourceLinkLocal = ll
		}
		if ra.SourceLinkLocal == "" && cfg.Chassis.Cluster != nil {
			// RETH HA startup installs a stable router link-local on the active
			// member. Bind RA to that address so the sender does not auto-pick a
			// transient EUI-64 link-local which can later be removed by HA reconcile.
			// #17086 SSOT: the group comes from InterfaceRefRG/RefRG (via
			// RethRGOwners/declaresDeclaredDottedRG), so a member interface binds
			// its RETH's stable address and a stray group on a non-RETH binds
			// nothing.
			// #17049: only when the RA's own unit carries a placement under the
			// single placement definition (per-unit, FamilyInet6; a sibling
			// unit's placement does not install the address on this RA's netdev).
			if rg := cfg.RefRG(ra.Interface); rg != 0 {
				ra.SourceLinkLocal = stableRethLinkLocalForRA(cfg, ra.Interface, rg)
			}
		}
	}

	// Resolve interface names for RA senders (needs real Linux names).
	// ResolveKernelIfName maps a logical unit to its configured vlan-id for
	// the kernel VLAN sub-interface suffix (reth0.80 with `vlan-id 180` →
	// member.180), whereas the old LinuxIfName(ResolveReth(...)) preserved the
	// UNIT number as the suffix (member.80) and bound RA to a netdev that does
	// not exist. It also keeps the resolved name consistent with
	// rethInterfacesForRG (which already suffixes by unit.VlanID), so the
	// cluster RA ownership match in desiredClusterRA does not drop the sender
	// when unit# != vlan-id (#5107).
	for _, ra := range result {
		ra.Interface = cfg.ResolveKernelIfName(ra.Interface)
	}

	return result
}

// resolveRASourceLinkLocal resolves the operator-configured IPv6 link-local
// source address for an RA interface, returning the base InterfaceConfig (used
// by the caller for the RETH stable-link-local fallback) and the link-local
// string ("" when none is configured).
//
// raInterface arrives in Junos form straight from
// `protocols router-advertisement interface <name>`. It may be a bare
// physical/RETH name ("reth1", "ge-0/0/2") OR unit-qualified ("reth0.50",
// "ge-0/0/2.50"). cfg.Interfaces.Interfaces is keyed by the BASE name with
// logical units under ifc.Units, so a unit-qualified RA name never matches the
// map directly — split the unit off first (this was the #2996 miss: the old
// lookup hit the map with the full unit-qualified string and only ever read
// Units[0]).
//
// Selection rule (must be deterministic across reconciles):
//   - unit-qualified ("base.N"): use the link-local configured on THAT unit.
//   - bare ("base"): scan units in ASCENDING unit-number order and use the
//     first (lowest-numbered) unit that carries a configured link-local. This
//     is byte-identical to the historical Units[0]-only lookup when unit 0
//     holds the link-local, and now also finds a link-local that lives only on
//     a higher unit.
//
// Within a single unit, the first link-local in Addresses order wins (matching
// the prior `break`-on-first-match behavior).
func resolveRASourceLinkLocal(cfg *config.Config, raInterface string) (*config.InterfaceConfig, string) {
	base, unitTok, hasUnit := strings.Cut(raInterface, ".")
	ifc, ok := cfg.Interfaces.Interfaces[base]
	if !ok || ifc == nil {
		return nil, ""
	}
	if hasUnit && unitTok != "" {
		// RA bound to a specific unit: prefer that unit's link-local only.
		if n, err := strconv.Atoi(unitTok); err == nil {
			if unit, ok := ifc.Units[n]; ok {
				return ifc, unitConfiguredLinkLocal(unit)
			}
		}
		return ifc, ""
	}
	// Bare interface: scan units lowest-first for a stable choice.
	nums := make([]int, 0, len(ifc.Units))
	for n := range ifc.Units {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		if ll := unitConfiguredLinkLocal(ifc.Units[n]); ll != "" {
			return ifc, ll
		}
	}
	return ifc, ""
}

// unitConfiguredLinkLocal returns the first configured IPv6 link-local unicast
// address (CIDR-stripped) on the unit, or "" when none is configured.
// Delegates to the single definition in pkg/config (#17049).
func unitConfiguredLinkLocal(unit *config.InterfaceUnit) string {
	return config.UnitConfiguredLinkLocal(unit)
}

// stableRethLinkLocalForRA returns the stable RETH link-local to bind as the
// RA source for raInterface, or "" when the RA's unit is not backed by the
// stable LL. rg is the RA ref's owning redundancy group, resolved by the
// caller from the config SSOT (Config.RefRG over RethRGOwners —
// #17086), never from a raw InterfaceConfig.RedundancyGroup read: a
// member ref carries its RETH's group, and a stray group on a non-RETH
// carries nothing. Eligibility itself comes from master's config SSOT
// (#17049): Config.StableRethLinkLocalPlacements(rg) already encodes the
// per-unit gate — UnitHasIPv6 (FamilyInet6 marker, DHCPv6/DHCPv6Client, or
// any IPv6 address), no explicitly configured link-local, and neither the
// interface nor the unit disabled. This helper only scopes that
// placement set to the RA's own unit: a unit-qualified ref
// ("reth0.50") binds only when a placement exists for THAT unit of an
// interface owning rg, so an RA on an IPv4-only, disabled, or
// configured-link-local unit does not bind the stable address merely
// because a sibling unit carries a placement — pkg/ra would bind an
// address never installed on the RA's netdev and every NDP listen on it
// would fail. A bare ref ("reth0") names no unit, so any placement on an
// interface owning rg binds. Negative or malformed unit suffixes are
// rejected outright (fail-safe: the sender auto-selects). The ref is
// parsed with SplitInterfaceUnitRef so a declared dotted base (#9821,
// e.g. `p.0`, owned via declaresDeclaredDottedRG in RethRGOwners) is not
// mis-cut into base `p` + unit 0. With no matching placement the sender
// falls back to its auto-selected link-local.
func stableRethLinkLocalForRA(cfg *config.Config, raInterface string, rg int) string {
	if cfg == nil || cfg.Chassis.Cluster == nil || rg <= 0 {
		return ""
	}
	placements := cfg.StableRethLinkLocalPlacements(rg)
	if len(placements) == 0 {
		return ""
	}
	split := cfg.SplitInterfaceUnitRef(raInterface)
	wantUnit := -1
	if split.HasUnit {
		n, err := strconv.Atoi(split.UnitTok)
		if err != nil || n < 0 {
			return "" // malformed/negative unit: fail-safe, sender auto-selects
		}
		wantUnit = n
	}
	// Placements are keyed by the OWNING interface (IfRef "base.unit"),
	// while the RA ref may name a member (its RedundantParent chain owns
	// rg) or the owner itself. Match the placement whose kernel netdev
	// equals the RA ref's resolved kernel name — the same device the
	// sender will bind — so member, owner, declared-dotted, and VLAN
	// (unit.VlanID) spellings agree without re-deriving ownership here.
	wantNetdev := cfg.ResolveKernelIfName(raInterface)
	for _, p := range placements {
		if wantUnit >= 0 && p.Unit != wantUnit {
			continue
		}
		if p.Netdev != wantNetdev {
			continue
		}
		return config.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, rg).String()
	}
	return ""
}

func cloneRAInterfaceConfig(src *config.RAInterfaceConfig) *config.RAInterfaceConfig {
	if src == nil {
		return nil
	}
	clone := *src
	if len(src.DNSServers) > 0 {
		clone.DNSServers = append([]string(nil), src.DNSServers...)
	}
	if len(src.Prefixes) > 0 {
		clone.Prefixes = make([]*config.RAPrefix, 0, len(src.Prefixes))
		for _, pfx := range src.Prefixes {
			if pfx == nil {
				clone.Prefixes = append(clone.Prefixes, nil)
				continue
			}
			pfxClone := *pfx
			clone.Prefixes = append(clone.Prefixes, &pfxClone)
		}
	}
	return &clone
}
