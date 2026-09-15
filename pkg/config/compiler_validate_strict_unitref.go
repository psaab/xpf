package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateInterfaceUnitReferencesStrict hard-rejects a cross-subsystem interface
// reference whose `.<unit>` suffix is not a valid logical unit — the residual
// #5829 deferred to #5933.
//
// #5829/#5932 typed the `interfaces <if> unit <n>` INSTANCE key (schema
// keyValidator ValidateLogicalUnit + a compiler defense-in-depth) so a
// non-numeric / negative / out-of-range logical unit is rejected at commit
// instead of silently dropping the whole unit — a unit-level firewall filter had
// been committing with no enforcement (fail-open). But the cross-subsystem
// interface REFERENCES that carry a `.unit` SUFFIX still parsed the suffix
// WITHOUT ValidateLogicalUnit:
//
//   - class-of-service interfaces <if>.<unit>                    (CoS shaper/classifier binding)
//   - security zones security-zone <z> interfaces <if>.<unit>   (zone membership)
//   - routing-instances <ri> interface <if>.<unit>              (VRF membership / route-leak)
//
// None of these fail-open a firewall FILTER (filters bind only inside the now-
// gated `interfaces <if> unit <n>` loop of compiler_interfaces.go — confirmed in
// the #5932 review), so materiality is lower than #5829's core. But a malformed
// `.unit` suffix here silently MIS-BINDS: the CoS shaper never attaches to a real
// unit, a zone-membership key never matches a configured unit
// (buildInterfaceZoneMap), and the routing-instance route-leak member is dropped
// (strings.Cut + strconv.Atoi -> continue in compiler_routing.go) — the operator
// sees a committed reference that carries no effect. Route every `.unit` suffix
// through the SAME canonical ValidateLogicalUnit so a malformed unit is rejected
// at commit consistently across subsystems.
//
// The suffix is split the SAME way each subsystem's runtime splits the reference
// (strings.Cut on the FIRST "."), so schema acceptance matches runtime binding
// exactly. A BARE interface (no ".") or a trailing-dot form ("base." — which the
// runtime treats as bare, see zoneIfaceLogicalKeys in
// compiler_validate_strict_zones.go) carries no specific unit and is skipped.
// References are visited in a deterministic (sorted) order so commit-check
// surfaces a STABLE first-error message.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (flag lenientInterfaceUnitRef) so an already-persisted or peer-synced config
// that an older binary accepted still BOOTS (#1960 fail-closed-on-load doctrine;
// the runtime already ignores an unresolvable `.unit` suffix, so a leniently-
// loaded malformed reference is inert — the shaper/zone-member/route-leak simply
// does not bind, exactly as before this gate, now with an operator-visible
// warning). Mirrors the sibling strict gates in compiler_validate_strict_zones.go.
func validateInterfaceUnitReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	// checkRef validates one interface reference's OPTIONAL ".unit" suffix. ctx
	// names the subsystem + scope so the operator error is actionable. cosArm
	// selects the legacy first-dot suffix: CoS binders key exact declared names
	// with nested `unit` children and never fold dotted unit refs, so the CoS
	// arm keeps legacy acceptance (a double-dot CoS key still rejects) while
	// the RI and zone arms — whose binders moved to the split — validate the
	// split suffix (#9821).
	checkRef := func(ctx, ref string, cosArm bool) error {
		s := cfg.SplitInterfaceUnitRef(ref)
		if !s.HasUnit {
			return nil // bare interface (declared or not) — no unit slot
		}
		unitTok := s.UnitTok
		if cosArm {
			_, unitTok, _ = strings.Cut(ref, ".")
		}
		if unitTok == "" {
			return nil // trailing-dot bare form — no unit slot
		}
		if err := ValidateLogicalUnit(unitTok, cfg); err != nil {
			return fmt.Errorf("%s interface reference %q has invalid logical unit %q: %w",
				ctx, ref, unitTok, err)
		}
		return nil
	}

	// (1) class-of-service interfaces <if>.<unit> — the CoS shaper/classifier
	// binding. The interface reference is the map KEY, which carries the `.unit`
	// suffix inline (e.g. "ge-0/0/0.0").
	if cfg.ClassOfService != nil {
		names := make([]string, 0, len(cfg.ClassOfService.Interfaces))
		for name := range cfg.ClassOfService.Interfaces {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := checkRef("class-of-service interfaces", name, true); err != nil {
				return err
			}
		}
	}

	// (2) security zones security-zone <z> interfaces <if>.<unit> — zone
	// membership. Zones are visited in sorted order; each zone's Interfaces slice
	// is in stable config order.
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == "" {
				continue
			}
			ctx := fmt.Sprintf("security zones security-zone %q", zoneName)
			if err := checkRef(ctx, iface, false); err != nil {
				return err
			}
		}
	}

	// (3) routing-instances <ri> interface <if>.<unit> — VRF membership /
	// route-leak. Routing instances are visited in stable config order.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		for _, iface := range ri.Interfaces {
			if iface == "" {
				continue
			}
			ctx := fmt.Sprintf("routing-instances %q", ri.Name)
			if err := checkRef(ctx, iface, false); err != nil {
				return err
			}
		}
	}

	return nil
}
