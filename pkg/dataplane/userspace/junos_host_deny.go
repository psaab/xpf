package userspace

import (
	"github.com/psaab/xpf/pkg/config"
)

// junos_host_deny.go adapts the config-level #4146 junos-host DENY projection
// (config.BuildJunosHostDenyProjection) into the JunosHostProgram shape the
// daemon codegen consumes. The projection SSOT lives entirely in pkg/config —
// it owns policies / address book / applications / schedulers / feed bindings,
// resolves the kernel-netdev iifname scope (config.JunosHostZoneIngressNetdevs,
// lifeline-excluded and free of any cross-zone-ambiguous shared parent), and is
// reused by the #4168 commit warning so the warning can never be suppressed for
// a deny that produced no kernel rule. This wrapper only forwards the already-
// resolved IngressNetdevs (the ZONE scope is always `iifname` — a daddr-derived
// zone scope under-/over-denies across zones, plan §3.2) and the rendered
// first-match rules (#9504). A rule may additionally carry a `daddr` predicate when the policy
// authored an explicit `match destination-address`; that NARROWS the deny on top
// of the iifname scope and never replaces it.
//
// The direct host-bound packet is delivered by the Linux kernel, so enforcement
// is Go-only in the nft `xpf_hostinbound` chain: no Rust, no shim, no verifier
// interaction.

// JunosHostProgram is one ingress zone's effective junos-host program,
// enriched with the kernel iifnames the daemon scopes each DROP rule by. Only
// representable programs that resolve to >=1 non-lifeline netdev AND emit >=1
// rule are returned.
type JunosHostProgram struct {
	Zone string
	// IngressIfnames is the sorted, de-duplicated set of kernel netdev names for
	// the zone's non-lifeline interfaces (physical, VLAN-subunit, and — for a
	// bondless-RETH VLAN whose frames arrive on the physical member — the parent
	// member netdev). Never a lifeline; never a netdev shared with another zone.
	IngressIfnames []string
	// RulesV4 / RulesV6 are the projected rules (config SSOT), each family in
	// first-match order.
	RulesV4 []config.JunosHostDenyRule
	RulesV6 []config.JunosHostDenyRule
	// CoarseAdmitsIKE / CoarseIdentResets / HasApplicationAnyDeny drive the
	// daemon's fine-eligible-L4 exemption rules ahead of an `application any`
	// drop (§6.6). CoarseAdmitsIKE / CoarseIdentResets are true iff the
	// corresponding netdev subset below is non-empty.
	CoarseAdmitsIKE       bool
	CoarseIdentResets     bool
	HasApplicationAnyDeny bool
	// IKEExemptNetdevs / IdentResetNetdevs are the SUBSET of IngressIfnames whose
	// effective per-interface host-inbound set admits IKE / RSTs ident (#5565).
	// The daemon scopes the IKE / ident exemption shield to these netdevs, so a
	// per-interface `ike`/`ident-reset` override never widens to a sibling
	// interface in the same zone. A zone-level exception yields the full
	// IngressIfnames set (zone-wide, no regression). Sorted subsets.
	IKEExemptNetdevs  []string
	IdentResetNetdevs []string
}

// BuildJunosHostPrograms returns the per-ingress-zone junos-host programs
// the daemon renders into the kernel `xpf_hostinbound` chain. It calls the
// config projection for the representable first-match rules and resolves the
// iifname scope from the live interface snapshots. A representable program that
// resolves to no non-lifeline netdev (lifeline-only, or a freshly-renamed
// interface not yet in the snapshot) is dropped — it emits nothing and the
// #4168 warning stays (the config projection already keeps the warning for such
// a zone because it never lands in RenderedPolicyKeys without a rendered rule).
func BuildJunosHostPrograms(cfg *config.Config) []JunosHostProgram {
	proj := config.BuildJunosHostDenyProjection(cfg)
	if len(proj.Programs) == 0 {
		return nil
	}
	var out []JunosHostProgram
	for _, p := range proj.Programs {
		if !p.Representable {
			continue
		}
		if len(p.RulesV4) == 0 && len(p.RulesV6) == 0 {
			continue
		}
		// IngressNetdevs is the config-computed iifname scope
		// (config.JunosHostZoneIngressNetdevs): lifeline-excluded and free of any
		// cross-zone-ambiguous shared parent. A representable program that
		// resolves to no netdev emits nothing (and its config projection kept the
		// #4168 warning — the two agree by construction on this SSOT).
		if len(p.IngressNetdevs) == 0 {
			continue
		}
		out = append(out, JunosHostProgram{
			Zone:                  p.Zone,
			IngressIfnames:        p.IngressNetdevs,
			RulesV4:               p.RulesV4,
			RulesV6:               p.RulesV6,
			CoarseAdmitsIKE:       p.CoarseAdmitsIKE,
			CoarseIdentResets:     p.CoarseIdentResets,
			HasApplicationAnyDeny: p.HasApplicationAnyDeny,
			IKEExemptNetdevs:      p.IKEExemptNetdevs,
			IdentResetNetdevs:     p.IdentResetNetdevs,
		})
	}
	return out
}
