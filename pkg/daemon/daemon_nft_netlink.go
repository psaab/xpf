package daemon

// daemon_nft_netlink.go is the #6387 PR-3 CUTOVER: it wires the daemon's
// host-inbound / lo0 / cold-boot-fence / gap-fence installation and table
// teardown to the PR-2 pkg/nftables netlink Installer, dropping the exec-`nft`
// dependency. Production installs every ruleset through the google/nftables
// netlink API (invariant H9: the kernel nf_tables MODULE is still required, only
// the userspace `nft` BINARY is not). The exec-`nft` package vars nftApplyPayload
// / nftDeleteTable and the build*Payload text builders in daemon_nft.go are
// RETAINED as the parity-test ORACLE (the T1 CI proves netlink == exec-nft);
// production no longer feeds them.
//
// The converters below copy the daemon's dpuserspace views / junos-host programs
// / lo0 terms into the self-contained pkg/nftables input specs field-for-field.
// They were authored test-only by PR-2 (daemon_nft_netlink_parity_test.go) and
// are promoted here to production, unchanged, exactly as the PR-2 plan noted.

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// nftInstaller is the netlink host-inbound / lo0 / fence installer seam (#6387
// PR-3). Production installs every host-inbound / lo0 / cold-boot-fence /
// gap-fence ruleset AND every table teardown through the google/nftables netlink
// API, so a node needs only the kernel nf_tables MODULE — never the `nft` BINARY
// (the #6387 fw1 trap). It is a package var so the fail-closed regression tests
// inject an install/teardown failure through a fake Installer without a live
// kernel: this is the SINGLE failure-injection seam that replaces the pre-PR-3
// nftApplyPayload / nftDeleteTable stub seam (all five kernel-touching ops —
// real install, cold-boot fence, gap fence, lo0 install, table delete — share
// it, so a netlink install failure still fails the commit closed, invariant H7).
var nftInstaller xnft.Installer = xnft.NewNetlinkInstaller()

// nftProbeAvailable functionally probes whether the kernel nf_tables subsystem is
// usable (#6387 §12.5). It is a package var so tests can force "available" and
// keep the failure classification deterministic without opening a real netlink
// socket. In production it is the real functional probe (a benign netlink LIST
// that permits normal kernel autoload of a modular nf_tables).
var nftProbeAvailable = xnft.ProbeNFTablesAvailable

// nftUnavailableLogOnce guards the one-time DISTINCT "nf_tables subsystem
// unavailable" operator log (#6387 §12.5), so a persistent unavailability across
// repeated applies (commit / DHCP re-render) logs once rather than per apply.
var nftUnavailableLogOnce sync.Once

// tagNftInstallErr classifies a netlink install/teardown failure (#6387 §12.5).
// When the failure is because the kernel nf_tables subsystem is unavailable (the
// module is absent and not autoloadable), it emits a one-time DISTINCT operator
// log and wraps the error with ErrNFTablesUnavailable so BOTH the returned commit
// error AND the derived Config-Sync (CF) monitor-failure reason
// (cluster.Manager.SetConfigSyncHealth is fed applyErr.Error() by PR-1) name the
// TRUE cause instead of a generic per-ruleset apply error. It NEVER downgrades
// the fail-closed contract (invariant H7): the (possibly wrapped) error is always
// returned so the commit still fails closed; the probe only classifies WHY. A
// nil err returns nil.
func tagNftInstallErr(err error) error {
	if err == nil {
		return nil
	}
	if !nftSubsystemUnavailable(err) {
		return err
	}
	nftUnavailableLogOnce.Do(func() {
		slog.Error("nf_tables subsystem unavailable: the kernel nf_tables module is absent or not "+
			"autoloadable, so host-inbound / lo0 / fence rulesets cannot be installed via netlink — "+
			"the commit fails closed and Config-Sync reports a monitor-failure until the subsystem is "+
			"available (install/enable the nf_tables kernel module)", "err", err)
	})
	return fmt.Errorf("%w: %w", xnft.ErrNFTablesUnavailable, err)
}

// nftSubsystemUnavailable reports whether err (or a fresh functional probe)
// indicates the kernel nf_tables subsystem is unavailable. The netlink install
// error is generically wrapped, so on any failure a benign LIST probe classifies
// WHY: a genuine subsystem-absent verdict tags the error, while a per-ruleset
// kernel rejection (subsystem present) does not. The probe is a classification
// aid only — it NEVER masks or replaces the real failure.
func nftSubsystemUnavailable(err error) bool {
	if xnft.IsNFTablesUnavailable(err) {
		return true
	}
	return xnft.IsNFTablesUnavailable(nftProbeAvailable())
}

// --- converters (daemon/dpuserspace -> pkg/nftables spec) -------------------
//
// Promoted verbatim from the PR-2 parity test (daemon_nft_netlink_parity_test.go)
// per the plan §5.1/§12.4 "the field-copy PR-3 will promote to production". Each
// copies daemon values into the self-contained pkg/nftables input spec (declared
// in netlink_spec.go to avoid the dpuserspace<->nftables import cycle).

func toNftViews(views []dpuserspace.ZoneHostInboundView) []xnft.HostInboundZoneView {
	out := make([]xnft.HostInboundZoneView, 0, len(views))
	for _, v := range views {
		out = append(out, xnft.HostInboundZoneView{
			Zone:           v.Zone,
			SystemServices: v.SystemServices,
			Protocols:      v.Protocols,
			V4Addrs:        v.V4Addrs,
			V6Addrs:        v.V6Addrs,
			IngressNetdevs: v.IngressNetdevs,
		})
	}
	return out
}

func toNftHostInboundSpec(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, programs []dpuserspace.JunosHostProgram, wg []uint16) xnft.HostInboundSpec {
	spec := xnft.HostInboundSpec{
		Views:         toNftViews(views),
		UnzonedV4:     unzonedV4,
		UnzonedV6:     unzonedV6,
		WGListenPorts: wg,
	}
	for _, p := range programs {
		spec.Programs = append(spec.Programs, toNftProgram(p))
	}
	return spec
}

func toNftProgram(p dpuserspace.JunosHostProgram) xnft.JunosHostProgram {
	return xnft.JunosHostProgram{
		Zone:                  p.Zone,
		IngressIfnames:        p.IngressIfnames,
		RulesV4:               toNftDenyRules(p.RulesV4),
		RulesV6:               toNftDenyRules(p.RulesV6),
		CoarseAdmitsIKE:       p.CoarseAdmitsIKE,
		CoarseIdentResets:     p.CoarseIdentResets,
		HasApplicationAnyDeny: p.HasApplicationAnyDeny,
		IKEExemptNetdevs:      p.IKEExemptNetdevs,
		IdentResetNetdevs:     p.IdentResetNetdevs,
	}
}

func toNftDenyRules(rules []config.JunosHostDenyRule) []xnft.JunosHostDenyRule {
	out := make([]xnft.JunosHostDenyRule, 0, len(rules))
	for _, r := range rules {
		nr := xnft.JunosHostDenyRule{
			Family:         r.Family,
			SrcAny:         r.SrcAny,
			SrcExcluded:    r.SrcExcluded,
			Src:            r.Src,
			PermitSubtract: r.PermitSubtract,
			DstAny:         r.DstAny,
			DstExcluded:    r.DstExcluded,
			Dst:            r.Dst,
		}
		for _, l4 := range r.L4 {
			nr.L4 = append(nr.L4, xnft.JunosHostDenyL4{
				Proto:       l4.Proto,
				Ports:       toNftPortRanges(l4.Ports),
				SourcePorts: toNftPortRanges(l4.SourcePorts),
				ICMPType:    l4.ICMPType,
				ICMPCode:    l4.ICMPCode,
			})
		}
		out = append(out, nr)
	}
	return out
}

func toNftPortRanges(prs []config.PortRange) []xnft.PortRange {
	out := make([]xnft.PortRange, 0, len(prs))
	for _, pr := range prs {
		out = append(out, xnft.PortRange{Lo: pr.Lo, Hi: pr.Hi})
	}
	return out
}

func toNftLo0Spec(cfg *config.Config, filterV4, filterV6 string) xnft.Lo0FilterSpec {
	var spec xnft.Lo0FilterSpec
	pl := cfg.PolicyOptions.PrefixLists
	if filterV4 != "" {
		if f, ok := cfg.Firewall.FiltersInet[filterV4]; ok {
			for _, term := range f.Terms {
				spec.V4Terms = append(spec.V4Terms, toNftLo0Term(term, pl))
			}
		}
	}
	if filterV6 != "" {
		if f, ok := cfg.Firewall.FiltersInet6[filterV6]; ok {
			for _, term := range f.Terms {
				spec.V6Terms = append(spec.V6Terms, toNftLo0Term(term, pl))
			}
		}
	}
	return spec
}

func toNftLo0Term(term *config.FirewallFilterTerm, pl map[string]*config.PrefixList) xnft.Lo0FilterTerm {
	src, srcEx, srcC := dpuserspace.ResolveFilterPrefixListAddrs(
		term.SourceAddresses, term.SourcePrefixLists, pl, "", term.Name, "source", term.Action)
	dst, dstEx, dstC := dpuserspace.ResolveFilterPrefixListAddrs(
		term.DestAddresses, term.DestPrefixLists, pl, "", term.Name, "destination", term.Action)
	return xnft.Lo0FilterTerm{
		Name:              term.Name,
		SrcAddrs:          src,
		SrcExcept:         srcEx,
		SrcConstrained:    srcC,
		DstAddrs:          dst,
		DstExcept:         dstEx,
		DstConstrained:    dstC,
		Protocols:         term.Protocols,
		SourcePorts:       term.SourcePorts,
		DestinationPorts:  term.DestinationPorts,
		SourcePortsExcept: term.SourcePortsExcept,
		DestPortsExcept:   term.DestPortsExcept,
		DSCPs:             term.DSCPs,
		ICMPTypes:         term.ICMPTypes,
		ICMPCodes:         term.ICMPCodes,
		// #6806: ICMPTypes/ICMPCodes above are the RESOLVED bytes only, so an
		// unresolvable `from icmp-type` / `icmp-code` token vanishes at this
		// boundary unless its marker is carried too. Without these two lines the
		// mirror rendered the term with NO ICMP predicate — matching every ICMP
		// type in its scope — while the userspace mirror set the identically
		// named wire fields and failed the snapshot closed. Mirrors the
		// FlexMatchUnrepresentable line below (#6804).
		ICMPTypeUnrepresentable: len(term.UnknownICMPTypes) > 0,
		ICMPCodeUnrepresentable: len(term.UnknownICMPCodes) > 0,
		TCPFlags:                term.TCPFlags,
		// #6804: carry the flexible-match-range so the kernel mirror renders the
		// term's narrowing. Before this the spec had no field for it, so the
		// predicate was dropped at this boundary and the term rendered WIDER
		// than configured — a control-plane fail-open on the chain that is the
		// PRIMARY enforcement for host traffic.
		FlexMatch:                lo0FlexMatch(term.FlexMatch),
		FlexMatchUnrepresentable: len(term.FlexMatchRangeNames) > 1 || len(term.UnknownFlexMatch) > 0,
		IsFragment:               term.IsFragment,
		Log:                      term.Log,
		Count:                    term.Count,
		Action:                   term.Action,
		NextTerm:                 term.NextTerm,
		RoutingInstance:          term.RoutingInstance,
	}
}

// lo0FlexMatch converts a compiled flexible-match-range into the mirror's
// transport type (#6804). nil in, nil out: a term with no flex-match carries no
// predicate and must render exactly as before.
//
// The conversion is deliberately field-for-field with no interpretation — the
// byte width, the mask application and the endianness all live in the netlink
// builder, so the two renderers cannot disagree about what the same config
// means.
func lo0FlexMatch(fm *config.FlexMatchConfig) *xnft.Lo0FlexMatch {
	if fm == nil {
		return nil
	}
	return &xnft.Lo0FlexMatch{
		ByteOffset: fm.ByteOffset,
		BitLength:  fm.BitLength,
		Value:      fm.Value,
		Mask:       fm.Mask,
	}
}
