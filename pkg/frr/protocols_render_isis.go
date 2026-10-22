// protocols_render_isis.go renders the IS-IS stanza of
// generateProtocolsCluster15158 (#16125 verbatim extraction).
//
// The body below is the contiguous `if isis != nil` subtree moved
// verbatim out of generateProtocolsCluster15158, including the
// deliberate auth precompute that runs before any stanza emission;
// output ordering, the shared BFD accumulator and every fail-closed
// auth belt are unchanged.

package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderISIS16125 renders the `router isis xpf` stanza and its
// per-interface blocks into b. Moved verbatim from
// generateProtocolsCluster15158 (#16125); bfd is the shared BFD
// accumulator owned by the caller.
func (m *Manager) renderISIS16125(b *strings.Builder, isis *config.ISISConfig, vrfSuffix string, policyOptions *config.PolicyOptionsConfig, clusterMode bool, qnhMetrics *qnhMetricScope11447, bfd *bfdSection) {
	if isis != nil {
		// #14977 (D33-05): pre-validate IS-IS authentication BEFORE
		// emitting the router stanza or any interface activation, the
		// way #14388 pre-validates OSPF MD5. #14399 only warned when a
		// type had no key, and the #9050 belt only omitted the password
		// line when a key was unrenderable — both left `router isis`
		// and `ip router isis` active with zero passwords: an
		// unauthenticated adjacency. An unrecognized type carrying a
		// key silently downgraded to plaintext (#8443's render arm,
		// superseded here as at the RIP site). Fail closed on the
		// enclosing capability:
		//   - global auth unusable -> omit the whole IS-IS stanza
		//     (router + every interface activation);
		//   - one interface's auth unusable -> omit only that
		//     interface; healthy siblings and a healthy global
		//     password still render byte-identically.
		// Absent type + key keeps the #9105 plaintext render, and the
		// no-auth-at-all shape is untouched.
		isisGlobalAuthBad14977 := false
		var isisGlobalTok14977 string
		if isis.AuthKey.Reveal() == "" && !config.AuthTypeAbsent(isis.AuthType) {
			isisGlobalAuthBad14977 = true
		}
		if isis.AuthKey.Reveal() != "" {
			if config.AuthTypeUnrecognized(isis.AuthType) {
				isisGlobalAuthBad14977 = true
			} else if tok, ok := authTokenOrOmit("isis-global", &isis.AuthKey); ok {
				isisGlobalTok14977 = tok
			} else {
				isisGlobalAuthBad14977 = true
			}
		}
		isisIfaceAuthBad14977 := make(map[string]bool, len(isis.Interfaces))
		isisIfaceTok14977 := make(map[string]string, len(isis.Interfaces))
		for _, iface := range isis.Interfaces {
			if iface == nil {
				continue
			}
			bad := false
			if iface.AuthKey.Reveal() == "" && !config.AuthTypeAbsent(iface.AuthType) {
				bad = true
			}
			if iface.AuthKey.Reveal() != "" {
				if config.AuthTypeUnrecognized(iface.AuthType) {
					bad = true
				} else if tok, ok := authTokenOrOmit("isis-interface", &iface.AuthKey); ok {
					isisIfaceTok14977[iface.Name] = tok
				} else {
					bad = true
				}
			}
			if bad {
				isisIfaceAuthBad14977[iface.Name] = true
			}
		}
		if isisGlobalAuthBad14977 {
			slog.Warn("frr: omitting the IS-IS stanza; its authentication cannot be rendered — "+
				"refusing to activate IS-IS unauthenticated (#14977)",
				"authentication_type", sanitizeFRRValue(isis.AuthType))
		}
		isisRender14977 := !isisGlobalAuthBad14977
		if isisRender14977 {
			fmt.Fprintf(b, "router isis xpf%s\n", vrfSuffix)
			// #9493: the NET was rendered verbatim, spaces and all.
			if isis.NET != "" {
				if config.ValidISISNET(isis.NET) {
					fmt.Fprintf(b, " net %s\n", isis.NET)
				} else {
					slog.Warn("frr: omitting a malformed IS-IS NET (#9493)", "net", sanitizeFRRValue(isis.NET))
				}
			}
			// #8446: canonicalize through the SHARED predicate the commit gate
			// uses (config.CanonicalISISLevel) rather than switching on the raw
			// stored string. This switch previously had no `default` arm, so a
			// value outside the three it named emitted NO is-type line and FRR
			// silently fell back to its own default, level-1-2 — WIDENING the
			// router's adjacency scope. `level-2-only` (the spelling emitted
			// three lines below) hit that path, so feeding our own output back
			// in turned a Level-2-only router into a Level-1-2 one.
			//
			// The strict commit gate rejects a non-canonical value, but the
			// tolerant Load / peer-sync paths only warn (#1960 no-brick), so the
			// renderer keeps its own belt: an unrecognized value renders the
			// SAFE default rather than nothing. Narrower than authored is a
			// recoverable misconfiguration; wider than authored is a silent
			// security regression. Same shape as the #6686 as-path belt.
			level, ok := config.CanonicalISISLevel(isis.Level)
			if !ok {
				level = config.DefaultISISLevel
			}
			switch level {
			case "level-1":
				b.WriteString(" is-type level-1\n")
			case "level-1-2":
				b.WriteString(" is-type level-1-2\n")
			default:
				// level-2 and every unrecognized value: the narrow default.
				b.WriteString(" is-type level-2-only\n")
			}
			// #9666: isisd's grammar, not the OSPF-shaped line. #15156: chain-composed.
			b.WriteString(m.resolveISISRedistributeChainCluster15158(isis.Export, policyOptions, isis.Level, clusterMode, qnhMetricScopeForDaemon11447(qnhMetrics, "isis")))
			if isis.WideMetricsOnly {
				b.WriteString(" metric-style wide\n")
			}
			if isis.Overload {
				b.WriteString(" set-overload-bit\n")
			}
			// #14399/#14977: authentication-type with NO key renders
			// UNAUTHENTICATED. The strict gate rejects new instances; a
			// config arriving via tolerant load / peer sync now fails
			// closed above (isisGlobalAuthBad14977) instead of only
			// warning here. This warning is unreachable for that shape.
			if isis.AuthKey.Reveal() == "" && !config.AuthTypeAbsent(isis.AuthType) {
				slog.Warn("frr: isis authentication-type is set with NO authentication-key; "+
					"rendering UNAUTHENTICATED -- no area/domain password is emitted. Set "+
					"authentication-key to authenticate (#14399)",
					"authentication_type", isis.AuthType)
			}
			if isis.AuthKey.Reveal() != "" {
				// #9105: an ABSENT type is not `unrecognized`, so this warning could not
				// fire for it -- and it renders the key in CLEARTEXT exactly as a
				// chosen `simple` does. Warn on both: the commit gate stops every NEW
				// instance, this tells the operator about an existing one arriving
				// through the tolerant load path. An unrecognized type no longer
				// reaches here (#14977 omits the stanza above).
				if config.AuthTypeAbsent(isis.AuthType) {
					slog.Warn("frr: isis authentication-key is set with NO authentication-type; "+
						"rendering PLAINTEXT -- the key travels in clear in every PDU. Set "+
						"authentication-type md5 to authenticate with a digest (#9105)",
						"accepted", config.AuthTypeSpellings())
				}
				if config.AuthTypeIsMD5(isis.AuthType) {
					fmt.Fprintf(b, " area-password md5 %s\n", isisGlobalTok14977)
					fmt.Fprintf(b, " domain-password md5 %s\n", isisGlobalTok14977)
				} else {
					fmt.Fprintf(b, " area-password clear %s\n", isisGlobalTok14977)
					fmt.Fprintf(b, " domain-password clear %s\n", isisGlobalTok14977)
				}
			}
			b.WriteString("exit\n!\n")
		} // isisRender14977 (global stanza)
		if isisRender14977 {
			for _, iface := range isis.Interfaces {
				if iface == nil {
					continue
				}
				if isisIfaceAuthBad14977[iface.Name] {
					slog.Warn("frr: omitting IS-IS interface; its authentication cannot be rendered — "+
						"refusing to activate it unauthenticated (#14977)",
						"interface", sanitizeFRRValue(iface.Name), "authentication_type", sanitizeFRRValue(iface.AuthType))
					continue
				}
				fmt.Fprintf(b, "interface %s\n", iface.Name)
				fmt.Fprintf(b, " ip router isis xpf\n")
				// #8450: enable the IPv6 topology too. Only `ip router isis` was
				// emitted, so isisd ran IPv4-only on every interface and IS-IS
				// learned and advertised NO IPv6 routes — on a dual-stack product,
				// with the compiler happily accepting IS-IS on dual-stack
				// interfaces and knownRedistProtocols extended for IPv6 IGPs
				// (#2943). FRR itself enables both address families for a
				// configured `router isis`, so emitting both matches its defaults;
				// on an interface with no IPv6 address there is nothing to
				// advertise and the line is inert.
				fmt.Fprintf(b, " ipv6 router isis xpf\n")
				// #8450: the per-interface circuit type. ISISInterface.Level was
				// compiled and stored and then never rendered, so an interface an
				// operator restricted to one level kept forming adjacencies at the
				// ROUTER-WIDE is-type — dead config that fails OPEN. An empty value
				// renders no line, which is the correct "inherit the router-wide
				// is-type" behaviour in both FRR and Junos. An unrecognised value
				// also renders no line rather than a broken one: the strict commit
				// gate rejects it, and on the tolerant Load / peer-sync path
				// (#1960) an omitted circuit-type is the pre-#8450 behaviour, which
				// is recoverable, where an invalid `isis circuit-type <junk>` line
				// would fail the WHOLE frr-reload (#1880/#2223).
				if ct, ok := config.CanonicalISISCircuitType(iface.Level); ok && ct != "" {
					fmt.Fprintf(b, " isis circuit-type %s\n", ct)
				}
				if iface.Passive {
					b.WriteString(" isis passive\n")
				}
				if iface.Metric < 0 || iface.Metric > config.MaxISISMetric {
					slog.Warn("frr: omitting invalid IS-IS interface metric (#11823)",
						"interface", sanitizeFRRValue(iface.Name), "metric", iface.Metric)
				} else if iface.Metric > 0 {
					fmt.Fprintf(b, " isis metric %d\n", iface.Metric)
				}
				// #14399/#14977: per-interface type with NO key renders
				// UNAUTHENTICATED (see the area/domain belt above); that
				// shape is now omitted before this loop (#14977), so this
				// warning is unreachable for it.
				if iface.AuthKey.Reveal() == "" && !config.AuthTypeAbsent(iface.AuthType) {
					slog.Warn("frr: isis interface authentication-type is set with NO authentication-key; "+
						"rendering UNAUTHENTICATED -- no interface password is emitted. Set "+
						"authentication-key to authenticate (#14399)",
						"interface", iface.Name, "authentication_type", iface.AuthType)
				}
				if iface.AuthKey.Reveal() != "" {
					// #9105: an ABSENT type is not `unrecognized`, so this warning could not
					// fire for it -- and it renders the key in CLEARTEXT exactly as a
					// chosen `simple` does. Warn on both: the commit gate stops every NEW
					// instance, this tells the operator about an existing one arriving
					// through the tolerant load path. An unrecognized type no
					// longer reaches here (#14977 omits the interface above).
					if config.AuthTypeAbsent(iface.AuthType) {
						slog.Warn("frr: isis interface authentication-key is set with NO authentication-type; "+
							"rendering PLAINTEXT -- the key travels in clear in every PDU. Set "+
							"authentication-type md5 to authenticate with a digest (#9105)",
							"accepted", config.AuthTypeSpellings())
					}
					// #9496: the per-interface pair goes through the same #9050 belt as
					// every other routing-auth site. sanitizeFRRValue maps a TAB into a
					// splitter and passes a space through, so a whitespace secret arriving
					// via a tolerant load, peer sync or rollback rendered a splittable line.
					// #14977: emit only the token pre-validated before the loop.
					if config.AuthTypeIsMD5(iface.AuthType) {
						fmt.Fprintf(b, " isis password md5 %s\n", isisIfaceTok14977[iface.Name])
					} else {
						fmt.Fprintf(b, " isis password clear %s\n", isisIfaceTok14977[iface.Name])
					}
				}
				// `isis bfd` / `isis bfd profile <name>` are interface-scoped
				// commands and MUST be emitted INSIDE the interface block,
				// before `exit`. Emitting them after `exit` lands them at
				// global config scope, which vtysh rejects — and one rejected
				// line fails the WHOLE managed-section reload (#1880/#2223),
				// breaking every IS-IS interface with BFD enabled. This mirrors
				// the OSPFv3 per-interface BFD ordering above (#2942).
				if iface.BFD {
					if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
						profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
						bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
						// #15015: `isis bfd profile` alone does NOT
						// enable BFD in FRR 10.6 — it only sets the
						// bfd-monitoring/profile leaf; the enabled leaf
						// is set solely by `isis bfd`, and adjacency
						// setup skips circuits with enabled=false.
						// Emit the bare enable first (mirrors
						// cli_show_ip_isis_bfd_monitoring's order).
						b.WriteString(" isis bfd\n")
						fmt.Fprintf(b, " isis bfd profile %s\n", profile)
					} else {
						b.WriteString(" isis bfd\n")
					}
				}
				b.WriteString("exit\n!\n")
			}
		} // isisRender14977 (interfaces)
	}
}
