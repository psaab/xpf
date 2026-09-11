// redistribute.go converts a Junos routing export value into FRR
// `redistribute` commands, skipping-and-warning on anything that cannot
// resolve to a source protocol so one bad line never poisons the whole
// managed frr-reload (#1880/#2223).
//
// Split out of policy_render.go (#6424) as a pure code-motion refactor;
// the emitted frr.conf is byte-identical.
//
// Symbols:
//   - knownRedistProtocols
//   - resolveRedistribute
//   - isDefinedPolicyStatement
package frr

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// knownRedistProtocols are the FRR redistribute protocol keywords.
// ospf6 / ripng are the FRR keywords for OSPFv3 / RIPng redistribution;
// without them a bare `export ospf6` / `export ripng` falls through to the
// skip-and-warn path and IPv6 IGP redistribution cannot be expressed (#2943).
// #7121: the domain moved to config.FRRRoutingProtocolKeyword so the COMMIT
// gate can consult it. It lived here, where a commit-time validator could not
// reach it (pkg/frr imports pkg/config, not the reverse), which is why an
// unknown `from protocol` token committed clean and degraded the reload.
func knownRedistProtocol(name string) bool {
	return config.RoutingProtocolResolvable(name)
}

// resolveRedistribute converts a Junos export value into FRR redistribute commands.
// If the value is a known protocol name, it emits a bare "redistribute <proto>".
// If it matches a policy-statement, it extracts protocols from the terms and emits
// "redistribute <proto> route-map <name>" for each.
//
// Invariant: this never emits a syntactically-invalid `redistribute
// <name>` line. FRR's `redistribute` requires a source protocol token
// (connected/static/ospf/bgp/rip/isis/kernel); a bare policy-statement or
// typo name is rejected by FRR's parser. Because the line lands in the
// xpf-managed section, ONE rejected line fails the WHOLE reload, not just
// this stanza. frr-reload.py exits non-zero, and the additive `vtysh -f`
// fallback in reloadLocked applies every other line but also exits non-zero
// on that one: FRR stable/10.6 vtysh_config_from_file keeps going past a
// rejected line and returns its error. So the reload fails, and every retry
// re-reads the same file and fails the same way. What is lost is REMOVAL, not
// addition: a later commit that deletes a route, neighbour or policy leaves it
// live in FRR for as long as the bad line is rendered (#1880/#2223, #9510). So
// when an export cannot be resolved to a source protocol we SKIP it and warn
// rather than poison the managed reload.
//
// Two cases reach the skip-and-warn path:
//
//   - The export names a defined policy-statement, but none of its terms
//     carry a `from protocol` (e.g. it matches only from community /
//     prefix-list / as-path). This case PASSES the commit-time strict
//     validator, which checks only that the name is a known token OR a
//     defined policy-statement — it does NOT require a `from protocol`.
//     FRR's redistribute has no construct to express "redistribute
//     whatever this policy matches" without a source protocol, so there
//     is no valid line to emit.
//   - The export is neither a known protocol token nor a defined
//     policy-statement (a name that slipped past validation on a tolerant
//     load / peer-sync path, opts.lenientRoutingExportRef in pkg/config).
//     The strict validator REJECTS this case at commit; only the lenient
//     load/peer-sync path can reach the renderer with such a name.
//
// A source protocol can also be valid in general and still be rejected where
// the line lands. FRR's redistribute grammar is per address family, so
// `redistribute ospf6` under `router ospf` is rejected exactly like a typo
// (#9510). redistSourceFitsNode filters that on BOTH paths, at the use site,
// rather than rejecting the policy at commit: a policy-statement is reusable,
// and `from protocol ospf6` is valid under `router ospf6`.
func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig, self string, bgpAcceptDefault map[string]bool) string {
	// Junos spells directly-connected routes "direct"; FRR's redistribute
	// keyword is "connected". A bare `export direct` must render
	// `redistribute connected`, not the FRR-invalid `redistribute direct`
	// (which fails the reload). This mirrors the policy-term FromProtocols
	// normalization below and in generatePolicyOptions. The commit-time
	// gate (validateRoutingExportReferencesStrict, pkg/config) accepts
	// "direct" as a known token, so this keeps render and validation in
	// agreement (#2144).
	if export == "direct" {
		export = "connected"
	}
	if knownRedistProtocol(export) {
		// A protocol can never redistribute itself: FRR rejects
		// `redistribute ospf` under `router ospf` (etc.), and ONE
		// rejected line degrades the WHOLE managed reload (#1880/#2223).
		// Drop the self-redistribute rather than poison the section
		// (#2943). self is "" for callers with no enclosing protocol.
		if self != "" && export == self {
			slog.Warn("FRR redistribute export skipped: protocol cannot redistribute itself",
				"protocol", self)
			return ""
		}
		// #9510: the source must also be in a family the enclosing router's
		// redistribute grammar lists (redistribute_afi_9510.go).
		if !redistSourceFitsNode(export, self) {
			slog.Warn("FRR redistribute export skipped: source protocol is not in this router's address family",
				"protocol", self, "source", export)
			return ""
		}
		// #8597 (muse-004 K87): sanitized for PARITY, not because this site is
		// reachable with a dirty operand.
		//
		// This branch is gated by knownRedistProtocol above — an ALLOWLIST,
		// which is the stronger belt — so a control byte can never arrive here.
		// Measured: knownRedistProtocol("static\n x") is false. The belt is
		// here so the file has no unbelted `redistribute %s` interpolation for
		// a future audit to have to reason about, and so a future change that
		// widens the allowlist does not silently open the hole.
		//
		// The two-operand site below is the one that WAS reachable.
		return fmt.Sprintf(" redistribute %s\n", sanitizeFRRValue(export))
	}

	if po != nil && po.PolicyStatements != nil {
		if ps, ok := po.PolicyStatements[export]; ok {
			protocols := make(map[string]bool)
			skipped := false
			for _, term := range ps.Terms {
				for _, proto := range term.FromProtocols {
					if proto == "direct" {
						proto = "connected"
					}
					// Skip a policy term that matches the enclosing
					// protocol's own routes — `redistribute ospf
					// route-map X` under `router ospf` is self-
					// redistribution and FRR rejects it (#2943).
					if self != "" && proto == self {
						skipped = true
						continue
					}
					// #9510: a term whose source is outside the enclosing
					// router's address family is dropped here, at the use
					// site. The same policy stays valid under a router
					// whose grammar lists that source.
					if !redistSourceFitsNode(proto, self) {
						slog.Warn("FRR redistribute policy term skipped: source protocol is not in this router's address family",
							"policy", export, "protocol", self, "source", proto)
						skipped = true
						continue
					}
					protocols[proto] = true
				}
			}
			if len(protocols) > 0 {
				sorted := make([]string, 0, len(protocols))
				for p := range protocols {
					sorted = append(sorted, p)
				}
				sort.Strings(sorted)
				// #4481: if this policy is ALSO applied as a BGP route-map
				// in/out with no explicit default, its shared route-map carries
				// a trailing PERMIT (Junos BGP default-accept, #2998). That
				// permit must NOT govern the redistribute default (Junos
				// redistribute defaults to REJECT), so reference the fail-closed
				// per-use-site alias generatePolicyOptions emits for it.
				rmName := export
				if policyNeedsRedistAlias(export, ps, bgpAcceptDefault) {
					rmName = redistFailClosedRouteMap(export)
				}
				var sb strings.Builder
				for _, proto := range sorted {
					// #8597 (muse-004 K87): both operands are RAW CONFIG
					// STRINGS — `proto` comes from term.FromProtocols and
					// `rmName` from the policy name — and both reached frr.conf
					// with no belt and no allowlist. Measured before the fix:
					//
					//	proto  "static\n line two"
					//	  -> " redistribute static\n line two route-map exp\n"
					//	rmName "exp\nrouter bgp 65000"
					//	  -> " redistribute static route-map exp\nrouter bgp 65000\n"
					//
					// Each injects a second frr.conf statement. Every other operand interpolation in this
					// package goes through sanitizeFRRValue (bfd.go,
					// config_render.go, prefix_list_render.go); these two were
					// missed, so an audit using the #4482 inventory to ask "are
					// all FRR interpolations belted" would answer yes and stop.
					//
					// sanitizeFRRValue maps control bytes to a space, which is
					// the sink's own separator — the weaker belt this package's
					// README describes under #6796. It is applied here for
					// PARITY, not because it is the strongest available check:
					// a protocol allowlist would be stronger, and is a separate
					// change with its own over-rejection question. What this
					// closes is a newline or NUL splitting one statement into
					// two.
					fmt.Fprintf(&sb, " redistribute %s route-map %s\n",
						sanitizeFRRValue(proto), frrName(rmName))
				}
				return sb.String()
			}
			if skipped {
				// Every `from protocol` was filtered above, as self or as
				// another address family. "has no `from protocol`" would send
				// the operator looking for a term that already exists.
				slog.Warn("FRR redistribute export skipped: no `from protocol` in the policy-statement applies under this router",
					"policy", export, "protocol", self)
				return ""
			}
			// Defined policy-statement with no resolvable source protocol:
			// nothing valid to redistribute. Skip + warn rather than emit
			// the FRR-invalid `redistribute <policy>` that would degrade the
			// managed-section reload (#2223).
			slog.Warn("FRR redistribute export skipped: policy-statement has no `from protocol`",
				"policy", export,
				"hint", "redistribute requires a source protocol; add `from protocol <proto>` to the policy or use a bare protocol token")
			return ""
		}
	}

	// Unknown token: neither a known protocol nor a defined policy-statement
	// (a name that slipped past the strict validator on a tolerant load /
	// peer-sync path). Never emit a bare `redistribute <name>` — it has no
	// valid source protocol and would be rejected by frr-reload, degrading
	// the entire managed reload (#2223).
	slog.Warn("FRR redistribute export skipped: not a known protocol or defined policy-statement",
		"export", export,
		"hint", "use a known protocol (connected/static/ospf/bgp/rip/isis/kernel) or a defined policy-statement with a `from protocol`")
	return ""
}

// isDefinedPolicyStatement reports whether name resolves to a defined
// policy-statement in policyOptions. This is the SAME predicate the
// commit-time validator uses (checkRedist/checkPolicyRef in
// pkg/config/compiler_validate_strict.go) to distinguish a route-map-out
// reference from a bare redistribute protocol token. A defined
// policy-statement renders as `route-map <name> out`; anything else (a
// bare protocol token, or a typo that slipped past the strict validator on
// a lenient load/HA-sync path) goes to resolveRedistribute.
func isDefinedPolicyStatement(name string, po *config.PolicyOptionsConfig) bool {
	if po == nil || po.PolicyStatements == nil {
		return false
	}
	_, ok := po.PolicyStatements[name]
	return ok
}
