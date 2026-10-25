// protocols_render_rip.go renders the RIP stanza of
// generateProtocolsCluster15158 (#16125 verbatim extraction).
//
// The body below is the contiguous `if rip != nil` subtree moved
// verbatim out of generateProtocolsCluster15158; output ordering
// and every fail-closed auth belt are unchanged.

package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderRIP16125 renders the `router rip` stanza and its
// per-interface authentication blocks into b. Moved verbatim from
// generateProtocolsCluster15158 (#16125).
func (m *Manager) renderRIP16125(b *strings.Builder, rip *config.RIPConfig, vrfSuffix string, policyOptions *config.PolicyOptionsConfig, clusterMode bool, qnhMetrics *qnhMetricScope11447) {
	// #16572: `protocols rip disable` renders nothing at all.
	if rip != nil && rip.Disable {
		return
	}
	if rip != nil {
		// #14398: a non-absent `authentication-type` with NO
		// `authentication-key` must never render as a silent no-auth RIP
		// block. The strict gate rejects it at commit; on the tolerant
		// path (#1960 — a persisted config must still boot) fail closed
		// by NOT enrolling any interface in RIP: emitting `router rip` +
		// `network <iface>` with zero auth lines is exactly the silent
		// unauthenticated adjacency the gate exists to prevent. Warn
		// loudly; do NOT emit a keyless auth line (FRR behaviour for a
		// keyless mode line is not established, and a rejected line
		// would fail the whole managed-section reload).
		//
		// #14977 (D33-05): the same fail-closed rule covers the two
		// shapes #14398 missed. (a) A non-empty key that is not a
		// single vtysh token: previously every interface was enrolled
		// and `ip rip authentication mode` rendered with NO string.
		// (b) An UNRECOGNIZED type carrying a key: #8443 deliberately
		// kept rendering it as plaintext (the recorded rationale is
		// adjacency-flap avoidance on upgrade), but that leaves a
		// silently DOWNGRADED adjacency — the operator's `show
		// configuration` still claims the type they typed. #14977
		// supersedes the render arm of that choice: fail closed and
		// say so. Absent type + key keeps its #9105 plaintext render
		// (a chosen plaintext and an absent type remain
		// indistinguishable, and flipping it would flap adjacencies
		// that never claimed a type); keyed md5/simple/text and the
		// neither-leaf shape are byte-unchanged.
		ripKeylessAuth14398 := !config.AuthTypeAbsent(rip.AuthType) && rip.AuthKey.Reveal() == ""
		if ripKeylessAuth14398 {
			slog.Warn("frr: rip authentication-type is set with NO authentication-key; "+
				"NOT enrolling any interface in RIP rather than rendering unauthenticated RIP. "+
				"Set authentication-key to provide the key (#14398)",
				"authentication_type", rip.AuthType)
		}
		ripAuthTok14977, ripAuthTokOK14977 := "", true
		if rip.AuthKey.Reveal() != "" {
			ripAuthTok14977, ripAuthTokOK14977 = authTokenOrOmit("rip", &rip.AuthKey)
		}
		ripUnrecognized14977 := rip.AuthKey.Reveal() != "" && config.AuthTypeUnrecognized(rip.AuthType)
		// #15013 (A12-01): an over-long key (>16 characters) is
		// rejected by ripd on EVERY frr-reload, so emitting it would
		// brick the reload forever. Fail closed exactly like the
		// unrenderable-token arm: omit RIP enrollment entirely
		ripResolvedKey15990, ripResolvedOK15990 := "", true
		if rip.AuthKey.Reveal() != "" {
			ripResolvedKey15990, ripResolvedOK15990 = resolvedAuthSecret(&rip.AuthKey)
		}
		ripKeyTooLong15013 := rip.AuthKey.Reveal() != "" && ripResolvedOK15990 && len([]rune(ripResolvedKey15990)) > config.MaxRIPAuthKeyLen
		if ripKeyTooLong15013 {
			slog.Warn("frr: rip authentication-key exceeds the 16-character maximum accepted by ripd; "+
				"NOT enrolling any interface in RIP rather than rendering a line ripd rejects on every reload (#15013)",
				"key_len", len([]rune(ripResolvedKey15990)), "max", config.MaxRIPAuthKeyLen)
		}
		ripFailClosed14977 := ripKeylessAuth14398 || !ripAuthTokOK14977 || ripUnrecognized14977 || ripKeyTooLong15013
		if !ripAuthTokOK14977 {
			slog.Warn("frr: rip authentication-key is not renderable as a single vtysh token; "+
				"NOT enrolling any interface in RIP rather than rendering unauthenticated RIP (#14977)",
				"authentication_type", rip.AuthType)
		}
		if ripUnrecognized14977 {
			slog.Warn("frr: unrecognized rip authentication-type; "+
				"NOT enrolling any interface in RIP rather than silently downgrading to plaintext (#14977)",
				"authentication_type", rip.AuthType, "accepted", config.AuthTypeSpellings())
		}
		if ripFailClosed14977 {
			// Fail closed on the enclosing capability: no `router rip`
			// enrollment and no per-interface auth block at all.
		} else {
			// #16625: per-group export. When Groups is present,
			// render per-interface outbound filtering instead of
			// one global redistribute chain (which leaked/lossed
			// per-group policy). Contested interfaces (in 2+
			// groups with differing exports — strict-rejected,
			// lenient-warned) are withheld entirely: fail closed.
			contested16625 := make(map[string]bool)
			for _, iface := range config.RIPContestedInterfaces16625(rip) {
				contested16625[iface] = true
				slog.Warn("frr: rip interface in multiple groups with different exports; NOT enrolling it rather than leaking one group's routes to another (#16625)",
					"interface", iface)
			}
			enrolled16625 := make([]string, 0, len(rip.Interfaces))
			for _, iface := range rip.Interfaces {
				if contested16625[iface] {
					continue
				}
				enrolled16625 = append(enrolled16625, iface)
			}
			// Any enrolled interface at all? If every interface is
			// contested, emit no router rip stanza (mirrors the
			// auth fail-closed shape) rather than an empty one.
			if len(rip.Interfaces) > 0 && len(enrolled16625) == 0 && len(rip.Groups) > 0 {
				// fail closed: nothing safe to enroll
			} else {
				// #16866: the per-interface outbound gate applies
				// to EVERY RIP render, grouped or not. ripd's
				// `network <if>` originates connected subnets and
				// re-advertises RIP-learned routes outside the
				// redistribute route-maps; Junos advertises
				// neither without an export policy that accepts
				// them. Group-less renders synthesize one implicit
				// group carrying the Redistribute chain (bare
				// tokens / undefined names are inexpressible and
				// render deny-all), so no enrolled interface is
				// ever left ungated.
				ripForRender16866 := rip
				if len(rip.Groups) == 0 && len(enrolled16625) > 0 {
					synth := *rip
					synth.Groups = []*config.RIPGroup{{Name: "xpf-implicit-16866", Interfaces: append([]string(nil), enrolled16625...), Export: append([]string(nil), rip.Redistribute...)}}
					ripForRender16866 = &synth
				}
				ripDefs16866, ripBody16866 := m.renderRIPPerGroup16625(ripForRender16866, enrolled16625, policyOptions, clusterMode, qnhMetrics, m.nextRIPGroupIndex16625())
				b.WriteString(ripDefs16866)
				fmt.Fprintf(b, "router rip%s\n", vrfSuffix)
				// #16620: pin RIP to the Junos RIP preference 100; see
				// protocol_distance_16620.go.
				b.WriteString(junosRIPDistanceLine)
				for _, iface := range enrolled16625 {
					fmt.Fprintf(b, " network %s\n", iface)
				}
				for _, iface := range rip.Passive {
					if contested16625[iface] {
						continue
					}
					fmt.Fprintf(b, " passive-interface %s\n", iface)
				}
				b.WriteString(ripBody16866)
				// #12531: restore per-QNH RIP metrics with ripd-native
				// offset-lists. ripd ignores route-map set metric for
				// redistributed statics (live FRR 10.7.1: map readback had
				// metric 7, RIP database and RIPv2 wire stayed at 1), and
				// no daemon-scoped load confines a route-map action to
				// ripd. The offset-list lives only in this router rip
				// stanza, matches the QNH destination via its generated
				// access-list, and adds metric-1 so the advertised metric
				// equals the configured QNH metric (clamped to 16).
				// NOTE (#16625): QNH offset-lists are router-global;
				// with per-group filtering a QNH metric may apply on
				// an interface whose group does not export that route
				// — harmless (no route, no advertisement).
				b.WriteString(renderRIPQNHMetricOffsets12531(qnhMetrics, rip, policyOptions))
				b.WriteString("exit\n!\n")
			}
			// RIP per-interface authentication. #16625: only
			// enrolled interfaces get an auth block.
			authIfaces16625 := rip.Interfaces
			if len(rip.Groups) > 0 {
				authIfaces16625 = enrolled16625
			}
			if rip.AuthKey.Reveal() != "" {
				for _, iface := range authIfaces16625 {
					fmt.Fprintf(b, "interface %s\n", iface)
					// #9105: an ABSENT type is not `unrecognized`, so this warning could not
					// fire for it -- and it renders the key in CLEARTEXT exactly as a
					// chosen `simple` does. Warn on both: the commit gate stops every NEW
					// instance, this tells the operator about an existing one arriving
					// through the tolerant load path. (An unrecognized type no
					// longer reaches here: #14977 fails it closed above.)
					if config.AuthTypeAbsent(rip.AuthType) {
						slog.Warn("frr: rip authentication-key is set with NO authentication-type; "+
							"rendering PLAINTEXT -- the key travels in clear in every PDU. Set "+
							"authentication-type md5 to authenticate with a digest (#9105)",
							"accepted", config.AuthTypeSpellings())
					}
					if config.AuthTypeIsMD5(rip.AuthType) {
						b.WriteString(" ip rip authentication mode md5\n")
					} else {
						b.WriteString(" ip rip authentication mode text\n")
					}
					fmt.Fprintf(b, " ip rip authentication string %s\n", ripAuthTok14977)
					b.WriteString("exit\n!\n")
				}
			}
		}
	}
}
