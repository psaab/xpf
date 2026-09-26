package ipsec

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"

	"github.com/psaab/xpf/pkg/termsafe"
)

// dpdSettings holds the resolved dead-peer-detection parameters for a
// connection (derived from the gateway + VPN config).
type dpdSettings struct {
	Delay   int
	Timeout int
	Action  string
}

// errIKEChainUnresolved signals that a gateway names an IKE policy whose
// reference chain cannot be resolved (the policy is undefined, or the
// policy's `proposals` reference dangles, AND the legacy direct-proposal
// fallback also misses). Returning this instead of an empty proposal with
// a nil error is the fail-closed core of #2270: an empty proposal makes
// renderConfig omit the `proposals =` line, which silently hands phase-1
// negotiation to strongSwan's compiled-in default set (a crypto downgrade).
// renderConfig recognises this sentinel and SKIPS the offending VPN (one
// bad reference never zeroes a healthy tunnel); the commit-time validator
// validateIKEPolicyChainReferencesStrict (pkg/config) hard-rejects the
// dangling reference up front so a new operator edit fails loudly.
var errIKEChainUnresolved = errors.New(
	"ike gateway names an ike-policy whose proposal chain does not resolve")

// errESPChainUnresolved signals that a VPN names an ipsec-policy whose
// reference chain cannot be resolved (the policy is undefined and no legacy
// proposal of that name exists, or the policy resolves but none of its
// proposal references do). It is the ESP (Phase 2) mirror of
// errIKEChainUnresolved (#9919 F-090): returning this instead of a
// fabricated suite honours the #4298 never-fabricate principle — a dangling
// reference carries operator crypto intent, and substituting ANY suite
// (strongSwan's `default` before #2073/#4117, the fixed `aes256-sha256`
// after) negotiates crypto the operator never authored. renderConfig
// recognises this sentinel and SKIPS the offending VPN (one bad reference
// never zeroes a healthy tunnel, and the skipped tunnel's stale SA is torn
// down via the rendered-set diff); the commit-time validator
// validateIPsecPolicyProposalReferencesStrict (pkg/config) hard-rejects the
// dangling reference up front so a new operator edit fails loudly.
var errESPChainUnresolved = errors.New(
	"vpn names an ipsec-policy whose proposal chain does not resolve")

// errDHGroupUnresolved signals that a VPN's EFFECTIVE Diffie-Hellman group
// is unusable (#9919 F-161): an unparseable token, a present-but-empty leaf,
// or a numeric group the renderer cannot spell (99, the real-but-omitted
// 17/18, 0 authored explicitly, negatives). An unusable group must never
// silently drop its modp term (IKE falling back to charon's default group,
// ESP losing PFS) nor render an empty keyword charon refuses while the
// diagnostics point at charon. renderConfig recognises this sentinel and
// SKIPS the offending VPN; the commit-time validator
// validateIPsecDHGroupsStrict (pkg/config) hard-rejects the value up front
// so a new operator edit fails loudly.
var errDHGroupUnresolved = errors.New(
	"proposal carries a Diffie-Hellman group that cannot be rendered")

// errProposalUnresolved signals that every proposal available to a VPN was
// rejected by the render-side crypto safety belt. The commit-time validator
// names the authored value, while this sentinel lets tolerant loads skip the
// affected VPN instead of emitting an unsafe or incomplete proposal list.
var errProposalUnresolved = errors.New(
	"IPsec proposal cannot be rendered safely")

// renderAlgorithmValueSafe is the renderer's second belt for already-persisted
// values. It rejects swanctl-significant characters; the shared domain
// predicates below reject alphabetic but unsupported algorithm tokens.
func renderAlgorithmValueSafe(value string) bool {
	return config.IsSafeIPsecAlgorithmValue(value)
}

func algorithmValuesBad(kind, name, encryption, auth string) (bool, string) {
	if !renderAlgorithmValueSafe(encryption) {
		return true, fmt.Sprintf("%s %q encryption-algorithm %q contains "+
			"a swanctl-significant character", kind, name, encryption)
	}
	if !config.IsSupportedIPsecEncryptionAlgorithm(encryption) {
		return true, fmt.Sprintf("%s %q uses unsupported encryption-algorithm %q",
			kind, name, encryption)
	}
	if !renderAlgorithmValueSafe(auth) {
		return true, fmt.Sprintf("%s %q authentication-algorithm %q contains "+
			"a swanctl-significant character", kind, name, auth)
	}
	if !config.IsSupportedIPsecAuthenticationAlgorithm(auth) {
		return true, fmt.Sprintf("%s %q uses unsupported authentication-algorithm %q",
			kind, name, auth)
	}
	return false, ""
}

func ikeProposalBad(name string, prop *config.IKEProposal) (bool, string) {
	if bad, detail := algorithmValuesBad("ike-proposal", name, prop.EncryptionAlg, prop.AuthAlg); bad {
		return true, detail
	}
	if !config.IsIPsecAEADEncryptionAlgorithm(prop.EncryptionAlg) && prop.AuthAlg == "" {
		return true, fmt.Sprintf("ike-proposal %q is non-AEAD IKE without "+
			"authentication-algorithm", name)
	}
	return false, ""
}

func espProposalBad(name string, prop *config.IPsecProposal) (bool, string) {
	if bad, detail := algorithmValuesBad("ipsec-proposal", name, prop.EncryptionAlg, prop.AuthAlg); bad {
		return true, detail
	}
	if !strings.EqualFold(prop.Protocol, "ah") &&
		!config.IsIPsecAEADEncryptionAlgorithm(prop.EncryptionAlg) && prop.AuthAlg == "" {
		return true, fmt.Sprintf("ipsec-proposal %q is non-AEAD ESP without "+
			"authentication-algorithm", name)
	}
	return false, ""
}

func renderedProposalBad(kind, name, proposal string) (bool, string) {
	if proposal == "" {
		return true, fmt.Sprintf("%s proposal %q rendered an empty proposal", kind, name)
	}
	if !renderAlgorithmValueSafe(proposal) {
		return true, fmt.Sprintf("%s proposal %q rendered %q with a "+
			"swanctl-significant character", kind, name, proposal)
	}
	return false, ""
}

// dhGroupBad reports whether a DH value is unusable: a recorded InvalidSpec
// (the compiler saw a token it could not store — unparseable, unspellable
// numeric, or present-but-empty), or a non-zero numeric the renderer cannot
// spell (a directly-constructed struct bypassing the compiler, or a group
// from a newer peer). Zero with no spec is "not configured" (no PFS / no
// modp term intended), never bad. The detail names the offending value for
// the skip warning.
func dhGroupBad(group int, invalidSpec string) (bad bool, detail string) {
	if invalidSpec != "" {
		return true, fmt.Sprintf("dh-group %q", invalidSpec)
	}
	if group != 0 {
		if _, ok := config.DHGroupKeyword(group); !ok {
			return true, fmt.Sprintf("dh-group %d (supported: %v)", group, config.SupportedDHGroups())
		}
	}
	return false, ""
}

// resolveIKESettings resolves the IKE (Phase 1) auth method, proposal
// string, lifetime, and aggressive-mode flag from the gateway's IKE policy
// chain.
//
// It distinguishes two superficially similar empty-proposal cases:
//   - gw is nil or names no ike-policy: the intentional no-policy case —
//     return an empty proposal with a nil error (strongSwan's default set
//     is the operator's choice).
//   - gw names an ike-policy but the chain cannot resolve: return
//     errIKEChainUnresolved so the caller never silently emits a
//     proposal-less connection (#2270).
//
// A proposal whose DH group is unusable (#9919 F-161) is dropped from the
// list like a dangling reference (#3904 ANY-semantics: one bad entry never
// zeroes the good ones); only when NOTHING remains renderable does it
// return errDHGroupUnresolved so the caller skips the VPN instead of
// negotiating with a silently-dropped modp term or a charon-refused
// empty keyword.
func resolveIKESettings(cfg *config.IPsecConfig, gw *config.IPsecGateway) (authMethod, proposals string, lifetime int, aggressive bool, err error) {
	authMethod = "psk"
	if gw == nil || gw.IKEPolicy == "" {
		return authMethod, "", 0, false, nil
	}

	if ikePol, ok := cfg.IKEPolicies[gw.IKEPolicy]; ok {
		aggressive = ikePol.Mode == "aggressive"
		// #3904: `proposals [ p1 p2 ]` offers every listed IKE proposal.
		// Build each resolvable reference and comma-join into one swanctl
		// `proposals =` list (strongSwan negotiates the first mutually
		// acceptable one). The auth method and lifetime are connection-level,
		// taken from the first resolvable proposal to preserve single-proposal
		// behaviour exactly.
		var built []string
		var firstLifetime int
		authResolved := false
		var dhSkipped []string
		var proposalSkipped []string
		for _, ref := range ikePol.Proposals {
			ikeProp, ok := cfg.IKEProposals[ref]
			if !ok || ikeProp == nil {
				continue
			}
			// #9919 F-161: the DH check precedes auth resolution, so a
			// proposal coupling a bad DH value with a bad auth token is
			// SKIPPED (per-entry) rather than aborting the whole render.
			if bad, detail := dhGroupBad(ikeProp.DHGroup, ikeProp.DHGroupInvalidSpec); bad {
				dhSkipped = append(dhSkipped, fmt.Sprintf("ike-proposal %q %s", ref, detail))
				continue
			}
			if bad, detail := ikeProposalBad(ref, ikeProp); bad {
				proposalSkipped = append(proposalSkipped, detail)
				slog.Warn("skipping IPsec IKE proposal during render", "proposal", ref, "detail", detail)
				continue
			}
			builtProposal := buildIKEProposalFromIKE(ikeProp)
			if bad, detail := renderedProposalBad("IKE", ref, builtProposal); bad {
				proposalSkipped = append(proposalSkipped, detail)
				slog.Warn("skipping IPsec IKE proposal during render", "proposal", ref, "detail", detail)
				continue
			}
			if !authResolved {
				authMethod, err = authMethodToSwan(ikeProp.AuthMethod)
				if err != nil {
					return "", "", 0, false, err
				}
				firstLifetime = ikeProp.LifetimeSeconds
				authResolved = true
			}
			built = append(built, builtProposal)
		}
		if len(built) > 0 {
			return authMethod, strings.Join(built, ","), firstLifetime, aggressive, nil
		}
		if len(proposalSkipped) > 0 {
			return "", "", 0, aggressive, fmt.Errorf("%w: ike-policy %q (%s)",
				errProposalUnresolved, gw.IKEPolicy, strings.Join(proposalSkipped, "; "))
		}
		// Nothing renderable: a bad-DH entry is a more actionable
		// diagnosis than a dangling chain, so name it when present.
		if len(dhSkipped) > 0 {
			return "", "", 0, aggressive, fmt.Errorf("%w: ike-policy %q (%s)",
				errDHGroupUnresolved, gw.IKEPolicy, strings.Join(dhSkipped, "; "))
		}
	}

	if !hasIKEChain(cfg, gw.IKEPolicy) {
		if prop, ok := cfg.Proposals[gw.IKEPolicy]; ok && prop != nil {
			// #9919 F-161: the legacy direct-proposal form carries a DH
			// group too; a bad one skips like the chain form.
			if bad, detail := dhGroupBad(prop.DHGroup, prop.DHGroupInvalidSpec); bad {
				return "", "", 0, aggressive, fmt.Errorf("%w: ike-policy %q names proposal %q with %s",
					errDHGroupUnresolved, gw.IKEPolicy, gw.IKEPolicy, detail)
			}
			if bad, detail := algorithmValuesBad("ike-proposal", gw.IKEPolicy, prop.EncryptionAlg, prop.AuthAlg); bad {
				return "", "", 0, aggressive, fmt.Errorf("%w: ike-policy %q names proposal %q with %s",
					errProposalUnresolved, gw.IKEPolicy, gw.IKEPolicy, detail)
			}
			builtProposal := buildIKEProposal(prop)
			if bad, detail := renderedProposalBad("IKE", gw.IKEPolicy, builtProposal); bad {
				return "", "", 0, aggressive, fmt.Errorf("%w: ike-policy %q names proposal %q with %s",
					errProposalUnresolved, gw.IKEPolicy, gw.IKEPolicy, detail)
			}
			return authMethod, builtProposal, prop.LifetimeSeconds, aggressive, nil
		}
	}
	// gw.IKEPolicy is set but neither the ike-policy -> ike-proposal chain
	// nor the legacy direct-proposal fallback resolves. Fail closed: do NOT
	// return an empty proposal with a nil error (#2270).
	return "", "", 0, aggressive, fmt.Errorf("%w: ike-policy %q", errIKEChainUnresolved, gw.IKEPolicy)
}

// vpnUsesAHProposal reports whether the VPN's ipsec-policy resolves to any
// proposal with `protocol ah`. AH (Authentication Header) is integrity-only
// and has no ESP render path — buildESPProposal would fabricate an aes256
// cipher and renderConfig would emit esp_proposals — so renderConfig skips
// such a VPN (#4298, V-2) rather than misrepresent AH as ESP. It mirrors
// resolveESPSettings' resolution order exactly: the policy's proposal list,
// the policy-name fallback for a policy with no explicit proposals, and the
// legacy form where the ipsec-policy value is itself a proposal name.
func vpnUsesAHProposal(cfg *config.IPsecConfig, vpn *config.IPsecVPN) bool {
	if cfg == nil || vpn == nil || vpn.IPsecPolicy == "" {
		return false
	}
	isAH := func(name string) bool {
		if p, ok := cfg.Proposals[name]; ok && p != nil {
			return strings.EqualFold(p.Protocol, "ah")
		}
		return false
	}
	if pol, ok := cfg.Policies[vpn.IPsecPolicy]; ok && pol != nil {
		refs := pol.Proposals
		if len(refs) == 0 {
			refs = []string{vpn.IPsecPolicy}
		}
		for _, r := range refs {
			if isAH(r) {
				return true
			}
		}
		return false
	}
	// Legacy form: the ipsec-policy value is itself a defined proposal name.
	return isAH(vpn.IPsecPolicy)
}

// resolveESPSettings resolves the ESP (Phase 2) proposal string and lifetime
// from the VPN's IPsec policy chain.
//
// ABSENT vs DANGLING (#4117, #9919 F-090). A VPN that names NO ipsec-policy
// at all legitimately wants strongSwan's compiled-in "default" ESP suite —
// the operator made no crypto choice, so the built-in default is their
// explicit choice and nothing dangles. This is the ONLY path that returns
// esp_proposals = default with a nil error. A NAMED-but-unresolved
// (dangling) reference returns errESPChainUnresolved so the caller SKIPS the
// VPN rather than fabricate a suite the operator never authored (the #4298
// principle; the IKE mirror is errIKEChainUnresolved, #2270).
//
// DH groups (#9919 F-161): only the EFFECTIVE group is judged, because the
// policy-level PFS group overrides each proposal's own dh-group in
// buildESPProposal. A policy carrying a configured PFS value is judged on
// the PFS value alone — a good PFS renders even when every proposal's DH
// is bad (the overridden terms are inert), while a bad PFS skips even when
// a proposal's DH is good (falling back would silently discard the
// operator's PFS choice). With no PFS, proposals filter with #3904
// ANY-semantics: bad-DH entries drop, and only when nothing remains
// renderable does it return errDHGroupUnresolved.
//
// Precedence is chain-before-DH: a policy whose proposals all dangle
// reports the dangling chain even when the PFS value is also bad (either
// way the VPN skips; the chain break is the first fix).
func resolveESPSettings(cfg *config.IPsecConfig, vpn *config.IPsecVPN) (string, int, error) {
	if vpn.IPsecPolicy == "" {
		return "default", 0, nil
	}

	if ipsecPol, ok := cfg.Policies[vpn.IPsecPolicy]; ok && ipsecPol != nil {
		propRefs := ipsecPol.Proposals
		if len(propRefs) == 0 {
			propRefs = []string{vpn.IPsecPolicy}
		}
		// Phase 1: chain resolvability. Collect every reference that
		// names a defined proposal; none at all is a dangling chain.
		type resolvable struct {
			ref  string
			prop *config.IPsecProposal
		}
		var good []resolvable
		for _, ref := range propRefs {
			if prop, ok := cfg.Proposals[ref]; ok && prop != nil {
				good = append(good, resolvable{ref, prop})
			}
		}
		if len(good) == 0 {
			return "", 0, fmt.Errorf("%w: ipsec-policy %q resolves but none of its proposal references %q resolve",
				errESPChainUnresolved, vpn.IPsecPolicy, propRefs)
		}
		// Phase 2: the effective DH group. A bad PFS value poisons the
		// policy regardless of the proposals (no silent fallback to a
		// proposal DH the operator did not choose for PFS).
		if bad, detail := dhGroupBad(ipsecPol.PFSGroup, ipsecPol.PFSGroupInvalidSpec); bad {
			return "", 0, fmt.Errorf("%w: ipsec-policy %q carries unusable PFS %s",
				errDHGroupUnresolved, vpn.IPsecPolicy, detail)
		}
		pfsGroup := ipsecPol.PFSGroup
		var built []string
		var firstLifetime int
		var dhSkipped []string
		var proposalSkipped []string
		for _, r := range good {
			if pfsGroup == 0 {
				if bad, detail := dhGroupBad(r.prop.DHGroup, r.prop.DHGroupInvalidSpec); bad {
					dhSkipped = append(dhSkipped, fmt.Sprintf("proposal %q %s", r.ref, detail))
					continue
				}
			}
			if bad, detail := espProposalBad(r.ref, r.prop); bad {
				proposalSkipped = append(proposalSkipped, detail)
				slog.Warn("skipping IPsec ESP proposal during render", "proposal", r.ref, "detail", detail)
				continue
			}
			builtProposal := buildESPProposal(r.prop, pfsGroup)
			if bad, detail := renderedProposalBad("ESP", r.ref, builtProposal); bad {
				proposalSkipped = append(proposalSkipped, detail)
				slog.Warn("skipping IPsec ESP proposal during render", "proposal", r.ref, "detail", detail)
				continue
			}
			if len(built) == 0 {
				firstLifetime = r.prop.LifetimeSeconds
			}
			built = append(built, builtProposal)
		}
		if len(built) > 0 {
			return strings.Join(built, ","), firstLifetime, nil
		}
		if len(proposalSkipped) > 0 {
			return "", 0, fmt.Errorf("%w: ipsec-policy %q (%s)",
				errProposalUnresolved, vpn.IPsecPolicy, strings.Join(proposalSkipped, "; "))
		}
		return "", 0, fmt.Errorf("%w: ipsec-policy %q (%s)",
			errDHGroupUnresolved, vpn.IPsecPolicy, strings.Join(dhSkipped, "; "))
	}

	if prop, ok := cfg.Proposals[vpn.IPsecPolicy]; ok && prop != nil {
		// Legacy form: the ipsec-policy value is itself the NAME of a
		// defined ESP proposal (no policy object). Render it directly,
		// subject to the same DH check.
		if bad, detail := dhGroupBad(prop.DHGroup, prop.DHGroupInvalidSpec); bad {
			return "", 0, fmt.Errorf("%w: ipsec-policy %q names a proposal with %s",
				errDHGroupUnresolved, vpn.IPsecPolicy, detail)
		}
		if bad, detail := espProposalBad(vpn.IPsecPolicy, prop); bad {
			return "", 0, fmt.Errorf("%w: ipsec-policy %q names a proposal with %s",
				errProposalUnresolved, vpn.IPsecPolicy, detail)
		}
		builtProposal := buildESPProposal(prop, 0)
		if bad, detail := renderedProposalBad("ESP", vpn.IPsecPolicy, builtProposal); bad {
			return "", 0, fmt.Errorf("%w: ipsec-policy %q names a proposal with %s",
				errProposalUnresolved, vpn.IPsecPolicy, detail)
		}
		return builtProposal, prop.LifetimeSeconds, nil
	}

	// Dangling POLICY reference — vpn.IPsecPolicy names neither a defined
	// ipsec-policy nor a defined ESP proposal. Fail closed: skip, never
	// fabricate.
	return "", 0, fmt.Errorf("%w: ipsec-policy %q names neither a defined ipsec-policy nor a proposal",
		errESPChainUnresolved, vpn.IPsecPolicy)
}

// deriveDPD computes the dead-peer-detection settings for a connection.
//
// DPD is enabled whenever the gateway carries a `dead-peer-detection` stanza
// (gw.DPDEnable), regardless of whether an explicit mode keyword was given. A
// bare `dead-peer-detection;` therefore yields a DPD-enabled connection with
// the strongSwan defaults (10s delay, restart/clear action) — before #3994 the
// enable check was gw.DeadPeerDetect != "", so the bare form was silently
// treated as disabled. gw.DeadPeerDetect != "" is still honoured as a fallback
// so a hand-built gateway that sets only the mode still enables DPD.
func deriveDPD(gw *config.IPsecGateway, vpn *config.IPsecVPN) dpdSettings {
	if gw == nil || (!gw.DPDEnable && gw.DeadPeerDetect == "") {
		return dpdSettings{}
	}

	delay := gw.DPDInterval
	if delay <= 0 {
		delay = 10
	}
	threshold := gw.DPDThreshold
	if threshold <= 0 {
		threshold = 5
	}

	action := ""
	switch gw.DeadPeerDetect {
	case "always-send":
		action = "restart"
	case "optimized":
		if vpn != nil && vpn.EstablishTunnels == "immediately" {
			action = "restart"
		} else {
			action = "clear"
		}
	case "probe-idle-tunnel":
		if vpn != nil && vpn.EstablishTunnels == "immediately" {
			action = "restart"
		} else {
			action = "trap"
		}
	default:
		// No explicit mode keyword (bare `dead-peer-detection;`). Junos
		// treats a bare stanza as its default DPD behaviour, which matches
		// the "optimized" mode: restart an always-on tunnel, otherwise clear
		// the dead SA so it re-establishes on the next packet. Emitting a
		// concrete action here means the bare form gets a sensible
		// dpd_action instead of relying on strongSwan's implicit default
		// (#3994).
		if vpn != nil && vpn.EstablishTunnels == "immediately" {
			action = "restart"
		} else {
			action = "clear"
		}
	}

	return dpdSettings{
		Delay:   delay,
		Timeout: delay * threshold,
		Action:  action,
	}
}

// hasIKEChain checks if the IKE policy -> IKE proposal chain is available.
func hasIKEChain(cfg *config.IPsecConfig, ikePolicyName string) bool {
	if cfg.IKEPolicies == nil {
		return false
	}
	pol, ok := cfg.IKEPolicies[ikePolicyName]
	if !ok {
		return false
	}
	if cfg.IKEProposals == nil {
		return false
	}
	// #3904: `proposals` is a list — the chain is available when ANY
	// reference resolves (resolveIKESettings renders every resolvable
	// reference; the legacy direct-proposal fallback is consulted only when
	// none resolve).
	for _, ref := range pol.Proposals {
		if _, ok := cfg.IKEProposals[ref]; ok {
			return true
		}
	}
	return false
}

// normalizeEncAlg maps a Junos encryption-algorithm name to its swanctl
// token. For AES-GCM it returns the explicit 16-octet-ICV token
// (aes-256-gcm -> aes256gcm16). This is a canonicalization for clarity,
// not a parse fix: strongSwan also accepts the bare "aes256gcm" alias
// (it maps to ENCR_AES_GCM_ICV16 in proposal_keywords_static.txt), so
// the previous bare render parsed fine — the suffix just makes the ICV
// length explicit in the generated config, matching the operator's
// Junos intent (Junos AES-GCM uses a 16-octet ICV). The load-bearing
// #2125 correctness fix is the explicit IKE PRF the callers add for
// AEAD, not this spelling. isGCM reports whether the algorithm is AEAD
// (the caller skips the integrity algorithm for AEAD and, for IKE,
// appends an explicit PRF instead).
//
// Already-suffixed forms (e.g. aes256gcm128 fed directly by config or
// older tests) pass through the generic dash-strip unchanged so they
// keep rendering as before. Non-GCM algorithms return ("", false) and
// the caller applies the historical "-cbc"/"-" normalization.
func normalizeEncAlg(enc string) (token string, isGCM bool) {
	enc = strings.ToLower(enc)
	switch enc {
	case "aes-128-gcm", "aes128gcm":
		return "aes128gcm16", true
	case "aes-192-gcm", "aes192gcm":
		return "aes192gcm16", true
	case "aes-256-gcm", "aes256gcm":
		return "aes256gcm16", true
	}
	if strings.Contains(enc, "gcm") {
		// Already carries an ICV suffix; strip Junos punctuation but
		// otherwise leave the supported lower-case token intact.
		t := strings.ReplaceAll(enc, "-cbc", "")
		t = strings.ReplaceAll(t, "-", "")
		return t, true
	}
	return "", false
}

// gcmPRF derives the swanctl PRF token for an IKE (Phase 1) AEAD
// proposal. AEAD ciphers carry no integrity algorithm for strongSwan to
// derive a PRF from, so IKEv2 GCM proposals MUST name a PRF explicitly
// (e.g. aes256gcm16-prfsha256-modp2048). When the proposal names an
// auth/integrity algorithm we mirror it as the PRF; otherwise we default
// to prfsha256.
func gcmPRF(authAlg string) string {
	authAlg = strings.ToLower(authAlg)
	switch {
	case strings.Contains(authAlg, "512"):
		return "prfsha512"
	case strings.Contains(authAlg, "384"):
		return "prfsha384"
	case strings.Contains(authAlg, "256"):
		return "prfsha256"
	case strings.Contains(authAlg, "sha1"), strings.Contains(authAlg, "sha-1"):
		return "prfsha1"
	default:
		return "prfsha256"
	}
}

// normalizeAuthAlg maps a Junos authentication-algorithm name to the
// swanctl/charon integrity token that strongSwan actually accepts.
//
// Junos names an ESP integrity algorithm with an explicit HMAC
// truncation length: hmac-sha-256-128, hmac-sha1-96, hmac-md5-96,
// hmac-sha-384-192, hmac-sha-512-256. strongSwan's proposal keyword
// table names the BASE algorithm only (sha256, sha1, md5, sha384,
// sha512) and derives the RFC-mandated truncation internally. The Junos
// truncation suffix must therefore be mapped away, NOT dash-stripped: a
// naive strings.ReplaceAll(authAlg, "-", "") on hmac-sha-256-128 yields
// "sha256128", which is not a token in strongSwan's
// proposal_keywords_static.txt, so charon rejects the ENTIRE ESP/IKE
// proposal and the tunnel silently never loads (#3851).
//
// The IKE (Phase 1) config layer feeds the shorter Junos spellings
// (sha-256, sha1, md5) with no truncation suffix, and swanctl tokens
// (sha256) can also arrive already normalized; all collapse to the same
// canonical token here, so the function is idempotent.
//
// AEAD (GCM) proposals never reach this function — the callers take the
// gcmPRF() branch for AEAD ciphers, which carry their own ICV and no
// separate integrity algorithm.
func normalizeAuthAlg(authAlg string) string {
	// Collapse every Junos/swanctl spelling to one comparable token:
	// drop the hmac- prefix and all dashes. hmac-sha-256-128 ->
	// "sha256128", sha-256 -> "sha256", sha256 -> "sha256".
	a := strings.ToLower(authAlg)
	a = strings.ReplaceAll(a, "hmac-", "")
	a = strings.ReplaceAll(a, "-", "")

	// Map the collapsed token (with any truncation-length suffix) to the
	// strongSwan base-algorithm keyword. Longer SHA-2 digests are matched
	// before sha1 so no truncation suffix can be misread.
	switch {
	case a == "":
		return ""
	case strings.HasPrefix(a, "sha512"):
		return "sha512"
	case strings.HasPrefix(a, "sha384"):
		return "sha384"
	case strings.HasPrefix(a, "sha256"):
		return "sha256"
	case strings.HasPrefix(a, "sha224"):
		return "sha224"
	case strings.HasPrefix(a, "sha1"):
		return "sha1"
	case strings.HasPrefix(a, "md5"):
		return "md5"
	default:
		// Unknown algorithm: return the collapsed token unchanged rather
		// than inventing a spelling. This preserves the historical
		// behaviour for any name outside the known SHA/MD5 family.
		return a
	}
}

// buildIKEProposalFromIKE builds a swanctl IKE proposal string from an IKE proposal.
func buildIKEProposalFromIKE(prop *config.IKEProposal) string {
	var parts []string

	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	enc = strings.ToLower(enc)
	if tok, isGCM := normalizeEncAlg(enc); isGCM {
		parts = append(parts, tok)
		// IKEv2 AEAD proposals require an explicit PRF.
		parts = append(parts, gcmPRF(prop.AuthAlg))
	} else {
		enc = strings.ReplaceAll(enc, "-cbc", "")
		enc = strings.ReplaceAll(enc, "-", "")
		parts = append(parts, enc)
		if prop.AuthAlg != "" {
			parts = append(parts, normalizeAuthAlg(prop.AuthAlg))
		}
	}

	if prop.DHGroup > 0 {
		parts = append(parts, formatDHGroup(prop.DHGroup))
	}

	return strings.Join(parts, "-")
}

// buildIKEProposal builds a swanctl IKE (Phase 1) proposal string from a proposal config.
func buildIKEProposal(prop *config.IPsecProposal) string {
	var parts []string

	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	enc = strings.ToLower(enc)
	if tok, isGCM := normalizeEncAlg(enc); isGCM {
		parts = append(parts, tok)
		// IKEv2 AEAD proposals require an explicit PRF — there is no
		// integrity algorithm to derive one from.
		parts = append(parts, gcmPRF(prop.AuthAlg))
	} else {
		enc = strings.ReplaceAll(enc, "-cbc", "")
		enc = strings.ReplaceAll(enc, "-", "")
		parts = append(parts, enc)
		if prop.AuthAlg != "" {
			parts = append(parts, normalizeAuthAlg(prop.AuthAlg))
		}
	}

	if prop.DHGroup > 0 {
		parts = append(parts, formatDHGroup(prop.DHGroup))
	}

	return strings.Join(parts, "-")
}

func buildESPProposal(prop *config.IPsecProposal, pfsGroup int) string {
	var parts []string

	// Encryption algorithm
	enc := prop.EncryptionAlg
	if enc == "" {
		enc = "aes256"
	}
	enc = strings.ToLower(enc)
	// Normalize Junos names to swanctl names. AEAD (GCM) ciphers carry
	// an ICV suffix and take no separate integrity algorithm and no PRF.
	if tok, isGCM := normalizeEncAlg(enc); isGCM {
		parts = append(parts, tok)
	} else {
		enc = strings.ReplaceAll(enc, "-cbc", "")
		enc = strings.ReplaceAll(enc, "-", "")
		parts = append(parts, enc)
		// Authentication algorithm (non-GCM only)
		if prop.AuthAlg != "" {
			parts = append(parts, normalizeAuthAlg(prop.AuthAlg))
		}
	}

	// DH group
	dhGroup := prop.DHGroup
	if pfsGroup > 0 {
		dhGroup = pfsGroup
	}
	if dhGroup > 0 {
		parts = append(parts, formatDHGroup(dhGroup))
	}

	return strings.Join(parts, "-")
}

func dhGroupBits(group int) int {
	switch group {
	case 1:
		return 768
	case 2:
		return 1024
	case 5:
		return 1536
	case 14:
		return 2048
	case 15:
		return 3072
	case 16:
		return 4096
	case 19:
		return 256 // ecp256
	case 20:
		return 384 // ecp384
	default:
		return group
	}
}

// formatDHGroup renders a Diffie-Hellman group number as its canonical
// swanctl proposal keyword. The single source of truth for the suffix in
// every IKE/ESP proposal builder (#2392): the elliptic-curve groups must
// emit the strongSwan ECP/curve spellings (ecp256, ecp384, ecp521,
// curve25519, ...) — NOT modp<bits>. Rendering group 19/20 as
// modp256/modp384 (what the bare dhGroupBits suffix produced before #2392)
// is not a token in strongSwan's proposal_keywords table, so the whole
// proposal is rejected and the tunnel fails to load.
//
// The spellings come straight from strongSwan's proposal keyword table
// (src/libstrongswan/crypto/proposal/proposal.c diffie_hellman_group_names
// / proposal_keywords_static.txt):
//   - ECP groups:        19->ecp256, 20->ecp384, 21->ecp521,
//     25->ecp192, 26->ecp224
//   - Brainpool ECP:     27->ecp224bp, 28->ecp256bp, 29->ecp384bp,
//     30->ecp512bp
//   - Montgomery curves: 31->curve25519, 32->curve448
//   - MODP-with-prime-order-subgroup (RFC 5114): 22->modp1024s160,
//     23->modp2048s224, 24->modp2048s256. These have their own keywords
//     and must NOT fall through to modp<dhGroupBits> — dhGroupBits has no
//     22/23/24 case, so the fall-through emitted the strongSwan-invalid
//     tokens modp22/modp23/modp24 and the whole proposal was rejected at
//     swanctl load (#2604, the sibling of the #2392 ECP fix).
//
// The config layer (ValidateDHGroup, pkg/config) accepts any positive
// integer DH group, so every group an operator can commit must render to
// a valid keyword here. Any group not in the explicit table above is a
// classic MODP group as far as dhGroupBits is concerned and renders as
// modp<dhGroupBits(group)> (the unchanged pre-#2392 behaviour for the
// classic MODP groups 1/2/5/14/15/16).
func formatDHGroup(group int) string {
	// #8597 (muse-004 K88): the keyword table is config.DHGroupKeyword, the
	// SAME map ValidateDHGroup accepts against.
	//
	// This used to carry its own switch with a `default: modp<dhGroupBits(n)>`
	// fall-through, and the validator accepted any positive integer — so the
	// gate and the renderer had different ideas of the accepted set. Measured:
	// 99 -> "modp99", 17 -> "modp17", 33 -> "modp33", all of which charon
	// rejects. 17 is the worst of them: it is a REAL group (RFC 3526
	// modp6144), so the render is not merely unspelled but wrong.
	//
	// The fall-through is gone rather than corrected, because a fall-through is
	// what let an unspellable group reach swanctl in the first place. An
	// unlisted group is now refused at commit with the accepted set named; if
	// one ever reaches here anyway (a tolerant load, a future caller), it
	// renders the empty string, which fails LOUDLY at proposal-build rather
	// than becoming a plausible-looking keyword charon quietly refuses.
	kw, _ := config.DHGroupKeyword(group)
	return kw
}

// SAStatus represents an IPsec Security Association as reported by
// `swanctl --list-sas`. For a connection with an established CHILD SA the
// Name is the child SA name and the endpoint/traffic-selector/counter fields
// are populated from the child; for an IKE SA with no child yet (e.g.
// CONNECTING) the Name is the IKE SA name and only the endpoint fields carry.
type SAStatus struct {
	Name           string
	ConnectionName string
	LocalAddr      string
	RemoteAddr     string
	State          string
	LocalTS        string
	RemoteTS       string
	InBytes        string
	OutBytes       string
	InPackets      string
	OutPackets     string
	SPIIn          string
	SPIOut         string
	// Rekey is the raw child (or IKE) SA timing line, e.g.
	// "installed 42s ago, rekeying in 3358s, expires in 3918s".
	Rekey string
}

// TerminateAllSAs terminates all active IKE SAs via swanctl.
func (m *Manager) TerminateAllSAs() (int, error) {
	sas, err := m.GetSAStatus()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, ikeName := range terminateIKENames(sas) {
		if out, err := runSwanctl("--terminate", "--ike", ikeName); err != nil {
			slog.Warn("swanctl terminate failed", "ike", ikeName, "err", err, "output", string(out))
		} else {
			count++
		}
	}
	return count, nil
}

// terminateIKENames is TerminateAllSAs' selection, split from the swanctl exec so the names it
// terminates can be driven from parsed `--list-sas` output (#9623): each SA's IKE connection
// name, else its own name, deduplicated in listing order.
func terminateIKENames(sas []SAStatus) []string {
	names := make([]string, 0, len(sas))
	seen := make(map[string]bool)
	for _, sa := range sas {
		ikeName := sa.ConnectionName
		if ikeName == "" {
			ikeName = sa.Name
		}
		if ikeName == "" || seen[ikeName] {
			continue
		}
		seen[ikeName] = true
		names = append(names, ikeName)
	}
	return names
}

// ActiveConnectionNames returns the deduplicated SA names `swanctl --list-sas`
// reports: the CHILD SA name for every connection with a child, and the IKE SA
// name only for an IKE SA that has no child yet (parseSAOutput emits the IKE row
// only then). It is what HA IPsec SA sync advertises and what the peer later
// hands to InitiateConnection, which takes a CHILD name.
//
// It is NOT a list of VPN names (#9511). A VPN with traffic-selector entries
// renders each selector as its own child `<vpn>-<selector>`, so once its children
// exist its names here are those children, not `<vpn>`. Only an IKE SA with no
// child yet contributes `<vpn>`, and for a multi-selector VPN InitiateConnection
// cannot bring that name up, because no child section carries it. Do not "fix"
// the child rows by publishing SAStatus.ConnectionName: that would make EVERY
// initiate of a multi-selector VPN fail (#9075, GEMINI-050-072). A consumer that
// needs the VPN resolves the name with BuildSANameIndex.
func (m *Manager) ActiveConnectionNames() ([]string, error) {
	sas, err := m.GetSAStatus()
	if err != nil {
		return nil, err
	}
	return activeSANames(sas), nil
}

// activeSANames is ActiveConnectionNames' selection, split from the swanctl exec
// so the published names can be driven from parsed `--list-sas` output (#9511).
func activeSANames(sas []SAStatus) []string {
	names := make([]string, 0, len(sas))
	seen := make(map[string]bool)
	for _, sa := range sas {
		if sa.Name != "" && !seen[sa.Name] {
			seen[sa.Name] = true
			names = append(names, sa.Name)
		}
	}
	return names
}

// InitiateConnection initiates a single IPsec connection by name.
func (m *Manager) InitiateConnection(name string) error {
	if out, err := runSwanctl("--initiate", "--child", name); err != nil {
		return fmt.Errorf("swanctl --initiate %s: %w: %s", name, err, termsafe.SanitizeForDisplay(string(out)))
	}
	return nil
}

// GetSAStatus queries strongSwan for active SAs.
func (m *Manager) GetSAStatus() ([]SAStatus, error) {
	// #9068: the shared stdout-only exec, not a second inline copy of it.
	// This function's own comment — "the parser needs stdout alone" — was
	// right, and liveConnNames was fed CombinedOutput by a different channel
	// for the same parser. Two spellings of one exec discipline is how that
	// divergence happened; there is now one.
	stdoutB, stderrB, runErr := runSwanctlSplit("--list-sas")
	stdout, stderr := string(stdoutB), string(stderrB)
	if err := runErr; err != nil {
		// #6584: the error string reaches a terminal on both renderers
		// (pkg/cli prints "error: %v", the gRPC status is re-wrapped and
		// printed by cmd/cli), so raw swanctl stderr is the same class.
		return nil, fmt.Errorf("swanctl --list-sas: %w: %s", err, termsafe.SanitizeForDisplay(stderr))
	}

	sas := parseSAOutput(stdout)
	// #6584: sanitize once, here, so every renderer (local CLI, gRPC mirror,
	// and any future one) is covered by construction.
	for i := range sas {
		sanitizeSAStatus(&sas[i])
	}
	return sas, nil
}

// parseSAOutput parses the human-readable output of `swanctl --list-sas`
// (the command GetSAStatus invokes). The real strongSwan layout is, for each
// tunnel:
//
//	site-a: #1, ESTABLISHED, IKEv2, 8f7c..._i* 4d3c..._r
//	  local  '10.0.1.1' @ 10.0.1.1[500]
//	  remote '10.0.2.1' @ 10.0.2.1[500]
//	  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
//	  established 42s ago, rekeying in 13342s
//	  site-a: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
//	    installed 42s ago, rekeying in 3358s, expires in 3918s
//	    in  c1234567,  1420 bytes,    12 packets,     2s ago
//	    out c7654321,  1638 bytes,    14 packets,     2s ago
//	    local  10.0.1.0/24
//	    remote 10.0.2.0/24
//
// The IKE SA header has no leading whitespace; endpoints appear as
// "local/remote 'id' @ host[port]" (the "@" distinguishes an endpoint from a
// child traffic-selector line, which is a bare CIDR); the CHILD SA header is
// indented and carries ", reqid <n>,"; per-direction counters are the
// "in/out <spi>, <bytes> bytes, <packets> packets" lines. An earlier version
// of this parser assumed an "ipsec statusall"-style layout (local: A === B /
// local_ts = C / bytes_in=N) that swanctl never emits, so every SA field but
// the name/state came back blank (#3937).
// sanitizeSAStatus neutralizes terminal control sequences in every field of a
// parsed swanctl SA record (#6584).
//
// It runs at INGEST rather than at each renderer, because the alternative is
// roughly two dozen guard sites: `show security ipsec security-associations`
// and its `detail` form print thirteen fields per SA one line at a time, the
// statistics view prints a width-formatted row, and every one of those has a
// byte-for-byte gRPC mirror. #6579's own review recorded what happens to a
// sweep that wide -- "reverting all 14 call-site edits left the suite green,
// because the only test file exercised the primitive" -- and the miss it
// actually shipped was an entire renderer. One choke point cannot be
// half-applied, and it covers a renderer added later for free. The tree
// already accepts this shape: LLDP is sanitized at ingest for the same reason.
//
// SanitizeForDisplay (single-line) is right for every field here: these are
// FIELDS the callers format into rows, so an embedded LF is itself a forgery
// vector -- it fakes a row.
//
// Guarding the WHOLE record, not the fields believed to be peer-controlled, is
// the #6579 rule. The parser is strings.Split/Fields-based, so which swanctl
// column lands in which struct field is a property of the CURRENT strongSwan
// output format, not an invariant. Today RemoteTS/LocalTS carry the traffic
// selectors the peer proposed and parseEndpointHost discards the quoted peer
// IKE identity; neither fact is guaranteed by anything in this repo.
func sanitizeSAStatus(sa *SAStatus) {
	sa.Name = termsafe.SanitizeForDisplay(sa.Name)
	sa.ConnectionName = termsafe.SanitizeForDisplay(sa.ConnectionName)
	sa.LocalAddr = termsafe.SanitizeForDisplay(sa.LocalAddr)
	sa.RemoteAddr = termsafe.SanitizeForDisplay(sa.RemoteAddr)
	sa.State = termsafe.SanitizeForDisplay(sa.State)
	sa.LocalTS = termsafe.SanitizeForDisplay(sa.LocalTS)
	sa.RemoteTS = termsafe.SanitizeForDisplay(sa.RemoteTS)
	sa.InBytes = termsafe.SanitizeForDisplay(sa.InBytes)
	sa.OutBytes = termsafe.SanitizeForDisplay(sa.OutBytes)
	sa.InPackets = termsafe.SanitizeForDisplay(sa.InPackets)
	sa.OutPackets = termsafe.SanitizeForDisplay(sa.OutPackets)
	sa.SPIIn = termsafe.SanitizeForDisplay(sa.SPIIn)
	sa.SPIOut = termsafe.SanitizeForDisplay(sa.SPIOut)
	sa.Rekey = termsafe.SanitizeForDisplay(sa.Rekey)
}

func parseSAOutput(output string) []SAStatus {
	var sas []SAStatus
	var currentConn *SAStatus
	var currentChild *SAStatus
	connHasChild := false

	flushChild := func() {
		if currentChild != nil {
			sas = append(sas, *currentChild)
			currentChild = nil
		}
	}
	flushConn := func() {
		flushChild()
		if currentConn != nil && !connHasChild {
			sas = append(sas, *currentConn)
		}
		currentConn = nil
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// IKE SA header: no leading whitespace, "name: #<id>, <STATE>, IKEv<n>".
		if line[0] != ' ' && line[0] != '\t' && strings.Contains(trimmed, ": #") &&
			!strings.Contains(trimmed, ", reqid ") {
			flushConn()
			currentConn = parseIKEHeader(trimmed)
			connHasChild = false
			continue
		}

		if currentConn == nil {
			continue
		}

		// Child SA header: indented "name: #<id>, reqid <n>, <STATE>, ...".
		if strings.Contains(trimmed, ": #") && strings.Contains(trimmed, ", reqid ") {
			flushChild()
			currentChild = parseChildHeader(trimmed, currentConn)
			connHasChild = true
			continue
		}

		target := currentConn
		if currentChild != nil {
			target = currentChild
		}

		switch {
		// IKE endpoint lines carry "@ host[port]"; child traffic-selector
		// lines ("local  10.0.1.0/24") are bare CIDRs with no "@".
		case strings.HasPrefix(trimmed, "local ") && strings.Contains(trimmed, "@"):
			if h := parseEndpointHost(trimmed); h != "" {
				currentConn.LocalAddr = h
				if currentChild != nil {
					currentChild.LocalAddr = h
				}
			}
		case strings.HasPrefix(trimmed, "remote ") && strings.Contains(trimmed, "@"):
			if h := parseEndpointHost(trimmed); h != "" {
				currentConn.RemoteAddr = h
				if currentChild != nil {
					currentChild.RemoteAddr = h
				}
			}
		case strings.HasPrefix(trimmed, "local ") && currentChild != nil:
			currentChild.LocalTS = strings.TrimSpace(strings.TrimPrefix(trimmed, "local"))
		case strings.HasPrefix(trimmed, "remote ") && currentChild != nil:
			currentChild.RemoteTS = strings.TrimSpace(strings.TrimPrefix(trimmed, "remote"))
		case strings.HasPrefix(trimmed, "in "):
			spi, b, p := parseTrafficLine(trimmed)
			target.SPIIn, target.InBytes, target.InPackets = spi, b, p
		case strings.HasPrefix(trimmed, "out "):
			spi, b, p := parseTrafficLine(trimmed)
			target.SPIOut, target.OutBytes, target.OutPackets = spi, b, p
		case strings.Contains(trimmed, "rekeying in ") || strings.Contains(trimmed, "expires in "):
			target.Rekey = trimmed
		}
	}

	flushConn()
	return sas
}

// parseIKEHeader parses an IKE SA header line, e.g.
// "site-a: #1, ESTABLISHED, IKEv2, 8f7c..._i* 4d3c..._r". State is the
// comma-field immediately after "name: #<id>".
func parseIKEHeader(line string) *SAStatus {
	sa := &SAStatus{}
	if colon := strings.Index(line, ":"); colon >= 0 {
		sa.Name = strings.TrimSpace(line[:colon])
	}
	sa.ConnectionName = sa.Name
	if parts := strings.Split(line, ","); len(parts) >= 2 {
		sa.State = strings.TrimSpace(parts[1])
	}
	return sa
}

// parseChildHeader parses a child SA header line, e.g.
// "site-a: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128".
// State is the comma-field after the "reqid <n>" field. Endpoints are
// inherited from the parent IKE SA (swanctl prints them only once, on the IKE
// header block).
func parseChildHeader(line string, conn *SAStatus) *SAStatus {
	sa := &SAStatus{
		ConnectionName: conn.Name,
		LocalAddr:      conn.LocalAddr,
		RemoteAddr:     conn.RemoteAddr,
	}
	if colon := strings.Index(line, ":"); colon >= 0 {
		sa.Name = strings.TrimSpace(line[:colon])
	}
	parts := strings.Split(line, ",")
	for i, p := range parts {
		if strings.Contains(p, "reqid ") && i+1 < len(parts) {
			sa.State = strings.TrimSpace(parts[i+1])
			break
		}
	}
	return sa
}

// parseEndpointHost extracts the host from an IKE endpoint line, e.g.
// "local  '10.0.1.1' @ 10.0.1.1[500]" -> "10.0.1.1". The "[port]" suffix and
// any trailing "[virtual-ip]" tokens are stripped; IPv6 hosts are preserved
// because only the "[port]" bracket is removed.
func parseEndpointHost(line string) string {
	at := strings.Index(line, "@")
	if at < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[at+1:])
	if sp := strings.IndexAny(rest, " \t"); sp >= 0 {
		rest = rest[:sp]
	}
	if b := strings.IndexByte(rest, '['); b >= 0 {
		rest = rest[:b]
	}
	return rest
}

// parseTrafficLine extracts the SPI, byte count and packet count from a child
// SA counter line, e.g. "in  c1234567,  1420 bytes,    12 packets,     2s ago".
func parseTrafficLine(line string) (spi, bytesCount, packets string) {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		spi = strings.TrimRight(fields[1], ",")
	}
	for i, f := range fields {
		switch {
		case strings.HasPrefix(f, "bytes") && i > 0:
			bytesCount = strings.TrimRight(fields[i-1], ",")
		case strings.HasPrefix(f, "packets") && i > 0:
			packets = strings.TrimRight(fields[i-1], ",")
		}
	}
	return
}
