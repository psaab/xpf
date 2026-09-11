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
		for _, ref := range ikePol.Proposals {
			ikeProp, ok := cfg.IKEProposals[ref]
			if !ok {
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
			built = append(built, buildIKEProposalFromIKE(ikeProp))
		}
		if len(built) > 0 {
			return authMethod, strings.Join(built, ","), firstLifetime, aggressive, nil
		}
	}

	if !hasIKEChain(cfg, gw.IKEPolicy) {
		if prop, ok := cfg.Proposals[gw.IKEPolicy]; ok {
			return authMethod, buildIKEProposal(prop), prop.LifetimeSeconds, aggressive, nil
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
func resolveESPSettings(cfg *config.IPsecConfig, vpn *config.IPsecVPN) (string, int) {
	// ABSENT vs DANGLING (#4117). A VPN that names NO ipsec-policy at all
	// legitimately wants strongSwan's compiled-in "default" ESP suite — the
	// operator made no crypto choice, so the built-in default is their
	// explicit choice and nothing dangles. This is the ONLY path that emits
	// esp_proposals = default. A NAMED-but-unresolved (dangling) reference
	// must NEVER fall through to it (see the fail-closed fallback below).
	if vpn.IPsecPolicy == "" {
		return "default", 0
	}

	pfsGroup := 0
	if ipsecPol, ok := cfg.Policies[vpn.IPsecPolicy]; ok {
		pfsGroup = ipsecPol.PFSGroup
		// #3904: `proposals [ p1 p2 ]` offers every listed ESP proposal.
		// Build each resolvable reference (the policy-level PFS group
		// applies to all) and comma-join. An empty list falls back to a
		// proposal named after the policy, as before.
		propRefs := ipsecPol.Proposals
		if len(propRefs) == 0 {
			propRefs = []string{vpn.IPsecPolicy}
		}
		var built []string
		var firstLifetime int
		for _, propRef := range propRefs {
			if prop, ok := cfg.Proposals[propRef]; ok {
				if len(built) == 0 {
					firstLifetime = prop.LifetimeSeconds
				}
				built = append(built, buildESPProposal(prop, pfsGroup))
			}
		}
		if len(built) > 0 {
			return strings.Join(built, ","), firstLifetime
		}
		// Dangling proposal reference: the policy resolves but none of its
		// proposal references do. Fall through to the conservative fixed
		// fallback below — never bare "default".
	} else if prop, ok := cfg.Proposals[vpn.IPsecPolicy]; ok {
		// Legacy form: the ipsec-policy value is itself the NAME of a
		// defined ESP proposal (no policy object). Render it directly.
		return buildESPProposal(prop, 0), prop.LifetimeSeconds
	}
	// else: dangling POLICY reference — vpn.IPsecPolicy names neither a
	// defined ipsec-policy nor a defined ESP proposal. Fail closed below.

	// #4117 / #2073: a NAMED ipsec-policy reference did not resolve — either
	// the policy is undefined, or the policy resolves but its proposal
	// reference dangles. The commit-time strict validators
	// (validateIPsecPolicyProposalReferencesStrict) hard-reject this for new
	// operator edits, so this branch is only reached on a tolerant-path boot
	// of an already-persisted or peer-synced config (where the validator
	// downgraded to a warning so the node still boots).
	//
	// Do NOT fall through to bare "default" (strongSwan's compiled-in ESP
	// suite): a NAMED reference carries operator crypto intent, and
	// substituting the built-in default silently WEAKENS ESP — the same
	// silent-downgrade class the IKE (Phase-1) path fails closed on (#2270).
	// Emit a conservative FIXED suite instead: aes256-sha256, a strong known
	// cipher+integrity pair, carrying the configured perfect-forward-secrecy
	// group when one is set. A non-AEAD (CBC) ESP transform requires an
	// integrity algorithm, so the fallback always pairs a cipher with an
	// integrity alg (and a modp term when PFS is configured). The string is
	// built directly with swanctl's canonical keyword spellings (aes256 /
	// sha256 / modp<bits>): "sha256" is the strongSwan base keyword
	// normalizeAuthAlg maps hmac-sha-256-128 to (#3851), not the invalid
	// dash-stripped "sha256128" its proposal parser rejects. formatDHGroup
	// renders the PFS group with its canonical swanctl keyword — modp<bits>
	// for the MODP groups and the ECP/curve spellings for the elliptic-curve
	// groups (19->ecp256, 20->ecp384, ...) — so the #2392 ECP fix applies
	// here too. Direct spelling is used because the reference dangles (there
	// is no proposal object to hand to buildESPProposal), not because the
	// builder is unsafe.
	//
	// #4117 chose the conservative fixed fallback over the IKE-style
	// whole-VPN SKIP for ESP parity with #2073, which already emits this
	// fallback for the pfsGroup > 0 dangling case (with tests asserting the
	// suite is EMITTED, not skipped). Skipping only when pfsGroup == 0 would
	// fracture that: a no-PFS dangling config would lose its tunnel entirely
	// while an otherwise-identical with-PFS config keeps a working fallback
	// tunnel — a surprising availability asymmetry driven solely by whether
	// PFS happened to be configured. The tolerant/peer-sync boot path's
	// intent is to keep an already-persisted tunnel alive with strong,
	// known crypto rather than drop it; this fallback honours that intent
	// uniformly. IKE fails closed instead because it has no equivalent
	// strong fixed suite to offer.
	espProposals := "aes256-sha256"
	if pfsGroup > 0 {
		espProposals = fmt.Sprintf("aes256-sha256-%s", formatDHGroup(pfsGroup))
	}
	slog.Warn("ipsec policy reference does not resolve; emitting a "+
		"conservative fixed ESP suite instead of the strongSwan default "+
		"(a dangling reference must not silently weaken ESP crypto)",
		"policy", vpn.IPsecPolicy, "esp_proposals", espProposals,
		"pfs_group", pfsGroup)
	return espProposals, 0
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
	switch enc {
	case "aes-128-gcm", "aes128gcm":
		return "aes128gcm16", true
	case "aes-192-gcm", "aes192gcm":
		return "aes192gcm16", true
	case "aes-256-gcm", "aes256gcm":
		return "aes256gcm16", true
	}
	if strings.Contains(enc, "gcm") {
		// Already carries an ICV suffix (or some other GCM spelling);
		// strip Junos punctuation but otherwise leave it intact.
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
