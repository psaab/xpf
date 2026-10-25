package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsecname"
	"github.com/psaab/xpf/pkg/rendersafe"
)

// childSelector is a resolved child SA traffic-selector pair for swanctl
// config generation. ESP/DF/start/dpd/if_id are per-VPN (per-child in
// swanctl), so they travel with the child when several VPNs share one
// gateway connection (#15024).
type childSelector struct {
	Name         string
	LocalTS      string
	RemoteTS     string
	ESPProposals string
	ESPLifetime  int
	DFBit        string
	StartAction  string // "start", "trap", or "" (responder-only)
	DPDAction    string
	IfID         uint32
}

// gatewayConn is one swanctl connection: the shared IKE parameters of a
// gateway group plus every member VPN's children and PSKs (#15024).
type gatewayConn struct {
	name           string
	member         string // representative (first sorted) member VPN
	vpn            *config.IPsecVPN
	gw             *config.IPsecGateway
	remoteAddr     string
	localAddr      string
	authMethod     string
	ikeProposals   string
	ikeLifetime    int
	aggressive     bool
	dpdDelay       int
	dpdTimeout     int
	children       []childSelector
	pskValues      []pskValue
	pskSelectorKey string
}

// pskValue is one member PSK with its authored encoding (#15991,
// fold): hex is true only for a `pre-shared-key hexadecimal` value
// (#15027), which renders as the token `0x<value>` so strongSwan
// hex-decodes it. An ASCII value must reach charon as its literal
// bytes: swanctl's loader (strongSwan 6.1.0 load_creds.c load_secret)
// strips the settings quotes, then hex-decodes ANY value starting
// with "0x" (strcasepfx, either case) and base64-decodes any "0s"
// value — quoting changes nothing. An ASCII value starting with
// either prefix therefore renders base64-armored as `0s<base64 of
// the bytes>` (see swanctlSecretToken); every other ASCII value
// renders as the plain quoted string.
type pskValue struct {
	value string
	hex   bool
}

// isNamedGatewayVPN reports whether vpn references a defined gateway
// object (the #15024 grouped shape), as opposed to an inline endpoint
// or the empty endpoint, which keep per-VPN connections.
func isNamedGatewayVPN(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN) bool {
	if ipsecCfg == nil || vpn == nil || vpn.Gateway == "" {
		return false
	}
	_, ok := ipsecCfg.Gateways[vpn.Gateway]
	return ok
}

// gatewayKeyCollision reports whether the sanitized key is claimed by
// both a named-gateway connection and an inline/empty-endpoint VPN
// connection (#16676). Only that cross-kind fold is unsafe: two VPNs
// referencing the SAME gateway object intentionally share one
// connection, and two VPNs referencing DIFFERENT gateway objects can
// never share a key because the key IS the gateway name. An
// inline/empty VPN keys by its own name, so it collides with a
// gateway connection exactly when its name equals a gateway name
// that at least one other VPN references as a gateway object.
func gatewayKeyCollision(ipsecCfg *config.IPsecConfig, key string) bool {
	if ipsecCfg == nil || key == "" {
		return false
	}
	if _, isGateway := ipsecCfg.Gateways[key]; !isGateway {
		return false
	}
	hasGatewayMember, hasInlineMember := false, false
	for name, vpn := range ipsecCfg.VPNs {
		if vpn == nil {
			continue
		}
		if isNamedGatewayVPN(ipsecCfg, vpn) {
			if sanitizeSwanctlValue(vpn.Gateway) == key {
				hasGatewayMember = true
			}
		} else if sanitizeSwanctlValue(name) == key {
			hasInlineMember = true
		}
	}
	return hasGatewayMember && hasInlineMember
}

// gatewayKeyFor returns the swanctl connection name for vpn. A VPN
// referencing a defined gateway renders under the gateway name
// (#15024, shared by every VPN referencing that gateway); any other
// VPN (inline endpoint, empty endpoint, dangling reference) renders
// under its own name — EXCEPT when that key is cross-kind colliding
// (#16676): an inline/empty VPN whose name equals a gateway name
// used by another VPN. Folding those would drop the later member's
// peer/auth/proposals and negotiate its children (including the
// st0 if_id) with the wrong peer, so the inline VPN is prefixed
// with "inline-" to keep two distinct connections. The gateway
// connection keeps the bare gateway name (CONTROL unchanged). The
// prefix cannot itself collide: gateway and VPN names are
// section-safe (letters/digits/'-'/'_' via the #9495 gate), and a
// gateway literally named "inline-<x>" keys bare as "inline-<x>"
// while an inline VPN named "<x>" colliding with gateway "<x>"
// keys as "inline-<x>" — distinct gateway names give distinct
// prefixed keys, and an inline VPN can only collide with the
// gateway whose name equals its own.
func gatewayKeyFor(ipsecCfg *config.IPsecConfig, name string, vpn *config.IPsecVPN, gw *config.IPsecGateway) string {
	if gw != nil && isNamedGatewayVPN(ipsecCfg, vpn) {
		return sanitizeSwanctlValue(vpn.Gateway)
	}
	key := sanitizeSwanctlValue(name)
	if gatewayKeyCollision(ipsecCfg, key) {
		return "inline-" + key
	}
	return key
}

func (m *Manager) generateConfig(ipsecCfg *config.IPsecConfig) string {
	cfg, _, _ := m.renderConfig(ipsecCfg)
	return cfg
}

// renderConfig renders the swanctl snippet and returns the EXACT set of
// swanctl connection names it actually emitted. Since #15024 a connection
// is per IKE gateway: VPNs sharing a named gateway render as children of
// the gateway-named connection, so the returned set holds gateway names
// (the sanitized VPN name only for inline/empty endpoints, where each VPN
// keeps its own connection). A VPN present in ipsecCfg.VPNs but OMITTED
// from the render — a skip class: an unrenderable gateway reference
// (#2074), an unresolved ike-policy chain (#2270), an unusable IKE DH group
// (#9919 F-161), an unsupported IKE authentication method, a malformed PSK,
// a PSK connection with no effective secret (#14139), a responder-only or
// gateway-less PSK connection with no peer identity to scope its secret
// to (#14591/#15989), a `protocol ah` proposal with no ESP render path
// (#4298), a section-breaking VPN or gateway name (#9495), an unresolved
// ipsec-policy chain (#9919 F-090), an unusable ESP/PFS DH group
// (#9919 F-161), a non-empty bind-interface that resolves to no XFRM
// if_id (#10681), an external-interface with no resolved local-address
// (#11689), or an explicit selector set with no renderable children (#10884) —
// is NOT in
// the returned set even though renderConfig still returns success. Apply
// diffs THIS rendered set (not the raw VPN map keys) so a previously-loaded
// connection that dropped out of the render is treated as a removal and its
// stale child SA is torn down (#5494). Returning the rendered set is the
// single source of truth for "what is actually loaded", so the skip logic
// here can never drift from the teardown diff in promoteConnNames.
// renderConfig is renderConfigMembers with only the connection set
// returned; see renderedMembers for the per-VPN membership contract.
func (m *Manager) renderConfig(ipsecCfg *config.IPsecConfig) (string, map[string]bool, error) {
	text, rendered, _, err := m.renderConfigMembers(ipsecCfg)
	return text, rendered, err
}

// renderedMembers reports, per configured VPN name, whether that VPN
// survived the render and contributed a child to its connection
// (#15989 fold). Connection-name membership alone (rendered[conn]) is
// NOT proof a given VPN survived: a gateway-less VPN skipped by the
// #15989 belt maps to its own name, which may equal a healthy named
// gateway's connection rendered for a sibling VPN, and name-based
// projections (ConnectionNamesForVPN, ExpectedLoadedConns,
// re-initiation) would then falsely treat the skipped VPN as loaded.
// Every projection must consult this set, never rendered[conn] alone.
//
// renderConfigMembers is the fail-closed render plus the membership set.
func (m *Manager) renderConfigMembers(ipsecCfg *config.IPsecConfig) (string, map[string]bool, map[string]bool, error) {
	return m.renderConfigMembersWithExternalInterfaceFailClosed(ipsecCfg, true)
}

// renderConfigForConfigOnly is for projections that cannot consult live
// interface addresses. It keeps the configured VPN candidate visible so
// ExpectedLoadedConns can report runtime-dependent local addresses as
// unvalidatable, while SA-name and selector-fence projections stay
// conservative. Production config always uses renderConfig above.
func (m *Manager) renderConfigForConfigOnly(ipsecCfg *config.IPsecConfig) (string, map[string]bool, error) {
	text, rendered, _, err := m.renderConfigMembersForConfigOnly(ipsecCfg)
	return text, rendered, err
}

// renderConfigMembersForConfigOnly is the config-only membership
// variant (see renderConfigMembers).
func (m *Manager) renderConfigMembersForConfigOnly(ipsecCfg *config.IPsecConfig) (string, map[string]bool, map[string]bool, error) {
	return m.renderConfigMembersWithExternalInterfaceFailClosed(ipsecCfg, false)
}

func (m *Manager) renderConfigMembersWithExternalInterfaceFailClosed(
	ipsecCfg *config.IPsecConfig, failClosedExternalInterface bool,
) (string, map[string]bool, map[string]bool, error) {
	var b strings.Builder

	b.WriteString("# xpf managed config - do not edit\n\n")

	// skipped records VPNs whose gateway reference is not renderable
	// (#2074) so the secrets block below emits no orphan secret for a
	// connection that was never written.
	skipped := make(map[string]bool)

	// renderedMembers accumulates the names of VPNs that survived every
	// skip check and contributed a child (see renderConfigMembers).
	renderedMembers := make(map[string]bool)

	// rendered accumulates the sanitized connection name (gateway name for
	// a named-gateway group, VPN name for inline/empty endpoints, #15024)
	// of every connection emitted into connections{}. This is the
	// authoritative "loaded connection set" Apply diffs against
	// prevConnNames (#5494).
	rendered := make(map[string]bool)
	// decodedPSKs caches validated values for the secrets block, keyed by
	// VPN name. A malformed key skips its VPN before emitting a connection.
	decodedPSKs := make(map[string]string, len(ipsecCfg.VPNs))
	// hexPSKs marks the subset of decodedPSKs whose value is hex
	// digits authored as `pre-shared-key hexadecimal` (#15027): those
	// render unquoted as `secret = 0x<hex>` so strongSwan derives the
	// raw bytes the peer holds, not the ASCII digits.
	hexPSKs := make(map[string]bool, len(ipsecCfg.VPNs))

	// groups collects surviving VPNs by connection key in sorted order.
	groups := make(map[string]*gatewayConn)
	var groupOrder []string

	// Connections are collected first, then emitted grouped by gateway.
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]
		// Expand once before writing the connection so an explicit selector set
		// with no renderable children skips this VPN rather than loading a
		// connection whose malformed local_ts/remote_ts made charon discard it.
		children := effectiveTrafficSelectors(name, vpn)
		if len(children) == 0 {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: no traffic-selector child has renderable local/remote selectors",
				"vpn", name)
			continue
		}

		// Resolve the remote gateway endpoint. remote_addrs must be a
		// real IP / hostname strongSwan can use — never a bare gateway
		// config-object name (#2074). The hard diagnostic for a bad
		// reference is the commit-time validator
		// (validateIPsecGatewayReferencesStrict); this render belt is the
		// by-construction backstop for any path that reaches render
		// without passing local commit (HA peer-sync, direct
		// IPsecConfig construction, a config persisted before the fix).
		remoteAddr, localAddr, gw, ok := resolveRemoteAddr(ipsecCfg, vpn)
		if !ok {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: ike gateway not renderable "+
				"(undefined or addressless) — fix the gateway reference",
				"vpn", name, "gateway", vpn.Gateway)
			continue
		}
		if failClosedExternalInterface && gw != nil && gw.ExternalIface != "" && localAddr == "" {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: external-interface has no resolvable local address; omitting local_addrs would bind all local addresses, including management interfaces — configure an address or fix the interface",
				"vpn", name, "external_interface", gw.ExternalIface)
			continue
		}

		// Resolve the IKE settings BEFORE writing the connection block so a
		// gateway whose ike-policy chain does not resolve SKIPS this VPN
		// instead of emitting a proposal-less connection (#2270). An empty
		// `proposals =` line lets strongSwan fall back to its compiled-in
		// default phase-1 set — a silent crypto downgrade. The hard
		// diagnostic for a dangling reference is the commit-time validator
		// (validateIKEPolicyChainReferencesStrict); this render belt is the
		// by-construction backstop for any path that reaches render without
		// passing local commit (HA peer-sync, direct IPsecConfig
		// construction, a config persisted before the fix). One bad
		// reference never zeroes a healthy tunnel. Unsupported auth-methods
		// carry errProposalUnresolved and are skipped per VPN, like unsafe
		// proposal values.
		authMethod, ikeProposals, ikeLifetime, aggressive, err := resolveIKESettings(ipsecCfg, gw)
		if err != nil {
			if errors.Is(err, errIKEChainUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: ike-policy chain does not "+
					"resolve — fix the ike-policy / ike-proposal reference "+
					"(emitting no proposal would silently downgrade phase-1 "+
					"to strongSwan defaults)",
					"vpn", name, "ike_policy", gw.IKEPolicy)
				continue
			}
			// #9919 F-161: an unusable IKE DH group skips this VPN like a
			// dangling chain — it must never abort the whole render (one
			// bad value would zero every healthy tunnel). The error names
			// the offending values.
			if errors.Is(err, errDHGroupUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: unusable Diffie-Hellman group "+
					"(emitting the proposal would silently drop the modp term "+
					"or render a keyword charon refuses) — fix the dh-group value",
					"vpn", name, "detail", err.Error())
				continue
			}
			if errors.Is(err, errProposalUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: no safe IKE proposal set remains "+
					"(unsupported authentication or unsafe/conflicting proposal settings)",
					"vpn", name, "detail", err.Error())
				continue
			}
			return "", nil, nil, fmt.Errorf("vpn %s: %w", name, err)
		}

		// #4298 (V-2): a proposal with `protocol ah` (Authentication Header)
		// has no ESP render path — buildESPProposal would default the empty
		// encryption to aes256 and renderConfig would emit esp_proposals, so
		// the operator would silently get ESP with a fabricated cipher instead
		// of the AH (integrity-only) they asked for. The commit-time gate
		// (validateIPsecProposalProtocolStrict) hard-rejects AH, so this belt
		// only fires on the tolerant load / peer-sync path or a directly-
		// constructed IPsecConfig: SKIP the VPN rather than emit a fabricated
		// ESP tunnel, mirroring the errIKEChainUnresolved skip above.
		if vpnUsesAHProposal(ipsecCfg, vpn) {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: ipsec proposal uses protocol ah "+
				"(Authentication Header) which xpf does not support — use "+
				"protocol esp (rendering ESP would fabricate a cipher the "+
				"operator never specified)",
				"vpn", name, "ipsec_policy", vpn.IPsecPolicy)
			continue
		}

		// #9495: a VPN name written raw as a section header must not break the
		// swanctl file. Commit refuses such a name (validateIPsecSectionNamesStrict);
		// this belt covers a persisted or peer-synced one. One such name would
		// otherwise make strongSwan discard EVERY tunnel in the file, or inject
		// settings. SKIP it (the secrets block honours skipped too) and keep the rest.
		// Since #15024 the connection/secret headers carry the gateway name
		// for a named group, so that name is checked too; a solo VPN's child
		// is named after the VPN, so its own name is checked regardless.
		connKey := gatewayKeyFor(ipsecCfg, name, vpn, gw)
		if ipsecname.SectionBreaking(sanitizeSwanctlValue(name)) || ipsecname.SectionBreaking(connKey) {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: its name would break the swanctl section it is "+
				"written into (whitespace, a brace, '#', '=', ',', a quote, '.', '%', ':' "+
				"or non-ASCII); rename the VPN to letters, digits, '-' and '_' (#9495)",
				"vpn", name)
			continue
		}

		// #16676 render belt: a surviving VPN whose gatewayKeyFor key
		// is already owned by a group with different IKE parameters
		// (resolved gateway object, remote/local address, or auth
		// method) must never fold silently — the first member would
		// supply the peer and this VPN's children would negotiate
		// with the wrong peer. gatewayKeyFor already separates the
		// known cross-kind (inline-vs-gateway-name) collision by
		// construction; this belt catches any residual same-key
		// different-peer fold (e.g. sanitized-name aliasing) on the
		// tolerant load / peer-sync path: skip the later VPN, keep
		// the first, never drop its peer silently.
		if existing, ok := groups[connKey]; ok {
			if existing.gw != gw || existing.remoteAddr != remoteAddr || existing.localAddr != localAddr || existing.authMethod != authMethod {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: its swanctl connection name is already claimed by a VPN with a different gateway endpoint — rename the VPN or the gateway so each peer gets its own connection (#16676)",
					"vpn", name, "connection", connKey)
				continue
			}
		}

		// #10681: a NON-EMPTY bind-interface that resolves to no XFRM if_id
		// (anything but st<N> / st<N>.<unit>, e.g. secure0 or ge-0/0/0) is
		// the #5297 invalid-name arm's subject: the strict commit gate rejects
		// it, and the lenient load / peer-sync path warns that the VPN
		// "carries no traffic (silent tunnel down)". The render must agree
		// with that diagnostic: without this skip the connection and its
		// children are still emitted — only the if_id_in/out lines are gated
		// on if_id > 0 below — so strongSwan loads a live if_id-less SA
		// (explicit traffic-selectors, or the identity fallback, or the
		// strongSwan dynamic default) under a "carries no traffic" claim,
		// and the #5619 plaintext advisory skips the VPN on the same false
		// premise. SKIP it: no connection, no children, and (via skipped)
		// no orphan secret. An EMPTY bind-interface is NOT skipped here —
		// that is the #10638 missing arm (quarantine backstop), and the
		// policy-based rows in policy_10427_test.go pin that it renders.
		if vpn.BindInterface != "" && xfrmiIfID(vpn.BindInterface) == 0 {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: bind-interface is not a secure-tunnel "+
				"interface (must be st<N> or st<N>.<unit>); without an XFRM if_id "+
				"the tunnel cannot come up route-based — fix the bind-interface "+
				"(emitting the connection would load a live SA the #5297 "+
				"diagnostic describes as carrying no traffic)",
				"vpn", name, "bind_interface", vpn.BindInterface)
			continue
		}

		// Resolve the ESP settings BEFORE writing the connection block so a
		// VPN whose ipsec-policy chain does not resolve, or whose effective
		// DH group is unusable, SKIPS like the IKE chain above (#9919 F-090
		// / F-161) instead of emitting a fabricated suite or a weakened /
		// charon-refused proposal. The hard diagnostics are the commit-time
		// validators (validateIPsecPolicyProposalReferencesStrict,
		// validateIPsecDHGroupsStrict); this render belt is the
		// by-construction backstop for any path that reaches render without
		// passing local commit. Every error this resolver returns today is
		// skip-class; the abort arm stays as documented-defensive symmetry
		// with the IKE branch above (a future hard-error class must fail
		// the render loudly, never render past it).
		espProposals, espLifetime, err := resolveESPSettings(ipsecCfg, vpn)
		if err != nil {
			if errors.Is(err, errESPChainUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: ipsec-policy chain does not "+
					"resolve — fix the ipsec-policy / ipsec-proposal reference "+
					"(rendering a substitute suite would negotiate crypto the "+
					"operator never authored)",
					"vpn", name, "detail", err.Error())
				continue
			}
			if errors.Is(err, errDHGroupUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: unusable Diffie-Hellman group "+
					"(emitting the proposal would silently drop PFS or render "+
					"a keyword charon refuses) — fix the dh-group / keys value",
					"vpn", name, "detail", err.Error())
				continue
			}
			if errors.Is(err, errProposalUnresolved) {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: no safe ESP proposal remains "+
					"(an unsafe algorithm or missing integrity term would "+
					"weaken/change the swanctl proposal)",
					"vpn", name, "detail", err.Error())
				continue
			}
			return "", nil, nil, fmt.Errorf("vpn %s: %w", name, err)
		}
		// Normalize the effective PSK before emitting the connection. A bad
		// Junos $9$ value must leave this VPN out of the rendered set, so Apply
		// unloads it and tears down any stale SA instead of aborting before
		// promoteConnNames.
		secret := vpn.PSK.Reveal()
		secretHex := vpn.PSKHex
		secretBadHex := vpn.PSKHex && !validHexPSKRender(secret)
		if secret == "" && gw != nil {
			if ikePol, ok := ipsecCfg.IKEPolicies[gw.IKEPolicy]; ok && ikePol != nil {
				secret = ikePol.PSK.Reveal()
				secretHex = ikePol.PSKHex
				secretBadHex = ikePol.PSKHex && !validHexPSKRender(secret)
			}
		}
		if secret != "" && secretBadHex {
			// #15027 render belt: a hex-flagged value that is not
			// valid even-length hex (directly constructed or
			// peer-synced config that bypassed the strict commit
			// gate) must never render as an ASCII secret — skip
			// like every other malformed-PSK class so Apply
			// unloads it and tears down any stale SA.
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: hexadecimal pre-shared "+
				"key is not valid hexadecimal (must be non-empty, "+
				"even-length hex digits) — fix the key or use "+
				"ascii-text", "vpn", name)
			continue
		}
		if secret != "" {
			decoded, err := normalizePSK(secret)
			if err != nil {
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: malformed pre-shared key "+
					"(invalid Junos $9$ encoding) — replace it with a valid key",
					"vpn", name, "detail", err.Error())
				continue
			}
			if decoded == "" {
				// #15990 render belt: a key that decodes to zero
				// bytes must never be stored — the secrets block
				// would emit `secret = ""`, which strongSwan
				// rejects at load and which is never a legitimate
				// credential. (Unreachable for `$9$` values since
				// the #15990 decoder fix; kept so no future decoder
				// change can reintroduce the empty emission.)
				skipped[name] = true
				slog.Warn("skipping IPsec VPN: pre-shared key "+
					"decodes to an empty secret — replace it with a valid key",
					"vpn", name)
				continue
			}
			decodedPSKs[name] = decoded
			if secretHex {
				hexPSKs[name] = true
			}
		} else if authMethod == "psk" {
			// A PSK connection with no effective secret (#14139, D5-06)
			// would render auth = psk with no matching secrets{} entry,
			// leaving strongSwan to consult another VPN's secret whose
			// identities overlap. Every other credential/render failure
			// skips the VPN; a missing credential must do the same
			// (fail-closed), so Apply unloads it and tears down any
			// stale SA. Pubkey (certificate) VPNs have no PSK by
			// design and are unaffected.
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: pre-shared-key authentication "+
				"with no pre-shared key configured (neither the vpn "+
				"pre-shared-key nor the ike-policy fallback) — configure "+
				"a key (rendering the connection without a secret would "+
				"let strongSwan select another VPN's secret)",
				"vpn", name)
			continue
		}

		// #15752 (G18-02): a pubkey VPN with no effective local certificate
		// (gateway, else ike-policy via EffectiveLocalCertificate) would
		// render auth = pubkey with no certs — charon then picks any loaded
		// cert or fails IKE_AUTH. Skip like every other credential failure;
		// the strict gate is validateIPsecCertAuthStrict.
		if authMethod == "pubkey" && config.EffectiveLocalCertificate(ipsecCfg, vpn, gw) == "" {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: public-key authentication "+
				"with no local-certificate configured (neither the gateway "+
				"local-certificate nor the ike-policy fallback) — configure "+
				"a local-certificate (rendering the connection without a "+
				"certificate would let strongSwan select any loaded "+
				"certificate)", "vpn", name)
			continue
		}

		// A responder-only or gateway-less PSK VPN with no peer identity
		// (#14591, Y09-04; #15989, H-4) accepts an initiator from any
		// address, and with no configured peer identity/endpoint its
		// secret carries no peer id selector — a lone "%any" local-owner
		// selector — so it matches any peer, and strongSwan's key
		// selection by the claimed IDi lets a holder of another VPN's PSK
		// authenticate into this connection by claiming that site's
		// identity. Every other credential failure skips the VPN; an
		// unscoped responder secret must do the same (fail-closed), so
		// Apply unloads it and tears down any stale SA. The commit-time
		// gate (validateIPsecResponderIdentityStrict) hard-rejects both
		// shapes; this belt covers the tolerant load / peer-sync path.
		// Gateway-less: gw == nil && remoteAddr == "" (resolveRemoteAddr's
		// empty-endpoint arm). Inline endpoints (gw == nil but a usable
		// IP/hostname remote) keep rendering — the peer address scopes
		// their secret. Pubkey (certificate) VPNs are unaffected. The
		// peer identity may be an explicit remote-identity or the
		// `dynamic hostname` FQDN (#14590) — either satisfies the
		// responder-only gate. Use responderOnlyGateway so a
		// dynamic-hostname gateway whose ResponderOnly flag was not
		// carried is gated identically.
		if authMethod == "psk" && gw == nil && remoteAddr == "" {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: no ike gateway configured, "+
				"so its pre-shared key cannot be scoped to a peer — "+
				"configure an ike gateway with an address or an "+
				"inline gateway endpoint (rendering the connection "+
				"would let a holder of another VPN's key authenticate "+
				"into it by claiming that peer's identity)",
				"vpn", name)
			continue
		}
		if authMethod == "psk" && responderOnlyGateway(gw) && gw.RemoteIDValue == "" && gw.DynamicHostname == "" {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: responder-only gateway has "+
				"no remote-identity or dynamic hostname, so its "+
				"pre-shared key cannot be scoped to the peer — "+
				"configure a remote-identity on the gateway "+
				"(rendering the connection would let a holder of "+
				"another VPN's key authenticate into it by "+
				"claiming that peer's identity)",
				"vpn", name, "gateway", vpn.Gateway)
			continue
		}
		// #16708: a hostname-addressed PSK gateway (or inline hostname
		// endpoint) with no explicit remote-identity has no peer
		// identity to scope by either: the hostname is a dial target,
		// never the identity the peer presents (#16680), so the secret
		// would carry no peer selector at all. Pre-#16708 it carried
		// only the box-shared local owner (%any / pinned local address /
		// local-id), which charon's responder-side verifier tries
		// against every peer (mem_cred matches a secret when ANY owner
		// equals either side), so a holder of any other VPN's PSK was
		// accepted on the strength of the shared local side alone.
		// Fail closed exactly like the responder-only shape above:
		// commit rejects (validateIPsecResponderIdentityStrict) and
		// this belt skips the VPN on tolerant load / peer sync. A
		// mixed hostname+IP list keeps rendering: its IP literals
		// still scope the secret. Pubkey VPNs are unaffected.
		if authMethod == "psk" && !responderOnlyGateway(gw) && len(pskPeerSelectors(remoteAddr, gw)) == 0 {
			skipped[name] = true
			slog.Warn("skipping IPsec VPN: hostname-addressed gateway "+
				"has no remote-identity, so its pre-shared key cannot "+
				"be scoped to the peer — configure a remote-identity "+
				"on the gateway or address it by IP literal "+
				"(rendering the connection would let a holder of "+
				"another VPN's key authenticate into it)",
				"vpn", name, "gateway", vpn.Gateway)
			continue
		}

		// This VPN passed every skip check. Fold it into its gateway
		// connection (#15024): the first (sorted) member supplies the
		// shared IKE parameters; later members contribute only children
		// and PSKs. Per-child settings ride on each childSelector.
		dpd := deriveDPD(gw, vpn)
		startAction := ""
		if gw == nil || !responderOnlyGateway(gw) {
			switch vpn.EstablishTunnels {
			case "immediately":
				startAction = "start"
			case "on-traffic", "":
				startAction = "trap"
			}
		}
		ifID := xfrmiIfID(vpn.BindInterface)
		enriched := make([]childSelector, len(children))
		for i, c := range children {
			c.ESPProposals = espProposals
			c.ESPLifetime = espLifetime
			c.DFBit = vpn.DFBit
			c.StartAction = startAction
			c.DPDAction = dpd.Action
			c.IfID = ifID
			enriched[i] = c
		}
		gc, exists := groups[connKey]
		if !exists {
			gc = &gatewayConn{
				name: connKey, member: name, vpn: vpn, gw: gw,
				remoteAddr: remoteAddr, localAddr: localAddr,
				authMethod: authMethod, ikeProposals: ikeProposals,
				ikeLifetime: ikeLifetime, aggressive: aggressive,
				dpdDelay: dpd.Delay, dpdTimeout: dpd.Timeout,
				pskSelectorKey: name,
			}
			groups[connKey] = gc
			groupOrder = append(groupOrder, connKey)
			rendered[connKey] = true
		}
		gc.children = append(gc.children, enriched...)
		renderedMembers[name] = true
		if d, ok := decodedPSKs[name]; ok {
			// #15991: carry the authored encoding with the value
			// through the gateway-group fold. A hex PSK and an
			// ASCII value that literally starts with "0x" are
			// distinct credentials and must dedupe and render
			// distinctly — never by string prefix alone.
			pv := pskValue{value: d, hex: hexPSKs[name]}
			seen := false
			for _, v := range gc.pskValues {
				if v == pv {
					seen = true
				}
			}
			if !seen {
				gc.pskValues = append(gc.pskValues, pv)
			}
		}
	}
	sort.Strings(groupOrder)

	b.WriteString("connections {\n")
	for _, key := range groupOrder {
		gc := groups[key]
		gw := gc.gw
		fmt.Fprintf(&b, "  %s {\n", gc.name)
		if gw != nil && gw.Version == "v2-only" {
			b.WriteString("    version = 2\n")
		} else if gw != nil && gw.Version == "v1-only" {
			b.WriteString("    version = 1\n")
		}
		if gc.aggressive {
			b.WriteString("    aggressive = yes\n")
		}
		// local_addrs / remote_addrs: sanitized like before (#6469) — an
		// embedded newline must not inject a connection-level directive.
		if gc.localAddr != "" {
			fmt.Fprintf(&b, "    local_addrs = %s\n", sanitizeSwanctlValue(gc.localAddr))
		}
		if gc.remoteAddr != "" {
			fmt.Fprintf(&b, "    remote_addrs = %s\n", sanitizeSwanctlValue(gc.remoteAddr))
		}
		if gw != nil {
			switch gw.NATTraversal {
			case "disable":
				b.WriteString("    encap = no\n")
			case "force":
				b.WriteString("    encap = yes\n")
			default:
				if gw.NoNATTraversal {
					b.WriteString("    encap = no\n")
				}
			}
		}
		if gc.dpdDelay > 0 {
			fmt.Fprintf(&b, "    dpd_delay = %ds\n", gc.dpdDelay)
		}
		if gc.dpdTimeout > 0 {
			fmt.Fprintf(&b, "    dpd_timeout = %ds\n", gc.dpdTimeout)
		}
		b.WriteString("    local {\n")
		fmt.Fprintf(&b, "      auth = %s\n", gc.authMethod)
		// #15752: certs only on pubkey, from the effective cert (gateway
		// wins over ike-policy). A psk local{} must never carry certs.
		if gc.authMethod == "pubkey" {
			if cert := config.EffectiveLocalCertificate(ipsecCfg, gc.vpn, gw); cert != "" {
				fmt.Fprintf(&b, "      certs = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(cert)))
			}
		}
		if gw != nil && gw.LocalIDValue != "" {
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity(gw.LocalIDType, gw.LocalIDValue))))
		}
		b.WriteString("    }\n")
		b.WriteString("    remote {\n")
		fmt.Fprintf(&b, "      auth = %s\n", gc.authMethod)
		if gw != nil && gw.RemoteIDValue != "" {
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))))
		} else if gw != nil && gw.DynamicHostname != "" {
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity("hostname", gw.DynamicHostname))))
		} else if gc.authMethod == "psk" && !responderOnlyGateway(gw) {
			// #15193: Junos's default remote identity is the gateway
			// address. Render it so the peer identity charon initiates
			// against (and expects as IDr) is pinned instead of left to
			// negotiate. PSK only — pubkey peer verification is
			// certificate-based and must not gain an invented id, and a
			// responder-only peer has no fixed address to default to.
			//
			// #15766: that default is only sound for a SINGLE-address
			// peer. swanctl `remote.id` takes exactly one identity, so
			// pinning the first address of a multi-address gateway
			// rejects the same peer presenting from any other
			// configured address (address fallback / dual-homed peer).
			// With no single identity to pin, omit the default and let
			// charon negotiate the peer's presented address identity;
			// the PSK stays scoped by one id-<n> selector per peer
			// address (pskIDSelectorsLocal, #14139), so no unscoped
			// secret results.
			//
			// #16680: a single HOSTNAME address likewise yields no
			// default id — the hostname is a dial target, never the
			// identity a default-identity peer presents (its resolved
			// IP). defaultRemoteID enforces the IP-literal check.
			if gw != nil {
				if id := defaultRemoteID(gw); id != "" {
					fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(id)))
				}
			} else if addrs := config.SplitIPsecEndpointList(gc.remoteAddr); len(addrs) == 1 && addrs[0] != "%any" {
				// Inline endpoint (no gateway object): the dialed
				// address is likewise the default peer identity — for
				// a single-address endpoint only (#15766), and only
				// when it is an IP literal (#16680): a hostname dial
				// target is never the identity the peer presents.
				if _, err := netip.ParseAddr(addrs[0]); err == nil {
					fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(addrs[0])))
				}
			}
		}
		b.WriteString("    }\n")
		if gc.ikeProposals != "" {
			fmt.Fprintf(&b, "    proposals = %s\n", sanitizeSwanctlValue(gc.ikeProposals))
		}
		// #9919 F-163: rekey_time without rand_time (strongSwan default jitter).
		if lt := clampIPsecLifetimeSeconds(gc.ikeLifetime); lt > 0 {
			fmt.Fprintf(&b, "    rekey_time = %ds\n", lt)
		}
		fmt.Fprintf(&b, "    children {\n")
		for _, child := range gc.children {
			fmt.Fprintf(&b, "      %s {\n", sanitizeSwanctlValue(child.Name))
			if child.LocalTS != "" {
				fmt.Fprintf(&b, "        local_ts = %s\n", sanitizeSwanctlValue(child.LocalTS))
			}
			if child.RemoteTS != "" {
				fmt.Fprintf(&b, "        remote_ts = %s\n", sanitizeSwanctlValue(child.RemoteTS))
			}
			fmt.Fprintf(&b, "        esp_proposals = %s\n", sanitizeSwanctlValue(child.ESPProposals))
			if child.ESPLifetime > 0 {
				fmt.Fprintf(&b, "        rekey_time = %ds\n", clampIPsecLifetimeSeconds(child.ESPLifetime))
			}
			switch child.DFBit {
			case "copy", "set":
				fmt.Fprintf(&b, "        copy_df = yes\n")
			case "clear":
				fmt.Fprintf(&b, "        copy_df = no\n")
			}
			if child.StartAction != "" {
				fmt.Fprintf(&b, "        start_action = %s\n", child.StartAction)
			}
			if child.DPDAction != "" {
				fmt.Fprintf(&b, "        dpd_action = %s\n", child.DPDAction)
			}
			if child.IfID > 0 {
				fmt.Fprintf(&b, "        if_id_in = %d\n", child.IfID)
				fmt.Fprintf(&b, "        if_id_out = %d\n", child.IfID)
			}
			fmt.Fprintf(&b, "      }\n")
		}
		fmt.Fprintf(&b, "    }\n")
		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n\n")

	// Secrets — one ike-<connection> block per connection (#15024), holding
	// every member VPN's distinct PSK comma-joined (swanctl `secret` is a
	// comma-separated list) and scoped by the representative member's peer
	// selectors (#3952). Identical PSKs collapse to one value.
	b.WriteString("secrets {\n")
	for _, key := range groupOrder {
		gc := groups[key]
		if len(gc.pskValues) == 0 {
			continue
		}
		remoteAddr, localAddr, gw, _ := resolveRemoteAddr(ipsecCfg, gc.vpn)
		fmt.Fprintf(&b, "  ike-%s {\n", gc.name)
		if len(gc.pskValues) == 1 && gc.pskValues[0].hex {
			// #15027 (A16-04): a lone hexadecimal PSK renders as
			// raw bytes — swanctl's `0x` prefix makes strongSwan
			// hex-decode the value (validated hex, no quoting
			// needed), matching the peer holding the same Junos
			// hex key. Quoting it derived the ASCII digits.
			fmt.Fprintf(&b, "    secret = 0x%s\n", gc.pskValues[0].value)
		} else {
			// ASCII and grouped renders go through
			// swanctlSecretRendered: the loader decodes the
			// VALUE, not the quoting (#15991 fold) — a quoted
			// "0x…" still hex-decodes, so a colliding ASCII
			// value is base64-armored (`0s<base64>`), which
			// charon base64-decodes back to the literal bytes.
			fmt.Fprintf(&b, "    secret = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(swanctlSecretRendered(gc.pskValues))))
		}
		// Scope this PSK to its peer with id selectors (#3952). A PSK
		// secret with NO id matches ANY peer, so with two or more PSK
		// VPNs strongSwan can bind the wrong secret to a peer and IKE
		// authentication fails. Each id-<n> narrows the secret to a
		// peer whose IKE identity matches — the configured remote-id,
		// else the remote gateway address (#16708: no box-shared local
		// owner; see pskIDSelectorsLocal).
		for i, sel := range pskIDSelectorsLocal(remoteAddr, localAddr, gw) {
			fmt.Fprintf(&b, "    id-%d = \"%s\"\n", i+1,
				escapeSwanctlQuoted(sanitizeSwanctlValue(sel)))
		}
		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n")

	return b.String(), rendered, renderedMembers, nil
}

// resolveRemoteAddr resolves the swanctl remote_addrs value for a VPN, plus
// the effective local address and the resolved gateway. ok=false means there
// is nothing usable to render — the caller MUST skip the connection so a bare
// gateway config-object NAME never leaks into remote_addrs (#2074):
//
//   - defined gateway with an address            -> remote = that (dialed)
//   - defined gateway flagged responder-only     -> remote = "%any"
//     (strongSwan responds, never initiates). This covers both bare
//     `dynamic` and `dynamic hostname <fqdn>`: the FQDN is the peer's
//     expected IKE identity (rendered as remote id @FQDN and as the PSK
//     selector), never a DNS dial target (#14590). A peer that should be
//     dialed by name is expressed with gateway `address <fqdn>`.
//   - defined gateway with a dynamic hostname but NOT flagged
//     responder-only (directly constructed / peer-synced config) is
//     likewise treated as responder-only: DynamicHostname only ever
//     means the identity form (#14590)
//   - defined gateway with neither + not responder-only   -> ok=false
//   - no gateway object, vpn.Gateway is a usable IP/host -> remote = it
//   - no gateway object, vpn.Gateway empty               -> ok=true,
//     remote="" (connection emitted with no remote_addrs line, as before)
//   - no gateway object, vpn.Gateway a dangling/dotless name -> ok=false
//
// This mirrors the commit-time validator validateIPsecGatewayReferencesStrict
// exactly, using the same config.IsUsableIPsecEndpoint predicate.
// responderOnlyGateway reports whether gw never initiates: the compiled
// ResponderOnly flag, or a `dynamic hostname` gateway whose flag was not
// carried (direct construction / peer sync) — DynamicHostname only ever
// means the responder identity form (#14590).
func responderOnlyGateway(gw *config.IPsecGateway) bool {
	return gw != nil && (gw.ResponderOnly || gw.DynamicHostname != "")
}

func resolveRemoteAddr(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN) (
	remoteAddr, localAddr string, gw *config.IPsecGateway, ok bool) {

	localAddr = vpn.LocalAddr
	if g, found := ipsecCfg.Gateways[vpn.Gateway]; found {
		gw = g
		switch {
		case gw.Address != "":
			remoteAddr = gw.Address
		case gw.ResponderOnly || gw.DynamicHostname != "":
			// Responder-only / dynamic-IP peer (#2404, #14590): the peer
			// initiates from an unknown source address, so strongSwan
			// listens with remote_addrs = %any and never initiates.
			remoteAddr = "%any"
		default:
			// Gateway exists but has nothing routable and is not flagged
			// responder-only. Do NOT fall back to the object name.
			return "", localAddr, gw, false
		}
		if gw.LocalAddress != "" && localAddr == "" {
			localAddr = gw.LocalAddress
		}
		return remoteAddr, localAddr, gw, true
	}
	if vpn.Gateway == "" {
		// Legitimately omitted remote endpoint — emit the connection with
		// no remote_addrs line (unchanged behavior).
		return "", localAddr, nil, true
	}
	if config.IsUsableIPsecEndpointList(vpn.Gateway) {
		// Legacy inline shape: the VPN names the peer endpoint directly
		// as a literal IP or dotted hostname, with no Gateways entry —
		// possibly a comma-separated multi-address list (#15766), which
		// remote_addrs renders verbatim.
		return vpn.Gateway, localAddr, nil, true
	}
	// Dangling / dotless single-label name — not a known gateway and not
	// a usable IP/hostname. Rendering it would leak the name.
	return "", localAddr, nil, false
}

// ConnectionNamesForVPN maps each VPN in ipsecCfg to the swanctl connection
// name its surviving render contributes to (#15024): the gateway name for a
// named-gateway group, else the VPN name. VPNs the renderer skips are absent.
// Membership is per-VPN (renderedMembers), never rendered[conn] alone: a
// skipped VPN whose own name equals a healthy named gateway's connection
// must not inherit that connection (#15989 fold). It renders once
// (production fail-closed via PrepareConfig) — callers must not re-derive
// the grouping.
func ConnectionNamesForVPN(cfg *config.Config) map[string]string {
	if cfg == nil {
		return nil
	}
	ipsecCfg := PrepareConfig(cfg)
	_, _, members, err := (&Manager{}).renderConfigMembers(ipsecCfg)
	if err != nil {
		return nil
	}
	out := make(map[string]string)
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		if !members[name] {
			continue
		}
		vpn := ipsecCfg.VPNs[name]
		_, _, gw, ok := resolveRemoteAddr(ipsecCfg, vpn)
		if !ok {
			continue
		}
		out[name] = gatewayKeyFor(ipsecCfg, name, vpn, gw)
	}
	return out
}

// RenderedVPNSet returns the VPN names that the production swanctl render
// loads (#15024: keyed by VPN, not connection — grouped members all count).
// It prepares external-interface addresses from the full config and
// uses the production fail-closed render, so selector fences exclude VPNs
// whose local address cannot be resolved just as strongSwan does.
// Returns nil when config/render fails; callers must treat nil as UNKNOWN and
// keep the current fail-closed behavior (emit for shape-valid VPNs).
func RenderedVPNSet(cfg *config.Config) map[string]bool {
	m := ConnectionNamesForVPN(cfg)
	if m == nil {
		return nil
	}
	out := make(map[string]bool, len(m))
	for vpn := range m {
		out[vpn] = true
	}
	return out
}

func sortedVPNNames(vpns map[string]*config.IPsecVPN) []string {
	names := make([]string, 0, len(vpns))
	for name := range vpns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func effectiveTrafficSelectors(connName string, vpn *config.IPsecVPN) []childSelector {
	// A nil VPN has no traffic selectors and no LocalID/RemoteID to fall
	// back to — return no children rather than dereferencing vpn. The
	// sole caller iterates non-nil config VPN map values, so this guard
	// is defensive, but the previous nil branch panicked on vpn.LocalID.
	if vpn == nil {
		return nil
	}
	if len(vpn.TrafficSelectors) == 0 {
		// Render-side belt for the #8003 commit gate, and the same two-layer
		// shape this file already uses for sanitizeSwanctlValue: commit rejects
		// it, the belt keeps an already-persisted or peer-synced value inert on
		// the lenient load path (#1960 fail-closed-on-load class).
		//
		// LocalID/RemoteID are populated from `local-identity`/`remote-identity`,
		// which in Junos are IDENTITIES and are normally an FQDN or a DN, while
		// this fallback renders them as swanctl local_ts/remote_ts. Measured on
		// strongSwan 6.0.5, a value that is not a selector shape does not
		// degrade the child, it discards the ENTIRE connection:
		//
		//   loading connection 'm_fqdnts' failed: invalid value for: local_ts,
		//   config discarded
		//
		// Dropping a non-selector value is therefore strictly better than
		// passing it through. The key is then omitted, strongSwan applies its
		// documented `dynamic` default (the tunnel outer address — verified on
		// the same run, NOT 0.0.0.0/0 as was long assumed), and the VPN comes up
		// narrow instead of not at all. A working narrow tunnel is recoverable
		// and visible; a discarded connection is neither.
		//
		// config.IsTrafficSelectorShape is the SAME predicate the commit gate
		// applies, deliberately shared rather than re-derived here.
		local, remote := vpn.LocalID, vpn.RemoteID
		if local != "" && !config.IsTrafficSelectorShape(local) {
			local = ""
		}
		if remote != "" && !config.IsTrafficSelectorShape(remote) {
			remote = ""
		}
		// Route-based (bind-interface set -> if_id emitted): default the
		// selectors to the whole address space, which is what Junos does for an
		// st0-bound VPN's proxy ID. Routing decides what enters a route-based
		// tunnel, not the selector, so a narrow selector here is not a security
		// boundary -- it is just a smaller hole than the operator asked for.
		//
		// MEASURED, on strongSwan 6.0.5 on the cluster, reading the XFRM policy
		// the kernel actually enforces rather than a status view. With no
		// selector rendered (the `dynamic` default) charon installs:
		//
		//   src 10.99.12.1/32 dst 10.99.12.2/32  dir out  if_id 0x1092
		//
		// -- the tunnel ENDPOINTS, /32 to /32. Transit traffic does not match
		// that policy and so never enters the tunnel. With 0.0.0.0/0 on both
		// sides the same connection installs:
		//
		//   src 0.0.0.0/0 dst 0.0.0.0/0          dir out  if_id 0x1092
		//
		// So a route-based VPN configured the ordinary Junos way -- bind-interface,
		// no traffic-selector -- carried endpoint traffic only, silently.
		//
		// Scope is deliberately narrow. This applies ONLY when if_id > 0. For a
		// POLICY-based VPN the selector IS the enforcement boundary, and
		// widening it there would be a real widening, so that case still renders
		// nothing and keeps strongSwan's `dynamic` default. An explicitly
		// configured traffic-selector, and a selector-shaped local-identity,
		// both still win over this default -- the operator said what they wanted.
		//
		// Default each empty side independently. An omitted side is an omission,
		// not an instruction to let strongSwan apply its `dynamic` endpoint /32
		// default, which would suppress routed transit on that side.
		if xfrmiIfID(vpn.BindInterface) > 0 {
			if local == "" {
				local = config.IPsecRouteBasedDefaultTrafficSelector
			}
			if remote == "" {
				remote = config.IPsecRouteBasedDefaultTrafficSelector
			}
		}
		return []childSelector{{
			Name:     connName,
			LocalTS:  local,
			RemoteTS: remote,
		}}
	}

	names := make([]string, 0, len(vpn.TrafficSelectors))
	for name := range vpn.TrafficSelectors {
		names = append(names, name)
	}
	sort.Strings(names)

	// Child names come from ipsecname.ChildNames, the ONE derivation the commit-time
	// SA-name collision gate (#9624) also uses, so what commit checks is what renders.
	// It maps each selector onto swanctl's child alphabet and makes bases that collide
	// WITHIN this VPN injective (#5122). Two distinct selector names that differ only in
	// disallowed characters (e.g. `site/a` and `site:a`) would otherwise render DUPLICATE
	// child sections, which strongSwan rejects or silently merges. Non-colliding names
	// are unchanged, and the disambiguator is a pure function of the original name, so
	// the same config renders identically across renders and HA nodes.
	childNames := ipsecname.ChildNames(connName, names)
	children := make([]childSelector, 0, len(names))
	for _, name := range names {
		ts := vpn.TrafficSelectors[name]
		localTS := vpn.LocalID
		remoteTS := vpn.RemoteID
		if ts.LocalIP != "" {
			localTS = ts.LocalIP
		}
		if ts.RemoteIP != "" {
			remoteTS = ts.RemoteIP
		}
		// Keep only selector-shaped values so a tolerant load cannot pass an
		// FQDN/DN to charon as local_ts/remote_ts.
		if (localTS != "" && !config.IsTrafficSelectorShape(localTS)) ||
			(remoteTS != "" && !config.IsTrafficSelectorShape(remoteTS)) {
			slog.Warn("omitting IPsec traffic-selector with an unrenderable local/remote selector",
				"vpn", connName, "traffic_selector", name)
			continue
		}
		// The explicit-selector branch reaches the same route-based empty-side
		// case as the identity fallback above. Leaving either key out lets
		// strongSwan install its dynamic endpoint /32 policy, which does not
		// match transit packets routed through the XFRM interface.
		if xfrmiIfID(vpn.BindInterface) > 0 {
			if localTS == "" {
				localTS = config.IPsecRouteBasedDefaultTrafficSelector
			}
			if remoteTS == "" {
				remoteTS = config.IPsecRouteBasedDefaultTrafficSelector
			}
		}

		children = append(children, childSelector{
			Name:     childNames[name],
			LocalTS:  localTS,
			RemoteTS: remoteTS,
		})
	}
	return children
}

// ChildSelector is an exported view of the renderer's resolved selector pair.
// Its fields are the exact values rendered as swanctl local_ts/remote_ts.
type ChildSelector = childSelector

// EffectiveTrafficSelectors exposes the renderer's selector expansion to
// snapshot producers so the dataplane fence cannot drift from rendered
// bind-less selectors. A VPN's selectors are grouped under its gateway
// connection since #15024, but child names are unchanged (<vpn>-<selector>,
// or <vpn> for a sole child), so this expansion is grouping-independent.
func EffectiveTrafficSelectors(connName string, vpn *config.IPsecVPN) []ChildSelector {
	return effectiveTrafficSelectors(connName, vpn)
}

// SANameIndex maps every SA name `swanctl --list-sas` can report for a config to
// the configured VPNs whose render produces it (#9511): each rendered connection
// (IKE SA) name and each rendered CHILD SA name.
//
// It exists because ActiveConnectionNames publishes CHILD SA names, which is
// what InitiateConnection needs (`swanctl --initiate --child <name>`), and a VPN
// with traffic-selector entries renders one child `<vpn>-<selector>` per selector
// (plus the #5122 disambiguator on a sanitised collision) and no child named
// `<vpn>`. Publishing the VPN name instead would break the initiate (the #9075
// GEMINI-050-072 adjudication), so a consumer that needs the VPN (the HA
// per-redundancy-group attribution) inverts the render here.
//
// A name maps to MORE THAN ONE VPN when two renders collide: VPN `a` with
// selector `b-c` and VPN `a-b` with selector `c` both emit child `a-b-c`, and VPN
// `blue` with selector `red` emits child `blue-red` while VPN `blue-red` emits a
// connection and a child of that name. Nothing in the name says which one swanctl
// reported, so the index keeps every candidate and never picks one.
type SANameIndex map[string][]string

// BuildSANameIndex indexes the SA names ipsecCfg renders.
//
// Eligibility is the RENDERER's, decided per VPN by the whole-config
// render's membership set (renderedMembers, #15989 fold):
//
//   - the renderer SKIPS it (an unrenderable gateway, an unresolved
//     ike-policy chain, an unusable DH group, an unsupported auth method,
//     a malformed PSK, an AH proposal, a section-breaking name, an
//     unresolved ipsec-policy chain, an invalid bind-interface, an
//     explicit selector set with no renderable children, or a
//     gateway-less/responder-only PSK with no peer identity): it loads
//     nothing and contributes no name, so it cannot make a loaded VPN's
//     name look ambiguous — even when its own name equals a healthy
//     sibling's gateway connection;
//   - it renders: its connection name and every child the renderer emits
//     for it (effectiveTrafficSelectors + sanitizeSwanctlValue, the
//     render's own expansion) are indexed.
//
// A whole-config HARD render error falls back to the pre-fold #9511
// keep-names rule, restored cheaply in the fold: BuildSANameIndex
// re-renders per VPN, and a VPN whose OWN render fails outright keeps
// its names as candidates (an extra candidate only makes attribution
// stricter — it may skip an initiate, never cause one — so a failed
// Apply leaving the previous config loaded can still attribute; see
// BuildSANameIndex). A VPN whose render SUCCEEDS membership-clean
// contributes nothing, and the successful whole-config membership
// path never borrows names, so the #15989 collision stays closed.
// The fallback is untested defensive code: every resolver error today
// is skip-class, so no reachable config triggers it; it guards the
// documented future hard-error class, and reachable behavior is
// identical with or without it.
//
// Building renders the config once on the healthy path, so build once
// per config, not per name. ipsecCfg is only read. The active config
// is indexed without PrepareConfig because that can block on DNS; the
// config-only render projection retains external-interface candidates
// whose local bind is resolved only at apply time.
func BuildSANameIndex(ipsecCfg *config.IPsecConfig) SANameIndex {
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		return nil
	}
	// Render the WHOLE config once (#15024): grouping is a whole-config
	// property — a per-VPN render cannot know its connection is shared.
	// Membership is per-VPN (#15989 fold): a skipped VPN must not borrow
	// a sibling's rendered connection that happens to share its name.
	_, _, members, renderErr := (&Manager{}).renderConfigMembersForConfigOnly(ipsecCfg)
	idx := make(SANameIndex)
	if renderErr != nil {
		// #9511 keep-names on hard error (restored in the #15989 fold):
		// the whole render failed, so there is no membership to trust.
		// Re-render per VPN as the pre-fold index did: a VPN that SKIPS
		// cleanly (empty per-VPN render) contributes nothing; a VPN
		// whose own render FAILS outright keeps its names as candidates.
		// Keeping them can only add candidates, and a caller that
		// requires every candidate (HA attribution) can only become
		// stricter: it may skip an initiate, never cause one. The
		// daemon indexes the config strongSwan has LOADED, whose whole
		// render succeeded, so this arm arises only before the first
		// load in a process, when it falls back to the promoted config.
		for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
			vpn := ipsecCfg.VPNs[name]
			one := *ipsecCfg
			one.VPNs = map[string]*config.IPsecVPN{name: vpn}
			if _, r, err := (&Manager{}).renderConfigForConfigOnly(&one); err == nil && len(r) == 0 {
				continue // renders cleanly to nothing: skipped, no names
			}
			_, _, gw, _ := resolveRemoteAddr(ipsecCfg, vpn)
			conn := gatewayKeyFor(ipsecCfg, name, vpn, gw)
			idx.add(conn, name)
			for _, child := range effectiveTrafficSelectors(name, vpn) {
				idx.add(sanitizeSwanctlValue(child.Name), name)
			}
		}
		return idx
	}
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		if !members[name] {
			continue
		}
		vpn := ipsecCfg.VPNs[name]
		_, _, gw, _ := resolveRemoteAddr(ipsecCfg, vpn)
		conn := gatewayKeyFor(ipsecCfg, name, vpn, gw)
		idx.add(conn, name)
		for _, child := range effectiveTrafficSelectors(name, vpn) {
			idx.add(sanitizeSwanctlValue(child.Name), name)
		}
	}
	return idx
}

func (x SANameIndex) add(saName, vpn string) {
	for _, v := range x[saName] {
		if v == vpn {
			return
		}
	}
	x[saName] = append(x[saName], vpn)
}

// VPNs returns the configured VPNs whose render produces saName, in name order,
// or nil when no loaded VPN does. More than one entry is a render collision.
func (x SANameIndex) VPNs(saName string) []string {
	return append([]string(nil), x[saName]...)
}

// Collisions returns every SA name more than one VPN renders, formatted
// `name=[vpn ...]`, in name order; nil when every name is unique.
func (x SANameIndex) Collisions() []string {
	var out []string
	for name, vpns := range x {
		if len(vpns) > 1 {
			out = append(out, fmt.Sprintf("%s=%v", name, vpns))
		}
	}
	sort.Strings(out)
	return out
}

// sanitizeSwanctlValue replaces every ASCII control byte (C0, 0x00-0x1F, which
// includes newline, plus DEL 0x7F) with a SPACE before the value is interpolated
// into a generated swanctl.conf line. Render-side belt for #1798.
//
// # The consuming grammar, and why a space is the right substitute here (#6833)
//
// swanctl.conf is `section { key = value }` with values running to end of line
// and `#` starting a comment. The load-bearing byte for an interpolated value is
// therefore the NEWLINE: it ends the current setting and lets the remainder be
// read as a new key, or as a new section. That is the byte #1798 named and it is
// genuinely the live one here.
//
// A space is safe at every current call site, and that is a checked claim rather
// than an assumption:
//
//   - The UNQUOTED interpolations are `local_addrs`, `remote_addrs`, `proposals`,
//     `esp_proposals`, `local_ts`, `remote_ts` and section names. The list-valued
//     ones among these are COMMA-separated in swanctl, not whitespace-separated,
//     so an injected space produces one malformed value rather than two entries.
//   - The QUOTED interpolations (`certs`, `id`, `secret`) additionally pass
//     through escapeSwanctlQuoted, so the quoting protects them independently.
//
// If a future call site interpolates into a key whose grammar makes whitespace
// SIGNIFICANT, this substitution stops being safe and the caller must re-derive
// it — a space would then manufacture the delimiter the belt exists to prevent
// (the #6829 shape, where the space and not the newline was the live byte).
// TestSwanctlSanitizerCallSitesAreUnquotedOrEscaped_6833 pins the current
// inventory so such a site cannot be added silently.
func sanitizeSwanctlValue(s string) string {
	return rendersafe.ReplaceControlBytes(s, ' ')
}

// escapeSwanctlQuoted escapes a string for safe inclusion inside a
// swanctl double-quoted value (secret = "...", id = "...",
// certs = "..."). The swanctl settings lexer treats a bare double-quote
// as the string terminator and processes backslash escapes inside
// quotes (\\ -> a literal backslash, \" -> a literal double-quote).
// Without escaping, a value containing a double-quote — legal in a real
// pre-shared key or a distinguished-name identity — truncates or
// corrupts the rendered config (#2126).
//
// Order matters: backslashes are doubled FIRST, then double-quotes are
// escaped. Escaping quotes first would let the second pass double the
// backslash it just inserted. A literal backslash renders as \\ (lexer
// \\. -> \) and a literal " renders as \" (lexer \\. -> "), so a PSK
// like `a\nb` renders as `a\\nb` and round-trips to the literal
// backslash + n, never the \n newline escape.
func escapeSwanctlQuoted(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// pskIDSelectors returns the ordered list of swanctl secret `id-<n>`
// selector values that scope a PSK to its peer (#3952). A PSK secret with
// no id matches ANY peer, so with two or more PSK VPNs strongSwan may bind
// the wrong secret to a peer and IKE authentication fails. Each returned
// value is the remote peer's IKE identity — the discriminator between
// two PSK VPNs to different peers:
//
//   - the configured remote-id when set, else the `dynamic hostname`
//     identity (@FQDN, #14590) for a dynamic peer, otherwise the concrete
//     remote gateway address (strongSwan uses the peer IP as its default
//     identity when no id is negotiated) — one selector per IP-literal
//     address when the gateway carries a comma-separated multi-address
//     list (#14139). A hostname dial target contributes NO peer selector
//     (#16680): it is not an IKE identity (the peer presents its resolved
//     IP). A hostname-addressed PSK VPN with no remote-identity therefore
//     has nothing to scope by and is skipped at render / rejected at
//     commit (#16708, see below).
//
// No local owner (#16708, R3-VA16-S1 — supersedes #15193's local owner).
// #15193 added a box-shared local owner to every non-responder secret —
// the configured local-id, else the pinned local address, else %any — so
// charon's initiator-side lookup would select the secret. Measured
// against strongSwan 6.1.0 that owner also matches the RESPONDER side of
// every exchange on the box: mem_cred enumerates a secret when ANY of
// its owners matches EITHER side of the (me, other) pair, and the IKEv2
// PSK verifier tries every enumerated secret against the peer's AUTH.
// Every secret therefore verified every peer: a holder of one VPN's PSK
// authenticated into another fixed-address VPN from that peer's address,
// and into a responder-only `dynamic hostname` VPN from any address by
// claiming its identity (reopening #14591). The peer selector does NOT
// rescue this — verification accepts any enumerated secret, it does not
// require the peer-side owner to be the one that matched.
//
// Dropping the local owner is safe for the #15193 initiator cells
// because the connection render pins `remote.id` for fixed-address PSK
// gateways (defaultRemoteID / the inline arm), so charon's initiator
// lookup carries the peer identity as other_id:
//
//   - IKEv2 build: get_shared(my_id, other_id) enumerates the secret via
//     its peer owner (other_id = the pinned remote.id, or the peer's
//     negotiated address identity when no id is pinned — multi-address
//     and responder shapes);
//   - IKEv1 phase1: the configured-identity lookup uses other_id = the
//     pinned remote.id, and the address fallback lookup is keyed by the
//     peer's socket address — both hit the peer owner.
//
// Re-measured in the netns charon lab (docs/log/16708.md): peer-only
// secrets establish xpf-initiated and peer-initiated IKEv2 in the
// default, pinned-local-address, configured-local-id, multi-address and
// hostname-endpoint shapes, and the wrong-key attempts in both #16708
// cases now get AUTH_FAILED from the xpf side.
//
// A dynamic responder-only peer (remote_addrs = %any) with no configured
// remote-id and no dynamic hostname yields no selector — %any is not a
// usable peer identity. Since #14591 such a PSK VPN is skipped at render
// and rejected at commit (validateIPsecResponderIdentityStrict), an
// unscoped secret never loads; the empty-list arm remains only for
// shapes the render belt has already skipped.
func pskIDSelectors(remoteAddr string, gw *config.IPsecGateway) []string {
	return pskIDSelectorsLocal(remoteAddr, "", gw)
}

// pskIDSelectorsLocal returns the peer-only selectors for a connection.
// The localAddr parameter is retained only so existing call sites keep
// passing the connection's effective local address; #16708 renders no
// local owner, so the value is deliberately unused.
func pskIDSelectorsLocal(remoteAddr, _ string, gw *config.IPsecGateway) []string {
	return pskPeerSelectors(remoteAddr, gw)
}

// pskPeerSelectors is the peer-identity discriminator described on
// pskIDSelectors: explicit remote-id, else the dynamic-hostname @FQDN,
// else one selector per IP-literal gateway address.
func pskPeerSelectors(remoteAddr string, gw *config.IPsecGateway) []string {
	var ids []string
	seen := make(map[string]bool)
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		ids = append(ids, v)
	}
	// Remote peer identity — the discriminator. Prefer the explicit
	// remote-id (the identity the peer presents / we expect), else the
	// concrete remote gateway address. remoteAddr may be a comma-
	// separated multi-address list (the same list rendered verbatim
	// into remote_addrs): emit one selector per address (#14139,
	// D5-06). The whole comma-joined string is not an IKE identity —
	// it matches no peer, silently leaving the secret unscoped for
	// every address in the list.
	if gw != nil && gw.RemoteIDValue != "" {
		add(formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))
	} else if gw != nil && gw.DynamicHostname != "" {
		// #14590: a dynamic-hostname peer is matched by its presented
		// FQDN identity, so the PSK is scoped by @FQDN — never by the
		// bare hostname as a dial address.
		add(formatIdentity("hostname", gw.DynamicHostname))
	} else {
		// #16680: a hostname dial target is not an IKE identity. Junos
		// defaults the peer identity to the resolved IP, and strongSwan
		// likewise presents its IP when no id is negotiated, so a
		// hostname string can never match the peer that actually
		// presents. Skip non-IP entries here. IP literals keep the
		// #3952/#14139 per-address discriminator. A hostname-only
		// gateway with no remote-identity yields no selector: #16708
		// skips/rejects that shape rather than scoping the secret by
		// a box-shared local owner (see pskIDSelectors).
		for _, addr := range strings.Split(remoteAddr, ",") {
			addr = strings.TrimSpace(addr)
			if _, err := netip.ParseAddr(addr); err != nil {
				continue
			}
			add(addr)
		}
	}
	return ids
}

// defaultRemoteID returns the implicit remote identity for a gateway that
// carries no explicit remote-identity and no dynamic hostname and is not
// responder-only: its sole fixed address. Junos defaults the peer's IKE
// identity to the gateway address; strongSwan likewise keys the peer by
// its IP when no id is negotiated. Rendering it explicitly pins what
// charon, acting as initiator, sends/expects as IDr and what swanctl
// matches the PSK against (#15193). The caller must have already
// established the gateway is a fixed-address, non-responder peer; this
// helper stays pure so the connection render and the secret scoping can
// never disagree.
//
// #15766: a multi-address gateway yields "" — swanctl remote.id is
// single-valued, so pinning the first address would reject the same peer
// presenting from any other configured address. The caller then omits
// remote.id; the PSK selectors still carry one entry per peer address.
// An empty gateway address likewise yields "".
//
// #16680: a single HOSTNAME address yields "" as well. The hostname is
// a dial target (remote_addrs, which strongSwan DNS-resolves at
// initiate time), never the identity the peer presents: Junos defaults
// the peer identity to the resolved IP and strongSwan defaults to its
// own IP, so pinning id = "<hostname>" fails charon's identity check
// in both directions (AUTH_FAILED) against a default-identity peer.
// No DNS lookup runs here — render stays synchronous and pure — so
// the resolved IP cannot be pinned either; omitting remote.id lets
// charon negotiate the peer's presented (IP) identity instead.
func defaultRemoteID(gw *config.IPsecGateway) string {
	if gw == nil || gw.RemoteIDValue != "" || gw.DynamicHostname != "" {
		return ""
	}
	addrs := config.SplitIPsecEndpointList(gw.Address)
	if len(addrs) != 1 {
		return ""
	}
	if _, err := netip.ParseAddr(addrs[0]); err != nil {
		return ""
	}
	return addrs[0]
}

// formatIdentity formats an IKE identity for strongSwan (#15752, G18-03;
// strongSwan identity parsing: @ = FQDN, @# = KEY_ID hex/literal, a DN
// containing '=' parses as ASN.1 DN as-is, @@/bare user@host = RFC822).
func formatIdentity(idType, idValue string) string {
	switch idType {
	case "hostname", "fqdn":
		return "@" + idValue
	case "key-id":
		// KEY_ID: @#<value> (strongSwan treats the tail as hex when it
		// decodes, else the literal bytes via the quoted swanctl string).
		if idValue == "" {
			return ""
		}
		return "@#" + idValue
	case "distinguished-name":
		// DN as-is (contains '='); empty = cert-derived DN, caller omits id.
		return idValue
	default: // "inet", "inet6", "user-at-hostname", "email", etc.
		return idValue
	}
}

func authMethodToSwan(method string) (string, error) {
	switch method {
	case "", "pre-shared-keys":
		return "psk", nil
	case "rsa-signatures", "ecdsa-signatures", "ecdsa-signatures-256", "ecdsa-signatures-384":
		// Junos ecdsa-signatures-256/384 select the ECDSA curve/hash;
		// swanctl auth itself is uniformly pubkey (the cert's key type
		// constrains the signature scheme, strongSwan docs local.auth).
		return "pubkey", nil
	default:
		return "", fmt.Errorf("%w: unsupported IKE authentication-method %q", errProposalUnresolved, method)
	}
}

// xfrmiIfID derives the XFRM interface ID from a bind-interface name.
func xfrmiIfID(bindIface string) uint32 {
	_, ifID := config.XFRMIfNameAndID(bindIface)
	return ifID
}

// renderedConnectionHashes fingerprints each emitted connection's effective
// swanctl connection and secret blocks. Hashing rendered output includes
// resolved proposals, authentication/PSK, selectors, endpoints, identities,
// and lifetimes while excluding non-rendered cosmetic fields and source-map
// ordering. Connection and secret blocks are selected separately because
// swanctl stores PSKs outside connections{}.
func renderedConnectionHashes(cfg string, rendered map[string]bool) (map[string]string, error) {
	hashes := make(map[string]string, len(rendered))
	if len(rendered) == 0 {
		return hashes, nil
	}

	const connectionsHeader = "connections {\n"
	const secretsHeader = "\nsecrets {\n"
	connectionsStart := strings.Index(cfg, connectionsHeader)
	secretsStart := strings.Index(cfg, secretsHeader)
	if connectionsStart < 0 || secretsStart < 0 || secretsStart < connectionsStart {
		return nil, fmt.Errorf("rendered IPsec config is missing connections or secrets section")
	}
	connections := cfg[connectionsStart+len(connectionsHeader) : secretsStart]
	secrets := cfg[secretsStart+len(secretsHeader):]

	for name := range rendered {
		connection, ok := renderedSectionEntry(connections, name)
		if !ok {
			return nil, fmt.Errorf("rendered IPsec connection %q has no connection block", name)
		}
		secret, _ := renderedSectionEntry(secrets, "ike-"+name)
		content := make([]byte, 0, len(connection)+1+len(secret))
		content = append(content, connection...)
		content = append(content, 0)
		content = append(content, secret...)
		hash := sha256.Sum256(content)
		hashes[name] = hex.EncodeToString(hash[:])
	}
	return hashes, nil
}

// renderedSectionEntry returns one top-level, two-space-indented section
// block. Rendered values are single-line, so the exact top-level closing
// indentation cannot occur inside a value or nested child block.
//
// The start marker is anchored to a line start at exactly two spaces
// ("<two spaces><name> {\n" preceded by a newline, or at offset 0 of the
// section): a name like local, remote or children also appears as a
// nested four-space block ("    local {\n") inside every connection, and
// an unanchored strings.Index of "  local {\n" matches that nested
// header at its third space, returning an earlier connection's tail
// instead of the named connection's own block (#15180). Searching
// "\n"+"  <name> {\n" only matches a header that starts a line; the
// four nested spaces can never satisfy it, because the two characters
// before the name would be spaces, not "\n"+two spaces at line start.
func renderedSectionEntry(section, name string) (string, bool) {
	marker := "  " + name + " {\n"
	start := -1
	if strings.HasPrefix(section, marker) {
		start = 0
	} else if idx := strings.Index(section, "\n"+marker); idx >= 0 {
		start = idx + 1
	}
	if start < 0 {
		return "", false
	}
	closeOffset := strings.Index(section[start+len(marker):], "\n  }\n")
	if closeOffset < 0 {
		return "", false
	}
	end := start + len(marker) + closeOffset + len("\n  }\n")
	return section[start:end], true
}
