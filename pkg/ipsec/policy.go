package ipsec

import (
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rendersafe"
)

// childSelector is a resolved child SA traffic-selector pair for swanctl
// config generation.
type childSelector struct {
	Name     string
	LocalTS  string
	RemoteTS string
}

func (m *Manager) generateConfig(ipsecCfg *config.IPsecConfig) string {
	cfg, _, _ := m.renderConfig(ipsecCfg)
	return cfg
}

// renderConfig renders the swanctl snippet and returns the EXACT set of
// swanctl connection names it actually emitted (the sanitized VPN names
// written into the connections{} block). A VPN present in ipsecCfg.VPNs but
// OMITTED from the render — a skip class: an unrenderable gateway reference
// (#2074), an unresolved ike-policy chain (#2270), or a `protocol ah`
// proposal with no ESP render path (#4298) — is NOT in the returned set even
// though renderConfig still returns success. Apply diffs THIS rendered set
// (not the raw VPN map keys) so a previously-loaded connection that dropped
// out of the render is treated as a removal and its stale child SA is torn
// down (#5494). Returning the rendered set is the single source of truth for
// "what is actually loaded", so the skip logic here can never drift from the
// teardown diff in promoteConnNames.
func (m *Manager) renderConfig(ipsecCfg *config.IPsecConfig) (string, map[string]bool, error) {
	var b strings.Builder

	b.WriteString("# xpf managed config - do not edit\n\n")

	// skipped records VPNs whose gateway reference is not renderable
	// (#2074) so the secrets loop below emits no orphan ike-<name> secret
	// for a connection that was never written.
	skipped := make(map[string]bool)

	// rendered accumulates the sanitized connection name of every VPN that
	// survives the skip checks and is emitted into connections{}. This is
	// the authoritative "loaded connection set" Apply diffs against
	// prevConnNames (#5494).
	rendered := make(map[string]bool)

	// Connections
	b.WriteString("connections {\n")
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]

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
		// reference never zeroes a healthy tunnel. A non-chain resolve error
		// (e.g. an unknown auth-method token from authMethodToSwan) is a
		// different class and still aborts the whole render.
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
			return "", nil, fmt.Errorf("vpn %s: %w", name, err)
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

		// This VPN passed every skip check, so it is emitted into the
		// loaded config. Record its sanitized connection name in the
		// rendered set (#5494) — the same key swanctl reports in
		// --list-sas and that promoteConnNames diffs for teardown.
		rendered[sanitizeSwanctlValue(name)] = true

		fmt.Fprintf(&b, "  %s {\n", sanitizeSwanctlValue(name))
		espProposals, espLifetime := resolveESPSettings(ipsecCfg, vpn)
		dpd := deriveDPD(gw, vpn)

		// IKE version
		if gw != nil && gw.Version == "v2-only" {
			b.WriteString("    version = 2\n")
		} else if gw != nil && gw.Version == "v1-only" {
			b.WriteString("    version = 1\n")
		}

		if aggressive {
			b.WriteString("    aggressive = yes\n")
		}

		// local_addrs / remote_addrs carry the endpoint address list
		// (a real IP / dotted hostname, an IPv6 literal, a comma-
		// separated multi-address list, or the responder-only "%any").
		// Run them through sanitizeSwanctlValue for parity with the
		// local_ts / remote_ts belt below and the id / PSK belts above:
		// these are UNQUOTED list slots, so an embedded control
		// character — a newline in particular — would otherwise inject an
		// arbitrary `key = value` line (downgrade `version`, flip
		// `aggressive`, add `also`/`children`) into the connection block.
		// sanitizeSwanctlValue collapses the newline to a space, keeping
		// the whole value on one line so a tampered address renders inert
		// instead of live. It touches nothing in a legitimate address
		// (letters, digits, `.`, `:`, `,`, `%` are all preserved), so a
		// valid single/comma-list/IPv6 endpoint is byte-identical. The
		// commit-time gate (validateIPsecEndpointsStrict) rejects such a
		// value; this render belt is the by-construction backstop for a
		// path that reaches render without local commit (HA peer-sync,
		// direct IPsecConfig construction, a config persisted before the
		// fix). Unquoted, so NO escapeSwanctlQuoted — that belt is for the
		// quoted id / cert / secret slots only (#6469).
		if localAddr != "" {
			fmt.Fprintf(&b, "    local_addrs = %s\n", sanitizeSwanctlValue(localAddr))
		}
		if remoteAddr != "" {
			fmt.Fprintf(&b, "    remote_addrs = %s\n", sanitizeSwanctlValue(remoteAddr))
		}

		// NAT traversal
		if gw != nil {
			switch gw.NATTraversal {
			case "disable":
				b.WriteString("    encap = no\n")
			case "force":
				b.WriteString("    encap = yes\n")
				b.WriteString("    forceencaps = yes\n")
			default:
				// "enable" or empty = strongSwan default (auto-detect NAT)
				if gw.NoNATTraversal {
					b.WriteString("    encap = no\n")
				}
			}
		}

		if dpd.Delay > 0 {
			fmt.Fprintf(&b, "    dpd_delay = %ds\n", dpd.Delay)
		}
		if dpd.Timeout > 0 {
			fmt.Fprintf(&b, "    dpd_timeout = %ds\n", dpd.Timeout)
		}

		// Local auth section
		b.WriteString("    local {\n")
		fmt.Fprintf(&b, "      auth = %s\n", authMethod)
		if gw != nil && gw.LocalCertificate != "" {
			fmt.Fprintf(&b, "      certs = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(gw.LocalCertificate)))
		}
		if gw != nil && gw.LocalIDValue != "" {
			// Quote + escape the identity: a distinguished-name id with
			// spaces/commas (id = CN=fw, O=acme) is mis-parsed when
			// emitted unquoted, and swanctl accepts a quoted value for
			// every identity type (@fqdn, IP, DN) (#2126).
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity(gw.LocalIDType, gw.LocalIDValue))))
		}
		b.WriteString("    }\n")

		// Remote auth section
		b.WriteString("    remote {\n")
		fmt.Fprintf(&b, "      auth = %s\n", authMethod)
		if gw != nil && gw.RemoteIDValue != "" {
			fmt.Fprintf(&b, "      id = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))))
		}
		b.WriteString("    }\n")

		if ikeProposals != "" {
			// Sanitize the IKE proposal list for the same reason as the
			// child-SA esp_proposals below and the local_ts/remote_ts belt:
			// buildIKEProposal / buildIKEProposalFromIKE append
			// prop.EncryptionAlg / prop.AuthAlg VERBATIM on the unknown-
			// algorithm fall-through (normalizeAuthAlg's default branch returns
			// the collapsed token unchanged; normalizeEncAlg's generic gcm strip
			// only removes `-cbc`/`-`), so a control character in a peer-synced
			// or directly-constructed proposal survives into this UNQUOTED list
			// slot and an embedded newline would inject a connection-level
			// swanctl directive. sanitize-only, NOT escapeSwanctlQuoted (this is
			// an unquoted list slot like local_ts/remote_ts): a proposal token is
			// alnum / `-` / `,`, all preserved by sanitizeSwanctlValue, so a
			// legitimate proposal or comma-list renders byte-identical (#6469).
			fmt.Fprintf(&b, "    proposals = %s\n", sanitizeSwanctlValue(ikeProposals))
		}
		if ikeLifetime > 0 {
			fmt.Fprintf(&b, "    rekey_time = %ds\n", ikeLifetime)
			b.WriteString("    rand_time = 0s\n")
		}

		// #7165: `start_action` is a CHILD setting in swanctl.conf, not a
		// connection setting. It used to be emitted here as well as in the
		// child below, and strongSwan rejects the connection outright:
		//
		//   loading connection 'vpn-a' failed: unknown option: start_action,
		//   config discarded
		//   loaded 0 of 1 connections, 1 failed to load
		//
		// "config discarded" is the whole connection, not the one line — so
		// every VPN configured with `establish-tunnels immediately` produced a
		// config that strongSwan refused in its entirety, and IPsec did not come
		// up at all. The child-level emit below is the correct one and is
		// sufficient on its own; nothing here replaces it.
		//
		// This survived because nothing ever LOADED the generated config: the
		// renderer's tests assert on the emitted text, and text assertions
		// cannot know which keys strongSwan accepts. Found by #7165 item 2,
		// whose entire subject was the absence of that proof.

		// Compute XFRM interface ID from bind-interface name
		ifID := xfrmiIfID(vpn.BindInterface)

		fmt.Fprintf(&b, "    children {\n")
		for _, child := range effectiveTrafficSelectors(name, vpn) {
			fmt.Fprintf(&b, "      %s {\n", sanitizeSwanctlValue(child.Name))
			// local_ts / remote_ts carry the traffic-selector prefixes
			// (`traffic-selector local-ip/remote-ip`, or the
			// local-identity/remote-identity fallback). Run them through
			// sanitizeSwanctlValue for parity with child.Name above: an
			// embedded control character — a newline in particular — would
			// otherwise inject an arbitrary `key = value` line (e.g.
			// `updown = /tmp/x.sh`, executed by charon as ROOT) or an extra
			// swanctl section into the children{} block. The commit-time
			// gate (validateIPsecTrafficSelectorsStrict, #4098) rejects such
			// a value; this render-side belt keeps an already-persisted /
			// peer-synced value inert on the lenient load path (#1798/#4098).
			if child.LocalTS != "" {
				fmt.Fprintf(&b, "        local_ts = %s\n", sanitizeSwanctlValue(child.LocalTS))
			}
			if child.RemoteTS != "" {
				fmt.Fprintf(&b, "        remote_ts = %s\n", sanitizeSwanctlValue(child.RemoteTS))
			}
			// esp_proposals sits INSIDE the children{ <child> { } } block —
			// the same block whose local_ts/remote_ts belt above cites an
			// injected `updown = /tmp/x.sh` executed by charon as ROOT.
			// buildESPProposal appends prop.EncryptionAlg / prop.AuthAlg
			// VERBATIM on the unknown-algorithm fall-through, so a control
			// character in a peer-synced or directly-constructed ESP proposal
			// survives; an embedded newline here injects a child-SA directive
			// (updown → root exec, or an esp_proposals/mode/mark_* crypto
			// rewrite) — a strictly worse vector than the endpoint one on the
			// identical validation-bypassed threat model. sanitize-only,
			// unquoted list slot; a legitimate proposal / comma-list renders
			// byte-identical (#6469).
			fmt.Fprintf(&b, "        esp_proposals = %s\n", sanitizeSwanctlValue(espProposals))
			if espLifetime > 0 {
				fmt.Fprintf(&b, "        rekey_time = %ds\n", espLifetime)
				b.WriteString("        rand_time = 0s\n")
			}
			// Junos df-bit → strongSwan copy_df (outer IP-header DF handling;
			// the DF bit lives in the outer encapsulating IP header, not ESP).
			// strongSwan copy_df has two states: yes (default) copies the inner
			// DF bit to the outer header; no forces the outer DF bit to 0
			// (XFRM_STATE_NOPMTUDISC), which allows the encapsulated packet to be
			// fragmented. There is no "force outer DF=1" — copy_df=yes is the
			// closest DF-preserving / PMTUD-enabling behavior.
			//   copy  → copy_df = yes   (outer DF = inner DF)
			//   set   → copy_df = yes   (preserve DF / keep PMTUD; can't force 1)
			//   clear → copy_df = no    (outer DF = 0, allow fragmentation)
			// #4015: previously "set" emitted copy_df=no (which CLEARS DF) and
			// "clear" fell through to the default copy_df=yes, i.e. set/clear were
			// inverted — a "df-bit clear" blackholed oversized packets via PMTUD.
			switch vpn.DFBit {
			case "copy", "set":
				fmt.Fprintf(&b, "        copy_df = yes\n")
			case "clear":
				fmt.Fprintf(&b, "        copy_df = no\n")
			}
			if vpn.EstablishTunnels == "immediately" {
				fmt.Fprintf(&b, "        start_action = start\n")
			}
			if dpd.Action != "" {
				fmt.Fprintf(&b, "        dpd_action = %s\n", dpd.Action)
			}
			if ifID > 0 {
				fmt.Fprintf(&b, "        if_id_in = %d\n", ifID)
				fmt.Fprintf(&b, "        if_id_out = %d\n", ifID)
			}
			fmt.Fprintf(&b, "      }\n")
		}
		fmt.Fprintf(&b, "    }\n")

		fmt.Fprintf(&b, "  }\n")
	}
	b.WriteString("}\n\n")

	// Secrets — resolve PSK from IKE policy chain
	b.WriteString("secrets {\n")
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		if skipped[name] {
			// No connection was written for this VPN (#2074) — emit no
			// orphan ike-<name> secret.
			continue
		}
		vpn := ipsecCfg.VPNs[name]
		// Resolve the remote endpoint + gateway once: it feeds both the
		// IKE-policy-chain PSK lookup and the id selectors below. This VPN
		// was not skipped, so resolveRemoteAddr returned ok=true and a
		// usable remoteAddr ("", a concrete address, or "%any").
		remoteAddr, _, gw, _ := resolveRemoteAddr(ipsecCfg, vpn)
		secret := vpn.PSK.Reveal()
		// Resolve PSK from IKE policy chain: VPN -> gateway -> IKE policy -> PSK
		if secret == "" && gw != nil {
			if ikePol, ok := ipsecCfg.IKEPolicies[gw.IKEPolicy]; ok {
				secret = ikePol.PSK.Reveal()
			}
		}
		if secret != "" {
			decoded, err := normalizePSK(secret)
			if err != nil {
				return "", nil, fmt.Errorf("vpn %s: %w", name, err)
			}
			fmt.Fprintf(&b, "  ike-%s {\n", sanitizeSwanctlValue(name))
			// sanitizeSwanctlValue strips control chars (#1798); the
			// quote/backslash escaper (#2126) makes a PSK containing a
			// double-quote or backslash render as a balanced, swanctl-
			// parseable quoted string instead of corrupting the block.
			fmt.Fprintf(&b, "    secret = \"%s\"\n", escapeSwanctlQuoted(sanitizeSwanctlValue(decoded)))
			// Scope this PSK to its peer with id selectors (#3952). A PSK
			// secret with NO id matches ANY peer, so with two or more PSK
			// VPNs strongSwan can bind the wrong secret to a peer and IKE
			// authentication fails. Each id-<n> narrows the secret to a
			// peer whose IKE identity matches — the configured remote-id,
			// else the remote gateway address (plus the local-id when set).
			for i, sel := range pskIDSelectors(remoteAddr, gw) {
				fmt.Fprintf(&b, "    id-%d = \"%s\"\n", i+1,
					escapeSwanctlQuoted(sanitizeSwanctlValue(sel)))
			}
			fmt.Fprintf(&b, "  }\n")
		}
	}
	b.WriteString("}\n")

	return b.String(), rendered, nil
}

// resolveRemoteAddr resolves the swanctl remote_addrs value (a real IP /
// dotted hostname) for a VPN, plus the effective local address and the
// resolved gateway. ok=false means there is nothing usable to render —
// the caller MUST skip the connection so a bare gateway config-object
// NAME never leaks into remote_addrs (#2074):
//
//   - defined gateway with an address / dynamic hostname -> remote = that
//   - defined gateway flagged responder-only (dynamic, no addr/host)
//     -> remote = "%any" (strongSwan responds, never initiates) (#2404)
//   - defined gateway with neither + not responder-only   -> ok=false
//   - no gateway object, vpn.Gateway is a usable IP/host -> remote = it
//   - no gateway object, vpn.Gateway empty               -> ok=true,
//     remote="" (connection emitted with no remote_addrs line, as before)
//   - no gateway object, vpn.Gateway a dangling/dotless name -> ok=false
//
// This mirrors the commit-time validator validateIPsecGatewayReferencesStrict
// exactly, using the same config.IsUsableIPsecEndpoint predicate.
func resolveRemoteAddr(ipsecCfg *config.IPsecConfig, vpn *config.IPsecVPN) (
	remoteAddr, localAddr string, gw *config.IPsecGateway, ok bool) {

	localAddr = vpn.LocalAddr
	if g, found := ipsecCfg.Gateways[vpn.Gateway]; found {
		gw = g
		switch {
		case gw.Address != "":
			remoteAddr = gw.Address
		case gw.DynamicHostname != "":
			remoteAddr = gw.DynamicHostname
		case gw.ResponderOnly:
			// Responder-only / dynamic-IP peer (#2404): the peer initiates
			// from an unknown source address, so strongSwan listens with
			// remote_addrs = %any and never initiates to this gateway.
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
	if config.IsUsableIPsecEndpoint(vpn.Gateway) {
		// Legacy inline shape: the VPN names the peer endpoint directly
		// as a literal IP or dotted hostname, with no Gateways entry.
		return vpn.Gateway, localAddr, nil, true
	}
	// Dangling / dotless single-label name — not a known gateway and not
	// a usable IP/hostname. Rendering it would leak the name.
	return "", localAddr, nil, false
}

func sortedVPNNames(vpns map[string]*config.IPsecVPN) []string {
	names := make([]string, 0, len(vpns))
	for name := range vpns {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// routeBasedDefaultTS is the traffic selector a route-based (XFRM-interface)
// VPN gets when nothing else specifies one. Both families are offered because
// xpf is dual-stack and routing, not the selector, decides what enters the
// tunnel; strongSwan narrows the pair during negotiation, so a v4-only peer
// simply agrees on the v4 half.
const routeBasedDefaultTS = "0.0.0.0/0,::/0"

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
		if local == "" && remote == "" && xfrmiIfID(vpn.BindInterface) > 0 {
			local, remote = routeBasedDefaultTS, routeBasedDefaultTS
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

	// sanitizeChildName is not injective: it maps every disallowed rune to a
	// single '-', so two distinct selector names differing only in sanitized
	// characters (e.g. `site/a` and `site:a`, both legal Junos identifier
	// chars) both collapse to `site-a` and render DUPLICATE swanctl child
	// sections. strongSwan then rejects the config or silently merges/loses
	// one child — a selector-specific site-to-site outage (#5122). Detect any
	// base name shared by two or more selectors and append a stable hash of
	// the ORIGINAL selector name to EACH colliding entry so every configured
	// selector renders a UNIQUE child section. Non-colliding names are left
	// byte-for-byte unchanged (no churn), and the disambiguator is a pure
	// function of the original name, so the same config renders identically
	// across renders and across HA nodes (config-sync + idempotent commit).
	bases := make([]string, len(names))
	counts := make(map[string]int, len(names))
	for i, name := range names {
		bases[i] = sanitizeChildName(name)
		counts[bases[i]]++
	}
	// Reserve every non-colliding base first so a disambiguated collided name
	// can never land on a name a distinct selector already owns.
	used := make(map[string]bool, len(names))
	for i := range names {
		if counts[bases[i]] == 1 {
			used[bases[i]] = true
		}
	}

	children := make([]childSelector, 0, len(names))
	for i, name := range names {
		ts := vpn.TrafficSelectors[name]
		localTS := vpn.LocalID
		remoteTS := vpn.RemoteID
		if ts.LocalIP != "" {
			localTS = ts.LocalIP
		}
		if ts.RemoteIP != "" {
			remoteTS = ts.RemoteIP
		}
		childName := bases[i]
		if counts[bases[i]] > 1 {
			childName = bases[i] + "-" + childNameDisambiguator(name)
			// Astronomically unlikely: the disambiguated name still collides
			// (a hash collision, or a distinct selector literally named
			// `<base>-<hash>`). Extend deterministically until unique so the
			// injectivity guarantee is absolute.
			for used[childName] {
				childName += "x"
			}
			used[childName] = true
		}
		children = append(children, childSelector{
			Name:     connName + "-" + childName,
			LocalTS:  localTS,
			RemoteTS: remoteTS,
		})
	}
	return children
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
// Eligibility is the RENDERER's, decided ONE VPN AT A TIME. Each VPN is rendered
// on its own, sharing every other section of ipsecCfg:
//
//   - the renderer SKIPS it (an unrenderable gateway, an unresolved ike-policy
//     chain, an AH proposal): it loads nothing and contributes no name, so it
//     cannot make a loaded VPN's name look ambiguous;
//   - it renders: its connection name and every child the renderer emits for it
//     (effectiveTrafficSelectors + sanitizeSwanctlValue, the render's own
//     expansion) are indexed;
//   - its render FAILS outright: its names are indexed anyway. Keeping them can
//     only ADD candidates to a name, and a caller that requires every candidate
//     (the HA attribution) can only become stricter: it may skip an initiate,
//     never cause one. Dropping them could turn a collision this VPN takes part
//     in back into a single answer. The daemon indexes the config strongSwan has
//     LOADED, whose whole render succeeded, so this case arises only before the
//     first load in a process, when it falls back to the promoted config.
//
// Rendering per VPN is also what keys eligibility by VPN identity: two VPN names
// that sanitise to one connection name cannot borrow each other's result. And one
// broken VPN cannot empty the index, which a single whole-config render would.
//
// Building renders every VPN and repeats the render's skip warnings, so build once
// per config, not per name. ipsecCfg is only read. A caller holding the active
// config indexes its IPsec section rather than PrepareConfig's output, which can
// block on DNS; PrepareConfig derives runtime local addresses, which neither SA
// names nor the skip decisions read.
func BuildSANameIndex(ipsecCfg *config.IPsecConfig) SANameIndex {
	if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
		return nil
	}
	idx := make(SANameIndex)
	for _, name := range sortedVPNNames(ipsecCfg.VPNs) {
		vpn := ipsecCfg.VPNs[name]
		one := *ipsecCfg
		one.VPNs = map[string]*config.IPsecVPN{name: vpn}
		if _, rendered, err := (&Manager{}).renderConfig(&one); err == nil && len(rendered) == 0 {
			continue
		}
		idx.add(sanitizeSwanctlValue(name), name)
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

// childNameDisambiguator returns a short, stable hash of the ORIGINAL selector
// name, used to make colliding sanitized child-section names injective (#5122).
// It is a deterministic pure function of the input (fnv-1a 64-bit, low 32 bits
// as 8 hex chars), so distinct original names that sanitize to the same base
// receive distinct suffixes, and the same config renders the same name on every
// node — a prerequisite for HA config-sync and idempotent commits.
func childNameDisambiguator(original string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(original))
	return fmt.Sprintf("%08x", uint32(h.Sum64()))
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

func sanitizeChildName(name string) string {
	if name == "" {
		return "traffic-selector"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "traffic-selector"
	}
	return out
}

// pskIDSelectors returns the ordered list of swanctl secret `id-<n>`
// selector values that scope a PSK to its peer (#3952). A PSK secret with
// no id matches ANY peer, so with two or more PSK VPNs strongSwan may bind
// the wrong secret to a peer and IKE authentication fails. Each returned
// value is an IKE identity strongSwan matches against the peer of the
// exchange (the peer's identity must match at least one selector):
//
//   - the remote peer identity: the configured remote-id when set,
//     otherwise the concrete remote gateway address (strongSwan uses the
//     peer IP as its default identity when no id is negotiated). This is
//     the discriminator between two PSK VPNs to different peers;
//   - the local identity, added only when a local-id is explicitly
//     configured, so the secret is also selected when strongSwan looks it
//     up by our own identity (a harmless extra owner — two VPNs on the
//     same firewall typically share the local id, so it never disambiguates
//     on its own, but it can never cause a wrong-peer match either).
//
// A dynamic responder-only peer (remote_addrs = %any) with no configured
// remote-id yields no address selector — %any is not a usable identity —
// so the list carries only whatever identities ARE known (the local-id, if
// any). When the list is empty the caller emits no id, preserving the
// legacy any-peer behavior for a config that offers nothing to scope by.
func pskIDSelectors(remoteAddr string, gw *config.IPsecGateway) []string {
	var ids []string
	seen := make(map[string]bool)
	add := func(v string) {
		if v == "" || v == "%any" || seen[v] {
			return
		}
		seen[v] = true
		ids = append(ids, v)
	}
	// Remote peer identity — the discriminator. Prefer the explicit
	// remote-id (the identity the peer presents / we expect), else the
	// concrete remote gateway address.
	if gw != nil && gw.RemoteIDValue != "" {
		add(formatIdentity(gw.RemoteIDType, gw.RemoteIDValue))
	} else {
		add(remoteAddr)
	}
	// Local identity, when explicitly configured.
	if gw != nil && gw.LocalIDValue != "" {
		add(formatIdentity(gw.LocalIDType, gw.LocalIDValue))
	}
	return ids
}

// formatIdentity formats an IKE identity for strongSwan.
func formatIdentity(idType, idValue string) string {
	switch idType {
	case "hostname", "fqdn":
		return "@" + idValue
	default: // "inet", "ipv4", etc.
		return idValue
	}
}

func authMethodToSwan(method string) (string, error) {
	switch method {
	case "", "pre-shared-keys":
		return "psk", nil
	case "rsa-signatures", "ecdsa-signatures":
		return "pubkey", nil
	default:
		return "", fmt.Errorf("unsupported IKE authentication-method %q", method)
	}
}

// xfrmiIfID derives the XFRM interface ID from a bind-interface name.
func xfrmiIfID(bindIface string) uint32 {
	_, ifID := config.XFRMIfNameAndID(bindIface)
	return ifID
}
