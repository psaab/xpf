package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/ipsecname"
)

// validateIPsecPolicyProposalReferencesStrict hard-rejects an IPsec
// (Phase 2) reference chain that cannot resolve to a real proposal.
//
// It covers two links (#2073 plus the #9919 F-090 half that had no gate):
//   - policy→proposal: a policy whose `proposals` reference does not resolve
//     to a defined IPsec proposal (or, with no `proposals` leaf, no proposal
//     named after the policy itself);
//   - vpn→policy: a VPN whose `ipsec-policy` names neither a defined
//     ipsec-policy nor (legacy form) a defined ESP proposal directly.
//
// A dangling chain used to render a substituted suite — first the strongSwan
// `default` (#2073), then a conservative fixed `aes256-sha256` fallback
// (#4117) — silently replacing the operator's crypto intent with a suite
// they never authored. Since #9919 the renderer SKIPS such a VPN (like the
// IKE dangling chain, #2270) rather than fabricate (the #4298 principle), so
// this gate is what fails the commit loudly up front.
//
// An EMPTY vpn.IPsecPolicy is the intentional no-policy case (strongSwan's
// default suite is the operator's explicit choice, nothing dangles) and is
// accepted, mirroring the IKE validator's exemption.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientIPsecPolicyProposalRef) so an already-
// persisted or peer-synced config still boots; the render-path belt in
// pkg/ipsec (resolveESPSettings -> errESPChainUnresolved -> renderConfig
// skips the VPN) keeps the bad tunnel out of the generated config rather
// than emitting a fabricated suite.
func validateIPsecPolicyProposalReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	policies := cfg.Security.IPsec.Policies
	proposals := cfg.Security.IPsec.Proposals
	// Policies is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pol := policies[name]
		if pol == nil {
			continue
		}
		// #3904: `proposals` is now a list — EVERY referenced proposal must
		// resolve (mirror the NAT bracket-list strict gate: a dangling
		// trailing reference is an operator typo the commit-check must catch,
		// not silently ignore as the pre-#3904 truncation did).
		propRefs := pol.Proposals
		explicitRef := len(propRefs) > 0
		if !explicitRef {
			// Mirror resolveESPSettings' policy-name fallback: a policy
			// with no `proposals` leaf resolves against a proposal named
			// after the policy itself.
			propRefs = []string{pol.Name}
		}
		for _, propRef := range propRefs {
			if _, ok := proposals[propRef]; ok {
				continue
			}
			if explicitRef {
				return fmt.Errorf("ipsec policy %q references undefined ipsec proposal %q "+
					"(including any perfect-forward-secrecy group; the VPN would be "+
					"skipped at render rather than negotiate its configured crypto — "+
					"fix the reference)", pol.Name, propRef)
			}
			// No explicit `proposals` leaf was given, so do not blame a
			// phantom proposal named after the policy — describe the actual
			// gap instead.
			return fmt.Errorf("ipsec policy %q has no resolvable ipsec proposal "+
				"(no `proposals` reference and no proposal named %q) — define a "+
				"proposal or reference one", pol.Name, pol.Name)
		}
	}
	// #9919 F-090: the vpn→policy link. A VPN whose `ipsec-policy` names
	// neither a defined ipsec-policy nor (legacy form) a defined ESP
	// proposal directly has no crypto to render; the renderer skips it
	// rather than fabricate a suite. Empty (no policy authored) is the
	// intentional-default case and is accepted. Appended after the
	// policy→proposal loop so a doubly-broken config reports the policy
	// link first, deterministically (sorted VPN names).
	vpns := cfg.Security.IPsec.VPNs
	vpnNames := make([]string, 0, len(vpns))
	for name := range vpns {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, name := range vpnNames {
		vpn := vpns[name]
		if vpn == nil || vpn.IPsecPolicy == "" {
			continue
		}
		if _, ok := policies[vpn.IPsecPolicy]; ok {
			continue
		}
		if _, ok := proposals[vpn.IPsecPolicy]; ok {
			continue
		}
		return fmt.Errorf("ipsec vpn %q references undefined ipsec-policy %q "+
			"(neither a defined ipsec-policy nor a proposal of that name; the "+
			"VPN would be skipped at render rather than negotiate a fabricated "+
			"suite — fix the reference)", name, vpn.IPsecPolicy)
	}
	return nil
}

// validateIKEPolicyChainReferencesStrict hard-rejects an IKE (Phase 1)
// reference chain that cannot resolve to a real proposal (#2270). A
// gateway names an `ike-policy`; that policy names a `proposals` (an
// `ike-proposal`). resolveIKESettings (pkg/ipsec/ike.go) walks
// gateway -> ike-policy -> ike-proposal. When that chain breaks — the
// ike-policy is undefined, or the policy's `proposals` reference dangles —
// resolveIKESettings used to return an empty proposal string with a nil
// error, and renderConfig (which guards the line with `if ikeProposals !=
// ""`) emitted the connection block with NO `proposals =` line. strongSwan
// then negotiates phase-1 with its compiled-in default proposal set instead
// of the configured/required crypto — a silent security-posture downgrade,
// the same class validateIPsecPolicyProposalReferencesStrict closes for the
// Phase-2 (ESP) chain.
//
// What is accepted (mirror resolveIKESettings exactly so commit and render
// agree on what resolves):
//   - a gateway with no `ike-policy` at all: the intentional no-policy
//     case — strongSwan's default set is the operator's explicit choice,
//     nothing dangles.
//   - gateway -> defined ike-policy -> defined ike-proposal.
//   - the legacy direct-proposal fallback: a gateway whose `ike-policy`
//     value is itself the NAME of a defined IPsec (Phase 2) proposal, which
//     resolveIKESettings renders via buildIKEProposal when the ike-policy
//     chain is absent. Accepted so a config that genuinely renders a
//     non-empty proposal is never rejected.
//
// Rejected:
//   - a gateway whose `ike-policy` names no defined ike-policy AND is not a
//     defined IPsec-proposal name (a typo / dangling reference).
//   - a gateway whose `ike-policy` resolves to a defined ike-policy but
//     that policy's `proposals` reference names no defined ike-proposal,
//     and the ike-policy value is not also a defined IPsec-proposal name.
//
// Only gateways actually referenced by a VPN are validated: an orphan
// gateway never reaches render, so an unreferenced dangling chain is inert
// (and Junos likewise only faults a gateway in use). Gateways are iterated
// via the sorted VPN list so the first-reported error is deterministic.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientIKEPolicyChainRef) so an already-persisted or
// peer-synced config carrying a dangling reference still BOOTS (#1960
// fail-closed-on-load class); the render-path safety net in pkg/ipsec
// (resolveIKESettings -> errIKEChainUnresolved -> renderConfig skips the
// VPN) keeps the bad tunnel out of the generated config rather than letting
// it negotiate with defaults. Commit / commit-check stay strict. Mirrors
// validateIPsecPolicyProposalReferencesStrict.
func validateIKEPolicyChainReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
	if len(ipsec.VPNs) == 0 {
		return nil
	}
	gateways := ipsec.Gateways
	ikePolicies := ipsec.IKEPolicies
	ikeProposals := ipsec.IKEProposals
	espProposals := ipsec.Proposals

	// chainResolves mirrors resolveIKESettings' acceptance: the
	// ike-policy -> ike-proposal chain, OR the legacy direct-proposal
	// fallback (the ike-policy value is itself a defined Phase-2 proposal
	// name).
	chainResolves := func(ikePolicyName string) bool {
		if pol, ok := ikePolicies[ikePolicyName]; ok && pol != nil {
			// #3904: `proposals` is a list — the chain resolves only when
			// EVERY referenced ike-proposal is defined. A partially-dangling
			// list is an operator typo the commit-check must catch (the
			// pre-#3904 scalar checked only the first reference).
			if len(pol.Proposals) > 0 {
				allResolve := true
				for _, ref := range pol.Proposals {
					if _, ok := ikeProposals[ref]; !ok {
						allResolve = false
						break
					}
				}
				if allResolve {
					return true
				}
			}
		}
		// Legacy fallback: a gateway's ike-policy value naming an IPsec
		// proposal directly. resolveIKESettings only consults this when the
		// ike-policy chain is absent, so checking it unconditionally here is
		// a superset that never wrongly rejects a renderable config.
		if _, ok := espProposals[ikePolicyName]; ok {
			return true
		}
		return false
	}

	// VPNs is a map (unordered); sort keys so the first-error commit-check
	// message is deterministic across runs.
	vpnNames := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, vpnName := range vpnNames {
		vpn := ipsec.VPNs[vpnName]
		if vpn == nil || vpn.Gateway == "" {
			continue
		}
		gw, ok := gateways[vpn.Gateway]
		if !ok || gw == nil {
			// An undefined / inline gateway is the domain of
			// validateIPsecGatewayReferencesStrict (#2074); there is no
			// ike-policy chain to validate here.
			continue
		}
		if gw.IKEPolicy == "" {
			// Intentional no-policy case (strongSwan defaults chosen).
			continue
		}
		if chainResolves(gw.IKEPolicy) {
			continue
		}
		// A gateway may be authored under either `security ike gateway` or
		// `security ipsec gateway` (both compileIKE and compileIPsec populate
		// the same Gateways map; #2279). The typed gateway does not record
		// which stanza it came from, so the message names both candidates
		// rather than asserting a single (possibly wrong) prefix.
		if _, polDefined := ikePolicies[gw.IKEPolicy]; !polDefined {
			return fmt.Errorf("gateway %q (under `security ike` or "+
				"`security ipsec`, used by ipsec vpn %q) references undefined "+
				"ike-policy %q; phase-1 would silently negotiate with the "+
				"strongSwan default proposal set instead of the configured "+
				"crypto",
				gw.Name, vpnName, gw.IKEPolicy)
		}
		pol := ikePolicies[gw.IKEPolicy]
		if len(pol.Proposals) == 0 {
			// The ike-policy exists but has no `proposals` leaf at all.
			// Reporting an "undefined ike-proposal \"\"" misleads the operator
			// into hunting for a proposal named "" — say plainly that the
			// policy is missing its proposals configuration.
			return fmt.Errorf("ike-policy %q (via gateway %q, ipsec vpn %q) "+
				"has no proposals configured; phase-1 would silently negotiate "+
				"with the strongSwan default proposal set instead of the "+
				"configured crypto",
				gw.IKEPolicy, gw.Name, vpnName)
		}
		// #3904: name the FIRST dangling reference in the list (chainResolves
		// was false, so at least one reference does not resolve).
		for _, ref := range pol.Proposals {
			if _, ok := ikeProposals[ref]; !ok {
				return fmt.Errorf("ike-policy %q (via gateway %q, ipsec vpn %q) "+
					"references undefined ike-proposal %q; phase-1 would silently "+
					"negotiate with the strongSwan default proposal set instead of "+
					"the configured crypto",
					gw.IKEPolicy, gw.Name, vpnName, ref)
			}
		}
		return fmt.Errorf("ike-policy %q (via gateway %q, ipsec vpn %q) "+
			"references undefined ike-proposal(s) %q; phase-1 would silently "+
			"negotiate with the strongSwan default proposal set instead of "+
			"the configured crypto",
			gw.IKEPolicy, gw.Name, vpnName, strings.Join(pol.Proposals, " "))
	}
	return nil
}

// validateIPsecProposalProtocolStrict hard-rejects an IPsec (Phase 2)
// proposal whose `protocol` is `ah` (#4298, V-2). AH (Authentication
// Header) is integrity-only with no encryption; swanctl expresses it via
// `ah_proposals`, not `esp_proposals`. xpf has no AH render path:
// buildESPProposal (pkg/ipsec) ignores the protocol and defaults empty
// encryption to aes256, and renderConfig always emits `esp_proposals`, so a
// `protocol ah` proposal used to render as ESP with a fabricated cipher —
// the operator asked for AH (integrity only) and silently got ESP with a
// made-up aes256 cipher. That is a crypto misrepresentation, so we reject it
// at commit rather than silently substitute.
//
// Only proposals that are actually referenced by an ipsec-policy (directly,
// via the policy-name fallback, or as a synthetic proposal-set member) reach
// render, but an unreferenced AH proposal is still an operator error worth
// surfacing, so every defined proposal is checked. Proposal names are sorted
// for a deterministic first error.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientIPsecProposalProtocol) so an already-persisted or
// peer-synced config still boots; the render-path belt in pkg/ipsec
// (vpnUsesAHProposal -> renderConfig skips the VPN) keeps the fabricated
// ESP tunnel out of the generated swanctl.conf rather than emitting it.
// Commit / commit-check stay strict. Mirrors
// validateIPsecPolicyProposalReferencesStrict.
func validateIPsecProposalProtocolStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	proposals := cfg.Security.IPsec.Proposals
	names := make([]string, 0, len(proposals))
	for name := range proposals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		prop := proposals[name]
		if prop == nil {
			continue
		}
		if strings.EqualFold(prop.Protocol, "ah") {
			return fmt.Errorf("ipsec proposal %q uses protocol ah "+
				"(Authentication Header), which xpf does not support — xpf "+
				"renders ESP only and will not silently substitute ESP with a "+
				"fabricated cipher; use `protocol esp` (or remove the proposal)",
				prop.Name)
		}
	}
	return nil
}

// IsSafeIPsecAlgorithmValue is the shared allowlist predicate for algorithm
// leaves that reach swanctl's unquoted proposal lists. Empty means the leaf
// was omitted and is therefore safe for this predicate; callers that require
// an algorithm (such as non-AEAD ESP integrity) enforce presence separately.
func IsSafeIPsecAlgorithmValue(value string) bool {
	if value == "" {
		return true
	}
	return ipsecname.SectionSafe(value)
}

// validateIPsecProposalAlgorithmsStrict rejects algorithm values that are not
// safe to interpolate into swanctl's unquoted proposal lists. SectionSafe is
// an allowlist (ASCII letters, digits, '-' and '_'), rather than a denylist:
// strongSwan parses '#' as a comment and '{', '}', '=' as structure, so an
// operator or peer-synced algorithm must never carry those bytes into the
// rendered `proposals` or `esp_proposals` value.
//
// A non-AEAD ESP proposal also requires an authentication algorithm. Without
// one, buildESPProposal emits only the cipher (and optional PFS), leaving
// integrity absent. Empty encryption means the renderer's default aes256,
// which is non-AEAD and therefore requires authentication too. AH proposals
// have no ESP render path and are handled by validateIPsecProposalProtocolStrict.
//
// The tolerant load path downgrades this error to a warning, while the
// renderer independently skips each affected proposal so legacy/persisted
// values cannot reach swanctl.
func validateIPsecProposalAlgorithmsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	var bad []string
	check := func(scope, name, field, value string) {
		if !IsSafeIPsecAlgorithmValue(value) {
			bad = append(bad, fmt.Sprintf(
				"%s proposal %q %s %q contains a character outside letters, digits, '-' and '_'",
				scope, name, field, value))
		}
	}
	ikeNames := make([]string, 0, len(cfg.Security.IPsec.IKEProposals))
	for name := range cfg.Security.IPsec.IKEProposals {
		ikeNames = append(ikeNames, name)
	}
	sort.Strings(ikeNames)
	for _, name := range ikeNames {
		p := cfg.Security.IPsec.IKEProposals[name]
		if p == nil {
			continue
		}
		check("security ike", name, "encryption-algorithm", p.EncryptionAlg)
		check("security ike", name, "authentication-algorithm", p.AuthAlg)
	}

	espNames := make([]string, 0, len(cfg.Security.IPsec.Proposals))
	for name := range cfg.Security.IPsec.Proposals {
		espNames = append(espNames, name)
	}
	sort.Strings(espNames)
	for _, name := range espNames {
		p := cfg.Security.IPsec.Proposals[name]
		if p == nil {
			continue
		}
		check("security ipsec", name, "encryption-algorithm", p.EncryptionAlg)
		check("security ipsec", name, "authentication-algorithm", p.AuthAlg)
		if !strings.EqualFold(p.Protocol, "ah") &&
			!strings.Contains(p.EncryptionAlg, "gcm") && p.AuthAlg == "" {
			bad = append(bad, fmt.Sprintf(
				"security ipsec proposal %q is non-AEAD ESP without authentication-algorithm "+
					"(set authentication-algorithm for integrity)",
				name))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%s", strings.Join(bad, "; "))
}

// validateIPsecManualKeyStrict hard-rejects an IPsec VPN that carries a
// `manual { ... }` manual-key SA block (#4300, V-4). xpf negotiates all SAs
// via IKE (strongSwan); there is no manual-key path, so compileIPsec used to
// drop the block silently and the VPN compiled to an empty shell that
// committed OK — a silent dead tunnel (no gateway, no policy, no SA).
// Rejecting it at commit gives the operator an immediate, clear diagnostic
// instead of a tunnel that is configured but forwards nothing.
//
// VPN names are sorted so a multi-VPN config reports a deterministic first
// failure. On the tolerant load / peer-sync paths the call site downgrades
// this to a warning (opts.lenientIPsecManualKey) so an already-persisted or
// peer-synced config still boots (#1960 fail-closed-on-load class) — the
// manual block was already inert (never compiled to an SA), so the boot is
// fail-safe. Commit / commit-check stay strict. Mirrors
// validateIPsecGatewayReferencesStrict.
func validateIPsecManualKeyStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	vpns := cfg.Security.IPsec.VPNs
	names := make([]string, 0, len(vpns))
	for name := range vpns {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vpn := vpns[name]
		if vpn == nil {
			continue
		}
		if vpn.Manual {
			return fmt.Errorf("ipsec vpn %q configures a manual-key SA "+
				"(`manual { ... }`), which xpf does not support — a manual-key "+
				"tunnel would commit but forward nothing (silent dead tunnel); "+
				"use an IKE-negotiated VPN (ike { gateway ...; ipsec-policy ...; })",
				vpn.Name)
		}
	}
	return nil
}

// validateIPsecEndpointsStrict (#5630) rejects an IKE gateway or IPsec VPN
// whose typed endpoint leaves are printable but not a usable strongSwan
// endpoint — neither a literal IP address nor a syntactically valid dotted
// hostname/FQDN. compileIKE / compileIPsec copy these leaves verbatim (a
// one-argument schema slot accepts any single token), and renderConfig
// (pkg/ipsec/policy.go, resolveRemoteAddr) interpolates them straight into
// the swanctl `remote_addrs` / `local_addrs` settings. A printable-but-
// invalid value — a malformed IP octet like 10.0.0.999, or a malformed FQDN
// — therefore passes strict commit and reaches strongSwan, where
// `swanctl --load-all` rejects or mishandles the generated connection: a
// config that commits but never loads is a silently broken tunnel (#5630,
// codex-review-181 M20 / A3-b01-F002).
//
// The four effective endpoint fields are:
//   - gateway `address`         -> remote_addrs
//   - gateway `dynamic hostname`-> remote_addrs
//   - gateway `local-address`   -> local_addrs
//   - vpn `local-address`       -> local_addrs
//
// Each is held to the same IsUsableIPsecEndpoint predicate the gateway
// cross-reference gate (validateIPsecGatewayReferencesStrict) already
// applies to an inline vpn.Gateway literal, so every effective endpoint —
// object field or inline literal — obeys one grammar and cannot drift.
// Valid IPv4, IPv6, and dotted-FQDN endpoints are preserved; only a value
// strongSwan itself would reject is caught, so a legitimate hostname or
// v6 gateway still commits.
//
// A gateway whose LocalAddress is empty but derives from external-interface
// is not checked here: the address is resolved from a live interface at
// render time, not from operator text. Gateway and VPN names are sorted so
// a multi-object config reports a deterministic first failure. On the
// tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientIPsecEndpoints) so a config an older binary
// persisted, or a peer synced, still boots (#1960 fail-closed-on-load
// class). Commit / commit-check stay strict. Mirrors
// validateIPsecGatewayReferencesStrict.
func validateIPsecEndpointsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec

	gwNames := make([]string, 0, len(ipsec.Gateways))
	for name := range ipsec.Gateways {
		gwNames = append(gwNames, name)
	}
	sort.Strings(gwNames)
	for _, name := range gwNames {
		gw := ipsec.Gateways[name]
		if gw == nil {
			continue
		}
		if gw.Address != "" && !IsUsableIPsecEndpoint(gw.Address) {
			return fmt.Errorf("security ike gateway %q address %q is not a "+
				"valid IP address or hostname; strongSwan would reject the "+
				"generated remote_addrs and the tunnel would never load",
				name, gw.Address)
		}
		if gw.DynamicHostname != "" && !IsUsableIPsecEndpoint(gw.DynamicHostname) {
			return fmt.Errorf("security ike gateway %q dynamic hostname %q is "+
				"not a valid hostname or IP address; strongSwan would reject "+
				"the generated remote_addrs and the tunnel would never load",
				name, gw.DynamicHostname)
		}
		if gw.LocalAddress != "" && !IsUsableIPsecEndpoint(gw.LocalAddress) {
			return fmt.Errorf("security ike gateway %q local-address %q is not "+
				"a valid IP address or hostname; strongSwan would reject the "+
				"generated local_addrs and the tunnel would never load",
				name, gw.LocalAddress)
		}
	}

	vpnNames := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, name := range vpnNames {
		vpn := ipsec.VPNs[name]
		if vpn == nil {
			continue
		}
		if vpn.LocalAddr != "" && !IsUsableIPsecEndpoint(vpn.LocalAddr) {
			return fmt.Errorf("security ipsec vpn %q local-address %q is not a "+
				"valid IP address or hostname; strongSwan would reject the "+
				"generated local_addrs and the tunnel would never load",
				name, vpn.LocalAddr)
		}
	}
	return nil
}

// validateIPsecProposalLifetimesStrict rejects a `lifetime-seconds` on an
// IKE (Phase-1) or IPsec (Phase-2) proposal that was PRESENT in the input
// but was not a usable positive integer -- a negative, a zero, or a
// non-numeric token.
//
// #9008: both leaves carry validator: ValidateIntegerMin(1) in setSchema,
// but SchemaValidate is invoked ONLY from compileTreeStrict. So the bound
// is enforced on the `Store.Commit -> compileTree -> compileTreeStrict`
// channel and NOWHERE ELSE: compileTreeLenient -- which backs Store.Load
// (daemon boot, reading back the on-disk active config) and the HA
// SyncApply path -- downgrades schema findings to slog.Warn, and the
// compiler then dropped the offending token without a trace. A negative
// was worse than dropped: strconv.Atoi parses "-5" cleanly, so it was
// STORED as LifetimeSeconds and carried into the swanctl renderer.
//
// The compiler now records the raw token (LifetimeSecondsInvalidSpec)
// because the compiled int cannot express either case: a non-numeric
// leaves 0, which is indistinguishable from "not configured", and a
// negative is a value the renderer cannot tell from an intended one.
//
// Wired through opts.lenientIPsecProposalLifetime, so the tolerant path
// WARNS where the strict path rejects. That asymmetry is deliberate and
// is the #1960 doctrine: Store.Load must not gain a new REJECTION -- a
// config an older binary accepted must still load, or a daemon restart
// after a downgrade strands the box on an unreadable active config. It
// may, and now does, gain a new WARNING.
func validateIPsecProposalLifetimesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	var bad []string
	for name, p := range cfg.Security.IPsec.IKEProposals {
		if p != nil && p.LifetimeSecondsInvalidSpec != "" {
			bad = append(bad, fmt.Sprintf(
				"security ike proposal %s lifetime-seconds %q", name, p.LifetimeSecondsInvalidSpec))
		}
	}
	for name, p := range cfg.Security.IPsec.Proposals {
		if p != nil && p.LifetimeSecondsInvalidSpec != "" {
			bad = append(bad, fmt.Sprintf(
				"security ipsec proposal %s lifetime-seconds %q", name, p.LifetimeSecondsInvalidSpec))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	// Map iteration order is randomised; sort so the message (and any test
	// asserting on it) is stable when more than one proposal is bad.
	sort.Strings(bad)
	return fmt.Errorf("%s: lifetime-seconds must be a positive integer (at least 1)",
		strings.Join(bad, "; "))
}

// validateIPsecDHGroupsStrict rejects a `dh-group` (IKE Phase-1 proposal,
// IPsec Phase-2 proposal) or `perfect-forward-secrecy keys` (IPsec policy
// PFS) value that was PRESENT in the input but is not a usable spellable
// group: an unparseable token ("nonsense"), a present-but-empty leaf, or a
// numeric group the renderer cannot spell (99, the real-but-omitted 17/18,
// 0, negatives).
//
// #9919 F-161, the #9008 shape for DH: every leaf carries
// validator: ValidateDHGroup in setSchema, but SchemaValidate runs ONLY from
// compileTreeStrict. On the tolerant path (Store.Load, HA SyncApply) the
// compiler dropped the token without a trace — DHGroup stayed 0 and the
// modp term silently vanished from the negotiated proposal (IKE fell back
// to charon's default group, ESP lost PFS) — or stored an unspellable
// numeric that rendered an empty keyword charon refuses, with diagnostics
// pointing at charon rather than at the value.
//
// The compiler now stores only spellable numerics and records anything else
// in DHGroupInvalidSpec / PFSGroupInvalidSpec (classifyDHGroup), which this
// gate reads. The numeric spellability arm below is defense-in-depth: a
// compiled numeric is always spellable-or-absent, but the check is cheap
// and keeps the gate total over its input.
//
// Wired through opts.lenientIPsecDHGroup, so the tolerant path WARNS where
// the strict path rejects (#1960: Store.Load must not gain a new rejection).
// The renderer (pkg/ipsec) separately SKIPS any VPN whose EFFECTIVE group
// is bad, so a warned config never negotiates weakened crypto.
func validateIPsecDHGroupsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	var bad []string
	for name, p := range cfg.Security.IPsec.IKEProposals {
		if p == nil {
			continue
		}
		if p.DHGroupInvalidSpec != "" {
			bad = append(bad, fmt.Sprintf(
				"security ike proposal %s dh-group %q is not a usable Diffie-Hellman group",
				name, p.DHGroupInvalidSpec))
			continue
		}
		if p.DHGroup != 0 {
			if _, ok := DHGroupKeyword(p.DHGroup); !ok {
				bad = append(bad, fmt.Sprintf(
					"security ike proposal %s dh-group %d is not a supported Diffie-Hellman group (accepted: %v)",
					name, p.DHGroup, SupportedDHGroups()))
			}
		}
	}
	for name, p := range cfg.Security.IPsec.Proposals {
		if p == nil {
			continue
		}
		if p.DHGroupInvalidSpec != "" {
			bad = append(bad, fmt.Sprintf(
				"security ipsec proposal %s dh-group %q is not a usable Diffie-Hellman group",
				name, p.DHGroupInvalidSpec))
			continue
		}
		if p.DHGroup != 0 {
			if _, ok := DHGroupKeyword(p.DHGroup); !ok {
				bad = append(bad, fmt.Sprintf(
					"security ipsec proposal %s dh-group %d is not a supported Diffie-Hellman group (accepted: %v)",
					name, p.DHGroup, SupportedDHGroups()))
			}
		}
	}
	for name, pol := range cfg.Security.IPsec.Policies {
		if pol == nil {
			continue
		}
		if pol.PFSGroupInvalidSpec != "" {
			bad = append(bad, fmt.Sprintf(
				"security ipsec policy %s perfect-forward-secrecy keys %q is not a usable Diffie-Hellman group",
				name, pol.PFSGroupInvalidSpec))
			continue
		}
		if pol.PFSGroup != 0 {
			if _, ok := DHGroupKeyword(pol.PFSGroup); !ok {
				bad = append(bad, fmt.Sprintf(
					"security ipsec policy %s perfect-forward-secrecy keys %d is not a supported Diffie-Hellman group (accepted: %v)",
					name, pol.PFSGroup, SupportedDHGroups()))
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	// Map iteration order is randomised; sort so the message (and any test
	// asserting on it) is stable when more than one value is bad (#9008).
	sort.Strings(bad)
	return fmt.Errorf("%s", strings.Join(bad, "; "))
}
