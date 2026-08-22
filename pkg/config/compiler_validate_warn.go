package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// deterministicIPv4Enforced reports whether a deterministic-NAT pool uses the
// IPv4-subscriber path (mode 1), which the userspace dataplane now enforces
// (#4559). It returns true only for a valid IPv4 host CIDR with a positive
// block size; an IPv6 host (mode 2 / NAT64) or an unparseable address is still
// deferred (round-robin fallback) and keeps the accepted-but-inert advisory.
// This mirrors the enforced/deferred split in
// userspace.deterministicSourceNATFields so the advisory and the dataplane
// agree on which pools are actually enforced.
func deterministicIPv4Enforced(det *DeterministicNATConfig) bool {
	if det == nil || det.BlockSize <= 0 || det.HostAddress == "" {
		return false
	}
	_, hostNet, err := net.ParseCIDR(det.HostAddress)
	if err != nil {
		return false
	}
	_, bits := hostNet.Mask.Size()
	return bits == 32
}

// deterministicNAPT64Enforced reports whether a deterministic-NAT pool uses the
// IPv6-subscriber path (mode 2 / NAPT64), which the userspace dataplane now
// enforces (#4559). Mode 2 is enforced ONLY through the NAT64 forward path, so
// two conditions must both hold: (1) the host CIDR is a valid IPv6 prefix of a
// SUPPORTED length (/32 or /64 — the only lengths that map to a 32-bit
// subscriber word, matching userspace.deterministicNAT64V6Fields and the
// retired-eBPF split), and (2) the pool is referenced as the source-pool of at
// least one `security nat nat64` rule-set (a v6→v4 translation only happens
// there — a plain source-NAT rule cannot translate an IPv6 subscriber to a v4
// pool). An IPv6-host deterministic pool that meets neither still round-robins
// and keeps the accepted-but-inert advisory.
func deterministicNAPT64Enforced(cfg *Config, poolName string, det *DeterministicNATConfig) bool {
	if det == nil || det.BlockSize <= 0 || det.HostAddress == "" || poolName == "" {
		return false
	}
	ip, hostNet, err := net.ParseCIDR(det.HostAddress)
	if err != nil {
		return false
	}
	if ip.To4() != nil || ip.To16() == nil {
		return false // not a genuine IPv6 host (mode 1 / unparseable)
	}
	ones, bits := hostNet.Mask.Size()
	if bits != 128 || (ones != 32 && ones != 64) {
		return false // unsupported subscriber-prefix length
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs != nil && rs.SourcePool == poolName {
			return true
		}
	}
	return false
}

// sortedPoolNames returns the keys of a NAT pool map in deterministic sorted
// order, so advisory / warning messages that enumerate pools are stable across
// compiles (Go map iteration order is randomized). Used by the #4291/#4292
// accepted-only NAT advisories.
func sortedPoolNames(pools map[string]*NATPool) []string {
	if len(pools) == 0 {
		return nil
	}
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidateConfig performs non-fatal validation on a compiled config.
// Returns warnings for unresolved references and operator-visible
// compatibility/deprecation conditions.
func ValidateConfig(cfg *Config) []string {
	var warnings []string

	// Note (#1476): the previous "ebpf is deprecated" warning was
	// removed because `validateDataplaneTypeStrict` now hard-rejects
	// `dataplane-type ebpf` at commit time with
	// `ErrEBPFDataplaneRetired`. ValidateConfig is never reached for
	// EBPF-typed configs after that gate; keeping the warning here
	// would be dead code.

	// #653: when `services application-identification` is enabled,
	// emit a one-line warning at commit time so operators see what
	// the knob actually does on xpf vs Junos vSRX. The runtime is
	// port + protocol matching only — there is NO L7 DPI / signature
	// engine. See `show services application-identification status`
	// and docs/services-application-identification.md for the full
	// contract.
	if cfg.Services.ApplicationIdentification {
		warnings = append(warnings,
			"services application-identification is enabled, but xpf "+
				"AppID is port+protocol catalog matching only — no L7 "+
				"DPI / signature engine. Run `show services "+
				"application-identification status` for the contract; "+
				"see docs/services-application-identification.md.")
	}

	if userspaceSynCookieProtectionActive(cfg) &&
		(cfg.System.RootAuthentication == nil ||
			cfg.System.RootAuthentication.EncryptedPassword == "") {
		warnings = append(warnings,
			"active userspace-dp SYN-cookie screen profiles require "+
				"system root-authentication encrypted-password material "+
				"for the userspace cookie key; the userspace dataplane "+
				"fails closed until it is set. Legacy eBPF SYN-cookie "+
				"handling uses kernel helpers and is not affected by "+
				"this warning.")
	}

	// #1944 §5.8: warn when a configured login user has no usable auth
	// method — no ssh-* keys AND no usable encrypted-password (absent, or
	// a bare lock sentinel which only locks the account). Mirrors the
	// root-auth warning style above; directly addresses the "non-root
	// operator cannot log in" bug class this issue closes.
	if cfg.System.Login != nil {
		for _, u := range cfg.System.Login.Users {
			if u == nil || u.Name == "" || u.Name == "root" {
				continue
			}
			// A usable password is a non-empty value that is neither a bare
			// lock sentinel ("*"/"!"/"!!") NOR a locked-but-restorable form
			// (any value beginning with "!", e.g. "!$6$salt$hash"). A
			// leading "!" means the account cannot password-login until it
			// is unlocked, so it does not count (Codex #1944 r1 Low).
			pw := u.EncryptedPassword.Reveal()
			usablePassword := pw != "" && pw != "*" && !strings.HasPrefix(pw, "!")
			if len(u.SSHKeys) == 0 && !usablePassword {
				warnings = append(warnings, fmt.Sprintf(
					"login user %s has no usable authentication method: no "+
						"ssh keys and no encrypted-password (a bare lock "+
						"sentinel does not count) — this account cannot log "+
						"in. Set `authentication encrypted-password` (hash "+
						"from `openssl passwd -6`) or an ssh key.", u.Name))
			}
		}
	}

	// Collect valid zone names
	zones := make(map[string]bool)
	for name := range cfg.Security.Zones {
		zones[name] = true
	}

	// Collect valid address-book entries (Addresses + AddressSets). Used by the
	// address-set member validation below, which deliberately does NOT accept a
	// dynamic-address feed binding as a set member (feed-in-set is enforced on
	// the dataplane set-row merge, not strict-accepted — #3294).
	addrs := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			addrs[name] = true
		}
		for name := range ab.AddressSets {
			addrs[name] = true
		}
	}

	// #3958: a policy source/destination-address reference is valid in several
	// forms that are NOT plain address-book names — the `any`/`any-ipv4`/
	// `any-ipv6` wildcards, a literal IPv4/IPv6 address or CIDR, and a
	// dynamic-address feed binding name. The previous warn check only excluded
	// `any` and address-book entries, so it emitted a false "not in
	// address-book" warning for every literal / any-ipv4 / any-ipv6 / feed
	// reference in a perfectly valid policy — alarm fatigue that trains
	// operators to ignore validation warnings. Mirror the strict gate
	// (validatePolicyMatchAddressesStrict, #2008/#3294) EXACTLY via the shared
	// policyMatchAddressTokenRecognized predicate so the warn pass and the
	// strict path cannot diverge; only a token recognized by NONE of the valid
	// forms — a genuinely undefined reference — still warns.
	policyAddrRefs := policyMatchNamedAddressRefs(cfg)

	// Validate application port specs and protocols
	for name, app := range cfg.Applications.Applications {
		if app == nil { // #3494: tolerant/HA-sync path may carry a nil application
			continue
		}
		if err := validatePortSpec(app.DestinationPort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: destination-port: %v", name, err))
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: source-port: %v", name, err))
		}
		if app.Protocol != "" {
			if err := validateProtocol(app.Protocol); err != nil {
				warnings = append(warnings, fmt.Sprintf("application %s: %v", name, err))
			}
		}
		// #4337: a per-application `alg <name>` outside the four the dataplane
		// implements (dns/ftp/sip/tftp) is accepted-but-inert, not hard-rejected
		// (relaxed from the #3353 commit reject — real vSRX app defs tag apps
		// with ALGs xpf does not implement, e.g. `alg ssh`, a pure drop-in
		// blocker). The per-application ALG is not carried into the userspace
		// snapshot (the wire has only the global alg_disable_flags bitfield), so
		// even a KNOWN name is informational; warn only for an UNKNOWN one so a
		// typo is still surfaced. Mirrors the global `security alg`
		// accepted-but-inert advisory (#4232). Enforcement deferred to the
		// per-application ALG slice of #2008.
		if app.ALG != "" && !validApplicationALG(app.ALG) {
			warnings = append(warnings, fmt.Sprintf(
				"application %s: alg %q accepted but not enforced — xpf implements "+
					"per-application ALG control only for dns/ftp/sip/tftp; an "+
					"unrecognized alg name commits but has no effect (enforcement "+
					"deferred to the per-application ALG slice of #2008)",
				name, app.ALG))
		}
	}

	// Validate policies. Exempt the reserved special-zone tokens (`any`,
	// `junos-host`, the empty token) via the SAME policyZoneSpecialTokens set
	// the strict gate (validatePolicyZoneReferencesStrict, #2401) uses — a
	// single source of truth so a config that legitimately references
	// `junos-host` (or carries an empty token) does not draw a spurious
	// "zone not defined" warning while the strict path correctly accepts it.
	policyZoneDefined := func(zone string) bool {
		if _, special := policyZoneSpecialTokens[zone]; special {
			return true
		}
		return zones[zone]
	}
	for _, zpp := range cfg.Security.Policies {
		// #3494: the tolerant / HA-sync config path (#3474) can leave a nil
		// zone-pair set (Policies is []*ZonePairPolicies); skip it like the
		// runtime walker (pkg/dataplane/userspace/policies.go) does rather
		// than panicking on zpp.FromZone while generating warnings.
		if zpp == nil {
			continue
		}
		if !policyZoneDefined(zpp.FromZone) {
			warnings = append(warnings, fmt.Sprintf(
				"policy from-zone %q: zone not defined", zpp.FromZone))
		}
		if !policyZoneDefined(zpp.ToZone) {
			warnings = append(warnings, fmt.Sprintf(
				"policy to-zone %q: zone not defined", zpp.ToZone))
		}
		for _, p := range zpp.Policies {
			// #3494: skip a nil rule (Policies is []*Policy) like the
			// runtime walker does, mirroring the guards already present at
			// lines ~813/1084, rather than dereferencing p.Match.
			if p == nil {
				continue
			}
			for _, addr := range p.Match.SourceAddresses {
				if !policyMatchAddressTokenRecognized(addr, policyAddrRefs) {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
			for _, addr := range p.Match.DestinationAddresses {
				if !policyMatchAddressTokenRecognized(addr, policyAddrRefs) {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: destination-address %q not in address-book", p.Name, addr))
				}
			}
			// An undefined `match application` reference is no longer
			// warned here: validatePolicyMatchApplicationsStrict (#3144)
			// hard-rejects it at commit and emits the warning on the
			// tolerant load / peer-sync path. Resolving it here too (with a
			// narrower 24-entry builtin list) produced a duplicate warning
			// and a false positive for predefined apps outside that list
			// (e.g. junos-pingv6, junos-tcp-any).
		}
	}

	// Validate NAT zone references
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil { // #3494: tolerant/HA-sync path may carry a nil rule-set
			continue
		}
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
		if rs.ToZone != "" && !zones[rs.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: to-zone %q not defined", rs.Name, rs.ToZone))
		}
	}
	// Static NAT rule-sets carry a `from zone` scope that the dataplane
	// enforces on the inbound (DNAT) direction (static_nat.rs match_dnat:
	// the entry is skipped unless its from_zone matches the ingress zone
	// name exactly). A typo'd or undefined zone therefore yields a rule
	// that silently never matches, with no other operator signal — mirror
	// the source-NAT zone validation above so the divergence surfaces at
	// commit (#2008 H15).
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"static-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
	}

	// Validate screen references in zones
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		if zone.ScreenProfile != "" {
			if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: screen profile %q not defined", name, zone.ScreenProfile))
			}
		}
	}

	// #3226: `system-services any-service` is a packet-wide host-inbound
	// full-admit, NOT a union of the known system-service tokens. On BOTH
	// enforcement layers (the nft kernel mirror `hostInboundAllowsAll` →
	// `<fam> daddr <addrs> accept` with no catch-all drop, and the Rust AF_XDP
	// classifier `all_services` short-circuit) it accepts EVERY IP protocol/port
	// — GRE/ESP/AH/OSPF/PIM/VRRP and arbitrary future protocol numbers — to the
	// zone's local firewall addresses. Junos defines `any-service` as "all system
	// services on an entire port range including the system services that are not
	// defined", so it IS the documented escape hatch; xpf's packet-wide reading is
	// a superset of that. The breadth is deliberate, so this is a WARNING, never a
	// reject. `HostInboundFullAdmitService` is the SSOT for which tokens are
	// full-admit (pkg/config/host_inbound_tokens.go). Emitted for the zone-level
	// stanza AND every per-interface override (#3362); one advisory per stanza.
	//
	// The sibling `system-services all` NO LONGER lands here: #3226 scoped it to
	// the named-service union (HostInboundAllExpansionServices), matching the
	// Junos definition ("traffic from the defined system services available on the
	// Routing Engine") and the shape #3199 gave `protocols all`. It draws the
	// separate scoping advisory below instead.
	fullAdmitAdvice := func(where string, svcs []string) {
		for _, svc := range svcs {
			if !HostInboundFullAdmitService(svc) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"%s: system-services %q is a broad packet-wide full-admit that "+
					"accepts EVERY IP protocol/port "+
					"(GRE/ESP/AH/OSPF/PIM/VRRP/future proto numbers) to the "+
					"zone's local addresses — a superset of Junos's per-service "+
					"union; if you intend only specific services, list them "+
					"explicitly.", where, svc))
			return // one advisory per stanza
		}
	}
	// #3226 scoping advisory for `system-services all`. The token is valid Junos
	// and is now enforced with the Junos meaning, so this is purely an UPGRADE
	// notice: a deploy that leaned on the old packet-wide breadth to admit a
	// non-named protocol/port loses that admit, and the catch-all host-inbound
	// drop is now armed for the zone.
	//
	// It is gated on the stanza's zone owning at least one NON-lifeline
	// interface, because the narrowing can only change enforcement where the
	// zone actually contributes host-inbound addresses. Lifeline interfaces
	// (fxp0 + the configured cluster control/fabric interfaces, #3277) are
	// excluded from the deny address sets by BuildZoneHostInboundViews, so a
	// lifeline-only zone emits no rules at all and `all` vs the expansion is
	// indistinguishable there. Every shipped HA config puts `system-services
	// all` on exactly such a zone (the lifeline-only `control` zone — see
	// docs/ha-cluster-userspace.conf), so an ungated advisory would fire on
	// every cluster commit forever while flagging a guaranteed no-op.
	lifelines := HostInboundLifelineSet(cfg)
	allScopingAdvice := func(where string, svcs []string, enforcing bool) {
		if !enforcing {
			return
		}
		for _, svc := range svcs {
			if strings.ToLower(strings.TrimSpace(svc)) != "all" {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"%s: system-services \"all\" now expands to the union of the "+
					"named system-services (Junos parity, #3226) and no longer "+
					"admits every IP protocol/port — GRE, OSPF/PIM/VRRP, "+
					"unlisted TCP/UDP ports and future protocol numbers are now "+
					"DENIED to the zone's local addresses unless listed "+
					"explicitly under system-services / protocols; use "+
					"\"any-service\" for the previous packet-wide admit. "+
					"ESP/AH are NOT affected: they keep an unconditional "+
					"global accept (host-terminated IPsec is decrypted by XFRM "+
					"before any host-inbound deny), so no action is needed for "+
					"them — and there is no esp/ah token to list in any case.", where))
			return // one advisory per stanza
		}
	}
	// #3226 fold: for several services in Juniper's `system-services`
	// enumeration xpf has no authoritative listening tuple — r2cp, rpm,
	// tcp-encap, appqoe and high-availability
	// (config.HostInboundUnportedSystemServices). Junos would open whatever port
	// applies; xpf refuses to guess, because an invented port opens a port with
	// no listener while STILL denying the port actually in use. So these tokens
	// commit (they are real Junos services — rejecting them is the #3200 parity
	// gap) but synthesize no admit on either enforcement surface.
	//
	// That divergence is fail-CLOSED but it must not be SILENT: an operator who
	// went to the trouble of naming the service plainly expects it to work.
	// Warn at the moment they name it, and name a remedy that ACTUALLY WORKS.
	//
	// `any-service` is the ONLY remedy, and the advisory names nothing else.
	// Two earlier revisions got this wrong and the history is worth keeping:
	//
	//   r3 told operators to "admit the real port with a firewall filter". False
	//     on the AF_XDP local-delivery path: #3485 deliberately runs the
	//     host-inbound gate FIRST so a denied packet incurs none of the lo0
	//     filter's side-effects (counter, log, reject reply); on a deny the lo0
	//     filter is never evaluated at all.
	//   r4 narrowed that to "kernel path only", reasoning that xpf_lo0 (hook
	//     input priority 0) runs before xpf_hostinbound (priority 10) so an lo0
	//     `accept` terminates first. The PRIORITIES are right and the CONCLUSION
	//     is wrong: in nftables `accept` ends the current BASE CHAIN, not the
	//     hook. The nftables man page is explicit — "An accept verdict ... ends
	//     the evaluation of the current base chain. ... The packet advances to
	//     the next base chain", whereas only drop "immediately ends the
	//     evaluation of the whole ruleset". So the packet still traverses
	//     xpf_hostinbound at priority 10 and still hits its catch-all drop.
	//     There is no mark, no return-path exclusion, no bypass wiring between
	//     the two chains.
	//
	// So an lo0 filter accept rescues NOTHING on EITHER surface, and the remedy
	// is withdrawn rather than narrowed. Making it work would mean building a
	// real bypass — an explicit mark set in xpf_lo0 and tested in
	// xpf_hostinbound, or merging the chains — which is a new security mechanism
	// that deliberately lets an lo0 filter override the zone host-inbound
	// default-deny. That needs its own design and threat review, and it would
	// STILL not help on the AF_XDP path without also reordering #3485. Out of
	// scope here; see docs/host-inbound-service-matrix.md.
	//
	// Gated on explicit naming only. `system-services all` also covers these
	// tokens (contributing nothing), but warning there would fire on a large
	// fraction of commits — including every lifeline-only HA `control` zone —
	// while telling the operator nothing they asked about. The `all` case is
	// documented in docs/host-inbound-service-matrix.md instead.
	//
	// SUPPRESSED when the same stanza already carries a full-admit token. The
	// advisory's entire content is "this traffic is DENIED, use any-service" —
	// but with `any-service` present nothing IS denied (the full-admit
	// short-circuit means no catch-all drop is emitted at all, and the AF_XDP
	// classifier admits unconditionally), so the warning would be false on its
	// premise AND would advise adding a token the operator has already added.
	// The two advisory passes run independently, so without this gate a stanza
	// naming both `any-service` and `rpm` emitted one warning saying
	// `any-service` admits everything and another saying rpm is denied.
	unportedAdvice := func(where string, svcs []string) {
		for _, svc := range svcs {
			if HostInboundFullAdmitService(svc) {
				return
			}
		}
		var named []string
		seen := map[string]bool{}
		for _, svc := range svcs {
			tok := strings.ToLower(strings.TrimSpace(svc))
			if !HostInboundUnportedSystemServices[tok] || seen[tok] {
				continue
			}
			seen[tok] = true
			named = append(named, tok)
		}
		if len(named) == 0 {
			return
		}
		sort.Strings(named)
		// The two reason classes describe different operator situations, so they
		// get different wording. For an operator-configured port the operator
		// KNOWS their port and can act on it; for an unsourced service nobody
		// knows it, including xpf, and saying "the port is configurable" there
		// would be a lie.
		var configured, unsourced []string
		for _, tok := range named {
			if HostInboundNoAdmitReason[tok] == HostInboundNoPortOperatorConfigured {
				configured = append(configured, tok)
			} else {
				unsourced = append(unsourced, tok)
			}
		}
		var why []string
		if len(configured) > 0 {
			why = append(why, fmt.Sprintf(
				"[%s] have an operator-configured port with no platform default, so there "+
					"is no fixed port for xpf to admit", strings.Join(configured, " ")))
		}
		if len(unsourced) > 0 {
			why = append(why, fmt.Sprintf(
				"for [%s] xpf could not find an authoritative listening port and will not "+
					"guess one", strings.Join(unsourced, " ")))
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s: system-services [%s] accepted but NOT enforced — %s (a guessed port "+
				"opens an unused port while still denying the one actually in use). "+
				"Their traffic is DENIED to the zone's local addresses. The only remedy "+
				"is \"any-service\"; an lo0 input filter does NOT help, on either "+
				"enforcement path.",
			where, strings.Join(named, " "), strings.Join(why, "; ")))
	}
	hiZoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		hiZoneNames = append(hiZoneNames, name)
	}
	sort.Strings(hiZoneNames)
	for _, name := range hiZoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil { // #3494: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		// True when the zone owns an interface that contributes host-inbound
		// addresses (i.e. is not a lifeline), so the #3226 narrowing is
		// observable on this zone.
		zoneEnforces := false
		for _, ifRef := range zone.Interfaces {
			if !HostInboundLifelineInterface(ifRef, lifelines) {
				zoneEnforces = true
				break
			}
		}
		// #3226 fold: every advisory below reasons about the EFFECTIVE token
		// set — the zone-level list UNION the per-interface override, via the
		// shared UnionHostInboundTokens — because that is what enforcement acts
		// on (Junos host-inbound is additive across the two levels). Reasoning
		// per RAW STANZA made the advisories contradict enforcement AND each
		// other: a zone `any-service` with a per-interface `rpm` warned that rpm
		// was DENIED when the union full-admits it. Sharing the union removes
		// the whole class rather than special-casing each pair.
		var zoneSvcs []string
		if zone.HostInboundTraffic != nil {
			zoneSvcs = zone.HostInboundTraffic.SystemServices
		}
		// A full-admit token anywhere in an effective set makes the scoping and
		// unported advisories moot for that set: nothing is denied, so telling
		// the operator traffic is DENIED (and to add `any-service`) would be
		// false on its premise and would advise a change already made.
		effectiveFullAdmits := func(svcs []string) bool {
			for _, svc := range svcs {
				if HostInboundFullAdmitService(svc) {
					return true
				}
			}
			return false
		}
		// The zone-level stanza governs every interface that does NOT override.
		// If EVERY interface in the zone overrides with a full-admit, the
		// zone-level narrowing is unobservable and its advisories are moot too.
		zoneObservable := !effectiveFullAdmits(zoneSvcs)
		if zoneObservable && len(zone.Interfaces) > 0 {
			allCovered := true
			for _, ifRef := range zone.Interfaces {
				hi := zone.InterfaceHostInbound[CanonicalInterfaceUnitRef(ifRef)]
				if hi == nil || !effectiveFullAdmits(hi.SystemServices) {
					allCovered = false
					break
				}
			}
			if allCovered {
				zoneObservable = false
			}
		}
		if zone.HostInboundTraffic != nil {
			where := fmt.Sprintf("zone %q host-inbound-traffic", name)
			fullAdmitAdvice(where, zoneSvcs)
			allScopingAdvice(where, zoneSvcs, zoneEnforces && zoneObservable)
			if zoneObservable {
				unportedAdvice(where, zoneSvcs)
			}
		}
		// #3362: per-interface overrides carry the same token grammar and the
		// same packet-wide breadth, so warn on each of them too. Iterated via
		// the SSOT sorted-refs helper for deterministic advisory ordering.
		for _, ifRef := range zone.SortedInterfaceHostInboundRefs() {
			hi := zone.InterfaceHostInbound[ifRef]
			if hi == nil {
				continue
			}
			where := fmt.Sprintf("zone %q interface %q host-inbound-traffic", name, ifRef)
			// The EFFECTIVE set for this interface, exactly as the dataplane
			// enforcement view builder computes it.
			effective := UnionHostInboundTokens(zoneSvcs, hi.SystemServices)
			// The full-admit notice stays keyed on the OVERRIDE's own tokens: it
			// reports what this stanza declares, and a zone-level `any-service`
			// already drew its own notice at the zone level.
			fullAdmitAdvice(where, hi.SystemServices)
			observable := !effectiveFullAdmits(effective)
			// An override is scoped to ONE interface, so gate it on that
			// interface's own lifeline status rather than the zone's.
			allScopingAdvice(where, effective,
				!HostInboundLifelineInterface(ifRef, lifelines) && observable)
			if observable {
				unportedAdvice(where, effective)
			}
		}
	}

	// Validate address-book entries have valid CIDR or IP formats
	if ab := cfg.Security.AddressBook; ab != nil {
		for name, entry := range ab.Addresses {
			if entry == nil { // #3494: tolerant/HA-sync path may carry a nil address
				continue
			}
			if entry.Value == "" {
				// An `address <name>` entry with no compiled prefix —
				// either no prefix at all, or only an as-yet-uncompiled
				// sub-stanza (dns-name/range-address/wildcard-address) —
				// resolves to nothing: net.ParseCIDR("") errors at match
				// time, so every policy referencing it denies (fail-closed,
				// #2229). That is safe but silent, so surface the operator
				// authoring error at commit. This is a WARNING, never a
				// hard reject: an empty-prefix address never forwarded and
				// rejecting it would brick existing configs.
				warnings = append(warnings, fmt.Sprintf(
					"address-book %q: no usable prefix configured; it will match nothing", name))
				continue
			}
			if _, _, err := net.ParseCIDR(entry.Value); err != nil {
				if net.ParseIP(entry.Value) == nil {
					warnings = append(warnings, fmt.Sprintf(
						"address-book %q: invalid address %q", name, entry.Value))
				}
			}
		}
		// Validate address-set members reference valid entries
		for setName, as := range ab.AddressSets {
			if as == nil { // #3494: tolerant/HA-sync path may carry a nil address-set
				continue
			}
			for _, m := range as.Addresses {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: member %q not in address-book", setName, m))
				}
			}
			for _, m := range as.AddressSets {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: nested set %q not in address-book", setName, m))
				}
			}
		}
	}

	// Validate static route destinations are valid CIDR
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr == nil { // #3494: tolerant/HA-sync path may carry a nil static route
			continue
		}
		if sr.Destination != "" {
			if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"static route: invalid destination %q", sr.Destination))
			}
		}
	}

	// Source/destination-NAT pool REFERENCES (`then ... pool <name>` naming a
	// pool not defined under `security nat source/destination pool`) are
	// validated by the strict commit gate validateNATPoolReferencesStrict
	// (#5626): hard-reject on commit / commit-check, downgraded to a warning on
	// the tolerant load / peer-sync path (opts.lenientDestNATAddresses). The
	// strict gate subsumes the warn-only loop that previously lived here (it
	// would otherwise emit a duplicate warning alongside the downgraded gate
	// warning on the lenient path). The snapshot builders independently fail
	// closed for a dangling pool (SNAT marks the rule unusable, DNAT drops it),
	// so a leniently-loaded config referencing an undefined pool installs
	// nothing rather than mis-translating.

	// Zone interface references (`security zones security-zone <z> interfaces
	// <if>` naming an interface not defined under `interfaces`) are validated by
	// the strict commit gate validateZoneInterfaceDefinedStrict (ps-review-002
	// F6, #4515): hard-reject on commit / commit-check, downgraded to a warning
	// on the tolerant load / peer-sync path. The strict gate subsumes the
	// warn-only loop that previously lived here (it would otherwise emit a
	// duplicate warning alongside the downgraded gate warning on the lenient
	// path). Its reference set is the GENEROUS zoneReferenceableInterfaceBases
	// union (lo0 + IPsec secure-tunnel bases + every configured interface), so it
	// does NOT false-reject a daemon-materialized dynamic-interface reference.
	//
	// configuredIfaces (the naive cfg.Interfaces.Interfaces set) is retained for
	// the routing-instance interface warn below, which stays warn-only.
	configuredIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		configuredIfaces[name] = true
	}

	// Validate scheduler references in policies
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil { // #3494: tolerant/HA-sync path may carry a nil zone-pair set
			continue
		}
		for _, p := range zpp.Policies {
			if p == nil { // #3494: tolerant/HA-sync path may carry a nil rule
				continue
			}
			if p.SchedulerName != "" {
				if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
				}
			}
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		if p == nil { // #3494: tolerant/HA-sync path may carry a nil global rule
			continue
		}
		if p.SchedulerName != "" {
			if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"global policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
			}
		}
	}

	// #3860: warn when a scheduler defines no effective window. Post-#3849/
	// #3858 the runtime evaluator (pkg/scheduler.isWithinWindow) fail-closes
	// such a scheduler to INACTIVE — an absent window is never treated as
	// always-on. That direction is safe (the config is degenerate), but an
	// operator migrating a config that relied on the old always-on bug loses
	// enforcement silently. Surface the flip at commit. A scheduler carrying
	// any time-of-day window (daily/weekday arm or all-day) or a start/stop
	// calendar range is well-formed and does NOT warn. Iterate by sorted name
	// so warnings are deterministic across commits (map iteration is
	// randomized).
	schedNames := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		schedNames = append(schedNames, name)
	}
	sort.Strings(schedNames)
	for _, name := range schedNames {
		sched := cfg.Schedulers[name]
		if sched == nil {
			continue
		}
		if schedulerHasEffectiveWindow(sched) {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"scheduler %q defines no time window; policies bound to it will "+
				"be INACTIVE (use `daily all-day` for always-on)", name))
	}

	// Validate routing-instance interface references
	for _, ri := range cfg.RoutingInstances {
		if ri == nil { // #3494: tolerant/HA-sync path may carry a nil routing-instance
			continue
		}
		for _, ifName := range ri.Interfaces {
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"routing-instance %q: interface %q not in interfaces config",
					ri.Name, ifName))
			}
		}
	}

	// Firewall filter references on interfaces (and lo0) are validated by the
	// strict commit gate validateFirewallFilterReferencesStrict (#3296):
	// hard-reject on commit / commit-check, downgraded to a warning on the
	// tolerant load / peer-sync path. The strict gate fully subsumes the
	// warn-only loop that previously lived here (it would otherwise emit a
	// duplicate warning alongside the downgraded gate warning on the lenient
	// path).

	// Validate chassis cluster fabric config
	if cc := cfg.Chassis.Cluster; cc != nil {
		// fabric1-interface without fabric1-peer-address (or vice versa) is incomplete
		if (cc.Fabric1Interface != "") != (cc.Fabric1PeerAddress != "") {
			warnings = append(warnings, "chassis cluster: fabric1-interface and fabric1-peer-address must both be set for dual-fabric")
		}
		// Check fabric interfaces are defined in interface config
		for _, pair := range [][2]string{
			{cc.FabricInterface, "fabric-interface"},
			{cc.Fabric1Interface, "fabric1-interface"},
		} {
			ifName, label := pair[0], pair[1]
			if ifName != "" {
				if _, ok := cfg.Interfaces.Interfaces[ifName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"chassis cluster %s %q: interface not defined", label, ifName))
				}
			}
		}
		// Check control interface is defined
		if cc.ControlInterface != "" {
			if _, ok := cfg.Interfaces.Interfaces[cc.ControlInterface]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"chassis cluster control-interface %q: interface not defined", cc.ControlInterface))
			}
		}
		// Check fabric member interfaces don't overlap between fab0 and fab1
		if cc.FabricInterface != "" && cc.Fabric1Interface != "" {
			fab0Members := make(map[string]bool)
			if f0 := cfg.Interfaces.Interfaces[cc.FabricInterface]; f0 != nil {
				for _, m := range f0.FabricMembers {
					fab0Members[m] = true
				}
			}
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				for _, m := range f1.FabricMembers {
					if fab0Members[m] {
						warnings = append(warnings, fmt.Sprintf(
							"chassis cluster: fabric member %q shared between %s and %s",
							m, cc.FabricInterface, cc.Fabric1Interface))
					}
				}
			}
		}
	}

	// Validate strict-vip-ownership requires VRRP (incompatible with no-reth-vrrp / private-rg-election)
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		for _, rg := range cc.RedundancyGroups {
			if rg == nil { // #3494: tolerant/HA-sync path may carry a nil redundancy-group
				continue
			}
			if rg.StrictVIPOwnership {
				warnings = append(warnings, fmt.Sprintf(
					"redundancy-group %d: strict-vip-ownership incompatible with no-reth-vrrp (no VRRP instances to gate on)", rg.ID))
			}
		}
	}

	// Warn if no-reth-vrrp set explicitly — redundant since private-rg-election is now default
	if cc := cfg.Chassis.Cluster; cc != nil && cc.PrivateRGElection && cc.NoRethVRRP {
		warnings = append(warnings, "chassis cluster: no-reth-vrrp is redundant (private-rg-election is the default)")
	}

	if cfg.System.PersistGroupsInheritance {
		warnings = append(warnings, "system commit persist-groups-inheritance configured but group inheritance persistence is not implemented")
	}

	// #2008 H13 Stage 1: the leaf is now typed (schema + field) instead of
	// being silently dropped, but the idle-yield dataplane runtime is not
	// implemented — the userspace AF_XDP workers busy-poll. Warn so the
	// operator knows the knob is accepted but currently has no effect.
	if cfg.ForwardingOptions.AllowDataplaneSleep {
		warnings = append(warnings, "forwarding-options allow-dataplane-sleep configured but is accepted-only — the userspace dataplane workers busy-poll and idle-yield is not yet implemented")
	}

	// #2078: the `security flow tcp-session` presence flags are typed and
	// committed but the userspace AF_XDP dataplane enforces none of them
	// today. no-syn-check / no-syn-check-in-tunnel would gate the
	// session-create SYN check; rst-invalidate-session would tear a session
	// down on RST; no-sequence-check (#2008 M9) would skip sequence-window
	// validation. The dataplane session table is a pure 5-tuple flow entry
	// with no TCP state machine and no sequence/window tracking, so there is
	// nothing for any of these knobs to enforce or skip. This is an
	// intentional, reviewed parity gap (see #2008 M9 and the RST design
	// rationale in docs/active-active-new-connections.md); research #2078
	// converged PLAN-KILL on enforcement. Warn so an operator who sets one
	// of these is not silently misled into believing it has runtime effect.
	if ts := cfg.Security.Flow.TCPSession; ts != nil {
		var unenforced []string
		if ts.NoSynCheck {
			unenforced = append(unenforced, "no-syn-check")
		}
		if ts.NoSynCheckInTunnel {
			unenforced = append(unenforced, "no-syn-check-in-tunnel")
		}
		if ts.RstInvalidateSession {
			unenforced = append(unenforced, "rst-invalidate-session")
		}
		if ts.NoSequenceCheck {
			unenforced = append(unenforced, "no-sequence-check")
		}
		if len(unenforced) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security flow tcp-session %s configured but accepted-only — the userspace dataplane has no TCP state machine and does not enforce these knobs (config-only parity, #2078)",
				strings.Join(unenforced, ", ")))
		}
	}

	// #4233/#4234: `security policies policy-rematch [extensive]` is typed and
	// recorded (compiler_security_policy.go). The Junos-DEFAULT deletion-clear
	// ships (#4234): a session admitted by a policy that a commit DELETES is
	// invalidated immediately at commit (daemon_apply.go →
	// clearSessionsForDeletedPolicies), independent of this knob. The
	// modified-policy re-evaluation ALSO now ships when policy-rematch is set
	// (clearSessionsForModifiedPolicies): a session admitted by a policy whose
	// MATCH or ACTION later changed is dropped at commit so the tightened policy
	// re-evaluates live traffic. What remains unenforced is `extensive`: Junos
	// re-evaluates even sessions of an UNCHANGED policy when a referenced
	// address-book / application object changes; xpf clears only the policies
	// whose own match/action text changed. Warn on `extensive` so an operator is
	// not misled; a plain `policy-rematch` needs no advisory now that its core is
	// enforced. The `extensive` gap stays tracked in #4234.
	if cfg.Security.PolicyRematchExtensive {
		warnings = append(warnings,
			"security policies policy-rematch extensive configured but only "+
				"partially enforced — xpf re-evaluates live sessions of a policy "+
				"whose own match/action changed, but does NOT re-evaluate sessions "+
				"of an UNCHANGED policy when a referenced address-book / application "+
				"object changes (the `extensive` case); those sessions keep "+
				"forwarding until idle timeout (#4234)")
	}

	// #4231 (fable-167 P-3): five `security flow` knobs are now typed +
	// committed (schema leaves + compileFlow) but the userspace AF_XDP
	// dataplane enforces none of them today. Mirror the #2078 tcp-session
	// accepted-only doctrine: warn so an operator who sets one is not silently
	// misled into believing it has runtime effect. sync-icmp-session gets its
	// own, distinct line because it is a no-op for a DIFFERENT reason than the
	// other four: xpf ALREADY syncs ICMP sessions to the HA peer
	// UNCONDITIONALLY — the session-sync path is protocol-agnostic at every
	// layer (publish_shared_session / snapshot_all_sessions_export in
	// userspace-dp; the Go pkg/cluster wire has no protocol filter), so the
	// Junos opt-in knob has nothing to turn on. The two duration knobs
	// (route-change-timeout, multicast-session-lifetime) are "present" when > 0
	// (0 = unset / disabled, no behavior to warn about); the toggles warn on
	// presence.
	{
		flow := cfg.Security.Flow
		var flowUnenforced []string
		if flow.RouteChangeTimeout > 0 {
			flowUnenforced = append(flowUnenforced, "route-change-timeout")
		}
		if flow.ForceIPReassembly {
			flowUnenforced = append(flowUnenforced, "force-ip-reassembly")
		}
		if flow.MulticastSessionLifetime > 0 {
			flowUnenforced = append(flowUnenforced, "multicast-session-lifetime")
		}
		if flow.PreserveIncomingFragmentSize {
			flowUnenforced = append(flowUnenforced, "preserve-incoming-fragment-size")
		}
		if len(flowUnenforced) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security flow %s configured but accepted-only — the userspace dataplane does not enforce these knobs (config-only parity, #4231)",
				strings.Join(flowUnenforced, ", ")))
		}
		if flow.SyncICMPSession {
			warnings = append(warnings,
				"security flow sync-icmp-session configured but has no effect — xpf syncs ICMP sessions to the HA peer UNCONDITIONALLY (the session-sync path is protocol-agnostic), so this Junos opt-in knob is a no-op: ICMP session sync is already always on and cannot be turned off (config-only parity, #4231)")
		}
	}

	// #4299 (fable-167 V-3): `security ipsec vpn <v> vpn-monitor` is typed +
	// captured (schema leaf + compileIPsec) but xpf does not implement its
	// ICMP-probe tunnel-liveness monitoring or st0 interface-state coupling.
	// Mirror the #2078/#4231 accepted-only doctrine: warn so an operator who
	// configures it is not silently misled into believing the tunnel is being
	// probed. IKE-layer DPD (dead-peer-detection, #3994) IS enforced and is a
	// partial substitute for peer liveness, but not for vpn-monitor's
	// interface-state coupling. Full enforcement is a monitoring follow-up.
	{
		var monVPNs []string
		for name := range cfg.Security.IPsec.VPNs {
			if vpn := cfg.Security.IPsec.VPNs[name]; vpn != nil && vpn.VPNMonitor {
				monVPNs = append(monVPNs, name)
			}
		}
		if len(monVPNs) > 0 {
			sort.Strings(monVPNs)
			warnings = append(warnings, fmt.Sprintf(
				"security ipsec vpn %s vpn-monitor configured but accepted-only "+
					"— xpf does not implement vpn-monitor ICMP-probe liveness or "+
					"st0 interface-state coupling; configure ike gateway "+
					"dead-peer-detection for IKE-layer peer liveness "+
					"(config-only parity, #4299)",
				strings.Join(monVPNs, ", ")))
		}
	}

	// #4313: `security ipsec proposal <p> lifetime-kilobytes <kb>` is now typed
	// + captured (schema leaf + compileIPsec) so the closed-world flip on the
	// Phase-2 proposal is leaf-complete, but the ESP child SA is not yet
	// programmed with a volume-based rekey threshold (the renderer emits only
	// rekey_time, not rekey_bytes). Mirror the #2078/#4231 accepted-only
	// doctrine: warn so an operator who sets a volume rekey is not silently
	// misled into believing the SA rekeys on bytes. Full enforcement is a
	// renderer + dataplane follow-up.
	{
		var lkbProps []string
		for name := range cfg.Security.IPsec.Proposals {
			if p := cfg.Security.IPsec.Proposals[name]; p != nil && p.LifetimeKilobytes > 0 {
				lkbProps = append(lkbProps, name)
			}
		}
		if len(lkbProps) > 0 {
			sort.Strings(lkbProps)
			warnings = append(warnings, fmt.Sprintf(
				"security ipsec proposal %s lifetime-kilobytes configured but "+
					"accepted-only — xpf does not program a volume-based (byte) "+
					"rekey threshold; the SA rekeys on lifetime-seconds only "+
					"(config-only parity, #4313)",
				strings.Join(lkbProps, ", ")))
		}
	}

	// #4291 (fable-167 N-2): the NAT `port-overloading` knobs are now typed +
	// committed (schema leaves + compileNAT) but the userspace AF_XDP SNAT
	// allocator enforces neither. `security nat source interface port-overloading
	// off` disables source-port reuse across destinations (a src-port-uniqueness
	// hardening posture) — xpf's allocator always overloads source ports, so
	// `off` hardens NOTHING. `port-overloading-factor <n>` scales the concurrent
	// translations per pool address — xpf has no factor-scaled port budget.
	// Mirror the #2078/#4231 accepted-only doctrine: warn so an operator is not
	// silently misled into believing `off` is a real control. Full enforcement is
	// a userspace-dp SNAT-allocator follow-up.
	{
		var poParts []string
		if cfg.Security.NAT.SourceInterfacePortOverloadingOff {
			poParts = append(poParts, "interface port-overloading off")
		}
		var poFactorPools []string
		for _, name := range sortedPoolNames(cfg.Security.NAT.SourcePools) {
			if p := cfg.Security.NAT.SourcePools[name]; p != nil && p.PortOverloadingFactor > 0 {
				poFactorPools = append(poFactorPools, name)
			}
		}
		if len(poFactorPools) > 0 {
			poParts = append(poParts, fmt.Sprintf("pool %s port-overloading-factor", strings.Join(poFactorPools, ", ")))
		}
		if len(poParts) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security nat source %s configured but accepted-only — the "+
					"userspace dataplane always overloads source ports, so "+
					"port-overloading off hardens nothing and "+
					"port-overloading-factor has no effect (config-only parity, "+
					"#4291)",
				strings.Join(poParts, " / ")))
		}
	}

	// #4292 (fable-167 N-3): NAT translation-TARGET routing-instance is now typed
	// + recorded (compileNAT) but not enforced. `then static-nat {inet|prefix
	// <ip>} routing-instance <ri>` and a source / destination NAT pool
	// `routing-instance <ri>` would place the TRANSLATED packet in a different
	// routing table (cross-VRF NAT) — distinct from the #3096 from/to SCOPE
	// routing-instance, which IS enforced. The dataplane does not route the
	// post-translation packet against a non-ingress table, so the target RI is
	// dropped. Mirror the #2078/#4231 accepted-only doctrine: warn so the dropped
	// target is operator-visible. Full enforcement is a cross-VRF-NAT userspace-dp
	// follow-up.
	{
		targetRISeen := make(map[string]bool)
		var targetRIParts []string
		addRI := func(part string) {
			if !targetRISeen[part] {
				targetRISeen[part] = true
				targetRIParts = append(targetRIParts, part)
			}
		}
		for _, rs := range cfg.Security.NAT.Static {
			if rs == nil {
				continue
			}
			for _, rule := range rs.Rules {
				if rule != nil && rule.ThenRoutingInstance != "" {
					addRI(fmt.Sprintf("static rule-set %q rule %q then static-nat routing-instance %q", rs.Name, rule.Name, rule.ThenRoutingInstance))
				}
			}
		}
		for _, name := range sortedPoolNames(cfg.Security.NAT.SourcePools) {
			if p := cfg.Security.NAT.SourcePools[name]; p != nil && p.RoutingInstance != "" {
				addRI(fmt.Sprintf("source pool %q routing-instance %q", name, p.RoutingInstance))
			}
		}
		if cfg.Security.NAT.Destination != nil {
			for _, name := range sortedPoolNames(cfg.Security.NAT.Destination.Pools) {
				if p := cfg.Security.NAT.Destination.Pools[name]; p != nil && p.RoutingInstance != "" {
					addRI(fmt.Sprintf("destination pool %q routing-instance %q", name, p.RoutingInstance))
				}
			}
		}
		if len(targetRIParts) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security nat translation-target routing-instance configured but "+
					"accepted-only — the userspace dataplane routes the "+
					"post-translation packet against the ingress / default "+
					"routing instance, so the target routing-instance is not "+
					"applied (%s) (config-only parity, #4292)",
				strings.Join(targetRIParts, "; ")))
		}
	}

	// #4559 (ps-034 M-01): deterministic CGNAT `port deterministic block-size
	// <n> host address <cidr>`. Both the IPv4-subscriber path (mode 1) and the
	// IPv6-subscriber / NAPT64 path (mode 2) are now ENFORCED on the userspace
	// dataplane: mode 1 via the source-NAT snapshot + allocate_deterministic_v4,
	// mode 2 via the NAT64 forward path (buildNAT64Snapshots carries the block /
	// host params; nat64.rs allocate_source → allocate_deterministic_v6 maps each
	// IPv6 subscriber to a fixed external IPv4 + port block). What REMAINS
	// deferred (and keeps the advisory) is a deterministic pool that the
	// dataplane cannot map: an IPv6 host of an UNSUPPORTED subscriber-prefix
	// length (only /32 and /64 map to a 32-bit subscriber word), an IPv6-host
	// pool NOT referenced by any `security nat nat64` rule-set (a plain
	// source-NAT rule cannot translate a v6 subscriber to a v4 pool), or a host
	// address that no longer parses. Warn ONLY for those so the operator is not
	// silently misled, mirroring the #4291/#4292 accepted-only doctrine.
	{
		var detPools []string
		for _, name := range sortedPoolNames(cfg.Security.NAT.SourcePools) {
			p := cfg.Security.NAT.SourcePools[name]
			if p == nil || p.Deterministic == nil {
				continue
			}
			// Enforced: an IPv4 host CIDR (mode 1) OR an IPv6 host referenced by a
			// NAT64 rule-set with a supported /32 or /64 prefix (mode 2). Anything
			// else still falls back to round-robin, so it keeps the advisory.
			if deterministicIPv4Enforced(p.Deterministic) {
				continue
			}
			if deterministicNAPT64Enforced(cfg, name, p.Deterministic) {
				continue
			}
			detPools = append(detPools, name)
		}
		if len(detPools) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security nat source pool %s: `port deterministic block-size` is "+
					"accepted but NOT enforced by the userspace dataplane "+
					"(round-robin/sticky SNAT is used instead). IPv4-subscriber "+
					"deterministic CGNAT (mode 1) and IPv6/NAPT64 (mode 2, a /32 or "+
					"/64 host referenced by a `security nat nat64` rule-set) ARE "+
					"enforced; this pool is neither (unsupported IPv6 prefix length, "+
					"not referenced by a nat64 rule-set, or an unparseable host "+
					"address) (#4559)",
				strings.Join(detPools, ", ")))
		}
	}

	// #4232 (fable-167 P-4a): a `security alg <proto>` stanza whose proto is
	// not one of the four the dataplane wires (dns/ftp/sip/tftp) was silently
	// dropped. Warn so the operator knows the stanza is accepted-but-inert
	// (e.g. h323, msrpc) rather than silently enforced. Dedup across repeated
	// `security {}` blocks (compileALG runs per security root) for a clean,
	// deterministic message.
	if protos := cfg.Security.ALG.UnsupportedProtos; len(protos) > 0 {
		seen := make(map[string]bool, len(protos))
		var uniq []string
		for _, p := range protos {
			if !seen[p] {
				seen[p] = true
				uniq = append(uniq, p)
			}
		}
		warnings = append(warnings, fmt.Sprintf(
			"security alg %s accepted but inert — the userspace dataplane implements ALG control only for dns/ftp/sip/tftp, so this stanza has no effect (#4232)",
			strings.Join(uniq, ", ")))
	}

	// #4232 (fable-167 P-4b): a DIRECT child of `policy <name>` whose keyword
	// the compiler does not read (anything but match/then/description/
	// scheduler-name) was silently dropped — a typo'd `descripton` /
	// `scheduler-nam` vanished. Junos rejects the unknown keyword at commit;
	// this advisory at least surfaces it. Report the fully-qualified policy
	// path so the operator can find the offending line.
	var policyUnknown []string
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			for _, kw := range pol.UnknownChildren {
				policyUnknown = append(policyUnknown,
					fmt.Sprintf("%s->%s/%s `%s`", zpp.FromZone, zpp.ToZone, pol.Name, kw))
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		for _, kw := range pol.UnknownChildren {
			policyUnknown = append(policyUnknown, fmt.Sprintf("global/%s `%s`", pol.Name, kw))
		}
	}
	if len(policyUnknown) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"security policy: unrecognized child keyword(s) accepted but dropped (probable typo — xpf reads only match/then/description/scheduler-name at the policy level; Junos rejects unknown keywords at commit): %s (#4232)",
			strings.Join(policyUnknown, ", ")))
	}

	// #3440 H1: `security flow aging` (early-ageout / high-watermark /
	// low-watermark) drives the Go-side conntrack GC watermark hysteresis
	// (pkg/conntrack/gc.go), but that GC sweep is skipped entirely whenever
	// the userspace AF_XDP dataplane is active (daemon_run.go installs
	// gc.SkipSweep = true for the userspace delta-drainer, which is the only
	// runtime forwarding path post #1373/#1476). The userspace session
	// expiry (userspace-dp/src/session/expire.rs) ages each entry only on its
	// own per-session idle timeout (expires_after_ns) with no watermark-driven
	// pressure shedding. So the documented early-ageout/watermark behavior
	// never runs on the userspace dataplane: an operator who configures it
	// believes they have pressure-based session shedding when they do not.
	// Warn so the knob is not silently misleading (matching the #2078 /
	// #2008 H13 accepted-only treatment). Note: per-application
	// inactivity-timeout (#3227) is a DIFFERENT, fully-enforced knob — it
	// reaches the userspace session table via the snapshot and is honored by
	// expire.rs; only the aging watermark machinery here is inert.
	if f := cfg.Security.Flow; f.AgingEarlyAgeout > 0 || f.AgingHighWatermark > 0 || f.AgingLowWatermark > 0 {
		warnings = append(warnings,
			"security flow aging configured but accepted-only — the userspace AF_XDP dataplane ages sessions on their per-session idle timeout only and does not enforce early-ageout / high-watermark / low-watermark pressure-based shedding (config-only, #3440)")
	}

	// #654: warn on `system processes X disable` for a process that
	// bpfrx does not actually manage. Silently accepting the knob (as
	// used to happen with e.g. `utmd disable` on vSRX) means the
	// operator gets no signal that the setting is a no-op.
	for _, proc := range cfg.System.DisabledProcesses {
		if !isKnownProcessName(proc) {
			warnings = append(warnings, fmt.Sprintf(
				"system processes %q disable: bpfrx does not manage %q; setting has no runtime effect", proc, proc))
		}
	}

	// #651: warn when archive-sites include inline `password`
	// credentials. Runtime archival shells out to `scp` with
	// `-o BatchMode=yes`, so the password is silently ignored and
	// archival can fail unless matching SSH keys are already set up.
	if cfg.System.Archival != nil {
		for _, url := range cfg.System.Archival.ArchiveSitesWithPassword {
			warnings = append(warnings, fmt.Sprintf(
				"system archival archive-sites %q: inline password is accepted but ignored — archival uses scp BatchMode and relies on SSH keys, not passwords", url))
		}
	}

	// #7146: the `system syslog file <f> archive` block — files, size,
	// start-time, transfer-interval, archive-sites, world/no-world-readable —
	// is fully modeled in setSchema and implemented by NOTHING. #4303 put
	// `archive` in compileSystem's recognized-modifier skip list, so every
	// knob was read and discarded: the stanza committed clean, rendered back
	// in `show configuration`, and produced no rotation, no retention, and no
	// off-box transfer. An operator configuring log archival believed they had
	// it. Make the acceptance LOUD instead of implementing archival (which is
	// a feature: rotation, size accounting, a transfer schedule, and an scp
	// path that would then need the #4589 leading-dash treatment).
	//
	// WARN, never reject: this stanza commits today, and a hard reject would
	// fail the tolerant load / peer-sync path on a config an operator already
	// has, which is the #1960 brick-on-upgrade shape.
	//
	// Note this is NOT the `system archival configuration` advisory above:
	// that feature archives the CONFIG and does run. Keywords only — an
	// archive-sites URL can embed credentials.
	if cfg.System.Syslog != nil {
		for _, f := range cfg.System.Syslog.Files {
			if f == nil || !f.ArchiveConfigured {
				continue
			}
			knobs := ""
			if len(f.ArchiveKnobs) > 0 {
				knobs = fmt.Sprintf(" [%s]", strings.Join(f.ArchiveKnobs, " "))
			}
			warnings = append(warnings, fmt.Sprintf(
				"system syslog file %q archive%s: accepted for Junos compatibility but NOT implemented — xpf writes /var/log/%s through an rsyslog drop-in and applies no rotation, no size cap, no retention count, no start-time schedule, and no off-box transfer, so this log file is never rotated and its contents are NOT archived anywhere. The configuration is valid and this is expected, not a fault in it; rotate and collect /var/log/%s with the host's own log policy (#7146)",
				f.Name, knobs, f.Name, f.Name))
		}
	}

	if cfg.System.Services != nil && cfg.System.Services.DNSProxyConfigured {
		warnings = append(warnings, "system services dns dns-proxy configured but DNS proxy/forwarder runtime is not implemented")
	}

	// #1715: `system services dns` no longer selects a systemd-resolved
	// owner runtime branch. xpf owns /etc/resolv.conf directly as a
	// managed plain file and keeps resolved disabled+masked regardless of
	// this stanza. Warn so an operator who set it expecting resolved is
	// not surprised that resolved stays off.
	if cfg.System.Services != nil && cfg.System.Services.DNSEnabled {
		warnings = append(warnings, "system services dns: resolved-owner mode is not supported; xpf manages /etc/resolv.conf directly and keeps systemd-resolved disabled+masked")
	}

	if fm := cfg.Services.FlowMonitoring; fm != nil {
		// #3270: flow-dir is derived from the per-zone sampling-direction
		// (`sampling input`/`output`). With no sampling-direction configured
		// anywhere the derived flowDirection is always 0 (ingress), so the
		// exported IE 61 would be a constant — warn the operator in that case.
		hasSampling := anySamplingDirectionConfigured(cfg)
		checkExtWarning := func(kind, name string, exts []string) {
			for _, ext := range exts {
				switch ext {
				case "app-id":
					warnings = append(warnings, fmt.Sprintf(
						"flow-monitoring %s template %s: export-extension app-id configured but application data is not available in flow records", kind, name))
				case "flow-dir":
					// #3270: flowDirection (IE 61) is exported again, derived in
					// Go from the per-zone sampling-direction. It is only
					// meaningful when at least one zone has `sampling input` or
					// `sampling output`; otherwise every record reports 0.
					if !hasSampling {
						warnings = append(warnings, fmt.Sprintf(
							"flow-monitoring %s template %s: export-extension flow-dir configured but no interface has sampling input/output; flowDirection will always be 0 (ingress)", kind, name))
					}
				}
			}
		}
		if fm.Version9 != nil {
			for _, tmpl := range fm.Version9.Templates {
				if tmpl == nil { // #3494: tolerant/HA-sync path may carry a nil template
					continue
				}
				checkExtWarning("version9", tmpl.Name, tmpl.ExportExtensions)
			}
		}
		if fm.VersionIPFIX != nil {
			for _, tmpl := range fm.VersionIPFIX.Templates {
				if tmpl == nil { // #3494: tolerant/HA-sync path may carry a nil template
					continue
				}
				checkExtWarning("version-ipfix", tmpl.Name, tmpl.ExportExtensions)
			}
		}
	}

	if cos := cfg.ClassOfService; cos != nil {
		warnedClassifierLossPriority := false
		warnedPriorityLowMinShare := false
		// #4315 (fable-167 F-2): a traffic-control-profile's guaranteed-rate
		// and delay-buffer-rate are typed + stored so garbage is rejected at
		// commit, but the userspace shaper has no per-unit consumer for them
		// (there is no absolute per-unit guaranteed-rate reservation — the
		// #1614 A1 guarantee-rate is a proportional fraction, a distinct
		// mechanism). shaping-rate + scheduler-map ARE enforced (folded into
		// the bound unit). Warn once so an operator who sets guaranteed-rate /
		// delay-buffer-rate is not misled into believing they bound the
		// minimum rate or buffer. Mirrors the #4218/#4220 accepted-but-inert
		// doctrine.
		warnedTCPInert := false
		for _, tcp := range cos.TrafficControlProfiles {
			if tcp == nil {
				continue
			}
			if (tcp.GuaranteedRateBytes > 0 || tcp.DelayBufferRateBytes > 0) && !warnedTCPInert {
				warnings = append(warnings,
					"class-of-service traffic-control-profiles guaranteed-rate / delay-buffer-rate are accepted for compatibility but inert: the userspace dataplane enforces only the profile's shaping-rate and scheduler-map on the bound unit (#4315), so those values have no runtime effect")
				warnedTCPInert = true
			}
		}
		// #4228 Gap 2: a `shaping-rate percent <n>` traffic-control-profile now
		// RESOLVES against the bound interface's configured line rate
		// (resolveCoSTrafficControlProfiles folds the resolved absolute rate
		// into unit.ShapingRateBytes). Warn only per-BINDING for the residual
		// inert case: a percent-only profile bound to an interface with no
		// configured `speed`/`bandwidth`, where the percent could not resolve
		// (unit.ShapingRateBytes stayed 0) and the unit is left unshaped.
		warnShapingPercentInert := func(unit *CoSInterfaceUnit, ifaceName string) {
			if unit == nil || unit.OutputTrafficControlProfile == "" || unit.ShapingRateBytes > 0 {
				return
			}
			tcp := cos.TrafficControlProfiles[unit.OutputTrafficControlProfile]
			if tcp == nil || tcp.ShapingRatePercent <= 0 || tcp.ShapingRateBytes > 0 {
				return
			}
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service traffic-control-profiles %q shaping-rate percent %.4g%% bound on interface %q has no effect: the interface has no configured speed/bandwidth, so xpf cannot resolve the percent against a line rate and the unit is left unshaped (set `interfaces %s speed <rate>` to enable it) (#4228 Gap 2)",
				tcp.Name, tcp.ShapingRatePercent, ifaceName, ifaceName))
		}
		for _, iface := range cos.Interfaces {
			if iface == nil {
				continue
			}
			warnShapingPercentInert(iface.Level, iface.Name)
			for _, unit := range iface.Units {
				warnShapingPercentInert(unit, iface.Name)
			}
		}
		// #4316 (fable-167 F-3b): inet-precedence rewrite and exp rewrite are
		// accepted for Junos compatibility but INERT — the userspace dataplane
		// rewrites on dscp only. Warn once per category so the operator is not
		// misled.
		//
		// #6847 RETRACTED the CLASSIFIER half of this advisory: an
		// inet-precedence classifier bound to a unit is now compiled, published
		// on the wire (cos_inet_precedence_classifier +
		// inet_precedence_classifiers) and enforced by the dataplane
		// (resolve_cos_inet_precedence_classifier_queue_id). Keeping the
		// "inert" warning would be actively wrong. The REWRITE direction below
		// is still inert and its advisory stays.
		if len(cos.INetPrecedenceRewriteRules) > 0 {
			warnings = append(warnings,
				"class-of-service rewrite-rules inet-precedence is accepted for compatibility but inert: the userspace dataplane rewrites dscp on egress only, so IP-precedence rewrite has no runtime effect")
		}
		if len(cos.EXPRewriteRules) > 0 {
			warnings = append(warnings,
				"class-of-service rewrite-rules exp is accepted for compatibility but inert: the userspace dataplane rewrites dscp on egress only, so MPLS EXP rewrite has no runtime effect")
		}
		// #4228 Gap 4: ieee-802.1 (PCP) rewrite-rules are fully modeled and
		// validated but accepted-but-inert — the dataplane rewrites dscp on
		// egress only and does not yet own the 802.1Q tag write. Warn once so an
		// operator who binds one is not misled. The classifier side
		// (classifiers ieee-802.1) IS enforced; only the egress rewrite waits on
		// TX 802.1Q tag ownership.
		if len(cos.IEEE8021RewriteRules) > 0 {
			warnings = append(warnings,
				"class-of-service rewrite-rules ieee-802.1 is accepted for compatibility but inert: the userspace dataplane rewrites dscp on egress only and does not yet own the 802.1Q tag write, so 802.1p PCP rewrite has no runtime effect")
		}
		for _, class := range cos.ForwardingClasses {
			if class == nil {
				continue
			}
			if class.Queue < 0 || class.Queue > 255 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
					class.Name, class.Queue))
			}
		}
		// #4228 Gap 2: schedulers whose transmit-rate percent resolves (bound
		// via a scheduler-map to an interface with a root shaping-rate). Used
		// below to warn only for a percent that has no base to resolve against.
		schedulersResolvingPercent := cosSchedulersWithShapedBinding(cos)
		// #915: surplus-sharing is meaningful only on transmit-rate
		// exact schedulers; warn when set without exact (see #1183
		// lesson). #4966: ValidateConfig is a READ-ONLY pass — it must
		// NOT mutate the config. The "runtime never sees the no-op
		// flag" guarantee is enforced at the compile-to-runtime edge
		// instead: buildClassOfServiceSnapshot gates SurplusSharing on
		// TransmitRateExact, so configured intent is preserved on the
		// active config while the effective (runtime) value is false.
		// Mutating here made validation non-idempotent — a second
		// ValidateConfig saw SurplusSharing already cleared and emitted
		// no warning, so recomputing surfaces (show system alarms)
		// dropped the warning entirely.
		for _, sched := range cos.Schedulers {
			if sched == nil {
				continue
			}
			if sched.SurplusSharing && !sched.TransmitRateExact {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
					sched.Name))
			}
			// #1746: warn-not-strip. A policy without enforcement is a
			// harmless no-op (the dataplane gates it on
			// equal-flow-enforcement), but the operator should know it
			// is inert.
			if sched.EqualFlowTargetPolicy != "" && !sched.EqualFlowEnforcement {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q equal-flow-target-policy %q has no effect without equal-flow-enforcement",
					sched.Name, sched.EqualFlowTargetPolicy))
			}
			// #1746: non-work-conserving cost warning. Clipping fast
			// flows frees capacity that CANNOT reach slow flows on
			// other workers, so these policies trade aggregate
			// throughput for per-flow evenness (see
			// docs/cos-traffic-shaping.md).
			if sched.EqualFlowEnforcement {
				switch sched.EqualFlowTargetPolicy {
				case "slowest", "mean":
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler %q equal-flow-target-policy %s is non-work-conserving: it clips fast flows and reduces aggregate class throughput; it cannot lift slow flows",
						sched.Name, sched.EqualFlowTargetPolicy))
				}
			}
			// #4218: codel-target (#1614 A3 CoDel AQM) is typed and stored
			// (CodelTargetNS) so a garbage value is rejected at commit, but
			// the AQM itself is NOT enforced — #1829 Phase 2 was PLAN-KILLED.
			// Warn so an operator who sets it is not misled into believing it
			// bounds queue latency. Mirrors the accepted-but-inert doctrine
			// used for loss-priority and the #2078/#3440 knobs.
			if sched.CodelTargetNS > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q codel-target is accepted for compatibility but inert: the userspace dataplane has no CoDel AQM (#1829 Phase 2 not shipped), so the configured target has no runtime effect",
					sched.Name))
			}
			// #4228 Gap 2 follow-up: buffer-size temporal <us> is typed + stored
			// (BufferSizeTemporalUS) so garbage is rejected at commit, but the
			// microsecond target is NOT yet resolved to a byte-size by the
			// dataplane (that needs the queue's transmit rate, which itself may
			// be a per-interface percent). Warn so an operator who sets it is not
			// misled into believing the queue buffer is sized. Mirrors the
			// accepted-but-inert doctrine used for codel-target and the percent
			// rate forms.
			if sched.BufferSizeTemporalUS > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q buffer-size temporal is accepted for Junos compatibility but inert: xpf does not yet resolve the microsecond target to a byte-size (it needs the queue's transmit rate), so the queue buffer falls back to the default sizing (#4228 Gap 2)",
					sched.Name))
			}
			// #4228 Gap 2: transmit-rate percent now RESOLVES per-interface —
			// forwarding_build/cos.rs computes the absolute byte/sec rate
			// against the bound interface's shaping-rate (the multi-pass
			// concern is handled by carrying the percent to the dataplane and
			// materializing it per interface). Warn only for the residual inert
			// cases: `remainder` (leftover-bandwidth resolution is still a
			// follow-up) and a `percent` scheduler with no shaping base to
			// resolve against — i.e. not bound via a scheduler-map to an
			// interface that has a root shaping-rate.
			if sched.TransmitRateRemainder {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q transmit-rate remainder is accepted for Junos compatibility but inert: the userspace dataplane consumes an absolute byte/sec rate and xpf does not yet resolve `remainder` against the leftover interface bandwidth, so the queue gets no explicit transmit-rate (#4228 Gap 2)",
					sched.Name))
			} else if sched.TransmitRatePercent > 0 && !schedulersResolvingPercent[sched.Name] {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q transmit-rate percent %.4g%% is accepted but has no effect: the scheduler is not bound via a scheduler-map to an interface with a root shaping-rate, so there is no base to resolve the percent against (#4228 Gap 2)",
					sched.Name, sched.TransmitRatePercent))
			}
		}
		for _, schedMap := range cos.SchedulerMaps {
			if schedMap == nil {
				continue
			}
			for className := range schedMap.Entries {
				if _, ok := cos.ForwardingClasses[className]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined forwarding-class %q",
						schedMap.Name, className))
				}
				// A scheduler-map entry naming an undefined scheduler is no
				// longer warn-only: validateClassOfServiceSchedulerMapRefsStrict
				// hard-rejects it at strict commit / commit-check and downgrades
				// it to a cfg.Warnings entry on the tolerant load / peer-sync
				// paths (#1960). Leaving a parallel warning here would
				// double-report it on the lenient path and duplicates a rule
				// that now lives in one place, consistent with every other
				// cross-reference gate (IPsec proposal, policy zone/scheduler,
				// log-stream, feed-name), none of which warn from ValidateConfig.
			}
		}
		for _, classifier := range cos.DSCPClassifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority now drives egress dscp rewrite-rule selection (#3995) but is not yet enforced for drop-precedence / WRED buffer management")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, classifier := range cos.IEEE8021Classifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service ieee-802.1 classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority now drives egress dscp rewrite-rule selection (#3995) but is not yet enforced for drop-precedence / WRED buffer management")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, rewriteRule := range cos.DSCPRewriteRules {
			if rewriteRule == nil {
				continue
			}
			for _, entry := range rewriteRule.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp rewrite-rule %q references undefined forwarding-class %q",
						rewriteRule.Name, entry.ForwardingClass))
				}
				// #3995: the userspace dataplane now keys the egress DSCP
				// rewrite on (forwarding-class, loss-priority), so a
				// rewrite-rule loss-priority is ENFORCED — no warning.
			}
		}
		// #4228 Gap 4: mirror the undefined-forwarding-class warn for the
		// accepted-but-inert ieee-802.1 (PCP) rewrite-rules.
		for _, rewriteRule := range cos.IEEE8021RewriteRules {
			if rewriteRule == nil {
				continue
			}
			for _, entry := range rewriteRule.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service ieee-802.1 rewrite-rule %q references undefined forwarding-class %q",
						rewriteRule.Name, entry.ForwardingClass))
				}
			}
		}
		// #4220 / #4219: priority-low-min-share (#1614 A2) is typed and
		// stored (PriorityLowMinShareBytes) so garbage is rejected at
		// commit, but the knob is INERT — it is wire-surface-only and no
		// scheduler code consults it (the cap_eff per-pass reservation that
		// would enforce it is deferred research). Warn ONCE (map iteration
		// is randomized; a generic message stays deterministic) so an
		// operator is not misled into believing the priority-low queue has
		// a protected minimum. The enforcement itself is a separate
		// deferred item.
		warnPriorityLowMinShareInert := func(bytes uint64) {
			if bytes > 0 && !warnedPriorityLowMinShare {
				warnings = append(warnings,
					"class-of-service priority-low-min-share is accepted for compatibility but inert: the userspace dataplane does not yet enforce a priority-low minimum share (#1614 A2; the cap_eff reservation is deferred), so the configured value has no runtime effect")
				warnedPriorityLowMinShare = true
			}
		}
		for _, iface := range cos.Interfaces {
			if iface == nil {
				continue
			}
			// #hb166 G-6: a class-of-service binding whose interface (or
			// logical unit) is not configured under [interfaces] commits
			// cleanly but shapes nothing — the dataplane applier only
			// visits CoS bindings inside the cfg.Interfaces iteration, so
			// a typo'd interface name or an unconfigured unit is a silent
			// no-op. Warn (not reject: the interface could be added
			// later) so the operator knows the binding is currently inert.
			ifCfg := cfg.Interfaces.Interfaces[iface.Name]
			if ifCfg == nil {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service interface %s is bound but not configured under [interfaces]; its shaping/classifiers are inert until the interface is configured",
					iface.Name))
			}
			if iface.Level != nil {
				warnPriorityLowMinShareInert(iface.Level.PriorityLowMinShareBytes)
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				if ifCfg != nil {
					if _, ok := ifCfg.Units[unit.Unit]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d is bound but unit %d is not configured under [interfaces %s]; its shaping/classifiers are inert",
							iface.Name, unit.Unit, unit.Unit, iface.Name))
					}
				}
				warnPriorityLowMinShareInert(unit.PriorityLowMinShareBytes)
				if unit.SchedulerMap != "" {
					if _, ok := cos.SchedulerMaps[unit.SchedulerMap]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined scheduler-map %q",
							iface.Name, unit.Unit, unit.SchedulerMap))
					}
				}
				// #4315 (fable-167 F-2): a dangling output-traffic-control-profile
				// reference resolves to no shaper — the binding shapes nothing.
				// Warn so the operator sees the inert binding rather than a silent
				// zero-shaping commit.
				if unit.OutputTrafficControlProfile != "" {
					if _, ok := cos.TrafficControlProfiles[unit.OutputTrafficControlProfile]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined output-traffic-control-profile %q; the unit is not shaped",
							iface.Name, unit.Unit, unit.OutputTrafficControlProfile))
					}
				}
				if unit.DSCPClassifier != "" {
					if _, ok := cos.DSCPClassifiers[unit.DSCPClassifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp classifier %q",
							iface.Name, unit.Unit, unit.DSCPClassifier))
					}
				}
				if unit.IEEE8021Classifier != "" {
					if _, ok := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined ieee-802.1 classifier %q",
							iface.Name, unit.Unit, unit.IEEE8021Classifier))
					}
				}
				if unit.DSCPRewriteRule != "" {
					if _, ok := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp rewrite-rule %q",
							iface.Name, unit.Unit, unit.DSCPRewriteRule))
					}
				}
				// #4228 Gap 4: a dangling ieee-802.1 (PCP) rewrite-rule binding.
				if unit.IEEE8021RewriteRule != "" {
					if _, ok := cos.IEEE8021RewriteRules[unit.IEEE8021RewriteRule]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined ieee-802.1 rewrite-rule %q",
							iface.Name, unit.Unit, unit.IEEE8021RewriteRule))
					}
				}
				// #hb166 T-4: a behavior-aggregate classifier code-point that
				// maps to a forwarding-class whose queue is NOT materialized on
				// this interface (no scheduler-map entry) is a silent blackhole
				// in the pre-fix dataplane. It is now fail-SAFE (the userspace
				// helper forwards such traffic on the best-effort queue,
				// forwarding_build/cos.rs), but the operator should still see
				// that the intended queue does not exist on this interface.
				// WARN, not reject: unlike the dangling-SCHEDULER case
				// (validateClassOfServiceSchedulerMapRefsStrict), a classifier
				// steering to a forwarding-class that simply lacks a
				// scheduler-map entry is a valid Junos config (queues exist by
				// default there), so a strict reject would refuse configs Junos
				// accepts.
				warnings = append(warnings,
					classOfServiceClassifierQueueWarnings(cos, iface.Name, unit)...)
			}
		}
		hasCoSRuntimeConfig := len(cos.Interfaces) > 0 ||
			len(cos.DSCPClassifiers) > 0 ||
			len(cos.IEEE8021Classifiers) > 0 ||
			len(cos.DSCPRewriteRules) > 0
		if hasCoSRuntimeConfig && effectiveDataplaneType(cfg.System.DataplaneType) != dataplaneTypeUserspace {
			warnings = append(warnings, "class-of-service shaping, classifier attachment, and dscp rewrite-rule attachment are only implemented in the userspace dataplane; configuration is accepted but will not take effect on this dataplane")
		}

		// #1614 A4: operator-visible warning when the sum of an
		// interface unit's exact-class transmit-rates exceeds the
		// unit's shaping-rate. Under oversubscription, every class
		// will receive less than its configured rate; the visible
		// distribution depends on the unit's oversubscription-policy.
		warnings = append(warnings, validateCoSOversubscriptionWarnings(cos)...)
	}

	// #1706 / #5854: the next-table and rib-group ip-rule reconcilers program
	// into fixed priority windows (100 next-table, 1000 rib-group) that their
	// clear() passes scan; the applier hard-caps at the window boundary so
	// out-of-range rules never leak, but a config that exceeds a window would be
	// silently truncated at apply time (routes claimed but not programmed). This
	// over-subscription is now a STRICT COMMIT REJECTION
	// (validateRoutingRuleWindowsStrict, runUniformGates) rather than a warning:
	// the strict commit / commit-check path hard-rejects it, and the tolerant
	// load / peer-sync paths downgrade it to a single cfg.Warnings entry
	// (opts.lenientRoutingRuleWindows), so it is no longer surfaced here (a
	// second warning here would double-report it on the tolerant path).

	// #3876: warn when an interface-routes rib-group import cannot be fully
	// realized by the Phase-1 per-prefix leak (no enumerable static connected
	// prefix, or a VRF→VRF import target that Phase 1 does not install) so the
	// operator sees a fail-loud diagnostic rather than a silent no-op.
	warnings = append(warnings, validateRibGroupLeakWarnings(cfg)...)

	// #1387: DHCP dynamic-DNS live-backend validation. Increment 2 wired the
	// live RFC 2136 backend, so the increment-1 "no records are published"
	// deferred-backend warning is retired. The warnings here flag a config
	// that the now-live path cannot act on (enabled rfc2136 with no
	// update-server), a still-deferred backend (kea-d2), and the now-consumed
	// free-form leaves (update-server parseability, TSIG algorithm support).
	// All are WARN-only (never an error) so a malformed inert value committed
	// against increment 1 cannot brick a boot (plan §4.5 / §7 Q-C).
	warnings = append(warnings, validateDDNSBackendWarnings(cfg)...)

	// #2691 P2: warn on a per-interface Surface A `dynamic-dns` binding that
	// references a missing/incomplete provider or omits a hostname, and on a
	// `system services dynamic-dns provider` whose rfc2136 backend is unusable.
	// WARN-only (never a hard reject) — a previously-inert misconfig must not
	// brick a boot; the runtime degrades to a logged no-op for that scope.
	warnings = append(warnings, validateSurfaceADDNSWarnings(cfg)...)

	// #2507: firewall-filter `then loss-priority <low|...|high>` is parsed and
	// stored on the term (FirewallFilterTerm.LossPriority) but is never wired
	// onto the wire (no FirewallTermSnapshot field) and the userspace dataplane
	// has no per-packet loss-priority consumer — the three-color policer always
	// meters at PacketColor::Green and color-aware mode stays fail-closed until
	// inherited packet color is carried through trusted metadata (see
	// userspace-dp/src/filter/README.md). So the action commits and silently
	// does nothing. Mirror the CoS classifier/rewrite loss-priority warning
	// above: WARN-only (loss-priority is valid Junos — never fail the commit),
	// once per filter/term, naming the filter and term so the operator knows
	// the QoS action is inert. Same principle as #2486 (ipsec-vpn): never
	// silently accept config the dataplane cannot enforce.
	warnings = append(warnings, validateFilterLossPriorityWarnings(cfg)...)

	// #4316 (fable-167 F-3a): `firewall filter <n> interface-specific` is
	// accepted but xpf keeps a single shared counter (not per-interface
	// instances). WARN so the operator knows `show firewall` aggregates.
	warnings = append(warnings, validateFirewallInterfaceSpecificWarnings(cfg)...)

	// #3445: an lo0 INPUT filter is mirrored onto a kernel nftables chain
	// (the PRIMARY enforcement for host-bound traffic the XDP shim shunts to the
	// kernel). That chain honors match predicates + `then log` + `then count`
	// but cannot faithfully honor the CoS / rate-control `then` modifiers
	// (policer, dscp-rewrite, forwarding-class). Warn — naming each term+modifier
	// — rather than silently dropping them from the kernel mirror. loss-priority
	// is already covered by validateFilterLossPriorityWarnings above.
	warnings = append(warnings, validateLo0FilterKernelMirrorWarnings(cfg)...)

	// #3295: a firewall filter attached to an interface/lo0 input/output hook
	// with no terminal catch-all term relies on xpf's implicit-accept of
	// unmatched traffic — the deliberate divergence from Junos's implicit final
	// discard. WARN-only: surface the divergence (and the explicit-final-term
	// workaround) without changing the runtime default, which would blackhole
	// the classify-and-pass output-filter idiom ("keep GOOD", #2124/#3261). See
	// docs/research/3295-filter-failopen/plan.md and
	// userspace-dp/src/filter/README.md.
	warnings = append(warnings, validateFilterNoCatchAllWarnings(cfg)...)

	// #2509: `security pre-id-default-policy then log session-init/session-close`
	// is parsed and stored on PreIDDefaultPolicy.LogSessionInit/LogSessionClose
	// but has NO consumer in the userspace dataplane after the eBPF retirement
	// (#1373/#1476). The only reader was the retired eBPF compiler
	// (pkg/dataplane/compiler.go, which mapped the bits to FlowConfigValue.
	// AppFlags). The userspace runtime has no pre-identification session-admit
	// path: app-id is best-effort labeling of already-admitted sessions, not a
	// "default policy admits the session before app-id resolves, then
	// re-evaluate" pipeline, so there is no session to stamp the pre-id log
	// mode onto (unlike the per-policy #2508 path, which stamps the admitting
	// policy's log flags at install). The stanza therefore commits and is
	// silently inert. Mirror the #2507 filter loss-priority / CoS
	// loss-priority warnings: WARN-only (pre-id-default-policy is valid Junos —
	// never fail the commit; a hard reject would brick a boot on a
	// previously-inert committed value), naming the inert action so the
	// operator knows the logging signal is not produced.
	warnings = append(warnings, validatePreIDDefaultPolicyLogWarnings(cfg)...)

	// #3534: `security policies default-policy-log session-init/session-close`
	// emits RT_FLOW session logs for the implicit default-policy verdict, but
	// only a default-PERMIT verdict installs a session for those records to fire
	// on. A default-DENY/REJECT verdict installs no session and is already logged
	// unconditionally via the policy-deny RT_FLOW record, so the session-init/
	// session-close flags are inert there. WARN-only (the stanza is valid and
	// must not brick a previously-committed config).
	warnings = append(warnings, validateDefaultPolicyLogWarnings(cfg)...)

	// #4373 (avo-review-007 E1): the per-policy analog of the default-policy log
	// advisory above. A NAMED or GLOBAL policy with `then deny`/`then reject` plus
	// `then log session-init`/`session-close` installs no session, so the RT_FLOW
	// SESSION_CREATE/CLOSE record never fires — an operator who adds `then reject;
	// then log session-close` expecting a close record is confused when none
	// appears. The deny is logged unconditionally via the policy-deny RT_FLOW
	// record instead. WARN-only (valid Junos; must not brick a committed config).
	warnings = append(warnings, validatePolicyLogInertOnDenyWarnings(cfg)...)

	// #4146 (H-1 slice c): warn when a `to-zone junos-host` policy expresses a
	// constraint STRICTER than the coarse kernel host-inbound gate can enforce
	// on the DIRECT host-bound path. Ordinary traffic to a firewall interface
	// IP is delivered by the Linux kernel — the XDP shim shunts local-destined
	// packets to the kernel on a session miss (userspace-xdp/src/lib.rs
	// is_local_destination) — and the nft xpf_hostinbound chain admits
	// configured system-services from ANY source with no per-source /
	// per-application deny. The fine junos-host restriction is enforced only on
	// the userspace AF_XDP LocalDelivery path (e.g. DNAT/static-NAT to a
	// firewall-local address), which the direct host-bound packet never
	// reaches, so a configured deny (or source-scoped permit) is silently
	// unenforced there — a false sense of security. WARN-only: the config is
	// legal Junos and the enforcement decision (a/b) is PLAN-DEFERRED
	// (availability-vs-security tradeoff). See docs/host-inbound-service-
	// matrix.md "to-zone junos-host and the direct host-bound path".
	warnings = append(warnings, validateJunosHostDirectDeliveryWarnings(cfg)...)

	// #4308 (fable-review-167 I-3): interface parity knobs that are typed +
	// compiled so they stop silently vanishing, but are ACCEPTED-ONLY today.
	warnings = append(warnings, validateInterfaceParityWarnings(cfg)...)

	// #4788 + #4785 half 1: `tunnel mode ipip` is now HARD-REJECTED at commit
	// (validateIpipTunnelUnimplementedStrict, compiler_tailgates.go), but the
	// advisory MUST stay registered here. The alarm surfaces — `show system
	// alarms` in the CLI and gRPC, plus the two security-alarm views —
	// RECOMPUTE ValidateConfig from the ACTIVE config rather than reading
	// cfg.Warnings, so removing it left a box already carrying a dead tunnel
	// (committed by an older build, loaded leniently per #1960) reporting "No
	// alarms currently active". The strict gate covers the next commit; this
	// covers the config already on disk.
	warnings = append(warnings, validateIpipTunnelDeadWarning(cfg)...)

	// #4309 (fable-review-167 I-4): DHCP relay overrides accepted-only advisory.
	warnings = append(warnings, validateDHCPRelayParityWarnings(cfg)...)

	// #4455 (HI-1): a zone that admits a multicast routing protocol relies on the
	// kernel input-chain `policy accept` fall-through to deliver that protocol's
	// host-bound multicast PACKET-WIDE (not scoped to the zone's ingress
	// interface). Surface that Junos-parity/hardening gap at commit; the per-zone
	// iifname enforcement remains deferred.
	warnings = append(warnings, validateHostInboundMulticastWarnings(cfg)...)
	warnings = append(warnings, validateHostInboundManagedRoutingMismatch(cfg)...)

	// #5837 (Track-1 mitigation): a destination-NAT / static-NAT rule whose
	// public (matched / external) destination address equals a configured
	// interface address is INERT on the first packet — the userspace AF_XDP shim
	// classifies a firewall-local destination as kernel-local and shunts it to the
	// host BEFORE consulting DNAT/static-NAT (is_local_destination runs before
	// pre_routing_dnat). Today that bypass is SILENT; this advisory makes it LOUD,
	// naming the rule + the colliding interface address. WARN-only on both compile
	// paths (valid Junos; works for reply/established traffic; the full dataplane
	// fix is NOT planned — Track-2 was #6051, plan-killed). See
	// docs/nat-destination.md and the preserved plan
	// docs/research/5837-xdp-dnat-before-local/plan.md §0a on branch
	// research/5837-xdp-dnat-before-local.
	warnings = append(warnings, validateNATInterfaceAddressCollisionWarnings(cfg)...)

	return warnings
}

// schedulerHasEffectiveWindow reports whether a compiled scheduler carries any
// window the runtime evaluator (pkg/scheduler.isWithinWindow) can act on: a
// daily/weekday time-of-day arm, an all-day flag, or a start/stop calendar
// range. A scheduler with none of these resolves to fail-closed INACTIVE at
// runtime (#3849/#3858) — ValidateConfig warns on it (#3860). The predicate
// mirrors pkg/scheduler.schedulerHasTimeWindow || schedulerHasDateRange; a
// bare `daily;` or an empty `scheduler x {}` leaves every field zero and
// therefore has no effective window.
func schedulerHasEffectiveWindow(s *SchedulerConfig) bool {
	if s == nil {
		return false
	}
	if s.AllDay || s.StartTime != "" || s.StopTime != "" || len(s.Days) > 0 {
		return true
	}
	if s.StartDate != "" || s.StopDate != "" {
		return true
	}
	return false
}

// anySamplingDirectionConfigured reports whether any interface unit has
// sampling input or output enabled (#3270). It mirrors what
// flowexport.BuildSamplingZones consumes per zone: flow-dir derivation reads
// the per-zone sampling-direction, which is empty when no unit sets either
// flag, in which case the exported flowDirection is a constant 0.
func anySamplingDirectionConfigured(cfg *Config) bool {
	for _, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for _, unit := range iface.Units {
			if unit == nil {
				continue
			}
			if unit.SamplingInput || unit.SamplingOutput {
				return true
			}
		}
	}
	return false
}
