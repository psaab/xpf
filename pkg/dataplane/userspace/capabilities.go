package userspace

import (
	"net"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

func deriveUserspaceConfig(cfg *config.Config) config.UserspaceConfig {
	// #9003: the defaults live under DefaultRuntimeDir (/run/xpf), NOT under
	// os.TempDir(). The previous defaults put the control socket — which carries
	// the WireGuard local private key and every preshared key in cleartext — in
	// a subdirectory of world-writable /tmp that xpfd creates with
	// os.MkdirAll(..., 0755), an operation that silently ADOPTS a pre-existing
	// directory of any owner. A local user who won the race to
	// `mkdir /tmp/xpf-userspace-dp` therefore owned the directory the root
	// helper bound inside. /run is root-owned 0755 on every systemd distro, so
	// the same subdirectory cannot be pre-created there.
	//
	// These spellings match the shipped reference configs
	// (docs/ha-cluster-userspace.conf, docs/ha-cluster-loss.conf), so a
	// deployment that OMITS the leaves now lands where one that sets them
	// already lands.
	out := config.UserspaceConfig{
		Workers:       1,
		RingEntries:   1024,
		ControlSocket: DefaultControlSocket,
		StateFile:     DefaultStateFile,
	}
	if cfg != nil && cfg.System.UserspaceDataplane != nil {
		// SHALLOW copy of a struct reached from the shared active config. Safe
		// ONLY because every field written below (Workers, RingEntries,
		// ControlSocket, StateFile, EventSocket) is a SCALAR — the one reference
		// field, SharedUMEM *SharedUMEMConfig, is carried along and never
		// written. Writing through a reference field here would land on the
		// daemon's live committed config, which is the #9141 defect
		// (resolveDHCPRethInterfaces rewrote a group's Interfaces slice through
		// exactly this kind of "copy"). Adding a write to a pointer/map/slice
		// field means deep-copying it first.
		out = *cfg.System.UserspaceDataplane
	}
	if out.Workers <= 0 {
		out.Workers = 1
	}
	if out.RingEntries <= 0 {
		out.RingEntries = 1024
	}
	if out.ControlSocket == "" {
		out.ControlSocket = DefaultControlSocket
	}
	if out.StateFile == "" {
		out.StateFile = filepath.Join(filepath.Dir(out.ControlSocket), "state.json")
	}
	if out.EventSocket == "" {
		out.EventSocket = filepath.Join(filepath.Dir(out.ControlSocket), "userspace-dp-events.sock")
	}
	return out
}

func deriveUserspaceCapabilities(cfg *config.Config) UserspaceCapabilities {
	caps := UserspaceCapabilities{ForwardingSupported: true}
	if cfg == nil {
		return caps
	}
	addReason := func(reason string) {
		caps.ForwardingSupported = false
		caps.UnsupportedReasons = append(caps.UnsupportedReasons, reason)
	}
	// #3261: this function reports ONLY class (ii) — genuinely-unsupported
	// dataplane SEMANTICS with no fail-closed snapshot representation (screen
	// SYN-cookie material, color-aware 3-color policers, persistent SNAT under
	// HA). These set ForwardingSupported=false and legitimately disarm.
	//
	// Class (i) — unrepresentable policy CONTENT (a policy naming an application
	// protocol/port or address the matcher cannot represent) is NOT decided
	// here. It must NOT disarm: buildOneRuleSnapshot emits a reserved sentinel
	// (the __unsupported__ application term or the __unsupported_address__
	// literal) and the helper's non-mutating integrity preflight rejects the
	// WHOLE snapshot while staying armed (previous-good retained; fresh boot =
	// default-deny). Crucially, class (i) is feed-aware: a dynamic-address feed
	// name resolves only through the snapshot's overlay (#2049), which this
	// cfg-only gate cannot see. Deriving it here would FALSE-POSITIVE on every
	// healthy feed policy. So the snapshot builder computes PolicyContentRejected
	// from the ACTUAL built rules' sentinels (collectPolicyContentRejections),
	// and that snapshot value — not this gate — drives both the diagnostic and
	// the narrow old-helper disarm.
	//
	// CLASS (ii):
	// Pool-mode source NAT is now implemented in the userspace dataplane
	// (PortAllocator with round-robin address + port allocation).
	// NAT64 is supported — NATv6v4 config (no-v6-frag-header option) is fine
	// Session timeouts (TCP/UDP/ICMP) are supported — only gate on unsupported flow features
	// TCP MSS clamping is supported in the userspace dataplane
	// GRE acceleration (key extraction into session ports) is supported
	if !userspaceSupportsScreenProfiles(cfg) {
		addReason(
			"userspace SYN-cookie screen profiles require system root-authentication encrypted-password material",
		)
	}
	if !userspaceSupportsThreeColorPolicers(cfg) {
		addReason("userspace three-color policers require color-blind mode and then discard")
	}
	// #8573: the persistent-NAT / chassis-cluster DISARM IS GONE, and the
	// sentence it reported — "userspace persistent-nat source pool leases are
	// not HA-synchronized" — was false when it was removed.
	//
	// Every persistent lease an active node holds now reaches a standby by one
	// of three routes: rebuilt from synced sessions for port-translating leases
	// (#7360) and address-only ones (#8132), and exported/imported over the
	// cluster sync for idle leases (#8121). That the three are EXHAUSTIVE is
	// bound by every_persistent_lease_creation_site_has_a_sync_route_8121
	// (#8572), which reds if a sixth insert site appears unclassified.
	//
	// MEASURED ON THE LOSS USERSPACE CLUSTER before removal, which is the run
	// #1449 made impossible and #8573 was filed to unblock — the gate disarmed
	// the forwarding its own verification needed. With the disarm lifted and a
	// rule-referenced persistent-nat pool committed on both nodes:
	//
	//   - both nodes armed (FWDD State Online), pool SNAT translating into the
	//     configured 30000-30999 window;
	//   - a lease created on the active appeared on the STANDBY with an
	//     identical source, translated identity and pool;
	//   - it survived a manual RG0 failover, present on both nodes after;
	//   - and — the part that matters — after a failback the new active
	//     translated the SAME source identity (10.0.61.241:51000) to the SAME
	//     translated identity (172.16.80.7:30003) that the OTHER node had
	//     allocated. The imported lease was HONOURED, not merely listed, which
	//     is the whole of what persistent NAT promises a subscriber.
	//
	// THE KNOWN RESIDUALS ARE NOT FORWARDING HAZARDS. There are two, and both
	// mean "this particular lease did not reach the standby", never "the
	// standby forwards with semantics it cannot honour":
	//
	//   1. THE SYNC WINDOW. A lease created on the active in the interval
	//      before the next export/import cycle is not on the standby yet, so a
	//      failover inside that window gives the flow a fresh translated
	//      identity instead of its pinned one. That is the window every other
	//      synced object lives in, and it is a far narrower statement than
	//      "leases are not HA-synchronized".
	//
	//   2. A REFUSED IMPORT. A lease whose pool address the standby's config
	//      lacks, whose port bit is already held, or that arrived expired, is
	//      refused by design (#8121). Each refusal is correct — the standby
	//      mints its own translation rather than install a duplicate or a
	//      wrong translated identity.
	//
	// The operator surface for both is per-node and comparative: the per-batch
	// journald line the helper emits naming the refusal classes (#8573 widened
	// its trigger to include skipped_unknown_address, which is the config-
	// divergence class and used to log nothing at all), plus `show security nat
	// source persistent-nat-table` on each node, which #8607 made non-empty and
	// which is the surface the measurement above is built out of. None of that
	// existed when this gate was written; disarming the whole dataplane was
	// standing in for observability that now exists.
	// Firewall filters are supported in the userspace dataplane. Legacy
	// single-rate `firewall policer` token buckets are ENFORCED as of #4514:
	// a `then discard` policer is lowered at compile into the metered
	// three-color srTCM runtime (committed bucket == the token bucket,
	// CIR=bandwidth-limit, CBS=burst-size-limit) so traffic above the rate is
	// discarded, with metering + drop counters + flow-cache re-metering. A
	// single-rate policer with a non-discard action (`then loss-priority` /
	// `then forwarding-class`) is metered but the marking is not yet acted
	// upon (same limitation as three-color `then loss-priority`). Three-color
	// policers are supported for the color-blind `then discard` runtime slice
	// above; unsupported color-aware and non-drop actions remain fail-closed
	// so the dataplane does not silently promote inherited color or ignore
	// configured treatment.
	// IPsec: kernel XFRM handles ESP encryption/decryption; the userspace
	// dataplane passes ESP/IKE traffic to the kernel via the slow-path.
	// GRE transit is now modeled as native userspace tunnel endpoints on the
	// physical NIC path. Kernel tunnel interfaces remain only for host/control
	// plane compatibility during migration.
	// Port mirroring is supported by the userspace dataplane through the
	// bounded mirror-clone runtime: snapshot mirror configs, per-binding
	// sampling, full-L2 clone delivery, lossy pressure handling, and status
	// counters are all owned by userspace-dp.
	// Flow export (NetFlow v9) is now supported in the userspace dataplane.
	//
	// #7409 — DELIBERATELY NOT A REASON: "a dynamic routing protocol is
	// configured". #7409's acceptance criterion offered a choice between
	// importing kernel-learned routes into the helper FIB and refusing to arm
	// when a routing protocol is configured. The import shipped; the arm-gate
	// was rejected, and the reasoning is recorded here because the gate reads
	// like the conservative option and will otherwise be re-proposed.
	//
	//  1. Keyed on protocols it closes NOTHING. The exposure is a learned
	//     route in a reinject-reachable kernel table, and a DHCP lease on a
	//     non-management interface produces exactly that with no protocol
	//     stanza at all (pkg/frr renders the AD-200 default and its RFC 3442
	//     classless routes through staticd). Measured across every config
	//     checked into this repo: ZERO configure BGP/OSPF/IS-IS/RIP, while
	//     examples/deploy/standalone.conf and test/incus/xpf-internet-test.conf
	//     hit the DHCP vector today.
	//  2. Extended to DHCP to make it sound, it BRICKS the fleet. 20 of 23
	//     shipped configs carry `family inet { dhcp; }`, including all three
	//     docs/ha-cluster*.conf — the smoke and failover substrate — plus both
	//     customer examples and the day-0 image fixture. And a refused arm is
	//     not graceful degradation to kernel forwarding: the #5275 transit gate
	//     drives ip_forward to 0 on every path landing in setDataplane(nil), so
	//     such a box forwards NOTHING. That trades a policy bypass for a
	//     guaranteed total outage.
	//  3. It is unsound in PRINCIPLE. pkg/frr writeManagedSection preserves
	//     operator content outside the managed markers verbatim, and nothing in
	//     this repo controls /etc/frr/daemons, so a hand-written `router bgp`
	//     installs main-table routes that cfg.Protocols cannot see. A
	//     config-keyed gate can never be sound about what FRR actually runs.
	return caps
}

// userspaceConfigUsesPersistentSourceNAT delegates to config.
//
// #8447: the body moved to pkg/config so the COMMIT-TIME ADVISORY and this
// CAPABILITY GATE read one predicate. They must agree by construction: an
// advisory that stops firing for a config that still disarms forwarding is
// silence that reads exactly like safety, and this gate stopping traffic
// without the advisory is the defect #8447 was filed for.
//
// Kept as a named wrapper rather than inlining the call, because the gate's
// own comments and tests refer to it by this name and the indirection is free.
func userspaceConfigUsesPersistentSourceNAT(cfg *config.Config) bool {
	return config.UsesPersistentSourceNATPool(cfg)
}

func userspaceSupportsThreeColorPolicers(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	for _, pol := range cfg.Firewall.ThreeColorPolicers {
		if pol == nil {
			continue
		}
		if !pol.ColorBlind {
			return false
		}
		if pol.ThenAction != "" && pol.ThenAction != "discard" {
			return false
		}
	}
	return true
}

func expandUserspacePolicyAddresses(cfg *config.Config, addrs []string) ([]string, bool) {
	if len(addrs) == 0 {
		return nil, true
	}
	expanded := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	addUnique := func(value string) {
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		expanded = append(expanded, value)
	}
	for _, addr := range addrs {
		switch {
		case addr == "" || addr == "any":
			addUnique("any")
		case config.IsPolicyAddressWildcardKeyword(addr):
			// #9574: a family keyword, which the compiled config now keeps, goes
			// on the legacy wire as its CIDR exactly as it did before the rewrite
			// moved out of compilePolicy.
			addUnique(config.PolicyAddressKeywordLiteral(addr))
		case isUserspaceLiteralAddress(addr):
			addUnique(normalizeUserspaceLiteralAddress(addr))
		default:
			values, ok := resolveUserspaceAddressBookEntry(cfg, addr)
			if !ok || len(values) == 0 {
				return nil, false
			}
			for _, value := range values {
				if value == "" {
					return nil, false
				}
				if !isUserspaceLiteralAddress(value) {
					return nil, false
				}
				addUnique(normalizeUserspaceLiteralAddress(value))
			}
		}
	}
	sort.Strings(expanded)
	return expanded, true
}

func isUserspaceLiteralAddress(value string) bool {
	if value == "" || value == "any" {
		return true
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	return net.ParseIP(value) != nil
}

func normalizeUserspaceLiteralAddress(value string) string {
	if value == "" || value == "any" {
		return value
	}
	if _, ipNet, err := net.ParseCIDR(value); err == nil && ipNet != nil {
		return ipNet.String()
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func resolveUserspaceAddressBookEntry(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || cfg.Security.AddressBook == nil || name == "" {
		return nil, false
	}
	addressBook := cfg.Security.AddressBook
	seenSets := make(map[string]bool)
	expanded := make([]string, 0, 4)
	var resolve func(string) bool
	resolve = func(ref string) bool {
		if ref == "" {
			return false
		}
		if addr := addressBook.Addresses[ref]; addr != nil {
			if addr.Value == "" {
				return false
			}
			expanded = append(expanded, addr.Value)
			return true
		}
		set := addressBook.AddressSets[ref]
		if set == nil {
			return false
		}
		if seenSets[ref] {
			return true
		}
		seenSets[ref] = true
		resolvedAny := false
		for _, member := range set.Addresses {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		for _, member := range set.AddressSets {
			if !resolve(member) {
				return false
			}
			resolvedAny = true
		}
		return resolvedAny
	}
	if !resolve(name) {
		return nil, false
	}
	sort.Strings(expanded)
	expanded = slices.Compact(expanded)
	return expanded, true
}

func expandUserspacePolicyApplications(cfg *config.Config, apps []string) ([]PolicyApplicationSnapshot, bool) {
	if len(apps) == 0 {
		return nil, true
	}
	expanded := make([]PolicyApplicationSnapshot, 0, len(apps))
	seen := make(map[string]struct{}, len(apps))
	for _, appName := range apps {
		if appName == "" || appName == "any" {
			return nil, true
		}
		resolved, ok := resolveUserspaceApplicationNames(cfg, appName)
		if !ok || len(resolved) == 0 {
			return nil, false
		}
		// #9525: an application the tolerant compile could only WARN about may
		// still resolve and parse here while matching something other than
		// what was authored (a port on a protocol with no L4 ports, a dropped
		// icmp-type, a dangling or conflicting match leaf, a discarded direct
		// body). Refuse the reference so the policy lowers to the #3261
		// __unsupported__ sentinel instead of installing that term. The set of
		// drops, and what is deliberately left out, is documented on
		// config.ApplicationReferenceMatchDrops.
		if len(config.ApplicationReferenceMatchDrops(appName, &cfg.Applications)) > 0 {
			return nil, false
		}
		for _, resolvedName := range resolved {
			app, ok := config.ResolveApplication(resolvedName, cfg.Applications.Applications)
			if !ok || app == nil {
				return nil, false
			}
			proto := normalizeUserspaceApplicationProtocol(app.Protocol)
			if proto == "" {
				return nil, false
			}
			// #2124: fail closed on any protocol the Rust matcher cannot
			// represent. Returning ok=false makes buildOneRuleSnapshot emit
			// the reserved __unsupported__ sentinel term so the helper
			// integrity preflight rejects the whole snapshot (#3261). Without
			// this a named protocol like esp/ah/sctp (accepted at commit, only
			// lowercased here) reaches the matcher, gets dropped, and the rule
			// collapses to match-any — permitting ALL traffic for the zone
			// pair.
			num, ok := appid.ProtocolNumber(proto)
			if !ok {
				return nil, false
			}
			// Canonicalize to the IANA number any protocol token the Rust
			// matcher could NOT parse before this fix — i.e. anything
			// `rustParsedProtocolBeforeFix` returns false for. In practice that
			// is the newly-supported named set (esp/ah/sctp/vrrp/igmp/pim/egp),
			// but it also covers any other appid-resolvable token outside the
			// pre-fix set (e.g. a junos-* alias such as junos-ospf, were one to
			// reach this path) so a mixed-version helper that predates the new
			// parse_protocol arms still parses it. Tokens the matcher has always
			// understood (tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric) are
			// left as-is to avoid churning the wire form (and the snapshot hash)
			// for every existing policy.
			if !rustParsedProtocolBeforeFix(proto) {
				proto = strconv.Itoa(int(num))
			}
			// #2124: ports must parse the way the Rust parse_port_spec does;
			// a malformed port would otherwise drop the term and collapse the
			// rule to match-any (the same fail-open as the protocol case).
			if !userspacePortSpecRepresentable(app.SourcePort) ||
				!userspacePortSpecRepresentable(app.DestinationPort) {
				return nil, false
			}
			snap := PolicyApplicationSnapshot{
				Name:            resolvedName,
				Protocol:        proto,
				SourcePort:      app.SourcePort,
				DestinationPort: app.DestinationPort,
				// #3020: carry the optional ICMP/ICMPv6 type/code constraint so
				// the Rust matcher enforces junos-ping == echo-request only,
				// rather than matching every ICMP type like junos-icmp-all.
				// nil stays nil (the all-ICMP aliases remain unconstrained).
				ICMPType: app.ICMPType,
				ICMPCode: app.ICMPCode,
				// #3227: carry the per-application inactivity (idle) timeout so
				// the userspace session GC ages a flow admitted by this app out
				// on the app's timeout, not the global per-protocol timeout
				// (the legacy eBPF maps wired this `appTimeout`; closing the
				// userspace parity regression). 0 = use the global timeout
				// (back-compat, byte-identical). A negative configured value is
				// impossible (the parser stores a non-negative int), but clamp
				// defensively so a stray value can never wrap the u32.
				InactivityTimeout: clampNonNegU32(app.InactivityTimeout),
			}
			key := strings.Join([]string{snap.Name, snap.Protocol, snap.SourcePort, snap.DestinationPort,
				icmpKeyPart(snap.ICMPType), icmpKeyPart(snap.ICMPCode),
				strconv.FormatUint(uint64(snap.InactivityTimeout), 10)}, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, snap)
		}
	}
	// #3298: emit the application terms in CONFIG order — the order the apps
	// appear in the policy `match application` list, and within an
	// application-set the order its members are configured (ExpandApplicationSet
	// preserves member order; resolveUserspaceApplicationNames no longer sorts).
	// The Rust matcher resolves an overlapping per-application inactivity-timeout
	// first-writer-wins on the exact port (policy.rs `exact_dst_ports.or_insert`,
	// #3227), so the emit order decides which timeout wins. #3346: the matcher
	// now also honors this emit order ACROSS application classes — it stamps each
	// term with its config-order index and the FIRST listed matching term wins
	// (Junos first-term-wins), so an exact-port term no longer beats a range or
	// icmp-constrained term listed earlier. This emit order is therefore the
	// cross-class precedence contract, not just the within-exact-class one.
	// Sorting by Name here
	// made that precedence alphabetical — contradicting #3227's
	// first-writer-wins-by-config-order contract and Junos/operator intent (two
	// overlapping apps would resolve to the timeout of whichever name sorts
	// first, not whichever the operator listed first). Config order is identical
	// on both HA peers (they compile the same config), so emission stays
	// deterministic across peers without the lexical sort. Term-level dedup is
	// the order-independent `seen` map above, so dropping the sort does not
	// re-introduce duplicate terms.
	return expanded, true
}

// icmpKeyPart renders an optional ICMP type/code constraint as a stable string
// for snapshot-term dedup + deterministic ordering (#3020). A nil constraint
// (match-all) sorts before any concrete value so it is distinct from type/code
// 0 (the "" vs "0" distinction the dedup key relies on).
func icmpKeyPart(v *uint8) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(int(*v))
}

// clampNonNegU32 converts a configured seconds value to the wire u32. A value
// <= 0 means "use the global per-protocol timeout" (the back-compat sentinel),
// so it maps to 0; a positive value passes through, saturating at the u32 max
// so a pathological config can never wrap. #3227.
func clampNonNegU32(v int) uint32 {
	if v <= 0 {
		return 0
	}
	if v > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

func resolveUserspaceApplicationNames(cfg *config.Config, name string) ([]string, bool) {
	if cfg == nil || name == "" {
		return nil, false
	}
	if _, ok := config.ResolveApplication(name, cfg.Applications.Applications); ok {
		return []string{name}, true
	}
	if _, ok := config.ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
		// #3298: ExpandApplicationSet already dedups (its `seen` map) and
		// returns members in CONFIG order. Do NOT sort here — a lexical sort
		// would make an overlapping per-application inactivity-timeout within an
		// application-set resolve by alphabetical member name instead of the
		// configured member order (the Rust matcher is first-writer-wins on the
		// exact port, #3227). The set-name dedup is handled upstream by the
		// `seen` term key in expandUserspacePolicyApplications.
		expanded, err := config.ExpandApplicationSet(name, &cfg.Applications)
		if err != nil || len(expanded) == 0 {
			return nil, false
		}
		return expanded, true
	}
	return nil, false
}

func normalizeUserspaceApplicationProtocol(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "icmp6":
		return "icmpv6"
	default:
		return strings.ToLower(strings.TrimSpace(proto))
	}
}

// rustParsedProtocolBeforeFix reports whether the Rust dataplane's
// parse_protocol recognized this protocol token PRIOR to #2124 (the named arms
// {tcp,udp,icmp,icmpv6,gre,ospf,ipip} plus any pure-numeric token). Such tokens
// are emitted on the wire unchanged so existing policy snapshots keep their
// current protocol string (and hash); only the newly-supported named protocols
// are canonicalized to their number for old-helper compatibility. `proto` is
// already lowercased by normalizeUserspaceApplicationProtocol.
func rustParsedProtocolBeforeFix(proto string) bool {
	switch proto {
	case "tcp", "udp", "icmp", "icmpv6", "gre", "ospf", "ipip":
		return true
	}
	// A bare numeric token (e.g. "132") was always parsed by parse_protocol's
	// numeric fallback.
	if _, err := strconv.ParseUint(proto, 10, 8); err == nil {
		return true
	}
	return false
}

// userspacePortSpecRepresentable reports whether a policy application port spec
// parses the way the Rust dataplane's parse_port_spec does (#2124). It must stay
// in lock-step with userspace-dp/src/policy.rs::parse_port_spec, because a spec
// this gate accepts but Rust rejects would silently drop the term and collapse
// the rule to match-any (the same fail-open this fix closes). Empty means "no
// port constraint" (ok); known service aliases resolve to a single port; a bare
// number must be 1..65535; a low-high range needs low > 0 && low <= high.
//
// The service-alias match is CASE-SENSITIVE on the raw spec, mirroring Rust
// `parse_port_spec` exactly (it matches `"http"` literally and does NOT
// lowercase). Lowercasing here would accept e.g. "HTTP" that Rust would reject
// and then drop — the precise mismatch that reopens the fail-open.
func userspacePortSpecRepresentable(spec string) bool {
	if spec == "" {
		return true
	}
	switch spec {
	case "http", "https", "ssh", "telnet", "ftp", "ftp-data", "smtp",
		"dns", "pop3", "imap", "snmp", "ntp", "bgp", "ldap", "syslog":
		return true
	}
	if low, high, found := strings.Cut(spec, "-"); found {
		l, errL := strconv.ParseUint(low, 10, 16)
		h, errH := strconv.ParseUint(high, 10, 16)
		if errL != nil || errH != nil {
			return false
		}
		return l != 0 && l <= h
	}
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return false
	}
	return p != 0
}
