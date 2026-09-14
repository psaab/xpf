package config

import "fmt"

// runUniformGatesRoutingRibRPM runs the routing rib rpm sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesRoutingRibRPM(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2226: rib-group `import-rib <rib>` cross-reference. An import-rib naming
	// a rib that resolves to no real routing table (a typo, a non-existent
	// instance, or unparseable garbage) compiled cleanly; the applier mapped
	// the unresolvable name to table 0, which differs from the (>= 100) source
	// table, and spuriously installed an `ip rule from all lookup <sourceTable>`
	// — a silent mis-leak of the source table into the main lookup. Strict on
	// commit / commit-check (hard reject so the typo is operator-visible);
	// lenient on load / peer-sync (warn — #1960; the applier's resolveRibTable
	// ok=false guard skips the phantom rib so it is already inert). Mirrors
	// validateRoutingExportReferencesStrict.
	if err := validateRibGroupImportRibReferencesStrict(cfg); err != nil {
		if opts.lenientRibGroupRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rib-group import-rib reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5693: next-table target definedness gate. A static route whose
	// `next-table <target>` names an UNDEFINED routing-instance was accepted
	// at commit and then silently dropped at apply time (the applier's
	// tableIDs lookup misses, warns, and skips) — the intended inter-VRF leak
	// never happened and traffic followed the ingress table's own routes.
	// Strict on commit / commit-check (hard reject so the typo is operator-
	// visible); lenient on load / peer-sync (warn — #1960; the applier's !ok
	// guard keeps a dangling next-table inert). Mirrors
	// validateRibGroupImportRibReferencesStrict.
	if err := validateNextTableTargetReferencesStrict(cfg); err != nil {
		if opts.lenientNextTableRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("next-table target reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9409: `protocols` under `instance-type forwarding`. The assembler clears
	// VRFName for a forwarding instance (correct for statics, which render into
	// `table <id>`) and the protocol renderer reads an empty VRFName as "the
	// GLOBAL instance", so an instance-scoped OSPF/OSPFv3/IS-IS/RIP was
	// activated in the global routing context and an instance-scoped BGP
	// neighbor silently JOINED THE GLOBAL AS — on a commit all four channels
	// accept with zero warnings. Strict on commit / commit-check (hard reject
	// so the unsupported composition is operator-visible); lenient on load /
	// peer-sync (warn — #1960; assembleFRRConfig drops a forwarding instance's
	// protocols rather than merging them, so a leniently-loaded config is
	// already inert). Mirrors validateNextTableTargetReferencesStrict.
	if err := validateForwardingInstanceProtocolsStrict(cfg); err != nil {
		if opts.lenientForwardingInstanceProtocols {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("forwarding-instance protocols (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5854: next-table / interface-routes rib-group ip-rule WINDOW gate. The
	// runtime applier programs these leaks into FIXED priority windows
	// (pkg/routing/rules.go: 100 next-table rules, 1000 rib-group leak rules) and
	// HARD-CAPS at each boundary, silently skipping any rule past it. A config
	// that exceeds a window therefore commits green but the reconciler stops at
	// the limit and returns success — the committed generation CLAIMS routes the
	// kernel never programs (blackhole / asymmetric routing / silent inter-VRF
	// leak loss). This was previously WARN-only (ValidateConfig). Strict on
	// commit / commit-check (hard reject so the over-subscription is
	// operator-visible before it truncates); lenient on load / peer-sync (warn —
	// #1960; the applier's window hard-cap keeps the excess inert, so an
	// already-committed or peer-synced over-limit generation still boots).
	// Mirrors validateNextTableTargetReferencesStrict.
	if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
		if opts.lenientRoutingRuleWindows {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("routing-rule window over-subscription (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5633: static-route disposition-conflict gate. Repeated same-prefix
	// static-route `set` lines merge into a single StaticRoute
	// (compileStaticRoutes) that appends next-hops and latches sticky terminal /
	// next-table fields, so declaring one destination once as `discard` (or
	// `next-table X`) and once with a `next-hop` compiled into ONE route holding
	// a blackhole/leak AND a forwarding next-hop — a contradiction the strict
	// gate accepted. The live snapshot copies every field and the Rust forwarder
	// resolves discard > next-table > next-hop, so the stale terminal/leak wins
	// and a later next-hop meant to restore forwarding is silently ignored.
	// Strict on commit / commit-check (hard reject so the contradiction is
	// operator-visible); lenient on load / peer-sync (warn — #1960; the dataplane
	// resolves the deterministic precedence so the config still boots). Mirrors
	// validateNextTableTargetReferencesStrict.
	if err := validateStaticRouteDispositionConflictStrict(cfg); err != nil {
		if opts.lenientRouteDispositionConflict {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static route disposition conflict (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9820: static-route next-hop family gate. An IPv6 static route with
	// an IPv4 next-hop commits clean today and renders `ipv6 route <v6dst>
	// <v4nh> [ifname]` — but FRR's `ipv6 route` grammar takes only an
	// IPv6 gateway or an interface, so the bare form fills the
	// interface-name slot (normally inactive absent a same-named
	// interface) and ordinary gateway-plus-interface emissions fail
	// parsing. The reverse direction (IPv4-via-IPv6) is a valid `ip
	// route` form and is kept. Strict on commit / commit-check (hard
	// reject so the unsupported combination is operator-visible); lenient
	// on load / peer-sync (warn — #1960; the renderer's
	// generateStaticRouteInTable SKIPS the offending next-hop so a
	// leniently-loaded config omits it with a warning rather than
	// poisoning the reload). Mirrors
	// validateStaticRouteDispositionConflictStrict.
	if err := validateStaticNextHopFamilyStrict(cfg); err != nil {
		if opts.lenientStaticNextHopFamily {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static route next-hop family (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5701: route-map sequence-number overflow gate. A policy-statement whose
	// per-term Cartesian expansion (families x from-prefix-list x from-community
	// x from-as-path) produces more sequences than the FRR route-map
	// sequence-number space (1..65535, step 10) renders a `route-map` line past
	// seq 65535. FRR rejects it (CMD_WARNING_CONFIG_FAILED) and a single failed
	// line makes the vtysh-batched frr-reload exit non-zero, poisoning the WHOLE
	// managed-section reload. Strict on commit / commit-check (hard reject so the
	// oversized policy is operator-visible); lenient on load / peer-sync (warn —
	// #1960; the renderer's generatePolicyOptions SKIPS an over-ceiling policy so
	// a leniently-loaded config renders nothing for it rather than poisoning the
	// reload). Mirrors validateNextTableTargetReferencesStrict.
	if err := validatePolicyRouteMapSequenceBoundStrict(cfg); err != nil {
		if opts.lenientPolicyRouteMapSeq {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("route-map sequence bound (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5732: composed BGP policy-CHAIN route-map sequence bound — the chain
	// companion to the per-policy #5701 gate above. renderComposedRouteMap
	// concatenates an `export`/`import [ A B ... ]` chain (#5277) into ONE
	// route-map with a running sequence number, so members that each pass the
	// per-policy gate can still SUM past the FRR ceiling and emit a `route-map`
	// line past seq 65535 — poisoning the whole frr-reload. Same strict/lenient
	// doctrine and the SAME MaxRouteMapSequences ceiling; the renderer's
	// renderComposedRouteMap independently skips an over-ceiling chain on the
	// tolerant path (shared ComposedChainSequenceCount predicate).
	if err := validateBGPComposedChainSequenceBoundStrict(cfg); err != nil {
		if opts.lenientPolicyRouteMapSeq {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("composed route-map chain sequence bound (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2492: RPM test source-address gate. A malformed `source-address`
	// (non-empty but unparseable) silently degrades the tcp-ping/http-get
	// probe dialer to a wildcard/kernel-chosen source bind, so the probe
	// measures the DEFAULT uplink instead of the pinned source path —
	// publishing PASS/FAIL for the wrong path while RPM feeds
	// event-options / ip-monitoring failover. A v6 source with a v4
	// IP-literal target (or vice-versa) is likewise unpinnable. Strict on
	// commit / commit-check (hard reject so the typo is operator-visible);
	// lenient on load / peer-sync (warn — #1960; the runtime probeDialer
	// guard returns ErrProbeSetup for the same malformed source, so the
	// leniently-loaded test HOLDS state instead of actuating routes off a
	// wildcard measurement). Hostname targets skip the family check
	// (the target family is unknown until DNS resolves). Mirrors
	// validateRibGroupImportRibReferencesStrict.
	if err := validateRPMSourceAddressStrict(cfg); err != nil {
		if opts.lenientRPMSourceAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm source-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2493 scoped-hostname gate REMOVED in #2614: a scoped RPM test
	// (routing-instance / destination-interface / next-hop) against a
	// hostname target now resolves IN the probe's VRF/path scope — the
	// runtime resolver (rpm.resolveProbeTarget / probeDialer.Resolver)
	// binds the DNS socket to the same SO_BINDTODEVICE / SO_MARK as the
	// probe socket, so the lookup egresses the VRF and hits the VRF's DNS.
	// The combination is therefore legitimate and no longer rejected at
	// commit (see docs/multi-wan.md).

	// #2494: IPv6 link-local RPM target zone gate. A link-local target
	// (fe80::/10) needs an egress-link scope — an explicit `%zone` on the
	// literal or a destination-interface — or the kernel cannot pick the
	// link and the ICMP echo is dead. A bare link-local with neither is
	// refused so the operator sees the gap at commit instead of a silently
	// dead probe driving ip-monitoring failover. Strict on commit /
	// commit-check (hard reject); lenient on load / peer-sync (warn —
	// #1960; the runtime probeICMP guard returns ErrProbeSetup for the
	// same scopeless link-local, so the leniently-loaded test HOLDS state
	// instead of actuating off a dead measurement).
	if err := validateRPMLinkLocalZoneStrict(cfg); err != nil {
		if opts.lenientRPMLinkLocalZone {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm link-local zone (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2495: http-get target scheme gate. An http-get target that carries
	// a scheme other than http/https (ftp://, gopher://, …) makes
	// http.NewRequestWithContext error before a packet is sent, so the
	// probe never runs and publishes a permanent FAIL into event-options /
	// ip-monitoring failover. A schemeless target (bare host / IP /
	// host:port) is fine — the runtime prepends http://. Strict on commit /
	// commit-check (hard reject so the bad scheme is operator-visible);
	// lenient on load / peer-sync (warn — #1960; the runtime
	// canonicalizeHTTPTarget guard returns the same error, so the
	// leniently-loaded test HOLDS state instead of actuating off a probe
	// that can never run).
	if err := validateRPMHTTPGetSchemeStrict(cfg); err != nil {
		if opts.lenientRPMHTTPGetScheme {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm http-get scheme (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2496: RPM test routing-instance cross-reference gate. A test whose
	// `routing-instance` names a nonexistent instance makes the runtime
	// bind the probe DATA socket to a synthesized vrf-<name> device
	// (SO_BINDTODEVICE) that does not exist → ENODEV → the probe never runs
	// and the test HOLDS its state forever, starving any event-options /
	// ip-monitoring policy keyed off it of a failover signal. An empty
	// routing-instance is the default (master) context and is accepted.
	// Strict on commit / commit-check (hard reject so the typo is
	// operator-visible); lenient on load / peer-sync (warn — #1960; the
	// runtime bind returns ENODEV for the same nonexistent instance, so the
	// leniently-loaded test HOLDS state instead of actuating off a dead
	// measurement). Mirrors the ip-monitoring preferred-route
	// routing-instance check in validateIPMonitoringStrict.
	if err := validateRPMRoutingInstanceStrict(cfg); err != nil {
		if opts.lenientRPMRoutingInstance {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rpm routing-instance (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5832: interface canonical-name collision / IFNAMSIZ gate. LinuxIfName
	// only replaces '/' with '-', so two DISTINCT authored names (ge-0/0/0 and
	// ge-0-0-0) canonicalize to the same Linux device / ifindex; each still
	// emits its own logical snapshot row (zone / routing-instance /
	// host-inbound / NAT), and the Rust forwarding-state builder keys by ifindex
	// and OVERWRITES the earlier row — the lexicographically later name silently
	// wins, hijacking that device's security-zone and routing identity. An
	// over-IFNAMSIZ canonical name is a sibling hazard (the device never gets
	// created). Strict on commit / commit-check (hard reject so the collision is
	// operator-visible before it silently reroutes traffic); lenient on load /
	// peer-sync (warn — #1960; naming the winner makes the overwrite visible so
	// a grandfathered config still boots without a silent hijack).
	if err := validateInterfaceNameCollisionStrict(cfg); err != nil {
		if opts.lenientIfNameCollision {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("interface name collision (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6722: redundant-ethernet membership coherence. A reth member is an L2
	// port; the reth owns the units, addresses, tunnel and security zone of the
	// shared device, and `ResolveReth` collapses the reth's rows onto the
	// member's netdev on exactly that basis. A member that names itself, names an
	// unconfigured parent, carries its own logical units, or carries its own
	// tunnel breaks the premise the egress-zone answer rests on — the last two
	// fail OPEN, because an independently addressed member unit or an
	// independently routed tunnel endpoint lives on the shared ifindex while only
	// the reth's row names a zone. Strict on commit / commit-check (hard reject
	// so the incoherence is operator-visible before it mis-zones traffic);
	// lenient on load / peer-sync (warn — #1960), where the runtime states the
	// SAME rule (`egressMemberIsBarePort`, pkg/dataplane/userspace/interfaces.go)
	// and leaves the contested ifindex with no zone, i.e. fail-closed.
	if err := validateRethMemberStrict(cfg); err != nil {
		if opts.lenientRethMember {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reth member (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6781 RETH redundancy-group ownership gate. Strict on commit /
	// commit-check: `redundant-ether-options redundancy-group <N>` on an
	// interface no port names as its redundant-parent is not a
	// redundant-ethernet interface, and the three consumers of that stanza
	// disagreed about it — networkd replaced the operator's address with a
	// link-local /32, the VRRP-backed owner claimed the real address as a VIP,
	// and the direct owner skipped it, so under no-reth-vrrp the address was
	// stripped and installed by nobody on both nodes. Lenient on load /
	// peer-sync (warn so an already-persisted or peer-synced config still
	// boots — #1960 no-brick; the runtime resolves ownership through the shared
	// structural predicate, so the interface stays a plain L3 interface).
	// Runs after validateRethMemberStrict, which has already established that
	// the redundant-parent declarations themselves are coherent. Same doctrine
	// as lenientRethMember.
	if err := validateRethRedundancyGroupStrict(cfg); err != nil {
		if opts.lenientRethRGOwnership {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reth redundancy-group (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
