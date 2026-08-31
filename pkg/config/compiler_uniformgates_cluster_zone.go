package config

import "fmt"

// runUniformGatesClusterZone runs the cluster zone sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesClusterZone(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #3332 trailing-token gate. Strict on commit / commit-check (hard-reject
	// a token that rode past a leaf's value arity in a shape the generic
	// schema-walk scalar gate cannot reach — multi:true address-book
	// `address` entries and the compact-hierarchical `dynamic hostname`
	// form). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; the dropped token
	// never reached the dataplane). Runs on the fully-compiled *Config so the
	// recorded TrailingTokens / DynamicHostnameExtras are available.
	if err := validateTrailingTokensStrict(cfg); err != nil {
		if opts.lenientTrailingTokens {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("trailing token (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3440 H2 flow-aging gate. Strict on commit / commit-check (hard-reject
	// an unknown `security flow aging` leaf or a low-watermark >=
	// high-watermark cross-field violation that the opaque untyped subtree
	// used to accept silently). Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick;
	// watermark aging is not enforced on the userspace dataplane anyway,
	// #3440 H1). Runs on the fully-compiled *Config (AgingUnknownLeaves and
	// the watermark ints populated by compileFlow).
	if err := validateFlowAgingStrict(cfg); err != nil {
		if opts.lenientFlowAging {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("flow aging (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4434 chassis-cluster heartbeat wire-width gate. Strict on commit /
	// commit-check (hard-reject a redundancy-group cardinality or id that
	// exceeds the single-byte heartbeat count / GroupID fields — 256 RGs
	// advertise as a count of 0 and desync the wire, an id > 255 truncates
	// and collides with another group; #4880 the per-RG node priority, #6549
	// the interface-monitor weight, both of which the heartbeat / VRRP wire
	// carries in one byte while the local election reads the raw int).
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the heartbeat marshaler
	// independently caps the group section to the wire limit,
	// marshalHeartbeatBody, so a leniently-loaded over-size config is bounded,
	// not a panic, and pkg/cluster clamps a leniently-loaded interface-monitor
	// weight — ClampInterfaceMonitorWeight / rgWeightFromDebt — so it cannot
	// diverge the two nodes' views). Runs on the fully-compiled *Config
	// (RedundancyGroups populated by compileChassis).
	if err := validateChassisClusterStrict(cfg); err != nil {
		if opts.lenientChassisRG {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("chassis cluster redundancy-group (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4573 VRRP VRID wire-width gate. Strict on commit / commit-check
	// (hard-reject a `vrrp-group <id>` outside the RFC 5798 VRID range 1..255 —
	// the id is truncated onto a single wire byte, so 256 wraps to the reserved
	// VRID 0 and the VIP never masters, and 257 aliases VRID 1 onto another
	// group). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — #1960 no-brick; the pkg/vrrp runtime
	// range check independently refuses to advertise an out-of-range VRID, so a
	// leniently-loaded bad id is bounded, not a wrong-VRID advert). Runs on the
	// fully-compiled *Config (VRRPGroups populated by parseVRRPGroups).
	if err := validateVRRPGroupIDStrict(cfg); err != nil {
		if opts.lenientVRRPGroupID {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("vrrp-group id (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5184 VRRP priority wire-width gate. Strict on commit / commit-check
	// (hard-reject a `vrrp-group <id> priority <n>` outside the RFC 5798 range
	// 1..255 — the priority is truncated onto a single wire byte, so 256 wraps
	// to the reserved priority 0 and the group advertises resignation and never
	// masters the VIP, 300 aliases to 44). The structured spellings are already
	// gated by the schema `priority` leaf's ValidateInteger(1,255), but the
	// PACKED hierarchical one-liner `vrrp-group 1 priority 256;` bypasses the
	// schema walker (its priority is consumed as an unvalidated identity token,
	// walkInstanceChildren) and is only caught here on the compiled *Config.
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config an older binary accepted still boots — #1960 no-brick). Runs on the
	// fully-compiled *Config (VRRPGroups populated by parseVRRPGroups), where the
	// wide int Priority still shows 256 as 256, before the sendAdvert uint8 cast.
	if err := validateVRRPGroupPriorityStrict(cfg); err != nil {
		if opts.lenientVRRPGroupPriority {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("vrrp-group priority (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4826 reth-derived VRRP VRID wire-width gate. Strict on commit /
	// commit-check (hard-reject a `redundant-ether-options
	// redundancy-group <id>` whose id would push the reth-derived VRRP
	// GroupID, RethVRRPGroupIDBase+id, past the RFC 5798 VRID range 1..255 —
	// the chassis redundancy-group id gate above caps id at 255, which is
	// the heartbeat wire bound, not the VRRP one; an id in 156..255 commits
	// cleanly today and then silently loses VRRP for that redundancy group
	// at runtime). Lenient on load / peer-sync (warn so an already-persisted
	// or peer-synced config still boots — #1960 no-brick; the pkg/vrrp
	// runtime range check independently refuses to advertise the
	// out-of-range VRID, so a leniently-loaded bad id is bounded, not a
	// wrong-VRID advert). Runs on the fully-compiled *Config (RedundancyGroup
	// populated by compileInterfaces). Same doctrine as lenientVRRPGroupID.
	if err := validateRethVRRPGroupIDStrict(cfg); err != nil {
		if opts.lenientRethVRRPGroupID {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reth redundancy-group id (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6779 VRRP virtual-address cardinality gate. Strict on commit /
	// commit-check (hard-reject a VRRP instance carrying more virtual
	// addresses of one family than the advertisement's single-byte address
	// count can express — 255, or 254 for IPv6 where RFC 5798 §6.1 reserves
	// the first slot for the mandatory link-local prepend). Marshal refuses
	// an out-of-range count instead of truncating it (#5090) and sendAdvert
	// swallows that error at Debug, so an oversized set makes every advert
	// fail AFTER becomeMaster claimed the VIPs — the node owns the addresses
	// and advertises nothing, so the peer promotes too (dual-master) or the
	// addresses are stranded. Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick;
	// the pkg/vrrp runtime guards refuse to build the instance and refuse to
	// claim MASTER, so a leniently-loaded oversized set is held out of the
	// election, not seated as a silent non-advertiser). Runs on the
	// fully-compiled *Config (VRRPGroups from parseVRRPGroups, RedundancyGroup
	// and unit Addresses from compileInterfaces). Same doctrine as
	// lenientRethVRRPGroupID.
	if err := validateVRRPVIPCountStrict(cfg); err != nil {
		if opts.lenientVRRPVIPCount {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("vrrp virtual-address count (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3055 reserved zone-name definition gate. Strict on commit / commit-check
	// (hard-reject a `security zones security-zone <name>` whose name is a
	// reserved sentinel — "junos-global" is reclassified by the userspace
	// dataplane as a device-wide global fallback evaluated for every flow, so a
	// zone of that name silently turns its zone-scoped policies into global
	// permits across unrelated zone pairs; "any"/"junos-host" are reserved
	// policy context tokens); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config an older binary accepted still
	// boots — #1960 no-brick).
	if err := validateReservedZoneNamesStrict(cfg); err != nil {
		if opts.lenientReservedZoneNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reserved zone name (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// Security-zone count cap (#2391 SUPERSEDED by #3075). After #3075 zone ids
	// are a stable name-hash in a u16 space, so this is a cheap pigeonhole belt:
	// a config cannot define more than MaxUsableZoneID (65533) distinct zones.
	// The StableZoneID collision gate above is the real duplicate-id protection.
	// Strict on commit / commit-check (hard-reject); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — #1960
	// no-brick). Runs AFTER the policy zone-reference gate so a structural error
	// and a bad zone reference still win the first-error slot.
	if err := validateZoneCountStrict(cfg); err != nil {
		if opts.lenientZoneCount {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone count (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3072 zone-interface membership gate. Strict on commit / commit-check
	// (hard-reject a config that assigns the same interface to more than one
	// security zone — the userspace interface->zone map resolves a duplicate
	// first-writer-wins over the SORTED zone names, so the interface silently
	// lands in whichever zone sorts first and traffic is evaluated against the
	// wrong zone's policy); lenient on load / peer-sync (warn so an already-
	// persisted or peer-synced config still boots — #1960 no-brick; the
	// interface->zone map keeps its deterministic first-writer-wins resolution,
	// so a leniently-loaded duplicate forwards exactly as before). Runs AFTER the
	// zone-count gate so a structural / policy / zone-count error still wins the
	// first-error slot.
	if err := validateZoneInterfaceMembershipStrict(cfg); err != nil {
		if opts.lenientZoneInterfaceMembership {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone interface membership (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// ps-review-002 F6 (#4515) zone-interface DEFINED gate. Strict on commit /
	// commit-check (hard-reject a `security zones security-zone <z> interfaces
	// <if>` entry naming an interface neither configured under `interfaces` nor
	// materialized as a dynamic interface — lo0 / an IPsec secure-tunnel
	// bind-interface; Junos rejects such a zone member, xpf previously only
	// warned then compiled it, so a typo'd member silently carried no traffic).
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the runtime brings the absent
	// interface DOWN independently, so the leniently-loaded member is inert).
	// The reference set is the GENEROUS zoneReferenceableInterfaceBases union so
	// the promotion cannot false-reject a legitimate lo0 / secure-tunnel
	// reference (the #4191 over-rejection class). Runs AFTER the zone-interface
	// membership gate so a duplicate-assignment error still wins the first-error
	// slot.
	if err := validateZoneInterfaceDefinedStrict(cfg); err != nil {
		if opts.lenientZoneInterfaceDefined {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone interface defined (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6735 zone-interface PACKED-TAIL gate. Strict on commit / commit-check
	// (hard-reject a member statement in which `host-inbound-traffic` is
	// followed by more tokens on the same Keys — bracket-list and packed-body
	// readings disagree about membership and the brackets that would tell them
	// apart are already gone, so the compiler silently keeps only the names
	// before the keyword and drops a valid member or a whole override).
	// Lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config still boots — #1960 no-brick; the trailing tokens were dropped
	// before this gate existed and still are).
	//
	// Runs BEFORE the non-empty gate, deliberately. The two overlap on exactly
	// one shape — `interfaces host-inbound-traffic ge-0/0/1.0;`, where the
	// keyword is FIRST so nothing precedes it and the stanza also compiles to
	// zero members. Both gates would fire; this one's message is strictly more
	// accurate, because telling an operator who plainly named `ge-0/0/1.0` that
	// the stanza "names no interface" sends them looking for the wrong problem.
	// Every other non-empty case (a keyword with NOTHING after it, a body-only
	// block) leaves this gate silent and still reaches that one.
	// #7523 NESTED ZONE-PAIR gate. Strict on commit / commit-check, lenient on
	// the tolerant Load / SyncApply ingress. Runs on the tree, not the compiled
	// *Config, because the nested shape compiles to NOTHING -- a compiled
	// SecurityConfig cannot distinguish "no policies were written" from "the
	// policies that were written were dropped", which is the whole defect.
	if err := validateNestedZonePairStrict(tree); err != nil {
		if opts.lenientNestedZonePair {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("nested zone pair (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	if err := validateZoneInterfacePackedTailStrict(tree); err != nil {
		if opts.lenientZoneInterfacePackedTail {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone interfaces packed tail (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6525 zone-interfaces NON-EMPTY gate. Strict on commit / commit-check
	// (hard-reject a `security zones security-zone <z> interfaces` stanza that
	// carries content yet compiles to ZERO members — the hierarchical
	// compact-leaf spelling `interfaces ge-0/0/1.0;` used to land the member
	// name on the stanza's own Keys tail, which compileZones never read, so the
	// zone bound no interface at all and the two gates above passed VACUOUSLY
	// over the empty member set). Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// stanza contributed no members before this gate existed and still
	// contributes none, so a leniently-loaded config forwards exactly as
	// before). Runs on the group-expanded *ConfigTree, not the compiled
	// *Config, because a compiled ZoneConfig cannot distinguish "no interfaces
	// stanza" from "a stanza that compiled to nothing". Runs AFTER the
	// zone-interface defined gate so a typo'd member still wins the first-error
	// slot; by construction the two cannot both fire on one stanza (this one
	// fires only on an EMPTY member set, which those two iterate away).
	if err := validateZoneInterfacesNonEmptyStrict(tree); err != nil {
		if opts.lenientZoneInterfacesNonEmpty {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("zone interfaces non-empty (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5933 cross-subsystem interface `.unit`-suffix reference gate. Strict on
	// commit / commit-check (hard-reject a class-of-service / security-zone /
	// routing-instance interface reference whose `.unit` suffix is non-numeric /
	// negative / out of range — such a reference silently MIS-BINDS: the CoS
	// shaper never attaches, the zone-membership key never matches a real unit,
	// the route-leak member is dropped). Lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960 no-brick; the
	// runtime already ignores an unresolvable `.unit` suffix, so a leniently-
	// loaded malformed reference is inert). Routes every reference through the
	// same canonical ValidateLogicalUnit #5829 introduced for the `interfaces
	// <if> unit <n>` instance key, closing the residual #5829 deferred to #5933.
	if err := validateInterfaceUnitReferencesStrict(cfg); err != nil {
		if opts.lenientInterfaceUnitRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("interface unit reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3200 host-inbound-traffic token gate. Strict on commit / commit-check
	// (hard-reject an unknown/typo system-services or protocols token that
	// would commit but enforce inconsistently — nft kernel mirror fails OPEN
	// for an all-unknown stanza while the Rust classifier fails CLOSED, a
	// split-brain posture); lenient on load / peer-sync (downgrade to a warning
	// so an already-persisted or peer-synced config carrying a stale token
	// still boots — #1960 no-brick; both enforcement layers ignore the unknown
	// token and the nft path now fails CLOSED for a zero-match zone, so a
	// leniently-loaded bad config is inert and consistent). Runs AFTER the zone
	// gates so a structural/zone-reference error still wins the first-error slot.
	if err := validateHostInboundTokensStrict(cfg); err != nil {
		if opts.lenientHostInboundTokens {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("host-inbound-traffic token (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3718 (Option B) duplicate host-local-address gate. Strict on commit /
	// commit-check (hard-reject a firewall-local interface address or VRRP VIP
	// that is host-inbound-reachable from more than one security zone with
	// DIFFERING host-inbound service/protocol sets — the kernel host-inbound
	// nftables chain matches destination address only over a single global input
	// chain, so the admission verdict is decided order-dependently by whichever
	// zone sorts first and can disagree with the ingress-scoped userspace-dp path
	// (split-brain)); lenient on load / peer-sync (warn so an already-persisted
	// or peer-synced config still boots — #1960 no-brick; the runtime reporter
	// AmbiguousHostInboundAddresses + the xpf_host_inbound_ambiguous_addresses
	// metric surface the ambiguity, which is NOT self-healing on that path). Runs
	// AFTER the host-inbound token gate so a token typo still wins the
	// first-error slot. Option A (kernel iifname ingress-scope) and Option C
	// (per-VRF host-inbound chains) are deferred follow-ons — see
	// docs/host-inbound-traffic.md.
	if err := validateDuplicateHostLocalAddressStrict(cfg); err != nil {
		if opts.lenientDuplicateHostLocalAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("duplicate host-local address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6611 cluster control-channel authentication gate. Strict on commit /
	// commit-check (hard-reject a `chassis cluster` with no
	// `authentication-key` — the fabric gRPC listener, the heartbeat and the
	// session-sync channel ALL key off that one PSK and all three fail OPEN
	// without it, so the whole control channel runs unauthenticated and any
	// host on the control segment can drive failover / read / clear / inject
	// sessions). Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced unkeyed config still boots — #1960 no-brick; this is the
	// upgrade path for a cluster that was unkeyed before the gate existed, and
	// the heartbeat and fabric gRPC grace lets the key then be rolled out one
	// node at a time WITHOUT dropping the cluster -- but not without dropping
	// SESSION SYNC, whose dual-accept #5078 removed; see pkg/cluster/README.md
	// -> "Rolling it onto a live unkeyed cluster", #6881). Runs LAST in the cluster-zone segment so every
	// structural cluster error still wins the first-error slot — an operator
	// fixing a malformed redundancy-group should not be handed the auth message
	// first. Runs on the fully-compiled *Config (ControlLinkAuthKey populated by
	// compileChassis).
	// #6630: a rotation overlap that is not one is rejected on the same
	// strict path as an absent key, and BEFORE it — an operator who set the
	// additional key to the same value has a config-shaped mistake, and the
	// absence message would not describe it.
	//
	// It honours the SAME lenient downgrade (#1960 no-brick): a config already
	// on disk, or pushed from a peer, must still boot. A degenerate overlap is
	// no more dangerous at runtime than not setting the leaf at all — it
	// accepts one key either way — so refusing to load one would brick a node
	// over a cosmetic mistake.
	// #7441: ordered BEFORE the absent-key gate so an operator who set
	// `strict-session-auth` without a key is told what THEY did, rather than
	// being handed the generic control-channel message and sent to add a key
	// with no hint that their posture leaf was inert. Same lenient downgrade.
	if err := validateStrictSessionAuthNeedsKeyStrict(cfg); err != nil {
		if opts.lenientClusterAuthKey {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("cluster authentication (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	if err := validateClusterAuthKeyOverlapStrict(cfg); err != nil {
		if opts.lenientClusterAuthKey {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("cluster authentication (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	if err := validateClusterAuthKeyStrict(cfg); err != nil {
		if opts.lenientClusterAuthKey {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("cluster authentication (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6611 key-strength advisories. Absence is binary and is rejected above;
	// strength is a continuum, so a short key or one copied verbatim from a
	// published reference config WARNS on both paths rather than failing the
	// config. Rejecting those would create a new brick class (including via
	// bootstrapFromFile, an unattended path) for an operator who already
	// configured authentication.
	cfg.Warnings = append(cfg.Warnings, ClusterAuthKeyStrengthWarnings(cfg)...)

	return nil
}
