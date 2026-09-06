package userspace

import (
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func buildSnapshot(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32) (*ConfigSnapshot, error) {
	return buildSnapshotWithSchedulerState(cfg, ucfg, generation, fibGeneration, nil, nil, nil)
}

func buildSnapshotWithSchedulerState(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32, activeState map[string]bool, routeOverlay []config.RouteOverlayEntry, feedOverlay map[string][]string) (*ConfigSnapshot, error) {
	return buildSnapshotWithSchedulerStateAndNATCounters(cfg, ucfg, generation, fibGeneration, activeState, routeOverlay, feedOverlay, nil)
}

// buildSnapshotWithSchedulerStateAndNATCounters builds the config snapshot and
// stamps the compiler-assigned per-rule NAT translation hit counter IDs (#2218)
// onto the SNAT/DNAT/static rule snapshots so the userspace dataplane can
// attribute a translation to the matched rule. natCounterIDs is the
// CompileResult.NATCounterIDs map (NATCounterKey "natType/ruleset/rule" ->
// stable key-derived counter ID, #2255); a nil map leaves every CounterID at 0
// ("no counter"), reproducing pre-#2218 wire shape for callers that do not have
// a compile result (tests, partial syncs).
func buildSnapshotWithSchedulerStateAndNATCounters(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32, activeState map[string]bool, routeOverlay []config.RouteOverlayEntry, feedOverlay map[string][]string, natCounterIDs map[string]uint32) (*ConfigSnapshot, error) {
	if cfg == nil {
		return &ConfigSnapshot{
			Version:       ProtocolVersion,
			Generation:    generation,
			FIBGeneration: 0,
			GeneratedAt:   time.Now().UTC(),
			Capabilities:  deriveUserspaceCapabilities(nil),
			MapPins:       userspaceMapPins(),
			Userspace:     ucfg,
		}, nil
	}
	// ONE kernel xfrm sample for the whole snapshot (#6691 round 10). The
	// interface rows and the fabric parents are both judged against it, and a
	// second dump could disagree with the first about the same device — which
	// would put a netdev's owners on opposite sides of the unanimity rule for
	// no reason but sampling.
	liveXfrm := sampleLiveXfrmNetdevs()
	interfaces := buildInterfaceSnapshotsFrom(cfg, liveXfrm)
	// #2514: the address-book content-ID assignment and the policy
	// snapshot builder (which consumes the same nameToID map) can return
	// an AddressBookIDCollisionError on an unresolvable folded-hash
	// collision. Surface it as a build error so the apply path rejects the
	// config and retains the prior dataplane state (fail-closed) — a
	// config-shaped input must never panic the daemon.
	policies, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, activeState, feedOverlay)
	if err != nil {
		return nil, err
	}
	// #3261: compute the class-(i) content-rejection diagnostic from the ACTUAL
	// built rules (feed-aware), then stamp it onto the capabilities below. The
	// cfg-only deriveUserspaceCapabilities cannot see the feed overlay, so this
	// is the single accurate source for "the helper integrity preflight will
	// reject this snapshot" (drives the diagnostic + the narrow old-helper
	// disarm). Class (ii) — genuine semantic gaps — comes from the cfg gate.
	caps := deriveUserspaceCapabilities(cfg)
	caps.PolicyContentRejected = collectPolicyContentRejections(policies)
	addressBooks, _, err := buildAddressBookTableWithFeeds(cfg, feedOverlay)
	if err != nil {
		return nil, err
	}
	// #3438: a BuildCatalog fault (overflow / malformed application-set) fails
	// the snapshot closed rather than shipping an empty catalog that would
	// silently degrade all session naming to UNKNOWN.
	appCatalog, err := buildAppCatalogSnapshot(cfg)
	if err != nil {
		return nil, err
	}
	// #3772 (M9): a kernel ip-rule enumeration failure fails the snapshot
	// closed so the apply path retains the prior dataplane state rather
	// than shipping a snapshot missing every route-leak route.
	routes, learnedRoutesCapped, err := buildRouteSnapshots(cfg, interfaces, routeOverlay)
	if err != nil {
		return nil, err
	}
	mirrorConfigs, mirrorExclusions := buildMirrorConfigSnapshots(cfg, interfaces)
	snap := &ConfigSnapshot{
		Version:       ProtocolVersion,
		Generation:    generation,
		FIBGeneration: fibGeneration,
		GeneratedAt:   time.Now().UTC(),
		Capabilities:  caps,
		MapPins:       userspaceMapPins(),
		Userspace:     ucfg,
		// #6311: the chassis-cluster node id becomes the high bit of every
		// worker's session-id namespace on the helper. Read from the compiled
		// config's cluster stanza; absent/standalone leaves it 0, which is the
		// pre-#6311 layout bit for bit.
		NodeID:          clusterNodeID(cfg),
		Zones:           buildZoneSnapshots(cfg),
		Interfaces:      interfaces,
		Fabrics:         buildFabricSnapshotsFrom(cfg, liveXfrm),
		TunnelEndpoints: buildTunnelEndpointSnapshots(cfg, interfaces),
		Neighbors:       buildNeighborSnapshots(cfg),
		Routes:          routes,
		// #9054: the helper needs to know the FIB it just received is
		// DELIBERATELY incomplete. See ConfigSnapshot.LearnedRouteImportCapped.
		LearnedRouteImportCapped: learnedRoutesCapped,
		Flow:                     buildFlowSnapshot(cfg),
		DefaultPolicy:            policyActionString(cfg.Security.DefaultPolicy),
		// #3534: thread the implicit-default-policy RT_FLOW log selection to the
		// dataplane so a default-PERMIT session emits session-init/close records.
		DefaultLogSessionInit:  cfg.Security.DefaultPolicyLogSessionInit,
		DefaultLogSessionClose: cfg.Security.DefaultPolicyLogSessionClose,
		Policies:               policies,
		// #3303: thread feedOverlay into the NAT builders so a NAT rule scoped
		// to a feed-backed `match {source,destination}-address-name` resolves the
		// live feed prefixes, exactly as the policy/address-book path does. Static
		// NAT has no address-name match, so it needs no overlay.
		SourceNAT:             buildSourceNATSnapshotsWithFeeds(cfg, natCounterIDs, feedOverlay),
		StaticNAT:             buildStaticNATSnapshots(cfg, natCounterIDs),
		DestinationNAT:        buildDestinationNATSnapshotsWithFeeds(cfg, natCounterIDs, feedOverlay),
		NAT64:                 buildNAT64Snapshots(cfg),
		Nptv6:                 buildNptv6Snapshots(cfg),
		Screens:               buildScreenSnapshots(cfg),
		ScreenMissingProfiles: buildScreenMissingProfileRefs(cfg),
		ScreenInertProfiles:   buildScreenInertProfileRefs(cfg),
		SYNCookieMasterKey:    buildSYNCookieMasterKey(cfg),
		Filters:               buildFirewallFilterSnapshots(cfg),
		Policers:              buildPolicerSnapshots(cfg),
		ThreeColorPolicers:    buildThreeColorPolicerSnapshots(cfg),
		ClassOfService:        buildClassOfServiceSnapshot(cfg),
		FlowExport:            buildFlowExportSnapshot(cfg),
		MirrorConfigs:         mirrorConfigs,
		MirrorExclusions:      mirrorExclusions,
		AddressBooks:          addressBooks,
		AppCatalog:            appCatalog,
		Config:                cfg,
		Summary: SnapshotSummary{
			HostName:       cfg.System.HostName,
			DataplaneType:  cfg.System.DataplaneType,
			InterfaceCount: len(cfg.Interfaces.Interfaces),
			ZoneCount:      len(cfg.Security.Zones),
			// #3625: PolicyCount is the total number of policy RULES the
			// dataplane will enforce — one per built PolicyRuleSnapshot,
			// spanning every zone-pair set's rules plus global policies.
			// It was len(cfg.Security.Policies), the number of zone-pair
			// policy SETS, so a global-only config reported 0 and a set
			// holding N rules reported 1. Deriving it from the built
			// `policies` slice also keeps the summary count equal to the
			// object count the Rust plane decodes (snapshot-integrity).
			PolicyCount:    len(policies),
			SchedulerCount: len(cfg.Schedulers),
			HAEnabled:      cfg.Chassis.Cluster != nil,
		},
	}
	// #3719: enforce the StableZoneID zone-isolation invariant BEFORE the
	// snapshot is published. On the lenient / HA-sync / pre-#3075-persisted
	// path two zone names can fold to the same numeric id; publishing both
	// merges two security zones in the dataplane. quarantineCollidingZones
	// drops the later-sorting colliding zone (and unzones its interfaces / drops
	// its policies so no dangling reference bricks the helper preflight),
	// leaving the rest of the config intact (#1960 no-brick). The stashed
	// collisions ride up to ApplyConfig, which fires the operator alarm and
	// stamps the status/metric.
	snap.zoneIDCollisions = quarantineCollidingZones(snap)
	if len(snap.zoneIDCollisions) > 0 {
		// Keep the operator-facing counts equal to what is actually published.
		snap.Summary.ZoneCount = len(snap.Zones)
		snap.Summary.PolicyCount = len(snap.Policies)
	}
	// #7717: report (do NOT foreclose) a NAT pool overlapping an interface-mode
	// SNAT egress address that is only knowable at snapshot build — a DHCP or
	// netlink-learned address the commit-time gate cannot see. Quarantining the
	// pool here is what §5.7 specifies, and it ships with the drain, in one
	// change, because the merged config gate says marking a pool unusable with
	// nothing draining strands live sessions.
	reportInterfaceSNATPoolOverlaps(snap)

	return snap, nil
}

// snapshotContentHash computes a SHA-256 hash over the stable content of a
// snapshot, excluding volatile fields (Generation, FIBGeneration, GeneratedAt)
// that change on every build even when the forwarding-relevant content is
// identical. Used to skip redundant control-socket publishes.
func snapshotContentHash(snap *ConfigSnapshot) ([32]byte, bool) {
	// Create a shallow copy with volatile fields zeroed, then JSON-encode.
	// This is cheaper than a custom hasher and reuses the existing JSON tags.
	tmp := *snap
	tmp.Generation = 0
	tmp.FIBGeneration = 0
	tmp.GeneratedAt = time.Time{}
	tmp.Config = nil // exclude raw config from content hash to avoid churn from non-forwarding metadata
	// #1197 (Copilot review): hash only PUBLISHABLE neighbors so
	// the dedup compares against what userspace-dp actually sees.
	// Filtered-out rows (state="none", malformed MAC) never reach
	// the dataplane, so churn in them must not shift the hash.
	tmp.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	data, err := json.Marshal(&tmp)
	if err != nil {
		slog.Warn("snapshotContentHash: marshal failed, skipping dedup", "err", err)
		return [32]byte{}, false
	}
	return sha256.Sum256(data), true
}

func userspaceMapPins() UserspaceMapPins {
	return UserspaceMapPins{
		Ctrl:        dataplane.UserspaceCtrlPinPath(),
		Bindings:    dataplane.UserspaceBindingsPinPath(),
		Heartbeat:   dataplane.UserspaceHeartbeatPinPath(),
		XSK:         dataplane.UserspaceXSKMapPinPath(),
		LocalV4:     dataplane.UserspaceLocalV4PinPath(),
		LocalV6:     dataplane.UserspaceLocalV6PinPath(),
		Sessions:    dataplane.UserspaceSessionsPinPath(),
		ConntrackV4: dataplane.ConntrackV4PinPath(),
		ConntrackV6: dataplane.ConntrackV6PinPath(),
		DnatTable:   dataplane.UserspaceDnatTablePinPath(),
		DnatTableV6: dataplane.UserspaceDnatTableV6PinPath(),
		Trace:       dataplane.UserspaceTracePinPath(),
	}
}

// clusterNodeID reports the chassis-cluster node id from the compiled config,
// or 0 when the node is standalone or has no cluster stanza (#6311).
//
// The id is bounded to 0..1 upstream — parseNodeIDFileContent rejects anything
// else when reading /etc/xpf/node-id, the config compiler validates the `chassis
// cluster node` leaf, and cluster.IsSupportedClusterNodeID pins the two-node
// topology. Narrowing here is defence in depth for the wire field, not a policy
// decision: the helper uses the value as a single discriminator BIT, so folding
// an impossible third node onto 0 is what it would do anyway.
func clusterNodeID(cfg *config.Config) uint8 {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return 0
	}
	if cfg.Chassis.Cluster.NodeID <= 0 {
		return 0
	}
	return 1
}
