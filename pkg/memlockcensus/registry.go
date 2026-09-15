package memlockcensus

// Site is one test that goes inert without the memlock privilege.
type Site struct {
	// File is the repo-relative path of the _test.go file.
	File string
	// Test is the function that calls rlimit.RemoveMemlock and skips on
	// failure. It is the NAME a reviewer would grep for and conclude the
	// underlying defect is guarded.
	Test string
}

// Registry is every memlock-gated guard in the tree, recorded so the set
// cannot grow or shrink silently (#8371).
//
// This is a REGISTRY, not an allowlist of defects. Each entry is a real guard
// that protects a real property; the entry records that its protection is
// CONDITIONAL on the environment. Adding a memlock-gated test without adding it
// here reds TestMemlockCensusMatchesTheTree, and removing one without deleting
// its row reds the same test in the other direction.
//
// Do not "fix" a red here by editing this list to match. The question the red
// asks is whether the new guard NEEDS the privilege. Several in this list do
// not: #8370 rewrote four of its own to drive applyPrimaryBindingRowsLocked /
// applyAliasBindingRowsLocked through the existing fakeCtrlMap seam (added by
// #5486 for exactly this reason), and they now execute unprivileged while still
// asserting the row was never written. Moving the assertion below the privilege
// boundary is the preferred remedy; recording it here is the fallback for tests
// that genuinely need a kernel map.
var Registry = []Site{
	{File: "pkg/dataplane/userspace/addr_only_commit_failclosed_4959_test.go", Test: "TestAddressOnlyCommitRejectedPublishFailsClosed4959"},
	{File: "pkg/dataplane/userspace/addr_only_commit_failclosed_4959_test.go", Test: "TestDeferredPublishRejectedFailsClosed4959"},
	{File: "pkg/dataplane/userspace/clear_all_helper_error_5881_test.go", Test: "TestClearAllSessionsSurfacesHelperDeleteError5881"},
	{File: "pkg/dataplane/userspace/clear_all_multichunk_fastfail_5380_test.go", Test: "TestClearAllSessionsFastFailsAcrossChunksOnHungHelper5380"},
	{File: "pkg/dataplane/userspace/clear_bounded_5304_test.go", Test: "TestClearAllSessionsDeliversEveryKeyToHelper5304"},
	{File: "pkg/dataplane/userspace/legacy_dataplane_batchclear_5096_test.go", Test: "TestBatchAndClearRouteToHelper5096"},
	{File: "pkg/dataplane/userspace/link_cycle_test.go", Test: "newLinkCycleTestManager"},
	{File: "pkg/dataplane/userspace/manager_ha_test.go", Test: "TestApplyHelperStatusInitialCtrlCleanupRunsOnlyOnce"},
	{File: "pkg/dataplane/userspace/manager_ha_test.go", Test: "TestMergeHAStateFromMaps"},
	{File: "pkg/dataplane/userspace/manager_ha_test.go", Test: "TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap"},
	{File: "pkg/dataplane/userspace/manager_ha_test.go", Test: "TestUpdateRGActiveActivationKeepsCtrlEnabledAfterAckedStatus"},
	{File: "pkg/dataplane/userspace/manager_sessionsync_test.go", Test: "TestSetClusterSyncedSessionV4MirrorFailureMarksHelperUnhealthy"},
	{File: "pkg/dataplane/userspace/manager_sessionsync_test.go", Test: "TestSetClusterSyncedSessionV4MirrorSuccessClearsStickyFailure"},
	{File: "pkg/dataplane/userspace/manager_sessionsync_test.go", Test: "TestSetClusterSyncedSessionV4SkipsReverseHelperMirror"},
	{File: "pkg/dataplane/userspace/manager_sessionsync_test.go", Test: "TestSetClusterSyncedSessionV6MirrorFailureMarksHelperUnhealthy"},
	{File: "pkg/dataplane/userspace/maps_sync_addrlist_prune_3924_test.go", Test: "TestSyncLocalAddressMapsPrunesStaleOnCompleteEnum"},
	{File: "pkg/dataplane/userspace/maps_sync_addrlist_prune_3924_test.go", Test: "TestSyncLocalAddressMapsSkipsPruneOnAddrListError"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestApplyHelperStatusAcceptsIfindexWithinCap"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestApplyHelperStatusDisablesLiveCtrlOnPublicationFailure"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestApplyHelperStatusRejectsOverCapIfindex"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestBlindFailClosedUserspaceCtrlAfterLookupFailure"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestClassifierMapRefreshMissingCtrlRowReturnsClassifierError"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestSamePlanClassifierMapRefreshFailsClosedOnNATSyncFailure"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestSyncInterfaceNATAddressMapsAddsBeforeRemovingStale"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestSyncInterfaceNATAddressMapsReplacesStaleWhenCapacityAllows"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestSyncLocalAddressMapsAddsBeforeRemovingStale"},
	{File: "pkg/dataplane/userspace/maps_sync_cap_test.go", Test: "TestVerifyBindingsWatchdogSkipsOverCapIfindex"},
	{File: "pkg/dataplane/userspace/maps_sync_ingress_partial_6537_test.go", Test: "newIngressManager"},
	{File: "pkg/dataplane/userspace/maps_sync_queue_id_bound_4894_test.go", Test: "TestApplyHelperStatusRejectsQueueIDBeyondStride"},
	{File: "pkg/dataplane/userspace/maps_sync_stale_binding_retry_5697_test.go", Test: "TestClearStaleBindingRowsKeepsLiveBindings"},
	{File: "pkg/dataplane/userspace/maps_sync_stale_binding_retry_5697_test.go", Test: "TestClearStaleBindingRowsRetainsFailedClearInRetryInventory"},
	{File: "pkg/dataplane/userspace/scoped_global_zoneset_failclosed_5488_test.go", Test: "TestSnapshotProtocolDisarmFailureFailsClosed5488"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestClearStaleSteeringRowsDeletesEveryRow9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestClearStaleSteeringRowsPopulatedTiming9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestSpawnClearsSteeringRows9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestDrainAndClearSteeringRows9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestDisarmReclaimsSteeringRows9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestLinkCycleStopReclaimsSteeringRows9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestDisarmBeforeUnsupportedPublish9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestDisarmSnapshotProtocolFailure9770"},
	{File: "pkg/dataplane/userspace/steering_spawn_clear_9770_test.go", Test: "TestSyncDesiredForwardingState9770"},
	{File: "pkg/dataplane/userspace/synced_import_refusal_6785_test.go", Test: "newAnsweringManager6785"},
	{File: "pkg/dataplane/userspace/synced_session_bpf_rollback_5305_test.go", Test: "newMirrorFailManager5305"},
	{File: "pkg/dataplane/userspace/synced_session_bpf_rollback_5305_test.go", Test: "newMirrorOKManager5305"},
	{File: "pkg/dataplane/userspace/xdp_shim_decouple_test.go", Test: "TestProgramBootstrapMapsDoesNotRequireLegacyFallbackProgram"},
	{File: "pkg/dataplane/userspace/xdp_shim_decouple_test.go", Test: "TestXSKLivenessFailureRestoresUserspaceShimEntry"},
	{File: "pkg/dataplane/userspace/xdp_shim_decouple_test.go", Test: "loadUserspaceXDPTestCollection"},
	{File: "pkg/dataplane/userspace_shim_loader_test.go", Test: "TestReconcileDisposableCollectionPinMigratesArrayToPerCPUArray"},
	{File: "pkg/dataplane/userspace_shim_loader_test.go", Test: "TestReconcileDisposableCollectionPinNoOpOnRealEmbeddedSpec"},
	{File: "pkg/dataplane/verify_userspace_shim_test.go", Test: "TestVerifyEmbeddedUserspaceShim"},
	{File: "pkg/dataplane/verify_userspace_shim_test.go", Test: "TestVerifyUserspaceShimShrinkEquivalence"},
}
