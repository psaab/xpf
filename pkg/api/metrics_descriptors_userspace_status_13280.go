package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceStatus13280Descriptors() {
	c.userspaceCosNoOwnerBindingDrops = prometheus.NewDesc(
		"xpf_userspace_cos_no_owner_binding_drops_total",
		"Cross-worker CoS redirects dropped because no binding owned the target egress.",
		nil, nil,
	)
	c.userspaceIoUringWriteRefused = prometheus.NewDesc(
		"xpf_userspace_io_uring_write_refused_total",
		"io_uring writes refused at the bounded in-flight registry capacity.",
		nil, nil,
	)
	c.userspaceIoUringWriteRefusedBytes = prometheus.NewDesc(
		"xpf_userspace_io_uring_write_refused_bytes_total",
		"Bytes belonging to io_uring writes refused at the bounded in-flight registry capacity.",
		nil, nil,
	)
	c.userspaceRouteChangeUnrejudgedSessions = prometheus.NewDesc(
		"xpf_userspace_route_change_unrejudged_sessions_total",
		"Sessions that could not be rejudged after a route change.",
		nil, nil,
	)
	c.userspaceOwnerRGFilingsDeclined = prometheus.NewDesc(
		"xpf_userspace_owner_rg_filings_declined_total",
		"Owner redundancy-group index filings declined because the peer-supplied group id was out of range.",
		nil, nil,
	)
	c.userspaceHATransitionDropped = prometheus.NewDesc(
		"xpf_userspace_ha_transition_dropped_total",
		"HA redundancy-group transition commands dropped at worker queue capacity.",
		[]string{"op"}, nil,
	)
	c.userspaceHATransitionStaleSkipped = prometheus.NewDesc(
		"xpf_userspace_ha_transition_stale_skipped_total",
		"HA redundancy-group transition debts skipped as stale at dispatch.",
		[]string{"op"}, nil,
	)
	c.userspaceSessionDeleteRefusedIdentity = prometheus.NewDesc(
		"xpf_userspace_session_delete_refused_identity_total",
		"Scoped HA session deletes refused because the session identity did not match.",
		nil, nil,
	)
	c.userspaceSessionDeleteDroppedReleased = prometheus.NewDesc(
		"xpf_userspace_session_delete_dropped_released_total",
		"Worker-queue-dropped session deletes whose NAT reservation was released by the coordinator.",
		nil, nil,
	)
	c.userspaceTunnelPurgeReservationsReleased = prometheus.NewDesc(
		"xpf_userspace_tunnel_purge_reservations_released_total",
		"Import-time untracked NAT reservations released during tunnel-remap purge.",
		nil, nil,
	)
	c.userspaceSyncedReverseRederived = prometheus.NewDesc(
		"xpf_userspace_synced_reverse_rederived_total",
		"Peer-synced reverse companions re-derived during reconcile replay.",
		nil, nil,
	)
	c.userspacePeerDeleteRefusedLocalOwned = prometheus.NewDesc(
		"xpf_userspace_peer_delete_refused_local_owned_total",
		"Peer session deletes refused because the session is owned by a locally active redundancy group.",
		nil, nil,
	)
	c.userspaceSessionDeleteReplicaDropped = prometheus.NewDesc(
		"xpf_userspace_session_delete_replica_dropped_total",
		"Session replica-delete updates dropped at worker queue capacity.",
		nil, nil,
	)
	c.userspaceSessionDeleteReplicaDropRepaired = prometheus.NewDesc(
		"xpf_userspace_session_delete_replica_drop_repaired_total",
		"Session replica-delete drops repaired by coordinator state reconciliation.",
		nil, nil,
	)
	c.userspaceS5Reinject = prometheus.NewDesc(
		"xpf_userspace_s5_reinject_total",
		"Helper-reported q0 S5 reinjections with terminal written outcomes.",
		nil, nil,
	)
	c.userspaceS5ReinjectCompletions = prometheus.NewDesc(
		"xpf_userspace_s5_reinject_completions_total",
		"Helper-reported q0 S5 reinject terminal completions by outcome.",
		[]string{"outcome"}, nil,
	)
}
