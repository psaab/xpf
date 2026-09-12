package dataplane

// #9714: the store-side half of the compile-time belt for the peer-delete
// capability, the same split as scoped_batch_delete_published_9364.go.
//
// peerSyncedSessionDeleter is resolved by runtime type assertion and is OPTIONAL:
// a dataplane that does not implement it gets the unmarked delete, which is the
// #9714 defect (a peer delete tearing down a live local session under a
// dual-primary split), with no error and every test that brings its own double
// still green. This file pins the shape of the interface the store asserts;
// pkg/dataplane/userspace/peer_synced_session_delete_adapter_9714.go pins that
// the published *LegacyDataPlaneAdapter and *Manager implement it. Neither half
// alone closes the seam.

var _ = peerSyncedSessionDeleter(nil)

type peerSyncedSessionDeleteContract interface {
	BatchDeletePeerSyncedSessionsScoped([]ScopedSessionKey) (int, []ScopedSessionKey, error)
	BatchDeletePeerSyncedSessionsScopedV6([]ScopedSessionKeyV6) (int, []ScopedSessionKeyV6, error)
	DeletePeerSyncedSession(SessionKey) (bool, error)
	DeletePeerSyncedSessionV6(SessionKeyV6) (bool, error)
}

func assertPeerSyncedSessionDeleteContract(c peerSyncedSessionDeleteContract) peerSyncedSessionDeleter {
	return c
}

var _ = assertPeerSyncedSessionDeleteContract
