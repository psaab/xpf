package userspace

import (
	"github.com/psaab/xpf/pkg/dataplane"
)

// #9714: the second half of the compile-time belt for the peer-delete capability,
// the same split as scoped_batch_delete_adapter_9364.go.
//
// The store resolves peerSyncedSessionDeleter by runtime type assertion, and a
// miss silently falls back to the unmarked delete: exactly the #9714 defect, with
// every test that supplies its own double still green. Manager.Sessions() builds
// the store over NewLegacyDataPlaneAdapter(m), so the ADAPTER is what the
// assertion is handed; #9482 is what a Manager-only method did. Both publishable
// types are asserted.
var (
	_ peerSyncedSessionDeleter = (*LegacyDataPlaneAdapter)(nil)
	_ peerSyncedSessionDeleter = (*Manager)(nil)
)

// peerSyncedSessionDeleter mirrors pkg/dataplane's unexported interface of the
// same name; pkg/dataplane's half of the belt keeps the two from drifting apart.
type peerSyncedSessionDeleter interface {
	BatchDeletePeerSyncedSessionsScoped([]dataplane.ScopedSessionKey) (int, []dataplane.ScopedSessionKey, error)
	BatchDeletePeerSyncedSessionsScopedV6([]dataplane.ScopedSessionKeyV6) (int, []dataplane.ScopedSessionKeyV6, error)
	DeletePeerSyncedSession(dataplane.SessionKey) (bool, error)
	DeletePeerSyncedSessionV6(dataplane.SessionKeyV6) (bool, error)
}
