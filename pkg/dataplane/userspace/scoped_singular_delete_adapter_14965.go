package userspace

import (
	"github.com/psaab/xpf/pkg/dataplane"
)

// #14965 — the second half of the compile-time belt for the scoped singular
// delete: the types the userspace backend PUBLISHES must satisfy it.
//
// See pkg/dataplane/scoped_singular_delete_published_14965.go for why the
// belt is split. Manager.Sessions() builds the store over
// NewLegacyDataPlaneAdapter(m), so the adapter is what the store's type
// assertion is handed; *Manager is asserted too because both are declared
// publishable as dataplane.RuntimeDataPlane (#9482).
var (
	_ scopedSingularDeleter = (*LegacyDataPlaneAdapter)(nil)
	_ scopedSingularDeleter = (*Manager)(nil)
)

// scopedSingularDeleter mirrors pkg/dataplane's unexported
// sessionScopedDeleter; pkg/dataplane's half of the belt keeps the two from
// drifting apart.
type scopedSingularDeleter interface {
	DeleteSessionScoped(dataplane.ScopedSessionKey) error
	DeleteSessionScopedV6(dataplane.ScopedSessionKeyV6) error
}
