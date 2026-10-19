package dataplane

// #14965 — bind the scoped singular-delete capability to the store's
// resolution, the same split belt as scoped_batch_delete_published_9364.go.
//
// sessionScopedDeleter is resolved by runtime type assertion and is OPTIONAL:
// a miss falls back to the bare DeleteSession, which re-derives the routing
// domain from the surviving mirror row and cannot carry PurgeTunnelVariants.
// On the userspace backend that fallback IS the #14965 defect on the per-key
// batch-retry recovery path, so the published adapter must not silently stop
// satisfying it. This file pins the shape pkg/dataplane resolves;
// pkg/dataplane/userspace/scoped_singular_delete_adapter_14965.go pins that
// the published types implement it.

var _ = sessionScopedDeleter(nil)

type scopedSingularDeleteContract interface {
	DeleteSessionScoped(ScopedSessionKey) error
	DeleteSessionScopedV6(ScopedSessionKeyV6) error
}

func assertScopedSingularDeleteContract(c scopedSingularDeleteContract) sessionScopedDeleter {
	return c
}

var _ = assertScopedSingularDeleteContract
