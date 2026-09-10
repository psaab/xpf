package dataplane

// #9364 — bind the scoped-batch-delete capability to the types that are actually
// published as this store's `DataPlane`, at compile time.
//
// `sessionDomainBatchDeleter` is resolved by RUNTIME TYPE ASSERTION, and it is an
// OPTIONAL capability: a miss does not error, it silently falls back to the
// key-only `BatchDeleteSessions`. That is a worse failure mode than a hard one.
// The fallback IS the pre-#9364 bare delete, so a type that stops satisfying the
// interface restores the exact defect this issue removed — the conntrack GC's
// deletes go out bare again, the helper probes every routing instance, and it
// refuses the ones two tenants match (#8636) — with no error anywhere and every
// test that supplies its own double still green.
//
// This is not hypothetical. #9482 is that failure, one interface over: #9344
// moved the daemon's owner-RG exporter to a new method, added it to
// `*dpuserspace.Manager`, and did not add it to `*dpuserspace.LegacyDataPlaneAdapter`
// — the type the userspace backend publishes. The assertion failed on the only
// type it was ever handed and the HA cold-prime bulk sync never ran on any node,
// for days, logging once a minute. The sibling capability in this same file
// (`clusterSyncedSessionInstaller`) happens to be forwarded correctly on the
// adapter today, and has no such belt; it is left alone because widening this
// guard is a separate change with its own blast radius, but the shape is the same
// and this is the record of why.
//
// WHY THIS FILE IS IN pkg/dataplane AND NAMES NO CONCRETE TYPE. It cannot: the
// interface is unexported here and the implementing types live in
// `pkg/dataplane/userspace`, which imports this package — naming them here would
// be an import cycle. So the belt is split, and each half asserts what it can see:
//
//   - HERE: that the store's own fallback path is total, i.e. that the two
//     methods the interface names have the signatures the store calls. A drift in
//     the interface breaks this file.
//   - `pkg/dataplane/userspace/scoped_batch_delete_adapter_9364.go`: that the
//     PUBLISHED adapter satisfies a structurally identical interface. A method
//     removed from the adapter breaks that file.
//
// Neither half alone is sufficient and together they close the seam: the
// interface cannot change without breaking here, and the adapter cannot stop
// implementing it without breaking there.
var _ = sessionDomainBatchDeleter(nil)

// scopedBatchDeleteContract restates the two signatures so a change to either —
// a renamed method, a different element type, a dropped return — is a build
// break rather than a silent downgrade to the bare path.
type scopedBatchDeleteContract interface {
	BatchDeleteSessionsScoped([]ScopedSessionKey) (int, error)
	BatchDeleteSessionsScopedV6([]ScopedSessionKeyV6) (int, error)
}

// The two interfaces must stay structurally identical: anything satisfying the
// contract satisfies the capability the store resolves.
func assertScopedBatchDeleteContract(c scopedBatchDeleteContract) sessionDomainBatchDeleter {
	return c
}

var _ = assertScopedBatchDeleteContract
