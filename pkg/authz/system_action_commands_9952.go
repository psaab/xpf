package authz

import "github.com/psaab/xpf/pkg/optopic"

// SystemActionVerbCommand lives HERE, in the shared authorization package,
// because BOTH local control surfaces dispatch the same verb and must charge it
// the same command (#9952).
//
// It was private to pkg/grpcapi until REST's `deny-commands` gate needed it.
// Copying it would have been the obvious move and it is the one this repo keeps
// paying for: two tables that agree today, drift silently, and each looks right
// on its own. gRPC now reads this one through a one-line alias, so a verb added
// to a handler is charged identically on both surfaces or on neither.
//
// SystemActionVerbCommand maps a SystemAction verb to the canonical operational
// command that sends it.
//
// The verb is NOT the command and cannot be derived from it: `clear-firewall-
// counters` is sent only by `clear firewall all`, `clear-nat-counters` by
// `clear security nat statistics`, and `clear-policy-counters` by
// `clear security policies hit-count`. Three different `clear` subtrees, three
// verb spellings that share a naming convention with none of them.
//
// PREFIX-FORM verbs are absent on purpose and cannot be listed: the handler's
// default branch parses `cluster-failover*` (#5810) and the `userspace-*`
// dataplane control forms out of a packed string, so they have no case label to
// enumerate and no fixed spelling to key. systemActionPermission already
// charges them the destructive floor; 5b must treat a verb with no entry the
// way it treats an unmapped method rather than assuming this table is total
// over what the handler accepts.
//
// The key set is pinned to the handler's own `switch req.Action` in both
// directions by the registry census in pkg/grpcapi (#16136).
//
// SystemActionVerbCommand is DERIVED from the optopic registry (#16136): from the optopic registry (#16136):
// the verb -> command column of pkg/optopic's SystemAction entries. Add
// or reprice a verb in pkg/optopic, not here.
var SystemActionVerbCommand = func() map[string]string {
	entries := optopic.SystemActionEntries()
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.IsPrefix() {
			out[e.Key] = e.Command
		}
	}
	return out
}()
