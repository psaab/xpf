// Package fortestcensus holds the *ForTest* hook liveness census (#17342).
//
// A `func ...ForTest...` in non-test Go code is a test seam. One that nothing
// calls is dead code whose doc comment still claims a test exercises it. The
// census (census_test.go) parses the whole module with go/parser and counts a
// hook LIVE only when an identifier in Go code resolves to it: comments and
// string literals are not identifiers, so neither can keep a hook alive.
// Hooks are identified by package directory, receiver type and name, so two
// packages' same-named hooks (Monitor.SetTickForTest in pkg/clockskew and
// pkg/natpoolalarm) are counted separately. A dead hook must be listed in
// scripts/go-fortest-liveness.allow with the file that defines it and a
// reason; a row whose hook gained a caller, moved, or is gone fails.
package fortestcensus
