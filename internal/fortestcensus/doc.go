// Package fortestcensus holds the exported *ForTest* seam rule (#17342).
//
// The deadcode gate (scripts/go-deadcode-gate.sh) reports an uncalled
// package function and an uncalled unexported method, but an uncalled
// EXPORTED method on a live type reads reachable to it, so a dead exported
// test seam escapes. This rule is the guard for that class, and it is purely
// syntactic: every exported func, method or interface method in non-test Go
// code whose name contains "ForTest" (ForTesting too) needs a row in
// scripts/go-fortest-seams.allow naming its package directory, receiver and
// name, with a one-line reason; a row naming no such seam fails. It counts no
// references. Unexported seams are left to the deadcode gate.
package fortestcensus
