package grpcapi

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Cross-package compile-time interface-satisfaction guards (#1516
// Copilot r3 finding). The compile-time assertion in
// pkg/dataplane/userspace/legacy_dataplane.go only verifies that
// LegacyDataPlaneAdapter has the method shape of an inline
// anonymous interface. It does NOT detect drift if the unexported
// interfaces (grpcRuntime, sessionCursorIterator, userspaceStatusProvider,
// userspaceFIBProvider, userspaceControlProvider) acquire a new method that
// LegacyDataPlaneAdapter no longer satisfies — the userspace package can't
// import grpcapi for that interface name.
//
// pkg/grpcapi CAN import pkg/dataplane/userspace (the dependency
// already exists via Config.DP's runtime type and the named
// provider probes), so the asymmetric guard lives here: pin the
// adapter against each unexported interface so a build failure
// here makes the drift impossible to miss.
//
// These are *_test.go-scoped to avoid bloating the production
// binary's symbol table with assertion-only references.
var (
	_ grpcRuntime              = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ sessionCursorIterator    = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ userspaceStatusProvider  = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ userspaceFIBProvider     = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ userspaceControlProvider = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
)
