// Package userspace map-name registry.
//
// These constants enumerate every BPF map name consumed by the
// userspace control plane (maps_sync.go, process.go, manager_ha.go)
// so map-name drift inside this Go package becomes a CI / test-time
// failure via the regression canaries in maps_decouple_test.go
// rather than a runtime "map not loaded" error at helper bringup.
// (Copilot r1: prior wording overstated this as "compile-time"; the
// enforcement is via go test, not the compiler.)
//
// Scope of guarantee:
//
//   - Catches new literal reintroductions inside
//     pkg/dataplane/userspace/ via the AST canary, including
//     const-ident aliases (local block or top-level, package-wide),
//     concatenation folds, parenthesized selectors, method aliases,
//     raw string literals, and Unicode-whitespace-padded forms.
//   - Does NOT prevent drift against the Rust helper's BPF object
//     names (defined in userspace-xdp/src/lib.rs via #[map(name=
//     "...")] attributes) or against the legacy loader's literals
//     in pkg/dataplane/loader_ebpf.go (the loader side keeps its
//     own duplicates until #1476 retires the loader).
//   - The dup-loader parity canary in maps_decouple_test.go pins
//     the two sides together during the #1476 window so a rename in
//     either side is caught at test time, not at bringup time.
//   - Out-of-scope bypasses (deliberate-attacker, not accidental
//     drift): constructing a map name via byte-slice
//     (`string([]byte{'u','s',...})`) or via struct-tag reflection
//     redirection — these require intent to bypass the canary and
//     are not patterns that arise from refactor accident. AGY r4
//     §II.3 / §II.4 documented these as acceptable residual.
//
// Issue: #1521 (sub-#1451 S6, blocks #1476).
package userspace

const (
	// Control / liveness maps consumed at helper bringup.
	mapNameUserspaceCtrl      = "userspace_ctrl"
	mapNameUserspaceBindings  = "userspace_bindings"
	mapNameUserspaceHeartbeat = "userspace_heartbeat"
	mapNameUserspaceXSK       = "userspace_xsk_map"
	mapNameUserspaceCPUMap    = "userspace_cpumap"
	mapNameUserspaceSessions  = "userspace_sessions"

	// Per-interface address, ingress-zone, and NAT maps consumed at snapshot apply.
	mapNameUserspaceIngressIfaces   = "userspace_ingress_ifaces"
	mapNameUserspaceLocalV4         = "userspace_local_v4"
	mapNameUserspaceLocalV6         = "userspace_local_v6"
	mapNameUserspaceInterfaceNATv4  = "userspace_interface_nat_v4"
	mapNameUserspaceInterfaceNATv6  = "userspace_interface_nat_v6"
	mapNameUserspaceWgIngressZones  = "userspace_wg_ingress_zones"
	mapNameUserspaceWgZoneAdmission = "userspace_wg_zone_admission"
	// userspace_ingress_ifaces is a one-byte bitset: bit 0 marks a live
	// adjudicated ingress, bit 1 marks VID 0 as unowned on a tagged-only bind.
	userspaceIngressIfaceFlagAdjudicated uint8 = 1
	userspaceIngressIfaceFlagTaggedOnly  uint8 = 2
	// Pinned BPF map name retained as a documented mixed-version
	// compatibility exception per PR #1514 (Refs #1509). Operator-
	// facing terminology is "degraded path" but the pinned map name
	// stays stable to preserve the rolling-upgrade window until the
	// canary alias retires. The cap test in maps_sync_cap_test.go
	// pins this string value verbatim.
	mapNameUserspaceShimDegradedStats = "userspace_fallback_stats"
)
