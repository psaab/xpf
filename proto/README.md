# proto/

Protobuf service and message definitions for the gRPC API. The wire
contract between `cmd/xpfd` (server, via `pkg/grpcapi`) and `cmd/cli`
(client).

## Layout

`xpf/v1/` — versioned namespace. `BpfrxService` is the only service
today; ~48 RPCs.

## Pinned generator versions

These constants are the recorded source of truth checked by
`make proto-check` (`scripts/proto_header_check.py`, hermetic: file
reads only, no network/protoc). `go install` paths pin the plugins;
`protoc` itself has no `go install` path, so CI fetches its pinned
release zip — `go.mod` tool directives cannot pin it.

- `protoc` v3.21.12
- `protoc-gen-go` v1.36.11
- `protoc-gen-go-grpc` v1.6.1

`protoc-gen-go` must equal `google.golang.org/protobuf` in `go.mod`
(the module that ships it). `protoc-gen-go-grpc` is released on the
`google.golang.org/grpc/cmd/protoc-gen-go-grpc` submodule version line
(currently v1.6.1), not the `google.golang.org/grpc` module version in
`go.mod` (v1.78.0), so its constant lives only here and in the header.
Install the pinned plugins with:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1
```

## Regeneration

```bash
PATH=$PATH:$HOME/go/bin make proto
```

Regenerates the Go stubs into `pkg/grpcapi/xpfv1/` (`xpf.pb.go`,
`xpf_grpc.pb.go`) with the ambient `protoc`/plugins. Use the pinned
versions above, or the regen silently re-stamps the headers.

`make proto-check` (hermetic) fails when a header stamp disagrees
with the constants above or with `go.mod`. That check cannot see a
`.proto` edited without regeneration (the stamps still match), so CI
additionally runs `make proto-regen-check`
(`scripts/proto_regen_check.sh`): it regenerates with the pinned
`protoc`/plugins above and fails on any diff against the checked-in
stubs. That leg needs the pinned toolchain/network and is CI-only —
never a local prerequisite.

## RPC categories

- **Config lifecycle:** `EnterConfigure`, `ExitConfigure`, `Set`,
  `Delete`, `Load`, `Commit`, `CommitCheck`, `CommitConfirmed`,
  `ConfirmCommit`, `Rollback`, `ShowConfig`, `ShowCompare`,
  `ShowRollback`, `ListHistory`.
- **Operational queries:** `GetStatus`, `GetGlobalStats`, `GetZones`,
  `GetPolicies`, `GetSessions`, `GetSessionSummary`, `GetNATSource`,
  `GetNATDestination`, `GetScreen`, `GetEvents`, `GetInterfaces`,
  `ShowInterfacesDetail`, `GetDHCPLeases`, `GetRoutes`,
  `GetOSPFStatus`, `GetBGPStatus`, `GetRIPStatus`, `GetISISStatus`,
  `GetIPsecSA`, `GetNATPoolStats`, `GetNATRuleStats`, `GetVRRPStatus`,
  `MatchPolicies`.
- **Diagnostics (server-streaming):** `Ping`, `Traceroute`.
- **Monitoring (server-streaming):** `MonitorPacketDrop`,
  `MonitorInterface`.
- **Mutations:** `ClearSessions`, `ClearCounters`,
  `ClearDHCPClientIdentifier`.
- **Generic:** `ShowText` (catch-all for schedulers, snmp, dhcp-relay,
  firewall, alg).
- **System:** `GetSystemInfo`, `SystemAction` (reboot / halt).
- **Tab completion:** `Complete`.

## Versioning

The `v1` directory is the contract version. Breaking changes require
`v2` alongside; the server can support both for a deprecation window.
Don't add fields with new tag numbers below 16 unless you really need
the wire-size win — protobuf reserves 1–15 for the most common fields,
and bumping a hot field above 15 is a one-byte regression per message.
