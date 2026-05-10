# proto/

Protobuf service and message definitions for the gRPC API. The wire
contract between `cmd/xpfd` (server, via `pkg/grpcapi`) and `cmd/cli`
(client).

## Layout

`xpf/v1/` — versioned namespace. `BpfrxService` is the only service
today; ~48 RPCs.

## Regeneration

```bash
PATH=$PATH:$HOME/go/bin make proto
```

Regenerates the Go stubs into `pkg/grpcapi/xpfv1/` (`xpf.pb.go`,
`xpf_grpc.pb.go`). The generator is in PATH after a Go install of
`protoc-gen-go` and `protoc-gen-go-grpc`.

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
