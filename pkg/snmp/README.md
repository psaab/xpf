# pkg/snmp

SNMPv2c and SNMPv3 agent. Responds to GET / GETNEXT / GETBULK on
ifTable, ifXTable, and a small set of system OIDs. Also sends link-up /
link-down traps. ASN.1 BER encoding is hand-coded, no external library.

## Entry points

- `Agent` — `agent.go`.
- `IfData` — `agent.go`. Per-interface metrics (name, MTU, speed,
  admin/oper status, octets, errors, drops).
- `V3UserDisplay` — `v3.go`.
- `NewAgent(cfg *config.SNMPConfig) *Agent` — `agent.go`.
- `Start()` — `agent.go`.
- `Stop()` — `agent.go`.
- `SetIfDataFn(fn)` — `agent.go`. Caller-supplied accessor for live
  interface data.
- `NotifyLinkUp` / `NotifyLinkDown` — `traps.go`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## ASN.1 specifics

- Tag constants used: Counter32 (0x41), Gauge32 (0x42), Counter64 (0x46).
- Exception values: `noSuchObject` (0x80), `noSuchInstance` (0x81),
  `endOfMibView` (0x82) — emitted for missing OIDs in walks.
- GETNEXT walking order is driven by a static OID list; it must stay in
  ascending order.

## Gotchas

- Maximum response packet size is 4096 bytes. GETBULK may legitimately
  require multiple responses.
- Traps fire immediately on link-state change — they aren't queued, so
  back-to-back link flaps produce back-to-back traps.
- Don't add a third BER library to this package. The hand-coded encoder
  is intentional; keeping the surface small avoids bringing in an SNMP
  framework with its own poll loop and threading model.
