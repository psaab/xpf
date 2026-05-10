# pkg/rpm

Real-time Performance Monitoring probes (ping, TCP, HTTP). Tracks RTT
and jitter, emits events for the event-options engine, and binds probes
to VRFs via `SO_BINDTODEVICE` when configured.

## Entry points

- `Manager` — `rpm.go`.
- `ProbeResult` — `rpm.go`. Per-test metrics (RTT, jitter,
  success/fail counters).
- `Event` — `rpm.go`. `test_failed`, `probe_failed`, `test_completed`.
- `New()` — `rpm.go`.
- `Apply(ctx context.Context, cfg *config.RPMConfig)` — `rpm.go`.
- `StopAll()` — `rpm.go`.
- `Results()` — `rpm.go`.
- `SetEventCallback(fn)` — `rpm.go`.

## Callers

`pkg/daemon`, `pkg/eventengine`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config` only.

## Gotchas

- VRF binding is set in the dialer's control function via
  `SO_BINDTODEVICE` to `vrf-<ri-name>` — not on the destination interface
  itself.
- Events expose both the test owner (probe name) and the test name so
  event-options policies can match on either via `attributes-match`.
- A consecutive-failure counter discriminates transient blips from
  sustained failures; `test_failed` only fires when the threshold is
  crossed, not on every individual missed probe.
