# pkg/ra

Embedded IPv6 Router Advertisement sender. Replaces external `radvd`
with per-interface goroutines built on `mdlayher/ndp`. Handles startup
burst, goodbye RAs, and re-burst recovery after RETH MAC link-cycle.

## Entry points

- `Manager` — `ra.go:17`.
- `New()` — `ra.go:23`.
- `Apply(cfg)` — `ra.go:31`. Starts/stops per-interface senders.
- `Withdraw(ifname)` — `ra.go:100`. Stop sending on one interface.
- `ResendBurst(ifname)` — `ra.go:117`. Re-send the startup burst (used
  after a link cycle).
- `WithdrawOnce(ifname)` — `ra.go:150`. Send a single goodbye RA
  (lifetime=0).
- `Status()` — `ra.go:210`. Per-interface SenderInfo.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Link DOWN→UP during a RETH MAC cycle kills the AF_PACKET socket.
  `ResendBurst()` is what closes that gap — without it, hosts see an RA
  outage from the moment of the link cycle until the next periodic RA.
- The goodbye RA carries router lifetime 0, telling hosts to drop this
  router as default gateway. Send one when explicitly withdrawing a zone
  or shutting down.
- IPv6 NODAD is set on the per-instance NDP socket so it doesn't fight
  the kernel's own duplicate-address detection on the link-local
  address.
- Per RFC 5798, `AdvertiseInterval` is stored in milliseconds but goes
  on the wire in centiseconds. Don't double-convert.
