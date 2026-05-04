# Userspace-DP Worker Supervisor — operator notes

## What it is

The userspace AF_XDP dataplane (`xpf-userspace-dp`) runs N worker
threads (one per binding/queue, configured at startup). Each worker
runs a `worker_loop` that polls XSK rings and drives the per-packet
pipeline (#925 Phase 1).

`worker_loop` is wrapped in `catch_unwind` by a supervisor helper
(`spawn_supervised_worker` in `userspace-dp/src/afxdp/coordinator/mod.rs`).
If a panic escapes the loop body, the supervisor:

1. Catches the panic with `catch_unwind` so it does not propagate
   to the parent thread.
2. Logs the rendered panic payload to journald via `eprintln!`.
3. Stores the panic message in a `Mutex<Option<String>>` per worker.
4. Sets the worker's `WorkerRuntimeAtomics.dead` flag to `true`.
5. Lets the supervised closure return normally (the closure itself
   has `()` return type) — because the panic was caught, the
   worker thread exits cleanly and `JoinHandle::join()` returns
   `Ok(())` rather than `Err(panic_payload)`.

The other workers and the control plane continue running. The dead
worker no longer processes packets — bindings/queues owned by it
stop forwarding. Other bindings keep running.

## How to detect a dead worker

### Prometheus (recommended)

`xpf_userspace_worker_dead{worker_id="<N>"}` is a binary gauge:
- `0`: worker `N` is healthy (no panic caught).
- `1`: worker `N` panicked and the supervisor caught it. Cleared
  only by daemon restart.

Suggested alert:

```yaml
- alert: XpfUserspaceWorkerDead
  expr: xpf_userspace_worker_dead == 1
  for: 30s
  labels: { severity: critical }
  annotations:
    summary: "userspace-dp worker {{ $labels.worker_id }} panicked"
    description: |
      Bindings owned by this worker are no longer forwarding.
      Restart xpfd to recover. Investigation:
        cli show chassis cluster data-plane statistics
      and look for the worker line marked
      `DEAD - panicked: <message>`.
```

The alert latency is bounded by `scrape_interval +
successful control-socket round trip`. Scrape interval is
operator-configured (typically 15–30 s); the control-socket
round trip is bounded by the dial timeout (`2 s`) and request
deadline (`3 s`) in `pkg/dataplane/userspace/process.go`, with
real-world latency well below those bounds. The `for: 30s`
alert clause absorbs both components comfortably.

### CLI / JSON status (deeper diagnosis)

The CoS-aware text formatter renders dead workers inline. The
canonical operator path is:

```
cli show chassis cluster data-plane statistics
```

A dead worker prints as:

```
  <id>   <tid>      DEAD - panicked: <panic_message>
```

For machine-readable output (e.g. piping to jq), the same data is
on the userspace-dp control socket. The control protocol decodes
the request as a JSON `ControlRequest` (see
`userspace-dp/src/protocol.rs::ControlRequest`); the field name
is `type`:

```
incus exec loss:xpf-userspace-fw0 -- bash -lc \
  'echo "{\"type\":\"status\"}" | socat - UNIX-CONNECT:/run/xpf/userspace-dp.sock | jq ".status.worker_runtime[] | select(.dead)"'
```

(See `test/incus/step1-capture.sh` for additional examples of the
same control-socket request shape.)

Both paths return the worker entry with `dead: true` and the
`panic_message` payload that the supervisor captured.

### Log inspection

The supervisor prints to stderr, which systemd routes to journald.
The actual log strings emitted by `spawn_supervised_worker` /
`spawn_supervised_aux` are:

- `xpf-userspace-dp: worker_loop panicked (worker_id=<N>): <message>`
- `xpf-userspace-dp: aux thread '<name>' panicked: <message>`

so:

```
journalctl -u xpfd -g 'panicked'
```

## Why no automatic respawn

#925 acceptance criteria allowed either implementing automatic
respawn or documenting the decision NOT to. We chose NOT to. Three
load-bearing reasons:

1. **Reentrancy hazard.** A panic mid-`poll_binding_process_descriptor`
   leaves the XSK rings, UMEM frame allocator, conntrack entries,
   and CoS scheduler state in an arbitrary state. Re-entering the
   same worker loop without rebuilding all of that risks corruption
   that's worse than the outage. A correct respawn would have to
   tear down and rebuild the binding's state machine end-to-end —
   an operation roughly equivalent to a daemon restart, but
   subtler.
2. **Sticky-failure trap.** If a panic is deterministic (e.g. an
   `assert!` tripwire on a specific config / packet shape /
   session entry), an unconditional respawn loops forever and
   becomes a CPU-hot livelock. Correct sticky-failure detection
   (count panics in a sliding window, mark the binding permanently
   failed after N) deserves its own design pass and is not
   included here.
3. **Operator visibility.** A dead worker that pages once with a
   clear `panic_message` is more actionable than a respawn that
   silently masks the bug. The first failure is the cheapest
   diagnostic moment; we don't want to hide it.

A future Phase 3 (deferred indefinitely, opened only if alert
evidence shows the dead-worker fleet rate is high enough to
justify the design work) could add respawn with sticky-failure
detection and per-binding state rebuild.

## HA interaction

A dead worker on the chassis-cluster primary does **NOT** trigger
chassis-cluster failover. Reasons:

- The chassis-cluster failover state machine watches **node-level**
  liveness (VRRP advertisements + the BPF watchdog map at
  `bpf/headers/xpf_helpers.h`). It does not watch per-worker
  liveness.
- A single dead worker affects only the bindings/queues owned by
  that worker; the other workers continue to forward. Escalating
  to a node-level failover for a partial outage would be a
  regression in HA semantics — every flow on the surviving
  workers would be disrupted.
- If an operator wants node-level escalation for this condition,
  the right path is **operator-driven**: alert on
  `xpf_userspace_worker_dead == 1`, then issue
  `request chassis cluster failover redundancy-group N` from the
  CLI / API. That keeps the policy decision out of the daemon.

The existing `make test-failover` / `make test-ha-crash` harnesses
exercise the VRRP + BPF-watchdog failover paths and are unchanged
by Phase 2.
