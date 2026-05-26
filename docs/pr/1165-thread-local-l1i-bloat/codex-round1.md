**Verdict: PLAN-KILL**

The empirical baseline holds, and #1165’s premise does not reproduce in this release binary. I would not ship code for this issue.

Key evidence:

- Release build succeeded with default features; `debug-log` is not default-enabled: `userspace-dp/Cargo.toml:6-8`.
- `nm --print-size --radix=d ... | grep RUST_STD_INTERNAL_VAL | grep xpf_userspace_dp` returned only:
  - `SEG_MISS_LOG`, 4 B, from `userspace-dp/src/afxdp/tx/dispatch.rs:403-406`
  - `PENDING_FILTER_COUNTER_RECORD`, 40 B, from `userspace-dp/src/filter/mod.rs:327-329`
- Function sizes match the plan: `worker_loop` 47,735 B, `poll_binding_process_descriptor` 71,056 B, `drain_pending_tx` 6,930 B, `enqueue_pending_forwards` 15,161 B.
- `objdump -d ... | grep -c __tls_get_addr` returned `0`.

The `cfg!(feature = "debug-log")` DCE claim is real. `BUILD_FWD_DBG_COUNT` sits under `if cfg!(feature = "debug-log")` at `userspace-dp/src/afxdp/frame/mod.rs:383-409`; the actual body is in `build_forwarded_frame_into_from_frame`, starting at `userspace-dp/src/afxdp/frame/mod.rs:218`. In the release binary, `nm ... | grep BUILD_FWD_DBG_COUNT` had no output, `strings ... | grep 'DBG BUILT'` had no output, and disassembly of that function had no `_eprint`, `BUILD_FWD_DBG_COUNT`, `DBG BUILT`, or `__tls_get_addr`.

The CPU-reality framing is not applicable to this binary. The only surviving logging TLS site is behind the segmentation-miss branch at `userspace-dp/src/afxdp/tx/dispatch.rs:397-425`, and that branch is gated by `count_forwarded_tcp_segmentation_miss_if_needed`, which returns false unless `!copied_source_frame && tcp_segmentation_needed` at `userspace-dp/src/afxdp/tx/dispatch.rs:1437-1448`. That is not “per-packet TLS lookup on the 14.8M pps path.” `PENDING_FILTER_COUNTER_RECORD` is structural batching, not logging telemetry: `userspace-dp/src/filter/mod.rs:346-364`.

Change 1 is also weaker than the plan claims. I tested a throwaway `/dev/shm` implementation matching the plan’s outlined helper shape. `enqueue_pending_forwards` grew from `15,161 B` to `15,360 B`; the new `log_seg_miss_cold` was `261 B`; `__tls_get_addr` stayed `0`. That fails the plan’s own pass criterion at `docs/pr/1165-thread-local-l1i-bloat/plan.md:299-302`. It also moves the `egress_mtu` lookup out of the existing `if n < 20` guard at `userspace-dp/src/afxdp/tx/dispatch.rs:407-414`, exactly as the plan sketches at `docs/pr/1165-thread-local-l1i-bloat/plan.md:198-209`, so post-20 segmentation misses would still pay the map lookup before entering the cold helper.

Pattern check: yes, this is the #944-style “perf issue does not reproduce on current codebase” case. The local precedent is explicit: `docs/pr/944-p128-ceiling/diagnostic.md:9-14` closes as needs-no-fix because the reported ceiling did not reproduce. Same call here: close with the empirical writeup, no code change.

Codex session ID: 019e658a-5571-7b42-a7ff-877d007008d9
Resume in Codex: codex resume 019e658a-5571-7b42-a7ff-877d007008d9
