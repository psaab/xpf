# #1441 — Modularize WireGuardEngine into Dedicated Submodules

**Status:** PLAN-KILLED at v1 (Claude SMR self-audit, pre-dispatch).

## Issue framing

The issue requests breaking up a 730-LOC monolithic file at
`userspace-dp/src/afxdp/wireguard.rs` into submodules: `mod.rs`,
`config.rs`, `trie.rs`, plus moving packet inspection to
`frame/inspect.rs`.

## PLAN-KILL rationale

The target file does NOT exist on master.

Verification on `origin/master` (current HEAD `cd048d2f`):

```
$ git ls-tree -r origin/master --name-only | grep -iE 'wireg|^.*/wg/'
docs/pr/wireguard-clean/plan.md
userspace-dp/src/afxdp/wg/allowed_ips.rs
userspace-dp/src/afxdp/wg/dscp.rs
userspace-dp/src/afxdp/wg/engine.rs
userspace-dp/src/afxdp/wg/framing.rs
userspace-dp/src/afxdp/wg/mod.rs
userspace-dp/src/afxdp/wg/mss.rs
userspace-dp/src/afxdp/wg/peer.rs
userspace-dp/src/afxdp/wg/scratch.rs
userspace-dp/src/afxdp/wg/session.rs
userspace-dp/src/afxdp/wg/tests.rs

$ git log --oneline origin/master -- userspace-dp/src/afxdp/wireguard.rs
(empty — file never committed to master)
```

PR #1499 (clean-room WireGuard engine, commit `49a29cf6`) landed the
modular layout directly: it never went through the monolithic
intermediate the issue describes. The structure on master already
matches — and exceeds — what the issue proposes:

| Issue prescription                                | Status on master                                           |
|---------------------------------------------------|------------------------------------------------------------|
| Move to `wg/mod.rs` (entry/coordination)          | DONE (`wg/mod.rs`, 105 LOC)                                |
| Move to `wg/config.rs` (peer reconciliation)      | DONE as `wg/peer.rs` (119 LOC) + `WgEngine::reconcile_peers`|
| Move to `wg/trie.rs` (LPM AllowedIPs)             | DONE as `wg/allowed_ips.rs` (291 LOC)                      |
| Move packet inspection to `frame/inspect.rs`      | Partial: outer-header serialization consolidated into `frame/headers.rs` by PR #1440 (`63dfe02a`); WG-specific inner parsing stays in `wg/framing.rs` (151 LOC) + `wg/mss.rs` (184 LOC) where it composes with the AEAD path |
| Decoupled unit tests                              | DONE (`wg/tests.rs`, 1390 LOC; engine.rs in-file tests are session/install-specific and properly colocated) |

## What's actually in `wg/engine.rs` today (1725 LOC)

- Lines 1-919: production code (~840 LOC after stripping comments)
  - `PeerTable` (`Vec<Arc<Peer>>` + `peer_index_by_pubkey` + `allowed_ips`)
    held behind `ArcSwap<PeerTable>` for atomic triple-swap. The struct
    doc explicitly forbids splitting these into independent locks
    because hot-path readers must observe them as a unit.
  - `WgEngine` struct: `local_private_key` (Zeroizing) +
    `listen_port` + `table` (ArcSwap) + `reconcile_lock` +
    `sessions_by_local_index` (RwLock demux map).
  - Slow-path API: `new`, `reconcile_peers`, `install_session`,
    `build_initiator_handshake`, `build_responder_handshake`.
  - Hot-path API: `try_encap`, `try_decap`.
  - Two inner-IP helpers (`inner_ip_len_after_decap`, `inner_src_ip`)
    that compose into `try_decap`'s AllowedIPs gate.
- Lines 920-1725: `#[cfg(test)]` mod (~800 LOC) covering
  session-install, peer-reconcile-vs-install races, encap reject
  paths. These tests directly exercise `WgEngine` internal state and
  are correctly colocated.

There is no clean further-extraction axis. The `WgEngine` struct
deliberately fuses key material + peer routing + session demux to
preserve the atomicity property documented in the `PeerTable` doc
comment (lines 217-231 of `engine.rs`):

> Holding three independent RwLocks does NOT give that property:
> a reader can release the index lock, the reconciler can swap,
> and then the reader can acquire the peers lock on the new state.

Splitting `WgEngine` into "engine" + "config reconciler" + "session
demuxer" submodules would just shuffle the same fused state across
files with `pub(super)` accessors and yield no test, perf, or
review-surface improvement.

## Precedent

This is the same pattern as **#1437** ("Eliminate Handshake
Allocation Path"), which was PLAN-KILLED because the target file
location (`afxdp/wireguard.rs:450-545`) did not exist on master.
Both #1437 and #1441 were filed against a pre-#1499 codebase that no
longer exists.

## Hot-path / no-alloc contract preserved

`WgWorkerScratch` at `wg/scratch.rs:1-63` is intact on master. Any
future engine.rs decomposition (if motivated by a fresh observation)
must still preserve "No `Vec<u8>` allocation in encap/decap" — but
since this plan is killed, there is no change to scrutinize against
that contract.

## Disposition

Close #1441 as "already done by #1499". No PR, no smoke, no merge.
