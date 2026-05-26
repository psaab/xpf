# #1437 — Eliminate Handshake Allocation Path in `construct_outer_frame_allocated`

## Status

**DRAFT v1 — PROPOSED PLAN-KILL, pending adversarial confirmation**

## Issue framing

Issue #1437 asks us to remove the `vec![0u8; 14 + ip_len]` heap
allocation inside `construct_outer_frame_allocated` at
`userspace-dp/src/afxdp/wireguard.rs:450-545`, and to change the
`WireGuardDecapResult::control_frame: Option<Vec<u8>>` field into
a (offset, length) reference into a preallocated scratch buffer.

The motivation is the standing "no hot-path allocation" mandate
in `docs/engineering-style.md`.

## Discovery: target code does not exist on master

The issue references three concrete symbols. Each was checked
against `origin/master` at commit `936b076d` (worktree base):

| Symbol referenced by issue                  | Exists on master? |
| ------------------------------------------- | ----------------- |
| `userspace-dp/src/afxdp/wireguard.rs`       | **No.**           |
| `construct_outer_frame_allocated`           | **No.**           |
| `WireGuardDecapResult` (with `control_frame: Option<Vec<u8>>`) | **No.** |
| `boringtun` dependency / `TunnResult` shape | **No.**           |
| `vec![0u8; 14 + ip_len]` at the cited site  | **No.**           |

Evidence:

```
$ grep -rn "construct_outer_frame\|WireGuardDecapResult\|14 + ip_len" \
    --include='*.rs' .
(no results)

$ grep -rn "boringtun\|TunnResult" --include='*.rs' .
(no results)

$ git ls-tree master userspace-dp/src/afxdp/ | grep -i wireguard
(no results)

$ git ls-tree master userspace-dp/src/afxdp/wg/
allowed_ips.rs  dscp.rs  engine.rs  framing.rs  mod.rs
mss.rs  outer.rs  peer.rs  scratch.rs  session.rs  tests.rs
```

The original `wireguard.rs` file (#1432, boringtun-based) was
never merged to master — its replacement PR #1499 ("clean-room
dataplane termination, snow-based") landed instead, as commit
`49a29cf6`. PR #1499's diff against its parent shows it
**created** the `wg/` directory; there was no `wireguard.rs`
file to delete because the boringtun work never reached master.

## Why this is a PLAN-KILL, not "implement the refactor on the new code"

The natural next question is: "OK, the file moved — find the
analogous alloc in the new `wg/` module and kill it there."
That does not apply here either, for two independent reasons:

### Reason 1: the new engine does not emit control frames at all

Per `userspace-dp/src/afxdp/wg/mod.rs:8-9`:

> Scope of this PR: engine, framing, allowed-IPs trie, helpers,
> and unit tests. Hot-path activation in `tx/dispatch.rs` and
> `poll_descriptor.rs` is intentionally deferred — see the plan
> doc for the rationale.

The current engine's public API is:

- `try_encap(peer_pubkey, inner_ip, &mut out) -> EncapOutcome` —
  writes the encrypted **transport data** record into the
  caller's `out` buffer. No allocation.
- `try_decap(wg_record, &mut out) -> DecapOutcome` — writes the
  decrypted **transport data** plaintext into the caller's `out`
  buffer. No allocation. No `control_frame` field.
- `build_initiator_handshake() / build_responder_handshake()` —
  returns a `snow::HandshakeState`. The caller drives the
  handshake by calling `HandshakeState::write_message` /
  `read_message` directly — i.e. the handshake-bytes
  construction is **not yet implemented inside the engine**.

The integration layer that will eventually call those snow APIs
and pack the resulting bytes into Ethernet/IP/UDP frames is
also not yet written (the cross-reference is `TODO(#1499 r4 /
integration PR)` at `engine.rs:807`).

There is no `construct_outer_frame_allocated` to eliminate
because there is no outer-frame construction code yet. The
allocation the issue wants gone is in code that has not been
written.

### Reason 2: when the integration layer is written, the alloc is already designed out

`userspace-dp/src/afxdp/wg/scratch.rs:18-34` already exists:

```rust
pub(crate) struct WgWorkerScratch {
    pub(crate) encap_out: RefCell<Vec<u8>>,  // sized once to max_frame
    pub(crate) decap_out: RefCell<Vec<u8>>,  // sized once to max_frame
}
```

with the documented contract (lines 2-5):

> No `vec![]` in encap/decap. The buffers are sized once at
> worker init and reused for every packet.

The integration PR cited by `mod.rs:7-9` and the `engine.rs:807`
TODO is explicitly chartered to wire this scratch into
`tx/dispatch.rs` and `poll_descriptor.rs`. The alloc-elimination
that issue #1437 demands is structurally enforced by the
already-merged `WgWorkerScratch` design — it is impossible to
land the integration PR with a `vec![0u8; 14 + ip_len]` on the
hot path without explicitly bypassing the scratch type. Any such
bypass would be caught by the same triple-review process this
PR is being driven through.

In other words: **the design that #1437 asks for is already
locked in by the merged #1499 code. There is nothing to do.**

## Risk assessment

| Class | Verdict |
| ----- | ------- |
| Behavioral regression risk | N/A — no behavior change proposed |
| Lifetime / borrow-checker risk | N/A |
| Performance regression risk | N/A |
| Architectural mismatch risk | **HIGH** — this is the exact #946-Phase-2 / #961 pattern. The issue targets an architecture (boringtun-based `wireguard.rs` with `Option<Vec<u8>> control_frame`) that no longer exists on master. Shipping a PR against the current `wg/` module would be wrong-target work. |

## Cross-reference to the Wave-1 mandate

The user's wave-1 instructions say:

> **PRIMARY GOAL**: eliminate the allocation. Read the issue
> body for the specific Box/Vec/String the issue wants gone.

Read literally, the issue wants
`let mut out = vec![0u8; 14 + ip_len];` at
`wireguard.rs:450-545` gone. That line does not exist anywhere
in `origin/master`. The same instructions also say:

> Reuse existing scratch/arena buffers if possible. Look at how
> the non-allocated path constructs frames and mirror that.

The non-allocated path **is** the only path — `WgWorkerScratch`
is already the mirror.

## Recommended outcome

PLAN-KILL with rationale recorded on the issue. The follow-up
work is structural and already tracked:

1. Issue #1437 should be **closed as overtaken by #1499**.
   The boringtun-based architecture it was filed against
   never merged.

2. When the integration PR (`tx/dispatch.rs` /
   `poll_descriptor.rs` wiring per `wg/mod.rs:8-9` and
   `engine.rs:807`) lands, hot-path-alloc enforcement is
   already implicit in the existing `WgWorkerScratch`
   contract. No separate "eliminate alloc" PR is needed.

3. If, when that integration PR lands, an outer-frame helper
   *is* written and *does* allocate, file a fresh issue against
   the actual `file.rs:line:line` of the new code. Issue #1437
   cannot be retargeted because its body cites a specific file,
   line range, type name, and field name — none of which exist.

## Open questions for adversarial review

This plan asks the reviewers to **verify the PLAN-KILL**, not
to bless an implementation. Specifically:

1. Does `grep -rn "construct_outer_frame\|WireGuardDecapResult"
   userspace-dp/src/` on `origin/master` at commit `936b076d`
   really return zero hits? (If you find a match anywhere in
   the tree, the kill is wrong.)

2. Is `userspace-dp/src/afxdp/wg/mod.rs:8-9`'s claim that
   hot-path activation is deferred to a future integration PR
   accurate, or is there a hidden activation site I missed?

3. Is `WgWorkerScratch` (`scratch.rs:18-34`) the only legitimate
   buffer-reuse mechanism for the future integration, or does
   the codebase have a different convention (e.g. a UMEM-frame-
   based path) that we should call out here so the integration
   PR uses it?

4. Is closing #1437 the right disposition, or should it be
   relabeled and held against the integration PR as a checklist
   item?

5. Most important — is there ANY interpretation under which
   #1437 is implementable against the current master without
   us first having to invent the missing
   `construct_outer_frame_allocated` ourselves? (If yes, that
   invention is the work, and the alloc-kill is a five-line
   afterthought. The issue would still be wrong-target as
   written.)

## Out of scope (explicitly)

- Rewriting #1437's body to target the new `wg/` module — that
  is a scope change, not a refactor.
- Pre-emptively writing the `tx/dispatch.rs` / `poll_descriptor.rs`
  integration layer. That is a substantially larger piece of
  work owned by the #1499 follow-up plan.
- Touching `WgWorkerScratch`. It already encodes the
  no-allocation contract; modifying it without an integration-
  layer caller is premature.
