# #1445 Consolidate Key Generation and Verification Logic — PLAN-KILL at study time

**Status:** PLAN-KILLED at study time (pre-reviewer) — target code does not
exist in the repository. Base commit: `cd048d2f` on `origin/master`
(2026-05-26 21:41 UTC).

## Verdict

PLAN-KILL. The refactor target — duplicated WireGuard / X25519 key
generation and verification logic across `pkg/config`, `pkg/cli`, and
`pkg/dataplane/userspace` — **does not exist in the codebase as of
`cd048d2f`**. Every concrete call site enumerated in the issue body
points either past the end of the cited file or to code that is not
present at the cited lines. There is nothing to consolidate.

This is the same pattern as #946 Phase 2 and #961 PacketContext: a
"Refactor: <Pattern>" issue whose architectural premise does not match
the codebase reality. Per the triple-review skill's standing rule —
"`Refactor: <Pattern>` issues that don't fit the codebase reality
SHOULD be killed at plan time" — and the project memory entry
*"difficult-path pragmatism"* — *"stop and report rather than ship a
wrong-target PR"* — this is killed before plan-review.

## Issue claims vs codebase reality

The issue body cites three concrete locations and three concrete
duplicated functions. Verification against the worktree at
`refactor/1445-key-gen-consolidate` (branched from
`origin/master @ cd048d2f`):

### Claim 1: `pkg/config/compiler_security.go:760-782` — `validatePrivateKey`

- **File length:** 753 lines (cited range starts past EOF).
- **`grep -n "validatePrivateKey" pkg/config/compiler_security.go`:** no match.
- **`grep -n "PrivateKey\|base64\|x25519\|wireguard\|crypto/rand"
  pkg/config/compiler_security.go`:** no match.
- **`head -7` import block:** only `fmt` and `strconv`. No crypto, no
  encoding/base64, no curve25519, no nacl, no anything that could host
  the cited validator.

### Claim 2: `pkg/cli/cli_request.go:1019-1044` — `handleRequestSecurityWireGuard`

- **File length:** 1010 lines (cited range starts past EOF).
- **`grep -n "handleRequestSecurityWireGuard\|WireGuard\|x25519\|PrivateKey"
  pkg/cli/cli_request.go`:** no match.
- **Imports:** `context, fmt, net, os, os/exec, strconv, strings, time`
  plus project internals (`cluster`, `dpuserspace`, `routing`). No
  crypto packages. The file handles `request` operational commands
  (ping, route lookup, IPsec SA termination, etc.), not key generation.

### Claim 3: `pkg/dataplane/userspace/snapshot.go:2396-2411` — `deriveWgPublicKey`

- **File length:** 2404 lines (cited range starts past EOF).
- **`grep -n "deriveWgPublicKey\|WgPublicKey\|x25519\|curve25519\|base64\.\(NewDecoder\|StdEncoding\)\.DecodeString" pkg/dataplane/userspace/snapshot.go`:** no match.
- **Lines 2380-2404 (cited tail):** netlink NUD-state stringifier
  (`reachable`/`stale`/`delay`/`probe`/`failed`/`noarp`/`incomplete`),
  not key derivation.
- **Imports of the file:** `crypto/sha256` is the only crypto package,
  used to hash configuration snapshots for change detection — not for
  X25519 key handling.

### Independent codebase-wide search

To make sure the functions don't live elsewhere under different names:

```
grep -rln "wireguard\|WireGuard\|WIREGUARD" --include='*.go'
  → pkg/dataplane/userspace/protocol.go    (only match)
grep -rn "validatePrivateKey\|handleRequestSecurityWireGuard\|
         deriveWgPublicKey\|GenerateX25519\|DeriveX25519\|
         ValidateX25519" --include='*.go'
  → (no matches)
grep -rin "x25519\|curve25519" --include='*.go'
  → pkg/dataplane/userspace/protocol.go    (only match — string
                                            "X25519" in field doc
                                            comments)
```

The single hit is `pkg/dataplane/userspace/protocol.go` lines 240-261,
which defines **JSON wire-protocol fields** (`WgLocalPrivkeyHex`,
`WgPeerPubkeyHex`) for the planned WireGuard clean-room termination
feature. The comment header explicitly says
*"WireGuard clean-room termination (see docs/pr/wireguard-clean/plan.md)"* —
i.e., this is a tag for a feature that has not yet been built. No
generation, validation, or derivation code exists; these fields are
literally just `string` JSON keys passed through to a Rust dataplane
helper that itself does not yet implement the termination.

### Adjacent crypto code in the repository

For completeness, the only "key" crypto code that does live in the Go
control plane is **configstore master-password encryption**:

- `pkg/configstore/crypto.go` — HKDF + AES-GCM envelope for encrypted
  config-tree JSON, with PRF selection driven by
  `set system master-password pseudorandom-function <hmac-sha2-{256,
  384,512}|hmac-sha1>`. This is completely unrelated to WireGuard
  X25519 keys: it operates on the Junos master-password tree node,
  uses HMAC PRFs (not curve25519), and serves the config-store
  encryption path, not a CLI key generator.
- `pkg/configstore/dataplane_retire.go:104` already audits
  `FindChild`-first-match (the memory note cited in the standing
  rules). No action needed in *this* PR.

There is no WireGuard key code adjacent to (or shadowed by) the
master-password code that this PR could plausibly be aimed at.

## Why this is a kill, not a "consolidate something else"

The triple-review skill explicitly forbids retargeting:

> **"Refactor: <Pattern>" issues that don't fit the codebase reality
> SHOULD be killed at plan time.** #946 Phase 2, #961 PacketContext
> both died this way. Don't push through a wrong-target architecture.

Memory entry *"difficult-path pragmatism"* reinforces:

> for "Refactor: <Pattern>" issues proposing large rearchitectures,
> stop and report rather than ship a wrong-target PR; #961/#946/#963/
> #1144 all hit this

The only consolidation that would be technically valid here would be a
hypothetical pre-implementation of the X25519 key utilities so that
*when* the WireGuard clean-room termination feature lands, its key
generation/derivation/validation lives in a shared package. That is
not what #1445 asks for — #1445 explicitly says "Refactor all call
sites in `compiler_security.go`, `cli_request.go`, and `snapshot.go`
to invoke this consolidated package", which assumes the call sites
exist. Building the consolidated package without callers would create
dead code that the actual WireGuard implementation PR is then free to
ignore or replace with a different shape.

## Recommendation

Close #1445 as `wontfix: target does not exist`. If/when the
WireGuard clean-room termination feature (docs/pr/wireguard-clean/
plan.md) is implemented, the consolidated key-handling helper should
be designed as part of *that* feature's plan, not as a speculative
pre-refactor.

If the issue was auto-generated from an outdated tree snapshot, the
correct next step is to re-run the duplicated-logic detector against
`origin/master @ cd048d2f` and file a new issue with current line
numbers and verified function names.

## Out of scope

- Auditing `pkg/configstore/crypto.go::masterPasswordPRF` for the
  `FindChild` first-match hazard mentioned in the standing rules.
  That code is unrelated to WireGuard X25519 key handling and a
  separate audit issue should track it; #1445's scope was strictly
  WireGuard key consolidation.
- Pre-building a `pkg/crypto/keys.go` helper in anticipation of the
  WireGuard termination feature — see "Why this is a kill" above.

## Reviewer notes

No adversarial Codex/Gemini review was dispatched for this plan: the
verdict is reached deterministically from absent code (file lengths
and `grep` misses are reproducible from the cited revision), and the
triple-review skill mandates kill at study time for wrong-target
refactors. If reviewers want to ratify the kill, the verification
above can be replayed against `cd048d2f` in under a minute.
