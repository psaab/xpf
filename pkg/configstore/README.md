# pkg/configstore

Atomic candidate / active / rollback configuration persistence. JSON files
written via temp-file + rename for crash safety, with a JSONL audit
journal and rolling commit history. AES-GCM at-rest encryption when a
master password is set.

## Entry points

- `Store` — high-level API: `Candidate`, `Active`, `Commit`,
  `CommitConfirmed`, `Rollback`, `History`.
- `DB` — `db.go:15`. Low-level atomic file I/O.
- `History` — `history.go`. Bounded ring of recent commits.
- `Journal` — `journal.go`. Append-only JSONL audit trail.
- `Crypto` — `crypto.go`. AES-256-GCM key derivation from
  `/etc/xpf/config-key`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`, `pkg/api`.

## Dependencies

`pkg/config` only.

## Gotchas

- Atomic write protocol: write temp file → fsync → rename. If the daemon
  is killed mid-fsync the previous file survives intact, and subsequent
  reads can fall back to a rollback slot.
- `Candidate` may be dirty (uncommitted edits accumulating). `Commit`
  atomically promotes candidate → active and bumps the rollback ring.
- Rollback slots are 0..49 (FIFO). Oldest is silently discarded when the
  ring is full.
- The encryption key path is fixed at `/etc/xpf/config-key`. If the file
  is missing on a node that previously committed encrypted state, the
  daemon refuses to start — there is no plaintext fallback.
- Commit atomicity (#846): `pkg/daemon` wraps `Commit()` together with
  `applyConfig()` under a single semaphore. Bypassing the daemon (e.g.
  using `Store` directly) loses that serialization, so concurrent CLI +
  HTTP commits can race.
