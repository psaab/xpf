# pkg/fsatomic

The project's single source of truth for replace-a-file-on-disk writes
(#1894). Two writers, one shared core:

- `WriteFileAtomic(path, data, perm, opts...)` — create-temp-in-same-dir,
  write, fchmod, close-with-error-check, rename. **Namespace atomicity
  only**: readers never see a torn file, but after a power cut the update
  may be lost or the rename may surface not-yet-flushed data.
- `WriteFileDurable(path, data, perm, opts...)` — the same plus an fsync
  of the temp file before the rename and an fsync of the (resolved)
  parent directory after it. Survives power loss.
- `SyncDir(dir)` — one directory fsync covering previously-completed
  renames/unlinks; lets multi-file shuffles (configstore rollback slots)
  batch namespace durability into a single fsync.
- `RenameDurable(old, new)` — rename plus the directory fsync that makes the
  new ENTRY durable (#9057). This is the **DurableNamespace** class: the
  artifact is the directory entry, not a file's contents. A rename is atomic
  for the entry and the entry is not durable until the directory is synced, so
  a power cut can lose which generation a name points at.

  **Do not use it in a shift loop.** Rotating N generations through it issues N
  directory fsyncs where one suffices, because every rename lands in the same
  directory — do the renames, then call `SyncDir` once. The `TestNoUnsyncedRename`
  canary accepts a bare `os.Rename` in a function that also reaches `SyncDir`
  for exactly that reason. A cross-directory move syncs BOTH directories,
  because syncing one of two looks like a durable move and is half of one.

- `MkdirAllDurable(dir, perm)` — `os.MkdirAll` plus an fsync of every
  newly-created level and of the deepest pre-existing ancestor. Required
  when a DurableState file lives in a directory the writer itself
  creates: `WriteFileDurable` persists the file's entry in its parent,
  not the parent's own entry in *its* parent, so on first boot a power
  cut could otherwise drop the whole just-created directory (PR #1900
  code-r1). Zero fsyncs when the path already exists.

## Persistence classes

Defined in `docs/engineering-style.md` ("Persistence classes"); the class
decides the writer:

| Class | Writer | Examples |
|---|---|---|
| DurableState | `WriteFileDurable` | active config, rollback slot 1, rescue config, `master.key`, DHCPv6 DUID, `frr.conf`, `/etc/hostname`, sudoers + `authorized_keys`, TLS cert + key, lifeline record, provisioned-users marker |
| AtomicGeneratedConfig | `WriteFileAtomic` | swanctl conf, Kea configs, networkd `.link`/`.network`, rollback slots 2..N, sshd/rsyslog/chrony drop-ins, `ssh_known_hosts`, `/etc/timezone`, `/etc/resolv.conf` |
| BestEffortKernelKnob | direct `os.WriteFile` | procfs/sysfs knobs (rename impossible there); the `/etc/resolv.conf` bind-mount in-place fallback (EXDEV/EBUSY) |

The AtomicGeneratedConfig class exists precisely so hot apply paths never
pay an fsync; fsync costs land only on operator-paced commit paths.

## Options

- `WithPreserveExisting()` — lift mode/ownership from an existing target
  (fchmod/fchown on the temp fd; chown only when the owner actually
  differs; a chown failure is surfaced, never silently renamed over a
  differently-owned file). Without it, the caller's `perm` is **enforced
  on every write** — unlike `os.WriteFile`, which keeps an existing
  inode's mode.
- `WithResolveSymlinks()` — write through a symlink to its resolved
  target (dangling links resolve to their destination); the durable
  dir-fsync targets the resolved parent. Without it, a symlinked target
  is replaced by a regular file.
- `WithOwner(uid, gid)` (#1916) — fchown the temp fd to a specific
  user/group BEFORE the rename, so the new inode is installed
  already-correctly-owned with no post-rename chown race. Required for
  DurableState `authorized_keys`: a plain durable write replaces the inode
  with a root-owned temp, and a crash before a separate chown would leave
  root-owned `0600` keys that sshd refuses (EACCES → lockout). Resolve the
  uid/gid cgo-free (the codebase parses `/etc/passwd` directly via
  `lookupUIDGID`, never `os/user`).
  - **Precedence vs `WithPreserveExisting`**: if both are set, owner =
    `WithOwner`'s, mode = preserved-existing's (explicit owner always wins).

`WithPreserveExisting()` + `WithResolveSymlinks()` together reproduce
`pkg/frr`'s `atomicWriteFile` (#1883) semantics, which this package lifted;
FRR now delegates here.

## Deliberate non-features

- **Hardlinks**: rename breaks `nlink>1` write-through (other links keep
  the old inode). No call site hardlinks these files; documented, not
  guarded.
- **Crash-leaked temps**: temp files (`.<base>.tmp-*`) are removed on
  every in-process failure path, but a crash can leak them. Owners of
  frequently-rewritten directories sweep on startup (configstore `NewDB`
  does for `.configdb`).
- **Post-rename file fsync**: redundant — the temp-fd fsync already
  flushed data+metadata; the dir fsync makes the rename durable.
- **EINTR loops**: Go's `os.File.Sync` retries EINTR internally
  (`internal/poll` `ignoringEINTR`).

## Failure semantics

The temp file is cleaned up and the target left untouched on every
failure **before** the rename. A `WriteFileDurable` error **after** the
rename (dir-fsync failure) means the new content is visible but its
durability is unknown; such a failure is returned as a typed
`*PostRenameSyncError` (#5185) so a caller can DISTINGUISH it from a
pre-rename failure. A pre-rename error leaves the OLD content intact (a
clean rejection is correct); the post-rename error leaves the NEW content
visible — a restart would load it — so a caller that keeps durable-on-disk
state in lockstep with applied in-memory state (configstore
Commit/CommitConfirmed) must **converge to the new content** instead of
reporting a plain rejection while the new content is durable on disk.
`*PostRenameSyncError` is still a plain `error` (its `Error()` names the
stage, `Unwrap()` exposes the fsync cause), so callers that do not care
treat it unchanged — the same crash-window trade the configstore #1799
persist-before-promote contract documents.

## Testing

`fsatomic_test.go` injects one failure per writer stage through the
package-private seams (create/write/chmod/chown/sync/close/rename/
dir-open) and asserts the three invariants: error names the stage,
target untouched (pre-rename stages), temp cleaned up. `WithOwner` is
tested for owned-before-rename ordering and for precedence over
`WithPreserveExisting`. The dedicated `afterRenameSyncDir` seam (#5185)
forces the POST-rename directory-fsync failure so the tests can assert the
pre/post classification: a post-rename failure is `*PostRenameSyncError`
with the NEW content visible on disk; the pre-rename rename/temp-fsync
failures are NOT `*PostRenameSyncError` and leave the OLD content intact.

`SetAfterRenameSyncDirForTesting(fn) (restore func())` (#5234) exports that
same post-rename seam so a DEPENDENT package's test can force the failure
through a `WriteFileDurable` call it does not control directly. `pkg/configstore`
uses it to drive a REAL post-rename failure through `db.WriteActive` and prove
the `*PostRenameSyncError` classification survives the DB layer's
`fmt.Errorf("persist %s: %w", …)` wrap (the converge-to-C tests otherwise
inject via the Store's `writeActiveFn` seam, which bypasses that wrap). It is
test-only — production code must never call it; it mutates a process-global
seam and is not safe under `t.Parallel`.

`SetRenameFileForTesting(fn) (restore func())` (#12549) exports the rename
seam the same way for the PRE-rename converse: the rename itself fails, the
error is NOT `*PostRenameSyncError`, and the OLD content stays in place.
`pkg/upgrade` uses it to fail the ARMED kernel-journal rename and prove that
an arm whose rename never landed is still refused (journal left at ARMING),
while the post-rename hook proves a landed ARMED write proceeds. Same
constraints: test-only, process-global, not safe under `t.Parallel`.

## Canary (`canary_test.go`)

`TestNoDirectOsWriteFile` is the writer-class enforcement test. It walks
EVERY production (non-`_test.go`) `.go` file under `pkg/` with `go/ast`
(not grep — comments may mention `os.WriteFile` and import aliases of
`os` are still caught) and flags any direct `os.WriteFile` whose
enclosing function is not on the allowlist. #1916 changed it from a
package allowlist (which let a NEW package silently escape) to a
repo-wide scan keyed RECEIVER-AWARE by `<pkg-relpath>::[RecvType.]func`
(a method `(*T).writeFile` keys as `pkg::T.writeFile`; a plain func keys
as `pkg::func`), so a future same-named function on a different receiver
in the same package does NOT inherit an exemption. The allowlist holds
only BestEffortKernelKnob entries (procfs/sysfs/bind-mount). A
self-test guard fails if the walk scans zero files. To keep a giant
function (e.g. `applyConfigLocked`) off the allowlist, extract its procfs
write into a tiny single-purpose helper and allowlist the helper.

## Callers

`pkg/configstore`, `pkg/frr`, `pkg/ipsec`, `pkg/dhcpserver`,
`pkg/networkd`, `pkg/dhcp`, `pkg/daemon`, `pkg/api`.

## Dependencies

Standard library only.
