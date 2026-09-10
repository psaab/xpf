# pkg/configstore

Durable candidate / active / rollback configuration persistence. JSON
files written via `fsatomic.WriteFileDurable` (#1894: temp + fsync +
rename + parent-dir fsync — they survive power loss, not just crashes),
with a JSONL audit journal and rolling commit history. AES-GCM at-rest
encryption when a master password is set.

The constructor is fail-closed (#1893): `New(filePath) (*Store, error)`
returns an error when the `.configdb` directory cannot be created.
There is no file-only fallback backend — every persistence path
dereferences the DB, so the old "falling back to file-only" warning was
describing code that never existed, followed by a nil-pointer panic on
the first Load/Save/commit.

## File permissions — secrets at rest (#4056)

Every persisted copy of the full config carries the config's secret
leaves (IKE/IPsec PSKs, WireGuard/auth keys, SNMP community, routing
auth). Those leaves are stored **cleartext** unless `system
master-password` is set (which AES-GCM-encrypts only the JSON DB body,
not the text copies). So all secret-bearing files are written
**owner-only 0600**, never world-readable 0644 — a 0644 copy exposed
every firewall secret to any local user and defeated the point of
master-password encryption. `fsatomic` enforces the mode on the temp fd
before the rename (`WriteFileAtomic`/`WriteFileDurable` replace the
inode on every write), so an existing 0644 file from a pre-#4056 build is
re-created 0600 on the next commit.

| File | Path | Mode | Writer |
|------|------|------|--------|
| Active / candidate / rollback DB | `.configdb/{active,candidate,rollback.N}.json` | 0600 | `db.go writeTreeMarked` |
| Pending commit-confirmed state (#4577) | `.configdb/confirm.json` | 0600 | `db.go WriteConfirm` |
| `master.key` | `.configdb/master.key` | 0600 | `crypto.go readOrCreateMasterKey` |
| Text rollback slots | `<config>.N` (e.g. `xpf.conf.1`) | 0600 | `store_commit.go saveRollbackFiles` |
| Rescue config | `rescue.conf` | 0600 | `store_persist.go SaveRescueConfig` |
| Config archives | `<archive-dir>/config-<ts>.<seq>.conf` | 0600 | `store_persist.go writeArchive` |
| Audit journal (#4579 A4-02, migrate #5188) | `.config.journal`(+`.N`) | 0600 | `journal/journal.go Log` / `migratePermsLocked` |

The `.configdb` and archive directories are created **0700** (they hold
only secret-bearing files); the daemon owns them, so read-back is
unaffected. The v2 audit journal (`.config.journal`) is compact metadata
only (timestamp/action/config-hash) and never config content or secret
values (#1896), so it is not a secret store the way the JSON DB is.
It is nevertheless written **0600** (#4579 A4-02): its `Detail` field
carries the operator's free-text commit comment verbatim, so a comment
that names a credential ("rotated the vpn psk to …") would otherwise be
world-readable. Tightening it to match the rest of the config surface is
cheap defense-in-depth; the daemon owns the file, so the history tail
read is unaffected.

Unlike the DB and text-copy files above — which `fsatomic` replaces the
inode on every write, so a pre-#4056 0644 file is re-created 0600 on the
next commit — the journal is **append-only**: `os.OpenFile` with
`O_APPEND` reuses the existing inode and **ignores the 0600 perm arg**,
so #4579 A4-02 only tightened NEW journals. An upgraded 0644 current
file, and any rotated legacy `.N` segment (v1 fat lines carrying full
configs incl. secrets), stayed world-readable with no migration pass.
`journal.migratePermsLocked` (#5188) closes that gap: on first use (Log
or Tail) it lstat's every owned segment (current + rotation siblings)
and chmods any that is more permissive than owner-only down to 0600, and
rotation re-asserts 0600 on the segment it renames. The pass only ever
tightens (a stricter file is left alone), refuses to follow a symlink,
and logs — rather than swallows — a chmod failure.

### Threat model — what 0600 + 0700 defends, and what it does not (#4056)

The `0600` file perms plus `0700` directory perms defend against
**non-root local users** (a compromised low-privilege process or an
interactive account without root) reading the secret leaves, and against
**casual leakage** of an individual file. That is the exposure #4058
closed — the world-readable 0644 copies previously handed every firewall
secret to any local user.

They do **not** defend against **root compromise** or **physical disk
theft** (a stolen disk, backup, or VM snapshot). At-rest encryption of
the config store is intentionally **not** applied to the persisted text
copies, and encrypting them with the on-box `master.key` would add **no
real defense** against those two threats: this is an **unattended-boot
appliance**, so the decryption key must live on the box (`rollback N` /
`loadRollbackHistory` and a future rescue-load must restore secrets with
no operator present). `master.key` is a plain random 0600 file
(`crypto.go readOrCreateMasterKey`) in the same 0700 `.configdb`
directory as the ciphertext, with **no TPM/HSM substrate** in the tree
to seal it. An attacker who can read `xpf.conf.N` can equally read
`master.key` one directory over and decrypt — so on-box encryption is
theater against the root/disk-theft threat, not defense. A genuine
at-rest feature therefore requires a **TPM/HSM-sealed key** (a separate,
maintainer-gated work item — deferred, see #4056), not symmetric
encryption with an on-box key.

The JSON DB body is the one copy that IS AES-GCM encrypted when
`system master-password` is set; the text rollback slots, archives, and
`rescue.conf` stay cleartext-at-rest (0600) by the reasoning above.

### What `system master-password` encryption does and does not protect (#6856)

The section above explains why the *text* copies are not encrypted. This one
states what encrypting the JSON DB body actually buys, because "AES-GCM at-rest
encryption" reads stronger than the guarantee it delivers.

**`system master-password` carries no secret.** It is an encryption-*policy*
knob. The subtree is closed-world and leaf-complete with exactly one leaf,
`pseudorandom-function` (`config/schema_system.go`), so the Junos form an
operator reaches for first — `set system master-password plain-text-password
<secret>` — is **rejected at commit**, not accepted and ignored. Presence of the
subtree is the on/off switch; the leaf's value selects only the HKDF hash.
`SystemConfig.MasterPassword` holds that selector *name*, not key material, and
is deliberately a plain string rather than a `config.Secret`
(`config/types_system.go`).

**The key is a random on-box file.** `readOrCreateMasterKey` generates 32 bytes
from `crypto/rand` and persists them to `.configdb/master.key` (0600) — the same
0700 directory as the ciphertext it protects. No operator input reaches the KDF.

So the guarantee is narrow, and narrower than "encrypted at rest" suggests:

| Threat | Protected? | Why |
|---|---|---|
| A reader who obtains the DB **body** but not `master.key` — a backup or file-disclosure scoped to `active.json` | **Yes** | the body is AES-GCM ciphertext and the key is a separate file |
| A copy of the **`.configdb` directory** — stolen appliance, disk image, whole-directory backup | **No** | `master.key` travels with the ciphertext |
| **Root** on a running box | **No** | unattended boot: the daemon must decrypt with no operator present |

Both rows of that contract are pinned by
`TestAtRestKeyTravelsWithTheConfigDirectory6856`
(`crypto_at_rest_threat_model_6856_test.go`) as a **paired** cell — a
directory copy must decrypt, and a body-only copy must not. If a future change
binds the KDF to an operator secret, moves `master.key` out of the DB directory,
or seals it to a TPM, that test REDS and this table must be rewritten in the
same change.

**Two things deliberately not done here.** Binding the KDF to an operator secret
is not a hardening tweak: it would first require *adding* a secret leaf the
schema currently rejects, and then answering unattended boot, HA key
distribution, and a power-cut-safe re-key migration — a maintainer decision,
deferred (#6856). And the HKDF info string `xpf-configstore-master-password`
(`crypto.go deriveEncryptionKeyFromSalt`) names a secret that never enters the
derivation: it is misleading, but changing it re-keys **every existing DB**, so
it must ride with that migration rather than being corrected casually.

**Off-box copy — `transfer-on-commit`:** the honest place to control the
residual is the off-box transfer, not on-box encryption. When
`system archival configuration transfer-on-commit` is set, the daemon
`scp`s the raw config file (cleartext secret leaves included) to the
operator-configured archive sites on every commit
(`daemon_flow.go scpArchiveTransfer`, `StrictHostKeyChecking=no`). This
is the one genuine off-box copy of the secrets; the operator must secure
the destination host and transport (extends the #651 warning about
inline archive-site passwords).

## Entry points

- `Store` — high-level API. Public methods include `ShowCandidate`,
  `ShowActive`, `ActiveConfig`, `ActiveTree`, `Commit`,
  `CommitCheck`, `CommitConfirmed`, `Rollback`, `ListHistory`,
  `EnterConfigure`, `EnterConfigureSession`,
  `EnterConfigureExclusive`, `ExitConfigure`, `SyncApply`,
  `MarkActiveApplied`, `ActiveApplied`, `ActiveDigest`,
  `MarkAppliedDigest`. (See
  `store.go` for the full surface — there's no shorthand
  `Candidate()` or `History()`; use the `Show*` / `List*` forms.)
- `MarkActiveApplied` / `MarkAppliedDigest` / `ActiveApplied` / `ActiveDigest` —
  the #4957 applied-config marker (+ the #6296 capture/replay pair).
  `SyncApply` (and `Commit`/`Load`) promote `s.active` BEFORE the daemon runs
  the apply and, under the #1799 degrade-not-fail doctrine, do NOT roll it back
  on an apply failure — so a config can be the active tree yet never have
  converged on the dataplane. The daemon stamps the marker after a
  fully-successful `applyConfigLocked` (boot, commit, config-sync); `ActiveApplied`
  reports whether the CURRENT active text matches that last-applied digest.
  `pkg/daemon` `handleConfigSync` ANDs its active-text convergence shortcut with
  `ActiveApplied()` so a promoted-but-unapplied synced config is not treated as
  converged (the HA config high-water then stays pinned until a retry lands).
  Two ways to stamp: `MarkActiveApplied` re-reads `s.active` at call time (the
  boot/commit paths use it while holding the apply semaphore, when active is
  stable); `MarkAppliedDigest` stamps a digest the caller CAPTURED earlier via
  `ActiveDigest`, for the exact config it applied. The config-sync receive path
  (`daemon.syncAndApply`) uses the capture/replay pair (#6296): it captures the
  digest right after `SyncApply` promotes the peer config and replays it on full
  success, both under the apply semaphore — so a concurrent secondary-side
  promoter (a local commit / commit-confirmed rollback) mutating `s.active` in
  what used to be a post-semaphore-release window can no longer make the marker
  key a different, never-applied tree. `ActiveDigest` returns exactly the value
  `ActiveApplied` compares against (`configTextDigest(s.active.Format())`).
- **`InvalidateAppliedDigest` — a FAILED apply un-records the marker (#9175).**
  "The marker is keyed on config text, so a stale value can only cause an
  idempotent re-apply, never a false convergence" USED TO STAND HERE, and it was
  false. It holds for a FORWARD sequence, where each promotion moves the active
  text away from the stamped digest. It does not hold for RE-PROMOTION of a text
  that already applied once in this process:

  | step | active | `ActiveApplied()` | |
  |---|---|---|---|
  | A applied | A | `true` | |
  | B promoted, apply FAILS | B | `false` | correct — the digest no longer matches |
  | A re-promoted, apply FAILS | A | **`true`** | **falsely converged** |

  The two stamps were the digest's only writers, so it recorded a success and
  nothing ever unrecorded one, and step 1's digest matches the active text again
  at step 3. `handleConfigSync` then takes its converged shortcut, returns nil,
  and the HA config high-water advances past a generation the dataplane never
  took — the #4957 fail-open re-entered through the remedy #4957 prescribed,
  visible only at failover. `pkg/daemon`'s `applyConfigLocked` now calls
  `InvalidateAppliedDigest` from a deferred close over its named return, so
  EVERY failing apply in the daemon clears the marker: that function is the one
  choke point the boot/background path, the commit path, the peer config-sync
  path and the commit-confirmed auto-rollback all go through, and every early
  return inside it is covered without a caller having to remember. The clear is
  unconditional rather than keyed to the failing text — the failing path does not
  always hold a digest (a context abort bails before any capture), and the wrong
  answer in that direction is the falsely-converged state, while the wrong answer
  in the other costs one idempotent re-apply.
- **`LoadOverride` accepts flat set input as well as hierarchical (#7527).**
  It used to call the hierarchical parser unconditionally and then atomically
  replace the candidate with the result. The parser treats newlines as
  whitespace, so a flat set-command file did not fail to parse — it collapsed
  into ONE junk top-level node, and the call returned `nil`:

  ```
  in:  "set system host-name a\nset system domain-name example.net"
  out: set set system host-name a set system domain-name example.net
  err: <nil>
  ```

  The operator's whole candidate became that, and both the CLI and the RPC
  printed success. It is reachable through an ordinary workflow, not a
  contrived one — `show configuration | display set > backup.txt` then
  `load override backup.txt` — and `load set` accepts only `terminal`, so
  there was no file-based path for flat input at all. The one an operator
  would reach for was the one that destroyed the candidate.

  `parseOverrideContent` now classifies with the same `hasFlatVerb` scan
  `LoadMerge` uses. **The difference between the two verbs is the starting
  tree**: merge replays onto a clone of the candidate, override replays onto
  an EMPTY one. Reusing the merge body directly would silently make
  `load override` a second spelling of `load merge`, which every other
  assertion about this path would still pass.

  Accepting flat input is the bounded choice rather than the risky one
  because **misclassification fails loud**. If a hierarchical file were
  mistaken for flat, the #3442 M3 rule rejects the first line carrying no
  recognized verb — an error naming the line, never a silently wrong
  candidate. The reverse direction is the defect that was fixed. The tree is
  built standalone and swapped in only on complete success, so a rejected
  override leaves the candidate byte-identical (#5187's atomicity, for the
  same reason: a partial delete of deny terms fails open).
- `MaxConfigSize` (16 MiB) + `checkConfigSize` — `store.go`. The
  transport-independent input-size ceiling checked at the head of every
  parse entry point: `LoadOverride`, `LoadMerge`, `LoadSet`, the HA
  `SyncApply` ingress, and the `CheckText` day-0 config-drive validator
  (#1879). It rejects an over-large or corrupt payload with a
  clean `config too large` error before `config.NewParser`, so a
  pathological input cannot exhaust memory or (with the pkg/config
  lexer/depth guards) crash xpfd with a stack overflow (H-2). It backstops
  the `grpc.MaxRecvMsgSize` / `http.MaxBytesReader` transport caps for the
  HA peer-sync path and any non-transport caller. Real configs are well
  under 1 MiB, so the ceiling never rejects a legitimate config.

  **The same ceiling bounds every tree and record the store WRITES into
  `.configdb` (#9617).** The bullet above is an INPUT bound, and a config
  that passes it can still serialize past 16 MiB: a JSON tree is many times
  its config text (18x for a run of small `groups` stanzas). `active.json`,
  `candidate.json`, `rollback.N.json` and `confirm.json` are all read back
  under `ReadBoundedFile(path, MaxConfigSize)`, and before #9617 no writer
  checked. An accepted commit could therefore write an `active.json` the next
  `Load` refuses (`ErrConfigDBUnreadable`: the daemon does not come back), and
  a successful `commit confirmed` could write a `confirm.json` the next boot
  refuses (#8566 reports that as degraded health, but the rollback window is
  gone). `writeTreeMarked` and `WriteConfirm` (via `encodeConfirm`) now refuse
  bytes over the ceiling with `ErrPersistExceedsReadCeiling`, using the
  reader's exact boundary (`len > max`). The check runs on the
  envelope-wrapped, possibly-encrypted bytes, exactly what the reader counts
  (`TestWriteActiveBoundaryIsTheReadersExactBytes_9617`), and BEFORE the
  write, so the file on disk stays the previous readable generation. `Commit`
  and `CommitConfirmed` fail pre-promotion with the candidate intact. The
  degrade-not-fail writers (HA `SyncApply`, confirm recovery, the timeout
  rollback) record the refusal as `persistDegraded` like any other failed
  write, because their in-memory apply is the safety property. The persist
  retry loop logs a size refusal once and does not re-attempt that tree (no
  retry can succeed); persistence stays degraded until a different active
  config is written. **Not gated:** the text renderings beside the DB — the
  `config.N` rollback files and the rescue config — are written from
  `Format()` without this check. Their readers also use `ReadBoundedFile`,
  and an over-ceiling rendering fails only that read: the rollback slot loads
  as a tombstone that `rollback N` rejects (#4810), and the rescue load
  returns an error.
- `DB` — `db.go`. Low-level durable file I/O (via `pkg/fsatomic`).
  `NewDB` sweeps crash-leaked `.*.tmp-*` temps from `.configdb`.
- `History` — `history.go`. Bounded ring of recent commits.
- `journal.Journal` — subpackage `journal/` (#1896). Append-only,
  size-rotated, tail-readable JSONL audit trail; `configstore` keeps
  the alias `JournalEntry = journal.Entry`. See "Audit journal" below.
- `crypto.go` — AES-256-GCM at-rest encryption helpers
  (`maybeEncryptTreeJSON`, `maybeDecryptTreeJSON`,
  `deriveEncryptionKey`). No public type; the encryption hooks are
  methods on `*DB`. The encryption key is derived via HKDF
  (info string `xpf-configstore-master-password`, mode 0600 random
  bytes) from a randomly-generated `master.key` file in the
  configstore directory. The "master-password" naming is an HKDF
  info string only — it isn't a user-supplied password.

### At-rest crypto hardening notes (#4579 A4-05/A4-06, #4705, #5231, #5638)

- **Split `system` stanza resolution (#4705).** "The tree declares a
  master-password" is decided by `masterPasswordPRF`, which scans **every**
  top-level `system` child — reusing `systemBlocksOf` (the same all-matches
  helper the dataplane-retirement walk uses) plus per-node
  `FindChildren("master-password")` — not just the first `FindChild("system")`
  match. The Junos parser does not merge duplicate top-level stanzas
  (`parseStatements` appends each) and `LoadOverride` / `SyncApply` feed the
  raw parsed tree to the write path, so a `master-password` living in a second
  `system {}` block is semantically active (the compiler folds all `system`
  nodes into one `cfg.System`). A first-match resolver missed it and wrote the
  whole DB — secrets included — in plaintext despite encryption being
  configured. Resolution now fails **closed**: if any `system` stanza carries a
  `pseudorandom-function`, the body is encrypted. Because the A4-06
  downgrade warning below also keys off `masterPasswordPRF`, centralizing the
  resolution here fixes that path for the split-stanza case too (the warning
  now fires when a second-stanza master-password DB is read back as plaintext).
- **Groups / apply-groups resolution (#5231).** The encrypt gate also covers a
  `master-password` declared inside a `groups { ... }` body and pulled in with
  `apply-groups <name>`. Such a master-password is **active at runtime** —
  `compileConfigWithOpts` expands `apply-groups` (via `tree.ExpandGroups`)
  *before* `compileSystem` reads `master-password`, so the effective
  `cfg.System.MasterPassword` is set — but the at-rest write path runs on the
  **unexpanded** persisted candidate tree (expansion happens only on a compile
  clone). A resolver that scanned only top-level `system` stanzas therefore
  missed the group-declared PRF and wrote `active.json` (IKE PSKs, WireGuard
  keys, SNMP communities, user secrets) in plaintext despite encryption being
  configured via a group. `masterPasswordPRF` now **recursively** walks every
  `groups` block (`masterPasswordPRFInSubtree`) and treats **any**
  `master-password { pseudorandom-function <X> }` descendant as
  encryption-configured, regardless of the intervening node name. The recursion
  is required — not cosmetic: a group's children can be authored under a `<*>`
  wildcard node whose body Junos merges into the top-level `system` stanza at
  apply-groups expansion (`walkGroupToContext` / `mergeNodes`,
  `pkg/config/ast_groups.go`), so a scan keyed on a literal `system` child
  (`systemBlocksOfNode`) MISSES the wildcard shape and still leaks plaintext
  end-to-end. The invariant is now **any master-password anywhere under any
  `groups` block triggers encryption**. This over-encrypts on a
  defined-but-unapplied group (a harmless false-positive — encrypting when
  unnecessary is always safe) and can never false-negative relative to runtime:
  `apply-groups` only *copies* existing leaves, so a PRF active after expansion
  physically exists somewhere under a group body here. The walk is read-only and
  total (nil-safe, never errors on a malformed group) because the write path must
  not fail.
- **Dormant / unsupported PRF isolation (#5638, codex-review-181 M30).**
  `masterPasswordPRF` now answers TWO separable questions instead of one. **(1)
  Is encryption required?** — the fail-closed broad scan above
  (`masterPasswordConfigured`): ANY master-password anywhere (active stanza,
  applied OR unapplied group, `<*>` wildcard, inactive node) means encrypt.
  **(2) Which PRF algorithm?** — resolved from the EFFECTIVE/APPLIED scope only
  (`effectiveMasterPasswordPRF`: strip inactive **then** expand applied groups
  on a clone, the same semantics the compiler and `schemaValidateExpandedTree`
  use), accepting **only** a selector `prfHash` supports; otherwise the fixed
  supported default (`defaultMasterPasswordPRF`, `sha256`). The old resolver
  conflated the two: its fail-closed superset returned whatever value a dormant
  subtree carried, so an **unsupported** PRF (`bogus`) hidden in an inactive
  node or an unapplied group — invisible to the #4578 commit gate, which
  validates the effective tree — was handed to `prfHash`, which rejects it.
  On the tolerant HA config-sync / upgrade-load path this made the persistence
  write fail **deterministically**: the standby promotes the peer tree in
  memory (Option B), `writeActive` fails, and the singleton retry re-selects the
  same bad value forever, leaving the node `/health`-503 with its authoritative
  generation permanently off disk (non-durable across restart). Constraining the
  ALGORITHM to a supported effective value (default fallback) keeps the DB
  encrypted while guaranteeing the write only ever receives a value `prfHash`
  accepts — deterministic and durable across active↔standby. The effective
  resolution runs on a clone and swallows every apply-groups expansion error
  (degrading to the default), so the "this write path must not fail" contract —
  which originally motivated NOT calling `ExpandGroups` here — still holds. A
  normal single active supported-PRF config takes a zero-allocation fast path
  and is bit-identical to the pre-#5638 resolver.
- **Unexpected-plaintext warning (A4-06).** Every write path encrypts the
  body when the tree declares a master-password, so `readTreeMeta` reading
  a config back as *plaintext* while its tree still declares a
  master-password means the file was written without the AES-GCM envelope
  — a downgrade to an older build, a restore from an unencrypted backup, or
  tampering. `maybeDecryptTreeJSON` reports whether it actually decrypted;
  `readTreeMeta` logs a one-time `slog.Warn` on the plaintext-with-declared-
  master-password case so the silent at-rest exposure is visible instead of
  loading the cleartext secrets without a trace. Reaching that state needs
  write access to the 0600/0700 `.configdb` (root/owner), so this is a
  visibility improvement, not a privilege-escalation fix.
- **Unknown inner-envelope format fails closed (#4888).** `unmarshalEnvelope`
  distinguishes a genuine plaintext body (no `format`, no `salt`/`nonce`/`data`
  — passed through) from an envelope-shaped body it cannot decrypt: an
  unknown/future `format` (e.g. a `xpf-master-password-v2` bump), or the
  AES-GCM fields present without the current `format`, returns an ERROR so
  `Store.Load` reports `ErrConfigDBUnreadable`. Without this, an inner encrypted
  envelope past the outer `#xpf-config-envelope` gate whose format was corrupted
  or is too-new would be `json.Unmarshal`'d into a `ConfigTree` with all unknown
  fields dropped — an EMPTY tree — booting a committed-empty config (loss of
  policy) instead of failing closed. This restores at the inner layer the same
  no-empty-load-on-unknown property the outer envelope provides.
- **#4888's guard tested four of the envelope's five fields (#8288).** The two
  guards above had a GAP BETWEEN them and a `{"prf":"sha256"}` body fell through
  it. #7454's key-presence guard is consulted only inside the decode-FAILURE
  branch, and that body is well-formed JSON which decodes cleanly, so it never
  ran. #4888's discriminator then tested `Format || Salt || Nonce || Data` —
  **omitting PRF** — so a body whose only envelope key was `prf` satisfied "no
  format AND no AES-GCM fields", which is precisely how the code defines a
  genuine plaintext body. Result: the empty-tree committed-empty boot that both
  guards exist to prevent, reached by the seam between them, and silent for the
  same #4579 reason as #7454.

  Confirmed by execution, with `{"salt":"x"}` refused in the same probe as a
  control so the result is not vacuous:

  ```
  body={"prf":"sha256"}                 -> ok=false err=<nil>   (PLAINTEXT passthrough)
  body={"prf":"sha256","Children":null} -> same
  body={"salt":"x"}                     -> refused
  ```

  **Fixed by using `len(envKeys) > 0` there, deliberately NOT by appending
  `|| env.PRF != ""`.** The obvious fix works, but the defect IS a five-field
  struct guarded by a hand-maintained four-field list, and adding a fifth item
  reproduces the shape that caused it. `envKeys` is derived from the body and
  answers the question #7454 already answers, so it cannot drift out of sync
  with the struct.

  It is also strictly stronger, and that is intended: `{"format":""}` carries
  the key with an empty value, which the field test passed through and key
  presence refuses. A body that names an envelope key at all was meant to be an
  envelope. The refusal now also names which keys it saw, so the operator is not
  sent looking for a `format` field the body does not have.

  The over-rejection risk is bounded by a property of the data, not by hope, and
  it is asserted rather than left to this paragraph:
  `TestPlaintextTreeCarriesNoEnvelopeKeys8288` marshals both an empty and a
  populated `ConfigTree` and fails if either carries an envelope key. That
  matters because `config.ConfigTree` has exactly ONE field (`Children`), so
  adding a second whose JSON name collided with one of the five would make every
  plaintext load fail closed — a brick on upgrade — and the cell says so at the
  point of change.
- **All three of the guards above read keys with a rule the DECODER does not
  use (#8597).** `encoding/json` matches an incoming object key to a struct
  field by preferring an exact match but **accepting a case-insensitive one**.
  `envelopeKeysPresent` used an exact lowercase lookup, so the guard and the
  decoder disagreed about what counts as an envelope key, and every body whose
  key differed only in case fell into the gap. Measured:

  ```
  {"format": 123}      -> rejected (fail-closed)
  {"Format": 123}      -> PASSED THROUGH AS PLAINTEXT
  {"Format":"garbage"} -> PASSED THROUGH AS PLAINTEXT
  {"Salt": 5}          -> PASSED THROUGH AS PLAINTEXT
  ```

  Same destination as the three fixes above — empty `ConfigTree`, committed-empty
  boot, silent for the #4579 reason — reached by flipping one letter's case.

  This is the **fourth** member of the family, and the pattern across all four
  is worth stating rather than fixing a fifth time: **a guard placed in front of
  a decoder has to answer the decoder's question, in the decoder's terms.**
  #4888 tested four of five fields, #7454 tested the wrong error class, #8288
  tested a hand-maintained subset, and all three matched keys case-sensitively
  against a case-insensitive decoder.

  `envelopeKeysPresent` now folds before the membership test and returns the
  CANONICAL lowercase names, so the operator-facing diagnostics do not echo a
  corrupt body's casing. Case-folding WIDENS the guard, so the over-rejection
  measurement is repeated for it:
  `TestPlaintextKeySetCannotCollideWhenFolded_8597` marshals a real
  `ConfigTree` and fails if any of its top-level keys folds onto an envelope
  name — the same reasoning as `TestPlaintextTreeCarriesNoEnvelopeKeys8288`,
  re-run under the wider rule rather than assumed to carry over.

  `TestEnvelopeGuardIsCaseInsensitive_8597` asserts the AGREEMENT between each
  case-variant body and its lowercase twin, and fails first if the twin is not
  refused — so it cannot pass by both spellings being accepted.
- **A wrong JSON TYPE on an envelope field fails closed too (#7454).** #4888's
  guard sits AFTER the initial unmarshal, and that unmarshal swallowed every
  error as *"not the envelope object shape at all — a genuine plaintext body.
  Pass through."* That comment is true for a **syntax** error. It is not true
  for a `*json.UnmarshalTypeError`: a perfectly good JSON object, with the right
  keys, one carrying the wrong JSON type (`"salt": 5`, `"format": []`,
  `"prf": {}`, `"nonce": true`) took the same branch and passed through as
  plaintext — reaching the empty-tree, committed-empty boot that the guard
  immediately below it exists to prevent.

  **The failure was completely silent.** The #4579 plaintext-downgrade warning
  does not fire either: it keys on `masterPasswordPRF(tree) != ""` and the tree
  is empty. Contrast the string-valued path, which is correctly fatal all the
  way to `daemon_run_bringup.go` refusing to start.

  The fix decides envelope-ness by **key presence**, before the typed decode,
  rather than by discriminating the error type. It is strictly stronger and
  carries **no over-rejection risk here**: the plaintext body written by
  `writeTreeMarked` is `json.MarshalIndent` of a `config.ConfigTree`, whose only
  top-level key is `Children`. None of the five envelope keys can appear in a
  genuine plaintext body, so any body carrying one was MEANT to be an envelope
  and a decode failure on it is corruption — whatever its shape.

  **Measured, and it corrects the issue's framing:** JSON `null` is *not* a type
  error in Go. It decodes into any type as a no-op, leaving the zero value, so a
  null-valued field reaches the envelope's own required-field check (or #4888's
  discriminator check, for a null `format`) and was **already** fail-closed by a
  different guard. Only a genuine wrong type took the passthrough branch. The
  table keeps both kinds of row with their distinct expected diagnoses, because
  an operator tells a corrupt envelope from an unsupported one by that wording
  and the two have different remedies.

  Reachability is a corrupted or tampered `active.json`, so this is
  "fails OPEN to no-policy where the neighbouring branch fails closed", not
  attacker-reachable — but a partial disk write or a truncated value is a
  plausible way in, and it is exactly the state the fail-closed design exists to
  prevent.
- **Non-object top-level body fails closed (#5474).** After the envelope is
  stripped and any AES-GCM ciphertext decrypted, `readTreeMeta` requires the
  final plaintext ConfigTree body to be a JSON OBJECT (`requireJSONObject`)
  BEFORE decoding it into `*ConfigTree`. This closes a fail-OPEN gap: Go's
  `json.Unmarshal([]byte("null"), &ConfigTree{})` returns NO error and leaves
  the tree at its zero value, so a legacy/plaintext (or enveloped-but-
  unencrypted) active body of literal `null` used to decode to a semantically
  EMPTY config and `Store.Load` would compile+boot it normally — the firewall
  coming up with policy ABSENT instead of failing closed. Top-level arrays and
  scalars already error against the struct target, but `null` is syntactically
  valid and decodes to zero policy; the object gate rejects all three uniformly
  with an error `Store.Load` tags `ErrConfigDBUnreadable`. The valid empty
  config `{}` is preserved as valid, and well-formed populated objects plus the
  encrypted-envelope path (whose inner body always marshals from a struct to an
  object) decode byte-for-byte as before.
- **GCM AAD binding (A4-05) — deliberately NOT changed.** `Seal`/`Open` pass
  a nil additional-authenticated-data argument. Binding the envelope header
  (PRF/salt) as AAD is textbook defense-in-depth, but the scheme already
  fails *closed* on any header swap: the key is HKDF-derived from the PRF
  and the stored salt, so tampering with either yields the wrong key and
  `Open` fails the GCM tag anyway. More importantly, switching to a non-nil
  AAD is a **ciphertext-format change**: an `active.json` sealed by an older
  build with nil AAD would fail to open after the change (the tag no longer
  matches), bricking decryption on upgrade. The non-exploitable gap does not
  justify an upgrade-brick risk, so the nil AAD is retained.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`, `pkg/api`.

## Dependencies

`pkg/config` only.

## Generation-bound commit transaction (#5848)

Candidate compilation/pre-flight and candidate promotion are two separately
locked store operations. `CompileCandidate`/`CommitCheck` take only
`s.mu.RLock`; `CommitWithDescription`/`CommitConfirmed` separately take
`s.mu.Lock` and recompile the *then-current* `s.candidate`. The daemon's
commit path uses that gap to run an EXTERNAL pre-flight the store cannot do
itself — the #1956 device-map management-lockout gate, which resolves the
proposed config against LIVE hardware while the operator is still connected.
Candidate mutations (`Set`/`Delete`/`LoadOverride`/`LoadMerge`/`LoadSet`/
`Deactivate`/`Activate`/`Copy`/`Rename`/`Insert`/`Annotate`/`Rollback`) do
NOT take the daemon apply semaphore, and internal callers pass
`sessionID == ""` which bypasses config-lock holder enforcement (REST instead
carries its server-generated per-session holder identity, #5870/#6197, but
same-session and internal concurrency remain). So a concurrent edit could land
between the daemon's pre-flight of candidate C1 and `Commit`'s promotion, and
the daemon would persist+apply an unexamined C2 — a management-lockout-gate
bypass (examined generation != promoted generation).

The fix is a monotonic **candidate generation token** (`candidateGen`, bumped
via `bumpCandidateGenLocked` under `s.mu.Lock` at EVERY candidate change:
mutation, load, rollback, enter/exit/reclaim config mode, the peer-sync reset,
and the post-commit reset — a table-driven test asserts each mutating op bumps
it) plus a generation-bound commit path:

- `CompileCandidateGen() (*config.Config, uint64, error)` — compiles the
  candidate AND reads the generation under ONE `RLock`, so the compiled
  snapshot and the token are a consistent pair. The daemon runs its hardware
  pre-flight on that immutable snapshot OUTSIDE the store lock (`s.mu` is never
  held across netlink/hardware probing).
- `CommitWithDescriptionGen(desc, expectedGen)` / `CommitConfirmedGen(minutes,
  expectedGen)` — promote ONLY if `candidateGen == expectedGen`, else return
  `ErrCandidateGenerationConflict` without mutating any state. The plain
  `CommitWithDescription`/`CommitConfirmed` remain for the direct callers (CLI,
  event-engine) that perform no external pre-flight.

The daemon (`commitWithGenBinding`, `pkg/daemon/daemon_apply.go`) snapshots →
pre-flights → commits bound to the snapshot generation, retrying the whole
sequence a bounded number of times on conflict and surfacing the conflict to
the REST/gRPC caller if the candidate keeps changing. The token is
**authoritative over content**: a candidate edited and reverted to
byte-identical bytes still yields a new token, so the conservative outcome is a
conflict/retry — never a silent substitution. The rollback target for
commit-confirmed (the active config) is stable across the transaction because
every path that mutates `active` runs under the daemon apply semaphore the
commit path holds from pre-flight through promotion.

Scope: REST config mutations carry a server-generated per-session holder
identity that participates in the config-lock gate (#5870/#6197, see
"Config-lock ownership gate"). Generation binding remains necessary for
same-session/internal concurrent callers.

## Authority-bound commit: holder turnover (#6808)

Generation binding answers *"is the candidate CONTENT the one that was
examined?"*. It does **not** answer *"is the SESSION that was authorized to
commit still the one holding the lock?"* — `CommitWithDescriptionGen` /
`CommitConfirmedGen` take no session id at all. Those are different questions
and neither implies the other.

The gap that opened: the REST and gRPC commit paths verified the config-lock
holder and then invoked a daemon callback carrying **no identity**
(`s.commitFn(ctx, comment)`). Between the two, the lock could turn over — the
holder exits, disconnects, or is reclaimed on its idle lease (#4476), and
another session enters and stages different edits — and the in-flight commit
would snapshot and promote the **new** holder's candidate under the **original**
holder's authorization.

Generation binding does not close it, and the retry loop makes it worse. A
turnover that completes *before* the daemon's `CompileCandidateGen` — i.e. while
the commit waits on the apply semaphore, which is where a busy daemon actually
waits — yields a perfectly *consistent* generation pair, describing the new
holder's candidate. And because `commitWithGenBinding` retries
`ErrCandidateGenerationConflict` by design, a turnover reported as a generation
conflict would make the retry re-snapshot and promote the new holder's work
automatically.

The fix binds the **authority**, checked under the same `s.mu` acquisition as
the generation:

- **`holderEpoch`** — a counter advanced on every config-lock ACQUISITION and
  RELEASE (`EnterConfigureSession`, `EnterConfigureExclusive`,
  `ExitConfigureSession`, `ExitConfigure`, `ForceExitConfigure`,
  `reclaimStaleLockLocked`). It is distinct from `candidateGen`, which tracks
  candidate *content*, and from `configLockAt`, a wall-clock stamp that cannot
  distinguish a still-held lock from a released-and-retaken one. A same-session
  re-entry does **not** advance it: the lock never changed hands.
- **`AuthorizeCommit(sessionID) (CommitAuthority, error)`** — verifies the
  holder and mints the authority under **one** lock acquisition. Two calls would
  leave a window in which the lock turns over between "you are the holder" and
  "here is the epoch you hold it at" — the same defect one level down. It
  replaces `EnsureConfigHolder`, which had no remaining callers once every
  commit path was converted.
- **`CommitWithDescriptionGenAs` / `CommitConfirmedGenAs`** — verify the
  authority AND the generation under one `s.mu`, immediately before promotion.
- **`ErrConfigHolderTurnover`** — a sentinel deliberately DISTINCT from
  `ErrCandidateGenerationConflict`, because the correct reaction is opposite: a
  generation conflict means "re-examine and retry"; a turnover means "the
  authority that permitted this commit is gone", and retrying would perform the
  substitution.

### The zero value is invalid, not a bypass

`CommitAuthority`'s zero value is **rejected** with `ErrCommitAuthorityMissing`.
An internal/system committer (HA config-sync apply, event engine, in-process
shell CLI, tests) must say so explicitly with `InternalCommitter()`.

This is the point of the design, not an ornament. Letting the zero value mean
"internal committer, skip the check" would put the god-mode capability at exactly
the value a forgotten field or a `CommitAuthority{}` written in good faith
already produces. The explicit parameter would then catch *omission* — it would
not compile — while silently admitting a **wrong-but-compiling zero** that reads
as deliberate in review. Splitting "this caller legitimately has no holder" from
"nobody said" makes the first a written statement and the second an error.

The authority travels as an explicit **parameter**, not on a `Context`, for the
same reason: an absent context value is indistinguishable from a deliberate one
and would degrade silently to a bypass on an authorization path.

### Scope

The identical gate-then-unscoped-callback shape existed at **four** sites, not
the two the issue title names: REST commit and commit-confirmed
(`pkg/api/config.go`) and gRPC `Commit`/`CommitConfirmed`
(`pkg/grpcapi/server_config.go`). gRPC additionally has a **non-adversarial**
trigger — `configLockStatsHandler.HandleConn` auto-releases the lock on
`ConnEnd` from a separate goroutine with no coordination with an in-flight
commit, so an ordinary disconnect reaches the substitution with no attacker
timing.

## Persist-failure semantics (#1799)

A `db.WriteActive` failure used to be non-fatal everywhere (one-shot
WARN), so a commit could report success and silently revert to the
previous on-disk config at the next restart. The contract is now
per-path:

- **Operator commits (`Commit`, `CommitWithDescription`,
  `CommitConfirmed`) — Option A, persist-before-promote.** The
  candidate is written to the on-disk active config BEFORE any
  in-memory promotion. On failure the commit returns an error with the
  candidate left intact and NOTHING mutated: no
  active/candidate/compiled/dirty change, no history push, no journal
  entry, no rollback-file save. Since `WriteActive` is temp-file +
  rename atomic, the old active survives on disk — a restart after a
  failed commit serves the previous config and the operator saw an
  error, never a silent revert.
- **Post-rename durability failure — converge, don't reject (#5185).**
  The "old active survives on disk" guarantee above holds only for a
  PRE-rename failure. `fsatomic.WriteFileDurable` fsyncs the parent
  directory AFTER the rename; if that dir-fsync fails, the rename already
  happened — the NEW candidate (C) is VISIBLE on disk (a restart loads C),
  only its durability across power loss is unknown. Reporting a plain
  "commit failed" there would leave durable(C) != in-memory/applied(A):
  the operator is told REJECTED while a restart activates C. `fsatomic`
  now returns that case as a typed `*fsatomic.PostRenameSyncError`;
  `Commit`/`CommitWithDescription`/`CommitConfirmed` classify it
  (`isPostRenameDurabilityFailure`) and, instead of rejecting, CONVERGE:
  promote C in memory, return the compiled config so the daemon applies C
  (restoring durable == in-memory == applied), and raise the Option-B
  degraded machinery (health 503, gauge, journal ERROR, background
  re-fsync retry — the `commit_postrename` / `commit_confirmed_postrename`
  actions). Converge-to-C is chosen over durably-restoring-A because
  restoring A needs ANOTHER rename that can itself fail post-rename
  (`fsatomic` cannot guarantee an atomic restore), whereas C is already
  the durable content, so converging needs no further write to hold the
  invariant. A PRE-rename failure (any non-typed write error) is still a
  clean rejection with A intact. The classification travels through the DB
  layer's `fmt.Errorf("persist %s: %w", …)` wrap in `db.go writeTreeMarked`;
  `isPostRenameDurabilityFailure` (`errors.As`) sees the typed error through
  that `%w`. A downgrade to `%v` would silently break classification, so
  `postrename_dbboundary_5234_test.go` drives a REAL post-rename dir-fsync
  failure through `db.WriteActive` (via fsatomic's exported
  `SetAfterRenameSyncDirForTesting` seam) and asserts both the direct
  classification and the end-to-end converge — FAILing RED if the wrap is
  ever downgraded (#5234).
- **Crash window (persist-then-promote ambiguity).** Because the disk
  write happens first, a crash after `WriteActive` succeeds but before
  the in-memory promotion completes means a restart loads the NEW tree
  even though the commit never reported success (no history/journal
  entry, and for `CommitConfirmed` no armed rollback timer). This is
  the deliberate trade: the old ordering's failure mode was a commit
  that REPORTED success and silently reverted on restart. A
  disconnected operator should treat an unanswered commit as
  ambiguous — same as Junos — and inspect `show configuration` after
  reconnecting.
- **`commit confirmed <minutes>` is range-bounded (#4868).**
  `CommitConfirmed` rejects a timeout above `MaxCommitConfirmedMinutes`
  (65535, the Junos range) so `time.Duration(minutes)*time.Minute` cannot
  overflow int64 nanoseconds into a wrapped/negative deadline that fires
  an immediate or wrong auto-rollback after the candidate is already
  promoted. The guard runs before `writeActive`/promote (no mutation on
  reject) and the gRPC handler maps it to `InvalidArgument`. Both CLIs
  parse the timeout with `ParseInt(_, 10, 32)` and enforce `[1, 65535]`
  before the RPC, so a malformed/zero/negative/`MaxInt32+1`/`2^32+1`
  timeout ERRORS instead of silently arming the 10-minute default or a
  truncated value; an unknown `commit` modifier (e.g. the typo `commit
  confimed`) and an out-of-int32 `rollback` index are likewise rejected
  before any mutation rather than falling through to a permanent commit /
  rollback-0 candidate discard.
- **`commit confirmed` survives a crash inside the window (#4577).**
  The auto-rollback timer is an in-memory `time.AfterFunc` that does NOT
  outlive the process, so before this fix a daemon crash/reboot inside
  the confirm window made the UNCONFIRMED config PERMANENT — the
  safety hatch was silently lost (an operator commits a
  management-stranding config relying on the auto-revert, the daemon
  crashes, the box is stranded). `CommitConfirmed` now also persists a
  `confirm.json` in `.configdb` holding the absolute **deadline**, the
  **rollback-target tree** (`confirmPrevTree` — the ORIGINAL
  last-confirmed tree for a nested re-arm), and the **first-commit**
  flag (`confirmPrevFirst`, the #1922 Item 1b never-committed case —
  see the #6538 note below; it used to be re-derived as
  `confirmPrevCfg == nil` at each consumer). It is written durably (temp+fsync+rename+dir-fsync),
  encrypted with the same master-password machinery as `active.json`
  (the target tree may carry secret leaves), 0600, AFTER the successful
  `writeActive`+promote (a failed commit-confirmed never leaves a
  `confirm.json`). `Store.Load` (`recoverPendingConfirmLocked`) restores
  it at boot: if the deadline already passed during downtime it rolls
  back to the prev tree now (including the Item 1b committed=0 marker on
  a first-commit target); if the deadline is still in the future it
  re-arms the timer for the REMAINING duration. Every confirmation path
  (`clearPendingConfirmLocked` — plain commit / HA sync / explicit
  confirm / demotion) and the timeout rollback (`PromoteRollback`)
  remove `confirm.json`; a nested `commit confirmed` re-writes it with
  the extended deadline. The removal is a **durable transition** too
  (#4864): `DeleteConfirm` unlinks `confirm.json` and then fsyncs the
  parent directory (`fsatomic.SyncDir`), matching the dir-fsync `WriteConfirm`
  performs — a bare `os.Remove` is not durable, so a crash in the window
  before the dirent removal flushes could replay a stale `confirm.json` on
  reboot and revert an already-confirmed config (in HA, re-diverge a confirmed
  standby). The unlink + dir fsync route through the package durability seams
  (`rbRemove`/`rbSyncDir`) so a dropped dir sync fails a test RED. A clean restart inside the window also keeps
  the hatch (Junos parity: the pending confirm persists across a
  reboot and rolls back if not confirmed). One residual window remains:
  a crash in the microseconds between the `writeActive` syscall and the
  `confirm.json` write leaves no `confirm.json` — vastly smaller than
  the whole multi-minute window this closes.

  **The re-armed timer dispatches into a HALF-BUILT daemon (#6739).**
  `recoverPendingConfirmLocked` runs at the tail of `Load`, which the daemon
  calls in startup **phase 1**; the daemon's managers are not constructed until
  **phase 3**, and nothing holds the daemon's apply semaphore across the phases.
  The remaining duration is strictly positive (an already-expired window takes
  the synchronous branch above and never reaches this re-arm) but is bounded
  below only by how close the boot is to the deadline, so a reboot shortly
  before the deadline arms a timer with seconds on it. The store is not the
  right layer to fix that — it owns the deadline, not the daemon's startup
  ordering — but the re-arm is where the hazard originates, so it is recorded
  here. The daemon side (the fail-closed `d.vrrpMgr` guard, and the
  dispatch-level coverage that binds it) is documented in
  `pkg/daemon/README.md`, "The recovered commit-confirmed rollback fires against
  a HALF-BUILT daemon (#6739)". The startup-readiness gate that would move the
  dispatch point is work item G, held in #7675 with H and H2.
- **A commit-confirmed record the next boot would refuse is never written
  (#9617).** The active DB's size does not bound its confirm record:
  `confirm.json` nests the rollback target one indentation level deeper than
  `active.json` (`MarshalIndent`, two bytes per line), so a readable active DB
  can have an unreadable record, and the record is written only after
  promotion. `commitConfirmedLocked` therefore encodes the record BEFORE
  `writeActive`, through the same `encodeConfirm` the write uses: the same
  rollback target (the ORIGINAL one for a nested re-arm), the same deadline
  (hoisted above the preflight), the guarded hash of the tree about to become
  active, and `resolved: true` — the #8565 tombstone form, the larger of the
  two shapes the window writes — so a window that arms can also be resolved.
  Any encode failure refuses the commit with the candidate intact.
- **A degenerate `confirm.json` is rejected, never treated as a valid
  pending confirm (#5637, codex-review-181 M29).** `ReadConfirm` now
  validates the record's shape and fields, mirroring the #5474
  `readTreeMeta` hardening. Go's `json.Unmarshal` of a top-level `null`
  (or `{}`) into `*confirmRecord` returns NO error and yields a
  ZERO-VALUE record — zero `Deadline`, nil `PrevTree`.
  `recoverPendingConfirmLocked` would then read `time.Now().After(zeroTime)`
  as TRUE (an "expired" window) and synthesize a rollback to an EMPTY
  prev tree, silently WIPING the just-loaded active config to
  policy-absent (fail-OPEN) on boot. `ReadConfirm` therefore (1) rejects a
  null/array/scalar decrypted body via `requireJSONObject` BEFORE
  decoding, and (2) rejects a decoded record with a zero `Deadline` or a
  nil `PrevTree` — an object check alone still accepts `{}`. A
  legitimately-written record always carries a real future deadline
  (`time.Now().Add(window)`) and a non-nil `PrevTree`
  (`confirmPrevTree = s.active.Clone()`, non-nil even for a first commit —
  `FirstCommit` distinguishes the empty-bootstrap case), so valid records
  round-trip unchanged. A rejected read is fail-CLOSED:
  `recoverPendingConfirmLocked` already logs the read error and skips
  restoration (keeping the loaded active config, never panicking), so a
  degenerate record can no longer drive a bogus empty rollback. A
  genuinely ABSENT `confirm.json` is still the no-confirm-pending path
  (`(nil, nil)`), not an error.
- **`confirm.json` removal is ordered AFTER the resolving write is
  durable (#5473).** Resolving a pending window is a **degrade-not-fail**
  operation at three loci — the timeout auto-rollback (`PromoteRollback`),
  boot recovery (`recoverPendingConfirmLocked`), and an HA config-sync that
  supersedes the window (`SyncApply`): each promotes the replacement config
  in memory and then runs an active-config write that MAY fail (Option B —
  the in-memory revert/apply is the safety property and always stands). The
  removal of `confirm.json` is the **crash-recovery-lifecycle** transition
  and must not happen until that replacement is DURABLE. Before this fix all
  three unconditionally deleted `confirm.json` even when the write FAILED:
  on-disk `active.json` was still the pre-rollback config `C`, and the record
  that would re-drive the rollback to the target `A` was gone — so a crash
  before the degraded-persist retry healed booted `C` (the exact config
  `commit confirmed` was meant to revert) with NO recovery record. Now the
  removal is gated on the write: on SUCCESS `confirm.json` is removed exactly
  as before (durable transition, idempotent on the microsecond crash window);
  on FAILURE it is RETAINED and its removal is DEFERRED
  (`confirmResolvePendingPersist`) until the replacement lands durably — the
  persist-retry heal or any superseding commit/sync finalizes it via
  `clearConfirmResolutionPendingLocked`. Fail-closed: a crash while the write
  is un-healed boots into a state that RE-RUNS the rollback to `A` (the
  persisted deadline having passed) rather than stranding `C`. `SyncApply`
  cancels the timer with `cancelPendingConfirmTimerLocked` (the timer-half of
  `clearPendingConfirmLocked`) precisely so `confirm.json` removal can be
  ordered after its degrade-not-fail write. Distinct from #4864 (which made
  the delete itself dir-fsync-durable): #4864 fixes HOW the record is deleted,
  #5473 fixes WHEN.
- **Confirmation is gated on DURABLE removal of `confirm.json` (#5835).**
  #4864 made the delete dir-fsync-durable and #5473 ordered it after the
  resolving write, but the removal itself was still **best-effort**:
  `removeConfirmState` only LOGGED a `DeleteConfirm` failure. So a
  confirmation (plain commit / HA sync / explicit `commit`-confirm /
  demotion) reported SUCCESS while `confirm.json` lingered on disk — a
  restart then read the stale record and resurrected its rollback,
  reverting the operator-confirmed config (in HA, re-diverging a confirmed
  standby). Three corrections close this:
  - **Removal failure is surfaced/retained, never swallowed.**
    `removeConfirmState` now RETURNS the error. The EXPLICIT `ConfirmCommit`
    propagates it to the operator (the confirm took effect in memory but is
    not durable). The non-returning paths route through
    `resolveConfirmRemovalLocked`, which retains **retry debt**
    (`confirmRemoveDegraded`) and starts the singleton persist-retry loop —
    the SAME loop that heals a degraded active write — so the stale record
    is re-deleted with backoff until durable. `ConfigPersistDegraded()`
    (→ /health) is true while the debt stands; `ConfirmRemovalDegraded()`
    exposes it specifically. The in-memory timer/rollback bookkeeping is
    cancelled as before (the record delete needs only the file path, not the
    tree), so nothing is irreversibly lost — the retry re-drives the delete.
  - **The #4864 dir fsync is reachable on an absent-file RETRY.**
    `DeleteConfirm` used to `return nil` on `os.IsNotExist` BEFORE the dir
    fsync. If a prior attempt unlinked the file but its dir fsync FAILED, the
    dirent removal was not yet durable, yet the absent-file retry reported a
    false success. It now falls through to the dir fsync even when the file
    is already absent (idempotent, harmless when it never existed), and keeps
    returning an error until a fsync succeeds — the `confirmRemoveDegraded`
    flag is the cross-call operation state distinguishing "never existed /
    durable" from "unlink succeeded, dir sync owed".
  - **The record is bound to the config it guards (`GuardedHash`).**
    `confirm.json` records the sha256 of the unconfirmed active tree's
    `Format()` at arm time (an additive JSON field). On boot recovery, if
    the loaded active config no longer matches, a later commit/confirm has
    advanced the active config while this record's removal had failed — the
    record is STALE and `recoverPendingConfirmLocked` IGNORES it (no rollback,
    no re-arm) rather than reverting an unrelated, already-confirmed
    generation. A legacy record (empty `GuardedHash`, pre-#5835) skips the
    check and recovers exactly as #4577, preserving the cross-upgrade hatch.
  - **A resolved record carries a TOMBSTONE (#8565).** The `GuardedHash`
    binding above separates "pending" from "resolved" only when the
    resolution CHANGED the active config. A confirmation changes nothing —
    `ConfirmCommit` and `ConfirmPendingOnDemotion` replace no tree — so the
    hash still matched and recovery treated a resolved-but-undeleted record
    as LIVE: past the deadline it REVERTED a config the operator had
    explicitly confirmed, and inside the window it re-armed the rollback over
    it. This README previously recorded that as a residual that "fails SAFE
    … consistent with `ConfirmCommit` having returned an error"; that
    rationale covers only the one path that HAS an error to return.
    `ConfirmPendingOnDemotion` returns a bool and the plain-commit / HA-sync
    paths discard the error, so on those the operator's confirmation was
    reverted with no diagnostic anywhere. `resolveConfirmRemovalLocked` now
    writes the record back with `Resolved` set (an additive JSON field)
    DURABLY BEFORE deleting it, and `recoverPendingConfirmLocked` finishes the
    owed deletion instead of acting on it. Which way it errs: a tombstoned
    record is ignored, so the CONFIRMED config stands — #4577 is untouched
    because an UNRESOLVED record carries no tombstone and still reverts. The
    tombstone is written only where the removal is actually reached, which
    #5473 already defers until the resolving write is durable, so it can
    never mark a window whose resolution did not take effect; and a tombstone
    write that itself fails degrades to exactly the pre-#8565 behaviour. A
    TRANSIENT and a PERMANENT removal failure get the same answer on purpose
    — both mean the window is resolved — and differ only in how long
    `ConfigPersistDegraded()` keeps reporting the undeleted record.
  - **A boot read failure is REPORTED, not swallowed (#8566).**
*   **#9014 — the ARM write was the LAST confirm-durability leg with no
    health state.** `writeConfirmState` logged one `slog.Warn` and returned:
    no flag, no journal entry, no retry, and `CommitConfirmed` still returned
    `(compiled, nil)`. A crash or reboot inside the confirm window then found
    no record, the unconfirmed configuration stood permanently, and /health
    returned 200 throughout. The asymmetry was the decisive evidence, because
    the invariant it broke is written down in this same package, in #8566's
    own rationale directly below:

    | failure | flag | journal | retry | health |
    | --- | --- | --- | --- | --- |
    | confirm **read** at boot | `confirmRecoveryReadFailed` (#8566) | yes | — | degraded |
    | confirm **removal** | `confirmRemoveDegraded` (#5835) | yes | yes | degraded |
    | confirm **arm/write** (before #9014) | **none** | **none** | **none** | **200 OK** |

    It now logs at ERROR, journals `confirm_arm_error`, sets
    `confirmArmDegraded` (folded into `ConfigPersistDegraded()`), and takes
    retry debt in the singleton persist-retry loop, which re-drives
    `WriteConfirm` until it lands and journals `confirm_arm_recovered`.

    **The commit is deliberately NOT failed.** That matches both neighbours
    and the #1960 no-brick posture: the configuration is applied and correct,
    only its crash-recovery record is missing, and refusing the commit would
    turn a durability problem into an availability one.

    **The retry is generation-pinned, and this is the part that is easy to get
    wrong.** `confirmArmGen` records which window the debt belongs to. If the
    window is confirmed, superseded or rolled back while the write is still
    owed, re-driving it would create a crash-recovery record for a window that
    no longer exists — a restart would then resurrect a rollback the operator
    had already resolved. That is the exact mirror of #7675 on the removal
    side, where re-driving a delete would have removed a LIVE window's record.
    The debt is instead dropped with a `confirm_arm_superseded` journal entry.
    `TestArmWriteDebtIsNotResurrectedAfterResolution9014` pins it, and removing
    the generation guard reproduces the resurrection deterministically.

    A SUCCESSFUL arm — first try or a later re-arm — discharges any outstanding
    debt, because the record on disk is then current; holding health down
    behind a satisfied debt would misreport a durable window as unsafe.

    `DB.WriteConfirm` now goes through the `rbWriteFileDurable` seam rather
    than calling `fsatomic` directly. Until #9014 there was no way to fail the
    arm write in a test at all, which is part of why this was the leg with no
    guard: nothing could reach the failure path.

*   **#8566 — a failed confirm READ at boot lost the window silently.**
    `recoverPendingConfirmLocked` logged a WARN and returned nil when
    `ReadConfirm` failed, so `Load` succeeded and the daemon came up with the
    rollback window GONE — no timer, no debt, and `ConfigPersistDegraded()`
    false, so /health returned 200 and
    `xpf_daemon_config_persist_degraded` read 0. The still-UNCONFIRMED config
    stood permanently, which is the #4577 failure the record exists to
    prevent, and the only evidence was one log line. Every other way the
    store ends a boot unsafe raises degraded health; this one did not, so
    nothing alerted on it. The read failure now logs at ERROR, journals
    `confirm_recovery_read_error`, and sets `confirmRecoveryReadFailed`,
    which `ConfigPersistDegraded()` folds in (→ /health 503 + the gauge) and
    `ConfirmRecoveryReadFailed()` exposes on its own. Three deliberate
    non-changes: `Load` still SUCCEEDS (refusing to boot on an unreadable
    transient recovery file would turn a corrupt 200-byte file into an
    outage — the #1960 no-brick posture); the record is NOT deleted (a
    decrypt failure can be a transient master-key problem and the window may
    be readable on a later boot); and no bounded in-`Load` retry split by
    error class is added, because that is a startup-latency and taxonomy
    change with its own design. The state is not self-healing — the window
    is gone — so it clears on operator action: the next successful arm or
    removal of a confirm record.
  - **The removal debt is KEYED to the record it is owed for (#7675).**
    The retry above re-drove `removeConfirmState()` UNCONDITIONALLY, so it
    deleted whatever `confirm.json` was on disk. An operator who armed a
    BRAND-NEW `commit confirmed` while a debt was outstanding therefore had
    the NEW window's crash-recovery file deleted by a retry that believed it
    was clearing the old one — deterministic, not a race, and invisible: the
    in-memory timer stays armed and `IsConfirmPending()` is true, so the
    damage only shows after a restart, when the UNCONFIRMED config stands
    with no rollback (the #4577 failure the record exists to prevent).
    `resolveConfirmRemovalLocked` now captures the record's identity
    (`GuardedHash` + deadline + `FirstCommit`) BEFORE deleting and stores it
    as `confirmRemoveDebtID`; the retry clears the debt WITHOUT deleting when
    the record on disk is a different one, because a newer arm's
    `WriteConfirm` (temp+fsync+rename+dir-fsync) has already durably replaced
    the record the debt was owed for. Absent or unreadable is deliberately
    NOT "superseded": an absent record still owes the #4864 directory
    barrier, and an unreadable one cannot be a fresh arm, so both still
    re-drive the delete. #5473 had recognised this exact shape for its OWN
    deferred-resolution debt and drains it at every arm site before
    `writeConfirmState` writes the fresh record; #5835 added a second debt
    and did not extend that drain. Keying holds for an arm path that forgets.
- **Durable deletes match durable writes (#5197).** A delete of a
  secret-bearing artifact fsyncs its parent directory so the removal is
  durable, mirroring the `fsatomic.WriteFileDurable` its writer used — a
  bare `os.Remove` is not durable, so a power cut in the window before
  the directory-entry removal flushes can replay the deleted file on
  reboot. `DeleteRescueConfig` fsyncs `rescue.conf`'s directory after the
  unlink (its creator `SaveRescueConfig` is dir-synced); the resurrected
  copy would otherwise re-expose the cleartext secret leaves rescue.conf
  carries (IKE PSK / SNMP community / auth-keys, #4056). `FactoryResetConfigDir`
  (the on-box `request system zeroize`) additionally fsyncs `.configdb`
  BETWEEN the key-first `master.key` unlink and the ciphertext `RemoveAll`
  — so an interrupted wipe can never leave ciphertext together with a
  still-durable key — and PROPAGATES the final `configDir` fsync error
  (the pre-#5197 code discarded it), so a non-durable wipe is never
  reported as a clean factory reset. All routes go through the
  `rbRemove`/`rbSyncDir` seams so a dropped sync fails a test RED. The
  top-level sweep also removes fsatomic crash-leaked write temps
  (`.<base>.tmp-*`, #5475) — a daemon killed between `fsatomic`'s
  `CreateTemp` and its rename leaves a temp holding the full cleartext
  config text it was mid-writing (xpf.conf / rescue.conf / a rollback
  slot). `fsatomic` self-heals such a temp on the next write to that
  base (`NewDB` sweeps the same `.*.tmp-*` glob inside `.configdb`), but
  a factory reset + reboot means there is no next write, so an unswept
  top-level temp — and its secrets — would survive. The gRPC
  `zeroizeConfigDir` mirror in `pkg/grpcapi` carries the same barriers
  (its own `zeroizeSyncDir` seam) and the same `.<base>.tmp-*` sweep.
- **Ownership-scoped deletion (#5768).** The top-level sweep matches ONLY
  the artifacts xpf itself created/tracks — the live config file (by EXACT
  name, `configBase`, so a non-`.conf` `-config` base like `site.cfg` is
  erased too), `rescue.conf` (`RescueConfigBase`), `.config.journal[.N]`,
  the numbered text rollback slots `<configBase>.<N>`, and fsatomic crash
  temps — NEVER a broad `*.conf` suffix or `rollback*` prefix glob. The old
  globs deleted UNOWNED siblings when a custom `-config` resolved the config
  root to a shared directory or a subdir that slipped past the
  `FactoryResetForbiddenRoots` denylist (`/data/xpf.conf` → wipes `/data/*`;
  `/etc/frr/x.conf` → deletes xpf's own rendered `frr.conf`). A denylist is
  inherently incomplete on a wildcard wipe; ownership scoping bounds the
  deletion to xpf's own files instead, with the denylist kept as
  defense-in-depth. `FactoryResetConfigDir` (CLI) and the gRPC
  `zeroizeConfigDir` mirror apply the identical scoped match; the dedicated
  `<root>/.configdb` and (gRPC-only) `<root>/tls` subdir `RemoveAll`s stay —
  those are exclusively xpf-owned subdirectories.
- **Symlinked erase targets are REFUSED, not unlinked (#9013).** `os.Remove`
  and `os.RemoveAll` act on the **link** when a path's FINAL component is a
  symlink: they unlink it, return `nil`, and the real bytes stay on the target
  volume — so the operator saw "System zeroized. Configuration erased." while
  the archived config text, `active.json`, the live config, the rescue config,
  the audit journal, the numbered rollback slots, `master.key` or `tls/key.pem`
  survived. (Only the final component matters; when an INTERMEDIATE component
  is a link, `RemoveAll` resolves through it and does erase the real directory —
  measured, not assumed.) Every such path is now `Lstat`ed via the shared
  `configstore.SymlinkTarget` predicate before removal; a link is recorded and
  SKIPPED, and the wipe returns a `*FactoryResetSymlinkError` naming each path
  **and its target** so the operator knows where the secrets actually are.
  Refusing rather than resolving-and-erasing matches `ValidateFactoryResetRoot`'s
  doctrine: a link may point at a shared, remote or compliance volume that is
  not xpf's to destroy, so the reset fails CLOSED instead of guessing. A skipped
  erase OUTRANKS a failed one when both happen (an erasure that did not happen
  at all is strictly worse, because only a failure announces itself), and the
  two are `errors.Join`ed so neither is swallowed.
  - The `.configdb` ordering is why that check runs BEFORE any removal: the key
    deletion resolves THROUGH a symlinked directory and destroys the real
    `master.key`, and only then does `RemoveAll` unlink the link — destroying
    the key while leaving the config body. With no `system master-password`
    configured (the default, so `maybeEncryptTreeJSON` returns plaintext) that
    body is the full cleartext config, and the key-first cryptographic-erasure
    guarantee buys nothing.
  - The INVERSE shape — a real `.configdb` holding a symlinked `master.key` —
    leaves the real key while the body is erased, defeating cryptographic
    erasure in the other direction against a backup of the DB. There the body
    erase still proceeds: the key cannot be destroyed, but removing the
    ciphertext leaves nothing on this box for it to decrypt.
  - **The guard is applied to BOTH twins.** This erase logic exists twice, and
    `FactoryResetConfigDir` in this package has **no non-test caller** —
    `pkg/grpcapi`'s `zeroizeConfigDir` is the one production runs, via
    `PerformZeroizeWipe` (the gRPC path and, through the `zeroizeFullWipe` seam,
    the console). A guard written only against this package's copy would have
    been inert in production, which is why the predicate is shared rather than
    re-spelled. `tls/` is gRPC-only and is covered there.

- **`FactoryResetArchiveDir` — local config-archive erasure (#5186).**
  `zeroize` must remove EVERY on-box generation of config secrets. The
  config archive (`<archive-dir>/config-*.conf`, 0600 full-config-text
  with cleartext secret leaves — see the persistence-layout table above)
  was the omitted generation: a pre-#5186 wipe left `/var/lib/xpf/archive`
  behind, so a re-tenanted device kept the prior tenant's archived
  secrets. `FactoryResetArchiveDir` `RemoveAll`s the archive tree and
  fsyncs the parent (same error-surfacing + durability discipline), and
  BOTH the on-box CLI `request system zeroize` and the gRPC
  `performZeroizeWipe` route archive erasure through this one shared
  primitive. **Ownership guard:** it erases ONLY the xpf-owned default
  (`DefaultArchiveDir` = `/var/lib/xpf/archive`); a custom / remote /
  compliance archive destination is not provably xpf-owned, so it is
  SKIPPED with a warning rather than blindly deleted.
- **Archive-writer fence + join (#5869 / #6182, extended in #6185).**
  Erasing the directory is not enough — an archive writer can recreate it
  AFTER the wipe. Auto-archive launches a fire-and-forget writer goroutine
  per commit (`commitWithDescriptionLocked`) and `writeArchive` starts with
  `os.MkdirAll(archiveDir)`, so a writer scheduled just before a `zeroize`
  could resume after `FactoryResetArchiveDir` removed the archive dir and
  drop a `config-<ts>.<seq>.conf` snapshot of the PRIOR tenant's full config
  text back on disk — re-tenant secret residue. `Store` gains `archiveWG`
  (tracks in-flight writers) and `archiveFenced` (a one-way latch).
  `QuiesceArchival()` sets the fence under `s.mu` (no NEW writer launches;
  the `Add`/`Wait` ordering is race-free) then `archiveWG.Wait()` JOINS every
  in-flight writer — the load-bearing half, since a fence alone cannot close
  the write-after-wipe window. `ResumeArchival()` clears the fence only on the
  fail-closed recoverable path. **#6185:** the SYNCHRONOUS `Store.ArchiveConfig`
  path (zero production callers today) now honors the SAME fence — it no-ops
  when fenced and registers in `archiveWG` when not, so a future operator
  wiring (`request system configuration archive`) cannot bypass the zeroize
  fence. `daemon.factoryReset` calls `QuiesceArchival()` after entering the
  reset generation and before the wipe.
- **`CommitConfirmed` ordering.** Confirm state is only touched after
  the persist succeeds: on failure the rollback timer is NOT armed and
  an existing pending confirm (timer + rollback target) is left fully
  intact. A generation token guards the rollback callback: a timer
  that already fired but lost the lock race to a nested re-arm or an
  explicit confirmation no-ops instead of reverting the newer commit.
  Nested confirmed commits (a second `CommitConfirmed` while
  one is pending) PRESERVE `confirmPrevTree` — the rollback target
  stays the last truly CONFIRMED config, not the unconfirmed
  commit-1 tree.
- **A plain commit CONFIRMS a pending `commit confirmed` (#3861).**
  Junos semantics: any subsequent explicit `commit` confirms a pending
  `commit confirmed`. The frontend `commit` path intercepts a pending
  confirm (`IsConfirmPending`) and calls `ConfirmCommit` before it ever
  reaches the store commit — the interactive cli/gRPC/REST handlers all
  do this dance at their own layer. The NON-frontend committer that
  bypasses it is the eventengine autonomous-remediation commit, which
  reaches `Commit`/`CommitWithDescription` directly during a pending
  window (any future direct-store caller is covered too — the fix is
  defense-in-depth at the store layer, not a per-caller patch). Those
  paths now call `clearPendingConfirmLocked` AFTER the
  persist+promote succeeds: it cancels the armed rollback timer and
  bumps `confirmGen` so the just-promoted config becomes the confirmed
  config. Without it the pending timer's stale rollback target (the
  pre-confirm T0 tree) fired and SILENTLY reverted the background
  commit, discarding it (the eventengine sequence: operator `commit
  confirmed 5`; remediation `Store.Commit` at T+2; T+5 timeout reverts
  to T0, losing the remediation). This does NOT touch the nested
  confirmed→confirmed re-arm (that goes through `CommitConfirmed`, which
  re-arms and preserves the target) — only a PLAIN commit confirms.
- **A bare `commit` during the window also commits any NEW candidate edits
  (#4000).** The frontend intercept confirms-only (`ConfirmCommit`, timer
  cancel with no promotion) ONLY when the candidate is UNCHANGED
  (`!IsDirty()`). If the operator staged edits after `commit confirmed`, the
  intercept falls through to the normal commit, so `CommitWithDescription`
  applies the new candidate AND clears the timer (via the #3861
  `clearPendingConfirmLocked`). Junos semantics: a `commit` during a confirm
  window confirms the pending config AND commits new edits — they must not be
  silently dropped. The pre-#4000 intercept confirmed-and-discarded (the new
  edits were lost while `commit` returned success). `ConfirmCommit` itself
  never promotes the candidate, so routing a dirty candidate through it is the
  silent-loss bug; the `!IsDirty()` guard is the fix at all three frontends
  (cli/gRPC/REST).
- **`SyncApply` (HA config-sync receive) — Option B,
  degrade-not-fail.** The in-memory apply always proceeds (failing it
  would silently diverge the cluster; sync is one-way fire-and-forget).
  An authoritative config synced from the cluster primary also CONFIRMS
  any commit-confirmed window still pending on this node (#3861): a node
  that armed `commit confirmed`, failed over to standby, then received a
  primary sync must not later revert the synced config to its stale
  local pre-confirm tree. `SyncApply` calls `clearPendingConfirmLocked`
  with the in-memory promotion (the timer cancel stands even if the disk
  write below fails, matching the degrade-not-fail contract).
  A persist failure sets the store's degraded flag — surfaced by
  `ConfigPersistDegraded()` as `/health` 503 and the
  `xpf_daemon_config_persist_degraded` Prometheus gauge — writes a
  `persist_error` journal entry, and starts a SINGLETON background
  retry goroutine (1s backoff doubling to a 60s cap) that re-reads the
  CURRENT `s.active` under `s.mu` on each attempt, clears the flag on
  success, and exits. Successful writes on any commit/sync path also
  clear the flag.
- **`PromoteRollback` / `performAutoRollback` (confirm-timer expiry) —
  Option B.** The in-memory rollback always proceeds (reverting the
  running config is the safety property); a persist failure gets the
  same degraded flag + retry, which replaces the unconfirmed candidate
  the earlier `CommitConfirmed` left on disk with the rolled-back tree.

### Commit-confirmed timeout rollback ownership (#1922 Item 1a)

The store owns ONLY the store-state promotion primitive
(`PromoteRollback(gen) (prevCfg, ok)`): under `s.mu` it honors the
#1817 `confirmGen` staleness guard, promotes `active`/`compiled` to the
saved pre-confirmed state, persists with the #1799 degrade-not-fail
semantics, journals `auto_rollback`, and returns the compiled
pre-confirmed config. It does NOT touch the dataplane.

The DAEMON owns the rollback *transaction*. xpfd registers
`executeConfirmedRollback` via `SetRollbackExecutor` at daemon init, so
the confirm timer (which fires on its own goroutine) hands it the
generation; the executor acquires the apply semaphore FIRST, then calls
`PromoteRollback` + the full dataplane reconcile inside that one
critical section. This makes store promotion and dataplane re-apply
atomic with respect to a concurrent `commit` (which also holds the apply
semaphore), and — unlike the old interactive-only
`SetCentralRollbackHandler` callback — wires the rollback in SERVICE
mode (gRPC/REST/remote-cli) too. When no executor is registered (tests,
non-daemon embedders) the timer falls back to the self-contained
`performAutoRollback`, which promotes store state but does not re-apply
a dataplane it has no handle on.

The first-commit rollback target (#1922 Item 1b) is now implemented: on a
FRESH-store first `commit confirmed` timeout `PromoteRollback` reverts the
store to the empty bootstrap tree, persists the **never-committed marker**
(committed=0, NOT an empty *committed* tree — see step-0 marker below),
clears the in-memory `everCommitted` flag, and returns `(nil, true)`. The
daemon executor detects the nil `prevCfg` and calls `enterBootstrapMode`
(interface/FRR/dataplane takeover cleanup, keeping the management lifeline)
instead of applying an empty config to the dataplane. A subsequent restart
therefore re-classifies into bootstrap (the marker disambiguates
never-committed from operator-committed-empty).

**First-commit-ness is RECORDED, not re-derived from the nil (#6538).**
`confirmPrevCfg == nil` carries two unrelated meanings, and the action taken
on one of them is destructive for the other:

1. *there was no compiled config to stash* — this genuinely is the first
   commit on a fresh store; and
2. *the recovered rollback target failed even the LENIENT compile* —
   `recoverPendingConfirmLocked` re-arming a window that was still open at
   boot. `Store.Load` repairs the tree it reads from `active.json`
   (`rewriteRetiredDataplaneType`, `SanitizeTreeControlChars`) but never the
   `PrevTree` carried inside `confirm.json`, so a target committed on an
   older build — `system dataplane-type ebpf` is the concrete case — reaches
   the recovery uncompilable.

`Store.confirmPrevFirst` records the fact where it is known (the arm site
reads the PRE-promotion `s.compiled`; the recovery site reads the persisted
`rec.FirstCommit`) and both consumers read the flag: `PromoteRollback`'s
`firstCommitRollback`, and the `firstCommit` bit `writeConfirmState`
persists on a nested re-arm. Deriving them from the nil made meaning (2)
persist `committed=0` **over a real config**, so the next restart
re-classified a production box into bootstrap (day-0 / claim-all) — and a
nested arm wrote `FirstCommit=true` into `confirm.json`, making that
mislabelling durable across the reboot after it.

The **runtime** action on a nil `prevCfg` is deliberately unchanged and
unbranched: with no compiled config to apply, `enterBootstrapMode`'s
lifeline safe state is exactly what #1960 prescribes for a
present-but-uncompilable committed config, and the next boot re-derives that
state from disk through the main `Load` path. Only the PERSISTENCE differs
between the two provenances.

**The expired-during-downtime branch fails closed (#6538).** When that
branch cannot compile its rollback target it still performs the rollback —
reverting the unconfirmed config is the safety property, and the reverted
tree must stay reachable for `configure` / `show | compare` / `rollback` —
but `recoverPendingConfirmLocked` now RETURNS an `ErrConfigCompile`-tagged
error, which `Load` propagates. Previously it warned, assigned the nil into
`s.compiled`, set `everCommitted = true`, and `Load` returned success: the
daemon then saw `ActiveConfig() == nil` + `everCommitted` and resolved to a
NORMAL boot with **no compiled policy**, running the positional claim-all
interface rename. That is precisely the shape #1960 fails closed on, and the
tagged error routes it through the same `classifyLoadError` →
`loadCompileFailed` → #1922 bootstrap/lifeline path.

### Config lock: shared/private vs. exclusive holders (#3979)

Only one session edits config at a time. The store tracks the holder in
two fields depending on the mode the session entered:

- **shared / private** (`EnterConfigure`, `EnterConfigureSession`) —
  holder recorded in `configHolder`.
- **exclusive** (`EnterConfigureExclusive`, from `configure exclusive`) —
  holder recorded in `exclusiveHolder`; `configHolder` stays empty.
  `IsExclusiveLocked()` keys off `exclusiveHolder != ""`.

The release path (`ExitConfigureSession`) must match the session against
**whichever field its acquiring mode set**. It compares against
`effectiveHolderLocked()` — `exclusiveHolder` when set, else
`configHolder` — so a session releases the exact lock it holds.

**Every exit clears BOTH fields.** `ExitConfigure`,
`ExitConfigureSession`, `ForceExitConfigure` and the
`reclaimStaleLockLocked` re-acquire all reset `configHolder` *and*
`exclusiveHolder`, so no exit leaves a holder string behind for the next
reader of `ConfigHolder()`.

**#7635 (fixed):** `ExitConfigure` cleared only `exclusiveHolder`. A
shared-mode lock taken by `EnterConfigureSession("X")` therefore left
`configHolder == "X"` after the exit, and the public `ConfigHolder()`
accessor returned that stale string alongside `locked == false`. It was
never operator-visible — all three consumers (`clear system config-lock`
in `pkg/cli`, the REST `clear-config-lock` action in `pkg/api`, and the
gRPC diag action) check the `locked` bool first — and never exploitable,
because `ensureHolderLocked` short-circuits on `!s.configDir` and because
every in-tree caller of `ExitConfigure` pairs it with the unsessioned
`EnterConfigure`. But neither of those is a property of the function, so
the release is now complete on all four paths rather than resting on its
callers. Guarded by
`TestEveryConfigModeExitClearsBothHolders_7635`, which enters with a
non-empty session id precisely because an `EnterConfigure()` fixture
would pass vacuously.

**#3979 (fixed):** the release guard previously compared only
`configHolder`. An exclusive holder sets `exclusiveHolder` and leaves
`configHolder` empty, so the guard saw `configHolder("") != sessionID`
and returned `false` **without clearing anything**. The exclusive lock
then persisted with no live holder, and every subsequent
`configure` / `configure exclusive` / `configure private` was rejected
until daemon restart — a single operator running `configure exclusive`
then disconnecting bricked all future config edits. The connection-close
auto-release (`configLockStatsHandler`'s `ConnEnd`, `pkg/grpcapi`; #5849)
routes through `ExitConfigureSession`, so it silently failed too; matching
the effective holder restores that stale-holder reclaim on disconnect.

`ConfigHolder()` likewise reports the effective holder, so
`clear system config-lock` / diagnostic output attributes an exclusive
lock to its real holder instead of an empty string. A genuinely-active
holder still blocks other sessions (`EnterConfigure*` rejects with
`ErrConfigLocked` while `configDir` is set), and a non-holder's exit
cannot steal the lock. `ForceExitConfigure` (`clear system config-lock`)
remains the unconditional operator override.

### Config lock: idle-lease reaper (#4476)

The gRPC config path auto-releases the lock when a client's CONNECTION
ends (`configLockStatsHandler`'s `ConnEnd` in `pkg/grpcapi`, #5849, calls
`ExitConfigureSession` exactly once — keyed by the connection-scoped id,
never on per-RPC cancellation, so a cancelled unary no longer discards the
connection's candidate). The **REST** config
path has no such hook: `POST /api/v1/config/enter`
(`configEnterHandler`) takes the global lock with a per-session holder token (#6197; historically an empty holder, which #6196/#6197 replaced), and a
stateless HTTP client that never calls `/config/exit` leaves it held. On
its own that wedged every CLI/gRPC/REST config edit with `ErrConfigLocked`
until `clear system config-lock` or a daemon restart — a management-plane
config-edit DoS.

`configLockAt` (recorded at acquire) now backs an **idle-lease reaper**:

- **Refresh on activity** — every config mutation calls
  `touchConfigLockLocked()` (`store_lock.go`), which stamps
  `configLockAt = now` while `configDir` is set. Both transports funnel
  edits through the store's mutating methods (`Set`/`Delete`/`Deactivate`/
  `Activate`/`Copy`/`Rename`/`Insert`/`Annotate`/`Load*` in
  `store_command.go`; `Commit`/`CommitConfirmed`/`Rollback` in
  `store_commit.go`), and same-session re-entry refreshes too. Reads
  (`show`/status polls) deliberately do **not** refresh, so a lock whose
  holder stops editing ages out. The internal HA-sync ingress
  (`SyncApply`) and the commit-confirmed timeout revert
  (`PromoteRollback`) are timer/peer paths, not user activity, and do not
  refresh.
- **Reclaim on acquire** — `EnterConfigureSession` /
  `EnterConfigureExclusive` call `reclaimStaleLockLocked()` before
  rejecting a would-be entrant. It releases the current lock (mirroring
  `ForceExitConfigure`'s teardown, including `exclusiveHolder` /
  `editPath`) **only** when `time.Since(configLockAt) >=
  configLockLeaseTTL`, then the caller enters cleanly. A stale lock is
  therefore reclaimed exactly when another session needs it — the only
  moment a stuck lock causes harm — so no background goroutine is
  required.

`configLockLeaseTTL` defaults to **10 minutes**: long enough that an
operator hand-composing a change (each `set`/`delete` refreshes the
lease) is never reclaimed mid-edit, short enough to bound a wedged REST
lock. An actively-edited lock is never stolen; only a genuinely-idle one
is. The tests in `store_lock_lease_4476_test.go` cover both directions
(stale lock reclaimed, active/refreshed lock preserved) and are the
RED-on-revert guard. Note that recovery still surfaces the lock while it
is stale — a companion REST clear-config-lock action (L-1 / #4484) would
let a REST operator release it explicitly without waiting for the next
entrant; that is tracked separately.

### Cluster read-only gate (#3893)

On an HA chassis cluster the RG0 primary is the INTENDED sole config
authority: on a secondary **whose gate is armed** the store is read-only
and receives config only via `SyncApply` (peer sync from the primary).
The daemon arms and disarms that mode from the RG0
primary↔secondary TRANSITION handler — `applyRG0OwnershipTransition`
(`pkg/daemon/daemon_ha.go`) — and from nowhere else:
`SetClusterReadOnly(true)` when this node becomes secondary,
`SetClusterReadOnly(false)` when it is promoted to primary.

**Arming is not universal — do not read the heading as unconditional
(#6896).** That transition handler is the only production caller of
`SetClusterReadOnly` (`git grep -n SetClusterReadOnly -- '*.go'` returns
the setter plus its two lines in `daemon_ha.go`); there is no startup
arming and no reconcile that re-derives the flag, and
`Store.clusterReadOnly` is a plain `bool` with no constructor
initialisation, so it starts `false` (pinned by
`TestClusterReadOnly_ZeroValueStoreIsWritable_6896`). A node that
cold-starts, seats as RG0 secondary and never transitions therefore has
a **writable** store — and `pkg/api/config.go` enters a configure
session with no RG0 check of its own, where gRPC guards on
`IsLocalPrimary(0)` (`pkg/grpcapi/server_config.go`) and the interactive
CLI has its own check (`pkg/cli/cli_dispatch.go`). That gap is
**#6890**; the dropped-transition-event variant — the manager reaches
primary while the store stays read-only — is **#6889**. Both are OPEN.
Everything below describes what the gate does ONCE ARMED; it is the
design intent, not a property every secondary has.

`clusterReadOnly` was originally checked ONLY at the `EnterConfigure*`
gate. That left two holes: a config session **opened before** the node
became secondary, and any mutating path that did not re-enter
`EnterConfigure`. Once a session was open, `Set`/`Delete`/`Commit`/
`Load*`/`Rollback` only verified `candidate != nil` — so an open session
could `Set` + `Commit` on the read-only secondary and **diverge** its
active config from the primary (a local edit the primary never sees,
which the next config-sync overwrites — churn/divergence).

The gate is now enforced on **every user-session mutating op** through
`ensureWritableLocked()` (called under `s.mu`): `Set`, `Delete`,
`DeactivateFromInput`/`ActivateFromInput`, `Copy`, `Rename`, `Insert`,
`Annotate`, `LoadOverride`/`LoadMerge`/`LoadSet`, `CommitWithDescription`
(and thus `Commit`), `CommitConfirmed`, and `Rollback`, in addition to
the retained `EnterConfigure*` gate. A rejected op returns the
`ErrClusterReadOnly` sentinel ("configuration is read-only on the
cluster secondary"), which `errors.Is` distinguishes from the transient
`ErrConfigLocked`.

**Internal-sync bypass (load-bearing):** the secondary must still APPLY
config authored by the primary. `SyncApply` (HA peer-sync ingress) and
`PromoteRollback` (commit-confirmed timeout revert) promote the
`active`/`compiled` state **directly** and never route through the gated
`Set`/`Commit`/`Load`/`Rollback` methods, so they are unaffected by this
gate — exactly the distinction between a user-driven mutation (blocked
on a secondary whose gate is armed) and an internal convergence apply
(must proceed).
Boot-time `bootstrapFromFile` enters config mode first, so it too is
governed by the same gate (a no-op there because `clusterReadOnly` is
`false` at boot, before any RG0 transition).

### Config-lock ownership gate (#5059)

The candidate is intentionally **singular and shared** — `EnterConfigure*`
records the holder session and blocks a second *enter*, but the mutating
methods themselves used to verify only `ensureWritableLocked()` +
`candidate != nil`. That meant a session that **never entered config mode**
(only the *enter* was gated) could still call `Set`/`Delete`/`Load`/
`Rollback` directly, mutate another session's pending candidate, refresh the
true holder's idle lease (`touchConfigLockLocked`), and `Commit` it — all
with no ownership check. Serialization under `s.mu` orders those calls; it is
not authorization. This surface is reachable on the loopback gRPC listener
and, more importantly, on the HA fabric listener.

Ownership is now enforced atomically under `s.mu` via
`ensureHolderLocked(sessionID)`, called inside every user mutator's critical
section through session-scoped `*As` variants: `SetAs`,
`SetFromInputAs`, `DeleteAs`, `DeleteFromInputAs`,
`DeactivateFromInputAs`/`ActivateFromInputAs`, `CopyAs`, `RenameAs`,
`InsertAs`, `AnnotateAs`, `LoadOverrideAs`/`LoadMergeAs`/`LoadSetAs`,
`RollbackAs`, and `ConfirmCommitAs`. (`AnnotateAs` closed a #5379 gap — before
it, `Annotate` was the one candidate mutator with no ownership check at all, so
a non-holder could annotate another session's candidate and refresh the true
holder's idle lease.) The commit-family RPCs whose mutation runs through a daemon
callback (`Commit`, `CommitConfirmed`) call the exported `EnsureConfigHolder`
first. The gRPC handlers thread `connSessionID(ctx)` — the connection-scoped id
(#5849), the same identifier `EnterConfigureSession` records — into every one
of these, so a second remote session is rejected with `ErrConfigLockedByOther`
(mapped to `codes.PermissionDenied`).

Two deliberate bypasses keep the internal paths working:

- **`sessionID == ""` is the internal/system capability** — daemon apply, HA
  sync, the in-process CLI, and tests all call the plain (non-`As`) methods,
  which delegate with an empty session and skip the ownership check.
- **A lock with no recorded holder** (`effectiveHolderLocked() == ""`, i.e.
  the internal/local `EnterConfigure()` path) is not owned by any session, so
  a user session is not blocked from it. A remote gRPC caller always carries a
  non-empty `connSessionID` (its connection-scoped id, #5849) and records it on
  `EnterConfigureSession`, so it cannot manufacture an empty-holder state to
  slip through.

**REST config mutations use distinct holder identities (#5870, #6197).**
Originally the stateless REST config endpoints (`pkg/api/config.go`) called the
plain methods with `sessionID == ""`, so a remote REST caller silently wielded
the internal/system bypass and could Set/Delete/Load/Rollback/Commit a candidate
that a CLI or gRPC session legitimately held. Every REST config
enter/set/delete/deactivate/activate/load/annotate/rollback/commit/
commit-confirmed/confirm is routed through the `*As` variants and the
`EnsureConfigHolder` commit gate. `POST /api/v1/config/enter` generates a
distinct 128-bit identity, returns it as `data.session_id`, and records it as
the holder. The client must send that value in the `X-Config-Session` header on
subsequent holder-scoped requests (including exit); enter accepts an existing
valid token only to re-enter the same session and refresh its idle lease.
A mutation from a different REST client, or from CLI/gRPC, is rejected with
`ErrConfigLockedByOther` (HTTP 409 Conflict), and CLI/gRPC is symmetrically
rejected while REST holds the candidate. Missing or malformed REST tokens fail
with HTTP 400 before reaching the store, so they cannot become the
`sessionID == ""` internal/system bypass. `/config/exit` releases only the
matching holder through `ExitConfigureSession`. Read-only endpoints are
unaffected, and a wedged REST lock is still reclaimed by the #4476 idle-lease
reaper.

Like `ErrClusterReadOnly`, `ErrConfigLockedByOther` is `errors.Is`-matchable;
it is transient (the holder commits or exits). The internal `SyncApply` /
`PromoteRollback` convergence applies never route through the gated methods,
so they are unaffected — same distinction as the read-only gate above.

### Step-0 committed marker (#1922 Item 2)

The config-DB compatibility envelope (#1917) carries a `committed=` header
field that records whether the on-disk `active.json` is a
successfully-committed config (`committed=1`) or the never-committed
marker (`committed=0`) written by the Item-1b first-commit rollback. The
five-case boot predicate (in `pkg/daemon`) reads `Store.EverCommitted()`
to decide bootstrap vs normal when the active config is empty.

**Migration rule (mandatory):** a DB written by an OLDER build omits the
field; `parseEnvelopeHeader` defaults a missing `committed=` to **true**,
and a legacy no-envelope DB also reads committed. An upgraded box with an
existing active config can therefore never misclassify into bootstrap; the
never-committed marker is forward-only. `WriteActive` stamps
`committed=1`; `WriteActiveMarker(tree, false)` writes the never-committed
marker. `everCommitted` is set on `Commit` / `CommitConfirmed` /
`SyncApply` and cleared by the first-commit rollback.

Test seams (`test_seams.go`): `SetWriteActiveForTesting` injects
persistence failures on every persist path;
`SetWriteActiveMarkerForTesting` observes the step-0 committed bit;
`SetPersistRetryBackoffForTesting` makes the retry loop deterministic.

### `Store.Load` error sentinels (fail-closed boot)

`Load` returns one of three error shapes the daemon distinguishes with
`errors.Is`:

- **`ErrConfigDBUnreadable` (#1917 D1)** — a PRESENT `active.json` whose
  bytes cannot be read (JSON parse error, decrypt failure, a too-new
  compatibility envelope, or a top-level body that is not a JSON object —
  `null`/array/scalar, #5474). The daemon FAILS CLOSED by exiting `Run`, so an
  unreadable/too-new/non-object DB is never overwritten by a blind bootstrap.
- **`ErrConfigCompile` (#1960)** — a PRESENT `active.json` that read+parsed
  fine but no longer COMPILES, even through the tolerant `compileTreeLenient`
  path (e.g. a committed config whose referenced apply-group was later
  deleted in a partially-edited DB). `Load` has already set
  `everCommitted=true` from the on-disk `committed=` marker but leaves
  `compiled` nil, so `ActiveConfig()` returns nil. Without a guard that
  tuple (`ActiveConfig()==nil` + `EverCommitted()==true`) drives the daemon
  boot predicate to NORMAL and positional claim-all interface naming. The
  daemon detects `ErrConfigCompile`, skips the text-config bootstrap import,
  and enters the #1922 bootstrap/lifeline safe state (mgmt preserved, no
  claim-all, control plane up) instead of exiting (a hard exit would also
  strand mgmt). See `pkg/daemon` `classifyLoadError` / `computeBootClass`.
  - **`Load` still populates for in-band recovery.** `compiled` MUST stay nil
    (that is the bootstrap signal), but on this path `Load` assigns the
    parsed-but-broken tree to `active` and calls `loadRollbackHistory()`
    anyway. So the operator's recovery is real: `EnterConfigure` clones the
    broken tree (the candidate shows the config to fix, not an empty tree),
    and `Rollback(n)` reaches the on-disk history. `active` is always non-nil
    (the constructor seeds an empty tree), so `(active non-nil, compiled nil)`
    here is the same shape a fresh boot already has — no new invariant.
- **any other error** — logged as a warning; the daemon proceeds and the
  boot predicate decides bootstrap vs normal as usual.

An ABSENT DB is NOT an error (`Load` returns nil; start-fresh).

## Audit journal (#1896)

`.config.journal` (next to the config file) is a JSONL audit trail
owned by the `journal/` subpackage.

- **Compact v2 entries** — `{v, timestamp, action, detail,
  config_hash}`. The v1 format appended the FULL compiled config per
  commit (read by nobody — `show system commit` prints only
  timestamp/action/detail) so the file grew by a config snapshot per
  commit and leaked config content (incl. secrets) into a 0644 file.
  Full trees live in the rollback files (above), which remain the
  canonical config history.
- **`system_action` entries (#4108 F8)** — `Store.LogSystemAction(verb)`
  appends a `{action: "system_action", detail: <verb>}` record for the
  destructive maintenance verbs `reboot`/`halt`/`power-off`/`zeroize`
  (written by `grpcapi.Server.SystemAction` BEFORE the action runs). The
  append is fsynced, so the record is durable on disk before the box goes
  down or the config is wiped — the `slog.Warn` line only reaches
  journald, which does not survive a reboot. For `reboot`/`halt`/`power-off`
  the on-disk record persists across the reboot. For `zeroize`, the wipe
  now **removes `.config.journal`** (and its rotated `.config.journal.N`
  segments) as part of the factory reset (#4576 — a completed reset must
  not hand its audit log / commit history / comments to the next tenant,
  and legacy v1 fat lines could carry full config incl. secrets in a 0644
  file). The cross-wipe trail is therefore the pre-execution fsync (an
  *interrupted* wipe still leaves the record) plus remote syslog — not
  on-box journal survival. `system_action` is deliberately EXCLUDED from
  `ListCommitHistory` (`show system commit` shows config commits only). The
  local gRPC transport is unauthenticated, so no operator identity is
  attributed — action + timestamp is the best-effort record.
- **`config_hash`** — sha256 hex of the post-action active tree's
  `Format()` text, the same text `saveRollbackFiles` writes: while a
  slot is retained, `sha256sum <config>.N` correlates the rollback
  file to its journal entry. Best-effort correlation only — slots
  shift every commit and only ~50 are kept.
- **Bounded reads** — `ListCommitHistory(limit)` is O(limit), not
  O(lifetime): `journal.Tail` reverse-scans segments newest-first in
  64 KiB chunks and stops at `limit` entries. Semantics preserved from
  v1: last `limit` entries of ANY action, then filtered to commit
  actions. `limit <= 0` still reads everything. Line assembly is
  capped at 16 MiB (corrupt newline-free content is skipped, not
  buffered whole).
- **Detail cap (#4891)** — an operator-supplied commit description is
  bounded at `maxCommitDescriptionBytes` (4 KiB). `CommitWithDescription`
  rejects an over-cap comment with a clear error BEFORE persist/promote
  (the #1960 strict-at-commit doctrine), so an oversized comment never
  bloats the journal. As a structural belt, `journalLog` also truncates
  any `Detail` past the cap (UTF-8-safe, with an explicit
  `…[truncated N bytes]` marker) — without the bound an oversized line
  would exceed the 16 MiB tail-assembly cap above and the reverse-tail
  scanner would silently discard the record it was meant to preserve.
- **Rotation** — at append time, when the current segment reaches
  1 MiB it rotates to `.config.journal.1` (keep 2 rotated segments,
  oldest deleted). A pre-#1896 fat journal rotates to `.1` intact on
  the first append — old history stays readable until it ages out; no
  migration pass, and boot never reads the journal.
- **Rotation defers to an in-flight append (#7174 C06)** — `Log`
  releases `j.mu` before its fsync (#4829), so a writer can be parked
  between its `f.Write` and its `f.Sync` while another writer rotates.
  The renames are harmless (a rename preserves the inode, so the parked
  writer's bytes move with it into `.1`), but rotation also UNLINKS the
  oldest kept segment, and once that inode is gone the parked writer's
  fsync still succeeds and `Log` still returns nil — the audit record is
  lost with no error anywhere, because `Store.journalLog` only warns when
  `Log` returns one. `maybeRotateLocked` therefore checks the inode of
  the segment it is about to destroy against `Journal.inflight` (appends
  registered under `j.mu` from their write until their fsync) and defers
  the rotation when they match. Deferring cannot starve: the condition
  names one OLD inode and later appends land on the current segment, so
  the next append after that writer's fsync rotates; the cost is a
  current segment that overshoots the threshold by one record. Reaching
  the destroyed slot takes `maxSegments+1` rotations, so this is an
  audit-integrity edge case rather than a routine loss — it is closed
  because of how silently it fails, not how often.
  Fail-on-revert: `TestRotationDoesNotDestroyInflightAppend7174C06` and
  its control `TestRotationResumesAfterInflightAppendDrains7174C06`
  (a guard that deferred forever would satisfy the first while disabling
  retention).
- **Durability** — appends are fsynced (operator-paced; the commit
  path already pays several fsyncs), `fsatomic.SyncDir` covers
  create/rotate namespace changes, and a torn tail (crash between
  write and fsync) is confined to one line: the reader's parse-or-skip
  rule drops it and the next append starts on a fresh line. The fsync
  running with `j.mu` RELEASED is a **deliberate, reviewed choice**
  (#4829), not an oversight: it is what keeps a concurrent `Tail` from
  blocking for the writer's entire fsync, and the durability contract is
  unchanged because `Log` returns success only after `f.Sync` (and, on a
  namespace change, `SyncDir`) succeed. #7174 C06 listed it alongside the
  rotation-unlink gap as one row; it was re-examined and left alone —
  moving the fsync back under the lock reintroduces #4829, and
  `TestTailNotBlockedByLogFsync` pins that it stays out. What the
  off-lock fsync DOES create is the in-flight window the rotation bullet
  above closes.
- **Back-compat** — legacy v1 lines (with `before`/`after` payloads)
  decode tolerantly; unknown fields are ignored. A journal `Log`
  failure is a `slog.Warn`, never a commit failure, and the
  `persist_error` path does not recurse.
- **Concurrency** — `Journal` serializes `Log`/`Tail` internally;
  `ListCommitHistory` deliberately takes no `Store.mu` (rotation +
  concurrent read would otherwise duplicate entries).

## Gotchas

- **Commit-check normalizes brace-elided statements BEFORE group expansion
  (#8921).** `schemaValidateExpandedTreeForNode` runs strip-inactive ->
  `config.NormalizeCompactForScan` -> `ExpandGroups` -> validate, the order the
  compiler already used. Strip MUST come first: the fold declines when the next
  sibling continues the container it would build, so an `inactive:` sibling the
  compiler never sees would make commit-check decline a fold the compiler
  performs (measured: an inline `neighbor 192.0.2.1 hold-time 30; inactive:
  hold-time 9;` failed to override the group's value again). It used to expand the tree as authored, and
  `ExpandGroups` merges a group body into inline config by statement SHAPE: a
  group spelling `neighbor 192.0.2.1 hold-time 2;` packed did not meet the
  inline `neighbor 192.0.2.1 { hold-time 30; }`, was appended beside it instead
  of being overridden, and was then normalized and refused as an invalid
  hold-time -- while the braced group body merged, the override won, and the
  same config validated clean (and the compiler accepted both). The
  definitions source handed to `SchemaValidateWithDefinitions` is the same
  stripped, normalized pre-expansion tree, because `collectSchemaRefs` also
  reads definitions by shape.
  `TestCommitValidationNormalizesBeforeGroupExpansion8921` pins it for both
  group-body spellings, the inactive-sibling case, and both node paths.
- Durable write protocol (#1894): `fsatomic.WriteFileDurable` — temp
  file in `.configdb`, fsync, rename, parent-dir fsync. The previous
  file survives an interrupted write intact, and a completed write
  survives power loss (the pre-#1894 writer skipped both fsyncs, so a
  "successful" commit could surface as a zero-length file or silently
  revert after a power cut).
- Rollback text files (`<config>.N`) are the CANONICAL rollback
  history (`loadRollbackHistory` reads them at boot; the DB rollback
  slots have no production callers). `saveRollbackFiles` writes slot 1
  durably and slots 2..N atomically (never missing, never torn; they
  may lag after a power cut), then one `fsatomic.SyncDir` makes the
  shuffle and the stale-slot unlinks durable — a single dir fsync
  instead of ~50 fsync pairs under the store mutex.
- Rollback-history degradation (#3441 L1): a rollback-slot write or the
  trailing dir-sync failing no longer just logs a warning. The commit
  still succeeds (the canonical active config already persisted via the
  #1799 path), but the store sets a degraded bit — surfaced by
  `RollbackHistoryDegraded()` — and journals a `rollback_persist_error`
  entry, so a stale-on-restart rollback history is visible rather than
  silent. The bit clears on the next fully-successful save.
- `loadRollbackHistory` / `cleanupRollbackFiles` stop ONLY on a
  genuinely-missing slot (`os.IsNotExist`), not on an arbitrary read/
  remove error (#3441 L2/L3): a transient or permission error on an
  intermediate slot logs-and-continues so the later readable slots still
  load and every stale slot is still cleared (preserving the
  contiguous-sequence invariant the loader assumes).
- Auto-archive correctness (#3441 H4): `CommitWithDescription` captures
  the JUST-COMMITTED `Format()` text plus a nanosecond-resolution
  timestamp inside the commit critical section and hands only those
  immutable values to the async archive goroutine. Previously the
  goroutine read `s.active.Format()` whenever it eventually ran (so a
  rapid second commit could make it archive the wrong tree) and named
  the file at second resolution (so two same-second commits overwrote
  one another). The filename
  (`config-YYYYMMDD-HHMMSS.nnnnnnnnn.<seq>.conf`) carries a nanosecond
  timestamp PLUS a monotonic per-process sequence number: the timestamp
  alone is not unique (two serialized commits can format the same
  nanosecond under a coarse clock or an NTP step-back), so the seq
  guarantees no archive is ever overwritten while the leading timestamp
  keeps rotation's lexical sort chronological. `ArchiveConfig` captures
  the text, timestamp AND seq together under the lock (no after-unlock
  `time.Now()` race). Rotation prunes by the parsed seq, and
  `SetArchiveConfig` seeds the per-process counter from the highest seq on
  disk so it stays globally monotonic across restarts (#5523 C179-060).
  The SYNCHRONOUS mirror `ArchiveConfig` writes to a dir passed as a
  PARAMETER (decoupled from the active `archiveDir`), so the shared counter —
  seeded from whatever dir `SetArchiveConfig` last activated — can sit BELOW
  that dir's on-disk max. #6403: it now holds the WRITE lock (not `RLock`)
  across the seed scan + seq claim and seeds the counter from ITS target dir's
  on-disk max (monotonic-up, mirroring the commit path's
  `ensureArchiveSeededLocked`) BEFORE claiming, so its archive always outranks
  the dir's existing contents. Claiming under the write lock also makes the
  seed+claim mutually exclusive with a concurrent `SetArchiveConfig` reseed, so
  the process-global counter cannot be bumped between its seed and its claim in
  the off-lock write window. Only the WRITE itself stays off-lock (a long
  archival I/O must not block reconcile/`QuiesceArchival`, #6185); the seed scan
  is a `ReadDir` under the lock, bounded by `archiveScanBudget` (#6776, below),
  exactly what the commit path already does. A genuine seed scan error
  (mount/permission — the on-disk max unknown) fails the synchronous call rather
  than write a below-max archive, as does a scan that exceeds the budget; a
  nonexistent dir is confirmed-empty, seq 0, and the write path's `MkdirAll`
  creates it.
  These monotonicity / no-overwrite guarantees hold **once the target
  archive dir has been successfully scanned** — the reseed is retried on
  every archiving commit until that scan succeeds (#6404), and while the
  scan is still failing (the on-disk max unknown) an archiving commit
  SKIPS its archive rather than write a below-max seq that rotation would
  prune, archiving normally on the next commit after the scan recovers —
  see the #6396/#6404 hardening note below.
  Two #6396 residual hardenings: `parseArchiveSeq` requires the current
  two-dot `config-<ts>.<seq>.conf` shape (the ts's own
  seconds.nanoseconds dot PLUS the seq dot), so a legacy pre-#3441
  `config-<ts>.conf` — whose trailing nanoseconds would otherwise be
  mis-read as a huge seq — is treated as unparseable (oldest, pruned
  first) in a mixed legacy+current dir; and `SetArchiveConfig` re-seeds on
  a target dir that DIFFERS from the last successfully-seeded one
  (monotonic-up only), not just at process start, so a runtime switch to a
  previously-used dir cannot let that dir's higher-seq archives outrank the
  ones this process is about to write. The re-seed keys off `archiveSeedDir`
  (the last successfully-scanned dir), and `maxArchiveSeq` distinguishes a
  directory READ error from a legitimately empty dir: a transient scan failure
  leaves the counter unchanged and the dir un-seeded so the next call retries,
  rather than pinning the counter at 0 below the on-disk max and pruning every
  fresh archive as stale (#6396 Codex MINOR 4). #6404 closed the remaining
  reseed windows the #6396 retry left open, all via the shared
  `ensureArchiveSeededLocked` helper (called under the write lock; it returns
  whether the counter is CONFIRMED relative to the active dir):
  the archiving commit path re-attempts the reseed BEFORE it captures its seq,
  so a commit that lands after a failed `SetArchiveConfig` scan but before the
  next explicit retry re-scans the dir instead of writing a still-low seq that
  rotation would prune as stale (edge 1). If that commit-time rescan ALSO fails
  (a persistent scan error), the counter is still unconfirmed, so the commit
  SKIPS its archive entirely rather than write a below-max seq — skipping one
  archive during the failure window is strictly safer than writing a mis-seq'd
  one that rotation prunes out of order; the next commit after the scan recovers
  archives normally (Codex round-2 MAJOR). A nonexistent dir (first use,
  `os.ErrNotExist`) is treated as a CONFIRMED-empty dir, not a scan failure:
  there are no pre-existing archives to outrank, so seq 0 is correct and the
  write path's `MkdirAll` creates it. Disabling archival (`SetArchiveConfig("")`)
  INVALIDATES `archiveSeedDir`, so a disable→re-enable to the SAME dir
  (`A`→`""`→`A`) re-scans `A` and accounts for any on-disk max that advanced
  while archival was off (edge 2); likewise a genuine scan FAILURE clears
  `archiveSeedDir`, so navigating away to a dir that fails to scan and back
  (`A`→failed-`B`→`A`) re-scans `A` rather than trusting the stale marker (Codex
  adjacent).
  **The reseed scan is time-bounded (#6776).** `ensureArchiveSeededLocked` runs
  under `s.mu` held for WRITING — the GLOBAL store mutex, the same one that
  gates `Load`, every commit and every config read — and the scan it performs is
  `readdir(2)`. A `readdir` on a filesystem that has stopped answering (a
  network mount under the archive path, a stalled block device) blocks
  uninterruptibly, and no context or deadline can cancel it: a thread parked in
  a filesystem wait is not reachable from userspace. That matters most at cold
  boot, where the boot apply's step 15b `SetArchiveConfig` runs in daemon
  PHASE 4 — *before* the gRPC/REST/CLI listeners start in PHASE 5 — so an
  unbounded scan there means the daemon never reaches its control plane at all.
  The scan therefore runs on a throwaway goroutine and the lock-holder waits at
  most `archiveScanBudget` (5s) for it (`awaitArchiveScanLocked`). On expiry the
  goroutine is ABANDONED, not cancelled, and the outcome is **fail-open**: the
  caller is released, bring-up and config work proceed, and only archival is
  suspended. Fail-open is the deliberate choice — config archival is a
  DR/compliance convenience, and refusing to bring a firewall up because a
  directory did not answer converts a degraded-storage event into a total
  outage. The suspension reuses the existing #6404 semantics exactly, because a
  timed-out scan leaves the on-disk max in the same state a read error does —
  UNKNOWN: the counter is NOT reseeded (never rewound to 0), `archiveSeedDir` is
  cleared so a later call retries, and an archiving commit SKIPS its archive
  rather than write a below-max seq rotation would prune. The abandoned scan is
  not discarded: its buffered result channel is retained (`archiveScanCh`, keyed
  by `archiveScanDir`), so the next call collects the result with a NON-blocking
  poll once the filesystem answers, and archival resumes at the correct seq.
  That retention is also what bounds the cost — a persistently wedged archive
  filesystem costs exactly ONE budget-length stall and ONE leaked scan goroutine
  per process, not one per commit. 5s is chosen as ~3 orders of magnitude of
  headroom over a healthy scan (the dir is retention-capped at `max-archives`,
  default 10, so a real `readdir` costs microseconds), so the budget cannot fire
  on a merely loaded disk. NOTE on scope: the scanned directory is always the
  local `/var/lib/xpf/archive` — the compiler hardcodes it and there is no
  `archive-dir` configuration leaf — so it becomes remote only if an operator or
  image makes that path a mount point. The `archive-sites` remote leg is a
  separate path (scp, already 30s-bounded, off-lock); it never lists a remote
  directory.
  The
  rollback/archive writers
  route through package-var seams (`rbWriteFileDurable`,
  `rbWriteFileAtomic`, `rbSyncDir`, `rbRemove`) so tests can pin the
  durability call and inject failures (#1916 pattern).
- Remote transfer-on-commit source (#3867): the daemon's
  `archiveConfig` (`system archival configuration transfer-on-commit`,
  `pkg/daemon/daemon_flow.go`) serializes the CURRENT active config via
  `Store.ShowActive()` — the SAME `s.active.Format()` text this local
  auto-archive and `show configuration` render — writes it to a temp
  file, and scp's THAT to each archive site. It no longer scp's the
  boot file `d.opts.ConfigFile` (`/etc/xpf/xpf.conf`): that file is
  written once at install and is never rewritten now the store is
  DB-canonical, so uploading it archived the day-0 config on every
  commit (a silently-wrong DR/compliance archive while scp logged
  success). The temp file keeps the boot-file basename so a
  directory-destination site retains the historical remote filename,
  and is removed after every upload completes. The transfer step is
  injectable behind `Daemon.archiveTransfer` (default
  `scpArchiveTransfer`) so tests can capture the uploaded bytes and
  assert the archive-source selection.
- `master.key` is written durably BEFORE any tree encrypted with it
  (the key persist runs inside writeTree's encrypt step) — a lost key
  meant a permanently undecryptable active config.
- The candidate (in-memory) tree may be dirty (uncommitted edits
  accumulating). `Commit` atomically promotes candidate → active
  and bumps the rollback ring — but only after the new active has
  durably persisted (#1799 Option A above).
- Rollback slots are 0..49 (FIFO). Oldest is silently discarded when
  the ring is full.
- The encryption key lives at `<db.dir>/master.key` (mode 0600,
  generated on first encrypted commit). If the file is missing on a
  node that previously committed encrypted state, decryption fails —
  there is no plaintext fallback.
- Flat-load fail-closed (#3442 M3/M4): `LoadSet` and the flat-set branch
  of `LoadMerge` (`store_command.go`) reject any non-blank, non-`#` line
  that does not start with a recognized verb (gate `hasFlatVerb`) with a
  line-numbered error. Previously `LoadMerge` ran such a line through
  `applyEditLine` → `ParseSetVerb`, whose bare-path default turned a
  typo/free-text line (e.g. `not-a-set-line`) into a junk top-level node,
  and `LoadSet` silently `continue`d on it so REST/gRPC/CLI returned OK
  while dropping the intended command. The `ParseSetVerb` bare-path default
  is reserved for internal callers that prepend the verb themselves
  (`SetEdit`, `Deactivate`, `Activate`).
  - **Recognized verbs = exactly what `applyEditLine` replays:** `set`,
    `delete`, `deactivate`, `activate`. The interactive structural-edit
    verbs `annotate`/`copy`/`insert`/`rename` (handled only in
    `pkg/cli/cli_dispatch.go`) are intentionally NOT accepted on the flat
    path — they use distinct multi-clause grammar (`copy X to Y`,
    `insert X before Y`, `annotate X "comment"`) and never appear in a
    flat-load artifact, since `show | display set`
    (`ConfigTree.FormatSet`) emits only `set`/`deactivate` lines. Pre-fix
    they were already silently mangled into junk `set annotate ...` nodes,
    so rejecting them is the M3 fix, not a regression.
  - **Whitespace:** the gate matches the first whitespace-delimited token,
    so a tab between the verb and the path is tolerated (the lexer treats
    tabs as whitespace) — not only a literal space.
  - Hierarchical `LoadMerge` is unaffected — it round-trips through
    `FormatSet()`, which always emits verb-prefixed lines.
- Flat-load request atomicity (#5187): `LoadSet` and BOTH `LoadMerge`
  branches (flat set-format and hierarchical-via-`FormatSet`) replay every
  edit line into a deep clone of the candidate (`ConfigTree.Clone`) and swap
  it into `s.candidate` — setting `dirty` and refreshing the config-lock
  lease — ONLY after ALL lines apply. On ANY line error the method returns
  WITHOUT touching `s.candidate`, `dirty`, or the lease, so
  `candidate_after_error == candidate_before_request` byte-for-byte. This
  mirrors `LoadOverride`, which already parsed into a separate tree before
  the swap. Previously all three replayed each line directly onto the live
  candidate and returned on the first failure, leaving every EARLIER
  set/delete line committed while the RPC/CLI reported the load FAILED — a
  non-atomic import. The partial-delete case was fail-OPEN: replacement deny
  lines placed AFTER the failing line were dropped, yet the candidate had
  already advanced. (Distinct from the #3442 fix above, which addressed
  silent-skip of a malformed line, not partial application.)
- Commit atomicity (#846): `pkg/daemon` wraps `Commit()` together with
  `applyConfig()` under a single semaphore. Bypassing the daemon (e.g.
  using `Store` directly) loses that serialization, so concurrent CLI +
  HTTP commits can race.

## Bounded config reads (#4909, #6753)

`MaxConfigSize` (16 MiB) is the ceiling on any configuration payload the store
accepts. Historically it was enforced **only after the payload was resident**:
`checkConfigSize` takes an already-materialised string, so it bounds what the
store will *accept*, never what a caller will *allocate*. A caller doing
`os.ReadFile` then handing the result over read a multi-gigabyte file in full
and only then had it refused (#6753).

Read configuration files through **`ReadBoundedConfigFile`** (or
`ReadBoundedFile` / `ReadBounded` for a different ceiling). They bound the read
itself:

- `io.LimitReader(max+1)` caps the allocation by the *limit*, not by what
  `Stat` claimed — closing the #4909 TOCTOU where a FUSE-backed or racing file
  under-reports its size and then streams an unbounded body.
- The open uses `O_NONBLOCK` and the path is rejected unless it is a **regular
  file**. Opening a FIFO for reading blocks until a writer appears, so a plain
  `os.Open` hangs before any size check can run. That is a distinct defect from
  the size cap and a size-only fix does not address it.

Identify the over-cap refusal with `errors.Is(err, ErrExceedsLimit)`, never by
matching the message. The store's own post-materialisation rejection is a
*different* refusal produced by independently-maintained wording, so a
substring test silently changes verdict when either message is reworded — and
rewording the store's to contain the matched word makes such a test pass
against unfixed code (#7469). Callers must wrap with `%w`, not `%v`: `%v`
flattens the chain and breaks `errors.Is` at that surface only.

Both CLI surfaces (`pkg/cli` local, `cmd/cli` remote) and `cmd/xpfd` call the
same implementation. They previously did not, and #4883-D records the cost of
that shape at a neighbouring site: the local and remote CLI diverged, and the
divergence itself is what produced the bug.
