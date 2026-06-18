# Codex hostile plan review r1 (#1981)

**Verdict:** PLAN-NEEDS-MAJOR

Verbatim Codex output (gpt-5.x-codex):

---

PLAN-NEEDS-MAJOR

The plan is directionally sound, but not ready.

Major findings:

1. **P1 regresses #1965.** The plan says write `.generation=unpacking` as the first preinst mutation, before the lock probe. That means a contended `apt upgrade` can mutate `staged/` while an operator cut already holds `/run/xpf/upgrade.lock`. If the probe then fails, no unpack occurs, but future `xpfd upgrade` sees `unpacking` and refuses. That violates the current “apt aborts before any mutation” contract in [debian/xpf.preinst](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/debian/xpf.preinst:213). Put differently: the fix for a dpkg/operator race creates a preinst/operator race.

2. **The crash matrix misses “preinst wrote sentinel, then preinst aborts before unpack.”** This is not hypothetical: lock contention, script error, SIGKILL, or failed future logic can strand `unpacking` while the staged tree is still the old consistent tree. Debian Policy confirms `new-preinst upgrade` runs before unpack, and if it fails, dpkg calls `new-postrm abort-upgrade` and then `old-postinst abort-upgrade`; the plan’s “old scripts only” statement is incomplete. See Debian Policy §6.5/§6.6: https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html

3. **Generation refusal after PREFLIGHT leaves a stale DB snapshot journal.** Current flow writes `STAGED`, runs `preflight`, snapshots config DB, transitions `PREFLIGHT`, then calls `copyStaged` ([pkg/upgrade/cutover.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:247)). If `.generation=unpacking` makes `copyStaged` refuse, live daemon is untouched, but the journal and `.dbsnap` remain. A later same-version retry can skip preflight and use an old DB snapshot, regressing the #1967 stale-snapshot cleanup invariant. The plan’s test note saying “no journal written” is wrong for this refusal point.

4. **Postinst-before-auto-cut is necessary and mostly correct.** Debian Policy §6.7 confirms `postinst configure` runs after files are unpacked, and `$2` is empty on first configure. So P2 is right that first-install seed must produce a valid staged manifest because first install does not run the upgrade auto-cut. But the plan must specify fallback behavior when `seed-runtime` fails; “via seed” alone leaves the degraded direct-staged fallback with no valid manifest.

5. **D closes the torn-copy window only if the manifest file lifecycle is tightened.** A valid before/after genid plus per-managed-binary checksums rejects torn managed binaries. A “torn” set can only pass if unchanged files are byte-identical, which is harmless for this invariant. But the plan must state whether `.generation` is excluded from `copyTree(staged, versions/<ver>)`; today `copyTree` copies all regular files, including dotfiles ([pkg/upgrade/runner.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/runner.go:255)). Leaving runtime marker files inside immutable version dirs may be benign, but it is currently unspecified.

6. **Option B rejection is still not earned.** D’s hidden costs are real: preinst state mutation, abort-upgrade cleanup, stale journal cleanup, and marker-copy semantics. B avoids the worst D-specific failure mode by letting cuts read the last published complete generation while dpkg rewrites live `staged/`. Disk cost is a valid objection, but the plan currently understates the operational simplicity B buys.

dpkg ordering/dotfile survival: the plan is basically right that a non-payload `.generation` under a package-owned directory will not be replaced by unpack; dpkg unpacks package files and removes files in the old package but not the new, not arbitrary unlisted files. Removal/purge only removes installed files; unknown runtime files require maintainer-script cleanup. See dpkg man page: https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html

Required plan fixes before ready: move or guard the preinst sentinel relative to the lock gate, define abort/preinst-failure cleanup semantics, reset/rewind journal and DB snapshot on generation refusal, specify first-install fallback manifest behavior, and explicitly decide whether `.generation` is copied into version dirs.
