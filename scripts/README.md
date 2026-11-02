# scripts — gate, census, and operator tooling

Index for the 194 tracked files here (193 pre-existing + this README). The censuses are
the point of this directory: each one makes a class of silent
disappearance fail by name. The index is **in place** — deliberately no
tree moves and no shared repowalk — because the censuses key on different
populations (`selftest-census.sh` includes `unparsed` Go skips in one
leg's accounting, `go-skip-census.sh` reports them as a floor of their
own; `harness-census.sh` and `selftest-census.sh` scan different roots),
and moving a file or editing a guard while homogenising them would mask
exactly the disappearance they exist to catch.

## Start here

| Question | Run |
|---|---|
| Everything hermetic | `make selftest` → `run-selftests.sh` (the aggregate; it also runs most censuses below) |
| Is a test/harness unreached? | `sh scripts/harness-census.sh`, `sh scripts/selftest-census.sh` |
| Did a skip/ignore/tag silently grow? | `sh scripts/go-skip-census.sh`, `sh scripts/ignored-cell-census.sh`, `sh scripts/go-buildtag-census.sh` (each wired into `make`, see the table) |
| Image / dist / deploy legs only | `run-selftests.sh` §1–§3, or the subsystem README (`dist/README.md`) and `make image`, `make dist-selftest` |

## Census → invariant → gate → self-test

A census that cannot be made to fail is indistinguishable from one that
examines nothing, so every row's self-test carries fixture pairs (a tree
that must pass and its near-identical twin that must fail) or a mutation
that must flip the verdict.

| Census / gate | Invariant it protects | Gate (Make / aggregate) | Self-test |
|---|---|---|---|
| `harness-census.sh` | Every runnable harness under `test/incus/*.sh` + `scripts/userspace-*.sh` is invoked by a Makefile recipe (directly or transitively) or declared with a reason in `test/incus/HARNESSES.unreached`; the declared list only shrinks; a broken matcher trips the `test-failover.sh` positive control | `make harness-census`, `run-selftests.sh` §4 | `test/incus/harness-census-selftest.sh` |
| `selftest-census.sh` | Every hermetic self-test over 9 shell globs + 5 Python globs is invoked by `run-selftests.sh` (registration = a `run_bash`/`run_shell` line, comments stripped); the §4 odd-name set is exactly the declared 10; every `--selftest)` arm is registered with the flag; every §3 Python file has a `__main__` guard; every tracked `scripts/*test*.py` is covered by the glob union | `run-selftests.sh` (final leg), `make selftest` | `test/incus/selftest-census-selftest.sh` |
| `ignored-cell-census.sh` | Every Rust `#[ignore]` carries a reason declaring its kind (`MEASUREMENT:` or `#N:`), and with `--check-issues` every `#N:` issue is still open — closing it reds the census, which is the wake-up | `make ignored-cell-census`, `run-selftests.sh` | `test/incus/ignored-cell-census-selftest.sh` |
| `go-skip-census.sh` | Go skip call sites do not grow past `go-skip-census.floors`; every site lands in a named bucket including `unparsed` (a variable/constant/call message, or `t.SkipNow()`), which has its own floor; privilege-absent vs privilege-present skips are reported by name and direction, because no single run examines both | `make go-skip-census`, `run-selftests.sh`, `make selftest` | `test/incus/go-skip-census-selftest.sh` |
| `go-buildtag-census.sh` | Every pre-package `//go:build` in a `*_test.go` gets a `go vet -tags` compile leg (single-identifier), or an exact reviewed declaration in `test/incus/GO_BUILDTAG_REVIEWED` (shrink-only); blindness to the known tagged file fails closed | `make test-go` (in-recipe), `run-selftests.sh` lint list | `test/incus/go-buildtag-census-selftest.sh` |
| `miri-census.sh` + `miri-leg.sh` | Every `userspace-dp/` file mentioning Miri is covered by a module in `userspace-dp/MIRI.registry` (run by `make test-miri`) or declared in `MIRI.unregistered`; the leg scores totally (no `test result:` line, `0 passed`, below-floor, or an `unsupported operation` all FAIL — a filter matching nothing must not read as clean) | `make miri-census`, `make test-miri`, `run-selftests.sh` | `test/incus/miri-census-selftest.sh` |
| `debug-leg-census.py` | The three checked-in debug-leg registries reconcile exactly with Cargo's live bin/test census (runnable + ignored listings, target-qualified names) | `make test-rust` (leg 2) | `scripts/debug-leg-census-selftest.sh` |
| `rust-source-census-13961.py` | Every Rust source under the root is reachable from its crate roots (`mod`/`#[path]`/`include!`) | `make rust-source-census-13961`, `make test` aggregate | its `--self-test` in the same recipe |
| `go-test-json.sh` | `make` gate legs keep their coverage while emitting a name-attributable `go test -json` side stream; text paths pin `-json=false` against inherited `GOFLAGS`; empty jsonfile path is byte-identical to a direct text `go test` | `make test-go`/`test-rust` via `GOTESTJSON` | `scripts/go-test-json-selftest.sh` |
| `go-timeout-watch.awk` | the one go-test timeout predicate (#18778): alarm with tests running or not requires the alarm goroutine's first frame (so printed panic+list text stays a failure); binary killed at `-timeout` + 1m requires the following package FAIL; exit 3 = VOID, naming every timed-out package. Text mode passes lines through; `-v TAGGED=1` reads `<pkg><TAB><line>` from a `-json` stream | `go-test-json.sh`, `go-test-watch.sh`, `mutate-lib.sh` `mutation_timed_out` | `scripts/go-test-json-selftest.sh`, `scripts/mutate-selftest.sh` |
| `close_keyword_lint.py` + `close_keyword_lint_ci.sh` | A negated or scope-disclaimed close keyword (`Closes #N` under a "does not fix" heading, etc.) never reaches the default branch, in PR title, body, or commits — GitHub does not read negation | `make close-keyword-lint`, `make selftest`, git hook | `scripts/test_close_keyword_lint.py`, `test/incus/selftest-census-selftest.sh` (odd-set leg) |
| `refactoring-audit.sh`, `refactoring-audit-lib.sh`, `refactoring-audit-classify.sh`, `refactoring-audit-structs.sh`, `refactoring-audit-touched.sh`, `refactoring-audit-refresh.sh` | Modularity heatmap: files ≥1500 LOC and structs over the field-type floor are listed with category tags; the touched-set probe prices this branch's delta vs merge base | `make audit-check`, `audit-structs`, `audit-refresh`, `test-go` touched leg | `pkg/refactoraudit` canaries via `refactoring-audit-classify.sh` |
| `check-userspace-dt-needed-10204.py` | The three `libxpf*.a` stay static archives (absent from `DT_NEEDED`); no shared libelf/libz/libzstd leaks through a transitive dependency | `make check-userspace-dt-needed`, `test-rust` prerequisite | (gate is the check; negative leg in the Makefile recipe) |
| `ci_affected_go_tests.sh` | A change runs its owning package, reverse importers, and the import-less census packages — seeding from non-Go paths must not silently select nothing | CI selector | `scripts/ci_affected_go_tests_selftest.sh` |
| `mutate.sh` + `mutate-lib.sh` | A mutation scores KILLED only when the named target's own failure moves (occurrence-proven both directions, bounded, build-failure = VOID not survived) | per-issue drivers `mutate-*.py` (below) | `scripts/mutate-selftest.sh` |
| `run-selftests.sh` interpreter census (§, inline) | Every `run_shell` registration is POSIX; a bash script registered with `run_shell` fails by name (dash `Bad substitution` is a syntax error, not a result) | `make selftest` | (inline; trips on the runner itself) |
| Scratch pinning | No audited build/test path defaults scratch to `/tmp`, `/dev/shm`, or `/var/tmp`; `TMPDIR`/`GOCACHE`/`CARGO_TARGET_DIR` default under `/var/worktrees/.cache`, `GOTMPDIR` defaults to the short `/wtgt` root (#16494, AF_UNIX sun_path bound, proven by the executed `scripts/sunpath-canary` bind) | `make selftest` | `scripts/scratch-pinning-selftest.sh` |
| No `git stash` | No tracked script uses `git stash` (shared stack across concurrent worktrees) | `run-selftests.sh` | `scripts/no-git-stash-selftest.sh` |

Not censuses, listed here so they are not mistaken for unindexed files:
`cut_stall_sampler.sh`/`cut_stall_analyze.py` (non-mutating cut recorder
+ offline analyzer), `iperf-json-metrics.py`, `mtr_report_check.py`
(classifies an `mtr --report` capture; unit-tested below),
`rolling_upgrade_oracle.py` (also `test/incus/rolling_upgrade_oracle_test.py`),
`review-dedup-check.py` + `search-review-index.sh` (prior-review search),
`skill_file_push_lint.py` (rejects hand-rolled Incus binary pushes in
skills), `migrate-bpfrx-to-xpf.sh` (one-shot rename migration, run on the
firewall VM), `verify-nat-source-split-6988.py`,
`verify-nat-allocator-split-16135.py`, `verify-nat64-split-16188.py`
(deterministic code-motion verifiers for their splits).

## The aggregate: `run-selftests.sh`

`make selftest` runs, in order: §1 shell-syntax lint over a hand list
(`SH_SCRIPTS` — guarded against drift by
`test_selftest_lint_coverage_6499.py`), §2 optional shellcheck, §3 Python
unittests (globs `scripts/image/test_*.py`, `scripts/dist/test_*.py`,
`scripts/deploy/test_*.py`, `scripts/test_*.py`, `scripts/*_test.py`),
§3b `test/incus` Python via `unittest discover`, §4 shell self-tests
(explicit `run_bash`/`run_shell` registrations), then the harness,
ignored-cell, Miri, go-buildtag, go-skip, interpreter, and self-test
censuses, then the ledger lint. Exit 77 from a leg = SKIP (missing tool),
anything else non-zero = FAIL. It needs no cluster, but it is not
hermetic: image/dist legs use host `minisign`/`gpg`/libguestfs and can
take minutes.

## Subsystems

| Dir | What | Entry points |
|---|---|---|
| `image/` | Appliance image bake + day-0 | `bake.py` (bake), `validate.py` (boot matrix, own entry point, excluded from `run-selftests.sh`), `validate-build-metadata.py` (Makefile guard), `xpf-day0-config`, `xpf-grow-root`, `xpf-uefi-slots`, `xpf-kernel-promote`, `incus-agent-setup`, `make_config_drive.py`, `seed_layout_10771.py`, `bridge_floor_10171.py`, `build_provenance.py`, units `xpf-day0-config.service`, `xpf-ssh-hostkeys.service`, `xpf-grow-root.service`, `xpf-input-closed.service`, `xpf-kernel-promote.service`, `xpf-kernel-promote-failed.service`, `xpf-transit-closed.service`, `xpf-uefi-slots.service`, `incus-agent.service`, rules `99-incus-agent.rules`, `grub.d/09_xpf`; shipped shell here is syntax-linted by `run-selftests.sh` §1 |
| `dist/` | Signed distribution | See `dist/README.md`: `sign.py`, `publish.py`, `build-apt-repo.sh`, `install.sh`, `image_inventory.py`, `retain_shim_verdict.py`, `selftest.sh`, `xpf-archive-keyring.asc.placeholder`, `xpf-image.pub.placeholder` |
| `deploy/` | `xpf-deploy.py` + its tests | `xpf-deploy.py`; tests globbed by `run-selftests.sh` §3 (listed by filename below) |
| `docs/` | Doc gates | `check-upgrade-docs.sh` (`make docs-check`), `check-no-ci-claims.sh`, `check-upgrade-docs-selftest.sh`, `check-no-ci-claims-selftest.sh` |
| `git-hooks/` | `commit-msg` hook + `install.sh` (`make install-git-hooks`) | enforces the commit-subject/close-keyword contract locally |

### Python tests by subsystem (all run through `run-selftests.sh` §3)

- Root (10): `test_base_pin_docs_6501.py`, `test_close_keyword_lint.py`,
  `test_cut_stall_analyze.py`, `test_debhelper_token_placement.py`,
  `test_mtr_report_check.py`, `test_review_storage.py`,
  `test_run_selftests_python_skips_10750.py`,
  `test_selftest_lint_coverage_6499.py`,
  `test_selftest_main_guard_9669.py`, `test_skill_file_push_lint.py`,
  plus the suffix-convention `userspace_ha_validation_matrix_test.py`.
- `image/` (38 `test_*.py`): `test_bake_base_pin.py`,
  `test_bake_bridge_floor_10171.py`, `test_bake_dirty_detection_12158.py`,
  `test_bake_freeze_9921.py`, `test_bake_gate_boundary_12209.py`,
  `test_bake_hugepages_16243.py`, `test_bake_kernel_hold_enumeration.py`,
  `test_bake_package_identity_10850.py`, `test_bake_provenance_12141.py`,
  `test_bake_sign_ordering.py`, `test_bake_sshd_password_auth_10771.py`,
  `test_bake_transit_sysctls_10765.py`, `test_bake_version_pathsafe.py`,
  `test_build_metadata_12698.py`,
  `test_config_drive_creation_umask_6764.py`,
  `test_day0_machine_id_independence_10769.py`, `test_day0_openstack_15785.py`,
  `test_day0_probe_order_6502.py`, `test_day0_safe_read_9921.py`,
  `test_kernel_promote_explicit_path.py`, `test_make_config_drive_mode.py`,
  `test_seed_layout_10771.py`, `test_slot_refresh_15089.py`,
  `test_ssh_hostkeys_regen_16445.py`, `test_systemd_unit_canary_16198.py`,
  `test_uefi_slots_6499.py`, `test_validate_ab_slots_6494.py`,
  `test_validate_ab_substrate_6498.py`, `test_validate_day0_perms_6503.py`,
  `test_validate_freeze_9921.py`, `test_validate_gate_reactions_10770.py`,
  `test_validate_guest_absent_7424.py`, `test_validate_image_seal_6547.py`,
  `test_validate_ownership.py`, `test_validate_runner_seam_16196.py`, `test_validate_scenarios.py`,
  `test_validate_secureboot_6497.py`, `test_validate_skip_ledger_7347.py`.
- `dist/` (21 `test_*.py`): `test_build_apt_repo_binding_12144.py`,
  `test_build_apt_repo_inputs_9921.py`,
  `test_build_apt_repo_reprepro_10123.py`,
  `test_build_apt_repo_valid_until_12544.py`, `test_debian_rules_keyring.py`,
  `test_dist_multi_key_rotation_10767.py`, `test_dist_resign_9920.py`,
  `test_image_inventory_6500.py`, `test_install_apt_channel_10767.py`,
  `test_install_apt_pinning_11133.py`,
  `test_install_cleanup_trap_t1_10848.py`,
  `test_install_keyring_atomic_12142.py`,
  `test_install_networkd_preflight_12153.py`,
  `test_install_url_validate_9921.py`, `test_publish_apt_freshness_15277.py`,
  `test_publish_provenance.py`, `test_publish_snapshot.py`,
  `test_publish_url_validate.py`, `test_retain_shim_verdict.py`,
  `test_verify_negative_12208.py`, `test_version_fixture_16190.py`
  (+ `version_fixture_16190.json`).
- `deploy/` (27 `test_*.py`): `test_xpf_deploy_channel_fetch_6504.py`,
  `test_xpf_deploy_cohort_9325.py`, `test_xpf_deploy_correctness.py`,
  `test_xpf_deploy_daemon_hold_7559.py`, `test_xpf_deploy_disk.py`,
  `test_xpf_deploy_fetch_bounds_10853.py`, `test_xpf_deploy_fetchkey_10767.py`,
  `test_xpf_deploy_gate.py`, `test_xpf_deploy_golden_guard_8597.py`,
  `test_xpf_deploy_image_roll_digest_10852.py`,
  `test_xpf_deploy_image_roll_identity.py`, `test_xpf_deploy_iso_mode.py`,
  `test_xpf_deploy_kernel_roll.py`, `test_xpf_deploy_leak_13206.py`,
  `test_xpf_deploy_lease_chmod_16050.py`,
  `test_xpf_deploy_lease_renew_fence.py`, `test_xpf_deploy_lease_ttl.py`,
  `test_xpf_deploy_libvirt_uri_9669.py`, `test_xpf_deploy_nicorder.py`,
  `test_xpf_deploy_pathsafety.py`,
  `test_xpf_deploy_recreate_keepalive_6762.py`,
  `test_xpf_deploy_robustness.py`, `test_xpf_deploy_roll_gate_refusal.py`,
  `test_xpf_deploy_signed_digest_9170.py`,
  `test_xpf_deploy_unverified_primary_6759.py`,
  `test_xpf_deploy_verify_toctou.py`,
  `test_xpf_deploy_watermark_inversion_9238.py`.

Shell self-tests at the root: `ci_affected_go_tests_selftest.sh`,
`debug-leg-census-selftest.sh`, `go-test-json-selftest.sh`,
`mutate-selftest.sh`, `no-git-stash-selftest.sh`,
`scratch-pinning-selftest.sh` (all §4-registered), plus the odd-name
`dist/selftest.sh` and `image/test-grow-root.sh` (pre-date the
`*-selftest.sh` convention; explicitly registered and counted in the
self-test census odd set).

## Live validation (not censuses, not in `run-selftests.sh`)

All five are `DIAGNOSTIC:` in `test/incus/HARNESSES.unreached`
(manual-only, reached slices named there and in `test/incus/README.md`):

| Script | What |
|---|---|
| `userspace-ha-validation.sh` | v3 fast/matrix CoS×v4/v6 push/reverse smoke on the loss cluster; `--perf` perf-record control |
| `userspace-ha-failover-validation.sh` | arbitrary RG/source/target/cycle failover matrix; `--deploy`/`restore-baseline` workflow |
| `userspace-native-gre-validation.sh` | native-GRE transit + failover walkthrough |
| `userspace-perf-compare.sh` | ad-hoc perf A/B between two builds |
| `userspace-phase-cycle.sh` | re-runs the HA validation across phases |

## One-shot mutation matrices

`mutate-9177.py`, `mutate-9364.py`, `mutate-9412.py`, `mutate-9452.py`,
`mutate-9482.py`, `mutate-9507.py`, `mutate-9508.py`, `mutate-9509.py`,
`mutate-9546.py`, `mutate-9551.py`, `mutate-9582.py` — historical,
issue-scoped drivers over `mutate.sh`; kept as the evidence trail for
their issues, not entry points. Each header states its scoring carve-out
(e.g. a compile-time guard whose kill signal *is* a build failure).

## Adding a script

1. Put it where its population already lives (root for gate tooling,
   the subsystem dir for image/dist/deploy/docs) and give it the
   subsystem's naming: `*-selftest.sh` / `test_*.py` / `*_test.py` for a
   test, `*-census.sh` only if it scans the whole tree and fails on an
   empty sweep.
2. Header: what it asserts, what it prints when the property is false,
   and how to run it. A census additionally needs a positive control and
   a shrink-only declaration file if it keeps one.
3. Register it: a self-test goes in `run-selftests.sh` with the
   interpreter it declares (`run_bash` vs `run_shell`); a census gets a
   `make` leaf *and* a fold into the aggregate (or an explicit reason it
   stays manual); a harness gets a Makefile recipe or a
   `HARNESSES.unreached` declaration.
4. Prove it can fail: add the fixture pair / mutation cell to its
   self-test, then run `make selftest` and the census by name. An
   unregistered file fails `selftest-census.sh` / `harness-census.sh`
   by name — that failure is the registration reminder, not noise.

## Cross-checks (decisive)

```
make selftest                    # aggregate: every leg above that is hermetic-runnable
sh scripts/selftest-census.sh    # every self-test invoked; odd-set exact
sh scripts/harness-census.sh     # every harness reached or declared
sh scripts/go-skip-census.sh     # skip floors; `unparsed` bucket named
sh scripts/ignored-cell-census.sh --check-issues
sh scripts/go-buildtag-census.sh
```
