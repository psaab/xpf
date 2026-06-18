# AGY Adversarial Plan Review: Staged Generation Immutability (#1981)

**Target:** `docs/research/1981-staged-generation-immutability/plan.md`  
**Verdict:** **PLAN-NEEDS-MAJOR**

---

## Executive Summary

The plan for **Issue #1981** addresses a critical race condition between `dpkg`'s file-by-file unpack storm and operator-driven/automated cut-overs (`xpfd upgrade`). It recommends **Option D (Hybrid)**, which introduces a maintainer-script-managed sentinel file (`staged/.generation`) containing either an `"unpacking"` marker or a valid manifest (genid + per-binary sha256 checksums). 

While the core cryptographic verification of Option D is mathematically sound, the plan contains **severe maintainer-script lifecycle and rollback integration gaps** that will leave upgraded hosts permanently wedged or unable to upgrade. 

Specifically, the plan fails to address:
1. **The `abort-upgrade` Permanent Wedge (Critical):** Failed package upgrades that trigger dpkg's error-unwind flow will leave the host running the restored old package, but with `.generation` stuck at `"unpacking"`.
2. **First-Install / Legacy-Migration Race Window (Medium):** The preinst script does not write `"unpacking"` during `install` transitions, leaving a race window open during initial/legacy package installation.
3. **Seeding Path Drift (Medium):** The plan's claim that `pkg/upgrade/runtime/seed.go` writes the valid `.generation` manifest is not supported by the existing implementation.

Furthermore, we challenge the plan's rejection of **Option B (Immutable Versioned Staging)**. Option B cleanly avoids all maintainer-script lifecycle hazards, Sentinel-recovery code, and lock-coupling, making the plan's rejection of B on disk/GC complexity grounds highly questionable.

---

## Detailed Findings & Attacks

### 1. [CRITICAL] The `abort-upgrade` / Error-Unwind Permanent Wedge

#### The Attack Path
Under Option D, the new package's `preinst` invalidates the staged directory by writing `"unpacking"` to `staged/.generation`. If the package unpack fails (e.g., disk full, power loss) or if the `postinst configure` script fails, `dpkg` executes its error-unwind routine:
1. `dpkg` rolls back the binaries in `/usr/local/share/xpf/staged/` to the previously installed package's version.
2. `dpkg` executes the previously installed package's `postinst abort-upgrade <failed-version>` script to restore it to a configured state.

Because the previous package (which also implements the `.generation` check) only writes the valid manifest during the `configure` case of `postinst`, **its `abort-upgrade` branch does nothing**. As a result:
- The host is restored to the old package version, and the old daemon is left running.
- However, `staged/.generation` remains set to `"unpacking"`.
- If the operator attempts to perform a manual cut-over (`xpfd upgrade`) or if a deferred/rolling upgrade is driven, `copyStaged` will read `"unpacking"` and **refuse the cut indefinitely**.
- The host's upgrade system is now permanently wedged. The only recovery is manual deletion of the sentinel or an `apt install --reinstall` force-run.

#### Required Invariant Modification
The maintainer-script contract **must** enforce that the `postinst` writes the valid manifest unconditionally during *any* transition back to a configured state. 
- Modify the postinst contract (P2) to write the valid manifest on `configure`, `abort-upgrade`, `abort-remove`, and `abort-deconfigure`.
- This ensures that if `dpkg` rolls back to the old version, the old version's `postinst abort-upgrade` runs `xpfd` to compute and write a valid manifest for the restored binaries, restoring the system to a clean state.

---

### 2. [MEDIUM] Unprotected First-Install / Legacy-Migration Race

#### The Attack Path
`debian/xpf.preinst` only executes lock checking and layout migration during the `upgrade` case:
```bash
case "$1" in
    upgrade)
        # Lock check + migrate_legacy_layout
        ;;
    install|abort-upgrade)
        ;;
esac
```
During a first install or when migrating a legacy non-dpkg install (which dpkg treats as `install` because there is no previous package in its database):
1. `preinst install` runs and does nothing. It does **not** write `"unpacking"` to `staged/.generation`.
2. `dpkg` begins unpacking files. `staged/` is populated file-by-file (torn-binary state).
3. If the host is performing a legacy migration, a legacy non-dpkg `xpfd` daemon is already active on the host. If the operator runs `xpfd upgrade` (which they can, since `/usr/local/sbin/xpfd` is still the legacy binary):
   - The old daemon ignores `.generation` anyway, so it will copy a torn set. (This is an unavoidable bootstrapping limitation).
   - But if a new version `V_new` has been partially installed, and the user runs a manual `xpfd upgrade` that resolves to the new binary before the postinst completes, or if a concurrent package operation is running, the check will see `.generation` is absent (or has dirty/stale content) rather than explicitly `"unpacking"`.

#### Required Invariant Modification
To prevent any possibility of concurrent reads during an initial install's unpack window:
- `preinst` must handle the `install` case by creating the target directory if it does not exist (`mkdir -p /usr/local/share/xpf/staged`) and writing `"unpacking"` to `staged/.generation`.
- This ensures that the `"unpacking"` sentinel is present from the very beginning of the unpack window, regardless of whether it is a first-install, upgrade, or downgrade.

---

### 3. [MEDIUM] Design-to-Code Drift in `pkg/upgrade/runtime/seed.go`

#### The Attack Path
Step 5 of Option D in the plan states:
> *`5. pkg/upgrade/runtime/seed.go (first install): after seeding versions/<v>/, write a valid staged/.generation for the freshly-staged set...`*

However, the actual implementation of `pkg/upgrade/runtime/seed.go` in the codebase does **not** write `staged/.generation` at all. It only copies files to `versions/<ver>` and sets up symlinks.
- If the first install runs `xpfd seed-runtime`, it will successfully populate `versions/<ver>` and set up links.
- But `staged/.generation` will be left absent or stale.
- A subsequent manual cut-over or verification check by the operator will fail because the manifest in the staging directory is missing or invalid.

#### Required Invariant Modification
- The design must explicitly mandate that `pkg/upgrade/runtime/seed.go` imports the manifest writing package and writes a valid `.generation` file to the staging directory immediately after successfully creating the versioned runtime copy.

---

### 4. [ARCHITECTURAL CRITIQUE] Re-evaluation of Option B's Rejection

The plan rejects **Option B (Immutable Versioned Staging)** due to:
1. An extra binary copy step on install (disk cost of ~65MB).
2. The complexity of garbage-collecting the versioned staging directories (`staged-gen/`).

However, pressure-testing the lifecycle of Option B reveals that it is **architecturally superior** to Option D because it completely decouples the cut-over mechanism from the dpkg maintainer script execution state:
* **No Sentinel Complexity:** Option B does not write or manage `"unpacking"` states.
* **Immunity to Rollback Wedges:** Since `copyStaged` reads from `staged-gen/<genid>` (which is written atomically in `postinst` *after* a successful unpack), there is no race window during unpack. If an upgrade aborts, the old package's `staged-gen/<old-genid>` remains intact and fully functional. The old package can be cut over normally without any risk of being wedged.
* **No `preinst` Sentinel Code:** Option B requires no modifications to `preinst` or complicated `set +e` subshell error absorption wrappers.

Given that a typical appliance disk partition easily accommodates multiple 65MB binary sets, and that xpf already implements garbage collection for the `versions/` directory (which can be easily extended to `staged-gen/`), **the plan's rejection of Option B on complexity grounds is flawed**. Option B reduces high-risk maintainer-script coupling in exchange for a tiny, well-understood disk and GC overhead.

---

## Verdict & Action Items

The plan **NEEDS-MAJOR** revision before implementation can proceed. The following changes must be incorporated into the plan:

1. **Mandate `postinst` writes on abort/unwind:** Update §6 (P2) to require `.generation` manifest updates on `abort-upgrade`, `abort-remove`, and `abort-deconfigure`.
2. **Invalidate in `preinst install`:** Update §6 (P1) to require `preinst install` to create `staged/` and write `"unpacking"` to cover legacy-migration unpack windows.
3. **Align Seeding Implementation:** Align the design with `pkg/upgrade/runtime/seed.go` to ensure `Seed()` writes the valid manifest to the staging directory.
4. **Ensure Monotonic GenIDs:** Add a constraint to P5 specifying that `genid` must incorporate a monotonically fresh component (e.g., nanosecond timestamp or random token) to prevent collision issues during reinstallations of the same version.
