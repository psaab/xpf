#!/usr/bin/env python3
"""xpf appliance image validation (#1879 Path C), in Python.

Boots the baked artifacts under LOCAL incus (instances xpf-image-* —
never the shared loss cluster) and proves the first-boot contract:

  a  no config drive  -> factory bootstrap: boots UNDER SECURE BOOT (the
     production posture, asserted not inherited — #6497), xpfd active,
     fxp0 DHCP, sshd listening, in-guest `xpfd verify-dataplane` PASSES
     against the image's own kernel (the bake gate), AND the #1930 LANE-1
     A/B kernel channel actually came up in the guest (#6494): both slots
     registered with their own signed shim and reachable in BootOrder, and
     both first-boot oneshots ran clean.
  b  valid day-0 drive -> config validated + installed + committed at first
     boot (hostname applied); a reboot does NOT re-apply (stamp).
  c  invalid day-0 drive -> commit-check REJECT logged, nothing installed,
     boot survives, factory bootstrap still reachable; THEN the operator
     swaps in a VALID drive and reboots and the config now applies (the
     fix->reboot->applied retry contract, #4209 H-9 / pairs with H-1).
  d  resized disk (#1925) -> first-boot root auto-grow fills a LARGER root
     disk (partition + ext4), stamps, is idempotent on reboot, and leaves the
     ESP/boot substrate intact; a control boot at the bake size is a clean
     no-op.
  e  cluster node-id drive (#4209 H-9) -> a node-id=1 day-0 drive persists
     /etc/xpf/node-id=1, boots into cluster mode, and (with >=3 NICs) the
     daemon assigns the node-1 vSRX names em0 + ge-7/0/N (FPC 7).
  q  libvirt/plain-QEMU bootability (#4209 H-9) -> the SAME qcow2 the docs
     sell for "libvirt/KVM, plain QEMU" is a valid, non-corrupt qcow2 of at
     least the bake floor (ALWAYS — a missing qemu-img FAILS the gate rather
     than skipping it, #7347), and — gated on qemu-system-x86_64 +
     /dev/kvm + OVMF — actually boots under direct QEMU with the day-0 config
     on a cdrom (the cdrom day-0 attach path incus never exercises). Prefers
     an SB-ENFORCING firmware pair; an SB-off fallback is reported AS one
     rather than presented as Secure Boot proof (#6497).

Usage:
  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|d|e|q|all]
"""

import argparse
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts", "dist"))
from bridge_floor_10171 import bridge_floor_live_snippet  # noqa: E402  (#10171)
import make_config_drive  # noqa: E402
import sign  # noqa: E402  (#1924 signed-distribution helper)

ALIAS = "xpf-image-validate"

# The bake provisions an 8 GiB root disk (see scripts/image/bake.py); a qcow2
# whose virtual size is below this floor is truncated / an incomplete artifact
# that no hypervisor could boot correctly.
BAKE_MIN_BYTES = 8 * 1024 ** 3

# Scenario registry — the single source of truth for the CLI choices AND the
# dispatch map, so a new scenario is wired in one place and is introspectable
# by the hermetic unit test (test_validate_scenarios.py). "q" (QEMU) and "e"
# (node-id) are the #4209 H-9 additions.
SCENARIO_METHODS = {
    "a": "scenario_a", "b": "scenario_b", "c": "scenario_c",
    "d": "scenario_d", "e": "scenario_e", "q": "scenario_qemu",
}
SCENARIO_ORDER = ["a", "b", "c", "d", "e", "q"]

# ── Secure Boot posture (#6497) ──────────────────────────────────────
# The production appliance posture is UEFI Secure Boot ON — test/incus/setup.sh
# sets security.secureboot: "true" "to match the production posture (#1943)".
# The Tier-1 gate is the only thing between a bake and a release signature, and
# it used to prove nothing about SB at all: the incus scenarios INHERITED it
# from the incus default rather than setting it, and the plain-QEMU leg
# deliberately preferred a NON-secboot OVMF and had no SB-on variant. A default
# flip, a profile override, or a hypervisor without the MS db silently degraded
# the whole gate to SB-off — and still passed.
#
# That matters more than "the image is signed": the #1930 A/B substrate makes
# Secure-Boot-LOCKDOWN-sensitive design choices that nothing automated
# exercised. scripts/image/grub.d/09_xpf documents that `regexp` may be
# unavailable under lockdown and that the slot selector must be a GRUB *script*
# so GRUB can parse it there. The only SB-on validation of that chain was a
# one-time manual probe on a hand-staged stock VM, not the baked artifact.
#
# So: the incus scenarios now set security.secureboot EXPLICITLY and assert the
# guest reports SB enabled, and the QEMU leg prefers an SB-ENFORCING firmware
# pair and says loudly when it has fallen back to SB-off.

# SB-ENFORCING pair, preferred. The CODE build must be the secboot one (a
# non-secboot build ignores SB even with MS keys present) and the VARS must
# carry the Microsoft KEK/db, so the Canonical-signed shim the image ships
# verifies with NO MOK enrollment. Debian/Ubuntu ship these as *.ms.fd;
# Fedora as *.secboot.fd.
_OVMF_SECBOOT_CODE_CANDIDATES = (
    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.ms.fd",
    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
    "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
)
_OVMF_MS_VARS_CANDIDATES = (
    "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
    "/usr/share/OVMF/OVMF_VARS.ms.fd",
    "/usr/share/OVMF/OVMF_VARS_4M.secboot.fd",
    "/usr/share/edk2/x64/OVMF_VARS.secboot.4m.fd",
    "/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd",
)
# SB-OFF fallback, used only when no enforcing pair exists on the host. Kept so
# a minimal host still gets plain-QEMU bootability coverage — but the caller
# must LOG that this leg is not Secure-Boot proof (that silent conflation is
# the #6497 defect).
_OVMF_CODE_CANDIDATES = (
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
    "/usr/share/qemu/OVMF_CODE.fd",
)
_OVMF_VARS_CANDIDATES = (
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
    "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    "/usr/share/qemu/OVMF_VARS.fd",
)

# EFI global variable holding the firmware's Secure Boot state. The efivarfs
# file is 4 attribute bytes followed by the value, so byte 4 is the flag.
# Reading it needs no package: mokutil is NOT in bake.py's RUNTIME_PACKAGES,
# so an assertion that required mokutil would fail on package drift rather than
# on a real SB regression.
_SECUREBOOT_EFIVAR = ("/sys/firmware/efi/efivars/"
                      "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")


def _qemu_firmware_choice(find=None):
    """Pick the OVMF pair for the plain-QEMU leg. Returns
    (code, vars, secure_boot, reason).

    Prefers an SB-ENFORCING pair (secboot CODE + MS-keyed VARS) so the leg
    actually exercises the shim->grub->kernel chain the appliance ships under
    lockdown. Falls back to the SB-off pair only when no enforcing pair exists,
    and reports secure_boot=False so the caller can say so out loud instead of
    presenting an SB-off boot as bootability proof (#6497).

    `find` is injected so the preference order is unit-testable without
    depending on which OVMF packages the test host happens to have. It
    defaults to _find_first, resolved at CALL time rather than as a default
    argument value: _find_first is defined further down this file, and binding
    it in the signature raised NameError at import. py_compile does not catch
    that (it checks syntax, not import), so the unit tests — which import the
    module — are the green that matters for this file.
    """
    if find is None:
        find = _find_first
    code = find(_OVMF_SECBOOT_CODE_CANDIDATES)
    varsf = find(_OVMF_MS_VARS_CANDIDATES)
    if code and varsf:
        return code, varsf, True, f"Secure Boot ENFORCING ({code} + {varsf})"
    code = find(_OVMF_CODE_CANDIDATES)
    varsf = find(_OVMF_VARS_CANDIDATES)
    if code and varsf:
        return code, varsf, False, (
            "no SB-enforcing OVMF pair on this host (need a secboot CODE build "
            "AND MS-keyed VARS) — falling back to SB-OFF firmware; this leg "
            "proves plain-QEMU bootability only, NOT the Secure Boot chain")
    return None, None, False, (
        "no usable OVMF firmware pair found (neither SB-enforcing nor SB-off)")


def _secureboot_verdict(efivar_byte, mokutil_out, lockdown_out):
    """Pure verdict over the guest's Secure Boot readings: is SB actually ON?
    Returns (ok, reason).

    Three independent readings, because each can be unavailable for a reason
    that is not "SB is off":
      - efivar_byte: byte 4 of the SecureBoot EFI variable, as a string, or ""
        if unreadable. AUTHORITATIVE — it is the firmware's own answer and needs
        no package. "1" = enabled, "0" = disabled.
      - mokutil_out: `mokutil --sb-state` output, or "" if mokutil is absent.
        mokutil is NOT in the image's package set, so its absence must not be
        read as SB being off.
      - lockdown_out: /sys/kernel/security/lockdown, or "" if securityfs is not
        mounted / the LSM is absent. CORROBORATING only: an active lockdown
        policy is strong evidence the kernel booted SB-enabled, but lockdown can
        also be forced on the cmdline, so it never OVERRIDES a definite "off".

    A definite "off" from any authoritative source loses. Absence of every
    reading is a FAIL, not a pass: a gate that cannot observe the property it
    exists to assert has not asserted it (#6497 is exactly the failure of
    treating an unobserved posture as a satisfied one).
    """
    efivar_byte = (efivar_byte or "").strip()
    mok = (mokutil_out or "").strip().lower()
    lock = (lockdown_out or "").strip().lower()

    if efivar_byte == "0":
        return False, ("firmware reports Secure Boot DISABLED (SecureBoot "
                       "efivar = 0) — the guest did not boot under Secure Boot")
    if "secureboot disabled" in mok:
        return False, "mokutil reports SecureBoot disabled"

    if efivar_byte == "1":
        extra = f"; lockdown={lock}" if lock else ""
        return True, f"firmware reports Secure Boot ENABLED (SecureBoot efivar = 1){extra}"
    if "secureboot enabled" in mok:
        return True, "mokutil reports SecureBoot enabled"
    if "[integrity]" in lock or "[confidentiality]" in lock:
        return True, (f"kernel lockdown is active ({lock}) — SB-enabled boot "
                      "(the SecureBoot efivar was unreadable)")

    return False, (
        "could not observe Secure Boot state at all "
        f"(efivar={efivar_byte!r}, mokutil={mok!r}, lockdown={lock!r}). The "
        "production posture is SB ON; a gate that cannot see the property is "
        "not asserting it, so this FAILS rather than passing silently.")


def _qemu_img_verdict(imginfo, min_bytes):
    """Pure verdict over `qemu-img info --output=json` output: is this a
    bootable qcow2 of at least `min_bytes` virtual size? Returns (ok, reason).
    Split out so the config-level bootability check is unit-testable without a
    real image (#4209 H-9)."""
    fmt = imginfo.get("format")
    if fmt != "qcow2":
        return False, (f"image format is {fmt!r}, not qcow2 — libvirt/plain-QEMU "
                       "consume the qcow2 export")
    vsize = imginfo.get("virtual-size")
    if not isinstance(vsize, int) or vsize < min_bytes:
        return False, (f"virtual-size {vsize} below the {min_bytes}-byte bake floor "
                       "— truncated / incomplete image")
    return True, f"qcow2, virtual-size {vsize / (1024 ** 3):.1f}GiB"


# ── #1930 LANE-1 A/B slot registration (#6494) ────────────────────────
# The bake STAGES /boot/efi/EFI/{xpf-A,xpf-B} and ENABLES xpf-uefi-slots.service
# + xpf-kernel-promote.service, and hard-asserts the signed shim is there. What
# it cannot assert offline is the half that only happens in-guest: UEFI Boot####
# variables live in the target's firmware NVRAM, which virt-customize cannot
# write, so registration is a first-boot oneshot on the real machine.
#
# That oneshot is deliberately NON-FATAL on every failure path ("degraded, not
# bricked" — a read-only/no-efivars platform must still boot), and nothing
# downstream re-read its outcome. So a regression in the ESP disk/part parse,
# the loader-path match, or the efibootmgr write shipped a fully "validated"
# image whose verify-gated kernel channel was silently unavailable, and the
# operator discovered it only when `xpfd upgrade kernel arm` exited 2 with "A/B
# slots not both registered ... the first-boot registration oneshot must run
# first" (pkg/upgrade/kernel_run.go ErrKernelChannelUnavailable).
#
# A gate for a production appliance image should prove the upgrade substrate it
# ships, not only the files that substrate is made of.
#
# The slots the #1930 channel requires. Both must exist; the channel refuses to
# arm unless BOTH are registered, so one is as unavailable as none.
_AB_SLOTS = ("xpf-A", "xpf-B")

# An efibootmgr entry line is "BootXXXX[*]<space>LABEL<TAB>loader-path". The
# label is followed by a TAB and the path, NOT line-end — anchoring at $ is the
# miss that created duplicate slots live during #1930. Mirrors the shell regex
# in scripts/image/xpf-uefi-slots register_slot() on purpose: the gate must
# agree with the script about what "registered" means, or it certifies a state
# the script would not accept.
_EFIBOOT_ENTRY_RE = re.compile(
    r"^Boot([0-9A-Fa-f]{4})\*?[ \t]+(?P<label>\S+)[ \t]+(?P<rest>.*)$")
_BOOTORDER_RE = re.compile(r"^BootOrder:\s*(?P<order>\S*)\s*$", re.MULTILINE)


def _efibootmgr_slot_verdict(out, slots=_AB_SLOTS):
    """Pure verdict over `efibootmgr` (or `efibootmgr -v`) output: are BOTH
    #1930 A/B slots registered exactly once, each pointing at its own signed
    shim, and both reachable in BootOrder? Returns (ok, reason).

    Split out from the scenario so the acceptance criterion is unit-testable
    without a hypervisor, in the _qemu_img_verdict idiom (#4209 H-9).

    Three separate properties, reported separately, because they have three
    different causes:
      - exactly once  -> a duplicate means the registration guard's label match
                         missed (the #1930 live bug); a duplicate ALSO poisons
                         BootNext, since which Boot#### the slot means is then
                         ambiguous.
      - loader path   -> an entry that merely shares the LABEL but points
                         elsewhere chainloads the wrong loader.
      - in BootOrder  -> a slot the firmware will never reach is registered but
                         unusable, which is not "registered" in any sense the
                         kernel channel can act on.
    """
    ids = {}          # slot -> [Boot#### ids with the RIGHT loader path]
    wrong_path = {}   # slot -> [rendered lines whose path does not match]
    for line in out.splitlines():
        m = _EFIBOOT_ENTRY_RE.match(line.rstrip())
        if not m:
            continue
        label = m.group("label")
        if label not in slots:
            continue
        # efibootmgr prints "...File(\EFI\xpf-A\shimx64.efi)" or the bare
        # "...\EFI\xpf-A\shimx64.efi". Match the slot's shim path with any
        # separator between the components and case-insensitively, exactly as
        # the shell guard does (grep -qiE "EFI.${slot}.shimx64\.efi").
        want = re.compile(r"EFI.%s.shimx64\.efi" % re.escape(label), re.IGNORECASE)
        if want.search(m.group("rest")):
            ids.setdefault(label, []).append(m.group(1))
        else:
            wrong_path.setdefault(label, []).append(line.strip())

    problems = []
    for slot in slots:
        got = ids.get(slot, [])
        if not got:
            bad = wrong_path.get(slot)
            if bad:
                problems.append(
                    f"{slot}: registered but the loader path is NOT "
                    f"\\EFI\\{slot}\\shimx64.efi ({bad!r}) — it would chainload "
                    "the wrong loader")
            else:
                problems.append(
                    f"{slot}: NOT registered — the first-boot xpf-uefi-slots "
                    "oneshot did not create it (LANE-1 kernel channel "
                    "unavailable on this image)")
        elif len(got) > 1:
            problems.append(
                f"{slot}: registered {len(got)} times ({', '.join(got)}) — a "
                "duplicated slot makes BootNext ambiguous")

    mo = _BOOTORDER_RE.search(out)
    if mo is None:
        problems.append("efibootmgr reported no BootOrder line — cannot prove "
                        "either slot is reachable by the firmware")
    else:
        order = [x for x in mo.group("order").split(",") if x]
        for slot in slots:
            got = ids.get(slot, [])
            if got and not any(i.upper() in (o.upper() for o in order) for i in got):
                problems.append(
                    f"{slot}: registered ({got[0]}) but absent from BootOrder "
                    f"({mo.group('order')!r}) — the firmware would never reach it")

    if problems:
        return False, "; ".join(problems)
    return True, ("both A/B slots registered exactly once with the right shim "
                  "loader and present in BootOrder")


# The three files the bake stages into EACH slot dir, and the selector's own
# variable names. Kept in the same place as the slot list so the ESP-staging
# assertion and the registration assertion are read together.
#
# Both halves matter and fail differently:
#   - shimx64.efi/grubx64.efi ABSENT -> xpf-uefi-slots' register_slot() sees no
#     shim, returns 1, and the slot is NEVER registered. That failure surfaces
#     downstream as "slot not registered", so asserting the staging separately
#     is what tells an operator whether the BAKE or the in-guest ONESHOT broke.
#   - xpf.selector absent or naming the WRONG kernel -> the slot registers fine
#     and boots, but GRUB's 09_xpf branch sources a selector that points at a
#     vmlinuz/initrd pair that is not on this image, so THAT slot is a dead
#     boot entry. Nothing else in the gate would notice: the entry exists, the
#     oneshot exits 0, and the failure only appears when the firmware actually
#     falls through to that slot — i.e. during a rollback, the one moment the
#     channel exists for.
_AB_SLOT_FILES = ("shimx64.efi", "grubx64.efi", "xpf.selector")
_SELECTOR_VARS = {"xpf_slot_kernel": "vmlinuz-", "xpf_slot_initrd": "initrd.img-"}

# `set xpf_slot_kernel="vmlinuz-7.0.0-15-generic"` — the GRUB-script form
# bake.py seeds and scripts/image/grub.d/09_xpf sources. Quotes optional so a
# hand-edited selector without them still parses (and is then judged on its
# VALUE, not rejected on its punctuation).
_SELECTOR_SET_RE = re.compile(
    r'^\s*set\s+(?P<var>xpf_slot_\w+)\s*=\s*"?(?P<val>[^"\s]*)"?\s*$')


# In-guest probe feeding _ab_slot_esp_verdict. Emits a flat line protocol
# rather than raw `ls`/`cat` output so the verdict is a pure function over
# something stable: no locale, no ls format, no ordering assumptions. Every
# required file is reported either way (present AND MISSING lines), so a probe
# that silently produced nothing cannot be mistaken for a clean run.
_AB_SLOT_ESP_PROBE = (
    "for slot in " + " ".join(_AB_SLOTS) + "; do "
    "d=/boot/efi/EFI/$slot; "
    "for f in " + " ".join(_AB_SLOT_FILES) + "; do "
    'if [ -f "$d/$f" ]; then echo "FILE $slot $f present"; '
    'else echo "FILE $slot $f MISSING"; fi; done; '
    'if [ -f "$d/xpf.selector" ]; then '
    'while IFS= read -r l; do echo "SEL $slot $l"; done < "$d/xpf.selector"; '
    "fi; done"
)


def _ab_slot_esp_verdict(out, kver, slots=_AB_SLOTS):
    """Pure verdict over the in-guest ESP probe: is each #1930 A/B slot dir
    fully staged, and does each slot's selector name the RUNNING kernel?
    Returns (ok, reason).

    `out` is the probe's line protocol (see Harness._probe_ab_slot_esp):
        FILE <slot> <name> present|MISSING
        SEL  <slot> <verbatim selector line>

    A slot whose selector file is missing is reported ONCE (as a missing file);
    its variable values are not additionally reported, so one defect produces
    one diagnosis rather than three.

    Naming the RUNNING kernel is the right assertion on a FACTORY boot, which
    is the only place this is called (scenario A): the bake seeds both
    selectors at `ls /lib/modules | sort -V | tail -1` and hard-asserts exactly
    one kernel remains, and scenario A re-asserts that count, so the running
    kernel IS the seeded one. After a promotion the two selectors legitimately
    differ — asserting equality there would be wrong, which is why this is a
    scenario-A assertion and not a general one.
    """
    present = {}   # slot -> set(filenames found)
    missing = {}   # slot -> [filenames reported MISSING]
    sel = {}       # slot -> {var: value}
    for line in (out or "").splitlines():
        parts = line.split(None, 3)
        if len(parts) >= 4 and parts[0] == "FILE":
            _, slot, fname, state = parts[:4]
            if state == "present":
                present.setdefault(slot, set()).add(fname)
            else:
                missing.setdefault(slot, []).append(fname)
        elif len(parts) >= 3 and parts[0] == "SEL":
            m = _SELECTOR_SET_RE.match(line.split(None, 2)[2])
            if m:
                sel.setdefault(parts[1], {})[m.group("var")] = m.group("val")

    problems = []
    for slot in slots:
        got = present.get(slot, set())
        absent = [f for f in _AB_SLOT_FILES if f not in got]
        if absent:
            problems.append(
                f"{slot}: /boot/efi/EFI/{slot} is missing {', '.join(absent)} "
                "— the bake did not stage this slot, so xpf-uefi-slots can "
                "never register it (LANE-1 unavailable on this image)")
            continue
        vals = sel.get(slot, {})
        for var, prefix in sorted(_SELECTOR_VARS.items()):
            want = prefix + kver
            got_val = vals.get(var)
            if got_val is None:
                problems.append(
                    f"{slot}: xpf.selector does not set {var} — GRUB's 09_xpf "
                    "branch would source a selector that names no kernel")
            elif got_val != want:
                problems.append(
                    f"{slot}: xpf.selector sets {var}={got_val!r}, not "
                    f"{want!r} (the running kernel) — this slot would "
                    "chainload a kernel this image does not ship")

    if problems:
        return False, "; ".join(problems)
    return True, (f"both A/B slot dirs fully staged ({', '.join(_AB_SLOT_FILES)}) "
                  f"with selectors seeded at the running kernel {kver}")


# ── #1930 INC-0 kernel hold (#6498) ───────────────────────────────────
# The bake HOLDS the kernel so an unattended apt run cannot move the running
# kernel out from under the verifier-gated shim .o (#1864): a kernel the .o was
# never verified against can REJECT it at boot, i.e. no dataplane. bake.py
# verifies the hold at bake time; nothing re-read it on the booted image, so a
# hold that did not survive virt-sysprep/export/first boot shipped green.
#
# ENUMERATION, and why it is NOT the literal `linux-*`. #6498's acceptance
# criterion says "every installed linux-* package appears in apt-mark showhold".
# Taken literally that assertion REDS every valid image: `linux-base` is a hard
# dependency of linux-image-*-generic, and `linux-libc-dev` /
# `linux-sysctl-defaults` are installed too — none are kernel packages and
# bake.py deliberately does not hold them. The property the criterion reaches
# for is "the kernel cannot move", so the gate enumerates exactly the set
# bake.py holds. The globs are MIRRORED from bake.py's hold fragment on
# purpose and a drift canary asserts the two agree
# (test_validate_ab_substrate_6498.py): a gate that enumerated a different set
# than the bake holds would either red on a good image or certify an
# unprotected one.
_KERNEL_PKG_GLOBS = ("linux-image-*", "linux-headers-*", "linux-modules-*",
                     "linux-generic")


# The guest-side enumeration. Mirrors bake.py's hold fragment exactly: the
# same globs, the same ${db:Status-Status} filter (dpkg-query -W matches every
# package dpkg KNOWS OF, including purged and never-installed names that
# `apt-mark hold` cannot select — the #1926 abort).
_INSTALLED_KERNEL_PKGS_PROBE = (
    "dpkg-query -W -f='${db:Status-Status} ${Package}\\n' "
    + " ".join(f"'{g}'" for g in _KERNEL_PKG_GLOBS)
    + " 2>/dev/null | awk '$1==\"installed\"{print $2}' | sort -u"
)


def _kernel_hold_verdict(installed, held):
    """Pure verdict over the guest's kernel-package enumeration and
    `apt-mark showhold`: is every installed kernel package held?
    Returns (ok, reason).

    An EMPTY enumeration is a FAIL, not a vacuous pass. That is the whole
    failure mode this guards: bake.py's own hold fragment aborted every bake
    twice during #1926 because the enumeration collapsed to nothing (an
    unescaped `${Package}`, then dpkg-query returning never-installed names),
    and an "all zero of them are held" pass here would argue against anyone
    ever re-examining it.
    """
    inst = sorted({p for p in (installed or "").split() if p})
    hold = {p for p in (held or "").split() if p}
    if not inst:
        return False, (
            "could not enumerate any INSTALLED kernel package in the guest "
            f"({', '.join(_KERNEL_PKG_GLOBS)}) — the image ships a kernel, so "
            "an empty enumeration is a broken probe (or a broken image), not "
            "an image with nothing to hold. Refusing to pass vacuously")
    unheld = [p for p in inst if p not in hold]
    if unheld:
        return False, (
            f"{len(unheld)} of {len(inst)} installed kernel packages are NOT "
            f"in `apt-mark showhold`: {', '.join(unheld)} — an unattended apt "
            "run can move the kernel out from under the verifier-gated shim "
            ".o (#1864/#1930 INC-0), which can leave the appliance with no "
            "dataplane after a background upgrade")
    return True, (f"all {len(inst)} installed kernel packages held "
                  f"({', '.join(inst)})")


def _oneshot_clean_verdict(name, exec_main_status, active_state, result):
    """Pure verdict over `systemctl show` fields for a first-boot oneshot:
    did it RUN and exit 0? Returns (ok, reason).

    A oneshot with RemainAfterExit=yes reports ActiveState=active after a clean
    run. The distinction that matters is "did not run" vs "ran and failed":
    inactive means a Condition skipped it (the unit was never enabled, or
    ConditionPathExists=/boot/efi did not hold — an image with no ESP), which
    is a DIFFERENT bake defect from a non-zero exit, so they are reported
    separately rather than as one 'not clean'.
    """
    if active_state in ("inactive", "") and result in ("", "success"):
        return False, (f"{name} never ran (ActiveState={active_state!r}) — the "
                       "bake did not enable it, or its Condition did not hold "
                       "on this image")
    if result and result != "success":
        return False, f"{name} failed (Result={result!r}, ExecMainStatus={exec_main_status!r})"
    if exec_main_status not in ("0", 0):
        return False, f"{name} exited {exec_main_status!r}, not 0"
    return True, f"{name} ran clean (ExecMainStatus=0)"


# ── day-0 config permissions (#6503) ──────────────────────────────────
# The day-0 loader installs /etc/xpf/xpf.conf mode 0600 because it "may carry
# credential material (root-authentication encrypted-password, IKE PSKs)"
# (scripts/image/xpf-day0-config). Scenario B asserted the file EXISTS and is
# non-empty (`test -s`) and nothing about the mode — docs/image-validation.md
# said so in as many words — so a regression to 0644 would ship
# world-readable IKE PSKs and password hashes in a signed image and pass the
# Tier-1 gate.
#
# The probe reads three fields from ONE `stat`, because a mode check alone has
# a hole: `stat` follows a symlink only with -L, so without it a symlinked
# xpf.conf reports the LINK's 0777 — but a naive check that ran `stat -L`
# would report the TARGET's mode while the file an attacker controls is the
# link. A credential file must be a regular file, owned by root, mode exactly
# 0600.
_DAY0_CONF = "/etc/xpf/xpf.conf"
_DAY0_CONF_STAT = f"stat -c '%a %U:%G %F' {_DAY0_CONF} 2>/dev/null"


def _conf_mode_verdict(stat_out, want_mode=0o600, want_owner="root:root"):
    """Pure verdict over `stat -c '%a %U:%G %F'` for the installed day-0
    config: is it a root-owned regular file with exactly mode 0600?
    Returns (ok, reason).

    The mode is compared as an OCTAL VALUE, not as a string. This is
    ROBUSTNESS, not a caught bug: GNU `stat -c %a` emits "600" unpadded, so a
    string compare against "600" rejects "4600" (a setuid bit) just as an int
    compare does. What the value compare buys is independence from the
    RENDERING — a zero-padded "0600" from a non-GNU stat is the same mode and
    must not be a false red, while every extra bit is still rejected because
    0o4600 != 0o600. Said plainly because the reverse claim (that a string
    compare would let 4600 through) is FALSE and was in an earlier draft of
    this comment; the mutation matrix caught it.

    Unreadable / absent output is a FAIL, not a pass. A gate that cannot
    observe the property it exists to assert has not asserted it.
    """
    fields = (stat_out or "").strip().split(None, 2)
    if len(fields) < 3:
        return False, (
            f"could not stat {_DAY0_CONF} in the guest (got {stat_out!r}) — "
            "the day-0 config is missing, or the probe failed; either way the "
            "permission is unobserved, which is not the same as satisfied")
    mode_s, owner, ftype = fields
    try:
        mode = int(mode_s, 8)
    except ValueError:
        return False, f"{_DAY0_CONF}: unparseable mode {mode_s!r}"

    problems = []
    if ftype != "regular file":
        problems.append(
            f"is a {ftype!r}, not a regular file — a symlinked config puts the "
            "bytes xpfd reads outside the mode this gate checks")
    if mode != want_mode:
        problems.append(
            f"has mode {mode_s} (0o{mode:o}), not {want_mode:04o} — a day-0 "
            "config may carry root-authentication encrypted-password and IKE "
            "PSKs, so any extra bit makes them readable to every local user "
            "on the appliance")
    if owner != want_owner:
        problems.append(f"is owned by {owner}, not {want_owner}")
    if problems:
        return False, f"{_DAY0_CONF} " + "; ".join(problems)
    return True, f"{_DAY0_CONF} is a root:root regular file, mode {mode_s}"


# ── Image seal / clone identity (#6547) ──────────────────────────────
#
# The bake seals the image with virt-sysprep so no PER-DEVICE IDENTITY ships
# inside the golden artifact: every appliance must regenerate its own
# machine-id, SSH host keys, SNMPv3 EngineID and random-seed on first boot.
# This gate — the last thing between a bake and a release signature — asserted
# NOTHING about that. A clone-identity regression therefore shipped SIGNED and
# passed the publish gate.
#
# The acute risk was bounded (bake's `run()` is check=True, so an outright
# virt-sysprep failure raises), but the real exposure is DRIFT: the `--enable`
# list was a hand-maintained string literal and the identity purge is a
# `rm -rf ... 2>/dev/null || true` whose failure is swallowed by construction.
# Nothing would have caught a member falling out of either, or the step being
# refactored away. The consequence is fleet-wide shared SSH host keys (every
# appliance answers with the same host identity, so an operator's known_hosts
# cannot distinguish one from an impostor), a shared machine-id, and a shared
# SNMPv3 EngineID — from which every clone derives BYTE-IDENTICAL localized USM
# keys and will accept another appliance's authenticated SNMPv3 requests.
#
# The assertion is made OFFLINE, against the exported qcow2, and that is not an
# implementation convenience — it is the only place the property is observable.
# Inside a BOOTED guest every one of these identities has already been
# regenerated by first boot, so an in-guest probe would find a machine-id and
# host keys present and could not tell a freshly-generated identity from a
# baked-in one. The shipped bytes are what the operator receives, so the
# shipped bytes are what is checked.
#
# Each entry names the seal step that produces its outcome. The hermetic test
# (test_validate_image_seal_6547.py) binds those names to bake.py's
# SYSPREP_ENABLE_OPS / SYSPREP_PURGE_PATHS, so dropping a member from the bake
# reds — the seal and the gate that verifies it cannot drift apart silently.
#
# kind:
#   "empty"  — the path may exist but MUST be empty (systemd's uninitialized
#              machine-id is a present, zero-byte file; virt-sysprep truncates
#              rather than deletes it, and an absent file is equally fine).
#   "absent" — nothing may match the glob at all.
_SEAL_IDENTITY_CHECKS = (
    {
        "glob": "/etc/machine-id",
        "kind": "empty",
        "sealed_by": "machine-id",
        "why": "a shared machine-id gives every appliance one systemd/journal "
               "identity and seeds derived per-host secrets identically",
    },
    {
        "glob": "/etc/ssh/ssh_host_*",
        "kind": "absent",
        "sealed_by": "ssh-hostkeys",
        "why": "a shared SSH host key means every appliance answers with the "
               "same host identity, so known_hosts cannot tell one from an "
               "impostor and a stolen key impersonates the whole fleet",
    },
    {
        "glob": "/var/lib/xpf/snmp-engine-id",
        "kind": "absent",
        "sealed_by": "/var/lib/xpf/snmp-engine-id",
        "why": "a shared SNMPv3 EngineID makes every clone derive "
               "byte-identical localized USM keys, so each appliance accepts "
               "another's authenticated SNMPv3 requests (#5283)",
    },
    {
        "glob": "/var/lib/xpf/snmp-engineboots",
        "kind": "absent",
        "sealed_by": "/var/lib/xpf/snmp-engineboots",
        "why": "a shipped engineBoots counter replays against the SNMPv3 "
               "time-window check (#5283)",
    },
    {
        "glob": "/var/lib/systemd/random-seed",
        "kind": "absent",
        "sealed_by": "/var/lib/systemd/random-seed",
        "why": "a shared random-seed credits identical entropy into every "
               "appliance's pool at the same point in early boot",
    },
)


def _image_seal_verdict(found, checks=_SEAL_IDENTITY_CHECKS):
    """Pure verdict over the offline image inventory: does the exported qcow2
    carry any per-device identity? Returns (ok, reason).

    `found` maps each check's glob to the list of paths present in the image
    for it, plus — for an "empty" check — the file's byte length under the key
    `"<glob>:size"`. A glob MISSING from `found` is a FAIL, not a pass: a gate
    that could not observe the property it exists to assert has not asserted
    it, and an unreadable image is exactly when a silent pass is most costly.

    Every failing check is reported, not just the first. These are independent
    identities and an operator re-baking should see all of them at once rather
    than rediscovering them one signature attempt at a time.
    """
    problems = []
    for c in checks:
        glob = c["glob"]
        if glob not in found:
            problems.append(
                f"{glob}: NOT OBSERVED — the image inventory carries no result "
                f"for it, so the {c['sealed_by']!r} seal step is unverified "
                "(an unobserved property is not a satisfied one)")
            continue
        hits = found[glob]
        if c["kind"] == "absent":
            if hits:
                problems.append(
                    f"{glob}: image ships {len(hits)} file(s) "
                    f"({', '.join(sorted(hits)[:4])}) — the {c['sealed_by']!r} "
                    f"seal step did not take effect; {c['why']}")
            continue
        # kind == "empty"
        size = found.get(f"{glob}:size")
        if hits and size:
            problems.append(
                f"{glob}: image ships {size} bytes of content — the "
                f"{c['sealed_by']!r} seal step did not take effect; {c['why']}")
    if problems:
        return False, ("image is NOT sealed — a per-device identity would ship "
                       "inside the signed artifact and be shared by every "
                       "clone: " + "; ".join(problems))
    return True, ("image seal verified: no machine-id, SSH host key, SNMPv3 "
                  "EngineID/engineBoots or random-seed ships in the artifact")


def _find_first(candidates):
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def info(m):
    print(f"==> {m}")


def fail(m):
    print(f"FAIL: {m}", file=sys.stderr)
    sys.exit(1)


def incus(*args, check=True, capture=False):
    return subprocess.run(["incus", *args], check=check,
                          capture_output=capture, text=True)


def guest(inst, *cmd, check=True, capture=False):
    return subprocess.run(["incus", "exec", inst, "--", *cmd],
                          check=check, capture_output=capture, text=True)


def guest_sh(inst, script):
    """Run a shell snippet in the guest; return True on exit 0."""
    return subprocess.run(["incus", "exec", inst, "--", "sh", "-c", script],
                          capture_output=True, text=True).returncode == 0


def guest_absent(inst, path):
    """Return True iff `path` is OBSERVABLY absent in the guest (#7424 row 2).

    The negative assertions this replaces ran an in-guest existence probe
    through `guest(...)` and treated a zero return code as "the path is there",
    which fails OPEN. `incus exec` exits non-zero both when the in-guest
    `test -e` finds nothing AND when incus itself could not run the command --
    instance not running, agent not up yet, connection refused. Only `== 0` was
    tested, so those two are indistinguishable and every transport failure
    scored as "absent, PASS". The unearned greens were the central negative
    claims of scenarios A and C: "the factory boot installed no config" and
    "the REJECT wrote nothing".

    Note the asymmetry that hid this: the sibling POSITIVE assertions are
    `if not guest_sh(...): fail(...)`, so a transport failure makes THEM fail
    closed. Only the negatives were exposed, which is why the file looked
    uniformly careful.

    The fix is to require the guest to SAY which it is. A token can only be
    produced by a shell that actually ran, so a transport failure yields no
    token and is reported as an unobserved check rather than as absence. This
    is the pattern the file already uses three times and states the reason for
    at :384 ("a probe that silently produced nothing cannot be mistaken for a
    clean run") and :704-706 ("a gate that could not observe the property it
    exists to assert has not asserted it").
    """
    r = subprocess.run(
        ["incus", "exec", inst, "--", "sh", "-c",
         f'if [ -e {shlex.quote(path)} ]; then echo XPF_PRESENT; else echo XPF_ABSENT; fi'],
        capture_output=True, text=True)
    out = (r.stdout or "").strip()
    if out == "XPF_ABSENT":
        return True
    if out == "XPF_PRESENT":
        return False
    fail(f"could not observe whether {path} exists in {inst} "
         f"(rc={r.returncode}, stdout={out!r}, stderr={(r.stderr or '').strip()!r}) — "
         "this is NOT evidence of absence. A gate that could not observe the "
         "property it exists to assert has not asserted it (#7424)")


class Harness:
    def __init__(self, qcow2, metadata, net, keep, verify_sig=True):
        self.qcow2, self.metadata, self.net, self.keep = qcow2, metadata, net, keep
        # verify_sig: True = verify if a .minisig is present (default),
        # "force" = require one, False = never (dev escape hatch).
        self.verify_sig = verify_sig
        # Live source paths, kept for signed-manifest lookup (the *.SHA256SUMS
        # sit next to the live files, not the staging dir). freeze_artifacts()
        # repoints self.qcow2/self.metadata at the staged copies; _frozen
        # guards its idempotence.
        self.qcow2_src, self.metadata_src = qcow2, metadata
        self._frozen = False
        self.created_net = False
        self.instances = []
        # #7347: the skip LEDGER. Before this, a scenario that skipped and one
        # that asserted were indistinguishable to main() -- scenarios were run
        # for effect and main() returned 0 unconditionally, so a skipped leg
        # reached bake.py as a pass and was signed as `validated: true`.
        #
        # Every skip now has to be RECORDED, and every recorded skip is named
        # in the closing summary. A skip that is not survivable on the bake
        # path is `fatal=True` and makes main() exit non-zero.
        self.skipped = []
        self.work = tempfile.mkdtemp(prefix="xpf-validate-")
        # Per-run ownership token (#4905-D). The alias + every instance name is
        # namespaced with it, and every destructive op refuses to touch an
        # object that lacks THIS run's ownership tag — so a concurrent bake or
        # an unrelated same-named VM/image is never force-deleted. process-
        # unique (uuid4) so two `validate.py` runs on one host never collide.
        self.run_id = uuid.uuid4().hex[:8]
        self.alias = f"{ALIAS}-{self.run_id}"
        self.imported_alias = False   # True once WE imported self.alias

    def iname(self, suffix):
        """Run-namespaced instance name for a scenario slot (#4905-D)."""
        return f"xpf-image-{self.run_id}-{suffix}"

    def _owned_delete(self, name):
        """Force-delete instance `name` ONLY if it carries THIS run's ownership
        tag (user.xpf-owner == run_id). Refuses to delete an instance this run
        did not create — a concurrent bake or an unrelated same-named VM
        (#4905-D). A missing instance is a safe no-op."""
        got = incus("config", "get", name, "user.xpf-owner",
                    check=False, capture=True)
        if got.returncode != 0:
            return  # instance does not exist / not queryable — nothing to delete
        owner = (got.stdout or "").strip()
        if owner != self.run_id:
            info(f"refusing to delete instance {name}: ownership tag {owner!r} "
                 f"!= this run {self.run_id!r} (concurrent bake / unrelated VM) "
                 "— #4905-D")
            return
        incus("delete", "-f", name, check=False, capture=True)

    # ── lifecycle ──
    def ensure_network(self):
        # dns.mode=none is REQUIRED, not cosmetic. incus registers one DNS
        # record per instance per managed network, so a second NIC on the same
        # network is refused at device-add time:
        #   Instance DNS name "<inst>" conflict between "extranic0" and "eth0"
        #   because both are connected to same network
        # Scenario e needs three NICs on one network to prove the node-1
        # positional naming (em0 + ge-7/0/N), and scenario d's control leg
        # needs none of the DNS records. Turning DNS off keeps DHCP — which is
        # all any scenario consumes — and removes the conflict.
        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
            info(f"creating validation network {self.net} (NAT + DHCP, no DNS)")
            incus("network", "create", self.net, "ipv4.address=10.199.99.1/24",
                  "ipv4.nat=true", "ipv6.address=none", "dns.mode=none")
            self.created_net = True
        else:
            # A network left behind by an earlier run (or a concurrent bake)
            # may predate this setting. Idempotent, and harmless to a
            # concurrent run: no scenario resolves an instance by DNS.
            incus("network", "set", self.net, "dns.mode=none", check=False,
                  capture=True)

    def freeze_artifacts(self):
        """Copy the qcow2 + metadata into private 0700 staging and repoint
        every consumer at the staged copies (#9921 F-068 verify-then-freeze).

        Before this, verify_signatures hashed the LIVE paths while import,
        the seal probes, and the QEMU leg re-opened those same re-openable
        paths minutes later — so a concurrent host writer during the gate
        window could make `validated: true` attest to never-validated bytes
        (the TOCTOU #5817/#7347 already closed for fetch's
        `_verified_private_artifacts`, which this mirrors). Now the gate
        verifies and boots exactly the bytes frozen here: a post-freeze live
        swap is invisible to every consumer below.

        Idempotent (flag-guarded): main() calls it before the first read, and
        assert_image_sealed()/verify_signatures() call it defensively first,
        so every entry freezes even if the main wiring regresses. Basenames
        are preserved so the signed-manifest {basename: hash} binding still
        applies; the manifests themselves are looked up next to the LIVE
        files (self.*_src), verified TOCTOU-safe by sign.verify_manifest_map.
        """
        if self._frozen:
            return
        os.chmod(self.work, 0o700)
        for attr, src in (("qcow2", self.qcow2_src),
                          ("metadata", self.metadata_src)):
            if not os.path.isfile(src):
                fail(f"cannot freeze {src}: not a regular file — refusing to "
                     "validate an artifact the gate cannot pin down (#9921)")
            dst = os.path.join(self.work, os.path.basename(src))
            if os.path.exists(dst) or os.path.islink(dst):
                fail(f"staging collision for {src}: {dst} already exists — "
                     "refusing to validate an ambiguous artifact set (#9921)")
            shutil.copyfile(src, dst)
            setattr(self, attr, dst)
        info(f"froze gate inputs in {self.work}: "
             f"{os.path.basename(self.qcow2)} "
             f"sha256:{sign.sha256_file(self.qcow2)} "
             f"{os.path.basename(self.metadata)} "
             f"sha256:{sign.sha256_file(self.metadata)}")
        self._frozen = True

    def verify_signatures(self):
        """Verify the EXACT qcow2 + metadata files against the signed
        per-version manifest sitting next to them (#1924 §5.2). Per-file:
        each artifact's hash is checked against the signed manifest entry for
        its basename. Default ON when a .minisig is present; --no-verify-sig
        opts out for a local dev bake that skipped signing."""
        # Freeze FIRST, before the no-verify early return: import and the
        # scenarios consume these paths in every mode (#9921 F-068).
        self.freeze_artifacts()
        if not self.verify_sig:
            return
        sigdir = os.path.dirname(os.path.abspath(self.qcow2_src))
        import glob
        manifests = sorted(glob.glob(os.path.join(sigdir, "*.SHA256SUMS")))
        sigs = [m for m in manifests if os.path.isfile(m + ".minisig")]
        if not sigs:
            if self.verify_sig == "force":
                fail("--verify-sig forced but no signed *.SHA256SUMS.minisig "
                     f"found next to {self.qcow2_src}")
            info("no signed manifest next to the artifacts — skipping "
                 "signature verification (dev bake; use --verify-sig to force)")
            return
        # Bind BOTH consumed files to the SAME signed manifest (AGY-A3): a
        # mismatched pair (qcow2 from v2's manifest, metadata from v1's) must
        # NOT pass. Find the single manifest that authenticates both; if none
        # does, fail.
        chosen = None
        last_err = None
        for manifest in sigs:
            sig = manifest + ".minisig"
            try:
                sign.verify_image_artifact(self.qcow2, manifest, sig)
                sign.verify_image_artifact(self.metadata, manifest, sig)
                chosen = manifest
                break
            except sign.SignError as e:
                last_err = e
        if not chosen:
            fail("image signature verification FAILED — no single signed "
                 f"manifest authenticates both {os.path.basename(self.qcow2)} and "
                 f"{os.path.basename(self.metadata)}: {last_err}")
        info(f"signature OK: {os.path.basename(self.qcow2)} + "
             f"{os.path.basename(self.metadata)} (manifest {os.path.basename(chosen)})")

    def assert_image_sealed(self):
        """Assert the exported qcow2 carries NO per-device identity (#6547).

        Runs BEFORE the image is imported or booted, and reads the artifact
        OFFLINE with libguestfs — the only place the property is observable.
        By the time a guest is up, first boot has regenerated the machine-id,
        the SSH host keys and the random-seed, so an in-guest probe finds them
        present and cannot distinguish a freshly-generated identity from a
        baked-in one.

        libguestfs missing is a FAILURE, not a skip. This gate is the last step
        before a release signature, it runs on the host that just baked the
        image (bake.py already `require()`s virt-cat and the rest of
        libguestfs-tools), and a security gate that skips itself when its tool
        is absent is the vacuous-gate shape this check exists to remove.
        """
        # Freeze before the first artifact read (#9921 F-068); idempotent.
        self.freeze_artifacts()
        info("verifying image seal (no per-device identity in the artifact)...")
        for tool in ("virt-ls", "virt-cat"):
            if shutil.which(tool) is None:
                fail(f"{tool} not found — install libguestfs-tools. The image "
                     "seal cannot be verified without reading the artifact, "
                     "and an unverified seal must not be signed (#6547)")

        found = {}
        for c in _SEAL_IDENTITY_CHECKS:
            glob = c["glob"]
            directory, _, pattern = glob.rpartition("/")
            directory = directory or "/"
            # virt-ls a DIRECTORY (not the glob) and filter here: virt-ls does
            # not expand shell globs, and an absent directory must read as "no
            # matches" rather than as an unobserved check.
            r = subprocess.run(["virt-ls", "-a", self.qcow2, directory],
                               capture_output=True, text=True)
            if r.returncode != 0:
                if "No such file or directory" in (r.stderr or ""):
                    found[glob] = []
                    continue
                fail(f"could not read {directory} from {self.qcow2}: "
                     f"{(r.stderr or '').strip()} (#6547 seal unverifiable)")
            names = [n for n in (r.stdout or "").split() if n]
            hits = [f"{directory.rstrip('/')}/{n}"
                    for n in names if fnmatch.fnmatch(n, pattern)]
            found[glob] = hits
            if c["kind"] == "empty" and hits:
                cat = subprocess.run(["virt-cat", "-a", self.qcow2, glob],
                                     capture_output=True, text=True)
                if cat.returncode != 0:
                    fail(f"could not read {glob} from {self.qcow2}: "
                         f"{(cat.stderr or '').strip()} (#6547 seal unverifiable)")
                found[f"{glob}:size"] = len((cat.stdout or "").strip())

        ok, reason = _image_seal_verdict(found)
        if not ok:
            fail(reason)
        info(reason)

    def import_image(self):
        self.verify_signatures()
        # self.alias is run-namespaced, so a concurrent bake using the default
        # `xpf-image-validate` alias is NOT clobbered (#4905-D). The pre-delete
        # only targets our own unique alias (idempotent within a run).
        incus("image", "delete", self.alias, check=False, capture=True)
        info(f"importing image into local incus as {self.alias}")
        incus("image", "import", self.metadata, self.qcow2, "--alias", self.alias)
        self.imported_alias = True   # cleanup may now delete THIS alias (#4905-D)

    def launch(self, name, iso=None, root_size=None, extra_nics=0):
        # Ownership-gated pre-delete (#4905-D): only reclaim a same-named
        # instance if it is one WE created (it won't normally exist — the name
        # is run-namespaced).
        self._owned_delete(name)
        # Tag the instance with this run's ownership token so drop()/cleanup()
        # can prove it is ours before force-deleting (#4905-D).
        # security.secureboot EXPLICITLY (#6497). incus defaults it to true
        # today, but the gate must not INHERIT the posture it exists to prove:
        # a default flip, a profile override, or a host image without the MS db
        # would silently degrade every scenario to SB-off and still pass. The
        # production posture is SB ON (test/incus/setup.sh:265-273, #1943), so
        # the gate states it.
        incus("init", self.alias, name, "--vm", "--network", self.net,
              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB",
              "-c", "security.secureboot=true",
              "-c", f"user.xpf-owner={self.run_id}", capture=True)
        # Register for teardown IMMEDIATELY after init, not after the device
        # adds below. The instance exists and carries this run's ownership tag
        # from the moment init returns; registering later meant any failure
        # between here and the end of launch() (a refused device add, a bad
        # ISO path) left a VM behind that cleanup could not see, because
        # cleanup only walks self.instances.
        self.instances.append(name)
        if root_size:
            # Override the instance's root disk to a size LARGER than the
            # image (#1925 Scenario D). `device override root` materializes an
            # instance-local copy of the profile's root device so size= sticks
            # before the VM ever boots — the operator-resized-disk case.
            incus("config", "device", "override", name, "root",
                  f"size={root_size}", capture=True)
        # Additional NICs beyond the default fxp0 slot, so the daemon's
        # positional namer has em0 (idx 1) + ge-*/0/* (idx >= 2) to assign —
        # required to prove the cluster node-id naming (#4209 H-9 scenario e).
        for i in range(extra_nics):
            incus("config", "device", "add", name, f"extranic{i}", "nic",
                  f"network={self.net}", capture=True)
        if iso:
            incus("config", "device", "add", name, "day0", "disk",
                  f"source={os.path.realpath(iso)}", capture=True)
        incus("start", name)
        self.wait_agent(name)

    def drop(self, name):
        if not self.keep:
            self._owned_delete(name)   # ownership-gated (#4905-D)
            if name in self.instances:
                self.instances.remove(name)

    def cleanup(self):
        if self.keep:
            print(f"keeping instances {self.instances}, alias {self.alias}, "
                  f"network {self.net}")
            # Retain the per-run scratch dir under --keep too (codex-182
            # A10-b03-C01). Scenarios B/C/E/Q write config files and day-0
            # ISOs under self.work and attach those HOST paths to the
            # instances. Deleting self.work while keeping the VMs leaves each
            # retained instance referencing a source that can no longer be
            # reopened on a later restart/inspection/reproduction — the exact
            # forensic environment --keep was asked to preserve. Print the
            # path so the operator can find the retained media.
            print(f"keeping work dir {self.work} (day-0 media / config drives)")
            return
        for i in self.instances:
            self._owned_delete(i)   # ownership-gated (#4905-D)
        # Only delete the alias if WE imported it this run, and only the
        # run-namespaced name — never a bystander's `xpf-image-validate`
        # (#4905-D).
        if self.imported_alias:
            incus("image", "delete", self.alias, check=False, capture=True)
        # created_net already gates the network delete to one WE created.
        if self.created_net:
            incus("network", "delete", self.net, check=False, capture=True)
        subprocess.run(["rm", "-rf", self.work], check=False)

    # ── waiters ──
    def _wait(self, name, pred, tries, secs, what):
        for _ in range(tries):
            if pred():
                return
            time.sleep(secs)
        fail(f"{name}: {what}")

    def wait_agent(self, name):
        self._wait(name, lambda: guest(name, "true", check=False, capture=True).returncode == 0,
                   80, 3, "incus agent not ready after 240s")

    def wait_xpfd(self, name):
        self._wait(name, lambda: guest(name, "systemctl", "is-active", "--quiet", "xpfd",
                                       check=False, capture=True).returncode == 0,
                   40, 3, "xpfd not active after 120s")

    def wait_fxp0_dhcp(self, name):
        self._wait(name, lambda: guest_sh(name, 'ip -4 addr show fxp0 2>/dev/null | grep -q "inet "'),
                   30, 3, "fxp0 has no IPv4 DHCP address after 90s")

    # ── scenarios ──
    def scenario_a(self):
        info("── Scenario A: first boot, NO config drive ──")
        a = self.iname("a")   # run-namespaced instance name (#4905-D)
        self.launch(a)
        self.wait_xpfd(a)
        kver = guest(a, "uname", "-r", capture=True).stdout.strip()
        info(f"guest kernel: {kver}")
        rel = kver.split("-")[0]
        if not _kver_ge(rel, (6, 18)):
            fail(f"guest kernel {kver} < 6.18")
        if not guest_sh(a, 'uname -r | grep -q -- -generic'):
            fail("running kernel is not the -generic flavor")
        if not guest_sh(a, 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox"'):
            fail("linux-modules-extra (mlx5/i40e driver set) missing")
        if not guest_sh(a, '[ "$(ls /lib/modules | wc -l)" -eq 1 ]'):
            fail("more than one kernel in /lib/modules — stale cloudimg kernel not purged")
        # #10171: mirror the bake-time bridge nf_tables floor against the
        # kernel that actually booted. The bake check protects the artifact;
        # this catches a foreign boot path or an image/kernel substitution
        # before the scenario claims an appliance kernel is covered.
        floor = guest(a, "sh", "-c", bridge_floor_live_snippet(),
                      check=False, capture=True)
        if floor.returncode != 0:
            detail = (floor.stderr or floor.stdout).strip()
            fail(f"bridge nf_tables kernel floor rejected: {detail}")
        if not guest_sh(a, 'grep -qw init_on_alloc=0 /proc/cmdline'):
            fail("init_on_alloc=0 missing from the booted kernel cmdline")
        self.assert_kernel_hold(a)
        self.assert_secure_boot(a)
        info("in-guest verify-dataplane (the bake gate, image kernel)...")
        if guest(a, "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
                 check=False).returncode != 0:
            fail("in-guest verify-dataplane REJECTED — image must not ship")
        # #7114: the appliance marker is what re-enables the factory
        # fxp0-DHCP bootstrap on this artifact. The bake purges cloud-init and
        # netplan, so on a no-config-drive boot xpfd's #1922 lifeline finds no
        # default route; without the marker it declines to touch any NIC and
        # the port below stays DOWN and unrenamed. Assert the marker FIRST so a
        # bake that stopped writing it fails with its own cause instead of as
        # the downstream "fxp0 has no address" timeout.
        if not guest_sh(a, 'test -f /etc/xpf/appliance'):
            fail("/etc/xpf/appliance missing — the bake did not write the #7114 "
                 "appliance-image marker; xpfd will hold the factory boot in the "
                 "console-only bootstrap state (no fxp0, no DHCP)")
        self.wait_fxp0_dhcp(a)
        # #4172: frr-pythontools (/usr/lib/frr/frr-reload.py) MUST be present
        # or every FRR reload silently degrades to the additive `vtysh -f`
        # fallback and stale-config removal never converges (a deleted route
        # keeps forwarding). It is NOT pulled in transitively by `frr`, so
        # assert presence here — package-name drift fails with a clear cause
        # rather than as the downstream "deleted route still active" symptom.
        if not guest_sh(a, 'test -x /usr/lib/frr/frr-reload.py'):
            fail("frr-reload.py missing (/usr/lib/frr/frr-reload.py) — "
                 "frr-pythontools not installed (#4172 FRR reload permanently "
                 "degraded; stale-config removal never converges)")
        if not guest_sh(a, 'ss -tln | grep -q ":22 "'):
            fail("sshd not listening")
        if not guest_sh(a,
                        '/usr/sbin/sshd -T | grep -qxE "permitrootlogin (prohibit-password|without-password|no)"'):
            fail("sshd effective config does not refuse root password auth")
        if not guest_sh(a, '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'):
            fail("sshd effective config does not pin PermitEmptyPasswords no")
        self.assert_ab_kernel_channel(a)
        if not guest_absent(a, "/etc/xpf/xpf.conf"):
            fail("unexpected /etc/xpf/xpf.conf")
        if not guest_absent(a, "/etc/xpf/.day0-config-applied"):
            fail("unexpected day-0 stamp")
        if not guest_sh(a,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
            fail("day-0 loader did not log the no-medium fallback")
        info("Scenario A PASS")
        self.drop(a)

    def assert_kernel_hold(self, inst):
        """Assert the #1930 INC-0 kernel hold survived onto the BOOTED image
        (#6498) — every installed kernel package is in `apt-mark showhold`.

        bake.py verifies the hold at bake time (per-package, not a count), but
        that check runs inside virt-customize, before virt-sysprep, the
        sparsify/export, and the first boot. Nothing re-read it afterwards, so
        a hold that did not survive any of those steps shipped in a signed,
        `validated: true` image — and the consequence is not cosmetic: an
        unattended apt run that moves the kernel can leave the appliance
        booting a kernel the verifier-gated shim .o was never verified
        against, i.e. with no dataplane.

        The unattended-upgrades blacklist (99-xpf-kernel-hold) is the second
        half of the same protection, but it is a `--write` of a static file
        with no in-guest behaviour to observe short of running an actual
        unattended-upgrade — so this asserts the half that has an observable.
        """
        inst_pkgs = guest(inst, "sh", "-c", _INSTALLED_KERNEL_PKGS_PROBE,
                          check=False, capture=True).stdout
        held = guest(inst, "sh", "-c", "apt-mark showhold 2>/dev/null",
                     check=False, capture=True).stdout
        ok, reason = _kernel_hold_verdict(inst_pkgs, held)
        if not ok:
            fail("#1930 INC-0 kernel hold assertion FAILED: " + reason)
        info(f"kernel hold: {reason}")

    def assert_day0_conf_perms(self, inst):
        """Assert the installed day-0 config's credential posture (#6503).

        Called from every scenario where the loader actually INSTALLS a config
        — B (valid drive), C's retry leg (fix + reboot applies), and E
        (node-id drive) — because they all reach the same `install -o root -g
        root -m 0600` and a regression there would ship in a signed image from
        any of them.

        Deliberately NOT asserted: /etc/xpf's own directory mode. The loader
        sets it best-effort (`chmod 0750 ... || true`) and the directory comes
        from the .deb on a real appliance, so it is not the loader's contract
        to pin here.
        """
        out = guest(inst, "sh", "-c", _DAY0_CONF_STAT,
                    check=False, capture=True).stdout
        ok, reason = _conf_mode_verdict(out)
        if not ok:
            fail("day-0 config permission assertion FAILED: " + reason +
                 "\n  The loader installs it 0600 precisely because it may "
                 "carry credential material (scripts/image/xpf-day0-config); "
                 "the Tier-1 gate has to pin that, exactly as scenario A pins "
                 "the sshd posture.")
        info(f"day-0 config perms: {reason}")

    def assert_secure_boot(self, inst):
        """Assert the guest actually booted under UEFI Secure Boot (#6497).

        Reads three independent sources and lets _secureboot_verdict decide, so
        the reason a reading is missing is distinguished from the property being
        false:

          - byte 4 of the SecureBoot EFI variable. AUTHORITATIVE and
            package-free — the first 4 bytes of an efivarfs file are the
            variable's attributes, so the flag is at offset 4.
          - `mokutil --sb-state`, when present. mokutil is NOT in bake.py's
            RUNTIME_PACKAGES, so this is a bonus reading, never a requirement:
            asserting through mokutil alone would turn a package-set change
            into a Secure Boot "regression".
          - /sys/kernel/security/lockdown, corroborating only (lockdown can also
            be forced from the cmdline, so it never overrides a definite off).
        """
        efivar = guest(inst, "sh", "-c",
                       f"od -An -t u1 -j 4 -N 1 {_SECUREBOOT_EFIVAR} 2>/dev/null",
                       check=False, capture=True).stdout.strip()
        mok = guest(inst, "sh", "-c",
                    "command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null",
                    check=False, capture=True).stdout.strip()
        lock = guest(inst, "sh", "-c",
                     "cat /sys/kernel/security/lockdown 2>/dev/null",
                     check=False, capture=True).stdout.strip()
        ok, reason = _secureboot_verdict(efivar, mok, lock)
        if not ok:
            fail("Secure Boot assertion FAILED: " + reason +
                 "\n  The appliance's production posture is Secure Boot ON "
                 "(#1943). The #1930 A/B slot selector (scripts/image/grub.d/"
                 "09_xpf) is written as a GRUB script specifically because "
                 "`regexp` may be unavailable under Secure-Boot lockdown, so an "
                 "SB-off validation run does not exercise the chain this image "
                 "ships.")
        info(f"Secure Boot: {reason}")
    def _show_unit(self, inst, unit, prop):
        """One `systemctl show -p <prop> --value <unit>` field from the guest."""
        return guest(inst, "systemctl", "show", "-p", prop, "--value", unit,
                     check=False, capture=True).stdout.strip()

    def assert_ab_kernel_channel(self, inst):
        """Assert the #1930 LANE-1 A/B kernel-channel substrate actually came
        up IN THE GUEST (#6494) — not merely that the bake staged its files.

        Three things, in the order their failures would be diagnosed:
          1. the registration oneshot ran clean (it is non-fatal by design, so
             its own exit is the only place a failure is recorded at all);
          2. both slots are registered exactly once, with the right shim loader,
             and reachable in BootOrder — the state `xpfd upgrade kernel arm`
             refuses to proceed without;
          3. the promotion gate ran clean on this ordinary boot.

        On (3), note what is NOT asserted: the "promotion gate: clean" line.
        That line is only emitted once the gate has exec'd xpfd to run the
        promote verb. On a factory boot with nothing armed the script exits 0
        much earlier, logging "no armed kernel candidate recorded", so requiring
        the former here would fail every good image. What IS asserted is that
        the unit ran and exited 0, plus the ordinary-boot line, which together
        prove the gate EXECUTED rather than being skipped by a Condition — the
        thing an operator is relying on when they arm a candidate later.
        """
        info("#1930 LANE-1: A/B slot registration + promotion gate...")

        # Both oneshots are WantedBy=multi-user.target and are NOT ordered
        # Before=xpfd (deliberately — a hanging efibootmgr must never block the
        # #1922 mgmt lifeline), so xpfd being active does not imply they have
        # finished. Wait for each to settle rather than racing it.
        for unit in ("xpf-uefi-slots.service", "xpf-kernel-promote.service"):
            self._wait(inst,
                       lambda u=unit: self._show_unit(inst, u, "ActiveState")
                       not in ("activating", "reloading"),
                       40, 3, f"{unit} still activating after 120s")

        ok, reason = _oneshot_clean_verdict(
            "xpf-uefi-slots.service",
            self._show_unit(inst, "xpf-uefi-slots.service", "ExecMainStatus"),
            self._show_unit(inst, "xpf-uefi-slots.service", "ActiveState"),
            self._show_unit(inst, "xpf-uefi-slots.service", "Result"))
        if not ok:
            jrn = guest(inst, "journalctl", "-u", "xpf-uefi-slots", "-b",
                        "--no-pager", check=False, capture=True).stdout
            fail(f"#1930 A/B slot registration: {reason}\n{jrn[-800:]}")

        # The ESP dirs are the PRECONDITION for registration: register_slot()
        # returns 1 without ever calling efibootmgr when a slot has no shim. So
        # assert the staging BEFORE the NVRAM state — otherwise an unstaged
        # slot is diagnosed as "the oneshot did not register it", pointing at
        # the wrong half of the channel.
        kver = guest(inst, "uname", "-r", capture=True).stdout.strip()
        esp = guest(inst, "sh", "-c", _AB_SLOT_ESP_PROBE,
                    check=False, capture=True).stdout
        ok, reason = _ab_slot_esp_verdict(esp, kver)
        if not ok:
            fail("#1930 A/B slot ESP staging FAILED in-guest: " + reason +
                 "\n--- probe ---\n" + esp)
        info(f"  ESP OK: {reason}")

        got = guest(inst, "efibootmgr", check=False, capture=True)
        if got.returncode != 0:
            fail("efibootmgr failed in the guest "
                 f"(rc={got.returncode}: {(got.stderr or '').strip()!r}) — the "
                 "#1930 A/B kernel channel needs it to register the slots, so "
                 "an image where it is absent or cannot read NVRAM ships with "
                 "LANE-1 permanently unavailable")
        ok, reason = _efibootmgr_slot_verdict(got.stdout)
        if not ok:
            fail("#1930 A/B slot registration FAILED in-guest: " + reason +
                 "\n--- efibootmgr ---\n" + got.stdout)
        info(f"  slots OK: {reason}")

        ok, reason = _oneshot_clean_verdict(
            "xpf-kernel-promote.service",
            self._show_unit(inst, "xpf-kernel-promote.service", "ExecMainStatus"),
            self._show_unit(inst, "xpf-kernel-promote.service", "ActiveState"),
            self._show_unit(inst, "xpf-kernel-promote.service", "Result"))
        if not ok:
            jrn = guest(inst, "journalctl", "-u", "xpf-kernel-promote", "-b",
                        "--no-pager", check=False, capture=True).stdout
            fail(f"#1930 promotion gate: {reason}\n{jrn[-800:]}")
        if not guest_sh(inst,
                        'journalctl -u xpf-kernel-promote -b --no-pager '
                        '| grep -q "no armed kernel candidate recorded"'):
            fail("#1930 promotion gate did not log the ordinary-boot path "
                 "(\"no armed kernel candidate recorded\") — it exited 0 without "
                 "reaching its decision, so an armed candidate would go "
                 "unverified on a later boot")
        info("  promotion gate ran clean on this ordinary boot")

    def scenario_b(self):
        info("── Scenario B: first boot WITH valid day-0 config drive ──")
        b = self.iname("b")   # run-namespaced instance name (#4905-D)
        conf = os.path.join(self.work, "day0-valid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-b;\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-valid.iso"),
                                                   validate=False)
        self.launch(b, iso)
        self.wait_xpfd(b)
        if guest(b, "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode != 0:
            fail("day-0 stamp missing")
        if guest(b, "test", "-s", "/etc/xpf/xpf.conf", check=False).returncode != 0:
            fail("/etc/xpf/xpf.conf missing")
        self.assert_day0_conf_perms(b)
        if not guest_sh(b,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("day-0 loader did not log the install")
        self._wait(b,
                   lambda: guest_sh(b,
                                    'echo "show configuration" | /usr/local/sbin/cli 2>/dev/null '
                                    '| grep -q "host-name xpf-day0-b"'),
                   20, 3, "committed config does not show host-name xpf-day0-b")
        if not guest_sh(b, '[ "$(hostname)" = xpf-day0-b ]'):
            fail("hostname not applied")
        info(f"rebooting {b} — second boot must NOT re-apply...")
        incus("restart", b)
        self.wait_agent(b)
        self.wait_xpfd(b)
        if not guest_sh(b,
                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("second boot re-applied the day-0 config")
        if not guest_sh(b,
                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
            fail("second boot: day-0 loader neither condition-skipped nor stamp-skipped")
        info("Scenario B PASS")
        self.drop(b)

    def scenario_c(self):
        info("── Scenario C: first boot WITH INVALID day-0 config drive ──")
        c = self.iname("c")   # run-namespaced instance name (#4905-D)
        conf = os.path.join(self.work, "day0-invalid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-invalid.iso"),
                                                   validate=False)
        self.launch(c, iso)
        self.wait_xpfd(c)
        if not guest_sh(c,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
            fail("day-0 loader did not log the commit-check REJECT")
        if not guest_absent(c, "/etc/xpf/xpf.conf"):
            fail("invalid config was installed")
        if not guest_absent(c, "/etc/xpf/.day0-config-applied"):
            fail("stamp written on REJECT")
        self.wait_fxp0_dhcp(c)
        if not guest_sh(c, '[ "$(hostname)" != xpf-day0-c ]'):
            fail("invalid config changed the hostname")
        info("Scenario C reject leg PASS (fallback reachable, boot survived)")

        # ── Retry leg (#4209 H-9, pairs with H-1): the REJECT wrote no stamp
        # and left no committed active.json, so the box is still factory-
        # default. Swap the bad drive for a VALID one and reboot — the day-0
        # loader must re-probe and apply it. A regression that guarded on the
        # bare .configdb directory (H-1) would have declared "already
        # configured" here and never retried. ──
        info("C retry: swapping in a VALID drive and rebooting...")
        good = os.path.join(self.work, "day0-c-fixed.conf")
        with open(good, "w") as f:
            f.write("system {\n    host-name xpf-day0-c-fixed;\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        good_iso = make_config_drive.build_config_drive(
            good, os.path.join(self.work, "day0-c-fixed.iso"), validate=False)
        # Replace the day0 medium in place, then reboot.
        incus("config", "device", "remove", c, "day0", capture=True)
        incus("config", "device", "add", c, "day0", "disk",
              f"source={os.path.realpath(good_iso)}", capture=True)
        incus("restart", c)
        self.wait_agent(c)
        self.wait_xpfd(c)
        if guest(c, "test", "-e", "/etc/xpf/.day0-config-applied",
                 check=False).returncode != 0:
            fail("retry: day-0 stamp missing after fix+reboot — the retry "
                 "contract is broken (a rejected first boot could never be fixed)")
        if not guest_sh(c,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q '
                        '"day-0 config installed"'):
            fail("retry: day-0 loader did not install the fixed config on reboot")
        self.assert_day0_conf_perms(c)
        self._wait(c,
                   lambda: guest_sh(c, '[ "$(hostname)" = xpf-day0-c-fixed ]'),
                   20, 3, "retry: fixed hostname xpf-day0-c-fixed not applied")
        info("Scenario C PASS (reject survived, fix+reboot applied — retry contract)")
        self.drop(c)

    def _root_fs_gib(self, name):
        """Total size of the root filesystem in GiB (float), via df."""
        out = guest(name, "sh", "-c",
                    "df -B1 --output=size / | tail -n1", capture=True).stdout.strip()
        return int(out) / (1024.0 ** 3)

    def _root_part_gib(self, name):
        """Total size of the partition backing / in GiB (float), via lsblk
        on the resolved root source device — proves the PARTITION grew, not
        just the fs."""
        src = guest(name, "sh", "-c", "findmnt -no SOURCE /",
                    capture=True).stdout.strip()
        out = guest(name, "sh", "-c",
                    f"lsblk -bno SIZE {src} | head -n1", capture=True).stdout.strip()
        return int(out) / (1024.0 ** 3)

    def scenario_d(self):
        info("── Scenario D: first-boot root auto-grow on a resized disk (#1925) ──")
        d = self.iname("d")     # run-namespaced instance names (#4905-D)
        d2 = self.iname("d2")

        # ── Grow case: provision a root disk LARGER than the 8 GiB bake. ──
        info("D1 grow: launching with a 20GiB root disk (bake is 8GiB)...")
        self.launch(d, root_size="20GiB")
        self.wait_xpfd(d)
        # growpart + resize2fs MUST survive the cloud-init purge + autoremove
        # (#1925); a missing tool makes the grow a permanent no-op. Assert
        # presence first so package-name drift fails here with a clear cause
        # rather than as the downstream "partition still 8GiB" symptom.
        if not guest_sh(d, 'command -v growpart >/dev/null'):
            fail("growpart missing in the image — cloud-guest-utils not installed "
                 "(#1925 grow would no-op; the cloud-init purge orphaned it)")
        if not guest_sh(d, 'command -v resize2fs >/dev/null'):
            fail("resize2fs missing in the image — e2fsprogs not installed (#1925)")
        if not guest_sh(d, 'systemctl is-active --quiet xpf-grow-root'):
            fail("xpf-grow-root.service is not active after first boot")
        if guest(d, "test", "-e", "/etc/xpf/.root-grown",
                 check=False).returncode != 0:
            fail("root-grow stamp /etc/xpf/.root-grown missing after grow")
        part = self._root_part_gib(d)
        fs = self._root_fs_gib(d)
        info(f"D1 grow: root partition {part:.1f}GiB, filesystem {fs:.1f}GiB")
        # The 20GiB disk minus the small ESP/BIOS/BOOT partitions leaves the
        # root partition well above the 8GiB bake floor; assert it grew past a
        # conservative midpoint so a no-grow regression (still ~8GiB) fails.
        if part < 15.0:
            fail(f"root partition only {part:.1f}GiB on a 20GiB disk — did not grow")
        if fs < 15.0:
            fail(f"root filesystem only {fs:.1f}GiB on a 20GiB disk — resize2fs did not run")
        # The grow must not have disturbed the dataplane gate.
        if guest(d, "nice", "-n", "19", "/usr/local/sbin/xpfd",
                 "verify-dataplane", check=False).returncode != 0:
            fail("verify-dataplane REJECTED after root grow")
        # Boot/ESP partitions intact: exactly the root partition grew, the
        # partition count is unchanged, and the ESP is still mounted.
        if not guest_sh(d, 'mountpoint -q /boot/efi'):
            fail("ESP (/boot/efi) not mounted after grow — boot substrate disturbed")

        # ── Idempotency: reboot must NOT re-grow / re-stamp. ──
        info("D1 idempotency: rebooting — second boot must skip the grow...")
        incus("restart", d)
        self.wait_agent(d)
        self.wait_xpfd(d)
        if not guest_sh(d,
                        'systemctl show -p ConditionResult xpf-grow-root | grep -q '
                        '"ConditionResult=no"'):
            fail("second boot did not condition-skip xpf-grow-root (stamp ineffective)")
        part2 = self._root_part_gib(d)
        if abs(part2 - part) > 0.1:
            fail(f"root partition changed across reboot ({part:.1f} -> {part2:.1f}GiB)")
        info("D1 PASS (grew once, idempotent on reboot, boot substrate intact)")
        self.drop(d)

        # ── Control (no-op) case: bake-size disk must boot clean, no grow. ──
        info("D2 control: launching at the exact bake size (no resize)...")
        self.launch(d2)
        self.wait_xpfd(d2)
        # The grow ran (one-shot fired) but was a no-op: growpart NOCHANGE +
        # resize2fs no-op. The stamp is written either way (clean exit), and
        # the box boots clean with the dataplane gate green.
        if guest(d2, "test", "-e", "/etc/xpf/.root-grown",
                 check=False).returncode != 0:
            fail("root-grow stamp missing on the control (no-op) boot")
        if not guest_sh(d2,
                        'journalctl -u xpf-grow-root -b --no-pager | '
                        'grep -qiE "NOCHANGE|done"'):
            fail("control boot: xpf-grow-root did not log a no-op grow")
        if guest(d2, "nice", "-n", "19", "/usr/local/sbin/xpfd",
                 "verify-dataplane", check=False).returncode != 0:
            fail("verify-dataplane REJECTED on the control boot")
        info("D2 PASS (clean boot, grow was a no-op at bake size)")
        self.drop(d2)
        info("Scenario D PASS")

    def scenario_e(self):
        info("── Scenario E: cluster node-id day-0 drive (#4209 H-9) ──")
        e = self.iname("e")   # run-namespaced instance name (#4905-D)
        conf = os.path.join(self.work, "day0-node1.conf")
        with open(conf, "w") as f:
            # The `chassis cluster` stanza is REQUIRED, not decoration.
            # /etc/xpf/node-id does NOT select cluster naming: the daemon reads
            # clusterMode from the committed config
            # (namingParamsFromConfig -> cfg.Chassis.Cluster != nil), and
            # hasNodeIDFile() feeds only computeBootClass (bootstrap vs
            # normal). A node-id box with a cluster-less config runs STANDALONE
            # naming by design (#4179). Without this stanza the daemon
            # correctly produces fxp0 + ge-0-0-X and the em0 assertion below
            # can never pass (#7129).
            #
            # authentication-key is mandatory for a cluster stanza to survive
            # the real commit-check gate — the control channel fails OPEN
            # without a PSK. It is a throwaway literal: this VM never peers
            # with anything, and the scenario asserts naming only.
            f.write("system {\n    host-name xpf-node1;\n}\n"
                    "chassis {\n    cluster {\n        node 1;\n"
                    "        peer-address 10.99.12.1;\n"
                    "        authentication-key "
                    "\"xpf-image-validate-scenario-e-not-a-real-key\";\n"
                    "    }\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        # node_id=1 writes a `node-id` file (contents "1") alongside xpf.conf on
        # the drive; the loader persists it to /etc/xpf/node-id and the daemon
        # reads it BEFORE positional naming (fpc=7 for node 1).
        iso = make_config_drive.build_config_drive(
            conf, os.path.join(self.work, "day0-node1.iso"), node_id=1,
            validate=False)
        # Two extra NICs so the namer has em0 (idx 1) and ge-7-0-0 (idx 2).
        self.launch(e, iso, extra_nics=2)
        self.wait_xpfd(e)
        if guest(e, "test", "-e", "/etc/xpf/.day0-config-applied",
                 check=False).returncode != 0:
            fail("node-id drive: day-0 stamp missing")
        # node-id persisted verbatim.
        nid = guest(e, "sh", "-c",
                    "cat /etc/xpf/node-id 2>/dev/null",
                    capture=True).stdout.strip()
        if nid != "1":
            fail(f"/etc/xpf/node-id is '{nid}', expected '1' — node-id not "
                 "persisted from the day-0 drive")
        self.assert_day0_conf_perms(e)
        # Cluster-mode naming: node 1 uses FPC 7. em0 is assigned only in
        # cluster mode (position 2); ge-7/0/0 proves the node-1 FPC branch.
        if not guest_sh(e, 'ip link show em0 >/dev/null 2>&1'):
            fail("em0 not present — daemon did not enter cluster naming mode "
                 "for a node-id-present image")
        # KERNEL link name, not the Junos display name: the namer assigns
        # ge-{FPC}-0-{idx-2}, so `ip link show ge-7/0/0` could never match
        # whatever the daemon did (#7129). `show interfaces terse` is where
        # the slashes live.
        if not guest_sh(e, 'ip link show ge-7-0-0 >/dev/null 2>&1'):
            fail("ge-7-0-0 not present — node-1 FPC-7 positional naming did not "
                 "run (a node-0 image would name it ge-0-0-0)")
        info("Scenario E PASS (node-id=1 persisted, cluster em0 + ge-7-0-N naming)")
        self.drop(e)

    def skip(self, what, reason, fatal):
        """Record a skipped leg, and say so in a form main() can act on.

        `fatal` is a CLASSIFICATION, not a severity guess, and it is decided by
        one question: does bake.py guarantee the tool on a real bake host?

          - qemu-img is require()d in bake.py's preflight (bake.py:805), so its
            absence cannot happen on a legitimate bake. It is not routed here
            at all -- it is a hard fail() at the call site.
          - /dev/kvm is only a WARNING in that same preflight ("no /dev/kvm
            access — libguestfs will use TCG (slow)"), and qemu-system-x86_64
            is not required at all. A TCG bake host is therefore a SUPPORTED
            configuration, and the boot leg genuinely cannot run there. Making
            it fatal would break bakes that work today, so it is fatal=False --
            recorded and reported, never silent.

        This is the one place the #7347 fix deliberately departs from that
        issue's proposal ("exit non-zero if ANY scenario SKIPped"). Applied
        literally, that would fail every bake on a TCG host. The issue's own
        analysis agrees the boot leg is "a genuine partial skip" and that "the
        severity is concentrated in" the qemu-img return.
        """
        self.skipped.append((what, reason, fatal))
        info(f"SKIP {what}{' (FATAL)' if fatal else ''}: {reason}")

    def scenario_qemu(self):
        info("── Scenario Q: libvirt/plain-QEMU bootability (#4209 H-9) ──")
        # ── Config-level probe (ALWAYS — a missing qemu-img is a FAILURE, not
        # a skip): the qcow2 the docs sell for libvirt/KVM + plain QEMU must be
        # a valid, non-corrupt qcow2 of at least the bake floor. Catches a
        # truncated / wrong-format / corrupt export that incus import might
        # still accept but a raw qcow2 consumer (libvirt) would refuse.
        #
        # #7347: this used to `return` when qemu-img was absent, which skipped
        # the ENTIRE scenario. main() ran the scenarios for effect and returned
        # 0 regardless, bake.py read exit 0 as a pass, and finalize_artifacts
        # went on to stamp `validated: true` into the MINISIGNED manifest with
        # no structural evidence behind it. A scenario that returns is
        # indistinguishable from one that asserted, and here the difference was
        # laundered through a signature -- downstream `publish.py` and
        # `xpf-deploy.py fetch` verify the signature and read a signed image as
        # a validated one.
        #
        # Failing is safe by construction: bake.py's own preflight require()s
        # qemu-img (bake.py:805), so on a real bake host it is present. The
        # skip could only ever fire where this gate should not have been
        # trusted in the first place. Same posture as assert_image_sealed's
        # libguestfs check (#6547/#7317): a security gate that skips itself
        # when its tool is absent is the vacuous-gate shape these checks exist
        # to remove. ──
        if not shutil.which("qemu-img"):
            fail("qemu-img not found — install qemu-utils. The qcow2's "
                 "structural validity cannot be probed without it, and an "
                 "unprobed image must not be signed as validated (#7347)")
        raw = subprocess.run(["qemu-img", "info", "--output=json", self.qcow2],
                             capture_output=True, text=True)
        if raw.returncode != 0:
            fail(f"qemu-img info failed on {self.qcow2}: {raw.stderr.strip()}")
        ok, reason = _qemu_img_verdict(json.loads(raw.stdout), BAKE_MIN_BYTES)
        if not ok:
            fail(f"qcow2 is not libvirt-bootable: {reason}")
        info(f"qcow2 structural probe OK: {reason}")
        chk = subprocess.run(["qemu-img", "check", "-q", self.qcow2],
                             capture_output=True, text=True)
        # qemu-img check exits 0 clean, 2/3 on leaked/corrupt clusters.
        if chk.returncode not in (0,):
            fail("qemu-img check reported qcow2 corruption:\n"
                 f"{chk.stdout}{chk.stderr}")
        info("qcow2 consistency check OK (no corruption)")

        # ── Boot leg (gated): actually boot the SAME qcow2 under direct QEMU
        # with a valid day-0 config on a cdrom, and confirm via the serial
        # console that the appliance booted its userland and the day-0 loader
        # applied the config off the cdrom — the plain-QEMU + cdrom-day-0 path
        # incus never exercises. Needs qemu-system + KVM + OVMF; SKIP (probe
        # stands) when any is absent, mirroring the root-required skips. ──
        qsys = shutil.which("qemu-system-x86_64")
        # #6497: prefer an SB-ENFORCING firmware pair. The appliance ships a
        # Secure-Boot-signed chain and the #1930 slot selector is written for
        # lockdown, so an SB-off boot is not proof of the chain this image
        # actually ships. When no enforcing pair exists on the host we still run
        # the SB-off leg for plain-QEMU bootability coverage — but we SAY so,
        # loudly and in the log, instead of presenting it as Secure Boot proof.
        # That silent conflation is the defect: the old comment here read
        # "plain-QEMU bootability is proven fine with SB off", which is true and
        # was being counted as something it is not.
        ovmf, ovmf_vars, sb_on, fw_reason = _qemu_firmware_choice()
        if not qsys or not os.path.exists("/dev/kvm") or not ovmf or not ovmf_vars:
            self.skip(
                "Q/boot-leg",
                "need qemu-system-x86_64 + /dev/kvm + OVMF "
                f"(qemu={bool(qsys)} kvm={os.path.exists('/dev/kvm')} "
                f"firmware: {fw_reason}) — the structural probe above stands",
                fatal=False)
            return
        if sb_on:
            info(f"QEMU firmware: {fw_reason}")
        else:
            info(f"NOTE: {fw_reason}")
            info("      Install an OVMF secboot build + MS-keyed VARS "
                 "(ovmf on Debian/Ubuntu: OVMF_CODE_4M.secboot.fd + "
                 "OVMF_VARS_4M.ms.fd) to make this leg cover the Secure Boot "
                 "chain. Scenario A still asserts SB in-guest under incus.")
        conf = os.path.join(self.work, "day0-qemu.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-qemu;\n}\n")
        iso = make_config_drive.build_config_drive(
            conf, os.path.join(self.work, "day0-qemu.iso"), validate=False)
        vars_copy = os.path.join(self.work, "OVMF_VARS.fd")
        shutil.copyfile(ovmf_vars, vars_copy)
        serial = os.path.join(self.work, "qemu-serial.log")
        argv = [qsys, "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "2048", "-smp", "2", "-nographic",
                "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf}",
                "-drive", f"if=pflash,format=raw,file={vars_copy}",
                # snapshot=on: never mutate the artifact under test.
                "-drive", f"file={self.qcow2},if=virtio,format=qcow2,snapshot=on",
                "-drive", f"file={os.path.realpath(iso)},media=cdrom",
                "-serial", f"file:{serial}", "-nic", "none"]
        info("booting the qcow2 under direct QEMU (serial-captured, snapshot, "
             f"secure-boot={'on' if sb_on else 'OFF'})...")
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.time() + 360
            txt = ""
            while time.time() < deadline:
                if proc.poll() is not None:
                    _, err = proc.communicate()
                    fail(f"QEMU exited early (rc={proc.returncode}): "
                         f"{(err or b'').decode(errors='replace')[-400:]}")
                if os.path.isfile(serial):
                    txt = open(serial, errors="replace").read()
                    if "day-0 config installed" in txt:
                        info("QEMU boot: day-0 config installed off the cdrom")
                        break
                    if "REJECTED by commit-check" in txt:
                        fail("QEMU boot: day-0 loader REJECTED a valid config")
                time.sleep(3)
            else:
                fail("QEMU boot: no 'day-0 config installed' on the serial "
                     f"console within 360s (serial tail:\n{txt[-600:]})")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if sb_on:
            info("Scenario Q PASS (qcow2 valid + boots under plain QEMU with "
                 "cdrom day-0, SECURE BOOT ENFORCING — shim->grub->kernel "
                 "verified by the firmware)")
        else:
            info("Scenario Q PASS (qcow2 valid + boots under plain QEMU with "
                 "cdrom day-0) — SECURE BOOT OFF on this leg; it is NOT "
                 "Secure Boot proof (see the firmware note above)")


def _kver_ge(ver, floor):
    try:
        parts = tuple(int(x) for x in ver.split(".")[:2])
    except ValueError:
        return False
    return parts >= floor


def maybe_reexec_incus_admin():
    if subprocess.run(["incus", "list"], capture_output=True).returncode == 0:
        return
    import grp
    try:
        in_grp = "incus-admin" in [g.gr_name for g in grp.getgrall()
                                   if os.getlogin() in g.gr_mem]
    except Exception:
        in_grp = False
    if in_grp:
        # Quote every token — a qcow2/metadata path with spaces or shell
        # metacharacters must not break (or inject into) the `sg -c` shell.
        cmd = " ".join(shlex.quote(a) for a in [sys.executable] + sys.argv)
        os.execvp("sg", ["sg", "incus-admin", "-c", cmd])


def _stderr(m):
    print(m, file=sys.stderr)


def _skip_verdict(skipped, allow_skip):
    """Pure verdict over the skip ledger: (exit_code, lines_to_report).

    Split out of main() so the DECISION is testable without incus, a network,
    an image import or six VM boots. The bug this replaces was precisely that
    the decision did not exist: scenarios were run for effect and main()
    returned 0 unconditionally, so a leg that skipped reached bake.py as a pass
    and was signed `validated: true` (#7347).

    Reporting every skip by name is not cosmetic. The failure mode being fixed
    is that a skip was INVISIBLE downstream, so a run that skipped must say
    which leg and why, whether or not it also fails.
    """
    fatal = [x for x in skipped if x[2]]
    lines = []
    if skipped:
        lines.append(f"Validation complete, with {len(skipped)} skipped leg(s):")
        for what, reason, is_fatal in skipped:
            lines.append(f"  {'FATAL ' if is_fatal else ''}{what}: {reason}")
    else:
        lines.append("Validation complete (no legs skipped).")
    if fatal and not allow_skip:
        lines.append(
            f"FAIL: REFUSING to report success: {len(fatal)} leg(s) were "
            "skipped, not asserted. An artifact whose gate skipped must not be "
            "signed as validated (#7347). Pass --allow-skip for a dev run that "
            "knowingly accepts this.")
        return 1, lines
    if fatal:
        lines.append(
            "NOTE: --allow-skip was given, so the skipped leg(s) above do NOT "
            "fail this run. Do not sign an artifact validated this way.")
    return 0, lines


def main():
    maybe_reexec_incus_admin()
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--qcow2", required=True)
    p.add_argument("--metadata", required=True)
    p.add_argument("--keep", action="store_true")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--verify-sig", dest="verify_sig", action="store_const",
                   const="force", help="require a signed manifest (#1924)")
    g.add_argument("--no-verify-sig", dest="verify_sig", action="store_const",
                   const=False, help="skip image signature verification (dev)")
    p.set_defaults(verify_sig=True)  # default: verify if a .minisig is present
    # #7347: the dev escape hatch, shaped like --no-verify-sig above. It is
    # deliberately NOT passed by bake.py, so the bake path cannot skip a leg
    # and still report success.
    p.add_argument("--allow-skip", action="store_true",
                   help="do not fail when a leg is skipped rather than asserted "
                        "(dev only — never on a path that signs the artifact)")
    p.add_argument("scenario", nargs="?", default="all",
                   choices=SCENARIO_ORDER + ["all"])
    a = p.parse_args()
    if not os.path.isfile(a.qcow2):
        fail(f"--qcow2 not found: {a.qcow2}")
    if not os.path.isfile(a.metadata):
        fail(f"--metadata not found: {a.metadata}")
    net = os.environ.get("XPF_VALIDATE_NETWORK", "xpf-image-net")
    h = Harness(a.qcow2, a.metadata, net, a.keep, a.verify_sig)
    try:
        # #9921 F-068: freeze the gate inputs before ANY artifact read (seal
        # is first). Idempotent; seal/verify also freeze defensively.
        h.freeze_artifacts()
        # #6547: the seal is verified on the EXPORTED ARTIFACT, before the
        # image is imported or any scenario boots. First, because it is the
        # only point at which a per-device identity is observable; second, so a
        # clone-identity regression fails the gate cheaply rather than after
        # six VM boots.
        h.assert_image_sealed()
        h.ensure_network()
        h.import_image()
        keys = SCENARIO_ORDER if a.scenario == "all" else [a.scenario]
        for k in keys:
            getattr(h, SCENARIO_METHODS[k])()
        # #7347: the scenarios used to be run purely for effect and main()
        # returned 0 unconditionally, so a leg that SKIPPED was indistinguish-
        # able from one that ASSERTED -- and bake.py reads exit 0 as a pass and
        # signs `validated: true`. Report every skip by name, and refuse to
        # return 0 when a skip was classified as not survivable.
        code, lines = _skip_verdict(h.skipped, a.allow_skip)
        for line in lines:
            (info if code == 0 else _stderr)(line)
        return code
    finally:
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
