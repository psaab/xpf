#!/usr/bin/env python3
"""Systemd-unit staging canary over the explicit lists (#16198).

The unit sets are staged/enabled/cleaned by hand in three places that no
single build step cross-checks:

  * ``debian/rules`` stages units as ``debian/xpf.<name>.service`` (one by
    ``sed`` transform), enables a subset via ``dh_installsystemd``, and
    removes the staged copies in ``override_dh_clean``;
  * ``scripts/image/bake.py`` ``--copy-in``s a partly different set into
    the image and ``systemctl enable``s a subset of that;
  * the unit sources themselves reference other units via
    ``OnFailure=`` / ``RequiredBy=``.

Only the promote unit's ``OnFailure=`` target had a staging assert (in
``debian/rules`` itself, same instrument that writes the list). A dropped
``cp``, a forgotten ``dh_installsystemd`` line, a stale clean entry, or a
renamed ``OnFailure=`` target otherwise ships silently -- the #4202
dangling-recovery-unit defect was exactly this shape.

This canary is a SECOND, differently-filtered instrument over the same
explicit lists: ``debian/rules`` is read as joined make logical lines,
``bake.py`` is read through its Python AST string constants, and the unit
sources are read as systemd directives. The lists stay explicit and
remain the source of truth -- there is NO generator. The expected sets
below are test data only; the intentional image/deb divergence is
encoded as explicit allowlists, never as literal set equality:

  * image-only (bake ``--copy-in``, not in the .deb): ``xpf-grow-root``
    grows the baked image's root partition on first boot and is
    meaningless on a foreign host; ``incus-agent`` is pulled in by its
    udev rule, never enabled, and only exists inside an image.
  * deb-only (in the .deb, not bake ``--copy-in``): ``xpfd`` and
    ``xpf-day0-config`` reach the image through the ``apt-get install``
    of the .deb inside ``virt_customize``, not through a raw copy-in.

Acceptance (#16198): reds on a seeded dropped unit and on a seeded
dangling ``OnFailure=`` target, greens on the current explicit lists
with the allowlists applied. The seeded cases are the in-memory
counterfactual tests at the bottom -- they feed mutated inputs through
the same comparator so a canary that examined nothing cannot pass.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RULES = ROOT / "debian" / "rules"
BAKE = HERE / "bake.py"

# ---------------------------------------------------------------------------
# Manifest (test data only). Unit names are the INSTALLED names
# (``debian/xpf.xpfd.service`` installs as ``xpfd.service``).
# ---------------------------------------------------------------------------

# Every unit the .deb stages, installed name -> repo source.
DEB_STAGED = {
    "xpfd.service": "test/incus/xpfd.service",
    "xpf-day0-config.service": "scripts/image/xpf-day0-config.service",
    "xpf-ssh-hostkeys.service": "scripts/image/xpf-ssh-hostkeys.service",
    "xpf-transit-closed.service": "scripts/image/xpf-transit-closed.service",
    "xpf-input-closed.service": "scripts/image/xpf-input-closed.service",
    "xpf-uefi-slots.service": "scripts/image/xpf-uefi-slots.service",
    "xpf-kernel-promote.service": "scripts/image/xpf-kernel-promote.service",
    "xpf-kernel-promote-failed.service":
        "scripts/image/xpf-kernel-promote-failed.service",
}

# Staged but deliberately NOT enabled: triggered only via OnFailure=.
DEB_NOT_ENABLED = {"xpf-kernel-promote-failed.service"}

# Every unit bake --copy-ins into /usr/lib/systemd/system.
BAKE_COPY_IN = {
    "incus-agent.service",
    "xpf-transit-closed.service",
    "xpf-input-closed.service",
    "xpf-ssh-hostkeys.service",
    "xpf-uefi-slots.service",
    "xpf-kernel-promote.service",
    "xpf-kernel-promote-failed.service",
    "xpf-grow-root.service",
}

# Copy-in'd but deliberately NOT enabled by the bake: incus-agent is
# udev-activated; the promote-failed unit is OnFailure=-triggered.
BAKE_NOT_ENABLED = {"incus-agent.service", "xpf-kernel-promote-failed.service"}

# Explicit allowlists for the intentional divergence. A unit that lands
# in exactly one of {deb, image} without being named here reds the
# canary; so does an allowlist entry that stops being divergent.
IMAGE_ONLY = {"xpf-grow-root.service", "incus-agent.service"}
DEB_ONLY = {"xpfd.service", "xpf-day0-config.service"}

# OnFailure=/RequiredBy= targets that are NOT ours to stage: units owned
# by other packages / systemd itself. An xpf-owned target may never be
# added here -- it must be staged (that is the #4202 lesson).
EXTERNAL_REF_TARGETS = {"systemd-networkd.service"}

# The sed transform debian/rules applies to the xpfd unit source.
XPFD_GATE_LINE = "ExecStartPre=/usr/local/sbin/xpfd verify-dataplane"
XPFD_SOURCE = "test/incus/xpfd.service"


# ---------------------------------------------------------------------------
# Instrument 1: debian/rules as joined make logical lines.
# ---------------------------------------------------------------------------

def _logical_lines(text: str) -> list[str]:
    return text.replace("\\\n", " ").splitlines()


def parse_rules(text: str) -> dict:
    staged: dict[str, str] = {}  # installed name -> repo source
    enabled: set[str] = set()
    not_enabled: set[str] = set()
    clean: set[str] = set()
    gate_line = None
    in_clean = False
    for line in _logical_lines(text):
        if line.startswith("override_dh_clean:"):
            in_clean = True
        elif line and not line[0] in "\t# " and line.rstrip().endswith(":"):
            in_clean = False
        if in_clean:
            clean.update(re.findall(r"debian/xpf\.([A-Za-z0-9._-]+\.service)", line))
        m = re.match(r"\s*cp\s+(\S+\.service)\s+debian/xpf\.([A-Za-z0-9._-]+\.service)\s*$", line)
        if m:
            staged[m.group(2)] = m.group(1)
            continue
        m = re.search(r"sed\s.*?\s(\S+\.service)\s*>\s*debian/xpf\.([A-Za-z0-9._-]+\.service)", line)
        if m:
            staged[m.group(2)] = m.group(1)
            g = re.search(r"\bi\s+(ExecStartPre=\S+(?:\s+\S+)*?)'", line)
            if g:
                gate_line = g.group(1)
            continue
        if "dh_installsystemd" in line:
            m = re.search(r"--name=([A-Za-z0-9._-]+)", line)
            if m:
                (not_enabled if "--no-enable" in line else enabled).add(
                    m.group(1) + ".service")
    return {
        "staged": staged,
        "enabled": enabled,
        "not_enabled": not_enabled,
        "clean": clean,
        "gate_line": gate_line,
    }


# ---------------------------------------------------------------------------
# Instrument 2: bake.py through its AST string constants (never regex over
# the raw source -- that would be the same filter as the rules parser's
# line scan wearing a second hat).
# ---------------------------------------------------------------------------

def _render(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return ""


def parse_bake(text: str) -> dict:
    strings = [_render(n) for n in ast.walk(ast.parse(text))
               if isinstance(n, (ast.Constant, ast.JoinedStr))]
    copy_in = set()
    enabled = set()
    deb_install = False
    for s in strings:
        copy_in.update(re.findall(
            r"/([A-Za-z0-9._-]+\.service):/usr/lib/systemd/system", s))
        enabled.update(re.findall(
            r"systemctl enable ([A-Za-z0-9._-]+\.service)", s))
        if "apt-get install" in s and "/var/tmp/" in s:
            deb_install = True
    return {"copy_in": copy_in, "enabled": enabled, "deb_install": deb_install}


# ---------------------------------------------------------------------------
# Instrument 3: unit sources as systemd directives.
# ---------------------------------------------------------------------------

def parse_refs(text: str) -> dict[str, set[str]]:
    refs: dict[str, set[str]] = {"OnFailure": set(), "RequiredBy": set()}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;[":
            continue
        key, sep, value = line.partition("=")
        if sep and key.strip() in refs:
            refs[key.strip()].update(value.split())
    return refs


def apply_xpfd_transform(source_text: str, gate_line: str) -> str:
    out = []
    for line in source_text.splitlines():
        if re.match(r"\s*ExecStart\s*=", line):
            out.append(gate_line)
        out.append(line)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Comparator. Pure: mutated inputs in, problem strings out.
# ---------------------------------------------------------------------------

def canary_problems(rules: dict, bake: dict, unit_texts: dict[str, str],
                    source_units: set[str]) -> list[str]:
    p: list[str] = []
    staged, enabled = rules["staged"], rules["enabled"]

    if set(staged) != set(DEB_STAGED):
        p.append(f"debian/rules staged set diverges from manifest: "
                 f"missing={sorted(set(DEB_STAGED) - set(staged))} "
                 f"extra={sorted(set(staged) - set(DEB_STAGED))}")
    for name, src in DEB_STAGED.items():
        if name in staged and staged[name] != src:
            p.append(f"{name}: staged from {staged[name]}, manifest source is {src}")
    if enabled != set(DEB_STAGED) - DEB_NOT_ENABLED:
        p.append(f"debian/rules enabled set diverges: "
                 f"missing={sorted((set(DEB_STAGED) - DEB_NOT_ENABLED) - enabled)} "
                 f"extra={sorted(enabled - (set(DEB_STAGED) - DEB_NOT_ENABLED))}")
    if rules["not_enabled"] != DEB_NOT_ENABLED:
        p.append(f"debian/rules --no-enable set {sorted(rules['not_enabled'])} "
                 f"!= manifest {sorted(DEB_NOT_ENABLED)}")
    if rules["clean"] != set(staged):
        p.append(f"override_dh_clean removes xpf.* files for "
                 f"{sorted(rules['clean'])}, staged units are {sorted(staged)}")
    if rules["gate_line"] != XPFD_GATE_LINE:
        p.append(f"xpfd sed gate line is {rules['gate_line']!r}, "
                 f"expected {XPFD_GATE_LINE!r}")
    if staged.get("xpfd.service") != XPFD_SOURCE:
        p.append("xpfd.service is not the sed transform of "
                 f"{XPFD_SOURCE} (staged from {staged.get('xpfd.service')!r})")

    if bake["copy_in"] != BAKE_COPY_IN:
        p.append(f"bake --copy-in unit set diverges from manifest: "
                 f"missing={sorted(BAKE_COPY_IN - bake['copy_in'])} "
                 f"extra={sorted(bake['copy_in'] - BAKE_COPY_IN)}")
    bake_enabled = bake["copy_in"] - BAKE_NOT_ENABLED
    if bake["enabled"] != bake_enabled:
        p.append(f"bake systemctl enable set diverges: "
                 f"missing={sorted(bake_enabled - bake['enabled'])} "
                 f"extra={sorted(bake['enabled'] - bake_enabled)}")
    if not bake["deb_install"]:
        p.append("bake never apt-installs the .deb from /var/tmp, so the "
                 "deb-only units would not reach the image")

    # The intentional divergence must be exactly the allowlists.
    if bake["copy_in"] - set(staged) != IMAGE_ONLY:
        p.append(f"image-only set {sorted(bake['copy_in'] - set(staged))} "
                 f"!= allowlist {sorted(IMAGE_ONLY)}")
    if set(staged) - bake["copy_in"] != DEB_ONLY:
        p.append(f"deb-only set {sorted(set(staged) - bake['copy_in'])} "
                 f"!= allowlist {sorted(DEB_ONLY)}")

    # Every unit source on disk is shipped by at least one path, and the
    # shipped sources are exactly the sources on disk (no orphan unit).
    shipped = set(staged) | bake["copy_in"]
    if source_units != shipped:
        p.append(f"unit sources on disk vs shipped units diverge: "
                 f"unshipped={sorted(source_units - shipped)} "
                 f"sourceless={sorted(shipped - source_units)}")

    # Every OnFailure=/RequiredBy= target of every shipped unit is itself
    # staged somewhere it can be found, or explicitly external.
    for name in sorted(shipped):
        text = unit_texts.get(name)
        if text is None:
            p.append(f"{name}: no unit text supplied")
            continue
        for directive, targets in parse_refs(text).items():
            for target in sorted(targets):
                if target not in shipped and target not in EXTERNAL_REF_TARGETS:
                    p.append(f"{name}: {directive}={target} is dangling -- "
                             f"not staged in the .deb or the image and not "
                             f"an allowlisted external unit")
    return p


def _load() -> tuple[dict, dict, dict[str, str], set[str]]:
    rules = parse_rules(RULES.read_text())
    bake = parse_bake(BAKE.read_text())
    sources = {p.name: p for p in (HERE.glob("*.service"))}
    sources["xpfd.service"] = ROOT / "test" / "incus" / "xpfd.service"
    unit_texts = {}
    for name, path in sources.items():
        text = path.read_text()
        if name == "xpfd.service":
            text = apply_xpfd_transform(text, rules["gate_line"] or "")
        unit_texts[name] = text
    return rules, bake, unit_texts, set(sources)


class SystemdUnitCanaryTests(unittest.TestCase):
    def test_current_explicit_lists_green_with_allowlists(self):
        rules, bake, unit_texts, source_units = _load()
        self.assertEqual(canary_problems(rules, bake, unit_texts, source_units), [])

    def test_xpfd_transform_lands_gate_before_execstart(self):
        rules, _, unit_texts, _ = _load()
        lines = unit_texts["xpfd.service"].splitlines()
        gates = [i for i, l in enumerate(lines) if l == XPFD_GATE_LINE]
        self.assertEqual(len(gates), 1, lines)
        self.assertRegex(lines[gates[0] + 1], r"^\s*ExecStart\s*=")

    # -- Counterfactuals: seeded defects MUST red through the comparator. --

    def test_seeded_dropped_deb_unit_reds(self):
        rules, bake, unit_texts, source_units = _load()
        text = RULES.read_text()
        dropped = re.sub(r"(?m)^\tcp scripts/image/xpf-uefi-slots\.service.*\n", "", text)
        self.assertNotEqual(dropped, text)
        problems = canary_problems(parse_rules(dropped), bake, unit_texts, source_units)
        self.assertTrue(any("xpf-uefi-slots" in s for s in problems), problems)

    def test_seeded_dropped_bake_unit_reds(self):
        rules, bake, unit_texts, source_units = _load()
        bake = dict(bake, copy_in=bake["copy_in"] - {"xpf-grow-root.service"})
        problems = canary_problems(rules, bake, unit_texts, source_units)
        self.assertTrue(any("xpf-grow-root" in s for s in problems), problems)

    def test_seeded_dangling_onfailure_reds(self):
        rules, bake, unit_texts, source_units = _load()
        unit_texts = dict(unit_texts)
        unit_texts["xpf-kernel-promote.service"] = unit_texts[
            "xpf-kernel-promote.service"].replace(
                "OnFailure=xpf-kernel-promote-failed.service",
                "OnFailure=xpf-no-such-unit.service")
        problems = canary_problems(rules, bake, unit_texts, source_units)
        self.assertTrue(any("dangling" in s and "xpf-no-such-unit" in s
                            for s in problems), problems)

    def test_seeded_dangling_requiredby_reds(self):
        rules, bake, unit_texts, source_units = _load()
        unit_texts = dict(unit_texts)
        unit_texts["xpf-input-closed.service"] = unit_texts[
            "xpf-input-closed.service"].replace(
                "RequiredBy=xpfd.service", "RequiredBy=xpf-gone.service")
        problems = canary_problems(rules, bake, unit_texts, source_units)
        self.assertTrue(any("dangling" in s and "xpf-gone" in s
                            for s in problems), problems)

    def test_seeded_clean_omission_reds(self):
        rules, bake, unit_texts, source_units = _load()
        rules = dict(rules, clean=rules["clean"] - {"xpfd.service"})
        problems = canary_problems(rules, bake, unit_texts, source_units)
        self.assertTrue(any("override_dh_clean" in s for s in problems), problems)


if __name__ == "__main__":
    unittest.main()
