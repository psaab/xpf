#!/usr/bin/env python3
"""Hermetic unit tests for the #6503 day-0 config permission assertion.

The day-0 loader installs `/etc/xpf/xpf.conf` mode 0600 because it "may carry
credential material (root-authentication encrypted-password, IKE PSKs)"
(`scripts/image/xpf-day0-config`). Scenario B of the Tier-1 gate asserted the
file EXISTS and is non-empty (`test -s`) and nothing about the mode —
`docs/image-validation.md` said so in as many words — so a regression to 0644
would ship world-readable IKE PSKs and password hashes inside a signed image
and pass the gate green.

Two details worth stating, because a naive version of this check has both bugs:

  * THE MODE IS COMPARED AS AN OCTAL VALUE, not as the string "600" — for
    RENDERING independence, not because a string compare would let a bad mode
    through. GNU `stat -c %a` emits "600" unpadded, so `!= "600"` rejects
    "4600" exactly as `!= 0o600` does; the string-compare mutation is only
    distinguishable because a zero-padded "0600" is the same mode and must not
    be a false red. (An earlier draft of this file claimed a string compare
    "silently accepts 4600". That is FALSE, and the mutation matrix is what
    caught it: the string-compare mutation did not red.)

  * THE PROBE DOES NOT PASS `stat -L`. Verified on a real filesystem: for a
    symlink, `stat -c '%a %U:%G %F'` reports the LINK (`777 ... symbolic
    link`), while `stat -L` reports the TARGET (`644 ... regular file`). A
    check that followed the link would read the target's mode while the file
    an attacker controls is the link — so a 0600 target behind a
    world-writable link would PASS. The file type is therefore part of the
    verdict, not an afterthought.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
validate = load_subject("validate", _HERE / "validate.py")

GOOD = "600 root:root regular file"


class ConfModeVerdictTests(unittest.TestCase):
    def test_root_owned_regular_file_mode_600_passes(self):
        ok, reason = validate._conf_mode_verdict(GOOD)
        self.assertTrue(ok, reason)

    def test_trailing_newline_and_padding_are_tolerated(self):
        ok, reason = validate._conf_mode_verdict("  600 root:root regular file \n")
        self.assertTrue(ok, reason)

    def test_world_readable_0644_fails(self):
        # THE regression this exists for.
        ok, reason = validate._conf_mode_verdict("644 root:root regular file")
        self.assertFalse(ok)
        self.assertIn("644", reason)

    def test_group_readable_0640_fails(self):
        ok, _ = validate._conf_mode_verdict("640 root:root regular file")
        self.assertFalse(ok)

    def test_world_writable_0666_fails(self):
        ok, _ = validate._conf_mode_verdict("666 root:root regular file")
        self.assertFalse(ok)

    def test_setuid_bit_on_an_otherwise_correct_mode_fails(self):
        ok, reason = validate._conf_mode_verdict("4600 root:root regular file")
        self.assertFalse(ok)
        self.assertIn("4600", reason)

    def test_a_zero_padded_rendering_of_the_same_mode_passes(self):
        # The actual reason the comparison is over the octal VALUE: "0600" and
        # "600" are the same mode, and a verdict that rejected one rendering
        # would be a false red, not a caught regression. This is the ONLY
        # assertion a string compare against "600" fails, which is why it is
        # written out rather than left implicit.
        ok, reason = validate._conf_mode_verdict("0600 root:root regular file")
        self.assertTrue(ok, reason)

    def test_non_root_owner_fails(self):
        ok, reason = validate._conf_mode_verdict("600 nobody:nogroup regular file")
        self.assertFalse(ok)
        self.assertIn("nobody:nogroup", reason)

    def test_root_owner_wrong_group_fails(self):
        ok, _ = validate._conf_mode_verdict("600 root:staff regular file")
        self.assertFalse(ok)

    def test_a_symlink_fails_even_though_its_own_mode_is_irrelevant(self):
        # `stat` without -L reports the LINK: 777 symbolic link. Both the type
        # and the mode are wrong here, but the TYPE is the load-bearing half —
        # see the class below.
        ok, reason = validate._conf_mode_verdict("777 root:root symbolic link")
        self.assertFalse(ok)
        self.assertIn("symbolic link", reason)

    def test_a_symlink_whose_mode_LOOKS_right_still_fails(self):
        # The case that makes the type check load-bearing rather than
        # decorative: if the probe had used `stat -L`, a 0600 TARGET behind an
        # attacker-controlled link would report exactly this and PASS on mode
        # alone. Only the file-type field rejects it.
        ok, reason = validate._conf_mode_verdict("600 root:root symbolic link")
        self.assertFalse(ok)
        self.assertIn("symbolic link", reason)

    def test_a_directory_fails(self):
        ok, _ = validate._conf_mode_verdict("600 root:root directory")
        self.assertFalse(ok)

    def test_empty_output_fails_rather_than_passing_vacuously(self):
        # An absent file or a failed probe leaves the property UNOBSERVED,
        # which is not the same as satisfied.
        ok, reason = validate._conf_mode_verdict("")
        self.assertFalse(ok)
        self.assertIn("unobserved", reason)

    def test_truncated_output_fails(self):
        ok, _ = validate._conf_mode_verdict("600 root:root")
        self.assertFalse(ok)

    def test_unparseable_mode_fails(self):
        ok, reason = validate._conf_mode_verdict("rw------- root:root regular file")
        self.assertFalse(ok)
        self.assertIn("unparseable", reason)

    def test_all_three_problems_are_reported_together(self):
        ok, reason = validate._conf_mode_verdict("777 nobody:nogroup symbolic link")
        self.assertFalse(ok)
        for needle in ("symbolic link", "777", "nobody:nogroup"):
            self.assertIn(needle, reason)


class ProbeShapeTests(unittest.TestCase):
    def test_the_probe_does_not_follow_symlinks(self):
        # If -L is ever added, the verdict starts reading the target and the
        # symlink cases above become unreachable in production while still
        # passing here.
        self.assertNotIn("-L", validate._DAY0_CONF_STAT)

    def test_the_probe_asks_for_exactly_the_three_fields_the_verdict_parses(self):
        self.assertIn("%a", validate._DAY0_CONF_STAT)
        self.assertIn("%U:%G", validate._DAY0_CONF_STAT)
        self.assertIn("%F", validate._DAY0_CONF_STAT)

    def test_the_probe_targets_the_installed_config(self):
        self.assertIn("/etc/xpf/xpf.conf", validate._DAY0_CONF_STAT)


class WiringTests(unittest.TestCase):
    """A verdict nothing calls asserts nothing. The loader reaches the same
    `install -o root -g root -m 0600` from every scenario that installs a
    config, so all three pin it."""

    SRC = (_HERE / "validate.py").read_text(encoding="utf-8")

    def _body(self, name):
        return self.SRC.split(f"def {name}(self", 1)[1].split("\n    def ", 1)[0]

    def test_scenario_b_asserts_the_config_permissions(self):
        self.assertIn("self.assert_day0_conf_perms(", self._body("scenario_b"))

    def test_scenario_c_retry_leg_asserts_them_too(self):
        self.assertIn("self.assert_day0_conf_perms(", self._body("scenario_c"))

    def test_scenario_e_node_id_drive_asserts_them_too(self):
        self.assertIn("self.assert_day0_conf_perms(", self._body("scenario_e"))

    def test_the_assertion_uses_the_verdict(self):
        self.assertIn("_conf_mode_verdict(", self._body("assert_day0_conf_perms"))


if __name__ == "__main__":
    unittest.main()
