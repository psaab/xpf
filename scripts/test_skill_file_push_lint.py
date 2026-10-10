#!/usr/bin/env python3
"""Regression tests for the Claude skill binary-push lint."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.skill_file_push_lint import findings


class SkillFilePushLintTest(unittest.TestCase):
    def test_flags_manual_binary_push_in_skill(self):
        with tempfile.TemporaryDirectory(prefix="skill-file-push-lint-") as directory:
            root = Path(directory)
            skill = root / ".claude" / "skills" / "unsafe" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text(
                "# Unsafe steps\nincus file push binary target\n", encoding="utf-8"
            )

            self.assertEqual(
                findings(root),
                [".claude/skills/unsafe/SKILL.md:2: incus file push binary target"],
            )

    def test_all_shipped_skill_markdown_is_clean(self):
        self.assertEqual(findings(), [])


if __name__ == "__main__":
    unittest.main()
