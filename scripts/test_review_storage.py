#!/usr/bin/env python3
"""Hermetic regression tests for review deduplication across storage layouts.

Run directly or through make selftest. Fixtures replace filesystem reads and
discovery, so no existing temporary reports, Git checkout metadata, or network
access are needed. Publication and watcher behavior are not exercised here.
"""

import io
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from load_subject import load_subject  # noqa: E402


dedup = load_subject("review_dedup", Path(__file__).with_name("review-dedup-check.py"))

NEW_REPORT = "/var/tmp/deep-review-reports/gpt-5.6-sol-review-storage-001.md"
FINISHED_REPORT = "/var/tmp/deep-review-finished/gpt-5.6-sol-review-storage-007.md"
OLD_REPORT = "/tmp/muse-spark-review-009.md"
NEW_INDEX = "/var/tmp/deep-review-work/review-index.json"
OLD_INDEX = "/tmp/review-index.json"
NEW_ISSUES = "/var/tmp/deep-review-work/issue-pr-index.json"
OLD_ISSUES = "/tmp/issue-pr-index.json"


class ReviewStorageTests(unittest.TestCase):
    def setUp(self):
        self.files = {}
        self.discovered = {
            "/var/tmp/deep-review-reports/*-review*.md": [NEW_REPORT],
            "/var/tmp/deep-review-finished/*-review*.md": [FINISHED_REPORT],
            "/tmp/*-review*.md": [OLD_REPORT],
        }
        reads = patch.object(dedup, "open", side_effect=self.read, create=True)
        reads.start()
        self.addCleanup(reads.stop)
        discovery = patch.object(
            dedup.glob, "glob", side_effect=self.discovered.__getitem__
        )
        self.glob = discovery.start()
        self.addCleanup(discovery.stop)

    def read(self, path, *args, **kwargs):
        if str(path) not in self.files:
            raise FileNotFoundError(path)
        return io.StringIO(self.files[str(path)])

    def test_active_finished_and_legacy_roots_without_indexes(self):
        self.files = {
            NEW_REPORT: "Title: Current finding\n",
            FINISHED_REPORT: "Title: Archived finding\n",
            OLD_REPORT: "Title: Legacy finding\n",
        }
        self.assertEqual(dedup.load_review_titles(), [
            (Path(NEW_REPORT).name, "Current finding"),
            (Path(FINISHED_REPORT).name, "Archived finding"),
            (Path(OLD_REPORT).name, "Legacy finding"),
        ])
        self.assertEqual(self.glob.call_args_list, [
            call("/var/tmp/deep-review-reports/*-review*.md"),
            call("/var/tmp/deep-review-finished/*-review*.md"),
            call("/tmp/*-review*.md"),
        ])

    def test_stale_indexes_cannot_hide_archived_only_findings(self):
        for index in (NEW_INDEX, OLD_INDEX):
            with self.subTest(index=index):
                self.files = {
                    index: json.dumps([
                        {"filename": "cached.md", "titles": ["Cached finding"]},
                    ]),
                    FINISHED_REPORT: "Title: Archived finding\n",
                }
                self.assertEqual(dedup.load_review_titles(), [
                    ("cached.md", "Cached finding"),
                    (Path(FINISHED_REPORT).name, "Archived finding"),
                ])

    def test_matching_finds_review_after_active_original_is_gone(self):
        title = "Archived review storage finding"
        self.files = {FINISHED_REPORT: "Title: " + title + "\n"}
        matches = dedup.check_finding(title)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][:3], (Path(FINISHED_REPORT).name, title, 1.0))

    def test_partial_archive_copies_do_not_duplicate_title_rows(self):
        archived_copy = "/var/tmp/deep-review-finished/" + Path(NEW_REPORT).name
        self.discovered["/var/tmp/deep-review-finished/*-review*.md"] = [archived_copy]
        self.files = {
            NEW_REPORT: "Title: Original finding\n",
            archived_copy: "Title: Original finding\n",
        }
        self.assertEqual(dedup.load_review_titles(), [
            (Path(NEW_REPORT).name, "Original finding"),
        ])

    def test_legacy_cached_index_cannot_hide_new_reports(self):
        self.files = {
            OLD_INDEX: json.dumps([
                {"filename": "cached.md", "titles": ["Cached finding"]},
            ]),
            NEW_REPORT: "Title: Newly published finding\n",
            OLD_REPORT: "Title: Legacy finding\n",
        }
        self.assertEqual(set(dedup.load_review_titles()), {
            ("cached.md", "Cached finding"),
            (Path(NEW_REPORT).name, "Newly published finding"),
            (Path(OLD_REPORT).name, "Legacy finding"),
        })

    def test_merge_indexes_and_scans_without_duplicate_rows(self):
        entry = {"filename": Path(NEW_REPORT).name, "titles": ["Current finding"]}
        self.files = {
            NEW_INDEX: json.dumps([entry]),
            OLD_INDEX: json.dumps([
                entry, {"filename": "cached.md", "titles": ["Cached finding"]},
            ]),
            NEW_REPORT: "Title: Current finding\n",
        }
        self.assertEqual(dedup.load_review_titles(), [
            (Path(NEW_REPORT).name, "Current finding"),
            ("cached.md", "Cached finding"),
        ])

    def test_corrupt_index_cannot_hide_reports(self):
        for index in (NEW_INDEX, OLD_INDEX):
            with self.subTest(index=index):
                self.files = {
                    index: "{invalid-json",
                    NEW_REPORT: "Title: Current finding\n",
                }
                self.assertEqual(dedup.load_review_titles(), [
                    (Path(NEW_REPORT).name, "Current finding"),
                ])

    def test_disappeared_report_does_not_hide_readable_report(self):
        # Both names were discovered, but the current report is no longer readable.
        self.files = {OLD_REPORT: "Title: Legacy finding\n"}
        self.assertEqual(dedup.load_review_titles(), [
            (Path(OLD_REPORT).name, "Legacy finding"),
        ])

    def test_empty_roots_need_no_preexisting_state(self):
        for paths in self.discovered.values():
            paths.clear()
        self.assertEqual(dedup.load_review_titles(), [])
        self.assertEqual(dedup.load_issue_titles(), [])

    def test_merge_issue_indexes_without_duplicate_rows(self):
        self.files = {
            NEW_ISSUES: json.dumps({"issues": [
                {"number": 1, "title": "A"}, {"number": 3, "title": "C"},
            ]}),
            OLD_ISSUES: json.dumps({"issues": [
                {"number": 1, "title": "A"}, {"number": 2, "title": "B"},
            ]}),
        }
        self.assertEqual(dedup.load_issue_titles(), [
            ("ISSUE #1", "A"), ("ISSUE #3", "C"), ("ISSUE #2", "B"),
        ])

    def test_legacy_issue_index_survives_absent_empty_or_bad_current_index(self):
        for current in (None, '{"issues": []}', "{invalid-json"):
            with self.subTest(current=current):
                self.files = {
                    OLD_ISSUES: json.dumps({"issues": [{"number": 2, "title": "B"}]}),
                }
                if current is not None:
                    self.files[NEW_ISSUES] = current
                self.assertEqual(dedup.load_issue_titles(), [("ISSUE #2", "B")])

    def test_matching_uses_fresh_reports_despite_legacy_cache(self):
        title = "Review storage layout changed"
        self.files = {
            OLD_INDEX: json.dumps([
                {"filename": "cached.md", "titles": ["Unrelated cached finding"]},
            ]),
            NEW_REPORT: "Title: " + title + "\n",
        }
        matches = dedup.check_finding(title)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][:3], (Path(NEW_REPORT).name, title, 1.0))

    def test_result_prefixes_are_not_scanned_as_discoveries(self):
        for paths in self.discovered.values():
            for prefix in ("report-", "result-"):
                result = str(Path(paths[0]).with_name(prefix + Path(paths[0]).name))
                paths.append(result)
                self.files[result] = "Title: Derivative finding\n"
        self.files[NEW_REPORT] = "Title: Original finding\n"
        self.assertEqual(dedup.load_review_titles(), [
            (Path(NEW_REPORT).name, "Original finding"),
        ])

    def test_cached_result_basenames_and_full_paths_are_not_discoveries(self):
        for index in (NEW_INDEX, OLD_INDEX):
            with self.subTest(index=index):
                entries = [{"filename": Path(NEW_REPORT).name, "titles": ["Original"]}]
                for prefix in ("report-", "result-"):
                    basename = prefix + Path(NEW_REPORT).name
                    for name in (basename, "/var/tmp/deep-review-reports/" + basename,
                                 "/var/tmp/deep-review-finished/" + basename):
                        entries.append({"filename": name, "titles": ["Derivative"]})
                self.files = {index: json.dumps(entries)}
                self.assertEqual(dedup.load_review_titles(), [
                    (Path(NEW_REPORT).name, "Original"),
                ])

    def test_research_result_header_is_not_a_discovery(self):
        self.files = {
            NEW_REPORT: "Artifact kind: research-result\nTitle: Derivative\n",
            OLD_REPORT: "Title: Original\n",
        }
        self.assertEqual(dedup.load_review_titles(), [(Path(OLD_REPORT).name, "Original")])

    def test_cached_titles_cannot_override_a_research_result_header(self):
        for filename in (Path(NEW_REPORT).name, NEW_REPORT):
            with self.subTest(filename=filename):
                self.files = {
                    NEW_INDEX: json.dumps([{"filename": filename, "titles": ["Cached derivative"]}]),
                    NEW_REPORT: "Artifact kind: research-result\nTitle: Derivative\n",
                }
                self.assertEqual(dedup.load_review_titles(), [])

    def test_derivative_does_not_hide_same_named_original_in_another_root(self):
        legacy_original = "/tmp/" + Path(NEW_REPORT).name
        self.discovered["/tmp/*-review*.md"] = [legacy_original]
        self.files = {
            NEW_INDEX: json.dumps([
                {"filename": NEW_REPORT, "titles": ["Derivative"]},
                {"filename": Path(NEW_REPORT).name, "titles": ["Ambiguous cache row"]},
                {"filename": legacy_original, "titles": ["Original cached evidence"]},
            ]),
            NEW_REPORT: "Artifact kind: research-result\nTitle: Derivative\n",
            legacy_original: "Title: Original finding\n",
        }
        self.assertEqual(dedup.load_review_titles(), [
            (legacy_original, "Original cached evidence"),
            (Path(legacy_original).name, "Original finding"),
        ])

    def test_matching_does_not_attribute_a_derivative_as_discovery(self):
        title = "Review storage layout changed"
        result = str(Path(NEW_REPORT).with_name("report-" + Path(NEW_REPORT).name))
        self.discovered["/var/tmp/deep-review-reports/*-review*.md"].append(result)
        self.files = {
            NEW_INDEX: json.dumps([{"filename": result, "titles": [title]}]),
            result: "Title: " + title + "\n",
        }
        self.assertEqual(dedup.check_finding(title), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
