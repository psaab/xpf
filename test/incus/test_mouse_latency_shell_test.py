import pathlib
import re
import unittest


SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency.sh").read_text()
MATRIX_SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency-matrix.sh").read_text()


class MouseLatencyShellTests(unittest.TestCase):
    def test_surplus_fixture_env_is_validated_and_passed_to_apply(self):
        self.assertIn('MOUSE_COS_SURPLUS_SHARING="${MOUSE_COS_SURPLUS_SHARING:-0}"', SCRIPT)
        self.assertIn('MOUSE_COS_SURPLUS_SHARING=1', SCRIPT)
        self.assertIn("MOUSE_COS_SURPLUS_SHARING='$MOUSE_COS_SURPLUS_SHARING' must be boolean", SCRIPT)

        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ "\$MOUSE_COS_SURPLUS_SHARING" -eq 1 \]\]; then\s+'
                r'APPLY_COS_FLAGS\+=\(--surplus-sharing\)\s+fi',
                re.MULTILINE,
            ),
        )

    def test_surplus_fixture_choice_is_written_to_manifest(self):
        self.assertIn(
            'MOUSE_CLASS="$MOUSE_CLASS" MOUSE_COS_SURPLUS_SHARING="$MOUSE_COS_SURPLUS_SHARING"',
            SCRIPT,
        )
        self.assertIn('"cos_surplus_sharing": os.environ["MOUSE_COS_SURPLUS_SHARING"] == "1"', SCRIPT)

    def test_matrix_documents_surplus_fixture_knob(self):
        self.assertIn("Set MOUSE_COS_SURPLUS_SHARING=1", MATRIX_SCRIPT)
        self.assertIn("per-rep manifest records the selected fixture bit", MATRIX_SCRIPT)


if __name__ == "__main__":
    unittest.main()
