import contextlib
import datetime
import io
import runpy
import socket
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "kev_check.py"
FIXTURE = ROOT / "tests" / "fixtures" / "kev.json"


class OfflineFileTests(unittest.TestCase):
    def test_file_mode_uses_saved_catalog_without_network(self):
        output = io.StringIO()
        class FixedDate(datetime.date):
            @classmethod
            def today(cls):
                return cls(2026, 12, 31)

            @classmethod
            def fromisoformat(cls, value):
                return cls(*map(int, value.split("-")))

        with patch.object(sys, "argv", [str(SCRIPT), "--file", str(FIXTURE), "--days", "30"]), \
                patch.object(urllib.request, "build_opener", side_effect=AssertionError("network used")), \
                patch.object(urllib.request, "urlopen", side_effect=AssertionError("network used")), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network used")), \
                patch.object(socket, "socket", side_effect=AssertionError("network used")), \
                patch.object(datetime, "date", FixedDate), \
                contextlib.redirect_stdout(output):
            runpy.run_path(str(SCRIPT), run_name="__main__")

        self.assertIn("KEV catalog fixture-1", output.getvalue())
        self.assertIn("CVE-FIXTURE-0001", output.getvalue())
        self.assertIn("No finding is not proof of no compromise", output.getvalue())

    def test_empty_file_argument_does_not_fall_back_to_network(self):
        opener = patch.object(urllib.request, "build_opener", side_effect=AssertionError("network used"))
        with patch.object(sys, "argv", [str(SCRIPT), "--file", ""]), \
                opener as build_opener, \
                patch.object(urllib.request, "urlopen", side_effect=AssertionError("network used")), \
                patch.object(socket, "create_connection", side_effect=AssertionError("network used")), \
                patch.object(socket, "socket", side_effect=AssertionError("network used")), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(SCRIPT), run_name="__main__")

        self.assertIsInstance(result.exception.code, str)
        self.assertIn("Could not read KEV catalog", result.exception.code)
        build_opener.assert_not_called()

    def test_excessively_nested_json_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested.json"
            path.write_text("[" * 2000 + "]" * 2000, encoding="utf-8")
            with patch.object(sys, "argv", [str(SCRIPT), "--file", str(path)]), \
                    patch.object(urllib.request, "build_opener", side_effect=AssertionError("network used")), \
                    patch.object(urllib.request, "urlopen", side_effect=AssertionError("network used")), \
                    patch.object(socket, "create_connection", side_effect=AssertionError("network used")), \
                    patch.object(socket, "socket", side_effect=AssertionError("network used")):
                with self.assertRaises(SystemExit) as result:
                    runpy.run_path(str(SCRIPT), run_name="__main__")

        self.assertIsInstance(result.exception.code, str)
        self.assertIn("Could not read KEV catalog", result.exception.code)


if __name__ == "__main__":
    unittest.main()
