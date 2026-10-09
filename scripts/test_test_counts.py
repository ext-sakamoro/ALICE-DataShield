#!/usr/bin/env python3
"""scripts/test_counts.py の試験: 0 本の target は合計が 0 でなくても失敗する"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_counts as tc  # noqa: E402

LOG = """\
     Running unittests src/lib.rs (target/debug/deps/alice_datashield-1)
running 96 tests
test result: ok. 96 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running tests/dp_bridge.rs (target/debug/deps/dp_bridge-2)
running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   Doc-tests alice_datashield
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
"""
EMPTY_TARGET = LOG.replace("running 3 tests\ntest result: ok. 3 passed", "running 0 tests\ntest result: ok. 0 passed")


class Counts(unittest.TestCase):
    def test_each_target_is_counted(self):
        self.assertEqual(tc.count(LOG), [("lib", 96), ("dp_bridge", 3), ("doc:alice_datashield", 1)])
        self.assertEqual(tc.check(LOG, {})[0], [])

    def test_a_target_with_zero_tests_fails_although_the_total_is_not_zero(self):
        errors, targets = tc.check(EMPTY_TARGET, {})
        self.assertEqual(sum(p for _, p in targets), 97)
        self.assertTrue(any("dp_bridge" in e for e in errors), errors)

    def test_an_allowlisted_empty_target_passes(self):
        self.assertEqual(tc.check(EMPTY_TARGET, {"dp_bridge": "compiled out on purpose"})[0], [])

    def test_an_allowlist_line_without_a_reason_is_an_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# header\ndp_bridge\nlib a real reason\n")
        allowed, errors = tc.load_allowlist(Path(f.name))
        Path(f.name).unlink()
        self.assertIn("dp_bridge", allowed)
        self.assertTrue(any("no reason" in e for e in errors), errors)

    def test_coloured_and_windows_output_is_read(self):
        e = "\x1b"
        coloured = (LOG.replace("     Running", f"{e}[1m{e}[92m     Running{e}[0m")
                    .replace("tests/dp_bridge.rs", "tests\\\\dp_bridge.rs")
                    .replace("test result: ok.", f"test result: {e}[32mok{e}(B{e}[m."))
        self.assertEqual(tc.count(coloured), tc.count(LOG))

    def test_no_target_at_all_fails(self):
        self.assertTrue(tc.check("compiling only\n", {})[0])


if __name__ == "__main__":
    unittest.main()
