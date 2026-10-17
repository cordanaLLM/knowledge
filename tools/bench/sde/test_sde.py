#!/usr/bin/env python3
"""Unit tests for sde-bench grading harness."""

from pathlib import Path
import unittest
from unittest.mock import patch

from tools.bench.sde.sde import (
    PinMismatchError,
    SubprocessError,
    TrapResolutionError,
    check_pin,
    codebase_of,
    compute_solved,
    filter_patch,
    inline_states,
    parse_trap_reference,
    pytest_verdict,
    realfn_key,
    swap_anchor,
    trap_states,
    verify_pin_sha,
)


class TestTrapReferenceParse(unittest.TestCase):
    def test_positive(self) -> None:
        text = """
import sys, os, shutil, subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gen"))
from traps import TRAPS

_h = os.environ.get("SDEBENCH_BOLTONS_HOST")
if not _h:
    sys.exit("...")
HOST = Path(os.path.expanduser(_h))
REF = '979fa9b613fa8c0a455ae16ea6f2ec91c11ecafe'
TRAP = TRAPS['budget']
"""
        mod, dict_name, key = parse_trap_reference(text)
        self.assertEqual(mod, "traps")
        self.assertEqual(dict_name, "TRAPS")
        self.assertEqual(key, "budget")

    def test_negative(self) -> None:
        text = """
import sys, os
from pathlib import Path
# No traps reference imported or indexed
"""
        with self.assertRaises(TrapResolutionError):
            parse_trap_reference(text)

    def test_boundary_two_imports(self) -> None:
        text = """
import sys, os
from emit_host_h import H_MSG
from traps import TRAPS

TRAP = TRAPS['dedupe']
SUBJ, BODY = H_MSG['dedupe']
"""
        mod, dict_name, key = parse_trap_reference(text)
        self.assertEqual(mod, "traps")
        self.assertEqual(dict_name, "TRAPS")
        self.assertEqual(key, "dedupe")

    def test_boundary_realfn_traps(self) -> None:
        text = """
import sys, os
from realfn_traps import REALFN_TRAPS
from emit_realfn_h import H_MSG

T = REALFN_TRAPS['pluralize']
SUBJ, BODY = H_MSG['pluralize']
"""
        mod, dict_name, key = parse_trap_reference(text)
        self.assertEqual(mod, "realfn_traps")
        self.assertEqual(dict_name, "REALFN_TRAPS")
        self.assertEqual(key, "pluralize")


class TestPatchFilter(unittest.TestCase):
    def test_drops_tests_changes(self) -> None:
        patch_text = """diff --git a/boltons/cacheutils.py b/boltons/cacheutils.py
--- a/boltons/cacheutils.py
+++ b/boltons/cacheutils.py
@@ -1,3 +1,3 @@
-old_code
+new_code
diff --git a/tests/test_cacheutils.py b/tests/test_cacheutils.py
--- a/tests/test_cacheutils.py
+++ b/tests/test_cacheutils.py
@@ -1,3 +1,3 @@
-old_test
+new_test
"""
        filtered = filter_patch(patch_text)
        self.assertIn("boltons/cacheutils.py", filtered)
        self.assertIn("new_code", filtered)
        self.assertNotIn("tests/test_cacheutils.py", filtered)
        self.assertNotIn("new_test", filtered)

    def test_only_tests_changes(self) -> None:
        patch_text = """diff --git a/tests/test_foo.py b/tests/test_foo.py
--- a/tests/test_foo.py
+++ b/tests/test_foo.py
@@ -1,1 +1,1 @@
-assert False
+assert True
"""
        filtered = filter_patch(patch_text)
        self.assertEqual(filtered, "")

    def test_no_tests_changes(self) -> None:
        patch_text = """diff --git a/boltons/strutils.py b/boltons/strutils.py
--- a/boltons/strutils.py
+++ b/boltons/strutils.py
@@ -1,1 +1,1 @@
-a
+b
"""
        filtered = filter_patch(patch_text)
        self.assertEqual(filtered, patch_text)


class TestVerdictSolvedLogic(unittest.TestCase):
    def test_all_true_solved(self) -> None:
        self.assertTrue(compute_solved(existing=True, repro=True, hidden=True))

    def test_any_false_not_solved(self) -> None:
        cases = [
            (False, True, True),
            (True, False, True),
            (True, True, False),
            (False, False, True),
            (False, True, False),
            (True, False, False),
            (False, False, False),
        ]
        for existing, repro, hidden in cases:
            with self.subTest(existing=existing, repro=repro, hidden=hidden):
                self.assertFalse(compute_solved(existing, repro, hidden))


class TestPinCheck(unittest.TestCase):
    def test_matching_sha(self) -> None:
        sha = "979fa9b613fa8c0a455ae16ea6f2ec91c11ecafe"
        verify_pin_sha(sha, sha)

    def test_mismatching_sha(self) -> None:
        expected = "979fa9b613fa8c0a455ae16ea6f2ec91c11ecafe"
        actual = "afcce15c1f608242e28e48832c301f39c5aed708"
        with self.assertRaises(PinMismatchError) as ctx:
            verify_pin_sha(expected, actual)
        self.assertEqual(ctx.exception.expected, expected)
        self.assertEqual(ctx.exception.actual, actual)

    @patch("tools.bench.sde.sde.get_head_sha")
    def test_check_pin_success(self, mock_get_sha) -> None:
        mock_get_sha.return_value = "1234abcd"
        result = check_pin(Path("/fake/repo"), "1234abcd")
        self.assertEqual(result, "1234abcd")

    @patch("tools.bench.sde.sde.get_head_sha")
    def test_check_pin_failure(self, mock_get_sha) -> None:
        mock_get_sha.return_value = "mismatch"
        with self.assertRaises(PinMismatchError):
            check_pin(Path("/fake/repo"), "expected")


class TestPytestVerdict(unittest.TestCase):
    CMD = ["podman", "run", "sde-grader", "python", "-m", "pytest"]

    def test_pass_and_fail_are_verdicts(self) -> None:
        self.assertTrue(pytest_verdict(0, self.CMD, Path("/w"), ""))
        self.assertFalse(pytest_verdict(1, self.CMD, Path("/w"), "1 failed"))

    def test_no_tests_collected_raises(self) -> None:
        with self.assertRaises(SubprocessError) as ctx:
            pytest_verdict(5, self.CMD, Path("/w"), "no tests ran")
        self.assertEqual(ctx.exception.rc, 5)

    def test_podman_cannot_run_image_raises(self) -> None:
        for rc in (2, 3, 4, 125, 126, 127):
            with self.assertRaises(SubprocessError, msg=f"rc {rc}"):
                pytest_verdict(rc, self.CMD, Path("/w"), "Error: image not known")


class TestTrapStates(unittest.TestCase):
    def test_planted_states(self) -> None:
        states = trap_states({"bug": "b", "correct": "c", "naive": ["n0", "n1"]})
        self.assertEqual([name for name, _kw, _want in states], ["bug", "correct", "naive0", "naive1"])
        self.assertEqual(states[0][1], {"module_text": "b"})
        self.assertEqual(states[1][2], (True, True, True, True))

    def test_realfn_states_single_naive_string(self) -> None:
        states = trap_states({"anchor": "a", "correct": "c", "naive": "n"})
        self.assertEqual([name for name, _kw, _want in states], ["head", "correct", "naive0"])
        self.assertEqual(states[0][1], {}, "head grades the unchanged real module")
        self.assertEqual(states[2][1], {"anchor_swap": ("a", "n")})

    def test_neither_shape_raises(self) -> None:
        with self.assertRaises(TrapResolutionError):
            trap_states({"correct": "c"})

    def test_inline_states(self) -> None:
        text = 'import os\nREAL = """    return a"""\nSHABBY = """    return b"""\nDOCUMENTED = "x"\n'
        self.assertEqual(inline_states(text), {"anchor": "    return b", "correct": "    return a", "naive": []})
        self.assertIsNone(inline_states("REAL = 'a'\n"), "both texts are needed")
        self.assertIsNone(inline_states("REAL = f()\nSHABBY = 'b'\n"), "only string constants, nothing is run")

    def test_codebase_of(self) -> None:
        self.assertEqual(codebase_of(Path("/c/sde-bench/boltons-budget/tasks/main/task.json")), "boltons-budget")

    def test_realfn_key(self) -> None:
        self.assertEqual(realfn_key("boltons-findhashtags"), "findhashtags")
        self.assertEqual(realfn_key("boltons-findhashtags-history"), "findhashtags")
        self.assertEqual(realfn_key("boltons-history-x"), "history-x", "only a trailing suffix is a source")

    def test_swap_anchor(self) -> None:
        self.assertEqual(swap_anchor("a\nX\nX\n", "X", "Y"), "a\nY\nX\n", "replaced once")
        with self.assertRaises(TrapResolutionError):
            swap_anchor("no anchor here", "X", "Y")


if __name__ == "__main__":
    unittest.main()
