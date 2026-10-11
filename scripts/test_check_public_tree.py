"""Planted cases for check_public_tree.py: each rule is seen refusing.

The planted values are put together from parts, so that this file passes the
check it tests. Run with `python3 -m unittest discover -s scripts`.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_public_tree as checker

ROOT = pathlib.Path(__file__).resolve().parent.parent
GIT_TIMEOUT_SECONDS = 60
PRIVATE = ".".join(["10", "20", "30", "40"])
SHARED = ".".join(["100", "64", "0", "1"])
LINK_LOCAL = ".".join(["169", "254", "1", "1"])
RETIRED = "retired" + ".example"
DIGESTS = frozenset({hashlib.sha256(RETIRED.encode()).hexdigest()})
WORD = "quux" + "name"
WORDS = frozenset({(len(WORD), hashlib.sha256(WORD.encode()).hexdigest())})


def home(prefix: str) -> str:
    return prefix + "someone"


def tree(files: dict[str, str]) -> pathlib.Path:
    """A git repository in a temporary directory with the given tracked files."""
    root = pathlib.Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for command in (["init", "-q"], ["add", "-A"]):
        subprocess.run(
            ["git", "-C", str(root), *command], check=True, timeout=GIT_TIMEOUT_SECONDS
        )
    return root


def run(files: dict[str, str]) -> list[str]:
    return checker.check(tree(files), DIGESTS, WORDS)


class CleanTree(unittest.TestCase):
    def test_this_repository_is_clean(self):
        self.assertEqual(checker.check(ROOT), [])

    def test_free_values_pass(self):
        text = "\n".join(
            [
                "127.0.0.1 0.0.0.0 192.0.2.7 198.51.100.7 203.0.113.7 8.8.8.8",
                "version 1.2.3.4567 and 999.1.1.1 are no addresses",
                "https://gateway.example.com/v1 and /home/ alone and ~/notes",
                "not" + RETIRED + " ends like the domain without being under it",
            ]
        )
        self.assertEqual(run({"a.txt": text}), [])

    def test_listed_address_passes(self):
        files = {"a.txt": PRIVATE, checker.ADDRESS_LIST: f"# why\n\n{PRIVATE} a.txt\n"}
        self.assertEqual(run(files), [])


class HomePath(unittest.TestCase):
    def test_each_form_is_refused(self):
        for prefix in ("/home/", "/Users/", "C:" + "\\Users\\"):
            with self.subTest(prefix=prefix):
                found = run({"a.txt": "first line\ncache = " + home(prefix) + "/cache\n"})
                self.assertEqual(found, ["a.txt:2: home path " + home(prefix)])

    def test_path_of_a_file_is_read_too(self):
        found = run({"home/someone/a.txt".replace("home/", "x/home/"): "nothing"})
        self.assertEqual(len(found), 1)
        self.assertIn("(its path): home path", found[0])


class PrivateAddress(unittest.TestCase):
    def test_each_range_is_refused(self):
        for address in (PRIVATE, SHARED, LINK_LOCAL, ".".join(["172", "16", "0", "9"])):
            with self.subTest(address=address):
                found = run({"a.txt": f"server={address}:8080"})
                self.assertEqual(
                    found,
                    [f"a.txt: private address {address} is not in {checker.ADDRESS_LIST}"],
                )

    def test_entry_for_another_file_does_not_cover(self):
        files = {"a.txt": PRIVATE, "b.txt": PRIVATE, checker.ADDRESS_LIST: f"{PRIVATE} a.txt\n"}
        self.assertEqual(
            run(files), [f"b.txt: private address {PRIVATE} is not in {checker.ADDRESS_LIST}"]
        )

    def test_entry_that_matches_nothing_is_refused(self):
        files = {"a.txt": "nothing", checker.ADDRESS_LIST: f"{PRIVATE} a.txt\n"}
        self.assertEqual(
            run(files), [f"{checker.ADDRESS_LIST}: entry {PRIVATE} a.txt matches nothing"]
        )

    def test_line_that_is_no_entry_is_refused(self):
        for line in ("a.txt", "8.8.8.8 a.txt", f"{PRIVATE}", f"{PRIVATE}\ta.txt"):
            with self.subTest(line=line):
                found = run({"a.txt": "nothing", checker.ADDRESS_LIST: line + "\n"})
                self.assertEqual(len(found), 1)
                self.assertIn("not an entry of the form", found[0])


class RetiredDomain(unittest.TestCase):
    def test_domain_and_every_host_under_it_is_refused(self):
        for host in (RETIRED, "git." + RETIRED, "a.b." + RETIRED, RETIRED.upper()):
            with self.subTest(host=host):
                found = run({"a.txt": f"url: https://{host}/path"})
                self.assertEqual(found, ["a.txt:1: host name under a retired domain"])

    def test_address_at_the_domain_is_refused(self):
        found = run({"a.txt": "someone@" + RETIRED})
        self.assertEqual(found, ["a.txt:1: host name under a retired domain"])

    def test_path_of_a_file_is_read_too(self):
        found = run({f"hosts/{RETIRED}/a.txt": "nothing"})
        self.assertEqual(len(found), 1)
        self.assertIn("(its path): host name under a retired domain", found[0])

    def test_finding_does_not_print_the_domain(self):
        found = run({"a.txt": "git." + RETIRED})
        self.assertNotIn(RETIRED, "".join(found))

    def test_the_digest_of_this_repository_is_one_sha256(self):
        self.assertEqual(len(checker.RETIRED_DOMAIN_DIGESTS), 1)
        for digest in checker.RETIRED_DOMAIN_DIGESTS:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class RetiredWord(unittest.TestCase):
    def test_word_is_refused_in_each_form(self):
        forms = (
            WORD,
            WORD.upper() + "_HOME",
            WORD + "Knowledge",
            "/etc/" + WORD + "/trust",
            "x" + WORD + "x",
        )
        for form in forms:
            with self.subTest(form=form):
                found = run({"a.txt": f"first line\nvalue: {form}\n"})
                self.assertEqual(found, ["a.txt:2: retired product word"])

    def test_path_of_a_file_is_read_too(self):
        found = run({f"cmd/{WORD}-server/a.txt": "nothing"})
        self.assertEqual(len(found), 1)
        self.assertIn("(its path): retired product word", found[0])

    def test_finding_does_not_print_the_word(self):
        found = run({"a.txt": WORD.upper()})
        self.assertNotIn(WORD, "".join(found).lower())

    def test_parts_of_the_word_pass(self):
        found = run(
            {"a.txt": f"{WORD[:-1]} {WORD[1:]} {WORD[:4]}-{WORD[4:]} {WORD[:4]}1{WORD[4:]}"}
        )
        self.assertEqual(found, [])

    def test_the_word_of_this_repository_is_refused(self):
        word = "".join(["ca", "u", "da"])
        found = checker.check(tree({"a.txt": f"{word.upper()}_HOME={word}Knowledge"}))
        self.assertEqual(found, ["a.txt:1: retired product word"])

    def test_the_digest_of_this_repository_is_one_sha256(self):
        self.assertEqual(len(checker.RETIRED_WORDS), 1)
        for length, digest in checker.RETIRED_WORDS:
            self.assertGreater(length, 3)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class ExitCode(unittest.TestCase):
    def main(self, root: pathlib.Path) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return checker.main(["--root", str(root)])

    def test_clean_is_zero(self):
        self.assertEqual(self.main(tree({"a.txt": "nothing"})), 0)

    def test_finding_is_one(self):
        self.assertEqual(self.main(tree({"a.txt": home("/home/")})), 1)

    def test_directory_outside_a_repository_is_two(self):
        self.assertEqual(self.main(pathlib.Path(tempfile.mkdtemp())), 2)


if __name__ == "__main__":
    unittest.main()
