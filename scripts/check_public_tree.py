#!/usr/bin/env python3
"""Refuses private names in the tracked tree.

Every file git tracks is read, and four things fail the run:

- a home path: `/home/<name>`, `/Users/<name>` or `<drive>:\\Users\\<name>`;
- a private address: an IPv4 literal in a private, shared or link-local range
  that `scripts/public-tree-addresses.txt` does not list for that file. An
  entry of the list that matches nothing fails too, so the list cannot hold
  more than the tree needs;
- a host name under a domain this repository used before it became public.
  The domain is held as its SHA-256 digest, so that this file does not name it;
- the product word this tool carried before it was renamed, in any letter case
  and inside a longer identifier. It is held as its length and digest.

Loopback addresses and the documentation ranges (RFC 5737) are free to use.

usage: check_public_tree.py [--root <directory>]
exit code: 0 clean, 1 findings, 2 the tree could not be read
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import pathlib
import re
import subprocess
import sys

GIT_TIMEOUT_SECONDS = 60
ADDRESS_LIST = "scripts/public-tree-addresses.txt"
RETIRED_DOMAIN_DIGESTS = frozenset({"f8a9513c4576b4db3cdf74b692db1b25843d846fc31238b1d7338b56a8c10b20"})

RETIRED_WORDS = frozenset({(5, "4f503d51973917232863b3caf679237ea31a85fc4128e7e6ca4827fdfa1ed5f4")})

HOME_PATH = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\Users\\)[A-Za-z0-9._-]+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
LETTERS = re.compile(r"[A-Za-z]+")
LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
HOST = re.compile(rf"{LABEL}(?:\.{LABEL})+")
FREE_RANGES = tuple(
    ipaddress.ip_network(text) for text in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
SHARED_RANGE = ipaddress.ip_network("100.64.0.0/10")


def tracked_files(root: pathlib.Path) -> list[str]:
    done = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
        timeout=GIT_TIMEOUT_SECONDS,
    )
    if done.returncode != 0:
        raise OSError(done.stderr.decode(errors="replace").strip() or "git ls-files failed")
    return [name for name in done.stdout.decode().split("\0") if name]


def is_private_address(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if address.is_loopback or address.is_unspecified:
        return False
    if any(address in network for network in FREE_RANGES):
        return False
    return address.is_private or address.is_link_local or address in SHARED_RANGE


def names_retired_domain(host: str, digests: frozenset[str], seen: dict[str, bool]) -> bool:
    """True when any run of two or more labels of the host is a retired domain."""
    host = host.lower()
    if host in seen:
        return seen[host]
    labels = host.split(".")
    found = False
    for start in range(len(labels) - 1):
        for end in range(start + 2, len(labels) + 1):
            window = ".".join(labels[start:end])
            if hashlib.sha256(window.encode()).hexdigest() in digests:
                found = True
    seen[host] = found
    return found


def scan_text(
    path: str, text: str, digests: frozenset[str], seen: dict[str, bool]
) -> tuple[list[str], set[tuple[str, str]]]:
    """Findings of the home and domain rules, and the private addresses of one file."""
    findings = []
    addresses = set()
    for number, line in enumerate(text.splitlines(), start=1):
        for match in HOME_PATH.finditer(line):
            findings.append(f"{path}:{number}: home path {match.group(0)}")
        for match in IPV4.finditer(line):
            if is_private_address(match.group(0)):
                addresses.add((path, match.group(0)))
        for match in HOST.finditer(line):
            if names_retired_domain(match.group(0), digests, seen):
                findings.append(f"{path}:{number}: host name under a retired domain")
    return findings, addresses


def names_retired_word(run: str, words: frozenset[tuple[int, str]], seen: dict[str, bool]) -> bool:
    """True when any stretch of the run of letters is a retired word."""
    run = run.lower()
    if run in seen:
        return seen[run]
    found = False
    for length, digest in words:
        for start in range(len(run) - length + 1):
            if hashlib.sha256(run[start : start + length].encode()).hexdigest() == digest:
                found = True
    seen[run] = found
    return found


def word_findings(
    path: str, text: str, words: frozenset[tuple[int, str]], seen: dict[str, bool]
) -> list[str]:
    """One finding for each line of the file that holds a retired word."""
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        if any(names_retired_word(run, words, seen) for run in LETTERS.findall(line)):
            findings.append(f"{path}:{number}: retired product word")
    return findings


def read_address_list(text: str) -> tuple[set[tuple[str, str]], list[str]]:
    """Entries `<address> <path>`; a line that is neither an entry nor a comment is an error."""
    entries = set()
    errors = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2 or not is_private_address(parts[0]) or not parts[1].strip():
            errors.append(f"{ADDRESS_LIST}:{number}: not an entry of the form <address> <path>")
            continue
        entries.add((parts[1].strip(), parts[0]))
    return entries, errors


def check(
    root: pathlib.Path,
    digests: frozenset[str] = RETIRED_DOMAIN_DIGESTS,
    words: frozenset[tuple[int, str]] = RETIRED_WORDS,
) -> list[str]:
    findings = []
    addresses = set()
    seen: dict[str, bool] = {}
    runs: dict[str, bool] = {}
    for name in tracked_files(root):
        path = root / name
        if path.is_symlink() or not path.is_file():
            continue
        text = path.read_bytes().decode(errors="replace")
        found, private = scan_text(name, text, digests, seen)
        findings += found + word_findings(name, text, words, runs)
        if name != ADDRESS_LIST:
            addresses |= private
        more, _ = scan_text(name, name, digests, seen)
        more += word_findings(name, name, words, runs)
        findings += [entry.replace(f"{name}:1:", f"{name} (its path):") for entry in more]
    listed = set()
    list_path = root / ADDRESS_LIST
    if list_path.is_file():
        listed, errors = read_address_list(list_path.read_text(encoding="utf-8"))
        findings += errors
    for path, address in sorted(addresses - listed):
        findings.append(f"{path}: private address {address} is not in {ADDRESS_LIST}")
    for path, address in sorted(listed - addresses):
        findings.append(f"{ADDRESS_LIST}: entry {address} {path} matches nothing")
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Refuses private names in the tracked tree.")
    parser.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    arguments = parser.parse_args(argv)
    try:
        findings = check(pathlib.Path(arguments.root))
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: the tree could not be read: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        print(f"{len(findings)} finding(s): the tree is not fit to be public", file=sys.stderr)
        return 1
    print("public tree check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
