#!/usr/bin/env python3
"""Grader for sde-bench, Vectorize's benchmark of whether a coding agent benefits from a memory system.

The dataset (61 bug-fix tasks on the boltons library) is fetched at a pinned commit and never copied here. A change
is graded in a pristine build of the task inside a pinned container without network: existing tests, the visible
repro and the held-out hidden test. Only pytest exits 0 and 1 are a verdict; anything else is an error."""

import argparse
import ast
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

DATASET_REPO = "https://github.com/vectorize-io/sde-bench"
DATASET_PIN = "afcce15c1f608242e28e48832c301f39c5aed708"
BOLTONS_REPO = "https://github.com/vectorize-io/boltons"
BOLTONS_PIN = "979fa9b613fa8c0a455ae16ea6f2ec91c11ecafe"

IMAGE_TAG = "sde-grader:py313-pytest911"
PYTEST_VERDICT = {0: True, 1: False}  # pytest exit codes that are a test result; any other exit is an error
MAX_ITEMS = 1000
MAX_LINES = 100000


class PinMismatchError(RuntimeError):
    def __init__(self, message: str, expected: str, actual: str):
        super().__init__(message)
        self.expected = expected
        self.actual = actual


class TrapResolutionError(RuntimeError):
    pass


class SubprocessError(RuntimeError):
    def __init__(self, cmd: list[str], path: str | Path, rc: int, stderr: str = ""):
        super().__init__(f"Command {cmd} in {path} failed with rc {rc}: {stderr.strip()}")
        self.cmd = cmd
        self.path = path
        self.rc = rc
        self.stderr = stderr


def get_cache_dir() -> Path:
    env_cache = os.environ.get("SDE_CACHE")
    if env_cache:
        return Path(os.path.expanduser(env_cache))
    return Path.home() / ".cache" / "sde-bench"


def get_paths() -> tuple[Path, Path]:
    cache_dir = get_cache_dir()
    return cache_dir / "sde-bench", cache_dir / "boltons"


def get_head_sha(repo_dir: Path) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if res.returncode != 0:
        raise SubprocessError(["git", "rev-parse", "HEAD"], repo_dir, res.returncode, res.stderr)
    return res.stdout.strip()


def verify_pin_sha(expected: str, actual: str) -> None:
    if expected != actual:
        raise PinMismatchError(f"Pin mismatch: expected {expected}, got {actual}", expected=expected, actual=actual)


def check_pin(repo_dir: Path, expected_sha: str) -> str:
    actual = get_head_sha(repo_dir)
    verify_pin_sha(expected_sha, actual)
    return actual


def is_test_path(path: str) -> bool:
    clean = path.strip()
    if clean.startswith("a/") or clean.startswith("b/"):
        clean = clean[2:]
    return clean.startswith("tests/") or "/tests/" in clean


def filter_patch(patch_text: str) -> str:
    """Drops unified diff sections targeting tests/* paths."""
    lines = patch_text.splitlines(keepends=True)
    sections: list[list[str]] = []
    current: list[str] = []

    for line in lines[:MAX_LINES]:
        if line.startswith("diff --git ") or (line.startswith("--- ") and not current):
            if current:
                sections.append(current)
                current = []
        current.append(line)
    if current:
        sections.append(current)

    kept: list[str] = []
    for sec in sections[:MAX_LINES]:
        is_test = False
        for line in sec[:50]:
            if line.startswith("diff --git "):
                parts = line.split()
                if len(parts) >= 4 and (is_test_path(parts[2]) or is_test_path(parts[3])):
                    is_test = True
                    break
            elif line.startswith("--- ") or line.startswith("+++ "):
                target = line[4:].split("\t")[0].strip()
                if is_test_path(target):
                    is_test = True
                    break
        if not is_test:
            kept.extend(sec)
    return "".join(kept)


def parse_trap_reference(text: str) -> tuple[str, str, str]:
    """Parse module, trap dictionary name, and key from build.py text."""
    imports = re.findall(r"from (\w+) import (\w+)", text)
    indices = re.findall(r"(\w+)\[['\"](\w+)['\"]\]", text)
    trap_imports = [(mod, sym) for mod, sym in imports if "TRAPS" in sym]
    if not trap_imports:
        raise TrapResolutionError("no TRAPS import found in build.py")

    for mod, sym in trap_imports:
        for dict_name, key in indices:
            if dict_name == sym:
                return (mod, dict_name, key)
    raise TrapResolutionError(f"no index on trap symbol {trap_imports[0][1]} found in build.py")


def compute_solved(existing: bool, repro: bool, hidden: bool) -> bool:
    return bool(existing and repro and hidden)


def _sync_repo(repo_url: str, dest: Path, pin: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").is_dir():
        res = subprocess.run(["git", "clone", repo_url, str(dest)], capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            raise SubprocessError(["git", "clone", repo_url, str(dest)], dest.parent, res.returncode, res.stderr)
    res_co = subprocess.run(["git", "-C", str(dest), "checkout", "-q", pin], capture_output=True, text=True, timeout=120)
    if res_co.returncode != 0:
        raise SubprocessError(["git", "checkout", pin], dest, res_co.returncode, res_co.stderr)


def cmd_fetch(args: argparse.Namespace) -> int:
    sde_bench_dir, boltons_dir = get_paths()
    _sync_repo(DATASET_REPO, sde_bench_dir, DATASET_PIN)
    _sync_repo(BOLTONS_REPO, boltons_dir, BOLTONS_PIN)
    try:
        check_pin(sde_bench_dir, DATASET_PIN)
        check_pin(boltons_dir, BOLTONS_PIN)
    except PinMismatchError as err:
        sys.stderr.write(f"Pin mismatch: expected {err.expected}, actual {err.actual}\n")
        sys.exit(2)
    return 0


def codebase_of(task_json: Path) -> str:
    """Codebase folder of <dataset>/<codebase>/tasks/main/task.json."""
    return task_json.parents[2].name


def cmd_tasks(args: argparse.Namespace) -> int:
    sde_bench_dir, _ = get_paths()
    task_files = sorted(sde_bench_dir.glob("*/tasks/main/task.json"))[:MAX_ITEMS]
    for p in task_files:
        data = json.loads(p.read_text(encoding="utf-8"))
        task_id = data.get("task_id", codebase_of(p))
        codebase = data.get("codebase", codebase_of(p))
        source = data.get("source", "")
        tier = data.get("tier", "")
        category = data.get("category", "")
        print(f"{task_id} {codebase} {source} {tier} {category}")
    return 0


def cmd_image(args: argparse.Namespace) -> int:
    containerfile = Path(__file__).resolve().parent / "Containerfile"
    context_dir = containerfile.parent
    cmd = ["podman", "build", "-t", IMAGE_TAG, "-f", str(containerfile), str(context_dir)]
    res = subprocess.run(cmd, timeout=900)
    if res.returncode != 0:
        raise SubprocessError(cmd, context_dir, res.returncode, "podman build failed")
    return 0


def _build_codebase(codebase_dir: Path, task_data: dict[str, Any], boltons: Path, temp_dir: Path) -> None:
    build_py = codebase_dir / task_data.get("build", "build.py")
    env = {**os.environ, "SDEBENCH_BOLTONS_HOST": str(boltons)}
    cmd = [sys.executable, str(build_py), str(temp_dir)]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        raise SubprocessError(cmd, codebase_dir, res.returncode, res.stderr)


def swap_anchor(text: str, anchor: str, replacement: str) -> str:
    """The real module with its anchor line replaced once, as upstream's emit_realfn.validate does; an anchor the
    module does not hold raises, since the state would then grade the unchanged module."""
    if anchor not in text:
        raise TrapResolutionError(f"anchor not found in the built module: {anchor[:80]!r}")
    return text.replace(anchor, replacement, 1)


def _apply_change(
    temp_dir: Path,
    task_data: dict[str, Any],
    patch_content: str | None,
    module_text: str | None,
    anchor_swap: tuple[str, str] | None = None,
) -> None:
    if anchor_swap is not None:
        target = temp_dir / task_data["module"]
        target.write_text(swap_anchor(target.read_text(encoding="utf-8"), *anchor_swap), encoding="utf-8")
    elif patch_content is not None:
        filtered = filter_patch(patch_content)
        if filtered.strip():
            cmd = ["git", "-C", str(temp_dir), "apply", "--exclude=tests/*"]
            res = subprocess.run(cmd, input=filtered, text=True, capture_output=True, timeout=120)
            if res.returncode != 0:
                raise SubprocessError(cmd, temp_dir, res.returncode, res.stderr)
    elif module_text is not None:
        target = temp_dir / task_data["module"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(module_text, encoding="utf-8")


def _copy_tests(codebase_dir: Path, task_data: dict[str, Any], temp_dir: Path) -> None:
    tasks_dir = codebase_dir / "tasks" / "main"
    reg_src = tasks_dir / task_data.get("regression_test_file", "regression_test.py")
    hid_src = tasks_dir / task_data.get("hidden_test_file", "hidden_test.py")
    for dst_rel in task_data.get("fail_to_pass", [])[:MAX_ITEMS]:
        dst = temp_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(reg_src, dst)
    for dst_rel in task_data.get("hidden_to_pass", [])[:MAX_ITEMS]:
        dst = temp_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(hid_src, dst)


def _run_pytest_in_container(temp_dir: Path, test_paths: list[str]) -> bool:
    if not test_paths:
        return True
    cmd = [
        "podman",
        "run",
        "--rm",
        "--network=none",
        "-v",
        f"{temp_dir}:/w:Z",
        "-w",
        "/w",
        IMAGE_TAG,
        "python",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        *test_paths,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return pytest_verdict(res.returncode, cmd, temp_dir, res.stdout + res.stderr)


def pytest_verdict(rc: int, cmd: list[str], path: Path, output: str) -> bool:
    """True for pytest exit 0, False for exit 1 (tests ran and failed). Every other exit (2 interrupted, 3 internal
    error, 4 usage error, 5 no tests collected, 125-127 podman could not run the image) raises: a run that did not
    test is never graded as a failing test."""
    if rc in PYTEST_VERDICT:
        return PYTEST_VERDICT[rc]
    raise SubprocessError(cmd, path, rc, output[-2000:])


def grade_codebase(
    codebase: str,
    patch_content: str | None = None,
    module_text: str | None = None,
    sde_bench_dir: Path | None = None,
    boltons_dir: Path | None = None,
    anchor_swap: tuple[str, str] | None = None,
) -> dict[str, Any]:
    default_sde, default_boltons = get_paths()
    sde_bench = sde_bench_dir or default_sde
    boltons = boltons_dir or default_boltons
    codebase_dir = sde_bench / codebase
    task_json = codebase_dir / "tasks" / "main" / "task.json"
    if not task_json.is_file():
        raise FileNotFoundError(f"task.json not found for codebase: {task_json}")
    task_data = json.loads(task_json.read_text(encoding="utf-8"))

    temp_dir = Path(tempfile.mkdtemp(prefix=f"sde_grade_{codebase}_"))
    try:
        _build_codebase(codebase_dir, task_data, boltons, temp_dir)
        _apply_change(temp_dir, task_data, patch_content, module_text, anchor_swap)
        _copy_tests(codebase_dir, task_data, temp_dir)
        existing = _run_pytest_in_container(temp_dir, task_data.get("pass_to_pass", []))
        repro = _run_pytest_in_container(temp_dir, task_data.get("fail_to_pass", []))
        hidden = _run_pytest_in_container(temp_dir, task_data.get("hidden_to_pass", []))
        solved = compute_solved(existing, repro, hidden)
        return {
            "task": task_data.get("task_id", codebase),
            "existing": existing,
            "repro": repro,
            "hidden": hidden,
            "solved": solved,
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def cmd_grade(args: argparse.Namespace) -> int:
    patch_content = None
    module_text = None
    if args.patch:
        patch_path = Path(args.patch)
        if not patch_path.is_file():
            raise FileNotFoundError(f"Patch file not found: {patch_path}")
        patch_content = patch_path.read_text(encoding="utf-8")
    elif args.module_text:
        mod_path = Path(args.module_text)
        if not mod_path.is_file():
            raise FileNotFoundError(f"Module text file not found: {mod_path}")
        module_text = mod_path.read_text(encoding="utf-8")

    result = grade_codebase(args.codebase, patch_content=patch_content, module_text=module_text)
    print(json.dumps(result))
    return 0


EXPECT_HEAD = (True, False, False, False)  # existing, repro, hidden, solved
EXPECT_CORRECT = (True, True, True, True)
EXPECT_NAIVE = (True, True, False, False)
REALFN_SUFFIXES = ("-history", "-amended")


def _import_gen(sde_bench_dir: Path, mod_name: str) -> Any:
    gen_dir = sde_bench_dir / "gen"
    if str(gen_dir) not in sys.path:
        sys.path.insert(0, str(gen_dir))
    return importlib.import_module(mod_name)


def realfn_key(codebase: str) -> str:
    """REALFN_TRAPS key of a real-function codebase: boltons-<key>, optionally with a source suffix."""
    name = codebase.removeprefix("boltons-")
    for suffix in REALFN_SUFFIXES:
        name = name.removesuffix(suffix)
    return name


INLINE_BUG, INLINE_CORRECT = "SHABBY", "REAL"  # a hand-written task's build.py names its shipped and its original text


def inline_states(build_text: str) -> dict[str, Any] | None:
    """An anchor trap from a build.py that defines its shipped bug and boltons' original text as plain string
    constants (boltons-omdset); None when it does not. Read with ast, never by running the build file."""
    found = {}
    for node in ast.parse(build_text).body[:MAX_ITEMS]:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in (INLINE_BUG, INLINE_CORRECT) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            found[node.targets[0].id] = node.value.value
    if set(found) != {INLINE_BUG, INLINE_CORRECT}:
        return None
    return {"anchor": found[INLINE_BUG], "correct": found[INLINE_CORRECT], "naive": []}


def resolve_trap(sde_bench_dir: Path, codebase: str, build_text: str) -> dict[str, Any]:
    """The trap a task's build.py uses; a build that defines its own states inline is read as an anchor trap, and a
    build without a TRAPS import is a real-function task, keyed by its name."""
    inline = inline_states(build_text)
    if inline is not None:
        return inline
    try:
        mod_name, dict_name, key = parse_trap_reference(build_text)
    except TrapResolutionError:
        mod_name, dict_name, key = "realfn_traps", "REALFN_TRAPS", realfn_key(codebase)
    traps = getattr(_import_gen(sde_bench_dir, mod_name), dict_name)
    if key not in traps:
        raise TrapResolutionError(f"{mod_name}.{dict_name} has no key {key!r} for {codebase}")
    return traps[key]


def _naives(trap: dict[str, Any]) -> list[str]:
    naive = trap.get("naive", [])
    return ([naive] if isinstance(naive, str) else list(naive))[:MAX_ITEMS]


def trap_states(trap: dict[str, Any]) -> list[tuple[str, dict[str, Any], tuple[bool, bool, bool, bool]]]:
    """(state, grade keyword arguments, expected verdict) per reference state. Planted traps carry whole module
    texts (bug, correct, naive list); real-function traps replace their anchor line in the real module (head = no
    change, correct, one naive string), as upstream's gen/emit_realfn.py validates them."""
    if "anchor" in trap:
        swap = trap["anchor"]
        states = [("head", {}, EXPECT_HEAD), ("correct", {"anchor_swap": (swap, trap["correct"])}, EXPECT_CORRECT)]
        return states + [(f"naive{i}", {"anchor_swap": (swap, n)}, EXPECT_NAIVE) for i, n in enumerate(_naives(trap))]
    if "bug" in trap:
        states = [("bug", {"module_text": trap["bug"]}, EXPECT_HEAD), ("correct", {"module_text": trap["correct"]}, EXPECT_CORRECT)]
        return states + [(f"naive{i}", {"module_text": n}, EXPECT_NAIVE) for i, n in enumerate(_naives(trap))]
    raise TrapResolutionError(f"trap holds neither bug nor anchor: keys {sorted(trap)}")


def _selfcheck_state(codebase: str, state: str, kwargs: dict[str, Any], expected: tuple[bool, bool, bool, bool],
                     sde: Path, boltons: Path) -> bool:
    res = grade_codebase(codebase, sde_bench_dir=sde, boltons_dir=boltons, **kwargs)
    ok = (res["existing"], res["repro"], res["hidden"], res["solved"]) == expected
    print(f"{codebase} {state} {'ok' if ok else 'MISMATCH'} {json.dumps(res)}", flush=True)
    return ok


def selfcheck_codebase(codebase: str, sde_bench_dir: Path, boltons_dir: Path) -> bool:
    build_py = sde_bench_dir / codebase / "build.py"
    if not build_py.is_file():
        print(f"{codebase} build.py missing: {build_py}")
        return False
    try:
        states = trap_states(resolve_trap(sde_bench_dir, codebase, build_py.read_text(encoding="utf-8")))
    except TrapResolutionError as err:
        print(f"{codebase} trap unresolved: {err}")
        return False
    results = [_selfcheck_state(codebase, name, kw, want, sde_bench_dir, boltons_dir) for name, kw, want in states]
    return all(results)


def cmd_selfcheck(args: argparse.Namespace) -> int:
    sde_bench_dir, boltons_dir = get_paths()
    if args.tasks:
        codebases = [t.strip() for t in args.tasks.split(",") if t.strip()][:MAX_ITEMS]
    else:
        codebases = sorted(codebase_of(p) for p in sde_bench_dir.glob("*/tasks/main/task.json"))[:MAX_ITEMS]

    all_ok = True
    for codebase in codebases:
        if not selfcheck_codebase(codebase, sde_bench_dir, boltons_dir):
            all_ok = False
    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SDE benchmark runner and grader")
    sub = parser.add_subparsers(dest="subcommand", required=True)
    sub.add_parser("fetch", help="Clone and checkout pinned repositories")
    sub.add_parser("tasks", help="List all benchmark tasks")
    sub.add_parser("image", help="Build grader container image")
    grade_p = sub.add_parser("grade", help="Grade a codebase change")
    grade_p.add_argument("codebase", help="Target codebase identifier")
    grp = grade_p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--patch", help="Path to patch file")
    grp.add_argument("--module-text", help="Path to full module text file")
    sc_p = sub.add_parser("selfcheck", help="Run selfcheck on codebases")
    sc_p.add_argument("--tasks", help="Comma-separated codebases (default: all)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.subcommand == "fetch":
        return cmd_fetch(args)
    if args.subcommand == "tasks":
        return cmd_tasks(args)
    if args.subcommand == "image":
        return cmd_image(args)
    if args.subcommand == "grade":
        return cmd_grade(args)
    if args.subcommand == "selfcheck":
        return cmd_selfcheck(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
