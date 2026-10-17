# sde-bench grader

sde-bench is the upstream name of Vectorize's dataset (github.com/vectorize-io/sde-bench); upstream does not expand the abbreviation. This folder grades changes against its tasks: 61 bug-fix tasks on the boltons library whose correct fix depends on a project decision recorded in git history or in a past developer conversation.

## Purpose

The benchmark determines whether a coding agent benefits from persistent memory across software engineering tasks. This harness provides the evaluation and grading harness only; agent orchestration and trial execution are handled separately.

Each task defines three sets of test suites:
- `pass_to_pass` (`existing`): baseline regression tests that verify existing codebase behaviors are preserved.
- `fail_to_pass` (`repro`): reproduction tests that fail at the buggy state and pass once the issue is fixed.
- `hidden_to_pass` (`hidden`): tests that verify compliance with historical decisions, conventions, or constraints not inferable from the reproduction test alone.

A task is considered `solved` if and only if `existing`, `repro`, and `hidden` test suites all pass. Test file modifications in candidate patches are dropped during evaluation.

## Pins

- **Dataset**: [https://github.com/vectorize-io/sde-bench](https://github.com/vectorize-io/sde-bench) at commit `afcce15c1f608242e28e48832c301f39c5aed708` (MIT License, Copyright (c) 2026 Vectorize, Inc.).
- **Fixture repository**: [https://github.com/vectorize-io/boltons](https://github.com/vectorize-io/boltons) at commit `979fa9b613fa8c0a455ae16ea6f2ec91c11ecafe` (BSD-3-Clause License).
- **Execution environment**: `docker.io/library/python:3.13-slim@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024` with `pytest==9.1.1`.

No benchmark dataset files are vendored in this repository; they are fetched at run time and pinned to exact Git object hashes.

## Commands

### Fetch repositories

Clones and checks out both upstream repositories at their pinned commits inside `$SDE_CACHE` (defaults to `~/.cache/sde-bench`):

```bash
python3 tools/bench/sde/sde.py fetch
```

### Build grader container image

Builds the isolated podman test container from `Containerfile`:

```bash
python3 tools/bench/sde/sde.py image
```

### List tasks

Lists all available benchmark tasks:

```bash
python3 tools/bench/sde/sde.py tasks
```

### Grade candidate change

Grades a change against a codebase, accepting either a unified diff patch or replacement module source:

```bash
# With a patch file:
python3 tools/bench/sde/sde.py grade boltons-budget --patch candidate.diff

# With a module text file:
python3 tools/bench/sde/sde.py grade boltons-budget --module-text retry.py
```

Outputs a JSON object:
```json
{"task": "boltons-budget-001", "existing": true, "repro": true, "hidden": true, "solved": true}
```

### Self-check

Verifies grader discrimination against reference trap states (bug, correct fix, and naive candidates):

```bash
# Selected tasks:
python3 tools/bench/sde/sde.py selfcheck --tasks boltons-budget,boltons-dedupe-history

# All tasks:
python3 tools/bench/sde/sde.py selfcheck
```

## Credits and Licenses

- **sde-bench**: Vectorize, Inc., MIT License ("Copyright (c) 2026 Vectorize, Inc."), retrieved from `github.com/vectorize-io/sde-bench`.
- **boltons**: BSD-3-Clause License ("Copyright (c) 2013, Mahmoud Hashemi"), retrieved from `github.com/vectorize-io/boltons`, a fork kept by Vectorize as the fixture.

## Grading errors

Only pytest exit 0 (pass) and exit 1 (tests failed) are a verdict. Any other exit, such as no tests collected, a usage error or podman failing to start the image, stops the grade with the command, its exit code and the end of its output. The grader changes no host configuration; build the image once with `sde.py image`.
