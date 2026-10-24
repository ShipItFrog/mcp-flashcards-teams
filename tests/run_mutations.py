"""Prove the test suite catches real mistakes: run it once per deliberately broken
variant (tests/mutations.py) and require at least one test to FAIL each time.

A run that errors during setup (e.g. a mutation that no longer applies) does not
count as caught: it is reported as invalid.

With a local Postgres available (see tests/conftest.py), every run must also run the
Postgres tests: FLASHCARDS_REQUIRE_PG=1 turns a skip into a failure. Without one, the
pg- variants can't be checked; they are reported as not run, and the run fails.

Usage:  python tests/run_mutations.py
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "tests"), str(ROOT)]
from mutations import MUTATIONS  # noqa: E402


POSTGRES = bool(os.environ.get("FLASHCARDS_TEST_PG_BIN") or importlib.util.find_spec("postgresql_binaries"))
# A healthy run takes well under a minute; this only stops a variant that hangs the suite.
RUN_TIMEOUT_SECONDS = 600


def run(mutation: str | None) -> tuple[int, str, list[str]]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    env.pop("FLASHCARDS_MUTATION", None)
    if POSTGRES:
        env["FLASHCARDS_REQUIRE_PG"] = "1"
    if mutation:
        env["FLASHCARDS_MUTATION"] = mutation
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rf"],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=RUN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        # A variant that hangs the suite is not "caught": a hang isn't a failing test.
        return -1, f"timeout after {RUN_TIMEOUT_SECONDS} s", []
    summary = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "(no output)"
    failed = sorted(set(re.findall(r"^FAILED (\S+?)(?:\[| - |$)", r.stdout, re.MULTILINE)))
    return r.returncode, summary, failed


def main() -> int:
    code, summary, _ = run(None)
    print(f"baseline (real code): {summary}")
    if code != 0:
        print("baseline must pass first")
        return 1
    problems, not_run = [], []
    for name in MUTATIONS:
        if name.startswith("pg-") and not POSTGRES:
            print(f"\n{name}: NOT RUN (no local Postgres)")
            not_run.append(name)
            continue
        code, summary, failed = run(name)
        if code == -1:
            status = "INVALID (hung)"
        elif "error" in summary:
            status = "INVALID (errors, not failures)"
        elif code == 1 and failed:
            status = "CAUGHT"
        else:
            status = "NOT CAUGHT"
        print(f"\n{name}: {status} - {summary}")
        for test in failed:
            print(f"    {test}")
        if status != "CAUGHT":
            problems.append(name)
    if problems:
        print(f"\nnot caught or invalid: {problems}")
    if not_run:
        print(f"\nnot run, so not proven: {not_run} (pip install -r requirements-dev.txt)")
    if not problems and not not_run:
        print("\nall mutations caught")
    return 1 if problems or not_run else 0


if __name__ == "__main__":
    sys.exit(main())
