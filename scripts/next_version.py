#!/usr/bin/env python3
"""Compute the next semantic version based on Conventional Commits since last tag.

Rules (same as previous bash script):
  - BREAKING CHANGE: footer (anywhere in body) OR type! syntax => major
  - feat: => minor (unless major already chosen)
  - fix:, perf:, refactor:, chore:, docs:, test: => patch (if nothing higher)
  - No matching commits => exit code 2 (signal skip)

Behavior:
  - If no prior tag (vMAJOR.MINOR.PATCH) exists, base version is v0.0.0
  - First bump from base depends on detected commit types (e.g. first feat -> v0.1.0)

Exit codes:
  0 -> printed next version
  1 -> error
  2 -> no bump needed
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass


BREAKING_RE = re.compile(r"BREAKING CHANGE:", re.IGNORECASE)
SUBJECT_MAJOR_RE = re.compile(r"^[A-Za-z]+(?:\([^)]*\))?!:")
FEAT_RE = re.compile(r"^feat(?:\(|!|: )")  # we will test differently
PATCH_TYPES = ("fix", "perf", "refactor", "chore", "docs", "test")


def run(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)


def latest_tag() -> str | None:
    cp = run("git", "describe", "--tags", "--abbrev=0")
    if cp.returncode != 0:
        return None
    tag = cp.stdout.strip()
    return tag or None


def commit_shas(range_expr: str | None) -> list[str]:
    if range_expr:
        cp = run("git", "log", "--format=%H", range_expr)
    else:
        cp = run("git", "log", "--format=%H", "HEAD")
    if cp.returncode != 0:
        return []
    return [l for l in cp.stdout.splitlines() if l]


@dataclass
class Classification:
    major: bool = False
    minor: bool = False
    patch: bool = False

    def bump(self) -> str | None:
        if self.major:
            return "major"
        if self.minor:
            return "minor"
        if self.patch:
            return "patch"
        return None


def classify_commits(shas: list[str]) -> Classification:
    result = Classification()
    for sha in shas:
        cp = run("git", "show", "-s", "--format=%B", sha)
        if cp.returncode != 0:
            continue
        message = cp.stdout.strip()
        if not message:
            continue
        lines = message.splitlines()
        subject = lines[0]
        # Major detection
        if BREAKING_RE.search(message) or SUBJECT_MAJOR_RE.match(subject):
            result.major = True
            break  # highest bump
        # Minor detection
        if subject.startswith("feat:") or subject.startswith("feat(") or subject.startswith("feat!:"):
            if not result.major:
                result.minor = True
            continue
        # Patch detection
        for t in PATCH_TYPES:
            if subject.startswith(f"{t}:") or subject.startswith(f"{t}("):
                if not (result.major or result.minor):
                    result.patch = True
                break
    return result


def parse_version(tag: str) -> tuple[int, int, int]:
    v = tag.lstrip("v")
    parts = v.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid tag format: {tag}")
    return tuple(int(p) for p in parts)  # type: ignore


def main() -> int:
    tag = latest_tag()
    if tag is None:
        base = "v0.0.0"
        range_expr = None
    else:
        base = tag
        range_expr = f"{tag}..HEAD"

    shas = commit_shas(range_expr)
    if not shas:
        # No commits at all (unlikely) -> skip
        print(f"No new commits since {base}", file=sys.stderr)
        return 2

    classification = classify_commits(shas)
    bump = classification.bump()
    if bump is None:
        print("No conventional commit keywords detected; skipping bump", file=sys.stderr)
        return 2

    major, minor, patch = parse_version(base)
    if bump == "major":
        major += 1; minor = 0; patch = 0
    elif bump == "minor":
        minor += 1; patch = 0
    elif bump == "patch":
        patch += 1
    else:
        print(f"Unknown bump {bump}", file=sys.stderr)
        return 1

    print(f"v{major}.{minor}.{patch}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
