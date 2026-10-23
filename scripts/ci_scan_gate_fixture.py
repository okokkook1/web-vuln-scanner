"""Run a real scan -> baseline -> diff-gate flow against the local fixture server."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.fixture_server import fixture_server  # noqa: E402
from vulnscan.db import Database  # noqa: E402
from vulnscan.diff import compare_scans  # noqa: E402


def _run(args: list[str], expected: int = 0) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", "vulnscan", *args]
    print("$", " ".join(command), flush=True)
    result = subprocess.run(command, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    if result.returncode != expected:
        raise SystemExit(
            f"command exited {result.returncode}, expected {expected}: "
            + " ".join(command)
        )
    return result


def _scan_args(
    target: str,
    profile: str,
    data_dir: Path,
    out_dir: Path,
) -> list[str]:
    return [
        "scan",
        "--url",
        target,
        "--profile",
        profile,
        "--allow-private",
        "--acknowledge-authorized",
        "--rps",
        "20",
        "--max-requests",
        "120",
        "--depth",
        "2",
        "--timeout",
        "5",
        "--data-dir",
        str(data_dir),
        "--out",
        str(out_dir),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    data_dir = args.data_dir.resolve()
    out_dir = args.out.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    with fixture_server() as target:
        _run(_scan_args(target, "passive", data_dir, out_dir))
        db = Database(data_dir / "vulnscan.db")
        db.init()
        baseline = db.list_scans(limit=1)[0]

        _run(
            [
                "baseline",
                "set",
                "--scan",
                baseline.id,
                "--created-by",
                "ci",
                "--data-dir",
                str(data_dir),
            ]
        )
        shown = _run(
            [
                "baseline",
                "show",
                "--scan",
                baseline.id,
                "--json",
                "--data-dir",
                str(data_dir),
            ]
        )
        payload = json.loads(shown.stdout)
        if payload["baseline"] != baseline.id:
            raise SystemExit("baseline show did not return the stored scan")

        _run(_scan_args(target, "safe", data_dir, out_dir))
        db = Database(data_dir / "vulnscan.db")
        db.init()
        current = db.list_scans(limit=1)[0]
        result = compare_scans(db, current.id, baseline.id)
        if result.summary["new"] < 1:
            raise SystemExit("safe scan produced no new findings for the diff gate")

        _run(
            [
                "diff",
                "--current",
                current.id,
                "--baseline",
                "--fail-on",
                "new",
                "--data-dir",
                str(data_dir),
            ],
            expected=1,
        )
        _run(
            [
                "diff",
                "--current",
                current.id,
                "--baseline",
                "--fail-on",
                "new_confirmed",
                "--data-dir",
                str(data_dir),
            ],
            expected=0,
        )

        db.set_finding_review(
            result.new[0].id,
            "confirmed",
            "CI real-scan gate fixture",
            "ci",
        )
        _run(
            [
                "diff",
                "--current",
                current.id,
                "--baseline",
                "--fail-on",
                "new_confirmed",
                "--data-dir",
                str(data_dir),
            ],
            expected=1,
        )

    reports = sorted(out_dir.glob("vulnscan-*.json"))
    if len(reports) < 2:
        raise SystemExit(f"expected two JSON reports, found {len(reports)}")
    print(f"OK: real scan gate verified; reports={len(reports)}")


if __name__ == "__main__":
    main()
