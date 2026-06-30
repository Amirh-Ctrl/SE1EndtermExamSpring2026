from __future__ import annotations

import csv
import sys
import trace
import unittest
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    source_root = project_root / "src"
    tests_root = project_root / "tests"
    report_path = project_root / "coverage_report.csv"
    sys.path.insert(0, str(source_root))

    test_result: unittest.result.TestResult | None = None

    def run_tests() -> None:
        nonlocal test_result
        suite = unittest.defaultTestLoader.discover(str(tests_root))
        test_result = unittest.TextTestRunner(verbosity=2).run(suite)

    tracer = trace.Trace(count=True, trace=False)
    tracer.runfunc(run_tests)
    counts = tracer.results().counts
    rows = []

    for source_file in sorted(source_root.rglob("*.py")):
        statements = _statement_lines(source_file)
        executed = {
            line_number
            for filename, line_number in counts
            if Path(filename).resolve() == source_file.resolve() and line_number in statements
        }
        total = len(statements)
        covered = len(executed)
        percent = 100.0 if total == 0 else round((covered / total) * 100, 2)
        rows.append(
            {
                "file": str(source_file.relative_to(project_root)).replace("\\", "/"),
                "statements": total,
                "covered": covered,
                "coverage_percent": percent,
            }
        )

    total_statements = sum(int(row["statements"]) for row in rows)
    total_covered = sum(int(row["covered"]) for row in rows)
    total_percent = 100.0 if total_statements == 0 else round((total_covered / total_statements) * 100, 2)
    rows.append(
        {
            "file": "TOTAL",
            "statements": total_statements,
            "covered": total_covered,
            "coverage_percent": total_percent,
        }
    )

    with report_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["file", "statements", "covered", "coverage_percent"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Coverage CSV written to {report_path}")
    return 0 if test_result is not None and test_result.wasSuccessful() else 1


def _statement_lines(path: Path) -> set[int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    result = set()
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped not in {'"""', "'''"}:
            result.add(index)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
