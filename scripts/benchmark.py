#!/usr/bin/env python3
"""Benchmark Syntinel's detection rate against demo/vulnerable-app.

Runs `syntinel scan` N times and reports, per run:
- recall: how many of the 5 seeded vulnerable files produced >=1 finding
- false positives: how many of the 3 clean files produced any finding

Usage: python scripts/benchmark.py --runs 3
"""

import argparse
import asyncio
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from syntinel.core.config import Settings  # noqa: E402
from syntinel.services.scan_service import ScanOptions, ScanService  # noqa: E402

DEMO_ROOT = Path(__file__).resolve().parent.parent / "demo" / "vulnerable-app"
VULNERABLE_FILES = [
    "app/db.py", "app/config.py", "app/orders.py", "app/files.py", "app/auth.py",
]
CLEAN_FILES = ["clean/safe_queries.py", "clean/safe_orders.py", "clean/password_hashing.py"]


async def run_once() -> dict:
    settings = Settings()
    service = ScanService(settings)
    options = ScanOptions(use_semgrep=True, use_llm=bool(settings.groq_api_key))
    report = await service.scan(str(DEMO_ROOT), options)

    flagged = {str(Path(f.file_path).resolve()) for f in report.findings}
    vuln_hits = sum(
        1 for f in VULNERABLE_FILES if str((DEMO_ROOT / f).resolve()) in flagged
    )
    false_positives = sum(
        1 for f in CLEAN_FILES if str((DEMO_ROOT / f).resolve()) in flagged
    )

    return {
        "recall": vuln_hits / len(VULNERABLE_FILES),
        "false_positive_rate": false_positives / len(CLEAN_FILES),
        "total_findings": len(report.findings),
        "duration_seconds": report.duration_seconds,
    }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    results = [await run_once() for _ in range(args.runs)]

    print(json.dumps(results, indent=2))
    print()
    mean_recall = statistics.mean(r["recall"] for r in results)
    mean_fpr = statistics.mean(r["false_positive_rate"] for r in results)
    print(f"Mean recall: {mean_recall:.0%}")
    print(f"Mean false-positive rate: {mean_fpr:.0%}")


if __name__ == "__main__":
    asyncio.run(main())
