#!/usr/bin/env python3
"""Simple benchmark for rulebase flattening throughput."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from cp_review.normalize.flatten import flatten_access_rulebase_pages


def run_benchmark(iterations: int, multiplier: int) -> dict[str, float]:
    fixture = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample_rulebase_page.json"
    page = json.loads(fixture.read_text(encoding="utf-8"))
    pages = [page for _ in range(multiplier)]
    durations: list[float] = []
    total_rules = 0

    for _ in range(iterations):
        start = time.perf_counter()
        rules, warnings = flatten_access_rulebase_pages(
            package_name="Standard",
            layer={"name": "Network", "type": "access-layer"},
            pages=pages,
        )
        durations.append(time.perf_counter() - start)
        total_rules = len(rules)
        _ = len(warnings)

    avg = statistics.mean(durations)
    p95_index = max(0, min(len(durations) - 1, int(len(durations) * 0.95) - 1))
    sorted_durations = sorted(durations)
    return {
        "iterations": float(iterations),
        "page_multiplier": float(multiplier),
        "rules_per_iteration": float(total_rules),
        "avg_seconds": avg,
        "p95_seconds": sorted_durations[p95_index],
        "rules_per_second": (total_rules / avg) if avg > 0 else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark flatten_access_rulebase_pages")
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--multiplier", type=int, default=300)
    args = parser.parse_args()

    result = run_benchmark(args.iterations, args.multiplier)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
