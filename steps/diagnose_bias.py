"""Read-only summary of possible dataset shortcuts by class."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
from urllib.parse import urlsplit


def diagnose(input_file: Path, max_rows: int | None = None) -> dict:
    if max_rows is not None and max_rows <= 0:
        raise ValueError("max_rows must be positive")
    stats = defaultdict(lambda: {"count": 0, "https": 0, "has_path": 0, "length_sum": 0, "source": Counter()})
    with input_file.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
            raise ValueError("CSV must contain url and label columns")
        for index, row in enumerate(reader):
            if max_rows is not None and index >= max_rows:
                break
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if not url or not label:
                continue
            try:
                parts = urlsplit(url if "://" in url else "//" + url)
            except ValueError:
                continue
            item = stats[label]
            item["count"] += 1
            item["https"] += parts.scheme.lower() == "https"
            item["has_path"] += bool(parts.path and parts.path != "/")
            item["length_sum"] += len(url)
            item["source"][(row.get("source") or "unknown").strip() or "unknown"] += 1
    return {
        label: {
            "count": item["count"],
            "https_rate": round(item["https"] / item["count"], 4),
            "path_rate": round(item["has_path"] / item["count"], 4),
            "average_url_length": round(item["length_sum"] / item["count"], 2),
            "top_sources": item["source"].most_common(10),
        }
        for label, item in sorted(stats.items())
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect class-specific URL and source patterns without writing files")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("--max-rows", type=int)
    args = parser.parse_args()
    print(json.dumps(diagnose(args.input_file, args.max_rows), ensure_ascii=False, indent=2))
