from __future__ import annotations

import argparse
import concurrent.futures
from contextlib import ExitStack
import csv
from datetime import datetime, timezone
import hashlib
from itertools import islice
import json
import logging
import math
import os
from pathlib import Path
import random
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    csv.field_size_limit(128 * 1024 * 1024)
except Exception:
    csv.field_size_limit(2147483647)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from url_detector.config import CLASSES
from functools import lru_cache
import ipaddress
import sqlite3
from urllib.parse import urlsplit
from collections import Counter, defaultdict
DATA_PROCESSED_DIR = Path(os.environ["AIC_RUN_DIR"]).resolve() / "processed" if os.environ.get("AIC_RUN_DIR") else BASE_DIR / "data" / "processed"

def setup_logger(name: str = "Buoc06-TapDuLieu") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

logger = setup_logger("Buoc06-TapDuLieu")

LABEL_IDS = {name: index for index, name in enumerate(CLASSES)}

LABEL_ALIASES = {
    "benign": "benign",
    "safe": "benign",
    "good": "benign",
    "ham": "benign",
    "legitimate": "benign",
    "0": "benign",
    "phish": "phishing",
    "phishing": "phishing",
    "bad": "malicious",
    "1": "malicious",
    "malware": "malware",
    "virus": "malware",
    "trojan": "malware",
    "exploit": "malware",
    "defacement": "malicious",
    "defaced": "malicious",
    "deface": "malicious",
    "malicious": "malicious",
}

def find_source_dataset() -> Path:
    candidates = [
        DATA_PROCESSED_DIR / "04_features.csv",
        DATA_PROCESSED_DIR / "03_cleaned.csv",
        DATA_PROCESSED_DIR / "cleaned_records.csv",
        DATA_PROCESSED_DIR / "dataset_unified.csv",
    ]
    for c in candidates:
        if c.is_file():
            return c
    found_unified = list(DATA_PROCESSED_DIR.glob("**/dataset_unified.csv"))
    if found_unified:
        return found_unified[0]
    raise FileNotFoundError("Khong tim thay tap du lieu de chia tach. Vui long chay Buoc 04 hoac Buoc 05 truoc.")

def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=16*1024*1024) as handle:
        for block in iter(lambda: handle.read(16*1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()

def _hash_fraction(value: str) -> float:
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big") / 2**64

def _split_name(key: str, seed: int, train_ratio: float, val_ratio: float) -> str:
    fraction = _hash_fraction(f"{seed}:split:{key}")
    return "train" if fraction < train_ratio else ("val" if fraction < train_ratio + val_ratio else "test")

def run_dataset_split(
    input_file: Optional[str] = None,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
    max_samples: Optional[int] = None,
    holdout_sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ratios = (train_ratio, val_ratio, test_ratio)
    if any(not math.isfinite(r) or r <= 0 for r in ratios) or not math.isclose(sum(ratios), 1.0, abs_tol=1e-9):
        raise ValueError("Train/val/test ratios must be positive and sum to 1")
    if max_samples is not None and max_samples <= 0:
        raise ValueError("So dong mau phai duong")
    in_path = Path(input_file) if input_file else find_source_dataset()
    if not in_path.is_file():
        raise FileNotFoundError(f"Khong tim thay tep du lieu: {in_path}")
    if not PSL_PATH.is_file():
        raise FileNotFoundError(f"Thieu Public Suffix List snapshot: {PSL_PATH}")
    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    paths = {name: DATA_PROCESSED_DIR / f"{name}.csv" for name in ("train", "val", "test")}
    if in_path.resolve() in {path.resolve() for path in paths.values()}:
        raise ValueError("Input must differ from train.csv, val.csv and test.csv")
    started = time.time()
    counts = {"train": 0, "val": 0, "test": 0, "total": 0}
    class_dist = {name: {} for name in paths}
    group_dist = {name: 0 for name in paths}
    source_dist = {name: {} for name in paths}
    skipped = {"invalid_url": 0, "unknown_label": 0, "malformed_row": 0}

    in_size_mb = round(in_path.stat().st_size / (1024 * 1024), 2)
    s_label = f"{max_samples:,}" if max_samples else "toan bo"
    print(f"\nBuoc 06: Phan chia tap du lieu ({in_path.name} - {in_size_mb} MB, mau: {s_label})", flush=True)
    print(f"Ty le chia: Train {int(train_ratio*100)}% - Val {int(val_ratio*100)}% - Test {int(test_ratio*100)}% (Seed={seed})", flush=True)

    with tempfile.TemporaryDirectory(prefix=".split_", dir=DATA_PROCESSED_DIR) as scratch:
        scratch = Path(scratch)
        with open(in_path, "r", encoding="utf-8-sig", newline="", buffering=16*1024*1024) as source_file:
            reader = csv.reader(source_file)
            header = next(reader, None)
        if not header:
            raise ValueError(f"Tep {in_path} rong khong co du lieu.")
        lowered = [col.strip().lower() for col in header]
        url_idx = next((i for i, col in enumerate(lowered) if col in ("url", "urls", "domain")), None)
        label_idx = next((i for i, col in enumerate(lowered) if col in ("label", "class", "target")), None)
        split_idx = next((i for i, col in enumerate(lowered) if col in ("source_split", "split")), None)
        source_idx = lowered.index("source") if "source" in lowered else None
        if url_idx is None or label_idx is None:
            raise ValueError("CSV can cot URL va label ro rang")
        id_idx = lowered.index("label_id") if "label_id" in lowered else None
        out_header = list(header) if id_idx is not None else [*header, "label_id"]

        pins: Dict[str, int] = {}
        holdout_set = set(holdout_sources or [])
        if holdout_set and source_idx is None:
            raise ValueError("Source holdout requires a source column")
        if split_idx is not None or holdout_set:
            print("-> [1/4] Kiem tra va ghim nhan goc cua publisher vao RAM...", flush=True)
            ranks = {"test": 0, "validation": 1, "val": 1, "train": 2}
            with open(in_path, "r", encoding="utf-8-sig", newline="", buffering=16*1024*1024) as fin:
                reader = csv.reader(fin)
                next(reader, None)
                for number, row in enumerate(reader):
                    if max_samples is not None and number >= max_samples:
                        break
                    if len(row) != len(header) or not row[url_idx].strip():
                        continue
                    split_val = row[split_idx].strip().lower() if split_idx is not None else ""
                    rank = 0 if (source_idx is not None and row[source_idx].strip() in holdout_set) else ranks.get(split_val)
                    if rank is not None:
                        key = canonical_group_key(row[url_idx])
                        curr = pins.get(key)
                        if curr is None or rank < curr:
                            pins[key] = rank
            print(f"  -> Da ghim {len(pins):,} domain/key vao RAM.", flush=True)

        print("-> [2/4] Phan nhom URL theo domain/host va dua vao cac bucket...", flush=True)
        t_split0 = time.time()
        split_cache: Dict[str, str] = {}
        with ExitStack() as stack:
            buckets = {}
            writers = {}
            with open(in_path, "r", encoding="utf-8-sig", newline="", buffering=16*1024*1024) as fin:
                reader = csv.reader(fin)
                next(reader, None)
                for number, row in enumerate(reader):
                    if max_samples is not None and number >= max_samples:
                        break
                    if len(row) != len(header):
                        skipped["malformed_row"] += 1
                        continue
                    url = row[url_idx].strip()
                    if not url:
                        skipped["invalid_url"] += 1
                        continue
                    label = LABEL_ALIASES.get(row[label_idx].strip().lower(), row[label_idx].strip().lower())
                    if label not in LABEL_IDS:
                        skipped["unknown_label"] += 1
                        continue
                    row[label_idx] = label
                    key = canonical_group_key(url)
                    target = split_cache.get(key)
                    if target is None:
                        pinned_rank = pins.get(key) if pins else None
                        if pinned_rank is not None:
                            target = ("test", "val", "train")[pinned_rank]
                        else:
                            target = _split_name(key, seed, train_ratio, val_ratio)
                        split_cache[key] = target
                        group_dist[target] += 1

                    if id_idx is None:
                        row = [*row, str(LABEL_IDS[label])]
                    else:
                        row[id_idx] = str(LABEL_IDS[label])
                    bucket = int(_hash_fraction(f"{seed}:shuffle:{key}:{number}") * 16)
                    bucket_key = (target, bucket)
                    if bucket_key not in writers:
                        shard = scratch / f"{target}_{bucket:02d}.csv"
                        handle = stack.enter_context(open(shard, "w", encoding="utf-8", newline="", buffering=1024*1024))
                        buckets[bucket_key] = shard
                        writers[bucket_key] = csv.writer(handle)
                    writers[bucket_key].writerow(row)
                    counts[target] += 1
                    counts["total"] += 1
                    class_dist[target][label] = class_dist[target].get(label, 0) + 1
                    if source_idx is not None:
                        source = row[source_idx].strip() or "unknown"
                        source_dist[target][source] = source_dist[target].get(source, 0) + 1
                    if number > 0 and number % 500000 == 0:
                        s_sec = round(time.time() - t_split0, 1)
                        spd = int(number / max(s_sec, 0.1))
                        print(f"   Da phan chia {number:,} dong ({spd:,} dong/s) -> Train: {counts['train']:,} | Val: {counts['val']:,} | Test: {counts['test']:,}...", flush=True)

        print("-> [3/4] Xao tron du lieu theo khoi va xuat file train/val/test...", flush=True)
        rng = random.Random(seed)
        for target, output in paths.items():
            print(f"   Dang xuat {output.name} ({counts[target]:,} dong)...", flush=True)
            with open(output, "w", encoding="utf-8", newline="", buffering=8*1024*1024) as fout:
                writer = csv.writer(fout)
                writer.writerow(out_header)
                order = list(range(16))
                rng.shuffle(order)
                for bucket in order:
                    shard = buckets.get((target, bucket))
                    if shard is None:
                        continue
                    with open(shard, "r", encoding="utf-8", newline="", buffering=1024*1024) as fin:
                        reader = csv.reader(fin)
                        while True:
                            block = list(islice(reader, 10000))
                            if not block:
                                break
                            rng.shuffle(block)
                            writer.writerows(block)

    print("-> [4/4] Tinh ma bam SHA-256 song song va tao dataset_version.json...", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_in = executor.submit(_file_sha256, in_path)
        future_splits = {name: executor.submit(_file_sha256, paths[name]) for name in paths}
        in_sha256 = future_in.result()
        split_hashes = {name: future.result() for name, future in future_splits.items()}

    version_metadata = {
        "version": f"v_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(in_path),
        "source_sha256": in_sha256,
        "source_bytes": in_path.stat().st_size,
        "schema": out_header,
        "total_rows": counts["total"],
        "skipped_rows": skipped,
        "split_policy": "SHA256(seed, registrable domain from pinned Public Suffix List including private rules); IP and unknown suffixes grouped by exact host; publisher test > val > train pins take precedence",
        "public_suffix_list_sha256": _file_sha256(PSL_PATH),
        "group_counts": group_dist,
        "source_counts_by_split": source_dist,
        "source_split_present": split_idx is not None,
        "source_holdout": sorted(holdout_set),
        "shuffle_policy": "16 disk buckets per split, shuffled in bounded 10000-row blocks",
        "integrity_verified": True,
        "seed": seed,
        "splits": {
            name: {
                "rows": counts[name],
                "ratio": round(counts[name] / max(1, counts["total"]), 4),
                "class_distribution": class_dist[name],
                "sha256": split_hashes[name],
                "bytes": paths[name].stat().st_size,
                "modified_ns": paths[name].stat().st_mtime_ns,
            }
            for name in paths
        },
    }
    with open(DATA_PROCESSED_DIR / "dataset_version.json", "w", encoding="utf-8") as handle:
        json.dump(version_metadata, handle, ensure_ascii=False, indent=2)
    elapsed = round(time.time() - started, 2)
    avg_speed = int(counts["total"] / max(elapsed, 0.1))
    print(f"  -> Hoan tat trong {elapsed}s ({avg_speed:,} dong/s): Train={counts['train']:,} | Val={counts['val']:,} | Test={counts['test']:,}\n", flush=True)
    logger.info("Hoan thanh Buoc 06 -> %s dong trong %ss: train=%s val=%s test=%s",
                f"{counts['total']:,}", elapsed, f"{counts['train']:,}", f"{counts['val']:,}", f"{counts['test']:,}")
    return version_metadata

def prompt_menu_input() -> Tuple[Optional[str], float, float, float, Optional[int]]:
    cand = find_source_dataset()
    def_file = str(cand)
    print("\nBuoc 06: Phan chia tap du lieu")
    ans_file = input(f"Tep dataset [Enter={cand.name}]: ").strip()
    in_file = ans_file if ans_file else def_file

    print("1. 70% Train - 15% Val - 15% Test (mac dinh)")
    print("2. 80% Train - 10% Val - 10% Test")
    ans_ratio = input("Chon [1-2, Enter=1]: ").strip()
    if ans_ratio == "2":
        tr, vr, te = 0.80, 0.10, 0.10
    else:
        tr, vr, te = 0.70, 0.15, 0.15

    ans_samples = input("Gioi han so dong mau (Enter=Toan bo): ").strip()
    s_size = int(ans_samples) if ans_samples.isdigit() else None

    return in_file, tr, vr, te, s_size

PSL_PATH = Path(__file__).resolve().parent / "public_suffix_list.dat"


@lru_cache(maxsize=1)
def _rules() -> tuple[set[str], set[str], set[str]]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in PSL_PATH.read_text(encoding="utf-8").splitlines():
        rule = raw.strip().lower()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exception.add(rule[1:])
        elif rule.startswith("*."):
            wildcard.add(rule[2:])
        else:
            exact.add(rule)
    return exact, wildcard, exception


def canonical_group_key(url: str) -> str:
    value = url.strip()
    try:
        host = (urlsplit(value if "://" in value else "//" + value).hostname or "").lower().rstrip(".")
    except ValueError:
        host = ""
    if not host:
        return f"raw:{value.lower()}"
    try:
        return f"ip:{ipaddress.ip_address(host).compressed}"
    except ValueError:
        pass
    host = host.removeprefix("www.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return f"host:{host}"
    labels = host.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return f"host:{host}"
    exact, wildcard, exception = _rules()
    suffix_length = 1
    matched = False
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in exception:
            suffix_length = len(labels) - index - 1
            matched = True
            break
        if candidate in exact:
            suffix_length = max(suffix_length, len(labels) - index)
            matched = True
        if index > 0 and candidate in wildcard:
            suffix_length = max(suffix_length, len(labels) - index + 1)
            matched = True
    if not matched or len(labels) <= suffix_length:
        return f"host:{host}"
    return f"domain:{'.'.join(labels[-suffix_length - 1:])}"


def _digest(value: str) -> bytes:
    return hashlib.blake2b(value.encode("utf-8"), digest_size=16).digest()


def _host_and_near(url: str) -> tuple[str, str]:
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        host = (parts.hostname or "").lower().rstrip(".")
        host = host.encode("idna").decode("ascii")
        port = parts.port
    except (ValueError, UnicodeError):
        return "", url.lower()
    if not host:
        return "", url.lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.removeprefix("www.")
    port_text = "" if port in (None, 80, 443) else f":{port}"
    near = f"{host}{port_text}{(parts.path or '/').rstrip('/') or '/'}?{parts.query}"
    return host, near


def audit_split(processed_dir: Path, output: Path) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    db_path = output.with_suffix(".sqlite")
    if db_path.exists():
        raise FileExistsError(f"Existing audit database: {db_path}")
    rows = Counter()
    source_splits = defaultdict(Counter)
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        for table in ("groups", "hosts", "urls", "near"):
            db.execute(f"CREATE TABLE {table} (key BLOB PRIMARY KEY, mask INTEGER NOT NULL)")
        for split, mask in (("train", 1), ("val", 2), ("test", 4)):
            with (processed_dir / f"{split}.csv").open("r", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                batch = {name: [] for name in ("groups", "hosts", "urls", "near")}
                for row in reader:
                    url = row.get("url") or ""
                    if not url:
                        continue
                    host, near = _host_and_near(url)
                    batch["groups"].append((_digest(canonical_group_key(url)), mask))
                    batch["hosts"].append((_digest(host), mask))
                    batch["urls"].append((_digest(url), mask))
                    batch["near"].append((_digest(near), mask))
                    rows[split] += 1
                    source_splits[row.get("source") or "unknown"][split] += 1
                    if len(batch["groups"]) >= 10000:
                        _flush(db, batch)
                _flush(db, batch)
        summary = {}
        for table in ("groups", "hosts", "urls", "near"):
            unique, overlap = db.execute(f"SELECT COUNT(*), SUM(CASE WHEN mask IN (3,5,6,7) THEN 1 ELSE 0 END) FROM {table}").fetchone()
            summary[table] = {"unique": unique, "across_splits": overlap or 0}
    report = {"rows": dict(rows), "overlap": summary, "source_counts_by_split": {k: dict(v) for k, v in source_splits.items()},
              "near_key_note": "Candidate only: lowercased host, optional www removed, default port removed, trailing path slash removed, fragment removed. Manual destination review required.",
              "grouping": "Pinned Public Suffix List with private suffixes; IP by exact host"}
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def _flush(db: sqlite3.Connection, batch: dict) -> None:
    for table, values in batch.items():
        db.executemany(f"INSERT INTO {table}(key,mask) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET mask=mask|excluded.mask", values)
        values.clear()
    db.commit()




if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_file, tr, vr, te, s_size = prompt_menu_input()
        run_dataset_split(input_file=in_file, train_ratio=tr, val_ratio=vr, test_ratio=te, max_samples=s_size)
    else:
        parser = argparse.ArgumentParser(description="Buoc 06: Phan chia tap du lieu (Dataset Split)")
        parser.add_argument("-i", "--input", default=None, help="Tep csv nguon")
        parser.add_argument("-s", "--samples", type=int, default=None, help="Gioi han so dong")
        parser.add_argument("--train-ratio", type=float, default=0.70, help="Ty le Train (mac dinh 0.70)")
        parser.add_argument("--val-ratio", type=float, default=0.15, help="Ty le Val (mac dinh 0.15)")
        parser.add_argument("--test-ratio", type=float, default=0.15, help="Ty le Test (mac dinh 0.15)")
        parser.add_argument("--holdout-source", action="append", default=[], help="Nguon giu rieng cho test; co the lap lai")
        parser.add_argument("--audit-split", action="store_true", help="Kiem tra trung lap train/val/test hien tai")
        parser.add_argument("--audit-output", type=Path, default=None)
        args = parser.parse_args()

        if args.audit_split:
            print(audit_split(DATA_PROCESSED_DIR, args.audit_output or DATA_PROCESSED_DIR.parent / "metrics" / "split_audit.json"))
        else:
            run_dataset_split(input_file=args.input, train_ratio=args.train_ratio, val_ratio=args.val_ratio, test_ratio=args.test_ratio, max_samples=args.samples, holdout_sources=args.holdout_source)
