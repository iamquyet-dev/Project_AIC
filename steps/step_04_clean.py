from __future__ import annotations

import argparse
import csv
import logging
import multiprocessing as mp
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import zlib

try:
    csv.field_size_limit(128 * 1024 * 1024)
except Exception:
    csv.field_size_limit(2147483647)

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"

CPU_COUNT = os.cpu_count() or 4
DEFAULT_WORKERS = min(16, max(1, CPU_COUNT - 2))

MISSING_TOKENS = {"nan", "null", "none", "na", "n/a", "<na>", "undefined", "unknown", ""}
VALID_LABELS = {"benign", "phishing", "malware", "malicious"}
IP_PATTERN = re.compile(r"\d{1,3}\.\d{1,3}")

def setup_logger(name: str = "Buoc04-LamSach") -> logging.Logger:
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

logger = setup_logger("Buoc04-LamSach")

def is_valid_url(u: str) -> bool:
    if not u:
        return False
    u_len = len(u)
    if u_len < 4 or u_len > 4096:
        return False
    if " " in u and "%20" not in u:
        return False
    if "." not in u and "localhost" not in u and not IP_PATTERN.search(u):
        return False
    return True

def _clean_shard_worker(args: Tuple[str, str, str, List[str], int, int]) -> Dict[str, int]:
    shard_in, part_clean, part_rej, fieldnames, shard_id, total_shards = args
    counts = {"processed": 0, "cleaned": 0, "missing": 0, "invalid": 0, "duplicate": 0, "conflict": 0, "unknown_label": 0}
    p_in = Path(shard_in)
    if not p_in.exists() or p_in.stat().st_size == 0:
        return counts

    # Phase 2.1: In-memory Indexing & Conflict detection within shard
    seen: Dict[str, str] = {}
    conflicts: Set[str] = set()

    with open(shard_in, "r", encoding="utf-8-sig", newline="", buffering=8*1024*1024) as fin:
        reader = csv.DictReader(fin)
        for row in reader:
            if None in row:
                continue
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if not is_valid_url(url) or label not in VALID_LABELS:
                continue
            prev_label = seen.get(url)
            if prev_label is None:
                seen[url] = label
            elif prev_label != label:
                conflicts.add(url)

    # Phase 2.2: Filtering and emitting within shard
    emitted: Set[str] = set()
    with open(shard_in, "r", encoding="utf-8-sig", newline="", buffering=8*1024*1024) as fin, \
         open(part_clean, "w", encoding="utf-8", newline="", buffering=8*1024*1024) as fout, \
         open(part_rej, "w", encoding="utf-8", newline="", buffering=4*1024*1024) as frej:
        reader = csv.DictReader(fin)
        accepted = csv.DictWriter(fout, fieldnames=fieldnames)
        rejected = csv.DictWriter(frej, fieldnames=[*fieldnames, "_aic211_reject_reason"])
        for row in reader:
            counts["processed"] += 1
            if None in row:
                reason = "malformed_csv_row"
                row.pop(None)
            else:
                url = (row.get("url") or "").strip()
                label = (row.get("label") or "").strip().lower()
                if not url or label in MISSING_TOKENS:
                    reason = "missing_url_or_label"
                    counts["missing"] += 1
                elif label not in VALID_LABELS:
                    reason = "unknown_label"
                    counts["unknown_label"] += 1
                elif not is_valid_url(url):
                    reason = "invalid_url_format"
                    counts["invalid"] += 1
                elif url in conflicts:
                    reason = "conflicting_labels"
                    counts["conflict"] += 1
                elif url in emitted:
                    reason = "duplicate_url"
                    counts["duplicate"] += 1
                else:
                    emitted.add(url)
                    reason = ""
            if reason:
                rejected.writerow({**row, "_aic211_reject_reason": reason})
            else:
                accepted.writerow(row)
                counts["cleaned"] += 1

    return counts

def run_clean(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    rejected_file: Optional[str] = None,
    max_samples: Optional[int] = None,
    workers: Optional[int] = None,
) -> Path:
    in_path = Path(input_file) if input_file else DATA_PROCESSED_DIR / "02_normalized.csv"
    out_path = Path(output_file) if output_file else DATA_PROCESSED_DIR / "03_cleaned.csv"
    rej_path = Path(rejected_file) if rejected_file else DATA_PROCESSED_DIR / "03_rejected.csv"
    if len({in_path.resolve(), out_path.resolve(), rej_path.resolve()}) != 3:
        raise ValueError("Input, output va rejected phai la ba tep khac nhau")
    if max_samples is not None and max_samples <= 0:
        raise ValueError("So dong mau phai duong")
    if not in_path.exists():
        raise FileNotFoundError(f"Khong tim thay tep dau vao: {in_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rej_path.parent.mkdir(parents=True, exist_ok=True)

    file_size_mb = round(in_path.stat().st_size / (1024 * 1024), 2)
    num_workers = workers or DEFAULT_WORKERS
    if max_samples and max_samples < 50000:
        num_workers = 1
    num_workers = min(num_workers, os.cpu_count() or 1)

    print(f"\nBuoc 04: Lam sach du lieu & Loc trung lap ({in_path.name} - {file_size_mb} MB)")
    print(f"Khoi dong xu ly da tien trinh tren {num_workers} workers song song...", flush=True)

    t0 = time.time()
    temp_dir = out_path.parent / "_temp_clean"
    temp_dir.mkdir(parents=True, exist_ok=True)

    shard_paths = [temp_dir / f"shard_{i:02d}.csv" for i in range(num_workers)]
    clean_parts = [temp_dir / f"clean_{i:02d}.csv" for i in range(num_workers)]
    rej_parts = [temp_dir / f"rej_{i:02d}.csv" for i in range(num_workers)]

    shard_files = [open(sp, "w", encoding="utf-8", newline="", buffering=4*1024*1024) for sp in shard_paths]
    shard_writers = [csv.writer(sf) for sf in shard_files]

    # Giai doan 1: Băm phân mảnh (Hash Partitioning) theo URL
    print(f"-> Giai doan 1/3: Phan manh du lieu thanh {num_workers} bucket theo URL...", flush=True)
    t_shard0 = time.time()
    total_sharded = 0
    header: List[str] = []

    with open(in_path, "r", encoding="utf-8-sig", newline="", buffering=16*1024*1024) as fin:
        reader = csv.reader(fin)
        header_raw = next(reader, None)
        if not header_raw:
            raise ValueError(f"Tep {in_path} rong")
        header = [col.strip().lstrip("\ufeff") for col in header_raw]
        if not {"url", "label"}.issubset({c.lower() for c in header}):
            raise ValueError("CSV Clean can cot url va label")

        url_idx = 1
        for idx, col in enumerate(header):
            if col.strip().lower() == "url":
                url_idx = idx
                break

        for sw in shard_writers:
            sw.writerow(header)

        for row in reader:
            if max_samples is not None and total_sharded >= max_samples:
                break
            u = row[url_idx].strip() if len(row) > url_idx else ""
            shard_id = (zlib.crc32(u.encode("utf-8", errors="ignore")) & 0x7FFFFFFF) % num_workers if u else 0
            shard_writers[shard_id].writerow(row)
            total_sharded += 1
            if total_sharded % 1000000 == 0:
                s_sec = round(time.time() - t_shard0, 1)
                spd = int(total_sharded / max(s_sec, 0.1))
                print(f"  -> Da phan manh {total_sharded:,} dong ({spd:,} dong/s)...", flush=True)

    for sf in shard_files:
        sf.close()

    t_shard_end = round(time.time() - t_shard0, 2)
    shard_spd = int(total_sharded / max(t_shard_end, 0.1))
    print(f"  -> Hoan thanh phan manh {total_sharded:,} dong trong {t_shard_end}s ({shard_spd:,} dong/s)\n", flush=True)

    # Giai doan 2: Xu ly song song tren RAM
    print(f"-> Giai doan 2/3: Loc trung lap & xung dot song song ({num_workers} workers tren RAM)...", flush=True)
    t_pool0 = time.time()
    tasks = [
        (str(sp), str(cp), str(rp), header, i + 1, num_workers)
        for i, (sp, cp, rp) in enumerate(zip(shard_paths, clean_parts, rej_parts))
    ]

    if num_workers > 1:
        with mp.Pool(processes=num_workers) as pool:
            results = pool.map(_clean_shard_worker, tasks)
    else:
        results = [_clean_shard_worker(tasks[0])]

    t_pool_end = round(time.time() - t_pool0, 2)
    print(f"  -> Hoan thanh loc song song trong {t_pool_end}s\n", flush=True)

    # Giai doan 3: Hop nhat ket qua
    print(f"-> Giai doan 3/3: Hop nhat ket qua vao {out_path.name} va {rej_path.name}...", flush=True)
    t_cat0 = time.time()

    with open(out_path, "w", encoding="utf-8", newline="", buffering=16*1024*1024) as fout:
        writer = csv.writer(fout)
        writer.writerow(header)
        for cp in clean_parts:
            if cp.exists():
                with open(cp, "r", encoding="utf-8", newline="", buffering=16*1024*1024) as cfin:
                    shutil.copyfileobj(cfin, fout, length=16*1024*1024)
                cp.unlink()

    with open(rej_path, "w", encoding="utf-8", newline="", buffering=16*1024*1024) as frej:
        writer = csv.writer(frej)
        writer.writerow([*header, "_aic211_reject_reason"])
        for rp in rej_parts:
            if rp.exists():
                with open(rp, "r", encoding="utf-8", newline="", buffering=8*1024*1024) as rfin:
                    shutil.copyfileobj(rfin, frej, length=8*1024*1024)
                rp.unlink()

    for sp in shard_paths:
        if sp.exists():
            sp.unlink()
    try:
        temp_dir.rmdir()
    except Exception:
        pass

    counts = {"processed": 0, "cleaned": 0, "missing": 0, "invalid": 0, "duplicate": 0, "conflict": 0, "unknown_label": 0}
    for r in results:
        for k in counts:
            counts[k] += r[k]

    t_cat_end = round(time.time() - t_cat0, 2)
    total_elapsed = round(time.time() - t0, 2)
    avg_speed = int(counts["processed"] / max(total_elapsed, 0.1))

    logger.info(
        "Hoan thanh Buoc 04 -> %s dong hop le, %s trung URL, %s xung dot nhan, %s thieu, %s sai URL trong %ss (%s dong/s): %s",
        f"{counts['cleaned']:,}", f"{counts['duplicate']:,}", f"{counts['conflict']:,}", f"{counts['missing']:,}",
        f"{counts['invalid']:,}", total_elapsed, f"{avg_speed:,}", out_path.name,
    )
    return out_path

def prompt_menu_input() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[int]]:
    default_in = str(DATA_PROCESSED_DIR / "02_normalized.csv")
    default_out = str(DATA_PROCESSED_DIR / "03_cleaned.csv")
    default_rej = str(DATA_PROCESSED_DIR / "03_rejected.csv")

    print("\nBuoc 04: Lam sach du lieu (Da tien trinh Hash-Partitioning)")
    ans_in = input(f"Tep dau vao [Enter={Path(default_in).name}]: ").strip()
    in_file = ans_in if ans_in else default_in

    print("1. Xu ly toan bo (mac dinh)")
    print("2. Chay thu nghiem (100,000 dong)")
    print("3. Tu nhap so luong")
    limit_choice = input("Chon [1-3, Enter=1]: ").strip()
    if limit_choice == "2":
        max_rows = 100000
    elif limit_choice == "3":
        custom_r = input("Nhap so dong: ").strip()
        max_rows = int(custom_r) if custom_r.isdigit() and int(custom_r) > 0 else None
    else:
        max_rows = None

    return in_file, default_out, default_rej, max_rows

if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_file, out_file, rej_file, max_rows = prompt_menu_input()
        run_clean(input_file=in_file, output_file=out_file, rejected_file=rej_file, max_samples=max_rows)
    else:
        parser = argparse.ArgumentParser(description="Buoc 04: Lam sach du lieu (Clean)")
        parser.add_argument("-i", "--input", default=None, help="Tep dau vao csv")
        parser.add_argument("-o", "--output", default=None, help="Tep dau ra csv")
        parser.add_argument("--rejected", default=None, help="Tep chua cac ban ghi bi loai")
        parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"So tien trinh (mac dinh {DEFAULT_WORKERS})")
        parser.add_argument("-s", "--samples", type=int, default=None, help="Gioi han so dong")
        args = parser.parse_args()

        run_clean(input_file=args.input, output_file=args.output, rejected_file=args.rejected, max_samples=args.samples, workers=args.workers)
