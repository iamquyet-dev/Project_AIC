from __future__ import annotations

import argparse
import csv
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"

MISSING_TOKENS = {"nan", "null", "none", "na", "n/a", "<na>", "undefined", "unknown", ""}
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

def run_clean(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    rejected_file: Optional[str] = None,
    max_samples: Optional[int] = None,
) -> Path:
    in_path = Path(input_file) if input_file else DATA_PROCESSED_DIR / "02_normalized.csv"
    out_path = Path(output_file) if output_file else DATA_PROCESSED_DIR / "03_cleaned.csv"
    rej_path = Path(rejected_file) if rejected_file else DATA_PROCESSED_DIR / "03_rejected.csv"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        raise FileNotFoundError(f"Khong tim thay tep dau vao: {in_path}")

    file_size = in_path.stat().st_size
    t0 = time.time()
    seen_hashes: Set[int] = set()
    dropped_null = 0
    dropped_invalid = 0
    dropped_duplicates = 0
    cleaned_count = 0
    total_processed = 0

    header_line = "_aic211_source_row,url,label,timestamp_utc,channel,source,_aic211_ipv4\n"
    rej_header_line = "_aic211_source_row,url,label,timestamp_utc,channel,source,_aic211_ipv4,_aic211_reject_reason\n"

    print(f"Lam sach: {in_path.name} ({round(file_size / (1024*1024), 2)} MB)", flush=True)

    with open(out_path, "w", encoding="utf-8", newline="", buffering=16*1024*1024) as fout, \
         open(rej_path, "w", encoding="utf-8", newline="", buffering=4*1024*1024) as frej, \
         open(in_path, "r", encoding="utf-8-sig", errors="ignore", buffering=16*1024*1024) as fin:

        fout.write(header_line)
        frej.write(rej_header_line)

        header_str = fin.readline()
        for line in fin:
            if not line:
                continue
            total_processed += 1
            line_clean = line.rstrip("\r\n")

            parts = [p.strip().strip('"') for p in line_clean.split(",")]
            if len(parts) < 3:
                dropped_invalid += 1
                frej.write(f"{line_clean},malformed_csv_row\n")
                continue

            url = parts[1]
            label = parts[2]
            label_lower = label.lower()

            if not url or label_lower in MISSING_TOKENS:
                dropped_null += 1
                frej.write(f"{line_clean},missing_url_or_label\n")
                continue

            if not is_valid_url(url):
                dropped_invalid += 1
                frej.write(f"{line_clean},invalid_url_format\n")
                continue

            h_val = hash((url, label_lower))
            if h_val in seen_hashes:
                dropped_duplicates += 1
                frej.write(f"{line_clean},duplicate_url_label_pair\n")
                continue
            seen_hashes.add(h_val)

            fout.write(line)
            cleaned_count += 1

            if total_processed % 2000000 == 0:
                elapsed = round(time.time() - t0, 1)
                speed = int(total_processed / max(elapsed, 0.1))
                print(f"  -> Da xu ly: {total_processed:,} dong ({speed:,} dong/s) [Hop le: {cleaned_count:,}]...", flush=True)

            if max_samples and cleaned_count >= max_samples:
                break

    elapsed_total = round(time.time() - t0, 2)
    avg_speed = int(total_processed / max(elapsed_total, 0.1))
    logger.info(
        f"Hoan thanh Buoc 04 -> Da lam sach {cleaned_count:,} ban ghi trong {elapsed_total}s ({avg_speed:,} dong/s) vao {out_path.name}"
    )
    return out_path

def prompt_menu_input() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[int]]:
    default_in = str(DATA_PROCESSED_DIR / "02_normalized.csv")
    default_out = str(DATA_PROCESSED_DIR / "03_cleaned.csv")
    default_rej = str(DATA_PROCESSED_DIR / "03_rejected.csv")

    print("\nBuoc 04: Lam sach du lieu")
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
        parser.add_argument("-s", "--samples", type=int, default=None, help="Gioi han so dong")
        args = parser.parse_args()

        run_clean(input_file=args.input, output_file=args.output, rejected_file=args.rejected, max_samples=args.samples)
