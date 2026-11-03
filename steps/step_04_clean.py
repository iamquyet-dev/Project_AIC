from __future__ import annotations

import argparse
import csv

csv.field_size_limit(16 * 1024 * 1024)
import logging
import os
from pathlib import Path
import re
import sqlite3
import tempfile
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

def run_clean(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    rejected_file: Optional[str] = None,
    max_samples: Optional[int] = None,
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

    started = time.time()
    counts = {"processed": 0, "cleaned": 0, "missing": 0, "invalid": 0, "duplicate": 0, "conflict": 0, "unknown_label": 0}
    with tempfile.TemporaryDirectory(prefix=".clean_index_", dir=out_path.parent) as scratch:
        db = sqlite3.connect(Path(scratch) / "seen.sqlite")
        try:
            db.execute("PRAGMA journal_mode=OFF")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("CREATE TABLE seen (url TEXT PRIMARY KEY, label TEXT NOT NULL, conflict INTEGER NOT NULL DEFAULT 0, emitted INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID")
            # Index labels before writing any accepted row, so every conflicting
            # URL is excluded regardless of which source appeared first.
            with open(in_path, "r", encoding="utf-8-sig", newline="", buffering=16*1024*1024) as fin:
                reader = csv.DictReader(fin)
                if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
                    raise ValueError("CSV Clean can cot url va label")
                for number, row in enumerate(reader):
                    if max_samples is not None and number >= max_samples:
                        break
                    if None in row:
                        continue
                    url = (row.get("url") or "").strip()
                    label = (row.get("label") or "").strip().lower()
                    if not is_valid_url(url) or label not in VALID_LABELS:
                        continue
                    db.execute(
                        "INSERT INTO seen(url,label) VALUES (?,?) "
                        "ON CONFLICT(url) DO UPDATE SET conflict=CASE WHEN label<>excluded.label THEN 1 ELSE conflict END",
                        (url, label),
                    )
                    if number % 50000 == 0:
                        db.commit()
            db.commit()
            with open(in_path, "r", encoding="utf-8-sig", newline="", buffering=16*1024*1024) as fin, \
                 open(out_path, "w", encoding="utf-8", newline="", buffering=16*1024*1024) as fout, \
                 open(rej_path, "w", encoding="utf-8", newline="", buffering=4*1024*1024) as frej:
                reader = csv.DictReader(fin)
                if not reader.fieldnames or not {"url", "label"}.issubset(reader.fieldnames):
                    raise ValueError("CSV Clean can cot url va label")
                fields = list(reader.fieldnames)
                accepted = csv.DictWriter(fout, fieldnames=fields)
                rejected = csv.DictWriter(frej, fieldnames=[*fields, "_aic211_reject_reason"])
                accepted.writeheader()
                rejected.writeheader()
                for number, row in enumerate(reader):
                    if max_samples is not None and number >= max_samples:
                        break
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
                        else:
                            state = db.execute("SELECT conflict,emitted FROM seen WHERE url=?", (url,)).fetchone()
                            if state is None:
                                raise RuntimeError(f"Khong co URL trong index: {url}")
                            if state[0]:
                                reason = "conflicting_labels"
                                counts["conflict"] += 1
                            elif state[1]:
                                reason = "duplicate_url"
                                counts["duplicate"] += 1
                            else:
                                db.execute("UPDATE seen SET emitted=1 WHERE url=?", (url,))
                                reason = ""
                    if reason:
                        rejected.writerow({**row, "_aic211_reject_reason": reason})
                    else:
                        accepted.writerow(row)
                        counts["cleaned"] += 1
                    if counts["processed"] % 50000 == 0:
                        db.commit()
            db.commit()
        finally:
            db.close()
    elapsed = round(time.time() - started, 2)
    logger.info(
        "Hoan thanh Buoc 04 -> %s dong hop le, %s trung URL, %s xung dot nhan, %s thieu, %s sai URL trong %ss: %s",
        f"{counts['cleaned']:,}", f"{counts['duplicate']:,}", f"{counts['conflict']:,}", f"{counts['missing']:,}",
        f"{counts['invalid']:,}", elapsed, out_path.name,
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
