from __future__ import annotations

import argparse
from collections import Counter
import csv

csv.field_size_limit(128 * 1024 * 1024)
import ipaddress
import logging
import math
import multiprocessing as mp
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PROCESSED_DIR = Path(os.environ["AIC_RUN_DIR"]).resolve() / "processed" if os.environ.get("AIC_RUN_DIR") else BASE_DIR / "data" / "processed"

CPU_COUNT = os.cpu_count() or 4
try:
    from . import safe_default_workers, resource_log
except ImportError:
    from __init__ import safe_default_workers, resource_log
DEFAULT_WORKERS = safe_default_workers()

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "biz.vn", "info.vn",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "org.tw", "edu.tw", "gov.tw",
    "com.sg", "edu.sg", "gov.sg",
    "co.za", "net.za", "org.za",
    "com.ru", "net.ru", "org.ru",
}

SUSPICIOUS_TOKENS = (
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "update", "secure", "security", "banking", "bank",
    "confirm", "confirmation", "password", "credential",
    "paypal", "ebayisapi", "webscr", "cmd=", "admin", "wallet",
    "authenticate", "billing", "recover"
)

def setup_logger(name: str = "Buoc05-DacTrung") -> logging.Logger:
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

logger = setup_logger("Buoc05-DacTrung")

def is_ip_address(host: str) -> bool:
    if not host:
        return False
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False

def parse_tld(host: str) -> str:
    if not host or is_ip_address(host):
        return ""
    cleaned = host.lower().strip(".")
    if not cleaned:
        return ""
    parts = cleaned.split(".")
    if len(parts) <= 1:
        return ""
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS:
        return last_two
    return parts[-1]

def calc_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)

FEATURE_COLUMNS = [
    "_aic211_source_row", "url", "label", "url_length", "hostname_length",
    "path_length", "entropy", "digit_ratio", "special_ratio", "dot_count",
    "hyphen_count", "slash_count", "hostname_is_ip", "uses_https",
    "suspicious_token_count", "tld", "channel", "source", "source_split",
    "url_raw", "label_raw", "source_observed_utc", "retrieved_utc", "verification_status", "timestamp_utc",
]


def _feature_values(row: Dict[str, str]) -> List[Any]:
    url = (row.get("url") or "").strip()
    if not url:
        return []
    has_scheme = "://" in url
    target = url if has_scheme else "http://" + url
    try:
        parts = urlsplit(target)
        scheme = parts.scheme.lower() if has_scheme else ""
        host = (parts.hostname or "").lower()
        path = parts.path or ""
    except ValueError:
        scheme, host, path = "", "", ""
    length = len(url)
    digits = sum(char.isdigit() for char in url)
    specials = sum(not char.isalnum() for char in url)
    return [
        row.get("_aic211_source_row", ""), url, row.get("label", "unknown"),
        length, len(host), len(path), calc_entropy(url),
        round(digits / length, 4), round(specials / length, 4),
        url.count("."), url.count("-"), url.count("/"),
        int(is_ip_address(host)), int(scheme == "https"),
        sum(url.lower().count(token) for token in SUSPICIOUS_TOKENS),
        parse_tld(host), row.get("channel", ""), row.get("source", ""), row.get("source_split", ""),
        row.get("url_raw", url), row.get("label_raw", ""), row.get("source_observed_utc", ""),
        row.get("retrieved_utc", ""), row.get("verification_status", "unverified"), row.get("timestamp_utc", ""),
    ]


def _features_slice(args: Tuple[str, int, int, str]) -> int:
    in_file, start_pos, end_pos, part_out = args
    count = 0
    with open(in_file, "rb") as fin, open(part_out, "w", encoding="utf-8", newline="", buffering=8*1024*1024) as fout:
        header_raw = fin.readline()
        header = next(csv.reader([header_raw.decode("utf-8-sig")]))
        if start_pos > 0:
            fin.seek(start_pos - 1)
            if fin.read(1) != b"\n":
                fin.readline()
        writer = csv.writer(fout)
        while fin.tell() < end_pos:
            offset = fin.tell()
            raw = fin.readline()
            if not raw:
                break
            if not raw.strip():
                continue
            fields = next(csv.reader([raw.decode("utf-8").rstrip("\r\n")], strict=True))
            if len(fields) != len(header):
                raise ValueError(f"Malformed cleaned CSV row at byte {offset}: {in_file}")
            values = _feature_values(dict(zip(header, fields)))
            if values:
                writer.writerow(values)
                count += 1
    return count


def run_features(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    workers: Optional[int] = None,
    max_samples: Optional[int] = None,
) -> Path:
    in_path = Path(input_file) if input_file else DATA_PROCESSED_DIR / "03_cleaned.csv"
    out_path = Path(output_file) if output_file else DATA_PROCESSED_DIR / "04_features.csv"
    if in_path.resolve() == out_path.resolve():
        raise ValueError("Input va output phai khac nhau")
    if not in_path.exists():
        raise FileNotFoundError(f"Khong tim thay tep dau vao: {in_path}")
    if max_samples is not None and max_samples <= 0:
        raise ValueError("So dong mau phai duong")
    requested = workers if workers is not None else DEFAULT_WORKERS
    if requested <= 0:
        raise ValueError("So tien trinh phai duong")
    num_workers = min(requested, os.cpu_count() or 1)
    logger.info(resource_log(num_workers))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()

    if max_samples is not None:
        count = 0
        with open(in_path, "r", encoding="utf-8-sig", newline="") as fin, open(out_path, "w", encoding="utf-8", newline="") as fout:
            reader = csv.DictReader(fin)
            writer = csv.writer(fout)
            writer.writerow(FEATURE_COLUMNS)
            for row in reader:
                values = _feature_values(row)
                if values:
                    writer.writerow(values)
                    count += 1
                if count >= max_samples:
                    break
    else:
        file_size = in_path.stat().st_size
        chunk_bytes = max(1, file_size // num_workers)
        temp_dir = out_path.parent / "_temp_features"
        temp_dir.mkdir(parents=True, exist_ok=True)
        tasks = []
        parts = []
        for index in range(num_workers):
            start_byte = index * chunk_bytes
            end_byte = file_size if index == num_workers - 1 else (index + 1) * chunk_bytes
            part = temp_dir / f"part_{index:02d}.csv"
            tasks.append((str(in_path), start_byte, end_byte, str(part)))
            parts.append(part)
        with mp.Pool(processes=num_workers) as pool:
            counts = pool.map(_features_slice, tasks)
        count = sum(counts)
        with open(out_path, "w", encoding="utf-8", newline="") as fout:
            csv.writer(fout).writerow(FEATURE_COLUMNS)
            for part in parts:
                with open(part, "r", encoding="utf-8", newline="") as fin:
                    shutil.copyfileobj(fin, fout, length=16 * 1024 * 1024)
                part.unlink()
        temp_dir.rmdir()

    elapsed = round(time.time() - started, 2)
    logger.info("Hoan thanh Buoc 05 -> %s dong trong %ss vao %s", f"{count:,}", elapsed, out_path.name)
    return out_path

def prompt_menu_input() -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    default_in = str(DATA_PROCESSED_DIR / "03_cleaned.csv")
    default_out = str(DATA_PROCESSED_DIR / "04_features.csv")
    default_w = DEFAULT_WORKERS

    print("\nBuoc 05: Trich xuat dac trung")
    ans_in = input(f"Tep dau vao [Enter={Path(default_in).name}]: ").strip()
    in_file = ans_in if ans_in else default_in

    print(f"1. Chay da luong ({default_w} tien trinh - mac dinh)")
    print("2. Chay nhe (8 tien trinh)")
    print("3. Tu nhap so tien trinh")
    w_choice = input("Chon [1-3, Enter=1]: ").strip()
    if w_choice == "2":
        workers = 8
    elif w_choice == "3":
        custom_w = input("Nhap so tien trinh: ").strip()
        workers = int(custom_w) if custom_w.isdigit() and int(custom_w) > 0 else default_w
    else:
        workers = default_w

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

    return in_file, default_out, workers, max_rows

if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_file, out_file, workers, max_rows = prompt_menu_input()
        run_features(input_file=in_file, output_file=out_file, workers=workers, max_samples=max_rows)
    else:
        parser = argparse.ArgumentParser(description="Buoc 05: Trich xuat dac trung (Features)")
        parser.add_argument("-i", "--input", default=None, help="Tep csv dau vao")
        parser.add_argument("-o", "--output", default=None, help="Tep csv dau ra")
        parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"So tien trinh (mac dinh {DEFAULT_WORKERS})")
        parser.add_argument("-s", "--samples", type=int, default=None, help="Gioi han so dong")
        args = parser.parse_args()

        run_features(input_file=args.input, output_file=args.output, workers=args.workers, max_samples=args.samples)
