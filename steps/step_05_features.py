from __future__ import annotations

import argparse
from collections import Counter
import csv
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
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"

CPU_COUNT = os.cpu_count() or 4
DEFAULT_WORKERS = min(16, max(1, CPU_COUNT - 2))

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

def _features_slice(args: Tuple[str, int, int, str]) -> int:
    in_file, start_pos, end_pos, part_out = args
    count = 0
    with open(in_file, "rb") as fin, open(part_out, "w", encoding="utf-8", newline="", buffering=8*1024*1024) as fout:
        writer = csv.writer(fout)
        if start_pos > 0:
            fin.seek(start_pos)
            skip_b = fin.readline()
            cur_pos = start_pos + len(skip_b)
        else:
            fin.seek(0)
            cur_pos = 0

        while cur_pos < end_pos:
            raw_b = fin.readline()
            if not raw_b:
                break
            cur_pos += len(raw_b)

            try:
                line_str = raw_b.decode("utf-8", errors="ignore").strip()
                if not line_str:
                    continue
                parts = [p.strip().strip('"') for p in line_str.split(",")]
                if len(parts) < 3:
                    continue
                if cur_pos - len(raw_b) == 0 and "source_row" in line_str:
                    continue

                source_row = parts[0]
                url = parts[1]
                label = parts[2]

                u_raw = url.strip()
                if not u_raw:
                    continue

                has_scheme = "://" in u_raw
                target = u_raw if has_scheme else ("http://" + u_raw)
                try:
                    p = urlsplit(target)
                    scheme = p.scheme.lower() if has_scheme else ""
                    host = (p.hostname or "").lower()
                    path = p.path or ""
                except Exception:
                    scheme, host, path = "", "", ""

                u_len = len(u_raw)
                digits = sum(c.isdigit() for c in u_raw)
                specials = sum(not c.isalnum() for c in u_raw)
                url_lower = u_raw.lower()

                digit_ratio = round(digits / u_len, 4) if u_len > 0 else 0.0
                special_ratio = round(specials / u_len, 4) if u_len > 0 else 0.0
                entropy = calc_entropy(u_raw)

                hostname_is_ip = 1 if is_ip_address(host) else 0
                uses_https = 1 if scheme == "https" else 0
                tld_val = parse_tld(host)
                suspicious_count = sum(url_lower.count(tok) for tok in SUSPICIOUS_TOKENS)

                writer.writerow([
                    source_row, u_raw, label, u_len, len(host), len(path),
                    entropy, digit_ratio, special_ratio, u_raw.count("."),
                    u_raw.count("-"), u_raw.count("/"), hostname_is_ip, uses_https,
                    suspicious_count, tld_val
                ])
                count += 1
            except Exception:
                continue

    return count

def run_features(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    workers: Optional[int] = None,
    max_samples: Optional[int] = None,
) -> Path:
    in_path = Path(input_file) if input_file else DATA_PROCESSED_DIR / "03_cleaned.csv"
    out_path = Path(output_file) if output_file else DATA_PROCESSED_DIR / "04_features.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        raise FileNotFoundError(f"Khong tim thay tep dau vao: {in_path}")

    file_size = in_path.stat().st_size
    num_workers = workers or DEFAULT_WORKERS
    t0 = time.time()
    header = [
        "_aic211_source_row", "url", "label", "url_length", "hostname_length",
        "path_length", "entropy", "digit_ratio", "special_ratio", "dot_count",
        "hyphen_count", "slash_count", "hostname_is_ip", "uses_https",
        "suspicious_token_count", "tld"
    ]

    print(f"Trich xuat dac trung: {in_path.name} ({round(file_size / (1024*1024), 2)} MB) - {num_workers} tien trinh", flush=True)

    if max_samples and max_samples < 500000:
        count = 0
        with open(out_path, "w", encoding="utf-8", newline="") as fout, open(in_path, "r", encoding="utf-8-sig", errors="ignore") as fin:
            writer = csv.writer(fout)
            writer.writerow(header)
            reader = csv.DictReader(fin)
            for row in reader:
                u_raw = (row.get("url") or "").strip()
                if not u_raw:
                    continue
                label = (row.get("label") or "unknown").strip()
                source_row = row.get("_aic211_source_row", count + 1)

                has_scheme = "://" in u_raw
                target = u_raw if has_scheme else ("http://" + u_raw)
                try:
                    p = urlsplit(target)
                    scheme = p.scheme.lower() if has_scheme else ""
                    host = (p.hostname or "").lower()
                    path = p.path or ""
                except Exception:
                    scheme, host, path = "", "", ""

                u_len = len(u_raw)
                digits = sum(c.isdigit() for c in u_raw)
                specials = sum(not c.isalnum() for c in u_raw)
                url_lower = u_raw.lower()

                digit_ratio = round(digits / u_len, 4) if u_len > 0 else 0.0
                special_ratio = round(specials / u_len, 4) if u_len > 0 else 0.0
                entropy = calc_entropy(u_raw)

                hostname_is_ip = 1 if is_ip_address(host) else 0
                uses_https = 1 if scheme == "https" else 0
                tld_val = parse_tld(host)
                suspicious_count = sum(url_lower.count(tok) for tok in SUSPICIOUS_TOKENS)

                writer.writerow([
                    source_row, u_raw, label, u_len, len(host), len(path),
                    entropy, digit_ratio, special_ratio, u_raw.count("."),
                    u_raw.count("-"), u_raw.count("/"), hostname_is_ip, uses_https,
                    suspicious_count, tld_val
                ])
                count += 1
                if count >= max_samples:
                    break
        elapsed = round(time.time() - t0, 2)
        avg_speed = int(count / max(elapsed, 0.1))
        logger.info(f"Hoan thanh Buoc 05 -> Da trich xuat dac trung cho {count:,} dong trong {elapsed}s ({avg_speed:,} dong/s) vao {out_path.name}")
        return out_path

    temp_dir = out_path.parent / "_temp_features"
    temp_dir.mkdir(parents=True, exist_ok=True)

    chunk_bytes = file_size // num_workers
    tasks = []
    part_files = []

    for i in range(num_workers):
        start_b = i * chunk_bytes
        end_b = file_size if i == (num_workers - 1) else (i + 1) * chunk_bytes
        p_file = temp_dir / f"part_{i:02d}.csv"
        part_files.append(p_file)
        tasks.append((str(in_path), start_b, end_b, str(p_file)))

    with mp.Pool(processes=num_workers) as pool:
        counts = pool.map(_features_slice, tasks)

    total_feat = sum(counts)
    t_process = round(time.time() - t0, 2)
    speed_proc = int(total_feat / max(t_process, 0.1))
    print(f"Xong xu ly song song: {total_feat:,} dong trong {t_process}s ({speed_proc:,} dong/s)", flush=True)

    with open(out_path, "w", encoding="utf-8", newline="") as fout:
        writer = csv.writer(fout)
        writer.writerow(header)
        for pf in part_files:
            if pf.exists():
                with open(pf, "r", encoding="utf-8", errors="ignore") as pfin:
                    shutil.copyfileobj(pfin, fout, length=16 * 1024 * 1024)
                try:
                    pf.unlink()
                except Exception:
                    pass

    try:
        temp_dir.rmdir()
    except Exception:
        pass

    elapsed_total = round(time.time() - t0, 2)
    avg_speed = int(total_feat / max(elapsed_total, 0.1))
    logger.info(f"Hoan thanh Buoc 05 -> Da trich xuat dac trung {total_feat:,} ban ghi trong {elapsed_total}s ({avg_speed:,} dong/s) vao {out_path.name}")
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
