from __future__ import annotations

import argparse
import csv

csv.field_size_limit(128 * 1024 * 1024)
from datetime import datetime, timezone
import json
import logging
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

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

LABEL_MAPPING = {
    "safe": "benign",
    "good": "benign",
    "ham": "benign",
    "legitimate": "benign",
    "phish": "phishing",
    "virus": "malware",
    "trojan": "malware",
    "mal": "malware",
    "defacement": "malicious",
    "defaced": "malicious",
    "deface": "malicious",
}

def setup_logger(name: str = "Buoc03-ChuanHoa") -> logging.Logger:
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

logger = setup_logger("Buoc03-ChuanHoa")

def _normalize_slice(args: Tuple[str, int, int, str, str]) -> int:
    in_file, start_pos, end_pos, part_out, ts_now = args
    count = 0
    with open(in_file, "rb") as fin, open(part_out, "w", encoding="utf-8", newline="", buffering=8*1024*1024) as fout:
        writer = csv.writer(fout)
        if start_pos > 0:
            fin.seek(start_pos - 1)
            if fin.read(1) != b"\n":
                fin.readline()
        else:
            fin.readline()  # Skip the header once.

        while fin.tell() < end_pos:
            row_start = fin.tell()
            raw = fin.readline()
            if not raw:
                break
            if not raw.strip():
                continue
            fields = next(csv.reader([raw.decode("utf-8").rstrip("\r\n")]))
            if len(fields) < 4:
                raise ValueError(f"Malformed parsed CSV row at byte {row_start}: {in_file}")
            url_raw, label_raw, url, label = fields[:4]
            ipv4 = fields[4] if len(fields) > 4 else ""
            channel = fields[5] if len(fields) > 5 else "agent"
            origin = fields[6] if len(fields) > 6 else "raw"
            source_split = fields[7] if len(fields) > 7 else ""
            observed = fields[8] if len(fields) > 8 else ""
            retrieved = fields[9] if len(fields) > 9 else ""
            verification = fields[10] if len(fields) > 10 else "unverified"
            normalized_url = (url or url_raw).strip()
            normalized_label = label.strip().lower()
            normalized_label = LABEL_MAPPING.get(normalized_label, normalized_label)
            output = [row_start, normalized_url, normalized_label, ts_now, channel, origin, ipv4, source_split]
            if len(fields) > 8:
                output.extend([url_raw, label_raw, observed, retrieved, verification])
            writer.writerow(output)
            count += 1
    return count

def run_normalize(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    workers: Optional[int] = None,
    max_samples: Optional[int] = None,
) -> Path:
    in_path = Path(input_file) if input_file else DATA_PROCESSED_DIR / "01_parsed.csv"
    out_path = Path(output_file) if output_file else DATA_PROCESSED_DIR / "02_normalized.csv"
    if in_path.resolve() == out_path.resolve():
        raise ValueError("Input va output phai khac nhau")
    if max_samples is not None and max_samples <= 0:
        raise ValueError("So dong mau phai duong")
    if workers is not None and workers <= 0:
        raise ValueError("So tien trinh phai duong")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        raise FileNotFoundError(f"Khong tim thay tep dau vao: {in_path}")

    file_size = in_path.stat().st_size
    num_workers = workers or DEFAULT_WORKERS
    logger.info(resource_log(num_workers))
    t0 = time.time()
    ts_now = datetime.now(timezone.utc).isoformat()
    header = ["_aic211_source_row", "url", "label", "timestamp_utc", "channel", "source", "_aic211_ipv4", "source_split", "url_raw", "label_raw", "source_observed_utc", "retrieved_utc", "verification_status"]

    print(f"Chuan hoa: {in_path.name} ({round(file_size / (1024*1024), 2)} MB) - {num_workers} tien trinh", flush=True)

    if max_samples is not None:
        count = 0
        with open(out_path, "w", encoding="utf-8", newline="") as fout, open(in_path, "r", encoding="utf-8-sig", errors="ignore") as fin:
            writer = csv.writer(fout)
            writer.writerow(header)
            reader = csv.DictReader(fin)
            for row in reader:
                count += 1
                u = (row.get("url") or row.get("url_raw") or "").strip()
                lbl = row.get("label") or row.get("label_raw") or ""
                lbl_norm = LABEL_MAPPING.get(lbl.lower().strip(), lbl.lower().strip())
                writer.writerow([count, u, lbl_norm, ts_now, row.get("channel", "agent"), row.get("source", "raw"), row.get("_aic211_ipv4", ""), row.get("source_split", ""), row.get("url_raw", u), row.get("label_raw", lbl), row.get("source_observed_utc", ""), row.get("retrieved_utc", ""), row.get("verification_status", "unverified")])
                if count >= max_samples:
                    break
        elapsed = round(time.time() - t0, 2)
        avg_speed = int(count / max(elapsed, 0.1))
        logger.info(f"Hoan thanh Buoc 03 -> Da chuan hoa {count:,} ban ghi trong {elapsed}s ({avg_speed:,} dong/s) vao {out_path.name}")
        return out_path

    temp_dir = out_path.parent / "_temp_normalizing"
    temp_dir.mkdir(parents=True, exist_ok=True)

    chunk_bytes = max(1, file_size // num_workers)
    tasks = []
    part_files = []

    for i in range(num_workers):
        start_b = i * chunk_bytes
        end_b = file_size if i == (num_workers - 1) else (i + 1) * chunk_bytes
        p_file = temp_dir / f"part_{i:02d}.csv"
        part_files.append(p_file)
        tasks.append((str(in_path), start_b, end_b, str(p_file), ts_now))

    with mp.Pool(processes=num_workers) as pool:
        counts = pool.map(_normalize_slice, tasks)

    total_norm = sum(counts)
    t_process = round(time.time() - t0, 2)
    speed_proc = int(total_norm / max(t_process, 0.1))
    print(f"Xong xu ly song song: {total_norm:,} dong trong {t_process}s ({speed_proc:,} dong/s)", flush=True)

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
    avg_speed = int(total_norm / max(elapsed_total, 0.1))
    logger.info(f"Hoan thanh Buoc 03 -> Da chuan hoa {total_norm:,} ban ghi trong {elapsed_total}s ({avg_speed:,} dong/s) vao {out_path.name}")
    return out_path

def prompt_menu_input() -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    default_in = str(DATA_PROCESSED_DIR / "01_parsed.csv")
    default_out = str(DATA_PROCESSED_DIR / "02_normalized.csv")
    default_w = DEFAULT_WORKERS

    print("\nBuoc 03: Chuan hoa URL")
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
        custom_r = input("Nhap so dong muon xu ly: ").strip()
        max_rows = int(custom_r) if custom_r.isdigit() and int(custom_r) > 0 else None
    else:
        max_rows = None

    return in_file, default_out, workers, max_rows

if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_file, out_file, workers, max_rows = prompt_menu_input()
        run_normalize(input_file=in_file, output_file=out_file, workers=workers, max_samples=max_rows)
    else:
        parser = argparse.ArgumentParser(description="Buoc 03: Chuan hoa du lieu (Normalize)")
        parser.add_argument("-i", "--input", default=None, help="Tep dau vao csv")
        parser.add_argument("-o", "--output", default=None, help="Tep dau ra csv")
        parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"So tien trinh (mac dinh {DEFAULT_WORKERS})")
        parser.add_argument("-s", "--samples", type=int, default=None, help="Gioi han so dong")
        args = parser.parse_args()

        run_normalize(input_file=args.input, output_file=args.output, workers=args.workers, max_samples=args.samples)
