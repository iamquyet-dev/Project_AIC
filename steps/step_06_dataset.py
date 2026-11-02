from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import random
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
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"

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

LABEL_IDS = {
    "benign": 0,
    "phishing": 1,
    "malware": 2,
    "defacement": 3,
    "malicious": 4,
}

LABEL_ALIASES = {
    "benign": "benign",
    "safe": "benign",
    "good": "benign",
    "ham": "benign",
    "legitimate": "benign",
    "0": "benign",
    "phish": "phishing",
    "phishing": "phishing",
    "bad": "phishing",
    "1": "phishing",
    "malware": "malware",
    "virus": "malware",
    "trojan": "malware",
    "exploit": "malware",
    "defacement": "defacement",
    "defaced": "defacement",
    "deface": "defacement",
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

def shuffle_file_on_disk(file_path: Path):
    if not file_path.exists():
        return
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        header = f.readline()
        lines = f.readlines()
    random.seed(42)
    random.shuffle(lines)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.writelines(lines)

def run_dataset_split(
    input_file: Optional[str] = None,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
    max_samples: Optional[int] = None,
) -> Dict[str, Any]:
    in_path = Path(input_file) if input_file else find_source_dataset()
    print(f"Chia tap du lieu: {in_path.name}")

    t0 = time.time()
    random.seed(seed)
    train_path = DATA_PROCESSED_DIR / "train.csv"
    val_path = DATA_PROCESSED_DIR / "val.csv"
    test_path = DATA_PROCESSED_DIR / "test.csv"
    version_path = DATA_PROCESSED_DIR / "dataset_version.json"

    counts = {"train": 0, "val": 0, "test": 0, "total": 0}
    class_dist = {"train": {}, "val": {}, "test": {}}

    with open(in_path, "r", encoding="utf-8-sig", errors="ignore", buffering=16*1024*1024) as f_in:
        reader = csv.reader(f_in)
        header = next(reader, None)
        if not header:
            raise ValueError(f"Tep {in_path} rong khong co du lieu.")

        url_idx = 0
        label_idx = 1
        split_idx = -1

        for idx, col in enumerate(header):
            c_lower = col.strip().lower()
            if c_lower in ("url", "urls", "domain"):
                url_idx = idx
            elif c_lower in ("label", "class", "target"):
                label_idx = idx
            elif c_lower in ("source_split", "split"):
                split_idx = idx

        out_header = list(header)
        if "label_id" not in out_header:
            out_header.append("label_id")

        with open(train_path, "w", encoding="utf-8", newline="", buffering=8*1024*1024) as f_tr, \
             open(val_path, "w", encoding="utf-8", newline="", buffering=4*1024*1024) as f_va, \
             open(test_path, "w", encoding="utf-8", newline="", buffering=4*1024*1024) as f_te:

            w_tr = csv.writer(f_tr)
            w_va = csv.writer(f_va)
            w_te = csv.writer(f_te)

            w_tr.writerow(out_header)
            w_va.writerow(out_header)
            w_te.writerow(out_header)

            for i, row in enumerate(reader):
                if max_samples and i >= max_samples:
                    break

                if not row or len(row) <= max(url_idx, label_idx):
                    continue

                raw_lbl = row[label_idx].strip().lower()
                canonical_lbl = LABEL_ALIASES.get(raw_lbl, raw_lbl)
                label_id_val = LABEL_IDS.get(canonical_lbl, 4)

                src_split = row[split_idx].strip().lower() if (split_idx >= 0 and split_idx < len(row)) else ""

                if src_split in ("test", "validation", "val", "train"):
                    target = "val" if src_split in ("validation", "val") else ("test" if src_split == "test" else "train")
                else:
                    r = random.random()
                    target = "train" if r < train_ratio else ("val" if r < train_ratio + val_ratio else "test")

                out_row = list(row)
                if "label_id" not in header:
                    out_row.append(str(label_id_val))

                if target == "train":
                    w_tr.writerow(out_row)
                elif target == "val":
                    w_va.writerow(out_row)
                else:
                    w_te.writerow(out_row)

                counts[target] += 1
                counts["total"] += 1
                class_dist[target][canonical_lbl] = class_dist[target].get(canonical_lbl, 0) + 1

                if counts["total"] % 2000000 == 0:
                    elapsed = round(time.time() - t0, 1)
                    speed = int(counts["total"] / max(elapsed, 0.1))
                    print(f"  -> Da chia: {counts['total']:,} dong ({speed:,} dong/s) [Train: {counts['train']:,}, Val: {counts['val']:,}, Test: {counts['test']:,}]...", flush=True)

    print("  -> Dang xao tron ngau nhien (shuffle) cac tap du lieu tren dia...")
    for p in (test_path, val_path, train_path):
        shuffle_file_on_disk(p)

    version_metadata = {
        "version": f"v_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(in_path),
        "total_rows": counts["total"],
        "splits": {
            "train": {"rows": counts["train"], "ratio": round(counts["train"]/max(1, counts["total"]), 4), "class_distribution": class_dist["train"]},
            "val": {"rows": counts["val"], "ratio": round(counts["val"]/max(1, counts["total"]), 4), "class_distribution": class_dist["val"]},
            "test": {"rows": counts["test"], "ratio": round(counts["test"]/max(1, counts["total"]), 4), "class_distribution": class_dist["test"]},
        }
    }
    with open(version_path, "w", encoding="utf-8") as fv:
        json.dump(version_metadata, fv, ensure_ascii=False, indent=2)

    elapsed_total = round(time.time() - t0, 2)
    avg_speed = int(counts["total"] / max(elapsed_total, 0.1))
    logger.info(
        f"Hoan thanh Buoc 06 -> Da chia tap du lieu {counts['total']:,} ban ghi trong {elapsed_total}s ({avg_speed:,} dong/s): "
        f"Train={counts['train']:,}, Val={counts['val']:,}, Test={counts['test']:,}. "
        f"Da luu: {train_path.name}, {val_path.name}, {test_path.name}"
    )
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
        args = parser.parse_args()

        run_dataset_split(input_file=args.input, train_ratio=args.train_ratio, val_ratio=args.val_ratio, test_ratio=args.test_ratio, max_samples=args.samples)
