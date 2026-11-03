from __future__ import annotations

import argparse
from datetime import datetime, timezone
import io
import itertools
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from url_detector.config import DATA_RAW_DIR
from url_detector.common import setup_logger

logger = setup_logger("Buoc01-ThuThap")

DATA_EXTENSIONS = {".csv", ".tsv", ".json", ".jsonl", ".txt", ".zip"}
SKIP_METADATA = {
    "manifest.json", "budget_plan.json", "already_present.json",
    "already_present_references.json", "catalog_additional.json",
    "catalog_expansion.json", "catalog_extra.json", "catalog_final.json",
    "catalog_initial.json", "catalog_secondary.json", "not_downloaded.json",
    "raw_events.jsonl", "readme.md", "sha256sums.txt", "verification.json",
    "download_sources.py", "session.json", "last_session.json",
}

def find_raw_directory(user_dir: Optional[str] = None) -> Path:
    if user_dir:
        p = Path(user_dir).expanduser().resolve()
        if p.exists():
            return p
    candidates = [
        DATA_RAW_DIR,
        Path(r"E:\Project_AIC\data\raw"),
        Path(__file__).resolve().parent.parent / "data" / "raw",
        Path("./data/raw").resolve(),
        Path("../data/raw").resolve(),
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return DATA_RAW_DIR

def is_metadata_file(name: str) -> bool:
    nl = name.lower()
    return nl in SKIP_METADATA or nl.startswith(("publisher_", "catalog_", "manifest_"))

def discover_sources(raw_dir: Path) -> List[Dict[str, Any]]:
    sources: List[Dict[str, Any]] = []
    all_items = list(raw_dir.iterdir())
    dirs = [d for d in all_items if d.is_dir() and not d.name.startswith((".", "__"))]
    root_files = [f for f in all_items if f.is_file() and not f.name.startswith((".", "__"))]

    for f in root_files:
        if is_metadata_file(f.name):
            continue
        if f.suffix.lower() in (".csv", ".txt", ".jsonl") and f.stat().st_size > 100:
            sources.append({
                "type": "file",
                "source_name": "root_raw",
                "path": f,
                "inner_file": None,
                "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
            })

    for d in sorted(dirs, key=lambda x: x.name):
        for f in d.rglob("*"):
            if not f.is_file() or f.name.startswith((".", "__")) or is_metadata_file(f.name):
                continue
            ext = f.suffix.lower()
            if ext in (".csv", ".txt", ".jsonl") and f.stat().st_size > 100:
                sources.append({
                    "type": "file",
                    "source_name": d.name,
                    "path": f,
                    "inner_file": None,
                    "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                })
            elif ext == ".zip" and "html" not in f.name.lower() and f.stat().st_size > 100:
                try:
                    with zipfile.ZipFile(f, "r") as zf:
                        for zname in zf.namelist():
                            if zname.lower().endswith((".csv", ".txt", ".jsonl")) and not zname.startswith((".", "__")) and "readme" not in zname.lower() and not zname.endswith("MANIFEST.txt"):
                                sources.append({
                                    "type": "zip",
                                    "source_name": d.name,
                                    "path": f,
                                    "inner_file": zname,
                                    "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                                })
                except Exception:
                    pass

    print(f"Tim thay {len(sources)} file nguon trong {raw_dir}:")
    for i, s in enumerate(sources, start=1):
        inner = f" -> {s['inner_file']}" if s["inner_file"] else ""
        print(f"  {i}. [{s['source_name']}] {s['path'].name}{inner} ({s['size_mb']} MB)")
    return sources

def collect_single_file(file_path: Path, out_file: Path, max_samples: Optional[int] = 5000) -> int:
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"Tep dau vao khong ton tai: {file_path}")
    if file_path == out_file.resolve():
        raise ValueError("Input va output phai khac nhau")

    limit = None if (max_samples is None or max_samples <= 0) else max_samples
    print(f"Doc file: {file_path.name} ({round(file_path.stat().st_size / (1024*1024), 2)} MB)")

    source_name = file_path.parent.name
    collected_count = 0
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with open(out_file, "w", encoding="utf-8") as fout:
        if file_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(file_path, "r") as zf:
                for zname in zf.namelist():
                    if zname.lower().endswith((".csv", ".txt", ".jsonl")):
                        with zf.open(zname) as bfin:
                            fin = io.TextIOWrapper(bfin, encoding="utf-8", errors="ignore")
                            header_line = fin.readline()
                            is_csv = "," in header_line or "\t" in header_line
                            for line_num, line in enumerate(itertools.chain([header_line], fin), start=1):
                                line_str = line.strip()
                                if not line_str or (line_num == 1 and is_csv and "http" not in line_str.lower() and "." not in line_str):
                                    continue
                                channel = "api_pull" if "phish" in source_name.lower() else ("agent" if "benign" in source_name.lower() or "tranco" in source_name.lower() else "syslog")
                                record = {
                                    "channel": channel,
                                    "source_name": source_name,
                                    "source_file": f"{file_path.name}/{zname}",
                                    "line_num": line_num,
                                    "timestamp_raw": datetime.now(timezone.utc).isoformat(),
                                    "raw_payload": line_str,
                                }
                                fout.write(json.dumps(record, ensure_ascii=False) + "\n")
                                collected_count += 1
                                if limit and collected_count >= limit:
                                    break
                    if limit and collected_count >= limit:
                        break
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fin:
                header_line = fin.readline()
                is_csv = "," in header_line or "\t" in header_line
                for line_num, line in enumerate(itertools.chain([header_line], fin), start=1):
                    line_str = line.strip()
                    if not line_str or (line_num == 1 and is_csv and "http" not in line_str.lower() and "." not in line_str):
                        continue
                    channel = "api_pull" if "phish" in source_name.lower() else ("agent" if "benign" in source_name.lower() or "tranco" in source_name.lower() else "syslog")
                    record = {
                        "channel": channel,
                        "source_name": source_name,
                        "source_file": file_path.name,
                        "line_num": line_num,
                        "timestamp_raw": datetime.now(timezone.utc).isoformat(),
                        "raw_payload": line_str,
                    }
                    fout.write(json.dumps(record, ensure_ascii=False) + "\n")
                    collected_count += 1
                    if limit and collected_count >= limit:
                        break

    print(f"Thu thap xong {collected_count:,} ban ghi vao {out_file.name}")
    return collected_count

def collect_from_sources(sources: List[Dict[str, Any]], out_file: Path, max_samples: Optional[int] = 5000) -> int:
    if not sources:
        print("Khong tim thay file du lieu.")
        return 0

    limit = None if (max_samples is None or max_samples <= 0) else max_samples
    samples_per_src = max(10, limit // max(1, min(len(sources), 50))) if limit else sys.maxsize
    collected_count = 0
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with open(out_file, "w", encoding="utf-8") as fout:
        for s in sources:
            source_name = s["source_name"]
            read_in_src = 0
            try:
                if s["type"] == "zip":
                    with zipfile.ZipFile(s["path"], "r") as zf:
                        with zf.open(s["inner_file"]) as bfin:
                            fin = io.TextIOWrapper(bfin, encoding="utf-8", errors="ignore")
                            header_line = fin.readline()
                            is_csv = "," in header_line or "\t" in header_line
                            for line_num, line in enumerate(itertools.chain([header_line], fin), start=1):
                                line_str = line.strip()
                                if not line_str or (line_num == 1 and is_csv and "http" not in line_str.lower() and "." not in line_str):
                                    continue
                                channel = "api_pull" if "phish" in source_name.lower() else ("agent" if "benign" in source_name.lower() or "tranco" in source_name.lower() else "syslog")
                                record = {
                                    "channel": channel,
                                    "source_name": source_name,
                                    "source_file": f"{s['path'].name}/{s['inner_file']}",
                                    "line_num": line_num,
                                    "timestamp_raw": datetime.now(timezone.utc).isoformat(),
                                    "raw_payload": line_str,
                                }
                                fout.write(json.dumps(record, ensure_ascii=False) + "\n")
                                collected_count += 1
                                read_in_src += 1
                                if (read_in_src >= samples_per_src) or (limit and collected_count >= limit):
                                    break
                else:
                    with open(s["path"], "r", encoding="utf-8", errors="ignore") as fin:
                        header_line = fin.readline()
                        is_csv = "," in header_line or "\t" in header_line
                        for line_num, line in enumerate(itertools.chain([header_line], fin), start=1):
                            line_str = line.strip()
                            if not line_str or (line_num == 1 and is_csv and "http" not in line_str.lower() and "." not in line_str):
                                continue
                            channel = "api_pull" if "phish" in source_name.lower() else ("agent" if "benign" in source_name.lower() or "tranco" in source_name.lower() else "syslog")
                            record = {
                                "channel": channel,
                                "source_name": source_name,
                                "source_file": s["path"].name,
                                "line_num": line_num,
                                "timestamp_raw": datetime.now(timezone.utc).isoformat(),
                                "raw_payload": line_str,
                            }
                            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
                            collected_count += 1
                            read_in_src += 1
                            if (read_in_src >= samples_per_src) or (limit and collected_count >= limit):
                                break
            except Exception as exc:
                logger.warning("Bo qua nguon %s: %s", s["path"], exc)

            if limit and collected_count >= limit:
                break

    print(f"Thu thap xong {collected_count:,} ban ghi vao {out_file.name}")
    return collected_count

def run_collection(
    input_path: Optional[str] = None,
    raw_dir: Optional[str] = None,
    sample_size: Optional[int] = 5000,
    output_path: Optional[str] = None,
) -> Path:
    target = input_path or raw_dir
    out_file = Path(output_path) if output_path else DATA_RAW_DIR / "raw_events.jsonl"

    if target:
        tp = Path(target).expanduser().resolve()
        if not tp.exists():
            raise FileNotFoundError(f"Khong tim thay nguon du lieu: {tp}")
        if out_file.resolve() == tp:
            raise ValueError("Input va output phai khac nhau")
        if tp.is_file():
            collect_single_file(tp, out_file, max_samples=sample_size)
            return out_file
        elif tp.is_dir():
            sources = discover_sources(tp)
            collect_from_sources(sources, out_file, max_samples=sample_size)
            return out_file

    auto_dir = find_raw_directory()
    sources = discover_sources(auto_dir)
    collect_from_sources(sources, out_file, max_samples=sample_size)
    return out_file

def prompt_menu_input() -> Tuple[Optional[str], Optional[int]]:
    def_dir = str(find_raw_directory())
    print("\nBuoc 01: Thu thap du lieu")
    ans_src = input(f"Duong dan raw [Enter={def_dir}]: ").strip()
    target_src = ans_src if ans_src else def_dir

    print("1. Thu thap 5,000 dong (mac dinh)")
    print("2. Thu thap 50,000 dong")
    print("3. Thu thap toan bo")
    print("4. Nhap so luong tuy y")
    choice = input("Chon [1-4, Enter=1]: ").strip()

    if choice == "2":
        s_size = 50000
    elif choice == "3":
        s_size = None
    elif choice == "4":
        custom = input("Nhap so luong dong: ").strip()
        s_size = int(custom) if custom.isdigit() else 5000
    else:
        s_size = 5000

    return target_src, s_size

if __name__ == "__main__":
    if len(sys.argv) == 1:
        target_src, s_size = prompt_menu_input()
        run_collection(input_path=target_src, sample_size=s_size)
    else:
        parser = argparse.ArgumentParser(description="Buoc 01: Thu thap du lieu (Collection)")
        parser.add_argument("-i", "--input", default=None, help="Tep du lieu hoac thu muc raw")
        parser.add_argument("--raw-dir", default=None, help="Thu muc raw")
        parser.add_argument("-s", "--samples", default="5000", help="So luong ban ghi (mac dinh 5000)")
        parser.add_argument("--all", action="store_true", help="Lay toan bo du lieu")
        parser.add_argument("-o", "--output", default=None, help="Tep jsonl dau ra")
        args = parser.parse_args()

        if args.all or str(args.samples).lower() in ("0", "all", "none"):
            s_size = None
        else:
            try:
                s_size = int(args.samples)
            except ValueError:
                s_size = 5000

        run_collection(input_path=args.input, raw_dir=args.raw_dir, sample_size=s_size, output_path=args.output)
