from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import math
import multiprocessing as mp
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import zipfile

try:
    import pyarrow.parquet as pq
except ImportError:
    pq = None

try:
    import rarfile
except ImportError:
    rarfile = None

try:
    import ijson
except ImportError:
    ijson = None

try:
    import pandas as pd
except ImportError:
    pd = None

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_RAW_DIR = BASE_DIR / "data" / "raw"
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"

CPU_COUNT = os.cpu_count() or 4
DEFAULT_WORKERS = min(16, max(1, CPU_COUNT - 2))

IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

SKIP_METADATA = {
    "manifest.json", "budget_plan.json", "already_present.json",
    "already_present_references.json", "catalog_additional.json",
    "catalog_expansion.json", "catalog_extra.json", "catalog_final.json",
    "catalog_initial.json", "catalog_secondary.json", "not_downloaded.json",
    "raw_events.jsonl", "readme.md", "sha256sums.txt", "verification.json",
    "download_sources.py", "session.json", "last_session.json",
}

def setup_logger(name: str = "Buoc02-TienXuLy") -> logging.Logger:
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

logger = setup_logger("Buoc02-TienXuLy")

def discover_raw_sources(raw_dir: Path) -> List[Dict[str, Any]]:
    sources: List[Dict[str, Any]] = []
    if not raw_dir.exists():
        return sources

    for f in sorted(raw_dir.rglob("*")):
        if not f.is_file() or f.name.startswith((".", "__")):
            continue
        nl = f.name.lower()
        if nl in SKIP_METADATA or nl.startswith(("publisher_", "catalog_", "manifest_")):
            continue
        if "snippet" in nl or "all_html" in nl:
            continue

        ext = f.suffix.lower()
        sz = f.stat().st_size
        if sz < 100:
            continue

        sz_mb = round(sz / (1024 * 1024), 2)
        src_name = f.parent.name if f.parent != raw_dir else "root_raw"

        if ext in (".csv", ".tsv", ".txt", ".jsonl"):
            sources.append({
                "type": "text",
                "source_name": src_name,
                "path": str(f),
                "inner_file": None,
                "size_mb": sz_mb,
            })
        elif ext == ".parquet":
            sources.append({
                "type": "parquet",
                "source_name": src_name,
                "path": str(f),
                "inner_file": None,
                "size_mb": sz_mb,
            })
        elif ext == ".json":
            sources.append({
                "type": "json",
                "source_name": src_name,
                "path": str(f),
                "inner_file": None,
                "size_mb": sz_mb,
            })
        elif ext == ".zip":
            try:
                with zipfile.ZipFile(f, "r") as zf:
                    for zname in zf.namelist():
                        zn_low = zname.lower()
                        if zn_low.endswith((".csv", ".tsv", ".txt", ".jsonl")) and not zname.startswith((".", "__")) and "readme" not in zn_low and not zn_low.endswith("manifest.txt"):
                            sources.append({
                                "type": "zip",
                                "source_name": src_name,
                                "path": str(f),
                                "inner_file": zname,
                                "size_mb": sz_mb,
                            })
            except Exception:
                pass
        elif ext == ".rar":
            opened = False
            if rarfile:
                try:
                    with rarfile.RarFile(f) as rf:
                        for rname in rf.namelist():
                            rn_low = rname.lower()
                            if rn_low.endswith((".csv", ".tsv", ".txt", ".jsonl")) and not rname.startswith((".", "__")):
                                sources.append({
                                    "type": "rar",
                                    "source_name": src_name,
                                    "path": str(f),
                                    "inner_file": rname,
                                    "size_mb": sz_mb,
                                })
                    opened = True
                except Exception:
                    opened = False
            if not opened:
                tar_exe = shutil.which("tar")
                if tar_exe:
                    try:
                        p_tar = subprocess.run([tar_exe, "-tf", str(f)], capture_output=True, text=True)
                        for line in p_tar.stdout.splitlines():
                            tname = line.strip()
                            tn_low = tname.lower()
                            if tn_low.endswith((".csv", ".tsv", ".txt", ".jsonl")) and not tname.startswith((".", "__")):
                                sources.append({
                                    "type": "rar",
                                    "source_name": src_name,
                                    "path": str(f),
                                    "inner_file": tname,
                                    "size_mb": sz_mb,
                                })
                    except Exception:
                        pass
        elif ext in (".xlsx", ".xls"):
            sources.append({
                "type": "excel",
                "source_name": src_name,
                "path": str(f),
                "inner_file": None,
                "size_mb": sz_mb,
            })

    return sources

def _map_label(val: Any, source_name: str) -> str:
    vl = str(val).lower().strip().strip('"').strip("'")
    if vl in ("0", "0.0", "benign", "safe", "ham", "good", "legitimate"):
        return "benign"
    elif vl in ("1", "1.0", "bad", "malicious", "mal"):
        return "phishing" if "phish" in source_name.lower() else "malicious"
    elif vl in ("phishing", "phish"):
        return "phishing"
    elif vl in ("malware", "trojan", "virus"):
        return "malware"
    elif vl in ("defacement", "defaced", "deface"):
        return "defacement"

    s_low = source_name.lower()
    if "phish" in s_low:
        return "phishing"
    elif "malware" in s_low or "malicious" in s_low:
        return "malware"
    elif "benign" in s_low or "tranco" in s_low or "majestic" in s_low:
        return "benign"
    return "unknown"

def _parse_single_source_worker(args: Tuple[Dict[str, Any], str, Optional[int]]) -> int:
    s_info, part_out, limit = args
    f_path = Path(s_info["path"])
    source_name = s_info["source_name"]
    s_type = s_info["type"]
    inner_file = s_info.get("inner_file")
    channel = "api_pull" if "phish" in source_name.lower() else ("agent" if "benign" in source_name.lower() or "tranco" in source_name.lower() else "syslog")

    count = 0
    with open(part_out, "w", encoding="utf-8", buffering=8*1024*1024) as fout:
        try:
            if s_type == "parquet":
                count = _process_parquet(f_path, fout, source_name, channel, limit)
            elif s_type == "rar" and inner_file:
                count = _process_rar(f_path, inner_file, fout, source_name, channel, limit)
            elif s_type == "zip" and inner_file:
                count = _process_zip(f_path, inner_file, fout, source_name, channel, limit)
            elif s_type == "json":
                count = _process_json(f_path, fout, source_name, channel, limit)
            elif s_type == "excel":
                count = _process_excel(f_path, fout, source_name, channel, limit)
            else:
                with open(f_path, "r", encoding="utf-8", errors="ignore") as fin:
                    count = _process_stream(fin, fout, source_name, channel, limit)
        except Exception as exc:
            logger.warning("Bo qua nguon %s%s: %s", f_path, f"::{inner_file}" if inner_file else "", exc)
            fout.seek(0)
            fout.truncate()
            count = 0

    return count

def _process_parquet(f_path: Path, fout, source_name: str, channel: str, limit: Optional[int]) -> int:
    if not pq:
        return 0
    count = 0
    pf = pq.ParquetFile(str(f_path))
    names = pf.schema_arrow.names

    url_col = None
    label_col = None
    for n in names:
        nl = n.lower()
        if not url_col and any(k in nl for k in ("url", "domain", "link", "webpage", "site", "host")):
            url_col = n
        elif not label_col and any(k in nl for k in ("label", "class", "target", "status", "category", "type", "is_phishing", "result")):
            label_col = n

    if not url_col:
        return 0

    cols = [url_col] + ([label_col] if label_col else [])
    for batch in pf.iter_batches(batch_size=100000, columns=cols):
        u_list = batch[url_col].to_pylist()
        l_list = batch[label_col].to_pylist() if label_col else [None] * len(u_list)

        for raw_u, raw_l in zip(u_list, l_list):
            if not raw_u:
                continue
            u = str(raw_u).strip()
            if not u or u == "None" or len(u) < 3:
                continue
            lbl = _map_label(raw_l, source_name)
            m = IP_RE.search(u)
            ip = m.group(0) if m else ""
            clean_u = u.replace('"', '""')
            clean_lbl = lbl.replace('"', '""')
            fout.write(f'"{clean_u}","{clean_lbl}","{clean_u}","{clean_lbl}","{ip}","{channel}","{source_name}"\n')
            count += 1
            if limit and count >= limit:
                break
        if limit and count >= limit:
            break

    return count

def _process_rar(f_path: Path, inner_file: str, fout, source_name: str, channel: str, limit: Optional[int]) -> int:
    tar_exe = shutil.which("tar")
    if tar_exe:
        proc = subprocess.Popen([tar_exe, "-xOf", str(f_path), inner_file], stdout=subprocess.PIPE, bufsize=8*1024*1024)
        fin = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="ignore")
        count = _process_stream(fin, fout, source_name, channel, limit)
        try:
            proc.kill()
        except Exception:
            pass
        return count
    elif rarfile:
        with rarfile.RarFile(str(f_path)) as rf, rf.open(inner_file) as bf:
            fin = io.TextIOWrapper(bf, encoding="utf-8", errors="ignore")
            return _process_stream(fin, fout, source_name, channel, limit)
    return 0

def _process_zip(f_path: Path, inner_file: str, fout, source_name: str, channel: str, limit: Optional[int]) -> int:
    with zipfile.ZipFile(f_path, "r") as zf, zf.open(inner_file) as bf:
        fin = io.TextIOWrapper(bf, encoding="utf-8", errors="ignore")
        return _process_stream(fin, fout, source_name, channel, limit)

def _process_json(f_path: Path, fout, source_name: str, channel: str, limit: Optional[int]) -> int:
    count = 0
    if ijson:
        try:
            with open(f_path, "rb") as fin:
                for item in ijson.items(fin, "item"):
                    if not isinstance(item, dict):
                        continue
                    u = item.get("url") or item.get("domain_name") or item.get("domain") or item.get("link") or ""
                    if not u:
                        continue
                    lbl_raw = item.get("label") or item.get("category") or item.get("status") or item.get("type") or ""
                    lbl = _map_label(lbl_raw, source_name)
                    m = IP_RE.search(str(u))
                    ip = m.group(0) if m else ""
                    clean_u = str(u).strip().replace('"', '""')
                    clean_lbl = lbl.replace('"', '""')
                    fout.write(f'"{clean_u}","{clean_lbl}","{clean_u}","{clean_lbl}","{ip}","{channel}","{source_name}"\n')
                    count += 1
                    if limit and count >= limit:
                        break
            return count
        except Exception:
            pass

    with open(f_path, "r", encoding="utf-8", errors="ignore") as fin:
        return _process_stream(fin, fout, source_name, channel, limit)

def _process_excel(f_path: Path, fout, source_name: str, channel: str, limit: Optional[int]) -> int:
    if not pd:
        return 0
    count = 0
    try:
        df = pd.read_excel(f_path, nrows=limit)
        url_col = None
        label_col = None
        for col in df.columns:
            cl = str(col).lower()
            if not url_col and any(k in cl for k in ("url", "domain", "link")):
                url_col = col
            elif not label_col and any(k in cl for k in ("label", "class", "target", "status")):
                label_col = col

        if not url_col:
            return 0

        for _, row in df.iterrows():
            u = str(row[url_col]).strip()
            if not u or u == "nan" or len(u) < 3:
                continue
            lbl_raw = str(row[label_col]) if label_col else ""
            lbl = _map_label(lbl_raw, source_name)
            m = IP_RE.search(u)
            ip = m.group(0) if m else ""
            clean_u = u.replace('"', '""')
            clean_lbl = lbl.replace('"', '""')
            fout.write(f'"{clean_u}","{clean_lbl}","{clean_u}","{clean_lbl}","{ip}","{channel}","{source_name}"\n')
            count += 1
            if limit and count >= limit:
                break
    except Exception:
        pass
    return count

def _process_stream(fin, fout, source_name: str, channel: str, limit: Optional[int]) -> int:
    import itertools

    first_line = fin.readline()
    if not first_line:
        return 0
    first_clean = first_line.strip()
    is_json = first_clean.startswith("{") and first_clean.endswith("}")
    sep = "\t" if "\t" in first_clean and "," not in first_clean else ","
    first_fields = next(csv.reader([first_line], delimiter=sep), []) if not is_json else []
    names = [field.strip().lower().lstrip("\ufeff") for field in first_fields]
    url_names = {"url", "urls", "domain", "domain_name", "link", "webpage", "website", "site", "host"}
    label_names = {"label", "class", "classlabel", "target", "result", "status", "type", "is_phishing"}
    has_header = any(name in url_names for name in names)
    url_idx = next((i for i, name in enumerate(names) if name in url_names), 0)
    label_idx = next((i for i, name in enumerate(names) if name in label_names and i != url_idx), -1)
    writer = csv.writer(fout)
    count = 0

    if has_header:
        records = csv.reader(fin, delimiter=sep)
        for fields in records:
            if len(fields) <= url_idx:
                continue
            u = fields[url_idx].strip()
            if len(u) < 3 or any(c in u for c in "\r\n"):
                continue
            raw_lbl = fields[label_idx] if 0 <= label_idx < len(fields) else ""
            lbl = _map_label(raw_lbl, source_name)
            match = IP_RE.search(u)
            writer.writerow([u, lbl, u, lbl, match.group(0) if match else "", channel, source_name])
            count += 1
            if limit and count >= limit:
                break
    else:
        for line in itertools.chain([first_line], fin):
            if not line.strip():
                continue
            u, lbl, ip = _parse_line_general(line, source_name)
            if len(u) < 3 or any(c in u for c in "\r\n"):
                continue
            writer.writerow([u, lbl, u, lbl, ip, channel, source_name])
            count += 1
            if limit and count >= limit:
                break
    return count

def _parse_line_general(line_str: str, source_name: str) -> Tuple[str, str, str]:
    p = line_str.strip()
    u = ""
    lbl_raw = ""
    if p.startswith("{") and p.endswith("}"):
        try:
            d = json.loads(p)
            raw_p = d.get("raw_payload", "")
            if raw_p:
                return _parse_line_general(raw_p, d.get("source_name", source_name))
            u = d.get("url") or d.get("url_raw") or d.get("domain_name") or d.get("domain") or ""
            lbl_raw = d.get("label") or d.get("label_raw") or d.get("category") or d.get("status") or ""
        except Exception:
            pass

    if not u:
        if "," in p:
            parts = next(csv.reader([p]), [])
            known_labels = {"0", "0.0", "1", "1.0", "benign", "safe", "ham", "good", "legitimate", "bad", "malicious", "mal", "phishing", "phish", "malware", "trojan", "virus", "defacement", "defaced", "deface"}
            if len(parts) >= 2 and parts[-1].strip().lower() in known_labels:
                u = ",".join(parts[:-1]).strip()
                lbl_raw = parts[-1]
            elif p.startswith(("http://", "https://", "HTTP://", "HTTPS://")):
                u = p
            elif parts and "." in parts[0] and ("/" in parts[0] or len(parts) == 2):
                u = p
            elif len(parts) == 1:
                u = parts[0].strip()
            parts = [part.strip().strip("'") for part in parts]
            for part in parts:
                if u:
                    break
                if part.startswith(("http://", "https://", "HTTP://", "HTTPS://")) or ("." in part and "/" in part and " " not in part):
                    u = part
                    break
            if not u:
                for part in parts:
                    if "." in part and len(part) >= 4 and " " not in part:
                        u = part
                        break
            if not u:
                u = parts[0]
        else:
            u = p

    lbl = _map_label(lbl_raw, source_name)
    m = IP_RE.search(u)
    ip = m.group(0) if m else ""
    return u, lbl, ip

def run_parsing(
    input_path: Optional[str] = None,
    output_file: Optional[str] = None,
    workers: Optional[int] = None,
    max_samples: Optional[int] = None,
) -> Path:
    if max_samples is not None and max_samples <= 0:
        raise ValueError("So dong mau phai duong")
    target = Path(input_path) if input_path else DATA_RAW_DIR
    out_path = Path(output_file) if output_file else DATA_PROCESSED_DIR / "01_parsed.csv"
    if target.is_file() and target.resolve() == out_path.resolve():
        raise ValueError("Input va output phai khac nhau")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    num_workers = workers or DEFAULT_WORKERS

    if target.is_file():
        ext = target.suffix.lower()
        stype = "parquet" if ext == ".parquet" else ("zip" if ext == ".zip" else ("rar" if ext == ".rar" else ("json" if ext == ".json" else "text")))
        sources = [{
            "type": stype,
            "source_name": target.parent.name,
            "path": str(target),
            "inner_file": None,
            "size_mb": round(target.stat().st_size / (1024 * 1024), 2),
        }]
    else:
        sources = discover_raw_sources(target)

    if not sources:
        raise FileNotFoundError(f"Khong tim thay nguon du lieu hop le trong: {target}")

    total_mb = sum(s["size_mb"] for s in sources)
    print(f"Phat hien {len(sources)} tep nguon trong {target.name} ({round(total_mb, 1)} MB)")
    print(f"Tien xu ly da tien trinh ({num_workers} workers song song)...", flush=True)

    temp_dir = out_path.parent / "_temp_parsing"
    temp_dir.mkdir(parents=True, exist_ok=True)

    limit_per_src = max(1, math.ceil(max_samples / len(sources))) if max_samples is not None else None
    tasks = []
    part_files = []

    for i, s in enumerate(sources):
        pf = temp_dir / f"src_part_{i:03d}.csv"
        part_files.append(pf)
        tasks.append((s, str(pf), limit_per_src))

    with mp.Pool(processes=num_workers) as pool:
        counts = pool.map(_parse_single_source_worker, tasks)

    total_parsed = sum(counts)
    t_process = round(time.time() - t0, 2)
    speed_proc = int(total_parsed / max(t_process, 0.1))
    print(f"Xong phan tich {len(sources)} nguon: {total_parsed:,} dong trong {t_process}s ({speed_proc:,} dong/s)", flush=True)

    with open(out_path, "w", encoding="utf-8", newline="") as fout:
        writer = csv.writer(fout)
        writer.writerow(["url_raw", "label_raw", "url", "label", "_aic211_ipv4", "channel", "source"])
        total_written = 0
        for pf in part_files:
            if pf.exists():
                with open(pf, "r", encoding="utf-8", newline="") as pfin:
                    if max_samples is None:
                        shutil.copyfileobj(pfin, fout, length=16 * 1024 * 1024)
                    else:
                        for row in csv.reader(pfin):
                            if total_written >= max_samples:
                                break
                            writer.writerow(row)
                            total_written += 1
                pf.unlink()
    if max_samples is not None:
        total_parsed = total_written

    try:
        temp_dir.rmdir()
    except Exception:
        pass

    elapsed_total = round(time.time() - t0, 2)
    avg_speed = int(total_parsed / max(elapsed_total, 0.1))
    logger.info(f"Hoan thanh Buoc 02 -> Da trich xuat truc tiep {total_parsed:,} ban ghi trong {elapsed_total}s ({avg_speed:,} dong/s) vao {out_path.name}")
    return out_path

def prompt_menu_input() -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
    default_in = str(DATA_RAW_DIR)
    default_out = str(DATA_PROCESSED_DIR / "01_parsed.csv")
    default_w = DEFAULT_WORKERS

    print("\nBuoc 02: Tien xu ly & Phan tich URL truc tiep tu raw")
    ans_in = input(f"Thu muc hoac file raw [Enter={Path(default_in).name}]: ").strip()
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
        run_parsing(input_path=in_file, output_file=out_file, workers=workers, max_samples=max_rows)
    else:
        parser = argparse.ArgumentParser(description="Buoc 02: Tien xu ly & Phan tich URL truc tiep tu raw")
        parser.add_argument("-i", "--input", default=None, help="Thu muc raw hoac tep csv/txt/zip/rar/parquet")
        parser.add_argument("-o", "--output", default=None, help="Tep dau ra csv")
        parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"So tien trinh (mac dinh {DEFAULT_WORKERS})")
        parser.add_argument("-s", "--samples", type=int, default=None, help="Gioi han so dong")
        args = parser.parse_args()

        run_parsing(input_path=args.input, output_file=args.output, workers=args.workers, max_samples=args.samples)
