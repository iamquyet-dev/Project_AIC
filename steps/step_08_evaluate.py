from __future__ import annotations

import argparse
import csv
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from url_detector.config import (
    CLASSES,
    DATA_PROCESSED_DIR,
    MODEL_REGISTRY,
    MODELS_DIR,
)
from url_detector.common import compute_performance_metrics, setup_logger
from url_detector.model_runtime import ModelRuntime

logger = setup_logger("Buoc08-DanhGia")

def load_test_samples(test_path: Path, max_samples: Optional[int] = None) -> Tuple[List[str], List[str]]:
    urls: List[str] = []
    y_true: List[str] = []

    with open(test_path, "r", encoding="utf-8-sig", errors="ignore", buffering=16*1024*1024) as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            raise ValueError(f"Tep kiem thu {test_path} rong khong co du lieu.")

        url_idx = 1
        label_idx = 2
        for idx, col in enumerate(header):
            c_low = col.strip().lower()
            if c_low in ("url", "urls", "domain"):
                url_idx = idx
            elif c_low in ("label", "class", "target"):
                label_idx = idx

        for i, row in enumerate(reader):
            if max_samples and i >= max_samples:
                break
            if len(row) > max(url_idx, label_idx):
                u = row[url_idx].strip()
                lbl = row[label_idx].strip().lower()
                if u and lbl in CLASSES:
                    urls.append(u)
                    y_true.append(lbl)

    return urls, y_true

def evaluate_single_model(
    runtime: ModelRuntime,
    model_name: str,
    urls: List[str],
    y_true: List[str],
    batch_size: int = 50000,
) -> Dict[str, Any]:
    entry = runtime.load_model(model_name)
    pipe = entry["pipeline"]
    classes = entry["classes"]

    t0 = time.time()
    preds: List[str] = []
    total = len(urls)

    if total <= batch_size:
        raw_p = pipe.predict(urls)
        preds = [classes[p] if isinstance(p, (int, np.integer)) and p < len(classes) else str(p) for p in raw_p]
    else:
        for i in range(0, total, batch_size):
            chunk = urls[i : i + batch_size]
            raw_p = pipe.predict(chunk)
            chunk_labels = [classes[p] if isinstance(p, (int, np.integer)) and p < len(classes) else str(p) for p in raw_p]
            preds.extend(chunk_labels)
            done = min(i + batch_size, total)
            pct = round(done / total * 100, 1)
            print(f"  -> Tien do [{model_name}]: {done:,}/{total:,} URL ({pct}%)", end="\r", flush=True)
        print()

    total_eval_time = round(time.time() - t0, 2)
    speed = int(total / max(total_eval_time, 0.01))
    latency = round((total_eval_time * 1000) / max(total, 1), 4)

    metrics = compute_performance_metrics(y_true, preds, CLASSES)

    print(f"\nKet qua [{model_name}] ({total:,} mau, thoi gian {total_eval_time}s - {speed:,} URL/s):")
    print(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"  Precision: {metrics['precision_weighted']*100:.2f}%")
    print(f"  Recall:    {metrics['recall_weighted']*100:.2f}%")
    print(f"  F1-Score:  {metrics['weighted_f1']*100:.2f}%")
    print(f"  Do tre:    {latency:.4f} ms/URL")

    for cls_name, cls_m in metrics.get("per_class", {}).items():
        if cls_m["support"] > 0:
            print(f"    {cls_name:>11}: P={cls_m['precision']*100:.1f}%, R={cls_m['recall']*100:.1f}%, F1={cls_m['f1']*100:.1f}% ({cls_m['support']:,} mau)")

    metrics["model"] = model_name
    metrics["latency_ms"] = latency
    return metrics

def run_evaluate(
    test_file: Optional[str] = None,
    model_name: str = "all",
    samples: Optional[int] = None,
) -> List[Dict[str, Any]]:
    test_path = Path(test_file) if test_file else (DATA_PROCESSED_DIR / "test.csv")
    if not test_path.exists():
        for cand in [DATA_PROCESSED_DIR / "val.csv", DATA_PROCESSED_DIR / "04_features.csv"]:
            if cand.exists():
                test_path = cand
                break

    if not test_path.exists():
        raise FileNotFoundError(f"Khong tim thay tap kiem thu: {test_path}. Vui long chay Buoc 06 truoc.")

    s_label = f"{samples:,}" if samples else "toan bo"
    print(f"Nap tap kiem thu tu {test_path.name} (toi da: {s_label})...")
    urls, y_true = load_test_samples(test_path, max_samples=samples)

    if not urls:
        raise ValueError(f"Khong co URL kiem thu hop le nao trong {test_path.name}")

    dist = {}
    for lbl in y_true:
        dist[lbl] = dist.get(lbl, 0) + 1
    dist_str = ", ".join(f"{k}: {v:,}" for k, v in sorted(dist.items()))
    print(f"Da nap {len(urls):,} mau URL kiem thu ({dist_str})")

    runtime = ModelRuntime.get_instance()
    targets = list(MODEL_REGISTRY.keys()) if model_name == "all" else [model_name]
    results = []

    for key in targets:
        try:
            m_res = evaluate_single_model(runtime, key, urls, y_true)
            results.append(m_res)
        except Exception as e:
            print(f"\n[Bo qua] Khong the danh gia [{key}]: {e}")

    if len(results) > 1:
        print("\nBang so sanh hieu nang ca 3 mo hinh:")
        print(f"{'Mo hinh':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
        for r in results:
            print(f"{r['model']:<20} | {r['accuracy']*100:>8.2f}% | {r['precision_weighted']*100:>8.2f}% | {r['recall_weighted']*100:>8.2f}% | {r['weighted_f1']*100:>8.2f}%")

    logger.info(f"Hoan thanh Buoc 08 -> Da danh gia {len(results)} mo hinh tren {len(urls):,} mau kiem thu")
    return results

def prompt_menu_input() -> Tuple[Optional[str], str, Optional[int]]:
    print("\nBuoc 08: Danh gia mo hinh (Evaluate Models)")
    print("1. Tap test.csv (Kiem thu cuoi cung - Mac dinh)")
    print("2. Tap val.csv (Kiem dinh thu nghiem)")
    print("3. Tu nhap duong dan file khac")
    choice_f = input("Chon tap du lieu [1-3, Enter=1]: ").strip()
    if choice_f == "2":
        in_file = str(DATA_PROCESSED_DIR / "val.csv")
    elif choice_f == "3":
        custom = input("Nhap duong dan file: ").strip()
        in_file = custom if custom else str(DATA_PROCESSED_DIR / "test.csv")
    else:
        in_file = str(DATA_PROCESSED_DIR / "test.csv")

    print("1. Danh gia ca 3 mo hinh va so sanh (Mac dinh)")
    print("2. Chi danh gia Logistic Regression TF-IDF")
    print("3. Chi danh gia Support Vector Machine (SVM)")
    print("4. Chi danh gia Logistic Regression Lexical")
    choice_m = input("Chon [1-4, Enter=1]: ").strip()
    models_map = {"1": "all", "2": "logistic_tfidf", "3": "svm", "4": "logistic_lexical"}
    target_model = models_map.get(choice_m, "all")

    print("1. 1,000 dong (Kiem thu nhanh)")
    print("2. 5,000 dong (Can bang)")
    print("3. 20,000 dong")
    print("4. 100,000 dong")
    print("5. Toan bo du lieu kiem thu (Mac dinh)")
    print("6. Tu nhap so dong")
    choice_s = input("Chon [1-6, Enter=5]: ").strip()
    if choice_s == "1":
        samples = 1000
    elif choice_s == "2":
        samples = 5000
    elif choice_s == "3":
        samples = 20000
    elif choice_s == "4":
        samples = 100000
    elif choice_s == "6":
        custom = input("Nhap so dong: ").strip()
        samples = int(custom) if custom.isdigit() and int(custom) > 0 else None
    else:
        samples = None

    return in_file, target_model, samples

if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_f, mdl, smp = prompt_menu_input()
        run_evaluate(test_file=in_f, model_name=mdl, samples=smp)
    else:
        parser = argparse.ArgumentParser(description="Buoc 08: Danh gia mo hinh (Evaluate)")
        parser.add_argument("-i", "--input", default=None, help="Tep kiem thu (test.csv hoac val.csv)")
        parser.add_argument("-m", "--model", default="all", choices=["logistic_tfidf", "svm", "logistic_lexical", "all"], help="Ten mo hinh")
        parser.add_argument("-s", "--samples", type=int, default=None, help="So luong mau kiem thu")
        args = parser.parse_args()

        run_evaluate(test_file=args.input, model_name=args.model, samples=args.samples)
