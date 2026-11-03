from __future__ import annotations

import argparse
import csv

csv.field_size_limit(16 * 1024 * 1024)
import gc
import hashlib
import json
import logging
import os
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from url_detector.config import (
    CLASSES,
    DATA_PROCESSED_DIR,
    MODELS_DIR,
    MODEL_REGISTRY,
)
from url_detector.common import setup_logger
from url_detector.extractor import LexicalFeatureExtractor

logger = setup_logger("Buoc07-HuanLuyen")

MODEL_CONFIGS = {
    "logistic_tfidf": {
        "name": "Logistic Regression TF-IDF",
        "file": "model_word_tfidf_logistic.joblib",
    },
    "svm": {
        "name": "Linear SVM (Word + Char n-grams)",
        "file": "model_word_char_svm.joblib",
    },
    "logistic_lexical": {
        "name": "Logistic Regression Lexical",
        "file": "model_lexical_logistic.joblib",
    },
}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=16*1024*1024) as handle:
        for block in iter(lambda: handle.read(16*1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()

def build_pipeline(model_key: str) -> Pipeline:
    if model_key == "logistic_tfidf":
        return Pipeline([
            ("features", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=50000, sublinear_tf=True, stop_words=["http", "https", "www"])),
            ("classifier", SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-5, max_iter=25, tol=1e-3, random_state=42)),
        ])
    elif model_key == "svm":
        union = FeatureUnion([
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=35000, sublinear_tf=True, stop_words=["http", "https", "www"])),
            ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=35000, sublinear_tf=True)),
        ])
        return Pipeline([
            ("features", union),
            ("classifier", SGDClassifier(loss="modified_huber", penalty="l2", alpha=1e-5, max_iter=25, tol=1e-3, random_state=42)),
        ])
    elif model_key == "logistic_lexical":
        return Pipeline([
            ("features", LexicalFeatureExtractor()),
            ("scaler", StandardScaler()),
            ("classifier", SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, max_iter=25, tol=1e-3, random_state=42)),
        ])
    else:
        raise ValueError(f"Khong ro cau hinh mo hinh: {model_key}")

def load_training_data(file_path: Path, max_samples: Optional[int] = None) -> Tuple[List[str], List[str]]:
    if max_samples is not None and max_samples <= 0:
        raise ValueError("So mau phai duong")
    urls: List[str] = []
    labels: List[str] = []

    with open(file_path, "r", encoding="utf-8-sig", errors="ignore", buffering=16*1024*1024) as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            raise ValueError(f"Tep {file_path} khong co du lieu.")

        url_idx = None
        label_idx = None
        for idx, col in enumerate(header):
            c_low = col.strip().lower()
            if c_low in ("url", "urls", "domain"):
                url_idx = idx
            elif c_low in ("label", "class", "target"):
                label_idx = idx

        if url_idx is None or label_idx is None:
            raise ValueError("CSV train can cot URL va label ro rang")

        for i, row in enumerate(reader):
            if max_samples and i >= max_samples:
                break
            if len(row) > max(url_idx, label_idx):
                u = row[url_idx].strip()
                lbl = row[label_idx].strip().lower()
                if u and lbl in CLASSES:
                    urls.append(u)
                    labels.append(lbl)

    return urls, labels

def train_single_model(
    model_key: str,
    urls: List[str],
    labels: List[str],
    output_dir: Path,
    chunk_size: int = 200000,
    is_incremental: bool = False,
    training_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cfg = MODEL_CONFIGS[model_key]
    out_file = output_dir / cfg["file"]
    incremental_used = bool(is_incremental and out_file.exists())
    mode_str = "Huan luyen tang tien" if incremental_used else "Huan luyen moi"
    print(f"\n{mode_str} [{cfg['name']}] tren {len(urls):,} mau...")
    t0 = time.time()

    cls_to_idx = {c: i for i, c in enumerate(CLASSES)}
    y_indices = np.array([cls_to_idx[lbl] for lbl in labels], dtype=np.int32)
    all_class_indices = np.arange(len(CLASSES))

    if incremental_used:
        saved_obj = joblib.load(out_file)
        previous_training = saved_obj.get("training_info") if isinstance(saved_obj, dict) else None
        pipe = saved_obj["pipeline"]
        feat_step = pipe.named_steps["features"]
        clf_step = pipe.named_steps["classifier"]
        scaler_step = pipe.named_steps.get("scaler")
        print(f"  -> Da nap trong so mo hinh cu tu {out_file.name} de tiep tuc hoc.")
    else:
        previous_training = None
        pipe = build_pipeline(model_key)
        feat_step = pipe.named_steps["features"]
        clf_step = pipe.named_steps["classifier"]
        scaler_step = pipe.named_steps.get("scaler")

        unique_classes = np.arange(len(CLASSES))
        present = np.unique(y_indices)
        cw = compute_class_weight("balanced", classes=present, y=y_indices)
        cw_dict = {int(c): 1.0 for c in unique_classes}
        cw_dict.update({int(c): float(w) for c, w in zip(present, cw)})
        clf_step.set_params(class_weight=cw_dict)

        print("  -> Trich xuat dac trung...")
        t_feat0 = time.time()

        class_buckets: Dict[str, List[str]] = {c: [] for c in CLASSES}
        for u, lbl in zip(urls, labels):
            bucket = class_buckets.get(lbl)
            if bucket is not None and len(bucket) < 75000:
                bucket.append(u)

        vocab_urls: List[str] = []
        for c in CLASSES:
            vocab_urls.extend(class_buckets[c])

        random.seed(42)
        random.shuffle(vocab_urls)
        feat_step.fit(vocab_urls)
        t_feat = round(time.time() - t_feat0, 2)
        print(f"  -> Xong tu dien / dac trung tren {len(vocab_urls):,} mau phan tang trong {t_feat}s")

        if scaler_step is not None:
            sample_x = feat_step.transform(vocab_urls[:min(50000, len(vocab_urls))])
            scaler_step.fit(sample_x)
            del sample_x
            gc.collect()

    if len(urls) > chunk_size and hasattr(clf_step, "partial_fit"):
        indices = np.arange(len(urls), dtype=np.int32)
        rng = np.random.default_rng(42)
        rng.shuffle(indices)

        total_chunks = (len(urls) + chunk_size - 1) // chunk_size
        for c_idx in range(total_chunks):
            s_i = c_idx * chunk_size
            e_i = min(s_i + chunk_size, len(urls))
            batch_indices = indices[s_i:e_i]
            batch_u = [urls[idx] for idx in batch_indices]
            batch_y = y_indices[batch_indices]

            t_b0 = time.time()
            x_b = feat_step.transform(batch_u)
            if scaler_step is not None:
                x_b = scaler_step.transform(x_b)

            clf_step.partial_fit(x_b, batch_y, classes=all_class_indices)
            b_sec = round(time.time() - t_b0, 2)
            pct = round((c_idx + 1) / total_chunks * 100, 1)
            spd = int(len(batch_u) / max(b_sec, 0.01))
            print(f"  -> Lo {c_idx+1}/{total_chunks} ({pct}%): {e_i:,}/{len(urls):,} URL ({b_sec}s, {spd:,} URL/s)")
            del x_b, batch_u, batch_y, batch_indices
            gc.collect()
    else:
        indices = np.arange(len(urls), dtype=np.int32)
        rng = np.random.default_rng(42)
        rng.shuffle(indices)
        shuffled_urls = [urls[idx] for idx in indices]
        shuffled_y = y_indices[indices]

        x_all = feat_step.transform(shuffled_urls)
        if scaler_step is not None:
            x_all = scaler_step.transform(x_all)

        if hasattr(clf_step, "partial_fit"):
            clf_step.partial_fit(x_all, shuffled_y, classes=all_class_indices)
        else:
            clf_step.fit(x_all, shuffled_y)

        del x_all, shuffled_urls, shuffled_y
        gc.collect()

    output_dir.mkdir(parents=True, exist_ok=True)
    save_data = {
        "pipeline": pipe,
        "classes": CLASSES,
        "label_encoder": None,
        "model_name": model_key,
        "training_info": {
            **(training_info or {}),
            "model_key": model_key,
            "incremental": incremental_used,
            "previous_training": previous_training,
            "lineage_complete": bool(training_info and training_info.get("split_verified") and (not incremental_used or (previous_training and previous_training.get("lineage_complete")))),
        },
    }
    joblib.dump(save_data, out_file, compress=3)
    web_dir = Path(__file__).resolve().parent.parent / "web" / "models"
    if web_dir.exists() and out_file.parent.resolve() != web_dir.resolve():
        joblib.dump(save_data, web_dir / out_file.name, compress=3)
    elapsed = round(time.time() - t0, 2)
    speed = int(len(urls) / max(elapsed, 0.1))
    size_mb = round(out_file.stat().st_size / (1024 * 1024), 2)
    print(f"  -> Hoan thanh: {out_file.name} ({size_mb} MB) trong {elapsed}s ({speed:,} URL/s)")

    return {
        "key": model_key,
        "name": cfg["name"],
        "file": out_file.name,
        "size_mb": size_mb,
        "elapsed_sec": elapsed,
        "speed": speed,
        "path": out_file,
    }

def run_train(
    input_file: Optional[str] = None,
    output_dir: Optional[str] = None,
    model_choice: str = "all",
    samples: Optional[int] = None,
    is_incremental: bool = False,
) -> List[Path]:
    in_path = Path(input_file) if input_file else (DATA_PROCESSED_DIR / "train.csv")
    if not in_path.exists():
        raise FileNotFoundError(f"Khong tim thay tap du lieu train: {in_path}. Vui long chay Buoc 06 truoc.")

    out_d = Path(output_dir) if output_dir else MODELS_DIR
    out_d.mkdir(parents=True, exist_ok=True)

    t_total0 = time.time()
    s_label = f"{samples:,}" if samples else "toan bo"
    print(f"Nap du lieu train tu {in_path.name} (toi da: {s_label})...")
    urls, labels = load_training_data(in_path, max_samples=samples)
    if not urls:
        raise ValueError("Tap train khong co mau hop le")
    print(f"Da nap {len(urls):,} mau URL hop le thuoc {len(set(labels))} lop.")

    train_hash = _file_sha256(in_path)
    manifest_path = DATA_PROCESSED_DIR / "dataset_version.json"
    try:
        split_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        split_manifest = {}
    split_verified = (
        samples is None
        and in_path.resolve() == (DATA_PROCESSED_DIR / "train.csv").resolve()
        and split_manifest.get("integrity_verified") is True
        and split_manifest.get("splits", {}).get("train", {}).get("sha256") == train_hash
        and split_manifest.get("splits", {}).get("train", {}).get("rows") == len(urls)
    )
    training_info = {
        "train_path": str(in_path.resolve()),
        "train_sha256": train_hash,
        "train_bytes": in_path.stat().st_size,
        "rows_loaded": len(urls),
        "samples_requested": samples,
        "split_version": split_manifest.get("version") if split_verified else None,
        "split_manifest_sha256": _file_sha256(manifest_path) if split_verified else None,
        "split_verified": split_verified,
        "training_code_sha256": _file_sha256(Path(__file__)),
        "extractor_code_sha256": _file_sha256(Path(__file__).resolve().parent.parent / "url_detector" / "extractor.py"),
    }

    dist = {}
    for lbl in labels:
        dist[lbl] = dist.get(lbl, 0) + 1
    dist_str = ", ".join(f"{k}: {v:,}" for k, v in sorted(dist.items()))
    print(f"Phan bo lop: {dist_str}")

    targets = list(MODEL_CONFIGS.keys()) if model_choice == "all" else [model_choice]
    print(f"Khoi dong huan luyen {len(targets)} mo hinh: {', '.join(MODEL_CONFIGS[k]['name'] for k in targets)}...")

    summary_list = []
    saved_paths = []

    for key in targets:
        info = train_single_model(key, urls, labels, out_d, is_incremental=is_incremental, training_info=training_info)
        summary_list.append(info)
        saved_paths.append(info["path"])

    total_sec = round(time.time() - t_total0, 2)

    if len(summary_list) > 1:
        print("\nTong ket huan luyen ca 3 mo hinh:")
        print(f"{'Mo hinh':<35} | {'Dung luong':<10} | {'Thoi gian':<10} | {'Toc do':<12}")
        for s in summary_list:
            print(f"{s['name']:<35} | {s['size_mb']:>7.2f} MB | {s['elapsed_sec']:>8.2f}s | {s['speed']:>8,} URL/s")

    logger.info(f"Hoan thanh Buoc 07 -> Huan luyen xong {len(saved_paths)} mo hinh trong {total_sec}s")
    return saved_paths

def prompt_menu_input(ask_model: bool = True) -> Tuple[Optional[str], Optional[str], str, Optional[int], bool]:
    default_in = str(DATA_PROCESSED_DIR / "train.csv")
    default_out = str(MODELS_DIR)

    print("\nBuoc 07: Huan luyen mo hinh (Train Models)")
    ans_in = input(f"File du lieu train [Enter={Path(default_in).name}]: ").strip()
    in_file = ans_in if ans_in else default_in

    print("1. Huan luyen moi tu dau (Xoa cu hoc lai tu dau - Mac dinh)")
    print("2. Huan luyen tang tien tiep tuc (Giu nguyen trong so cu, hoc them du lieu)")
    choice_inc = input("Chon [1-2, Enter=1]: ").strip()
    is_inc = (choice_inc == "2")

    target_model = "all"
    if ask_model:
        print("1. Huan luyen toan bo ca 3 mo hinh (Mac dinh)")
        print("2. Chi huan luyen Logistic Regression TF-IDF")
        print("3. Chi huan luyen Linear SVM (Word + Char n-grams)")
        print("4. Chi huan luyen Logistic Regression Lexical (11 dac trung co ban)")
        choice_m = input("Chon [1-4, Enter=1]: ").strip()
        models_map = {"1": "all", "2": "logistic_tfidf", "3": "svm", "4": "logistic_lexical"}
        target_model = models_map.get(choice_m, "all")

    print("1. 100,000 dong (Kiem thu nhanh)")
    print("2. 500,000 dong (Can bang)")
    print("3. 1,000,000 dong (Chat luong cao)")
    print("4. Toan bo du lieu trong file (Mac dinh)")
    print("5. Tu nhap so dong")
    choice_s = input("Chon [1-5, Enter=4]: ").strip()
    if choice_s == "1":
        samples = 100000
    elif choice_s == "2":
        samples = 500000
    elif choice_s == "3":
        samples = 1000000
    elif choice_s == "5":
        custom = input("Nhap so dong muon train: ").strip()
        samples = int(custom) if custom.isdigit() and int(custom) > 0 else None
    else:
        samples = None

    return in_file, default_out, target_model, samples, is_inc

if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_f, out_d, mdl, smp, inc = prompt_menu_input()
        run_train(input_file=in_f, output_dir=out_d, model_choice=mdl, samples=smp, is_incremental=inc)
    else:
        parser = argparse.ArgumentParser(description="Buoc 07: Huan luyen mo hinh (Train)")
        parser.add_argument("-i", "--input", default=None, help="Tep train.csv")
        parser.add_argument("-o", "--output", default=None, help="Thu muc luu model")
        parser.add_argument("-m", "--model", default="all", choices=["logistic_tfidf", "svm", "logistic_lexical", "all"], help="Chon mo hinh")
        parser.add_argument("-s", "--samples", type=int, default=None, help="So luong mau train")
        parser.add_argument("--incremental", action="store_true", help="Hoc tang tien tiep tuc")
        args = parser.parse_args()

        run_train(input_file=args.input, output_dir=args.output, model_choice=args.model, samples=args.samples, is_incremental=args.incremental)
