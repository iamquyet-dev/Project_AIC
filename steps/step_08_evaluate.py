from __future__ import annotations

import argparse
import csv

csv.field_size_limit(128 * 1024 * 1024)
import hashlib
from datetime import datetime, timezone
import json
import logging
import math
import os
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from url_detector.config import (
    CLASSES,
    DATA_PROCESSED_DIR,
    FIGURES_DIR,
    METRICS_DIR,
    MODEL_REGISTRY,
    MODELS_DIR,
    PROJECT_ROOT,
    TABLES_DIR,
)
from url_detector.common import compute_performance_metrics, setup_logger
from url_detector.model_runtime import ModelRuntime

logger = setup_logger("Buoc08-DanhGia")

MODEL_DISPLAY_NAMES = {
    "svm": "1. Linear SVM (Word + Char n-grams)",
    "logistic_tfidf": "2. Logistic Regression (TF-IDF)",
    "logistic_lexical": "3. Logistic Regression (Lexical)",
}

MODEL_FILE_ALIASES = {
    "svm": ["cm_svm.png", "cm_word_char_svm.png"],
    "logistic_tfidf": ["cm_logistic_tfidf.png", "cm_word_tfidf_logistic.png"],
    "logistic_lexical": ["cm_logistic_lexical.png", "cm_lexical_logistic.png"],
}

def extra_report_dirs() -> List[Path]:
    return [Path(item.strip()) for item in os.environ.get("AIC_EXTRA_REPORT_DIRS", "").split(os.pathsep) if item.strip()]


def wilson_interval(successes: int, total: int) -> List[float]:
    if total <= 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    p = successes / total
    den = 1 + z*z / total
    center = (p + z*z / (2*total)) / den
    half = z * math.sqrt(p*(1-p)/total + z*z/(4*total*total)) / den
    return [max(0.0, center-half), min(1.0, center+half)]

def save_confusion_matrix_plot(model_key: str, metrics: Dict[str, Any]) -> None:
    cm_list = metrics.get("confusion_matrix")
    if not cm_list:
        return
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        cm = np.array(cm_list)
        fig, ax = plt.subplots(figsize=(6.5, 5.5), dpi=150)
        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.figure.colorbar(im, ax=ax)

        display_name = MODEL_DISPLAY_NAMES.get(model_key, model_key)
        ax.set(
            xticks=np.arange(len(CLASSES)),
            yticks=np.arange(len(CLASSES)),
            xticklabels=CLASSES,
            yticklabels=CLASSES,
            title=f"Ma tran nham lan - {display_name}",
            ylabel="Nhan Thuc Te (True)",
            xlabel="Nhan Du Doan (Predicted)",
        )
        plt.setp(ax.get_xticklabels(), rotation=30, ha="right", rotation_mode="anchor")

        thresh = cm.max() / 2.0 if cm.max() > 0 else 1.0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                val = cm[i, j]
                txt = f"{val:,}" if val >= 1000 else f"{val}"
                ax.text(
                    j, i, txt,
                    ha="center", va="center",
                    color="white" if val > thresh else "black",
                    fontsize=8,
                )
        fig.tight_layout()

        aliases = MODEL_FILE_ALIASES.get(model_key, [f"cm_{model_key}.png"])
        names = aliases if os.environ.get("AIC_SAVE_LEGACY_CM") == "1" else aliases[:1]
        for d in [FIGURES_DIR, *extra_report_dirs()]:
            d.mkdir(parents=True, exist_ok=True)
            for fname in names:
                fig.savefig(d / fname, dpi=150)

        plt.close(fig)
        print(f"  -> Da cap nhat bieu do ma tran: {names[0]}")
    except Exception as e:
        print(f"  -> Khong the xuat anh ma tran: {e}")

def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=16*1024*1024) as handle:
        for block in iter(lambda: handle.read(16*1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save_summary_reports(results: List[Dict[str, Any]], test_file_name: str, total_count: int, dist: Dict[str, int], provenance: Optional[Dict[str, Any]] = None) -> None:
    if not results:
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    models_summary = []
    for r in results:
        m_key = r.get("model", "")
        models_summary.append({
            "name": MODEL_DISPLAY_NAMES.get(m_key, m_key),
            "model_key": m_key,
            "accuracy": r.get("accuracy", 0.0),
            "precision_weighted": r.get("precision_weighted", 0.0),
            "recall_weighted": r.get("recall_weighted", 0.0),
            "weighted_f1": r.get("weighted_f1", 0.0),
            "macro_precision": r.get("macro_precision", 0.0),
            "macro_recall": r.get("macro_recall", 0.0),
            "macro_f1": r.get("macro_f1", 0.0),
            "latency_ms": r.get("latency_ms", 0.0),
            "per_class": r.get("per_class", {}),
            "confusion_matrix": r.get("confusion_matrix", []),
            "model_sha256": r.get("model_sha256"),
            "training_info": r.get("training_info"),
            "accuracy_ci95": r.get("accuracy_ci95", []),
            "threat_detection_rate": r.get("threat_detection_rate", 0.0),
            "false_benign_alarm_rate": r.get("false_benign_alarm_rate", 0.0),
            "threat_detection_ci95": r.get("threat_detection_ci95", []),
            "false_benign_alarm_ci95": r.get("false_benign_alarm_ci95", []),
        })

    summary_payload = {
        "timestamp": now_iso,
        "task": "multi_class_classification",
        "dataset": test_file_name,
        "total_rows": total_count,
        "classes": CLASSES,
        "class_distribution": dist,
        "provenance_verified": bool(provenance and provenance.get("verified")),
        "provenance": provenance or {"verified": False, "reason": "Báo cáo cũ không có manifest."},
        "models": models_summary,
        "plots": {name: f"outputs/figures/{aliases[0]}" for name, aliases in MODEL_FILE_ALIASES.items()},
    }

    metrics_dirs = [METRICS_DIR, *extra_report_dirs()]
    for md in metrics_dirs:
        md.mkdir(parents=True, exist_ok=True)
        target_f = md / "multiclass_summary.json"
        target_f.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    csv_lines = ["Model,Accuracy,Accuracy_CI95_Low,Accuracy_CI95_High,Threat_Detection_Rate,False_Benign_Alarm_Rate,Precision_Weighted,Recall_Weighted,Weighted_F1,Macro_Precision,Macro_Recall,Macro_F1,Latency_ms"]
    for r in results:
        m_key = r.get("model", "")
        m_name = MODEL_DISPLAY_NAMES.get(m_key, m_key)
        csv_lines.append(f'"{m_name}",{r["accuracy"]*100:.2f}%,{r["accuracy_ci95"][0]*100:.2f}%,{r["accuracy_ci95"][1]*100:.2f}%,{r["threat_detection_rate"]*100:.2f}%,{r["false_benign_alarm_rate"]*100:.2f}%,{r["precision_weighted"]*100:.2f}%,{r["recall_weighted"]*100:.2f}%,{r["weighted_f1"]*100:.2f}%,{r["macro_precision"]*100:.2f}%,{r["macro_recall"]*100:.2f}%,{r["macro_f1"]*100:.2f}%,{r.get("latency_ms", 0):.4f} ms')
    csv_content = "\n".join(csv_lines)

    md_lines = [
        "# Bang So Sanh Hieu Nang Cac Mo Hinh AIC211",
        "",
        "| Mo hinh | Accuracy (CI 95%) | Phat hien de doa | Bao nham benign | Precision (Weighted) | Recall (Weighted) | Weighted-F1 | Do tre (ms/URL) |",
        "|---|---|---|---|---|---|---|---|--|",
    ]
    for r in results:
        m_key = r.get("model", "")
        m_name = MODEL_DISPLAY_NAMES.get(m_key, m_key)
        md_lines.append(f"| **{m_name}** | {r['accuracy']*100:.2f}% ({r['accuracy_ci95'][0]*100:.2f}–{r['accuracy_ci95'][1]*100:.2f}%) | {r['threat_detection_rate']*100:.2f}% | {r['false_benign_alarm_rate']*100:.2f}% | {r['precision_weighted']*100:.2f}% | {r['recall_weighted']*100:.2f}% | {r['weighted_f1']*100:.2f}% | {r.get('latency_ms', 0):.4f} ms |")
    md_content = "\n".join(md_lines)

    table_dirs = [TABLES_DIR, *extra_report_dirs()]
    for td in table_dirs:
        td.mkdir(parents=True, exist_ok=True)
        (td / "models_comparison.csv").write_text(csv_content, encoding="utf-8")
        (td / "models_comparison.md").write_text(md_content, encoding="utf-8")

    print("\nDa cap nhat bao cao JSON va bang so sanh trong outputs/")

def load_test_samples(test_path: Path, max_samples: Optional[int] = None) -> Tuple[List[str], List[str]]:
    urls: List[str] = []
    y_true: List[str] = []

    with open(test_path, "r", encoding="utf-8-sig", errors="ignore", buffering=16*1024*1024) as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            raise ValueError(f"Tep kiem thu {test_path} rong khong co du lieu.")

        url_idx = None
        label_idx = None
        for idx, col in enumerate(header):
            c_low = col.strip().lower()
            if c_low in ("url", "urls", "domain"):
                url_idx = idx
            elif c_low in ("label", "class", "target"):
                label_idx = idx

        if url_idx is None or label_idx is None:
            raise ValueError("CSV test can cot URL va label ro rang")

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
    save_plot: bool = True,
) -> Dict[str, Any]:
    entry = runtime.load_model(model_name)
    pipe = entry["pipeline"]
    classes = entry["classes"]

    t0 = time.time()
    preds: List[str] = []
    total = len(urls)

    if total <= batch_size:
        raw_p = pipe.predict(urls)
        preds = [classes[p] if isinstance(p, (int, np.integer)) and 0 <= p < len(classes) else str(p) for p in raw_p]
    else:
        for i in range(0, total, batch_size):
            chunk = urls[i : i + batch_size]
            raw_p = pipe.predict(chunk)
            chunk_labels = [classes[p] if isinstance(p, (int, np.integer)) and 0 <= p < len(classes) else str(p) for p in raw_p]
            preds.extend(chunk_labels)
            done = min(i + batch_size, total)
            pct = round(done / total * 100, 1)
            print(f"  -> Tien do [{model_name}]: {done:,}/{total:,} URL ({pct}%)", end="\r", flush=True)
        print()

    total_eval_time = round(time.time() - t0, 2)
    speed = int(total / max(total_eval_time, 0.01))
    latency = round((total_eval_time * 1000) / max(total, 1), 4)

    if any(pred not in CLASSES for pred in preds):
        raise ValueError("Mo hinh tra ve nhan ngoai CLASSES")
    metrics = compute_performance_metrics(y_true, preds, CLASSES)
    correct = sum(actual == predicted for actual, predicted in zip(y_true, preds))
    threats = sum(actual != "benign" for actual in y_true)
    detected = sum(actual != "benign" and predicted != "benign" for actual, predicted in zip(y_true, preds))
    benign = total - threats
    false_alarms = sum(actual == "benign" and predicted != "benign" for actual, predicted in zip(y_true, preds))
    metrics.update({
        "accuracy_ci95": wilson_interval(correct, total),
        "threat_detection_rate": detected / threats if threats else 0.0,
        "threat_detection_ci95": wilson_interval(detected, threats),
        "false_benign_alarm_rate": false_alarms / benign if benign else 0.0,
        "false_benign_alarm_ci95": wilson_interval(false_alarms, benign),
    })

    print(f"\nKet qua [{model_name}] ({total:,} mau, thoi gian {total_eval_time}s - {speed:,} URL/s):")
    print(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"  CI 95% Accuracy: {metrics['accuracy_ci95'][0]*100:.2f}% - {metrics['accuracy_ci95'][1]*100:.2f}%")
    print(f"  Precision: {metrics['precision_weighted']*100:.2f}%")
    print(f"  Recall:    {metrics['recall_weighted']*100:.2f}%")
    print(f"  F1-Score:  {metrics['weighted_f1']*100:.2f}%")
    print(f"  Do tre:    {latency:.4f} ms/URL")
    print(f"  Phat hien de doa: {metrics['threat_detection_rate']*100:.2f}% ({detected:,}/{threats:,})")
    print(f"  CI 95% phat hien: {metrics['threat_detection_ci95'][0]*100:.2f}% - {metrics['threat_detection_ci95'][1]*100:.2f}%")
    print(f"  Bao nham benign: {metrics['false_benign_alarm_rate']*100:.2f}% ({false_alarms:,}/{benign:,})")
    print(f"  CI 95% bao nham: {metrics['false_benign_alarm_ci95'][0]*100:.2f}% - {metrics['false_benign_alarm_ci95'][1]*100:.2f}%")

    for cls_name, cls_m in metrics.get("per_class", {}).items():
        if cls_m["support"] > 0:
            print(f"    {cls_name:>11}: P={cls_m['precision']*100:.1f}%, R={cls_m['recall']*100:.1f}%, F1={cls_m['f1']*100:.1f}% ({cls_m['support']:,} mau)")

    metrics["model"] = model_name
    metrics["latency_ms"] = latency
    metrics["training_info"] = entry.get("training_info")
    model_path = entry.get("path")
    metrics["model_sha256"] = _file_sha256(Path(model_path)) if model_path and Path(model_path).is_file() else None

    if save_plot:
        save_confusion_matrix_plot(model_name, metrics)

    return metrics

def sample_split_uniformly(path: Path, sample_size: int, seed: int) -> Tuple[List[str], List[str], int]:
    if sample_size <= 0:
        raise ValueError("So mau moi tap phai duong")
    rng = random.Random(seed)
    urls: List[str] = []
    labels: List[str] = []
    valid_rows = 0
    with open(path, "r", encoding="utf-8-sig", errors="ignore", newline="", buffering=16*1024*1024) as handle:
        reader = csv.DictReader(handle)
        fields = {field.strip().lower(): field for field in (reader.fieldnames or [])}
        if "url" not in fields or "label" not in fields:
            raise ValueError(f"CSV thieu cot url/label: {path}")
        for row in reader:
            url = (row.get(fields["url"]) or "").strip()
            label = (row.get(fields["label"]) or "").strip().lower()
            if not url or label not in CLASSES:
                continue
            valid_rows += 1
            if len(urls) < sample_size:
                urls.append(url)
                labels.append(label)
            else:
                selected = rng.randrange(valid_rows)
                if selected < sample_size:
                    urls[selected] = url
                    labels[selected] = label
    return urls, labels, valid_rows


def run_generalization_audit(model_name: str = "all", samples_per_split: int = 100000, seed: int = 42) -> Dict[str, Any]:
    """Compare frozen models on uniform samples of train, val and test."""
    paths = {name: DATA_PROCESSED_DIR / f"{name}.csv" for name in ("train", "val", "test")}
    for path in paths.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    runtime = ModelRuntime.get_instance()
    targets = list(MODEL_REGISTRY) if model_name == "all" else [model_name]
    report: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_policy": "Uniform reservoir over all valid rows of each split; diagnostic only",
        "samples_per_split": samples_per_split,
        "seed": seed,
        "independent_domain_or_source_holdout": False,
        "model_lineage_complete": {
            key: bool((runtime.load_model(key).get("training_info") or {}).get("lineage_complete"))
            for key in targets
        },
        "splits": {},
        "models": {},
    }
    for name, path in paths.items():
        urls, labels, valid_rows = sample_split_uniformly(path, samples_per_split, seed)
        report["splits"][name] = {"valid_rows": valid_rows, "sampled_rows": len(urls)}
        for key in targets:
            result = evaluate_single_model(runtime, key, urls, labels, save_plot=False)
            report["models"].setdefault(key, {})[name] = {
                "accuracy": result["accuracy"],
                "weighted_f1": result["weighted_f1"],
                "macro_f1": result["macro_f1"],
                "per_class": result["per_class"],
            }
    for scores in report["models"].values():
        scores["train_test_f1_gap"] = round(scores["train"]["weighted_f1"] - scores["test"]["weighted_f1"], 4)
        scores["train_val_f1_gap"] = round(scores["train"]["weighted_f1"] - scores["val"]["weighted_f1"], 4)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICS_DIR / "generalization_audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def run_evaluate(
    test_file: Optional[str] = None,
    model_name: str = "all",
    samples: Optional[int] = None,
) -> List[Dict[str, Any]]:
    if samples is not None and samples <= 0:
        raise ValueError("So mau phai duong")
    test_path = Path(test_file) if test_file else (DATA_PROCESSED_DIR / "test.csv")
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
    if len(urls) < 10000:
        logger.warning("Tap danh gia chi co %s mau; khoang tin cay va ket luan theo lop co the kem on dinh", len(urls))

    runtime = ModelRuntime.get_instance()
    targets = list(MODEL_REGISTRY.keys()) if model_name == "all" else [model_name]
    results = []

    for key in targets:
        try:
            m_res = evaluate_single_model(runtime, key, urls, y_true)
            results.append(m_res)
        except Exception as e:
            print(f"\n[Bo qua] Khong the danh gia [{key}]: {e}")

    if not results:
        raise RuntimeError("Khong co mo hinh nao danh gia thanh cong")

    if len(results) > 1:
        print("\nBang so sanh hieu nang ca 3 mo hinh:")
        print(f"{'Mo hinh':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
        for r in results:
            print(f"{r['model']:<20} | {r['accuracy']*100:>8.2f}% | {r['precision_weighted']*100:>8.2f}% | {r['recall_weighted']*100:>8.2f}% | {r['weighted_f1']*100:>8.2f}%")

    dataset_hash = _file_sha256(test_path)
    manifest_path = DATA_PROCESSED_DIR / "dataset_version.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    manifest_hash = _file_sha256(manifest_path) if manifest_path.is_file() else None
    split_name = test_path.stem if test_path.parent.resolve() == DATA_PROCESSED_DIR.resolve() else None
    dataset_matches = bool(
        split_name in ("train", "val", "test")
        and manifest.get("integrity_verified") is True
        and manifest.get("splits", {}).get(split_name, {}).get("sha256") == dataset_hash
    )
    models_match = all(
        isinstance(result.get("training_info"), dict)
        and result["training_info"].get("lineage_complete") is True
        and result["training_info"].get("split_version") == manifest.get("version")
        and result["training_info"].get("split_manifest_sha256") == manifest_hash
        and result["training_info"].get("train_sha256") == manifest.get("splits", {}).get("train", {}).get("sha256")
        for result in results
    )
    provenance = {
        "verified": dataset_matches and models_match,
        "split_version": manifest.get("version") if dataset_matches else None,
        "dataset_sha256": dataset_hash,
        "dataset_matches_manifest": dataset_matches,
        "models_match_manifest": models_match,
        "scope": "Hash/file lineage only; does not establish independence of domains, sources or time.",
    }
    save_summary_reports(results, test_path.name, len(urls), dist, provenance)

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
        parser.add_argument("--audit-generalization", action="store_true", help="So sanh train/val/test bang mau deu tren toan bo moi tap")
        args = parser.parse_args()

        if args.audit_generalization:
            run_generalization_audit(model_name=args.model, samples_per_split=args.samples or 100000)
        else:
            run_evaluate(test_file=args.input, model_name=args.model, samples=args.samples)
