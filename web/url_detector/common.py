from __future__ import annotations

from collections import Counter
import json
import logging
import math
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlsplit

import numpy as np

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def setup_logger(name: str = "AIC211", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

def calc_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return float(-sum((c / length) * math.log2(c / length) for c in counts.values()))

def clean_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    u = url.strip()
    try:
        u = unquote(u)
    except Exception:
        pass
    return u

def parse_url_components(url: str) -> Dict[str, str]:
    clean = clean_url(url)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", clean):
        clean = "http://" + clean

    try:
        parts = urlsplit(clean)
        return {
            "raw": url,
            "scheme": parts.scheme.lower(),
            "netloc": parts.netloc.lower(),
            "hostname": (parts.hostname or "").lower(),
            "path": parts.path or "/",
            "query": parts.query or "",
            "fragment": parts.fragment or "",
        }
    except Exception:
        return {
            "raw": url,
        }

def compute_performance_metrics(
    y_true: List[Union[int, str]],
    y_pred: List[Union[int, str]],
    classes: List[str],
) -> Dict[str, Any]:
    cls_to_idx = {c: i for i, c in enumerate(classes)}
    n = len(classes)
    cm = [[0] * n for _ in range(n)]

    for t, p in zip(y_true, y_pred):
        t_str, p_str = str(t), str(p)
        if t_str in cls_to_idx and p_str in cls_to_idx:
            cm[cls_to_idx[t_str]][cls_to_idx[p_str]] += 1

    per_class = {}
    precisions = []
    recalls = []
    supports = []
    f1s = []

    total_correct = sum(cm[i][i] for i in range(n))
    total_samples = sum(sum(row) for row in cm)
    accuracy = total_correct / total_samples if total_samples > 0 else 0.0

    for i, cls in enumerate(classes):
        tp = cm[i][i]
        fp = sum(cm[k][i] for k in range(n) if k != i)
        fn = sum(cm[i][k] for k in range(n) if k != i)
        sup = sum(cm[i])

        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

        per_class[cls] = {
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1": round(f1, 4),
            "support": sup,
        }
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)
        supports.append(sup)

    macro_p = sum(precisions) / n if n > 0 else 0.0
    macro_r = sum(recalls) / n if n > 0 else 0.0
    macro_f1 = sum(f1s) / n if n > 0 else 0.0

    weighted_p = sum(p * s for p, s in zip(precisions, supports)) / total_samples if total_samples > 0 else 0.0
    weighted_r = sum(r * s for r, s in zip(recalls, supports)) / total_samples if total_samples > 0 else 0.0
    weighted_f1 = sum(f * s for f, s in zip(f1s, supports)) / total_samples if total_samples > 0 else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "precision_weighted": round(weighted_p, 4),
        "recall_weighted": round(weighted_r, 4),
        "weighted_f1": round(weighted_f1, 4),
        "macro_precision": round(macro_p, 4),
        "macro_recall": round(macro_r, 4),
        "macro_f1": round(macro_f1, 4),
        "per_class": per_class,
        "confusion_matrix": cm,
    }

def save_json(data: Any, path: Union[str, Path]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_json(path: Union[str, Path]) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
