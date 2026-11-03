from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import types
from urllib.parse import urlsplit

import joblib
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

ROOT = Path(__file__).resolve().parent
MODELS_DIR = ROOT / "models"
UPLOADS_DIR = ROOT / "uploads"
REPORTS_DIR = ROOT / "reports"

SUSPICIOUS_TOKENS = (
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "banking", "bank", "confirm", "password",
    "paypal", "admin", "wallet", "authenticate", "billing", "download",
    "exe", "apk", "zip", "tar", "payload", "cmd", "powershell"
)

LEXICAL_FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "url_entropy",
    "digit_ratio", "dot_count", "hyphen_count", "slash_count",
    "is_ip", "is_https", "suspicious_token_count"
]

CLASS_LABELS = {
    "benign": "An toàn (Benign)",
    "phishing": "Lừa đảo (Phishing)",
    "malware": "Mã độc (Malware)",
    "defacement": "Giao diện (Defacement)",
    "malicious": "Độc hại (Malicious)",
    "0": "An toàn (0)",
    "1": "Độc hại (1)",
}

CLASS_COLORS = {
    "benign": "#10b981",
    "0": "#10b981",
    "phishing": "#ef4444",
    "malware": "#f97316",
    "defacement": "#8b5cf6",
    "malicious": "#e11d48",
    "1": "#e11d48",
}


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def calc_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 6)


class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):

    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        records = []
        for item in X:
            raw = str(item).strip()
            l = len(raw)
            has_scheme = "://" in raw
            target = raw if has_scheme else ("http://" + raw)
            try:
                p = urlsplit(target)
                host = p.hostname or ""
                path = p.path or ""
            except Exception:
                host, path = "", ""

            raw_lower = raw.lower()
            digit_cnt = sum(c.isdigit() for c in raw)

            is_ip = 0
            if host:
                parts = host.split(".")
                if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                    is_ip = 1

            suspicious_count = sum(raw_lower.count(tok) for tok in SUSPICIOUS_TOKENS)

            feats = [
                float(l),
                float(len(host)),
                float(len(path)),
                calc_entropy(raw),
                float(digit_cnt / max(1, l)),
                float(raw.count(".")),
                float(raw.count("-")),
                float(raw.count("/")),
                float(is_ip),
                1.0 if has_scheme and raw_lower.startswith("https://") else 0.0,
                float(suspicious_count),
            ]
            records.append(feats)

        return np.array(records, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array(LEXICAL_FEATURE_NAMES, dtype=object)


import __main__

setattr(__main__, "LexicalFeatureExtractor", LexicalFeatureExtractor)

for mod_name in (
    "train_three_models",
    "url_detector",
    "url_detector.extractor",
    "url_detector.common",
    "url_detector.detector",
    "url_detector.config",
    "url_detector.model_runtime",
    "url_detector.thresholded",
):
    if mod_name not in sys.modules:
        m = types.ModuleType(mod_name)
        m.LexicalFeatureExtractor = LexicalFeatureExtractor
        m.calc_entropy = calc_entropy
        m.SUSPICIOUS_TOKENS = SUSPICIOUS_TOKENS
        m.LEXICAL_FEATURE_NAMES = LEXICAL_FEATURE_NAMES
        sys.modules[mod_name] = m

if "url_detector" in sys.modules and "url_detector.extractor" in sys.modules:
    sys.modules["url_detector"].extractor = sys.modules["url_detector.extractor"]


def tokenize_url(url: str) -> dict:
    raw_tokens = re.findall(r"[A-Za-z0-9]+", url)
    lower_tokens = [t.lower() for t in raw_tokens]
    filtered_tokens = [t for t in lower_tokens if t not in ("http", "https", "www")]
    suspicious = [t for t in lower_tokens if t in SUSPICIOUS_TOKENS]
    try:
        p = urlsplit(url if "://" in url else "http://" + url)
        host = p.hostname or ""
        path = p.path or ""
    except Exception:
        host, path = "", ""
    return {
        "host": host,
        "path": path,
        "tokens": filtered_tokens[:50],
        "suspicious_found": list(set(suspicious)),
        "entropy": calc_entropy(url),
        "length": len(url),
    }


class ModelRegistry:
    def __init__(self, models_dir: Path):
        self.models_dir = models_dir
        self.models_cache: dict[str, dict] = {}
        self.active_model_key = "model_word_char_svm"
        self._discover_models()

    def _discover_models(self):
        default_specs = {
            "model_word_char_svm": {
                "name": "Word + char n-grams · Linear SVM",
                "file": "model_word_char_svm.joblib",
                "desc": "Mô hình Linear SVM kết hợp từ vựng và chuỗi n-gram ký tự (3-5 ký tự).",
                "type": "svm",
            },
            "model_word_tfidf_logistic": {
                "name": "Word TF-IDF · Logistic Regression",
                "file": "model_word_tfidf_logistic.joblib",
                "desc": "Mô hình Hồi quy Logistic kết hợp đặc trưng tần suất từ vựng TF-IDF.",
                "type": "logistic",
            },
            "model_lexical_logistic": {
                "name": "Lexical features · Logistic Regression",
                "file": "model_lexical_logistic.joblib",
                "desc": "Mô hình Hồi quy Logistic huấn luyện trên 11 đặc trưng cấu trúc URL.",
                "type": "lexical",
            },
        }

        self.available_models = {}
        for key, spec in default_specs.items():
            f_path = self.models_dir / spec["file"]
            if f_path.is_file():
                f_bytes = f_path.stat().st_size
                self.available_models[key] = {
                    "id": key,
                    "name": spec["name"],
                    "file": spec["file"],
                    "file_size_bytes": f_bytes,
                    "file_size_human": format_file_size(f_bytes),
                    "file_size_mb": round(f_bytes / (1024 * 1024), 2),
                    "description": spec["desc"],
                    "path": str(f_path),
                }

        for f in self.models_dir.glob("*.joblib"):
            if f.name.startswith(".vocab_cache"):
                continue
            key = f.stem
            if key not in self.available_models:
                f_bytes = f.stat().st_size
                self.available_models[key] = {
                    "id": key,
                    "name": f.stem.replace("_", " ").title(),
                    "file": f.name,
                    "file_size_bytes": f_bytes,
                    "file_size_human": format_file_size(f_bytes),
                    "file_size_mb": round(f_bytes / (1024 * 1024), 2),
                    "description": "Mô hình người dùng nạp vào hệ thống.",
                    "path": str(f),
                }

        if "model_word_char_svm" in self.available_models:
            self.active_model_key = "model_word_char_svm"
        elif self.available_models:
            self.active_model_key = list(self.available_models.keys())[0]

    def list_models(self) -> list[dict]:
        res = []
        for k, v in self.available_models.items():
            item = dict(v)
            item["is_active"] = (k == self.active_model_key)
            res.append(item)
        return res

    def get_model(self, key: str | None = None) -> dict:
        target_key = key or self.active_model_key
        if target_key not in self.available_models:
            raise ValueError(f"Không tìm thấy mô hình: {target_key}")

        if target_key not in self.models_cache:
            m_path = Path(self.available_models[target_key]["path"])
            loaded = joblib.load(m_path)

            if isinstance(loaded, dict) and "pipeline" in loaded:
                pipe = loaded["pipeline"]
                classes = loaded.get("classes", ["benign", "malicious"])
                model_name = loaded.get("model_name", self.available_models[target_key]["name"])
            else:
                pipe = loaded
                classes = getattr(pipe, "classes_", ["benign", "malicious"])
                model_name = self.available_models[target_key]["name"]

            self.models_cache[target_key] = {
                "pipeline": pipe,
                "classes": list(classes),
                "name": model_name,
                "key": target_key,
            }

        return self.models_cache[target_key]

    def set_active_model(self, key: str):
        if key in self.available_models:
            self.get_model(key)
            self.active_model_key = key
            return True
        return False

    def register_uploaded_model(self, file_path: Path, name: str | None = None) -> str:
        key = file_path.stem
        test_load = joblib.load(file_path)
        dest_path = self.models_dir / file_path.name
        if file_path != dest_path:
            if dest_path.exists():
                raise FileExistsError(f"Mô hình đã tồn tại: {dest_path.name}")
            import shutil
            shutil.copy2(file_path, dest_path)

        display_name = name or key.replace("_", " ").title()
        f_bytes = dest_path.stat().st_size
        self.available_models[key] = {
            "id": key,
            "name": display_name,
            "file": dest_path.name,
            "file_size_bytes": f_bytes,
            "file_size_human": format_file_size(f_bytes),
            "file_size_mb": round(f_bytes / (1024 * 1024), 2),
            "description": "Mô hình người dùng nạp vào hệ thống.",
            "path": str(dest_path),
        }
        self.active_model_key = key
        if key in self.models_cache:
            del self.models_cache[key]
        self.get_model(key)
        return key


REGISTRY = ModelRegistry(MODELS_DIR)


def predict_urls(urls: list[str], model_key: str | None = None) -> list[dict]:
    model_obj = REGISTRY.get_model(model_key)
    pipe = model_obj["pipeline"]
    classes = model_obj["classes"]

    clean_urls = [str(u).strip() for u in urls if str(u).strip()]
    if not clean_urls:
        return []

    try:
        probs = pipe.predict_proba(clean_urls)
    except Exception:
        decision = pipe.decision_function(clean_urls)
        exp_d = np.exp(decision - np.max(decision, axis=-1, keepdims=True))
        probs = exp_d / exp_d.sum(axis=-1, keepdims=True)

    results = []
    for i, url in enumerate(clean_urls):
        row_probs = probs[i]
        top_idx = int(np.argmax(row_probs))
        predicted_class = str(classes[top_idx])

        prob_dist = {}
        for c_idx, c_name in enumerate(classes):
            prob_dist[str(c_name)] = round(float(row_probs[c_idx]), 4)

        benign_prob = round(prob_dist.get("benign", 0.0) + prob_dist.get("0", 0.0), 4)
        risk_score = round(float(max(0.0, 1.0 - benign_prob)), 4)

        if predicted_class in ("benign", "0"):
            risk_level = "safe"
            verdict_text = "AN TOÀN (BENIGN)"
            verdict_color = "#10b981"
        elif risk_score < 0.65:
            risk_level = "suspicious"
            verdict_text = "NGHI VẤN (" + predicted_class.upper() + ")"
            verdict_color = "#f59e0b"
        else:
            risk_level = "dangerous"
            verdict_text = "ĐỘC HẠI (" + predicted_class.upper() + ")"
            verdict_color = "#ef4444"

        token_info = tokenize_url(url)

        results.append({
            "url": url,
            "predicted_class": predicted_class,
            "class_label": CLASS_LABELS.get(predicted_class, predicted_class),
            "verdict": verdict_text,
            "verdict_color": verdict_color,
            "risk_score": risk_score,
            "risk_percent": round(risk_score * 100, 1),
            "score_calibrated": False,
            "risk_level": risk_level,
            "probabilities": prob_dist,
            "classes": [str(c) for c in classes],
            "details": token_info,
            "model_name": model_obj["name"],
        })

    return results
