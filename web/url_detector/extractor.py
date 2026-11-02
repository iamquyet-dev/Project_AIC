from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

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

import __main__
import types

setattr(__main__, "LexicalFeatureExtractor", LexicalFeatureExtractor)

if "train_three_models" not in sys.modules:
    _fake_mod = types.ModuleType("train_three_models")
    _fake_mod.LexicalFeatureExtractor = LexicalFeatureExtractor
    _fake_mod.calc_entropy = calc_entropy
    _fake_mod.SUSPICIOUS_TOKENS = SUSPICIOUS_TOKENS
    _fake_mod.LEXICAL_FEATURE_NAMES = LEXICAL_FEATURE_NAMES
    sys.modules["train_three_models"] = _fake_mod
