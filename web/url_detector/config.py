from __future__ import annotations

import os
from pathlib import Path

DETECTOR_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DETECTOR_DIR.parent

DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"

OUTPUTS_DIR = PROJECT_ROOT / "outputs"
MODELS_DIR = OUTPUTS_DIR / "models"
METRICS_DIR = OUTPUTS_DIR / "metrics"
FIGURES_DIR = OUTPUTS_DIR / "figures"
TABLES_DIR = OUTPUTS_DIR / "tables"

for p in (DATA_RAW_DIR, DATA_PROCESSED_DIR, MODELS_DIR, METRICS_DIR, FIGURES_DIR, TABLES_DIR):
    p.mkdir(parents=True, exist_ok=True)

CLASSES = ["benign", "malicious", "phishing", "malware"]
DEFAULT_BENIGN_LABEL = "benign"

MODEL_REGISTRY = {
    "svm": {
        "file": MODELS_DIR / "model_word_char_svm.joblib",
    },
    "logistic_tfidf": {
        "file": MODELS_DIR / "model_word_tfidf_logistic.joblib",
    },
    "logistic_lexical": {
        "file": MODELS_DIR / "model_lexical_logistic.joblib",
    },
}

DEFAULT_MODEL = "logistic_tfidf"

DEFAULT_THRESHOLD = 0.50
HIGH_CONFIDENCE_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.40
BATCH_SIZE = 5000

SUSPICIOUS_TOKENS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "banking", "bank", "confirm", "password",
    "paypal", "admin", "wallet", "authenticate", "billing", "download",
    "invoice", "support", "service", "ebay", "appleid", "office365",
]
