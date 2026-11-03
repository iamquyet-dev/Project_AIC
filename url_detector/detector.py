from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import joblib
import numpy as np

from url_detector.extractor import LexicalFeatureExtractor, tokenize_url, calc_entropy

logger = logging.getLogger(__name__)

class ThreatDetector:

    def __init__(self, model_path: Optional[Union[str, Path]] = None):
        self.model_path = Path(model_path) if model_path else None
        self.pipeline: Any = None
        self.classes: List[str] = []
        self.label_encoder: Any = None
        self.model_name: str = ""
        self.threshold: float = 0.5

        if self.model_path and self.model_path.exists():
            self.load(self.model_path)

    def load(self, model_path: Union[str, Path]) -> "ThreatDetector":
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Khong tim thay tep mo hinh: {model_path}")

        data = joblib.load(model_path)
        if isinstance(data, dict) and "pipeline" in data:
            self.pipeline = data["pipeline"]
            self.classes = list(data.get("classes", []))
            self.label_encoder = data.get("label_encoder")
            self.model_name = data.get("model_name", model_path.stem)
        else:
            self.pipeline = data
            self.classes = getattr(data, "classes_", ["benign", "malicious", "phishing"])
            self.model_name = model_path.stem

        self.model_path = model_path
        logger.info(f"Da tai bo nhan dien [{self.model_name}] voi {len(self.classes)} lop nhan.")
        return self

    def predict(self, urls: Union[str, List[str]]) -> List[Dict[str, Any]]:
        if isinstance(urls, str):
            urls = [urls]

        if not urls:
            return []

        if self.pipeline is None:
            raise RuntimeError("Pipeline mo hinh chua duoc tai. Vui long goi load() truoc.")

        preds = self.pipeline.predict(urls)

        has_proba = hasattr(self.pipeline, "predict_proba")
        probs = self.pipeline.predict_proba(urls) if has_proba else None

        results = []
        for i, url in enumerate(urls):
            pred_idx = preds[i]
            if isinstance(pred_idx, (int, np.integer)) and self.classes and 0 <= pred_idx < len(self.classes):
                label = self.classes[pred_idx]
            else:
                label = str(pred_idx)

            prob_dist = {}
            confidence = 1.0
            if probs is not None:
                prob_row = probs[i]
                for c_idx, c_name in enumerate(self.classes):
                    if c_idx < len(prob_row):
                        prob_dist[c_name] = round(float(prob_row[c_idx]), 4)
                confidence = float(np.max(prob_row))

            label_is_threat = label.lower() not in ("benign", "0", "safe")
            threat_score = 1.0 - prob_dist.get("benign", 0.0) if "benign" in prob_dist else (1.0 if label_is_threat else 0.0)
            is_threat = threat_score >= self.threshold

            results.append({
                "url": url,
                "label": label,
                "is_threat": is_threat,
                "threat_score": round(threat_score, 4),
                "confidence": round(confidence, 4),
                "probabilities": prob_dist,
            })

        return results

    def set_threshold(self, threshold: float) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Nguong phan loai phai nam trong khoang 0.0 den 1.0")
        self.threshold = threshold
