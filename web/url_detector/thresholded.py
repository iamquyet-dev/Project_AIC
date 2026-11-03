from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from url_detector.config import DEFAULT_THRESHOLD, HIGH_CONFIDENCE_THRESHOLD, SUSPICIOUS_THRESHOLD

logger = logging.getLogger(__name__)

class ThresholdManager:

    def __init__(
        self,
        default_threshold: float = DEFAULT_THRESHOLD,
        suspicious_threshold: float = SUSPICIOUS_THRESHOLD,
        critical_threshold: float = HIGH_CONFIDENCE_THRESHOLD,
    ):
        self.default_threshold = default_threshold
        self.suspicious_threshold = suspicious_threshold
        self.critical_threshold = critical_threshold

    def determine_threat_level(self, threat_prob: float) -> Dict[str, Any]:
        if not np.isfinite(threat_prob) or not 0.0 <= threat_prob <= 1.0:
            raise ValueError("Xac suat de doa phai nam trong khoang 0..1")
        if threat_prob >= self.critical_threshold:
            level = "critical"
        elif threat_prob >= self.default_threshold:
            level = "dangerous"
        elif threat_prob >= self.suspicious_threshold:
            level = "suspicious"
        else:
            level = "safe"
        return {"level": level, "is_threat": threat_prob >= self.default_threshold, "score": float(threat_prob)}

    @staticmethod
    def sweep_thresholds(
        y_true_binary: List[int],
        y_score_threat: List[float],
        thresholds: Optional[List[float]] = None
    ) -> List[Dict[str, float]]:
        if thresholds is None:
            thresholds = [round(t * 0.05, 2) for t in range(1, 20)]

        results = []
        y_true = np.array(y_true_binary)
        y_score = np.array(y_score_threat)

        for th in thresholds:
            y_pred = (y_score >= th).astype(int)
            tp = int(np.sum((y_pred == 1) & (y_true == 1)))
            fp = int(np.sum((y_pred == 1) & (y_true == 0)))
            fn = int(np.sum((y_pred == 0) & (y_true == 1)))
            tn = int(np.sum((y_pred == 0) & (y_true == 0)))

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            acc = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0

            results.append({
                "threshold": th,
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            })

        return results

    @staticmethod
    def find_best_threshold(sweep_results: List[Dict[str, float]], optimize_for: str = "f1") -> Dict[str, float]:
        if not sweep_results:
            return {"threshold": DEFAULT_THRESHOLD}
        best = max(sweep_results, key=lambda x: x.get(optimize_for, 0.0))
        return best
