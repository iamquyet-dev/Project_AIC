from __future__ import annotations

import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np

from url_detector.config import BATCH_SIZE, DEFAULT_MODEL, MODEL_REGISTRY, MODELS_DIR
from url_detector.extractor import LexicalFeatureExtractor, calc_entropy, tokenize_url

logger = logging.getLogger(__name__)

class ModelRuntime:

    _instance: Optional["ModelRuntime"] = None
    _cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, models_dir: Optional[Union[str, Path]] = None):
        self.models_dir = Path(models_dir) if models_dir else MODELS_DIR
        self.active_model_name: str = DEFAULT_MODEL

    @classmethod
    def get_instance(cls) -> "ModelRuntime":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def list_available_models(self) -> List[Dict[str, Any]]:
        available = []
        for key, reg in MODEL_REGISTRY.items():
            fpath = reg["file"]
            exists = fpath.exists()
            size_mb = round(fpath.stat().st_size / (1024 * 1024), 2) if exists else 0.0
            available.append({
                "key": key,
                "id": reg.get("id", key),
                "name": reg.get("name", key),
                "feature_type": reg.get("feature_type", key),
                "file_path": str(fpath),
                "exists": exists,
                "size_mb": size_mb,
                "is_active": (key == self.active_model_name),
            })
        return available

    def load_model(self, model_key_or_name: str) -> Dict[str, Any]:
        if model_key_or_name in self._cache:
            return self._cache[model_key_or_name]

        path: Optional[Path] = None
        if model_key_or_name in MODEL_REGISTRY:
            path = MODEL_REGISTRY[model_key_or_name]["file"]
        else:
            cand = self.models_dir / model_key_or_name
            if cand.exists():
                path = cand
            elif (self.models_dir / f"{model_key_or_name}.joblib").exists():
                path = self.models_dir / f"{model_key_or_name}.joblib"

        if not path or not path.exists():
            raise FileNotFoundError(f"Khong tim thay tep mo hinh: {model_key_or_name}")

        t0 = time.time()
        logger.info(f"Dang tai trong so mo hinh tu {path.name}...")
        data = joblib.load(path)
        load_time = round(time.time() - t0, 3)

        if isinstance(data, dict) and "pipeline" in data:
            entry = {
                "pipeline": data["pipeline"],
                "classes": list(data.get("classes", [])),
                "label_encoder": data.get("label_encoder"),
                "model_name": data.get("model_name", path.stem),
                "path": str(path),
                "load_time": load_time,
            }
        else:
            entry = {
                "pipeline": data,
                "classes": getattr(data, "classes_", ["benign", "malicious", "phishing"]),
                "label_encoder": None,
                "model_name": path.stem,
                "path": str(path),
                "load_time": load_time,
            }

        self._cache[model_key_or_name] = entry
        logger.info(f"Da tai thanh cong mo hinh {entry['model_name']} trong {load_time}s")
        return entry

    def set_active_model(self, model_key_or_name: str) -> None:
        self.load_model(model_key_or_name)
        self.active_model_name = model_key_or_name

    def predict(
        self,
        urls: Union[str, List[str]],
        model_name: Optional[str] = None
    ) -> Tuple[List[str], Optional[np.ndarray], float]:
        target_model = model_name or self.active_model_name
        model_entry = self.load_model(target_model)
        pipe = model_entry["pipeline"]
        classes = model_entry["classes"]

        if isinstance(urls, str):
            urls = [urls]

        t0 = time.time()
        raw_preds = pipe.predict(urls)
        has_proba = hasattr(pipe, "predict_proba")
        probs = pipe.predict_proba(urls) if has_proba else None
        latency_ms = round((time.time() - t0) * 1000, 2)

        labels = []
        for p in raw_preds:
            if isinstance(p, (int, np.integer)) and classes and 0 <= p < len(classes):
                labels.append(classes[p])
            else:
                labels.append(str(p))

        return labels, probs, latency_ms

    def batch_predict(
        self,
        urls: List[str],
        batch_size: int = BATCH_SIZE,
        model_name: Optional[str] = None
    ) -> Tuple[List[str], Optional[np.ndarray]]:
        if batch_size <= 0:
            raise ValueError("batch_size phai duong")
        target_model = model_name or self.active_model_name
        model_entry = self.load_model(target_model)
        pipe = model_entry["pipeline"]
        classes = model_entry["classes"]

        all_preds = []
        all_probs = []
        has_proba = hasattr(pipe, "predict_proba")

        for i in range(0, len(urls), batch_size):
            chunk = urls[i : i + batch_size]
            p = pipe.predict(chunk)
            all_preds.extend(p)
            if has_proba:
                all_probs.append(pipe.predict_proba(chunk))

        final_labels = [classes[idx] if isinstance(idx, (int, np.integer)) and 0 <= idx < len(classes) else str(idx) for idx in all_preds]
        final_probs = np.vstack(all_probs) if has_proba and all_probs else None
        return final_labels, final_probs
