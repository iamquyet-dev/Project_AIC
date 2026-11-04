from __future__ import annotations

import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import mimetypes
import os
from pathlib import Path
import re
import shutil
import time
import types
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
if str(ROOT.parent) not in sys.path:
    sys.path.insert(0, str(ROOT.parent))

import pandas as pd
from core import REGISTRY, predict_urls, CLASS_LABELS, CLASS_COLORS, LexicalFeatureExtractor, calc_entropy, SUSPICIOUS_TOKENS, LEXICAL_FEATURE_NAMES

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

MODELS_DIR = ROOT / "models"
UPLOADS_DIR = ROOT / "uploads"
STATIC_DIR = ROOT / "static"
REPORTS_DIR = ROOT / "reports"
METRICS_DIR = ROOT.parent / "outputs" / "metrics"
FIGURES_DIR = ROOT.parent / "outputs" / "figures"
DATASET_VERSION = ROOT.parent / "data" / "processed" / "dataset_version.json"

UPLOADS_DIR.mkdir(exist_ok=True)


def load_dataset_summary():
    if not DATASET_VERSION.is_file():
        return {"verified": False, "reason": "Chưa có metadata chia tập dữ liệu."}
    try:
        metadata = json.loads(DATASET_VERSION.read_text(encoding="utf-8"))
        splits = metadata.get("splits", {})
        current = bool(metadata.get("integrity_verified"))
        for name in ("train", "val", "test"):
            path = DATASET_VERSION.parent / f"{name}.csv"
            info = splits.get(name, {})
            if not path.is_file() or info.get("bytes") != path.stat().st_size or info.get("modified_ns") != path.stat().st_mtime_ns:
                current = False
        return {
            "verified": current,
            "reason": "Metadata chưa xác minh với các file chia tập hiện tại." if not current else "",
            "version": metadata.get("version"),
            "total_rows": metadata.get("total_rows"),
            "splits": splits,
        }
    except (OSError, ValueError, TypeError):
        return {"verified": False, "reason": "Không đọc được metadata chia tập dữ liệu."}


def verify_web_report(report: dict) -> dict:
    names = {"svm": "model_word_char_svm.joblib", "logistic_tfidf": "model_word_tfidf_logistic.joblib", "logistic_lexical": "model_lexical_logistic.joblib"}
    checks = {}
    for model in report.get("models", []):
        key = model.get("model_key")
        filename = names.get(key)
        web_path = MODELS_DIR / filename if filename else None
        output_path = ROOT.parent / "outputs" / "models" / filename if filename else None
        expected = model.get("model_sha256")
        checks[key] = bool(expected and web_path and output_path and web_path.is_file() and output_path.is_file()
                           and hashlib.sha256(web_path.read_bytes()).hexdigest() == expected
                           and hashlib.sha256(output_path.read_bytes()).hexdigest() == expected)
    summary = load_dataset_summary()
    split_version = report.get("provenance", {}).get("split_version")
    verified = bool(report.get("provenance_verified") and summary.get("verified") and split_version
                    and summary.get("version") == split_version and len(checks) == 3 and all(checks.values()))
    return {"verified": verified, "models": checks, "reason": "" if verified else "Chưa xác minh báo cáo với đủ ba model web, model đầu ra và phiên bản dữ liệu hiện tại."}


class WebAppHandler(BaseHTTPRequestHandler):
    server_version = "AIC211-Engine/1.0"

    def send_json(self, status: int, data: dict | list):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_file_response(self, file_path: Path, mime_type: str | None = None):
        if not file_path.is_file():
            self.send_json(404, {"error": "Không tìm thấy file."})
            return
        if not mime_type:
            mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        if mime_type.startswith("text/") or mime_type in ("application/javascript", "application/json"):
            if "charset" not in mime_type:
                mime_type = f"{mime_type}; charset=utf-8"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url_parts = urlsplit(self.path)
        path = url_parts.path

        if path == "/api/status":
            self.send_json(200, {
                "status": "ready",
                "active_model": REGISTRY.active_model_key,
                "models": REGISTRY.list_models(),
                "class_labels": CLASS_LABELS,
                "class_colors": CLASS_COLORS,
                "dataset_summary": load_dataset_summary(),
            })
            return

        if path == "/api/models":
            self.send_json(200, {
                "active": REGISTRY.active_model_key,
                "models": REGISTRY.list_models()
            })
            return

        if path == "/api/metrics":
            summary_path = METRICS_DIR / "multiclass_summary.json"
            if not summary_path.is_file():
                summary_path = REPORTS_DIR / "multiclass_summary.json"
            if summary_path.is_file():
                report = json.loads(summary_path.read_text(encoding="utf-8"))
                report["web_report_match"] = verify_web_report(report)
                self.send_json(200, report)
            else:
                self.send_json(200, {"message": "Chưa có file báo cáo multiclass_summary.json"})
            return

        if path.startswith("/reports/"):
            rel_name = path.removeprefix("/reports/")
            if Path(rel_name).name != rel_name:
                self.send_json(404, {"error": "Không tìm thấy file."})
                return
            target_f = FIGURES_DIR / rel_name
            if not target_f.is_file():
                target_f = REPORTS_DIR / rel_name
            self.send_file_response(target_f)
            return

        if path == "/" or path == "/index.html":
            self.send_file_response(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if path == "/styles.css":
            self.send_file_response(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
            return
        if path == "/app.js":
            self.send_file_response(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
            return

        candidate = (STATIC_DIR / path.lstrip("/")).resolve()
        if not candidate.is_relative_to(STATIC_DIR.resolve()):
            self.send_json(404, {"error": "Không tìm thấy file."})
            return
        if candidate.is_file():
            self.send_file_response(candidate)
            return

        self.send_json(404, {"error": f"Đường dẫn không tồn tại: {path}"})

    def do_POST(self):
        origin = self.headers.get("Origin")
        allowed_origin = os.environ.get("AIC_PUBLIC_ORIGIN", f"http://{self.headers.get('Host')}").rstrip("/")
        if origin and origin.rstrip("/") != allowed_origin:
            self.send_json(403, {"error": "Origin không hợp lệ."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > 25 * 1024 * 1024:
            self.send_json(413, {"error": "Kích thước yêu cầu không hợp lệ."})
            return
        url_parts = urlsplit(self.path)
        path = url_parts.path

        if path == "/api/predict":
            try:
                body = self.rfile.read(length).decode("utf-8")
                data = json.loads(body)
                urls = data.get("urls", [])
                if isinstance(urls, str):
                    urls = [urls]
                model_key = data.get("model_id") or REGISTRY.active_model_key
                if model_key not in REGISTRY.available_models:
                    self.send_json(400, {"error": f"Không tìm thấy mô hình: {model_key}"})
                    return
                if not isinstance(urls, list) or not 1 <= len(urls) <= 10000 or any(not isinstance(u, str) or len(u) > 4096 for u in urls):
                    self.send_json(400, {"error": "Cần 1 đến 10,000 URL hợp lệ, mỗi URL tối đa 4096 ký tự."})
                    return

                t0 = time.time()
                results = predict_urls(urls, model_key)
                elapsed_ms = round((time.time() - t0) * 1000, 2)

                self.send_json(200, {
                    "model_used": model_key,
                    "elapsed_ms": elapsed_ms,
                    "total_scanned": len(results),
                    "results": results
                })
            except Exception as e:
                self.send_json(500, {"error": f"Lỗi dự đoán: {str(e)}"})
            return

        if path == "/api/models/select":
            try:
                body = self.rfile.read(length).decode("utf-8")
                data = json.loads(body)
                model_id = data.get("model_id")
                if REGISTRY.set_active_model(model_id):
                    self.send_json(200, {
                        "success": True,
                        "active_model": model_id,
                        "message": f"Đã chuyển sang mô hình: {model_id}"
                    })
                else:
                    self.send_json(400, {"error": f"Không tìm thấy mô hình: {model_id}"})
            except Exception as e:
                self.send_json(500, {"error": str(e)})
            return

        if path == "/api/upload_model":
            if os.environ.get("AIC_ALLOW_MODEL_UPLOAD") != "1":
                self.send_json(403, {"error": "Nạp mô hình bị tắt. Chỉ bật AIC_ALLOW_MODEL_UPLOAD=1 khi bạn tin cậy tệp mô hình."})
                return
            content_type = self.headers.get("Content-Type", "")
            try:
                if "application/json" in content_type:
                    body = self.rfile.read(length).decode("utf-8")
                    req_data = json.loads(body)
                    if "file_path" in req_data:
                        src_path = Path(req_data["file_path"])
                        if not src_path.is_file():
                            raise FileNotFoundError(f"Không tìm thấy file: {src_path}")
                        new_key = REGISTRY.register_uploaded_model(src_path, req_data.get("name"))
                        self.send_json(200, {
                            "success": True,
                            "model_id": new_key,
                            "message": f"Đã nhập thành công mô hình: {new_key}",
                            "models": REGISTRY.list_models()
                        })
                        return
                    elif "file_name" in req_data and "base64_data" in req_data:
                        import base64
                        raw_bytes = base64.b64decode(req_data["base64_data"])
                        save_p = MODELS_DIR / Path(req_data["file_name"]).name
                        if save_p.exists() or save_p.suffix.lower() != ".joblib":
                            raise ValueError("Tên file không hợp lệ hoặc đã tồn tại")
                        save_p.write_bytes(raw_bytes)
                        new_key = REGISTRY.register_uploaded_model(save_p, req_data.get("name"))
                        self.send_json(200, {
                            "success": True,
                            "model_id": new_key,
                            "message": f"Đã lưu và nạp mô hình: {new_key}",
                            "models": REGISTRY.list_models()
                        })
                        return

                raw_data = self.rfile.read(length)
                boundary = content_type.split("boundary=")[-1].encode("utf-8")
                parts = raw_data.split(boundary)
                uploaded_filename = f"model_upload_{int(time.time())}.joblib"
                file_bytes = None
                for part in parts:
                    if b"filename=" in part:
                        header_part, content_part = part.split(b"\r\n\r\n", 1)
                        content_part = content_part.rstrip(b"\r\n--")
                        m = re.search(r'filename="([^"]+)"', header_part.decode("utf-8", errors="ignore"))
                        if m:
                            uploaded_filename = m.group(1)
                        file_bytes = content_part
                        break

                if file_bytes:
                    target_dest = MODELS_DIR / Path(uploaded_filename).name
                    if target_dest.exists() or target_dest.suffix.lower() != ".joblib":
                        raise ValueError("Tên file không hợp lệ hoặc đã tồn tại")
                    target_dest.write_bytes(file_bytes)
                    new_key = REGISTRY.register_uploaded_model(target_dest)
                    self.send_json(200, {
                        "success": True,
                        "model_id": new_key,
                        "message": f"Đã nạp mô hình {uploaded_filename} thành công!",
                        "models": REGISTRY.list_models()
                    })
                else:
                    self.send_json(400, {"error": "Không đọc được dữ liệu file tải lên."})

            except Exception as e:
                self.send_json(500, {"error": f"Lỗi nạp model: {str(e)}"})
            return

        if path == "/api/upload_dataset":
            try:
                body = self.rfile.read(length).decode("utf-8")
                req_data = json.loads(body)
                dataset_path = req_data.get("path")
                if not dataset_path or not Path(dataset_path).is_file():
                    self.send_json(400, {"error": f"Không tìm thấy file dataset: {dataset_path}"})
                    return

                p = Path(dataset_path)
                if p.suffix.lower() == ".parquet":
                    import pyarrow.parquet as pq
                    parquet = pq.ParquetFile(p)
                    batch = next(parquet.iter_batches(batch_size=50000), None)
                    if batch is None:
                        raise ValueError("File Parquet không có dòng dữ liệu")
                    df = batch.to_pandas()
                else:
                    df = pd.read_csv(p, nrows=50000)

                cols = df.columns.tolist()
                label_candidates = [c for c in cols if c.lower() in ("label", "source_label", "label_raw", "type", "class")]
                label_col = label_candidates[0] if label_candidates else (cols[1] if len(cols) > 1 else cols[0])
                dist = {str(k): int(v) for k, v in df[label_col].value_counts().items()}

                meta_info = {
                    "path": str(p),
                    "file_name": p.name,
                    "file_size_mb": round(p.stat().st_size / (1024 * 1024), 2),
                    "columns": cols,
                    "label_column": label_col,
                    "sample_rows": len(df),
                    "class_distribution": dist,
                    "preview": df.head(10).to_dict(orient="records")
                }
                (REPORTS_DIR / "dataset_active.json").write_text(json.dumps(meta_info, ensure_ascii=False, indent=2), encoding="utf-8")

                self.send_json(200, {
                    "success": True,
                    "message": f"Đã nhập thành công dataset {p.name} ({round(p.stat().st_size/(1024*1024), 2)} MB)",
                    "dataset": meta_info
                })
            except Exception as e:
                self.send_json(500, {"error": f"Lỗi đọc dataset: {str(e)}"})
            return

        self.send_json(404, {"error": "API không tồn tại"})


def run_server(host="127.0.0.1", port=8501):
    server = ThreadingHTTPServer((host, port), WebAppHandler)
    print("=" * 70)
    print(" AIC211 CYBERSECURITY WEB PLATFORM (PHÂN LOẠI URL ĐA LỚP)")
    print(f" Web đang chạy tại: http://localhost:{port} (và http://{host}:{port})")
    print(" Bấm Ctrl + C để dừng server.")
    print("=" * 70)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1", help="Listen host")
    parser.add_argument("--port", type=int, default=8501, help="Listen port")
    args = parser.parse_args()
    run_server(args.host, args.port)
