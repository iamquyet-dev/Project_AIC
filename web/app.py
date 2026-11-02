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
import mimetypes
import os
from pathlib import Path
import shutil
import sys
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    import pandas as pd
except ImportError:
    pd = None
from core import REGISTRY, predict_urls, CLASS_LABELS, CLASS_COLORS, LexicalFeatureExtractor

import __main__
import types
setattr(__main__, "LexicalFeatureExtractor", LexicalFeatureExtractor)

if "train_three_models" not in sys.modules:
    _fake_mod = types.ModuleType("train_three_models")
    _fake_mod.LexicalFeatureExtractor = LexicalFeatureExtractor
    sys.modules["train_three_models"] = _fake_mod

MODELS_DIR = ROOT / "models"
UPLOADS_DIR = ROOT / "uploads"
STATIC_DIR = ROOT / "static"
REPORTS_DIR = ROOT / "reports"

UPLOADS_DIR.mkdir(exist_ok=True)

class WebAppHandler(BaseHTTPRequestHandler):
    server_version = "AIC211-Engine/1.0"

    def log_message(self, format, *args):
        sys.stdout.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()

    def send_json(self, status: int, data: dict | list):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
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
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url_parts = urlsplit(self.path)
        path = url_parts.path

        if path == "/api/status":
            summary_path = REPORTS_DIR / "multiclass_summary.json"
            summary_data = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
            self.send_json(200, {
                "status": "ready",
                "active_model": REGISTRY.active_model_key,
                "models": REGISTRY.list_models(),
                "class_labels": CLASS_LABELS,
                "class_colors": CLASS_COLORS,
                "dataset_summary": {
                    "total_rows": summary_data.get("total_rows", 30640872),
                    "classes": summary_data.get("classes", ["benign", "phishing", "malware", "defacement", "malicious"]),
                    "class_distribution": summary_data.get("class_distribution", {}),
                }
            })
            return

        if path == "/api/models":
            self.send_json(200, {
                "active": REGISTRY.active_model_key,
                "models": REGISTRY.list_models()
            })
            return

        if path == "/api/metrics":
            summary_path = REPORTS_DIR / "multiclass_summary.json"
            if summary_path.is_file():
                self.send_json(200, json.loads(summary_path.read_text(encoding="utf-8")))
            else:
                self.send_json(200, {"message": "Chưa có file báo cáo multiclass_summary.json"})
            return

        if path.startswith("/reports/"):
            rel_name = path.replace("/reports/", "")
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

        candidate = STATIC_DIR / path.lstrip("/")
        if candidate.is_file():
            self.send_file_response(candidate)
            return

        self.send_json(404, {"error": f"Đường dẫn không tồn tại: {path}"})

    def do_POST(self):
        url_parts = urlsplit(self.path)
        path = url_parts.path

        if path == "/api/predict":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                data = json.loads(body)
                urls = data.get("urls", [])
                if isinstance(urls, str):
                    urls = [urls]
                model_key = data.get("model_id") or REGISTRY.active_model_key

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
                length = int(self.headers.get("Content-Length", "0"))
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
            content_type = self.headers.get("Content-Type", "")
            try:
                length = int(self.headers.get("Content-Length", "0"))
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
                        save_p = MODELS_DIR / req_data["file_name"]
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
                    target_dest = MODELS_DIR / uploaded_filename
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
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                req_data = json.loads(body)
                dataset_path = req_data.get("path")
                if not dataset_path or not Path(dataset_path).is_file():
                    self.send_json(400, {"error": f"Không tìm thấy file dataset: {dataset_path}"})
                    return

                p = Path(dataset_path)
                if pd is not None:
                    if p.suffix.lower() == ".parquet":
                        df = pd.read_parquet(p)
                    else:
                        df = pd.read_csv(p, nrows=50000)
                    cols = df.columns.tolist()
                    label_candidates = [c for c in cols if c.lower() in ("label", "source_label", "label_raw", "type", "class")]
                    label_col = label_candidates[0] if label_candidates else (cols[1] if len(cols) > 1 else cols[0])
                    dist = {str(k): int(v) for k, v in df[label_col].value_counts().items()}
                    sample_count = len(df)
                    preview_records = df.head(10).to_dict(orient="records")
                else:
                    import csv
                    preview_records = []
                    cols = []
                    sample_count = 0
                    with open(p, "r", encoding="utf-8", errors="ignore") as f_in:
                        reader = csv.DictReader(f_in)
                        cols = reader.fieldnames or []
                        for i, r in enumerate(reader):
                            if i < 10:
                                preview_records.append(r)
                            sample_count += 1
                            if sample_count >= 50000:
                                break
                    label_candidates = [c for c in cols if c.lower() in ("label", "source_label", "label_raw", "type", "class")]
                    label_col = label_candidates[0] if label_candidates else (cols[1] if len(cols) > 1 else cols[0])
                    dist = {"total": sample_count}

                meta_info = {
                    "path": str(p),
                    "file_name": p.name,
                    "file_size_mb": round(p.stat().st_size / (1024 * 1024), 2),
                    "columns": cols,
                    "label_column": label_col,
                    "sample_rows": sample_count,
                    "class_distribution": dist,
                    "preview": preview_records
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

def run_server(host="0.0.0.0", port=8501):
    server = ThreadingHTTPServer((host, port), WebAppHandler)
    print("=" * 70)
    print(" AIC211 CYBERSECURITY WEB PLATFORM (PHÂN LOẠI URL ĐA LỚP)")
    print(f" Web đang chạy tại: http://localhost:{port} (và http://{host}:{port})")
    print(f" Thư mục Model:      {MODELS_DIR}")
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
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=8501, help="Listen port")
    args = parser.parse_args()
    run_server(args.host, args.port)
