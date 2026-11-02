# Hệ Thống Phát Hiện Mối Đe Dọa URL Đa Lớp (AIC211 URL Threat Detection)

Hệ thống học máy phát hiện nguy cơ URL đa lớp (Multi-Class URL Threat Detection) dành cho đồ án AIC211. Phân loại 4 nhãn nguy cơ: `benign` (an toàn), `phishing` (lừa đảo), `malware` (mã độc), và `malicious` (tấn công/defacement).

---

## 1. Cấu Trúc Dự Án (Project Architecture)

```
Project_AIC/
├── data/
│   ├── processed/
│   │   ├── formats_ready_20261029_021120/   # Dữ liệu hợp nhất đã làm sạch & tiền xử lý
│   │   ├── train.csv, val.csv, test.csv
│   │   └── feature_matrix.csv
│   └── raw/
│       ├── datasets_download/               # 41 tập dữ liệu nguồn thô (18.2 GB)
│       └── raw_events.jsonl
├── url_detector/                            # Module thuật toán chính
│   ├── __init__.py
│   ├── common.py                            # Hàm tiện ích chung (parse URL, Shannon entropy, metrics)
│   ├── config.py                            # Cấu hình đường dẫn, nhãn cảnh báo, tham số
│   ├── detector.py                          # ThreatDetector engine (suy luận & tính threat score)
│   ├── extractor.py                         # LexicalFeatureExtractor (11 đặc trưng cấu trúc & n-grams)
│   ├── model_runtime.py                     # Quản lý nạp model, cache RAM, đo latency
│   └── thresholded.py                       # Quản lý ngưỡng phân cấp báo động (SAFE/HIGH/CRITICAL)
├── outputs/
│   ├── figures/                             # 3 biểu đồ ma trận nhầm lẫn (cm_*.png)
│   ├── metrics/                             # Báo cáo đánh giá chi tiết (multiclass_summary.json)
│   ├── models/                              # 3 mô hình đã huấn luyện (.joblib)
│   └── tables/                              # Bảng so sánh hiệu năng (.csv, .md đầy đủ Precision/Recall)
├── steps/                                   # Quy trình 7 bước
│   ├── step_01_collection.py                # 1. Collection: Agent, Syslog, API pull
│   ├── step_02_parsing.py                   # 2. Parsing: JSON / CSV, Raw text
│   ├── step_03_normalize.py                 # 3. Normalize: UTC time, Canonical fields
│   ├── step_04_clean.py                     # 4. Clean: Nulls, Duplicates, Validation
│   ├── step_05_features.py                  # 5. Features: Counts, Rates, History
│   ├── step_06_dataset.py                   # 6. Dataset: Labels, Split, Version
│   ├── step_07_model.py                     # 7. Model: Train, Infer, Threshold
│   └── run_all.py                           # Chạy toàn bộ 7 bước ngay trong thư mục steps/
├── web/                                     # Giao diện ứng dụng Web (chuẩn VPS)
│   ├── app.py                               # Server backend phục vụ API suy luận & báo cáo
│   ├── core.py                              # Bộ nạp mô hình & tính điểm rủi ro
│   ├── models/                              # Gói mô hình phục vụ suy luận tức thì
│   ├── reports/                             # Báo cáo ma trận nhầm lẫn & tệp thống kê
│   └── static/                              # Giao diện HTML/CSS/JS (có phóng to ảnh)
├── .gitignore                               # Bỏ qua venv, pycache, file tạm
├── README.md                                # Tài liệu hướng dẫn
├── requirements.txt                         # Thư viện phụ thuộc chuẩn
└── run_all.py                               # Chạy toàn bộ pipeline tại thư mục gốc
```

---

## 2. Bảng So Sánh Hiệu Năng 3 Mô Hình Huấn Luyện

Đánh giá độc lập trên tập kiểm thử gồm **2.731.595 dòng URL**:

| Mô hình | Đặc trưng trích xuất | Accuracy | Precision (Weighted) | Recall (Weighted) | Weighted-F1 | Precision (Macro) | Recall (Macro) | Macro-F1 | Dung lượng file | Thời gian huấn luyện |
|---|---|---|---|---|---|---|---|---|---|---|
| **1. Linear SVM** | Word + char n-grams (3-5 ký tự) | **92.13%** | **93.16%** | **92.13%** | **92.26%** | 42.45% | 34.46% | 36.19% | 3.98 MB | 105.66 phút |
| **2. Logistic Regression** | Word TF-IDF | **87.53%** | 87.58% | 87.52% | 87.32% | 35.85% | 31.45% | 32.32% | 2.34 MB | 24.86 phút |
| **3. Logistic Regression** | 11 đặc trưng cấu trúc (Lexical) | **77.08%** | 85.82% | 77.08% | 80.65% | 31.47% | 28.71% | 29.73% | 1.9 KB | 57.59 phút |

---

## 3. Hướng Dẫn Chạy

### Chạy kiểm tra Pipeline
```bash
python run_all.py --samples 500
```
Hoặc từ thư mục `steps/`:
```bash
cd steps
python run_all.py --samples 500
```

### Chạy Web Local
```bash
cd web
python app.py --port 8501
```
Truy cập: `http://localhost:8501`
