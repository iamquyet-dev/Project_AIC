# Hệ Thống Phát Hiện Mối Đe Dọa URL Đa Lớp (AIC211 URL Threat Defense)

Hệ thống học máy phát hiện nguy cơ an ninh mạng từ liên kết URL đa lớp (Multi-Class URL Threat Detection) dành cho đề án AIC211. Nhận diện và phân loại chính xác 4 lớp nguy cơ:
- `benign`: Liên kết an toàn, trang web chính thống.
- `phishing`: Trang web lừa đảo, giả mạo tài khoản / ngân hàng.
- `malware`: Trang phân phối mã độc, virus, tệp thực thi độc hại.
- `malicious`: Tấn công khai thác lỗ hổng, defacement, độc hại tổng hợp.

---

## 1. Cấu Trúc Dự Án Chi Tiết (Project Directory Tree)

```text
Project_AIC/
├── data/                                    # Quản lý kho dữ liệu thô và đã xử lý
│   ├── raw/                                 # 41 tập dữ liệu an ninh mạng thô từ Kaggle, PhishVN, Mendeley, Tranco...
│   │   ├── compphish/                       # Dữ liệu phishing so sánh
│   │   ├── deepurlbench/                    # Bộ benchmark URL chiều sâu
│   │   ├── kaggle_domain_features/          # Đặc trưng tên miền Kaggle
│   │   ├── kaggle_malicious_websites/       # Danh sách website độc hại Kaggle
│   │   ├── kaggle_phishing_features/        # Thuộc tính phishing nâng cao
│   │   ├── kaggle_phishing_site_urls/       # Tập mẫu URL phishing thực tế
│   │   ├── majestic_domain_ranking/         # Xếp hạng uy tín tên miền Majestic
│   │   ├── mendeley_large_url_corpus/       # Tập ngữ liệu lớn Mendeley
│   │   ├── openphish_snapshot/              # Nguồn dữ liệu thời gian thực OpenPhish
│   │   ├── phishvn_open/                    # Bộ dữ liệu lừa đảo tiếng Việt PhishVN
│   │   ├── tranco_domain_ranking/           # Danh sách Top 1 triệu tên miền tin cậy Tranco
│   │   └── uci_phiusiil_2024/               # Bộ dữ liệu chuẩn quốc tế UCI Phiusiil 2024
│   └── processed/                           # Dữ liệu hợp nhất sau pipeline làm sạch & chuẩn hóa
│       ├── 01_parsed.csv                    # Dữ liệu bóc tách thô đa nguồn
│       ├── 02_normalized.csv                # Chuẩn hóa cấu trúc URL và nhãn phân loại
│       ├── 03_cleaned.csv                   # Loại bỏ trùng lặp, lọc URL hợp lệ
│       ├── 03_rejected.csv                  # Nhật ký các dòng rác bị loại bỏ
│       ├── 04_features.csv                  # Dữ liệu trích xuất đặc trưng
│       ├── train.csv                        # Tập huấn luyện (~30.28 triệu mẫu, phân bố đều 4 lớp)
│       ├── val.csv                          # Tập kiểm định (~6.48 triệu mẫu)
│       ├── test.csv                         # Tập kiểm thử độc lập (~6.48 triệu mẫu)
│       └── dataset_version.json             # Siêu dữ liệu cấu hình phiên bản tập dữ liệu
│
├── steps/                                   # Quy trình thực thi 8 bước chuẩn học máy
│   ├── __init__.py                          # Package khởi tạo
│   ├── step_01_collection.py                # Bước 1: Quét và thu thập các nguồn dữ liệu thô
│   ├── step_02_parsing.py                   # Bước 2: Bóc tách cú pháp đa định dạng (CSV, JSON, TSV, Text)
│   ├── step_03_normalize.py                 # Bước 3: Chuẩn hóa nhãn về 4 lớp chuẩn & tiền tố URL
│   ├── step_04_clean.py                     # Bước 4: Làm sạch, khử trùng lặp, kiểm tra tính hợp lệ
│   ├── step_05_features.py                  # Bước 5: Trích xuất đặc trưng cấu trúc & từ vựng URL
│   ├── step_06_dataset.py                   # Bước 6: Phân chia tập dữ liệu train / val / test phân tầng
│   ├── step_07_model.py                     # Bước 7: Menu điều hướng huấn luyện mô hình
│   ├── step_07_train.py                     # Bước 7 (Lõi): Huấn luyện 3 mô hình (Online Learning, partial_fit theo lô 200k)
│   ├── step_08_evaluate.py                  # Bước 8: Đánh giá mô hình, tự động xuất ma trận nhầm lẫn & báo cáo ngày
│   └── run_all.py                           # Kịch bản thực thi tuần tự từ bước 01 đến bước 08
│
├── url_detector/                            # Thư viện thuật toán cốt lõi của hệ thống
│   ├── __init__.py                          # Khởi tạo module
│   ├── common.py                            # Đo Shannon entropy, tính metric (Precision, Recall, F1, Matrix)
│   ├── config.py                            # Cấu hình danh mục 4 lớp, đường dẫn và danh sách từ khóa nghi vấn
│   ├── detector.py                          # ThreatDetector engine (tính điểm rủi ro & đưa ra cảnh báo)
│   ├── extractor.py                         # LexicalFeatureExtractor (11 đặc trưng cấu trúc URL)
│   ├── model_runtime.py                     # Nạp mô hình tối ưu bộ nhớ RAM, đo độ trễ suy luận
│   └── thresholded.py                       # Quản lý ngưỡng cảnh báo đa cấp (An toàn / Nghi vấn / Độc hại)
│
├── outputs/                                 # Kết quả đầu ra của quá trình huấn luyện & đánh giá
│   ├── figures/                             # Biểu đồ ma trận nhầm lẫn (Confusion Matrix)
│   │   ├── cm_word_char_svm.png             # Ma trận mô hình Linear SVM (Word + Char n-grams)
│   │   ├── cm_word_tfidf_logistic.png       # Ma trận mô hình Logistic Regression (Word TF-IDF)
│   │   ├── cm_lexical_logistic.png          # Ma trận mô hình Logistic Regression (Lexical Features)
│   │   └── YYYY-MM-DD/                      # Thư mục lưu trữ lịch sử đánh giá theo từng ngày chạy
│   ├── metrics/                             # Tệp báo cáo số liệu JSON
│   │   ├── multiclass_summary.json          # Báo cáo đánh giá đầy đủ 4 lớp của các mô hình
│   │   └── YYYY-MM-DD/                      # Thư mục lưu trữ JSON theo từng ngày chạy
│   ├── models/                              # Lưu trữ mô hình huấn luyện hoàn chỉnh (.joblib)
│   │   ├── model_word_char_svm.joblib       # Mô hình Linear SVM
│   │   ├── model_word_tfidf_logistic.joblib # Mô hình Logistic TF-IDF
│   │   └── model_lexical_logistic.joblib    # Mô hình Logistic Lexical
│   └── tables/                              # Bảng thống kê so sánh hiệu năng
│       ├── models_comparison.csv            # Bảng so sánh định dạng bảng CSV
│       ├── models_comparison.md             # Bảng so sánh định dạng Markdown
│       └── YYYY-MM-DD/                      # Thư mục lưu trữ bảng so sánh theo từng ngày chạy
│
├── web/                                     # Nền tảng ứng dụng Web độc lập (chạy Local hoặc VPS)
│   ├── models/                              # Thư mục chứa mô hình phục vụ suy luận thời gian thực
│   │   ├── model_word_char_svm.joblib
│   │   ├── model_word_tfidf_logistic.joblib
│   │   └── model_lexical_logistic.joblib
│   ├── reports/                             # Báo cáo, bảng so sánh và biểu đồ ma trận phục vụ giao diện
│   │   ├── cm_word_char_svm.png
│   │   ├── cm_word_tfidf_logistic.png
│   │   ├── cm_lexical_logistic.png
│   │   ├── models_comparison.csv
│   │   ├── models_comparison.md
│   │   └── multiclass_summary.json
│   ├── static/                              # Tài nguyên giao diện người dùng
│   │   ├── app.js                           # Xử lý sự kiện giao diện, gọi API phân tích, chuyển mô hình
│   │   ├── index.html                       # Giao diện Dark Mode chuyên nghiệp chuẩn Trung tâm SOC
│   │   └── styles.css                       # Thiết kế responsive, bảng màu tương phản cao
│   ├── uploads/                             # Thư mục tạm cho tệp kiểm tra người dùng tải lên
│   ├── url_detector/                        # Thư viện thuật toán nhúng trực tiếp phục vụ web
│   ├── .htaccess                            # Cấu hình máy chủ web Apache/LiteSpeed
│   ├── app.py                               # Server backend phục vụ API RESTful & phân phối giao diện
│   ├── core.py                              # Bộ xử lý suy luận, tương thích nạp mô hình không phụ thuộc môi trường
│   ├── requirements.txt                     # Thư viện tối giản cho môi trường web
│   └── test.py                              # Kịch bản kiểm thử nhanh các API của web
│
├── .gitattributes                           # Cấu hình xử lý xuống dòng Git (LF/CRLF)
├── .gitignore                               # Bỏ qua tệp nén lớn, bộ nhớ đệm, môi trường ảo
├── README.md                                # Tài liệu kỹ thuật chi tiết của dự án
├── requirements.txt                         # Toàn bộ thư viện phụ thuộc Python của dự án
└── run_all.py                               # Kịch bản chạy toàn bộ pipeline ngay từ thư mục gốc
```

---

## 2. Bảng Đánh Giá Hiệu Năng 3 Mô Hình

Kết quả kiểm thử độc lập trên **6.484.817 mẫu URL** (tập `test.csv` hoàn toàn mới):

| Mô hình | Đặc trưng trích xuất | Accuracy | Precision (Weighted) | Recall (Weighted) | F1-Score (Weighted) | Tốc độ xử lý | Độ trễ | Dung lượng |
|---|---|---|---|---|---|---|---|---|
| **Linear SVM** | Word + Char n-grams (3-5 ký tự) | **80.61%** | **80.94%** | **80.61%** | **80.65%** | 6.052 URL/s | 0.1652 ms | 2.67 MB |
| **Logistic Regression** | Word TF-IDF | **75.89%** | **76.28%** | **75.89%** | **75.83%** | **44.416 URL/s** | **0.0225 ms** | 1.89 MB |
| **Logistic Regression** | 11 đặc trưng cấu trúc (Lexical) | **59.08%** | **59.99%** | **59.08%** | **59.41%** | 17.746 URL/s | 0.0564 ms | 1.6 KB |

### Chi tiết nhận diện theo từng lớp (Mô hình tốt nhất: Linear SVM):
- **Benign (An toàn)**: Precision = 86.0%, Recall = 89.2%, **F1-Score = 87.6%** (trên 3.423.772 mẫu).
- **Phishing (Lừa đảo)**: Precision = 85.1%, Recall = 76.8%, **F1-Score = 80.7%** (trên 2.115.471 mẫu).
- **Malware (Mã độc)**: Precision = 54.8%, Recall = 67.3%, **F1-Score = 60.4%** (trên 428.475 mẫu).
- **Malicious (Độc hại)**: Precision = 52.3%, Recall = 50.2%, **F1-Score = 51.2%** (trên 517.099 mẫu).

---

## 3. Hướng Dẫn Sử Dụng & Vận Hành

### Cài đặt môi trường
```bash
pip install -r requirements.txt
```

### Chạy quy trình từng bước
- **Huấn luyện mô hình**:
  ```bash
  cd steps
  python step_07_train.py
  ```
  *(Hỗ trợ huấn luyện từ đầu hoặc huấn luyện tăng tiến - Incremental learning, tự động đồng bộ sang Web)*.

- **Đánh giá & Xuất báo cáo**:
  ```bash
  cd steps
  python step_08_evaluate.py
  ```
  *(Tự động vẽ ma trận nhầm lẫn, lưu vào cả `outputs/figures/` và thư mục lưu trữ theo ngày)*.

- **Chạy toàn bộ Pipeline tự động**:
  ```bash
  python run_all.py
  ```

### Khởi động Giao diện Web
```bash
cd web
python app.py --port 8501
```
Mở trình duyệt truy cập: `http://localhost:8501` hoặc qua domain máy chủ triển khai.
