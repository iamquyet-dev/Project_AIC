# Hệ Thống Phát Hiện Mối Đe Dọa URL Đa Lớp (AIC211 URL Threat Defense)

Hệ thống học máy phát hiện nguy cơ an ninh mạng từ liên kết URL đa lớp (Multi-Class URL Threat Detection) dành cho đề án AIC211. Mục tiêu là phân loại URL đầy đủ thành 4 lớp:
- `benign`: URL được nguồn xác minh là lành tính tại thời điểm thu thập.
- `phishing`: Trang web lừa đảo, giả mạo tài khoản / ngân hàng.
- `malware`: Trang phân phối mã độc, virus, tệp thực thi độc hại.
- `malicious`: Tấn công khai thác lỗ hổng, defacement, độc hại tổng hợp.

---

## 1. Sơ Đồ Luồng Hoạt Động Của Hệ Thống (Workflow Architecture)

Dành cho người mới hoặc người đánh giá đề tài hiểu nhanh cách hệ thống vận hành:

```text
[ DỮ LIỆU ĐẦU VÀO (data/) ]
  41 tập dữ liệu thô (Kaggle, PhishVN, Mendeley, Tranco...)
               │
               ▼
[ QUY TRÌNH 8 BƯỚC (steps/) ]
  01. Thu thập  ──>  02. Bóc tách  ──>  03. Chuẩn hóa  ──>  04. Làm sạch
  05. Đặc trưng ──>  06. Chia tập  ──>  07. Huấn luyện ──>  08. Đánh giá
               │
               ▼
[ KẾT QUẢ ĐẦU RA (outputs/) ]
  ├── 3 Mô hình trí tuệ nhân tạo (.joblib)
  ├── Biểu đồ ma trận nhầm lẫn (Confusion Matrix .png)
  └── Báo cáo số liệu đánh giá (JSON, CSV, Markdown)
               │
               ▼
[ ỨNG DỤNG THỰC TẾ (web/) ]
  Giao diện Dark Mode chuẩn SOC: Phân tích URL thời gian thực, đo độ trễ, cảnh báo đa cấp
```

---

## 2. Cây Thư Mục Dự Án (Dễ Hiểu - Giải Thích Chi Tiết Từng File)

```text
Project_AIC/
│
├── 📂 data/                                 # [KHO DỮ LIỆU] - Chứa toàn bộ dữ liệu của đề tài
│   ├── 📁 raw/                              # Dữ liệu THÔ thu thập từ 41 nguồn an ninh mạng quốc tế & Việt Nam
│   │   ├── compphish/                       # Mẫu URL lừa đảo so sánh
│   │   ├── kaggle_malicious_websites/       # Danh sách website độc hại từ Kaggle
│   │   ├── mendeley_large_url_corpus/       # Tập dữ liệu nghiên cứu lớn của Mendeley
│   │   ├── openphish_snapshot/              # Luồng cấp dữ liệu phishing thời gian thực
│   │   ├── phishvn_open/                    # Bộ dữ liệu lừa đảo tiếng Việt (PhishVN)
│   │   ├── tranco_domain_ranking/           # Bảng xếp hạng tên miền, không phải nhãn URL benign
│   │   └── uci_phiusiil_2024/               # Bộ dữ liệu lừa đảo chuẩn học thuật UCI 2024
│   │
│   └── 📁 processed/                        # Dữ liệu ĐÃ QUA XỬ LÝ (sau khi lọc sạch & chuẩn hóa)
│       ├── 01_parsed.csv                    # Dữ liệu sau bước 02: Bóc tách cấu trúc ban đầu
│       ├── 02_normalized.csv                # Dữ liệu sau bước 03: Đã chuẩn hóa về 4 nhãn chuẩn
│       ├── 03_cleaned.csv                   # Dữ liệu sau bước 04: Đã loại bỏ trùng lặp và link rác
│       ├── 03_rejected.csv                  # Nhật ký các dòng bị từ chối/loại bỏ vì sai định dạng
│       ├── 04_features.csv                  # Dữ liệu sau bước 05: Đã trích xuất các thuộc tính URL
│       ├── train.csv                        # Tập HUẤN LUYỆN: 27.518.983 mẫu URL theo manifest hiện có
│       ├── val.csv                          # Tập KIỂM ĐỊNH: 5.937.490 mẫu URL theo manifest hiện có
│       ├── test.csv                         # Tập KIỂM THỬ ĐỘC LẬP: 5.913.123 mẫu URL test nội bộ theo manifest hiện có
│       └── dataset_version.json             # File lưu thông tin phiên bản và số lượng mẫu từng lớp
│
├── 📂 steps/                                # [QUY TRÌNH HỌC MÁY] - 8 bước thực thi tự động từ A-Z
│   ├── step_01_collection.py                # Bước 1: Thu thập, quét và thống kê toàn bộ file dữ liệu thô
│   ├── step_02_parsing.py                   # Bước 2: Bóc tách các định dạng khác nhau (CSV, JSON, Text) về bảng
│   ├── step_03_normalize.py                 # Bước 3: Chuẩn hóa nhãn (đưa về 4 nhãn chuẩn) và tiền tố URL
│   ├── step_04_clean.py                     # Bước 4: Làm sạch, khử trùng lặp tuyệt đối, xóa URL lỗi
│   ├── step_05_features.py                  # Bước 5: Trích xuất đặc trưng (độ dài, entropy, số chấm, từ khóa nghi vấn)
│   ├── step_06_dataset.py                   # Bước 6: Phân chia tập dữ liệu train/val/test theo tỷ lệ chuẩn phân tầng
│   ├── step_07_model.py                     # Bước 7 (Menu): Giao diện chọn mô hình và số lượng mẫu cần train
│   ├── step_07_train.py                     # Bước 7 (Lõi): Thuật toán train theo lô (200k/lô), học tăng tiến, n-grams
│   ├── step_08_evaluate.py                  # Bước 8: Đánh giá độ chính xác, tự động vẽ ma trận nhầm lẫn & lưu theo ngày
│   └── run_all.py                           # File chạy tự động liên hoàn từ bước 01 đến bước 08
│
├── 📂 url_detector/                         # [BỘ NÃO THUẬT TOÁN] - Thư viện lõi xử lý và suy luận URL
│   ├── __init__.py                          # Khởi tạo gói Python
│   ├── common.py                            # Các hàm toán học: Tính Shannon Entropy, độ đo Precision/Recall/F1
│   ├── config.py                            # Cấu hình danh sách 4 nhãn, đường dẫn thư mục, danh mục từ khóa nguy hiểm
│   ├── detector.py                          # Động cơ ThreatDetector: Tổng hợp kết quả và tính mức độ nguy hại (%)
│   ├── extractor.py                         # LexicalFeatureExtractor: Trích xuất 11 đặc trưng cấu trúc URL
│   ├── model_runtime.py                     # Quản lý nạp model vào RAM, tối ưu tốc độ và đo độ trễ suy luận
│   └── thresholded.py                       # Cơ chế phân ngưỡng cảnh báo (An toàn < 40%, Nghi vấn 40-65%, Độc hại > 65%)
│
├── 📂 outputs/                              # [KẾT QUẢ ĐẦU RA] - Sản phẩm sau khi huấn luyện và đánh giá
│   ├── 📁 models/                           # 3 file mô hình máy học hoàn chỉnh (đã huấn luyện xong)
│   │   ├── model_word_char_svm.joblib       # 1. SGDClassifier modified_huber (word + char n-gram)
│   │   ├── model_word_tfidf_logistic.joblib # 2. SGDClassifier log_loss (word TF-IDF)
│   │   └── model_lexical_logistic.joblib    # 3. SGDClassifier log_loss (11 đặc trưng lexical)
│   │
│   ├── 📁 figures/                          # Biểu đồ Ma trận nhầm lẫn (Confusion Matrix Heatmap)
│   │   ├── cm_svm.png                       # Biểu đồ ma trận 4x4 mô hình SVM
│   │   ├── cm_logistic_tfidf.png            # Biểu đồ ma trận 4x4 mô hình Logistic TF-IDF
│   │   ├── cm_logistic_lexical.png          # Biểu đồ ma trận 4x4 mô hình Lexical
│   │
│   ├── 📁 metrics/                          # File báo cáo số liệu chi tiết
│   │   ├── multiclass_summary.json          # Toàn bộ thông số F1, Precision, Recall từng lớp của 3 mô hình
│   │
│   └── 📁 tables/                           # Bảng so sánh hiệu năng tổng hợp
│       ├── models_comparison.csv            # Bảng so sánh định dạng bảng tính CSV
│       ├── models_comparison.md             # Bảng so sánh định dạng văn bản Markdown
│
├── 📂 web/                                  # [ỨNG DỤNG WEB THỰC TẾ] - Giao diện phân tích URL trực quan
│   ├── 📁 models/                           # Chứa các mô hình máy học phục vụ suy luận trực tiếp cho web
│   ├── 📁 reports/                          # Báo cáo cũ; web ưu tiên đọc outputs/metrics và outputs/figures
│   ├── 📁 static/                           # Giao diện người dùng (Frontend)
│   │   ├── index.html                       # Trang web trung tâm SOC: nhập URL, xem tỷ lệ %, tra cứu kết quả
│   │   ├── styles.css                       # Giao diện Dark Mode hiện đại, tối ưu hiển thị trên di động & máy tính
│   │   └── app.js                           # Xử lý logic gọi API phân tích URL, đổi mô hình, phóng to biểu đồ
│   ├── 📁 url_detector/                     # Module thuật toán nhúng trực tiếp, giúp web chạy độc lập không phụ thuộc
│   ├── app.py                               # Web Server backend: phục vụ API phân tích URL và phân phối trang web
│   ├── core.py                              # Bộ xử lý suy luận cốt lõi: nạp mô hình, tính ma trận xác suất 4 lớp
│   ├── CHAY_WEB.cmd                         # File bấm đúp chuột (1-click) để khởi động web ngay lập tức
│   └── requirements.txt                     # Danh sách thư viện Python tối giản dành riêng cho môi trường Web
│
├── .gitignore                               # Quy tắc loại trừ: không đưa file rác, file tạm, file nén nặng lên Git
├── README.md                                # Tài liệu giới thiệu và hướng dẫn toàn diện của dự án
├── requirements.txt                         # Danh sách toàn bộ thư viện cần thiết cho toàn bộ dự án
└── run_all.py                               # Kịch bản chạy toàn bộ quy trình ngay tại thư mục gốc
```

---

## 3. Bảng Tra Cứu Nhanh 5 Khối Thành Phần

| Khối chức năng | Thư mục | Vai trò chính | Người sử dụng chính |
|---|---|---|---|
| **Dữ liệu (Data)** | `data/` | Lưu trữ 41 nguồn thô và 3 tập mẫu `train/val/test` sạch | Kỹ sư dữ liệu (Data Engineer) |
| **Quy trình (Pipeline)** | `steps/` | 8 script độc lập thực thi từ tiền xử lý đến train & test | Kỹ sư máy học (ML Engineer) |
| **Thuật toán (Core Engine)** | `url_detector/` | Trích xuất đặc trưng, tính entropy, luật chấm điểm nguy hại | Lập trình viên thuật toán |
| **Sản phẩm (Outputs)** | `outputs/` | Chứa file não mô hình `.joblib`, biểu đồ nhiệt `.png`, báo cáo `.json` | Người đánh giá / Báo cáo đề tài |
| **Ứng dụng (Web App)** | `web/` | Web phân tích trực quan cho người dùng cuối kiểm tra link nghi vấn | Người dùng / Chuyên viên an ninh mạng |

---

## 4. Kết quả và trạng thái xác minh

[**Báo cáo kết quả và giới hạn 04/11/2026**](BAO_CAO_KET_QUA_VA_GIOI_HAN_2026-11-04.md) tách rõ test nội bộ, chẩn đoán ngoài tập qua web và lượt chạy thử mã mới. [Quy tắc nhãn theo nguồn](docs/SOURCE_LABEL_POLICY_2026-11-04.md) nêu các nhãn chưa xác minh.

**Test nội bộ hiện có**: `v_20261103_134343`, `test.csv` 5.913.123 URL, báo cáo tạo ngày 03/11/2026 20:22:49 UTC. Split của phiên bản này theo hostname, chưa phải holdout độc lập theo registrable domain, nguồn hay thời gian. Hash model và dataset khớp lineage trong [JSON](outputs/metrics/multiclass_summary.json), nhưng không chứng minh hiệu năng trên feed mới.

| Model thực tế | Accuracy | Macro-F1 | Recall phishing | Recall malware |
|---|---:|---:|---:|---:|
| Word + char, `SGDClassifier(loss="modified_huber")` | 87,48% | 81,37% | 81,09% | 78,04% |
| Word TF-IDF, `SGDClassifier(loss="log_loss")` | 78,75% | 63,69% | 59,57% | 72,26% |
| Lexical, `SGDClassifier(loss="log_loss")` | 67,15% | 47,00% | 55,78% | 22,07% |

Trên 300 URL phishing mới từ OpenPhish qua web, recall theo thứ tự là 47,00% / 31,67% / 32,00%; không thể tính accuracy tổng thể hay báo động nhầm benign từ một tập chỉ có phishing. Trên 20 URLhaus tập trung vào IP và `/i`/`/bin.sh`, cả ba model đều 0/20 đúng lớp malware. Lô 10.000 tên miền gắn cờ chỉ dùng để rà soát vì nhãn ở cấp domain. Các bộ này đã được xem và dùng để định hướng sửa nên không phải final holdout mới.

**Bản chạy thử mới** trong `runs/run_20261104_verified_smoke` chỉ kiểm tra kỹ thuật với giới hạn 5.000 mẫu; train thiếu lớp `malicious`, test có 4 URL malware. Không công bố điểm smoke run như kết quả model mới. Mã đã hỗ trợ chạy thử vào thư mục mới bằng `python -B steps/run_all.py --isolated --run-dir runs/run_TEN_MOI`; thêm `--all-rows` chỉ sau khi xác minh mapping nguồn và có tập đủ bốn lớp, benign mới và final holdout chưa nhìn thấy.

Các công cụ kiểm tra nằm trong step tương ứng: `step_02_parsing.py --source-inventory`, `step_06_dataset.py --audit-split`, và `step_08_evaluate.py --analyze-diagnostics`, `--diagnose-bias` hoặc `--audit-web-decision`. Mỗi lệnh chỉ chạy tác vụ được chọn khi dùng cờ này.

---

## 5. Hướng Dẫn Vận Hành Hệ Thống

### 1. Cài đặt thư viện
```bash
pip install -r requirements.txt
```

### 2. Huấn luyện mô hình mới (Step 07)
```bash
cd steps
python step_07_train.py
```
- Chọn `1`: Huấn luyện mới từ đầu (hoặc `2`: Huấn luyện tăng tiến trên nền mô hình cũ).
- Chọn số dòng: Mặc định chọn `4` để dùng toàn bộ train của phiên bản dữ liệu đã xác minh.
- *Sau khi huấn luyện xong, mô hình sẽ tự động cập nhật vào cả thư mục `outputs/models/` và `web/models/`*.

### 3. Đánh giá mô hình & Xuất báo cáo (Step 08)
```bash
cd steps
python step_08_evaluate.py
```
- Mặc định chỉ kiểm thử trên `test.csv`; muốn dùng `val.csv` cần chọn rõ trong menu hoặc truyền `--input`.
- Mỗi mô hình lưu một biểu đồ `cm_*.png` vào `outputs/figures/`. Đặt `AIC_SAVE_LEGACY_CM=1` nếu cần thêm tên file cũ; đặt `AIC_EXTRA_REPORT_DIRS` nếu cần chép báo cáo sang thư mục khác.

### 4. Khởi động Web phân tích URL
- **Cách 1 (Nhanh nhất trên Windows)**: Vào thư mục `web` và bấm đúp chuột vào file `CHAY_WEB.cmd`.
- **Cách 2 (Lệnh dòng lệnh)**:
  ```bash
  cd web
  python app.py --port 8501
  ```
- Mở trình duyệt và truy cập `http://localhost:8501`. Mặc định web chỉ lắng nghe tại `127.0.0.1`; triển khai trên máy chủ cần cấu hình `--host`, `AIC_PUBLIC_ORIGIN` nếu dùng HTTPS/reverse proxy và biện pháp bảo vệ phù hợp. Tính năng nạp file mô hình `joblib` chỉ hoạt động khi đặt `AIC_ALLOW_MODEL_UPLOAD=1` và chỉ nên dùng với file tin cậy.
