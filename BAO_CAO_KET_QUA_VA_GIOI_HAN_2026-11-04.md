# Kết quả AIC211 và giới hạn bằng chứng — 04/11/2026

**Đơn vị bài toán:** URL đầy đủ; bốn lớp `benign`, `malicious` (gồm defacement theo định nghĩa hiện tại), `phishing`, `malware`. Các điểm dưới đây thuộc **model cũ** `v_20261103_134343`, không phải model vừa huấn luyện lại. `provenance_verified=true` chỉ xác nhận hash/file lineage, chưa chứng minh nguồn, campaign hoặc thời gian độc lập.

## 1. Test nội bộ `data/processed/test.csv`

Thời điểm báo cáo JSON: 03/11/2026 20:22:49 UTC. Tổng 5.913.123 URL, support: benign 3.478.583, malicious 248.742, phishing 1.981.192, malware 204.606. Chính sách chia cũ dùng hostname chính xác và publisher pins; vì thế các chỉ số chưa phải ước lượng generalization theo registrable domain. [JSON đầy đủ](outputs/metrics/multiclass_summary.json) ghi confusion matrix, precision/recall/F1/support từng lớp và hash từng model.

| Model (estimator thực) | Accuracy | Macro-F1 | Recall phishing | Recall malware | Hash model |
|---|---:|---:|---:|---:|---|
| Word + char, `SGDClassifier(loss="modified_huber")` | 87,48% | 81,37% | 81,09% | 78,04% | `19c173fa…66e0bfe74` |
| Word TF-IDF, `SGDClassifier(loss="log_loss")` | 78,75% | 63,69% | 59,57% | 72,26% | `6073fcb2…c21e14e` |
| Lexical, `SGDClassifier(loss="log_loss")` | 67,15% | 47,00% | 55,78% | 22,07% | `8b38a0f4…1c81b4d` |

Ma trận nhầm lẫn có thứ tự hàng/cột `benign, malicious, phishing, malware` trong [JSON](outputs/metrics/multiclass_summary.json) và các ảnh [SVM](outputs/figures/cm_svm.png), [TF-IDF](outputs/figures/cm_logistic_tfidf.png), [lexical](outputs/figures/cm_logistic_lexical.png). Phishing bị gán benign: 303.377 / 518.357 / 604.480; malware bị gán benign: 30.991 / 38.902 / 104.412 theo cùng thứ tự. Báo động nhầm trên benign theo `pipeline.predict` là 281.302 / 272.304 / 750.708 trên 3.478.583 benign. Đây là **quyết định nhãn bốn lớp**, chưa phải phép kiểm định cờ nguy cơ mới của web.

## 2. Các bộ chẩn đoán ngoài tập qua web

Các bộ sau đã được xem để xây kế hoạch nên **không còn là final holdout chưa nhìn thấy**. Ba model đã dùng cùng URL đầu vào và toàn bộ CSV được lưu. Hash web model khớp output model trong thời điểm kiểm thử theo [log tổng hợp](test%20case/WEB_TEST_TONG_HOP_2026-11-04.md); API hiện kiểm tra lại hash trước khi hiện điểm nội bộ.

| Nguồn và đơn vị nhãn | Support | Word + char | TF-IDF | Lexical | Kết luận được phép |
|---|---:|---:|---:|---:|---|
| OpenPhish 04/11, URL đầy đủ nhãn phishing | 300 phishing | 141/300 = 47,00% recall | 95/300 = 31,67% | 96/300 = 32,00% | Chỉ đo recall phishing trên feed này; lần lượt 142/169/169 URL bị gán benign |
| URLhaus 04/11, URL malware online, chủ yếu IP + `/i`/`/bin.sh` | 20 malware | 0/20 đúng lớp | 0/20 | 0/20 | Lỗi rõ trên nhóm mẫu tương quan; không ước lượng mọi URL malware |
| 10.000 tên miền gắn cờ, chuyển thành `https://domain/` | 10.000 domain | 52,10% gắn cờ | 37,47% | 34,51% | Chỉ dùng để rà soát; nhãn domain không xác nhận URL gốc |

Đầu vào và CSV đầy đủ: [300 URL](test%20case/WEB_TEST_OPENPHISH_300_CASES_2026-11-04.txt), [SVM](test%20case/WEB_TEST_OPENPHISH_300_SVM_2026-11-04.csv), [TF-IDF](test%20case/WEB_TEST_OPENPHISH_300_TFIDF_2026-11-04.csv), [lexical](test%20case/WEB_TEST_OPENPHISH_300_LEXICAL_2026-11-04.csv); [10.000 URL tổng hợp](test%20case/WEB_TEST_10000_CASES_2026-11-04.txt), [SVM](test%20case/WEB_TEST_10000_SVM_2026-11-04.csv), [TF-IDF](test%20case/WEB_TEST_10000_TFIDF_2026-11-04.csv), [lexical](test%20case/WEB_TEST_10000_LEXICAL_2026-11-04.csv); [log 60 URL](test%20case/WEB_TEST_CASES_2026-11-04.md). Không tính accuracy tổng thể, precision hay tỷ lệ báo động nhầm benign từ 300 URL chỉ có nhãn phishing. 20 URLhaus không đủ để ước lượng recall malware tổng quát. Đợt 10.000 domain không được gọi là accuracy/sai URL.

[Thống kê nhóm lỗi](docs/diagnostic_error_counts.json) và [119 dòng lấy mẫu có seed để rà nhãn](docs/diagnostic_label_review.csv) được tạo từ CSV/log web cũ. Trạng thái mẫu đều là `unreviewed`; chưa đưa các URL này vào train hay dùng để chọn model.

## 3. Chạy thử quy trình mới trong thư mục riêng

`runs/run_20261104_verified_smoke` là **smoke run 5.000 mẫu giới hạn**, không phải thử nghiệm final: 4.880 dòng parse, 2.248 dòng clean; train 1.526, validation 359, test 363. Chỉ có 3 lớp trong train và 4 URL malware trong test, thiếu lớp `malicious`; điểm test không dùng để chọn model hay công bố hiệu năng. [Manifest](runs/run_20261104_verified_smoke/run_manifest.json) giữ hash mã, đầu ra và interpreter; [JSON thử](runs/run_20261104_verified_smoke/metrics/multiclass_summary.json) giữ số đo chẩn đoán. [Audit split](runs/run_20261104_verified_smoke/metrics/split_audit.json) đếm 1.880 nhóm registrable domain/IP, không có nhóm, hostname, URL chính xác hay ứng viên gần trùng xuất hiện ở nhiều tập trong mẫu thử này; nhiều **nguồn vẫn xuất hiện ở cả ba tập**. [Audit cờ nguy cơ trên validation](runs/run_20261104_verified_smoke/metrics/web_decision_validation.json) dùng cùng quy tắc `1 - điểm benign >= 0,50` của web, chưa chọn ngưỡng theo mức báo động nhầm chấp nhận được.

## 4. Điều kiện còn thiếu trước khi công bố model mới

- Rà tài liệu publisher cho các nhãn nhị phân và nhãn thiếu theo [quy tắc nguồn](docs/SOURCE_LABEL_POLICY_2026-11-04.md); hiện chưa có chứng nhận nhãn URL cho đủ bốn lớp và benign mới.
- Xây validation có nguồn/thời gian thật và final holdout URL mới **sau khi khóa model**, kiểm tra không trùng URL, registrable domain hoặc campaign. `timestamp_utc` hiện là thời điểm xử lý, không phải thời điểm feed quan sát.
- Chọn cấu hình/ngưỡng bằng validation, đo cả nhãn bốn lớp và cờ nguy cơ web trên đủ bốn lớp. Chạy ba model qua web với cùng file đầu vào, lưu CSV đầy đủ và hash mỗi bản phát hành.

Chưa có cơ sở kết luận model đã cải thiện, học vẹt hoặc báo cáo JSON bị làm giả. Model và dataset hiện hành được giữ nguyên cho đến khi quy trình xác minh trên hoàn tất.
