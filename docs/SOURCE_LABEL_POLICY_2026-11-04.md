# Quy tắc nhãn và giới hạn dữ liệu AIC211

Ngày lập: 04/11/2026. Đây là quy trình xác minh, chưa phải chứng nhận nhãn của 39 triệu dòng hiện có.

## Đơn vị dự đoán

Mỗi mẫu huấn luyện hoặc đánh giá phải là **URL đầy đủ** có nhãn ở cấp URL. Giữ `url_original`, `label_original`, `label_mapped`, `source`, thời điểm nguồn quan sát URL, thời điểm tải, trạng thái xác minh, bằng chứng và lý do loại theo [mẫu rà nhãn](URL_LABEL_REVIEW_TEMPLATE.csv). `timestamp_utc` do bước chuẩn hóa tạo chỉ là **thời điểm xử lý**, không được dùng cho temporal holdout. Thiếu thời điểm nguồn thì ghi `unknown`.

## Quy tắc hiện áp dụng

| Dạng nguồn/nhãn | Quy tắc | Trạng thái |
|---|---|---|
| OpenPhish Community Feed, URL không có cột nhãn | `phishing` tại thời điểm snapshot; giữ URL gốc và hash feed | Có tài liệu feed ở mức URL; vẫn cần rà mẫu URL trước final test |
| Nhãn chữ đúng `benign`, `phishing`, `malware`, `malicious` | Giữ nhãn chữ gốc | Tạm dùng cho xử lý; xác minh ngữ nghĩa theo từng publisher trước kết luận |
| `defacement`, `defaced`, `deface` | Gộp vào `malicious` | Định nghĩa bài toán bốn lớp; không tuyên bố có lớp defacement riêng |
| Nhãn `0`, `1`, `bad`, `mal` và nhãn nhị phân không rõ chiều | `unknown`, loại khỏi tập huấn luyện/đánh giá cho đến khi có mapping theo tài liệu nguồn | Chưa xác minh đồng loạt 41 nguồn |
| Tranco, Majestic, domain radar, snapshot chỉ có domain | Phân tích riêng, không làm ground truth benign/phishing của `https://domain/` | Không vào test URL |
| Bộ chỉ có đặc trưng hoặc URL đã ẩn danh | Không đưa vào mô hình URL thô | Cần extractor tương thích nếu muốn nghiên cứu riêng |

[Bảng nguồn](source_label_inventory.csv) liệt kê các nhóm nguồn, loại dữ liệu và URL tài liệu ghi trong metadata cục bộ. Các dòng `review_source_label_semantics_before_final_training` chưa được xác minh nên **không được dùng để tuyên bố kết quả final**. Không suy nhãn từ tên thư mục có chữ `phish`. Không đánh đồng ba nguồn nhị phân khác nhau nếu chưa kiểm tra chiều của `0/1`.

## Quy trình chốt nhãn

1. Đọc tài liệu publisher và lược đồ từng file; ghi mapping kèm đường dẫn tài liệu và ngày truy cập. Lấy mẫu ngẫu nhiên có seed từ mỗi cặp nhãn gốc/nguồn.
2. Xác minh URL còn nguyên, nhãn đúng cấp URL và thời điểm nguồn quan sát. Với benign, kiểm tra chính URL và đường dẫn, không dựa vào thứ hạng domain.
3. Chạy bước clean để loại URL cùng chuỗi khác nhãn. `03_clean_audit.json` ghi số loại, cặp nhãn/cặp nguồn và URL mẫu; rà mẫu với bản gốc. URL khác cách viết nhưng cùng đích cần kiểm tra riêng trước khi đưa vào final holdout.
4. Chỉ khóa train/validation và final holdout sau khi có đủ bốn lớp từ nhiều nguồn, benign mới và không trùng URL/nhóm registrable domain. Final holdout phải được lấy **sau khi khóa model**, không dùng để chọn ngưỡng.

Tham khảo: [OpenPhish Knowledge Base](https://www.openphish.com/kb.html), [OpenPhish Feeds](https://openphish.com/phishing_feeds.html), [URLhaus Community API](https://urlhaus.abuse.ch/api/), [Public Suffix List](https://publicsuffix.org/list/).
