# BÁO CÁO CUỐI KỲ AIC211 — BẢN REWORK

**Môn học:** AIC211 — [điền tên đầy đủ theo đề cương]<br>
**Đề tài:** Phát hiện mối đe dọa từ URL bằng học máy đa lớp, bản sửa quy trình dữ liệu và đánh giá<br>
**Nhóm/thành viên:** [điền họ tên, mã số, vai trò]<br>
**Giảng viên/học viên hướng dẫn:** [điền]<br>
**Học kỳ:** [điền]<br>
**Phiên bản báo cáo:** 04/11/2026; phạm vi E:\Project_AIC_rework_2026-11-04, nhánh codex/merged-steps-aic211, commit 340eca4.<br>
**Trạng thái công bố:** bản rework đã có kiểm thử kỹ thuật giới hạn; chưa có kết quả huấn luyện đầy đủ mới đủ điều kiện thay thế điểm lịch sử của main.

## 1. Tóm tắt điều hành

Bản rework giữ bài toán dự đoán một URL đầy đủ trong bốn lớp benign, phishing, malware và malicious; defacement thuộc malicious theo định nghĩa hiện tại. Mục tiêu sửa là làm rõ nhãn theo nguồn, lưu dấu vết dữ liệu, kiểm soát trùng nhóm khi chia tập, đo cờ nguy cơ của web và tách kiểm thử ngoài nguồn khỏi test nội bộ. Bản sửa giữ model và dataset cũ của main để đối chiếu lịch sử, đồng thời chạy pipeline mới trong thư mục runs/ riêng.

Kết quả kỹ thuật mới nhất ở runs/run_20261104_merged_steps_final_smoke dùng giới hạn tổng 5.000 dòng phân bổ theo nguồn, có 4.880 dòng sau parsing và 2.248 dòng sau clean; split train/validation/test là 1.526/359/363. Test chỉ có 184 benign, 175 phishing, 4 malware và **0 malicious**. Điểm macro-F1 smoke của word + char là 0,3797; TF-IDF từ 0,3447; lexical 0,2087. Đây không phải kết quả dự án hoàn chỉnh: số mẫu nhỏ, lớp thiếu, nguồn còn giao nhau giữa split, và file đánh giá ghi provenance_verified=false vì hash model chưa khớp manifest. Không thể dùng các điểm đó để khẳng định rework tốt hơn hoặc kém hơn main.

## 2. Giới thiệu và nêu vấn đề

Một hệ thống dùng trong SOC cần phân biệt đúng kiểu nguy cơ và tránh hai hậu quả chính: để lọt URL nguy hiểm, hoặc báo động nhầm làm gián đoạn truy cập hợp pháp. Kết quả test nội bộ của bản main cho macro-F1 cao hơn các baseline, nhưng 300 URL OpenPhish mới qua web chỉ đạt recall đúng lớp phishing 47,00% với word + char. Bản rework giải quyết **chất lượng phép đo và truy vết**, trước khi tuyên bố cải thiện mô hình.

Đơn vị của dữ liệu và dự đoán là URL đầy đủ. Một nhãn ở cấp tên miền không tự xác minh đường dẫn cụ thể; một vector URL đã ẩn danh không phải chuỗi URL để nhập vào web. Quy trình mới đòi hỏi tên nguồn, nhãn gốc, nhãn quy đổi, thời điểm nguồn quan sát, thời điểm lấy dữ liệu và trạng thái rà soát. Những trường còn thiếu phải được ghi là chưa biết thay vì suy đoán.

### 2.1 Mục tiêu kỹ thuật của bản rework

Bản main cho phép tái hiện một phép đo nội bộ nhưng chưa chứng minh tách biệt theo registrable domain, nguồn hoặc thời gian. Rework vì vậy đặt bốn mục tiêu kiểm chứng được: ghi nhãn gốc và nguồn để rà mapping; loại trùng và xung đột nhãn kèm lý do; giữ các URL cùng nhóm miền trong một split; và lưu hash cùng kết quả audit theo từng run. Đây là cải tiến quy trình. Một mô hình chỉ được gọi là cải thiện sau khi được huấn luyện trên dữ liệu đủ bốn lớp, đánh giá cùng baseline trên final holdout mới và có lineage khớp.

### 2.2 Đơn vị suy luận và quyết định vận hành

Web nhận một URL đầy đủ và trả một trong bốn nhãn; cờ nguy cơ là phép quyết định thứ hai, tính từ điểm benign. Hai đầu ra cần được đánh giá riêng. Ví dụ phishing bị gán malware là sai lớp nhưng vẫn có thể được cắm cờ; phishing bị gán benign vừa sai lớp vừa có nguy cơ bị bỏ lọt. Vì vậy báo cáo phân tích confusion matrix đa lớp, số bỏ sót theo cờ, và báo động nhầm trên benign. Không dùng một điểm accuracy duy nhất để đại diện cho cả hai mục tiêu.

## 3. Tập dữ liệu và phân tích thăm dò

### 3.1 Nguồn, nhãn và phân bố

[Bản quy tắc nhãn](docs/SOURCE_LABEL_POLICY_2026-11-04.md) và [bảng kiểm kê nguồn](docs/source_label_inventory.csv) là tài liệu làm việc, chưa chứng nhận toàn bộ khoảng 39 triệu URL lịch sử. Nhãn chữ rõ nghĩa được giữ; defacement được gộp vào malicious. Nhãn 0/1, bad, mal hoặc nhãn nhị phân khác không được áp cùng một chiều cho mọi nguồn nếu chưa có tài liệu publisher. Danh sách miền như Tranco/Majestic được phân tích riêng; không dùng tên miền uy tín để gán benign cho mọi URL. OpenPhish Community Feed cung cấp URL phishing theo snapshot và có điều khoản sử dụng [1]; URLhaus mô tả URL trực tiếp phân phối payload malware [2].

| Công đoạn smoke mới nhất | Số dòng |
|---|---:|
| Giới hạn đọc toàn run | 5.000 |
| Parsing | 4.880 |
| Clean và tạo đặc trưng | 2.248 |
| Train | 1.526 |
| Validation | 359 |
| Test | 363 |

Bảng 1. Đếm trong [manifest run](runs/run_20261104_merged_steps_final_smoke/run_manifest.json) và [dataset_version.json](runs/run_20261104_merged_steps_final_smoke/processed/dataset_version.json). Số dòng parse không đồng nghĩa số nhãn đã xác minh thủ công.

| Tập smoke | benign | phishing | malware | malicious |
|---|---:|---:|---:|---:|
| Train | 819 | 706 | 1 | 0 |
| Validation | 221 | 136 | 2 | 0 |
| Test | 184 | 175 | 4 | 0 |

Bảng 2. Phân bố sau clean/split. Lớp malware có quá ít mẫu để ước lượng ổn định; lớp malicious vắng mặt hoàn toàn. Macro-F1 bốn lớp trên tập này là một số đo chẩn đoán của smoke run, không phải chỉ số năng lực bốn lớp.

### 3.2 Phân tích thăm dò cần hoàn tất

Bản rework có log rejected rows, nguồn và split; đó là cơ sở để phân tích nhãn thiếu, xung đột, URL sai và chênh lệch nguồn. Trước báo cáo final, nhóm cần lập bảng theo **nguồn × nhãn × thời điểm**, số URL trùng chính xác, gần trùng và mâu thuẫn nhãn, tỷ lệ URL có scheme/path/query, URL IP và tỷ lệ nguồn hiện diện trong mỗi tập. Không dùng biểu đồ lấy từ 5.000 dòng giới hạn để nói về toàn bộ dữ liệu.

### 3.3 Điều kiện để có tập đánh giá cuối kỳ hợp lệ

Mỗi dòng dùng cho thí nghiệm cuối phải có URL gốc, nhãn ở cấp URL, nguồn, thời điểm nguồn quan sát nếu có, thời điểm tải, quy tắc ánh xạ nhãn, trạng thái xác minh và hash snapshot. Trước khi chia tập cần loại URL giống hệt nhưng mang nhãn xung đột, ghi số lượng theo cặp nhãn và nguồn, rồi rà mẫu theo seed cố định. Một URL xuất hiện trong feed gần đây có thể đã thay đổi trạng thái; do đó phải ghi thời điểm của bằng chứng, không diễn giải nhãn lịch sử như trạng thái hiện tại.

Tập validation phải đủ bốn lớp và benign mới để chọn cấu hình, ngưỡng cảnh báo và mức báo động nhầm. Tập final holdout phải được thu sau khi khóa các lựa chọn ấy, không trùng URL hoặc nhóm registrable domain/campaign với train. Cần báo cáo thêm một holdout theo nguồn và thời gian quan sát thật. Nếu dùng lỗi của final holdout để sửa model, bộ đó trở thành chẩn đoán và phải lấy bộ final mới. Những điều kiện này chưa đạt trong smoke run hiện có.

### 3.4 Mức hao hụt mẫu và cấu trúc nguồn trong smoke run

Giới hạn chạy mới đọc tối đa 5.000 dòng phân bố theo nguồn, còn 4.880 dòng sau parsing (97,6% giới hạn) và 2.248 dòng sau clean/tạo đặc trưng (46,1% số đã parse). Chênh lệch 2.632 dòng giữa parse và clean cần được phân rã theo lý do từ `03_clean_audit.json` và file rejected; không nên gọi tất cả là “dữ liệu lỗi”. Trong 2.248 mẫu sau clean, phishing và benign chiếm gần như toàn bộ; malware chỉ có 7 mẫu trên cả ba split, malicious bằng 0. Đây là đặc điểm của mẫu giới hạn, không phải phân bố đã xác minh của kho 39 triệu dòng.

Theo [audit split](runs/run_20261104_merged_steps_final_smoke/metrics/split_audit.json), nguồn `phreshphish_expansion` có 953 train, 193 validation và 196 test, tổng 1.342/2.248 mẫu. Cùng một nguồn xuất hiện ở cả ba split, tương tự các nguồn khác; chống trùng nhóm miền không tương đương holdout theo nguồn. `timestamp_utc` hiện được tạo khi xử lý, còn `source_observed_utc` chưa đủ để khẳng định phép chia thời gian. Do đó số điểm test smoke dễ phản ánh thành phần nguồn hơn là hiệu năng trên dòng URL mới.

!FIGURE:attrition_rework.png|Hình 1. Số dòng qua các mốc của smoke run; trục số là đếm thô, không phải tỷ lệ của toàn bộ kho dữ liệu.

## 4. Phương pháp và thiết kế pipeline

Pipeline vẫn gồm tám bước thu thập, parsing, chuẩn hóa, clean, đặc trưng, chia tập, huấn luyện và đánh giá, nhưng rework thêm audit theo từng bước và chạy cách ly trong runs/. Quy tắc clean loại URL thiếu/sai và URL cùng chuỗi có nhãn mâu thuẫn; nhãn không rõ nghĩa được giữ ở trạng thái unknown hoặc loại theo chính sách nguồn. Các thay đổi về nhãn và split đòi hỏi huấn luyện lại từ bước ảnh hưởng.

!FIGURE:pipeline_rework.png|Hình 2. Pipeline tám bước của rework theo bố cục khối trong hình người dùng cung cấp; các ô ghi đầu vào, đầu ra và audit có thật trong run riêng.

### 4.1 Đầu vào, đầu ra và kiểm soát của từng bước

**Collection và parsing.** Dữ liệu được kiểm kê trong `data/raw`, có thể có metadata nguồn kèm hash. Bộ parsing xuất `01_parsed.csv`, giữ URL/nhãn gốc và thông tin nguồn. `run_manifest.json` của smoke ghi metadata cục bộ nhưng `hash_verified_in_this_run=false` đối với raw metadata; đó là mô tả nguồn, chưa phải xác minh lại toàn bộ tệp gốc. **Normalize.** `02_normalized.csv` đưa dữ liệu vào schema chung và phân biệt thời điểm xử lý với thời điểm nguồn quan sát. Nhãn mơ hồ phải để unknown hoặc loại theo quy tắc nguồn, không suy từ tên thư mục.

**Clean và features.** Clean xuất đồng thời `03_cleaned.csv`, `03_rejected.csv` và `03_clean_audit.json`, tách URL trùng chính xác, xung đột nhãn, thiếu hoặc sai định dạng. Audit lưu cặp nhãn và cặp nguồn xung đột để kiểm tra thủ công. Bước đặc trưng xuất `04_features.csv` với cả trường provenance và đặc trưng lexical; các cột URL gốc/nhãn gốc không được dùng làm shortcut cho mô hình. **Dataset.** Bước chia dùng nhóm registrable domain từ Public Suffix List được ghim phiên bản, ưu tiên publisher pins và có tùy chọn holdout nguồn. `split_audit.json` kiểm tra nhóm, host, URL chính xác và khóa gần trùng giao giữa split.

**Model và evaluation.** Ba pipeline học máy được train trong `runs/<run>/models`, tách khỏi model lịch sử. Evaluation xuất metrics đa lớp và audit cờ nguy cơ trên `val.csv`; final holdout không được dùng để chọn ngưỡng. Mỗi stage ghi hash đầu ra vào manifest của run. Việc có hash là điều kiện truy vết, nhưng người đọc vẫn phải kiểm tra hash model, dataset và mã có khớp cùng một lần chạy hay không.

### 4.2 Nhóm miền, publisher pins và các loại holdout

Main dùng hostname chính xác; rework xác định registrable domain bằng snapshot Public Suffix List gồm cả private rules. Các subdomain thuộc cùng phạm vi đăng ký được nhóm trước khi chia; IP hoặc hậu tố không nhận diện được dùng host chính xác. Hash với seed 42 giúp chia lặp lại, còn publisher split được ưu tiên khi hiện diện. Điều này giảm nguy cơ cùng tổ chức/miền đi vào train và test qua nhiều subdomain, nhưng không chứng minh độc lập theo campaign, nguồn hoặc thời điểm. Muốn kiểm tra khả năng tổng quát hóa theo nguồn phải dùng `--holdout-source` hoặc một bộ thu riêng đã khóa sau huấn luyện.

### 4.3 Đường đi của model và điểm cờ nguy cơ

Lexical + SGD log loss, word TF-IDF + SGD log loss, và word/char n-gram + SGD modified Huber vẫn là ba cấu hình so sánh. Cờ web dùng `risk_score = 1 - raw_benign_score`, rồi gắn cờ nếu điểm ít nhất 0,50. Điểm này chưa được chứng minh là xác suất đã hiệu chuẩn. Khi tính precision và tải cảnh báo, phải lấy cùng file validation và đúng hash model đang phục vụ web; kết quả `pipeline.predict` bốn lớp không được thay cho kết quả cờ của web.

Khác biệt quan trọng ở split: bản main dùng hostname chính xác; rework dùng SHA-256(seed, registrable domain) với Public Suffix List được ghim phiên bản. IP và hậu tố chưa rõ được nhóm theo host chính xác; publisher pins vẫn được ưu tiên. Public Suffix List định nghĩa phần hậu tố công cộng, hỗ trợ nhận diện phạm vi đăng ký miền [3]. [split_audit.json](runs/run_20261104_merged_steps_final_smoke/metrics/split_audit.json) ghi 1.880 nhóm, 2.063 hostname và 2.248 URL duy nhất; không thấy nhóm, host, URL chính xác hoặc khóa gần trùng giao giữa ba tập trong smoke này. Khóa gần trùng chỉ là ứng viên kỹ thuật, không xác nhận hai URL có cùng đích. Nhiều nguồn vẫn có mặt trong cả ba split; do đó phép này chưa phải holdout theo nguồn hoặc thời gian.

Ba baseline được giữ để so sánh trên cùng run: lexical + SGD log loss, word TF-IDF + SGD log loss, và word/char n-gram + SGD modified Huber. Tên “SVM” là nhãn cấu hình; estimator thực tế không phải LinearSVC. Mỗi run lưu interpreter, giới hạn mẫu, worker, hash mã và output trong manifest. Web tính risk_score từ điểm benign thô và có audit riêng cho cờ nguy cơ ở validation; điểm này chưa được chứng minh là xác suất đã hiệu chuẩn.

## 5. Thí nghiệm và kết quả

### 5.1 Smoke run rework mới nhất

[JSON đánh giá](runs/run_20261104_merged_steps_final_smoke/metrics/multiclass_summary.json) ghi 363 URL test. Bảng dưới đây được trình bày để kiểm tra pipeline, **không dùng làm bảng hiệu năng final**.

| Model | Accuracy smoke | Macro-precision | Macro-recall | Macro-F1 | Recall phishing | Recall malware |
|---|---:|---:|---:|---:|---:|---:|
| Word + char, modified Huber | 65,01% | 42,87% | 38,98% | 37,97% | 65,14% | 25,00% |
| Word TF-IDF, log loss | 68,32% | 35,53% | 34,39% | 34,47% | 56,57% | 0,00% |
| Lexical, log loss | 29,75% | 33,96% | 27,17% | 20,87% | 21,71% | 50,00% |

Bảng 3. Mỗi mẫu malware đổi recall 25 điểm phần trăm, cho thấy độ bất định rất lớn. Lớp malicious có support 0 và F1 ghi 0 theo cách xuất báo cáo; không thể diễn giải như khả năng nhận diện lớp này.

Precision/recall/F1 của word + char trên test smoke: benign 87,68/65,76/75,16%; phishing 81,43/65,14/72,38%; malware 2,38/25,00/4,35%; malicious không có support. Confusion matrix có hàng là nhãn thật, cột là nhãn dự đoán theo thứ tự benign, malicious, phishing, malware:

| Thật \ Dự đoán | benign | malicious | phishing | malware |
|---|---:|---:|---:|---:|
| benign | 121 | 27 | 24 | 12 |
| malicious | 0 | 0 | 0 | 0 |
| phishing | 17 | 15 | 114 | 29 |
| malware | 0 | 1 | 2 | 1 |

Bảng 4. Ma trận word + char của smoke run. Có 17 phishing bị gán benign và 63 benign bị gán một lớp nguy cơ. Số báo động nhầm ở đây gắn với quyết định nhãn bốn lớp; audit cờ nguy cơ của web là phép đo khác.

**Giới hạn lineage:** JSON ghi dataset_matches_manifest=true nhưng models_match_manifest=false, dẫn đến provenance_verified=false. Cần điều tra và tái tạo manifest/model khớp hash trước khi dùng run làm bằng chứng phát hành. Run smoke được tạo trong thư mục cách ly; các file model lịch sử trong outputs/ không được xem là model mới.

### 5.2 Audit cờ nguy cơ web trên validation

[audit validation](runs/run_20261104_merged_steps_final_smoke/metrics/web_decision_validation.json) dùng ngưỡng 0,50 cho risk_score = 1 - điểm benign thô. Với word + char, confusion nhị phân là TN=115, FP=106, FN=9, TP=129 trên 359 validation URL. Ngưỡng này phát hiện nhiều URL nguy cơ nhưng tạo 106 cảnh báo nhầm trên 221 benign validation, một chi phí vận hành cao. Điểm chưa calibration và chỉ có 2 malware; ngưỡng cần chọn lại theo mục tiêu bỏ sót và tải rà soát trên validation có đủ lớp. Không chọn ngưỡng dựa vào test smoke hay chẩn đoán OpenPhish đã xem.

### 5.3 Đối chiếu lịch sử với main

Bản rework đang giữ [báo cáo lịch sử của main](outputs/metrics/multiclass_summary.json): 5.913.123 test nội bộ, word + char macro-F1 81,37%, TF-IDF 63,69%, lexical 47,00%. Những số này thuộc dataset/model cũ v_20261103_134343, **không** thuộc pipeline rework mới. Chẩn đoán web trên 300 URL OpenPhish của bản main cho recall phishing 47,00%, 31,67%, 32,00% theo cùng thứ tự model [4]. Lô đó đã được dùng để thiết kế rework nên chỉ còn là bộ chẩn đoán hồi quy; một final holdout mới phải được lấy sau khi khóa model rework.

Không lập bảng “main vs rework: bên nào tốt hơn” từ 5,9 triệu test cũ và 363 smoke URL mới vì khác dữ liệu, split, chất lượng nhãn và model provenance. Phép so sánh hợp lệ phải chạy cả ba baseline cũ và mô hình cải tiến trên cùng bộ đánh giá mới, với hash model, nguồn và thời điểm đầy đủ.

### 5.4 Cái giá vận hành của ngưỡng cờ nguy cơ

Trên validation smoke có 221 benign và 138 URL thuộc ba lớp nguy cơ. Với word + char tại ngưỡng 0,50, 129/138 nguy cơ được gắn cờ (recall 93,48%) nhưng 106/221 benign cũng bị gắn cờ (tỷ lệ báo động nhầm 47,96%). Precision của cờ là 129/(129+106) = 54,89% trong đúng tập validation này. TF-IDF bỏ sót 47 nguy cơ nhưng chỉ báo nhầm 36 benign; lexical bỏ sót 17 và báo nhầm 146. Các tỷ lệ phụ thuộc mạnh vào phân bố mẫu smoke và không dự báo tải SOC thực tế.

| Cấu hình cờ nguy cơ | TP | FN | FP | TN | Recall nguy cơ | Báo động nhầm trên benign |
|---|---:|---:|---:|---:|---:|---:|
| Word + char | 129 | 9 | 106 | 115 | 93,48% | 47,96% |
| Word TF-IDF | 91 | 47 | 36 | 185 | 65,94% | 16,29% |
| Lexical | 121 | 17 | 146 | 75 | 87,68% | 66,06% |

Bảng 5. Tính từ [web_decision_validation.json](runs/run_20261104_merged_steps_final_smoke/metrics/web_decision_validation.json). TP/FN xét tất cả lớp nguy cơ, FP/TN xét benign; đây là validation, không phải test final. Trước triển khai cần chọn ngưỡng theo mức bỏ sót và năng lực rà soát, kiểm tra độ hiệu chuẩn của điểm và đo lại trên benign mới đại diện.

## 6. Phân tích lỗi và thảo luận bảo mật

Tập [diagnostic_error_counts.json](docs/diagnostic_error_counts.json) trích từ CSV web lịch sử, trong đó OpenPhish 300 có 142 phishing gán benign bởi word + char, 169 bởi TF-IDF và 169 bởi lexical. Lô 20 URLhaus trước đó có 0/20 đúng lớp malware ở cả ba model; đa số là mẫu IP và đường dẫn ngắn nên chỉ kết luận cho nhóm nhỏ đó. [Mẫu rà nhãn](docs/diagnostic_label_review.csv) có 119 dòng với trạng thái unreviewed; không được dùng như nhãn đã xác minh để tăng dữ liệu train.

False negative có thể bỏ lọt liên kết độc hại; false positive có thể tạo chặn nhầm và quá tải nhân sự. Báo cáo cần tách lỗi **sai lớp tấn công** khỏi **bỏ sót nguy cơ**. Khi một phishing bị gán malware, hệ thống vẫn cảnh báo nguy cơ nhưng sai mục tiêu điều tra. Ngược lại, phishing gán benign là trường hợp nguy hiểm hơn cho cơ chế cho phép tự động. URL chứa token hoặc thông tin cá nhân cần được che trước khi đưa vào slide; không truy cập liên kết nghi vấn trong buổi trình bày.

### 6.1 Quy trình điều tra lỗi có thể tái lập

Mỗi ca lỗi cần lưu URL đã che token, nhãn nguồn, thời điểm nguồn quan sát, phiên bản model, hash CSV và quyết định của web. Lấy mẫu theo seed từ bốn nhóm: phishing gán benign, malware gán benign, benign bị cắm cờ và nhầm giữa các lớp tấn công. Người rà mẫu kiểm tra bằng chứng gốc, không truy cập URL đáng ngờ trong môi trường trình bày. Nếu nhãn gốc mơ hồ, ghi “chưa xác minh” thay vì tự chuyển thành lỗi model. Chỉ sau khi đóng nhãn mới có thể dùng các ca này để sửa data hoặc đánh giá theo nhóm.

Các con số từ `diagnostic_error_counts.json` và 119 dòng `diagnostic_label_review.csv` là danh sách ưu tiên rà soát, không phải kết quả rà nhãn. Một lỗi từng được quan sát trên lô OpenPhish/URLhaus cũ không được dùng như final holdout độc lập sau khi đã ảnh hưởng thiết kế rework. Muốn kiểm tra giả thuyết “mô hình bỏ sót URL IP” cần thu mẫu mới đủ lớn, có nhóm so sánh và nhãn URL đáng tin cậy.

## 7. Giới hạn, đạo đức và rủi ro hoạt động

Điểm yếu chưa giải quyết gồm nhãn theo nguồn chưa xác minh đồng loạt, thiếu malicious và rất ít malware trong smoke, nguồn còn giao nhau, thiếu timestamp nguồn đáng tin cho temporal holdout, và cờ nguy cơ chưa calibration. Hash mismatch của run mới nhất khiến lineage model chưa đạt điều kiện công bố. Giấy phép và điều khoản từng nguồn phải được ghi theo snapshot; OpenPhish Community Feed và URLhaus có điều kiện sử dụng riêng [1][2]. Tránh dùng danh sách miền làm nhãn URL hoặc dùng URL cũ làm bằng chứng an toàn hiện tại.

Web local bind 127.0.0.1 theo README. File joblib chỉ được nạp khi tin cậy vì định dạng này có thể thực thi mã khi deserialize. Tính năng upload model được khóa bằng AIC_ALLOW_MODEL_UPLOAD và phải giữ tắt trong demo thông thường. Hệ thống phân loại URL này không dùng LLM khi suy luận; hallucination/prompt injection không phải rủi ro trực tiếp của classifier. Nếu nhóm dùng GenAI để viết mã hoặc tài liệu, cần khai báo công cụ, phần hỗ trợ và người kiểm chứng.

### 7.1 Danh sách chặn trước khi công bố model rework

Thứ nhất, phải xác minh ngữ nghĩa nhãn của từng publisher và có đủ bốn lớp trong train, validation và holdout. Thứ hai, sửa `models_match_manifest=false` rồi tái chạy để hash model và split khớp. Thứ ba, tạo final holdout theo nguồn/thời gian sau khi khóa model và ngưỡng; URL trùng, nhóm miền trùng và campaign đã biết phải được kiểm soát. Thứ tư, báo cáo cả precision, recall, F1, confusion matrix, cờ nguy cơ và độ bất định cho lớp hiếm. Thứ năm, xác minh web dùng đúng model đã đo. Mỗi điều kiện có thể kiểm tra bằng tệp và hash; hiện tại chưa đủ để công bố kết quả mới.

Ngoài chất lượng mô hình, dữ liệu URL có thể chứa token, định danh cá nhân và tên miền còn hoạt động. Tài liệu nộp chỉ đưa thống kê và ví dụ đã che nhạy cảm, ghi điều khoản của feed, ngày snapshot và người kiểm chứng. Model joblib chỉ nạp từ nguồn tin cậy; upload model giữ tắt trong demo. Công cụ GenAI nếu dùng để hỗ trợ mã hoặc bản thảo phải được khai báo, còn việc kiểm tra dữ liệu và kết luận thuộc trách nhiệm nhóm.

## 8. Kết luận và công việc tương lai

Rework đã tạo nền tảng kiểm soát nhãn, split theo registrable domain, audit chồng lấn và chạy cách ly. Những cải tiến này là về **quy trình đánh giá**, chưa chứng minh mô hình dự đoán tốt hơn. Để hoàn tất đề tài, nhóm cần: (1) xác minh nhãn ở cấp URL cho đủ bốn lớp và benign mới; (2) sửa lỗi hash model/manifest; (3) tạo validation và final holdout theo nguồn/thời gian thật, không giao nhóm; (4) huấn luyện lại ba baseline và từng cải tiến có kiểm soát; (5) chọn model/ngưỡng bằng validation rồi chỉ đánh giá final holdout một lần; (6) xác minh model web cùng hash với model báo cáo và xuất CSV đầy đủ. Nếu model mới không thắng baseline trên final holdout, báo cáo kết quả đó trung thực.

## 9. Tài liệu tham khảo

1. [OpenPhish, Phishing Feeds](https://openphish.com/phishing_feeds.html), truy cập 04/11/2026.
2. [URLhaus, Community API](https://urlhaus.abuse.ch/api), truy cập 04/11/2026.
3. [Public Suffix List](https://publicsuffix.org/list/), truy cập 04/11/2026.
4. [Log kiểm thử web 04/11/2026](test%20case/WEB_TEST_TONG_HOP_2026-11-04.md); nguồn số liệu ngoài tập và giới hạn nhãn domain.
5. [Manifest run](runs/run_20261104_merged_steps_final_smoke/run_manifest.json), [dataset_version.json](runs/run_20261104_merged_steps_final_smoke/processed/dataset_version.json), [multiclass_summary.json](runs/run_20261104_merged_steps_final_smoke/metrics/multiclass_summary.json), [split_audit.json](runs/run_20261104_merged_steps_final_smoke/metrics/split_audit.json), [web_decision_validation.json](runs/run_20261104_merged_steps_final_smoke/metrics/web_decision_validation.json). Bảng 1–4 trích từ các tệp này.

## Phụ lục A. Tái lập và tự kiểm tra trước nộp

Theo [README](README.md), môi trường Python tương thích được cài từ requirements.txt; lệnh chạy cách ly là: python -B steps/run_all.py --isolated --run-dir runs/run_TEN_MOI. Chỉ dùng --all-rows sau khi chốt mapping nhãn theo nguồn và tạo holdout mới. Lệnh smoke không thay thế chạy đầy đủ. Trước khi nộp, nhóm cần chạy test mã, ghi interpreter/seed/worker/hash và kiểm tra biểu đồ, slide, web cùng một model/dataset manifest.

| Mục tự kiểm tra | Tình trạng của bản rework |
|---|---|
| Bài toán bảo mật và giá trị thực tế | Đã mô tả |
| Nguồn, class distribution, vấn đề dữ liệu | Có policy và manifest; nhãn nguồn chưa xác minh xong |
| Baseline so sánh | Có ba cấu hình trên smoke; final comparison còn thiếu |
| Precision, recall, F1, confusion matrix | Có trên smoke; chưa đủ lớp để công bố final |
| FP/FN theo security operations | Có phân tích; mẫu ngoài tập chưa rà nhãn xong |
| Mất cân bằng lớp | Đã nêu; cần mẫu đủ bốn lớp và chiến lược kiểm định |
| LLM/GenAI | Không dùng ở suy luận; khai báo hỗ trợ phát triển trước nộp |
| README tái chạy | Có lệnh cách ly; full run chưa xác nhận |
| Slides khớp report và code | Chưa xác minh trong phạm vi báo cáo |
| Hình, bảng, tham khảo | Có nguồn; cần rà định dạng nộp cuối |

**Khai báo AI và thông tin bìa còn phải điền:** tên môn, thành viên, giảng viên, học kỳ, công cụ AI hỗ trợ, phạm vi sử dụng, người rà soát và ngày nộp.
