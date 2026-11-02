# Bảng So Sánh Hiệu Năng 3 Mô Hình AIC211 (Đầy đủ Precision, Recall, F1)

| Mô hình | Đặc trưng | Accuracy | Precision (Weighted) | Recall (Weighted) | Weighted-F1 | Precision (Macro) | Recall (Macro) | Macro-F1 | Dung lượng | Thời gian Train |
|---|---|---|---|---|---|---|---|---|---|---|
| **1. Linear SVM** | Word + char n-grams (3-5 ký tự) | **92.13%** | 93.16% | 92.13% | **92.26%** | 42.45% | 34.46% | 36.19% | 3.98 MB | 105.66 phút |
| **2. Logistic Regression** | Word TF-IDF | **87.53%** | 87.58% | 87.52% | **87.32%** | 35.85% | 31.45% | 32.32% | 2.34 MB | 24.86 phút |
| **3. Logistic Regression** | 11 đặc trưng cấu trúc (Lexical) | **77.08%** | 85.82% | 77.08% | **80.65%** | 31.47% | 28.71% | 29.73% | 1.9 KB | 57.59 phút |
