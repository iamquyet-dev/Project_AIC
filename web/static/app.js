'use strict';

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[ch]);
}

const state = {
  activeModel: 'model_word_char_svm',
  models: [],
  selectedUploadFile: null,
};

const CLASS_COLORS = {
  benign: '#10b981',
  '0': '#10b981',
  phishing: '#ef4444',
  malware: '#f97316',
  defacement: '#8b5cf6',
  malicious: '#e11d48',
  '1': '#e11d48',
};

const CLASS_NAME_MAP = {
  benign: 'An toàn (Benign)',
  '0': 'An toàn (0)',
  phishing: 'Lừa đảo (Phishing)',
  malware: 'Mã độc (Malware)',
  defacement: 'Giao diện (Defacement)',
  malicious: 'Độc hại (Malicious)',
  '1': 'Độc hại (1)',
};

// 1. Chuyen doi Tab
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach((c) => c.classList.remove('active'));
    btn.classList.add('active');
    const target = document.getElementById(btn.dataset.tab);
    if (target) target.classList.add('active');
  });
});

// 2. Lay trang thai he thong & danh sach model
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    state.activeModel = data.active_model;
    state.models = data.models || [];
    renderModelDropdown();
    renderModelsList();
    renderDatasetSummary(data.dataset_summary || {});
  } catch (err) {
    console.error('Lỗi nạp thông tin trạng thái:', err);
    renderDatasetSummary({ verified: false, reason: 'Không kết nối được tới máy chủ.' });
  }
}

function renderDatasetSummary(summary) {
  const note = document.getElementById('dataset-summary-note');
  const distribution = document.getElementById('class-distribution');
  if (!summary.verified) {
    note.textContent = summary.reason || 'Chưa xác minh phiên bản dữ liệu.';
    for (const id of ['dataset-total', 'dataset-classes', 'dataset-train', 'dataset-test']) {
      document.getElementById(id).textContent = '—';
    }
    distribution.textContent = 'Chưa hiển thị phân bố vì metadata không khớp dữ liệu hiện tại.';
    return;
  }

  const splits = summary.splits || {};
  const totals = {};
  for (const split of Object.values(splits)) {
    for (const [label, count] of Object.entries(split.class_distribution || {})) {
      totals[label] = (totals[label] || 0) + Number(count);
    }
  }
  const format = (value) => Number(value || 0).toLocaleString('vi-VN');
  note.textContent = `Phiên bản ${summary.version || 'không tên'} — số liệu từ manifest chia tập đã đối chiếu file.`;
  document.getElementById('dataset-total').textContent = format(summary.total_rows);
  document.getElementById('dataset-classes').textContent = format(Object.keys(totals).length);
  document.getElementById('dataset-train').textContent = format(splits.train?.rows);
  document.getElementById('dataset-test').textContent = format(splits.test?.rows);
  distribution.innerHTML = '';
  for (const [label, count] of Object.entries(totals)) {
    const row = document.createElement('div');
    row.className = 'dist-row';
    const labelElement = document.createElement('span');
    labelElement.textContent = `${CLASS_NAME_MAP[label] || label}: ${format(count)} dòng`;
    row.appendChild(labelElement);
    distribution.appendChild(row);
  }
}

async function fetchMetrics() {
  const note = document.getElementById('metrics-note');
  const body = document.getElementById('metrics-body');
  try {
    const response = await fetch('/api/metrics');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const report = await response.json();
    if (!Array.isArray(report.models) || !report.models.length) throw new Error('Chưa có báo cáo đánh giá.');
    const rows = Number(report.total_rows || 0).toLocaleString('vi-VN');
    const verified = report.provenance_verified === true;
    note.textContent = `${report.dataset || 'Tập chưa rõ'} · ${rows} URL · ${report.timestamp || 'không rõ ngày'}. ${verified ? 'Đã đối chiếu phiên bản mô hình và dữ liệu.' : 'Chưa xác minh khớp phiên bản mô hình/dữ liệu; không dùng để kết luận học vẹt.'}`;
    body.innerHTML = '';
    const featureNames = {
      svm: 'Word + char n-grams (3-5 ký tự)',
      logistic_tfidf: 'Word TF-IDF',
      logistic_lexical: '11 đặc trưng cấu trúc (Lexical)',
    };
    const modelIds = {
      svm: 'model_word_char_svm',
      logistic_tfidf: 'model_word_tfidf_logistic',
      logistic_lexical: 'model_lexical_logistic',
    };
    const percent = (value) => `${(Number(value || 0) * 100).toFixed(2)}%`;
    for (const model of report.models) {
      const row = document.createElement('tr');
      const modelInfo = state.models.find((item) => item.id === modelIds[model.model_key]);
      for (const value of [
        model.name || model.model_key,
        featureNames[model.model_key] || 'Không rõ',
        percent(model.accuracy),
        percent(model.precision_weighted),
        percent(model.recall_weighted),
        percent(model.weighted_f1),
        percent(model.macro_f1),
        modelInfo?.file_size_human || '—',
      ]) {
        const cell = document.createElement('td');
        cell.textContent = value;
        row.appendChild(cell);
      }
      body.appendChild(row);
    }
  } catch (err) {
    note.textContent = `Không thể hiển thị báo cáo: ${err.message}`;
    body.innerHTML = '<tr><td colspan="8">Chưa có số liệu đánh giá hợp lệ.</td></tr>';
  }
}

function renderModelDropdown() {
  const select = document.getElementById('header-model-select');
  if (!select) return;
  select.innerHTML = '';
  state.models.forEach((m) => {
    const opt = document.createElement('option');
    opt.value = m.id;
    const sizeStr = m.file_size_human || (m.file_size_mb >= 1 ? `${m.file_size_mb} MB` : `${Math.round(m.file_size_mb * 1024)} KB`);
    opt.textContent = `${m.name} (${sizeStr})`;
    if (m.id === state.activeModel) opt.selected = true;
    select.appendChild(opt);
  });
}

function renderModelsList() {
  const container = document.getElementById('models-list');
  if (!container) return;
  container.innerHTML = '';
  state.models.forEach((m) => {
    const isAct = m.id === state.activeModel;
    const sizeStr = m.file_size_human || (m.file_size_mb >= 1 ? `${m.file_size_mb} MB` : `${Math.round(m.file_size_mb * 1024)} KB`);
    const card = document.createElement('div');
    card.className = `model-card-item ${isAct ? 'active-model' : ''}`;
    card.innerHTML = `
      <div class="model-info">
        <h4>${escapeHtml(m.name)} ${isAct ? '<span class="badge-active">Đang sử dụng</span>' : ''}</h4>
        <p>${escapeHtml(m.description || '')}</p>
        <p class="mono muted" style="margin-top: 4px;">File: ${escapeHtml(m.file)} · Dung lượng: ${escapeHtml(sizeStr)}</p>
      </div>
      <div>
        ${
          isAct
            ? '<button class="btn btn-secondary btn-sm" disabled>Đang sử dụng</button>'
            : '<button class="btn btn-primary btn-sm">Kích hoạt</button>'
        }
      </div>
    `;
    if (!isAct) card.querySelector('button').addEventListener('click', () => selectModel(m.id));
    container.appendChild(card);
  });
}

async function selectModel(modelId) {
  const scanButton = document.getElementById('btn-scan');
  scanButton.disabled = true;
  try {
    const res = await fetch('/api/models/select', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ model_id: modelId }),
    });
    const data = await res.json();
    if (data.success) {
      state.activeModel = modelId;
      renderModelDropdown();
      renderModelsList();
    } else {
      renderModelDropdown();
      alert(`Lỗi: ${data.error}`);
    }
  } catch (err) {
    renderModelDropdown();
    alert(`Lỗi kết nối: ${err.message}`);
  } finally {
    scanButton.disabled = false;
  }
}

// 3. Bat su kien thay doi Dropdown o Header
document.getElementById('header-model-select').addEventListener('change', (e) => {
  selectModel(e.target.value);
});

// 4. Phan tich URL
const urlInput = document.getElementById('url-input-area');
const urlCounter = document.getElementById('url-counter');

function updateUrlCount() {
  const lines = urlInput.value.split('\n').filter((s) => s.trim().length > 0);
  urlCounter.textContent = `${lines.length} URL`;
}
urlInput.addEventListener('input', updateUrlCount);

document.querySelectorAll('.sample-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    urlInput.value = btn.dataset.sample;
    updateUrlCount();
  });
});

document.getElementById('btn-scan').addEventListener('click', async () => {
  const rawText = urlInput.value.trim();
  const urls = rawText.split('\n').map((s) => s.trim()).filter(Boolean);
  if (!urls.length) {
    alert('Vui lòng nhập ít nhất một URL.');
    return;
  }

  const btnScan = document.getElementById('btn-scan');
  const btnScanText = document.getElementById('btn-scan-text');
  btnScan.disabled = true;
  btnScanText.textContent = 'Đang phân tích...';

  const container = document.getElementById('scan-results-container');
  container.innerHTML = '<div class="alert-box">Đang trích xuất đặc trưng và suy luận mô hình...</div>';

  try {
    const res = await fetch('/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ urls, model_id: state.activeModel }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    renderResults(data);
  } catch (err) {
    container.innerHTML = `<div class="alert-box" style="background: rgba(239,68,68,0.2); color:#fca5a5;">Lỗi: ${escapeHtml(err.message)}</div>`;
  } finally {
    btnScan.disabled = false;
    btnScanText.textContent = 'Phân tích URL';
  }
});

function exportResultsToCsv(results, modelName) {
  const headers = ['URL', 'Phán đoán', 'Mức rủi ro', 'Điểm rủi ro (%)', 'Benign (%)', 'Malicious (%)', 'Phishing (%)', 'Malware (%)', 'Hostname', 'Độ dài', 'Entropy', 'Từ khóa cảnh báo', 'Mô hình'];
  const rows = [headers.join(',')];
  results.forEach((r) => {
    const esc = (val) => `"${String(val ?? '').replace(/"/g, '""')}"`;
    const probs = r.probabilities || {};
    rows.push([
      esc(r.url),
      esc(r.verdict),
      esc(r.risk_level),
      r.risk_percent ?? '',
      probs.benign !== undefined ? (probs.benign * 100).toFixed(1) : '',
      probs.malicious !== undefined ? (probs.malicious * 100).toFixed(1) : '',
      probs.phishing !== undefined ? (probs.phishing * 100).toFixed(1) : '',
      probs.malware !== undefined ? (probs.malware * 100).toFixed(1) : '',
      esc(r.details?.host || ''),
      r.details?.length ?? '',
      r.details?.entropy ?? '',
      esc((r.details?.suspicious_found || []).join('; ')),
      esc(modelName || r.model_name || '')
    ].join(','));
  });
  const blob = new Blob(["\uFEFF" + rows.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `AIC211_KetQua_${results.length}_URL.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function renderResults(data) {
  const container = document.getElementById('scan-results-container');
  const total = data.results.length;

  let safeCount = 0, suspCount = 0, dangCount = 0;
  data.results.forEach((r) => {
    if (r.risk_level === 'safe') safeCount++;
    else if (r.risk_level === 'suspicious') suspCount++;
    else dangCount++;
  });

  container.innerHTML = `
    <div style="background:rgba(30,41,59,0.7); border:1px solid #334155; padding:14px; border-radius:8px; margin-bottom:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:12px;">
        <div>
          <h3 style="margin:0 0 4px 0;">Kết quả phân tích (${total.toLocaleString()} URL · ${Number(data.elapsed_ms)} ms)</h3>
          <span class="mono muted" style="font-size:12px;">Mô hình: ${escapeHtml(data.model_used)}</span>
        </div>
        <button id="btn-export-csv" style="background:#0284c7; color:#fff; border:none; padding:8px 16px; border-radius:6px; cursor:pointer; font-weight:600; display:inline-flex; align-items:center; gap:6px;">
          📥 Tải toàn bộ kết quả (CSV)
        </button>
      </div>
      <div style="display:flex; gap:12px; flex-wrap:wrap;">
        <div style="flex:1; min-width:140px; background:rgba(16,185,129,0.15); border:1px solid #10b981; padding:8px 12px; border-radius:6px;">
          <div style="color:#10b981; font-size:11px; font-weight:600;">AN TOÀN</div>
          <div style="font-size:20px; font-weight:bold; color:#10b981;">${safeCount.toLocaleString()}</div>
        </div>
        <div style="flex:1; min-width:140px; background:rgba(245,158,11,0.15); border:1px solid #f59e0b; padding:8px 12px; border-radius:6px;">
          <div style="color:#f59e0b; font-size:11px; font-weight:600;">NGHI VẤN</div>
          <div style="font-size:20px; font-weight:bold; color:#f59e0b;">${suspCount.toLocaleString()}</div>
        </div>
        <div style="flex:1; min-width:140px; background:rgba(239,68,68,0.15); border:1px solid #ef4444; padding:8px 12px; border-radius:6px;">
          <div style="color:#ef4444; font-size:11px; font-weight:600;">ĐỘC HẠI</div>
          <div style="font-size:20px; font-weight:bold; color:#ef4444;">${dangCount.toLocaleString()}</div>
        </div>
      </div>
    </div>
    <div id="cards-wrapper"></div>
  `;

  document.getElementById('btn-export-csv').addEventListener('click', () => {
    exportResultsToCsv(data.results, data.model_used);
  });

  const cardsWrapper = document.getElementById('cards-wrapper');
  const renderLimit = 50;
  const initialItems = total > renderLimit ? data.results.slice(0, renderLimit) : data.results;

  function createResultCard(item) {
    const card = document.createElement('div');
    card.className = `result-card ${item.risk_level}`;

    let barsHtml = '';
    for (const [clsName, probVal] of Object.entries(item.probabilities)) {
      const col = CLASS_COLORS[clsName] || '#3b82f6';
      const pct = (probVal * 100).toFixed(1);
      const labelDisplayName = escapeHtml(CLASS_NAME_MAP[clsName] || clsName);
      barsHtml += `
        <div class="prob-item">
          <div class="prob-title">
            <span>${labelDisplayName}</span>
            <strong>${pct}%</strong>
          </div>
          <div class="prob-bar-track">
            <div class="prob-bar-fill" style="width: ${pct}%; background: ${col};"></div>
          </div>
        </div>
      `;
    }

    const suspiciousTag = item.details.suspicious_found && item.details.suspicious_found.length
      ? `<span style="color:#ef4444; font-weight:600;">Từ khóa cảnh báo: ${escapeHtml(item.details.suspicious_found.join(', '))}</span>`
      : '<span style="color:#10b981;">Không phát hiện từ khóa lừa đảo</span>';

    card.innerHTML = `
      <div class="result-header">
        <div class="result-url-wrap">
          <span class="verdict-badge ${escapeHtml(item.risk_level)}">${escapeHtml(item.verdict)}</span>
          <span class="result-url">${escapeHtml(item.url)}</span>
        </div>
        <div class="result-metrics">
          <div class="metric-gauge-val" style="color: ${item.verdict_color};">${item.risk_percent}%</div>
          <div class="metric-gauge-label">Điểm mô hình (chưa hiệu chuẩn)</div>
        </div>
      </div>

      <div class="prob-grid">
        ${barsHtml}
      </div>

      <div class="url-details-row">
        <span>Hostname: <strong>${escapeHtml(item.details.host || 'N/A')}</strong></span>
        <span>Độ dài: <strong>${item.details.length}</strong> ký tự</span>
        <span>Entropy: <strong>${item.details.entropy}</strong></span>
        ${suspiciousTag}
      </div>
    `;
    return card;
  }

  initialItems.forEach((item) => cardsWrapper.appendChild(createResultCard(item)));

  if (total > renderLimit) {
    const notice = document.createElement('div');
    notice.id = 'render-more-notice';
    notice.style.cssText = 'background:rgba(59,130,246,0.15); border:1px solid #3b82f6; padding:12px 16px; border-radius:8px; margin-top:14px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;';
    notice.innerHTML = `
      <span style="color:#93c5fd; font-size:13px;">
        Đang hiển thị <strong>${renderLimit}</strong> / <strong>${total.toLocaleString()}</strong> thẻ kết quả để giữ trình duyệt mượt mà. Vui lòng bấm <strong>Tải toàn bộ kết quả (CSV)</strong> để xem chi tiết trên Excel.
      </span>
      <button id="btn-show-all-cards" style="background:#334155; color:#f1f5f9; border:none; padding:6px 12px; border-radius:6px; cursor:pointer; font-size:12px;">
        Hiển thị tất cả lên web
      </button>
    `;
    container.appendChild(notice);

    document.getElementById('btn-show-all-cards').addEventListener('click', () => {
      data.results.slice(renderLimit).forEach((item) => cardsWrapper.appendChild(createResultCard(item)));
      notice.remove();
    });
  }
}

// 5. Nhap Model qua Duong dan
document.getElementById('form-import-model-path').addEventListener('submit', async (e) => {
  e.preventDefault();
  const filePath = document.getElementById('input-model-path').value.trim();
  if (!filePath) return;

  const statusBox = document.getElementById('upload-status');
  statusBox.hidden = false;
  statusBox.textContent = 'Đang nạp file mô hình...';

  try {
    const res = await fetch('/api/upload_model', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ file_path: filePath }),
    });
    const data = await res.json();
    if (data.success) {
      statusBox.textContent = data.message;
      state.models = data.models;
      state.activeModel = data.model_id;
      renderModelDropdown();
      renderModelsList();
    } else {
      statusBox.textContent = `Lỗi: ${data.error}`;
    }
  } catch (err) {
    statusBox.textContent = `Lỗi: ${err.message}`;
  }
});

// 6. Tai len Model qua Dropzone
const dropZone = document.getElementById('model-drop-zone');
const fileInput = document.getElementById('input-model-file');
const btnUpload = document.getElementById('btn-upload-model');

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length) {
    handleFileSelected(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files.length) {
    handleFileSelected(e.target.files[0]);
  }
});

function handleFileSelected(file) {
  state.selectedUploadFile = file;
  const sizeStr = file.size < 1024 * 1024
    ? `${(file.size / 1024).toFixed(1)} KB`
    : `${(file.size / (1024 * 1024)).toFixed(2)} MB`;
  dropZone.querySelector('p').textContent = `Đã chọn: ${file.name} (${sizeStr})`;
  btnUpload.disabled = false;
}

document.getElementById('form-upload-model-file').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.selectedUploadFile) return;

  const statusBox = document.getElementById('upload-status');
  statusBox.hidden = false;
  statusBox.textContent = 'Đang tải lên và phân tích mô hình...';

  const formData = new FormData();
  formData.append('model_file', state.selectedUploadFile);

  try {
    const res = await fetch('/api/upload_model', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    if (data.success) {
      statusBox.textContent = data.message;
      state.models = data.models;
      state.activeModel = data.model_id;
      renderModelDropdown();
      renderModelsList();
    } else {
      statusBox.textContent = `Lỗi: ${data.error}`;
    }
  } catch (err) {
    statusBox.textContent = `Lỗi: ${err.message}`;
  }
});

// 7. Nhap Dataset
document.getElementById('form-import-dataset').addEventListener('submit', async (e) => {
  e.preventDefault();
  const dPath = document.getElementById('input-dataset-path').value.trim();
  if (!dPath) return;

  const resultBox = document.getElementById('dataset-result');
  resultBox.hidden = false;
  resultBox.innerHTML = '<div class="alert-box">Đang đọc cấu trúc dataset...</div>';

  try {
    const res = await fetch('/api/upload_dataset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ path: dPath }),
    });
    const data = await res.json();
    if (data.success) {
      const d = data.dataset;
      let distRows = '';
      for (const [k, v] of Object.entries(d.class_distribution)) {
        distRows += `<li>${escapeHtml(k)}: <strong>${v.toLocaleString()}</strong></li>`;
      }
      resultBox.innerHTML = `
        <div class="card" style="margin-top: 14px;">
          <h4>Đã đọc thành công: ${escapeHtml(d.file_name)} (${Number(d.file_size_mb)} MB)</h4>
          <p class="muted">Cột nhãn nhận diện: <strong>${escapeHtml(d.label_column)}</strong> · Số dòng đọc mẫu: <strong>${Number(d.sample_rows).toLocaleString()}</strong></p>
          <ul style="margin-top: 8px; margin-left: 20px;">
            ${distRows}
          </ul>
        </div>
      `;
    } else {
      resultBox.innerHTML = `<div class="alert-box" style="background: rgba(239,68,68,0.2); color:#fca5a5;">Lỗi: ${escapeHtml(data.error)}</div>`;
    }
  } catch (err) {
    resultBox.innerHTML = `<div class="alert-box" style="background: rgba(239,68,68,0.2); color:#fca5a5;">Lỗi: ${escapeHtml(err.message)}</div>`;
  }
});

// Khoi tao khi tai trang
fetchStatus().then(fetchMetrics);
