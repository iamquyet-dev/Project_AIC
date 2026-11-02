'use strict';

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
  } catch (err) {
    console.error('Lỗi nạp thông tin trạng thái:', err);
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
        <h4>${m.name} ${isAct ? '<span class="badge-active">Đang sử dụng</span>' : ''}</h4>
        <p>${m.description || ''}</p>
        <p class="mono muted" style="margin-top: 4px;">File: ${m.file} · Dung lượng: ${sizeStr}</p>
      </div>
      <div>
        ${
          isAct
            ? '<button class="btn btn-secondary btn-sm" disabled>Đang sử dụng</button>'
            : `<button class="btn btn-primary btn-sm" onclick="selectModel('${m.id}')">Kích hoạt</button>`
        }
      </div>
    `;
    container.appendChild(card);
  });
}

async function selectModel(modelId) {
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
      alert(`Lỗi: ${data.error}`);
    }
  } catch (err) {
    alert(`Lỗi kết nối: ${err.message}`);
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
    container.innerHTML = `<div class="alert-box" style="background: rgba(239,68,68,0.2); color:#fca5a5;">Lỗi: ${err.message}</div>`;
  } finally {
    btnScan.disabled = false;
    btnScanText.textContent = 'Phân tích URL';
  }
});

function renderResults(data) {
  const container = document.getElementById('scan-results-container');
  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
      <h3>Kết quả phân tích (${data.total_scanned} URL · ${data.elapsed_ms} ms)</h3>
      <span class="mono muted">Mô hình: ${data.model_used}</span>
    </div>
  `;

  data.results.forEach((item) => {
    const card = document.createElement('div');
    card.className = `result-card ${item.risk_level}`;

    let barsHtml = '';
    for (const [clsName, probVal] of Object.entries(item.probabilities)) {
      const col = CLASS_COLORS[clsName] || '#3b82f6';
      const pct = (probVal * 100).toFixed(1);
      const labelDisplayName = CLASS_NAME_MAP[clsName] || clsName;
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
      ? `<span style="color:#ef4444; font-weight:600;">Từ khóa cảnh báo: ${item.details.suspicious_found.join(', ')}</span>`
      : '<span style="color:#10b981;">Không phát hiện từ khóa lừa đảo</span>';

    card.innerHTML = `
      <div class="result-header">
        <div class="result-url-wrap">
          <span class="verdict-badge ${item.risk_level}">${item.verdict}</span>
          <span class="result-url">${item.url}</span>
        </div>
        <div class="result-metrics">
          <div class="metric-gauge-val" style="color: ${item.verdict_color};">${item.risk_percent}%</div>
          <div class="metric-gauge-label">Mức nguy hại</div>
        </div>
      </div>

      <div class="prob-grid">
        ${barsHtml}
      </div>

      <div class="url-details-row">
        <span>Hostname: <strong>${item.details.host || 'N/A'}</strong></span>
        <span>Độ dài: <strong>${item.details.length}</strong> ký tự</span>
        <span>Entropy: <strong>${item.details.entropy}</strong></span>
        ${suspiciousTag}
      </div>
    `;
    container.appendChild(card);
  });
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
  dropZone.querySelector('p').innerHTML = `Đã chọn: <strong>${file.name}</strong> (${sizeStr})`;
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
        distRows += `<li>${k}: <strong>${v.toLocaleString()}</strong></li>`;
      }
      resultBox.innerHTML = `
        <div class="card" style="margin-top: 14px;">
          <h4>Đã đọc thành công: ${d.file_name} (${d.file_size_mb} MB)</h4>
          <p class="muted">Cột nhãn nhận diện: <strong>${d.label_column}</strong> · Số dòng đọc mẫu: <strong>${d.sample_rows.toLocaleString()}</strong></p>
          <ul style="margin-top: 8px; margin-left: 20px;">
            ${distRows}
          </ul>
        </div>
      `;
    } else {
      resultBox.innerHTML = `<div class="alert-box" style="background: rgba(239,68,68,0.2); color:#fca5a5;">Lỗi: ${data.error}</div>`;
    }
  } catch (err) {
    resultBox.innerHTML = `<div class="alert-box" style="background: rgba(239,68,68,0.2); color:#fca5a5;">Lỗi: ${err.message}</div>`;
  }
});

// Khoi tao khi tai trang
fetchStatus();
