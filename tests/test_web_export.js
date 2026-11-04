const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('web/static/app.js', 'utf8');
const start = source.indexOf('function exportResultsToCsv(');
const end = source.indexOf('\nfunction ', start + 1);
assert(start >= 0 && end > start);
let exported = '';
const context = {
  Blob: class { constructor(parts) { exported = parts.join(''); } },
  URL: { createObjectURL: () => 'blob:test', revokeObjectURL: () => {} },
  document: { body: { appendChild: () => {}, removeChild: () => {} }, createElement: () => ({ click: () => {} }) },
};
vm.runInNewContext(source.slice(start, end), context);
const results = Array.from({ length: 10000 }, (_, index) => ({
  url: `https://example.test/a,${index}?q="quoted"`, predicted_class: 'benign', risk_flag: index % 2 === 0,
  risk_level: 'safe', risk_percent: 42, score_calibrated: false, probabilities: { benign: 0.58 },
  details: { host: 'example.test', length: 42, entropy: 2, suspicious_found: [] },
  model_id: 'fixture', model_sha256: 'abc', scanned_at_utc: '2026-11-04T00:00:00Z',
}));
context.exportResultsToCsv(results, 'fixture');
const lines = exported.trim().split('\r\n');
assert.equal(lines.length, 10001);
assert(lines[1].includes('"https://example.test/a,0?q=""quoted"""'));
assert(lines[10000].includes('"https://example.test/a,9999?q=""quoted"""'));
assert(lines[0].includes('Model SHA-256'));
console.log('CSV export: 10000 ordered rows, comma/quote URL preserved');
