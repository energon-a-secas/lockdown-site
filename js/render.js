// ── DOM rendering ────────────────────────────────────────────

import { escHtml } from './utils.js';

const CATEGORY_META = {
  files:     { label: 'Exposed Files',       icon: '&#128193;' },
  headers:   { label: 'Security Headers',    icon: '&#128737;' },
  robots:    { label: 'Robots & Sitemap',    icon: '&#129302;' },
  seo:       { label: 'SEO Basics',          icon: '&#128269;' },
  endpoints: { label: 'API Endpoints',       icon: '&#128268;' },
  fuzz:      { label: 'Endpoint Fuzzing',    icon: '&#128270;' },
  leakage:   { label: 'Info Leakage',        icon: '&#128065;' },
};

export function render(state) {
  const gateCard = document.getElementById('gateCard');
  const scannerView = document.getElementById('scannerView');
  if (gateCard) gateCard.hidden = state.authenticated;
  if (scannerView) scannerView.hidden = !state.authenticated;
}

export function renderProgress(label, pct) {
  const card = document.getElementById('progressCard');
  const lbl = document.getElementById('progressLabel');
  const pctEl = document.getElementById('progressPct');
  const fill = document.getElementById('progressFill');
  if (card) card.hidden = false;
  if (lbl) lbl.textContent = label;
  if (pctEl) pctEl.textContent = Math.round(pct) + '%';
  if (fill) fill.style.width = pct + '%';
}

export function hideProgress() {
  const card = document.getElementById('progressCard');
  if (card) card.hidden = true;
}

export function renderResults(results, activeCategory) {
  const view = document.getElementById('resultsView');
  view.hidden = false;

  // Score
  const allFindings = Object.values(results.categories).flat();
  const critCount = allFindings.filter(f => f.severity === 'critical').length;
  const warnCount = allFindings.filter(f => f.severity === 'warning').length;
  const passCount = allFindings.filter(f => f.severity === 'pass').length;
  const total = allFindings.length || 1;
  const score = Math.max(0, Math.round(((passCount - critCount * 3 - warnCount) / total) * 100));
  const grade = score >= 80 ? 'A' : score >= 60 ? 'B' : score >= 40 ? 'C' : score >= 20 ? 'D' : 'F';

  const badge = document.getElementById('scoreBadge');
  badge.textContent = grade;
  badge.className = 'score-badge grade-' + grade.toLowerCase();

  document.getElementById('resultsUrl').textContent = results.url;

  renderTabs(results, activeCategory);
  renderFindings(results, activeCategory);
  renderNetworkLog(results.requests || []);
}

function renderTabs(results, activeCategory) {
  const container = document.getElementById('categoryTabs');
  const allCount = Object.values(results.categories).flat().length;

  let html = `<button class="cat-tab ${activeCategory === 'all' ? 'active' : ''}" data-cat="all">
    All <span class="tab-count">${allCount}</span>
  </button>`;

  for (const [key, findings] of Object.entries(results.categories)) {
    const meta = CATEGORY_META[key] || { label: key, icon: '' };
    const isActive = activeCategory === key;
    html += `<button class="cat-tab ${isActive ? 'active' : ''}" data-cat="${key}">
      ${meta.label} <span class="tab-count">${findings.length}</span>
    </button>`;
  }

  container.innerHTML = html;
}

function renderFindings(results, activeCategory) {
  const container = document.getElementById('findingsContainer');
  let html = '';

  const categoriesToShow = activeCategory === 'all'
    ? Object.entries(results.categories)
    : [[activeCategory, results.categories[activeCategory] || []]];

  for (const [key, findings] of categoriesToShow) {
    if (!findings.length) continue;
    const meta = CATEGORY_META[key] || { label: key, icon: '' };

    // Count severities for the group header
    const counts = { critical: 0, warning: 0, info: 0, pass: 0 };
    for (const f of findings) counts[f.severity]++;

    const countBadges = Object.entries(counts)
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => `<span class="group-severity-badge ${sev}">${n}</span>`)
      .join('');

    html += `<details class="finding-group" open>
      <summary class="finding-group-title">
        <span class="group-chevron"></span>
        ${meta.icon} ${escHtml(meta.label)}
        <span class="group-severity-badges">${countBadges}</span>
      </summary>
      <div class="finding-group-body">`;

    for (const f of findings) {
      html += `<div class="finding severity-${f.severity}">
        <div class="finding-header">
          <span class="severity-dot ${f.severity}"></span>
          <span class="finding-title">${escHtml(f.title)}</span>
        </div>`;

      if (f.endpoint) {
        html += `<div class="finding-endpoint">${escHtml(f.endpoint)}</div>`;
      }
      if (f.detail) {
        html += `<div class="finding-detail">${escHtml(f.detail)}</div>`;
      }
      if (f.hardening) {
        html += `<div class="finding-hardening"><strong>Hardening:</strong> ${escHtml(f.hardening)}</div>`;
      }

      html += `</div>`;
    }

    html += `</div></details>`;
  }

  if (!html) {
    html = '<p style="color:var(--text-muted)">No findings for this category.</p>';
  }

  container.innerHTML = html;
}

function renderNetworkLog(requests) {
  const container = document.getElementById('networkLog');
  if (!container || !requests.length) return;

  const statusColor = (s) => {
    if (s === null) return 'net-timeout';
    if (s >= 200 && s < 300) return 'net-ok';
    if (s >= 300 && s < 400) return 'net-redirect';
    if (s >= 400 && s < 500) return 'net-client-err';
    return 'net-server-err';
  };

  const formatSize = (bytes) => {
    if (bytes === null) return '-';
    if (bytes < 1024) return bytes + ' B';
    return (bytes / 1024).toFixed(1) + ' KB';
  };

  let html = `<details class="netlog-panel">
    <summary class="netlog-title">
      <span class="group-chevron"></span>
      Network Log
      <span class="tab-count">${requests.length} requests</span>
    </summary>
    <div class="netlog-body">
      <div class="netlog-header-row">
        <span class="netlog-col-method">Method</span>
        <span class="netlog-col-url">URL</span>
        <span class="netlog-col-status">Status</span>
        <span class="netlog-col-size">Size</span>
        <span class="netlog-col-time">Time</span>
      </div>`;

  for (const req of requests) {
    const cls = statusColor(req.status);
    const shortUrl = req.url.length > 70 ? req.url.substring(0, 67) + '...' : req.url;
    html += `<div class="netlog-row ${cls}">
      <span class="netlog-col-method">${req.method}</span>
      <span class="netlog-col-url" title="${escHtml(req.url)}">${escHtml(shortUrl)}</span>
      <span class="netlog-col-status">${req.status ?? 'TIMEOUT'}</span>
      <span class="netlog-col-size">${formatSize(req.size)}</span>
      <span class="netlog-col-time">${req.duration}ms</span>
    </div>`;
  }

  html += `</div></details>`;
  container.innerHTML = html;
}
