// ── DOM rendering ────────────────────────────────────────────

import { escHtml } from './utils.js';

const CATEGORY_META = {
  files:     { label: 'Exposed Files',       icon: '&#128193;' },
  headers:   { label: 'Security Headers',    icon: '&#128737;' },
  robots:    { label: 'Robots & Sitemap',    icon: '&#129302;' },
  seo:       { label: 'SEO Basics',          icon: '&#128269;' },
  endpoints: { label: 'API Endpoints',       icon: '&#128268;' },
  leakage:   { label: 'Info Leakage',        icon: '&#128065;' },
};

export function render(state) {
  // Gate vs scanner visibility
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

  // Tabs
  renderTabs(results, activeCategory);

  // Findings
  renderFindings(results, activeCategory);
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
    html += `<div class="finding-group">
      <div class="finding-group-title">${meta.icon} ${escHtml(meta.label)}</div>`;

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

    html += `</div>`;
  }

  if (!html) {
    html = '<p style="color:var(--text-muted)">No findings for this category.</p>';
  }

  container.innerHTML = html;
}
