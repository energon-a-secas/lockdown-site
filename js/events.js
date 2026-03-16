// ── Event handlers ───────────────────────────────────────────

import { verifyPassword, runScan } from './data.js';
import { render, renderProgress, hideProgress, renderResults } from './render.js';
import { normalizeUrl, toast } from './utils.js';
import { generateReport } from './report.js';

export function bindEvents(state) {
  // Password gate
  const gateSubmit = document.getElementById('gateSubmit');
  const gatePassword = document.getElementById('gatePassword');
  const gateError = document.getElementById('gateError');

  if (gateSubmit) {
    gateSubmit.addEventListener('click', () => handleGate(state, gatePassword, gateError));
  }
  if (gatePassword) {
    gatePassword.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleGate(state, gatePassword, gateError);
    });
  }

  // Scan button
  const scanBtn = document.getElementById('scanBtn');
  const targetUrl = document.getElementById('targetUrl');

  if (scanBtn) {
    scanBtn.addEventListener('click', () => handleScan(state));
  }
  if (targetUrl) {
    targetUrl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleScan(state);
    });
  }

  // Category tabs (delegated)
  const tabsContainer = document.getElementById('categoryTabs');
  if (tabsContainer) {
    tabsContainer.addEventListener('click', (e) => {
      const tab = e.target.closest('.cat-tab');
      if (!tab) return;
      state.activeCategory = tab.dataset.cat;
      renderResults(state.results, state.activeCategory);
    });
  }

  // Download report
  const downloadBtn = document.getElementById('downloadBtn');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
      if (!state.results) return;
      const md = generateReport(state.results);
      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const hostname = new URL(state.results.url).hostname;
      a.href = url;
      a.download = `lockdown-report-${hostname}.md`;
      a.click();
      URL.revokeObjectURL(url);
      toast('Report downloaded');
    });
  }
}

async function handleGate(state, input, errorEl) {
  const pw = input.value.trim();
  if (!pw) {
    errorEl.textContent = 'Enter a password';
    return;
  }
  errorEl.textContent = '';
  try {
    const ok = await verifyPassword(pw);
    if (ok) {
      state.authenticated = true;
      state._password = pw;
      render(state);
    } else {
      errorEl.textContent = 'Invalid password';
    }
  } catch (e) {
    errorEl.textContent = e.message || 'Connection error';
  }
}

async function handleScan(state) {
  const input = document.getElementById('targetUrl');
  const errorEl = document.getElementById('scanError');
  const scanBtn = document.getElementById('scanBtn');
  const scanBtnText = document.getElementById('scanBtnText');
  const scanBtnSpinner = document.getElementById('scanBtnSpinner');

  const url = normalizeUrl(input.value);
  if (!url) {
    errorEl.textContent = 'Enter a valid URL';
    return;
  }

  errorEl.textContent = '';
  state.scanning = true;
  state.results = null;
  state.activeCategory = 'all';
  document.getElementById('resultsView').hidden = true;

  scanBtn.disabled = true;
  scanBtnText.textContent = 'Scanning...';
  scanBtnSpinner.hidden = false;

  try {
    // Parse custom fuzz base paths
    const fuzzInput = document.getElementById('fuzzPaths');
    const fuzzBasePaths = fuzzInput && fuzzInput.value.trim()
      ? fuzzInput.value.split(',').map(p => p.trim()).filter(Boolean)
      : null;

    const results = await runScan(url, state._password, (label, pct) => {
      renderProgress(label, pct);
    }, fuzzBasePaths);

    state.results = results;
    hideProgress();
    renderResults(results, state.activeCategory);
  } catch (e) {
    hideProgress();
    errorEl.textContent = e.message || 'Scan failed';
  } finally {
    state.scanning = false;
    scanBtn.disabled = false;
    scanBtnText.textContent = 'Scan';
    scanBtnSpinner.hidden = true;
  }
}
