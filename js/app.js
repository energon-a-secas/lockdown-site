// ── Entry point ──────────────────────────────────────────────
// Keep this file under 50 lines.

import { state } from './state.js';
import { render } from './render.js';
import { bindEvents } from './events.js';
import { initConvex } from './data.js';

async function init() {
  await initConvex();
  render(state);
  bindEvents(state);
}

init();
