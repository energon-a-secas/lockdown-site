// ── State management ─────────────────────────────────────────
// Ephemeral state only. No localStorage persistence.

export const state = {
  scanning: false,
  targetUrl: '',
  progress: 0,
  progressLabel: '',
  results: null,
  activeCategory: 'all',
  error: '',
};
