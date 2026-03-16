# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Lockdown — Site Security Scanner

Scan websites for exposed endpoints, missing headers, open files, and SEO gaps. Modular ES module app with Convex backend.

**Run:** `npx convex dev` for backend, then `python3 -m http.server 8824` from `lockdown-site/` (ES modules require a server). Or `make serve` and `make convex`.

**Live:** lockdown.neorgon.com

## Architecture

Standard modular layout: `index.html` shell + `css/style.css` + `js/*.js`. Backend in `convex/scanner.ts`.

**Password gate:** Site requires a password before scanning. The password is stored as a Convex environment variable `LOCKDOWN_PASSWORD`. Every Convex action validates it before executing.

**Scan flow:** Frontend calls 6 Convex actions sequentially, updating a progress bar between each. Each action makes HTTP requests to the target URL from Convex's server-side runtime (no CORS issues). Results are assembled client-side and rendered as categorized findings.

**Scan categories:**
- `probeFiles` — checks 30+ sensitive file paths (.env, .git/config, .DS_Store, backup.sql, etc.)
- `checkHeaders` — verifies 7 security headers (HSTS, CSP, X-Frame-Options, etc.) + HTTPS
- `checkRobots` — analyzes robots.txt and sitemap.xml presence and configuration
- `checkSeo` — checks title, meta description, OG tags, viewport, canonical, favicon
- `probeEndpoints` — tests 24 common API/admin paths (/api, /graphql, /swagger, /admin, /metrics, etc.)
- `fuzzEndpoints` — brute-forces common resource names and query params under user-specified base paths (default /api, /api/v1, /api/v2)
- `checkLeakage` — inspects server headers, X-Powered-By, debug info, and secret patterns in HTML

**Finding model:** Each finding has `severity` (critical/warning/info/pass), `title`, optional `detail`, optional `endpoint`, and optional `hardening` recommendation.

**Report export:** `js/report.js` generates a full markdown report with severity summary table, grade, and per-category findings with hardening tips. Downloaded as `lockdown-report-{hostname}.md`.

**No persistence:** No database tables. All scan results are ephemeral. The only Convex env var is `LOCKDOWN_PASSWORD`.

## Key Files

| File | Purpose |
|------|---------|
| `js/app.js` | Entry point, initializes Convex + UI |
| `js/state.js` | Ephemeral state (auth, scan progress, results) |
| `js/data.js` | Convex client, scan orchestration |
| `js/render.js` | DOM rendering, results display |
| `js/events.js` | Event handlers (gate, scan, tabs, download) |
| `js/report.js` | Markdown report generator |
| `js/utils.js` | escHtml, toast, normalizeUrl |
| `convex/scanner.ts` | All 6 scan actions + password verification |
| `convex/schema.ts` | Empty schema (stateless) |

## Adding a New Scan Check

1. Add a new exported action in `convex/scanner.ts` that accepts `{ targetUrl, password }` and returns `Finding[]`.
2. Add the call to `runScan()` in `js/data.js` at the appropriate position in the sequence.
3. Add the category key to `CATEGORY_META` in `js/render.js` and `CATEGORY_LABELS` in `js/report.js`.
